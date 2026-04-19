use crate::ApeManager;
use crate::ape::path::path_inside_root;
use crate::ape::process::{
    AsyncIoState, FileHandle, FileType, NormalFileHandle, PipeEndHandle, PseudoCharDevice,
    PtyMasterHandle, PtySlaveHandle,
};
use crate::ape::user::USER_PATH_MAX;
use crate::io::tty::set_terminal_pgrp_local;
use alloc::format;
use alloc::vec::Vec;
use glenda::cap::{CSPACE_CAP, Endpoint, Page};
use glenda::client::{FsClient, TerminalClient};
use glenda::error::Error;
use glenda::interface::{
    CSpaceService, FileHandleService, FileSystemService, VirtualTerminalService,
};
use glenda::io::uring::{IoUringBuffer, IoUringClient};
use glenda::ipc::Badge;
use linux_raw_sys::general::{
    F_DUPFD, F_DUPFD_CLOEXEC, F_GETFD, F_GETFL, F_SETFD, F_SETFL, FD_CLOEXEC, O_CLOEXEC, O_NONBLOCK,
};

const DIRENT64_FIXED_SIZE: usize = 8 + 8 + 2 + 1;
const DIRENT64_MIN_RECLEN: usize = 24;
const PIPE2_ALLOWED_FLAGS: u32 = O_CLOEXEC | O_NONBLOCK;

#[inline]
fn align_up_8(v: usize) -> usize {
    (v + 7) & !7
}

// 4KB ring + 12KB data window，降低每 fd 的常驻内存。
const FS_ASYNC_REGION_SIZE: usize = 16 * 1024;
const FS_ASYNC_RING_SIZE: usize = 4096;
const FS_ASYNC_DATA_OFFSET: usize = FS_ASYNC_RING_SIZE;
const FS_ASYNC_SQ_ENTRIES: u32 = 16;
const FS_ASYNC_CQ_ENTRIES: u32 = 16;
const ENABLE_FS_ASYNC_IO: bool = true;

enum DevicePathKind {
    StdioTty,
    Pseudo(PseudoCharDevice),
    PtyMaster,
    PtySlave(usize),
}

fn classify_device_path(path: &str) -> Option<DevicePathKind> {
    if path == "/dev/ptmx" {
        return Some(DevicePathKind::PtyMaster);
    }
    if let Some(idx) = path.strip_prefix("/dev/pts/") {
        return idx.parse::<usize>().ok().map(DevicePathKind::PtySlave);
    }
    if path.starts_with("/dev/tty")
        || matches!(path, "/dev/console" | "/dev/stdin" | "/dev/stdout" | "/dev/stderr")
    {
        return Some(DevicePathKind::StdioTty);
    }

    let pseudo = match path {
        "/dev/null" => Some(PseudoCharDevice::Null),
        "/dev/zero" => Some(PseudoCharDevice::Zero),
        "/dev/random" => Some(PseudoCharDevice::Random),
        "/dev/urandom" => Some(PseudoCharDevice::URandom),
        _ => None,
    };
    pseudo.map(DevicePathKind::Pseudo)
}

pub(crate) fn do_openat<'a>(
    mgr: &mut ApeManager<'a>,
    pid: usize,
    dirfd: usize,
    pathname: usize,
    flags: usize,
    mode: usize,
) -> Result<isize, Error> {
    let _ = dirfd;
    let raw_path = mgr.strncpy_from_user(pid, pathname, USER_PATH_MAX)?;
    let path = mgr.resolve_path_for_process(pid, &raw_path)?;
    let root_dir = mgr.get_process(pid).ok_or(Error::NotFound)?.root_dir.clone();
    let guest_path = path_inside_root(&path, &root_dir).unwrap_or_else(|| path.clone());

    if let Some(kind) = classify_device_path(&guest_path) {
        match kind {
            DevicePathKind::PtyMaster => {
                let ep_slot = mgr.cspace_mgr.alloc(&mut *mgr.res_client)?;
                let vt_name = format!("pts-{}-{}", pid, guest_path);
                let (vt_id, vt_ep) = match mgr.vt_client.create_vt(Badge::null(), &vt_name, ep_slot)
                {
                    Ok(v) => v,
                    Err(e) => {
                        mgr.cspace_mgr.free(ep_slot);
                        return Err(e);
                    }
                };
                if let Err(e) = mgr.vt_client.set_pty_lock(Badge::null(), vt_id, true) {
                    let _ = mgr.vt_client.destroy_vt(Badge::null(), vt_id);
                    let _ = CSPACE_CAP.delete(ep_slot);
                    mgr.cspace_mgr.free(ep_slot);
                    return Err(e);
                }

                let term = TerminalClient::new(vt_ep);
                set_terminal_pgrp_local(mgr, term, pid as i32);

                let fd = {
                    let process = mgr.get_process_mut(pid).ok_or(Error::NotFound)?;
                    let fd = process.next_fd;
                    process.next_fd += 1;
                    process.fds.insert(
                        fd,
                        FileHandle {
                            file_type: FileType::PtyMaster(PtyMasterHandle {
                                term,
                                vt_id,
                                ep_slot,
                                locked: true,
                            }),
                        },
                    );
                    fd
                };
                mgr.ledger_record_fd_open(pid);
                return Ok(fd as isize);
            }
            DevicePathKind::PtySlave(vt_id) => {
                let locked = mgr.vt_client.get_pty_lock(Badge::null(), vt_id)?;
                if locked {
                    return Err(Error::PermissionDenied);
                }

                let slave_ep_slot = mgr.cspace_mgr.alloc(&mut *mgr.res_client)?;
                let vt_ep = match mgr.vt_client.open_vt(Badge::null(), vt_id, slave_ep_slot) {
                    Ok(ep) => ep,
                    Err(e) => {
                        mgr.cspace_mgr.free(slave_ep_slot);
                        return Err(e);
                    }
                };

                let fd = {
                    let process = mgr.get_process_mut(pid).ok_or(Error::NotFound)?;
                    let fd = process.next_fd;
                    process.next_fd += 1;
                    process.fds.insert(
                        fd,
                        FileHandle {
                            file_type: FileType::PtySlave(PtySlaveHandle {
                                term: TerminalClient::new(vt_ep),
                                vt_id,
                                ep_slot: slave_ep_slot,
                            }),
                        },
                    );
                    fd
                };
                mgr.ledger_record_fd_open(pid);
                return Ok(fd as isize);
            }
            DevicePathKind::StdioTty => {
                let term = mgr.stdio_term().ok_or(Error::NotFound)?;
                let fd = {
                    let process = mgr.get_process_mut(pid).ok_or(Error::NotFound)?;
                    let fd = process.next_fd;
                    process.next_fd += 1;
                    process.fds.insert(fd, FileHandle { file_type: FileType::Terminal(term) });
                    fd
                };
                mgr.ledger_record_fd_open(pid);
                return Ok(fd as isize);
            }
            DevicePathKind::Pseudo(dev) => {
                let fd = {
                    let process = mgr.get_process_mut(pid).ok_or(Error::NotFound)?;
                    let fd = process.next_fd;
                    process.next_fd += 1;
                    process.fds.insert(fd, FileHandle { file_type: FileType::PseudoChar(dev) });
                    fd
                };
                mgr.ledger_record_fd_open(pid);
                return Ok(fd as isize);
            }
        }
    }

    // 使用 Nexus 返回的独立句柄 endpoint（强制隔离）。
    let fs_ep_slot = mgr.cspace_mgr.alloc(&mut *mgr.res_client)?;
    let mut fs_open_client = FsClient::new(mgr.fs_client.endpoint());
    let open_flags = glenda::protocol::fs::OpenFlags::from_bits_truncate(flags);
    if let Err(e) = fs_open_client.open(Badge::null(), &path, open_flags, mode as u32, fs_ep_slot) {
        let _ = CSPACE_CAP.delete(fs_ep_slot);
        mgr.cspace_mgr.free(fs_ep_slot);
        return Err(e);
    }

    let fs_ep = Endpoint::from(fs_ep_slot);
    let mut fs_client = FsClient::new(fs_ep);

    let mut async_io = None;
    if ENABLE_FS_ASYNC_IO && mgr.should_try_fs_iouring() {
        if let Ok(region) = mgr.allocate_fs_async_region(pid, FS_ASYNC_REGION_SIZE) {
            let ring_buf = unsafe {
                IoUringBuffer::new(
                    region.vaddr as *mut u8,
                    FS_ASYNC_RING_SIZE,
                    FS_ASYNC_SQ_ENTRIES,
                    FS_ASYNC_CQ_ENTRIES,
                )
            };
            let mut ring = IoUringClient::new(ring_buf);
            // NOTE:
            // 通过 Nexus 代理的文件句柄 endpoint 无法可靠承载 io_uring 的 notify badge 路由，
            // 直接 notify 会在 Nexus 侧落入未知请求分支。
            // APE 的读写路径会在 submit 后显式调用 process_iouring()，因此这里不设置 notify。

            match fs_client.setup_iouring(
                Badge::null(),
                region.vaddr,
                region.size,
                Some(Page::from(region.frame_slot)),
            ) {
                Ok(()) => {
                    mgr.mark_fs_iouring_supported();
                    let data_vaddr = region.vaddr + FS_ASYNC_DATA_OFFSET;
                    if data_vaddr < region.vaddr + region.size {
                        let data_len = region.size - FS_ASYNC_DATA_OFFSET;
                        async_io = Some(AsyncIoState {
                            region_id: region.id,
                            ring,
                            data_vaddr,
                            data_len,
                            next_user_data: 1,
                        });
                    } else {
                        mgr.recycle_fs_async_region(region.id);
                    }
                }
                Err(Error::NotSupported) => {
                    mgr.mark_fs_iouring_unsupported();
                    warn!(
                        "sys_openat: setup_iouring not supported pid={}, path={}, disable async probe and fallback sync",
                        pid, path
                    );
                    mgr.recycle_fs_async_region(region.id);
                }
                Err(e) => {
                    warn!(
                        "sys_openat: setup_iouring failed pid={}, path={}, err={:?}; fallback sync and keep async probe enabled",
                        pid, path, e
                    );
                    mgr.recycle_fs_async_region(region.id);
                }
            }
        }
    }

    let fd = {
        let process = mgr.get_process_mut(pid).ok_or(Error::NotFound)?;
        let fd = process.next_fd;
        process.next_fd += 1;
        process.fds.insert(
            fd,
            FileHandle {
                file_type: FileType::Normal(NormalFileHandle {
                    fs_client,
                    fs_ep_slot,
                    offset: 0,
                    async_io,
                }),
            },
        );
        process.fd_paths.insert(fd, path);
        fd
    };
    mgr.ledger_record_fd_open(pid);

    Ok(fd as isize)
}

pub(crate) fn do_close<'a>(
    mgr: &mut ApeManager<'a>,
    pid: usize,
    fd: usize,
) -> Result<isize, Error> {
    let fd = u32::try_from(fd).map_err(|_| Error::InvalidSlot)?;
    let handle = {
        let process = mgr.get_process_mut(pid).ok_or(Error::NotFound)?;
        process.fd_paths.remove(&fd);
        process.fd_cloexec.remove(&fd);
        process.fds.remove(&fd).ok_or(Error::InvalidSlot)?
    };

    match handle.file_type {
        FileType::Terminal(_) | FileType::PseudoChar(_) => {}
        FileType::PtyMaster(master) => {
            let _ = mgr.vt_client.destroy_vt(Badge::null(), master.vt_id);
            let _ = CSPACE_CAP.delete(master.ep_slot);
            mgr.cspace_mgr.free(master.ep_slot);
        }
        FileType::PtySlave(slave) => {
            let _ = CSPACE_CAP.delete(slave.ep_slot);
            mgr.cspace_mgr.free(slave.ep_slot);
        }
        FileType::PipeRead(pipe) => {
            mgr.close_pipe_read_end(pipe.pipe_id);
        }
        FileType::PipeWrite(pipe) => {
            mgr.close_pipe_write_end(pipe.pipe_id);
        }
        FileType::Normal(mut normal) => {
            let _ = normal.fs_client.close(Badge::null());
            if !normal.fs_ep_slot.is_null() {
                let _ = CSPACE_CAP.delete(normal.fs_ep_slot);
                mgr.cspace_mgr.free(normal.fs_ep_slot);
            }
            if let Some(async_io) = normal.async_io {
                mgr.recycle_fs_async_region(async_io.region_id);
            }
        }
    }

    mgr.ledger_record_fd_close(pid);

    Ok(0)
}

pub(crate) fn do_fcntl<'a>(
    mgr: &mut ApeManager<'a>,
    pid: usize,
    fd: usize,
    cmd: usize,
    arg: usize,
) -> Result<isize, Error> {
    let fd = u32::try_from(fd).map_err(|_| Error::InvalidSlot)?;
    let cmd = u32::try_from(cmd).map_err(|_| Error::InvalidArgs)?;

    match cmd {
        F_GETFD => {
            let process = mgr.get_process_mut(pid).ok_or(Error::NotFound)?;
            if !process.fds.contains_key(&fd) {
                return Err(Error::InvalidSlot);
            }
            let cloexec = process.fd_cloexec.get(&fd).copied().unwrap_or(false);
            Ok(if cloexec { FD_CLOEXEC as isize } else { 0 })
        }
        F_SETFD => {
            let process = mgr.get_process_mut(pid).ok_or(Error::NotFound)?;
            if !process.fds.contains_key(&fd) {
                return Err(Error::InvalidSlot);
            }
            let cloexec = (arg & (FD_CLOEXEC as usize)) != 0;
            process.fd_cloexec.insert(fd, cloexec);
            Ok(0)
        }
        F_GETFL => {
            let process = mgr.get_process_mut(pid).ok_or(Error::NotFound)?;
            if !process.fds.contains_key(&fd) {
                return Err(Error::InvalidSlot);
            }
            // TODO(ape): 维护并返回真实文件状态标志（O_APPEND/O_NONBLOCK 等）。
            Ok(0)
        }
        F_SETFL => {
            let process = mgr.get_process_mut(pid).ok_or(Error::NotFound)?;
            if !process.fds.contains_key(&fd) {
                return Err(Error::InvalidSlot);
            }
            // TODO(ape): 应用并持久化可变状态标志，影响后续 I/O 行为。
            Ok(0)
        }
        F_DUPFD | F_DUPFD_CLOEXEC => {
            let (new_fd, pipe_clone) = {
                let process = mgr.get_process_mut(pid).ok_or(Error::NotFound)?;
                if !process.fds.contains_key(&fd) {
                    return Err(Error::InvalidSlot);
                }

                let min_fd = u32::try_from(arg).map_err(|_| Error::InvalidArgs)?;
                let mut new_fd = min_fd;
                while process.fds.contains_key(&new_fd) {
                    new_fd = new_fd.checked_add(1).ok_or(Error::OutOfMemory)?;
                }

                let cloned = process.fds.get(&fd).cloned().ok_or(Error::InvalidSlot)?;
                let pipe_clone = match cloned.file_type {
                    FileType::PipeRead(pipe) => Some((true, pipe.pipe_id)),
                    FileType::PipeWrite(pipe) => Some((false, pipe.pipe_id)),
                    _ => None,
                };

                process.fds.insert(new_fd, cloned);
                if let Some(path) = process.fd_paths.get(&fd).cloned() {
                    process.fd_paths.insert(new_fd, path);
                }

                let new_cloexec = cmd == F_DUPFD_CLOEXEC;
                process.fd_cloexec.insert(new_fd, new_cloexec);
                if process.next_fd <= new_fd {
                    process.next_fd = new_fd.saturating_add(1);
                }

                (new_fd, pipe_clone)
            };

            if let Some((is_read, pipe_id)) = pipe_clone {
                if is_read {
                    mgr.clone_pipe_read_end(pipe_id);
                } else {
                    mgr.clone_pipe_write_end(pipe_id);
                }
            }

            mgr.ledger_record_fd_open(pid);
            Ok(new_fd as isize)
        }
        _ => Err(Error::InvalidArgs),
    }
}

pub(crate) fn do_dup<'a>(mgr: &mut ApeManager<'a>, pid: usize, fd: usize) -> Result<isize, Error> {
    do_fcntl(mgr, pid, fd, F_DUPFD as usize, 0)
}

pub(crate) fn do_dup3<'a>(
    mgr: &mut ApeManager<'a>,
    pid: usize,
    oldfd: usize,
    newfd: usize,
    flags: usize,
) -> Result<isize, Error> {
    let oldfd = u32::try_from(oldfd).map_err(|_| Error::InvalidSlot)?;
    let newfd = u32::try_from(newfd).map_err(|_| Error::InvalidSlot)?;

    if oldfd == newfd {
        return Err(Error::InvalidArgs);
    }
    if (flags & !(O_CLOEXEC as usize)) != 0 {
        return Err(Error::InvalidArgs);
    }

    let (cloned, path_clone) = {
        let process = mgr.get_process(pid).ok_or(Error::NotFound)?;
        (
            process.fds.get(&oldfd).cloned().ok_or(Error::InvalidSlot)?,
            process.fd_paths.get(&oldfd).cloned(),
        )
    };

    let need_close_target = {
        let process = mgr.get_process(pid).ok_or(Error::NotFound)?;
        process.fds.contains_key(&newfd)
    };
    if need_close_target {
        do_close(mgr, pid, newfd as usize)?;
    }

    match cloned.file_type {
        FileType::PipeRead(pipe) => mgr.clone_pipe_read_end(pipe.pipe_id),
        FileType::PipeWrite(pipe) => mgr.clone_pipe_write_end(pipe.pipe_id),
        _ => {}
    }

    let process = mgr.get_process_mut(pid).ok_or(Error::NotFound)?;
    process.fds.insert(newfd, cloned);
    if let Some(path) = path_clone {
        process.fd_paths.insert(newfd, path);
    }
    process.fd_cloexec.insert(newfd, (flags & (O_CLOEXEC as usize)) != 0);
    if process.next_fd <= newfd {
        process.next_fd = newfd.saturating_add(1);
    }

    mgr.ledger_record_fd_open(pid);
    Ok(newfd as isize)
}

pub(crate) fn do_getdents64<'a>(
    mgr: &mut ApeManager<'a>,
    pid: usize,
    fd: usize,
    dirp: usize,
    count: usize,
) -> Result<isize, Error> {
    if count == 0 {
        return Ok(0);
    }
    if dirp == 0 {
        return Err(Error::InvalidAddress);
    }
    if count < DIRENT64_MIN_RECLEN {
        return Err(Error::InvalidArgs);
    }

    let fd = u32::try_from(fd).map_err(|_| Error::InvalidSlot)?;

    let mut handle = {
        let process = mgr.get_process_mut(pid).ok_or(Error::NotFound)?;
        process.fds.remove(&fd).ok_or(Error::InvalidSlot)?
    };

    let result = (|| {
        let entries = match &mut handle.file_type {
            FileType::Normal(normal) => normal.fs_client.getdents(Badge::null(), count)?,
            _ => return Err(Error::InvalidType),
        };

        let mut packed = Vec::new();
        for entry in entries {
            let name_len = entry.d_name.iter().position(|b| *b == 0).unwrap_or(entry.d_name.len());

            let reclen = align_up_8(DIRENT64_FIXED_SIZE + name_len + 1);
            if reclen > u16::MAX as usize {
                return Err(Error::OutOfMemory);
            }
            if packed.len().saturating_add(reclen) > count {
                break;
            }

            let start = packed.len();
            packed.extend_from_slice(&(entry.d_ino as u64).to_ne_bytes());
            packed.extend_from_slice(&entry.d_off.to_ne_bytes());
            packed.extend_from_slice(&(reclen as u16).to_ne_bytes());
            packed.push(entry.d_type);
            packed.extend_from_slice(&entry.d_name[..name_len]);
            packed.push(0);
            packed.resize(start + reclen, 0);
        }

        if !packed.is_empty() {
            mgr.copy_to_user(pid, dirp, &packed)?;
        }

        Ok(packed.len() as isize)
    })();

    let process = mgr.get_process_mut(pid).ok_or(Error::NotFound)?;
    process.fds.insert(fd, handle);
    result
}

pub(crate) fn do_pipe2<'a>(
    mgr: &mut ApeManager<'a>,
    pid: usize,
    pipefd: usize,
    flags: usize,
) -> Result<isize, Error> {
    if pipefd == 0 {
        return Err(Error::InvalidAddress);
    }

    let flags = u32::try_from(flags).map_err(|_| Error::InvalidArgs)?;
    if flags & !PIPE2_ALLOWED_FLAGS != 0 {
        return Err(Error::InvalidArgs);
    }

    let pipe_id = mgr.create_pipe();
    let cloexec = (flags & O_CLOEXEC) != 0;

    let (read_fd, write_fd) = {
        let process = mgr.get_process_mut(pid).ok_or(Error::NotFound)?;

        let mut read_fd = process.next_fd;
        while process.fds.contains_key(&read_fd) {
            read_fd = read_fd.checked_add(1).ok_or(Error::OutOfMemory)?;
        }

        let mut write_fd = read_fd.checked_add(1).ok_or(Error::OutOfMemory)?;
        while process.fds.contains_key(&write_fd) {
            write_fd = write_fd.checked_add(1).ok_or(Error::OutOfMemory)?;
        }

        process.fds.insert(
            read_fd,
            FileHandle { file_type: FileType::PipeRead(PipeEndHandle { pipe_id }) },
        );
        process.fds.insert(
            write_fd,
            FileHandle { file_type: FileType::PipeWrite(PipeEndHandle { pipe_id }) },
        );
        process.fd_cloexec.insert(read_fd, cloexec);
        process.fd_cloexec.insert(write_fd, cloexec);
        process.next_fd = write_fd.saturating_add(1);

        (read_fd, write_fd)
    };

    let read_i32 = i32::try_from(read_fd).map_err(|_| Error::OutOfMemory)?;
    let write_i32 = i32::try_from(write_fd).map_err(|_| Error::OutOfMemory)?;
    let mut out = [0u8; 8];
    out[..4].copy_from_slice(&read_i32.to_ne_bytes());
    out[4..].copy_from_slice(&write_i32.to_ne_bytes());

    if let Err(e) = mgr.copy_to_user(pid, pipefd, &out) {
        let process = mgr.get_process_mut(pid).ok_or(Error::NotFound)?;
        process.fds.remove(&read_fd);
        process.fds.remove(&write_fd);
        process.fd_cloexec.remove(&read_fd);
        process.fd_cloexec.remove(&write_fd);
        mgr.close_pipe_read_end(pipe_id);
        mgr.close_pipe_write_end(pipe_id);
        return Err(e);
    }

    mgr.ledger_record_fd_open(pid);
    mgr.ledger_record_fd_open(pid);
    Ok(0)
}
