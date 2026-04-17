use crate::ApeManager;
use crate::ape::path::path_inside_root;
use crate::ape::process::{
    AsyncIoState, FileHandle, FileType, NormalFileHandle, PseudoCharDevice, PtyMasterHandle,
    PtySlaveHandle,
};
use crate::ape::user::USER_PATH_MAX;
use crate::io::tty::set_terminal_pgrp_local;
use alloc::format;
use glenda::cap::{CSPACE_CAP, Endpoint, Page};
use glenda::client::{FsClient, TerminalClient};
use glenda::error::Error;
use glenda::interface::{
    CSpaceService, FileHandleService, FileSystemService, VirtualTerminalService,
};
use glenda::io::uring::{IoUringBuffer, IoUringClient};
use glenda::ipc::Badge;
use linux_raw_sys::general::{
    F_DUPFD, F_DUPFD_CLOEXEC, F_GETFD, F_GETFL, F_SETFD, F_SETFL, FD_CLOEXEC,
};

// 4KB ring + 12KB data window，降低每 fd 的常驻内存。
const FS_ASYNC_REGION_SIZE: usize = 16 * 1024;
const FS_ASYNC_RING_SIZE: usize = 4096;
const FS_ASYNC_DATA_OFFSET: usize = FS_ASYNC_RING_SIZE;
const FS_ASYNC_SQ_ENTRIES: u32 = 16;
const FS_ASYNC_CQ_ENTRIES: u32 = 16;
// TODO(ape): io_uring 路径稳定后启用，并补齐错误恢复与资源回收测试。
const ENABLE_FS_ASYNC_IO: bool = false;

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
                return Ok(fd as isize);
            }
            DevicePathKind::StdioTty => {
                let term = mgr.stdio_term().ok_or(Error::NotFound)?;
                let process = mgr.get_process_mut(pid).ok_or(Error::NotFound)?;
                let fd = process.next_fd;
                process.next_fd += 1;
                process.fds.insert(fd, FileHandle { file_type: FileType::Terminal(term) });
                return Ok(fd as isize);
            }
            DevicePathKind::Pseudo(dev) => {
                let process = mgr.get_process_mut(pid).ok_or(Error::NotFound)?;
                let fd = process.next_fd;
                process.next_fd += 1;
                process.fds.insert(fd, FileHandle { file_type: FileType::PseudoChar(dev) });
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
    if ENABLE_FS_ASYNC_IO {
        if let Ok(region) = mgr.allocate_fs_async_region(FS_ASYNC_REGION_SIZE) {
            log!(
                "sys_openat: try setup_iouring pid={}, path={}, region_id={}, vaddr={:#x}, size={}",
                pid,
                path,
                region.id,
                region.vaddr,
                region.size
            );

            let ring_buf = unsafe {
                IoUringBuffer::new(
                    region.vaddr as *mut u8,
                    FS_ASYNC_RING_SIZE,
                    FS_ASYNC_SQ_ENTRIES,
                    FS_ASYNC_CQ_ENTRIES,
                )
            };
            let mut ring = IoUringClient::new(ring_buf);
            ring.set_server_notify(fs_client.endpoint());

            match fs_client.setup_iouring(
                Badge::null(),
                region.vaddr,
                region.size,
                Some(Page::from(region.frame_slot)),
            ) {
                Ok(()) => {
                    log!("sys_openat: setup_iouring ok pid={}, path={}", pid, path);
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
                    log!(
                        "sys_openat: setup_iouring not supported pid={}, path={}, fallback sync",
                        pid,
                        path
                    );
                    mgr.recycle_fs_async_region(region.id);
                }
                Err(e) => {
                    error!(
                        "sys_openat: setup_iouring failed pid={}, path={}, err={:?}",
                        pid, path, e
                    );
                    let _ = fs_client.close(Badge::null());
                    let _ = CSPACE_CAP.delete(fs_ep_slot);
                    mgr.cspace_mgr.free(fs_ep_slot);
                    mgr.recycle_fs_async_region(region.id);
                    return Err(e);
                }
            }
        }
    }

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

    let process = mgr.get_process_mut(pid).ok_or(Error::NotFound)?;
    if !process.fds.contains_key(&fd) {
        return Err(Error::InvalidSlot);
    }

    match cmd {
        F_GETFD => {
            let cloexec = process.fd_cloexec.get(&fd).copied().unwrap_or(false);
            Ok(if cloexec { FD_CLOEXEC as isize } else { 0 })
        }
        F_SETFD => {
            let cloexec = (arg & (FD_CLOEXEC as usize)) != 0;
            process.fd_cloexec.insert(fd, cloexec);
            Ok(0)
        }
        F_GETFL => {
            // TODO(ape): 维护并返回真实文件状态标志（O_APPEND/O_NONBLOCK 等）。
            Ok(0)
        }
        F_SETFL => {
            // TODO(ape): 应用并持久化可变状态标志，影响后续 I/O 行为。
            Ok(0)
        }
        F_DUPFD | F_DUPFD_CLOEXEC => {
            let min_fd = u32::try_from(arg).map_err(|_| Error::InvalidArgs)?;
            let mut new_fd = min_fd;
            while process.fds.contains_key(&new_fd) {
                new_fd = new_fd.checked_add(1).ok_or(Error::OutOfMemory)?;
            }

            let cloned = process.fds.get(&fd).cloned().ok_or(Error::InvalidSlot)?;
            process.fds.insert(new_fd, cloned);
            if let Some(path) = process.fd_paths.get(&fd).cloned() {
                process.fd_paths.insert(new_fd, path);
            }

            let new_cloexec = cmd == F_DUPFD_CLOEXEC;
            process.fd_cloexec.insert(new_fd, new_cloexec);
            if process.next_fd <= new_fd {
                process.next_fd = new_fd.saturating_add(1);
            }
            Ok(new_fd as isize)
        }
        _ => Err(Error::InvalidArgs),
    }
}
