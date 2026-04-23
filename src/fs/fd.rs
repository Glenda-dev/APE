use crate::ApeManager;
use crate::ape::process::{
    AsyncIoState, FileHandle, FileType, NormalFileHandle, NormalHandleBackend,
};
use crate::ape::user::USER_PATH_MAX;
use alloc::vec::Vec;
use glenda::cap::{CSPACE_CAP, CapPtr, Endpoint, Page};
use glenda::client::FsClient;
use glenda::error::Error;
use glenda::interface::{CSpaceService, FileHandleService, FileSystemService};
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

fn duplicate_normal_handle(
    _mgr: &mut ApeManager<'_>,
    handle: &crate::ape::process::NormalFileHandle,
) -> Result<crate::ape::process::NormalFileHandle, Error> {
    Ok(crate::ape::process::NormalFileHandle {
        backend: NormalHandleBackend::Fs,
        fs_client: handle.fs_client,
        fs_ep_slot: handle.fs_ep_slot,
        offset: handle.offset,
        async_io: None,
    })
}

fn open_pipe_end_via_pipefs<'a>(
    mgr: &mut ApeManager<'a>,
    pipe_id: usize,
    path_suffix: &str,
    flags: glenda::protocol::fs::OpenFlags,
) -> Result<(FsClient, CapPtr), Error> {
    let pipe_ep = mgr.pipe_vfs_endpoint.ok_or(Error::NotFound)?;
    let fs_ep_slot = mgr.cspace_mgr.alloc(&mut *mgr.res_client)?;
    let path = alloc::format!("/{}/{}", pipe_id, path_suffix);
    let mut open_client = FsClient::new(pipe_ep);
    if let Err(e) = open_client.open(Badge::null(), &path, flags, 0, fs_ep_slot) {
        let _ = CSPACE_CAP.delete(fs_ep_slot);
        mgr.cspace_mgr.free(fs_ep_slot);
        return Err(e);
    }
    Ok((FsClient::new(Endpoint::from(fs_ep_slot)), fs_ep_slot))
}

// 4KB ring + 12KB data window，降低每 fd 的常驻内存。
const FS_ASYNC_REGION_SIZE: usize = 16 * 1024;
const FS_ASYNC_RING_SIZE: usize = 4096;
const FS_ASYNC_DATA_OFFSET: usize = FS_ASYNC_RING_SIZE;
const FS_ASYNC_SQ_ENTRIES: u32 = 16;
const FS_ASYNC_CQ_ENTRIES: u32 = 16;
const ENABLE_FS_ASYNC_IO: bool = true;

fn open_via_nexus_fs<'a>(
    mgr: &mut ApeManager<'a>,
    pid: usize,
    path: &str,
    flags: usize,
    mode: usize,
) -> Result<isize, Error> {
    // 使用 Nexus 返回的独立句柄 endpoint（强制隔离）。
    let fs_ep_slot = mgr.cspace_mgr.alloc(&mut *mgr.res_client)?;
    let mut fs_open_client = FsClient::new(mgr.fs_client.endpoint());
    let open_flags = glenda::protocol::fs::OpenFlags::from_bits_truncate(flags);
    if let Err(e) = fs_open_client.open(Badge::null(), path, open_flags, mode as u32, fs_ep_slot) {
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
            let ring = IoUringClient::new(ring_buf);

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
                    backend: NormalHandleBackend::Fs,
                    fs_client,
                    fs_ep_slot,
                    offset: 0,
                    async_io,
                }),
            },
        );
        process.fd_paths.insert(fd, path.into());
        fd
    };
    mgr.ledger_record_fd_open(pid);

    Ok(fd as isize)
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
    open_via_nexus_fs(mgr, pid, &path, flags, mode)
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
        FileType::Normal(normal) => {
            let fs_client = normal.fs_client;
            let fs_ep_slot = normal.fs_ep_slot;
            let async_io = normal.async_io;
            let mut still_shared = false;
            for other_pid in mgr.local_pids() {
                let Some(proc_ref) = mgr.get_process(other_pid) else {
                    continue;
                };
                if proc_ref.fds.values().any(|fh| {
                    matches!(
                        fh.file_type,
                        FileType::Normal(other)
                            if matches!(other.backend, NormalHandleBackend::Fs)
                                && other.fs_ep_slot == fs_ep_slot
                    )
                }) {
                    still_shared = true;
                    break;
                }
            }

            if !still_shared {
                let mut fs_client = fs_client;
                let _ = fs_client.close(Badge::null());
                if !fs_ep_slot.is_null() {
                    let _ = CSPACE_CAP.delete(fs_ep_slot);
                    mgr.cspace_mgr.free(fs_ep_slot);
                }
            }
            if let Some(async_io) = async_io {
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
            let (new_fd, cloned) = {
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
                (new_fd, cloned)
            };

            let cloned = match cloned.file_type {
                FileType::Normal(normal) => FileHandle {
                    file_type: FileType::Normal(duplicate_normal_handle(mgr, &normal)?),
                },
                other => FileHandle { file_type: other },
            };

            {
                let process = mgr.get_process_mut(pid).ok_or(Error::NotFound)?;
                process.fds.insert(new_fd, cloned);
                if let Some(path) = process.fd_paths.get(&fd).cloned() {
                    process.fd_paths.insert(new_fd, path);
                }

                let new_cloexec = cmd == F_DUPFD_CLOEXEC;
                process.fd_cloexec.insert(new_fd, new_cloexec);
                if process.next_fd <= new_fd {
                    process.next_fd = new_fd.saturating_add(1);
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

    let cloned = match cloned.file_type {
        FileType::Normal(normal) => {
            FileHandle { file_type: FileType::Normal(duplicate_normal_handle(mgr, &normal)?) }
        }
    };

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
            FileType::Normal(normal) => match normal.backend {
                NormalHandleBackend::Fs => normal.fs_client.getdents(Badge::null(), count)?,
            },
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
    if pipe_id == 0 {
        return Err(Error::NotFound);
    }
    let cloexec = (flags & O_CLOEXEC) != 0;
    let (read_client, read_ep_slot) =
        open_pipe_end_via_pipefs(mgr, pipe_id, "r", glenda::protocol::fs::OpenFlags::O_RDONLY)?;
    let (write_client, write_ep_slot) = match open_pipe_end_via_pipefs(
        mgr,
        pipe_id,
        "w",
        glenda::protocol::fs::OpenFlags::O_WRONLY,
    ) {
        Ok(v) => v,
        Err(e) => {
            let mut rc = read_client;
            let _ = rc.close(Badge::null());
            let _ = CSPACE_CAP.delete(read_ep_slot);
            mgr.cspace_mgr.free(read_ep_slot);
            return Err(e);
        }
    };

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
            FileHandle {
                file_type: FileType::Normal(NormalFileHandle {
                    backend: NormalHandleBackend::Fs,
                    fs_client: read_client,
                    fs_ep_slot: read_ep_slot,
                    offset: 0,
                    async_io: None,
                }),
            },
        );
        process.fds.insert(
            write_fd,
            FileHandle {
                file_type: FileType::Normal(NormalFileHandle {
                    backend: NormalHandleBackend::Fs,
                    fs_client: write_client,
                    fs_ep_slot: write_ep_slot,
                    offset: 0,
                    async_io: None,
                }),
            },
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
        let (read_handle, write_handle) = {
            let process = mgr.get_process_mut(pid).ok_or(Error::NotFound)?;
            let read_handle = process.fds.remove(&read_fd);
            let write_handle = process.fds.remove(&write_fd);
            process.fd_cloexec.remove(&read_fd);
            process.fd_cloexec.remove(&write_fd);
            (read_handle, write_handle)
        };

        if let Some(FileHandle { file_type: FileType::Normal(mut n) }) = read_handle {
            let _ = n.fs_client.close(Badge::null());
            let _ = CSPACE_CAP.delete(n.fs_ep_slot);
            mgr.cspace_mgr.free(n.fs_ep_slot);
        }
        if let Some(FileHandle { file_type: FileType::Normal(mut n) }) = write_handle {
            let _ = n.fs_client.close(Badge::null());
            let _ = CSPACE_CAP.delete(n.fs_ep_slot);
            mgr.cspace_mgr.free(n.fs_ep_slot);
        }
        return Err(e);
    }

    mgr.ledger_record_fd_open(pid);
    mgr.ledger_record_fd_open(pid);
    Ok(0)
}
