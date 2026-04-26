use crate::ApeManager;
use crate::ape::files::{
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
    handle: &NormalFileHandle,
) -> Result<NormalFileHandle, Error> {
    Ok(NormalFileHandle {
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
    let pipe_ep = mgr.subsystems.fs.lock().pipe_vfs_endpoint().ok_or(Error::NotFound)?;
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
                    mgr.recycle_fs_async_region(region.id);
                }
                Err(_) => {
                    mgr.recycle_fs_async_region(region.id);
                }
            }
        }
    }

    let fd = {
        let task = mgr.get_process(pid).ok_or(Error::NotFound)?;
        let mut files = task.files.state.write();
        let fd = files.next_fd;
        files.next_fd += 1;
        files.fds.insert(
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
        files.fd_paths.insert(fd, path.into());
        fd
    };
    mgr.ledger_record_fd_open(pid);

    Ok(fd as isize)
}

pub(crate) fn do_openat<'a>(
    mgr: &mut ApeManager<'a>,
    pid: usize,
    _dirfd: usize,
    pathname: usize,
    flags: usize,
    mode: usize,
) -> Result<isize, Error> {
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
        let task = mgr.get_process(pid).ok_or(Error::NotFound)?;
        let mut files = task.files.state.write();
        files.fd_paths.remove(&fd);
        files.fd_cloexec.remove(&fd);
        files.fds.remove(&fd).ok_or(Error::InvalidSlot)?
    };

    match handle.file_type {
        FileType::Normal(normal) => {
            let fs_client = normal.fs_client;
            let fs_ep_slot = normal.fs_ep_slot;
            let async_io = normal.async_io;
            let mut still_shared = false;
            for other_pid in mgr.local_pids() {
                let Some(task_ref) = mgr.get_process(other_pid) else {
                    continue;
                };
                if task_ref.files.state.read().fds.values().any(|fh| {
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
            let task = mgr.get_process(pid).ok_or(Error::NotFound)?;
            let files = task.files.state.read();
            if !files.fds.contains_key(&fd) {
                return Err(Error::InvalidSlot);
            }
            let cloexec = files.fd_cloexec.get(&fd).copied().unwrap_or(false);
            Ok(if cloexec { FD_CLOEXEC as isize } else { 0 })
        }
        F_SETFD => {
            let task = mgr.get_process(pid).ok_or(Error::NotFound)?;
            let mut files = task.files.state.write();
            if !files.fds.contains_key(&fd) {
                return Err(Error::InvalidSlot);
            }
            let cloexec = (arg & (FD_CLOEXEC as usize)) != 0;
            files.fd_cloexec.insert(fd, cloexec);
            Ok(0)
        }
        F_GETFL => {
            let task = mgr.get_process(pid).ok_or(Error::NotFound)?;
            if !task.files.state.read().fds.contains_key(&fd) {
                return Err(Error::InvalidSlot);
            }
            Ok(0)
        }
        F_SETFL => {
            let task = mgr.get_process(pid).ok_or(Error::NotFound)?;
            if !task.files.state.read().fds.contains_key(&fd) {
                return Err(Error::InvalidSlot);
            }
            Ok(0)
        }
        F_DUPFD | F_DUPFD_CLOEXEC => {
            let (new_fd, cloned) = {
                let task = mgr.get_process(pid).ok_or(Error::NotFound)?;
                let mut files = task.files.state.write();
                if !files.fds.contains_key(&fd) {
                    return Err(Error::InvalidSlot);
                }

                let min_fd = u32::try_from(arg).map_err(|_| Error::InvalidArgs)?;
                let mut new_fd = min_fd;
                while files.fds.contains_key(&new_fd) {
                    new_fd = new_fd.checked_add(1).ok_or(Error::OutOfMemory)?;
                }

                let cloned = files.fds.get(&fd).cloned().ok_or(Error::InvalidSlot)?;
                (new_fd, cloned)
            };

            let cloned = match cloned.file_type {
                FileType::Normal(normal) => FileHandle {
                    file_type: FileType::Normal(duplicate_normal_handle(mgr, &normal)?),
                },
            };

            {
                let task = mgr.get_process(pid).ok_or(Error::NotFound)?;
                let mut files = task.files.state.write();
                files.fds.insert(new_fd, cloned);
                if let Some(path) = files.fd_paths.get(&fd).cloned() {
                    files.fd_paths.insert(new_fd, path);
                }

                let new_cloexec = cmd == F_DUPFD_CLOEXEC;
                files.fd_cloexec.insert(new_fd, new_cloexec);
                if files.next_fd <= new_fd {
                    files.next_fd = new_fd.saturating_add(1);
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
        let task = mgr.get_process(pid).ok_or(Error::NotFound)?;
        let files = task.files.state.read();
        (
            files.fds.get(&oldfd).cloned().ok_or(Error::InvalidSlot)?,
            files.fd_paths.get(&oldfd).cloned(),
        )
    };

    let need_close_target = {
        let task = mgr.get_process(pid).ok_or(Error::NotFound)?;
        task.files.state.read().fds.contains_key(&newfd)
    };
    if need_close_target {
        do_close(mgr, pid, newfd as usize)?;
    }

    let cloned = match cloned.file_type {
        FileType::Normal(normal) => {
            FileHandle { file_type: FileType::Normal(duplicate_normal_handle(mgr, &normal)?) }
        }
    };

    let task = mgr.get_process(pid).ok_or(Error::NotFound)?;
    let mut files = task.files.state.write();
    files.fds.insert(newfd, cloned);
    if let Some(path) = path_clone {
        files.fd_paths.insert(newfd, path);
    }
    files.fd_cloexec.insert(newfd, (flags & (O_CLOEXEC as usize)) != 0);
    if files.next_fd <= newfd {
        files.next_fd = newfd.saturating_add(1);
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
        let task = mgr.get_process(pid).ok_or(Error::NotFound)?;
        task.files.state.write().fds.remove(&fd).ok_or(Error::InvalidSlot)?
    };

    let result = (|| {
        let entries = match &mut handle.file_type {
            FileType::Normal(normal) => match normal.backend {
                NormalHandleBackend::Fs => normal.fs_client.getdents(Badge::null(), count)?,
            },
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

    let task = mgr.get_process(pid).ok_or(Error::NotFound)?;
    task.files.state.write().fds.insert(fd, handle);
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
        let task = mgr.get_process(pid).ok_or(Error::NotFound)?;
        let mut files = task.files.state.write();

        let mut read_fd = files.next_fd;
        while files.fds.contains_key(&read_fd) {
            read_fd = read_fd.checked_add(1).ok_or(Error::OutOfMemory)?;
        }

        let mut write_fd = read_fd.checked_add(1).ok_or(Error::OutOfMemory)?;
        while files.fds.contains_key(&write_fd) {
            write_fd = write_fd.checked_add(1).ok_or(Error::OutOfMemory)?;
        }

        files.fds.insert(
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
        files.fds.insert(
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
        files.fd_cloexec.insert(read_fd, cloexec);
        files.fd_cloexec.insert(write_fd, cloexec);
        files.next_fd = write_fd.saturating_add(1);

        (read_fd, write_fd)
    };

    let read_i32 = i32::try_from(read_fd).map_err(|_| Error::OutOfMemory)?;
    let write_i32 = i32::try_from(write_fd).map_err(|_| Error::OutOfMemory)?;
    let mut out = [0u8; 8];
    out[..4].copy_from_slice(&read_i32.to_ne_bytes());
    out[4..].copy_from_slice(&write_i32.to_ne_bytes());

    if let Err(e) = mgr.copy_to_user(pid, pipefd, &out) {
        let task = mgr.get_process(pid).ok_or(Error::NotFound)?;
        let mut files = task.files.state.write();
        let read_handle = files.fds.remove(&read_fd);
        let write_handle = files.fds.remove(&write_fd);
        files.fd_cloexec.remove(&read_fd);
        files.fd_cloexec.remove(&write_fd);

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
