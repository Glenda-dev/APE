use crate::ApeManager;
use crate::ape::process::{AsyncIoState, FileHandle, FileType, NormalFileHandle};
use crate::ape::user::USER_PATH_MAX;
use alloc::vec;
use core::cmp::min;
use core::mem::size_of;
use glenda::cap::{CSPACE_CAP, Endpoint, Frame, Rights};
use glenda::client::FsClient;
use glenda::error::Error;
use glenda::interface::{CSpaceService, FileHandleService, FileSystemService};
use glenda::io::uring::{
    IOURING_OP_READ, IOURING_OP_WRITE, IoUringBuffer, IoUringClient, IoUringSqe,
};
use glenda::ipc::IPC_BUFFER_SIZE;
use glenda::ipc::{Badge, MsgFlags, MsgTag, UTCB};
use linux_raw_sys::general::{SEEK_CUR, SEEK_END, SEEK_SET};

// 4KB ring + 12KB data window，降低每 fd 的常驻内存。
const FS_ASYNC_REGION_SIZE: usize = 16 * 1024;
const FS_ASYNC_RING_SIZE: usize = 4096;
const FS_ASYNC_DATA_OFFSET: usize = FS_ASYNC_RING_SIZE;
const FS_ASYNC_SQ_ENTRIES: u32 = 16;
const FS_ASYNC_CQ_ENTRIES: u32 = 16;

fn is_tty_like_path(path: &str) -> bool {
    debug!("checking tty-like path: {}", path);
    if path.starts_with("/dev/tty") {
        return true;
    }
    matches!(path, "/dev/console" | "/dev/stdin" | "/dev/stdout" | "/dev/stderr")
}

#[repr(C)]
#[derive(Clone, Copy, Default)]
struct UserIovec {
    iov_base: usize,
    iov_len: usize,
}

fn with_fd_handle_mut<'a, T, F>(
    mgr: &mut ApeManager<'a>,
    pid: usize,
    fd: usize,
    f: F,
) -> Result<T, Error>
where
    F: FnOnce(&mut ApeManager<'a>, &mut FileHandle) -> Result<T, Error>,
{
    let fd = u32::try_from(fd).map_err(|_| Error::InvalidSlot)?;
    let mut handle = {
        let process = mgr.get_process_mut(pid).ok_or(Error::NotFound)?;
        process.fds.remove(&fd).ok_or(Error::InvalidSlot)?
    };

    let result = f(mgr, &mut handle);

    let process = mgr.get_process_mut(pid).ok_or(Error::NotFound)?;
    process.fds.insert(fd, handle);
    result
}

fn sys_rw_vector<'a, F>(
    mgr: &mut ApeManager<'a>,
    pid: usize,
    fd: usize,
    iov_ptr: usize,
    iov_cnt: usize,
    rw: F,
) -> Result<isize, Error>
where
    F: Fn(&mut ApeManager<'a>, usize, usize, usize, usize) -> Result<isize, Error>,
{
    if iov_cnt == 0 {
        return Ok(0);
    }
    if iov_cnt > 1024 {
        return Err(Error::InvalidArgs);
    }

    let mut total = 0usize;
    for i in 0..iov_cnt {
        let iov_addr = iov_ptr
            .checked_add(i.checked_mul(size_of::<UserIovec>()).ok_or(Error::InvalidAddress)?)
            .ok_or(Error::InvalidAddress)?;

        let mut raw = [0u8; size_of::<UserIovec>()];
        mgr.copy_from_user(pid, iov_addr, &mut raw)?;
        let iov = unsafe { (raw.as_ptr() as *const UserIovec).read_unaligned() };

        if iov.iov_len == 0 {
            continue;
        }

        let n = rw(mgr, pid, fd, iov.iov_base, iov.iov_len)?;
        if n < 0 {
            return Ok(n);
        }

        let n = n as usize;
        total = total.saturating_add(n);
        if n < iov.iov_len {
            break;
        }
    }

    Ok(total as isize)
}

fn async_submit_and_wait(
    fs_client: &mut FsClient,
    ring: &mut IoUringClient,
    next_user_data: &mut usize,
    off: usize,
    data_vaddr: usize,
    opcode: u8,
    requested_len: usize,
) -> Result<usize, Error> {
    let user_data = *next_user_data;
    *next_user_data = (*next_user_data).wrapping_add(1);

    let sqe = IoUringSqe {
        opcode,
        off,
        addr: data_vaddr,
        len: requested_len as u32,
        user_data,
        ..Default::default()
    };
    ring.submit(sqe)?;

    // 当前 FS io_uring 服务端主要是“process_iouring 驱动型”，这里保持小步驱动，
    // 避免过去 16 次盲轮询带来的额外 IPC 开销。
    for _ in 0..2 {
        fs_client.process_iouring()?;
        while let Some(cqe) = ring.pop_completion() {
            if cqe.user_data != user_data {
                continue;
            }
            if cqe.res < 0 {
                return Err(Error::IoError);
            }
            return Ok(min(cqe.res as usize, requested_len));
        }
    }

    Err(Error::WouldBlock)
}

pub fn sys_read<'a>(
    mgr: &mut ApeManager<'a>,
    pid: usize,
    fd: usize,
    buf_ptr: usize,
    len: usize,
) -> Result<isize, Error> {
    if len == 0 {
        return Ok(0);
    }
    with_fd_handle_mut(mgr, pid, fd, |mgr, handle| match &mut handle.file_type {
        FileType::Terminal(term) => {
            let mut utcb = unsafe { UTCB::new() };
            let tag = MsgTag::new(
                glenda::protocol::TERMINAL_PROTO,
                glenda::protocol::terminal::TERM_GET_STR,
                MsgFlags::HAS_BUFFER,
            );
            utcb.set_mr(0, len);
            utcb.set_msg_tag(tag);
            term.endpoint().call(utcb)?;
            utcb.error_check()?;

            let read_len = min(utcb.get_mr(0), min(len, utcb.buffer().len()));
            if read_len > 0 {
                mgr.copy_to_user(pid, buf_ptr, &utcb.buffer()[..read_len])?;
            }
            Ok(read_len as isize)
        }
        FileType::Normal(normal) => {
            if let Some(async_io) = normal.async_io.as_mut() {
                let fs_client = &mut normal.fs_client;
                let ring = &mut async_io.ring;
                let data_vaddr = async_io.data_vaddr;
                let data_len = async_io.data_len;
                let next_user_data = &mut async_io.next_user_data;
                let mut file_off = normal.offset;

                let total = mgr.with_user_session(pid, |sess| {
                    let mut total = 0usize;
                    while total < len {
                        let chunk = min(len - total, data_len);
                        if chunk == 0 {
                            break;
                        }

                        let read_len = async_submit_and_wait(
                            fs_client,
                            ring,
                            next_user_data,
                            file_off,
                            data_vaddr,
                            IOURING_OP_READ,
                            chunk,
                        )?;
                        if read_len == 0 {
                            break;
                        }

                        let src = unsafe {
                            core::slice::from_raw_parts(data_vaddr as *const u8, read_len)
                        };
                        let user_dst = buf_ptr.checked_add(total).ok_or(Error::InvalidAddress)?;
                        sess.copy_to_user(user_dst, src)?;

                        total += read_len;
                        file_off = file_off.saturating_add(read_len);

                        if read_len < chunk {
                            break;
                        }
                    }
                    Ok(total)
                })?;
                normal.offset = file_off;
                Ok(total as isize)
            } else {
                // 后端不支持 io_uring 时的同步回退路径。
                let total = mgr.with_user_session(pid, |sess| {
                    let mut total = 0usize;
                    let mut kbuf = [0u8; IPC_BUFFER_SIZE];
                    while total < len {
                        let chunk = min(len - total, kbuf.len());
                        if chunk == 0 {
                            break;
                        }

                        let read_len = normal.fs_client.read(
                            Badge::null(),
                            normal.offset,
                            &mut kbuf[..chunk],
                        )?;
                        if read_len == 0 {
                            break;
                        }

                        let user_dst = buf_ptr.checked_add(total).ok_or(Error::InvalidAddress)?;
                        sess.copy_to_user(user_dst, &kbuf[..read_len])?;

                        total += read_len;
                        normal.offset = normal.offset.saturating_add(read_len);
                        if read_len < chunk {
                            break;
                        }
                    }
                    Ok(total)
                })?;
                Ok(total as isize)
            }
        }
    })
}

pub fn sys_write<'a>(
    mgr: &mut ApeManager<'a>,
    pid: usize,
    fd: usize,
    buf_ptr: usize,
    len: usize,
) -> Result<isize, Error> {
    if len == 0 {
        return Ok(0);
    }
    with_fd_handle_mut(mgr, pid, fd, |mgr, handle| match &mut handle.file_type {
        FileType::Terminal(term) => {
            let mut kbuf = vec![0u8; len];
            mgr.copy_from_user(pid, buf_ptr, &mut kbuf)?;

            let mut utcb = unsafe { UTCB::new() };
            let tag = MsgTag::new(
                glenda::protocol::TERMINAL_PROTO,
                glenda::protocol::terminal::TERM_PUT_STR,
                MsgFlags::HAS_BUFFER,
            );
            let copied = utcb.write(&kbuf);
            utcb.set_msg_tag(tag);
            term.endpoint().call(utcb)?;
            utcb.error_check()?;

            let written = if utcb.get_mr(0) > 0 { min(utcb.get_mr(0), copied) } else { copied };
            Ok(written as isize)
        }
        FileType::Normal(normal) => {
            if let Some(async_io) = normal.async_io.as_mut() {
                let fs_client = &mut normal.fs_client;
                let ring = &mut async_io.ring;
                let data_vaddr = async_io.data_vaddr;
                let data_len = async_io.data_len;
                let next_user_data = &mut async_io.next_user_data;
                let mut file_off = normal.offset;

                let total = mgr.with_user_session(pid, |sess| {
                    let mut total = 0usize;
                    while total < len {
                        let chunk = min(len - total, data_len);
                        if chunk == 0 {
                            break;
                        }

                        let dst = unsafe {
                            core::slice::from_raw_parts_mut(data_vaddr as *mut u8, data_len)
                        };
                        let user_src = buf_ptr.checked_add(total).ok_or(Error::InvalidAddress)?;
                        sess.copy_from_user(user_src, &mut dst[..chunk])?;

                        let written = async_submit_and_wait(
                            fs_client,
                            ring,
                            next_user_data,
                            file_off,
                            data_vaddr,
                            IOURING_OP_WRITE,
                            chunk,
                        )?;
                        total += written;
                        file_off = file_off.saturating_add(written);

                        if written < chunk {
                            break;
                        }
                    }
                    Ok(total)
                })?;
                normal.offset = file_off;
                Ok(total as isize)
            } else {
                // 后端不支持 io_uring 时的同步回退路径。
                let total = mgr.with_user_session(pid, |sess| {
                    let mut total = 0usize;
                    let mut kbuf = [0u8; IPC_BUFFER_SIZE];
                    while total < len {
                        let chunk = min(len - total, kbuf.len());
                        if chunk == 0 {
                            break;
                        }

                        let user_src = buf_ptr.checked_add(total).ok_or(Error::InvalidAddress)?;
                        sess.copy_from_user(user_src, &mut kbuf[..chunk])?;

                        let written =
                            normal.fs_client.write(Badge::null(), normal.offset, &kbuf[..chunk])?;
                        total += written;
                        normal.offset = normal.offset.saturating_add(written);
                        if written < chunk {
                            break;
                        }
                    }
                    Ok(total)
                })?;
                Ok(total as isize)
            }
        }
    })
}

pub fn sys_openat<'a>(
    mgr: &mut ApeManager<'a>,
    pid: usize,
    _dirfd: usize,
    pathname: usize,
    flags: usize,
    mode: usize,
) -> Result<isize, Error> {
    let path = mgr.strncpy_from_user(pid, pathname, USER_PATH_MAX)?;
    let translated_path = mgr.resolve_path_for_process(pid, &path)?;

    if is_tty_like_path(&path) || is_tty_like_path(&translated_path) {
        let term = mgr.stdio_term.ok_or(Error::NotFound)?;
        let process = mgr.get_process_mut(pid).ok_or(Error::NotFound)?;
        let fd = process.next_fd;
        process.next_fd += 1;
        process.fds.insert(fd, FileHandle { file_type: FileType::Terminal(term) });
        return Ok(fd as isize);
    }

    let fs_badge = mgr.take_next_fs_handle_badge();
    let fs_ep_slot = mgr.cspace_mgr.alloc(&mut *mgr.res_client)?;
    CSPACE_CAP.mint_self(
        mgr.fs_client.endpoint().cap(),
        fs_ep_slot,
        glenda::ipc::Badge::new(fs_badge),
        Rights::ALL,
    )?;

    let mut fs_client = FsClient::new(Endpoint::from(fs_ep_slot));
    let open_flags = glenda::protocol::fs::OpenFlags::from_bits_truncate(flags);
    if let Err(e) = fs_client.open(Badge::null(), &translated_path, open_flags, mode as u32) {
        let _ = CSPACE_CAP.delete(fs_ep_slot);
        mgr.cspace_mgr.free(fs_ep_slot);
        return Err(e);
    }

    let mut async_io = None;
    if let Ok(region) = mgr.allocate_fs_async_region(FS_ASYNC_REGION_SIZE) {
        let ring_buf = unsafe {
            IoUringBuffer::new(
                region.vaddr as *mut u8,
                FS_ASYNC_RING_SIZE,
                FS_ASYNC_SQ_ENTRIES,
                FS_ASYNC_CQ_ENTRIES,
            )
        };
        let mut ring = IoUringClient::new(ring_buf);
        ring.set_server_notify(Endpoint::from(fs_ep_slot));

        match fs_client.setup_iouring(
            Badge::null(),
            region.vaddr,
            region.size,
            Some(Frame::from(region.frame_slot)),
        ) {
            Ok(()) => {
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
                // extfs/fatfs 尚未支持 io_uring，回退到同步路径。
                mgr.recycle_fs_async_region(region.id);
            }
            Err(e) => {
                let _ = fs_client.close(Badge::null());
                let _ = CSPACE_CAP.delete(fs_ep_slot);
                mgr.cspace_mgr.free(fs_ep_slot);
                mgr.recycle_fs_async_region(region.id);
                return Err(e);
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

    Ok(fd as isize)
}

pub fn sys_close<'a>(mgr: &mut ApeManager<'a>, pid: usize, fd: usize) -> Result<isize, Error> {
    let fd = u32::try_from(fd).map_err(|_| Error::InvalidSlot)?;
    let handle = {
        let process = mgr.get_process_mut(pid).ok_or(Error::NotFound)?;
        process.fds.remove(&fd).ok_or(Error::InvalidSlot)?
    };
    match handle.file_type {
        FileType::Terminal(_) => {}
        FileType::Normal(mut normal) => {
            let _ = normal.fs_client.close(Badge::null());
            let _ = CSPACE_CAP.delete(normal.fs_ep_slot);
            mgr.cspace_mgr.free(normal.fs_ep_slot);
            if let Some(async_io) = normal.async_io {
                mgr.recycle_fs_async_region(async_io.region_id);
            }
        }
    }

    Ok(0)
}

pub fn sys_lseek<'a>(
    mgr: &mut ApeManager<'a>,
    pid: usize,
    fd: usize,
    offset: isize,
    whence: usize,
) -> Result<isize, Error> {
    with_fd_handle_mut(mgr, pid, fd, |_mgr, handle| match &mut handle.file_type {
        FileType::Terminal(_) => Err(Error::InvalidArgs),
        FileType::Normal(normal) => {
            let base: isize = match whence as u32 {
                SEEK_SET => 0,
                SEEK_CUR => normal.offset as isize,
                SEEK_END => {
                    let stat = normal.fs_client.stat(Badge::null())?;
                    stat.size as isize
                }
                _ => return Err(Error::InvalidArgs),
            };

            let new_off = base.checked_add(offset).ok_or(Error::InvalidArgs)?;
            if new_off < 0 {
                return Err(Error::InvalidArgs);
            }

            normal.offset = new_off as usize;
            Ok(new_off)
        }
    })
}

pub fn sys_readv<'a>(
    mgr: &mut ApeManager<'a>,
    pid: usize,
    fd: usize,
    iov_ptr: usize,
    iov_cnt: usize,
) -> Result<isize, Error> {
    sys_rw_vector(mgr, pid, fd, iov_ptr, iov_cnt, sys_read)
}

pub fn sys_writev<'a>(
    mgr: &mut ApeManager<'a>,
    pid: usize,
    fd: usize,
    iov_ptr: usize,
    iov_cnt: usize,
) -> Result<isize, Error> {
    sys_rw_vector(mgr, pid, fd, iov_ptr, iov_cnt, sys_write)
}

pub fn sys_ioctl<'a>(
    mgr: &mut ApeManager<'a>,
    pid: usize,
    fd: usize,
    request: usize,
    argp: usize,
) -> Result<isize, Error> {
    let fd = u32::try_from(fd).map_err(|_| Error::InvalidSlot)?;
    let process = mgr.get_process(pid).ok_or(Error::NotFound)?;
    let handle = process.fds.get(&fd).ok_or(Error::InvalidSlot)?;

    match handle.file_type {
        FileType::Terminal(term) => {
            let mut utcb = unsafe { UTCB::new() };
            utcb.clear();
            utcb.set_msg_tag(MsgTag::new(
                glenda::protocol::TERMINAL_PROTO,
                glenda::protocol::terminal::TERM_IOCTL,
                MsgFlags::NONE,
            ));
            utcb.set_mr(0, request);
            utcb.set_mr(1, argp);
            term.endpoint().call(utcb)?;
            Ok(utcb.get_mr(0) as isize)
        }
        FileType::Normal(_) => Ok(0),
    }
}
