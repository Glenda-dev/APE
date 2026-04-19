use crate::ApeManager;
use crate::ape::process::{FileHandle, FileType, PseudoCharDevice};
use alloc::vec;
use core::cmp::min;
use core::mem::size_of;
use glenda::client::FsClient;
use glenda::error::Error;
use glenda::interface::{FileHandleService, FileSystemService, VirtualTerminalService};
use glenda::io::uring::{IOURING_OP_READ, IOURING_OP_WRITE, IoUringClient, IoUringSqe};
use glenda::ipc::Badge;
use glenda::ipc::IPC_BUFFER_SIZE;
use linux_raw_sys::ctypes::c_uint;
use linux_raw_sys::errno::{EAGAIN, EBADF, EPIPE};
use linux_raw_sys::general::{SEEK_CUR, SEEK_END, SEEK_SET, iovec};

pub(crate) fn do_read<'a>(
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
        FileType::PtyMaster(master) => {
            crate::io::tty::do_read_terminal(mgr, pid, master.term, buf_ptr, len)
        }
        FileType::PtySlave(slave) => {
            crate::io::tty::do_read_terminal(mgr, pid, slave.term, buf_ptr, len)
        }
        FileType::PseudoChar(dev) => match dev {
            PseudoCharDevice::Null => Ok(0),
            PseudoCharDevice::Zero | PseudoCharDevice::Random | PseudoCharDevice::URandom => {
                mgr.write_zeros_to_user(pid, buf_ptr, len)?;
                Ok(len as isize)
            }
        },
        FileType::PipeRead(pipe) => {
            let chunk = min(len, IPC_BUFFER_SIZE);
            let mut tmp = vec![0u8; chunk];
            let (n, writers_closed) =
                mgr.pipe_read(pipe.pipe_id, &mut tmp).ok_or(Error::InvalidSlot)?;
            if n == 0 {
                if writers_closed {
                    return Ok(0);
                }
                return Ok(-(EAGAIN as isize));
            }
            mgr.copy_to_user(pid, buf_ptr, &tmp[..n])?;
            Ok(n as isize)
        }
        FileType::PipeWrite(_) => Ok(-(EBADF as isize)),
        FileType::Terminal(term) => crate::io::tty::do_read_terminal(mgr, pid, *term, buf_ptr, len),
        FileType::Normal(normal) => {
            if normal.async_io.is_none() {
                let _ = mgr.try_enable_fs_async_io(pid, normal);
            }
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

                        let user_dst = buf_ptr.checked_add(total).ok_or(Error::InvalidAddress)?;
                        sess.copy_to_user_from_ptr(user_dst, data_vaddr as *const u8, read_len)?;

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

pub(crate) fn do_write<'a>(
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
        FileType::PtyMaster(master) => {
            crate::io::tty::do_write_terminal(mgr, pid, master.term, buf_ptr, len)
        }
        FileType::PtySlave(slave) => {
            crate::io::tty::do_write_terminal(mgr, pid, slave.term, buf_ptr, len)
        }
        FileType::PseudoChar(_) => Ok(len as isize),
        FileType::PipeRead(_) => Ok(-(EBADF as isize)),
        FileType::PipeWrite(pipe) => {
            let chunk = min(len, IPC_BUFFER_SIZE);
            let mut tmp = vec![0u8; chunk];
            mgr.copy_from_user(pid, buf_ptr, &mut tmp)?;
            let (n, no_readers) = mgr.pipe_write(pipe.pipe_id, &tmp).ok_or(Error::InvalidSlot)?;
            if no_readers {
                return Ok(-(EPIPE as isize));
            }
            if n == 0 {
                return Ok(-(EAGAIN as isize));
            }
            Ok(n as isize)
        }
        FileType::Terminal(term) => {
            crate::io::tty::do_write_terminal(mgr, pid, *term, buf_ptr, len)
        }
        FileType::Normal(normal) => {
            if normal.async_io.is_none() {
                let _ = mgr.try_enable_fs_async_io(pid, normal);
            }
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

                        let user_src = buf_ptr.checked_add(total).ok_or(Error::InvalidAddress)?;
                        sess.copy_from_user_to_ptr(user_src, data_vaddr as *mut u8, chunk)?;

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

pub(crate) fn do_readv<'a>(
    mgr: &mut ApeManager<'a>,
    pid: usize,
    fd: usize,
    iov_ptr: usize,
    iov_cnt: usize,
) -> Result<isize, Error> {
    sys_rw_vector(mgr, pid, fd, iov_ptr, iov_cnt, do_read)
}

pub(crate) fn do_writev<'a>(
    mgr: &mut ApeManager<'a>,
    pid: usize,
    fd: usize,
    iov_ptr: usize,
    iov_cnt: usize,
) -> Result<isize, Error> {
    sys_rw_vector(mgr, pid, fd, iov_ptr, iov_cnt, do_write)
}

pub(crate) fn do_lseek<'a>(
    mgr: &mut ApeManager<'a>,
    pid: usize,
    fd: usize,
    offset: isize,
    whence: usize,
) -> Result<isize, Error> {
    with_fd_handle_mut(mgr, pid, fd, |_mgr, handle| match &mut handle.file_type {
        FileType::PtyMaster(_) | FileType::PtySlave(_) => Err(Error::InvalidArgs),
        FileType::PseudoChar(_) => Ok(0),
        FileType::PipeRead(_) | FileType::PipeWrite(_) => Err(Error::InvalidArgs),
        FileType::Terminal(_) => Err(Error::InvalidArgs),
        FileType::Normal(normal) => {
            let base: isize = match whence as u32 {
                SEEK_SET => 0,
                SEEK_CUR => normal.offset as isize,
                SEEK_END => {
                    let st = normal.fs_client.stat(Badge::null())?;
                    st.size as isize
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

pub(crate) fn do_ioctl<'a>(
    mgr: &mut ApeManager<'a>,
    pid: usize,
    fd: usize,
    request: usize,
    argp: usize,
) -> Result<isize, Error> {
    let req = u32::try_from(request).map_err(|_| Error::InvalidArgs)?;

    with_fd_handle_mut(mgr, pid, fd, |mgr, handle| match &mut handle.file_type {
        FileType::PtyMaster(master) => crate::io::tty::do_ioctl_pty_master(
            mgr,
            pid,
            master.vt_id,
            &mut master.locked,
            master.term,
            req,
            argp,
        ),
        FileType::PtySlave(slave) => {
            crate::io::tty::do_ioctl_terminal(mgr, pid, slave.term, req, argp)
        }
        FileType::PipeRead(_) | FileType::PipeWrite(_) => Err(Error::InvalidType),
        FileType::PseudoChar(_) => Err(Error::InvalidType),
        FileType::Terminal(term) => crate::io::tty::do_ioctl_terminal(mgr, pid, *term, req, argp),
        FileType::Normal(_) => Err(Error::InvalidType),
    })
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
            .checked_add(i.checked_mul(size_of::<iovec>()).ok_or(Error::InvalidAddress)?)
            .ok_or(Error::InvalidAddress)?;

        let mut raw = [0u8; size_of::<iovec>()];
        mgr.copy_from_user(pid, iov_addr, &mut raw)?;
        let iov = unsafe { (raw.as_ptr() as *const iovec).read_unaligned() };

        let iov_len = usize::try_from(iov.iov_len).map_err(|_| Error::InvalidArgs)?;
        if iov_len == 0 {
            continue;
        }

        let iov_base = iov.iov_base as usize;
        let n = rw(mgr, pid, fd, iov_base, iov_len)?;
        if n < 0 {
            return Ok(n);
        }

        let n = n as usize;
        total = total.saturating_add(n);
        if n < iov_len {
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
        len: requested_len as c_uint,
        user_data,
        ..Default::default()
    };
    ring.submit(sqe)?;

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
