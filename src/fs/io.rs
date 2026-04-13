use crate::ApeManager;
use crate::ape::process::{FileHandle, FileType, PseudoCharDevice};
use crate::ape::utils::linux_conv::{
    host_window_size_to_linux_winsize, linux_winsize_to_host_window_size,
};
use alloc::vec;
use core::cmp::min;
use core::mem::size_of;
use glenda::client::{FsClient, TerminalClient};
use glenda::error::Error;
use glenda::interface::{FileHandleService, FileSystemService, VirtualTerminalService};
use glenda::io::uring::{IOURING_OP_READ, IOURING_OP_WRITE, IoUringClient, IoUringSqe};
use glenda::ipc::IPC_BUFFER_SIZE;
use glenda::ipc::{Badge, MsgFlags, MsgTag, UTCB};
use linux_raw_sys::ctypes::{c_int, c_uint};
use linux_raw_sys::general::{SEEK_CUR, SEEK_END, SEEK_SET, iovec, winsize};
use linux_raw_sys::ioctl::{
    TCGETS, TCSETS, TCSETSF, TCSETSW, TIOCGPGRP, TIOCGPTN, TIOCGWINSZ, TIOCSPGRP, TIOCSPTLCK,
    TIOCSWINSZ,
};

const TTY_TERMIOS_SIZE: usize = 44;

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
        FileType::PtyMaster(master) => read_from_terminal(mgr, pid, master.term, buf_ptr, len),
        FileType::PtySlave(slave) => read_from_terminal(mgr, pid, slave.term, buf_ptr, len),
        FileType::PseudoChar(dev) => match dev {
            PseudoCharDevice::Null => Ok(0),
            PseudoCharDevice::Zero | PseudoCharDevice::Random | PseudoCharDevice::URandom => {
                mgr.write_zeros_to_user(pid, buf_ptr, len)?;
                Ok(len as isize)
            }
        },
        FileType::Terminal(term) => read_from_terminal(mgr, pid, *term, buf_ptr, len),
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
                let total = mgr.with_user_session(pid, |sess| {
                    let mut total = 0usize;
                    let mut kbuf = [0u8; IPC_BUFFER_SIZE];
                    while total < len {
                        let chunk = min(len - total, kbuf.len());
                        if chunk == 0 {
                            break;
                        }

                        let read_len = normal
                            .fs_client
                            .read(Badge::null(), normal.offset, &mut kbuf[..chunk])?;
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
        FileType::PtyMaster(master) => write_to_terminal(mgr, pid, master.term, buf_ptr, len),
        FileType::PtySlave(slave) => write_to_terminal(mgr, pid, slave.term, buf_ptr, len),
        FileType::PseudoChar(_) => Ok(len as isize),
        FileType::Terminal(term) => write_to_terminal(mgr, pid, *term, buf_ptr, len),
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

                        let written = normal
                            .fs_client
                            .write(Badge::null(), normal.offset, &kbuf[..chunk])?;
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
        FileType::PtyMaster(master) => match req {
            TIOCGPTN => {
                write_user_u32(mgr, pid, argp, master.vt_id as u32)?;
                Ok(0)
            }
            TIOCSPTLCK => {
                let lock = read_user_u32(mgr, pid, argp)?;
                mgr.vt_client.set_pty_lock(Badge::null(), master.vt_id, lock != 0)?;
                master.locked = lock != 0;
                Ok(0)
            }
            _ => ioctl_to_terminal(mgr, pid, master.term, req, argp),
        },
        FileType::PtySlave(slave) => ioctl_to_terminal(mgr, pid, slave.term, req, argp),
        FileType::PseudoChar(_) => Err(Error::InvalidType),
        FileType::Terminal(term) => ioctl_to_terminal(mgr, pid, *term, req, argp),
        FileType::Normal(_) => Err(Error::InvalidType),
    })
}

fn read_user_winsize<'a>(
    mgr: &mut ApeManager<'a>,
    pid: usize,
    user_ptr: usize,
) -> Result<winsize, Error> {
    let mut raw = [0u8; size_of::<winsize>()];
    mgr.copy_from_user(pid, user_ptr, &mut raw)?;
    Ok(unsafe { (raw.as_ptr() as *const winsize).read_unaligned() })
}

fn write_user_winsize<'a>(
    mgr: &mut ApeManager<'a>,
    pid: usize,
    user_ptr: usize,
    value: winsize,
) -> Result<(), Error> {
    let raw = unsafe {
        core::slice::from_raw_parts((&value as *const winsize) as *const u8, size_of::<winsize>())
    };
    mgr.copy_to_user(pid, user_ptr, raw)
}

fn read_user_i32<'a>(mgr: &mut ApeManager<'a>, pid: usize, user_ptr: usize) -> Result<i32, Error> {
    let mut raw = [0u8; 4];
    mgr.copy_from_user(pid, user_ptr, &mut raw)?;
    Ok(i32::from_ne_bytes(raw))
}

fn write_user_i32<'a>(
    mgr: &mut ApeManager<'a>,
    pid: usize,
    user_ptr: usize,
    value: i32,
) -> Result<(), Error> {
    mgr.copy_to_user(pid, user_ptr, &value.to_ne_bytes())
}

fn read_user_u32<'a>(mgr: &mut ApeManager<'a>, pid: usize, user_ptr: usize) -> Result<u32, Error> {
    let mut raw = [0u8; 4];
    mgr.copy_from_user(pid, user_ptr, &mut raw)?;
    Ok(u32::from_ne_bytes(raw))
}

fn write_user_u32<'a>(
    mgr: &mut ApeManager<'a>,
    pid: usize,
    user_ptr: usize,
    value: u32,
) -> Result<(), Error> {
    mgr.copy_to_user(pid, user_ptr, &value.to_ne_bytes())
}

fn read_user_bytes<'a>(
    mgr: &mut ApeManager<'a>,
    pid: usize,
    user_ptr: usize,
    len: usize,
) -> Result<vec::Vec<u8>, Error> {
    let mut buf = vec![0u8; len];
    mgr.copy_from_user(pid, user_ptr, &mut buf)?;
    Ok(buf)
}

fn write_user_bytes<'a>(
    mgr: &mut ApeManager<'a>,
    pid: usize,
    user_ptr: usize,
    data: &[u8],
) -> Result<(), Error> {
    if data.is_empty() {
        return Ok(());
    }
    mgr.copy_to_user(pid, user_ptr, data)
}

fn read_from_terminal<'a>(
    mgr: &mut ApeManager<'a>,
    pid: usize,
    term: TerminalClient,
    buf_ptr: usize,
    len: usize,
) -> Result<isize, Error> {
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

fn write_to_terminal<'a>(
    mgr: &mut ApeManager<'a>,
    pid: usize,
    term: TerminalClient,
    buf_ptr: usize,
    len: usize,
) -> Result<isize, Error> {
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

fn ioctl_to_terminal<'a>(
    mgr: &mut ApeManager<'a>,
    pid: usize,
    term: TerminalClient,
    request: u32,
    argp: usize,
) -> Result<isize, Error> {
    match request {
        TIOCGWINSZ => {
            let mut utcb = unsafe { UTCB::new() };
            utcb.clear();
            utcb.set_msg_tag(MsgTag::new(
                glenda::protocol::TERMINAL_PROTO,
                glenda::protocol::terminal::TERM_GET_WINSIZE,
                MsgFlags::NONE,
            ));
            term.endpoint().call(utcb)?;
            let ws = unsafe { utcb.read_postcard()? };
            write_user_winsize(mgr, pid, argp, host_window_size_to_linux_winsize(ws))?;
            Ok(0)
        }
        TIOCSWINSZ => {
            let ws = read_user_winsize(mgr, pid, argp)?;
            let mut utcb = unsafe { UTCB::new() };
            utcb.clear();
            utcb.set_msg_tag(MsgTag::new(
                glenda::protocol::TERMINAL_PROTO,
                glenda::protocol::terminal::TERM_SET_WINSIZE,
                MsgFlags::HAS_BUFFER,
            ));
            unsafe {
                utcb.write_postcard(&linux_winsize_to_host_window_size(ws))?;
            }
            term.endpoint().call(utcb)?;
            Ok(0)
        }
        TCGETS => {
            let mut utcb = unsafe { UTCB::new() };
            utcb.clear();
            utcb.set_msg_tag(MsgTag::new(
                glenda::protocol::TERMINAL_PROTO,
                glenda::protocol::terminal::TERM_GET_TERMIOS,
                MsgFlags::NONE,
            ));
            term.endpoint().call(utcb)?;

            let copy_len = min(TTY_TERMIOS_SIZE, utcb.buffer().len());
            write_user_bytes(mgr, pid, argp, &utcb.buffer()[..copy_len])?;
            Ok(0)
        }
        TCSETS | TCSETSW | TCSETSF => {
            let payload = read_user_bytes(mgr, pid, argp, TTY_TERMIOS_SIZE)?;
            let mut utcb = unsafe { UTCB::new() };
            utcb.clear();
            utcb.set_msg_tag(MsgTag::new(
                glenda::protocol::TERMINAL_PROTO,
                glenda::protocol::terminal::TERM_SET_TERMIOS,
                MsgFlags::HAS_BUFFER,
            ));
            let copied = utcb.write(&payload);
            utcb.set_mr(0, copied);
            term.endpoint().call(utcb)?;
            Ok(0)
        }
        TIOCGPGRP => {
            let mut utcb = unsafe { UTCB::new() };
            utcb.clear();
            utcb.set_msg_tag(MsgTag::new(
                glenda::protocol::TERMINAL_PROTO,
                glenda::protocol::terminal::TERM_GET_PGRP,
                MsgFlags::NONE,
            ));
            term.endpoint().call(utcb)?;
            write_user_i32(mgr, pid, argp, utcb.get_mr(0) as c_int)?;
            Ok(0)
        }
        TIOCSPGRP => {
            let pgrp = read_user_i32(mgr, pid, argp)?;
            let mut utcb = unsafe { UTCB::new() };
            utcb.clear();
            utcb.set_msg_tag(MsgTag::new(
                glenda::protocol::TERMINAL_PROTO,
                glenda::protocol::terminal::TERM_SET_PGRP,
                MsgFlags::NONE,
            ));
            utcb.set_mr(0, pgrp as usize);
            term.endpoint().call(utcb)?;
            Ok(0)
        }
        _ => Err(Error::InvalidType),
    }
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
