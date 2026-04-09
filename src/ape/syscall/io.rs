use crate::ApeManager;
use crate::ape::process::FileType;
use crate::ape::user::USER_PATH_MAX;
use alloc::vec;
use core::cmp::min;
use glenda::error::Error;
use glenda::ipc::{MsgFlags, MsgTag, UTCB};
use glenda::log;
use linux_raw_sys::errno::ENOSYS;

pub fn sys_read<'a>(
    mgr: &mut ApeManager<'a>,
    pid: usize,
    fd: usize,
    buf_ptr: usize,
    len: usize,
) -> Result<isize, Error> {
    log!("sys_read: pid {} fd {} buf {:#x} len {}", pid, fd, buf_ptr, len);
    if len == 0 {
        return Ok(0);
    }
    let fd = u32::try_from(fd).map_err(|_| Error::InvalidSlot)?;
    let file_type = {
        let process = mgr.get_process(pid).ok_or(Error::NotFound)?;
        process.fds.get(&fd).ok_or(Error::InvalidSlot)?.file_type.clone()
    };

    match file_type {
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
                log!("sys_read: terminal read {} bytes", read_len);
            }
            Ok(read_len as isize)
        }
        FileType::Normal { .. } => Ok(0),
    }
}

pub fn sys_write<'a>(
    mgr: &mut ApeManager<'a>,
    pid: usize,
    fd: usize,
    buf_ptr: usize,
    len: usize,
) -> Result<isize, Error> {
    log!("sys_write: pid {} fd {} buf {:#x} len {}", pid, fd, buf_ptr, len);
    if len == 0 {
        return Ok(0);
    }
    let fd = u32::try_from(fd).map_err(|_| Error::InvalidSlot)?;
    let file_type = {
        let process = mgr.get_process(pid).ok_or(Error::NotFound)?;
        process.fds.get(&fd).ok_or(Error::InvalidSlot)?.file_type.clone()
    };

    match file_type {
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
        FileType::Normal { .. } => Ok(len as isize),
    }
}

pub fn sys_openat<'a>(
    mgr: &mut ApeManager<'a>,
    pid: usize,
    dirfd: usize,
    pathname: usize,
    flags: usize,
    mode: usize,
) -> Result<isize, Error> {
    let path = mgr.strncpy_from_user(pid, pathname, USER_PATH_MAX)?;
    log!(
        "sys_openat: pid {} dirfd {} path={} flags={:#x} mode={:#x}",
        pid,
        dirfd,
        path,
        flags,
        mode
    );
    let process = mgr.get_process_mut(pid).ok_or(Error::NotFound)?;
    let fd = process.next_fd;
    process.next_fd += 1;
    process.fds.insert(
        fd,
        crate::ape::process::FileHandle {
            file_type: crate::ape::process::FileType::Normal {
                cap: glenda::cap::CapPtr::null(),
                offset: 0,
            },
        },
    );
    Ok(fd as isize)
}

pub fn sys_close<'a>(mgr: &mut ApeManager<'a>, pid: usize, fd: usize) -> Result<isize, Error> {
    log!("sys_close: pid {} fd {}", pid, fd);
    let process = mgr.get_process_mut(pid).ok_or(Error::NotFound)?;
    let fd = u32::try_from(fd).map_err(|_| Error::InvalidSlot)?;
    process.fds.remove(&fd).ok_or(Error::InvalidSlot)?;
    Ok(0)
}

// TODO: Impl
pub fn sys_ioctl<'a>(
    mgr: &mut ApeManager<'a>,
    pid: usize,
    fd: usize,
    request: usize,
    argp: usize,
) -> Result<isize, Error> {
    log!("sys_ioctl: pid {} fd {} request {:#x} argp {:#x}", pid, fd, request, argp);
    Ok(ENOSYS as isize)
}
