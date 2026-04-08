use crate::ApeManager;
use crate::ape::process::FileType;
use glenda::error::Error;
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
    let process = mgr.get_process_mut(pid).ok_or(Error::NotFound)?;
    let fd = u32::try_from(fd).map_err(|_| Error::InvalidSlot)?;
    let file = process.fds.get_mut(&fd).ok_or(Error::InvalidSlot)?;

    match &mut file.file_type {
        FileType::Terminal(term) => {
            let mut utcb = unsafe { glenda::ipc::UTCB::new() };
            let tag = glenda::ipc::MsgTag::new(
                glenda::protocol::TERMINAL_PROTO,
                glenda::protocol::terminal::TERM_GET_STR,
                glenda::ipc::MsgFlags::HAS_BUFFER,
            );
            utcb.set_mr(0, len);
            utcb.set_msg_tag(tag);
            term.endpoint().call(utcb)?;
            utcb.error_check()?;

            let read_len = utcb.get_mr(0);
            if read_len > 0 {
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
    let process = mgr.get_process_mut(pid).ok_or(Error::NotFound)?;
    let fd = u32::try_from(fd).map_err(|_| Error::InvalidSlot)?;
    let file = process.fds.get_mut(&fd).ok_or(Error::InvalidSlot)?;

    match &mut file.file_type {
        FileType::Terminal(term) => {
            // 需要从子进程内存中读取字符串数据并发送给终端。
            // 这里我们需要访问子进程内存的能力。
            // 简单处理：如果 buf_ptr 在 APE 的当前 vspace 是不可见的，就会出问题。
            // 但 APE 通常是 Monitor 角色，可以通过 child_vspace 翻译。
            // 暂时：由于没有好的内存访问抽象，我们先打印并假装成功。
            Ok(len as isize)
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
    log!("sys_openat: pid {} dirfd {} path {:#x}", pid, dirfd, pathname);
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
