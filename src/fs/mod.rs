use crate::ApeManager;
use crate::ape::path::path_inside_root;
use crate::ape::process::{
    AsyncIoState, FileHandle, FileType, NormalFileHandle, PseudoCharDevice, PtyMasterHandle,
    PtySlaveHandle,
};
use crate::ape::user::USER_PATH_MAX;
use alloc::format;
use alloc::vec;
use core::cmp::min;
use core::mem::size_of;
use glenda::cap::{CSPACE_CAP, CapPtr, Endpoint, Frame};
use glenda::client::{FsClient, TerminalClient};
use glenda::error::Error;
use glenda::interface::{
    CSpaceService, FileHandleService, FileSystemService, VirtualTerminalService,
};
use glenda::io::uring::{
    IOURING_OP_READ, IOURING_OP_WRITE, IoUringBuffer, IoUringClient, IoUringSqe,
};
use glenda::ipc::IPC_BUFFER_SIZE;
use glenda::ipc::{Badge, MsgFlags, MsgTag, UTCB};
use glenda::protocol::terminal::WindowSize;
use linux_raw_sys::general::{SEEK_CUR, SEEK_END, SEEK_SET};

// 4KB ring + 12KB data window，降低每 fd 的常驻内存。
const FS_ASYNC_REGION_SIZE: usize = 16 * 1024;
const FS_ASYNC_RING_SIZE: usize = 4096;
const FS_ASYNC_DATA_OFFSET: usize = FS_ASYNC_RING_SIZE;
const FS_ASYNC_SQ_ENTRIES: u32 = 16;
const FS_ASYNC_CQ_ENTRIES: u32 = 16;
const ENABLE_FS_ASYNC_IO: bool = false;

const F_DUPFD: usize = 0;
const F_GETFD: usize = 1;
const F_SETFD: usize = 2;
const F_GETFL: usize = 3;
const F_SETFL: usize = 4;
const F_DUPFD_CLOEXEC: usize = 1030;
const FD_CLOEXEC: usize = 1;

const TTY_IOCTL_TCGETS: usize = 0x5401;
const TTY_IOCTL_TCSETS: usize = 0x5402;
const TTY_IOCTL_TCSETSW: usize = 0x5403;
const TTY_IOCTL_TCSETSF: usize = 0x5404;
const TTY_IOCTL_TIOCGPGRP: usize = 0x540F;
const TTY_IOCTL_TIOCSPGRP: usize = 0x5410;
const TTY_IOCTL_TIOCGWINSZ: usize = 0x5413;
const TTY_IOCTL_TIOCSWINSZ: usize = 0x5414;
const PTY_IOCTL_TIOCGPTN: usize = 0x8004_5430;
const PTY_IOCTL_TIOCSPTLCK: usize = 0x4004_5431;
const TTY_TERMIOS_SIZE: usize = 44;

#[repr(C)]
#[derive(Clone, Copy, Default)]
struct LinuxWinsize {
    ws_row: u16,
    ws_col: u16,
    ws_xpixel: u16,
    ws_ypixel: u16,
}

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

fn read_user_winsize<'a>(
    mgr: &mut ApeManager<'a>,
    pid: usize,
    user_ptr: usize,
) -> Result<LinuxWinsize, Error> {
    let mut raw = [0u8; core::mem::size_of::<LinuxWinsize>()];
    mgr.copy_from_user(pid, user_ptr, &mut raw)?;
    Ok(unsafe { (raw.as_ptr() as *const LinuxWinsize).read_unaligned() })
}

fn write_user_winsize<'a>(
    mgr: &mut ApeManager<'a>,
    pid: usize,
    user_ptr: usize,
    winsize: LinuxWinsize,
) -> Result<(), Error> {
    let raw = unsafe {
        core::slice::from_raw_parts(
            (&winsize as *const LinuxWinsize) as *const u8,
            core::mem::size_of::<LinuxWinsize>(),
        )
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
    val: i32,
) -> Result<(), Error> {
    mgr.copy_to_user(pid, user_ptr, &val.to_ne_bytes())
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

fn fill_user_with_zeros<'a>(
    mgr: &mut ApeManager<'a>,
    pid: usize,
    user_ptr: usize,
    len: usize,
) -> Result<(), Error> {
    if len == 0 {
        return Ok(());
    }
    let zeros = [0u8; 256];
    let mut done = 0usize;
    while done < len {
        let chunk = min(len - done, zeros.len());
        mgr.copy_to_user(pid, user_ptr + done, &zeros[..chunk])?;
        done += chunk;
    }
    Ok(())
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
    val: u32,
) -> Result<(), Error> {
    mgr.copy_to_user(pid, user_ptr, &val.to_ne_bytes())
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

fn set_terminal_pgrp(term: TerminalClient, pgrp: i32) -> Result<(), Error> {
    let mut utcb = unsafe { UTCB::new() };
    utcb.clear();
    utcb.set_msg_tag(MsgTag::new(
        glenda::protocol::TERMINAL_PROTO,
        glenda::protocol::terminal::TERM_SET_PGRP,
        MsgFlags::NONE,
    ));
    utcb.set_mr(0, pgrp as usize);
    term.endpoint().call(utcb)
}

fn ioctl_to_terminal<'a>(
    mgr: &mut ApeManager<'a>,
    pid: usize,
    term: TerminalClient,
    request: usize,
    argp: usize,
) -> Result<isize, Error> {
    match request {
        TTY_IOCTL_TIOCGWINSZ => {
            let mut utcb = unsafe { UTCB::new() };
            utcb.clear();
            utcb.set_msg_tag(MsgTag::new(
                glenda::protocol::TERMINAL_PROTO,
                glenda::protocol::terminal::TERM_GET_WINSIZE,
                MsgFlags::NONE,
            ));
            term.endpoint().call(utcb)?;
            let ws: WindowSize = unsafe { utcb.read_postcard()? };
            write_user_winsize(
                mgr,
                pid,
                argp,
                LinuxWinsize {
                    ws_row: ws.rows,
                    ws_col: ws.cols,
                    ws_xpixel: ws.xpixel,
                    ws_ypixel: ws.ypixel,
                },
            )?;
            Ok(0)
        }
        TTY_IOCTL_TIOCSWINSZ => {
            let ws = read_user_winsize(mgr, pid, argp)?;
            let mut utcb = unsafe { UTCB::new() };
            utcb.clear();
            utcb.set_msg_tag(MsgTag::new(
                glenda::protocol::TERMINAL_PROTO,
                glenda::protocol::terminal::TERM_SET_WINSIZE,
                MsgFlags::HAS_BUFFER,
            ));
            unsafe {
                utcb.write_postcard(&WindowSize {
                    rows: ws.ws_row,
                    cols: ws.ws_col,
                    xpixel: ws.ws_xpixel,
                    ypixel: ws.ws_ypixel,
                })?;
            }
            term.endpoint().call(utcb)?;
            Ok(0)
        }
        TTY_IOCTL_TCGETS => {
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
        TTY_IOCTL_TCSETS | TTY_IOCTL_TCSETSW | TTY_IOCTL_TCSETSF => {
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
        TTY_IOCTL_TIOCGPGRP => {
            let mut utcb = unsafe { UTCB::new() };
            utcb.clear();
            utcb.set_msg_tag(MsgTag::new(
                glenda::protocol::TERMINAL_PROTO,
                glenda::protocol::terminal::TERM_GET_PGRP,
                MsgFlags::NONE,
            ));
            term.endpoint().call(utcb)?;
            write_user_i32(mgr, pid, argp, utcb.get_mr(0) as i32)?;
            Ok(0)
        }
        TTY_IOCTL_TIOCSPGRP => {
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
        FileType::PtyMaster(master) => read_from_terminal(mgr, pid, master.term, buf_ptr, len),
        FileType::PtySlave(slave) => read_from_terminal(mgr, pid, slave.term, buf_ptr, len),
        FileType::PseudoChar(dev) => match dev {
            PseudoCharDevice::Null => Ok(0),
            PseudoCharDevice::Zero | PseudoCharDevice::Random | PseudoCharDevice::URandom => {
                fill_user_with_zeros(mgr, pid, buf_ptr, len)?;
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
        FileType::PtyMaster(master) => write_to_terminal(mgr, pid, master.term, buf_ptr, len),
        FileType::PtySlave(slave) => write_to_terminal(mgr, pid, slave.term, buf_ptr, len),
        FileType::PseudoChar(_dev) => Ok(len as isize),
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
                if let Err(e) = set_terminal_pgrp(term, pid as i32) {
                    warn!(
                        "sys_openat: set initial tty pgrp failed pid={}, vt_id={}, err={:?}",
                        pid,
                        vt_id,
                        e
                    );
                }

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
                let term = mgr.stdio_term.ok_or(Error::NotFound)?;
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
    if let Err(e) = fs_open_client.open(Badge::null(), &path, open_flags, mode as u32, fs_ep_slot)
    {
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
                Some(Frame::from(region.frame_slot)),
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
                    // extfs/fatfs 尚未支持 io_uring，回退到同步路径。
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

pub fn sys_close<'a>(mgr: &mut ApeManager<'a>, pid: usize, fd: usize) -> Result<isize, Error> {
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

pub fn sys_fcntl<'a>(
    mgr: &mut ApeManager<'a>,
    pid: usize,
    fd: usize,
    cmd: usize,
    arg: usize,
) -> Result<isize, Error> {
    let fd = u32::try_from(fd).map_err(|_| Error::InvalidSlot)?;
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
            let cloexec = (arg & FD_CLOEXEC) != 0;
            process.fd_cloexec.insert(fd, cloexec);
            Ok(0)
        }
        F_GETFL => {
            // 目前不追踪完整 open flags，返回 0 以兼容 busybox/musl 常见探测路径。
            Ok(0)
        }
        F_SETFL => {
            // 非阻塞等标志当前不改变后端行为，按成功返回。
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

            let new_cloexec = if cmd == F_DUPFD_CLOEXEC {
                true
            } else {
                // Linux dup/fcntl(F_DUPFD) 默认清除 cloexec。
                false
            };
            process.fd_cloexec.insert(new_fd, new_cloexec);
            if process.next_fd <= new_fd {
                process.next_fd = new_fd.saturating_add(1);
            }

            log!(
                "sys_fcntl: pid={}, cmd={}, fd={}, new_fd={}, cloexec={}",
                pid,
                cmd,
                fd,
                new_fd,
                new_cloexec
            );
            Ok(new_fd as isize)
        }
        _ => Err(Error::InvalidArgs),
    }
}

pub fn sys_lseek<'a>(
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
    with_fd_handle_mut(mgr, pid, fd, |mgr, handle| match &mut handle.file_type {
        FileType::PtyMaster(master) => match request {
            PTY_IOCTL_TIOCGPTN => {
                write_user_u32(mgr, pid, argp, master.vt_id as u32)?;
                Ok(0)
            }
            PTY_IOCTL_TIOCSPTLCK => {
                let lock = read_user_u32(mgr, pid, argp)?;
                mgr.vt_client.set_pty_lock(Badge::null(), master.vt_id, lock != 0)?;
                master.locked = lock != 0;
                Ok(0)
            }
            _ => ioctl_to_terminal(mgr, pid, master.term, request, argp),
        },
        FileType::PtySlave(slave) => ioctl_to_terminal(mgr, pid, slave.term, request, argp),
        FileType::PseudoChar(_) => Err(Error::InvalidType),
        FileType::Terminal(term) => ioctl_to_terminal(mgr, pid, *term, request, argp),
        FileType::Normal(_) => Err(Error::InvalidType),
    })
}
