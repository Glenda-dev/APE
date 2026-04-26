use crate::ApeManager;
use crate::ape::files::{FileHandle, FileType, NormalHandleBackend};
use alloc::vec;
use alloc::vec::Vec;
use core::cmp::min;
use core::mem::size_of;
use glenda::client::FsClient;
use glenda::error::Error;
use glenda::interface::{FileHandleService, FileSystemService};
use glenda::io::uring::{IOURING_OP_READ, IOURING_OP_WRITE, IoUringClient, IoUringSqe};
use glenda::ipc::Badge;
use linux_raw_sys::ctypes::c_uint;
use linux_raw_sys::general::{SEEK_CUR, SEEK_END, SEEK_SET, iovec};
use linux_raw_sys::ioctl::{
    TCGETS, TCSETS, TCSETSF, TCSETSW, TIOCGPGRP, TIOCGWINSZ, TIOCSPGRP, TIOCSWINSZ,
};

const FS_SYNC_RW_CHUNK: usize = 4096;
const IOCTL_DIR_NONE: usize = 0;
const IOCTL_DIR_WRITE: usize = 1;
const IOCTL_DIR_READ: usize = 2;
const IOCTL_MAX_STRUCT_SIZE: usize = 4096;

#[inline]
fn ioctl_dir(request: u32) -> usize {
    ((request as usize) >> 30) & 0x3
}

#[inline]
fn ioctl_size(request: u32) -> usize {
    ((request as usize) >> 16) & 0x3fff
}

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
        FileType::Normal(normal) => match &mut normal.backend {
            NormalHandleBackend::Fs => {
                let fs_client = &mut normal.fs_client;
                let mut total = 0usize;
                let mut kbuf = [0u8; FS_SYNC_RW_CHUNK];
                while total < len {
                    let chunk = min(len - total, kbuf.len());
                    if chunk == 0 {
                        break;
                    }
                    let read_len =
                        fs_client.read(Badge::null(), normal.offset, &mut kbuf[..chunk])?;
                    if read_len == 0 {
                        break;
                    }
                    let user_dst = buf_ptr.checked_add(total).ok_or(Error::InvalidAddress)?;
                    mgr.copy_to_user(pid, user_dst, &kbuf[..read_len])?;
                    total += read_len;
                    normal.offset = normal.offset.saturating_add(read_len);
                    if read_len < chunk {
                        break;
                    }
                }
                Ok(total as isize)
            }
        },
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
        FileType::Normal(normal) => match &mut normal.backend {
            NormalHandleBackend::Fs => {
                let fs_client = &mut normal.fs_client;
                let mut total = 0usize;
                let mut kbuf = [0u8; FS_SYNC_RW_CHUNK];
                while total < len {
                    let chunk = min(len - total, kbuf.len());
                    if chunk == 0 {
                        break;
                    }
                    let user_src = buf_ptr.checked_add(total).ok_or(Error::InvalidAddress)?;
                    mgr.copy_from_user(pid, user_src, &mut kbuf[..chunk])?;
                    let written = fs_client.write(Badge::null(), normal.offset, &kbuf[..chunk])?;
                    total += written;
                    normal.offset = normal.offset.saturating_add(written);
                    if written < chunk {
                        break;
                    }
                }
                Ok(total as isize)
            }
        },
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
        FileType::Normal(normal) => match &mut normal.backend {
            NormalHandleBackend::Fs => {
                let fs_client = &mut normal.fs_client;
                let base: isize = match whence as u32 {
                    SEEK_SET => 0,
                    SEEK_CUR => normal.offset as isize,
                    SEEK_END => {
                        let st = fs_client.stat(Badge::null())?;
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
        },
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
    if req == 0 {
        return Ok(0);
    }

    with_fd_handle_mut(mgr, pid, fd, |mgr, handle| match &mut handle.file_type {
        FileType::Normal(normal) => match normal.backend {
            NormalHandleBackend::Fs => {
                do_ioctl_fs_passthrough(mgr, pid, normal.fs_client, req, argp)
            }
        },
    })
}

fn do_ioctl_fs_passthrough<'a>(
    mgr: &mut ApeManager<'a>,
    pid: usize,
    mut fs_client: FsClient,
    request: u32,
    argp: usize,
) -> Result<isize, Error> {
    let dir = ioctl_dir(request);
    let encoded_size = ioctl_size(request);
    if encoded_size > IOCTL_MAX_STRUCT_SIZE {
        return Err(Error::InvalidArgs);
    }

    let mut in_len = if encoded_size > 0
        && (dir == IOCTL_DIR_WRITE || dir == (IOCTL_DIR_WRITE | IOCTL_DIR_READ))
    {
        encoded_size
    } else {
        0
    };
    let mut out_len = if encoded_size > 0
        && (dir == IOCTL_DIR_READ || dir == (IOCTL_DIR_WRITE | IOCTL_DIR_READ))
    {
        encoded_size
    } else {
        0
    };

    if in_len == 0 && out_len == 0 {
        match request {
            TIOCGWINSZ => out_len = size_of::<linux_raw_sys::general::winsize>(),
            TIOCSWINSZ => in_len = size_of::<linux_raw_sys::general::winsize>(),
            TIOCGPGRP => out_len = size_of::<i32>(),
            TIOCSPGRP => in_len = size_of::<i32>(),
            TCGETS => out_len = crate::ape::tty::TTY_TERMIOS_SIZE,
            TCSETS | TCSETSW | TCSETSF => in_len = crate::ape::tty::TTY_TERMIOS_SIZE,
            _ => {}
        }
    }
    let mut input = Vec::new();
    if in_len > 0 {
        if argp == 0 {
            return Err(Error::InvalidAddress);
        }
        input.resize(in_len, 0);
        mgr.copy_from_user(pid, argp, &mut input)?;
    }

    let (ret, out) = fs_client.ioctl_ex(
        Badge::null(),
        request,
        argp,
        if input.is_empty() { None } else { Some(input.as_slice()) },
        out_len,
    )?;

    if !out.is_empty() {
        if argp == 0 {
            return Err(Error::InvalidAddress);
        }
        mgr.copy_to_user(pid, argp, &out)?;
    }

    Ok(ret as isize)
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
    let task = mgr.get_process(pid).ok_or(Error::NotFound)?;
    let mut handle = {
        let mut files = task.files.state.write();
        files.fds.remove(&fd).ok_or(Error::InvalidSlot)?
    };

    let result = f(mgr, &mut handle);

    task.files.state.write().fds.insert(fd, handle);
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
