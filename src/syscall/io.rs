use crate::ApeManager;
use glenda::error::Error;

pub fn sys_read<'a>(
    mgr: &mut ApeManager<'a>,
    pid: usize,
    fd: usize,
    buf_ptr: usize,
    len: usize,
) -> Result<isize, Error> {
    crate::io::file::do_read(mgr, pid, fd, buf_ptr, len)
}

pub fn sys_write<'a>(
    mgr: &mut ApeManager<'a>,
    pid: usize,
    fd: usize,
    buf_ptr: usize,
    len: usize,
) -> Result<isize, Error> {
    crate::io::file::do_write(mgr, pid, fd, buf_ptr, len)
}

pub fn sys_ioctl<'a>(
    mgr: &mut ApeManager<'a>,
    pid: usize,
    fd: usize,
    request: usize,
    argp: usize,
) -> Result<isize, Error> {
    crate::io::file::do_ioctl(mgr, pid, fd, request, argp)
}

pub fn sys_readv<'a>(
    mgr: &mut ApeManager<'a>,
    pid: usize,
    fd: usize,
    iov_ptr: usize,
    iov_cnt: usize,
) -> Result<isize, Error> {
    crate::io::file::do_readv(mgr, pid, fd, iov_ptr, iov_cnt)
}

pub fn sys_writev<'a>(
    mgr: &mut ApeManager<'a>,
    pid: usize,
    fd: usize,
    iov_ptr: usize,
    iov_cnt: usize,
) -> Result<isize, Error> {
    crate::io::file::do_writev(mgr, pid, fd, iov_ptr, iov_cnt)
}

pub fn sys_lseek<'a>(
    mgr: &mut ApeManager<'a>,
    pid: usize,
    fd: usize,
    offset: isize,
    whence: usize,
) -> Result<isize, Error> {
    crate::io::file::do_lseek(mgr, pid, fd, offset, whence)
}
