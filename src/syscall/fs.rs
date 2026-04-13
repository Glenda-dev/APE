use crate::ApeManager;
use glenda::error::Error;

pub fn sys_read<'a>(
    mgr: &mut ApeManager<'a>,
    pid: usize,
    fd: usize,
    buf_ptr: usize,
    len: usize,
) -> Result<isize, Error> {
    crate::fs::io::do_read(mgr, pid, fd, buf_ptr, len)
}

pub fn sys_write<'a>(
    mgr: &mut ApeManager<'a>,
    pid: usize,
    fd: usize,
    buf_ptr: usize,
    len: usize,
) -> Result<isize, Error> {
    crate::fs::io::do_write(mgr, pid, fd, buf_ptr, len)
}

pub fn sys_openat<'a>(
    mgr: &mut ApeManager<'a>,
    pid: usize,
    dirfd: usize,
    pathname: usize,
    flags: usize,
    mode: usize,
) -> Result<isize, Error> {
    crate::fs::fd::do_openat(mgr, pid, dirfd, pathname, flags, mode)
}

pub fn sys_newfstatat<'a>(
    mgr: &mut ApeManager<'a>,
    pid: usize,
    dirfd: usize,
    pathname: usize,
    statbuf: usize,
    flags: usize,
) -> Result<isize, Error> {
    crate::fs::meta::do_newfstatat(mgr, pid, dirfd, pathname, statbuf, flags)
}

pub fn sys_close<'a>(mgr: &mut ApeManager<'a>, pid: usize, fd: usize) -> Result<isize, Error> {
    crate::fs::fd::do_close(mgr, pid, fd)
}

pub fn sys_lseek<'a>(
    mgr: &mut ApeManager<'a>,
    pid: usize,
    fd: usize,
    offset: isize,
    whence: usize,
) -> Result<isize, Error> {
    crate::fs::io::do_lseek(mgr, pid, fd, offset, whence)
}

pub fn sys_fcntl<'a>(
    mgr: &mut ApeManager<'a>,
    pid: usize,
    fd: usize,
    cmd: usize,
    arg: usize,
) -> Result<isize, Error> {
    crate::fs::fd::do_fcntl(mgr, pid, fd, cmd, arg)
}

pub fn sys_ioctl<'a>(
    mgr: &mut ApeManager<'a>,
    pid: usize,
    fd: usize,
    request: usize,
    argp: usize,
) -> Result<isize, Error> {
    crate::fs::io::do_ioctl(mgr, pid, fd, request, argp)
}

pub fn sys_readv<'a>(
    mgr: &mut ApeManager<'a>,
    pid: usize,
    fd: usize,
    iov_ptr: usize,
    iov_cnt: usize,
) -> Result<isize, Error> {
    crate::fs::io::do_readv(mgr, pid, fd, iov_ptr, iov_cnt)
}

pub fn sys_writev<'a>(
    mgr: &mut ApeManager<'a>,
    pid: usize,
    fd: usize,
    iov_ptr: usize,
    iov_cnt: usize,
) -> Result<isize, Error> {
    crate::fs::io::do_writev(mgr, pid, fd, iov_ptr, iov_cnt)
}