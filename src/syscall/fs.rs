use crate::ApeManager;
use glenda::error::Error;

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

pub fn sys_fcntl<'a>(
    mgr: &mut ApeManager<'a>,
    pid: usize,
    fd: usize,
    cmd: usize,
    arg: usize,
) -> Result<isize, Error> {
    crate::fs::fd::do_fcntl(mgr, pid, fd, cmd, arg)
}
