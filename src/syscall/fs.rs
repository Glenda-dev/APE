use crate::ApeManager;
use glenda::error::Error;

pub fn sys_dup<'a>(mgr: &mut ApeManager<'a>, pid: usize, fd: usize) -> Result<isize, Error> {
    crate::fs::fd::do_dup(mgr, pid, fd)
}

pub fn sys_dup3<'a>(
    mgr: &mut ApeManager<'a>,
    pid: usize,
    oldfd: usize,
    newfd: usize,
    flags: usize,
) -> Result<isize, Error> {
    crate::fs::fd::do_dup3(mgr, pid, oldfd, newfd, flags)
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

pub fn sys_fstat<'a>(
    mgr: &mut ApeManager<'a>,
    pid: usize,
    fd: usize,
    statbuf: usize,
) -> Result<isize, Error> {
    crate::fs::meta::do_fstat(mgr, pid, fd, statbuf)
}

pub fn sys_getdents64<'a>(
    mgr: &mut ApeManager<'a>,
    pid: usize,
    fd: usize,
    dirp: usize,
    count: usize,
) -> Result<isize, Error> {
    crate::fs::fd::do_getdents64(mgr, pid, fd, dirp, count)
}

pub fn sys_mkdirat<'a>(
    mgr: &mut ApeManager<'a>,
    pid: usize,
    dirfd: usize,
    pathname: usize,
    mode: usize,
) -> Result<isize, Error> {
    crate::fs::meta::do_mkdirat(mgr, pid, dirfd, pathname, mode)
}

pub fn sys_unlinkat<'a>(
    mgr: &mut ApeManager<'a>,
    pid: usize,
    dirfd: usize,
    pathname: usize,
    flags: usize,
) -> Result<isize, Error> {
    crate::fs::meta::do_unlinkat(mgr, pid, dirfd, pathname, flags)
}

pub fn sys_linkat<'a>(
    mgr: &mut ApeManager<'a>,
    pid: usize,
    olddirfd: usize,
    oldpath: usize,
    newdirfd: usize,
    newpath: usize,
    flags: usize,
) -> Result<isize, Error> {
    crate::fs::meta::do_linkat(mgr, pid, olddirfd, oldpath, newdirfd, newpath, flags)
}

pub fn sys_utimensat<'a>(
    mgr: &mut ApeManager<'a>,
    pid: usize,
    dirfd: usize,
    pathname: usize,
    times: usize,
    flags: usize,
) -> Result<isize, Error> {
    crate::fs::meta::do_utimensat(mgr, pid, dirfd, pathname, times, flags)
}

pub fn sys_mount<'a>(
    mgr: &mut ApeManager<'a>,
    pid: usize,
    source: usize,
    target: usize,
    fstype: usize,
    flags: usize,
    data: usize,
) -> Result<isize, Error> {
    crate::fs::meta::do_mount(mgr, pid, source, target, fstype, flags, data)
}

pub fn sys_umount2<'a>(
    mgr: &mut ApeManager<'a>,
    pid: usize,
    target: usize,
    flags: usize,
) -> Result<isize, Error> {
    crate::fs::meta::do_umount2(mgr, pid, target, flags)
}

pub fn sys_pipe2<'a>(
    mgr: &mut ApeManager<'a>,
    pid: usize,
    pipefd: usize,
    flags: usize,
) -> Result<isize, Error> {
    crate::fs::fd::do_pipe2(mgr, pid, pipefd, flags)
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
