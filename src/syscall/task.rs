use crate::ApeManager;
use crate::proc;
use glenda::error::Error;

#[inline]
fn pid_result(pid: usize) -> Result<isize, Error> {
    Ok(pid as isize)
}

pub fn sys_getpid<'a>(_mgr: &mut ApeManager<'a>, pid: usize) -> Result<isize, Error> {
    pid_result(pid)
}

pub fn sys_gettid<'a>(_mgr: &mut ApeManager<'a>, pid: usize) -> Result<isize, Error> {
    pid_result(pid)
}

pub fn sys_set_tid_address<'a>(
    mgr: &mut ApeManager<'a>,
    pid: usize,
    tidptr: usize,
) -> Result<isize, Error> {
    Ok(proc::do_set_tid_address(mgr, pid, tidptr)? as isize)
}

pub fn sys_exit<'a>(mgr: &mut ApeManager<'a>, pid: usize, code: usize) -> Result<isize, Error> {
    proc::do_exit(mgr, pid, code)?;
    Ok(0)
}

pub fn sys_exit_group<'a>(
    mgr: &mut ApeManager<'a>,
    pid: usize,
    code: usize,
) -> Result<isize, Error> {
    sys_exit(mgr, pid, code)
}

pub fn sys_getppid<'a>(mgr: &mut ApeManager<'a>, pid: usize) -> Result<isize, Error> {
    Ok(proc::do_getppid(mgr, pid)? as isize)
}

pub fn sys_fork<'a>(mgr: &mut ApeManager<'a>, pid: usize) -> Result<isize, Error> {
    Ok(proc::do_fork(mgr, pid)? as isize)
}
