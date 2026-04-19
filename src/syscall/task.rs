use crate::ApeManager;
use crate::task as task_subsystem;
use glenda::error::Error;

pub fn sys_getpid<'a>(_mgr: &mut ApeManager<'a>, pid: usize) -> Result<isize, Error> {
    Ok(task_subsystem::do_getpid(_mgr, pid)? as isize)
}

pub fn sys_gettid<'a>(_mgr: &mut ApeManager<'a>, pid: usize) -> Result<isize, Error> {
    Ok(task_subsystem::do_gettid(_mgr, pid)? as isize)
}

pub fn sys_set_tid_address<'a>(
    mgr: &mut ApeManager<'a>,
    pid: usize,
    tidptr: usize,
) -> Result<isize, Error> {
    Ok(task_subsystem::do_set_tid_address(mgr, pid, tidptr)? as isize)
}

pub fn sys_exit<'a>(mgr: &mut ApeManager<'a>, pid: usize, code: usize) -> Result<isize, Error> {
    task_subsystem::do_exit(mgr, pid, code)?;
    Ok(0)
}

pub fn sys_exit_group<'a>(
    mgr: &mut ApeManager<'a>,
    pid: usize,
    code: usize,
) -> Result<isize, Error> {
    task_subsystem::do_exit_group(mgr, pid, code)?;
    Ok(0)
}

pub fn sys_getppid<'a>(mgr: &mut ApeManager<'a>, pid: usize) -> Result<isize, Error> {
    Ok(task_subsystem::do_getppid(mgr, pid)? as isize)
}

pub fn sys_fork<'a>(mgr: &mut ApeManager<'a>, pid: usize) -> Result<isize, Error> {
    Ok(task_subsystem::do_fork(mgr, pid)? as isize)
}

pub fn sys_clone<'a>(
    mgr: &mut ApeManager<'a>,
    pid: usize,
    flags: usize,
    stack: usize,
    ptid: usize,
    ctid: usize,
    tls: usize,
) -> Result<isize, Error> {
    task_subsystem::do_clone(mgr, pid, flags, stack, ptid, ctid, tls)
}

pub fn sys_wait4<'a>(
    mgr: &mut ApeManager<'a>,
    pid: usize,
    target_pid: isize,
    wstatus: usize,
    options: usize,
    rusage: usize,
) -> Result<isize, Error> {
    task_subsystem::do_wait4(mgr, pid, target_pid, wstatus, options, rusage)
}

pub fn sys_setsid<'a>(_mgr: &mut ApeManager<'a>, pid: usize) -> Result<isize, Error> {
    Ok(task_subsystem::do_setsid(_mgr, pid)? as isize)
}

pub fn sys_getsid<'a>(mgr: &mut ApeManager<'a>, pid: usize, target: usize) -> Result<isize, Error> {
    Ok(task_subsystem::do_getsid(mgr, pid, target)? as isize)
}

pub fn sys_setpgid<'a>(
    mgr: &mut ApeManager<'a>,
    pid: usize,
    target: usize,
    pgid: usize,
) -> Result<isize, Error> {
    task_subsystem::do_setpgid(mgr, pid, target, pgid)
}

pub fn sys_getpgid<'a>(
    mgr: &mut ApeManager<'a>,
    pid: usize,
    target_pid: usize,
) -> Result<isize, Error> {
    Ok(task_subsystem::do_getpgid(mgr, pid, target_pid)? as isize)
}

pub fn sys_kill<'a>(
    mgr: &mut ApeManager<'a>,
    caller_pid: usize,
    target_pid: isize,
    sig: isize,
) -> Result<isize, Error> {
    task_subsystem::do_kill(mgr, caller_pid, target_pid, sig)
}

pub fn sys_execve<'a>(
    mgr: &mut ApeManager<'a>,
    pid: usize,
    filename_ptr: usize,
    argv_ptr: usize,
    envp_ptr: usize,
) -> Result<isize, Error> {
    task_subsystem::do_execve(mgr, pid, filename_ptr, argv_ptr, envp_ptr)?;
    Ok(0)
}
