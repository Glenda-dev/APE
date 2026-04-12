use crate::ApeManager;
use crate::proc;
use glenda::error::Error;
use linux_raw_sys::errno::*;

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

pub fn sys_clone<'a>(
    _mgr: &mut ApeManager<'a>,
    _pid: usize,
    _flags: usize,
    _stack: usize,
    _ptid: usize,
    _ctid: usize,
    _tls: usize,
) -> Result<isize, Error> {
    // 当前不支持 Linux clone 语义，避免进入不完整 fork 路径导致 APE 自身异常。
    Ok(-(ENOSYS as isize))
}

pub fn sys_wait4<'a>(
    _mgr: &mut ApeManager<'a>,
    _pid: usize,
    _target_pid: usize,
    _wstatus: usize,
    _options: usize,
    _rusage: usize,
) -> Result<isize, Error> {
    Ok(-(ECHILD as isize))
}

pub fn sys_setsid<'a>(_mgr: &mut ApeManager<'a>, pid: usize) -> Result<isize, Error> {
    Ok(pid as isize)
}

pub fn sys_getsid<'a>(
    _mgr: &mut ApeManager<'a>,
    pid: usize,
    _target: usize,
) -> Result<isize, Error> {
    Ok(pid as isize)
}

pub fn sys_setpgid<'a>(
    _mgr: &mut ApeManager<'a>,
    _pid: usize,
    _target: usize,
    _pgid: usize,
) -> Result<isize, Error> {
    Ok(0)
}

pub fn sys_getpgid<'a>(
    _mgr: &mut ApeManager<'a>,
    pid: usize,
    target_pid: usize,
) -> Result<isize, Error> {
    if target_pid == 0 { Ok(pid as isize) } else { Ok(target_pid as isize) }
}

pub fn sys_kill<'a>(
    _mgr: &mut ApeManager<'a>,
    caller_pid: usize,
    target_pid: isize,
    sig: isize,
) -> Result<isize, Error> {
    // 先兼容 busybox/musl 的作业控制与探测路径，避免 ENOSYS 引发循环。
    // 目前不做真正信号投递，返回成功并记录日志。
    log!(
        "sys_kill: caller_pid={}, target_pid={}, sig={} (compat no-op)",
        caller_pid,
        target_pid,
        sig
    );
    Ok(0)
}
