use crate::ApeManager;
use crate::system as system_subsystem;
use glenda::error::Error;

pub fn sys_uname<'a>(mgr: &mut ApeManager<'a>, pid: usize, buf_ptr: usize) -> Result<isize, Error> {
    system_subsystem::do_uname(mgr, pid, buf_ptr)
}

pub fn sys_rt_sigaction<'a>(
    mgr: &mut ApeManager<'a>,
    pid: usize,
    signum: usize,
    act: usize,
    oldact: usize,
    sigsetsize: usize,
) -> Result<isize, Error> {
    system_subsystem::do_rt_sigaction(mgr, pid, signum, act, oldact, sigsetsize)
}

pub fn sys_rt_sigprocmask<'a>(
    mgr: &mut ApeManager<'a>,
    pid: usize,
    how: usize,
    set: usize,
    oldset: usize,
    sigsetsize: usize,
) -> Result<isize, Error> {
    system_subsystem::do_rt_sigprocmask(mgr, pid, how, set, oldset, sigsetsize)
}

pub fn sys_rt_sigpending<'a>(
    mgr: &mut ApeManager<'a>,
    pid: usize,
    set: usize,
    sigsetsize: usize,
) -> Result<isize, Error> {
    system_subsystem::do_rt_sigpending(mgr, pid, set, sigsetsize)
}

pub fn sys_rt_sigtimedwait<'a>(
    mgr: &mut ApeManager<'a>,
    pid: usize,
    set: usize,
    info: usize,
    timeout: usize,
    sigsetsize: usize,
) -> Result<isize, Error> {
    system_subsystem::do_rt_sigtimedwait(mgr, pid, set, info, timeout, sigsetsize)
}

pub fn sys_rt_sigsuspend<'a>(
    mgr: &mut ApeManager<'a>,
    pid: usize,
    mask: usize,
    sigsetsize: usize,
) -> Result<isize, Error> {
    system_subsystem::do_rt_sigsuspend(mgr, pid, mask, sigsetsize)
}

pub fn sys_set_robust_list<'a>(
    mgr: &mut ApeManager<'a>,
    pid: usize,
    head: usize,
    len: usize,
) -> Result<isize, Error> {
    system_subsystem::do_set_robust_list(mgr, pid, head, len)
}

pub fn sys_prlimit64<'a>(
    mgr: &mut ApeManager<'a>,
    pid: usize,
    target_pid: usize,
    resource: usize,
    new_limit: usize,
    old_limit: usize,
) -> Result<isize, Error> {
    system_subsystem::do_prlimit64(mgr, pid, target_pid, resource, new_limit, old_limit)
}

pub fn sys_clock_gettime<'a>(
    mgr: &mut ApeManager<'a>,
    pid: usize,
    clockid: usize,
    tp: usize,
) -> Result<isize, Error> {
    system_subsystem::do_clock_gettime(mgr, pid, clockid, tp)
}

pub fn sys_gettimeofday<'a>(
    mgr: &mut ApeManager<'a>,
    pid: usize,
    tv: usize,
    tz: usize,
) -> Result<isize, Error> {
    system_subsystem::do_gettimeofday(mgr, pid, tv, tz)
}

pub fn sys_nanosleep<'a>(
    mgr: &mut ApeManager<'a>,
    pid: usize,
    req: usize,
    rem: usize,
) -> Result<isize, Error> {
    system_subsystem::do_nanosleep(mgr, pid, req, rem)
}

pub fn sys_ppoll<'a>(
    mgr: &mut ApeManager<'a>,
    pid: usize,
    fds_ptr: usize,
    nfds: usize,
    timeout: usize,
    sigmask: usize,
    sigsetsize: usize,
) -> Result<isize, Error> {
    system_subsystem::do_ppoll(mgr, pid, fds_ptr, nfds, timeout, sigmask, sigsetsize)
}

pub fn sys_getrandom<'a>(
    mgr: &mut ApeManager<'a>,
    pid: usize,
    buf_ptr: usize,
    len: usize,
    flags: usize,
) -> Result<isize, Error> {
    system_subsystem::do_getrandom(mgr, pid, buf_ptr, len, flags)
}

pub fn sys_getuid<'a>(mgr: &mut ApeManager<'a>, pid: usize) -> Result<isize, Error> {
    system_subsystem::do_getuid(mgr, pid)
}

pub fn sys_geteuid<'a>(mgr: &mut ApeManager<'a>, pid: usize) -> Result<isize, Error> {
    system_subsystem::do_geteuid(mgr, pid)
}

pub fn sys_getgid<'a>(mgr: &mut ApeManager<'a>, pid: usize) -> Result<isize, Error> {
    system_subsystem::do_getgid(mgr, pid)
}

pub fn sys_getegid<'a>(mgr: &mut ApeManager<'a>, pid: usize) -> Result<isize, Error> {
    system_subsystem::do_getegid(mgr, pid)
}

pub fn sys_getcwd<'a>(
    mgr: &mut ApeManager<'a>,
    pid: usize,
    buf_ptr: usize,
    size: usize,
) -> Result<isize, Error> {
    system_subsystem::do_getcwd(mgr, pid, buf_ptr, size)
}

pub fn sys_chdir<'a>(
    mgr: &mut ApeManager<'a>,
    pid: usize,
    path_ptr: usize,
) -> Result<isize, Error> {
    system_subsystem::do_chdir(mgr, pid, path_ptr)
}

pub fn sys_fchdir<'a>(mgr: &mut ApeManager<'a>, pid: usize, fd: usize) -> Result<isize, Error> {
    system_subsystem::do_fchdir(mgr, pid, fd)
}

pub fn sys_chroot<'a>(
    mgr: &mut ApeManager<'a>,
    pid: usize,
    path_ptr: usize,
) -> Result<isize, Error> {
    system_subsystem::do_chroot(mgr, pid, path_ptr)
}

pub fn sys_reboot<'a>(
    mgr: &mut ApeManager<'a>,
    pid: usize,
    magic: usize,
    magic2: usize,
    cmd: usize,
    arg: usize,
) -> Result<isize, Error> {
    system_subsystem::do_reboot(mgr, pid, magic, magic2, cmd, arg)
}

pub fn sys_sched_yield<'a>(mgr: &mut ApeManager<'a>, pid: usize) -> Result<isize, Error> {
    system_subsystem::do_sched_yield(mgr, pid)
}

pub fn sys_prctl<'a>(
    mgr: &mut ApeManager<'a>,
    pid: usize,
    option: usize,
    arg2: usize,
    arg3: usize,
    arg4: usize,
    arg5: usize,
) -> Result<isize, Error> {
    system_subsystem::do_prctl(mgr, pid, option, arg2, arg3, arg4, arg5)
}

pub fn sys_futex<'a>(
    mgr: &mut ApeManager<'a>,
    pid: usize,
    uaddr: usize,
    futex_op: usize,
    val: usize,
    timeout: usize,
    uaddr2: usize,
    val3: usize,
) -> Result<isize, Error> {
    system_subsystem::do_futex(mgr, pid, uaddr, futex_op, val, timeout, uaddr2, val3)
}
