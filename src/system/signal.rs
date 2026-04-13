use crate::ApeManager;
use core::mem::size_of;
use glenda::error::Error;
use linux_raw_sys::errno::{EAGAIN, EINTR};

pub(crate) fn do_rt_sigaction(
    mgr: &mut ApeManager<'_>,
    pid: usize,
    _signum: usize,
    _act: usize,
    oldact: usize,
    sigsetsize: usize,
) -> Result<isize, Error> {
    // TODO(ape): 真正维护每进程/线程的 sigaction 表，而非零填充回包。
    if oldact != 0 {
        let sa_len = size_of::<usize>()
            .checked_mul(3)
            .ok_or(Error::InvalidArgs)?
            .saturating_add(sigsetsize);
        mgr.write_zeros_to_user(pid, oldact, sa_len)?;
    }
    Ok(0)
}

pub(crate) fn do_rt_sigprocmask(
    mgr: &mut ApeManager<'_>,
    pid: usize,
    _how: usize,
    _set: usize,
    oldset: usize,
    sigsetsize: usize,
) -> Result<isize, Error> {
    // TODO(ape): 实现信号屏蔽字读写（SIG_BLOCK/SIG_UNBLOCK/SIG_SETMASK）。
    if oldset != 0 {
        mgr.write_zeros_to_user(pid, oldset, sigsetsize)?;
    }
    Ok(0)
}

pub(crate) fn do_rt_sigpending(
    mgr: &mut ApeManager<'_>,
    pid: usize,
    set: usize,
    sigsetsize: usize,
) -> Result<isize, Error> {
    // TODO(ape): 维护 pending signal 集并按用户缓冲区格式导出。
    if set != 0 {
        mgr.write_zeros_to_user(pid, set, sigsetsize)?;
    }
    Ok(0)
}

pub(crate) fn do_rt_sigtimedwait(
    _mgr: &mut ApeManager<'_>,
    _pid: usize,
    _set: usize,
    _info: usize,
    _timeout: usize,
    _sigsetsize: usize,
) -> Result<isize, Error> {
    // TODO(ape): 支持带超时的信号等待队列与 siginfo 回填。
    Ok(-(EAGAIN as isize))
}

pub(crate) fn do_rt_sigsuspend(
    _mgr: &mut ApeManager<'_>,
    _pid: usize,
    _mask: usize,
    _sigsetsize: usize,
) -> Result<isize, Error> {
    // TODO(ape): 实现 sigsuspend 真阻塞，直到信号到达后返回 EINTR。
    Ok(-(EINTR as isize))
}

pub(crate) fn do_set_robust_list(
    _mgr: &mut ApeManager<'_>,
    _pid: usize,
    _head: usize,
    _len: usize,
) -> Result<isize, Error> {
    // TODO(ape): 记录 robust_list 并在线程退出时执行健壮互斥修复。
    Ok(0)
}
