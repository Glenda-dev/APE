use crate::ApeManager;
use glenda::error::Error;

pub(crate) fn do_setsid(_mgr: &mut ApeManager<'_>, pid: usize) -> Result<usize, Error> {
    // TODO(ape): 实现会话/进程组管理，并创建新的 session leader。
    Ok(pid)
}

pub(crate) fn do_getsid(
    _mgr: &mut ApeManager<'_>,
    pid: usize,
    _target: usize,
) -> Result<usize, Error> {
    // TODO(ape): 返回真实 sid（支持 target pid 查询与权限校验）。
    Ok(pid)
}

pub(crate) fn do_setpgid(
    _mgr: &mut ApeManager<'_>,
    _pid: usize,
    _target: usize,
    _pgid: usize,
) -> Result<isize, Error> {
    // TODO(ape): 实现 setpgid(2) 的组切换与约束校验。
    Ok(0)
}

pub(crate) fn do_getpgid(
    _mgr: &mut ApeManager<'_>,
    pid: usize,
    target_pid: usize,
) -> Result<usize, Error> {
    // TODO(ape): 查询真实进程组 ID，而非参数回显。
    if target_pid == 0 { Ok(pid) } else { Ok(target_pid) }
}

pub(crate) fn do_kill(
    _mgr: &mut ApeManager<'_>,
    caller_pid: usize,
    target_pid: isize,
    sig: isize,
) -> Result<isize, Error> {
    log!(
        "do_kill: caller_pid={}, target_pid={}, sig={} (compat no-op)",
        caller_pid,
        target_pid,
        sig
    );
    // TODO(ape): 实现信号投递、权限校验和目标选择语义（kill/tkill/tgkill 兼容）。
    Ok(0)
}
