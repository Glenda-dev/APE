use crate::ApeManager;
use glenda::error::Error;
use glenda::interface::auth::AuthService;
use glenda::protocol::auth::IdentityInfo;
use libape::policy::{FutexOpClass, classify_futex_op};
use linux_raw_sys::errno::EAGAIN;

fn load_identity(mgr: &mut ApeManager<'_>, pid: usize) -> Result<IdentityInfo, Error> {
    match mgr.auth_client.get_identity(pid) {
        Ok(identity) => {
            if let Some(process) = mgr.get_process_mut(pid) {
                process.identity = identity;
            }
            Ok(identity)
        }
        Err(_) => mgr.get_process(pid).map(|p| p.identity).ok_or(Error::NotFound),
    }
}

pub(crate) fn do_getrandom(
    mgr: &mut ApeManager<'_>,
    pid: usize,
    buf_ptr: usize,
    len: usize,
    _flags: usize,
) -> Result<isize, Error> {
    // TODO(ape): 对接真实熵源与 GRND_* 语义（阻塞/非阻塞、随机池状态）。
    if len == 0 {
        return Ok(0);
    }
    mgr.write_zeros_to_user(pid, buf_ptr, len)?;
    Ok(len as isize)
}

pub(crate) fn do_getuid(mgr: &mut ApeManager<'_>, pid: usize) -> Result<isize, Error> {
    Ok(load_identity(mgr, pid)?.uid as isize)
}

pub(crate) fn do_geteuid(mgr: &mut ApeManager<'_>, pid: usize) -> Result<isize, Error> {
    Ok(load_identity(mgr, pid)?.euid as isize)
}

pub(crate) fn do_getgid(mgr: &mut ApeManager<'_>, pid: usize) -> Result<isize, Error> {
    Ok(load_identity(mgr, pid)?.gid as isize)
}

pub(crate) fn do_getegid(mgr: &mut ApeManager<'_>, pid: usize) -> Result<isize, Error> {
    Ok(load_identity(mgr, pid)?.egid as isize)
}

pub(crate) fn do_sched_yield(_mgr: &mut ApeManager<'_>, _pid: usize) -> Result<isize, Error> {
    // TODO(ape): 调用底层调度让出 CPU，而非仅返回成功。
    Ok(0)
}

pub(crate) fn do_prctl(
    _mgr: &mut ApeManager<'_>,
    _pid: usize,
    _option: usize,
    _arg2: usize,
    _arg3: usize,
    _arg4: usize,
    _arg5: usize,
) -> Result<isize, Error> {
    // TODO(ape): 按 option 分发 PR_* 子命令（如 PR_SET_NAME/PR_SET_DUMPABLE）。
    Ok(0)
}

pub(crate) fn do_futex(
    _mgr: &mut ApeManager<'_>,
    _pid: usize,
    _uaddr: usize,
    futex_op: usize,
    _val: usize,
    _timeout: usize,
    _uaddr2: usize,
    _val3: usize,
) -> Result<isize, Error> {
    // TODO(ape): 实现 futex 等待队列与唤醒匹配，补齐 FUTEX_* 完整语义。
    match classify_futex_op(futex_op) {
        FutexOpClass::Wake => Ok(0),
        FutexOpClass::Wait => Ok(-(EAGAIN as isize)),
        FutexOpClass::Other => Ok(0),
    }
}
