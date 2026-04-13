use crate::ApeManager;
use glenda::error::Error;
use linux_raw_sys::errno::EAGAIN;
use linux_raw_sys::general::{
    FUTEX_CMD_MASK, FUTEX_WAIT, FUTEX_WAIT_BITSET, FUTEX_WAIT_BITSET_PRIVATE, FUTEX_WAIT_PRIVATE,
    FUTEX_WAKE, FUTEX_WAKE_PRIVATE,
};

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

pub(crate) fn do_getuid(_mgr: &mut ApeManager<'_>, _pid: usize) -> Result<isize, Error> {
    // TODO(ape): 接入进程凭据，返回真实 uid。
    Ok(0)
}

pub(crate) fn do_geteuid(_mgr: &mut ApeManager<'_>, _pid: usize) -> Result<isize, Error> {
    // TODO(ape): 接入进程凭据，返回真实 euid。
    Ok(0)
}

pub(crate) fn do_getgid(_mgr: &mut ApeManager<'_>, _pid: usize) -> Result<isize, Error> {
    // TODO(ape): 接入进程凭据，返回真实 gid。
    Ok(0)
}

pub(crate) fn do_getegid(_mgr: &mut ApeManager<'_>, _pid: usize) -> Result<isize, Error> {
    // TODO(ape): 接入进程凭据，返回真实 egid。
    Ok(0)
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
    let cmd = futex_op & FUTEX_CMD_MASK as usize;
    match cmd as u32 {
        FUTEX_WAKE | FUTEX_WAKE_PRIVATE => Ok(0),
        FUTEX_WAIT | FUTEX_WAIT_PRIVATE | FUTEX_WAIT_BITSET | FUTEX_WAIT_BITSET_PRIVATE => {
            Ok(-(EAGAIN as isize))
        }
        _ => Ok(0),
    }
}
