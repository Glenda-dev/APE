use crate::ApeManager;
use glenda::error::Error;
use glenda::interface::auth::AuthService;
use glenda::protocol::auth::IdentityInfo;
use libape::policy::{FutexOpClass, classify_futex_op};
use linux_raw_sys::errno::EAGAIN;

fn load_identity(mgr: &mut ApeManager<'_>, pid: usize) -> Result<IdentityInfo, Error> {
    match mgr.auth_client.get_identity(pid) {
        Ok(identity) => {
            if let Some(task) = mgr.get_process(pid) {
                *task.cred.identity.write() = identity.clone();
            }
            Ok(identity)
        }
        Err(_) => {
            mgr.get_process(pid).map(|p| p.cred.identity.read().clone()).ok_or(Error::NotFound)
        }
    }
}

pub(crate) fn do_getrandom(
    mgr: &mut ApeManager<'_>,
    pid: usize,
    buf_ptr: usize,
    len: usize,
    _flags: usize,
) -> Result<isize, Error> {
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
    match classify_futex_op(futex_op) {
        FutexOpClass::Wake => Ok(0),
        FutexOpClass::Wait => Ok(-(EAGAIN as isize)),
        FutexOpClass::Other => Ok(0),
    }
}
