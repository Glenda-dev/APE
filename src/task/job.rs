use crate::ApeManager;
use crate::ape::process::{SIGNAL_MAX, signal_bit};
use crate::ape::utils::linux_conv::get_exit_code_for_signal;
use glenda::error::Error;
use linux_raw_sys::errno::{EINVAL, ESRCH};
use linux_raw_sys::general::{SIGCONT, SIGKILL, SIGSTOP, SIGTSTP, SIGTTIN, SIGTTOU};

#[inline]
fn is_stop_signal(sig: usize) -> bool {
    sig == SIGSTOP as usize
        || sig == SIGTSTP as usize
        || sig == SIGTTIN as usize
        || sig == SIGTTOU as usize
}

pub(crate) fn do_setsid(mgr: &mut ApeManager<'_>, pid: usize) -> Result<usize, Error> {
    let proc = mgr.get_process(pid).ok_or(Error::NotFound)?;
    if proc.process_group_id == pid {
        return Err(Error::PermissionDenied);
    }

    let proc = mgr.get_process_mut(pid).ok_or(Error::NotFound)?;
    proc.session_id = pid;
    proc.process_group_id = pid;
    proc.controlling_tty = None;
    Ok(pid)
}

pub(crate) fn do_getsid(
    mgr: &mut ApeManager<'_>,
    pid: usize,
    target: usize,
) -> Result<usize, Error> {
    let target_pid = if target == 0 { pid } else { target };
    let target_proc = mgr.get_process(target_pid).ok_or(Error::NotFound)?;
    Ok(target_proc.session_id)
}

pub(crate) fn do_setpgid(
    mgr: &mut ApeManager<'_>,
    pid: usize,
    target: usize,
    pgid: usize,
) -> Result<isize, Error> {
    let target_pid = if target == 0 { pid } else { target };
    let caller = mgr.get_process(pid).ok_or(Error::NotFound)?;
    let caller_session = caller.session_id;
    let caller_pgid = caller.process_group_id;

    let (target_session_id, default_pgid, target_parent_pid) = {
        let proc = mgr.get_process(target_pid).ok_or(Error::NotFound)?;
        (proc.session_id, proc.pid, proc.parent_pid)
    };

    if target_pid != pid {
        if target_parent_pid != pid || target_session_id != caller_session {
            return Err(Error::PermissionDenied);
        }
    }

    let new_pgid = if pgid == 0 { default_pgid } else { pgid };

    if new_pgid != target_pid {
        let group_leader = mgr.get_process(new_pgid).ok_or(Error::NotFound)?;
        if group_leader.session_id != target_session_id {
            return Err(Error::PermissionDenied);
        }
    }

    if target_pid == pid && new_pgid == caller_pgid {
        return Ok(0);
    }

    let proc = mgr.get_process_mut(target_pid).ok_or(Error::NotFound)?;
    proc.process_group_id = new_pgid;
    Ok(0)
}

pub(crate) fn do_getpgid(
    mgr: &mut ApeManager<'_>,
    pid: usize,
    target_pid: usize,
) -> Result<usize, Error> {
    let target = if target_pid == 0 { pid } else { target_pid };
    let proc = mgr.get_process(target).ok_or(Error::NotFound)?;
    Ok(proc.process_group_id)
}

pub(crate) fn do_kill(
    mgr: &mut ApeManager<'_>,
    caller_pid: usize,
    target_pid: isize,
    sig: isize,
) -> Result<isize, Error> {
    if sig < 0 {
        return Ok(-(EINVAL as isize));
    }

    let sig_num = sig as usize;
    if sig_num > SIGNAL_MAX {
        return Ok(-(EINVAL as isize));
    }

    let pids = mgr.local_pids();
    let mut targets = alloc::vec::Vec::new();

    if target_pid > 0 {
        let target = target_pid as usize;
        if pids.iter().any(|p| *p == target) {
            targets.push(target);
        }
    } else if target_pid == 0 {
        let caller_group =
            mgr.get_process(caller_pid).map(|p| p.process_group_id).unwrap_or(caller_pid);
        for pid in pids {
            if mgr
                .get_process(pid)
                .map(|proc| proc.process_group_id == caller_group)
                .unwrap_or(false)
            {
                targets.push(pid);
            }
        }
    } else if target_pid == -1 {
        targets = pids;
    } else {
        let target_group = (-target_pid) as usize;
        for pid in pids {
            if mgr
                .get_process(pid)
                .map(|proc| proc.process_group_id == target_group)
                .unwrap_or(false)
            {
                targets.push(pid);
            }
        }
    }

    if targets.is_empty() {
        return Ok(-(ESRCH as isize));
    }

    if sig_num != 0 {
        if sig_num == SIGKILL as usize {
            for target in targets.iter().copied().filter(|target| *target != caller_pid) {
                mgr.terminate_process_preserve_reply(
                    target,
                    get_exit_code_for_signal(SIGKILL),
                    false,
                )?;
            }

            if targets.iter().any(|target| *target == caller_pid) {
                mgr.terminate_process(caller_pid, get_exit_code_for_signal(SIGKILL), false)?;
            }

            log!(
                "do_kill: caller_pid={}, target_pid={}, sig={} (SIGKILL immediate), targets={}",
                caller_pid,
                target_pid,
                sig,
                targets.len()
            );
            return Ok(0);
        }

        if sig_num == SIGCONT as usize {
            for target in targets.iter().copied() {
                if let Some(proc) = mgr.get_process_mut(target) {
                    // SIGCONT 会清理 stop 类 pending。
                    for stop_sig in
                        [SIGSTOP as usize, SIGTSTP as usize, SIGTTIN as usize, SIGTTOU as usize]
                    {
                        if let Some(bit) = signal_bit(stop_sig) {
                            proc.signal_pending &= !bit;
                        }
                    }
                    proc.stopped = false;
                    let _ = proc.queue_signal(sig_num);
                    let _ = proc.tcb().resume();
                }
            }
            return Ok(0);
        }

        if is_stop_signal(sig_num) {
            for target in targets.iter().copied() {
                if let Some(proc) = mgr.get_process_mut(target) {
                    let _ = proc.queue_signal(sig_num);
                    if target != caller_pid {
                        let _ = proc.tcb().suspend();
                        proc.stopped = true;
                    }
                }
            }
            return Ok(0);
        }

        for target in targets.iter().copied() {
            if let Some(proc) = mgr.get_process_mut(target) {
                let _ = proc.queue_signal(sig_num);
            }
        }
    }

    log!(
        "do_kill: caller_pid={}, target_pid={}, sig={}, targets={}",
        caller_pid,
        target_pid,
        sig,
        targets.len()
    );
    Ok(0)
}
