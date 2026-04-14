use crate::ApeManager;
use glenda::error::Error;
use linux_raw_sys::errno::{EINVAL, ESRCH};

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
    if target_pid != pid {
        // Minimal compatibility scope for now: only allow self setpgid.
        return Err(Error::PermissionDenied);
    }

    let (session_id, default_pgid) = {
        let proc = mgr.get_process(target_pid).ok_or(Error::NotFound)?;
        (proc.session_id, proc.pid)
    };
    let new_pgid = if pgid == 0 { default_pgid } else { pgid };

    if new_pgid != target_pid {
        let group_leader = mgr.get_process(new_pgid).ok_or(Error::NotFound)?;
        if group_leader.session_id != session_id {
            return Err(Error::PermissionDenied);
        }
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

    let pids = mgr.local_pids();
    let has_pid = |id: usize| pids.iter().any(|p| *p == id);

    let matches_group = |group_id: usize| {
        pids.iter().any(|p| {
            mgr.get_process(*p)
                .map(|proc| proc.process_group_id == group_id)
                .unwrap_or(false)
        })
    };

    let ok = if target_pid > 0 {
        has_pid(target_pid as usize)
    } else if target_pid == 0 {
        let caller_group = mgr
            .get_process(caller_pid)
            .map(|p| p.process_group_id)
            .unwrap_or(caller_pid);
        matches_group(caller_group)
    } else if target_pid == -1 {
        !pids.is_empty()
    } else {
        let target_group = (-target_pid) as usize;
        matches_group(target_group)
    };

    if !ok {
        return Ok(-(ESRCH as isize));
    }

    log!(
        "do_kill: caller_pid={}, target_pid={}, sig={} (delivery pending)",
        caller_pid,
        target_pid,
        sig
    );
    Ok(0)
}
