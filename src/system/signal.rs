use crate::ApeManager;
use crate::ape::signal::{SIGNAL_MAX, SIGNAL_UNBLOCKABLE_MASK, SignalAction};
use crate::ape::task::{TaskLifecycleState, TaskStruct};
use crate::ape::utils::linux_conv::get_exit_code_for_signal;
use alloc::vec;
use alloc::vec::Vec;
use core::cmp::min;
use core::mem::size_of;
use core::sync::atomic::Ordering;
use glenda::error::Error;
use glenda::interface::TimeService;
use glenda::ipc::Badge;
use linux_raw_sys::errno::{EAGAIN, EINTR, EINVAL};
use linux_raw_sys::general::{
    __kernel_timespec, SA_RESTART, SIG_BLOCK, SIG_SETMASK, SIG_UNBLOCK, SIGCHLD, SIGCONT, SIGKILL,
    SIGSTOP, SIGTSTP, SIGTTIN, SIGTTOU, SIGURG, SIGWINCH,
};

const SIGACTION_HEAD_WORDS: usize = 3;
const SIGACTION_HEAD_LEN: usize = size_of::<usize>() * SIGACTION_HEAD_WORDS;
const SIGINFO_COMPAT_SIZE: usize = 128;
const SIGSET_BYTES: usize = size_of::<u64>();
const NSEC_PER_SEC: u64 = 1_000_000_000;
const SIGNAL_WAIT_POLL_MS: usize = 1;
const SIGNAL_WAIT_FALLBACK_NS: u64 = 2 * NSEC_PER_SEC;
const SIG_DFL_HANDLER: usize = 0;
const SIG_IGN_HANDLER: usize = 1;

#[inline]
fn encode_wait_stopped_status(sig: usize) -> i32 {
    ((sig as i32) << 8) | 0x7f
}

pub(crate) enum PendingSignalAction {
    None,
    Interrupt { restart: bool },
    Terminate(usize),
}

#[inline]
fn is_valid_signal(signum: usize) -> bool {
    (1..=SIGNAL_MAX).contains(&signum)
}

#[inline]
fn has_valid_sigset_size(sigsetsize: usize) -> bool {
    sigsetsize == SIGSET_BYTES
}

#[inline]
fn default_ignored_signal(signum: usize) -> bool {
    signum == SIGCHLD as usize || signum == SIGURG as usize || signum == SIGWINCH as usize
}

#[inline]
fn default_stop_signal(signum: usize) -> bool {
    signum == SIGSTOP as usize
        || signum == SIGTSTP as usize
        || signum == SIGTTIN as usize
        || signum == SIGTTOU as usize
}

#[inline]
fn read_usize_from(bytes: &[u8], start: usize) -> Result<usize, Error> {
    let end = start.checked_add(size_of::<usize>()).ok_or(Error::OutOfMemory)?;
    if end > bytes.len() {
        return Err(Error::InvalidArgs);
    }
    let mut raw = [0u8; size_of::<usize>()];
    raw.copy_from_slice(&bytes[start..end]);
    Ok(usize::from_ne_bytes(raw))
}

#[inline]
fn write_usize_to(bytes: &mut [u8], start: usize, value: usize) -> Result<(), Error> {
    let end = start.checked_add(size_of::<usize>()).ok_or(Error::OutOfMemory)?;
    if end > bytes.len() {
        return Err(Error::InvalidArgs);
    }
    bytes[start..end].copy_from_slice(&value.to_ne_bytes());
    Ok(())
}

fn import_sigset(
    mgr: &mut ApeManager<'_>,
    pid: usize,
    user_ptr: usize,
    sigsetsize: usize,
) -> Result<u64, Error> {
    if !has_valid_sigset_size(sigsetsize) {
        return Err(Error::InvalidArgs);
    }
    if user_ptr == 0 {
        return Err(Error::InvalidAddress);
    }

    let mut buf = vec![0u8; sigsetsize];
    mgr.copy_from_user(pid, user_ptr, &mut buf)?;

    let mut raw = [0u8; size_of::<u64>()];
    let n = min(raw.len(), buf.len());
    raw[..n].copy_from_slice(&buf[..n]);
    Ok(u64::from_ne_bytes(raw))
}

fn export_sigset(mask: u64, sigsetsize: usize) -> Result<Vec<u8>, Error> {
    if !has_valid_sigset_size(sigsetsize) {
        return Err(Error::InvalidArgs);
    }

    let mut out = vec![0u8; sigsetsize];
    let raw = mask.to_ne_bytes();
    let n = min(raw.len(), out.len());
    out[..n].copy_from_slice(&raw[..n]);
    Ok(out)
}

fn read_user_timespec(
    mgr: &mut ApeManager<'_>,
    pid: usize,
    ptr: usize,
) -> Result<__kernel_timespec, Error> {
    let mut raw = [0u8; size_of::<__kernel_timespec>()];
    mgr.copy_from_user(pid, ptr, &mut raw)?;
    Ok(unsafe { (raw.as_ptr() as *const __kernel_timespec).read_unaligned() })
}

#[inline]
fn mono_now_ns(mgr: &mut ApeManager<'_>) -> Result<u64, Error> {
    mgr.time_client.mono_now(Badge::null())
}

#[inline]
fn wait_tick(mgr: &mut ApeManager<'_>) {
    if mgr.time_client.sleep(Badge::null(), SIGNAL_WAIT_POLL_MS).is_err() {
        core::hint::spin_loop();
    }
}

#[inline]
fn timespec_to_ns(ts: __kernel_timespec) -> Result<u64, Error> {
    if ts.tv_sec < 0 || !(0..1_000_000_000).contains(&ts.tv_nsec) {
        return Err(Error::InvalidArgs);
    }
    let sec = ts.tv_sec as u64;
    let nsec = ts.tv_nsec as u64;
    sec.checked_mul(NSEC_PER_SEC).and_then(|v| v.checked_add(nsec)).ok_or(Error::OutOfMemory)
}

fn parse_timeout_deadline(
    mgr: &mut ApeManager<'_>,
    pid: usize,
    timeout_ptr: usize,
) -> Result<u64, Error> {
    let now = mono_now_ns(mgr)?;
    if timeout_ptr == 0 {
        return Ok(now.saturating_add(SIGNAL_WAIT_FALLBACK_NS));
    }

    let ts = read_user_timespec(mgr, pid, timeout_ptr)?;
    let timeout_ns = timespec_to_ns(ts)?;
    Ok(now.saturating_add(timeout_ns))
}

fn read_sigaction(
    mgr: &mut ApeManager<'_>,
    pid: usize,
    act: usize,
    sigsetsize: usize,
) -> Result<SignalAction, Error> {
    if act == 0 {
        return Err(Error::InvalidAddress);
    }

    let total = SIGACTION_HEAD_LEN.checked_add(sigsetsize).ok_or(Error::OutOfMemory)?;
    let mut raw = vec![0u8; total];
    mgr.copy_from_user(pid, act, &mut raw)?;

    let handler = read_usize_from(&raw, 0)?;
    let flags = read_usize_from(&raw, size_of::<usize>())?;
    let restorer = read_usize_from(&raw, size_of::<usize>() * 2)?;

    let mut mask_bytes = [0u8; size_of::<u64>()];
    let body = &raw[SIGACTION_HEAD_LEN..];
    let n = min(mask_bytes.len(), body.len());
    mask_bytes[..n].copy_from_slice(&body[..n]);

    Ok(SignalAction { handler, flags, restorer, mask: u64::from_ne_bytes(mask_bytes) })
}

fn write_sigaction(
    mgr: &mut ApeManager<'_>,
    pid: usize,
    oldact: usize,
    action: SignalAction,
    sigsetsize: usize,
) -> Result<(), Error> {
    if oldact == 0 {
        return Ok(());
    }

    let total = SIGACTION_HEAD_LEN.checked_add(sigsetsize).ok_or(Error::OutOfMemory)?;
    let mut out = vec![0u8; total];
    write_usize_to(&mut out, 0, action.handler)?;
    write_usize_to(&mut out, size_of::<usize>(), action.flags)?;
    write_usize_to(&mut out, size_of::<usize>() * 2, action.restorer)?;

    let mask_raw = action.mask.to_ne_bytes();
    let body = &mut out[SIGACTION_HEAD_LEN..];
    let n = min(mask_raw.len(), body.len());
    body[..n].copy_from_slice(&mask_raw[..n]);

    mgr.copy_to_user(pid, oldact, &out)
}

pub(crate) fn queue_process_signal(mgr: &mut ApeManager<'_>, pid: usize, signum: usize) -> bool {
    let (should_wake, should_interrupt_sleep) = {
        let Some(task) = mgr.get_process(pid) else {
            return false;
        };
        if !task.signal.queue_signal(signum) {
            return false;
        }
        let pending = task.signal.signal_pending.load(Ordering::SeqCst);
        let blocked = task.signal.get_blocked();
        let deliverable = (pending & !blocked) != 0;
        (task.signal.is_waiting_sigsuspend() && deliverable, deliverable)
    };

    if should_interrupt_sleep {
        let _ = mgr.interrupt_pending_sleep_reply(pid);
    }

    if should_wake {
        let restored = {
            let Some(task) = mgr.get_process(pid) else {
                return true;
            };
            let pending = task.signal.signal_pending.load(Ordering::SeqCst);
            let blocked = task.signal.get_blocked();
            if task.signal.is_waiting_sigsuspend() && (pending & !blocked) != 0 {
                task.signal.restore_mask_from_sigsuspend_wait()
            } else {
                false
            }
        };

        if restored
            && let Some(task) = mgr.get_process(pid)
            && let Err(e) = task.tcb().resume()
        {
            warn!("signal: failed to resume pid={} from sigsuspend wait: {:?}", pid, e);
        }
    }

    true
}

pub(crate) fn consume_deliverable_signal_on_syscall_return(
    mgr: &mut ApeManager<'_>,
    pid: usize,
) -> Result<PendingSignalAction, Error> {
    let (signum, action) = {
        let Some(task) = mgr.get_process(pid) else {
            return Ok(PendingSignalAction::None);
        };
        let pending = task.signal.signal_pending.load(Ordering::SeqCst);
        let blocked = task.signal.get_blocked();
        let deliverable = pending & !blocked;
        let Some(signum) = task.signal.pop_pending_signal_from_mask(deliverable) else {
            return Ok(PendingSignalAction::None);
        };
        (signum, task.signal.signal_action(&task.sighand, signum))
    };

    if action.handler == SIG_IGN_HANDLER {
        return Ok(PendingSignalAction::None);
    }

    if action.handler != SIG_DFL_HANDLER {
        let tcb = mgr.get_process(pid).ok_or(Error::NotFound)?.tcb();
        if let Err(e) = tcb.deliver_upcall(action.handler, signum, 0, 0, 0) {
            warn!(
                "signal: failed to deliver handler pid={} signo={} handler={:#x}: {:?}",
                pid, signum, action.handler, e
            );
        }
        let restart = (action.flags & SA_RESTART as usize) != 0;
        return Ok(PendingSignalAction::Interrupt { restart });
    }

    if default_ignored_signal(signum) {
        return Ok(PendingSignalAction::None);
    }

    if default_stop_signal(signum) {
        let transition = mgr.get_process(pid).map(|task| {
            (
                task.parent_pid.load(Ordering::SeqCst),
                task.process_group_id.load(Ordering::SeqCst),
                task.is_stopped(),
            )
        });
        let tcb = mgr.get_process(pid).ok_or(Error::NotFound)?.tcb();
        if tcb.suspend().is_ok()
            && let Some(task) = mgr.get_process(pid)
        {
            task.mark_stopped();
        }
        if let Some((parent_pid, pgid, was_stopped)) = transition
            && parent_pid != 0
            && !was_stopped
        {
            mgr.record_child_stopped(parent_pid, pid, encode_wait_stopped_status(signum), pgid);
        }
        return Ok(PendingSignalAction::Interrupt { restart: false });
    }

    if signum == SIGCONT as usize {
        let transition = mgr.get_process(pid).map(|task| {
            (
                task.parent_pid.load(Ordering::SeqCst),
                task.process_group_id.load(Ordering::SeqCst),
                task.is_stopped(),
            )
        });
        let tcb = mgr.get_process(pid).ok_or(Error::NotFound)?.tcb();
        if tcb.resume().is_ok()
            && let Some(task) = mgr.get_process(pid)
        {
            task.mark_running();
        }
        if let Some((parent_pid, pgid, was_stopped)) = transition
            && parent_pid != 0
            && was_stopped
        {
            mgr.record_child_continued(parent_pid, pid, pgid);
        }
        return Ok(PendingSignalAction::None);
    }

    Ok(PendingSignalAction::Terminate(get_exit_code_for_signal(signum as u32)))
}

pub(crate) fn do_rt_sigaction(
    mgr: &mut ApeManager<'_>,
    pid: usize,
    signum: usize,
    act: usize,
    oldact: usize,
    sigsetsize: usize,
) -> Result<isize, Error> {
    if !is_valid_signal(signum) || !has_valid_sigset_size(sigsetsize) {
        return Ok(-(EINVAL as isize));
    }

    let old = if oldact != 0 {
        let task = mgr.get_process(pid).ok_or(Error::NotFound)?;
        Some(task.signal.signal_action(&task.sighand, signum))
    } else {
        None
    };

    if oldact != 0 {
        write_sigaction(mgr, pid, oldact, old.unwrap_or_default(), sigsetsize)?;
    }

    if act != 0 {
        if signum == SIGKILL as usize || signum == SIGSTOP as usize {
            return Ok(-(EINVAL as isize));
        }

        let mut new_action = read_sigaction(mgr, pid, act, sigsetsize)?;
        new_action.mask &= !SIGNAL_UNBLOCKABLE_MASK;

        let task = mgr.get_process(pid).ok_or(Error::NotFound)?;
        task.sighand.signal_actions.lock().insert(signum, new_action);
    }

    Ok(0)
}

pub(crate) fn do_rt_sigprocmask(
    mgr: &mut ApeManager<'_>,
    pid: usize,
    how: usize,
    set: usize,
    oldset: usize,
    sigsetsize: usize,
) -> Result<isize, Error> {
    if !has_valid_sigset_size(sigsetsize) {
        return Ok(-(EINVAL as isize));
    }

    let old_mask = if oldset != 0 {
        let task = mgr.get_process(pid).ok_or(Error::NotFound)?;
        Some(task.signal.get_blocked())
    } else {
        None
    };

    if set != 0 {
        let set_mask = import_sigset(mgr, pid, set, sigsetsize)?;
        let task = mgr.get_process(pid).ok_or(Error::NotFound)?;

        match how as u32 {
            SIG_BLOCK => task.signal.set_blocked(task.signal.get_blocked() | set_mask),
            SIG_UNBLOCK => task.signal.set_blocked(task.signal.get_blocked() & !set_mask),
            SIG_SETMASK => task.signal.set_blocked(set_mask),
            _ => return Ok(-(EINVAL as isize)),
        }
    }

    if oldset != 0 {
        let out = export_sigset(old_mask.unwrap_or(0), sigsetsize)?;
        mgr.copy_to_user(pid, oldset, &out)?;
    }

    Ok(0)
}

pub(crate) fn do_rt_sigpending(
    mgr: &mut ApeManager<'_>,
    pid: usize,
    set: usize,
    sigsetsize: usize,
) -> Result<isize, Error> {
    if !has_valid_sigset_size(sigsetsize) {
        return Ok(-(EINVAL as isize));
    }
    if set == 0 {
        return Err(Error::InvalidAddress);
    }

    let pending = {
        let task = mgr.get_process(pid).ok_or(Error::NotFound)?;
        let pending_bits = task.signal.signal_pending.load(Ordering::SeqCst);
        let blocked = task.signal.get_blocked();
        pending_bits & blocked
    };
    let out = export_sigset(pending, sigsetsize)?;
    mgr.copy_to_user(pid, set, &out)?;

    Ok(0)
}

pub(crate) fn do_rt_sigtimedwait(
    mgr: &mut ApeManager<'_>,
    pid: usize,
    set: usize,
    info: usize,
    timeout: usize,
    sigsetsize: usize,
) -> Result<isize, Error> {
    if !has_valid_sigset_size(sigsetsize) {
        return Ok(-(EINVAL as isize));
    }

    let wait_mask = import_sigset(mgr, pid, set, sigsetsize)?;
    if wait_mask == 0 {
        return Ok(-(EAGAIN as isize));
    }

    let deadline = parse_timeout_deadline(mgr, pid, timeout).map_err(|_| Error::InvalidArgs)?;
    let signum = loop {
        let candidate = {
            let task = mgr.get_process(pid).ok_or(Error::NotFound)?;
            task.signal.pop_pending_signal_from_mask(wait_mask)
        };

        if let Some(signum) = candidate {
            break signum;
        }

        if mono_now_ns(mgr)? >= deadline {
            return Ok(-(EAGAIN as isize));
        }

        wait_tick(mgr);
    };

    if info != 0 {
        let signo = i32::try_from(signum).map_err(|_| Error::InvalidArgs)?;
        mgr.copy_to_user(pid, info, &signo.to_ne_bytes())?;
        if SIGINFO_COMPAT_SIZE > size_of::<i32>() {
            let tail = info.checked_add(size_of::<i32>()).ok_or(Error::OutOfMemory)?;
            mgr.write_zeros_to_user(pid, tail, SIGINFO_COMPAT_SIZE - size_of::<i32>())?;
        }
    }

    Ok(signum as isize)
}

pub(crate) fn do_rt_sigsuspend(
    mgr: &mut ApeManager<'_>,
    pid: usize,
    mask: usize,
    sigsetsize: usize,
) -> Result<isize, Error> {
    if !has_valid_sigset_size(sigsetsize) {
        return Ok(-(EINVAL as isize));
    }

    let mut suspend_mask = import_sigset(mgr, pid, mask, sigsetsize)?;
    suspend_mask &= !SIGNAL_UNBLOCKABLE_MASK;

    let old_mask = {
        let task = mgr.get_process(pid).ok_or(Error::NotFound)?;
        task.signal.get_blocked()
    };

    let observed_signal = {
        let task = mgr.get_process(pid).ok_or(Error::NotFound)?;
        task.signal.set_blocked(suspend_mask);
        let pending = task.signal.signal_pending.load(Ordering::SeqCst);
        let deliverable = pending & !task.signal.get_blocked();
        let observed = task.signal.pop_pending_signal_from_mask(deliverable);
        if observed.is_some() {
            task.signal.set_blocked(old_mask);
        } else {
            task.signal.arm_sigsuspend_wait(old_mask);
        }
        observed
    };

    if let Some(signum) = observed_signal {
        return Ok(-(EINTR as isize));
    }

    let tcb = mgr.get_process(pid).ok_or(Error::NotFound)?.tcb();
    if let Err(e) = tcb.suspend() {
        if let Some(task) = mgr.get_process(pid) {
            let _ = task.signal.restore_mask_from_sigsuspend_wait();
        }
    }

    Ok(-(EINTR as isize))
}

pub(crate) fn do_rt_sigreturn(mgr: &mut ApeManager<'_>, pid: usize) -> Result<isize, Error> {
    if let Some(task) = mgr.get_process(pid) {
        let _ = task.signal.restore_mask_from_sigsuspend_wait();
    }
    Ok(0)
}

pub(crate) fn do_set_robust_list(
    _mgr: &mut ApeManager<'_>,
    _pid: usize,
    _head: usize,
    _len: usize,
) -> Result<isize, Error> {
    Ok(0)
}
