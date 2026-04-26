use crate::ApeManager;
use crate::ape::files::FileType;
use alloc::vec;
use core::mem::size_of;
use glenda::error::Error;
use glenda::interface::TimeService;
use glenda::ipc::Badge;
use linux_raw_sys::errno::{EINTR, EINVAL};
use linux_raw_sys::general::__kernel_timespec;
use linux_raw_sys::general::{POLLNVAL, pollfd};
use core::sync::atomic::Ordering;

const SIGSET_BYTES: usize = size_of::<u64>();
const NSEC_PER_SEC: u64 = 1_000_000_000;
const PPOLL_SLEEP_MS: usize = 4;

#[inline]
fn has_valid_sigset_size(sigsetsize: usize) -> bool {
    sigsetsize == SIGSET_BYTES
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
    let n = core::cmp::min(raw.len(), buf.len());
    raw[..n].copy_from_slice(&buf[..n]);
    Ok(u64::from_ne_bytes(raw))
}

#[inline]
fn has_deliverable_signal(mgr: &ApeManager<'_>, pid: usize) -> bool {
    mgr.get_process(pid)
        .map(|task| {
            let pending = task.signal.signal_pending.load(Ordering::SeqCst);
            let blocked = task.signal.get_blocked();
            (pending & !blocked) != 0
        })
        .unwrap_or(false)
}

fn read_user_timespec(
    mgr: &mut ApeManager<'_>,
    pid: usize,
    ptr: usize,
) -> Result<__kernel_timespec, Error> {
    if ptr == 0 {
        return Err(Error::InvalidAddress);
    }
    let mut raw = [0u8; size_of::<__kernel_timespec>()];
    mgr.copy_from_user(pid, ptr, &mut raw)?;
    Ok(unsafe { (raw.as_ptr() as *const __kernel_timespec).read_unaligned() })
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
) -> Result<Option<u64>, Error> {
    if timeout_ptr == 0 {
        return Ok(None);
    }

    let ts = read_user_timespec(mgr, pid, timeout_ptr)?;
    let timeout_ns = timespec_to_ns(ts)?;
    let now = mgr.time_client.mono_now(Badge::null())?;
    Ok(Some(now.saturating_add(timeout_ns)))
}

fn poll_scan_once(
    mgr: &mut ApeManager<'_>,
    pid: usize,
    fds_ptr: usize,
    nfds: usize,
) -> Result<usize, Error> {
    let mut ready_count = 0usize;
    for i in 0..nfds {
        let p = fds_ptr
            .checked_add(i.checked_mul(size_of::<pollfd>()).ok_or(Error::InvalidAddress)?)
            .ok_or(Error::InvalidAddress)?;

        let mut raw = [0u8; size_of::<pollfd>()];
        mgr.copy_from_user(pid, p, &mut raw)?;
        let mut pfd = unsafe { (raw.as_ptr() as *const pollfd).read_unaligned() };

        pfd.revents = 0;
        if pfd.fd >= 0 {
            let fd = pfd.fd as u32;
            let valid = {
                let task = mgr.get_process(pid).ok_or(Error::NotFound)?;
                task.files.state.read().fds.contains_key(&fd)
            };
            if !valid {
                pfd.revents = POLLNVAL as i16;
                ready_count += 1;
            } else {
                let revents = poll_fd_once(mgr, pid, fd, pfd.events as u32)?;
                pfd.revents = (revents & 0xffff) as i16;
                if revents != 0 {
                    ready_count += 1;
                }
            }
        }

        let out = unsafe {
            core::slice::from_raw_parts((&pfd as *const pollfd) as *const u8, size_of::<pollfd>())
        };
        mgr.copy_to_user(pid, p, out)?;
    }
    Ok(ready_count)
}

fn poll_fd_once(mgr: &mut ApeManager<'_>, pid: usize, fd: u32, events: u32) -> Result<u32, Error> {
    let task = mgr.get_process(pid).ok_or(Error::NotFound)?;
    let mut handle = {
        let mut files = task.files.state.write();
        files.fds.remove(&fd).ok_or(Error::InvalidSlot)?
    };

    let result = (|| match &mut handle.file_type {
        FileType::Normal(normal) => normal.poll(events),
    })();

    task.files.state.write().fds.insert(fd, handle);
    result
}

pub(crate) fn do_ppoll(
    mgr: &mut ApeManager<'_>,
    pid: usize,
    fds_ptr: usize,
    nfds: usize,
    timeout: usize,
    sigmask: usize,
    sigsetsize: usize,
) -> Result<isize, Error> {
    if nfds == 0 {
        return Ok(0);
    }
    if fds_ptr == 0 {
        return Err(Error::InvalidAddress);
    }
    if nfds > 4096 {
        return Err(Error::InvalidArgs);
    }

    let old_mask = if sigmask != 0 {
        if !has_valid_sigset_size(sigsetsize) {
            return Ok(-(EINVAL as isize));
        }
        let task = mgr.get_process(pid).ok_or(Error::NotFound)?;
        Some(task.signal.get_blocked())
    } else {
        None
    };

    if sigmask != 0 {
        let temp_mask = import_sigset(mgr, pid, sigmask, sigsetsize)?;
        if let Some(task) = mgr.get_process(pid) {
            task.signal.set_blocked(temp_mask);
        }
    }

    let result = (|| {
        let deadline = parse_timeout_deadline(mgr, pid, timeout).map_err(|_| Error::InvalidArgs)?;
        loop {
            let ready_count = poll_scan_once(mgr, pid, fds_ptr, nfds)?;
            if ready_count > 0 {
                return Ok(ready_count as isize);
            }

            if has_deliverable_signal(mgr, pid) {
                return Ok(-(EINTR as isize));
            }

            let now = mgr.time_client.mono_now(Badge::null())?;
            if let Some(deadline_ns) = deadline {
                if now >= deadline_ns {
                    return Ok(0);
                }
                let remain_ns = deadline_ns.saturating_sub(now);
                let remain_ms =
                    usize::try_from(remain_ns.div_ceil(1_000_000)).unwrap_or(usize::MAX);
                let sleep_ms = core::cmp::max(1, core::cmp::min(PPOLL_SLEEP_MS, remain_ms));
                mgr.time_client.sleep(Badge::null(), sleep_ms)?;
            } else {
                mgr.time_client.sleep(Badge::null(), PPOLL_SLEEP_MS)?;
            }
        }
    })();

    if let Some(mask) = old_mask
        && let Some(task) = mgr.get_process(pid)
    {
        task.signal.set_blocked(mask);
    }

    result
}
