use crate::ApeManager;
use core::cmp::min;
use core::mem::size_of;
use core::sync::atomic::Ordering;
use glenda::error::Error;
use glenda::interface::TimeService;
use glenda::ipc::Badge;
use libape::version::*;
use linux_raw_sys::ctypes::c_char;
use linux_raw_sys::ctypes::c_long;
use linux_raw_sys::errno::{EINTR, EINVAL};
use linux_raw_sys::general::{
    __kernel_timespec, CLOCK_BOOTTIME, CLOCK_BOOTTIME_ALARM, CLOCK_MONOTONIC,
    CLOCK_MONOTONIC_COARSE, CLOCK_MONOTONIC_RAW, CLOCK_PROCESS_CPUTIME_ID, CLOCK_REALTIME,
    CLOCK_REALTIME_ALARM, CLOCK_REALTIME_COARSE, CLOCK_TAI, CLOCK_THREAD_CPUTIME_ID,
    RLIM64_INFINITY, rlimit64, timeval,
};
use linux_raw_sys::system::{__NEW_UTS_LEN, new_utsname};

const UTS_STR_LEN: usize = (__NEW_UTS_LEN as usize) + 1;
const NSEC_PER_SEC: u64 = 1_000_000_000;
const NSEC_PER_USEC: u64 = 1_000;
const TIMES_CLK_TCK: u64 = 100;

#[repr(C)]
#[derive(Clone, Copy, Default)]
struct LinuxTms {
    tms_utime: c_long,
    tms_stime: c_long,
    tms_cutime: c_long,
    tms_cstime: c_long,
}

#[inline]
fn ns_to_timespec(ns: u64) -> __kernel_timespec {
    __kernel_timespec {
        tv_sec: i64::try_from(ns / NSEC_PER_SEC).unwrap_or(i64::MAX),
        tv_nsec: i64::try_from(ns % NSEC_PER_SEC).unwrap_or(0),
    }
}

#[inline]
fn ns_to_timeval(ns: u64) -> timeval {
    timeval {
        tv_sec: i64::try_from(ns / NSEC_PER_SEC).unwrap_or(i64::MAX),
        tv_usec: i64::try_from((ns % NSEC_PER_SEC) / NSEC_PER_USEC).unwrap_or(0),
    }
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

fn timespec_to_ns(ts: __kernel_timespec) -> Result<u64, Error> {
    if ts.tv_sec < 0 || !(0..1_000_000_000).contains(&ts.tv_nsec) {
        return Err(Error::InvalidArgs);
    }

    let sec = ts.tv_sec as u64;
    let nsec = ts.tv_nsec as u64;
    sec.checked_mul(NSEC_PER_SEC).and_then(|v| v.checked_add(nsec)).ok_or(Error::OutOfMemory)
}

#[inline]
fn select_clock_source(clockid: usize) -> Option<bool> {
    Some(match clockid as u32 {
        CLOCK_REALTIME | CLOCK_REALTIME_COARSE | CLOCK_REALTIME_ALARM | CLOCK_TAI => true,
        CLOCK_MONOTONIC
        | CLOCK_MONOTONIC_RAW
        | CLOCK_MONOTONIC_COARSE
        | CLOCK_BOOTTIME
        | CLOCK_BOOTTIME_ALARM
        | CLOCK_PROCESS_CPUTIME_ID
        | CLOCK_THREAD_CPUTIME_ID => false,
        _ => return None,
    })
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

fn write_cstr(dst: &mut [c_char; UTS_STR_LEN], src: &str) {
    dst.fill(0 as c_char);
    let bytes = src.as_bytes();
    let n = min(bytes.len(), UTS_STR_LEN.saturating_sub(1));
    for (i, b) in bytes[..n].iter().enumerate() {
        dst[i] = *b as c_char;
    }
}

pub(crate) fn do_uname(
    mgr: &mut ApeManager<'_>,
    pid: usize,
    buf_ptr: usize,
) -> Result<isize, Error> {
    let mut uts = new_utsname {
        sysname: [0; UTS_STR_LEN],
        nodename: [0; UTS_STR_LEN],
        release: [0; UTS_STR_LEN],
        version: [0; UTS_STR_LEN],
        machine: [0; UTS_STR_LEN],
        domainname: [0; UTS_STR_LEN],
    };

    write_cstr(&mut uts.sysname, SYSNAME);
    write_cstr(&mut uts.nodename, NODENAME);
    write_cstr(&mut uts.release, RELEASE);
    write_cstr(&mut uts.version, VERSION);
    write_cstr(&mut uts.machine, MACHINE);
    write_cstr(&mut uts.domainname, DOMAINNAME);

    mgr.write_obj_to_user(pid, buf_ptr, &uts)?;
    Ok(0)
}

pub(crate) fn do_prlimit64(
    mgr: &mut ApeManager<'_>,
    pid: usize,
    _target_pid: usize,
    _resource: usize,
    _new_limit: usize,
    old_limit: usize,
) -> Result<isize, Error> {
    if old_limit != 0 {
        let lim = rlimit64 { rlim_cur: RLIM64_INFINITY as u64, rlim_max: RLIM64_INFINITY as u64 };
        mgr.write_obj_to_user(pid, old_limit, &lim)?;
    }
    Ok(0)
}

pub(crate) fn do_clock_gettime(
    mgr: &mut ApeManager<'_>,
    pid: usize,
    clockid: usize,
    tp: usize,
) -> Result<isize, Error> {
    if tp == 0 {
        return Err(Error::InvalidAddress);
    }

    let Some(use_realtime) = select_clock_source(clockid) else {
        return Ok(-(EINVAL as isize));
    };
    let ns = if use_realtime {
        mgr.time_client.time_now(Badge::null())?
    } else {
        mgr.time_client.mono_now(Badge::null())?
    };

    let ts = ns_to_timespec(ns);
    mgr.write_obj_to_user(pid, tp, &ts)?;
    Ok(0)
}

pub(crate) fn do_gettimeofday(
    mgr: &mut ApeManager<'_>,
    pid: usize,
    tv: usize,
    _tz: usize,
) -> Result<isize, Error> {
    if tv != 0 {
        let ns = mgr.time_client.time_now(Badge::null())?;
        let tv_obj = ns_to_timeval(ns);
        mgr.write_obj_to_user(pid, tv, &tv_obj)?;
    }
    Ok(0)
}

pub(crate) fn do_times(
    mgr: &mut ApeManager<'_>,
    pid: usize,
    tms_ptr: usize,
) -> Result<isize, Error> {
    let mono_ns = mgr.time_client.mono_now(Badge::null())?;
    let ticks = mono_ns
        .checked_mul(TIMES_CLK_TCK)
        .and_then(|v| v.checked_div(NSEC_PER_SEC))
        .unwrap_or(u64::MAX);

    if tms_ptr != 0 {
        let tms = LinuxTms::default();
        mgr.write_obj_to_user(pid, tms_ptr, &tms)?;
    }

    Ok(i64::try_from(ticks).unwrap_or(i64::MAX) as isize)
}

pub(crate) fn do_nanosleep(
    mgr: &mut ApeManager<'_>,
    pid: usize,
    req: usize,
    rem: usize,
) -> Result<isize, Error> {
    let req_ts = read_user_timespec(mgr, pid, req)?;
    let req_ns = timespec_to_ns(req_ts).map_err(|_| Error::InvalidArgs)?;
    if req_ns == 0 {
        if rem != 0 {
            let zero = __kernel_timespec { tv_sec: 0, tv_nsec: 0 };
            mgr.write_obj_to_user(pid, rem, &zero)?;
        }
        return Ok(0);
    }
    if has_deliverable_signal(mgr, pid) {
        if rem != 0 {
            mgr.write_obj_to_user(pid, rem, &req_ts)?;
        }
        return Ok(-(EINTR as isize));
    }

    mgr.schedule_nanosleep_async(pid, req_ns, rem)?;
    Err(Error::Success)
}
