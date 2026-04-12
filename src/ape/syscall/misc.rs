use crate::ApeManager;
use alloc::vec;
use core::cmp::min;
use core::mem::size_of;
use glenda::error::Error;

const UTS_STR_LEN: usize = 65;

#[repr(C)]
struct UtsName {
    sysname: [u8; UTS_STR_LEN],
    nodename: [u8; UTS_STR_LEN],
    release: [u8; UTS_STR_LEN],
    version: [u8; UTS_STR_LEN],
    machine: [u8; UTS_STR_LEN],
    domainname: [u8; UTS_STR_LEN],
}

#[repr(C)]
struct TimeSpec {
    tv_sec: i64,
    tv_nsec: i64,
}

#[repr(C)]
struct TimeVal {
    tv_sec: i64,
    tv_usec: i64,
}

#[repr(C)]
struct RLimit64 {
    rlim_cur: u64,
    rlim_max: u64,
}

fn write_cstr(dst: &mut [u8; UTS_STR_LEN], src: &str) {
    dst.fill(0);
    let bytes = src.as_bytes();
    let n = min(bytes.len(), UTS_STR_LEN.saturating_sub(1));
    dst[..n].copy_from_slice(&bytes[..n]);
}

fn write_obj_to_user<'a, T>(
    mgr: &mut ApeManager<'a>,
    pid: usize,
    user_ptr: usize,
    obj: &T,
) -> Result<(), Error> {
    let bytes =
        unsafe { core::slice::from_raw_parts((obj as *const T) as *const u8, size_of::<T>()) };
    mgr.copy_to_user(pid, user_ptr, bytes)
}

fn write_zeros_to_user<'a>(
    mgr: &mut ApeManager<'a>,
    pid: usize,
    user_ptr: usize,
    len: usize,
) -> Result<(), Error> {
    if user_ptr == 0 || len == 0 {
        return Ok(());
    }

    let mut done = 0usize;
    let zeros = [0u8; 64];
    while done < len {
        let chunk = min(len - done, zeros.len());
        mgr.copy_to_user(pid, user_ptr + done, &zeros[..chunk])?;
        done += chunk;
    }
    Ok(())
}

pub fn sys_uname<'a>(mgr: &mut ApeManager<'a>, pid: usize, buf_ptr: usize) -> Result<isize, Error> {
    let mut uts = UtsName {
        sysname: [0; UTS_STR_LEN],
        nodename: [0; UTS_STR_LEN],
        release: [0; UTS_STR_LEN],
        version: [0; UTS_STR_LEN],
        machine: [0; UTS_STR_LEN],
        domainname: [0; UTS_STR_LEN],
    };

    write_cstr(&mut uts.sysname, "Glenda");
    write_cstr(&mut uts.nodename, "glenda");
    write_cstr(&mut uts.release, "0.1.0");
    write_cstr(&mut uts.version, "Glenda Microkernel");
    write_cstr(&mut uts.machine, "riscv64");
    write_cstr(&mut uts.domainname, "localdomain");

    write_obj_to_user(mgr, pid, buf_ptr, &uts)?;
    Ok(0)
}

pub fn sys_rt_sigaction<'a>(
    mgr: &mut ApeManager<'a>,
    pid: usize,
    _signum: usize,
    _act: usize,
    oldact: usize,
    sigsetsize: usize,
) -> Result<isize, Error> {
    if oldact != 0 {
        let sa_len =
            size_of::<usize>().checked_mul(3).ok_or(Error::InvalidArgs)?.saturating_add(sigsetsize);
        write_zeros_to_user(mgr, pid, oldact, sa_len)?;
    }
    Ok(0)
}

pub fn sys_rt_sigprocmask<'a>(
    mgr: &mut ApeManager<'a>,
    pid: usize,
    _how: usize,
    _set: usize,
    oldset: usize,
    sigsetsize: usize,
) -> Result<isize, Error> {
    if oldset != 0 {
        write_zeros_to_user(mgr, pid, oldset, sigsetsize)?;
    }
    Ok(0)
}

pub fn sys_set_robust_list<'a>(
    _mgr: &mut ApeManager<'a>,
    _pid: usize,
    _head: usize,
    _len: usize,
) -> Result<isize, Error> {
    Ok(0)
}

pub fn sys_prlimit64<'a>(
    mgr: &mut ApeManager<'a>,
    pid: usize,
    _target_pid: usize,
    _resource: usize,
    _new_limit: usize,
    old_limit: usize,
) -> Result<isize, Error> {
    if old_limit != 0 {
        let lim = RLimit64 { rlim_cur: u64::MAX, rlim_max: u64::MAX };
        write_obj_to_user(mgr, pid, old_limit, &lim)?;
    }
    Ok(0)
}

pub fn sys_clock_gettime<'a>(
    mgr: &mut ApeManager<'a>,
    pid: usize,
    _clockid: usize,
    tp: usize,
) -> Result<isize, Error> {
    if tp == 0 {
        return Err(Error::InvalidAddress);
    }
    let ts = TimeSpec { tv_sec: 0, tv_nsec: 0 };
    write_obj_to_user(mgr, pid, tp, &ts)?;
    Ok(0)
}

pub fn sys_gettimeofday<'a>(
    mgr: &mut ApeManager<'a>,
    pid: usize,
    tv: usize,
    _tz: usize,
) -> Result<isize, Error> {
    if tv != 0 {
        let tv_obj = TimeVal { tv_sec: 0, tv_usec: 0 };
        write_obj_to_user(mgr, pid, tv, &tv_obj)?;
    }
    Ok(0)
}

pub fn sys_nanosleep<'a>(
    mgr: &mut ApeManager<'a>,
    pid: usize,
    _req: usize,
    rem: usize,
) -> Result<isize, Error> {
    if rem != 0 {
        let ts = TimeSpec { tv_sec: 0, tv_nsec: 0 };
        write_obj_to_user(mgr, pid, rem, &ts)?;
    }
    Ok(0)
}

pub fn sys_getrandom<'a>(
    mgr: &mut ApeManager<'a>,
    pid: usize,
    buf_ptr: usize,
    len: usize,
    _flags: usize,
) -> Result<isize, Error> {
    if len == 0 {
        return Ok(0);
    }

    let mut done = 0usize;
    let zeros = vec![0u8; 256];
    while done < len {
        let chunk = min(len - done, zeros.len());
        mgr.copy_to_user(pid, buf_ptr + done, &zeros[..chunk])?;
        done += chunk;
    }
    Ok(len as isize)
}

pub fn sys_getuid<'a>(_mgr: &mut ApeManager<'a>, _pid: usize) -> Result<isize, Error> {
    Ok(0)
}

pub fn sys_geteuid<'a>(_mgr: &mut ApeManager<'a>, _pid: usize) -> Result<isize, Error> {
    Ok(0)
}

pub fn sys_getgid<'a>(_mgr: &mut ApeManager<'a>, _pid: usize) -> Result<isize, Error> {
    Ok(0)
}

pub fn sys_getegid<'a>(_mgr: &mut ApeManager<'a>, _pid: usize) -> Result<isize, Error> {
    Ok(0)
}
