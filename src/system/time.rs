use crate::ApeManager;
use crate::ape::utils::write_obj_to_user;
use core::cmp::min;
use glenda::error::Error;
use linux_raw_sys::ctypes::c_char;
use linux_raw_sys::general::{RLIM64_INFINITY, __kernel_timespec, rlimit64, timeval};
use linux_raw_sys::system::{__NEW_UTS_LEN, new_utsname};

const UTS_STR_LEN: usize = (__NEW_UTS_LEN as usize) + 1;

fn write_cstr(dst: &mut [c_char; UTS_STR_LEN], src: &str) {
    dst.fill(0 as c_char);
    let bytes = src.as_bytes();
    let n = min(bytes.len(), UTS_STR_LEN.saturating_sub(1));
    for (i, b) in bytes[..n].iter().enumerate() {
        dst[i] = *b as c_char;
    }
}

pub(crate) fn do_uname(mgr: &mut ApeManager<'_>, pid: usize, buf_ptr: usize) -> Result<isize, Error> {
    let mut uts = new_utsname {
        sysname: [0; UTS_STR_LEN],
        nodename: [0; UTS_STR_LEN],
        release: [0; UTS_STR_LEN],
        version: [0; UTS_STR_LEN],
        machine: [0; UTS_STR_LEN],
        domainname: [0; UTS_STR_LEN],
    };

    write_cstr(&mut uts.sysname, "Linux");
    write_cstr(&mut uts.nodename, "glenda");
    write_cstr(&mut uts.release, "5.19.0-glenda-APE");
    write_cstr(&mut uts.version, "Glenda Microkernel");
    write_cstr(&mut uts.machine, "riscv64");
    write_cstr(&mut uts.domainname, "localdomain");

    write_obj_to_user(mgr, pid, buf_ptr, &uts)?;
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
    // TODO(ape): 按资源类型维护/读取真实 rlimit，而非统一返回无限值。
    if old_limit != 0 {
        let lim = rlimit64 { rlim_cur: RLIM64_INFINITY as u64, rlim_max: RLIM64_INFINITY as u64 };
        write_obj_to_user(mgr, pid, old_limit, &lim)?;
    }
    Ok(0)
}

pub(crate) fn do_clock_gettime(
    mgr: &mut ApeManager<'_>,
    pid: usize,
    _clockid: usize,
    tp: usize,
) -> Result<isize, Error> {
    // TODO(ape): 对接计时服务并支持不同 clockid 的真实时间源。
    if tp == 0 {
        return Err(Error::InvalidAddress);
    }
    let ts = __kernel_timespec { tv_sec: 0, tv_nsec: 0 };
    write_obj_to_user(mgr, pid, tp, &ts)?;
    Ok(0)
}

pub(crate) fn do_gettimeofday(
    mgr: &mut ApeManager<'_>,
    pid: usize,
    tv: usize,
    _tz: usize,
) -> Result<isize, Error> {
    // TODO(ape): 返回真实 wall-clock 时间，保留与 Linux 的 timeval 兼容行为。
    if tv != 0 {
        let tv_obj = timeval { tv_sec: 0, tv_usec: 0 };
        write_obj_to_user(mgr, pid, tv, &tv_obj)?;
    }
    Ok(0)
}

pub(crate) fn do_nanosleep(
    mgr: &mut ApeManager<'_>,
    pid: usize,
    _req: usize,
    rem: usize,
) -> Result<isize, Error> {
    // TODO(ape): 实现可中断 sleep，并在 EINTR 时回填剩余时间到 rem。
    if rem != 0 {
        let ts = __kernel_timespec { tv_sec: 0, tv_nsec: 0 };
        write_obj_to_user(mgr, pid, rem, &ts)?;
    }
    Ok(0)
}
