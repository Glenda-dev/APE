use crate::ApeManager;
use crate::ape::path::path_inside_root;
use crate::ape::process::FileType as ApeFileType;
use crate::ape::user::USER_PATH_MAX;
use alloc::string::String;
use alloc::vec;
use alloc::vec::Vec;
use core::cmp::min;
use core::mem::size_of;
use glenda::error::Error;
use glenda::interface::SystemService;
use glenda::interface::{FileHandleService, FileSystemService};
use glenda::ipc::Badge;
use glenda::protocol::fs::FileType as FsFileType;
use linux_raw_sys::errno::*;
use linux_raw_sys::general::*;

const UTS_STR_LEN: usize = 65;

#[inline]
fn ok_zero() -> Result<isize, Error> {
    Ok(0)
}

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

#[repr(C)]
#[derive(Clone, Copy, Default)]
struct PollFd {
    fd: i32,
    events: i16,
    revents: i16,
}

const POLLIN: i16 = 0x0001;
const POLLPRI: i16 = 0x0002;
const POLLOUT: i16 = 0x0004;
const POLLNVAL: i16 = 0x0020;

const LINUX_REBOOT_MAGIC1: usize = 0xfee1dead;
const LINUX_REBOOT_MAGIC2: usize = 672_274_793;
const LINUX_REBOOT_MAGIC2A: usize = 850_722_78;
const LINUX_REBOOT_MAGIC2B: usize = 369_367_448;
const LINUX_REBOOT_MAGIC2C: usize = 537_993_216;

const LINUX_REBOOT_CMD_RESTART: usize = 0x0123_4567;
const LINUX_REBOOT_CMD_HALT: usize = 0xCDEF_0123;
const LINUX_REBOOT_CMD_CAD_ON: usize = 0x89AB_CDEF;
const LINUX_REBOOT_CMD_CAD_OFF: usize = 0x0000_0000;
const LINUX_REBOOT_CMD_POWER_OFF: usize = 0x4321_FEDC;
const LINUX_REBOOT_CMD_RESTART2: usize = 0xA1B2_C3D4;

#[inline]
fn valid_reboot_magic2(v: usize) -> bool {
    matches!(
        v,
        LINUX_REBOOT_MAGIC2 | LINUX_REBOOT_MAGIC2A | LINUX_REBOOT_MAGIC2B | LINUX_REBOOT_MAGIC2C
    )
}

#[inline]
fn reboot_cmd_name(cmd: usize) -> &'static str {
    match cmd {
        LINUX_REBOOT_CMD_RESTART => "RESTART",
        LINUX_REBOOT_CMD_RESTART2 => "RESTART2",
        LINUX_REBOOT_CMD_POWER_OFF => "POWER_OFF",
        LINUX_REBOOT_CMD_HALT => "HALT",
        LINUX_REBOOT_CMD_CAD_ON => "CAD_ON",
        LINUX_REBOOT_CMD_CAD_OFF => "CAD_OFF",
        _ => "UNKNOWN",
    }
}

fn reboot_ape_runtime<'a>(mgr: &mut ApeManager<'a>, caller_pid: usize) -> Result<(), Error> {
    // 以本地 init(pid=1) 为优先重启对象；若不存在则回退到调用者。
    let init_pid = if mgr.get_process(1).is_some() { 1 } else { caller_pid };
    let pids: Vec<usize> = mgr.processes.keys().copied().collect();
    for victim in pids {
        if victim == init_pid {
            continue;
        }
        if let Err(e) = mgr.terminate_process_preserve_reply(victim, 0, false) {
            warn!(
                "sys_reboot: failed to terminate pid {} during APE reboot: {:?}",
                victim, e
            );
        }
    }

    let init_path = mgr.config.init_path.clone();
    log!(
        "sys_reboot: rebooting APE runtime by exec init pid={}, path={}",
        init_pid,
        init_path
    );
    mgr.execve_path(init_pid, &init_path, &[], &[])?;

    // 若重启对象不是当前正在执行 syscall 的线程，确保其可运行。
    if init_pid != caller_pid
        && let Some(proc) = mgr.get_process(init_pid)
        && let Err(e) = proc.tcb().resume()
    {
        warn!("sys_reboot: resume init pid {} failed: {:?}", init_pid, e);
    }

    Ok(())
}

fn shutdown_ape_runtime<'a>(mgr: &mut ApeManager<'a>) {
    log!("sys_reboot: shutting down APE service (no system reset)");
    mgr.stop();
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

#[inline]
fn is_dir_mode(mode: u32) -> bool {
    ((mode as usize) & FsFileType::S_IFMT.bits()) == FsFileType::S_IFDIR.bits()
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

pub fn sys_rt_sigpending<'a>(
    mgr: &mut ApeManager<'a>,
    pid: usize,
    set: usize,
    sigsetsize: usize,
) -> Result<isize, Error> {
    if set != 0 {
        write_zeros_to_user(mgr, pid, set, sigsetsize)?;
    }
    Ok(0)
}

pub fn sys_rt_sigtimedwait<'a>(
    _mgr: &mut ApeManager<'a>,
    _pid: usize,
    _set: usize,
    _info: usize,
    _timeout: usize,
    _sigsetsize: usize,
) -> Result<isize, Error> {
    // 目前无真实信号队列：按 Linux 语义返回“超时无信号”。
    Ok(-(EAGAIN as isize))
}

pub fn sys_rt_sigsuspend<'a>(
    _mgr: &mut ApeManager<'a>,
    _pid: usize,
    _mask: usize,
    _sigsetsize: usize,
) -> Result<isize, Error> {
    // Linux 下通常被信号打断返回 EINTR；这里保持兼容行为。
    Ok(-(EINTR as isize))
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

pub fn sys_ppoll<'a>(
    mgr: &mut ApeManager<'a>,
    pid: usize,
    fds_ptr: usize,
    nfds: usize,
    _timeout: usize,
    _sigmask: usize,
    _sigsetsize: usize,
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

    let mut ready_count = 0usize;
    for i in 0..nfds {
        let p = fds_ptr
            .checked_add(i.checked_mul(size_of::<PollFd>()).ok_or(Error::InvalidAddress)?)
            .ok_or(Error::InvalidAddress)?;

        let mut raw = [0u8; size_of::<PollFd>()];
        mgr.copy_from_user(pid, p, &mut raw)?;
        let mut pfd = unsafe { (raw.as_ptr() as *const PollFd).read_unaligned() };

        pfd.revents = 0;
        if pfd.fd >= 0 {
            let fd = pfd.fd as u32;
            let process = mgr.get_process(pid).ok_or(Error::NotFound)?;
            if !process.fds.contains_key(&fd) {
                pfd.revents = POLLNVAL;
                ready_count += 1;
            } else {
                let mut revents = 0i16;
                if (pfd.events & (POLLIN | POLLPRI)) != 0 {
                    revents |= POLLIN;
                }
                if (pfd.events & POLLOUT) != 0 {
                    revents |= POLLOUT;
                }
                pfd.revents = revents;
                if revents != 0 {
                    ready_count += 1;
                }
            }
        }

        let out = unsafe {
            core::slice::from_raw_parts((&pfd as *const PollFd) as *const u8, size_of::<PollFd>())
        };
        mgr.copy_to_user(pid, p, out)?;
    }

    Ok(ready_count as isize)
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
    ok_zero()
}

pub fn sys_geteuid<'a>(_mgr: &mut ApeManager<'a>, _pid: usize) -> Result<isize, Error> {
    ok_zero()
}

pub fn sys_getgid<'a>(_mgr: &mut ApeManager<'a>, _pid: usize) -> Result<isize, Error> {
    ok_zero()
}

pub fn sys_getegid<'a>(_mgr: &mut ApeManager<'a>, _pid: usize) -> Result<isize, Error> {
    ok_zero()
}

pub fn sys_getcwd<'a>(
    mgr: &mut ApeManager<'a>,
    pid: usize,
    buf_ptr: usize,
    size: usize,
) -> Result<isize, Error> {
    if buf_ptr == 0 {
        return Err(Error::InvalidAddress);
    }
    if size == 0 {
        return Err(Error::InvalidArgs);
    }

    let (root_dir, cwd_abs) = {
        let process = mgr.get_process(pid).ok_or(Error::NotFound)?;
        (process.root_dir.clone(), process.cwd.clone())
    };

    let guest_cwd = path_inside_root(&cwd_abs, &root_dir).unwrap_or_else(|| String::from("/"));
    let bytes = guest_cwd.as_bytes();
    let need = bytes.len().checked_add(1).ok_or(Error::OutOfMemory)?;
    if need > size {
        return Err(Error::MessageTooLong);
    }

    mgr.copy_to_user(pid, buf_ptr, bytes)?;
    let nul_ptr = buf_ptr.checked_add(bytes.len()).ok_or(Error::OutOfMemory)?;
    mgr.copy_to_user(pid, nul_ptr, &[0])?;
    Ok(need as isize)
}

pub fn sys_chdir<'a>(
    mgr: &mut ApeManager<'a>,
    pid: usize,
    path_ptr: usize,
) -> Result<isize, Error> {
    if path_ptr == 0 {
        return Err(Error::InvalidAddress);
    }

    let raw_path = mgr.strncpy_from_user(pid, path_ptr, USER_PATH_MAX)?;
    if raw_path.is_empty() {
        return Err(Error::NotFound);
    }

    let resolved = mgr.resolve_path_for_process(pid, &raw_path)?;
    let st = mgr.fs_client.stat_path(Badge::null(), &resolved)?;
    if !is_dir_mode(st.mode) {
        return Err(Error::InvalidArgs);
    }

    let process = mgr.get_process_mut(pid).ok_or(Error::NotFound)?;
    process.cwd = resolved;
    Ok(0)
}

pub fn sys_fchdir<'a>(mgr: &mut ApeManager<'a>, pid: usize, fd: usize) -> Result<isize, Error> {
    let fd = u32::try_from(fd).map_err(|_| Error::InvalidSlot)?;

    let target_cwd = {
        let process = mgr.get_process(pid).ok_or(Error::NotFound)?;
        let handle = process.fds.get(&fd).ok_or(Error::InvalidSlot)?;
        let path = process.fd_paths.get(&fd).cloned().ok_or(Error::InvalidArgs)?;

        match &handle.file_type {
            ApeFileType::Normal(normal) => {
                let st = normal.fs_client.stat(Badge::null())?;
                if !is_dir_mode(st.mode) {
                    return Err(Error::InvalidArgs);
                }
                path
            }
            _ => return Err(Error::InvalidArgs),
        }
    };

    let process = mgr.get_process_mut(pid).ok_or(Error::NotFound)?;
    process.cwd = target_cwd;
    Ok(0)
}

pub fn sys_chroot<'a>(
    mgr: &mut ApeManager<'a>,
    pid: usize,
    path_ptr: usize,
) -> Result<isize, Error> {
    if path_ptr == 0 {
        return Err(Error::InvalidAddress);
    }

    let raw_path = mgr.strncpy_from_user(pid, path_ptr, USER_PATH_MAX)?;
    if raw_path.is_empty() {
        return Err(Error::NotFound);
    }

    let resolved = mgr.resolve_path_for_process(pid, &raw_path)?;
    let st = mgr.fs_client.stat_path(Badge::null(), &resolved)?;
    if !is_dir_mode(st.mode) {
        return Err(Error::InvalidArgs);
    }

    let process = mgr.get_process_mut(pid).ok_or(Error::NotFound)?;
    process.root_dir = resolved.clone();
    process.cwd = resolved;
    Ok(0)
}

pub fn sys_reboot<'a>(
    mgr: &mut ApeManager<'a>,
    pid: usize,
    magic: usize,
    magic2: usize,
    cmd: usize,
    _arg: usize,
) -> Result<isize, Error> {
    log!(
        "sys_reboot: pid={}, magic={:#x}, magic2={:#x}, cmd={:#x}({})",
        pid,
        magic,
        magic2,
        cmd,
        reboot_cmd_name(cmd)
    );

    if magic != LINUX_REBOOT_MAGIC1 || !valid_reboot_magic2(magic2) {
        warn!("sys_reboot: invalid magic");
        return Err(Error::InvalidArgs);
    }

    match cmd {
        LINUX_REBOOT_CMD_CAD_ON | LINUX_REBOOT_CMD_CAD_OFF => {
            log!("sys_reboot: CAD command accepted as no-op");
            return Ok(0);
        }
        LINUX_REBOOT_CMD_RESTART | LINUX_REBOOT_CMD_RESTART2 => {
            reboot_ape_runtime(mgr, pid)?;
            return Ok(0);
        }
        LINUX_REBOOT_CMD_POWER_OFF | LINUX_REBOOT_CMD_HALT => {
            shutdown_ape_runtime(mgr);
            return Ok(0);
        }
        _ => {
            warn!("sys_reboot: unsupported cmd {:#x}", cmd);
            return Err(Error::InvalidArgs);
        }
    }
}

pub fn sys_sched_yield<'a>(_mgr: &mut ApeManager<'a>, _pid: usize) -> Result<isize, Error> {
    Ok(0)
}

pub fn sys_prctl<'a>(
    _mgr: &mut ApeManager<'a>,
    _pid: usize,
    _option: usize,
    _arg2: usize,
    _arg3: usize,
    _arg4: usize,
    _arg5: usize,
) -> Result<isize, Error> {
    Ok(0)
}

pub fn sys_futex<'a>(
    _mgr: &mut ApeManager<'a>,
    _pid: usize,
    _uaddr: usize,
    futex_op: usize,
    _val: usize,
    _timeout: usize,
    _uaddr2: usize,
    _val3: usize,
) -> Result<isize, Error> {
    let cmd = futex_op & FUTEX_CMD_MASK as usize;
    match cmd as u32 {
        FUTEX_WAKE | FUTEX_WAKE_PRIVATE => Ok(0),
        FUTEX_WAIT | FUTEX_WAIT_PRIVATE | FUTEX_WAIT_BITSET | FUTEX_WAIT_BITSET_PRIVATE => {
            Ok(-(EAGAIN as isize))
        }
        _ => Ok(0),
    }
}
