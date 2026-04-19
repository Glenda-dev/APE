#![allow(non_upper_case_globals)]

use crate::ApeManager;
use crate::ape::user::USER_PATH_MAX;
use alloc::format;
use alloc::string::{String, ToString};
use alloc::vec::Vec;
use core::cmp::min;
use core::mem::size_of;
use glenda::arch::time::get_time;
use linux_raw_sys::errno::*;
use linux_raw_sys::general::*;
use linux_raw_sys::ioctl::*;

const TRACE_BUF_PREVIEW: usize = 64;

pub(crate) fn syscall_name(sys_num: u32) -> &'static str {
    match sys_num {
        __NR_set_tid_address => "set_tid_address",
        __NR_gettid => "gettid",
        __NR_getpid => "getpid",
        __NR_getppid => "getppid",
        __NR_exit => "exit",
        __NR_exit_group => "exit_group",
        __NR_brk => "brk",
        __NR_mmap => "mmap",
        __NR_mprotect => "mprotect",
        __NR_munmap => "munmap",
        __NR_mremap => "mremap",
        __NR_lseek => "lseek",
        __NR_fcntl => "fcntl",
        __NR_ioctl => "ioctl",
        __NR_read => "read",
        __NR_write => "write",
        __NR_readv => "readv",
        __NR_writev => "writev",
        __NR_openat => "openat",
        __NR_pipe2 => "pipe2",
        __NR_linkat => "linkat",
        __NR_mount => "mount",
        __NR_umount2 => "umount2",
        __NR_newfstatat => "newfstatat",
        __NR_close => "close",
        __NR_getcwd => "getcwd",
        __NR_chdir => "chdir",
        __NR_fchdir => "fchdir",
        __NR_chroot => "chroot",
        __NR_uname => "uname",
        __NR_rt_sigsuspend => "rt_sigsuspend",
        __NR_rt_sigaction => "rt_sigaction",
        __NR_rt_sigprocmask => "rt_sigprocmask",
        __NR_rt_sigpending => "rt_sigpending",
        __NR_rt_sigtimedwait => "rt_sigtimedwait",
        __NR_rt_sigreturn => "rt_sigreturn",
        __NR_set_robust_list => "set_robust_list",
        __NR_prlimit64 => "prlimit64",
        __NR_clock_gettime => "clock_gettime",
        __NR_gettimeofday => "gettimeofday",
        __NR_nanosleep => "nanosleep",
        __NR_ppoll => "ppoll",
        __NR_getrandom => "getrandom",
        __NR_getuid => "getuid",
        __NR_geteuid => "geteuid",
        __NR_getgid => "getgid",
        __NR_getegid => "getegid",
        __NR_execve => "execve",
        __NR_clone => "clone",
        __NR_wait4 => "wait4",
        __NR_setsid => "setsid",
        __NR_getsid => "getsid",
        __NR_setpgid => "setpgid",
        __NR_getpgid => "getpgid",
        __NR_kill => "kill",
        __NR_reboot => "reboot",
        __NR_sched_yield => "sched_yield",
        __NR_prctl => "prctl",
        __NR_futex => "futex",
        _ => "unknown",
    }
}

pub(crate) fn format_result(sys_num: u32, ret: isize) -> String {
    if ret >= 0 {
        return match sys_num {
            __NR_brk | __NR_mmap | __NR_mremap => format!("{:#x}", ret as usize),
            _ => format!("{}", ret),
        };
    }

    let errno = (-ret) as u32;
    if let Some((name, desc)) = errno_name_desc(errno) {
        format!("-1 {} ({})", name, desc)
    } else {
        format!("{}", ret)
    }
}

fn errno_name_desc(errno: u32) -> Option<(&'static str, &'static str)> {
    Some(match errno {
        EPERM => ("EPERM", "Operation not permitted"),
        ENOENT => ("ENOENT", "No such file or directory"),
        ESRCH => ("ESRCH", "No such process"),
        EINTR => ("EINTR", "Interrupted system call"),
        EIO => ("EIO", "I/O error"),
        ENXIO => ("ENXIO", "No such device or address"),
        E2BIG => ("E2BIG", "Argument list too long"),
        ENOEXEC => ("ENOEXEC", "Exec format error"),
        EBADF => ("EBADF", "Bad file descriptor"),
        ECHILD => ("ECHILD", "No child processes"),
        EAGAIN => ("EAGAIN", "Resource temporarily unavailable"),
        ENOMEM => ("ENOMEM", "Cannot allocate memory"),
        EACCES => ("EACCES", "Permission denied"),
        EFAULT => ("EFAULT", "Bad address"),
        EBUSY => ("EBUSY", "Device or resource busy"),
        EEXIST => ("EEXIST", "File exists"),
        ENODEV => ("ENODEV", "No such device"),
        ENOTDIR => ("ENOTDIR", "Not a directory"),
        EISDIR => ("EISDIR", "Is a directory"),
        EINVAL => ("EINVAL", "Invalid argument"),
        ENFILE => ("ENFILE", "Too many open files in system"),
        EMFILE => ("EMFILE", "Too many open files"),
        ENOTTY => ("ENOTTY", "Inappropriate ioctl for device"),
        ETXTBSY => ("ETXTBSY", "Text file busy"),
        EFBIG => ("EFBIG", "File too large"),
        ENOSPC => ("ENOSPC", "No space left on device"),
        ESPIPE => ("ESPIPE", "Illegal seek"),
        EROFS => ("EROFS", "Read-only file system"),
        EMLINK => ("EMLINK", "Too many links"),
        EPIPE => ("EPIPE", "Broken pipe"),
        EDOM => ("EDOM", "Numerical argument out of domain"),
        ERANGE => ("ERANGE", "Numerical result out of range"),
        ENOSYS => ("ENOSYS", "Function not implemented"),
        ETIMEDOUT => ("ETIMEDOUT", "Connection timed out"),
        _ => return None,
    })
}

pub struct TraceState {
    enter_call: Option<String>,
    start_ticks: u64,
}

#[inline]
fn now_ticks() -> u64 {
    get_time() as u64
}

pub fn trace_syscall_enter<'a>(
    mgr: &mut ApeManager<'a>,
    pid: usize,
    sys_num: u32,
    args: [usize; 6],
) -> TraceState {
    let enter_call = match sys_num {
        // 输入参数以 enter 快照为准，避免 exit 时用户缓冲区被覆盖后失真。
        // 对带输出语义的参数，优先在 exit 重新读取。
        __NR_execve => Some(trace_execve_enter(mgr, pid, args)),
        __NR_openat => Some(trace_openat(mgr, pid, args)),
        __NR_newfstatat => Some(trace_newfstatat(mgr, pid, args)),
        __NR_chdir | __NR_chroot => Some(trace_path1(mgr, pid, sys_num, args)),
        __NR_write => Some(trace_write(mgr, pid, args)),
        __NR_writev => Some(trace_writev(mgr, pid, args)),
        _ => None,
    };
    TraceState { enter_call, start_ticks: now_ticks() }
}

pub fn trace_syscall_exit<'a>(
    mgr: &mut ApeManager<'a>,
    pid: usize,
    sys_num: u32,
    args: [usize; 6],
    ret: isize,
    state: &TraceState,
) {
    let elapsed_ticks = now_ticks().wrapping_sub(state.start_ticks);
    let call = match sys_num {
        __NR_execve => enter_or_fallback(state, || trace_execve_enter(mgr, pid, args)),
        __NR_exit => trace_exit_like("exit", args),
        __NR_exit_group => trace_exit_like("exit_group", args),
        __NR_brk => trace_brk(args),
        __NR_openat => enter_or_fallback(state, || trace_openat(mgr, pid, args)),
        __NR_pipe2 => trace_pipe2(args),
        __NR_linkat => trace_linkat(mgr, pid, args),
        __NR_mount => trace_mount(mgr, pid, args),
        __NR_umount2 => trace_umount2(mgr, pid, args),
        __NR_newfstatat => enter_or_fallback(state, || trace_newfstatat(mgr, pid, args)),
        __NR_read => trace_read(mgr, pid, args, ret),
        __NR_write => enter_or_fallback(state, || trace_write(mgr, pid, args)),
        __NR_readv => trace_readv(mgr, pid, args, ret),
        __NR_writev => enter_or_fallback(state, || trace_writev(mgr, pid, args)),
        __NR_mmap => trace_mmap(args),
        __NR_mprotect => trace_mprotect(args),
        __NR_munmap => trace_munmap(args),
        __NR_mremap => trace_mremap(args),
        __NR_close => trace_close(args),
        __NR_lseek => trace_lseek(args),
        __NR_fcntl => trace_fcntl(args),
        __NR_ioctl => trace_ioctl(args),
        __NR_chdir | __NR_chroot => {
            enter_or_fallback(state, || trace_path1(mgr, pid, sys_num, args))
        }
        __NR_fchdir => trace_fchdir(args),
        __NR_getcwd => trace_getcwd(args),
        __NR_uname => trace_uname(args),
        __NR_getpid => trace_noarg("getpid"),
        __NR_gettid => trace_noarg("gettid"),
        __NR_getppid => trace_noarg("getppid"),
        __NR_rt_sigaction => trace_rt_sigaction(args),
        __NR_rt_sigsuspend => trace_rt_sigsuspend(args),
        __NR_rt_sigprocmask => trace_rt_sigprocmask(args),
        __NR_rt_sigpending => trace_rt_sigpending(args),
        __NR_rt_sigtimedwait => enter_or_fallback(state, || trace_rt_sigtimedwait(mgr, pid, args)),
        __NR_rt_sigreturn => trace_noarg("rt_sigreturn"),
        __NR_prlimit64 => trace_prlimit64(args),
        __NR_clock_gettime => trace_clock_gettime(args),
        __NR_gettimeofday => trace_gettimeofday(args),
        __NR_nanosleep => trace_nanosleep(mgr, pid, args, ret),
        __NR_ppoll => trace_ppoll(mgr, pid, args),
        __NR_getrandom => trace_getrandom(mgr, pid, args, ret),
        __NR_getuid => trace_noarg("getuid"),
        __NR_geteuid => trace_noarg("geteuid"),
        __NR_getgid => trace_noarg("getgid"),
        __NR_getegid => trace_noarg("getegid"),
        __NR_set_tid_address => trace_set_tid_address(args),
        __NR_set_robust_list => trace_set_robust_list(args),
        __NR_kill => trace_kill(args),
        __NR_clone => trace_clone(args),
        __NR_wait4 => trace_wait4(args),
        __NR_setsid => trace_noarg("setsid"),
        __NR_getsid => trace_getsid(args),
        __NR_setpgid => trace_setpgid(args),
        __NR_getpgid => trace_getpgid(args),
        __NR_reboot => trace_reboot(args),
        __NR_sched_yield => trace_noarg("sched_yield"),
        __NR_prctl => trace_prctl(args),
        __NR_futex => trace_futex(args),
        _ => trace_default(sys_num, args),
    };

    debug!("[pid {}] {} = {} <{} ticks>", pid, call, format_result(sys_num, ret), elapsed_ticks);
}

fn enter_or_fallback<F>(state: &TraceState, fallback: F) -> String
where
    F: FnOnce() -> String,
{
    state.enter_call.clone().unwrap_or_else(fallback)
}

fn trace_default(sys_num: u32, args: [usize; 6]) -> String {
    let name = syscall_name(sys_num);
    if name == "unknown" {
        format!(
            "syscall#{}({:#x}, {:#x}, {:#x}, {:#x}, {:#x}, {:#x})",
            sys_num, args[0], args[1], args[2], args[3], args[4], args[5]
        )
    } else {
        format!(
            "{}({:#x}, {:#x}, {:#x}, {:#x}, {:#x}, {:#x})",
            name, args[0], args[1], args[2], args[3], args[4], args[5]
        )
    }
}

fn trace_execve_enter<'a>(mgr: &mut ApeManager<'a>, pid: usize, args: [usize; 6]) -> String {
    let filename_ptr = args[0];
    let argv_ptr = args[1];
    let envp_ptr = args[2];

    match mgr.parse_execve_user_input(pid, filename_ptr, argv_ptr, envp_ptr) {
        Ok(input) => {
            let argv_fmt = format_string_array(&input.argv, 4);
            let envc = input.envp.len();
            format!(
                "execve({}, {}, {:#x} /* {} vars */)",
                quote_string(&input.filename),
                argv_fmt,
                envp_ptr,
                envc
            )
        }
        Err(_) => format!(
            "execve({}, {:#x}, {:#x})",
            read_user_path(mgr, pid, filename_ptr),
            argv_ptr,
            envp_ptr
        ),
    }
}

fn trace_exit_like(name: &str, args: [usize; 6]) -> String {
    format!("{}({})", name, args[0] as isize)
}

fn trace_noarg(name: &str) -> String {
    format!("{}()", name)
}

fn trace_brk(args: [usize; 6]) -> String {
    let addr = args[0];
    if addr == 0 { "brk(NULL)".to_string() } else { format!("brk({:#x})", addr) }
}

fn trace_openat<'a>(mgr: &mut ApeManager<'a>, pid: usize, args: [usize; 6]) -> String {
    let dirfd = format_dirfd(args[0]);
    let path = read_user_path(mgr, pid, args[1]);
    let flags = format_open_flags(args[2] as u32);
    let mode = args[3];
    let need_mode = (args[2] as u32 & (O_CREAT | O_TMPFILE)) != 0;
    if need_mode {
        format!("openat({}, {}, {}, {:#o})", dirfd, path, flags, mode)
    } else {
        format!("openat({}, {}, {})", dirfd, path, flags)
    }
}

fn trace_newfstatat<'a>(mgr: &mut ApeManager<'a>, pid: usize, args: [usize; 6]) -> String {
    let dirfd = format_dirfd(args[0]);
    let path = read_user_path(mgr, pid, args[1]);
    let statbuf = format_ptr(args[2]);
    let flags = format_at_flags(args[3] as u32);
    format!("newfstatat({}, {}, {}, {})", dirfd, path, statbuf, flags)
}

fn trace_pipe2(args: [usize; 6]) -> String {
    format!("pipe2({}, {})", format_ptr(args[0]), format_pipe2_flags(args[1] as u32))
}

fn trace_linkat<'a>(mgr: &mut ApeManager<'a>, pid: usize, args: [usize; 6]) -> String {
    format!(
        "linkat({}, {}, {}, {}, {})",
        format_dirfd(args[0]),
        read_user_path(mgr, pid, args[1]),
        format_dirfd(args[2]),
        read_user_path(mgr, pid, args[3]),
        format_linkat_flags(args[4] as u32)
    )
}

fn trace_mount<'a>(mgr: &mut ApeManager<'a>, pid: usize, args: [usize; 6]) -> String {
    format!(
        "mount({}, {}, {}, {}, {})",
        read_user_path(mgr, pid, args[0]),
        read_user_path(mgr, pid, args[1]),
        read_user_path(mgr, pid, args[2]),
        format_mount_flags(args[3] as u32),
        format_ptr(args[4])
    )
}

fn trace_umount2<'a>(mgr: &mut ApeManager<'a>, pid: usize, args: [usize; 6]) -> String {
    format!(
        "umount2({}, {})",
        read_user_path(mgr, pid, args[0]),
        format_umount_flags(args[1] as u32)
    )
}

fn trace_read<'a>(mgr: &mut ApeManager<'a>, pid: usize, args: [usize; 6], ret: isize) -> String {
    let fd = args[0];
    let buf_ptr = args[1];
    let len = args[2];
    if ret > 0 {
        let got = ret as usize;
        if let Some(preview) = preview_user_buffer(mgr, pid, buf_ptr, got, TRACE_BUF_PREVIEW) {
            format!("read({}, {}, {})", fd, preview, len)
        } else {
            format!("read({}, {:#x}, {})", fd, buf_ptr, len)
        }
    } else {
        format!("read({}, {:#x}, {})", fd, buf_ptr, len)
    }
}

fn trace_write<'a>(mgr: &mut ApeManager<'a>, pid: usize, args: [usize; 6]) -> String {
    let fd = args[0];
    let buf_ptr = args[1];
    let len = args[2];
    if let Some(preview) = preview_user_buffer(mgr, pid, buf_ptr, len, TRACE_BUF_PREVIEW) {
        format!("write({}, {}, {})", fd, preview, len)
    } else {
        format!("write({}, {:#x}, {})", fd, buf_ptr, len)
    }
}

fn trace_readv<'a>(mgr: &mut ApeManager<'a>, pid: usize, args: [usize; 6], ret: isize) -> String {
    trace_rw_vector(mgr, pid, args, ret, false)
}

fn trace_writev<'a>(mgr: &mut ApeManager<'a>, pid: usize, args: [usize; 6]) -> String {
    trace_rw_vector(mgr, pid, args, -1, true)
}

fn trace_rw_vector<'a>(
    mgr: &mut ApeManager<'a>,
    pid: usize,
    args: [usize; 6],
    ret: isize,
    is_write: bool,
) -> String {
    let name = if is_write { "writev" } else { "readv" };
    let fd = args[0];
    let iov_ptr = args[1];
    let iov_cnt = args[2];

    if iov_ptr == 0 || iov_cnt == 0 {
        return format!("{}({}, {}, {})", name, fd, format_ptr(iov_ptr), iov_cnt);
    }

    if let Some(iov0) = read_first_nonempty_iovec(mgr, pid, iov_ptr, iov_cnt)
        .or_else(|| read_user_iovec(mgr, pid, iov_ptr))
    {
        let iov_base = iov0.iov_base as usize;
        let iov_len = iov0.iov_len as usize;

        if is_write {
            let preview = preview_user_buffer(mgr, pid, iov_base, iov_len, TRACE_BUF_PREVIEW)
                .unwrap_or_else(|| format_ptr(iov_base));
            return format!(
                "writev({}, [{{iov_base={}, iov_len={}}}, ...], {})",
                fd, preview, iov_len, iov_cnt
            );
        }

        let first_base = format_ptr(iov_base);
        if ret > 0 {
            let got = ret as usize;
            if let Some(preview) = preview_user_buffer(mgr, pid, iov_base, got, TRACE_BUF_PREVIEW) {
                return format!(
                    "readv({}, [{{iov_base={}, iov_len={}}}, ...], {})",
                    fd, preview, iov_len, iov_cnt
                );
            }
        }
        return format!(
            "readv({}, [{{iov_base={}, iov_len={}}}, ...], {})",
            fd, first_base, iov_len, iov_cnt
        );
    }

    format!("{}({}, {}, {})", name, fd, format_ptr(iov_ptr), iov_cnt)
}

fn trace_mmap(args: [usize; 6]) -> String {
    let addr = if args[0] == 0 { "NULL".to_string() } else { format!("{:#x}", args[0]) };
    let len = args[1];
    let prot = format_prot_flags(args[2] as u32);
    let flags = format_mmap_flags(args[3] as u32);
    let fd = args[4] as isize;
    let offset = args[5];
    if offset == 0 {
        format!("mmap({}, {}, {}, {}, {}, 0)", addr, len, prot, flags, fd)
    } else {
        format!("mmap({}, {}, {}, {}, {}, {:#x})", addr, len, prot, flags, fd, offset)
    }
}

fn trace_mprotect(args: [usize; 6]) -> String {
    format!("mprotect({:#x}, {}, {})", args[0], args[1], format_prot_flags(args[2] as u32))
}

fn trace_munmap(args: [usize; 6]) -> String {
    format!("munmap({:#x}, {})", args[0], args[1])
}

fn trace_mremap(args: [usize; 6]) -> String {
    format!(
        "mremap({:#x}, {}, {}, {}, {:#x})",
        args[0],
        args[1],
        args[2],
        format_mremap_flags(args[3] as u32),
        args[4]
    )
}

fn trace_close(args: [usize; 6]) -> String {
    format!("close({})", args[0])
}

fn trace_lseek(args: [usize; 6]) -> String {
    format!("lseek({}, {}, {})", args[0], args[1] as isize, format_whence(args[2] as u32))
}

fn trace_fcntl(args: [usize; 6]) -> String {
    format!("fcntl({}, {}, {:#x})", args[0], format_fcntl_cmd(args[1]), args[2])
}

fn trace_ioctl(args: [usize; 6]) -> String {
    format!("ioctl({}, {}, {:#x})", args[0], format_ioctl_req(args[1]), args[2])
}

fn trace_fchdir(args: [usize; 6]) -> String {
    format!("fchdir({})", args[0])
}

fn trace_path1<'a>(mgr: &mut ApeManager<'a>, pid: usize, sys_num: u32, args: [usize; 6]) -> String {
    let name = syscall_name(sys_num);
    format!("{}({})", name, read_user_path(mgr, pid, args[0]))
}

fn trace_getcwd(args: [usize; 6]) -> String {
    format!("getcwd({}, {})", format_ptr(args[0]), args[1])
}

fn trace_uname(args: [usize; 6]) -> String {
    format!("uname({})", format_ptr(args[0]))
}

fn trace_rt_sigaction(args: [usize; 6]) -> String {
    format!(
        "rt_sigaction({}, {}, {}, {})",
        format_signal(args[0] as isize),
        format_ptr(args[1]),
        format_ptr(args[2]),
        args[3]
    )
}

fn trace_rt_sigsuspend(args: [usize; 6]) -> String {
    format!("rt_sigsuspend({}, {})", format_ptr(args[0]), args[1])
}

fn trace_rt_sigprocmask(args: [usize; 6]) -> String {
    format!(
        "rt_sigprocmask({}, {}, {}, {})",
        format_sigmask_how(args[0] as isize),
        format_ptr(args[1]),
        format_ptr(args[2]),
        args[3]
    )
}

fn trace_rt_sigpending(args: [usize; 6]) -> String {
    format!("rt_sigpending({}, {})", format_ptr(args[0]), args[1])
}

fn trace_rt_sigtimedwait<'a>(mgr: &mut ApeManager<'a>, pid: usize, args: [usize; 6]) -> String {
    format!(
        "rt_sigtimedwait({}, {}, {}, {})",
        format_ptr(args[0]),
        format_ptr(args[1]),
        format_timespec(mgr, pid, args[2]),
        args[3]
    )
}

fn trace_prlimit64(args: [usize; 6]) -> String {
    format!(
        "prlimit64({}, {}, {:#x}, {:#x})",
        args[0] as isize,
        format_rlimit_resource(args[1] as u32),
        args[2],
        args[3]
    )
}

fn trace_clock_gettime(args: [usize; 6]) -> String {
    format!("clock_gettime({}, {})", format_clockid(args[0] as isize), format_ptr(args[1]))
}

fn trace_gettimeofday(args: [usize; 6]) -> String {
    format!("gettimeofday({}, {})", format_ptr(args[0]), format_ptr(args[1]))
}

fn trace_nanosleep<'a>(
    mgr: &mut ApeManager<'a>,
    pid: usize,
    args: [usize; 6],
    ret: isize,
) -> String {
    let req = format_timespec(mgr, pid, args[0]);
    let rem_ptr = args[1];

    // Linux 语义下，nanosleep 被 EINTR 打断时 rem 会由内核回填剩余时间；
    // 此处在 exit 读取 rem，优先反映实际输出。
    if ret == -(EINTR as isize) && rem_ptr != 0 {
        return format!("nanosleep({}, {})", req, format_timespec(mgr, pid, rem_ptr));
    }

    format!("nanosleep({}, {})", req, format_ptr(rem_ptr))
}

fn trace_ppoll<'a>(mgr: &mut ApeManager<'a>, pid: usize, args: [usize; 6]) -> String {
    format!(
        "ppoll({}, {}, {}, {}, {})",
        format_ptr(args[0]),
        args[1],
        format_timespec(mgr, pid, args[2]),
        format_ptr(args[3]),
        args[4]
    )
}

fn trace_getrandom<'a>(
    mgr: &mut ApeManager<'a>,
    pid: usize,
    args: [usize; 6],
    ret: isize,
) -> String {
    let buf_ptr = args[0];
    let len = args[1];
    let flags = format_getrandom_flags(args[2] as u32);
    let preview_len = if ret > 0 { ret as usize } else { len };
    if let Some(preview) = preview_user_buffer(mgr, pid, buf_ptr, preview_len, 16) {
        format!("getrandom({}, {}, {})", preview, len, flags)
    } else {
        format!("getrandom({}, {}, {})", format_ptr(buf_ptr), len, flags)
    }
}

fn trace_set_tid_address(args: [usize; 6]) -> String {
    format!("set_tid_address({})", format_ptr(args[0]))
}

fn trace_set_robust_list(args: [usize; 6]) -> String {
    format!("set_robust_list({}, {})", format_ptr(args[0]), args[1])
}

fn trace_kill(args: [usize; 6]) -> String {
    format!("kill({}, {})", args[0] as isize, format_signal(args[1] as isize))
}

fn trace_clone(args: [usize; 6]) -> String {
    format!(
        "clone({:#x}, {}, {}, {}, {})",
        args[0],
        format_ptr(args[1]),
        format_ptr(args[2]),
        format_ptr(args[3]),
        format_ptr(args[4])
    )
}

fn trace_wait4(args: [usize; 6]) -> String {
    format!(
        "wait4({}, {}, {:#x}, {})",
        args[0] as isize,
        format_ptr(args[1]),
        args[2],
        format_ptr(args[3])
    )
}

fn trace_getsid(args: [usize; 6]) -> String {
    format!("getsid({})", args[0] as isize)
}

fn trace_setpgid(args: [usize; 6]) -> String {
    format!("setpgid({}, {})", args[0] as isize, args[1] as isize)
}

fn trace_getpgid(args: [usize; 6]) -> String {
    format!("getpgid({})", args[0] as isize)
}

fn trace_reboot(args: [usize; 6]) -> String {
    format!("reboot({:#x}, {:#x}, {:#x}, {:#x})", args[0], args[1], args[2], args[3])
}

fn trace_prctl(args: [usize; 6]) -> String {
    format!("prctl({}, {:#x}, {:#x}, {:#x}, {:#x})", args[0], args[1], args[2], args[3], args[4])
}

fn trace_futex(args: [usize; 6]) -> String {
    let op = format_futex_op(args[1]);
    format!(
        "futex({}, {}, {}, {}, {}, {})",
        format_ptr(args[0]),
        op,
        args[2] as isize,
        format_ptr(args[3]),
        format_ptr(args[4]),
        args[5]
    )
}

fn read_user_path<'a>(mgr: &mut ApeManager<'a>, pid: usize, ptr: usize) -> String {
    if ptr == 0 {
        return "NULL".to_string();
    }
    match mgr.strncpy_from_user(pid, ptr, USER_PATH_MAX) {
        Ok(path) => quote_string(&path),
        Err(_) => format!("{:#x}", ptr),
    }
}

fn preview_user_buffer<'a>(
    mgr: &mut ApeManager<'a>,
    pid: usize,
    ptr: usize,
    len: usize,
    preview_len: usize,
) -> Option<String> {
    if ptr == 0 {
        return Some("NULL".to_string());
    }
    if len == 0 {
        return Some("\"\"".to_string());
    }

    let to_read = min(len, preview_len);
    if to_read == 0 {
        return Some("\"\"".to_string());
    }

    let mut buf = alloc::vec![0u8; to_read];
    if mgr.copy_from_user(pid, ptr, &mut buf).is_err() {
        return None;
    }

    let escaped = escape_bytes(&buf);
    let suffix = if len > to_read { "..." } else { "" };
    Some(format!("\"{}\"{}", escaped, suffix))
}

fn read_user_iovec<'a>(mgr: &mut ApeManager<'a>, pid: usize, ptr: usize) -> Option<iovec> {
    if ptr == 0 {
        return None;
    }
    let mut raw = [0u8; size_of::<iovec>()];
    if mgr.copy_from_user(pid, ptr, &mut raw).is_err() {
        return None;
    }
    Some(unsafe { (raw.as_ptr() as *const iovec).read_unaligned() })
}

fn read_first_nonempty_iovec<'a>(
    mgr: &mut ApeManager<'a>,
    pid: usize,
    iov_ptr: usize,
    iov_cnt: usize,
) -> Option<iovec> {
    let max_scan = core::cmp::min(iov_cnt, 8);
    for idx in 0..max_scan {
        let ptr = iov_ptr.checked_add(idx.checked_mul(size_of::<iovec>())?)?;
        let iov = read_user_iovec(mgr, pid, ptr)?;
        if iov.iov_len > 0 {
            return Some(iov);
        }
    }
    None
}

fn read_user_timespec<'a>(
    mgr: &mut ApeManager<'a>,
    pid: usize,
    ptr: usize,
) -> Option<__kernel_timespec> {
    if ptr == 0 {
        return None;
    }
    let mut raw = [0u8; size_of::<__kernel_timespec>()];
    if mgr.copy_from_user(pid, ptr, &mut raw).is_err() {
        return None;
    }
    Some(unsafe { (raw.as_ptr() as *const __kernel_timespec).read_unaligned() })
}

fn format_timespec<'a>(mgr: &mut ApeManager<'a>, pid: usize, ptr: usize) -> String {
    if ptr == 0 {
        return "NULL".to_string();
    }
    if let Some(ts) = read_user_timespec(mgr, pid, ptr) {
        return format!("{{tv_sec={}, tv_nsec={}}}", ts.tv_sec, ts.tv_nsec);
    }
    format_ptr(ptr)
}

fn escape_bytes(bytes: &[u8]) -> String {
    let mut out = String::new();
    for &b in bytes {
        match b {
            b'\\' => out.push_str("\\\\"),
            b'\"' => out.push_str("\\\""),
            b'\n' => out.push_str("\\n"),
            b'\r' => out.push_str("\\r"),
            b'\t' => out.push_str("\\t"),
            0x20..=0x7e => out.push(b as char),
            _ => out.push_str(&format!("\\x{:02x}", b)),
        }
    }
    out
}

fn quote_string(s: &str) -> String {
    format!("\"{}\"", escape_bytes(s.as_bytes()))
}

fn format_string_array(items: &[String], max_show: usize) -> String {
    let mut out = String::from("[");
    let show = min(items.len(), max_show);
    for (idx, item) in items.iter().take(show).enumerate() {
        if idx > 0 {
            out.push_str(", ");
        }
        out.push_str(&quote_string(item));
    }
    if items.len() > show {
        if show > 0 {
            out.push_str(", ");
        }
        out.push_str("...");
    }
    out.push(']');
    out
}

fn join_flags(parts: &[&str]) -> String {
    if parts.is_empty() {
        return "0".to_string();
    }
    let mut out = String::new();
    for (i, part) in parts.iter().enumerate() {
        if i > 0 {
            out.push('|');
        }
        out.push_str(part);
    }
    out
}

fn format_dirfd(dirfd: usize) -> String {
    if (dirfd as isize) == (AT_FDCWD as isize) {
        "AT_FDCWD".to_string()
    } else {
        format!("{}", dirfd as isize)
    }
}

fn format_ptr(ptr: usize) -> String {
    if ptr == 0 { "NULL".to_string() } else { format!("{:#x}", ptr) }
}

fn format_open_flags(flags: u32) -> String {
    let mut parts: Vec<&str> = Vec::new();
    match flags & O_ACCMODE {
        O_RDONLY => parts.push("O_RDONLY"),
        O_WRONLY => parts.push("O_WRONLY"),
        O_RDWR => parts.push("O_RDWR"),
        _ => {}
    }
    if flags & O_CLOEXEC != 0 {
        parts.push("O_CLOEXEC");
    }
    if flags & O_CREAT != 0 {
        parts.push("O_CREAT");
    }
    if flags & O_TRUNC != 0 {
        parts.push("O_TRUNC");
    }
    if flags & O_APPEND != 0 {
        parts.push("O_APPEND");
    }
    if flags & O_EXCL != 0 {
        parts.push("O_EXCL");
    }
    if flags & O_NONBLOCK != 0 {
        parts.push("O_NONBLOCK");
    }
    if flags & O_DIRECTORY != 0 {
        parts.push("O_DIRECTORY");
    }
    if flags & O_NOFOLLOW != 0 {
        parts.push("O_NOFOLLOW");
    }
    join_flags(&parts)
}

fn format_at_flags(flags: u32) -> String {
    if flags == 0 {
        return "0".to_string();
    }
    let mut parts: Vec<&str> = Vec::new();
    if flags & AT_SYMLINK_NOFOLLOW as u32 != 0 {
        parts.push("AT_SYMLINK_NOFOLLOW");
    }
    if flags & AT_EMPTY_PATH as u32 != 0 {
        parts.push("AT_EMPTY_PATH");
    }
    if flags & AT_NO_AUTOMOUNT as u32 != 0 {
        parts.push("AT_NO_AUTOMOUNT");
    }
    if flags & AT_REMOVEDIR as u32 != 0 {
        parts.push("AT_REMOVEDIR");
    }
    if flags & AT_SYMLINK_FOLLOW as u32 != 0 {
        parts.push("AT_SYMLINK_FOLLOW");
    }
    join_flags(&parts)
}

fn format_linkat_flags(flags: u32) -> String {
    if flags == 0 {
        return "0".to_string();
    }
    let mut parts: Vec<&str> = Vec::new();
    if flags & AT_SYMLINK_FOLLOW as u32 != 0 {
        parts.push("AT_SYMLINK_FOLLOW");
    }
    if flags & AT_EMPTY_PATH as u32 != 0 {
        parts.push("AT_EMPTY_PATH");
    }
    join_flags(&parts)
}

fn format_pipe2_flags(flags: u32) -> String {
    if flags == 0 {
        return "0".to_string();
    }
    let mut parts: Vec<&str> = Vec::new();
    if flags & O_CLOEXEC != 0 {
        parts.push("O_CLOEXEC");
    }
    if flags & O_NONBLOCK != 0 {
        parts.push("O_NONBLOCK");
    }
    join_flags(&parts)
}

fn format_mount_flags(flags: u32) -> String {
    if flags == 0 {
        return "0".to_string();
    }
    format!("{:#x}", flags)
}

fn format_umount_flags(flags: u32) -> String {
    if flags == 0 {
        return "0".to_string();
    }
    let mut parts: Vec<&str> = Vec::new();
    if flags & MNT_FORCE != 0 {
        parts.push("MNT_FORCE");
    }
    if flags & MNT_DETACH != 0 {
        parts.push("MNT_DETACH");
    }
    if flags & MNT_EXPIRE != 0 {
        parts.push("MNT_EXPIRE");
    }
    if flags & UMOUNT_NOFOLLOW != 0 {
        parts.push("UMOUNT_NOFOLLOW");
    }
    join_flags(&parts)
}

fn format_prot_flags(prot: u32) -> String {
    if prot == PROT_NONE {
        return "PROT_NONE".to_string();
    }
    let mut parts: Vec<&str> = Vec::new();
    if prot & PROT_READ != 0 {
        parts.push("PROT_READ");
    }
    if prot & PROT_WRITE != 0 {
        parts.push("PROT_WRITE");
    }
    if prot & PROT_EXEC != 0 {
        parts.push("PROT_EXEC");
    }
    join_flags(&parts)
}

fn format_mmap_flags(flags: u32) -> String {
    let mut parts: Vec<&str> = Vec::new();
    if flags & MAP_SHARED != 0 {
        parts.push("MAP_SHARED");
    }
    if flags & MAP_PRIVATE != 0 {
        parts.push("MAP_PRIVATE");
    }
    if flags & MAP_FIXED != 0 {
        parts.push("MAP_FIXED");
    }
    if flags & MAP_ANONYMOUS != 0 {
        parts.push("MAP_ANONYMOUS");
    }
    if flags & MAP_DENYWRITE != 0 {
        parts.push("MAP_DENYWRITE");
    }
    join_flags(&parts)
}

fn format_mremap_flags(flags: u32) -> String {
    if flags == 0 {
        return "0".to_string();
    }

    let mut parts: Vec<&str> = Vec::new();
    if flags & MREMAP_MAYMOVE != 0 {
        parts.push("MREMAP_MAYMOVE");
    }
    if flags & MREMAP_FIXED != 0 {
        parts.push("MREMAP_FIXED");
    }
    if flags & MREMAP_DONTUNMAP != 0 {
        parts.push("MREMAP_DONTUNMAP");
    }

    join_flags(&parts)
}

fn format_whence(whence: u32) -> &'static str {
    match whence {
        SEEK_SET => "SEEK_SET",
        SEEK_CUR => "SEEK_CUR",
        SEEK_END => "SEEK_END",
        _ => "UNKNOWN",
    }
}

fn format_fcntl_cmd(cmd: usize) -> &'static str {
    let cmd = cmd as u32;
    match cmd {
        F_DUPFD => "F_DUPFD",
        F_GETFD => "F_GETFD",
        F_SETFD => "F_SETFD",
        F_GETFL => "F_GETFL",
        F_SETFL => "F_SETFL",
        F_DUPFD_CLOEXEC => "F_DUPFD_CLOEXEC",
        _ => "F_?",
    }
}

fn format_ioctl_req(req: usize) -> &'static str {
    let req = req as u32;
    match req {
        TCGETS => "TCGETS",
        TCSETS => "TCSETS",
        TCSETSW => "TCSETSW",
        TCSETSF => "TCSETSF",
        TIOCGPGRP => "TIOCGPGRP",
        TIOCSPGRP => "TIOCSPGRP",
        TIOCGWINSZ => "TIOCGWINSZ",
        TIOCSWINSZ => "TIOCSWINSZ",
        TIOCGPTN => "TIOCGPTN",
        TIOCSPTLCK => "TIOCSPTLCK",
        _ => "IOCTL_?",
    }
}

fn format_getrandom_flags(flags: u32) -> String {
    let mut parts: Vec<&str> = Vec::new();
    if flags == 0 {
        return "0".to_string();
    }
    if flags & GRND_NONBLOCK != 0 {
        parts.push("GRND_NONBLOCK");
    }
    if flags & GRND_RANDOM != 0 {
        parts.push("GRND_RANDOM");
    }
    join_flags(&parts)
}

fn format_signal(sig: isize) -> String {
    let name = match sig {
        0 => "0",
        x if x == SIGHUP as isize => "SIGHUP",
        x if x == SIGINT as isize => "SIGINT",
        x if x == SIGQUIT as isize => "SIGQUIT",
        x if x == SIGILL as isize => "SIGILL",
        x if x == SIGTRAP as isize => "SIGTRAP",
        x if x == SIGABRT as isize => "SIGABRT",
        x if x == SIGBUS as isize => "SIGBUS",
        x if x == SIGFPE as isize => "SIGFPE",
        x if x == SIGKILL as isize => "SIGKILL",
        x if x == SIGUSR1 as isize => "SIGUSR1",
        x if x == SIGSEGV as isize => "SIGSEGV",
        x if x == SIGUSR2 as isize => "SIGUSR2",
        x if x == SIGPIPE as isize => "SIGPIPE",
        x if x == SIGALRM as isize => "SIGALRM",
        x if x == SIGTERM as isize => "SIGTERM",
        x if x == SIGSTKFLT as isize => "SIGSTKFLT",
        x if x == SIGCHLD as isize => "SIGCHLD",
        x if x == SIGCONT as isize => "SIGCONT",
        x if x == SIGSTOP as isize => "SIGSTOP",
        x if x == SIGTSTP as isize => "SIGTSTP",
        x if x == SIGTTIN as isize => "SIGTTIN",
        x if x == SIGTTOU as isize => "SIGTTOU",
        x if x == SIGURG as isize => "SIGURG",
        x if x == SIGXCPU as isize => "SIGXCPU",
        x if x == SIGXFSZ as isize => "SIGXFSZ",
        x if x == SIGVTALRM as isize => "SIGVTALRM",
        x if x == SIGPROF as isize => "SIGPROF",
        x if x == SIGWINCH as isize => "SIGWINCH",
        x if x == SIGIO as isize => "SIGIO",
        x if x == SIGPWR as isize => "SIGPWR",
        x if x == SIGSYS as isize => "SIGSYS",
        _ => return format!("{}", sig),
    };
    if sig == 0 { "0".to_string() } else { name.to_string() }
}

fn format_sigmask_how(how: isize) -> &'static str {
    match how as u32 {
        SIG_BLOCK => "SIG_BLOCK",
        SIG_UNBLOCK => "SIG_UNBLOCK",
        SIG_SETMASK => "SIG_SETMASK",
        _ => "SIGMASK_?",
    }
}

fn format_clockid(clockid: isize) -> &'static str {
    match clockid as u32 {
        CLOCK_REALTIME => "CLOCK_REALTIME",
        CLOCK_MONOTONIC => "CLOCK_MONOTONIC",
        CLOCK_PROCESS_CPUTIME_ID => "CLOCK_PROCESS_CPUTIME_ID",
        CLOCK_THREAD_CPUTIME_ID => "CLOCK_THREAD_CPUTIME_ID",
        CLOCK_MONOTONIC_RAW => "CLOCK_MONOTONIC_RAW",
        CLOCK_REALTIME_COARSE => "CLOCK_REALTIME_COARSE",
        CLOCK_MONOTONIC_COARSE => "CLOCK_MONOTONIC_COARSE",
        CLOCK_BOOTTIME => "CLOCK_BOOTTIME",
        CLOCK_REALTIME_ALARM => "CLOCK_REALTIME_ALARM",
        CLOCK_BOOTTIME_ALARM => "CLOCK_BOOTTIME_ALARM",
        CLOCK_TAI => "CLOCK_TAI",
        _ => "CLOCK_?",
    }
}

fn format_futex_op(op: usize) -> String {
    let op = op as u32;
    let cmd = op & (FUTEX_CMD_MASK as u32);
    let mut parts: Vec<&str> = Vec::new();
    let cmd_name = match cmd {
        FUTEX_WAIT => "FUTEX_WAIT",
        FUTEX_WAKE => "FUTEX_WAKE",
        FUTEX_FD => "FUTEX_FD",
        FUTEX_REQUEUE => "FUTEX_REQUEUE",
        FUTEX_CMP_REQUEUE => "FUTEX_CMP_REQUEUE",
        FUTEX_WAKE_OP => "FUTEX_WAKE_OP",
        FUTEX_LOCK_PI => "FUTEX_LOCK_PI",
        FUTEX_UNLOCK_PI => "FUTEX_UNLOCK_PI",
        FUTEX_TRYLOCK_PI => "FUTEX_TRYLOCK_PI",
        FUTEX_WAIT_BITSET => "FUTEX_WAIT_BITSET",
        FUTEX_WAKE_BITSET => "FUTEX_WAKE_BITSET",
        FUTEX_WAIT_REQUEUE_PI => "FUTEX_WAIT_REQUEUE_PI",
        FUTEX_CMP_REQUEUE_PI => "FUTEX_CMP_REQUEUE_PI",
        _ => "FUTEX_?",
    };
    parts.push(cmd_name);
    if op & FUTEX_PRIVATE_FLAG != 0 {
        parts.push("FUTEX_PRIVATE_FLAG");
    }
    if op & FUTEX_CLOCK_REALTIME != 0 {
        parts.push("FUTEX_CLOCK_REALTIME");
    }
    join_flags(&parts)
}

fn format_rlimit_resource(resource: u32) -> &'static str {
    match resource {
        RLIMIT_CPU => "RLIMIT_CPU",
        RLIMIT_FSIZE => "RLIMIT_FSIZE",
        RLIMIT_DATA => "RLIMIT_DATA",
        RLIMIT_STACK => "RLIMIT_STACK",
        RLIMIT_CORE => "RLIMIT_CORE",
        RLIMIT_RSS => "RLIMIT_RSS",
        RLIMIT_NPROC => "RLIMIT_NPROC",
        RLIMIT_NOFILE => "RLIMIT_NOFILE",
        RLIMIT_MEMLOCK => "RLIMIT_MEMLOCK",
        RLIMIT_AS => "RLIMIT_AS",
        RLIMIT_LOCKS => "RLIMIT_LOCKS",
        RLIMIT_SIGPENDING => "RLIMIT_SIGPENDING",
        RLIMIT_MSGQUEUE => "RLIMIT_MSGQUEUE",
        RLIMIT_NICE => "RLIMIT_NICE",
        RLIMIT_RTPRIO => "RLIMIT_RTPRIO",
        RLIMIT_RTTIME => "RLIMIT_RTTIME",
        _ => "RLIMIT_?",
    }
}
