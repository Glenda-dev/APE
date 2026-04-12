use glenda::error::Error;
use glenda::log;
use linux_raw_sys::errno::*;
use linux_raw_sys::general::*;

#[allow(non_upper_case_globals)]
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
        __NR_lseek => "lseek",
        __NR_fcntl => "fcntl",
        __NR_ioctl => "ioctl",
        __NR_read => "read",
        __NR_write => "write",
        __NR_readv => "readv",
        __NR_writev => "writev",
        __NR_openat => "openat",
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

pub(crate) fn map_error_to_errno(err: Error) -> isize {
    match err {
        Error::OutOfMemory | Error::CNodeFull => -(ENOMEM as isize),
        Error::InvalidArgs | Error::InvalidConfig => -(EINVAL as isize),
        Error::InvalidCapability | Error::InvalidMethod => -(EINVAL as isize),
        Error::InvalidType => -(ENOTTY as isize),
        Error::InvalidAddress => -(EFAULT as isize),
        Error::MessageTooLong => -(ENAMETOOLONG as isize),
        Error::InvalidSlot => -(EBADF as isize),
        Error::SlotNotEmpty => -(EEXIST as isize),
        Error::NotFound => -(ENOENT as isize),
        Error::AlreadyExists => -(EEXIST as isize),
        Error::ResourceBusy => -(EBUSY as isize),
        Error::WouldBlock => -(EAGAIN as isize),
        Error::Interrupted => -(EINTR as isize),
        Error::Timeout => -(ETIMEDOUT as isize),
        Error::PermissionDenied => -(EPERM as isize),
        Error::NotSupported | Error::NotImplemented => -(ENOSYS as isize),
        Error::IoError | Error::DeviceError | Error::InternalError | Error::Generic => {
            -(EIO as isize)
        }
        _ => -(ENOSYS as isize),
    }
}

pub(crate) fn log_syscall_result(
    pid: usize,
    name: &str,
    sys_num: u32,
    args: [usize; 6],
    ret: isize,
) {
    if name == "unknown" {
        log!(
            "[pid {}] syscall#{}({:#x}, {:#x}, {:#x}, {:#x}, {:#x}, {:#x}) = {}",
            pid,
            sys_num,
            args[0],
            args[1],
            args[2],
            args[3],
            args[4],
            args[5],
            ret
        );
    } else {
        log!(
            "[pid {}] {}({:#x}, {:#x}, {:#x}, {:#x}, {:#x}, {:#x}) = {}",
            pid,
            name,
            args[0],
            args[1],
            args[2],
            args[3],
            args[4],
            args[5],
            ret
        );
    }
}
