use crate::ApeManager;
use crate::ape::syscall::*;
use glenda::error::Error;
use glenda::log;
use linux_raw_sys::errno::*;
use linux_raw_sys::general::*;

#[allow(non_upper_case_globals)]
fn syscall_name(sys_num: u32) -> &'static str {
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
        __NR_ioctl => "ioctl",
        __NR_read => "read",
        __NR_write => "write",
        __NR_readv => "readv",
        __NR_writev => "writev",
        __NR_openat => "openat",
        __NR_close => "close",
        __NR_uname => "uname",
        __NR_rt_sigaction => "rt_sigaction",
        __NR_rt_sigprocmask => "rt_sigprocmask",
        __NR_set_robust_list => "set_robust_list",
        __NR_prlimit64 => "prlimit64",
        __NR_clock_gettime => "clock_gettime",
        __NR_gettimeofday => "gettimeofday",
        __NR_nanosleep => "nanosleep",
        __NR_getrandom => "getrandom",
        __NR_getuid => "getuid",
        __NR_geteuid => "geteuid",
        __NR_getgid => "getgid",
        __NR_getegid => "getegid",
        __NR_execve => "execve",
        __NR_clone => "clone",
        _ => "unknown",
    }
}

fn map_error_to_errno(err: Error) -> isize {
    match err {
        Error::OutOfMemory | Error::CNodeFull => -(ENOMEM as isize),
        Error::InvalidArgs | Error::InvalidConfig => -(EINVAL as isize),
        Error::InvalidAddress => -(EFAULT as isize),
        Error::MessageTooLong => -(ENAMETOOLONG as isize),
        Error::InvalidSlot => -(EBADF as isize),
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

#[allow(non_upper_case_globals)]
pub fn handler<'a>(
    mgr: &mut ApeManager<'a>,
    pid: usize,
    sys_num: usize,
    args: [usize; 6],
) -> isize {
    let sys_num_u32 = sys_num as u32;
    let name = syscall_name(sys_num_u32);

    let result = match sys_num_u32 {
        __NR_read => sys_read(mgr, pid, args[0], args[1], args[2]),
        __NR_write => sys_write(mgr, pid, args[0], args[1], args[2]),
        __NR_readv => sys_readv(mgr, pid, args[0], args[1], args[2]),
        __NR_writev => sys_writev(mgr, pid, args[0], args[1], args[2]),
        __NR_openat => sys_openat(mgr, pid, args[0], args[1], args[2], args[3]),
        __NR_close => sys_close(mgr, pid, args[0]),
        __NR_exit => sys_exit(mgr, pid, args[0]),
        __NR_exit_group => sys_exit_group(mgr, pid, args[0]),
        __NR_uname => sys_uname(mgr, pid, args[0]),
        __NR_getpid => sys_getpid(mgr, pid),
        __NR_gettid => sys_gettid(mgr, pid),
        __NR_getppid => sys_getppid(mgr, pid),
        __NR_set_tid_address => sys_set_tid_address(mgr, pid, args[0]),
        __NR_brk => sys_brk(mgr, pid, args[0]),
        __NR_mmap => {
            sys_mmap(mgr, pid, args[0], args[1], args[2] as u32, args[3] as u32, args[4], args[5])
        }
        __NR_mprotect => sys_mprotect(mgr, pid, args[0], args[1], args[2] as u32),
        __NR_munmap => sys_munmap(mgr, pid, args[0], args[1]),
        __NR_lseek => sys_lseek(mgr, pid, args[0], args[1] as isize, args[2]),
        __NR_ioctl => sys_ioctl(mgr, pid, args[0], args[1], args[2]),
        __NR_execve => sys_execve(mgr, pid, args[0], args[1], args[2]),
        __NR_rt_sigaction => sys_rt_sigaction(mgr, pid, args[0], args[1], args[2], args[3]),
        __NR_rt_sigprocmask => sys_rt_sigprocmask(mgr, pid, args[0], args[1], args[2], args[3]),
        __NR_set_robust_list => sys_set_robust_list(mgr, pid, args[0], args[1]),
        __NR_prlimit64 => sys_prlimit64(mgr, pid, args[0], args[1], args[2], args[3]),
        __NR_clock_gettime => sys_clock_gettime(mgr, pid, args[0], args[1]),
        __NR_gettimeofday => sys_gettimeofday(mgr, pid, args[0], args[1]),
        __NR_nanosleep => sys_nanosleep(mgr, pid, args[0], args[1]),
        __NR_getrandom => sys_getrandom(mgr, pid, args[0], args[1], args[2]),
        __NR_getuid => sys_getuid(mgr, pid),
        __NR_geteuid => sys_geteuid(mgr, pid),
        __NR_getgid => sys_getgid(mgr, pid),
        __NR_getegid => sys_getegid(mgr, pid),
        __NR_clone => sys_fork(mgr, pid),
        _ => Err(Error::NotImplemented), // map ENOSYS later
    };

    let ret = match result {
        Ok(ret) => ret,
        Err(e) => map_error_to_errno(e),
    };

    if name == "unknown" {
        log!(
            "[pid {}] syscall#{}({:#x}, {:#x}, {:#x}, {:#x}, {:#x}, {:#x}) = {}",
            pid,
            sys_num_u32,
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
    ret
}
