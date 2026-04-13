#![allow(non_upper_case_globals)]

use alloc::format;
use alloc::string::String;
use linux_raw_sys::errno::*;
use linux_raw_sys::general::*;

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
