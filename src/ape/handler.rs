use crate::ApeManager;
use crate::ape::syscall::*;
use ape::sys::constants::*;
use glenda::ipc::{Badge, UTCB};
use glenda::log;

pub fn handler<'a>(
    mgr: &mut ApeManager<'a>,
    pid: usize,
    sys_num: usize,
    args: [usize; 6],
) -> isize {
    log!("Syscall {} from PID {}", sys_num, pid);

    let result = match sys_num {
        SYS_GETPID => sys_getpid(mgr, pid),
        SYS_GETPPID => sys_getppid(mgr, pid),
        SYS_UNAME => sys_uname(mgr, pid, args[0]),
        SYS_READ => sys_read(mgr, pid, args[0], args[1], args[2]),
        SYS_WRITE => sys_write(mgr, pid, args[0], args[1], args[2]),
        SYS_OPENAT => sys_openat(mgr, pid, args[0], args[1], args[2], args[3]),
        SYS_CLOSE => sys_close(mgr, pid, args[0]),
        SYS_EXECVE => sys_execve(mgr, pid, args[0], args[1], args[2]).map(|v| v as isize),
        SYS_CLONE => sys_fork(mgr, pid).map(|v| v as isize),
        _ => Err(glenda::error::Error::NotImplemented), // map ENOSYS later
    };

    match result {
        Ok(ret) => ret,
        Err(e) => {
            error!("Syscall {} from PID {} failed with error: {:?}", sys_num, pid, e);
            (-ENOSYS) as isize
        }
    }
}
