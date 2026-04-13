use crate::ApeManager;
use crate::syscall::{fs as fs_sys, mm, system, task};
use glenda::error::Error;
use linux_raw_sys::general::*;

#[allow(non_upper_case_globals)]
pub(crate) fn route_syscall<'a>(
    mgr: &mut ApeManager<'a>,
    pid: usize,
    sys_num: usize,
    args: [usize; 6],
) -> Result<isize, Error> {
    let sys_num_u32 = sys_num as u32;
    match sys_num_u32 {
        __NR_read => fs_sys::sys_read(mgr, pid, args[0], args[1], args[2]),
        __NR_write => fs_sys::sys_write(mgr, pid, args[0], args[1], args[2]),
        __NR_readv => fs_sys::sys_readv(mgr, pid, args[0], args[1], args[2]),
        __NR_writev => fs_sys::sys_writev(mgr, pid, args[0], args[1], args[2]),
        __NR_openat => fs_sys::sys_openat(mgr, pid, args[0], args[1], args[2], args[3]),
        __NR_newfstatat => fs_sys::sys_newfstatat(mgr, pid, args[0], args[1], args[2], args[3]),
        __NR_close => fs_sys::sys_close(mgr, pid, args[0]),
        __NR_getcwd => system::sys_getcwd(mgr, pid, args[0], args[1]),
        __NR_chdir => system::sys_chdir(mgr, pid, args[0]),
        __NR_fchdir => system::sys_fchdir(mgr, pid, args[0]),
        __NR_chroot => system::sys_chroot(mgr, pid, args[0]),
        __NR_exit => task::sys_exit(mgr, pid, args[0]),
        __NR_exit_group => task::sys_exit_group(mgr, pid, args[0]),
        __NR_uname => system::sys_uname(mgr, pid, args[0]),
        __NR_getpid => task::sys_getpid(mgr, pid),
        __NR_gettid => task::sys_gettid(mgr, pid),
        __NR_getppid => task::sys_getppid(mgr, pid),
        __NR_set_tid_address => task::sys_set_tid_address(mgr, pid, args[0]),
        __NR_brk => mm::sys_brk(mgr, pid, args[0]),
        __NR_mmap => mm::sys_mmap(
            mgr,
            pid,
            args[0],
            args[1],
            args[2] as u32,
            args[3] as u32,
            args[4],
            args[5],
        ),
        __NR_mprotect => mm::sys_mprotect(mgr, pid, args[0], args[1], args[2] as u32),
        __NR_munmap => mm::sys_munmap(mgr, pid, args[0], args[1]),
        __NR_mremap => mm::sys_mremap(mgr, pid, args[0], args[1], args[2], args[3] as u32, args[4]),
        __NR_lseek => fs_sys::sys_lseek(mgr, pid, args[0], args[1] as isize, args[2]),
        __NR_fcntl => fs_sys::sys_fcntl(mgr, pid, args[0], args[1], args[2]),
        __NR_ioctl => fs_sys::sys_ioctl(mgr, pid, args[0], args[1], args[2]),
        __NR_execve => task::sys_execve(mgr, pid, args[0], args[1], args[2]),
        __NR_rt_sigaction => system::sys_rt_sigaction(mgr, pid, args[0], args[1], args[2], args[3]),
        __NR_rt_sigsuspend => system::sys_rt_sigsuspend(mgr, pid, args[0], args[1]),
        __NR_rt_sigprocmask => {
            system::sys_rt_sigprocmask(mgr, pid, args[0], args[1], args[2], args[3])
        }
        __NR_rt_sigpending => system::sys_rt_sigpending(mgr, pid, args[0], args[1]),
        __NR_rt_sigtimedwait => {
            system::sys_rt_sigtimedwait(mgr, pid, args[0], args[1], args[2], args[3])
        }
        __NR_set_robust_list => system::sys_set_robust_list(mgr, pid, args[0], args[1]),
        __NR_prlimit64 => system::sys_prlimit64(mgr, pid, args[0], args[1], args[2], args[3]),
        __NR_clock_gettime => system::sys_clock_gettime(mgr, pid, args[0], args[1]),
        __NR_gettimeofday => system::sys_gettimeofday(mgr, pid, args[0], args[1]),
        __NR_nanosleep => system::sys_nanosleep(mgr, pid, args[0], args[1]),
        __NR_ppoll => system::sys_ppoll(mgr, pid, args[0], args[1], args[2], args[3], args[4]),
        __NR_getrandom => system::sys_getrandom(mgr, pid, args[0], args[1], args[2]),
        __NR_getuid => system::sys_getuid(mgr, pid),
        __NR_geteuid => system::sys_geteuid(mgr, pid),
        __NR_getgid => system::sys_getgid(mgr, pid),
        __NR_getegid => system::sys_getegid(mgr, pid),
        __NR_clone => task::sys_clone(mgr, pid, args[0], args[1], args[2], args[3], args[4]),
        __NR_wait4 => task::sys_wait4(mgr, pid, args[0], args[1], args[2], args[3]),
        __NR_setsid => task::sys_setsid(mgr, pid),
        __NR_getsid => task::sys_getsid(mgr, pid, args[0]),
        __NR_setpgid => task::sys_setpgid(mgr, pid, args[0], args[1]),
        __NR_getpgid => task::sys_getpgid(mgr, pid, args[0]),
        __NR_kill => task::sys_kill(mgr, pid, args[0] as isize, args[1] as isize),
        __NR_reboot => system::sys_reboot(mgr, pid, args[0], args[1], args[2], args[3]),
        __NR_sched_yield => system::sys_sched_yield(mgr, pid),
        __NR_prctl => system::sys_prctl(mgr, pid, args[0], args[1], args[2], args[3], args[4]),
        __NR_futex => {
            system::sys_futex(mgr, pid, args[0], args[1], args[2], args[3], args[4], args[5])
        }
        _ => Err(Error::NotImplemented),
    }
}
