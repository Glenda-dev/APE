use crate::ApeManager;
use crate::syscall::*;
use glenda::error::Error;
use libape::policy::{ApeSyscall, decode_ape_syscall};

#[allow(non_upper_case_globals)]
pub(crate) fn route_syscall<'a>(
    mgr: &mut ApeManager<'a>,
    pid: usize,
    sys_num: usize,
    args: [usize; 6],
) -> Result<isize, Error> {
    match decode_ape_syscall(sys_num) {
        ApeSyscall::Read => io::sys_read(mgr, pid, args[0], args[1], args[2]),
        ApeSyscall::Write => io::sys_write(mgr, pid, args[0], args[1], args[2]),
        ApeSyscall::Readv => io::sys_readv(mgr, pid, args[0], args[1], args[2]),
        ApeSyscall::Writev => io::sys_writev(mgr, pid, args[0], args[1], args[2]),
        ApeSyscall::OpenAt => fs::sys_openat(mgr, pid, args[0], args[1], args[2], args[3]),
        ApeSyscall::NewFstatAt => fs::sys_newfstatat(mgr, pid, args[0], args[1], args[2], args[3]),
        ApeSyscall::Close => fs::sys_close(mgr, pid, args[0]),
        ApeSyscall::GetCwd => system::sys_getcwd(mgr, pid, args[0], args[1]),
        ApeSyscall::Chdir => system::sys_chdir(mgr, pid, args[0]),
        ApeSyscall::Fchdir => system::sys_fchdir(mgr, pid, args[0]),
        ApeSyscall::Chroot => system::sys_chroot(mgr, pid, args[0]),
        ApeSyscall::Exit => task::sys_exit(mgr, pid, args[0]),
        ApeSyscall::ExitGroup => task::sys_exit_group(mgr, pid, args[0]),
        ApeSyscall::Uname => system::sys_uname(mgr, pid, args[0]),
        ApeSyscall::GetPid => task::sys_getpid(mgr, pid),
        ApeSyscall::GetTid => task::sys_gettid(mgr, pid),
        ApeSyscall::GetPpid => task::sys_getppid(mgr, pid),
        ApeSyscall::SetTidAddress => task::sys_set_tid_address(mgr, pid, args[0]),
        ApeSyscall::Brk => mm::sys_brk(mgr, pid, args[0]),
        ApeSyscall::Mmap => mm::sys_mmap(
            mgr,
            pid,
            args[0],
            args[1],
            args[2] as u32,
            args[3] as u32,
            args[4],
            args[5],
        ),
        ApeSyscall::Mprotect => mm::sys_mprotect(mgr, pid, args[0], args[1], args[2] as u32),
        ApeSyscall::Munmap => mm::sys_munmap(mgr, pid, args[0], args[1]),
        ApeSyscall::Mremap => {
            mm::sys_mremap(mgr, pid, args[0], args[1], args[2], args[3] as u32, args[4])
        }
        ApeSyscall::Lseek => io::sys_lseek(mgr, pid, args[0], args[1] as isize, args[2]),
        ApeSyscall::Fcntl => fs::sys_fcntl(mgr, pid, args[0], args[1], args[2]),
        ApeSyscall::Ioctl => io::sys_ioctl(mgr, pid, args[0], args[1], args[2]),
        ApeSyscall::Execve => task::sys_execve(mgr, pid, args[0], args[1], args[2]),
        ApeSyscall::RtSigaction => {
            system::sys_rt_sigaction(mgr, pid, args[0], args[1], args[2], args[3])
        }
        ApeSyscall::RtSigsuspend => system::sys_rt_sigsuspend(mgr, pid, args[0], args[1]),
        ApeSyscall::RtSigprocmask => {
            system::sys_rt_sigprocmask(mgr, pid, args[0], args[1], args[2], args[3])
        }
        ApeSyscall::RtSigpending => system::sys_rt_sigpending(mgr, pid, args[0], args[1]),
        ApeSyscall::RtSigtimedwait => {
            system::sys_rt_sigtimedwait(mgr, pid, args[0], args[1], args[2], args[3])
        }
        ApeSyscall::RtSigreturn => system::sys_rt_sigreturn(mgr, pid),
        ApeSyscall::SetRobustList => system::sys_set_robust_list(mgr, pid, args[0], args[1]),
        ApeSyscall::Prlimit64 => system::sys_prlimit64(mgr, pid, args[0], args[1], args[2], args[3]),
        ApeSyscall::ClockGettime => system::sys_clock_gettime(mgr, pid, args[0], args[1]),
        ApeSyscall::Gettimeofday => system::sys_gettimeofday(mgr, pid, args[0], args[1]),
        ApeSyscall::Nanosleep => system::sys_nanosleep(mgr, pid, args[0], args[1]),
        ApeSyscall::Ppoll => system::sys_ppoll(mgr, pid, args[0], args[1], args[2], args[3], args[4]),
        ApeSyscall::Getrandom => system::sys_getrandom(mgr, pid, args[0], args[1], args[2]),
        ApeSyscall::Getuid => system::sys_getuid(mgr, pid),
        ApeSyscall::Geteuid => system::sys_geteuid(mgr, pid),
        ApeSyscall::Getgid => system::sys_getgid(mgr, pid),
        ApeSyscall::Getegid => system::sys_getegid(mgr, pid),
        ApeSyscall::Clone => task::sys_clone(mgr, pid, args[0], args[1], args[2], args[3], args[4]),
        ApeSyscall::Wait4 => task::sys_wait4(mgr, pid, args[0], args[1], args[2], args[3]),
        ApeSyscall::Setsid => task::sys_setsid(mgr, pid),
        ApeSyscall::Getsid => task::sys_getsid(mgr, pid, args[0]),
        ApeSyscall::Setpgid => task::sys_setpgid(mgr, pid, args[0], args[1]),
        ApeSyscall::Getpgid => task::sys_getpgid(mgr, pid, args[0]),
        ApeSyscall::Kill => task::sys_kill(mgr, pid, args[0] as isize, args[1] as isize),
        ApeSyscall::Reboot => system::sys_reboot(mgr, pid, args[0], args[1], args[2], args[3]),
        ApeSyscall::SchedYield => system::sys_sched_yield(mgr, pid),
        ApeSyscall::Prctl => system::sys_prctl(mgr, pid, args[0], args[1], args[2], args[3], args[4]),
        ApeSyscall::Futex => {
            system::sys_futex(mgr, pid, args[0], args[1], args[2], args[3], args[4], args[5])
        }
        ApeSyscall::Unsupported => Err(Error::NotImplemented),
    }
}
