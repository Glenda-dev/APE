//! Task 子系统语义层（非 ABI 层）。
//! 该模块承载与进程/线程生命周期及关系相关的核心操作，供 syscall 薄封装调用。

pub mod exec;
pub mod job;
pub mod lifecycle;

pub(crate) use exec::do_execve;
pub(crate) use job::{do_getpgid, do_getsid, do_kill, do_setpgid, do_setsid};
pub(crate) use lifecycle::{
    do_clone, do_exit, do_exit_group, do_fork, do_getpid, do_getppid, do_gettid,
    do_set_tid_address, do_wait4,
};
