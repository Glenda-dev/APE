use crate::ApeManager;
use crate::syscall::common::map_error_to_errno;
use crate::syscall::dispatch::route_syscall;
use linux_raw_sys::errno::ENOSYS;

/// Syscall 统一入口层（Phase1）：
/// - enter/exit 横切处理（strace）
/// - 错误到 errno 的统一映射
/// - 未实现 syscall 的统一记录
pub fn dispatch_syscall<'a>(
    mgr: &mut ApeManager<'a>,
    pid: usize,
    sys_num: usize,
    args: [usize; 6],
) -> isize {
    let sys_num_u32 = sys_num as u32;
    let result = route_syscall(mgr, pid, sys_num, args);

    let ret = match result {
        Ok(ret) => ret,
        Err(e) => map_error_to_errno(e),
    };

    if ret == -(ENOSYS as isize) {
        error!("syscall: unimplemented syscall number {} called by pid {}", sys_num, pid);
    }

    ret
}
