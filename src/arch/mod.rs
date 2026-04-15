pub mod riscv;
pub mod x86;

use glenda::ipc::MsgArgs;

pub type SyscallArgs = [usize; 6];

#[cfg(any(target_arch = "riscv32", target_arch = "riscv64"))]
pub use riscv::*;
#[cfg(any(target_arch = "x86_64", target_arch = "x86"))]
pub use x86::*;

#[cfg(not(any(
	target_arch = "riscv32",
	target_arch = "riscv64",
	target_arch = "x86_64",
	target_arch = "x86"
)))]
pub fn parse_syscall_args(args: MsgArgs) -> (usize, SyscallArgs) {
	// 保持与历史 fallback 一致：sys_num 在 mr0，参数从 mr1 开始。
	(args[0], [args[1], args[2], args[3], args[4], args[5], args[6]])
}
