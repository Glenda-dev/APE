use glenda::ipc::MsgArgs;

use super::SyscallArgs;

pub mod constants {
    pub const INST_PAGE_FAULT: usize = 12;
    pub const LOAD_PAGE_FAULT: usize = 13;
    pub const STORE_PAGE_FAULT: usize = 15;
}

/// RISC-V Linux ABI:
/// - a7: syscall number
/// - a0..a5: syscall args[0..6)
pub fn parse_syscall_args(args: MsgArgs) -> (usize, SyscallArgs) {
    (args[7], [args[0], args[1], args[2], args[3], args[4], args[5]])
}
