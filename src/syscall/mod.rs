//! Syscall 子系统分层：
//! - `entry`: syscall 统一入口与横切处理（trace/errno/ENOSYS 记录）
//! - `dispatch`: 仅负责 syscall 号路由
//! - `common`: 通用横切逻辑（errno 映射）
//! - `task/system/mm/fs`: 各领域 syscall ABI 入口（`sys_*`）
//! - `crate::trace`: strace 风格日志（按 syscall 类型格式化）

mod common;
mod dispatch;
mod entry;
pub mod fs;
pub mod io;
pub mod mm;
pub mod system;
pub mod task;

pub use entry::*;
