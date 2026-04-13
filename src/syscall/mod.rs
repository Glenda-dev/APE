//! Syscall 子系统分层：
//! - `dispatch`: 仅负责 syscall 号路由
//! - `common`: 通用横切逻辑（errno 映射）
//! - `task/system`: 各领域 syscall ABI 入口（`sys_*`）与内部语义实现（`do_*`）
//! - `crate::trace`: strace 风格日志（按 syscall 类型格式化）

mod common;
mod dispatch;
pub mod system;
pub mod task;

pub use dispatch::*;
