//! Syscall 子系统分层：
//! - `dispatch`: 仅负责 syscall 号路由
//! - `common`: 通用横切逻辑（名称映射、errno 映射、统一日志）
//! - `task/system`: 各领域 syscall ABI 入口（`sys_*`）与内部语义实现（`do_*`）

mod common;
mod dispatch;
pub mod system;
pub mod task;

pub use dispatch::*;
