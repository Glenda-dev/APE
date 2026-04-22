//! I/O subsystem root module (Linux-style layout placeholder).
//!
//! 当前 APE 的文件 I/O 主要通过 `crate::fs` 提供。
//! TODO(ape): 将 poll/epoll、设备事件与异步 I/O 逐步收敛到 io 子系统。
//! 后续可将设备 I/O、多路复用、异步事件等能力逐步下沉到本模块。

pub mod file;
