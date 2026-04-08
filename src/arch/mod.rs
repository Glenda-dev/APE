pub mod riscv;
pub mod x86;
#[cfg(any(target_arch = "riscv32", target_arch = "riscv64"))]
pub use riscv::*;
#[cfg(any(target_arch = "x86_64", target_arch = "x86"))]
pub use x86::*;
