#![no_std]
#![no_main]

extern crate alloc;
use glenda;
mod ape;
mod handler;
mod server;

pub use ape::ApeService;

#[macro_export]
macro_rules! log {
    ($($arg:tt)*) => ({
        glenda::println!("APE: {}", format_args!($($arg)*));
    })
}

#[unsafe(no_mangle)]
fn main() -> usize {
    log!("Starting ANSI/POSIX Environment (APE) Service...");
    0
}
