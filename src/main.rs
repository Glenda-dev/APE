#![no_std]
#![no_main]

#[macro_use]
extern crate glenda;

extern crate alloc;
mod handler;
mod process;
mod server;

pub use ape::ApeManager;

#[unsafe(no_mangle)]
fn main() -> usize {
    glenda::console::init_logging("APE");
    log!("Starting ANSI/POSIX Environment (APE) Service...");
    0
}
