#[cfg(feature = "strace")]
pub mod strace;

pub(crate) mod linux_conv;

use crate::ApeManager;
use core::mem::size_of;
use glenda::error::Error;
