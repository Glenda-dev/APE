#[cfg(feature = "strace")]
mod strace;

pub(crate) mod linux_conv;

use crate::ApeManager;
use core::mem::size_of;
use glenda::error::Error;

pub(crate) fn write_obj_to_user<'a, T>(
    mgr: &mut ApeManager<'a>,
    pid: usize,
    user_ptr: usize,
    obj: &T,
) -> Result<(), Error> {
    let bytes =
        unsafe { core::slice::from_raw_parts((obj as *const T) as *const u8, size_of::<T>()) };
    mgr.copy_to_user(pid, user_ptr, bytes)
}
