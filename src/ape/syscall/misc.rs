use crate::ApeManager;
use glenda::error::Error;
use glenda::log;

pub fn sys_uname<'a>(mgr: &mut ApeManager<'a>, pid: usize, buf_ptr: usize) -> Result<isize, Error> {
    log!("sys_uname: pid {} buf_ptr {:#x}", pid, buf_ptr);
    Ok(0)
}
