use crate::ApeManager;
use glenda::error::Error;

pub fn sys_stub_bypass<'a>(_mgr: &mut ApeManager<'a>) -> Result<isize, Error> {
    Ok(0)
}

pub fn sys_stub_kill<'a>(mgr: &mut ApeManager<'a>, pid: usize) -> Result<isize, Error> {
    mgr.terminate_process(pid, 0).map(|_| 0)
}

// TODO: Add stub fd
pub fn sys_stub_open(_mgr: &mut ApeManager<'_>, _pid: usize) -> Result<isize, Error> {
    unimplemented!("sys_stub_open is not implemented yet");
}
