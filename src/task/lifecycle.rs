use crate::ApeManager;
use crate::ape::process::MemoryMap;
use alloc::format;
use alloc::vec::Vec;
use glenda::error::Error;
use glenda::interface::{CSpaceService, ProcessService, ResourceService};
use glenda::ipc::Badge;
use linux_raw_sys::errno::{ECHILD, ENOSYS};

pub(crate) fn do_getpid(mgr: &mut ApeManager<'_>, pid: usize) -> Result<usize, Error> {
    let _ = mgr;
    Ok(pid)
}

pub(crate) fn do_gettid(mgr: &mut ApeManager<'_>, pid: usize) -> Result<usize, Error> {
    let _ = mgr;
    Ok(pid)
}

pub(crate) fn do_set_tid_address(
    mgr: &mut ApeManager<'_>,
    pid: usize,
    tidptr: usize,
) -> Result<usize, Error> {
    let process = mgr.get_process_mut(pid).ok_or(Error::NotFound)?;
    process.clear_child_tid = tidptr;
    Ok(pid)
}

pub(crate) fn do_exit(mgr: &mut ApeManager<'_>, pid: usize, code: usize) -> Result<(), Error> {
    mgr.terminate_process(pid, code, false)
}

pub(crate) fn do_exit_group(
    mgr: &mut ApeManager<'_>,
    pid: usize,
    code: usize,
) -> Result<(), Error> {
    do_exit(mgr, pid, code)
}

pub(crate) fn do_getppid(mgr: &mut ApeManager<'_>, pid: usize) -> Result<usize, Error> {
    let process = mgr.get_process(pid).ok_or(Error::NotFound)?;
    Ok(process.parent_pid)
}

pub(crate) fn do_fork(mgr: &mut ApeManager<'_>, pid: usize) -> Result<usize, Error> {
    let name = format!("fork-{}", pid);
    let child_host_pid = mgr.proc_client.create(Badge::null(), &name)?;
    let cnode_slot = mgr.cspace_mgr.alloc(&mut *mgr.res_client)?;
    let cnode = mgr.proc_client.get_cnode(Badge::null(), child_host_pid, cnode_slot)?;
    let child_pid = mgr.register_process(pid, child_host_pid, cnode);

    let parent_maps: Vec<MemoryMap> = {
        let parent = mgr.get_process(pid).ok_or(Error::NotFound)?;
        parent.memory_maps.values().cloned().collect()
    };

    for map in parent_maps {
        let mut child_map = map;
        child_map.cow = true;

        if let Some(process) = mgr.get_process_mut(child_pid) {
            process.add_memory_map(child_map);
        }
    }

    Ok(child_pid)
}

pub(crate) fn do_clone(
    _mgr: &mut ApeManager<'_>,
    _pid: usize,
    _flags: usize,
    _stack: usize,
    _ptid: usize,
    _ctid: usize,
    _tls: usize,
) -> Result<isize, Error> {
    // TODO(ape): 实现 clone(2) 语义，支持 CLONE_* 标志组合与线程模型。
    Ok(-(ENOSYS as isize))
}

pub(crate) fn do_wait4(
    _mgr: &mut ApeManager<'_>,
    _pid: usize,
    _target_pid: usize,
    _wstatus: usize,
    _options: usize,
    _rusage: usize,
) -> Result<isize, Error> {
    // TODO(ape): 实现 wait4(2) 子进程回收、状态写回与 options 语义。
    Ok(-(ECHILD as isize))
}
