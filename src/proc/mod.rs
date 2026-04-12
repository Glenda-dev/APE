//! Process 子系统语义层（非 ABI 层）。
//! 该模块承载与进程生命周期/关系相关的核心操作，供 syscall 薄封装调用。

mod lifecycle;

use crate::ApeManager;
use crate::ape::process::MemoryMap;
use alloc::vec::Vec;
use glenda::error::Error;
use glenda::interface::{CSpaceService, ProcessService, ResourceService};
use glenda::ipc::Badge;

pub(crate) fn do_set_tid_address<'a>(
    mgr: &mut ApeManager<'a>,
    pid: usize,
    tidptr: usize,
) -> Result<usize, Error> {
    let process = mgr.get_process_mut(pid).ok_or(Error::NotFound)?;
    process.clear_child_tid = tidptr;
    Ok(pid)
}

pub(crate) fn do_exit<'a>(mgr: &mut ApeManager<'a>, pid: usize, code: usize) -> Result<(), Error> {
    mgr.terminate_process(pid, code, false)
}

pub(crate) fn do_getppid<'a>(mgr: &mut ApeManager<'a>, pid: usize) -> Result<usize, Error> {
    let process = mgr.get_process(pid).ok_or(Error::NotFound)?;
    Ok(process.parent_pid)
}

pub(crate) fn do_fork<'a>(mgr: &mut ApeManager<'a>, pid: usize) -> Result<usize, Error> {
    // 1. 获取父进程信息
    let name = alloc::format!("fork-{}", pid);

    // 2. 创建新进程
    let child_pid = mgr.proc_client.create(Badge::null(), &name)?;

    // 3. 获取并注册子进程 CNode
    let cnode_slot = mgr.cspace_mgr.alloc(&mut *mgr.res_client)?;
    let cnode = mgr.proc_client.get_cnode(Badge::null(), child_pid, cnode_slot)?;
    mgr.register_process(pid, child_pid, cnode);

    // 4. 实现 CoW Fork 逻辑
    let parent_maps: Vec<MemoryMap> = {
        let parent = mgr.get_process(pid).ok_or(Error::NotFound)?;
        parent.memory_maps.values().cloned().collect()
    };

    for map in parent_maps {
        // 标记为 CoW
        let mut child_map = map.clone();
        child_map.cow = true;

        if let Some(process) = mgr.get_process_mut(child_pid) {
            process.add_memory_map(child_map);
        }
    }

    Ok(child_pid)
}
