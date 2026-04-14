use crate::ApeManager;
use crate::ape::process::MemoryMap;
use alloc::format;
use alloc::vec::Vec;
use glenda::cap::{CapPtr, Frame};
use glenda::error::Error;
use glenda::interface::{CSpaceService, ProcessService, ResourceService};
use glenda::ipc::Badge;
use glenda::mem::Perms;
use linux_raw_sys::errno::{ECHILD, ENOSYS};
use linux_raw_sys::general::{
    CLONE_CHILD_CLEARTID, CLONE_CHILD_SETTID, CLONE_PARENT_SETTID, CLONE_VFORK, CLONE_VM,
};

fn cow_fault_perms(perms: Perms) -> Perms {
    let mut p = perms;
    p.remove(Perms::WRITE);
    p
}

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

    let (
        parent_maps,
        parent_lazy_maps,
        parent_fds,
        parent_fd_paths,
        parent_fd_cloexec,
        parent_next_fd,
        parent_session_id,
        parent_process_group_id,
        parent_controlling_tty,
        parent_root_dir,
        parent_cwd,
        parent_stack_bottom,
        parent_stack_size,
        parent_max_stack_size,
        parent_heap_start,
        parent_heap_brk,
        parent_heap_limit,
        parent_mmap_base,
        parent_mmap_next,
        parent_mmap_limit,
        parent_clear_child_tid,
        parent_signal_actions,
        parent_signal_blocked,
        parent_stopped,
    ): (
        Vec<MemoryMap>,
        Vec<MemoryMap>,
        alloc::collections::BTreeMap<u32, crate::ape::process::FileHandle>,
        alloc::collections::BTreeMap<u32, alloc::string::String>,
        alloc::collections::BTreeMap<u32, bool>,
        u32,
        usize,
        usize,
        Option<usize>,
        alloc::string::String,
        alloc::string::String,
        usize,
        usize,
        usize,
        usize,
        usize,
        usize,
        usize,
        usize,
        usize,
        usize,
        alloc::collections::BTreeMap<usize, crate::ape::process::SignalAction>,
        u64,
        bool,
    ) = {
        let parent = mgr.get_process(pid).ok_or(Error::NotFound)?;
        (
            parent.memory_maps.values().cloned().collect(),
            parent.lazy_memory_maps.values().cloned().collect(),
            parent.fds.clone(),
            parent.fd_paths.clone(),
            parent.fd_cloexec.clone(),
            parent.next_fd,
            parent.session_id,
            parent.process_group_id,
            parent.controlling_tty,
            parent.root_dir.clone(),
            parent.cwd.clone(),
            parent.stack_bottom,
            parent.stack_size,
            parent.max_stack_size,
            parent.heap_start,
            parent.heap_brk,
            parent.heap_limit,
            parent.mmap_base,
            parent.mmap_next,
            parent.mmap_limit,
            parent.clear_child_tid,
            parent.signal_actions.clone(),
            parent.signal_blocked,
            parent.stopped,
        )
    };

    let mut parent_ro_remaps: Vec<(usize, usize, Perms)> = Vec::new();
    let mut child_maps = Vec::with_capacity(parent_maps.len());

    for mut map in parent_maps {
        if map.frame_cap != 0 && map.flags.contains(Perms::WRITE) {
            map.cow = true;
            parent_ro_remaps.push((map.vaddr, map.frame_cap, cow_fault_perms(map.flags)));
        }
        child_maps.push(map);
    }

    {
        let parent = mgr.get_process_mut(pid).ok_or(Error::NotFound)?;
        for map in parent.memory_maps.values_mut() {
            if map.frame_cap != 0 && map.flags.contains(Perms::WRITE) {
                map.cow = true;
            }
        }
    }

    for (vaddr, frame_cap, ro_perms) in parent_ro_remaps {
        let _ = mgr.unmap_process_pages(pid, vaddr, 1);
        mgr.map_process_frame(pid, Frame::from(CapPtr::from(frame_cap)), vaddr, ro_perms, 1)?;
    }

    {
        let child = mgr.get_process_mut(child_pid).ok_or(Error::NotFound)?;

        child.root_dir = parent_root_dir;
        child.cwd = parent_cwd;
        child.fds = parent_fds;
        child.fd_paths = parent_fd_paths;
        child.fd_cloexec = parent_fd_cloexec;
        child.next_fd = parent_next_fd;
        child.session_id = parent_session_id;
        child.process_group_id = parent_process_group_id;
        child.controlling_tty = parent_controlling_tty;

        child.stack_bottom = parent_stack_bottom;
        child.stack_size = parent_stack_size;
        child.max_stack_size = parent_max_stack_size;
        child.heap_start = parent_heap_start;
        child.heap_brk = parent_heap_brk;
        child.heap_limit = parent_heap_limit;
        child.mmap_base = parent_mmap_base;
        child.mmap_next = parent_mmap_next;
        child.mmap_limit = parent_mmap_limit;
        child.clear_child_tid = parent_clear_child_tid;
        child.signal_actions = parent_signal_actions;
        child.signal_blocked = parent_signal_blocked;
        // Linux 语义：fork 后子进程 pending signal 为空。
        child.signal_pending = 0;
        child.stopped = parent_stopped;

        child.memory_maps.clear();
        child.lazy_memory_maps.clear();

        for map in child_maps {
            child.add_memory_map(map);
        }
        for map in parent_lazy_maps {
            child.add_lazy_memory_map(map);
        }
    }

    Ok(child_pid)
}

pub(crate) fn do_clone(
    mgr: &mut ApeManager<'_>,
    pid: usize,
    flags: usize,
    _stack: usize,
    ptid: usize,
    ctid: usize,
    _tls: usize,
) -> Result<isize, Error> {
    let clone_flags = flags & !0xffusize;
    let supported = clone_flags == 0 || clone_flags == (CLONE_VM as usize | CLONE_VFORK as usize);

    if !supported {
        return Ok(-(ENOSYS as isize));
    }

    let child_pid = do_fork(mgr, pid)?;

    if (clone_flags & CLONE_PARENT_SETTID as usize) != 0 && ptid != 0 {
        mgr.write_obj_to_user(pid, ptid, &child_pid)?;
    }

    if let Some(child) = mgr.get_process_mut(child_pid) {
        if (clone_flags & CLONE_CHILD_CLEARTID as usize) != 0 {
            child.clear_child_tid = ctid;
        }
        if (clone_flags & CLONE_CHILD_SETTID as usize) != 0 && ctid != 0 {
            child.clear_child_tid = ctid;
        }
    }

    Ok(child_pid as isize)
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
