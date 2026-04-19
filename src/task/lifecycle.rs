use crate::ApeManager;
use crate::ape::process::MemoryMap;
use crate::layout::APE_SLOT;
use alloc::format;
use alloc::vec::Vec;
use glenda::arch::mem::PGSIZE;
use glenda::cap::{CapPtr, CapType, Endpoint, Page};
use glenda::error::Error;
use glenda::interface::{
    AuthService, CSpaceService, ProcessService, ResourceService, VSpaceService,
};
use glenda::ipc::Badge;
use glenda::mem::Perms;
use glenda::protocol::auth::IdentityInfo;
use glenda::utils::align::align_up;
use linux_raw_sys::errno::{ECHILD, ENOSYS};
use linux_raw_sys::general::{
    CLONE_CHILD_CLEARTID, CLONE_CHILD_SETTID, CLONE_PARENT_SETTID, CLONE_VFORK, CLONE_VM, WNOHANG,
};

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
    mgr.terminate_process_preserve_reply(pid, code, false)
}

pub(crate) fn do_exit_group(
    mgr: &mut ApeManager<'_>,
    pid: usize,
    code: usize,
) -> Result<(), Error> {
    mgr.terminate_process_preserve_reply(pid, code, false)
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
        parent_identity,
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
        IdentityInfo,
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
            parent.identity,
            parent.signal_actions.clone(),
            parent.signal_blocked,
            parent.stopped,
        )
    };

    let mut child_maps = Vec::with_capacity(parent_maps.len());

    for mut map in parent_maps {
        map.cow = false;
        child_maps.push(map);
    }

    for map in &mut child_maps {
        if map.frame_cap == 0 {
            continue;
        }
        let pages = align_up(map.size, PGSIZE) / PGSIZE;
        if pages == 0 {
            continue;
        }

        if map.flags.contains(Perms::WRITE) {
            let new_frame_slot = mgr.cspace_mgr.alloc(&mut *mgr.res_client)?;
            mgr.res_client.alloc(Badge::null(), CapType::Page, pages, new_frame_slot)?;
            mgr.ledger_record_frame_alloc(
                child_pid,
                new_frame_slot,
                pages,
                "fork_private_writable_map",
            );

            let old_frame = Page::from(CapPtr::from(map.frame_cap));
            let new_frame = Page::from(new_frame_slot);

            let src = mgr.vspace_mgr.map_scratch(
                old_frame,
                Perms::READ,
                pages,
                &mut *mgr.res_client,
                &mut *mgr.cspace_mgr,
            )?;

            let dst = match mgr.vspace_mgr.map_scratch(
                new_frame,
                Perms::READ | Perms::WRITE,
                pages,
                &mut *mgr.res_client,
                &mut *mgr.cspace_mgr,
            ) {
                Ok(v) => v,
                Err(e) => {
                    let _ = mgr.vspace_mgr.unmap(src, pages);
                    return Err(e);
                }
            };

            unsafe {
                core::ptr::copy_nonoverlapping(src as *const u8, dst as *mut u8, pages * PGSIZE);
            }

            let _ = mgr.vspace_mgr.unmap(src, pages);
            let _ = mgr.vspace_mgr.unmap(dst, pages);

            map.frame_cap = new_frame_slot.bits();
            map.cow = false;
        }

        mgr.map_process_frame(
            child_pid,
            Page::from(CapPtr::from(map.frame_cap)),
            map.vaddr,
            map.flags,
            pages,
        )?;
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
        child.identity = parent_identity;
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

    if let Some(child) = mgr.get_process(child_pid) {
        let _ = mgr.auth_client.set_identity(child_pid, child.identity);
    }

    {
        let parent_tcb = mgr.get_process(pid).ok_or(Error::NotFound)?.tcb();
        let child_tcb = mgr.get_process(child_pid).ok_or(Error::NotFound)?.tcb();
        let fault_ep = Endpoint::from(CapPtr::concat(
            mgr.get_process(child_pid).ok_or(Error::NotFound)?.cspace().cap(),
            APE_SLOT,
        ));
        child_tcb.set_fault_handler(fault_ep)?;
        child_tcb.fork_from(parent_tcb)?;
        child_tcb.resume()?;
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
    mgr: &mut ApeManager<'_>,
    pid: usize,
    target_pid: isize,
    wstatus: usize,
    options: usize,
    _rusage: usize,
) -> Result<isize, Error> {
    if let Some(proc) = mgr.get_process_mut(pid) {
        proc.clear_wait4_block();
    }

    let caller_pgid = mgr.get_process(pid).ok_or(Error::NotFound)?.process_group_id;

    if let Some((reaped_pid, status)) = mgr.pop_waitable_exited_child(pid, target_pid, caller_pgid)
    {
        if wstatus != 0 {
            mgr.copy_to_user(pid, wstatus, &status.to_ne_bytes())?;
        }
        return Ok(reaped_pid as isize);
    }

    if !mgr.has_waitable_child(pid, target_pid, caller_pgid) {
        return Ok(-(ECHILD as isize));
    }

    if (options & WNOHANG as usize) != 0 {
        return Ok(0);
    }

    if let Some(proc) = mgr.get_process_mut(pid) {
        proc.arm_wait4_block(target_pid, caller_pgid);
    }

    let tcb = mgr.get_process(pid).ok_or(Error::NotFound)?.tcb();
    if let Err(e) = tcb.suspend() {
        warn!("wait4: failed to suspend pid={} in blocking wait4: {:?}", pid, e);
        if let Some(proc) = mgr.get_process_mut(pid) {
            proc.clear_wait4_block();
        }
    }

    Ok(0)
}
