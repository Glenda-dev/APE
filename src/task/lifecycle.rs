use crate::ApeManager;
use crate::ape::files::{FileHandle, FileType};
use crate::ape::mm::{MemoryMap, MemoryType};
use crate::ape::signal::{SIGNAL_MAX, SignalAction, signal_bit};
use crate::ape::task::{TaskLifecycleState, TaskStruct};
use crate::layout::APE_SLOT;
use crate::syscall::map_error_to_errno;
use crate::system::signal::queue_process_signal;
use alloc::collections::BTreeMap;
use alloc::format;
use alloc::sync::Arc;
use alloc::vec::Vec;
use core::sync::atomic::Ordering;
use glenda::arch::mem::PGSIZE;
use glenda::cap::{CSPACE_CAP, CapPtr, Endpoint, Page, Reply};
use glenda::error::Error;
use glenda::interface::{
    AuthService, CSpaceService, ProcessService, ResourceService, VSpaceService,
};
use glenda::ipc::{Badge, UTCB};
use glenda::mem::Perms;
use glenda::protocol::auth::IdentityInfo;
use glenda::utils::align::align_up;
use linux_raw_sys::errno::{ECHILD, ENOSYS};
use linux_raw_sys::general::{
    CLONE_CHILD_CLEARTID, CLONE_CHILD_SETTID, CLONE_PARENT_SETTID, CLONE_VFORK, CLONE_VM, SIGCHLD,
    WNOHANG,
};

impl<'a> ApeManager<'a> {
    fn try_wake_pending_wait4_reply(&mut self, parent_pid: usize) -> bool {
        let Some(pending) = self.peek_wait4_reply(parent_pid) else {
            return false;
        };

        let ret = if let Some((reaped_pid, status)) = self.pop_waitable_child_event(
            parent_pid,
            pending.target_pid,
            pending.options,
            pending.caller_pgid,
        ) {
            if pending.wstatus != 0
                && let Err(e) =
                    self.copy_to_user(parent_pid, pending.wstatus, &status.to_ne_bytes())
            {
                map_error_to_errno(e)
            } else {
                reaped_pid as isize
            }
        } else if !self.has_waitable_child(
            parent_pid,
            pending.target_pid,
            pending.options,
            pending.caller_pgid,
        ) {
            -(ECHILD as isize)
        } else {
            return false;
        };

        let Some(pending) = self.take_wait4_reply(parent_pid) else {
            return false;
        };

        if let Some(parent) = self.get_process(parent_pid) {
            parent.signal.clear_wait4_block();
        }

        let mut utcb = unsafe { UTCB::new() };
        utcb.clear();
        utcb.set_mr(0, ret as usize);

        if let Err(e) = Reply::from(pending.reply_slot).reply(&mut utcb) {
            warn!(
                "wait4: failed to reply pending wait4 pid={} via slot {:?}: {:?}",
                parent_pid, pending.reply_slot, e
            );
        }
        let _ = CSPACE_CAP.delete(pending.reply_slot);
        self.cspace_mgr.free(pending.reply_slot);
        true
    }

    fn encode_wait_status(exit_code: usize) -> i32 {
        ((exit_code & 0xff) as i32) << 8
    }

    pub fn terminate_process(&mut self, pid: usize, exit_code: usize) -> Result<(), Error> {
        let (fd_list, mapped_pages, frame_pages, parent_pid, process_group_id) = {
            let task = self.get_process(pid).ok_or(Error::NotFound)?;
            task.set_lifecycle(TaskLifecycleState::Exiting);

            let fd_list = task.files.state.read().fds.keys().copied().collect::<Vec<u32>>();
            let mapped_pages = task
                .mm
                .state
                .read()
                .memory_maps
                .values()
                .map(|m| (m.vaddr, align_up(m.size, PGSIZE) / PGSIZE))
                .collect::<Vec<(usize, usize)>>();

            let mut frame_pages = BTreeMap::new();
            for map in task.mm.state.read().memory_maps.values() {
                if map.frame_cap == 0 {
                    continue;
                }
                let slot = CapPtr::from(map.frame_cap);
                let pages = align_up(map.size, PGSIZE) / PGSIZE;
                let entry = frame_pages.entry(slot).or_insert(0usize);
                *entry = core::cmp::max(*entry, pages);
            }

            (
                fd_list,
                mapped_pages,
                frame_pages,
                task.parent_pid.load(Ordering::SeqCst),
                task.process_group_id.load(Ordering::SeqCst),
            )
        };

        for fd in fd_list {
            let _ = crate::fs::fd::do_close(self, pid, fd as usize);
        }

        for (vaddr, pages) in mapped_pages {
            if pages > 0 {
                let _ = self.unmap_process_pages(pid, vaddr, pages);
            }
        }

        for (slot, pages) in frame_pages {
            self.release_process_frame_slot(pid, slot, pages, "process_exit_memory_map");
        }

        // Release CNode
        if let Some(task) = self.get_process(pid) {
            let slot = task.cspace.cap();
            let _ = CSPACE_CAP.revoke(slot);
            if let Err(e) = CSPACE_CAP.delete(slot)
                && e != Error::InvalidCapability
                && e != Error::InvalidSlot
            {
                warn!("exit: failed to delete child cnode slot {:?}: {:?}", slot, e);
            } else {
                self.cspace_mgr.free(slot);
            }
        }

        let should_skip_reply = self.service_state.ipc.active_caller_pid == Some(pid);

        if let Some(host_pid) = self.host_pid_by_local(pid) {
            let _ = self.proc_client.kill(Badge::null(), host_pid);
            self.remove_host_pid_mapping(host_pid);
        }

        let _ = self.release_process_intermediate_page_tables(pid);
        self.drop_wait4_reply(pid);
        self.drop_pending_sleep_reply(pid);

        let _ = self.ledger_take_process(pid);

        self.remove_process_record(pid);

        if parent_pid != 0 {
            let wait_status = Self::encode_wait_status(exit_code);
            self.mark_process_exited_snapshot(pid, parent_pid, process_group_id, wait_status);
            self.record_child_exit(parent_pid, pid, wait_status, process_group_id);

            let replied_wait4 = self.try_wake_pending_wait4_reply(parent_pid);
            if !replied_wait4 {
                let should_resume_wait4 = self
                    .get_process(parent_pid)
                    .map(|parent| parent.signal.wait4_block_matches(pid, process_group_id))
                    .unwrap_or(false);

                if should_resume_wait4 {
                    if let Some(parent) = self.get_process(parent_pid) {
                        parent.signal.clear_wait4_block();
                        if let Err(e) = parent.tcb().resume() {
                            warn!(
                                "wait4: failed to resume parent pid={} on child exit pid={}: {:?}",
                                parent_pid, pid, e
                            );
                        }
                    }
                }

                let _ = queue_process_signal(self, parent_pid, SIGCHLD as usize);
            }
        }

        if pid == 1 {
            panic!(
                "Init process faulted with exit code {:#x}, shutting down Ape service",
                exit_code
            );
        }

        if should_skip_reply {
            if let Err(e) = CSPACE_CAP.delete(self.service_state.ipc.reply.cap())
                && e != Error::InvalidCapability
                && e != Error::InvalidSlot
            {
                warn!(
                    "exit: failed to clear fixed reply slot {:?}: {:?}",
                    self.service_state.ipc.reply.cap(),
                    e
                );
            }
            Err(Error::Success)
        } else {
            Ok(())
        }
    }
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
    let task = mgr.get_process(pid).ok_or(Error::NotFound)?;
    task.signal.state.lock().clear_child_tid = tidptr;
    Ok(pid)
}

pub(crate) fn do_exit(mgr: &mut ApeManager<'_>, pid: usize, code: usize) -> Result<(), Error> {
    mgr.terminate_process(pid, code)
}

pub(crate) fn do_exit_group(
    mgr: &mut ApeManager<'_>,
    pid: usize,
    code: usize,
) -> Result<(), Error> {
    mgr.terminate_process(pid, code)
}

pub(crate) fn do_getppid(mgr: &mut ApeManager<'_>, pid: usize) -> Result<usize, Error> {
    let task = mgr.get_process(pid).ok_or(Error::NotFound)?;
    Ok(task.parent_pid.load(Ordering::SeqCst))
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
    ) = {
        let parent = mgr.get_process(pid).ok_or(Error::NotFound)?;
        let mm = parent.mm.state.read();
        let files = parent.files.state.read();
        let fs = parent.fs.state.read();
        let sig = parent.signal.state.lock();
        let sighand = parent.sighand.signal_actions.lock();

        (
            mm.memory_maps.values().cloned().collect::<Vec<_>>(),
            mm.lazy_memory_maps.values().cloned().collect::<Vec<_>>(),
            files.fds.clone(),
            files.fd_paths.clone(),
            files.fd_cloexec.clone(),
            files.next_fd,
            parent.session_id.load(Ordering::SeqCst),
            parent.process_group_id.load(Ordering::SeqCst),
            parent.controlling_tty.load(Ordering::SeqCst),
            fs.root_dir.clone(),
            fs.cwd.clone(),
            mm.stack_bottom,
            mm.stack_size,
            mm.max_stack_size,
            mm.heap_start,
            mm.heap_brk,
            mm.heap_limit,
            mm.mmap_base,
            mm.mmap_next,
            mm.mmap_limit,
            sig.clear_child_tid,
            parent.cred.identity.read().clone(),
            sighand.clone(),
            parent.signal.get_blocked(),
            parent.is_stopped(),
        )
    };

    let mut child_maps = parent_maps;
    let mut retained_shared_slots = alloc::collections::BTreeSet::new();

    for map in &mut child_maps {
        if map.frame_cap == 0 {
            continue;
        }
        let pages = align_up(map.size, PGSIZE) / PGSIZE;
        if pages == 0 {
            continue;
        }

        let frame_slot = CapPtr::from(map.frame_cap);
        let frame = Page::from(frame_slot);

        let writable = map.flags.contains(Perms::WRITE);
        let child_map_perms = if writable {
            let mut p = map.flags;
            p.remove(Perms::WRITE);
            p
        } else {
            map.flags
        };

        if let Err(e) = mgr.map_process_frame(child_pid, frame, map.vaddr, child_map_perms, pages) {
            return Err(e);
        }

        if writable && !map.cow {
            let mut parent_map_perms = map.flags;
            parent_map_perms.remove(Perms::WRITE);

            let _ = mgr.unmap_process_pages(pid, map.vaddr, pages);
            if let Err(e) = mgr.map_process_frame(pid, frame, map.vaddr, parent_map_perms, pages) {
                let _ = mgr.unmap_process_pages(child_pid, map.vaddr, pages);
                return Err(e);
            }
        }

        if retained_shared_slots.insert(frame_slot) {
            mgr.retain_shared_frame_cap(frame_slot);
        }

        if writable {
            map.cow = true;
            if let Some(parent) = mgr.get_process(pid) {
                if let Some(parent_map) = parent.mm.state.write().memory_maps.get_mut(&map.vaddr) {
                    parent_map.cow = true;
                }
            }
        }
    }

    {
        let child = mgr.get_process(child_pid).ok_or(Error::NotFound)?;

        {
            let mut fs = child.fs.state.write();
            fs.root_dir = parent_root_dir;
            fs.cwd = parent_cwd;
        }
        {
            let mut files = child.files.state.write();
            files.fds = parent_fds;
            files.fd_paths = parent_fd_paths;
            files.fd_cloexec = parent_fd_cloexec;
            files.next_fd = parent_next_fd;
        }

        child.session_id.store(parent_session_id, Ordering::SeqCst);
        child.process_group_id.store(parent_process_group_id, Ordering::SeqCst);
        child.controlling_tty.store(parent_controlling_tty, Ordering::SeqCst);

        {
            let mut mm = child.mm.state.write();
            mm.stack_bottom = parent_stack_bottom;
            mm.stack_size = parent_stack_size;
            mm.max_stack_size = parent_max_stack_size;
            mm.heap_start = parent_heap_start;
            mm.heap_brk = parent_heap_brk;
            mm.heap_limit = parent_heap_limit;
            mm.mmap_base = parent_mmap_base;
            mm.mmap_next = parent_mmap_next;
            mm.mmap_limit = parent_mmap_limit;
            mm.memory_maps.clear();
            mm.lazy_memory_maps.clear();
        }

        {
            let mut sig = child.signal.state.lock();
            sig.clear_child_tid = parent_clear_child_tid;
        }
        *child.cred.identity.write() = parent_identity;
        *child.sighand.signal_actions.lock() = parent_signal_actions;
        child.signal.set_blocked(parent_signal_blocked);
        child.signal.signal_pending.store(0, Ordering::SeqCst);

        if parent_stopped {
            child.mark_stopped();
        } else {
            child.mark_running();
        }

        for map in child_maps {
            child.mm.add_memory_map(map);
        }
        for map in parent_lazy_maps {
            child.mm.add_lazy_memory_map(map);
        }
    }

    if let Some(child) = mgr.get_process(child_pid) {
        let identity = child.cred.identity.read().clone();
        let _ = mgr.auth_client.set_identity(child_pid, identity);
    }

    {
        let parent_tcb = mgr.get_process(pid).ok_or(Error::NotFound)?.tcb();
        let child_tcb = mgr.get_process(child_pid).ok_or(Error::NotFound)?.tcb();
        let fault_ep = Endpoint::from(CapPtr::concat(
            mgr.get_process(child_pid).ok_or(Error::NotFound)?.cspace.cap(),
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

    if let Some(child) = mgr.get_process(child_pid) {
        if (clone_flags & (CLONE_CHILD_CLEARTID as usize | CLONE_CHILD_SETTID as usize)) != 0 {
            child.signal.state.lock().clear_child_tid = ctid;
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
    let task = mgr.get_process(pid).ok_or(Error::NotFound)?;
    task.signal.clear_wait4_block();

    let caller_pgid = task.process_group_id.load(Ordering::SeqCst);

    if let Some((reaped_pid, status)) =
        mgr.pop_waitable_child_event(pid, target_pid, options, caller_pgid)
    {
        if wstatus != 0 {
            mgr.copy_to_user(pid, wstatus, &status.to_ne_bytes())?;
        }
        mgr.clear_process_lifecycle_snapshot(reaped_pid);
        return Ok(reaped_pid as isize);
    }

    if !mgr.has_waitable_child(pid, target_pid, options, caller_pgid) {
        return Ok(-(ECHILD as isize));
    }

    if (options & WNOHANG as usize) != 0 {
        return Ok(0);
    }

    mgr.queue_wait4_reply(pid, target_pid, wstatus, options, caller_pgid)?;
    task.signal.arm_wait4_block(target_pid, caller_pgid);
    Err(Error::Success)
}
