pub mod async_runtime;
pub mod bootstrap;
pub mod cred;
pub mod fault;
pub mod fault_policy;
pub mod files;
pub mod fs;
pub mod mm;
pub mod path;
pub mod policy;
pub mod server;
pub mod signal;
pub mod state;
pub mod task;
pub mod tty;
pub mod user;
pub mod utils;

use crate::config::ApeConfig;
use crate::layout::{APE_SLOT, FS_ASYNC_POOL_BASE_VADDR, FS_ASYNC_POOL_MAX_REGIONS};
use alloc::collections::BTreeMap;
use alloc::string::String;
use alloc::sync::Arc;
use alloc::vec::Vec;
use cred::CredStruct;
use files::{AsyncIoRegion, AsyncIoState, FileHandle, FileType, FilesStruct, NormalFileHandle};
use fs::FsStruct;
use glenda::arch::mem::{PGSIZE, SHIFTS};
use glenda::cap::{
    CNode, CSPACE_CAP, CapPtr, CapType, Endpoint, Page, Reply, Rights, TCB_SLOT, VSPACE_SLOT,
};
use glenda::client::*;
use glenda::error::Error;
use glenda::interface::{
    AuthService, CSpaceService, FileHandleService, ResourceService, VSpaceService,
};
use glenda::ipc::{Badge, MsgFlags, MsgTag, UTCB};
use glenda::mem::{Perms, TRAMPOLINE_VA, get_trapframe_va, get_utcb_va};
use glenda::runtime::ThreadPool;
use glenda::sync::channel::{Receiver, Sender};
use glenda::sync::mutex::Mutex;
use glenda::utils::align::align_up;
use glenda::utils::manager::{CSpaceManager, VSpaceManager};
use mm::{MemoryMap, MemoryType, MmStruct};
use signal::{SighandStruct, SignalAction, SignalStruct, Wait4BlockRequest};
use state::{ApeFsState, ApeProcessLedger, ApeResourceLedger, ApeRuntimeState, ApeTaskState};
use task::{TaskLifecycleState, TaskStruct};

#[derive(Debug, Clone, Copy)]
pub struct PendingWaitReply {
    pub reply_slot: CapPtr,
    pub target_pid: isize,
    pub wstatus: usize,
    pub options: usize,
    pub caller_pgid: usize,
}

#[derive(Debug, Clone, Copy)]
pub struct PendingSleepReply {
    pub reply_slot: CapPtr,
    pub rem_ptr: usize,
    pub deadline_ns: u64,
    pub request_id: usize,
}

#[derive(Debug, Clone, Copy)]
pub struct SleepCompletion {
    pub pid: usize,
    pub request_id: usize,
}

#[derive(Debug, Clone, Copy)]
pub enum ApeAsyncEvent {
    Sleep(SleepCompletion),
}

pub struct ApeAsyncRuntime {
    pub executor: ThreadPool,
    pub completion_tx: Sender<ApeAsyncEvent>,
    pub completion_rx: Receiver<ApeAsyncEvent>,
    pub next_request_id: usize,
    pub pending_sleep_replies: BTreeMap<usize, PendingSleepReply>,
}

pub struct ApeIpc {
    pub running: bool,
    pub endpoint: Endpoint,
    pub recv: CapPtr,
    pub reply: Reply,
    pub active_caller_pid: Option<usize>,
}

pub struct ApeServiceState {
    pub ipc: ApeIpc,
    pub async_runtime: Mutex<Option<ApeAsyncRuntime>>,
}

pub struct ApeSubsystemState {
    pub task: ApeTaskState,
    pub runtime: ApeRuntimeState,
    pub fs: Mutex<ApeFsState>,
    pub resources: Mutex<ApeResourceLedger>,
}

pub struct ApeManager<'a> {
    pub service_state: ApeServiceState,
    pub subsystems: ApeSubsystemState,
    pub init_client: &'a mut InitClient,
    pub proc_client: &'a mut ProcessClient,
    pub res_client: &'a mut ResourceClient,
    pub vt_client: &'a mut VirtualTerminalClient,
    pub vol_client: &'a mut VolumeClient,
    pub fs_client: &'a mut FsClient,
    pub time_client: &'a mut TimeClient,
    pub auth_client: &'a mut AuthClient,
    pub cspace_mgr: &'a mut CSpaceManager,
    pub vspace_mgr: &'a mut VSpaceManager,
}

impl<'a> ApeManager<'a> {
    const FS_ASYNC_RING_SIZE: usize = 4096;
    const FS_ASYNC_DATA_OFFSET: usize = Self::FS_ASYNC_RING_SIZE;
    const FS_ASYNC_SQ_ENTRIES: u32 = 16;
    const FS_ASYNC_CQ_ENTRIES: u32 = 16;

    fn seed_initial_pagetable_paths(task: &TaskStruct) {
        for vaddr in [TRAMPOLINE_VA, get_utcb_va(0), get_trapframe_va(0)] {
            for level in (1..SHIFTS.len()).rev() {
                let prefix = vaddr >> SHIFTS[level];
                task.mm.record_intermediate_page_table(level, prefix, CapPtr::null());
            }
        }
    }

    pub fn new(
        init_client: &'a mut InitClient,
        proc_client: &'a mut ProcessClient,
        res_client: &'a mut ResourceClient,
        vt_client: &'a mut VirtualTerminalClient,
        vol_client: &'a mut VolumeClient,
        fs_client: &'a mut FsClient,
        time_client: &'a mut TimeClient,
        auth_client: &'a mut AuthClient,
        cspace_mgr: &'a mut CSpaceManager,
        vspace_mgr: &'a mut VSpaceManager,
    ) -> Self {
        Self {
            service_state: ApeServiceState {
                ipc: ApeIpc {
                    running: false,
                    endpoint: Endpoint::from(CapPtr::null()),
                    recv: CapPtr::null(),
                    reply: Reply::from(CapPtr::null()),
                    active_caller_pid: None,
                },
                async_runtime: Mutex::new(None),
            },
            subsystems: ApeSubsystemState {
                task: ApeTaskState::new(1),
                runtime: ApeRuntimeState::new(ApeConfig::default()),
                fs: Mutex::new(ApeFsState::new(FS_ASYNC_POOL_BASE_VADDR, 0x10000)),
                resources: Mutex::new(ApeResourceLedger::default()),
            },
            init_client,
            proc_client,
            res_client,
            vt_client,
            vol_client,
            fs_client,
            time_client,
            auth_client,
            cspace_mgr,
            vspace_mgr,
        }
    }

    pub fn init(&mut self) -> Result<(), Error> {
        self.bootstrap()
    }

    pub fn register_process(
        &mut self,
        parent_pid: usize,
        host_pid: usize,
        proc_cnode: CNode,
    ) -> usize {
        let pid = self.subsystems.task.alloc_pid();

        let _ = CSPACE_CAP.mint(
            self.service_state.ipc.endpoint.cap(),
            proc_cnode.cap(),
            APE_SLOT,
            Badge::new(pid),
            Rights::ALL,
        );

        let vspace = glenda::cap::VSpace::from(CapPtr::concat(proc_cnode.cap(), VSPACE_SLOT));
        let tcb = glenda::cap::TCB::from(CapPtr::concat(proc_cnode.cap(), TCB_SLOT));

        let mm = Arc::new(MmStruct::new(vspace));
        let files = Arc::new(FilesStruct::new());
        let fs = Arc::new(FsStruct::new());
        let sighand = Arc::new(SighandStruct::new());
        let signal = Arc::new(SignalStruct::new());
        let cred = Arc::new(CredStruct::new());

        let task = Arc::new(TaskStruct::new(
            pid, parent_pid, tcb, proc_cnode, mm, files, fs, sighand, signal, cred,
        ));

        Self::seed_initial_pagetable_paths(&task);
        let identity = task.cred.identity.read().clone();
        self.subsystems.task.register_process(pid, host_pid, task);
        let _ = self.subsystems.resources.lock().take_process(pid);
        let _ = self.auth_client.set_identity(pid, identity);
        pid
    }

    pub fn get_pid_by_host(&self, host_pid: usize) -> Option<usize> {
        self.subsystems.task.pid_by_host(host_pid)
    }

    pub fn get_process(&self, pid: usize) -> Option<Arc<TaskStruct>> {
        self.subsystems.task.process(pid)
    }

    pub fn resolve_path_for_process(&self, pid: usize, raw_path: &str) -> Result<String, Error> {
        let task = self.get_process(pid).ok_or(Error::NotFound)?;
        let fs = task.fs.state.read();
        Ok(self::path::resolve_path(raw_path, &fs.root_dir, &fs.cwd))
    }

    pub fn local_pids(&self) -> alloc::vec::Vec<usize> {
        self.subsystems.task.list_pids()
    }

    pub fn record_child_exit(
        &mut self,
        parent_pid: usize,
        child_pid: usize,
        wait_status: i32,
        process_group_id: usize,
    ) {
        self.subsystems.task.record_child_exit(
            parent_pid,
            child_pid,
            wait_status,
            process_group_id,
        );
    }

    pub fn record_child_stopped(
        &mut self,
        parent_pid: usize,
        child_pid: usize,
        wait_status: i32,
        process_group_id: usize,
    ) {
        self.subsystems.task.record_child_stopped(
            parent_pid,
            child_pid,
            wait_status,
            process_group_id,
        );
    }

    pub fn record_child_continued(
        &mut self,
        parent_pid: usize,
        child_pid: usize,
        process_group_id: usize,
    ) {
        self.subsystems.task.record_child_continued(parent_pid, child_pid, process_group_id);
    }

    pub fn has_waitable_child(
        &self,
        parent_pid: usize,
        target_pid: isize,
        options: usize,
        caller_pgid: usize,
    ) -> bool {
        self.subsystems.task.has_live_child_matching(parent_pid, target_pid, caller_pgid)
            || self.subsystems.task.has_child_event_matching(
                parent_pid,
                target_pid,
                options,
                caller_pgid,
            )
    }

    pub fn has_waitable_child_event(
        &self,
        parent_pid: usize,
        target_pid: isize,
        options: usize,
        caller_pgid: usize,
    ) -> bool {
        self.subsystems.task.has_child_event_matching(parent_pid, target_pid, options, caller_pgid)
    }

    pub fn pop_waitable_child_event(
        &mut self,
        parent_pid: usize,
        target_pid: isize,
        options: usize,
        caller_pgid: usize,
    ) -> Option<(usize, i32)> {
        self.subsystems.task.pop_child_event_matching(parent_pid, target_pid, options, caller_pgid)
    }

    pub fn first_waitable_stopped_child(
        &self,
        parent_pid: usize,
        target_pid: isize,
        caller_pgid: usize,
    ) -> Option<usize> {
        self.subsystems.task.first_stopped_child_matching(parent_pid, target_pid, caller_pgid)
    }

    pub fn host_pid_by_local(&self, local_pid: usize) -> Option<usize> {
        self.subsystems.task.host_pid_by_local(local_pid)
    }

    pub fn remove_host_pid_mapping(&mut self, host_pid: usize) {
        let _ = self.subsystems.task.remove_host_pid(host_pid);
    }

    pub fn remove_process_record(&mut self, pid: usize) {
        let _ = self.subsystems.task.remove_process(pid);
    }

    pub fn set_process_lifecycle_state(&mut self, pid: usize, state: TaskLifecycleState) {
        self.subsystems.task.set_process_lifecycle_state(pid, state);
    }

    pub(crate) fn release_process_frame_slot(
        &mut self,
        pid: usize,
        slot: CapPtr,
        pages: usize,
        reason: &str,
    ) {
        if self.subsystems.task.release_frame_cap(slot) {
            let _ = self.res_client.free(Badge::null(), slot);
            let _ = CSPACE_CAP.delete(slot);
            self.cspace_mgr.free(slot);
            self.ledger_record_frame_free(pid, slot, pages, reason);
        }
    }

    pub(crate) fn release_shared_frame_cap(&mut self, slot: CapPtr) -> bool {
        self.subsystems.task.release_frame_cap(slot)
    }

    pub(crate) fn retain_shared_frame_cap(&mut self, slot: CapPtr) {
        self.subsystems.task.retain_frame_cap(slot);
    }

    pub(crate) fn mark_process_exited_snapshot(
        &mut self,
        pid: usize,
        parent_pid: usize,
        pgid: usize,
        wait_status: i32,
    ) {
        self.subsystems.task.mark_process_exited(pid, parent_pid, pgid, wait_status);
    }

    pub fn clear_process_lifecycle_snapshot(&mut self, pid: usize) {
        self.subsystems.task.clear_process_lifecycle(pid);
    }

    pub fn set_active_caller_pid(&mut self, pid: usize) {
        self.service_state.ipc.active_caller_pid = Some(pid);
    }

    pub fn clear_active_caller_pid(&mut self) {
        self.service_state.ipc.active_caller_pid = None;
    }

    pub(crate) fn reserve_pending_reply_slot(&mut self) -> Result<CapPtr, Error> {
        let src_reply = self.service_state.ipc.reply.cap();
        if src_reply.is_null() {
            return Err(Error::InvalidCapability);
        }

        let mut retry = 0usize;
        let reply_slot = loop {
            let slot = self.cspace_mgr.alloc(&mut *self.res_client)?;
            if slot == src_reply {
                self.cspace_mgr.free(slot);
                retry = retry.saturating_add(1);
                if retry > 64 {
                    return Err(Error::OutOfMemory);
                }
                continue;
            }
            break slot;
        };

        if let Err(e) = CSPACE_CAP.transfer_self(src_reply, reply_slot) {
            self.cspace_mgr.free(reply_slot);
            return Err(e);
        }

        Ok(reply_slot)
    }

    pub fn queue_wait4_reply(
        &mut self,
        pid: usize,
        target_pid: isize,
        wstatus: usize,
        options: usize,
        caller_pgid: usize,
    ) -> Result<(), Error> {
        if self.subsystems.task.has_pending_wait_reply(pid) {
            return Err(Error::WouldBlock);
        }

        let reply_slot = self.reserve_pending_reply_slot()?;

        self.subsystems.task.insert_pending_wait_reply(
            pid,
            PendingWaitReply { reply_slot, target_pid, wstatus, options, caller_pgid },
        );
        Ok(())
    }

    pub fn take_wait4_reply(&mut self, pid: usize) -> Option<PendingWaitReply> {
        self.subsystems.task.take_pending_wait_reply(pid)
    }

    pub fn peek_wait4_reply(&self, pid: usize) -> Option<PendingWaitReply> {
        self.subsystems.task.peek_pending_wait_reply(pid)
    }

    pub fn drop_wait4_reply(&mut self, pid: usize) {
        if let Some(pending) = self.subsystems.task.take_pending_wait_reply(pid) {
            let _ = CSPACE_CAP.delete(pending.reply_slot);
            self.cspace_mgr.free(pending.reply_slot);
        }
    }

    pub fn config(&self) -> &ApeConfig {
        self.subsystems.runtime.config()
    }

    pub fn set_config(&mut self, config: ApeConfig) {
        self.subsystems.runtime.set_config(config);
    }

    pub fn stdio_term(&self) -> Option<glenda::client::TerminalClient> {
        self.subsystems.runtime.stdio_term()
    }

    pub fn set_stdio_term(&mut self, term: Option<glenda::client::TerminalClient>) {
        self.subsystems.runtime.set_stdio_term(term);
    }

    pub fn tty_registry(&self) -> &self::tty::TtyRegistry {
        self.subsystems.runtime.tty_registry()
    }

    pub fn tty_registry_mut(&mut self) -> &mut self::tty::TtyRegistry {
        self.subsystems.runtime.tty_registry_mut()
    }

    pub fn take_next_fs_handle_badge(&mut self) -> usize {
        self.subsystems.fs.lock().take_next_handle_badge()
    }

    pub fn allocate_fs_async_region(
        &mut self,
        pid: usize,
        size: usize,
    ) -> Result<AsyncIoRegion, Error> {
        let size_aligned = align_up(size, PGSIZE);

        if let Some(region) = self.subsystems.fs.lock().try_reuse_region() {
            self.subsystems.resources.lock().record_async_region_reused(pid);
            return Ok(region);
        }

        if self.subsystems.fs.lock().region_count() >= FS_ASYNC_POOL_MAX_REGIONS {
            return Err(Error::OutOfMemory);
        }

        let frame_slot = self.cspace_mgr.alloc(&mut *self.res_client)?;
        let pages = size_aligned / PGSIZE;
        let page_level = CapType::page_pages_to_level(pages).ok_or(Error::InvalidArgs)?;
        self.res_client.alloc(Badge::null(), CapType::Page, page_level, frame_slot)?;
        let frame = Page::from(frame_slot);
        self.subsystems.resources.lock().record_async_region_allocated(pid);

        let vaddr = self
            .subsystems
            .fs
            .lock()
            .reserve_async_vaddr(size_aligned)
            .ok_or(Error::OutOfMemory)?;

        self.vspace_mgr.map_page(
            frame,
            vaddr,
            Perms::READ | Perms::WRITE,
            pages,
            &mut *self.res_client,
            &mut *self.cspace_mgr,
        )?;

        let region = AsyncIoRegion {
            id: self.subsystems.fs.lock().region_count(),
            frame_slot,
            vaddr,
            size: size_aligned,
        };
        self.subsystems.fs.lock().push_region(region);
        Ok(region)
    }

    pub fn recycle_fs_async_region(&mut self, region_id: usize) {
        self.subsystems.fs.lock().recycle_region(region_id);
    }

    pub(crate) fn ledger_record_frame_alloc(
        &mut self,
        pid: usize,
        slot: CapPtr,
        pages: usize,
        reason: &str,
    ) {
        self.subsystems.resources.lock().record_frame_alloc(pid, slot, pages);
        let _ = (pid, slot, pages, reason);
    }

    pub(crate) fn ledger_record_frame_free(
        &mut self,
        pid: usize,
        slot: CapPtr,
        pages: usize,
        reason: &str,
    ) {
        self.subsystems.resources.lock().record_frame_free(pid, slot, pages);
        let _ = (pid, slot, pages, reason);
    }

    pub(crate) fn ledger_record_pagetable_alloc(&mut self, pid: usize, slot: CapPtr, reason: &str) {
        self.subsystems.resources.lock().record_pagetable_alloc(pid, slot);
        let _ = (pid, slot, reason);
    }

    pub(crate) fn ledger_record_pagetable_free(&mut self, pid: usize, slot: CapPtr, reason: &str) {
        self.subsystems.resources.lock().record_pagetable_free(pid, slot);
        let _ = (pid, slot, reason);
    }

    pub(crate) fn ledger_record_fd_open(&mut self, pid: usize) {
        self.subsystems.resources.lock().record_fd_open(pid);
    }

    pub(crate) fn ledger_record_fd_close(&mut self, pid: usize) {
        self.subsystems.resources.lock().record_fd_close(pid);
    }

    pub(crate) fn ledger_take_process(&mut self, pid: usize) -> ApeProcessLedger {
        self.subsystems.resources.lock().take_process(pid)
    }

    pub fn should_try_fs_iouring(&self) -> bool {
        self.subsystems.fs.lock().should_try_iouring()
    }

    pub fn create_pipe(&mut self) -> usize {
        let Some(ep) = self.subsystems.fs.lock().pipe_vfs_endpoint() else {
            return 0;
        };
        let utcb = unsafe { UTCB::new() };
        utcb.clear();
        utcb.set_msg_tag(MsgTag::new(
            glenda::protocol::FS_PROTO,
            glenda::protocol::fs::PIPE_CREATE,
            MsgFlags::NONE,
        ));
        if ep.call(utcb).is_err() {
            return 0;
        }
        utcb.get_mr(0)
    }

    pub fn mark_fs_iouring_supported(&mut self) {
        self.subsystems.fs.lock().mark_iouring_supported();
    }

    pub fn mark_fs_iouring_unsupported(&mut self) {
        self.subsystems.fs.lock().mark_iouring_unsupported();
    }

    pub(crate) fn try_enable_fs_async_io(
        &mut self,
        pid: usize,
        normal: &mut NormalFileHandle,
    ) -> Result<bool, Error> {
        if normal.async_io.is_some() || !self.should_try_fs_iouring() {
            return Ok(normal.async_io.is_some());
        }

        let region = match self.allocate_fs_async_region(pid, 16 * 1024) {
            Ok(r) => r,
            Err(Error::OutOfMemory) => return Ok(false),
            Err(e) => return Err(e),
        };

        let ring_buf = unsafe {
            glenda::io::uring::IoUringBuffer::new(
                region.vaddr as *mut u8,
                Self::FS_ASYNC_RING_SIZE,
                Self::FS_ASYNC_SQ_ENTRIES,
                Self::FS_ASYNC_CQ_ENTRIES,
            )
        };
        let ring = glenda::io::uring::IoUringClient::new(ring_buf);

        match normal.fs_client.setup_iouring(
            Badge::null(),
            region.vaddr,
            region.size,
            Some(Page::from(region.frame_slot)),
        ) {
            Ok(()) => {
                self.mark_fs_iouring_supported();
                let data_vaddr = region.vaddr + Self::FS_ASYNC_DATA_OFFSET;
                if data_vaddr < region.vaddr + region.size {
                    let data_len = region.size - Self::FS_ASYNC_DATA_OFFSET;
                    normal.async_io = Some(AsyncIoState {
                        region_id: region.id,
                        ring,
                        data_vaddr,
                        data_len,
                        next_user_data: 1,
                    });
                    Ok(true)
                } else {
                    self.recycle_fs_async_region(region.id);
                    Ok(false)
                }
            }
            Err(Error::NotSupported) => {
                self.mark_fs_iouring_unsupported();
                self.recycle_fs_async_region(region.id);
                Ok(false)
            }
            Err(_) => {
                // 对于瞬时失败（例如后端尚未就绪）不全局禁用，后续仍允许重试。
                self.recycle_fs_async_region(region.id);
                Ok(false)
            }
        }
    }
}
