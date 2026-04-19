pub mod bootstrap;
pub mod fault;
pub mod fault_policy;
pub mod path;
pub mod policy;
pub mod process;
pub mod server;
pub mod state;
pub mod task;
pub mod tty;
pub mod user;
pub mod utils;

use crate::config::ApeConfig;
use crate::layout::{APE_SLOT, FS_ASYNC_POOL_BASE_VADDR, FS_ASYNC_POOL_MAX_REGIONS};
use alloc::string::String;
use glenda::arch::mem::{PGSIZE, SHIFTS};
use glenda::cap::{CNode, CSPACE_CAP, CapPtr, CapType, Endpoint, Page, Reply, Rights};
use glenda::client::*;
use glenda::error::Error;
use glenda::interface::{
    AuthService, CSpaceService, FileHandleService, ResourceService, VSpaceService,
};
use glenda::ipc::Badge;
use glenda::mem::{Perms, TRAMPOLINE_VA, get_trapframe_va, get_utcb_va};
use glenda::utils::align::align_up;
use glenda::utils::manager::{CSpaceManager, VSpaceManager};
use process::{AsyncIoRegion, AsyncIoState, NormalFileHandle, SubProcess};
use state::{ApeFsState, ApeProcessLedger, ApeResourceLedger, ApeRuntimeState, ApeTaskState};

pub struct ApeIpc {
    pub running: bool,
    pub endpoint: Endpoint,
    pub reply: Reply,
    pub recv: CapPtr,
}

pub struct ApeManager<'a> {
    pub ipc: ApeIpc,
    task_state: ApeTaskState,
    runtime_state: ApeRuntimeState,
    fs_state: ApeFsState,
    resource_ledger: ApeResourceLedger,
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

    fn seed_initial_pagetable_paths(proc: &mut SubProcess) {
        for vaddr in [TRAMPOLINE_VA, get_utcb_va(0), get_trapframe_va(0)] {
            for level in (1..SHIFTS.len()).rev() {
                let prefix = vaddr >> SHIFTS[level];
                proc.intermediate_page_tables.entry((level, prefix)).or_insert(CapPtr::null());
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
            ipc: ApeIpc {
                running: false,
                endpoint: Endpoint::from(CapPtr::null()),
                recv: CapPtr::null(),
                reply: Reply::from(CapPtr::null()),
            },
            task_state: ApeTaskState::new(1),
            runtime_state: ApeRuntimeState::new(ApeConfig::default()),
            fs_state: ApeFsState::new(FS_ASYNC_POOL_BASE_VADDR, 0x10000),
            resource_ledger: ApeResourceLedger::default(),
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

    pub fn register_process(
        &mut self,
        parent_pid: usize,
        host_pid: usize,
        proc_cnode: CNode,
    ) -> usize {
        let pid = self.task_state.alloc_pid();

        let _ = CSPACE_CAP.mint(
            self.ipc.endpoint.cap(),
            proc_cnode.cap(),
            APE_SLOT,
            Badge::new(pid),
            Rights::ALL,
        );

        let mut proc = SubProcess::new(pid, parent_pid, proc_cnode);
        Self::seed_initial_pagetable_paths(&mut proc);
        let identity = proc.identity;
        self.task_state.register_process(pid, host_pid, proc);
        let _ = self.resource_ledger.take_process(pid);
        let _ = self.auth_client.set_identity(pid, identity);
        pid
    }

    pub fn get_pid_by_host(&self, host_pid: usize) -> Option<usize> {
        self.task_state.pid_by_host(host_pid)
    }

    pub fn get_process(&self, pid: usize) -> Option<&SubProcess> {
        self.task_state.process(pid)
    }

    pub fn get_process_mut(&mut self, pid: usize) -> Option<&mut SubProcess> {
        self.task_state.process_mut(pid)
    }

    pub fn resolve_path_for_process(&self, pid: usize, raw_path: &str) -> Result<String, Error> {
        let process = self.get_process(pid).ok_or(Error::NotFound)?;
        Ok(self::path::resolve_path(raw_path, &process.root_dir, &process.cwd))
    }

    pub fn local_pids(&self) -> alloc::vec::Vec<usize> {
        self.task_state.list_pids()
    }

    pub fn record_child_exit(
        &mut self,
        parent_pid: usize,
        child_pid: usize,
        wait_status: i32,
        process_group_id: usize,
    ) {
        self.task_state.record_child_exit(parent_pid, child_pid, wait_status, process_group_id);
    }

    pub fn has_waitable_child(
        &self,
        parent_pid: usize,
        target_pid: isize,
        caller_pgid: usize,
    ) -> bool {
        self.task_state.has_live_child_matching(parent_pid, target_pid, caller_pgid)
            || self.task_state.has_exited_child_matching(parent_pid, target_pid, caller_pgid)
    }

    pub fn pop_waitable_exited_child(
        &mut self,
        parent_pid: usize,
        target_pid: isize,
        caller_pgid: usize,
    ) -> Option<(usize, i32)> {
        self.task_state.pop_exited_child_matching(parent_pid, target_pid, caller_pgid)
    }

    pub fn host_pid_by_local(&self, local_pid: usize) -> Option<usize> {
        self.task_state.host_pid_by_local(local_pid)
    }

    pub fn remove_host_pid_mapping(&mut self, host_pid: usize) {
        let _ = self.task_state.remove_host_pid(host_pid);
    }

    pub fn remove_process_record(&mut self, pid: usize) {
        let _ = self.task_state.remove_process(pid);
    }

    pub fn config(&self) -> &ApeConfig {
        self.runtime_state.config()
    }

    pub fn set_config(&mut self, config: ApeConfig) {
        self.runtime_state.set_config(config);
    }

    pub fn stdio_term(&self) -> Option<glenda::client::TerminalClient> {
        self.runtime_state.stdio_term()
    }

    pub fn set_stdio_term(&mut self, term: Option<glenda::client::TerminalClient>) {
        self.runtime_state.set_stdio_term(term);
    }

    pub fn tty_registry(&self) -> &self::tty::TtyRegistry {
        self.runtime_state.tty_registry()
    }

    pub fn tty_registry_mut(&mut self) -> &mut self::tty::TtyRegistry {
        self.runtime_state.tty_registry_mut()
    }

    pub fn take_next_fs_handle_badge(&mut self) -> usize {
        self.fs_state.take_next_handle_badge()
    }

    pub fn allocate_fs_async_region(
        &mut self,
        pid: usize,
        size: usize,
    ) -> Result<AsyncIoRegion, Error> {
        let size_aligned = align_up(size, PGSIZE);

        if let Some(region) = self.fs_state.try_reuse_region() {
            self.resource_ledger.record_async_region_reused(pid);
            return Ok(region);
        }

        if self.fs_state.region_count() >= FS_ASYNC_POOL_MAX_REGIONS {
            return Err(Error::OutOfMemory);
        }

        let frame_slot = self.cspace_mgr.alloc(&mut *self.res_client)?;
        let pages = size_aligned / PGSIZE;
        let page_level = CapType::page_pages_to_level(pages).ok_or(Error::InvalidArgs)?;
        self.res_client.alloc(Badge::null(), CapType::Page, page_level, frame_slot)?;
        let frame = Page::from(frame_slot);
        self.resource_ledger.record_async_region_allocated(pid);

        let vaddr = self.fs_state.reserve_async_vaddr(size_aligned).ok_or(Error::OutOfMemory)?;

        self.vspace_mgr.map_page(
            frame,
            vaddr,
            Perms::READ | Perms::WRITE,
            pages,
            &mut *self.res_client,
            &mut *self.cspace_mgr,
        )?;

        let region = AsyncIoRegion {
            id: self.fs_state.region_count(),
            frame_slot,
            vaddr,
            size: size_aligned,
        };
        self.fs_state.push_region(region);
        Ok(region)
    }

    pub fn recycle_fs_async_region(&mut self, region_id: usize) {
        self.fs_state.recycle_region(region_id);
    }

    pub(crate) fn ledger_record_frame_alloc(
        &mut self,
        pid: usize,
        slot: CapPtr,
        pages: usize,
        reason: &str,
    ) {
        self.resource_ledger.record_frame_alloc(pid, slot, pages);
        let _ = (pid, slot, pages, reason);
    }

    pub(crate) fn ledger_record_frame_free(
        &mut self,
        pid: usize,
        slot: CapPtr,
        pages: usize,
        reason: &str,
    ) {
        self.resource_ledger.record_frame_free(pid, slot, pages);
        let _ = (pid, slot, pages, reason);
    }

    pub(crate) fn ledger_record_pagetable_alloc(&mut self, pid: usize, slot: CapPtr, reason: &str) {
        self.resource_ledger.record_pagetable_alloc(pid, slot);
        let _ = (pid, slot, reason);
    }

    pub(crate) fn ledger_record_pagetable_free(&mut self, pid: usize, slot: CapPtr, reason: &str) {
        self.resource_ledger.record_pagetable_free(pid, slot);
        let _ = (pid, slot, reason);
    }

    pub(crate) fn ledger_record_fd_open(&mut self, pid: usize) {
        self.resource_ledger.record_fd_open(pid);
    }

    pub(crate) fn ledger_record_fd_close(&mut self, pid: usize) {
        self.resource_ledger.record_fd_close(pid);
    }

    pub(crate) fn ledger_take_process(&mut self, pid: usize) -> ApeProcessLedger {
        self.resource_ledger.take_process(pid)
    }

    pub fn should_try_fs_iouring(&self) -> bool {
        self.fs_state.should_try_iouring()
    }

    pub fn mark_fs_iouring_supported(&mut self) {
        self.fs_state.mark_iouring_supported();
    }

    pub fn mark_fs_iouring_unsupported(&mut self) {
        self.fs_state.mark_iouring_unsupported();
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
