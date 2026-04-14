pub mod bootstrap;
pub mod fault;
pub mod path;
pub mod policy;
pub mod process;
pub mod server;
pub mod state;
pub mod task;
pub mod user;
pub mod utils;

use crate::config::ApeConfig;
use crate::layout::{APE_SLOT, FS_ASYNC_POOL_BASE_VADDR, FS_ASYNC_POOL_MAX_REGIONS};
use alloc::string::String;
use glenda::arch::mem::{PGSIZE, SHIFTS};
use glenda::cap::{CNode, CSPACE_CAP, CapPtr, CapType, Endpoint, Frame, Reply, Rights};
use glenda::client::*;
use glenda::error::Error;
use glenda::interface::{CSpaceService, ResourceService, VSpaceService};
use glenda::ipc::Badge;
use glenda::mem::{Perms, TRAMPOLINE_VA, get_trapframe_va, get_utcb_va};
use glenda::utils::align::align_up;
use glenda::utils::manager::{CSpaceManager, VSpaceManager};
use process::{AsyncIoRegion, SubProcess};
use state::{ApeFsState, ApeRuntimeState, ApeTaskState};

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
    pub init_client: &'a mut InitClient,
    pub proc_client: &'a mut ProcessClient,
    pub res_client: &'a mut ResourceClient,
    pub vt_client: &'a mut VirtualTerminalClient,
    pub vol_client: &'a mut VolumeClient,
    pub fs_client: &'a mut FsClient,
    pub cspace_mgr: &'a mut CSpaceManager,
    pub vspace_mgr: &'a mut VSpaceManager,
}

impl<'a> ApeManager<'a> {
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
            init_client,
            proc_client,
            res_client,
            vt_client,
            vol_client,
            fs_client,
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
        self.task_state.register_process(pid, host_pid, proc);
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

    pub fn take_next_fs_handle_badge(&mut self) -> usize {
        self.fs_state.take_next_handle_badge()
    }

    pub fn allocate_fs_async_region(&mut self, size: usize) -> Result<AsyncIoRegion, Error> {
        let size_aligned = align_up(size, PGSIZE);

        if let Some(region) = self.fs_state.try_reuse_region() {
            return Ok(region);
        }

        if self.fs_state.region_count() >= FS_ASYNC_POOL_MAX_REGIONS {
            return Err(Error::OutOfMemory);
        }

        let frame_slot = self.cspace_mgr.alloc(&mut *self.res_client)?;
        let pages = size_aligned / PGSIZE;
        self.res_client.alloc(Badge::null(), CapType::Frame, pages, frame_slot)?;
        let frame = Frame::from(frame_slot);

        let vaddr = self.fs_state.reserve_async_vaddr(size_aligned).ok_or(Error::OutOfMemory)?;

        self.vspace_mgr.map_frame(
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
}
