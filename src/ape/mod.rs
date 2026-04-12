pub mod bootstrap;
pub mod fault;
pub mod path;
pub mod policy;
pub mod process;
pub mod server;
pub mod user;

use crate::config::ApeConfig;
use alloc::collections::BTreeMap;
use alloc::string::String;
use alloc::vec::Vec;
use ape::cap::APE_SLOT;
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

const FS_ASYNC_POOL_BASE_VADDR: usize = 0x5800_0000;
const FS_ASYNC_POOL_MAX_REGIONS: usize = 64;

pub struct ApeIpc {
    pub running: bool,
    pub endpoint: Endpoint,
    pub reply: Reply,
    pub recv: CapPtr,
}

pub struct ApeManager<'a> {
    pub ipc: ApeIpc,
    pub processes: BTreeMap<usize, SubProcess>,
    pub host_pid_map: BTreeMap<usize, usize>, // host_pid -> pid
    pub next_pid: usize,
    pub init_client: &'a mut InitClient,
    pub proc_client: &'a mut ProcessClient,
    pub res_client: &'a mut ResourceClient,
    pub vt_client: &'a mut VirtualTerminalClient,
    pub vol_client: &'a mut VolumeClient,
    pub fs_client: &'a mut FsClient,
    pub cspace_mgr: &'a mut CSpaceManager,
    pub vspace_mgr: &'a mut VSpaceManager,
    pub config: ApeConfig,
    pub stdio_term: Option<glenda::client::TerminalClient>,
    pub fs_async_regions: Vec<AsyncIoRegion>,
    pub fs_async_free: Vec<usize>,
    pub next_fs_async_vaddr: usize,
    pub next_fs_handle_badge: usize,
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
            processes: BTreeMap::new(),
            host_pid_map: BTreeMap::new(),
            next_pid: 1,
            init_client,
            proc_client,
            res_client,
            vt_client,
            vol_client,
            fs_client,
            cspace_mgr,
            vspace_mgr,
            config: ApeConfig::default(),
            stdio_term: None,
            fs_async_regions: Vec::new(),
            fs_async_free: Vec::new(),
            next_fs_async_vaddr: FS_ASYNC_POOL_BASE_VADDR,
            next_fs_handle_badge: 0x10000,
        }
    }

    pub fn register_process(
        &mut self,
        parent_pid: usize,
        host_pid: usize,
        proc_cnode: CNode,
    ) -> usize {
        let pid = self.next_pid;
        self.next_pid += 1;

        let _ = CSPACE_CAP.mint(
            self.ipc.endpoint.cap(),
            proc_cnode.cap(),
            APE_SLOT,
            Badge::new(pid),
            Rights::ALL,
        );

        let mut proc = SubProcess::new(pid, parent_pid, proc_cnode);
        Self::seed_initial_pagetable_paths(&mut proc);
        self.processes.insert(pid, proc);
        self.host_pid_map.insert(host_pid, pid);
        pid
    }

    pub fn get_pid_by_host(&self, host_pid: usize) -> Option<usize> {
        self.host_pid_map.get(&host_pid).copied()
    }

    pub fn get_process(&self, pid: usize) -> Option<&SubProcess> {
        self.processes.get(&pid)
    }

    pub fn get_process_mut(&mut self, pid: usize) -> Option<&mut SubProcess> {
        self.processes.get_mut(&pid)
    }

    pub fn resolve_path_for_process(&self, pid: usize, raw_path: &str) -> Result<String, Error> {
        let process = self.get_process(pid).ok_or(Error::NotFound)?;
        Ok(self::path::resolve_path(raw_path, &process.root_dir, &process.cwd))
    }

    pub fn take_next_fs_handle_badge(&mut self) -> usize {
        let badge = self.next_fs_handle_badge;
        self.next_fs_handle_badge = self.next_fs_handle_badge.wrapping_add(1);
        badge
    }

    pub fn allocate_fs_async_region(&mut self, size: usize) -> Result<AsyncIoRegion, Error> {
        let size_aligned = align_up(size, PGSIZE);

        if let Some(region_id) = self.fs_async_free.pop() {
            if let Some(region) = self.fs_async_regions.get(region_id).copied() {
                return Ok(region);
            }
        }

        if self.fs_async_regions.len() >= FS_ASYNC_POOL_MAX_REGIONS {
            return Err(Error::OutOfMemory);
        }

        let frame_slot = self.cspace_mgr.alloc(&mut *self.res_client)?;
        let pages = size_aligned / PGSIZE;
        self.res_client.alloc(Badge::null(), CapType::Frame, pages, frame_slot)?;
        let frame = Frame::from(frame_slot);

        let vaddr = self.next_fs_async_vaddr;
        self.next_fs_async_vaddr =
            self.next_fs_async_vaddr.checked_add(size_aligned).ok_or(Error::OutOfMemory)?;

        self.vspace_mgr.map_frame(
            frame,
            vaddr,
            Perms::READ | Perms::WRITE,
            pages,
            &mut *self.res_client,
            &mut *self.cspace_mgr,
        )?;

        let region = AsyncIoRegion {
            id: self.fs_async_regions.len(),
            frame_slot,
            vaddr,
            size: size_aligned,
        };
        self.fs_async_regions.push(region);
        Ok(region)
    }

    pub fn recycle_fs_async_region(&mut self, region_id: usize) {
        if region_id < self.fs_async_regions.len() && !self.fs_async_free.contains(&region_id) {
            self.fs_async_free.push(region_id);
        }
    }
}
