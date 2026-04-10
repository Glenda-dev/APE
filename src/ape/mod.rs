pub mod bootstrap;
pub mod fault;
pub mod handler;
pub mod path;
pub mod policy;
pub mod process;
pub mod server;
pub mod syscall;
pub mod user;

use crate::config::ApeConfig;
use alloc::collections::BTreeMap;
use alloc::string::String;
use ape::cap::APE_SLOT;
use glenda::cap::{CNode, CSPACE_CAP, CapPtr, Endpoint, Reply, Rights};
use glenda::client::*;
use glenda::error::Error;
use glenda::ipc::Badge;
use glenda::utils::manager::{CSpaceManager, VSpaceManager};
use process::SubProcess;

pub struct ApeManager<'a> {
    pub running: bool,
    pub endpoint: Endpoint,
    pub reply: Reply,
    pub recv: CapPtr,
    pub processes: BTreeMap<usize, SubProcess>,
    pub host_pid_map: BTreeMap<usize, usize>, // host_pid -> pid
    pub next_pid: usize,
    pub init_client: &'a mut InitClient,
    pub proc_client: &'a mut ProcessClient,
    pub res_client: &'a mut ResourceClient,
    pub vt_client: &'a mut VirtualTerminalClient,
    pub volume_ep: Endpoint,
    pub fs_client: &'a mut FsClient,
    pub cspace_mgr: &'a mut CSpaceManager,
    pub vspace_mgr: &'a mut VSpaceManager,
    pub config: ApeConfig,
    pub stdio_term: Option<glenda::client::TerminalClient>,
}

impl<'a> ApeManager<'a> {
    pub fn new(
        init_client: &'a mut InitClient,
        proc_client: &'a mut ProcessClient,
        res_client: &'a mut ResourceClient,
        vt_client: &'a mut VirtualTerminalClient,
        volume_ep: Endpoint,
        fs_client: &'a mut FsClient,
        cspace_mgr: &'a mut CSpaceManager,
        vspace_mgr: &'a mut VSpaceManager,
    ) -> Self {
        Self {
            running: false,
            endpoint: Endpoint::from(CapPtr::null()),
            recv: CapPtr::null(),
            reply: Reply::from(CapPtr::null()),
            processes: BTreeMap::new(),
            host_pid_map: BTreeMap::new(),
            next_pid: 1,
            init_client,
            proc_client,
            res_client,
            vt_client,
            volume_ep,
            fs_client,
            cspace_mgr,
            vspace_mgr,
            config: ApeConfig::default(),
            stdio_term: None,
        }
    }

    pub fn resolve_path_for_process(&self, pid: usize, raw_path: &str) -> Result<String, Error> {
        let process = self.get_process(pid).ok_or(Error::NotFound)?;
        Ok(self::path::resolve_path(raw_path, &process.root_dir, &process.cwd))
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
            self.endpoint.cap(),
            proc_cnode.cap(),
            APE_SLOT,
            Badge::new(pid),
            Rights::ALL,
        );

        let proc = SubProcess::new(pid, parent_pid, proc_cnode);
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
}
