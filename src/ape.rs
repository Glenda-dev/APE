use crate::process::SubProcess;
use alloc::collections::BTreeMap;
use alloc::string::String;
use glenda::cap::{CapPtr, Endpoint, Reply};

pub struct ApeManager {
    pub running: bool,
    pub rootfs_uuid: String,
    pub endpoint: Endpoint,
    pub reply: Reply,
    pub processes: BTreeMap<usize, SubProcess>,
    pub next_pid: usize,
}

impl ApeManager {
    pub fn new(rootfs_uuid: String) -> Self {
        Self {
            running: false,
            rootfs_uuid,
            endpoint: Endpoint::from(CapPtr::null()),
            reply: Reply::from(CapPtr::null()),
            processes: BTreeMap::new(),
            next_pid: 1,
        }
    }

    pub fn register_process(
        &mut self,
        parent_pid: usize,
        endpoint: usize,
        vspace_cap: usize,
    ) -> usize {
        let pid = self.next_pid;
        self.next_pid += 1;

        let proc = SubProcess::new(pid, parent_pid, endpoint, vspace_cap);
        self.processes.insert(pid, proc);
        pid
    }

    pub fn get_process(&self, pid: usize) -> Option<&SubProcess> {
        self.processes.get(&pid)
    }

    pub fn get_process_mut(&mut self, pid: usize) -> Option<&mut SubProcess> {
        self.processes.get_mut(&pid)
    }
}
