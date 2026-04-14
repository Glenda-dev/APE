use crate::ape::process::{AsyncIoRegion, SubProcess};
use crate::ape::tty::TtyRegistry;
use crate::config::ApeConfig;
use alloc::collections::BTreeMap;
use alloc::vec::Vec;
use glenda::client::TerminalClient;

pub struct ApeTaskState {
    processes: BTreeMap<usize, SubProcess>,
    host_pid_map: BTreeMap<usize, usize>, // host_pid -> local pid
    next_pid: usize,
}

impl ApeTaskState {
    pub fn new(next_pid: usize) -> Self {
        Self { processes: BTreeMap::new(), host_pid_map: BTreeMap::new(), next_pid }
    }

    pub fn alloc_pid(&mut self) -> usize {
        let pid = self.next_pid;
        self.next_pid = self.next_pid.saturating_add(1);
        pid
    }

    pub fn register_process(&mut self, pid: usize, host_pid: usize, proc: SubProcess) {
        self.processes.insert(pid, proc);
        self.host_pid_map.insert(host_pid, pid);
    }

    pub fn process(&self, pid: usize) -> Option<&SubProcess> {
        self.processes.get(&pid)
    }

    pub fn process_mut(&mut self, pid: usize) -> Option<&mut SubProcess> {
        self.processes.get_mut(&pid)
    }

    pub fn remove_process(&mut self, pid: usize) -> Option<SubProcess> {
        self.processes.remove(&pid)
    }

    pub fn pid_by_host(&self, host_pid: usize) -> Option<usize> {
        self.host_pid_map.get(&host_pid).copied()
    }

    pub fn remove_host_pid(&mut self, host_pid: usize) -> Option<usize> {
        self.host_pid_map.remove(&host_pid)
    }

    pub fn host_pid_by_local(&self, local_pid: usize) -> Option<usize> {
        self.host_pid_map
            .iter()
            .find_map(|(host_pid, pid)| (*pid == local_pid).then_some(*host_pid))
    }

    pub fn list_pids(&self) -> Vec<usize> {
        self.processes.keys().copied().collect()
    }
}

pub struct ApeRuntimeState {
    config: ApeConfig,
    stdio_term: Option<TerminalClient>,
    tty_registry: TtyRegistry,
}

impl ApeRuntimeState {
    pub fn new(config: ApeConfig) -> Self {
        Self { config, stdio_term: None, tty_registry: TtyRegistry::new() }
    }

    pub fn config(&self) -> &ApeConfig {
        &self.config
    }

    pub fn set_config(&mut self, config: ApeConfig) {
        self.config = config;
    }

    pub fn stdio_term(&self) -> Option<TerminalClient> {
        self.stdio_term
    }

    pub fn set_stdio_term(&mut self, term: Option<TerminalClient>) {
        self.stdio_term = term;
    }

    pub fn tty_registry(&self) -> &TtyRegistry {
        &self.tty_registry
    }

    pub fn tty_registry_mut(&mut self) -> &mut TtyRegistry {
        &mut self.tty_registry
    }
}

pub struct ApeFsState {
    async_regions: Vec<AsyncIoRegion>,
    async_free: Vec<usize>,
    next_async_vaddr: usize,
    next_handle_badge: usize,
}

impl ApeFsState {
    pub fn new(next_async_vaddr: usize, next_handle_badge: usize) -> Self {
        Self {
            async_regions: Vec::new(),
            async_free: Vec::new(),
            next_async_vaddr,
            next_handle_badge,
        }
    }

    pub fn take_next_handle_badge(&mut self) -> usize {
        let badge = self.next_handle_badge;
        self.next_handle_badge = self.next_handle_badge.wrapping_add(1);
        badge
    }

    pub fn try_reuse_region(&mut self) -> Option<AsyncIoRegion> {
        self.async_free.pop().and_then(|region_id| self.async_regions.get(region_id).copied())
    }

    pub fn region_count(&self) -> usize {
        self.async_regions.len()
    }

    pub fn reserve_async_vaddr(&mut self, size_aligned: usize) -> Option<usize> {
        let vaddr = self.next_async_vaddr;
        self.next_async_vaddr = self.next_async_vaddr.checked_add(size_aligned)?;
        Some(vaddr)
    }

    pub fn push_region(&mut self, region: AsyncIoRegion) {
        self.async_regions.push(region);
    }

    pub fn recycle_region(&mut self, region_id: usize) {
        if region_id < self.async_regions.len() && !self.async_free.contains(&region_id) {
            self.async_free.push(region_id);
        }
    }
}
