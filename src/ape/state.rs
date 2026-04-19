use crate::ape::process::{AsyncIoRegion, SubProcess};
use crate::ape::tty::TtyRegistry;
use crate::config::ApeConfig;
use alloc::collections::BTreeMap;
use alloc::collections::btree_set::BTreeSet;
use alloc::vec::Vec;
use glenda::cap::CapPtr;
use glenda::client::TerminalClient;

#[derive(Debug, Clone, Default)]
pub struct ApeProcessLedger {
    pub alloc_frames: usize,
    pub free_frames: usize,
    pub alloc_pages: usize,
    pub free_pages: usize,
    pub alloc_pagetables: usize,
    pub free_pagetables: usize,
    pub fd_opened: usize,
    pub fd_closed: usize,
    pub async_regions_allocated: usize,
    pub async_regions_reused: usize,
    pub peak_live_frames: usize,
    pub live_frames: BTreeSet<CapPtr>,
    pub live_pagetables: BTreeSet<CapPtr>,
}

impl ApeProcessLedger {
    fn touch_peak(&mut self) {
        self.peak_live_frames = core::cmp::max(self.peak_live_frames, self.live_frames.len());
    }
}

#[derive(Debug, Clone, Default)]
pub struct ApeResourceLedger {
    per_process: BTreeMap<usize, ApeProcessLedger>,
}

impl ApeResourceLedger {
    fn process_mut(&mut self, pid: usize) -> &mut ApeProcessLedger {
        self.per_process.entry(pid).or_default()
    }

    pub fn record_frame_alloc(&mut self, pid: usize, slot: CapPtr, pages: usize) {
        let p = self.process_mut(pid);
        p.alloc_frames += 1;
        p.alloc_pages = p.alloc_pages.saturating_add(pages);
        p.live_frames.insert(slot);
        p.touch_peak();
    }

    pub fn record_frame_free(&mut self, pid: usize, slot: CapPtr, pages: usize) {
        let p = self.process_mut(pid);
        p.free_frames += 1;
        p.free_pages = p.free_pages.saturating_add(pages);
        p.live_frames.remove(&slot);
    }

    pub fn record_pagetable_alloc(&mut self, pid: usize, slot: CapPtr) {
        let p = self.process_mut(pid);
        p.alloc_pagetables += 1;
        p.live_pagetables.insert(slot);
    }

    pub fn record_pagetable_free(&mut self, pid: usize, slot: CapPtr) {
        let p = self.process_mut(pid);
        p.free_pagetables += 1;
        p.live_pagetables.remove(&slot);
    }

    pub fn record_fd_open(&mut self, pid: usize) {
        self.process_mut(pid).fd_opened += 1;
    }

    pub fn record_fd_close(&mut self, pid: usize) {
        self.process_mut(pid).fd_closed += 1;
    }

    pub fn record_async_region_allocated(&mut self, pid: usize) {
        self.process_mut(pid).async_regions_allocated += 1;
    }

    pub fn record_async_region_reused(&mut self, pid: usize) {
        self.process_mut(pid).async_regions_reused += 1;
    }

    pub fn take_process(&mut self, pid: usize) -> ApeProcessLedger {
        self.per_process.remove(&pid).unwrap_or_default()
    }
}

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
    iouring_supported: Option<bool>,
}

impl ApeFsState {
    pub fn new(next_async_vaddr: usize, next_handle_badge: usize) -> Self {
        Self {
            async_regions: Vec::new(),
            async_free: Vec::new(),
            next_async_vaddr,
            next_handle_badge,
            iouring_supported: None,
        }
    }

    pub fn should_try_iouring(&self) -> bool {
        self.iouring_supported != Some(false)
    }

    pub fn mark_iouring_supported(&mut self) {
        self.iouring_supported = Some(true);
    }

    pub fn mark_iouring_unsupported(&mut self) {
        self.iouring_supported = Some(false);
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
