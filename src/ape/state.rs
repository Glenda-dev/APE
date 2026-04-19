use crate::ape::process::{AsyncIoRegion, SubProcess};
use crate::ape::tty::TtyRegistry;
use crate::config::ApeConfig;
use alloc::collections::BTreeMap;
use alloc::collections::VecDeque;
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

#[derive(Debug, Clone, Copy)]
pub struct ChildExitEvent {
    pub child_pid: usize,
    pub wait_status: i32,
    pub process_group_id: usize,
}

pub struct ApeTaskState {
    processes: BTreeMap<usize, SubProcess>,
    host_pid_map: BTreeMap<usize, usize>, // host_pid -> local pid
    exited_children: BTreeMap<usize, VecDeque<ChildExitEvent>>, // parent_pid -> child exits
    next_pid: usize,
}

impl ApeTaskState {
    pub fn new(next_pid: usize) -> Self {
        Self {
            processes: BTreeMap::new(),
            host_pid_map: BTreeMap::new(),
            exited_children: BTreeMap::new(),
            next_pid,
        }
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

    pub fn record_child_exit(
        &mut self,
        parent_pid: usize,
        child_pid: usize,
        wait_status: i32,
        process_group_id: usize,
    ) {
        let queue = self.exited_children.entry(parent_pid).or_default();
        queue.push_back(ChildExitEvent { child_pid, wait_status, process_group_id });
    }

    fn matches_wait_target(
        child_pid: usize,
        child_pgid: usize,
        target_pid: isize,
        caller_pgid: usize,
    ) -> bool {
        if target_pid == -1 {
            return true;
        }
        if target_pid > 0 {
            return child_pid == target_pid as usize;
        }
        if target_pid == 0 {
            return child_pgid == caller_pgid;
        }

        let target_pgid = target_pid.unsigned_abs();
        child_pgid == target_pgid
    }

    pub fn has_live_child_matching(
        &self,
        parent_pid: usize,
        target_pid: isize,
        caller_pgid: usize,
    ) -> bool {
        self.processes.values().any(|proc| {
            proc.parent_pid == parent_pid
                && Self::matches_wait_target(
                    proc.pid,
                    proc.process_group_id,
                    target_pid,
                    caller_pgid,
                )
        })
    }

    pub fn has_exited_child_matching(
        &self,
        parent_pid: usize,
        target_pid: isize,
        caller_pgid: usize,
    ) -> bool {
        self.exited_children
            .get(&parent_pid)
            .map(|queue| {
                queue.iter().any(|event| {
                    Self::matches_wait_target(
                        event.child_pid,
                        event.process_group_id,
                        target_pid,
                        caller_pgid,
                    )
                })
            })
            .unwrap_or(false)
    }

    pub fn pop_exited_child_matching(
        &mut self,
        parent_pid: usize,
        target_pid: isize,
        caller_pgid: usize,
    ) -> Option<(usize, i32)> {
        let queue = self.exited_children.get_mut(&parent_pid)?;
        let pos = queue.iter().position(|event| {
            Self::matches_wait_target(
                event.child_pid,
                event.process_group_id,
                target_pid,
                caller_pgid,
            )
        })?;

        let event = queue.remove(pos)?;
        if queue.is_empty() {
            let _ = self.exited_children.remove(&parent_pid);
        }
        Some((event.child_pid, event.wait_status))
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
    pipes: BTreeMap<usize, PipeState>,
    next_pipe_id: usize,
}

const PIPE_DEFAULT_CAPACITY: usize = 64 * 1024;

struct PipeState {
    buf: VecDeque<u8>,
    readers: usize,
    writers: usize,
}

impl ApeFsState {
    pub fn new(next_async_vaddr: usize, next_handle_badge: usize) -> Self {
        Self {
            async_regions: Vec::new(),
            async_free: Vec::new(),
            next_async_vaddr,
            next_handle_badge,
            iouring_supported: None,
            pipes: BTreeMap::new(),
            next_pipe_id: 1,
        }
    }

    pub fn create_pipe(&mut self) -> usize {
        let pipe_id = self.next_pipe_id;
        self.next_pipe_id = self.next_pipe_id.wrapping_add(1);
        self.pipes.insert(
            pipe_id,
            PipeState {
                buf: VecDeque::with_capacity(PIPE_DEFAULT_CAPACITY),
                readers: 1,
                writers: 1,
            },
        );
        pipe_id
    }

    pub fn pipe_read(&mut self, pipe_id: usize, dst: &mut [u8]) -> Option<(usize, bool)> {
        let pipe = self.pipes.get_mut(&pipe_id)?;
        let mut n = 0usize;
        while n < dst.len() {
            if let Some(b) = pipe.buf.pop_front() {
                dst[n] = b;
                n += 1;
            } else {
                break;
            }
        }
        Some((n, pipe.writers == 0))
    }

    pub fn pipe_write(&mut self, pipe_id: usize, src: &[u8]) -> Option<(usize, bool)> {
        let pipe = self.pipes.get_mut(&pipe_id)?;
        if pipe.readers == 0 {
            return Some((0, true));
        }

        let free = PIPE_DEFAULT_CAPACITY.saturating_sub(pipe.buf.len());
        let write_len = core::cmp::min(free, src.len());
        for &b in &src[..write_len] {
            pipe.buf.push_back(b);
        }
        Some((write_len, false))
    }

    pub fn close_pipe_read_end(&mut self, pipe_id: usize) {
        let mut remove = false;
        if let Some(pipe) = self.pipes.get_mut(&pipe_id) {
            pipe.readers = pipe.readers.saturating_sub(1);
            remove = pipe.readers == 0 && pipe.writers == 0;
        }
        if remove {
            let _ = self.pipes.remove(&pipe_id);
        }
    }

    pub fn close_pipe_write_end(&mut self, pipe_id: usize) {
        let mut remove = false;
        if let Some(pipe) = self.pipes.get_mut(&pipe_id) {
            pipe.writers = pipe.writers.saturating_sub(1);
            remove = pipe.readers == 0 && pipe.writers == 0;
        }
        if remove {
            let _ = self.pipes.remove(&pipe_id);
        }
    }

    pub fn clone_pipe_read_end(&mut self, pipe_id: usize) {
        if let Some(pipe) = self.pipes.get_mut(&pipe_id) {
            pipe.readers = pipe.readers.saturating_add(1);
        }
    }

    pub fn clone_pipe_write_end(&mut self, pipe_id: usize) {
        if let Some(pipe) = self.pipes.get_mut(&pipe_id) {
            pipe.writers = pipe.writers.saturating_add(1);
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
