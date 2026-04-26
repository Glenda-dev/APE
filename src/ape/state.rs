use super::PendingWaitReply;
use crate::ape::files::AsyncIoRegion;
use crate::ape::task::{TaskLifecycleState, TaskStruct};
use crate::ape::tty::TtyRegistry;
use crate::config::ApeConfig;
use alloc::collections::BTreeMap;
use alloc::collections::VecDeque;
use alloc::collections::btree_set::BTreeSet;
use alloc::sync::Arc;
use alloc::vec::Vec;
use glenda::cap::{CapPtr, Endpoint};
use glenda::client::TerminalClient;
use glenda::sync::mutex::Mutex;
use glenda::sync::rwlock::RwLock;
use linux_raw_sys::general::{WCONTINUED, WUNTRACED};

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

#[derive(Debug, Clone, Copy)]
pub enum ChildStateEventKind {
    Exited,
    Stopped,
    Continued,
}

#[derive(Debug, Clone, Copy)]
pub struct ChildStateEvent {
    pub child_pid: usize,
    pub wait_status: i32,
    pub process_group_id: usize,
    pub kind: ChildStateEventKind,
}

#[derive(Debug, Clone, Copy)]
pub struct ProcessLifecycleSnapshot {
    pub parent_pid: usize,
    pub process_group_id: usize,
    pub state: TaskLifecycleState,
    pub wait_status: Option<i32>,
}

pub struct ApeTaskState {
    pub tasks: RwLock<BTreeMap<usize, Arc<TaskStruct>>>,
    pub host_pid_map: RwLock<BTreeMap<usize, usize>>, // host_pid -> local pid
    pub lifecycle: RwLock<BTreeMap<usize, ProcessLifecycleSnapshot>>, // pid -> snapshot
    pub child_events: RwLock<BTreeMap<usize, VecDeque<ChildStateEvent>>>, // parent_pid -> child state events
    pub pending_wait_replies: RwLock<BTreeMap<usize, PendingWaitReply>>, // parent_pid -> deferred wait4 reply
    pub frame_cap_refs: RwLock<BTreeMap<CapPtr, usize>>, // shared frame capability reference counters
    pub next_pid: Mutex<usize>,
}

impl ApeTaskState {
    pub fn new(next_pid: usize) -> Self {
        Self {
            tasks: RwLock::new(BTreeMap::new()),
            host_pid_map: RwLock::new(BTreeMap::new()),
            lifecycle: RwLock::new(BTreeMap::new()),
            child_events: RwLock::new(BTreeMap::new()),
            pending_wait_replies: RwLock::new(BTreeMap::new()),
            frame_cap_refs: RwLock::new(BTreeMap::new()),
            next_pid: Mutex::new(next_pid),
        }
    }

    pub fn retain_frame_cap(&self, slot: CapPtr) {
        let mut refs = self.frame_cap_refs.write();
        let entry = refs.entry(slot).or_insert(1);
        *entry = entry.saturating_add(1);
    }

    /// Returns true when caller should perform the actual resource free.
    pub fn release_frame_cap(&self, slot: CapPtr) -> bool {
        let mut refs = self.frame_cap_refs.write();
        let Some(count) = refs.get_mut(&slot) else {
            return true;
        };

        if *count > 1 {
            *count -= 1;
            return false;
        }

        refs.remove(&slot);
        true
    }

    pub fn alloc_pid(&self) -> usize {
        let mut next = self.next_pid.lock();
        let pid = *next;
        *next = next.saturating_add(1);
        pid
    }

    pub fn register_process(&self, pid: usize, host_pid: usize, task: Arc<TaskStruct>) {
        let snapshot = ProcessLifecycleSnapshot {
            parent_pid: task.parent_pid.load(core::sync::atomic::Ordering::SeqCst),
            process_group_id: task.process_group_id.load(core::sync::atomic::Ordering::SeqCst),
            state: TaskLifecycleState::Running,
            wait_status: None,
        };
        self.tasks.write().insert(pid, task);
        self.host_pid_map.write().insert(host_pid, pid);
        self.lifecycle.write().insert(pid, snapshot);
    }

    pub fn process(&self, pid: usize) -> Option<Arc<TaskStruct>> {
        self.tasks.read().get(&pid).cloned()
    }

    pub fn remove_process(&self, pid: usize) -> Option<Arc<TaskStruct>> {
        self.tasks.write().remove(&pid)
    }

    pub fn set_process_lifecycle_state(&self, pid: usize, state: TaskLifecycleState) {
        if let Some(task) = self.tasks.read().get(&pid) {
            let mut lifecycle = self.lifecycle.write();
            let entry = lifecycle.entry(pid).or_insert(ProcessLifecycleSnapshot {
                parent_pid: task.parent_pid.load(core::sync::atomic::Ordering::SeqCst),
                process_group_id: task.process_group_id.load(core::sync::atomic::Ordering::SeqCst),
                state,
                wait_status: None,
            });
            entry.parent_pid = task.parent_pid.load(core::sync::atomic::Ordering::SeqCst);
            entry.process_group_id =
                task.process_group_id.load(core::sync::atomic::Ordering::SeqCst);
            entry.state = state;
            return;
        }

        if let Some(entry) = self.lifecycle.write().get_mut(&pid) {
            entry.state = state;
        }
    }

    pub fn mark_process_exited(
        &self,
        pid: usize,
        parent_pid: usize,
        process_group_id: usize,
        wait_status: i32,
    ) {
        self.lifecycle.write().insert(
            pid,
            ProcessLifecycleSnapshot {
                parent_pid,
                process_group_id,
                state: TaskLifecycleState::Exited,
                wait_status: Some(wait_status),
            },
        );
    }

    pub fn clear_process_lifecycle(&self, pid: usize) {
        let _ = self.lifecycle.write().remove(&pid);
    }

    pub fn pid_by_host(&self, host_pid: usize) -> Option<usize> {
        self.host_pid_map.read().get(&host_pid).copied()
    }

    pub fn remove_host_pid(&self, host_pid: usize) -> Option<usize> {
        self.host_pid_map.write().remove(&host_pid)
    }

    pub fn host_pid_by_local(&self, local_pid: usize) -> Option<usize> {
        self.host_pid_map
            .read()
            .iter()
            .find_map(|(host_pid, pid)| (*pid == local_pid).then_some(*host_pid))
    }

    pub fn list_pids(&self) -> Vec<usize> {
        self.tasks.read().keys().copied().collect()
    }

    pub fn record_child_exit(
        &self,
        parent_pid: usize,
        child_pid: usize,
        wait_status: i32,
        process_group_id: usize,
    ) {
        let mut events = self.child_events.write();
        let queue = events.entry(parent_pid).or_default();
        queue.push_back(ChildStateEvent {
            child_pid,
            wait_status,
            process_group_id,
            kind: ChildStateEventKind::Exited,
        });
    }

    pub fn record_child_stopped(
        &self,
        parent_pid: usize,
        child_pid: usize,
        wait_status: i32,
        process_group_id: usize,
    ) {
        let mut events = self.child_events.write();
        let queue = events.entry(parent_pid).or_default();
        queue.push_back(ChildStateEvent {
            child_pid,
            wait_status,
            process_group_id,
            kind: ChildStateEventKind::Stopped,
        });
    }

    pub fn record_child_continued(
        &self,
        parent_pid: usize,
        child_pid: usize,
        process_group_id: usize,
    ) {
        let mut events = self.child_events.write();
        let queue = events.entry(parent_pid).or_default();
        queue.push_back(ChildStateEvent {
            child_pid,
            wait_status: 0xffff,
            process_group_id,
            kind: ChildStateEventKind::Continued,
        });
    }

    pub fn has_pending_wait_reply(&self, pid: usize) -> bool {
        self.pending_wait_replies.read().contains_key(&pid)
    }

    pub fn insert_pending_wait_reply(&self, pid: usize, pending: PendingWaitReply) {
        self.pending_wait_replies.write().insert(pid, pending);
    }

    pub fn take_pending_wait_reply(&self, pid: usize) -> Option<PendingWaitReply> {
        self.pending_wait_replies.write().remove(&pid)
    }

    pub fn peek_pending_wait_reply(&self, pid: usize) -> Option<PendingWaitReply> {
        self.pending_wait_replies.read().get(&pid).copied()
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
        self.tasks.read().values().any(|task| {
            task.parent_pid.load(core::sync::atomic::Ordering::SeqCst) == parent_pid
                && Self::matches_wait_target(
                    task.pid,
                    task.process_group_id.load(core::sync::atomic::Ordering::SeqCst),
                    target_pid,
                    caller_pgid,
                )
        })
    }

    pub fn first_stopped_child_matching(
        &self,
        parent_pid: usize,
        target_pid: isize,
        caller_pgid: usize,
    ) -> Option<usize> {
        self.tasks.read().values().find_map(|task| {
            (task.parent_pid.load(core::sync::atomic::Ordering::SeqCst) == parent_pid
                && task.is_stopped()
                && Self::matches_wait_target(
                    task.pid,
                    task.process_group_id.load(core::sync::atomic::Ordering::SeqCst),
                    target_pid,
                    caller_pgid,
                ))
            .then_some(task.pid)
        })
    }

    pub fn has_child_event_matching(
        &self,
        parent_pid: usize,
        target_pid: isize,
        options: usize,
        caller_pgid: usize,
    ) -> bool {
        self.child_events
            .read()
            .get(&parent_pid)
            .map(|queue| {
                queue.iter().any(|event| {
                    Self::event_kind_enabled(event.kind, options)
                        && Self::matches_wait_target(
                            event.child_pid,
                            event.process_group_id,
                            target_pid,
                            caller_pgid,
                        )
                })
            })
            .unwrap_or(false)
    }

    fn event_kind_enabled(kind: ChildStateEventKind, options: usize) -> bool {
        match kind {
            ChildStateEventKind::Exited => true,
            ChildStateEventKind::Stopped => (options & WUNTRACED as usize) != 0,
            ChildStateEventKind::Continued => (options & WCONTINUED as usize) != 0,
        }
    }

    pub fn pop_child_event_matching(
        &self,
        parent_pid: usize,
        target_pid: isize,
        options: usize,
        caller_pgid: usize,
    ) -> Option<(usize, i32)> {
        let mut events = self.child_events.write();
        let queue = events.get_mut(&parent_pid)?;
        let pos = queue.iter().position(|event| {
            Self::event_kind_enabled(event.kind, options)
                && Self::matches_wait_target(
                    event.child_pid,
                    event.process_group_id,
                    target_pid,
                    caller_pgid,
                )
        })?;

        let event = queue.remove(pos)?;
        if queue.is_empty() {
            let _ = events.remove(&parent_pid);
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
    dev_vfs_endpoint: Option<Endpoint>,
    tmp_vfs_endpoint: Option<Endpoint>,
    pipe_vfs_endpoint: Option<Endpoint>,
}

impl ApeFsState {
    pub fn new(next_async_vaddr: usize, next_handle_badge: usize) -> Self {
        Self {
            async_regions: Vec::new(),
            async_free: Vec::new(),
            next_async_vaddr,
            next_handle_badge,
            iouring_supported: None,
            dev_vfs_endpoint: None,
            tmp_vfs_endpoint: None,
            pipe_vfs_endpoint: None,
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

    pub fn set_dev_vfs_endpoint(&mut self, endpoint: Endpoint) {
        self.dev_vfs_endpoint = Some(endpoint);
    }

    pub fn dev_vfs_endpoint(&self) -> Option<Endpoint> {
        self.dev_vfs_endpoint
    }

    pub fn set_tmp_vfs_endpoint(&mut self, endpoint: Endpoint) {
        self.tmp_vfs_endpoint = Some(endpoint);
    }

    pub fn tmp_vfs_endpoint(&self) -> Option<Endpoint> {
        self.tmp_vfs_endpoint
    }

    pub fn set_pipe_vfs_endpoint(&mut self, endpoint: Endpoint) {
        self.pipe_vfs_endpoint = Some(endpoint);
    }

    pub fn pipe_vfs_endpoint(&self) -> Option<Endpoint> {
        self.pipe_vfs_endpoint
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
