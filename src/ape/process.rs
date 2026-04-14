use crate::layout::{
    DEFAULT_HEAP_LIMIT, DEFAULT_MAX_STACK_SIZE, DEFAULT_MMAP_BASE, DEFAULT_MMAP_LIMIT,
    DEFAULT_PROCESS_ROOT,
};
use alloc::collections::BTreeMap;
use alloc::string::String;
use glenda::cap::{CNode, CapPtr, TCB, TCB_SLOT, VSPACE_SLOT, VSpace};
use glenda::client::FsClient;
use glenda::client::TerminalClient;
use glenda::io::uring::IoUringClient;
use glenda::mem::{HEAP_VA, Perms, STACK_BASE};
use linux_raw_sys::general::{SIGKILL, SIGSTOP};

pub const SIGNAL_MIN: usize = 1;
pub const SIGNAL_MAX: usize = 64;
pub const SIGNAL_UNBLOCKABLE_MASK: u64 =
    (1u64 << (SIGKILL as usize - 1)) | (1u64 << (SIGSTOP as usize - 1));

#[derive(Debug, Clone, Copy, Default)]
pub struct SignalAction {
    pub handler: usize,
    pub flags: usize,
    pub restorer: usize,
    pub mask: u64,
}

#[inline]
pub fn signal_bit(signum: usize) -> Option<u64> {
    if (SIGNAL_MIN..=SIGNAL_MAX).contains(&signum) { Some(1u64 << (signum - 1)) } else { None }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MemoryType {
    Image,
    Stack,
    Heap,
    Anonymous,
}

#[derive(Debug, Clone)]
pub struct MemoryMap {
    pub vaddr: usize,
    pub paddr: usize,
    pub size: usize,
    pub flags: Perms,
    pub mem_type: MemoryType,
    pub cow: bool,
    pub frame_cap: usize, // Required for translate and map_scratch
}

#[derive(Debug, Clone, Copy)]
pub struct AsyncIoRegion {
    pub id: usize,
    pub frame_slot: CapPtr,
    pub vaddr: usize,
    pub size: usize,
}

#[derive(Debug, Clone, Copy)]
pub struct AsyncIoState {
    pub region_id: usize,
    pub ring: IoUringClient,
    pub data_vaddr: usize,
    pub data_len: usize,
    pub next_user_data: usize,
}

#[derive(Debug, Clone, Copy)]
pub struct NormalFileHandle {
    pub fs_client: FsClient,
    pub fs_ep_slot: CapPtr,
    pub offset: usize,
    pub async_io: Option<AsyncIoState>,
}

#[derive(Debug, Clone, Copy)]
pub struct PtyMasterHandle {
    pub term: TerminalClient,
    pub vt_id: usize,
    pub ep_slot: CapPtr,
    pub locked: bool,
}

#[derive(Debug, Clone, Copy)]
pub struct PtySlaveHandle {
    pub term: TerminalClient,
    pub vt_id: usize,
    pub ep_slot: CapPtr,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PseudoCharDevice {
    Null,
    Zero,
    Random,
    URandom,
}

#[derive(Debug, Clone, Copy)]
pub enum FileType {
    Normal(NormalFileHandle),
    Terminal(TerminalClient),
    PtyMaster(PtyMasterHandle),
    PtySlave(PtySlaveHandle),
    PseudoChar(PseudoCharDevice),
}

#[derive(Debug, Clone)]
pub struct FileHandle {
    pub file_type: FileType,
}

#[derive(Debug)]
pub struct SubProcess {
    pub pid: usize,
    pub parent_pid: usize,
    pub session_id: usize,
    pub process_group_id: usize,
    pub controlling_tty: Option<usize>,
    pub cnode_cap: CNode, // Copy of CNode capability
    pub root_dir: String,
    pub cwd: String,
    pub memory_maps: BTreeMap<usize, MemoryMap>, // vaddr -> mapping
    pub lazy_memory_maps: BTreeMap<usize, MemoryMap>, // vaddr(page) -> lazy mapping
    pub fds: BTreeMap<u32, FileHandle>,          // fd -> handle
    pub fd_paths: BTreeMap<u32, String>,         // fd -> resolved absolute path (if path-based)
    pub fd_cloexec: BTreeMap<u32, bool>,         // fd -> close-on-exec
    pub next_fd: u32,
    pub stack_bottom: usize,
    pub stack_size: usize,
    pub max_stack_size: usize,
    pub heap_start: usize,
    pub heap_brk: usize,
    pub heap_limit: usize,
    pub mmap_base: usize,
    pub mmap_next: usize,
    pub mmap_limit: usize,
    pub intermediate_page_tables: BTreeMap<(usize, usize), CapPtr>, // (level, vaddr-prefix) -> pagetable cap (null means externally managed)
    pub clear_child_tid: usize,
    pub signal_actions: BTreeMap<usize, SignalAction>, // signum -> disposition
    pub signal_blocked: u64,
    pub signal_pending: u64,
    pub stopped: bool,
}

impl SubProcess {
    pub fn new(pid: usize, parent_pid: usize, cnode_cap: CNode) -> Self {
        Self {
            pid,
            parent_pid,
            session_id: pid,
            process_group_id: pid,
            controlling_tty: None,
            cnode_cap,
            root_dir: String::from(DEFAULT_PROCESS_ROOT),
            cwd: String::from(DEFAULT_PROCESS_ROOT),
            memory_maps: BTreeMap::new(),
            lazy_memory_maps: BTreeMap::new(),
            fds: BTreeMap::new(),
            fd_paths: BTreeMap::new(),
            fd_cloexec: BTreeMap::new(),
            next_fd: 0,
            stack_bottom: STACK_BASE,
            stack_size: 0,
            max_stack_size: DEFAULT_MAX_STACK_SIZE,
            heap_start: HEAP_VA,
            heap_brk: HEAP_VA,
            heap_limit: DEFAULT_HEAP_LIMIT,
            mmap_base: DEFAULT_MMAP_BASE,
            mmap_next: DEFAULT_MMAP_BASE,
            mmap_limit: DEFAULT_MMAP_LIMIT,
            intermediate_page_tables: BTreeMap::new(),
            clear_child_tid: 0,
            signal_actions: BTreeMap::new(),
            signal_blocked: 0,
            signal_pending: 0,
            stopped: false,
        }
    }

    pub fn add_memory_map(&mut self, map: MemoryMap) {
        self.memory_maps.insert(map.vaddr, map);
    }

    pub fn add_lazy_memory_map(&mut self, map: MemoryMap) {
        self.lazy_memory_maps.insert(map.vaddr, map);
    }

    pub fn remove_lazy_memory_map(&mut self, vaddr: usize) {
        self.lazy_memory_maps.remove(&vaddr);
    }

    pub fn lookup_memory_map(&self, vaddr: usize) -> Option<&MemoryMap> {
        self.memory_maps
            .range(..=vaddr)
            .next_back()
            .and_then(|(_, map)| (vaddr < map.vaddr + map.size).then_some(map))
    }

    pub fn lookup_lazy_memory_map(&self, vaddr: usize) -> Option<&MemoryMap> {
        self.lazy_memory_maps
            .range(..=vaddr)
            .next_back()
            .and_then(|(_, map)| (vaddr < map.vaddr + map.size).then_some(map))
    }

    pub fn translate(&self, vaddr: usize) -> Option<usize> {
        self.lookup_memory_map(vaddr).map(|map| map.paddr + (vaddr - map.vaddr))
    }

    pub fn cspace(&self) -> CNode {
        self.cnode_cap.clone()
    }

    pub fn has_intermediate_page_table(&self, level: usize, path_prefix: usize) -> bool {
        self.intermediate_page_tables.contains_key(&(level, path_prefix))
    }

    pub fn record_intermediate_page_table(
        &mut self,
        level: usize,
        path_prefix: usize,
        cap: CapPtr,
    ) {
        self.intermediate_page_tables.insert((level, path_prefix), cap);
    }

    pub fn vspace(&self) -> VSpace {
        VSpace::from(CapPtr::concat(self.cnode_cap.cap(), VSPACE_SLOT))
    }

    pub fn tcb(&self) -> TCB {
        TCB::from(CapPtr::concat(self.cnode_cap.cap(), TCB_SLOT))
    }

    pub fn signal_action(&self, signum: usize) -> SignalAction {
        self.signal_actions.get(&signum).copied().unwrap_or_default()
    }

    pub fn set_signal_blocked(&mut self, mut mask: u64) {
        // SIGKILL/SIGSTOP 不可屏蔽。
        mask &= !SIGNAL_UNBLOCKABLE_MASK;
        self.signal_blocked = mask;
    }

    pub fn queue_signal(&mut self, signum: usize) -> bool {
        if let Some(bit) = signal_bit(signum) {
            self.signal_pending |= bit;
            true
        } else {
            false
        }
    }

    pub fn pop_pending_signal_from_mask(&mut self, mask: u64) -> Option<usize> {
        let ready = self.signal_pending & mask;
        if ready == 0 {
            return None;
        }

        let idx = ready.trailing_zeros() as usize;
        let bit = 1u64 << idx;
        self.signal_pending &= !bit;
        Some(idx + 1)
    }
}
