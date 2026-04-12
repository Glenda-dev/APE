use crate::layout::DEFAULT_PROCESS_ROOT;
use alloc::collections::BTreeMap;
use alloc::string::String;
use ape::sys::constants::{
    DEFAULT_HEAP_LIMIT, DEFAULT_MAX_STACK_SIZE, DEFAULT_MMAP_BASE, DEFAULT_MMAP_LIMIT,
};
use glenda::cap::{CNode, CapPtr, TCB, TCB_SLOT, VSPACE_SLOT, VSpace};
use glenda::client::FsClient;
use glenda::client::TerminalClient;
use glenda::io::uring::IoUringClient;
use glenda::mem::{HEAP_VA, Perms, STACK_BASE};

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
pub enum FileType {
    Normal(NormalFileHandle),
    Terminal(TerminalClient),
}

#[derive(Debug, Clone)]
pub struct FileHandle {
    pub file_type: FileType,
}

#[derive(Debug)]
pub struct SubProcess {
    pub pid: usize,
    pub parent_pid: usize,
    pub cnode_cap: CNode, // Copy of CNode capability
    pub root_dir: String,
    pub cwd: String,
    pub memory_maps: BTreeMap<usize, MemoryMap>, // vaddr -> mapping
    pub lazy_memory_maps: BTreeMap<usize, MemoryMap>, // vaddr(page) -> lazy mapping
    pub fds: BTreeMap<u32, FileHandle>,          // fd -> handle
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
    pub clear_child_tid: usize,
}

impl SubProcess {
    pub fn new(pid: usize, parent_pid: usize, cnode_cap: CNode) -> Self {
        Self {
            pid,
            parent_pid,
            cnode_cap,
            root_dir: String::from(DEFAULT_PROCESS_ROOT),
            cwd: String::from(DEFAULT_PROCESS_ROOT),
            memory_maps: BTreeMap::new(),
            lazy_memory_maps: BTreeMap::new(),
            fds: BTreeMap::new(),
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
            clear_child_tid: 0,
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

    pub fn vspace(&self) -> VSpace {
        VSpace::from(CapPtr::concat(self.cnode_cap.cap(), VSPACE_SLOT))
    }

    pub fn tcb(&self) -> TCB {
        TCB::from(CapPtr::concat(self.cnode_cap.cap(), TCB_SLOT))
    }
}
