use alloc::collections::BTreeMap;
use glenda::cap::{CNode, CapPtr, TCB, TCB_SLOT, VSPACE_SLOT, VSpace};
use glenda::client::TerminalClient;

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
    pub flags: usize,
    pub mem_type: MemoryType,
    pub cow: bool,
    pub frame_cap: usize, // Required for translate and map_scratch
}

#[derive(Debug, Clone)]
pub enum FileType {
    Normal { cap: CapPtr, offset: usize },
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
    pub cnode_cap: CNode,                        // Copy of CNode capability
    pub memory_maps: BTreeMap<usize, MemoryMap>, // vaddr -> mapping
    pub fds: BTreeMap<usize, FileHandle>,        // fd -> handle
    pub next_fd: usize,
    pub stack_bottom: usize,
    pub stack_size: usize,
}

impl SubProcess {
    pub fn new(pid: usize, parent_pid: usize, cnode_cap: CNode) -> Self {
        Self {
            pid,
            parent_pid,
            cnode_cap,
            memory_maps: BTreeMap::new(),
            fds: BTreeMap::new(),
            next_fd: 0,
            stack_bottom: 0,
            stack_size: 0,
        }
    }

    pub fn add_memory_map(&mut self, map: MemoryMap) {
        self.memory_maps.insert(map.vaddr, map);
    }

    pub fn translate(&self, vaddr: usize) -> Option<usize> {
        for (base, map) in self.memory_maps.iter() {
            if vaddr >= *base && vaddr < *base + map.size {
                let offset = vaddr - base;
                return Some(map.paddr + offset);
            }
        }
        None
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
