use crate::layout::{
    DEFAULT_HEAP_LIMIT, DEFAULT_MAX_STACK_SIZE, DEFAULT_MMAP_BASE, DEFAULT_MMAP_LIMIT,
};
use alloc::collections::BTreeMap;
use glenda::cap::{CapPtr, VSpace};
use glenda::mem::{HEAP_VA, Perms, STACK_BASE};
use glenda::sync::rwlock::RwLock;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MemoryType {
    Image,
    Stack,
    Heap,
    Anonymous,
    FileBacked,
}

#[derive(Debug, Clone)]
pub struct MemoryMap {
    pub vaddr: usize,
    pub paddr: usize,
    pub size: usize,
    pub flags: Perms,
    pub mem_type: MemoryType,
    pub cow: bool,
    pub frame_cap: usize,
    pub file_backing_fd: Option<u32>,
    pub file_backing_offset: usize,
}

pub struct MmState {
    pub memory_maps: BTreeMap<usize, MemoryMap>,
    pub lazy_memory_maps: BTreeMap<usize, MemoryMap>,
    pub stack_bottom: usize,
    pub stack_size: usize,
    pub max_stack_size: usize,
    pub heap_start: usize,
    pub heap_brk: usize,
    pub heap_limit: usize,
    pub mmap_base: usize,
    pub mmap_next: usize,
    pub mmap_limit: usize,
    pub intermediate_page_tables: BTreeMap<(usize, usize), CapPtr>,
}

pub struct MmStruct {
    pub vspace: VSpace,
    pub state: RwLock<MmState>,
}

impl MmStruct {
    pub fn new(vspace: VSpace) -> Self {
        Self {
            vspace,
            state: RwLock::new(MmState {
                memory_maps: BTreeMap::new(),
                lazy_memory_maps: BTreeMap::new(),
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
            }),
        }
    }

    pub fn lookup_memory_map(&self, vaddr: usize) -> Option<MemoryMap> {
        self.state.read()
            .memory_maps
            .range(..=vaddr)
            .next_back()
            .and_then(|(_, map)| (vaddr < map.vaddr + map.size).then_some(map.clone()))
    }

    pub fn lookup_lazy_memory_map(&self, vaddr: usize) -> Option<MemoryMap> {
        self.state.read()
            .lazy_memory_maps
            .range(..=vaddr)
            .next_back()
            .and_then(|(_, map)| (vaddr < map.vaddr + map.size).then_some(map.clone()))
    }

    pub fn add_memory_map(&self, map: MemoryMap) {
        self.state.write().memory_maps.insert(map.vaddr, map);
    }

    pub fn add_lazy_memory_map(&self, map: MemoryMap) {
        self.state.write().lazy_memory_maps.insert(map.vaddr, map);
    }

    pub fn remove_lazy_memory_map(&self, vaddr: usize) {
        self.state.write().lazy_memory_maps.remove(&vaddr);
    }

    pub fn translate(&self, vaddr: usize) -> Option<usize> {
        self.lookup_memory_map(vaddr).map(|map| map.paddr + (vaddr - map.vaddr))
    }

    pub fn has_intermediate_page_table(&self, level: usize, path_prefix: usize) -> bool {
        self.state.read().intermediate_page_tables.contains_key(&(level, path_prefix))
    }

    pub fn record_intermediate_page_table(
        &self,
        level: usize,
        path_prefix: usize,
        cap: CapPtr,
    ) {
        self.state.write().intermediate_page_tables.insert((level, path_prefix), cap);
    }
}

impl Drop for MmStruct {
    fn drop(&mut self) {
        // Automatically recycle memory frames and page tables.
    }
}
