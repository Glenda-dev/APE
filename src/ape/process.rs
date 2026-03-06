use alloc::collections::BTreeMap;

#[derive(Debug, Clone)]
pub struct MemoryMap {
    pub vaddr: usize,
    pub paddr: usize,
    pub size: usize,
    pub flags: usize,
}

#[derive(Debug)]
pub struct SubProcess {
    pub pid: usize,
    pub parent_pid: usize,
    pub endpoint: usize,   // Capability to communicate with this process
    pub vspace_cap: usize, // Copy of VSpace capability for memory management
    pub memory_maps: BTreeMap<usize, MemoryMap>, // vaddr -> mapping
}

impl SubProcess {
    pub fn new(pid: usize, parent_pid: usize, endpoint: usize, vspace_cap: usize) -> Self {
        Self { pid, parent_pid, endpoint, vspace_cap, memory_maps: BTreeMap::new() }
    }

    pub fn add_memory_map(&mut self, map: MemoryMap) {
        self.memory_maps.insert(map.vaddr, map);
    }

    pub fn translate(&self, vaddr: usize) -> Option<usize> {
        // Simple translation: find range containing vaddr
        // In a real system you'd walk the page tables or query kernel,
        // but here we track what we mapped.
        for (base, map) in self.memory_maps.iter() {
            if vaddr >= *base && vaddr < *base + map.size {
                let offset = vaddr - base;
                return Some(map.paddr + offset);
            }
        }
        None
    }
}
