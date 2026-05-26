use crate::ape::mm::{MemoryMap, MemoryType};
use crate::ape::task::TaskStruct;
use glenda::arch::mem::PGSIZE;

#[derive(Debug, Clone)]
pub enum FaultAction {
    StackGrowth { current_stack_low: usize, pages_to_map: usize },
    HeapLazy,
    LazyMmap(MemoryMap),
    Unmanaged,
}

pub fn classify_fault(task: &TaskStruct, addr: usize, page_addr: usize) -> FaultAction {
    let mm = task.mm.state.read();

    // Check lazy mappings
    if let Some(map) = task.mm.lookup_lazy_memory_map(addr) {
        return FaultAction::LazyMmap(map);
    }

    // Check stack growth
    let stack_low = mm.stack_bottom.saturating_sub(mm.max_stack_size);
    let current_stack_boundary = mm.stack_bottom.saturating_sub(mm.stack_size);

    if addr >= stack_low && addr < current_stack_boundary {
        let pages = (current_stack_boundary - page_addr) / PGSIZE;
        return FaultAction::StackGrowth {
            current_stack_low: current_stack_boundary,
            pages_to_map: pages,
        };
    }

    // Check heap
    if addr >= mm.heap_start && addr < mm.heap_brk {
        return FaultAction::HeapLazy;
    }

    FaultAction::Unmanaged
}
