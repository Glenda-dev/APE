use crate::ape::process::{MemoryMap, SubProcess};
use glenda::arch::mem::PGSIZE;

#[derive(Debug, Clone)]
pub enum FaultAction {
    StackGrowth { current_stack_low: usize, pages_to_map: usize },
    HeapLazy,
    LazyMmap(MemoryMap),
    Unmanaged,
}

pub fn classify_fault(process: &SubProcess, addr: usize, page_addr: usize) -> FaultAction {
    // 1) 栈增长（向下增长）
    let stack_low_limit = process.stack_bottom.saturating_sub(process.max_stack_size);
    let current_stack_low = process.stack_bottom.saturating_sub(process.stack_size);
    if addr < process.stack_bottom && addr >= stack_low_limit && page_addr < current_stack_low {
        let pages_to_map = (current_stack_low - page_addr) / PGSIZE;
        if pages_to_map > 0 {
            return FaultAction::StackGrowth { current_stack_low, pages_to_map };
        }
    }

    // 2) brk 管理的堆区懒分配
    if addr >= process.heap_start && addr < process.heap_brk {
        return FaultAction::HeapLazy;
    }

    // 3) mmap 懒分配
    if let Some(map) = process.lookup_lazy_memory_map(addr).cloned() {
        return FaultAction::LazyMmap(map);
    }

    FaultAction::Unmanaged
}
