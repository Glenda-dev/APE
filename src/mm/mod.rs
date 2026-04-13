use crate::ApeManager;
use crate::ape::process::{MemoryMap, MemoryType};
use alloc::vec::Vec;
use core::cmp::min;
use glenda::arch::mem::PGSIZE;
use glenda::cap::{CapPtr, Frame};
use glenda::error::Error;
use glenda::mem::Perms;
use glenda::utils::align::{align_down, align_up};
use linux_raw_sys::general::*;

fn prot_to_perms(prot: u32) -> Perms {
    let mut perms = Perms::empty();
    if prot & PROT_READ != 0 {
        perms |= Perms::READ;
    }
    if prot & PROT_WRITE != 0 {
        perms |= Perms::WRITE;
    }
    if prot & PROT_EXEC != 0 {
        perms |= Perms::EXECUTE;
    }
    perms
}

fn has_overlap(start: usize, end: usize, map_start: usize, map_size: usize) -> bool {
    let map_end = map_start.saturating_add(map_size);
    start < map_end && map_start < end
}

fn range_is_free(process: &crate::ape::process::SubProcess, start: usize, end: usize) -> bool {
    if end > process.mmap_limit || start < process.mmap_base || start >= end {
        return false;
    }

    if has_overlap(
        start,
        end,
        process.heap_start,
        process.heap_brk.saturating_sub(process.heap_start),
    ) {
        return false;
    }

    let stack_low = process.stack_bottom.saturating_sub(process.max_stack_size);
    if has_overlap(start, end, stack_low, process.max_stack_size) {
        return false;
    }

    for map in process.memory_maps.values() {
        if has_overlap(start, end, map.vaddr, map.size) {
            return false;
        }
    }

    for map in process.lazy_memory_maps.values() {
        if has_overlap(start, end, map.vaddr, map.size) {
            return false;
        }
    }

    true
}

fn range_is_free_excluding(
    process: &crate::ape::process::SubProcess,
    start: usize,
    end: usize,
    except_start: usize,
    except_end: usize,
) -> bool {
    if end > process.mmap_limit || start < process.mmap_base || start >= end {
        return false;
    }

    if has_overlap(
        start,
        end,
        process.heap_start,
        process.heap_brk.saturating_sub(process.heap_start),
    ) {
        return false;
    }

    let stack_low = process.stack_bottom.saturating_sub(process.max_stack_size);
    if has_overlap(start, end, stack_low, process.max_stack_size) {
        return false;
    }

    for map in process.memory_maps.values() {
        if has_overlap(start, end, map.vaddr, map.size) {
            let map_end = map.vaddr.saturating_add(map.size);
            let in_except = map.vaddr >= except_start && map_end <= except_end;
            if !in_except {
                return false;
            }
        }
    }

    for map in process.lazy_memory_maps.values() {
        if has_overlap(start, end, map.vaddr, map.size) {
            let map_end = map.vaddr.saturating_add(map.size);
            let in_except = map.vaddr >= except_start && map_end <= except_end;
            if !in_except {
                return false;
            }
        }
    }

    true
}

#[derive(Clone, Copy)]
enum RemapPageState {
    Mapped { frame_cap: usize, flags: Perms },
    Lazy { flags: Perms },
}

impl RemapPageState {
    fn flags(self) -> Perms {
        match self {
            Self::Mapped { flags, .. } | Self::Lazy { flags } => flags,
        }
    }
}

fn collect_remap_states(
    process: &crate::ape::process::SubProcess,
    old_addr: usize,
    old_len: usize,
) -> Result<Vec<RemapPageState>, Error> {
    let mut out = Vec::new();
    for page in (old_addr..old_addr + old_len).step_by(PGSIZE) {
        if let Some(map) = process.memory_maps.get(&page) {
            if map.mem_type != MemoryType::Anonymous || map.size != PGSIZE {
                return Err(Error::InvalidArgs);
            }
            out.push(RemapPageState::Mapped {
                frame_cap: map.frame_cap,
                flags: map.flags,
            });
            continue;
        }

        if let Some(map) = process.lazy_memory_maps.get(&page) {
            if map.mem_type != MemoryType::Anonymous || map.size != PGSIZE {
                return Err(Error::InvalidArgs);
            }
            out.push(RemapPageState::Lazy { flags: map.flags });
            continue;
        }

        return Err(Error::InvalidAddress);
    }
    Ok(out)
}

fn find_free_remap_target(process: &crate::ape::process::SubProcess, len_aligned: usize) -> Option<usize> {
    let mut candidate = process.mmap_next.max(process.mmap_base);
    while let Some(end) = candidate.checked_add(len_aligned) {
        if end > process.mmap_limit {
            break;
        }
        if range_is_free(process, candidate, end) {
            return Some(candidate);
        }
        candidate = candidate.saturating_add(PGSIZE);
    }
    None
}

pub(crate) fn do_brk<'a>(
    mgr: &mut ApeManager<'a>,
    pid: usize,
    addr: usize,
) -> Result<usize, Error> {
    let process = mgr.get_process_mut(pid).ok_or(Error::NotFound)?;

    if addr == 0 {
        return Ok(process.heap_brk);
    }

    if addr < process.heap_start || addr > process.heap_limit {
        return Ok(process.heap_brk);
    }

    process.heap_brk = addr;
    Ok(process.heap_brk)
}

pub(crate) fn do_mmap<'a>(
    mgr: &mut ApeManager<'a>,
    pid: usize,
    addr: usize,
    len: usize,
    prot: u32,
    flags: u32,
    _fd: usize,
    _offset: usize,
) -> Result<usize, Error> {
    if len == 0 {
        return Err(Error::InvalidArgs);
    }

    if flags & MAP_PRIVATE == 0 || flags & MAP_ANONYMOUS == 0 {
        return Err(Error::InvalidArgs);
    }

    let len_aligned = align_up(len, PGSIZE);
    let perms = prot_to_perms(prot);

    if flags & MAP_FIXED != 0 {
        if addr % PGSIZE != 0 {
            return Err(Error::InvalidArgs);
        }
        let start = addr;
        let end = match start.checked_add(len_aligned) {
            Some(v) => v,
            None => return Err(Error::OutOfMemory),
        };

        let mut mapped_pages_to_unmap = Vec::new();
        {
            let process = mgr.get_process_mut(pid).ok_or(Error::NotFound)?;

            if end > process.mmap_limit {
                return Err(Error::OutOfMemory);
            }

            // 保守处理：不允许覆盖 brk 堆区和预留栈区。
            if has_overlap(
                start,
                end,
                process.heap_start,
                process.heap_brk.saturating_sub(process.heap_start),
            ) {
                return Err(Error::InvalidArgs);
            }
            let stack_low = process.stack_bottom.saturating_sub(process.max_stack_size);
            if has_overlap(start, end, stack_low, process.max_stack_size) {
                return Err(Error::InvalidArgs);
            }

            // 允许替换匿名映射，但不允许覆盖 Image/Heap/Stack 等关键映射。
            for map in process.memory_maps.values() {
                if has_overlap(start, end, map.vaddr, map.size)
                    && map.mem_type != MemoryType::Anonymous
                {
                    return Err(Error::InvalidArgs);
                }
            }

            for page in (start..end).step_by(PGSIZE) {
                process.remove_lazy_memory_map(page);
                if let Some(map) = process.memory_maps.get(&page)
                    && map.mem_type == MemoryType::Anonymous
                    && map.size == PGSIZE
                {
                    mapped_pages_to_unmap.push(page);
                }
            }
            for page in &mapped_pages_to_unmap {
                process.memory_maps.remove(page);
            }
        }

        if !mapped_pages_to_unmap.is_empty() {
            for page in mapped_pages_to_unmap {
                mgr.unmap_process_pages(pid, page, 1)?;
            }
        }

        let process = mgr.get_process_mut(pid).ok_or(Error::NotFound)?;
        for page in (start..end).step_by(PGSIZE) {
            process.add_lazy_memory_map(MemoryMap {
                vaddr: page,
                paddr: 0,
                size: PGSIZE,
                flags: perms,
                mem_type: MemoryType::Anonymous,
                cow: false,
                frame_cap: 0,
            });
        }
        process.mmap_next = process.mmap_next.max(end);
        return Ok(start);
    }

    let process = mgr.get_process_mut(pid).ok_or(Error::NotFound)?;

    let mut candidate = if addr != 0 { align_down(addr, PGSIZE) } else { process.mmap_next };
    if candidate < process.mmap_base {
        candidate = process.mmap_base;
    }
    let mut chosen = None;

    while let Some(end) = candidate.checked_add(len_aligned) {
        if end > process.mmap_limit {
            break;
        }
        if range_is_free(process, candidate, end) {
            chosen = Some(candidate);
            break;
        }
        candidate = candidate.saturating_add(PGSIZE);
    }

    let start = match chosen {
        Some(v) => v,
        None => return Err(Error::OutOfMemory),
    };
    let end = start + len_aligned;

    for page in (start..end).step_by(PGSIZE) {
        process.add_lazy_memory_map(MemoryMap {
            vaddr: page,
            paddr: 0,
            size: PGSIZE,
            flags: perms,
            mem_type: MemoryType::Anonymous,
            cow: false,
            frame_cap: 0,
        });
    }

    process.mmap_next = process.mmap_next.max(end);
    Ok(start)
}

pub(crate) fn do_munmap<'a>(
    mgr: &mut ApeManager<'a>,
    pid: usize,
    addr: usize,
    len: usize,
) -> Result<isize, Error> {
    if len == 0 || addr % PGSIZE != 0 {
        return Err(Error::InvalidArgs);
    }

    let len_aligned = align_up(len, PGSIZE);
    let mut mapped_pages_to_unmap = Vec::new();

    {
        let process = mgr.get_process_mut(pid).ok_or(Error::NotFound)?;
        for page in (addr..addr + len_aligned).step_by(PGSIZE) {
            process.remove_lazy_memory_map(page);

            if let Some(map) = process.memory_maps.get(&page)
                && map.mem_type == MemoryType::Anonymous
                && map.size == PGSIZE
            {
                mapped_pages_to_unmap.push(page);
            }
        }

        for page in &mapped_pages_to_unmap {
            process.memory_maps.remove(page);
        }
    }

    if !mapped_pages_to_unmap.is_empty() {
        for page in mapped_pages_to_unmap {
            mgr.unmap_process_pages(pid, page, 1)?;
        }
    }

    Ok(0)
}

pub(crate) fn do_mprotect<'a>(
    mgr: &mut ApeManager<'a>,
    pid: usize,
    addr: usize,
    len: usize,
    prot: u32,
) -> Result<isize, Error> {
    if len == 0 {
        return Ok(0);
    }

    let start = align_down(addr, PGSIZE);
    let end = align_up(addr.checked_add(len).ok_or(Error::OutOfMemory)?, PGSIZE);
    let new_perms = prot_to_perms(prot);

    let mut pages = Vec::new();
    {
        let process = mgr.get_process(pid).ok_or(Error::NotFound)?;
        for page in (start..end).step_by(PGSIZE) {
            let map = process.lookup_memory_map(page).cloned().ok_or(Error::InvalidAddress)?;
            if page < map.vaddr || page >= map.vaddr.saturating_add(map.size) {
                return Err(Error::InvalidAddress);
            }
            pages.push((page, map.frame_cap));
        }
    }

    for (page, frame_cap) in &pages {
        let _ = mgr.unmap_process_pages(pid, *page, 1);
        mgr.map_process_frame(pid, Frame::from(CapPtr::from(*frame_cap)), *page, new_perms, 1)?;
    }

    if let Some(process) = mgr.get_process_mut(pid) {
        for (page, _) in pages {
            if let Some(map) = process.memory_maps.get_mut(&page) {
                map.flags = new_perms;
            }
            if let Some(map) = process.lazy_memory_maps.get_mut(&page) {
                map.flags = new_perms;
            }
        }
    }

    Ok(0)
}

pub(crate) fn do_mremap<'a>(
    mgr: &mut ApeManager<'a>,
    pid: usize,
    old_addr: usize,
    old_size: usize,
    new_size: usize,
    flags: u32,
    new_addr: usize,
) -> Result<usize, Error> {
    if old_size == 0 || new_size == 0 || old_addr % PGSIZE != 0 {
        return Err(Error::InvalidArgs);
    }

    let allowed = MREMAP_MAYMOVE | MREMAP_FIXED | MREMAP_DONTUNMAP;
    if flags & !allowed != 0 || (flags & MREMAP_DONTUNMAP) != 0 {
        return Err(Error::InvalidArgs);
    }
    if (flags & MREMAP_FIXED) != 0 && (flags & MREMAP_MAYMOVE) == 0 {
        return Err(Error::InvalidArgs);
    }

    let old_len = align_up(old_size, PGSIZE);
    let new_len = align_up(new_size, PGSIZE);
    let old_end = old_addr.checked_add(old_len).ok_or(Error::OutOfMemory)?;
    let new_end_in_place = old_addr.checked_add(new_len).ok_or(Error::OutOfMemory)?;
    let old_pages = old_len / PGSIZE;
    let new_pages = new_len / PGSIZE;

    let page_states = {
        let process = mgr.get_process(pid).ok_or(Error::NotFound)?;
        collect_remap_states(process, old_addr, old_len)?
    };
    let base_flags = page_states
        .first()
        .map(|s| s.flags())
        .unwrap_or(Perms::READ | Perms::WRITE);

    if (flags & MREMAP_FIXED) == 0 {
        if new_len <= old_len {
            if new_len < old_len {
                do_munmap(mgr, pid, old_addr + new_len, old_len - new_len)?;
            }
            return Ok(old_addr);
        }

        let can_expand_in_place = {
            let process = mgr.get_process(pid).ok_or(Error::NotFound)?;
            range_is_free_excluding(process, old_addr, new_end_in_place, old_addr, old_end)
        };

        if can_expand_in_place {
            let process = mgr.get_process_mut(pid).ok_or(Error::NotFound)?;
            for page in (old_end..new_end_in_place).step_by(PGSIZE) {
                process.add_lazy_memory_map(MemoryMap {
                    vaddr: page,
                    paddr: 0,
                    size: PGSIZE,
                    flags: base_flags,
                    mem_type: MemoryType::Anonymous,
                    cow: false,
                    frame_cap: 0,
                });
            }
            process.mmap_next = process.mmap_next.max(new_end_in_place);
            return Ok(old_addr);
        }

        if (flags & MREMAP_MAYMOVE) == 0 {
            return Err(Error::OutOfMemory);
        }
    }

    let target = if (flags & MREMAP_FIXED) != 0 {
        if new_addr % PGSIZE != 0 {
            return Err(Error::InvalidArgs);
        }
        new_addr
    } else {
        let process = mgr.get_process(pid).ok_or(Error::NotFound)?;
        find_free_remap_target(process, new_len).ok_or(Error::OutOfMemory)?
    };
    let target_end = target.checked_add(new_len).ok_or(Error::OutOfMemory)?;

    if target == old_addr {
        if new_len < old_len {
            do_munmap(mgr, pid, old_addr + new_len, old_len - new_len)?;
        } else if new_len > old_len {
            let can_expand_in_place = {
                let process = mgr.get_process(pid).ok_or(Error::NotFound)?;
                range_is_free_excluding(process, old_addr, target_end, old_addr, old_end)
            };
            if !can_expand_in_place {
                return Err(Error::OutOfMemory);
            }

            let process = mgr.get_process_mut(pid).ok_or(Error::NotFound)?;
            for page in (old_end..target_end).step_by(PGSIZE) {
                process.add_lazy_memory_map(MemoryMap {
                    vaddr: page,
                    paddr: 0,
                    size: PGSIZE,
                    flags: base_flags,
                    mem_type: MemoryType::Anonymous,
                    cow: false,
                    frame_cap: 0,
                });
            }
            process.mmap_next = process.mmap_next.max(target_end);
        }
        return Ok(old_addr);
    }

    if has_overlap(target, target_end, old_addr, old_len) {
        return Err(Error::InvalidArgs);
    }

    {
        let process = mgr.get_process(pid).ok_or(Error::NotFound)?;
        if !range_is_free(process, target, target_end) {
            return Err(Error::OutOfMemory);
        }
    }

    let copy_pages = min(old_pages, new_pages);
    let mut old_mapped_pages = Vec::new();
    for (idx, state) in page_states.iter().enumerate() {
        if let RemapPageState::Mapped { .. } = state {
            old_mapped_pages.push(old_addr + idx * PGSIZE);
        }
    }

    let mut mapped_dst_pages = Vec::new();
    for i in 0..copy_pages {
        if let RemapPageState::Mapped { frame_cap, flags } = page_states[i]
            && let Err(e) = mgr.map_process_frame(
                pid,
                Frame::from(CapPtr::from(frame_cap)),
                target + i * PGSIZE,
                flags,
                1,
            )
        {
            for page in mapped_dst_pages {
                let _ = mgr.unmap_process_pages(pid, page, 1);
            }
            return Err(e);
        }

        if matches!(page_states[i], RemapPageState::Mapped { .. }) {
            mapped_dst_pages.push(target + i * PGSIZE);
        }
    }

    {
        let process = mgr.get_process_mut(pid).ok_or(Error::NotFound)?;
        for page in (old_addr..old_end).step_by(PGSIZE) {
            process.memory_maps.remove(&page);
            process.lazy_memory_maps.remove(&page);
        }

        for i in 0..copy_pages {
            let vaddr = target + i * PGSIZE;
            match page_states[i] {
                RemapPageState::Mapped { frame_cap, flags } => {
                    process.add_memory_map(MemoryMap {
                        vaddr,
                        paddr: 0,
                        size: PGSIZE,
                        flags,
                        mem_type: MemoryType::Anonymous,
                        cow: false,
                        frame_cap,
                    });
                }
                RemapPageState::Lazy { flags } => {
                    process.add_lazy_memory_map(MemoryMap {
                        vaddr,
                        paddr: 0,
                        size: PGSIZE,
                        flags,
                        mem_type: MemoryType::Anonymous,
                        cow: false,
                        frame_cap: 0,
                    });
                }
            }
        }

        for i in copy_pages..new_pages {
            let vaddr = target + i * PGSIZE;
            process.add_lazy_memory_map(MemoryMap {
                vaddr,
                paddr: 0,
                size: PGSIZE,
                flags: base_flags,
                mem_type: MemoryType::Anonymous,
                cow: false,
                frame_cap: 0,
            });
        }

        process.mmap_next = process.mmap_next.max(target_end);
    }

    for page in old_mapped_pages {
        let _ = mgr.unmap_process_pages(pid, page, 1);
    }

    Ok(target)
}

