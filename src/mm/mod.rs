use crate::ApeManager;
use crate::ape::process::{MemoryMap, MemoryType};
use alloc::vec::Vec;
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

pub fn sys_brk<'a>(mgr: &mut ApeManager<'a>, pid: usize, addr: usize) -> Result<isize, Error> {
    Ok(do_brk(mgr, pid, addr)? as isize)
}

pub fn sys_mmap<'a>(
    mgr: &mut ApeManager<'a>,
    pid: usize,
    addr: usize,
    len: usize,
    prot: u32,
    flags: u32,
    fd: usize,
    offset: usize,
) -> Result<isize, Error> {
    Ok(do_mmap(mgr, pid, addr, len, prot, flags, fd, offset)? as isize)
}

pub fn sys_munmap<'a>(
    mgr: &mut ApeManager<'a>,
    pid: usize,
    addr: usize,
    len: usize,
) -> Result<isize, Error> {
    do_munmap(mgr, pid, addr, len)
}

pub fn sys_mprotect<'a>(
    mgr: &mut ApeManager<'a>,
    pid: usize,
    addr: usize,
    len: usize,
    prot: u32,
) -> Result<isize, Error> {
    do_mprotect(mgr, pid, addr, len, prot)
}
