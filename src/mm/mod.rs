use crate::ApeManager;
use crate::ape::mm::{MemoryMap, MemoryType};
use crate::ape::files::FileType;
use crate::ape::task::TaskStruct;
use alloc::collections::BTreeMap;
use alloc::vec::Vec;
use core::cmp::min;
use glenda::arch::mem::PGSIZE;
use glenda::cap::{CapPtr, CapType, Page};
use glenda::error::Error;
use glenda::interface::{CSpaceService, ResourceService, VSpaceService};
use glenda::ipc::Badge;
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

fn is_remappable_user_mapping(mem_type: MemoryType) -> bool {
    matches!(mem_type, MemoryType::Anonymous | MemoryType::FileBacked)
}

fn split_partial_multi_page_targets(
    task: &TaskStruct,
    start: usize,
    end: usize,
) -> Vec<usize> {
    task.mm.state.read()
        .memory_maps
        .values()
        .filter_map(|map| {
            if !is_remappable_user_mapping(map.mem_type) || map.frame_cap == 0 {
                return None;
            }
            let map_pages = align_up(map.size, PGSIZE) / PGSIZE;
            if map_pages <= 1 {
                return None;
            }
            let map_end = map.vaddr.saturating_add(map_pages * PGSIZE);
            if !has_overlap(start, end, map.vaddr, map_pages * PGSIZE) {
                return None;
            }

            if start > map.vaddr || end < map_end { Some(map.vaddr) } else { None }
        })
        .collect()
}

fn release_temp_frame_slots<'a>(
    mgr: &mut ApeManager<'a>,
    pid: usize,
    slots: &[CapPtr],
    reason: &str,
) {
    for slot in slots {
        mgr.release_process_frame_slot(pid, *slot, 1, reason);
    }
}

fn split_large_mapping_into_base_pages<'a>(
    mgr: &mut ApeManager<'a>,
    pid: usize,
    map_start: usize,
) -> Result<(), Error> {
    let map = {
        let task = mgr.get_process(pid).ok_or(Error::NotFound)?;
        task.mm.state.read().memory_maps.get(&map_start).cloned().ok_or(Error::NotFound)?
    };

    if !is_remappable_user_mapping(map.mem_type) || map.frame_cap == 0 {
        return Ok(());
    }

    let pages = align_up(map.size, PGSIZE) / PGSIZE;
    if pages <= 1 {
        return Ok(());
    }

    let old_slot = CapPtr::from(map.frame_cap);
    let old_frame = Page::from(old_slot);
    let src = mgr.vspace_mgr.map_scratch(
        old_frame,
        Perms::READ,
        pages,
        &mut *mgr.res_client,
        &mut *mgr.cspace_mgr,
    )?;

    let mut new_slots: Vec<CapPtr> = Vec::with_capacity(pages);
    for idx in 0..pages {
        let slot = match mgr.cspace_mgr.alloc(&mut *mgr.res_client) {
            Ok(v) => v,
            Err(e) => {
                let _ = mgr.vspace_mgr.unmap(src, pages);
                release_temp_frame_slots(
                    mgr,
                    pid,
                    &new_slots,
                    "split_large_mapping_alloc_slot_fail",
                );
                return Err(e);
            }
        };

        if let Err(e) = mgr.res_client.alloc(Badge::null(), CapType::Page, 1, slot) {
            mgr.cspace_mgr.free(slot);
            let _ = mgr.vspace_mgr.unmap(src, pages);
            release_temp_frame_slots(mgr, pid, &new_slots, "split_large_mapping_alloc_page_fail");
            return Err(e);
        }
        mgr.ledger_record_frame_alloc(pid, slot, 1, "split_large_mapping_new_page");

        let dst = match mgr.vspace_mgr.map_scratch(
            Page::from(slot),
            Perms::READ | Perms::WRITE,
            1,
            &mut *mgr.res_client,
            &mut *mgr.cspace_mgr,
        ) {
            Ok(v) => v,
            Err(e) => {
                mgr.release_process_frame_slot(pid, slot, 1, "split_large_mapping_map_dst_fail");
                let _ = mgr.vspace_mgr.unmap(src, pages);
                release_temp_frame_slots(
                    mgr,
                    pid,
                    &new_slots,
                    "split_large_mapping_map_dst_fail_cleanup",
                );
                return Err(e);
            }
        };

        unsafe {
            core::ptr::copy_nonoverlapping(
                (src + idx * PGSIZE) as *const u8,
                dst as *mut u8,
                PGSIZE,
            );
        }
        let _ = mgr.vspace_mgr.unmap(dst, 1);
        new_slots.push(slot);
    }

    let _ = mgr.vspace_mgr.unmap(src, pages);

    mgr.unmap_process_pages(pid, map.vaddr, pages)?;

    let mut mapped_new_pages = 0usize;
    for (idx, slot) in new_slots.iter().enumerate() {
        let vaddr = map.vaddr + idx * PGSIZE;
        if let Err(e) = mgr.map_process_frame(pid, Page::from(*slot), vaddr, map.flags, 1) {
            for back_idx in 0..mapped_new_pages {
                let _ = mgr.unmap_process_pages(pid, map.vaddr + back_idx * PGSIZE, 1);
            }
            let _ = mgr.map_process_frame(pid, old_frame, map.vaddr, map.flags, pages);
            release_temp_frame_slots(mgr, pid, &new_slots, "split_large_mapping_map_new_fail");
            return Err(e);
        }
        mapped_new_pages += 1;
    }

    {
        let task = mgr.get_process(pid).ok_or(Error::NotFound)?;
        let mut mm = task.mm.state.write();
        mm.memory_maps.remove(&map.vaddr);
        for (idx, slot) in new_slots.iter().enumerate() {
            let vaddr = map.vaddr + idx * PGSIZE;
            mm.memory_maps.insert(vaddr, MemoryMap {
                vaddr,
                paddr: 0,
                size: PGSIZE,
                flags: map.flags,
                mem_type: map.mem_type,
                cow: map.cow,
                frame_cap: slot.bits(),
                file_backing_fd: map.file_backing_fd,
                file_backing_offset: map.file_backing_offset.saturating_add(idx * PGSIZE),
            });
        }
    }

    mgr.release_process_frame_slot(pid, old_slot, pages, "split_large_mapping_old_frame");
    Ok(())
}

fn ensure_partial_multi_page_ranges_split<'a>(
    mgr: &mut ApeManager<'a>,
    pid: usize,
    start: usize,
    end: usize,
) -> Result<(), Error> {
    let targets = {
        let task = mgr.get_process(pid).ok_or(Error::NotFound)?;
        split_partial_multi_page_targets(&task, start, end)
    };

    for map_start in targets {
        split_large_mapping_into_base_pages(mgr, pid, map_start)?;
    }

    Ok(())
}

fn range_is_free(task: &TaskStruct, start: usize, end: usize) -> bool {
    let mm = task.mm.state.read();
    if end > mm.mmap_limit || start < mm.mmap_base || start >= end {
        return false;
    }

    if has_overlap(
        start,
        end,
        mm.heap_start,
        mm.heap_brk.saturating_sub(mm.heap_start),
    ) {
        return false;
    }

    let stack_low = mm.stack_bottom.saturating_sub(mm.max_stack_size);
    if has_overlap(start, end, stack_low, mm.max_stack_size) {
        return false;
    }

    for map in mm.memory_maps.values() {
        if has_overlap(start, end, map.vaddr, map.size) {
            return false;
        }
    }

    for map in mm.lazy_memory_maps.values() {
        if has_overlap(start, end, map.vaddr, map.size) {
            return false;
        }
    }

    true
}

fn range_is_free_excluding(
    task: &TaskStruct,
    start: usize,
    end: usize,
    except_start: usize,
    except_end: usize,
) -> bool {
    let mm = task.mm.state.read();
    if end > mm.mmap_limit || start < mm.mmap_base || start >= end {
        return false;
    }

    if has_overlap(
        start,
        end,
        mm.heap_start,
        mm.heap_brk.saturating_sub(mm.heap_start),
    ) {
        return false;
    }

    let stack_low = mm.stack_bottom.saturating_sub(mm.max_stack_size);
    if has_overlap(start, end, stack_low, mm.max_stack_size) {
        return false;
    }

    for map in mm.memory_maps.values() {
        if has_overlap(start, end, map.vaddr, map.size) {
            let map_end = map.vaddr.saturating_add(map.size);
            let in_except = map.vaddr >= except_start && map_end <= except_end;
            if !in_except {
                return false;
            }
        }
    }

    for map in mm.lazy_memory_maps.values() {
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
    task: &TaskStruct,
    old_addr: usize,
    old_len: usize,
) -> Result<Vec<RemapPageState>, Error> {
    let mut out = Vec::new();
    let mm = task.mm.state.read();
    for page in (old_addr..old_addr + old_len).step_by(PGSIZE) {
        if let Some(map) = mm.memory_maps.get(&page) {
            if map.mem_type != MemoryType::Anonymous || map.size != PGSIZE {
                return Err(Error::InvalidArgs);
            }
            out.push(RemapPageState::Mapped { frame_cap: map.frame_cap, flags: map.flags });
            continue;
        }

        if let Some(map) = mm.lazy_memory_maps.get(&page) {
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

fn find_free_remap_target(
    task: &TaskStruct,
    len_aligned: usize,
) -> Option<usize> {
    let mut candidate = {
        let mm = task.mm.state.read();
        mm.mmap_next.max(mm.mmap_base)
    };
    while let Some(end) = candidate.checked_add(len_aligned) {
        let mm = task.mm.state.read();
        if end > mm.mmap_limit {
            break;
        }
        if range_is_free(task, candidate, end) {
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
    let task = mgr.get_process(pid).ok_or(Error::NotFound)?;

    if addr == 0 {
        return Ok(task.mm.state.read().heap_brk);
    }

    if addr < task.mm.state.read().heap_start || addr > task.mm.state.read().heap_limit {
        return Ok(task.mm.state.read().heap_brk);
    }

    task.mm.state.write().heap_brk = addr;
    Ok(task.mm.state.read().heap_brk)
}

fn map_anonymous_range_eager<'a>(
    mgr: &mut ApeManager<'a>,
    pid: usize,
    start: usize,
    end: usize,
    perms: Perms,
) -> Result<(), Error> {
    let mut mapped: Vec<(usize, CapPtr)> = Vec::new();

    for page in (start..end).step_by(PGSIZE) {
        let slot = mgr.cspace_mgr.alloc(&mut *mgr.res_client)?;
        if let Err(e) = mgr.res_client.alloc(Badge::null(), CapType::Page, 1, slot) {
            mgr.cspace_mgr.free(slot);
            for (vaddr, old_slot) in mapped.iter().rev() {
                let _ = mgr.unmap_process_pages(pid, *vaddr, 1);
                if let Some(task) = mgr.get_process(pid) {
                    task.mm.state.write().memory_maps.remove(vaddr);
                }
                mgr.release_process_frame_slot(pid, *old_slot, 1, "mmap_anon_eager_rollback");
            }
            return Err(e);
        }
        mgr.ledger_record_frame_alloc(pid, slot, 1, "mmap_anon_eager");

        if let Err(e) = mgr.map_process_frame(pid, Page::from(slot), page, perms, 1) {
            mgr.release_process_frame_slot(pid, slot, 1, "mmap_anon_eager_map_fail");
            for (vaddr, old_slot) in mapped.iter().rev() {
                let _ = mgr.unmap_process_pages(pid, *vaddr, 1);
                if let Some(task) = mgr.get_process(pid) {
                    task.mm.state.write().memory_maps.remove(vaddr);
                }
                mgr.release_process_frame_slot(pid, *old_slot, 1, "mmap_anon_eager_rollback");
            }
            return Err(e);
        }

        if let Some(task) = mgr.get_process(pid) {
            task.mm.add_memory_map(MemoryMap {
                vaddr: page,
                paddr: 0,
                size: PGSIZE,
                flags: perms,
                mem_type: MemoryType::Anonymous,
                cow: false,
                frame_cap: slot.bits(),
                file_backing_fd: None,
                file_backing_offset: 0,
            });
        }

        mapped.push((page, slot));
    }

    Ok(())
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

    if flags & MAP_PRIVATE == 0 {
        return Err(Error::InvalidArgs);
    }

    let is_anonymous = (flags & MAP_ANONYMOUS) != 0;
    let file_backing = if is_anonymous {
        None
    } else {
        let fd = u32::try_from(_fd).map_err(|_| Error::InvalidSlot)?;
        let task = mgr.get_process(pid).ok_or(Error::NotFound)?;
        let files = task.files.state.read();
        let handle = files.fds.get(&fd).cloned().ok_or(Error::InvalidSlot)?;
        match handle.file_type {
            FileType::Normal(_) => Some((fd, _offset)),
        }
    };

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

        ensure_partial_multi_page_ranges_split(mgr, pid, start, end)?;

        let mut mapped_ranges_to_unmap: BTreeMap<usize, (usize, usize)> = BTreeMap::new();
        {
            let task = mgr.get_process(pid).ok_or(Error::NotFound)?;
            let mut mm_state = task.mm.state.write();

            if end > mm_state.mmap_limit {
                return Err(Error::OutOfMemory);
            }

            if has_overlap(
                start,
                end,
                mm_state.heap_start,
                mm_state.heap_brk.saturating_sub(mm_state.heap_start),
            ) {
                return Err(Error::InvalidArgs);
            }
            let stack_low = mm_state.stack_bottom.saturating_sub(mm_state.max_stack_size);
            if has_overlap(start, end, stack_low, mm_state.max_stack_size) {
                return Err(Error::InvalidArgs);
            }

            for map in mm_state.memory_maps.values() {
                if has_overlap(start, end, map.vaddr, map.size)
                    && !is_remappable_user_mapping(map.mem_type)
                {
                    return Err(Error::InvalidArgs);
                }
            }

            for page in (start..end).step_by(PGSIZE) {
                mm_state.lazy_memory_maps.remove(&page);
                if let Some(map) = mm_state.memory_maps.get(&page)
                    && is_remappable_user_mapping(map.mem_type)
                {
                    let map_pages = align_up(map.size, PGSIZE) / PGSIZE;
                    mapped_ranges_to_unmap.entry(map.vaddr).or_insert((map.frame_cap, map_pages));
                }
            }
            for vaddr in mapped_ranges_to_unmap.keys() {
                mm_state.memory_maps.remove(vaddr);
            }
        }

        if !mapped_ranges_to_unmap.is_empty() {
            for (vaddr, (frame_cap, pages)) in mapped_ranges_to_unmap {
                mgr.unmap_process_pages(pid, vaddr, pages)?;
                if frame_cap != 0 {
                    mgr.release_process_frame_slot(
                        pid,
                        CapPtr::from(frame_cap),
                        pages,
                        "mmap_fixed_replace",
                    );
                }
            }
        }

        if let Some((file_fd, file_offset)) = file_backing {
            let task = mgr.get_process(pid).ok_or(Error::NotFound)?;
            let mut mm = task.mm.state.write();
            for page in (start..end).step_by(PGSIZE) {
                let page_off = page.checked_sub(start).ok_or(Error::InvalidAddress)?;
                let backing_off = file_offset.checked_add(page_off).ok_or(Error::OutOfMemory)?;
                mm.lazy_memory_maps.insert(page, MemoryMap {
                    vaddr: page,
                    paddr: 0,
                    size: PGSIZE,
                    flags: perms,
                    mem_type: MemoryType::FileBacked,
                    cow: false,
                    frame_cap: 0,
                    file_backing_fd: Some(file_fd),
                    file_backing_offset: backing_off,
                });
            }
        } else {
            map_anonymous_range_eager(mgr, pid, start, end, perms)?;
        }

        if let Some(task) = mgr.get_process(pid) {
            let mut mm = task.mm.state.write();
            mm.mmap_next = mm.mmap_next.max(end);
        }
        return Ok(start);
    }

    let mut candidate = {
        let task = mgr.get_process(pid).ok_or(Error::NotFound)?;
        let mm = task.mm.state.read();
        let start = if addr != 0 { align_down(addr, PGSIZE) } else { mm.mmap_next };
        core::cmp::max(start, mm.mmap_base)
    };
    let mut chosen = None;

    while let Some(end) = candidate.checked_add(len_aligned) {
        let task = mgr.get_process(pid).ok_or(Error::NotFound)?;
        let mm = task.mm.state.read();
        if end > mm.mmap_limit {
            break;
        }
        if range_is_free(&task, candidate, end) {
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

    if let Some((file_fd, file_offset)) = file_backing {
        let task = mgr.get_process(pid).ok_or(Error::NotFound)?;
        let mut mm = task.mm.state.write();
        for page in (start..end).step_by(PGSIZE) {
            let page_off = page.checked_sub(start).ok_or(Error::InvalidAddress)?;
            let backing_off = file_offset.checked_add(page_off).ok_or(Error::OutOfMemory)?;
            mm.lazy_memory_maps.insert(page, MemoryMap {
                vaddr: page,
                paddr: 0,
                size: PGSIZE,
                flags: perms,
                mem_type: MemoryType::FileBacked,
                cow: false,
                frame_cap: 0,
                file_backing_fd: Some(file_fd),
                file_backing_offset: backing_off,
            });
        }
    } else {
        map_anonymous_range_eager(mgr, pid, start, end, perms)?;
    }

    let task = mgr.get_process(pid).ok_or(Error::NotFound)?;
    let mut mm = task.mm.state.write();
    mm.mmap_next = mm.mmap_next.max(end);
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
    let end = addr.checked_add(len_aligned).ok_or(Error::OutOfMemory)?;
    ensure_partial_multi_page_ranges_split(mgr, pid, addr, end)?;
    let mut mapped_ranges_to_unmap: BTreeMap<usize, (usize, usize)> = BTreeMap::new();

    {
        let task = mgr.get_process(pid).ok_or(Error::NotFound)?;
        let mut mm = task.mm.state.write();
        for page in (addr..end).step_by(PGSIZE) {
            mm.lazy_memory_maps.remove(&page);

            if let Some(map) = mm.memory_maps.get(&page)
                && is_remappable_user_mapping(map.mem_type)
            {
                let map_pages = align_up(map.size, PGSIZE) / PGSIZE;
                mapped_ranges_to_unmap.entry(map.vaddr).or_insert((map.frame_cap, map_pages));
            }
        }

        for vaddr in mapped_ranges_to_unmap.keys() {
            mm.memory_maps.remove(vaddr);
        }
    }

    if !mapped_ranges_to_unmap.is_empty() {
        for (vaddr, (frame_cap, pages)) in mapped_ranges_to_unmap {
            mgr.unmap_process_pages(pid, vaddr, pages)?;
            if frame_cap != 0 {
                mgr.release_process_frame_slot(pid, CapPtr::from(frame_cap), pages, "munmap");
            }
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

    ensure_partial_multi_page_ranges_split(mgr, pid, start, end)?;

    let mut ranges: BTreeMap<usize, (usize, usize)> = BTreeMap::new();
    {
        let task = mgr.get_process(pid).ok_or(Error::NotFound)?;
        let mm = task.mm.state.read();
        for page in (start..end).step_by(PGSIZE) {
            let map = task.mm.lookup_memory_map(page).ok_or(Error::InvalidAddress)?;
            if page < map.vaddr || page >= map.vaddr.saturating_add(map.size) {
                return Err(Error::InvalidAddress);
            }
            let map_pages = align_up(map.size, PGSIZE) / PGSIZE;
            ranges.entry(map.vaddr).or_insert((map.frame_cap, map_pages));
        }
    }

    for (vaddr, (frame_cap, pages)) in &ranges {
        let _ = mgr.unmap_process_pages(pid, *vaddr, *pages);
        mgr.map_process_frame(
            pid,
            Page::from(CapPtr::from(*frame_cap)),
            *vaddr,
            new_perms,
            *pages,
        )?;
    }

    if let Some(task) = mgr.get_process(pid) {
        let mut mm = task.mm.state.write();
        for vaddr in ranges.keys() {
            if let Some(map) = mm.memory_maps.get_mut(vaddr) {
                map.flags = new_perms;
            }
        }
        for page in (start..end).step_by(PGSIZE) {
            if let Some(map) = mm.lazy_memory_maps.get_mut(&page) {
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
        let task = mgr.get_process(pid).ok_or(Error::NotFound)?;
        collect_remap_states(&task, old_addr, old_len)?
    };
    let base_flags = page_states.first().map(|s| s.flags()).unwrap_or(Perms::READ | Perms::WRITE);

    if (flags & MREMAP_FIXED) == 0 {
        if new_len <= old_len {
            if new_len < old_len {
                do_munmap(mgr, pid, old_addr + new_len, old_len - new_len)?;
            }
            return Ok(old_addr);
        }

        let can_expand_in_place = {
            let task = mgr.get_process(pid).ok_or(Error::NotFound)?;
            range_is_free_excluding(&task, old_addr, new_end_in_place, old_addr, old_end)
        };

        if can_expand_in_place {
            let task = mgr.get_process(pid).ok_or(Error::NotFound)?;
            let mut mm = task.mm.state.write();
            for page in (old_end..new_end_in_place).step_by(PGSIZE) {
                mm.lazy_memory_maps.insert(page, MemoryMap {
                    vaddr: page,
                    paddr: 0,
                    size: PGSIZE,
                    flags: base_flags,
                    mem_type: MemoryType::Anonymous,
                    cow: false,
                    frame_cap: 0,
                    file_backing_fd: None,
                    file_backing_offset: 0,
                });
            }
            mm.mmap_next = mm.mmap_next.max(new_end_in_place);
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
        let task = mgr.get_process(pid).ok_or(Error::NotFound)?;
        find_free_remap_target(&task, new_len).ok_or(Error::OutOfMemory)?
    };
    let target_end = target.checked_add(new_len).ok_or(Error::OutOfMemory)?;

    if target == old_addr {
        if new_len < old_len {
            do_munmap(mgr, pid, old_addr + new_len, old_len - new_len)?;
        } else if new_len > old_len {
            let can_expand_in_place = {
                let task = mgr.get_process(pid).ok_or(Error::NotFound)?;
                range_is_free_excluding(&task, old_addr, target_end, old_addr, old_end)
            };
            if !can_expand_in_place {
                return Err(Error::OutOfMemory);
            }

            let task = mgr.get_process(pid).ok_or(Error::NotFound)?;
            let mut mm = task.mm.state.write();
            for page in (old_end..target_end).step_by(PGSIZE) {
                mm.lazy_memory_maps.insert(page, MemoryMap {
                    vaddr: page,
                    paddr: 0,
                    size: PGSIZE,
                    flags: base_flags,
                    mem_type: MemoryType::Anonymous,
                    cow: false,
                    frame_cap: 0,
                    file_backing_fd: None,
                    file_backing_offset: 0,
                });
            }
            mm.mmap_next = mm.mmap_next.max(target_end);
        }
        return Ok(old_addr);
    }

    if has_overlap(target, target_end, old_addr, old_len) {
        return Err(Error::InvalidArgs);
    }

    {
        let task = mgr.get_process(pid).ok_or(Error::NotFound)?;
        if !range_is_free(&task, target, target_end) {
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
                Page::from(CapPtr::from(frame_cap)),
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
        let task = mgr.get_process(pid).ok_or(Error::NotFound)?;
        let mut mm = task.mm.state.write();
        for page in (old_addr..old_end).step_by(PGSIZE) {
            mm.memory_maps.remove(&page);
            mm.lazy_memory_maps.remove(&page);
        }

        for i in 0..copy_pages {
            let vaddr = target + i * PGSIZE;
            match page_states[i] {
                RemapPageState::Mapped { frame_cap, flags } => {
                    mm.memory_maps.insert(vaddr, MemoryMap {
                        vaddr,
                        paddr: 0,
                        size: PGSIZE,
                        flags,
                        mem_type: MemoryType::Anonymous,
                        cow: false,
                        frame_cap,
                        file_backing_fd: None,
                        file_backing_offset: 0,
                    });
                }
                RemapPageState::Lazy { flags } => {
                    mm.lazy_memory_maps.insert(vaddr, MemoryMap {
                        vaddr,
                        paddr: 0,
                        size: PGSIZE,
                        flags,
                        mem_type: MemoryType::Anonymous,
                        cow: false,
                        frame_cap: 0,
                        file_backing_fd: None,
                        file_backing_offset: 0,
                    });
                }
            }
        }

        for i in copy_pages..new_pages {
            let vaddr = target + i * PGSIZE;
            mm.lazy_memory_maps.insert(vaddr, MemoryMap {
                vaddr,
                paddr: 0,
                size: PGSIZE,
                flags: base_flags,
                mem_type: MemoryType::Anonymous,
                cow: false,
                frame_cap: 0,
                file_backing_fd: None,
                file_backing_offset: 0,
            });
        }

        mm.mmap_next = mm.mmap_next.max(target_end);
    }

    for page in old_mapped_pages {
        let _ = mgr.unmap_process_pages(pid, page, 1);
    }

    Ok(target)
}
