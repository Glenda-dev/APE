use crate::ApeManager;
use crate::ape::process::{MemoryMap, MemoryType};
use crate::elf::{ElfFile, PF_W, PF_X, PT_LOAD};
use alloc::vec::Vec;
use core::cmp::min;
use glenda::arch::mem::PGSIZE;
use glenda::cap::{CapPtr, CapType, Frame, TCB, VSpace};
use glenda::error::Error;
use glenda::interface::{
    CSpaceService, FileHandleService, FileSystemService, ProcessService, ResourceService,
    ThreadService, VSpaceService,
};
use glenda::ipc::Badge;
use glenda::log;
use glenda::mem::Perms;
use glenda::protocol::fs::OpenFlags;
use glenda::utils::align::{align_down, align_up};
use glenda::utils::manager::{CSpaceManager, VSpaceManager};
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

pub fn sys_execve<'a>(
    mgr: &mut ApeManager<'a>,
    pid: usize,
    filename_ptr: usize,
    _argv_ptr: usize,
    _envp_ptr: usize,
) -> Result<isize, Error> {
    log!("execve: pid {} executing from ptr {:#x}", pid, filename_ptr);

    let path = ""; // TODO: get from filename_ptr
    let stat = mgr.fs_client.stat_path(Badge::new(pid), path)?;
    let size = stat.size as usize;

    // Check if we need to open
    let _fd = mgr.fs_client.open(Badge::new(pid), path, OpenFlags::O_RDONLY, 0)?;

    let num_pages = align_up(size, PGSIZE) / PGSIZE;
    let dest_cap = mgr.cspace_mgr.alloc(&mut *mgr.res_client)?;
    mgr.res_client.alloc(Badge::null(), CapType::Frame, num_pages, dest_cap)?;
    let frame = Frame::from(dest_cap);

    let scratch_vaddr = mgr.vspace_mgr.map_scratch(
        frame,
        Perms::READ | Perms::WRITE,
        num_pages,
        &mut *mgr.res_client,
        &mut *mgr.cspace_mgr,
    )?;

    let dest_slice =
        unsafe { core::slice::from_raw_parts_mut(scratch_vaddr as *mut u8, num_pages * PGSIZE) };

    let mut offset = 0;
    while offset < size {
        let read_len =
            mgr.fs_client.read(Badge::new(pid), offset, &mut dest_slice[offset..size])?;
        if read_len == 0 {
            break;
        }
        offset += read_len;
    }
    mgr.fs_client.close(Badge::new(pid))?;

    // In a real execve, unmap current user process image, setup new elf, etc.
    let elf = ElfFile::new(&dest_slice[..size]).map_err(|_| Error::InvalidArgs)?;
    let _entry_point = elf.entry_point();

    mgr.vspace_mgr.unmap(scratch_vaddr, num_pages)?;

    Ok(0)
}

pub fn sys_getpid<'a>(mgr: &mut ApeManager<'a>, pid: usize) -> Result<isize, Error> {
    log!("getpid:");
    Ok(pid as isize)
}

pub fn sys_gettid<'a>(mgr: &mut ApeManager<'a>, pid: usize) -> Result<isize, Error> {
    log!("gettid:");
    Ok(pid as isize)
}

pub fn sys_set_tid_address<'a>(
    mgr: &mut ApeManager<'a>,
    pid: usize,
    tidptr: usize,
) -> Result<isize, Error> {
    log!("set_tid_address: pid {} tidptr {:#x}", pid, tidptr);
    let process = mgr.get_process_mut(pid).ok_or(Error::NotFound)?;
    process.clear_child_tid = tidptr;
    Ok(pid as isize)
}

pub fn sys_exit<'a>(mgr: &mut ApeManager<'a>, pid: usize, code: usize) -> Result<isize, Error> {
    log!("exit: pid {} code {}", pid, code as isize);

    let host_pid = mgr
        .host_pid_map
        .iter()
        .find_map(|(host_pid, local_pid)| (*local_pid == pid).then_some(*host_pid));

    if let Some(host_pid) = host_pid {
        let _ = mgr.proc_client.kill(Badge::null(), host_pid);
        mgr.host_pid_map.remove(&host_pid);
    }

    mgr.processes.remove(&pid);
    Ok(0)
}

pub fn sys_exit_group<'a>(
    mgr: &mut ApeManager<'a>,
    pid: usize,
    code: usize,
) -> Result<isize, Error> {
    sys_exit(mgr, pid, code)
}

pub fn sys_brk<'a>(mgr: &mut ApeManager<'a>, pid: usize, addr: usize) -> Result<isize, Error> {
    let process = mgr.get_process_mut(pid).ok_or(Error::NotFound)?;

    if addr == 0 {
        return Ok(process.heap_brk as isize);
    }

    if addr < process.heap_start || addr > process.heap_limit {
        return Ok(process.heap_brk as isize);
    }

    process.heap_brk = addr;
    Ok(process.heap_brk as isize)
}

pub fn sys_mmap<'a>(
    mgr: &mut ApeManager<'a>,
    pid: usize,
    addr: usize,
    len: usize,
    prot: u32,
    flags: u32,
    _fd: usize,
    _offset: usize,
) -> Result<isize, Error> {
    if len == 0 {
        return Err(Error::InvalidArgs);
    }

    if flags & MAP_PRIVATE == 0 || flags & MAP_ANONYMOUS == 0 {
        return Err(Error::InvalidArgs);
    }

    let len_aligned = align_up(len, PGSIZE);
    let perms = prot_to_perms(prot);

    if flags & MAP_FIXED != 0 {
        if addr == 0 || addr % PGSIZE != 0 {
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

            if end > process.mmap_limit || start < process.mmap_base {
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
            let vspace = mgr.get_process(pid).ok_or(Error::NotFound)?.vspace();
            let mut vspace_mgr = VSpaceManager::new(vspace, 0, 0);
            for page in mapped_pages_to_unmap {
                vspace_mgr.unmap(page, 1)?;
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
        return Ok(start as isize);
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
    Ok(start as isize)
}

pub fn sys_munmap<'a>(
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
        let vspace = mgr.get_process(pid).ok_or(Error::NotFound)?.vspace();
        let mut vspace_mgr = VSpaceManager::new(vspace, 0, 0);
        for page in mapped_pages_to_unmap {
            vspace_mgr.unmap(page, 1)?;
        }
    }

    Ok(0)
}

pub fn sys_getppid<'a>(mgr: &mut ApeManager<'a>, pid: usize) -> Result<isize, Error> {
    let process = mgr.get_process(pid).ok_or(Error::NotFound)?;
    Ok(process.parent_pid as isize)
}

pub fn sys_fork<'a>(mgr: &mut ApeManager<'a>, pid: usize) -> Result<isize, Error> {
    log!("fork: process {} is forking", pid);
    // 1. 获取父进程信息
    let name = alloc::format!("fork-{}", pid);

    // 2. 创建新进程
    let child_pid = mgr.proc_client.create(Badge::null(), &name)?;

    // 3. 获取并注册子进程 CNode
    let cnode_slot = mgr.cspace_mgr.alloc(&mut *mgr.res_client)?;
    let cnode = mgr.proc_client.get_cnode(Badge::null(), child_pid, cnode_slot)?;
    mgr.register_process(pid, child_pid, cnode);

    // 4. 实现 CoW Fork 逻辑
    let parent_maps: Vec<MemoryMap> = {
        let parent = mgr.get_process(pid).ok_or(Error::NotFound)?;
        parent.memory_maps.values().cloned().collect()
    };

    for map in parent_maps {
        // 标记为 CoW
        let mut child_map = map.clone();
        child_map.cow = true;

        if let Some(process) = mgr.get_process_mut(child_pid) {
            process.add_memory_map(child_map);
        }
    }

    Ok(child_pid as isize)
}
