use crate::ApeManager;
use crate::ape::process::{MemoryMap, MemoryType};
use crate::ape::user::ExecveUserInput;
use crate::elf::{ElfFile, PF_W, PF_X, PT_LOAD};
use alloc::string::String;
use alloc::vec::Vec;
use ape::cap::APE_SLOT;
use core::cmp::{max, min};
use core::mem::size_of;
use glenda::arch::mem::PGSIZE;
use glenda::cap::{CSPACE_CAP, CapPtr, CapType, Endpoint, Frame};
use glenda::error::Error;
use glenda::interface::{
    CSpaceService, FileHandleService, FileSystemService, ProcessService, ResourceService,
    ThreadService, VSpaceService,
};
use glenda::ipc::Badge;
use glenda::log;
use glenda::mem::{HEAP_VA, Perms, STACK_BASE};
use glenda::mem::{TRAMPOLINE_VA, get_trapframe_va, get_utcb_va};
use glenda::protocol::fs::OpenFlags;
use glenda::utils::align::{align_down, align_up};
use glenda::utils::manager::VSpaceManager;
use linux_raw_sys::general::*;

const DEFAULT_ARG0: &str = "init";
const INITIAL_STACK_ALIGN: usize = 16;

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

impl<'a> ApeManager<'a> {
    fn read_exec_image_from_fs(&mut self, pid: usize, path: &str) -> Result<Vec<u8>, Error> {
        let mut translated_path = self.resolve_path_for_process(pid, path)?;
        let mut stat = self.fs_client.stat_path(Badge::null(), &translated_path)?;
        const S_IFMT: u32 = 0o170000;
        const S_IFLNK: u32 = 0o120000;
        if (stat.mode & S_IFMT) == S_IFLNK {
            if translated_path.ends_with("/sbin/init") {
                let fallback = translated_path.replace("/sbin/init", "/bin/busybox");
                translated_path = fallback;
                stat = self.fs_client.stat_path(Badge::null(), &translated_path)?;
            }
        }
        let size = stat.size as usize;
        if size == 0 {
            error!("read_exec_image_from_fs: exec image has zero size");
            return Err(Error::InvalidArgs);
        }
        let fd = self.fs_client.open(Badge::null(), &translated_path, OpenFlags::O_RDONLY, 0)?;

        let mut elf_data = alloc::vec![0u8; size];
        let mut offset = 0;
        while offset < size {
            let read_len = self.fs_client.read(Badge::null(), offset, &mut elf_data[offset..])?;
            if read_len == 0 {
                error!("read_exec_image_from_fs: unexpected EOF while reading exec image");
                self.fs_client.close(Badge::null())?;
                return Err(Error::IoError);
            }
            offset += read_len;
        }
        self.fs_client.close(Badge::null())?;
        let _ = fd;
        Ok(elf_data)
    }

    fn setup_initial_stack(
        &mut self,
        pid: usize,
        child_vspace_mgr: &mut VSpaceManager,
        argv: &[String],
        envp: &[String],
    ) -> Result<usize, Error> {
        let stack_page_vaddr = STACK_BASE - PGSIZE;
        let perms = Perms::READ | Perms::WRITE;

        let frame_slot = self.cspace_mgr.alloc(&mut *self.res_client)?;
        self.res_client.alloc(Badge::null(), CapType::Frame, 1, frame_slot)?;
        let frame = Frame::from(frame_slot);

        child_vspace_mgr.map_frame(
            frame,
            stack_page_vaddr,
            perms,
            1,
            &mut *self.res_client,
            &mut *self.cspace_mgr,
        )?;

        let scratch_vaddr = self.vspace_mgr.map_scratch(
            frame,
            perms,
            1,
            &mut *self.res_client,
            &mut *self.cspace_mgr,
        )?;

        let stack = unsafe { core::slice::from_raw_parts_mut(scratch_vaddr as *mut u8, PGSIZE) };
        stack.fill(0);

        let mut sp = PGSIZE;

        let effective_argv: Vec<&str> = if argv.is_empty() {
            alloc::vec![DEFAULT_ARG0]
        } else {
            argv.iter().map(|s| s.as_str()).collect()
        };

        let mut argv_ptrs = Vec::with_capacity(effective_argv.len());
        for arg in effective_argv.iter().rev() {
            let bytes = arg.as_bytes();
            let need = bytes.len().checked_add(1).ok_or(Error::OutOfMemory)?;
            if sp < need {
                return Err(Error::OutOfMemory);
            }
            sp -= need;
            stack[sp..sp + bytes.len()].copy_from_slice(bytes);
            stack[sp + bytes.len()] = 0;
            argv_ptrs.push(stack_page_vaddr + sp);
        }
        argv_ptrs.reverse();

        let mut envp_ptrs = Vec::with_capacity(envp.len());
        for env in envp.iter().rev() {
            let bytes = env.as_bytes();
            let need = bytes.len().checked_add(1).ok_or(Error::OutOfMemory)?;
            if sp < need {
                return Err(Error::OutOfMemory);
            }
            sp -= need;
            stack[sp..sp + bytes.len()].copy_from_slice(bytes);
            stack[sp + bytes.len()] = 0;
            envp_ptrs.push(stack_page_vaddr + sp);
        }
        envp_ptrs.reverse();

        // Linux/musl 兼容启动栈：
        // [argc][argv...][NULL][envp...][NULL][AT_NULL][0]
        let mut words = Vec::new();
        words.push(argv_ptrs.len());
        words.extend(argv_ptrs.iter().copied());
        words.push(0);
        words.extend(envp_ptrs.iter().copied());
        words.push(0);
        words.push(0);
        words.push(0);

        let words_size = words.len().checked_mul(size_of::<usize>()).ok_or(Error::OutOfMemory)?;
        if sp < words_size {
            return Err(Error::OutOfMemory);
        }
        sp -= words_size;
        sp &= !(INITIAL_STACK_ALIGN - 1);

        if sp.checked_add(words_size).ok_or(Error::OutOfMemory)? > PGSIZE {
            return Err(Error::OutOfMemory);
        }

        for (idx, word) in words.iter().enumerate() {
            let start = sp + idx * size_of::<usize>();
            let end = start + size_of::<usize>();
            stack[start..end].copy_from_slice(&word.to_ne_bytes());
        }

        self.vspace_mgr.unmap(scratch_vaddr, 1)?;

        if let Some(process) = self.get_process_mut(pid) {
            process.add_memory_map(MemoryMap {
                vaddr: stack_page_vaddr,
                paddr: 0,
                size: PGSIZE,
                flags: perms,
                mem_type: MemoryType::Stack,
                cow: false,
                frame_cap: frame_slot.bits(),
            });
            process.stack_size = PGSIZE;
        }

        Ok(stack_page_vaddr + sp)
    }

    pub(crate) fn execve_path(
        &mut self,
        pid: usize,
        path: &str,
        argv: &[String],
        envp: &[String],
    ) -> Result<(), Error> {
        let elf_data = self.read_exec_image_from_fs(pid, path)?;
        let elf = ElfFile::new(&elf_data)
            .map_err(|e| error!("Failed to parse ELF file: {}", e))
            .map_err(|_| Error::InvalidArgs)?;
        let entry_point = elf.entry_point();

        let old_maps: Vec<(usize, usize)> = {
            let process = self.get_process(pid).ok_or(Error::NotFound)?;
            process
                .memory_maps
                .values()
                .map(|map| (map.vaddr, align_up(map.size, PGSIZE) / PGSIZE))
                .collect()
        };

        let vspace_cap = self.get_process(pid).ok_or(Error::NotFound)?.vspace();
        let mut child_vspace_mgr = VSpaceManager::new(vspace_cap, 0, 0);
        for (vaddr, pages) in old_maps {
            if pages != 0 {
                let _ = child_vspace_mgr.unmap(vaddr, pages);
            }
        }

        if let Some(process) = self.get_process_mut(pid) {
            process.memory_maps.clear();
            process.lazy_memory_maps.clear();
            process.stack_size = 0;
        }

        child_vspace_mgr.mark_existing(TRAMPOLINE_VA, PGSIZE);
        child_vspace_mgr.mark_existing(get_utcb_va(0), PGSIZE);
        child_vspace_mgr.mark_existing(get_trapframe_va(0), PGSIZE);

        let mut max_vaddr = 0usize;
        for phdr in elf.program_headers() {
            if phdr.p_type != PT_LOAD {
                continue;
            }

            let vaddr = phdr.p_vaddr as usize;
            let mem_size = phdr.p_memsz as usize;
            let file_size = phdr.p_filesz as usize;
            let offset = phdr.p_offset as usize;

            if mem_size == 0 {
                continue;
            }
            if vaddr + mem_size > max_vaddr {
                max_vaddr = vaddr + mem_size;
            }

            let mut perms = Perms::READ;
            if phdr.p_flags & PF_W != 0 {
                perms |= Perms::WRITE;
            }
            if phdr.p_flags & PF_X != 0 {
                perms |= Perms::EXECUTE;
            }
            log!(
                "Mapping segment: vaddr={:#x} mem_size={:#x} file_size={:#x} offset={:#x} perms={:?}",
                vaddr,
                mem_size,
                file_size,
                offset,
                perms
            );
            let start_page = align_down(vaddr, PGSIZE);
            let end_page = align_up(vaddr + mem_size, PGSIZE);
            let num_pages = (end_page - start_page) / PGSIZE;

            let dest_cap = self.cspace_mgr.alloc(&mut *self.res_client)?;
            self.res_client.alloc(Badge::null(), CapType::Frame, num_pages, dest_cap)?;
            let frame = Frame::from(dest_cap);

            child_vspace_mgr.map_frame(
                frame,
                start_page,
                perms,
                num_pages,
                &mut *self.res_client,
                &mut *self.cspace_mgr,
            )?;

            if let Some(process) = self.get_process_mut(pid) {
                process.add_memory_map(MemoryMap {
                    vaddr: start_page,
                    paddr: 0,
                    size: num_pages * PGSIZE,
                    flags: perms,
                    mem_type: MemoryType::Image,
                    cow: false,
                    frame_cap: dest_cap.bits(),
                });
            }

            let scratch_vaddr = self.vspace_mgr.map_scratch(
                frame,
                Perms::READ | Perms::WRITE,
                num_pages,
                &mut *self.res_client,
                &mut *self.cspace_mgr,
            )?;

            let dest_slice = unsafe {
                core::slice::from_raw_parts_mut(scratch_vaddr as *mut u8, num_pages * PGSIZE)
            };
            dest_slice.fill(0);

            let padding = vaddr - start_page;
            if padding < dest_slice.len() && offset < elf_data.len() {
                let max_file_copy = min(file_size, elf_data.len() - offset);
                let actual_copy = min(max_file_copy, dest_slice.len() - padding);
                dest_slice[padding..padding + actual_copy]
                    .copy_from_slice(&elf_data[offset..offset + actual_copy]);
            }

            self.vspace_mgr.unmap(scratch_vaddr, num_pages)?;
        }

        if let Some(process) = self.get_process_mut(pid) {
            let heap_start = align_up(max(max_vaddr, HEAP_VA), PGSIZE);
            process.heap_start = heap_start;
            process.heap_brk = heap_start;
            process.heap_limit = process.mmap_base;
            process.mmap_next = process.mmap_base;
            process.stack_bottom = STACK_BASE;
            process.stack_size = 0;
        }

        let initial_sp = self.setup_initial_stack(pid, &mut child_vspace_mgr, argv, envp)?;
        let (tcb_cap, fault_ep) = {
            let process = self.get_process(pid).ok_or(Error::NotFound)?;
            let fault_ep = Endpoint::from(CapPtr::concat(process.cspace().cap(), APE_SLOT));
            (process.tcb(), fault_ep)
        };

        tcb_cap.set_entrypoint(entry_point, initial_sp, 0)?;
        tcb_cap.set_fault_handler(fault_ep, false)?;
        Ok(())
    }
}

pub fn sys_execve<'a>(
    mgr: &mut ApeManager<'a>,
    pid: usize,
    filename_ptr: usize,
    argv_ptr: usize,
    envp_ptr: usize,
) -> Result<isize, Error> {
    let exec_input: ExecveUserInput =
        mgr.parse_execve_user_input(pid, filename_ptr, argv_ptr, envp_ptr)?;
    let translated_filename = mgr.resolve_path_for_process(pid, &exec_input.filename)?;

    log!(
        "execve: pid {} filename={} translated={} argc={} envc={}",
        pid,
        exec_input.filename,
        translated_filename,
        exec_input.argv.len(),
        exec_input.envp.len()
    );

    // 保持行为与 Linux 接近：允许 filename 与 argv[0] 不同。
    mgr.execve_path(pid, &translated_filename, &exec_input.argv, &exec_input.envp)?;

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

    // 当前请求来自将要退出的目标线程（CALL 语义）。
    // 先清空 Ape 的 reply 槽位，避免这枚 Reply Cap 在 Warren 回收目标 TCB 前
    // 继续持有对目标线程的额外引用。
    if let Err(e) = CSPACE_CAP.delete(mgr.ipc.reply.cap())
        && e != Error::InvalidCapability
        && e != Error::InvalidSlot
    {
        warn!("exit: failed to clear ape reply slot {:?}: {:?}", mgr.ipc.reply.cap(), e);
    }

    // 提前释放 Ape 持有的子进程 CNode 能力，避免 Warren 回收子进程 CNode 时
    // 因外部引用残留而 ref_count > 1。
    if let Some(slot) = mgr.get_process(pid).map(|p| p.cnode_cap.cap()) {
        let _ = CSPACE_CAP.revoke(slot);
        if let Err(e) = CSPACE_CAP.delete(slot)
            && e != Error::InvalidCapability
            && e != Error::InvalidSlot
        {
            warn!("exit: failed to delete child cnode slot {:?}: {:?}", slot, e);
        } else {
            mgr.cspace_mgr.free(slot);
        }
    }

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
