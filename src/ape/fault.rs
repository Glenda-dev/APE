use crate::ApeManager;
use crate::ape::process::{MemoryMap, MemoryType};
#[cfg(feature = "strace")]
use crate::ape::utils::strace;
use crate::arch::constants::{INST_PAGE_FAULT, LOAD_PAGE_FAULT, STORE_PAGE_FAULT};
use crate::syscall::dispatch_syscall;
use alloc::vec::Vec;
use ape::sys::constants::{
    SIGILL_EXIT_CODE, SIGSEGV_EXIT_CODE, SIGTRAP_EXIT_CODE, UNKNOWN_FAULT_EXIT_CODE,
};
use glenda::arch::mem::{PGSIZE, SHIFTS};
use glenda::cap::{CSPACE_CAP, CapPtr, CapType, Frame, PageTable};
use glenda::error::Error;
use glenda::interface::{
    CSpaceService, FaultService, ResourceService, SystemService, VSpaceService,
};
use glenda::ipc::{Badge, MsgArgs, MsgFlags, MsgTag, UTCB};
use glenda::mem::Perms;
use glenda::protocol;
use glenda::utils::align::align_down;

impl<'a> ApeManager<'a> {
    fn pt_path_prefix(vaddr: usize, level: usize) -> usize {
        vaddr >> SHIFTS[level]
    }

    pub(crate) fn release_pagetable_slot(&mut self, slot: CapPtr) {
        let released = match self.res_client.free(Badge::null(), slot) {
            Ok(()) => true,
            Err(e) if e == Error::InvalidCapability || e == Error::InvalidSlot => true,
            Err(e) => {
                warn!(
                    "fault: failed to free pagetable cap {:?} via resource service: {:?}",
                    slot, e
                );
                false
            }
        };

        if released {
            let _ = CSPACE_CAP.delete(slot);
            self.cspace_mgr.free(slot);
        }
    }

    pub(crate) fn release_process_intermediate_page_tables(
        &mut self,
        pid: usize,
    ) -> Result<(), Error> {
        let slots_to_release: Vec<CapPtr> = {
            let process = self.get_process(pid).ok_or(Error::NotFound)?;
            process
                .intermediate_page_tables
                .values()
                .copied()
                .filter(|cap| !cap.is_null())
                .collect()
        };

        if let Some(process) = self.get_process_mut(pid) {
            process.intermediate_page_tables.clear();
        }

        for slot in slots_to_release {
            self.release_pagetable_slot(slot);
        }

        Ok(())
    }

    pub(crate) fn ensure_intermediate_page_tables(
        &mut self,
        pid: usize,
        page_addr: usize,
    ) -> Result<(), Error> {
        let vspace = self.get_process(pid).ok_or(Error::NotFound)?.vspace();

        let mut missing_paths = Vec::new();
        {
            let process = self.get_process(pid).ok_or(Error::NotFound)?;
            for level in (1..SHIFTS.len()).rev() {
                let prefix = Self::pt_path_prefix(page_addr, level);
                if !process.has_intermediate_page_table(level, prefix) {
                    missing_paths.push((level, prefix));
                }
            }
        }

        for (level, prefix) in missing_paths {
            let slot = self.cspace_mgr.alloc(&mut *self.res_client)?;
            if let Err(e) = self.res_client.alloc(Badge::null(), CapType::PageTable, 0, slot) {
                self.cspace_mgr.free(slot);
                return Err(e);
            }

            let pt = PageTable::from(slot);
            match vspace.map_table(pt, page_addr, level) {
                Ok(()) => {
                    if let Some(process) = self.get_process_mut(pid) {
                        process.record_intermediate_page_table(level, prefix, slot);
                    }
                }
                Err(Error::AlreadyExists) => {
                    // 页表已存在（可能由其他路径预先建立），记录路径，避免重复探测。
                    self.release_pagetable_slot(slot);
                    if let Some(process) = self.get_process_mut(pid) {
                        process.record_intermediate_page_table(level, prefix, CapPtr::null());
                    }
                }
                Err(e) => {
                    self.release_pagetable_slot(slot);
                    return Err(e);
                }
            }
        }

        Ok(())
    }

    pub(crate) fn map_process_frame(
        &mut self,
        pid: usize,
        frame: Frame,
        vaddr: usize,
        perms: Perms,
        pages: usize,
    ) -> Result<(), Error> {
        for i in 0..pages {
            self.ensure_intermediate_page_tables(pid, vaddr + i * PGSIZE)?;
        }

        let vspace = self.get_process(pid).ok_or(Error::NotFound)?.vspace();
        vspace.map(frame, vaddr, perms, pages)
    }

    pub(crate) fn unmap_process_pages(
        &mut self,
        pid: usize,
        vaddr: usize,
        pages: usize,
    ) -> Result<(), Error> {
        let vspace = self.get_process(pid).ok_or(Error::NotFound)?.vspace();
        vspace.unmap(vaddr, pages * PGSIZE)
    }

    fn fault_access_allowed(cause: usize, perms: Perms) -> bool {
        match cause {
            INST_PAGE_FAULT => perms.contains(Perms::EXECUTE),
            LOAD_PAGE_FAULT => perms.contains(Perms::READ),
            STORE_PAGE_FAULT => perms.contains(Perms::WRITE),
            _ => true,
        }
    }

    fn map_fault_page(
        &mut self,
        pid: usize,
        page_addr: usize,
        perms: Perms,
        mem_type: MemoryType,
    ) -> Result<(), Error> {
        let frame_slot = self.cspace_mgr.alloc(&mut *self.res_client)?;
        self.res_client.alloc(Badge::null(), CapType::Frame, 1, frame_slot)?;
        let frame = Frame::from(frame_slot);
        self.map_process_frame(pid, frame, page_addr, perms, 1)?;

        let process = self.get_process_mut(pid).ok_or(Error::NotFound)?;
        process.add_memory_map(MemoryMap {
            vaddr: page_addr,
            paddr: 0,
            size: PGSIZE,
            flags: perms,
            mem_type,
            cow: false,
            frame_cap: frame_slot.bits(),
        });
        Ok(())
    }

    fn remap_existing_page(
        &mut self,
        pid: usize,
        page_addr: usize,
        frame_cap: usize,
        perms: Perms,
    ) -> Result<(), Error> {
        let frame = Frame::from(CapPtr::from(frame_cap));

        // 先尝试移除旧映射（若不存在则忽略），随后补齐中间页表并重映射。
        let _ = self.unmap_process_pages(pid, page_addr, 1);
        self.map_process_frame(pid, frame, page_addr, perms, 1)?;

        if let Some(process) = self.get_process_mut(pid)
            && let Some(map) = process.memory_maps.get_mut(&page_addr)
        {
            map.flags = perms;
        }
        Ok(())
    }
}

impl<'a> FaultService for ApeManager<'a> {
    fn page_fault(
        &mut self,
        badge: Badge,
        addr: usize,
        pc: usize,
        cause: usize,
    ) -> Result<(), Error> {
        let pid = badge.bits();
        log!("page_fault: pid={} addr={:#x} pc={:#x} cause={:#x}", pid, addr, pc, cause);
        let page_addr = align_down(addr, PGSIZE);

        let mapped = {
            let process = self.get_process(pid).ok_or(Error::NotFound)?;
            process.lookup_memory_map(addr).cloned()
        };

        if let Some(map) = mapped {
            log!(
                "page_fault: mapped hit pid={} addr={:#x} map_vaddr={:#x} size={:#x} perms={:?} type={:?}",
                pid,
                addr,
                map.vaddr,
                map.size,
                map.flags,
                map.mem_type
            );
            if !Self::fault_access_allowed(cause, map.flags) {
                if map.mem_type == MemoryType::Image {
                    let adjusted = if cause == STORE_PAGE_FAULT
                        && map.flags.contains(Perms::EXECUTE)
                        && !map.flags.contains(Perms::WRITE)
                    {
                        let mut p = map.flags | Perms::WRITE;
                        p.remove(Perms::EXECUTE);
                        Some(p)
                    } else if cause == INST_PAGE_FAULT
                        && map.flags.contains(Perms::WRITE)
                        && !map.flags.contains(Perms::EXECUTE)
                    {
                        let mut p = map.flags | Perms::EXECUTE;
                        p.remove(Perms::WRITE);
                        Some(p)
                    } else {
                        None
                    };

                    if let Some(new_perms) = adjusted {
                        log!(
                            "page_fault: remap image perms pid={} vaddr={:#x} {:?} -> {:?}",
                            pid,
                            map.vaddr,
                            map.flags,
                            new_perms
                        );
                        self.remap_existing_page(pid, map.vaddr, map.frame_cap, new_perms)?;
                        return Ok(());
                    }
                }

                error!(
                    "page_fault: permission denied pid={} addr={:#x} pc={:#x} cause={:#x} perms={:?}",
                    pid, addr, pc, cause, map.flags
                );
                return self.terminate_process(pid, SIGSEGV_EXIT_CODE, true);
            }

            // 元数据存在但仍触发 fault：尝试按记录重装该页映射（例如页表项被替换/丢失）。
            log!(
                "page_fault: remap existing pid={} vaddr={:#x} perms={:?}",
                pid,
                map.vaddr,
                map.flags
            );
            self.remap_existing_page(pid, map.vaddr, map.frame_cap, map.flags)?;
            return Ok(());
        }

        let (stack_bottom, stack_size, max_stack_size, heap_start, heap_brk) = {
            let process = self.get_process(pid).ok_or(Error::NotFound)?;
            (
                process.stack_bottom,
                process.stack_size,
                process.max_stack_size,
                process.heap_start,
                process.heap_brk,
            )
        };

        // 1) 栈增长（向下增长）
        let stack_low_limit = stack_bottom.saturating_sub(max_stack_size);
        let current_stack_low = stack_bottom.saturating_sub(stack_size);
        if addr < stack_bottom && addr >= stack_low_limit && page_addr < current_stack_low {
            log!(
                "page_fault: stack growth pid={} addr={:#x} pc={:#x} cause={:#x}",
                pid,
                addr,
                pc,
                cause
            );
            let perms = Perms::READ | Perms::WRITE;
            if !Self::fault_access_allowed(cause, perms) {
                return self.terminate_process(pid, SIGSEGV_EXIT_CODE, true);
            }

            let pages_to_map = (current_stack_low - page_addr) / PGSIZE;
            for idx in 0..pages_to_map {
                let vaddr = current_stack_low - (idx + 1) * PGSIZE;
                self.map_fault_page(pid, vaddr, perms, MemoryType::Stack)?;
                if let Some(process) = self.get_process_mut(pid) {
                    process.stack_size += PGSIZE;
                }
            }
            return Ok(());
        }

        // 2) brk 管理的堆区懒分配
        if addr >= heap_start && addr < heap_brk {
            log!(
                "page_fault: heap growth pid={} addr={:#x} pc={:#x} cause={:#x}",
                pid,
                addr,
                pc,
                cause
            );
            let perms = Perms::READ | Perms::WRITE;
            if !Self::fault_access_allowed(cause, perms) {
                return self.terminate_process(pid, SIGSEGV_EXIT_CODE, true);
            }
            self.map_fault_page(pid, page_addr, perms, MemoryType::Heap)?;
            return Ok(());
        }

        // 3) mmap 懒分配
        let lazy_map = {
            let process = self.get_process(pid).ok_or(Error::NotFound)?;
            process.lookup_lazy_memory_map(addr).cloned()
        };
        if let Some(map) = lazy_map {
            log!(
                "page_fault: lazy mmap pid={} addr={:#x} pc={:#x} cause={:#x}",
                pid,
                addr,
                pc,
                cause
            );
            if !Self::fault_access_allowed(cause, map.flags) {
                return self.terminate_process(pid, SIGSEGV_EXIT_CODE, true);
            }
            if let Some(process) = self.get_process_mut(pid) {
                process.remove_lazy_memory_map(page_addr);
            }
            self.map_fault_page(pid, page_addr, map.flags, map.mem_type)?;
            return Ok(());
        }

        error!(
            "page_fault: unmanaged region pid={} addr={:#x} pc={:#x} cause={:#x}",
            pid, addr, pc, cause
        );
        self.terminate_process(pid, SIGSEGV_EXIT_CODE, true)
    }

    fn unknown_fault(
        &mut self,
        badge: Badge,
        cause: usize,
        value: usize,
        pc: usize,
    ) -> Result<(), Error> {
        let pid = badge.bits();
        error!("unknown_fault: pid={} cause={:#x} value={:#x} pc={:#x}", pid, cause, value, pc);
        self.terminate_process(pid, UNKNOWN_FAULT_EXIT_CODE, true)
    }
    fn illegal_instruction(&mut self, badge: Badge, inst: usize, pc: usize) -> Result<(), Error> {
        let pid = badge.bits();
        error!("illegal_instruction: pid={} inst={:#x} pc={:#x}", pid, inst, pc);
        self.terminate_process(pid, SIGILL_EXIT_CODE, true)
    }
    fn breakpoint(&mut self, badge: Badge, pc: usize) -> Result<(), Error> {
        let pid = badge.bits();
        warn!("breakpoint: pid={} pc={:#x}", pid, pc);
        self.terminate_process(pid, SIGTRAP_EXIT_CODE, true)
    }
    fn access_fault(&mut self, badge: Badge, addr: usize, pc: usize) -> Result<(), Error> {
        let pid = badge.bits();
        error!("access_fault: pid={} addr={:#x} pc={:#x}", pid, addr, pc);
        self.terminate_process(pid, SIGSEGV_EXIT_CODE, true)
    }
    fn access_misaligned(&mut self, badge: Badge, addr: usize, pc: usize) -> Result<(), Error> {
        let pid = badge.bits();
        error!("access_misaligned: pid={} addr={:#x} pc={:#x}", pid, addr, pc);
        self.terminate_process(pid, SIGSEGV_EXIT_CODE, true)
    }
    fn virt_exit(
        &mut self,
        badge: Badge,
        reason: usize,
        detail0: usize,
        detail1: usize,
        detail2: usize,
    ) -> Result<(), Error> {
        let pid = badge.bits();
        error!(
            "virt_exit: pid={} reason={:#x} detail0={:#x} detail1={:#x} detail2={:#x}",
            pid, reason, detail0, detail1, detail2
        );
        self.terminate_process(pid, UNKNOWN_FAULT_EXIT_CODE, true)
    }
    fn handle_syscall(&mut self, pid: usize, args: MsgArgs) -> Result<(), Error> {
        let sys_num = args[0];
        let sys_args = [args[1], args[2], args[3], args[4], args[5], args[6]];

        #[cfg(feature = "strace")]
        let trace_state = strace::trace_syscall_enter(mgr, pid, sys_num as u32, args);

        let ret = dispatch_syscall(&mut *self, pid, sys_num, sys_args);
        #[cfg(feature = "strace")]
        strace::trace_syscall_exit(mgr, pid, sys_num as u32, args, ret, &trace_state);
        let utcb = unsafe { UTCB::new() };
        // 关键：syscall 回包必须显式清理 capability 传递状态，
        // 否则可能携带之前 IPC（如 openat->nexus OPEN）的 HAS_CAP/CapPtr 残留。
        utcb.clear();
        utcb.set_mr(0, ret as usize);
        Ok(())
    }
}
