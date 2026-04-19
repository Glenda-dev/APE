use crate::ApeManager;
use crate::ape::fault_policy::{FaultAction, classify_fault};
use crate::ape::process::{FileType, MemoryMap, MemoryType};
use crate::ape::utils::linux_conv::get_exit_code_for_signal;
#[cfg(feature = "strace")]
use crate::ape::utils::strace;
use crate::arch::constants::{INST_PAGE_FAULT, LOAD_PAGE_FAULT, STORE_PAGE_FAULT};
use crate::arch::parse_syscall_args;
use crate::syscall::dispatch_syscall;
use crate::system::signal::{PendingSignalAction, consume_deliverable_signal_on_syscall_return};
use alloc::vec::Vec;
use glenda::arch::mem::{PGSIZE, SHIFTS};
use glenda::cap::{CSPACE_CAP, CapPtr, CapType, Page, PageTable};
use glenda::error::Error;
use glenda::interface::{
    CSpaceService, FaultService, FileHandleService, ResourceService, SystemService, VSpaceService,
};
use glenda::ipc::{Badge, MsgArgs, MsgFlags, MsgTag, UTCB};
use glenda::mem::Perms;
use glenda::protocol;
use glenda::utils::align::{align_down, align_up};
use linux_raw_sys::errno::EINTR;
use linux_raw_sys::general::{SIGBUS, SIGILL, SIGSEGV, SIGTRAP};

const L1_HUGE_PAGES: usize = 1 << (SHIFTS[1] - SHIFTS[0]);
const L1_HUGE_SIZE: usize = L1_HUGE_PAGES * PGSIZE;

impl<'a> ApeManager<'a> {
    fn cow_fault_perms(perms: Perms) -> Perms {
        let mut p = perms;
        p.remove(Perms::WRITE);
        p
    }

    fn pt_path_prefix(vaddr: usize, level: usize) -> usize {
        vaddr >> SHIFTS[level]
    }

    pub(crate) fn release_pagetable_slot(&mut self, pid: usize, slot: CapPtr) {
        let released = match self.res_client.free(Badge::null(), slot) {
            Ok(()) => true,
            Err(e)
                if e == Error::InvalidCapability
                    || e == Error::InvalidSlot
                    || e == Error::NotSupported =>
            {
                true
            }
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
            self.ledger_record_pagetable_free(pid, slot, "release_intermediate_pagetable");
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
            self.release_pagetable_slot(pid, slot);
        }

        Ok(())
    }

    pub(crate) fn ensure_intermediate_page_tables(
        &mut self,
        pid: usize,
        page_addr: usize,
    ) -> Result<(), Error> {
        self.ensure_intermediate_page_tables_with_leaf(pid, page_addr, 1)
    }

    fn ensure_intermediate_page_tables_with_leaf(
        &mut self,
        pid: usize,
        page_addr: usize,
        leaf_level: usize,
    ) -> Result<(), Error> {
        let vspace = self.get_process(pid).ok_or(Error::NotFound)?.vspace();

        let mut missing_paths = Vec::new();
        {
            let process = self.get_process(pid).ok_or(Error::NotFound)?;
            for level in (leaf_level..SHIFTS.len()).rev() {
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
            self.ledger_record_pagetable_alloc(pid, slot, "ensure_intermediate_pagetables");

            let pt = PageTable::from(slot);
            match vspace.map_table(pt, page_addr, level) {
                Ok(()) => {
                    if let Some(process) = self.get_process_mut(pid) {
                        process.record_intermediate_page_table(level, prefix, slot);
                    }
                }
                Err(Error::AlreadyExists) => {
                    // 页表已存在（可能由其他路径预先建立），记录路径，避免重复探测。
                    self.release_pagetable_slot(pid, slot);
                    if let Some(process) = self.get_process_mut(pid) {
                        process.record_intermediate_page_table(level, prefix, CapPtr::null());
                    }
                }
                Err(e) => {
                    self.release_pagetable_slot(pid, slot);
                    return Err(e);
                }
            }
        }

        Ok(())
    }

    pub(crate) fn map_process_frame(
        &mut self,
        pid: usize,
        frame: Page,
        vaddr: usize,
        perms: Perms,
        pages: usize,
    ) -> Result<(), Error> {
        let mut i = 0;
        while i < pages {
            let curr_vaddr = vaddr + i * PGSIZE;
            let remain = pages - i;
            if curr_vaddr % L1_HUGE_SIZE == 0 && remain >= L1_HUGE_PAGES {
                self.ensure_intermediate_page_tables_with_leaf(pid, curr_vaddr, 2)?;
                i += L1_HUGE_PAGES;
            } else {
                self.ensure_intermediate_page_tables_with_leaf(pid, curr_vaddr, 1)?;
                i += 1;
            }
        }

        let vspace = self.get_process(pid).ok_or(Error::NotFound)?.vspace();
        match vspace.map(frame, vaddr, perms, pages) {
            Ok(()) => Ok(()),
            Err(Error::MappingFailed) => {
                // 大页尝试失败（常见于物理地址未对齐）时，回退到全 4K 路径。
                let _ = vspace.unmap(vaddr, pages * PGSIZE);
                for j in 0..pages {
                    self.ensure_intermediate_page_tables_with_leaf(pid, vaddr + j * PGSIZE, 1)?;
                }
                vspace.map(frame, vaddr, perms, pages)
            }
            Err(e) => Err(e),
        }
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
        self.res_client.alloc(Badge::null(), CapType::Page, 1, frame_slot)?;
        self.ledger_record_frame_alloc(pid, frame_slot, 1, "map_fault_page");
        let frame = Page::from(frame_slot);
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
            file_backing_fd: None,
            file_backing_offset: 0,
        });
        Ok(())
    }

    fn map_file_backed_fault_page(
        &mut self,
        pid: usize,
        page_addr: usize,
        map: &MemoryMap,
        request_pages: usize,
    ) -> Result<usize, Error> {
        let fd = map.file_backing_fd.ok_or(Error::InvalidArgs)?;
        let file_offset = map.file_backing_offset;

        let mut span_pages = core::cmp::max(request_pages, 1);
        {
            let process = self.get_process(pid).ok_or(Error::NotFound)?;
            for idx in 1..span_pages {
                let va = page_addr.saturating_add(idx * PGSIZE);
                let Some(candidate) = process.lazy_memory_maps.get(&va) else {
                    span_pages = idx;
                    break;
                };
                if candidate.mem_type != MemoryType::FileBacked
                    || candidate.file_backing_fd != map.file_backing_fd
                    || candidate.flags.bits() != map.flags.bits()
                    || candidate.file_backing_offset
                        != map.file_backing_offset.saturating_add(idx * PGSIZE)
                {
                    span_pages = idx;
                    break;
                }
            }
        }
        span_pages = core::cmp::max(span_pages, 1);

        let try_zero_copy = {
            let mut fs_client = {
                let process = self.get_process(pid).ok_or(Error::NotFound)?;
                let handle = process.fds.get(&fd).ok_or(Error::InvalidSlot)?;
                match handle.file_type {
                    FileType::Normal(normal) => normal.fs_client,
                    _ => return Err(Error::InvalidType),
                }
            };

            let recv_slot = self.cspace_mgr.alloc(&mut *self.res_client)?;
            let map_res = fs_client.map_pages(Badge::null(), file_offset, span_pages, recv_slot);
            match map_res {
                Ok(read_len) if read_len > 0 => {
                    let frame = Page::from(recv_slot);
                    if let Err(e) =
                        self.map_process_frame(pid, frame, page_addr, map.flags, span_pages)
                    {
                        self.release_process_frame_slot(
                            pid,
                            recv_slot,
                            span_pages,
                            "map_file_backed_fault_page_map_page_cap_fail",
                        );
                        return Err(e);
                    }

                    let map_size = span_pages * PGSIZE;
                    let process = self.get_process_mut(pid).ok_or(Error::NotFound)?;
                    for idx in 0..span_pages {
                        process.remove_lazy_memory_map(page_addr + idx * PGSIZE);
                    }
                    process.add_memory_map(MemoryMap {
                        vaddr: page_addr,
                        paddr: 0,
                        size: map_size,
                        flags: map.flags,
                        mem_type: MemoryType::FileBacked,
                        cow: false,
                        frame_cap: recv_slot.bits(),
                        file_backing_fd: map.file_backing_fd,
                        file_backing_offset: map.file_backing_offset,
                    });
                    return Ok(span_pages);
                }
                Ok(_) => {
                    self.release_process_frame_slot(
                        pid,
                        recv_slot,
                        span_pages,
                        "map_file_backed_fault_page_zero_len",
                    );
                    Err(Error::IoError)
                }
                Err(Error::NotSupported) => {
                    self.cspace_mgr.free(recv_slot);
                    Ok(())
                }
                Err(e) => {
                    self.cspace_mgr.free(recv_slot);
                    Err(e)
                }
            }
        };

        if let Err(e) = try_zero_copy {
            return Err(e);
        }

        let mut fs_client = {
            let process = self.get_process(pid).ok_or(Error::NotFound)?;
            let handle = process.fds.get(&fd).ok_or(Error::InvalidSlot)?;
            match handle.file_type {
                FileType::Normal(normal) => normal.fs_client,
                _ => return Err(Error::InvalidType),
            }
        };

        let frame_slot = self.cspace_mgr.alloc(&mut *self.res_client)?;
        if let Err(e) = self.res_client.alloc(Badge::null(), CapType::Page, 1, frame_slot) {
            self.cspace_mgr.free(frame_slot);
            return Err(e);
        }
        self.ledger_record_frame_alloc(pid, frame_slot, 1, "map_file_backed_fault_page");
        let frame = Page::from(frame_slot);

        if let Err(e) = self.map_process_frame(pid, frame, page_addr, map.flags, 1) {
            self.release_process_frame_slot(
                pid,
                frame_slot,
                1,
                "map_file_backed_fault_page_map_fail",
            );
            return Err(e);
        }

        let scratch = match self.vspace_mgr.map_scratch(
            frame,
            Perms::READ | Perms::WRITE,
            1,
            &mut *self.res_client,
            &mut *self.cspace_mgr,
        ) {
            Ok(v) => v,
            Err(e) => {
                let _ = self.unmap_process_pages(pid, page_addr, 1);
                self.release_process_frame_slot(
                    pid,
                    frame_slot,
                    1,
                    "map_file_backed_fault_page_scratch_fail",
                );
                return Err(e);
            }
        };

        let read_res = {
            let dst = unsafe { core::slice::from_raw_parts_mut(scratch as *mut u8, PGSIZE) };
            dst.fill(0);
            fs_client.read(Badge::null(), file_offset, dst)
        };

        let _ = self.vspace_mgr.unmap(scratch, 1);

        if let Err(e) = read_res {
            let _ = self.unmap_process_pages(pid, page_addr, 1);
            self.release_process_frame_slot(
                pid,
                frame_slot,
                1,
                "map_file_backed_fault_page_read_fail",
            );
            return Err(e);
        }

        let process = self.get_process_mut(pid).ok_or(Error::NotFound)?;
        process.remove_lazy_memory_map(page_addr);
        process.add_memory_map(MemoryMap {
            vaddr: page_addr,
            paddr: 0,
            size: PGSIZE,
            flags: map.flags,
            mem_type: MemoryType::FileBacked,
            cow: false,
            frame_cap: frame_slot.bits(),
            file_backing_fd: map.file_backing_fd,
            file_backing_offset: map.file_backing_offset,
        });
        Ok(1)
    }

    fn remap_existing_page(
        &mut self,
        pid: usize,
        page_addr: usize,
        frame_cap: usize,
        perms: Perms,
        pages: usize,
    ) -> Result<(), Error> {
        let frame = Page::from(CapPtr::from(frame_cap));

        // 先尝试移除旧映射（若不存在则忽略），随后补齐中间页表并重映射。
        let _ = self.unmap_process_pages(pid, page_addr, pages);
        self.map_process_frame(pid, frame, page_addr, perms, pages)?;

        if let Some(process) = self.get_process_mut(pid)
            && let Some(map) = process.memory_maps.get_mut(&page_addr)
        {
            map.flags = perms;
        }
        Ok(())
    }

    fn resolve_cow_fault(
        &mut self,
        pid: usize,
        page_addr: usize,
        old_frame_cap: usize,
        perms: Perms,
    ) -> Result<(), Error> {
        if !perms.contains(Perms::WRITE) {
            return Err(Error::PermissionDenied);
        }

        let new_frame_slot = self.cspace_mgr.alloc(&mut *self.res_client)?;
        self.res_client.alloc(Badge::null(), CapType::Page, 1, new_frame_slot)?;
        self.ledger_record_frame_alloc(pid, new_frame_slot, 1, "resolve_cow_fault_new_frame");

        let old_frame = Page::from(CapPtr::from(old_frame_cap));
        let new_frame = Page::from(new_frame_slot);

        let src = self.vspace_mgr.map_scratch(
            old_frame,
            Perms::READ,
            1,
            &mut *self.res_client,
            &mut *self.cspace_mgr,
        )?;

        let dst = match self.vspace_mgr.map_scratch(
            new_frame,
            Perms::READ | Perms::WRITE,
            1,
            &mut *self.res_client,
            &mut *self.cspace_mgr,
        ) {
            Ok(v) => v,
            Err(e) => {
                let _ = self.vspace_mgr.unmap(src, 1);
                return Err(e);
            }
        };

        unsafe {
            core::ptr::copy_nonoverlapping(src as *const u8, dst as *mut u8, PGSIZE);
        }

        let _ = self.vspace_mgr.unmap(src, 1);
        let _ = self.vspace_mgr.unmap(dst, 1);

        let _ = self.unmap_process_pages(pid, page_addr, 1);
        self.map_process_frame(pid, new_frame, page_addr, perms, 1)?;

        if let Some(process) = self.get_process_mut(pid)
            && let Some(map) = process.memory_maps.get_mut(&page_addr)
        {
            map.frame_cap = new_frame_slot.bits();
            map.cow = false;
            map.flags = perms;
        }

        self.release_process_frame_slot(
            pid,
            CapPtr::from(old_frame_cap),
            1,
            "resolve_cow_fault_old_frame",
        );

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
        let page_addr = align_down(addr, PGSIZE);

        let mapped = {
            let process = self.get_process(pid).ok_or(Error::NotFound)?;
            process.lookup_memory_map(addr).cloned()
        };

        if let Some(map) = mapped {
            if cause == STORE_PAGE_FAULT && map.cow {
                if !map.flags.contains(Perms::WRITE) {
                    return self.terminate_process(pid, get_exit_code_for_signal(SIGSEGV), true);
                }

                self.resolve_cow_fault(pid, map.vaddr, map.frame_cap, map.flags)?;
                return Ok(());
            }

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
                        self.remap_existing_page(
                            pid,
                            map.vaddr,
                            map.frame_cap,
                            new_perms,
                            align_up(map.size, PGSIZE) / PGSIZE,
                        )?;
                        return Ok(());
                    }
                }

                error!(
                    "page_fault: permission denied pid={} addr={:#x} pc={:#x} cause={:#x} perms={:?}",
                    pid, addr, pc, cause, map.flags
                );
                return self.terminate_process(pid, get_exit_code_for_signal(SIGSEGV), true);
            }

            // 元数据存在但仍触发 fault：尝试按记录重装该页映射（例如页表项被替换/丢失）。
            warn!(
                "page_fault: remap existing pid={} vaddr={:#x} perms={:?}",
                pid, map.vaddr, map.flags
            );
            let remap_perms = if map.cow { Self::cow_fault_perms(map.flags) } else { map.flags };
            self.remap_existing_page(
                pid,
                map.vaddr,
                map.frame_cap,
                remap_perms,
                align_up(map.size, PGSIZE) / PGSIZE,
            )?;
            if map.cow
                && let Some(process) = self.get_process_mut(pid)
                && let Some(meta) = process.memory_maps.get_mut(&map.vaddr)
            {
                meta.flags = map.flags;
            }
            return Ok(());
        }

        let fault_action = {
            let process = self.get_process(pid).ok_or(Error::NotFound)?;
            classify_fault(process, addr, page_addr)
        };

        match fault_action {
            FaultAction::StackGrowth { current_stack_low, pages_to_map } => {
                let perms = Perms::READ | Perms::WRITE;
                if !Self::fault_access_allowed(cause, perms) {
                    return self.terminate_process(pid, get_exit_code_for_signal(SIGSEGV), true);
                }

                for idx in 0..pages_to_map {
                    let vaddr = current_stack_low - (idx + 1) * PGSIZE;
                    self.map_fault_page(pid, vaddr, perms, MemoryType::Stack)?;
                    if let Some(process) = self.get_process_mut(pid) {
                        process.stack_size += PGSIZE;
                    }
                }
                return Ok(());
            }
            FaultAction::HeapLazy => {
                let perms = Perms::READ | Perms::WRITE;
                if !Self::fault_access_allowed(cause, perms) {
                    return self.terminate_process(pid, get_exit_code_for_signal(SIGSEGV), true);
                }
                self.map_fault_page(pid, page_addr, perms, MemoryType::Heap)?;
                return Ok(());
            }
            FaultAction::LazyMmap(map) => {
                if !Self::fault_access_allowed(cause, map.flags) {
                    return self.terminate_process(pid, get_exit_code_for_signal(SIGSEGV), true);
                }
                if map.mem_type == MemoryType::FileBacked {
                    let request_pages = if page_addr % L1_HUGE_SIZE == 0
                        && map.file_backing_offset % L1_HUGE_SIZE == 0
                    {
                        L1_HUGE_PAGES
                    } else {
                        4
                    };
                    if let Err(e) =
                        self.map_file_backed_fault_page(pid, page_addr, &map, request_pages)
                    {
                        error!(
                            "page_fault: file-backed lazy map failed pid={} page={:#x} off={:#x} err={:?}",
                            pid, page_addr, map.file_backing_offset, e
                        );
                        return self.terminate_process(pid, get_exit_code_for_signal(SIGBUS), true);
                    }
                } else {
                    if let Some(process) = self.get_process_mut(pid) {
                        process.remove_lazy_memory_map(page_addr);
                    }
                    self.map_fault_page(pid, page_addr, map.flags, map.mem_type)?;
                }
                return Ok(());
            }
            FaultAction::Unmanaged => {}
        }

        error!(
            "page_fault: unmanaged region pid={} addr={:#x} pc={:#x} cause={:#x}",
            pid, addr, pc, cause
        );
        self.terminate_process(pid, get_exit_code_for_signal(SIGSEGV), true)
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
        self.terminate_process(pid, usize::MAX, true)
    }
    fn illegal_instruction(&mut self, badge: Badge, inst: usize, pc: usize) -> Result<(), Error> {
        let pid = badge.bits();
        error!("illegal_instruction: pid={} inst={:#x} pc={:#x}", pid, inst, pc);
        self.terminate_process(pid, get_exit_code_for_signal(SIGILL), true)
    }
    fn breakpoint(&mut self, badge: Badge, pc: usize) -> Result<(), Error> {
        let pid = badge.bits();
        warn!("breakpoint: pid={} pc={:#x}", pid, pc);
        self.terminate_process(pid, get_exit_code_for_signal(SIGTRAP), true)
    }
    fn access_fault(&mut self, badge: Badge, addr: usize, pc: usize) -> Result<(), Error> {
        let pid = badge.bits();
        error!("access_fault: pid={} addr={:#x} pc={:#x}", pid, addr, pc);
        self.terminate_process(pid, get_exit_code_for_signal(SIGSEGV), true)
    }
    fn access_misaligned(&mut self, badge: Badge, addr: usize, pc: usize) -> Result<(), Error> {
        let pid = badge.bits();
        error!("access_misaligned: pid={} addr={:#x} pc={:#x}", pid, addr, pc);
        self.terminate_process(pid, get_exit_code_for_signal(SIGSEGV), true)
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
        self.terminate_process(pid, usize::MAX, true)
    }
    fn handle_syscall(&mut self, pid: usize, args: MsgArgs) -> Result<(), Error> {
        let (sys_num, sys_args) = parse_syscall_args(args);
        #[cfg(feature = "strace")]
        let trace_state = strace::trace_syscall_enter(&mut *self, pid, sys_num as u32, sys_args);

        let mut ret = dispatch_syscall(&mut *self, pid, sys_num, sys_args);

        match consume_deliverable_signal_on_syscall_return(self, pid) {
            Ok(PendingSignalAction::None) => {}
            Ok(PendingSignalAction::Interrupt) => {
                if ret >= 0 {
                    ret = -(EINTR as isize);
                }
            }
            Ok(PendingSignalAction::Terminate(exit_code)) => {
                // syscall 上下文终止进程时，保留 reply slot 避免破坏本次回包路径。
                let _ = self.terminate_process_preserve_reply(pid, exit_code, true);
            }
            Err(e) if e == Error::NotFound => {}
            Err(e) => {
                warn!(
                    "signal-delivery-on-syscall-return failed: pid={}, sys_num={}, err={:?}",
                    pid, sys_num, e
                );
            }
        }

        #[cfg(feature = "strace")]
        strace::trace_syscall_exit(&mut *self, pid, sys_num as u32, sys_args, ret, &trace_state);
        let utcb = unsafe { UTCB::new() };
        // 关键：syscall 回包必须显式清理 capability 传递状态，
        // 否则可能携带之前 IPC（如 openat->nexus OPEN）的 HAS_CAP/CapPtr 残留。
        utcb.clear();
        utcb.set_mr(0, ret as usize);
        Ok(())
    }
}
