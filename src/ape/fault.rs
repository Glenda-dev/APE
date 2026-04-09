use super::handler::handler;
use crate::ApeManager;
use crate::ape::process::{MemoryMap, MemoryType};
use crate::arch::constants::{INST_PAGE_FAULT, LOAD_PAGE_FAULT, STORE_PAGE_FAULT};
use ape::sys::constants::{
    SIGILL_EXIT_CODE, SIGSEGV_EXIT_CODE, SIGTRAP_EXIT_CODE, UNKNOWN_FAULT_EXIT_CODE,
};
use glenda::arch::mem::PGSIZE;
use glenda::cap::{CapType, Frame};
use glenda::error::Error;
use glenda::interface::{
    CSpaceService, FaultService, ProcessService, ResourceService, VSpaceService,
};
use glenda::ipc::{Badge, MsgArgs, UTCB};
use glenda::mem::Perms;
use glenda::utils::align::align_down;
use glenda::utils::manager::VSpaceManager;

impl<'a> ApeManager<'a> {
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

        let vspace = self.get_process(pid).ok_or(Error::NotFound)?.vspace();
        let mut vspace_mgr = VSpaceManager::new(vspace, 0, 0);
        vspace_mgr.map_frame(
            frame,
            page_addr,
            perms,
            1,
            &mut *self.res_client,
            &mut *self.cspace_mgr,
        )?;

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

    fn terminate_faulting_process(&mut self, pid: usize, code: usize) -> Result<(), Error> {
        let host_pid = self
            .host_pid_map
            .iter()
            .find_map(|(host_pid, local_pid)| (*local_pid == pid).then_some(*host_pid));

        if let Some(host_pid) = host_pid {
            let _ = self.proc_client.kill(Badge::null(), host_pid);
            self.host_pid_map.remove(&host_pid);
        }
        self.processes.remove(&pid);

        log!("fault: killed process pid={} with code={}", pid, code);
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
            if !Self::fault_access_allowed(cause, map.flags) {
                error!(
                    "page_fault: permission denied pid={} addr={:#x} pc={:#x} cause={:#x} perms={:?}",
                    pid, addr, pc, cause, map.flags
                );
                return self.terminate_faulting_process(pid, SIGSEGV_EXIT_CODE);
            }

            // 已有映射却仍触发 page fault，通常说明非法访问/COW 未实现等情况。
            error!(
                "page_fault: mapped page fault pid={} addr={:#x} pc={:#x} cause={:#x}",
                pid, addr, pc, cause
            );
            return self.terminate_faulting_process(pid, SIGSEGV_EXIT_CODE);
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
                return self.terminate_faulting_process(pid, SIGSEGV_EXIT_CODE);
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
                return self.terminate_faulting_process(pid, SIGSEGV_EXIT_CODE);
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
                return self.terminate_faulting_process(pid, SIGSEGV_EXIT_CODE);
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
        self.terminate_faulting_process(pid, SIGSEGV_EXIT_CODE)
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
        self.terminate_faulting_process(pid, UNKNOWN_FAULT_EXIT_CODE)
    }
    fn illegal_instruction(&mut self, badge: Badge, inst: usize, pc: usize) -> Result<(), Error> {
        let pid = badge.bits();
        error!("illegal_instruction: pid={} inst={:#x} pc={:#x}", pid, inst, pc);
        self.terminate_faulting_process(pid, SIGILL_EXIT_CODE)
    }
    fn breakpoint(&mut self, badge: Badge, pc: usize) -> Result<(), Error> {
        let pid = badge.bits();
        warn!("breakpoint: pid={} pc={:#x}", pid, pc);
        self.terminate_faulting_process(pid, SIGTRAP_EXIT_CODE)
    }
    fn access_fault(&mut self, badge: Badge, addr: usize, pc: usize) -> Result<(), Error> {
        let pid = badge.bits();
        error!("access_fault: pid={} addr={:#x} pc={:#x}", pid, addr, pc);
        self.terminate_faulting_process(pid, SIGSEGV_EXIT_CODE)
    }
    fn access_misaligned(&mut self, badge: Badge, addr: usize, pc: usize) -> Result<(), Error> {
        let pid = badge.bits();
        error!("access_misaligned: pid={} addr={:#x} pc={:#x}", pid, addr, pc);
        self.terminate_faulting_process(pid, SIGSEGV_EXIT_CODE)
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
        self.terminate_faulting_process(pid, UNKNOWN_FAULT_EXIT_CODE)
    }
    fn handle_syscall(&mut self, pid: usize, args: MsgArgs) -> Result<(), Error> {
        let sys_num = args[0];
        let sys_args = [args[1], args[2], args[3], args[4], args[5], args[6]];

        let ret = handler(&mut *self, pid, sys_num, sys_args);
        let utcb = unsafe { UTCB::new() };
        utcb.set_mr(0, ret as usize);
        Ok(())
    }
}
