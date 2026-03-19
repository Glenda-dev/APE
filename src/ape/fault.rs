use super::handler::handler;
use crate::ApeManager;
use crate::ape::process::{MemoryMap, MemoryType};
use glenda::arch::mem::PGSIZE;
use glenda::cap::{CapType, Frame};
use glenda::error::Error;
use glenda::interface::{CSpaceService, FaultService, ResourceService, VSpaceService};
use glenda::ipc::{Badge, MsgArgs};
use glenda::mem::Perms;
use glenda::utils::align::align_down;

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

        let process = self.processes.get_mut(&pid).ok_or(Error::Unknown)?;

        // Stack growth logic (example: 1MB stack max)
        if addr >= process.stack_bottom - 1024 * 1024 && addr < process.stack_bottom {
            let page_addr = align_down(addr, PGSIZE);
            let frame_slot = self.cspace_mgr.alloc(&mut *self.res_client)?;
            self.res_client.alloc(Badge::null(), CapType::Frame, 1, frame_slot)?;
            let frame = Frame::from(frame_slot);

            let mut vspace_mgr = glenda::utils::manager::VSpaceManager::new(process.vspace(), 0, 0);
            vspace_mgr.map_frame(
                frame,
                page_addr,
                Perms::READ | Perms::WRITE,
                1,
                &mut *self.res_client,
                &mut *self.cspace_mgr,
            )?;

            process.add_memory_map(MemoryMap {
                vaddr: page_addr,
                paddr: 0,
                size: PGSIZE,
                flags: (Perms::READ | Perms::WRITE).bits(),
                mem_type: MemoryType::Stack,
                cow: false,
                frame_cap: frame_slot.bits(),
            });

            return Ok(());
        }

        Err(Error::NotImplemented)
    }

    fn unknown_fault(
        &mut self,
        _badge: Badge,
        _cause: usize,
        _value: usize,
        _pc: usize,
    ) -> Result<(), Error> {
        Err(Error::NotImplemented)
    }
    fn illegal_instruction(
        &mut self,
        _badge: Badge,
        _inst: usize,
        _pc: usize,
    ) -> Result<(), Error> {
        Err(Error::NotImplemented)
    }
    fn breakpoint(&mut self, _badge: Badge, _pc: usize) -> Result<(), Error> {
        Err(Error::NotImplemented)
    }
    fn access_fault(&mut self, _badge: Badge, _addr: usize, _pc: usize) -> Result<(), Error> {
        Err(Error::NotImplemented)
    }
    fn access_misaligned(&mut self, _badge: Badge, _addr: usize, _pc: usize) -> Result<(), Error> {
        Err(Error::NotImplemented)
    }
    fn handle_syscall(&mut self, pid: usize, args: MsgArgs) -> Result<(), Error> {
        let sys_num = args[0];
        let sys_args = [args[1], args[2], args[3], args[4], args[5], args[6]];
        log!("Syscall {} from PID {}", sys_num, pid);

        let ret = handler(&mut *self, pid, sys_num, sys_args);
        // TODO: Set return value in UTCB or reply message
        Ok(())
    }
}
