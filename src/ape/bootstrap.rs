use crate::ApeManager;
use crate::ape::process::{FileHandle, FileType, MemoryMap, MemoryType};
use crate::elf::{ElfFile, PF_W, PF_X, PT_LOAD};
use core::cmp::min;
use glenda::arch::mem::PGSIZE;
use glenda::cap::{CapType, Frame};
use glenda::error::Error;
use glenda::interface::{
    CSpaceService, InitService, ProcessService, ResourceService, ThreadService, VSpaceService,
    VirtualTerminalService,
};
use glenda::ipc::Badge;
use glenda::mem::Perms;
use glenda::protocol;
use glenda::utils::align::{align_down, align_up};
use glenda::utils::manager::VSpaceManager;

impl<'a> ApeManager<'a> {
    pub fn bootstrap(&mut self) -> Result<(), Error> {
        self.init_client.report_service(Badge::null(), protocol::init::ServiceState::Starting)?;

        self.mount_rootfs()?;
        self.init_stdio()?;
        self.load_init()?;

        log!("bootstrap: bootstrap complete");
        Ok(())
    }

    fn mount_rootfs(&mut self) -> Result<(), Error> {
        log!("bootstrap: mounting rootfs...");
        // TODO: 从 fs 服务获取 rootfs 并在内部 VFS 挂载
        Ok(())
    }

    fn init_stdio(&mut self) -> Result<(), Error> {
        log!("bootstrap: initializing stdio...");
        // 1. 获取 vt0
        let vt_recv = self.cspace_mgr.alloc(&mut *self.res_client)?;
        let (_vt_id, vt_ep) = self.vt_client.create_vt(Badge::null(), "vt0", vt_recv)?;

        // 2. 创建 TerminalClient
        let term_client = glenda::client::TerminalClient::new(vt_ep);
        self.stdio_term = Some(term_client);

        Ok(())
    }

    fn load_init(&mut self) -> Result<(), Error> {
        log!("bootstrap: loading init process from initrd...");
        let config_slot = self.cspace_mgr.alloc(&mut *self.res_client)?;
        debug!("bootstrap: Allocated config slot: {:?}", config_slot);

        // 明确硬编码从 hello-posix 加载 (代表从 initrd 获取的示例)
        let (frame, size) =
            self.res_client.get_config(Badge::null(), "hello-posix", config_slot)?;
        debug!("bootstrap: Got config: frame={:?}, size={}", frame, size);

        let scratch_vaddr = self.vspace_mgr.map_scratch(
            frame,
            Perms::READ,
            align_up(size, PGSIZE) / PGSIZE,
            &mut *self.res_client,
            &mut *self.cspace_mgr,
        )?;
        debug!("bootstrap: Mapped scratch at vaddr: {:#x}", scratch_vaddr);

        let elf_data = unsafe { core::slice::from_raw_parts(scratch_vaddr as *const u8, size) };

        // 手动加载 ELF，不使用 sys_execve
        let elf = ElfFile::new(elf_data).map_err(|_| Error::InvalidArgs)?;
        let entry_point = elf.entry_point();
        debug!("bootstrap: ELF parsed: entry_point={:#x}", entry_point);

        // 1. Create process
        let host_pid = self.proc_client.create(Badge::null(), "init")?;
        debug!("bootstrap: Process created: host_pid={}", host_pid);

        // 2. Fetch CNode
        let cnode_slot = self.cspace_mgr.alloc(&mut *self.res_client)?;
        let cnode = self.proc_client.get_cnode(Badge::null(), host_pid, cnode_slot)?;
        debug!("bootstrap: Fetched process CNode into slot: {:?}", cnode_slot);

        // 3. Register
        let pid = self.register_process(0, host_pid, cnode);
        debug!("bootstrap: Process registered in APE (pid={}, host_pid={})", pid, host_pid);

        // 4. 为 init 进程初始化 stdio fds (0, 1, 2)
        if let Some(term) = self.stdio_term {
            let proc = self.get_process_mut(pid).unwrap();
            proc.fds.insert(0, FileHandle { file_type: FileType::Terminal(term) });
            proc.fds.insert(1, FileHandle { file_type: FileType::Terminal(term) });
            proc.fds.insert(2, FileHandle { file_type: FileType::Terminal(term) });
            proc.next_fd = 3;
        }

        let vspace_cap = self.get_process(pid).ok_or(Error::NotFound)?.vspace();
        let mut child_vspace_mgr = VSpaceManager::new(vspace_cap, 0, 0);

        let mut max_vaddr = 0;

        for phdr in elf.program_headers() {
            let vaddr = phdr.p_vaddr as usize;
            let mem_size = phdr.p_memsz as usize;
            let file_size = phdr.p_filesz as usize;
            let offset = phdr.p_offset as usize;

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

            if phdr.p_type == PT_LOAD {
                let start_page = align_down(vaddr, PGSIZE);
                let end_page = align_up(vaddr + mem_size, PGSIZE);
                let num_pages = (end_page - start_page) / PGSIZE;
                debug!(
                    "Loading PT_LOAD segment: vaddr={:#x}, p_memsz={:#x}, num_pages={}, perms={:?}",
                    vaddr, mem_size, num_pages, perms
                );
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
                        flags: perms.bits(),
                        mem_type: MemoryType::Image,
                        cow: false,
                        frame_cap: dest_cap.bits(),
                    });
                }

                let scratch_vaddr_child = self.vspace_mgr.map_scratch(
                    frame,
                    Perms::READ | Perms::WRITE,
                    num_pages,
                    &mut *self.res_client,
                    &mut *self.cspace_mgr,
                )?;

                let dest_slice = unsafe {
                    core::slice::from_raw_parts_mut(
                        scratch_vaddr_child as *mut u8,
                        num_pages * PGSIZE,
                    )
                };
                dest_slice.fill(0);
                let padding = vaddr - start_page;
                if padding < dest_slice.len() {
                    let actual_copy = min(file_size, dest_slice.len() - padding);
                    dest_slice[padding..padding + actual_copy]
                        .copy_from_slice(&elf_data[offset..offset + actual_copy]);
                }
                self.vspace_mgr.unmap(scratch_vaddr_child, num_pages)?;
            }
        }

        // Map stack
        let stack_pages = 512;
        max_vaddr = align_up(max_vaddr + PGSIZE, PGSIZE);
        let stack_bottom = max_vaddr;
        let stack_top = stack_bottom + stack_pages * PGSIZE;

        let dest_cap = self.cspace_mgr.alloc(&mut *self.res_client)?;
        self.res_client.alloc(Badge::null(), CapType::Frame, stack_pages, dest_cap)?;
        let frame = Frame::from(dest_cap);

        child_vspace_mgr.map_frame(
            frame,
            stack_bottom,
            Perms::READ | Perms::WRITE | Perms::EXECUTE,
            stack_pages,
            &mut *self.res_client,
            &mut *self.cspace_mgr,
        )?;

        if let Some(process) = self.get_process_mut(pid) {
            process.add_memory_map(MemoryMap {
                vaddr: stack_bottom,
                paddr: 0,
                size: stack_pages * PGSIZE,
                flags: (Perms::READ | Perms::WRITE | Perms::EXECUTE).bits(),
                mem_type: MemoryType::Stack,
                cow: false,
                frame_cap: dest_cap.bits(),
            });
        }

        self.proc_client.thread_create(Badge::new(pid), entry_point, 0, stack_top, 0)?;

        self.vspace_mgr.unmap(scratch_vaddr, align_up(size, PGSIZE) / PGSIZE)?;

        log!("bootstrap: init process loaded, pid: {}", pid);
        Ok(())
    }
}
