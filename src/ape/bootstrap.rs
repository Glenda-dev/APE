use crate::ApeManager;
use crate::ape::process::{FileHandle, FileType, MemoryMap, MemoryType};
use crate::elf::{ElfFile, PF_W, PF_X, PT_LOAD};
use crate::layout::{DEFAULT_INIT_PROCESS_NAME, DEFAULT_INIT_PROGRAM, DEFAULT_VT_NAME};
use ape::cap::APE_SLOT;
use ape::sys::constants::FIRST_USER_FD;
use core::cmp::{max, min};
use core::mem::size_of;
use glenda::arch::mem::PGSIZE;
use glenda::cap::{CapPtr, CapType, Endpoint, Frame, TCB_SLOT};
use glenda::error::Error;
use glenda::interface::{
    CSpaceService, InitService, ProcessService, ResourceService, ThreadService, VSpaceService,
    VirtualTerminalService,
};
use glenda::ipc::Badge;
use glenda::mem::{HEAP_VA, Perms, STACK_BASE};
use glenda::mem::{TRAMPOLINE_VA, get_trapframe_va, get_utcb_va};
use glenda::protocol;
use glenda::utils::align::{align_down, align_up};
use glenda::utils::manager::VSpaceManager;
use linux_raw_sys::general::*;

const INITIAL_ARG0: &[u8] = b"init\0";
const INITIAL_STACK_ALIGN: usize = 16;

fn use_ipc_syscall_path(program: &str) -> bool {
    !program.ends_with("-native")
}

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
        let (_vt_id, vt_ep) = self.vt_client.create_vt(Badge::null(), DEFAULT_VT_NAME, vt_recv)?;

        // 2. 创建 TerminalClient
        let term_client = glenda::client::TerminalClient::new(vt_ep);
        self.stdio_term = Some(term_client);

        Ok(())
    }

    fn setup_initial_stack(
        &mut self,
        pid: usize,
        child_vspace_mgr: &mut VSpaceManager,
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

        let arg0_off = PGSIZE - INITIAL_ARG0.len();
        stack[arg0_off..arg0_off + INITIAL_ARG0.len()].copy_from_slice(INITIAL_ARG0);
        let arg0_va = stack_page_vaddr + arg0_off;

        // Linux/musl 兼容的最小启动栈：
        // [argc][argv0][NULL][envp0=NULL][AT_NULL][0]
        let words = [1usize, arg0_va, 0, 0, 0, 0];
        let words_size = words.len() * size_of::<usize>();
        let mut words_off = arg0_off - words_size;
        words_off &= !(INITIAL_STACK_ALIGN - 1);

        for (idx, word) in words.iter().enumerate() {
            let start = words_off + idx * size_of::<usize>();
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

        Ok(stack_page_vaddr + words_off)
    }

    fn load_init(&mut self) -> Result<(), Error> {
        log!("bootstrap: loading init process from initrd...");
        let config_slot = self.cspace_mgr.alloc(&mut *self.res_client)?;
        debug!("bootstrap: Allocated config slot: {:?}", config_slot);

        // 当前从默认 init 程序加载 (代表从 initrd 获取的示例)
        let init_program = DEFAULT_INIT_PROGRAM;
        let (frame, size) = self.res_client.get_config(Badge::null(), init_program, config_slot)?;
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
        let host_pid = self.proc_client.create(Badge::null(), DEFAULT_INIT_PROCESS_NAME)?;
        debug!("bootstrap: Process created: host_pid={}", host_pid);

        // 2. Fetch CNode
        let cnode_slot = self.cspace_mgr.alloc(&mut *self.res_client)?;
        let cnode = self.proc_client.get_cnode(Badge::null(), host_pid, cnode_slot)?;
        debug!("bootstrap: Fetched process CNode into slot: {:?}", cnode_slot);

        // 3. Register
        let pid = self.register_process(0, host_pid, cnode);
        debug!("bootstrap: Process registered in APE (pid={}, host_pid={})", pid, host_pid);

        // 4. 为 init 进程初始化 stdio fds
        if let Some(term) = self.stdio_term {
            let proc = self.get_process_mut(pid).unwrap();
            proc.fds.insert(STDIN_FILENO, FileHandle { file_type: FileType::Terminal(term) });
            proc.fds.insert(STDOUT_FILENO, FileHandle { file_type: FileType::Terminal(term) });
            proc.fds.insert(STDERR_FILENO, FileHandle { file_type: FileType::Terminal(term) });
            proc.next_fd = FIRST_USER_FD;
        }

        let vspace_cap = self.get_process(pid).ok_or(Error::NotFound)?.vspace();
        let mut child_vspace_mgr = VSpaceManager::new(vspace_cap, 0, 0);
        child_vspace_mgr.mark_existing(TRAMPOLINE_VA, PGSIZE);
        child_vspace_mgr.mark_existing(get_utcb_va(0), PGSIZE);
        child_vspace_mgr.mark_existing(get_trapframe_va(0), PGSIZE);

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
                    "Loading segment: vaddr={:#x}, p_memsz={:#x}, num_pages={}, perms={:?}",
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
                        flags: perms,
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

        if let Some(process) = self.get_process_mut(pid) {
            let heap_start = align_up(max(max_vaddr, HEAP_VA), PGSIZE);
            process.heap_start = heap_start;
            process.heap_brk = heap_start;
            process.heap_limit = process.mmap_base;
            process.stack_bottom = STACK_BASE;
            process.stack_size = 0;
        }

        let initial_sp = self.setup_initial_stack(pid, &mut child_vspace_mgr)?;
        let (tcb_cap, fault_ep) = {
            let process = self.get_process(pid).ok_or(Error::NotFound)?;
            let fault_ep = Endpoint::from(CapPtr::concat(process.cspace().cap(), APE_SLOT));
            (process.tcb(), fault_ep)
        };
        log!("bootstrap: Setting entry point: {:#x}, sp={:#x}", entry_point, initial_sp);
        tcb_cap.set_entrypoint(entry_point, initial_sp, 0)?;
        tcb_cap.set_fault_handler(fault_ep, use_ipc_syscall_path(init_program))?;

        self.vspace_mgr.unmap(scratch_vaddr, align_up(size, PGSIZE) / PGSIZE)?;

        log!("bootstrap: init process loaded, pid: {}", pid);
        tcb_cap.resume()?;
        Ok(())
    }
}
