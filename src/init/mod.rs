use crate::ApeManager;
use crate::ape::process::{MemoryMap, MemoryType};
use crate::ape::user::ExecveUserInput;
use crate::elf::{ET_DYN, ET_EXEC, ElfFile, PF_W, PF_X, PT_LOAD, PT_PHDR};
use alloc::string::String;
use alloc::vec::Vec;
use ape::cap::APE_SLOT;
use core::cmp::{max, min};
use core::mem::size_of;
use glenda::arch::mem::PGSIZE;
use glenda::cap::{CapPtr, CapType, Endpoint, Frame};
use glenda::error::Error;
use glenda::interface::{
    CSpaceService, FileHandleService, FileSystemService, ResourceService, ThreadService,
    VSpaceService,
};
use glenda::ipc::Badge;
use glenda::mem::get_utcb_va;
use glenda::mem::{HEAP_VA, Perms, STACK_BASE};
use glenda::protocol::fs::OpenFlags;
use glenda::utils::align::{align_down, align_up};

const DEFAULT_ARG0: &str = "init";
const INITIAL_STACK_ALIGN: usize = 16;
const PIE_LOAD_BIAS: usize = 0;
const INTERP_LOAD_GAP: usize = 0x10_0000;
const INITIAL_TLS_PAGES: usize = 4;
const INITIAL_TLS_GAP_PAGES: usize = 8;

const AUXV_AT_PHDR: usize = 3;
const AUXV_AT_PHENT: usize = 4;
const AUXV_AT_PHNUM: usize = 5;
const AUXV_AT_PAGESZ: usize = 6;
const AUXV_AT_BASE: usize = 7;
const AUXV_AT_ENTRY: usize = 9;

struct LoadedElfInfo {
    entry: usize,
    load_end: usize,
    phdr_vaddr: Option<usize>,
}

impl<'a> ApeManager<'a> {
    fn read_exec_image_from_fs(&mut self, pid: usize, path: &str) -> Result<Vec<u8>, Error> {
        let mut translated_path = self.resolve_path_for_process(pid, path)?;
        let mut stat = self.fs_client.stat_path(Badge::null(), &translated_path)?;
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
        argv: &[String],
        envp: &[String],
        auxv: &[(usize, usize)],
    ) -> Result<usize, Error> {
        let stack_page_vaddr = STACK_BASE - PGSIZE;
        let perms = Perms::READ | Perms::WRITE;

        let frame_slot = self.cspace_mgr.alloc(&mut *self.res_client)?;
        self.res_client.alloc(Badge::null(), CapType::Frame, 1, frame_slot)?;
        let frame = Frame::from(frame_slot);

        self.map_process_frame(pid, frame, stack_page_vaddr, perms, 1)?;

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
        // [argc][argv...][NULL][envp...][NULL][auxv...][AT_NULL][0]
        let mut words = Vec::new();
        words.push(argv_ptrs.len());
        words.extend(argv_ptrs.iter().copied());
        words.push(0);
        words.extend(envp_ptrs.iter().copied());
        words.push(0);
        for (k, v) in auxv {
            words.push(*k);
            words.push(*v);
        }
        words.push(0); // AT_NULL
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

    fn setup_initial_tls(&mut self, pid: usize) -> Result<usize, Error> {
        let tls_start = get_utcb_va(0)
            .saturating_sub(INITIAL_TLS_GAP_PAGES * PGSIZE)
            .saturating_sub(INITIAL_TLS_PAGES * PGSIZE);
        let tls_size = INITIAL_TLS_PAGES * PGSIZE;

        let frame_slot = self.cspace_mgr.alloc(&mut *self.res_client)?;
        self.res_client.alloc(Badge::null(), CapType::Frame, INITIAL_TLS_PAGES, frame_slot)?;
        let frame = Frame::from(frame_slot);

        self.map_process_frame(
            pid,
            frame,
            tls_start,
            Perms::READ | Perms::WRITE,
            INITIAL_TLS_PAGES,
        )?;

        let scratch_vaddr = self.vspace_mgr.map_scratch(
            frame,
            Perms::READ | Perms::WRITE,
            INITIAL_TLS_PAGES,
            &mut *self.res_client,
            &mut *self.cspace_mgr,
        )?;
        let tls_slice =
            unsafe { core::slice::from_raw_parts_mut(scratch_vaddr as *mut u8, tls_size) };
        tls_slice.fill(0);
        self.vspace_mgr.unmap(scratch_vaddr, INITIAL_TLS_PAGES)?;

        if let Some(process) = self.get_process_mut(pid) {
            process.add_memory_map(MemoryMap {
                vaddr: tls_start,
                paddr: 0,
                size: tls_size,
                flags: Perms::READ | Perms::WRITE,
                mem_type: MemoryType::Anonymous,
                cow: false,
                frame_cap: frame_slot.bits(),
            });
        }

        // 将 tp 放在 TLS 区中间，兼容动态加载器早期的正负偏移访问。
        Ok(tls_start + tls_size / 2)
    }

    fn load_elf_into_process(
        &mut self,
        pid: usize,
        elf_data: &[u8],
        load_bias: usize,
    ) -> Result<LoadedElfInfo, Error> {
        let elf = ElfFile::new(elf_data)
            .map_err(|e| error!("Failed to parse ELF file: {}", e))
            .map_err(|_| Error::InvalidArgs)?;

        let mut load_end = 0usize;
        let mut phdr_vaddr = None;

        for phdr in elf.program_headers() {
            if phdr.p_type == PT_PHDR {
                phdr_vaddr = Some(load_bias + phdr.p_vaddr as usize);
            }
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

            let seg_start = load_bias + vaddr;
            let seg_end = seg_start + mem_size;
            if seg_end > load_end {
                load_end = seg_end;
            }

            let mut perms = Perms::READ;
            if phdr.p_flags & PF_W != 0 {
                perms |= Perms::WRITE;
            }
            if phdr.p_flags & PF_X != 0 {
                perms |= Perms::EXECUTE;
            }

            let start_page = align_down(seg_start, PGSIZE);
            let end_page = align_up(seg_end, PGSIZE);
            let num_pages = (end_page - start_page) / PGSIZE;

            for i in 0..num_pages {
                let page_vaddr = start_page + i * PGSIZE;

                let frame_cap = self.cspace_mgr.alloc(&mut *self.res_client)?;
                self.res_client.alloc(Badge::null(), CapType::Frame, 1, frame_cap)?;
                let frame = Frame::from(frame_cap);

                self.map_process_frame(pid, frame, page_vaddr, perms, 1)?;

                if let Some(process) = self.get_process_mut(pid) {
                    process.add_memory_map(MemoryMap {
                        vaddr: page_vaddr,
                        paddr: 0,
                        size: PGSIZE,
                        flags: perms,
                        mem_type: MemoryType::Image,
                        cow: false,
                        frame_cap: frame_cap.bits(),
                    });
                }

                let scratch_vaddr = self.vspace_mgr.map_scratch(
                    frame,
                    Perms::READ | Perms::WRITE,
                    1,
                    &mut *self.res_client,
                    &mut *self.cspace_mgr,
                )?;

                let page_slice =
                    unsafe { core::slice::from_raw_parts_mut(scratch_vaddr as *mut u8, PGSIZE) };
                page_slice.fill(0);

                let file_seg_end = seg_start.saturating_add(file_size);
                let copy_start = max(page_vaddr, seg_start);
                let copy_end = min(page_vaddr + PGSIZE, file_seg_end);
                if copy_end > copy_start && offset < elf_data.len() {
                    let src_off = offset + (copy_start - seg_start);
                    let dst_off = copy_start - page_vaddr;
                    let copy_len = copy_end - copy_start;
                    if src_off < elf_data.len() {
                        let actual = min(copy_len, elf_data.len() - src_off);
                        page_slice[dst_off..dst_off + actual]
                            .copy_from_slice(&elf_data[src_off..src_off + actual]);
                    }
                }

                self.vspace_mgr.unmap(scratch_vaddr, 1)?;
            }
        }

        let fallback_phdr = load_bias + elf.ph_offset();
        Ok(LoadedElfInfo {
            entry: load_bias + elf.entry_point(),
            load_end,
            phdr_vaddr: phdr_vaddr.or(Some(fallback_phdr)),
        })
    }

    pub(crate) fn do_execve_path(
        &mut self,
        pid: usize,
        path: &str,
        argv: &[String],
        envp: &[String],
    ) -> Result<(), Error> {
        let main_elf_data = self.read_exec_image_from_fs(pid, path)?;
        let main_elf = ElfFile::new(&main_elf_data)
            .map_err(|e| error!("Failed to parse ELF file: {}", e))
            .map_err(|_| Error::InvalidArgs)?;

        let main_file_type = main_elf.file_type();
        if main_file_type != ET_EXEC && main_file_type != ET_DYN {
            error!("execve_path: unsupported ELF type {} for {}", main_file_type, path);
            return Err(Error::InvalidArgs);
        }

        let main_load_bias = if main_file_type == ET_DYN { PIE_LOAD_BIAS } else { 0 };
        let interp_path = main_elf.interpreter_path().map(String::from);
        let old_maps: Vec<(usize, usize)> = {
            let process = self.get_process(pid).ok_or(Error::NotFound)?;
            process
                .memory_maps
                .values()
                .map(|map| (map.vaddr, align_up(map.size, PGSIZE) / PGSIZE))
                .collect()
        };

        for (vaddr, pages) in old_maps {
            if pages != 0 {
                let _ = self.unmap_process_pages(pid, vaddr, pages);
            }
        }

        if let Some(process) = self.get_process_mut(pid) {
            process.memory_maps.clear();
            process.lazy_memory_maps.clear();
            process.stack_size = 0;
        }

        let main_info = self.load_elf_into_process(pid, &main_elf_data, main_load_bias)?;

        let mut entry_point = main_info.entry;
        let mut aux_at_base = 0usize;

        if let Some(interp) = interp_path {
            let interp_elf_data = self.read_exec_image_from_fs(pid, &interp)?;
            let interp_base = align_up(main_info.load_end + INTERP_LOAD_GAP, PGSIZE);
            let interp_info = self.load_elf_into_process(pid, &interp_elf_data, interp_base)?;
            aux_at_base = interp_base;
            entry_point = interp_info.entry;
        }

        if let Some(process) = self.get_process_mut(pid) {
            let heap_start = align_up(max(main_info.load_end, HEAP_VA), PGSIZE);
            process.heap_start = heap_start;
            process.heap_brk = heap_start;
            process.heap_limit = process.mmap_base;
            process.mmap_next = process.mmap_base;
            process.stack_bottom = STACK_BASE;
            process.stack_size = 0;
        }

        let main_phdr = main_info.phdr_vaddr.unwrap_or(main_load_bias + main_elf.ph_offset());
        let auxv = [
            (AUXV_AT_PHDR, main_phdr),
            (AUXV_AT_PHENT, main_elf.ph_entry_size()),
            (AUXV_AT_PHNUM, main_elf.ph_num()),
            (AUXV_AT_PAGESZ, PGSIZE),
            (AUXV_AT_BASE, aux_at_base),
            (AUXV_AT_ENTRY, main_info.entry),
        ];

        let initial_sp = self.setup_initial_stack(pid, argv, envp, &auxv)?;
        let initial_tp = self.setup_initial_tls(pid)?;
        let (tcb_cap, fault_ep) = {
            let process = self.get_process(pid).ok_or(Error::NotFound)?;
            let fault_ep = Endpoint::from(CapPtr::concat(process.cspace().cap(), APE_SLOT));
            (process.tcb(), fault_ep)
        };
        tcb_cap.set_entrypoint(entry_point, initial_sp, initial_tp)?;
        tcb_cap.set_fault_handler(fault_ep, false)?;
        Ok(())
    }

    pub(crate) fn execve_path(
        &mut self,
        pid: usize,
        path: &str,
        argv: &[String],
        envp: &[String],
    ) -> Result<(), Error> {
        self.do_execve_path(pid, path, argv, envp)
    }
}

pub(crate) fn do_execve<'a>(
    mgr: &mut ApeManager<'a>,
    pid: usize,
    filename_ptr: usize,
    argv_ptr: usize,
    envp_ptr: usize,
) -> Result<(), Error> {
    let exec_input: ExecveUserInput =
        mgr.parse_execve_user_input(pid, filename_ptr, argv_ptr, envp_ptr)?;
    let translated_filename = mgr.resolve_path_for_process(pid, &exec_input.filename)?;

    // 保持行为与 Linux 接近：允许 filename 与 argv[0] 不同。
    mgr.do_execve_path(pid, &translated_filename, &exec_input.argv, &exec_input.envp)
}

pub fn sys_execve<'a>(
    mgr: &mut ApeManager<'a>,
    pid: usize,
    filename_ptr: usize,
    argv_ptr: usize,
    envp_ptr: usize,
) -> Result<isize, Error> {
    do_execve(mgr, pid, filename_ptr, argv_ptr, envp_ptr)?;
    Ok(0)
}
