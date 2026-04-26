use crate::ApeManager;
use crate::ape::mm::{MemoryMap, MemoryType};
use crate::ape::policy::SharedPagePoolPolicy;
use crate::ape::policy::lru::LruPolicy;
use crate::ape::task::TaskStruct;
use alloc::string::String;
use alloc::vec;
use alloc::vec::Vec;
use core::cmp::min;
use core::mem::size_of;
use glenda::arch::mem::PGSIZE;
use glenda::cap::{CapPtr, CapType, Page};
use glenda::error::Error;
use glenda::interface::{CSpaceService, ResourceService, VSpaceService};
use glenda::ipc::Badge;
use glenda::mem::Perms;
use glenda::utils::align::{align_down, align_up};

pub const USER_PATH_MAX: usize = 4096;
pub const USER_EXEC_ARGV_MAX: usize = 256;
pub const USER_EXEC_ENVP_MAX: usize = 256;
pub const USER_EXEC_STRING_MAX: usize = 4096;
pub const USER_SHARED_PAGE_POOL_SLOTS: usize = 16;

pub struct ExecveUserInput {
    pub filename: String,
    pub argv: Vec<String>,
    pub envp: Vec<String>,
}

pub struct SharedPagePoolEntry {
    pub map_vaddr: usize,
    pub scratch_vaddr: usize,
    pub pages: usize,
    pub frame_cap: usize,
    pub perms: Perms,
}

pub struct SharedPagePool<P: SharedPagePoolPolicy> {
    pub entries: [Option<SharedPagePoolEntry>; USER_SHARED_PAGE_POOL_SLOTS],
    pub occupied: [bool; USER_SHARED_PAGE_POOL_SLOTS],
    pub policy: P,
}

impl<P: SharedPagePoolPolicy> SharedPagePool<P> {
    pub fn new(policy: P) -> Self {
        Self {
            entries: [const { None }; USER_SHARED_PAGE_POOL_SLOTS],
            occupied: [false; USER_SHARED_PAGE_POOL_SLOTS],
            policy,
        }
    }

    fn find_hit(&self, map: &MemoryMap, perms: Perms) -> Option<usize> {
        for i in 0..USER_SHARED_PAGE_POOL_SLOTS {
            if self.occupied[i] {
                let entry = self.entries[i].as_ref().unwrap();
                if entry.frame_cap == map.frame_cap && entry.perms.contains(perms) {
                    return Some(i);
                }
            }
        }
        None
    }

    fn pick_slot(&mut self) -> Result<usize, Error> {
        for i in 0..USER_SHARED_PAGE_POOL_SLOTS {
            if !self.occupied[i] {
                return Ok(i);
            }
        }
        self.policy.victim(&self.occupied).ok_or(Error::OutOfMemory)
    }

    fn unmap_slot<'a>(&mut self, mgr: &mut ApeManager<'a>, slot: usize) -> Result<(), Error> {
        if let Some(entry) = self.entries[slot].take() {
            mgr.vspace_mgr.unmap(entry.scratch_vaddr, entry.pages)?;
            self.occupied[slot] = false;
        }
        Ok(())
    }

    fn acquire<'a>(
        &mut self,
        mgr: &mut ApeManager<'a>,
        map: &MemoryMap,
        perms: Perms,
    ) -> Result<usize, Error> {
        if let Some(slot) = self.find_hit(map, perms) {
            self.policy.touch(slot);
            return Ok(self.entries[slot].as_ref().unwrap().scratch_vaddr);
        }

        let slot = self.pick_slot()?;
        if self.occupied[slot] {
            self.unmap_slot(mgr, slot)?;
        }

        let pages = align_up(map.size, PGSIZE) / PGSIZE;
        let frame = Page::from(CapPtr::from(map.frame_cap));
        let scratch_vaddr = mgr.vspace_mgr.map_scratch(
            frame,
            perms,
            pages,
            &mut *mgr.res_client,
            &mut *mgr.cspace_mgr,
        )?;

        self.entries[slot] = Some(SharedPagePoolEntry {
            map_vaddr: map.vaddr,
            scratch_vaddr,
            pages,
            frame_cap: map.frame_cap,
            perms,
        });
        self.occupied[slot] = true;
        self.policy.touch(slot);

        Ok(scratch_vaddr)
    }

    fn release_all<'a>(&mut self, mgr: &mut ApeManager<'a>) -> Result<(), Error> {
        for i in 0..USER_SHARED_PAGE_POOL_SLOTS {
            if self.occupied[i] {
                self.unmap_slot(mgr, i)?;
            }
        }
        Ok(())
    }
}

pub struct UserAccessSession<'a, 'b, P: SharedPagePoolPolicy> {
    pub mgr: &'a mut ApeManager<'b>,
    pub pid: usize,
    pub pool: SharedPagePool<P>,
}

impl<'a, 'b, P: SharedPagePoolPolicy> UserAccessSession<'a, 'b, P> {
    pub fn new(mgr: &'a mut ApeManager<'b>, pid: usize, _slots: usize, policy: P) -> Self {
        Self { mgr, pid, pool: SharedPagePool::new(policy) }
    }

    fn finish(&mut self) -> Result<(), Error> {
        self.pool.release_all(self.mgr)
    }

    fn try_grow_stack_for_user_addr(&mut self, user_addr: usize) -> Result<bool, Error> {
        let page_addr = align_down(user_addr, PGSIZE);
        let (stack_bottom, max_stack_size, stack_size) = {
            let task = self.mgr.get_process(self.pid).ok_or(Error::NotFound)?;
            let mm = task.mm.state.read();
            (mm.stack_bottom, mm.max_stack_size, mm.stack_size)
        };

        let stack_low_limit = stack_bottom.saturating_sub(max_stack_size);
        if !(user_addr < stack_bottom && user_addr >= stack_low_limit) {
            return Ok(false);
        }

        let current_stack_low = stack_bottom.saturating_sub(stack_size);
        if page_addr >= current_stack_low {
            return Ok(false);
        }

        let pages_to_map = (current_stack_low - page_addr) / PGSIZE;
        if pages_to_map == 0 {
            return Ok(false);
        }

        for idx in 0..pages_to_map {
            let vaddr = current_stack_low - (idx + 1) * PGSIZE;
            let frame_slot = self.mgr.cspace_mgr.alloc(&mut *self.mgr.res_client)?;
            self.mgr.res_client.alloc(Badge::null(), CapType::Page, 1, frame_slot)?;
            self.mgr.ledger_record_frame_alloc(self.pid, frame_slot, 1, "user_copy_stack_growth");
            self.mgr.map_process_frame(
                self.pid,
                Page::from(frame_slot),
                vaddr,
                Perms::READ | Perms::WRITE,
                1,
            )?;

            let task = self.mgr.get_process(self.pid).ok_or(Error::NotFound)?;
            task.mm.add_memory_map(MemoryMap {
                vaddr,
                paddr: 0,
                size: PGSIZE,
                flags: Perms::READ | Perms::WRITE,
                mem_type: MemoryType::Stack,
                cow: false,
                frame_cap: frame_slot.bits(),
                file_backing_fd: None,
                file_backing_offset: 0,
            });
            let mut mm_state = task.mm.state.write();
            mm_state.stack_size = mm_state.stack_size.saturating_add(PGSIZE);
        }

        Ok(true)
    }

    fn lookup_map(&mut self, user_addr: usize, required: Perms) -> Result<MemoryMap, Error> {
        let map = {
            let task = self.mgr.get_process(self.pid).ok_or(Error::NotFound)?;
            task.mm.lookup_memory_map(user_addr)
        }
        .or_else(|| match self.try_grow_stack_for_user_addr(user_addr) {
            Ok(true) => {
                self.mgr.get_process(self.pid).and_then(|task| task.mm.lookup_memory_map(user_addr))
            }
            _ => None,
        })
        .ok_or(Error::InvalidAddress)?;

        if map.frame_cap == 0 || !map.flags.contains(required) {
            return Err(Error::InvalidAddress);
        }
        if user_addr < map.vaddr || user_addr >= map.vaddr.saturating_add(map.size) {
            return Err(Error::InvalidAddress);
        }

        Ok(map)
    }

    pub(crate) fn copy_from_user(&mut self, user_src: usize, dst: &mut [u8]) -> Result<(), Error> {
        if dst.is_empty() {
            return Ok(());
        }
        if user_src == 0 {
            return Err(Error::InvalidAddress);
        }

        let mut copied = 0usize;
        let mut cursor = user_src;

        while copied < dst.len() {
            let map = self.lookup_map(cursor, Perms::READ)?;

            let start = cursor - map.vaddr;
            let chunk = min(map.size - start, dst.len() - copied);
            if chunk == 0 {
                return Err(Error::InvalidAddress);
            }

            let scratch = self.pool.acquire(self.mgr, &map, Perms::READ)?;
            let src = unsafe { core::slice::from_raw_parts((scratch + start) as *const u8, chunk) };
            dst[copied..copied + chunk].copy_from_slice(src);

            copied += chunk;
            cursor = cursor.saturating_add(chunk);
        }

        Ok(())
    }

    pub(crate) fn copy_to_user(&mut self, user_dst: usize, src: &[u8]) -> Result<(), Error> {
        if src.is_empty() {
            return Ok(());
        }
        if user_dst == 0 {
            return Err(Error::InvalidAddress);
        }

        let mut copied = 0usize;
        let mut cursor = user_dst;

        while copied < src.len() {
            let map = self.lookup_map(cursor, Perms::WRITE)?;

            let start = cursor - map.vaddr;
            let chunk = min(map.size - start, src.len() - copied);
            if chunk == 0 {
                return Err(Error::InvalidAddress);
            }

            let scratch = self.pool.acquire(self.mgr, &map, Perms::READ | Perms::WRITE)?;
            let dst =
                unsafe { core::slice::from_raw_parts_mut((scratch + start) as *mut u8, chunk) };
            dst.copy_from_slice(&src[copied..copied + chunk]);

            copied += chunk;
            cursor = cursor.saturating_add(chunk);
        }

        Ok(())
    }

    pub(crate) fn strncpy_from_user(
        &mut self,
        user_src: usize,
        max_len: usize,
    ) -> Result<String, Error> {
        if user_src == 0 {
            return Err(Error::InvalidAddress);
        }
        if max_len == 0 {
            return Err(Error::InvalidArgs);
        }

        let mut out = Vec::new();
        let mut cursor = user_src;

        while out.len() < max_len {
            let map = self.lookup_map(cursor, Perms::READ)?;

            let start = cursor - map.vaddr;
            let available = min(map.size - start, max_len - out.len());
            if available == 0 {
                return Err(Error::MessageTooLong);
            }

            let scratch = self.pool.acquire(self.mgr, &map, Perms::READ)?;
            let bytes =
                unsafe { core::slice::from_raw_parts((scratch + start) as *const u8, available) };

            let mut consumed = 0usize;
            let mut found_nul = false;
            for &b in bytes {
                consumed += 1;
                if b == 0 {
                    found_nul = true;
                    break;
                }
                out.push(b);
            }

            if found_nul {
                return String::from_utf8(out).map_err(|_| Error::InvalidArgs);
            }

            cursor = cursor.saturating_add(consumed);
        }

        Err(Error::MessageTooLong)
    }

    fn read_user_usize(&mut self, user_src: usize) -> Result<usize, Error> {
        let mut buf = [0u8; size_of::<usize>()];
        self.copy_from_user(user_src, &mut buf)?;
        Ok(usize::from_ne_bytes(buf))
    }

    fn read_user_string_array(
        &mut self,
        array_ptr: usize,
        max_count: usize,
        max_str_len: usize,
    ) -> Result<Vec<String>, Error> {
        if array_ptr == 0 {
            return Ok(Vec::new());
        }

        let mut out = Vec::new();
        for i in 0..max_count {
            let ptr_addr = array_ptr
                .checked_add(i.checked_mul(size_of::<usize>()).ok_or(Error::InvalidAddress)?)
                .ok_or(Error::InvalidAddress)?;
            let elem_ptr = self.read_user_usize(ptr_addr)?;
            if elem_ptr == 0 {
                return Ok(out);
            }
            out.push(self.strncpy_from_user(elem_ptr, max_str_len)?);
        }

        Err(Error::MessageTooLong)
    }

    pub(crate) fn parse_execve_user_input(
        &mut self,
        filename_ptr: usize,
        argv_ptr: usize,
        envp_ptr: usize,
    ) -> Result<ExecveUserInput, Error> {
        let filename = self.strncpy_from_user(filename_ptr, USER_PATH_MAX)?;
        let argv =
            self.read_user_string_array(argv_ptr, USER_EXEC_ARGV_MAX, USER_EXEC_STRING_MAX)?;
        let envp =
            self.read_user_string_array(envp_ptr, USER_EXEC_ENVP_MAX, USER_EXEC_STRING_MAX)?;
        Ok(ExecveUserInput { filename, argv, envp })
    }
}

impl<'a> ApeManager<'a> {
    pub(crate) fn with_user_session<T, F>(&mut self, pid: usize, f: F) -> Result<T, Error>
    where
        F: FnOnce(&mut UserAccessSession<'_, 'a, LruPolicy>) -> Result<T, Error>,
    {
        let mut sess =
            UserAccessSession::new(self, pid, USER_SHARED_PAGE_POOL_SLOTS, LruPolicy::new());
        let result = f(&mut sess);
        let cleanup = sess.finish();

        match (result, cleanup) {
            (Err(e), _) => Err(e),
            (Ok(_), Err(e)) => Err(e),
            (Ok(v), Ok(())) => Ok(v),
        }
    }

    pub fn copy_from_user(
        &mut self,
        pid: usize,
        user_src: usize,
        dst: &mut [u8],
    ) -> Result<(), Error> {
        self.with_user_session(pid, |sess| sess.copy_from_user(user_src, dst))
    }

    pub fn copy_to_user(&mut self, pid: usize, user_dst: usize, src: &[u8]) -> Result<(), Error> {
        self.with_user_session(pid, |sess| sess.copy_to_user(user_dst, src))
    }

    pub fn write_zeros_to_user(
        &mut self,
        pid: usize,
        user_ptr: usize,
        len: usize,
    ) -> Result<(), Error> {
        if user_ptr == 0 || len == 0 {
            return Ok(());
        }

        let mut done = 0usize;
        let zeros = [0u8; 64];
        while done < len {
            let chunk = min(len - done, zeros.len());
            self.copy_to_user(pid, user_ptr + done, &zeros[..chunk])?;
            done += chunk;
        }
        Ok(())
    }

    pub fn strncpy_from_user(
        &mut self,
        pid: usize,
        user_src: usize,
        max_len: usize,
    ) -> Result<String, Error> {
        self.with_user_session(pid, |sess| sess.strncpy_from_user(user_src, max_len))
    }

    pub fn parse_execve_user_input(
        &mut self,
        pid: usize,
        filename_ptr: usize,
        argv_ptr: usize,
        envp_ptr: usize,
    ) -> Result<ExecveUserInput, Error> {
        self.with_user_session(pid, |sess| {
            sess.parse_execve_user_input(filename_ptr, argv_ptr, envp_ptr)
        })
    }

    pub(crate) fn write_obj_to_user<T>(
        &mut self,
        pid: usize,
        user_ptr: usize,
        obj: &T,
    ) -> Result<(), Error> {
        let bytes =
            unsafe { core::slice::from_raw_parts((obj as *const T) as *const u8, size_of::<T>()) };
        self.copy_to_user(pid, user_ptr, bytes)
    }
}
