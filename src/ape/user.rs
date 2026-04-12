use crate::ApeManager;
use crate::ape::policy::SharedPagePoolPolicy;
use crate::ape::policy::lru::LruPolicy;
use crate::ape::process::MemoryMap;
use alloc::string::String;
use alloc::vec::Vec;
use core::cmp::min;
use core::mem::size_of;
use glenda::arch::mem::PGSIZE;
use glenda::cap::{CapPtr, Frame};
use glenda::error::Error;
use glenda::interface::VSpaceService;
use glenda::mem::Perms;
use glenda::utils::align::align_up;

/// 对齐 Linux PATH_MAX 的常见值。
pub const USER_PATH_MAX: usize = 4096;
pub const USER_EXEC_ARGV_MAX: usize = 256;
pub const USER_EXEC_ENVP_MAX: usize = 256;
pub const USER_EXEC_STRING_MAX: usize = 4096;
pub const USER_SHARED_PAGE_POOL_SLOTS: usize = 8;

#[derive(Debug, Clone)]
pub struct ExecveUserInput {
    pub filename: String,
    pub argv: Vec<String>,
    pub envp: Vec<String>,
}

#[derive(Debug, Clone)]
struct CachedUserMapping {
    frame_cap: usize,
    map_vaddr: usize,
    map_size: usize,
    pages: usize,
    scratch_vaddr: usize,
    perms: Perms,
}

struct SharedPagePool<P: SharedPagePoolPolicy> {
    entries: Vec<Option<CachedUserMapping>>,
    occupied: Vec<bool>,
    policy: P,
}

impl<P: SharedPagePoolPolicy> SharedPagePool<P> {
    fn new(capacity: usize, policy: P) -> Self {
        Self {
            entries: (0..capacity).map(|_| None).collect(),
            occupied: alloc::vec![false; capacity],
            policy,
        }
    }

    fn find_hit(&self, map: &MemoryMap, perms: Perms) -> Option<usize> {
        self.entries.iter().position(|entry| {
            entry.as_ref().is_some_and(|e| {
                e.frame_cap == map.frame_cap
                    && e.map_vaddr == map.vaddr
                    && e.map_size == map.size
                    && e.perms.bits() == perms.bits()
            })
        })
    }

    fn unmap_slot<'a>(&mut self, mgr: &mut ApeManager<'a>, slot: usize) -> Result<(), Error> {
        if !self.occupied.get(slot).copied().unwrap_or(false) {
            return Ok(());
        }

        if let Some(entry) = self.entries[slot].take() {
            mgr.vspace_mgr.unmap(entry.scratch_vaddr, entry.pages)?;
        }
        self.occupied[slot] = false;
        self.policy.remove(slot);
        Ok(())
    }

    fn pick_slot(&mut self) -> Result<usize, Error> {
        if let Some(slot) = self.occupied.iter().position(|used| !*used) {
            return Ok(slot);
        }
        self.policy.victim(&self.occupied).ok_or(Error::OutOfMemory)
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
        let frame = Frame::from(CapPtr::from(map.frame_cap));
        let scratch_vaddr = mgr.vspace_mgr.map_scratch(
            frame,
            perms,
            pages,
            &mut *mgr.res_client,
            &mut *mgr.cspace_mgr,
        )?;

        self.entries[slot] = Some(CachedUserMapping {
            frame_cap: map.frame_cap,
            map_vaddr: map.vaddr,
            map_size: map.size,
            pages,
            scratch_vaddr,
            perms,
        });
        self.occupied[slot] = true;
        self.policy.insert(slot);

        Ok(scratch_vaddr)
    }

    fn release_all<'a>(&mut self, mgr: &mut ApeManager<'a>) -> Result<(), Error> {
        let mut first_err = None;
        for slot in 0..self.entries.len() {
            if self.occupied[slot]
                && let Err(e) = self.unmap_slot(mgr, slot)
                && first_err.is_none()
            {
                first_err = Some(e);
            }
        }

        if let Some(e) = first_err { Err(e) } else { Ok(()) }
    }
}

pub(crate) struct UserAccessSession<'m, 'a, P: SharedPagePoolPolicy> {
    mgr: &'m mut ApeManager<'a>,
    pid: usize,
    pool: SharedPagePool<P>,
}

impl<'m, 'a, P: SharedPagePoolPolicy> UserAccessSession<'m, 'a, P> {
    fn new(mgr: &'m mut ApeManager<'a>, pid: usize, pool_capacity: usize, policy: P) -> Self {
        Self { mgr, pid, pool: SharedPagePool::new(pool_capacity, policy) }
    }

    fn finish(&mut self) -> Result<(), Error> {
        self.pool.release_all(self.mgr)
    }

    fn lookup_map(&self, user_addr: usize, required: Perms) -> Result<MemoryMap, Error> {
        let map = {
            let process = self.mgr.get_process(self.pid).ok_or(Error::NotFound)?;
            process.lookup_memory_map(user_addr).cloned()
        }
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

            // RISC-V 要求可写页同时具备可读属性（W=1 且 R=0 为无效叶子 PTE）。
            // 对用户页执行 copy_to_user 时，scratch 映射必须至少是 RW，
            // 否则在 memcpy 写入路径上可能触发 page fault。
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

    /// Linux 风格 `copy_from_user`：从用户地址空间复制到内核缓冲区。
    pub fn copy_from_user(
        &mut self,
        pid: usize,
        user_src: usize,
        dst: &mut [u8],
    ) -> Result<(), Error> {
        self.with_user_session(pid, |sess| sess.copy_from_user(user_src, dst))
    }

    /// Linux 风格 `copy_to_user`：从内核缓冲区复制到用户地址空间。
    pub fn copy_to_user(&mut self, pid: usize, user_dst: usize, src: &[u8]) -> Result<(), Error> {
        self.with_user_session(pid, |sess| sess.copy_to_user(user_dst, src))
    }

    /// Linux 风格 `strncpy_from_user`：读取用户态 NUL 结尾字符串。
    ///
    /// - 成功：返回不带结尾 NUL 的 Rust `String`。
    /// - 失败：
    ///   - 无效地址/权限返回 `InvalidAddress`；
    ///   - 超过 `max_len` 仍未遇到 NUL 返回 `MessageTooLong`。
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
}
