use crate::ApeManager;
use crate::ape::process::{MemoryMap, MemoryType};
use crate::elf::{ElfFile, PF_W, PF_X, PT_LOAD};
use alloc::vec::Vec;
use core::cmp::min;
use glenda::arch::mem::PGSIZE;
use glenda::cap::{CapPtr, CapType, Frame, TCB, VSpace};
use glenda::error::Error;
use glenda::interface::{
    CSpaceService, FileHandleService, FileSystemService, ProcessService, ResourceService,
    ThreadService, VSpaceService,
};
use glenda::ipc::Badge;
use glenda::log;
use glenda::mem::Perms;
use glenda::protocol::fs::OpenFlags;
use glenda::utils::align::{align_down, align_up};
use glenda::utils::manager::{CSpaceManager, VSpaceManager};

pub fn sys_execve<'a>(
    mgr: &mut ApeManager<'a>,
    pid: usize,
    filename_ptr: usize,
    argv_ptr: usize,
    envp_ptr: usize,
) -> Result<usize, Error> {
    log!("execve: pid {} executing from ptr {:#x}", pid, filename_ptr);

    let path = ""; // TODO: get from filename_ptr
    let stat = mgr.fs_client.stat_path(Badge::new(pid), path)?;
    let size = stat.size as usize;

    // Check if we need to open
    let fd = mgr.fs_client.open(Badge::new(pid), path, OpenFlags::O_RDONLY, 0)?;

    let num_pages = align_up(size, PGSIZE) / PGSIZE;
    let dest_cap = mgr.cspace_mgr.alloc(&mut *mgr.res_client)?;
    mgr.res_client.alloc(Badge::null(), CapType::Frame, num_pages, dest_cap)?;
    let frame = Frame::from(dest_cap);

    let scratch_vaddr = mgr.vspace_mgr.map_scratch(
        frame,
        Perms::READ | Perms::WRITE,
        num_pages,
        &mut *mgr.res_client,
        &mut *mgr.cspace_mgr,
    )?;

    let dest_slice =
        unsafe { core::slice::from_raw_parts_mut(scratch_vaddr as *mut u8, num_pages * PGSIZE) };

    let mut offset = 0;
    while offset < size {
        let read_len =
            mgr.fs_client.read(Badge::new(pid), offset, &mut dest_slice[offset..size])?;
        if read_len == 0 {
            break;
        }
        offset += read_len;
    }
    mgr.fs_client.close(Badge::new(pid))?;

    // In a real execve, unmap current user process image, setup new elf, etc.
    let elf = ElfFile::new(&dest_slice[..size]).map_err(|_| Error::InvalidArgs)?;
    let _entry_point = elf.entry_point();

    mgr.vspace_mgr.unmap(scratch_vaddr, num_pages)?;

    Ok(0)
}

pub fn sys_getpid<'a>(mgr: &mut ApeManager<'a>, pid: usize) -> Result<isize, Error> {
    Ok(pid as isize)
}

pub fn sys_getppid<'a>(mgr: &mut ApeManager<'a>, pid: usize) -> Result<isize, Error> {
    let process = mgr.get_process(pid).ok_or(Error::Unknown)?;
    Ok(process.parent_pid as isize)
}

pub fn sys_fork<'a>(mgr: &mut ApeManager<'a>, pid: usize) -> Result<usize, Error> {
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
        let parent = mgr.get_process(pid).ok_or(Error::Unknown)?;
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

    Ok(child_pid)
}
