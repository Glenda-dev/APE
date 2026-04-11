use crate::ApeManager;
use crate::ape::process::{AsyncIoState, FileHandle, FileType, NormalFileHandle};
use crate::ape::user::USER_PATH_MAX;
use alloc::vec;
use core::cmp::min;
use glenda::cap::{CSPACE_CAP, CapPtr, Endpoint, Frame, Rights};
use glenda::client::FsClient;
use glenda::error::Error;
use glenda::interface::{CSpaceService, FileHandleService, FileSystemService};
use glenda::io::uring::{
    IOURING_OP_READ, IOURING_OP_WRITE, IoUringBuffer, IoUringClient, IoUringSqe,
};
use glenda::ipc::{Badge, MsgFlags, MsgTag, UTCB};
use glenda::log;
use linux_raw_sys::errno::ENOSYS;

const FS_ASYNC_REGION_SIZE: usize = 64 * 1024;
const FS_ASYNC_RING_SIZE: usize = 4096;
const FS_ASYNC_DATA_OFFSET: usize = FS_ASYNC_RING_SIZE;
const FS_ASYNC_SQ_ENTRIES: u32 = 16;
const FS_ASYNC_CQ_ENTRIES: u32 = 16;

fn async_submit_and_wait(
    normal: &mut NormalFileHandle,
    opcode: u8,
    requested_len: usize,
) -> Result<usize, Error> {
    let user_data = normal.async_io.next_user_data;
    normal.async_io.next_user_data = normal.async_io.next_user_data.wrapping_add(1);

    let sqe = IoUringSqe {
        opcode,
        off: normal.offset,
        addr: normal.async_io.data_vaddr,
        len: requested_len as u32,
        user_data,
        ..Default::default()
    };
    normal.async_io.ring.submit(sqe)?;

    for _ in 0..16 {
        normal.fs_client.process_iouring()?;
        while let Some(cqe) = normal.async_io.ring.pop_completion() {
            if cqe.user_data != user_data {
                continue;
            }
            if cqe.res < 0 {
                return Err(Error::IoError);
            }
            return Ok(min(cqe.res as usize, requested_len));
        }
    }

    Err(Error::WouldBlock)
}

pub fn sys_read<'a>(
    mgr: &mut ApeManager<'a>,
    pid: usize,
    fd: usize,
    buf_ptr: usize,
    len: usize,
) -> Result<isize, Error> {
    log!("sys_read: pid {} fd {} buf {:#x} len {}", pid, fd, buf_ptr, len);
    if len == 0 {
        return Ok(0);
    }
    let fd = u32::try_from(fd).map_err(|_| Error::InvalidSlot)?;
    let mut handle = {
        let process = mgr.get_process_mut(pid).ok_or(Error::NotFound)?;
        process.fds.remove(&fd).ok_or(Error::InvalidSlot)?
    };

    let result = match &mut handle.file_type {
        FileType::Terminal(term) => {
            let mut utcb = unsafe { UTCB::new() };
            let tag = MsgTag::new(
                glenda::protocol::TERMINAL_PROTO,
                glenda::protocol::terminal::TERM_GET_STR,
                MsgFlags::HAS_BUFFER,
            );
            utcb.set_mr(0, len);
            utcb.set_msg_tag(tag);
            term.endpoint().call(utcb)?;
            utcb.error_check()?;

            let read_len = min(utcb.get_mr(0), min(len, utcb.buffer().len()));
            if read_len > 0 {
                mgr.copy_to_user(pid, buf_ptr, &utcb.buffer()[..read_len])?;
                log!("sys_read: terminal read {} bytes", read_len);
            }
            Ok(read_len as isize)
        }
        FileType::Normal(normal) => {
            let mut total = 0usize;
            while total < len {
                let chunk = min(len - total, normal.async_io.data_len);
                if chunk == 0 {
                    break;
                }

                let read_len = async_submit_and_wait(normal, IOURING_OP_READ, chunk)?;
                if read_len == 0 {
                    break;
                }

                let src = unsafe {
                    core::slice::from_raw_parts(normal.async_io.data_vaddr as *const u8, read_len)
                };
                let user_dst = buf_ptr.checked_add(total).ok_or(Error::InvalidAddress)?;
                mgr.copy_to_user(pid, user_dst, src)?;

                total += read_len;
                normal.offset = normal.offset.saturating_add(read_len);

                if read_len < chunk {
                    break;
                }
            }
            Ok(total as isize)
        }
    };

    let process = mgr.get_process_mut(pid).ok_or(Error::NotFound)?;
    process.fds.insert(fd, handle);
    result
}

pub fn sys_write<'a>(
    mgr: &mut ApeManager<'a>,
    pid: usize,
    fd: usize,
    buf_ptr: usize,
    len: usize,
) -> Result<isize, Error> {
    log!("sys_write: pid {} fd {} buf {:#x} len {}", pid, fd, buf_ptr, len);
    if len == 0 {
        return Ok(0);
    }
    let fd = u32::try_from(fd).map_err(|_| Error::InvalidSlot)?;
    let mut handle = {
        let process = mgr.get_process_mut(pid).ok_or(Error::NotFound)?;
        process.fds.remove(&fd).ok_or(Error::InvalidSlot)?
    };

    let result = match &mut handle.file_type {
        FileType::Terminal(term) => {
            let mut kbuf = vec![0u8; len];
            mgr.copy_from_user(pid, buf_ptr, &mut kbuf)?;

            let mut utcb = unsafe { UTCB::new() };
            let tag = MsgTag::new(
                glenda::protocol::TERMINAL_PROTO,
                glenda::protocol::terminal::TERM_PUT_STR,
                MsgFlags::HAS_BUFFER,
            );
            let copied = utcb.write(&kbuf);
            utcb.set_msg_tag(tag);
            term.endpoint().call(utcb)?;
            utcb.error_check()?;

            let written = if utcb.get_mr(0) > 0 { min(utcb.get_mr(0), copied) } else { copied };
            Ok(written as isize)
        }
        FileType::Normal(normal) => {
            let mut total = 0usize;
            while total < len {
                let chunk = min(len - total, normal.async_io.data_len);
                if chunk == 0 {
                    break;
                }

                let dst = unsafe {
                    core::slice::from_raw_parts_mut(
                        normal.async_io.data_vaddr as *mut u8,
                        normal.async_io.data_len,
                    )
                };
                let user_src = buf_ptr.checked_add(total).ok_or(Error::InvalidAddress)?;
                mgr.copy_from_user(pid, user_src, &mut dst[..chunk])?;

                let written = async_submit_and_wait(normal, IOURING_OP_WRITE, chunk)?;
                total += written;
                normal.offset = normal.offset.saturating_add(written);

                if written < chunk {
                    break;
                }
            }
            Ok(total as isize)
        }
    };

    let process = mgr.get_process_mut(pid).ok_or(Error::NotFound)?;
    process.fds.insert(fd, handle);
    result
}

pub fn sys_openat<'a>(
    mgr: &mut ApeManager<'a>,
    pid: usize,
    dirfd: usize,
    pathname: usize,
    flags: usize,
    mode: usize,
) -> Result<isize, Error> {
    let path = mgr.strncpy_from_user(pid, pathname, USER_PATH_MAX)?;
    let translated_path = mgr.resolve_path_for_process(pid, &path)?;
    log!(
        "sys_openat: pid {} dirfd {} path={} translated={} flags={:#x} mode={:#x}",
        pid,
        dirfd,
        path,
        translated_path,
        flags,
        mode
    );

    let fs_badge = mgr.take_next_fs_handle_badge();
    let fs_ep_slot = mgr.cspace_mgr.alloc(&mut *mgr.res_client)?;
    CSPACE_CAP.mint_self(
        mgr.fs_client.endpoint().cap(),
        fs_ep_slot,
        glenda::ipc::Badge::new(fs_badge),
        Rights::ALL,
    )?;

    let mut fs_client = FsClient::new(Endpoint::from(fs_ep_slot));
    let open_flags = glenda::protocol::fs::OpenFlags::from_bits_truncate(flags);
    if let Err(e) = fs_client.open(Badge::null(), &translated_path, open_flags, mode as u32) {
        let _ = CSPACE_CAP.delete(fs_ep_slot);
        mgr.cspace_mgr.free(fs_ep_slot);
        return Err(e);
    }

    let region = match mgr.allocate_fs_async_region(FS_ASYNC_REGION_SIZE) {
        Ok(region) => region,
        Err(e) => {
            let _ = fs_client.close(Badge::null());
            let _ = CSPACE_CAP.delete(fs_ep_slot);
            mgr.cspace_mgr.free(fs_ep_slot);
            return Err(e);
        }
    };

    let ring_buf = unsafe {
        IoUringBuffer::new(
            region.vaddr as *mut u8,
            FS_ASYNC_RING_SIZE,
            FS_ASYNC_SQ_ENTRIES,
            FS_ASYNC_CQ_ENTRIES,
        )
    };
    let mut ring = IoUringClient::new(ring_buf);
    ring.set_server_notify(Endpoint::from(fs_ep_slot));

    if let Err(e) = fs_client.setup_iouring(
        Badge::null(),
        region.vaddr,
        region.size,
        Some(Frame::from(region.frame_slot)),
    ) {
        let _ = fs_client.close(Badge::null());
        let _ = CSPACE_CAP.delete(fs_ep_slot);
        mgr.cspace_mgr.free(fs_ep_slot);
        mgr.recycle_fs_async_region(region.id);
        return Err(e);
    }

    let data_vaddr = region.vaddr + FS_ASYNC_DATA_OFFSET;
    if data_vaddr >= region.vaddr + region.size {
        let _ = fs_client.close(Badge::null());
        let _ = CSPACE_CAP.delete(fs_ep_slot);
        mgr.cspace_mgr.free(fs_ep_slot);
        mgr.recycle_fs_async_region(region.id);
        return Err(Error::OutOfMemory);
    }

    let data_len = region.size - FS_ASYNC_DATA_OFFSET;
    let process = mgr.get_process_mut(pid).ok_or(Error::NotFound)?;
    let fd = process.next_fd;
    process.next_fd += 1;
    process.fds.insert(
        fd,
        FileHandle {
            file_type: FileType::Normal(NormalFileHandle {
                fs_client,
                fs_ep_slot,
                offset: 0,
                async_io: AsyncIoState {
                    region_id: region.id,
                    ring,
                    data_vaddr,
                    data_len,
                    next_user_data: 1,
                },
            }),
        },
    );

    Ok(fd as isize)
}

pub fn sys_close<'a>(mgr: &mut ApeManager<'a>, pid: usize, fd: usize) -> Result<isize, Error> {
    log!("sys_close: pid {} fd {}", pid, fd);
    let fd = u32::try_from(fd).map_err(|_| Error::InvalidSlot)?;
    let handle = {
        let process = mgr.get_process_mut(pid).ok_or(Error::NotFound)?;
        process.fds.remove(&fd).ok_or(Error::InvalidSlot)?
    };
    match handle.file_type {
        FileType::Terminal(_) => {}
        FileType::Normal(mut normal) => {
            let _ = normal.fs_client.close(Badge::null());
            let _ = CSPACE_CAP.delete(normal.fs_ep_slot);
            mgr.cspace_mgr.free(normal.fs_ep_slot);
            mgr.recycle_fs_async_region(normal.async_io.region_id);
        }
    }

    Ok(0)
}

// TODO: Impl
pub fn sys_ioctl<'a>(
    mgr: &mut ApeManager<'a>,
    pid: usize,
    fd: usize,
    request: usize,
    argp: usize,
) -> Result<isize, Error> {
    log!("sys_ioctl: pid {} fd {} request {:#x} argp {:#x}", pid, fd, request, argp);
    Ok(ENOSYS as isize)
}
