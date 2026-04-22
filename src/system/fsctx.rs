use crate::ApeManager;
use crate::ape::path::path_inside_root;
use crate::ape::process::{FileType as ApeFileType, NormalHandleBackend};
use crate::ape::user::USER_PATH_MAX;
use alloc::string::String;
use glenda::error::Error;
use glenda::interface::{FileHandleService, FileSystemService};
use glenda::ipc::Badge;
use glenda::protocol::fs::FileType as FsFileType;

#[inline]
fn is_dir_mode(mode: u32) -> bool {
    ((mode as usize) & FsFileType::S_IFMT.bits()) == FsFileType::S_IFDIR.bits()
}

pub(crate) fn do_getcwd(
    mgr: &mut ApeManager<'_>,
    pid: usize,
    buf_ptr: usize,
    size: usize,
) -> Result<isize, Error> {
    if buf_ptr == 0 {
        return Err(Error::InvalidAddress);
    }
    if size == 0 {
        return Err(Error::InvalidArgs);
    }

    let (root_dir, cwd_abs) = {
        let process = mgr.get_process(pid).ok_or(Error::NotFound)?;
        (process.root_dir.clone(), process.cwd.clone())
    };

    let guest_cwd = path_inside_root(&cwd_abs, &root_dir).unwrap_or_else(|| String::from("/"));
    let bytes = guest_cwd.as_bytes();
    let need = bytes.len().checked_add(1).ok_or(Error::OutOfMemory)?;
    if need > size {
        return Err(Error::MessageTooLong);
    }

    mgr.copy_to_user(pid, buf_ptr, bytes)?;
    let nul_ptr = buf_ptr.checked_add(bytes.len()).ok_or(Error::OutOfMemory)?;
    mgr.copy_to_user(pid, nul_ptr, &[0])?;
    Ok(need as isize)
}

pub(crate) fn do_chdir(
    mgr: &mut ApeManager<'_>,
    pid: usize,
    path_ptr: usize,
) -> Result<isize, Error> {
    if path_ptr == 0 {
        return Err(Error::InvalidAddress);
    }

    let raw_path = mgr.strncpy_from_user(pid, path_ptr, USER_PATH_MAX)?;
    if raw_path.is_empty() {
        return Err(Error::NotFound);
    }

    let resolved = mgr.resolve_path_for_process(pid, &raw_path)?;
    let st = mgr.fs_client.stat_path(Badge::null(), &resolved)?;
    if !is_dir_mode(st.mode) {
        return Err(Error::InvalidArgs);
    }

    let process = mgr.get_process_mut(pid).ok_or(Error::NotFound)?;
    process.cwd = resolved;
    Ok(0)
}

pub(crate) fn do_fchdir(mgr: &mut ApeManager<'_>, pid: usize, fd: usize) -> Result<isize, Error> {
    let fd = u32::try_from(fd).map_err(|_| Error::InvalidSlot)?;

    let target_cwd = {
        let process = mgr.get_process(pid).ok_or(Error::NotFound)?;
        let handle = process.fds.get(&fd).ok_or(Error::InvalidSlot)?;
        let path = process.fd_paths.get(&fd).cloned().ok_or(Error::InvalidArgs)?;

        match &handle.file_type {
            ApeFileType::Normal(normal) => {
                if !matches!(normal.backend, NormalHandleBackend::Fs) {
                    return Err(Error::InvalidArgs);
                }
                let st = normal.fs_client.stat(Badge::null())?;
                if !is_dir_mode(st.mode) {
                    return Err(Error::InvalidArgs);
                }
                path
            }
            _ => return Err(Error::InvalidArgs),
        }
    };

    let process = mgr.get_process_mut(pid).ok_or(Error::NotFound)?;
    process.cwd = target_cwd;
    Ok(0)
}

pub(crate) fn do_chroot(
    mgr: &mut ApeManager<'_>,
    pid: usize,
    path_ptr: usize,
) -> Result<isize, Error> {
    if path_ptr == 0 {
        return Err(Error::InvalidAddress);
    }

    let raw_path = mgr.strncpy_from_user(pid, path_ptr, USER_PATH_MAX)?;
    if raw_path.is_empty() {
        return Err(Error::NotFound);
    }

    let resolved = mgr.resolve_path_for_process(pid, &raw_path)?;
    let st = mgr.fs_client.stat_path(Badge::null(), &resolved)?;
    if !is_dir_mode(st.mode) {
        return Err(Error::InvalidArgs);
    }

    let process = mgr.get_process_mut(pid).ok_or(Error::NotFound)?;
    process.root_dir = resolved.clone();
    process.cwd = resolved;
    Ok(0)
}
