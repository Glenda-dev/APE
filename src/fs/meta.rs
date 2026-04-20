use crate::ApeManager;
use crate::ape::path::resolve_path;
use crate::ape::process::FileType;
use crate::ape::user::USER_PATH_MAX;
use crate::ape::utils::linux_conv::{fs_stat_to_linux_stat, make_linux_char_device_stat};
use alloc::string::String;
use glenda::cap::CSPACE_CAP;
use glenda::error::Error;
use glenda::interface::{
    CSpaceService, FileHandleService, FileSystemService, VirtualFileSystemService, VolumeService,
};
use glenda::ipc::Badge;
use linux_raw_sys::general::{
    AT_EMPTY_PATH, AT_FDCWD, AT_NO_AUTOMOUNT, AT_REMOVEDIR, AT_SYMLINK_FOLLOW, AT_SYMLINK_NOFOLLOW,
    MNT_DETACH, MNT_EXPIRE, MNT_FORCE, S_IFCHR, S_IFDIR, S_IFMT, UMOUNT_NOFOLLOW, stat,
};

const FSTATAT_ALLOWED_FLAGS: u32 = AT_SYMLINK_NOFOLLOW | AT_EMPTY_PATH | AT_NO_AUTOMOUNT;
const LINKAT_ALLOWED_FLAGS: u32 = AT_SYMLINK_FOLLOW | AT_EMPTY_PATH;
const UMOUNT2_ALLOWED_FLAGS: u32 = MNT_FORCE | MNT_DETACH | MNT_EXPIRE | UMOUNT_NOFOLLOW;

#[inline]
fn at_fdcwd(dirfd: usize) -> bool {
    (dirfd as isize) == (AT_FDCWD as isize)
}

#[inline]
fn is_dir_mode(mode: u32) -> bool {
    (mode & S_IFMT) == S_IFDIR
}

fn resolve_path_at(
    mgr: &mut ApeManager<'_>,
    pid: usize,
    dirfd: usize,
    raw_path: &str,
) -> Result<alloc::string::String, Error> {
    if raw_path.starts_with('/') || at_fdcwd(dirfd) {
        return mgr.resolve_path_for_process(pid, raw_path);
    }

    let fd = u32::try_from(dirfd).map_err(|_| Error::InvalidSlot)?;
    let (root_dir, dir_path) = {
        let process = mgr.get_process(pid).ok_or(Error::NotFound)?;
        let handle = process.fds.get(&fd).ok_or(Error::InvalidSlot)?;
        match handle.file_type {
            FileType::Normal(normal) => {
                let st = normal.fs_client.stat(Badge::null())?;
                if !is_dir_mode(st.mode) {
                    return Err(Error::InvalidArgs);
                }
            }
            FileType::Terminal(_)
            | FileType::PtyMaster(_)
            | FileType::PtySlave(_)
            | FileType::PseudoChar(_)
            | FileType::PipeRead(_)
            | FileType::PipeWrite(_) => return Err(Error::InvalidArgs),
        }

        (process.root_dir.clone(), process.fd_paths.get(&fd).cloned().ok_or(Error::InvalidArgs)?)
    };

    Ok(resolve_path(raw_path, &root_dir, &dir_path))
}

fn read_path_arg(mgr: &mut ApeManager<'_>, pid: usize, ptr: usize) -> Result<String, Error> {
    if ptr == 0 {
        return Err(Error::InvalidAddress);
    }
    let raw = mgr.strncpy_from_user(pid, ptr, USER_PATH_MAX)?;
    if raw.is_empty() {
        return Err(Error::NotFound);
    }
    mgr.resolve_path_for_process(pid, &raw)
}

fn close_slot(mgr: &mut ApeManager<'_>, slot: glenda::cap::CapPtr) {
    if !slot.is_null() {
        let _ = CSPACE_CAP.delete(slot);
        mgr.cspace_mgr.free(slot);
    }
}

pub(crate) fn do_fstat<'a>(
    mgr: &mut ApeManager<'a>,
    pid: usize,
    fd: usize,
    statbuf: usize,
) -> Result<isize, Error> {
    if statbuf == 0 {
        return Err(Error::InvalidAddress);
    }

    let fd = u32::try_from(fd).map_err(|_| Error::InvalidSlot)?;
    let st = {
        let process = mgr.get_process(pid).ok_or(Error::NotFound)?;
        let handle = process.fds.get(&fd).ok_or(Error::InvalidSlot)?;
        match handle.file_type {
            FileType::Normal(normal) => {
                fs_stat_to_linux_stat(normal.fs_client.stat(Badge::null())?)
            }
            FileType::Terminal(_) => make_linux_char_device_stat(fd as usize),
            FileType::PtyMaster(master) => make_linux_char_device_stat(master.vt_id),
            FileType::PtySlave(slave) => make_linux_char_device_stat(slave.vt_id),
            FileType::PseudoChar(_) => make_linux_char_device_stat(fd as usize),
            FileType::PipeRead(_) | FileType::PipeWrite(_) => return Err(Error::InvalidArgs),
        }
    };

    mgr.write_obj_to_user(pid, statbuf, &st)?;
    Ok(0)
}

pub(crate) fn do_mkdirat<'a>(
    mgr: &mut ApeManager<'a>,
    pid: usize,
    dirfd: usize,
    pathname: usize,
    mode: usize,
) -> Result<isize, Error> {
    if pathname == 0 {
        return Err(Error::InvalidAddress);
    }

    let raw_path = mgr.strncpy_from_user(pid, pathname, USER_PATH_MAX)?;
    if raw_path.is_empty() {
        return Err(Error::NotFound);
    }

    let resolved = resolve_path_at(mgr, pid, dirfd, &raw_path)?;
    mgr.fs_client.mkdir(Badge::null(), &resolved, mode as u32)?;
    Ok(0)
}

pub(crate) fn do_unlinkat<'a>(
    mgr: &mut ApeManager<'a>,
    pid: usize,
    dirfd: usize,
    pathname: usize,
    flags: usize,
) -> Result<isize, Error> {
    if pathname == 0 {
        return Err(Error::InvalidAddress);
    }

    let flags = u32::try_from(flags).map_err(|_| Error::InvalidArgs)?;
    if flags & !AT_REMOVEDIR != 0 {
        return Err(Error::InvalidArgs);
    }

    let raw_path = mgr.strncpy_from_user(pid, pathname, USER_PATH_MAX)?;
    if raw_path.is_empty() {
        return Err(Error::NotFound);
    }

    let resolved = resolve_path_at(mgr, pid, dirfd, &raw_path)?;
    let st = mgr.fs_client.stat_path(Badge::null(), &resolved)?;
    if (flags & AT_REMOVEDIR) != 0 {
        if !is_dir_mode(st.mode) {
            return Err(Error::InvalidArgs);
        }
    } else if is_dir_mode(st.mode) {
        return Err(Error::InvalidArgs);
    }

    mgr.fs_client.unlink(Badge::null(), &resolved)?;
    Ok(0)
}

pub(crate) fn do_linkat<'a>(
    mgr: &mut ApeManager<'a>,
    pid: usize,
    olddirfd: usize,
    oldpath: usize,
    newdirfd: usize,
    newpath: usize,
    flags: usize,
) -> Result<isize, Error> {
    if oldpath == 0 || newpath == 0 {
        return Err(Error::InvalidAddress);
    }

    let flags = u32::try_from(flags).map_err(|_| Error::InvalidArgs)?;
    if flags & !LINKAT_ALLOWED_FLAGS != 0 {
        return Err(Error::InvalidArgs);
    }

    let old_raw = mgr.strncpy_from_user(pid, oldpath, USER_PATH_MAX)?;
    let new_raw = mgr.strncpy_from_user(pid, newpath, USER_PATH_MAX)?;
    if old_raw.is_empty() || new_raw.is_empty() {
        return Err(Error::NotFound);
    }

    if (flags & AT_EMPTY_PATH) != 0 {
        // TODO: support AT_EMPTY_PATH by resolving olddirfd file-handle targets directly.
        return Err(Error::NotSupported);
    }

    let old_resolved = resolve_path_at(mgr, pid, olddirfd, &old_raw)?;
    let new_resolved = resolve_path_at(mgr, pid, newdirfd, &new_raw)?;
    if old_resolved == new_resolved {
        return Err(Error::AlreadyExists);
    }

    let st = mgr.fs_client.stat_path(Badge::null(), &old_resolved)?;
    if is_dir_mode(st.mode) {
        return Err(Error::InvalidArgs);
    }

    if (flags & AT_SYMLINK_FOLLOW) != 0 {
        // TODO: plumb AT_SYMLINK_FOLLOW/no-follow semantics through VFS path resolution.
    }

    mgr.fs_client.link(Badge::null(), &old_resolved, &new_resolved)?;
    Ok(0)
}

pub(crate) fn do_utimensat<'a>(
    mgr: &mut ApeManager<'a>,
    pid: usize,
    dirfd: usize,
    pathname: usize,
    _times: usize,
    flags: usize,
) -> Result<isize, Error> {
    let flags = u32::try_from(flags).map_err(|_| Error::InvalidArgs)?;
    if flags & !AT_SYMLINK_NOFOLLOW != 0 {
        return Err(Error::InvalidArgs);
    }

    if pathname == 0 {
        let fd = u32::try_from(dirfd).map_err(|_| Error::InvalidSlot)?;
        let process = mgr.get_process(pid).ok_or(Error::NotFound)?;
        let handle = process.fds.get(&fd).ok_or(Error::InvalidSlot)?;
        match handle.file_type {
            FileType::Normal(_) => Ok(0),
            _ => Err(Error::InvalidArgs),
        }
    } else {
        let raw_path = mgr.strncpy_from_user(pid, pathname, USER_PATH_MAX)?;
        if raw_path.is_empty() {
            return Err(Error::NotFound);
        }

        let resolved = resolve_path_at(mgr, pid, dirfd, &raw_path)?;
        let _ = mgr.fs_client.stat_path(Badge::null(), &resolved)?;
        Ok(0)
    }
}

pub(crate) fn do_mount<'a>(
    mgr: &mut ApeManager<'a>,
    pid: usize,
    source: usize,
    target: usize,
    _fstype: usize,
    _flags: usize,
    _data: usize,
) -> Result<isize, Error> {
    let source_raw = mgr.strncpy_from_user(pid, source, USER_PATH_MAX)?;
    if source_raw.is_empty() {
        return Err(Error::InvalidArgs);
    }

    let target_path = read_path_arg(mgr, pid, target)?;

    let recv_slot = mgr.cspace_mgr.alloc(&mut *mgr.res_client)?;
    let target_ep = match mgr.vol_client.mount_partition(Badge::null(), &source_raw, recv_slot) {
        Ok(ep) => ep,
        Err(e) => {
            close_slot(mgr, recv_slot);
            return Err(e);
        }
    };

    let result = mgr.fs_client.mount(Badge::null(), &target_path, target_ep);
    close_slot(mgr, recv_slot);
    result?;
    Ok(0)
}

pub(crate) fn do_umount2<'a>(
    mgr: &mut ApeManager<'a>,
    pid: usize,
    target: usize,
    flags: usize,
) -> Result<isize, Error> {
    let flags = u32::try_from(flags).map_err(|_| Error::InvalidArgs)?;
    if flags & !UMOUNT2_ALLOWED_FLAGS != 0 {
        return Err(Error::InvalidArgs);
    }

    let target_path = read_path_arg(mgr, pid, target)?;
    mgr.fs_client.unmount(Badge::null(), &target_path)?;
    Ok(0)
}

pub(crate) fn do_newfstatat<'a>(
    mgr: &mut ApeManager<'a>,
    pid: usize,
    dirfd: usize,
    pathname: usize,
    statbuf: usize,
    flags: usize,
) -> Result<isize, Error> {
    if statbuf == 0 {
        return Err(Error::InvalidAddress);
    }

    let flags = u32::try_from(flags).map_err(|_| Error::InvalidArgs)?;
    if flags & !FSTATAT_ALLOWED_FLAGS != 0 {
        return Err(Error::InvalidArgs);
    }

    let raw_path = mgr.strncpy_from_user(pid, pathname, USER_PATH_MAX)?;

    if raw_path.is_empty() {
        if (flags & AT_EMPTY_PATH) == 0 {
            return Err(Error::NotFound);
        }

        let st = if at_fdcwd(dirfd) {
            let cwd = mgr.get_process(pid).ok_or(Error::NotFound)?.cwd.clone();
            let fs_stat = mgr.fs_client.stat_path(Badge::null(), &cwd)?;
            fs_stat_to_linux_stat(fs_stat)
        } else {
            let fd = u32::try_from(dirfd).map_err(|_| Error::InvalidSlot)?;
            let process = mgr.get_process(pid).ok_or(Error::NotFound)?;
            let handle = process.fds.get(&fd).ok_or(Error::InvalidSlot)?;
            match handle.file_type {
                FileType::Normal(normal) => {
                    fs_stat_to_linux_stat(normal.fs_client.stat(Badge::null())?)
                }
                FileType::Terminal(_) => make_linux_char_device_stat(fd as usize),
                FileType::PtyMaster(master) => make_linux_char_device_stat(master.vt_id),
                FileType::PtySlave(slave) => make_linux_char_device_stat(slave.vt_id),
                FileType::PseudoChar(_) => make_linux_char_device_stat(fd as usize),
                FileType::PipeRead(_) | FileType::PipeWrite(_) => return Err(Error::InvalidArgs),
            }
        };

        mgr.write_obj_to_user(pid, statbuf, &st)?;
        return Ok(0);
    }

    let resolved = resolve_path_at(mgr, pid, dirfd, &raw_path)?;

    let fs_stat = if (flags & AT_SYMLINK_NOFOLLOW) != 0 {
        mgr.fs_client.lstat_path(Badge::null(), &resolved)?
    } else {
        mgr.fs_client.stat_path(Badge::null(), &resolved)?
    };

    let st = fs_stat_to_linux_stat(fs_stat);
    mgr.write_obj_to_user(pid, statbuf, &st)?;
    Ok(0)
}
