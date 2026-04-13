use crate::ApeManager;
use crate::ape::path::resolve_path;
use crate::ape::process::FileType;
use crate::ape::user::USER_PATH_MAX;
use crate::ape::utils::linux_conv::{fs_stat_to_linux_stat, make_linux_char_device_stat};
use crate::ape::utils::write_obj_to_user;
use glenda::error::Error;
use glenda::interface::{FileHandleService, FileSystemService};
use glenda::ipc::Badge;
use linux_raw_sys::general::{
    AT_EMPTY_PATH, AT_FDCWD, AT_NO_AUTOMOUNT, AT_SYMLINK_NOFOLLOW, S_IFCHR, S_IFDIR, S_IFMT,
    stat,
};

const FSTATAT_ALLOWED_FLAGS: u32 = AT_SYMLINK_NOFOLLOW | AT_EMPTY_PATH | AT_NO_AUTOMOUNT;

#[inline]
fn at_fdcwd(dirfd: usize) -> bool {
    (dirfd as isize) == (AT_FDCWD as isize)
}

#[inline]
fn is_dir_mode(mode: u32) -> bool {
    (mode & S_IFMT) == S_IFDIR
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
            }
        };

        write_obj_to_user(mgr, pid, statbuf, &st)?;
        return Ok(0);
    }

    let resolved = if raw_path.starts_with('/') || at_fdcwd(dirfd) {
        mgr.resolve_path_for_process(pid, &raw_path)?
    } else {
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
                _ => return Err(Error::InvalidArgs),
            }

            (
                process.root_dir.clone(),
                process.fd_paths.get(&fd).cloned().ok_or(Error::InvalidArgs)?,
            )
        };
        resolve_path(&raw_path, &root_dir, &dir_path)
    };

    let fs_stat = if (flags & AT_SYMLINK_NOFOLLOW) != 0 {
        mgr.fs_client.lstat_path(Badge::null(), &resolved)?
    } else {
        mgr.fs_client.stat_path(Badge::null(), &resolved)?
    };

    let st = fs_stat_to_linux_stat(fs_stat);
    write_obj_to_user(mgr, pid, statbuf, &st)?;
    Ok(0)
}
