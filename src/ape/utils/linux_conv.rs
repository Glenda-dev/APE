use glenda::protocol::fs::Stat as FsStat;
use glenda::protocol::terminal::WindowSize;
use linux_raw_sys::general::{S_IFCHR, stat, winsize};

pub(crate) fn fs_stat_to_linux_stat(st: FsStat) -> stat {
    let mut out: stat = unsafe { core::mem::zeroed() };
    out.st_dev = st.dev as _;
    out.st_ino = st.ino as _;
    out.st_mode = st.mode as _;
    out.st_nlink = st.nlink as _;
    out.st_uid = st.uid as _;
    out.st_gid = st.gid as _;
    out.st_rdev = st.rdev as _;
    out.st_size = st.size as _;
    out.st_blksize = st.blksize as _;
    out.st_blocks = st.blocks as _;
    out.st_atime = st.atime as _;
    out.st_atime_nsec = 0;
    out.st_mtime = st.mtime as _;
    out.st_mtime_nsec = 0;
    out.st_ctime = st.ctime as _;
    out.st_ctime_nsec = 0;
    out
}

pub(crate) fn make_linux_char_device_stat(ino: usize) -> stat {
    let mut out: stat = unsafe { core::mem::zeroed() };
    out.st_ino = ino as _;
    out.st_mode = (S_IFCHR | 0o666) as _;
    out.st_nlink = 1;
    out.st_blksize = 4096;
    out
}

pub(crate) fn host_window_size_to_linux_winsize(ws: WindowSize) -> winsize {
    winsize { ws_row: ws.rows, ws_col: ws.cols, ws_xpixel: ws.xpixel, ws_ypixel: ws.ypixel }
}

pub(crate) fn linux_winsize_to_host_window_size(ws: winsize) -> WindowSize {
    WindowSize { rows: ws.ws_row, cols: ws.ws_col, xpixel: ws.ws_xpixel, ypixel: ws.ws_ypixel }
}

pub(crate) fn get_exit_code_for_signal(signal: u32) -> usize {
    128 + signal as usize
}
