use crate::ApeManager;
use crate::ape::tty::{TTY_TERMIOS_SIZE, TtyCompatState, ansi, ldisc};
use crate::ape::utils::linux_conv::{
    host_window_size_to_linux_winsize, linux_winsize_to_host_window_size,
};
use core::cmp::min;
use core::mem::size_of;
use glenda::client::TerminalClient;
use glenda::error::Error;
use glenda::interface::VirtualTerminalService;
use glenda::ipc::{Badge, MsgFlags, MsgTag, UTCB};
use linux_raw_sys::ctypes::c_int;
use linux_raw_sys::general::winsize;
use linux_raw_sys::ioctl::{
    TCGETS, TCSETS, TCSETSF, TCSETSW, TIOCGPGRP, TIOCGPTN, TIOCGSID, TIOCGWINSZ, TIOCNOTTY,
    TIOCSCTTY, TIOCSPGRP, TIOCSPTLCK, TIOCSWINSZ,
};

fn read_user_winsize<'a>(
    mgr: &mut ApeManager<'a>,
    pid: usize,
    user_ptr: usize,
) -> Result<winsize, Error> {
    let mut raw = [0u8; size_of::<winsize>()];
    mgr.copy_from_user(pid, user_ptr, &mut raw)?;
    Ok(unsafe { (raw.as_ptr() as *const winsize).read_unaligned() })
}

fn write_user_winsize<'a>(
    mgr: &mut ApeManager<'a>,
    pid: usize,
    user_ptr: usize,
    value: winsize,
) -> Result<(), Error> {
    let raw = unsafe {
        core::slice::from_raw_parts((&value as *const winsize) as *const u8, size_of::<winsize>())
    };
    mgr.copy_to_user(pid, user_ptr, raw)
}

fn read_user_i32<'a>(mgr: &mut ApeManager<'a>, pid: usize, user_ptr: usize) -> Result<i32, Error> {
    let mut raw = [0u8; 4];
    mgr.copy_from_user(pid, user_ptr, &mut raw)?;
    Ok(i32::from_ne_bytes(raw))
}

fn read_user_u32<'a>(mgr: &mut ApeManager<'a>, pid: usize, user_ptr: usize) -> Result<u32, Error> {
    let mut raw = [0u8; 4];
    mgr.copy_from_user(pid, user_ptr, &mut raw)?;
    Ok(u32::from_ne_bytes(raw))
}

fn write_user_u32<'a>(
    mgr: &mut ApeManager<'a>,
    pid: usize,
    user_ptr: usize,
    value: u32,
) -> Result<(), Error> {
    mgr.copy_to_user(pid, user_ptr, &value.to_ne_bytes())
}

fn write_user_i32<'a>(
    mgr: &mut ApeManager<'a>,
    pid: usize,
    user_ptr: usize,
    value: i32,
) -> Result<(), Error> {
    mgr.copy_to_user(pid, user_ptr, &value.to_ne_bytes())
}

fn read_user_bytes<'a>(
    mgr: &mut ApeManager<'a>,
    pid: usize,
    user_ptr: usize,
    len: usize,
) -> Result<alloc::vec::Vec<u8>, Error> {
    let mut buf = alloc::vec![0u8; len];
    mgr.copy_from_user(pid, user_ptr, &mut buf)?;
    Ok(buf)
}

fn write_user_bytes<'a>(
    mgr: &mut ApeManager<'a>,
    pid: usize,
    user_ptr: usize,
    data: &[u8],
) -> Result<(), Error> {
    if data.is_empty() {
        return Ok(());
    }
    mgr.copy_to_user(pid, user_ptr, data)
}

fn query_prism_tty_state(term: TerminalClient) -> Result<TtyCompatState, Error> {
    let mut state = TtyCompatState::default();

    let mut winsize_utcb = unsafe { UTCB::new() };
    winsize_utcb.clear();
    winsize_utcb.set_msg_tag(MsgTag::new(
        glenda::protocol::TERMINAL_PROTO,
        glenda::protocol::terminal::TERM_GET_WINSIZE,
        MsgFlags::NONE,
    ));
    term.endpoint().call(winsize_utcb)?;
    state.winsize = unsafe { winsize_utcb.read_postcard()? };

    Ok(state)
}

fn ensure_tty_state<'a>(mgr: &mut ApeManager<'a>, term: TerminalClient) {
    if mgr.tty_registry().get(term).is_some() {
        return;
    }

    let state = query_prism_tty_state(term).unwrap_or_else(|e| {
        warn!("tty state hydrate from prism failed: {:?}, fallback defaults", e);
        TtyCompatState::default()
    });
    mgr.tty_registry_mut().insert(term, state);
}

pub(crate) fn set_terminal_pgrp_local<'a>(
    mgr: &mut ApeManager<'a>,
    term: TerminalClient,
    pgrp: i32,
) {
    mgr.tty_registry_mut().update_pgrp(term, pgrp);
}

fn ensure_prism_stream_mode(term: TerminalClient) {
    let mut utcb = unsafe { UTCB::new() };
    utcb.clear();
    utcb.set_msg_tag(MsgTag::new(
        glenda::protocol::TERMINAL_PROTO,
        glenda::protocol::terminal::TERM_STREAM_SET_MODE,
        MsgFlags::NONE,
    ));
    utcb.set_mr(0, 0);
    if let Err(e) = term.endpoint().call(utcb) {
        warn!("set TERM_STREAM_SET_MODE(ByteStream) failed: {:?}", e);
    }
}

fn prism_stream_poll(term: TerminalClient) -> Result<bool, Error> {
    ensure_prism_stream_mode(term);
    let mut utcb = unsafe { UTCB::new() };
    utcb.clear();
    utcb.set_msg_tag(MsgTag::new(
        glenda::protocol::TERMINAL_PROTO,
        glenda::protocol::terminal::TERM_STREAM_POLL,
        MsgFlags::NONE,
    ));
    term.endpoint().call(&mut utcb)?;
    Ok(utcb.get_mr(0) != 0)
}

fn prism_stream_read(term: TerminalClient, dst: &mut [u8]) -> Result<usize, Error> {
    if dst.is_empty() {
        return Ok(0);
    }

    ensure_prism_stream_mode(term);
    let mut utcb = unsafe { UTCB::new() };
    utcb.clear();
    utcb.set_msg_tag(MsgTag::new(
        glenda::protocol::TERMINAL_PROTO,
        glenda::protocol::terminal::TERM_STREAM_READ,
        MsgFlags::HAS_BUFFER,
    ));
    utcb.set_mr(0, dst.len());
    term.endpoint().call(&mut utcb)?;
    utcb.error_check()?;

    let read_len = min(utcb.get_mr(0), min(dst.len(), utcb.buffer().len()));
    if read_len > 0 {
        dst[..read_len].copy_from_slice(&utcb.buffer()[..read_len]);
    }
    Ok(read_len)
}

fn prism_stream_write(term: TerminalClient, data: &[u8]) -> Result<usize, Error> {
    if data.is_empty() {
        return Ok(0);
    }

    ensure_prism_stream_mode(term);
    let mut utcb = unsafe { UTCB::new() };
    utcb.clear();
    utcb.set_msg_tag(MsgTag::new(
        glenda::protocol::TERMINAL_PROTO,
        glenda::protocol::terminal::TERM_STREAM_WRITE,
        MsgFlags::HAS_BUFFER,
    ));
    let copied = utcb.write(data);
    term.endpoint().call(&mut utcb)?;
    utcb.error_check()?;
    Ok(if utcb.get_mr(0) > 0 { min(utcb.get_mr(0), copied) } else { copied })
}

pub(crate) fn terminal_poll_readable<'a>(
    mgr: &mut ApeManager<'a>,
    term: TerminalClient,
) -> Result<bool, Error> {
    ensure_tty_state(mgr, term);

    if let Some(state) = mgr.tty_registry().get(term)
        && ldisc::can_read_now(state)
    {
        return Ok(true);
    }

    if !prism_stream_poll(term)? {
        return Ok(false);
    }

    let mut input = [0u8; 256];
    let read_len = prism_stream_read(term, &mut input)?;
    if read_len == 0 {
        return Ok(false);
    }

    let echo = {
        let state = mgr.tty_registry_mut().get_mut(term).ok_or(Error::NotFound)?;
        ldisc::feed_input(state, &input[..read_len])
    };

    if !echo.is_empty() {
        let _ = prism_stream_write(term, &echo);
    }

    Ok(mgr.tty_registry().get(term).map(ldisc::can_read_now).unwrap_or(false))
}

pub(crate) fn do_read_terminal<'a>(
    mgr: &mut ApeManager<'a>,
    pid: usize,
    term: TerminalClient,
    buf_ptr: usize,
    len: usize,
) -> Result<isize, Error> {
    ensure_tty_state(mgr, term);

    loop {
        let ready = {
            let state = mgr.tty_registry_mut().get_mut(term).ok_or(Error::NotFound)?;
            ldisc::take_readable(state, len)
        };

        if !ready.is_empty() {
            mgr.copy_to_user(pid, buf_ptr, &ready)?;
            return Ok(ready.len() as isize);
        }

        let mut input = [0u8; 256];
        let read_len = prism_stream_read(term, &mut input)?;
        if read_len == 0 {
            core::hint::spin_loop();
            continue;
        }

        let echo = {
            let state = mgr.tty_registry_mut().get_mut(term).ok_or(Error::NotFound)?;
            ldisc::feed_input(state, &input[..read_len])
        };
        if !echo.is_empty() {
            let _ = prism_stream_write(term, &echo);
        }
    }
}

pub(crate) fn do_write_terminal<'a>(
    mgr: &mut ApeManager<'a>,
    pid: usize,
    term: TerminalClient,
    buf_ptr: usize,
    len: usize,
) -> Result<isize, Error> {
    ensure_prism_stream_mode(term);
    let mut kbuf = alloc::vec![0u8; len];
    mgr.copy_from_user(pid, buf_ptr, &mut kbuf)?;

    ensure_tty_state(mgr, term);
    if let Some(state) = mgr.tty_registry_mut().get_mut(term) {
        ansi::process_output(state, &kbuf);
    }

    let mut utcb = unsafe { UTCB::new() };
    let tag = MsgTag::new(
        glenda::protocol::TERMINAL_PROTO,
        glenda::protocol::terminal::TERM_STREAM_WRITE,
        MsgFlags::HAS_BUFFER,
    );
    let copied = utcb.write(&kbuf);
    utcb.set_msg_tag(tag);
    term.endpoint().call(utcb)?;
    utcb.error_check()?;

    let written = if utcb.get_mr(0) > 0 { min(utcb.get_mr(0), copied) } else { copied };
    Ok(written as isize)
}

pub(crate) fn do_ioctl_terminal<'a>(
    mgr: &mut ApeManager<'a>,
    pid: usize,
    term: TerminalClient,
    request: u32,
    argp: usize,
) -> Result<isize, Error> {
    match request {
        TIOCGWINSZ => {
            ensure_tty_state(mgr, term);
            let state = mgr.tty_registry().get(term).ok_or(Error::NotFound)?;
            let ws = host_window_size_to_linux_winsize(state.winsize);
            write_user_winsize(mgr, pid, argp, ws)?;
            Ok(0)
        }
        TIOCSWINSZ => {
            let ws = read_user_winsize(mgr, pid, argp)?;
            let host_ws = linux_winsize_to_host_window_size(ws);
            mgr.tty_registry_mut().update_winsize(term, host_ws);

            let mut utcb = unsafe { UTCB::new() };
            utcb.clear();
            utcb.set_msg_tag(MsgTag::new(
                glenda::protocol::TERMINAL_PROTO,
                glenda::protocol::terminal::TERM_SET_WINSIZE,
                MsgFlags::HAS_BUFFER,
            ));
            unsafe {
                utcb.write_postcard(&host_ws)?;
            }
            term.endpoint().call(utcb)?;
            Ok(0)
        }
        TCGETS => {
            ensure_tty_state(mgr, term);
            let state = mgr.tty_registry().get(term).ok_or(Error::NotFound)?;
            let termios = state.termios;
            write_user_bytes(mgr, pid, argp, &termios)?;
            Ok(0)
        }
        TCSETS | TCSETSW | TCSETSF => {
            let payload = read_user_bytes(mgr, pid, argp, TTY_TERMIOS_SIZE)?;
            let mut termios = [0u8; TTY_TERMIOS_SIZE];
            let n = min(TTY_TERMIOS_SIZE, payload.len());
            termios[..n].copy_from_slice(&payload[..n]);
            mgr.tty_registry_mut().update_termios(term, termios);
            Ok(0)
        }
        TIOCGPGRP => {
            ensure_tty_state(mgr, term);
            let state = mgr.tty_registry().get(term).ok_or(Error::NotFound)?;
            let pgrp = state.pgrp;
            write_user_i32(mgr, pid, argp, pgrp as c_int)?;
            Ok(0)
        }
        TIOCGSID => {
            let tty_key = term.endpoint().cap().bits();
            let proc = mgr.get_process(pid).ok_or(Error::NotFound)?;
            if proc.controlling_tty != Some(tty_key) {
                return Err(Error::InvalidType);
            }
            let sid = proc.session_id as i32;
            write_user_i32(mgr, pid, argp, sid as c_int)?;
            Ok(0)
        }
        TIOCSPGRP => {
            let pgrp = read_user_i32(mgr, pid, argp)?;
            mgr.tty_registry_mut().update_pgrp(term, pgrp);
            Ok(0)
        }
        TIOCSCTTY => {
            let tty_key = term.endpoint().cap().bits();
            let proc = mgr.get_process_mut(pid).ok_or(Error::NotFound)?;
            proc.controlling_tty = Some(tty_key);
            Ok(0)
        }
        TIOCNOTTY => {
            let tty_key = term.endpoint().cap().bits();
            let proc = mgr.get_process_mut(pid).ok_or(Error::NotFound)?;
            if proc.controlling_tty == Some(tty_key) {
                proc.controlling_tty = None;
            }
            Ok(0)
        }
        _ => Err(Error::InvalidType),
    }
}

pub(crate) fn do_ioctl_pty_master<'a>(
    mgr: &mut ApeManager<'a>,
    pid: usize,
    vt_id: usize,
    locked: &mut bool,
    term: TerminalClient,
    request: u32,
    argp: usize,
) -> Result<isize, Error> {
    match request {
        TIOCGPTN => {
            write_user_u32(mgr, pid, argp, vt_id as u32)?;
            Ok(0)
        }
        TIOCSPTLCK => {
            let lock = read_user_u32(mgr, pid, argp)?;
            mgr.vt_client.set_pty_lock(Badge::null(), vt_id, lock != 0)?;
            *locked = lock != 0;
            Ok(0)
        }
        _ => do_ioctl_terminal(mgr, pid, term, request, argp),
    }
}
