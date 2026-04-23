use crate::ape::tty::{TTY_TERMIOS_SIZE, TtyCompatState, ansi, ldisc};
use crate::ape::utils::linux_conv::{host_window_size_to_linux_winsize, linux_winsize_to_host_window_size};
use alloc::vec::Vec;
use core::cmp::min;
use core::mem::size_of;
use core::hint::spin_loop;
use glenda::cap::Endpoint;
use glenda::client::TerminalClient;
use glenda::error::Error;
use glenda::ipc::{MsgFlags, MsgTag, UTCB};
use glenda::protocol::terminal::WindowSize;
use glenda::sync::mutex::Mutex;
use glenda::sync::once::Once;
use linux_raw_sys::general::winsize;
use linux_raw_sys::ioctl::{
    TCGETS, TCSETS, TCSETSF, TCSETSW, TIOCGPGRP, TIOCGSID, TIOCGWINSZ, TIOCNOTTY, TIOCSCTTY,
    TIOCSPGRP, TIOCSWINSZ,
};

const IOC_NRBITS: u32 = 8;
const IOC_TYPEBITS: u32 = 8;
const IOC_SIZEBITS: u32 = 14;
const IOC_NRSHIFT: u32 = 0;
const IOC_TYPESHIFT: u32 = IOC_NRSHIFT + IOC_NRBITS;
const IOC_SIZESHIFT: u32 = IOC_TYPESHIFT + IOC_TYPEBITS;
const IOC_DIRSHIFT: u32 = IOC_SIZESHIFT + IOC_SIZEBITS;
const IOC_WRITE: u32 = 1;
const IOC_READ: u32 = 2;
const OFLAG_OFFSET: usize = 4;
const OFLAG_OPOST: u32 = 0x00001;
const OFLAG_ONLCR: u32 = 0x00004;
const OFLAG_OCRNL: u32 = 0x00008;

const fn ioc(dir: u32, ty: u32, nr: u32, sz: u32) -> u32 {
    (dir << IOC_DIRSHIFT) | (ty << IOC_TYPESHIFT) | (nr << IOC_NRSHIFT) | (sz << IOC_SIZESHIFT)
}

const fn ior(ty: u32, nr: u32, sz: u32) -> u32 {
    ioc(IOC_READ, ty, nr, sz)
}

const fn iow(ty: u32, nr: u32, sz: u32) -> u32 {
    ioc(IOC_WRITE, ty, nr, sz)
}

const fn tty_ioctl_read(nr: u32, sz: u32) -> u32 {
    ior(b'T' as u32, nr, sz)
}

const fn tty_ioctl_write(nr: u32, sz: u32) -> u32 {
    iow(b'T' as u32, nr, sz)
}

#[derive(Clone, Copy)]
enum TtyCmd {
    Tcgets,
    Tcsets,
    Tcsetsw,
    Tcsetsf,
    Tiocgwinsz,
    Tiocswinsz,
    Tiocgpgrp,
    Tiocspgrp,
    Tiocgsid,
    Tiocsctty,
    Tiocnotty,
}

fn decode_tty_cmd(cmd: u32) -> Option<TtyCmd> {
    let termios_sz = TTY_TERMIOS_SIZE as u32;
    let winsz_sz = size_of::<winsize>() as u32;
    let i32_sz = size_of::<i32>() as u32;

    match cmd {
        TCGETS => Some(TtyCmd::Tcgets),
        TCSETS => Some(TtyCmd::Tcsets),
        TCSETSW => Some(TtyCmd::Tcsetsw),
        TCSETSF => Some(TtyCmd::Tcsetsf),
        TIOCGWINSZ => Some(TtyCmd::Tiocgwinsz),
        TIOCSWINSZ => Some(TtyCmd::Tiocswinsz),
        TIOCGPGRP => Some(TtyCmd::Tiocgpgrp),
        TIOCSPGRP => Some(TtyCmd::Tiocspgrp),
        TIOCGSID => Some(TtyCmd::Tiocgsid),
        TIOCSCTTY => Some(TtyCmd::Tiocsctty),
        TIOCNOTTY => Some(TtyCmd::Tiocnotty),
        v if v == tty_ioctl_read(0x01, termios_sz) => Some(TtyCmd::Tcgets),
        v if v == tty_ioctl_write(0x02, termios_sz) => Some(TtyCmd::Tcsets),
        v if v == tty_ioctl_write(0x03, termios_sz) => Some(TtyCmd::Tcsetsw),
        v if v == tty_ioctl_write(0x04, termios_sz) => Some(TtyCmd::Tcsetsf),
        v if v == tty_ioctl_read(0x13, winsz_sz) => Some(TtyCmd::Tiocgwinsz),
        v if v == tty_ioctl_write(0x14, winsz_sz) => Some(TtyCmd::Tiocswinsz),
        v if v == tty_ioctl_read(0x77, i32_sz) => Some(TtyCmd::Tiocgpgrp),
        v if v == tty_ioctl_write(0x76, i32_sz) => Some(TtyCmd::Tiocspgrp),
        v if v == tty_ioctl_read(0x63, i32_sz) => Some(TtyCmd::Tiocgsid),
        _ => None,
    }
}

struct TtyState {
    compat: TtyCompatState,
}

pub struct TtyDevice {
    term: TerminalClient,
    state: Mutex<TtyState>,
}

static TTY_DEVICE: Once<TtyDevice> = Once::new();

impl TtyDevice {
    pub fn global() -> &'static Self {
        TTY_DEVICE.call_once(Self::new_stdio)
    }

    fn new_stdio() -> Self {
        let term = TerminalClient::new(crate::layout::STDIO_CAP);
        let compat = query_prism_tty_state(term).unwrap_or_else(|_| TtyCompatState::default());
        Self { term, state: Mutex::new(TtyState { compat }) }
    }

    pub fn set_foreground_pgrp(&self, pgrp: i32) {
        self.state.lock().compat.pgrp = pgrp;
    }

    pub fn poll_readable(&self) -> Result<bool, Error> {
        {
            let state = self.state.lock();
            if ldisc::can_read_now(&state.compat) {
                return Ok(true);
            }
        }

        if !prism_stream_poll(self.term)? {
            return Ok(false);
        }

        let mut input = [0u8; 256];
        let read_len = prism_stream_read(self.term, &mut input)?;
        if read_len == 0 {
            return Ok(false);
        }

        let echo = {
            let mut state = self.state.lock();
            ldisc::feed_input(&mut state.compat, &input[..read_len])
        };
        if !echo.is_empty() {
            let _ = self.write(&echo);
        }

        Ok(ldisc::can_read_now(&self.state.lock().compat))
    }

    pub fn read(&self, buf: &mut [u8]) -> Result<usize, Error> {
        if buf.is_empty() {
            return Ok(0);
        }

        loop {
            let ready = {
                let mut state = self.state.lock();
                ldisc::take_readable(&mut state.compat, buf.len())
            };
            if !ready.is_empty() {
                let n = ready.len();
                buf[..n].copy_from_slice(&ready);
                return Ok(n);
            }

            let mut input = [0u8; 256];
            let read_len = prism_stream_read(self.term, &mut input)?;
            if read_len == 0 {
                spin_loop();
                continue;
            }

            let echo = {
                let mut state = self.state.lock();
                ldisc::feed_input(&mut state.compat, &input[..read_len])
            };
            if !echo.is_empty() {
                let _ = self.write(&echo);
            }
        }
    }

    pub fn write(&self, buf: &[u8]) -> Result<usize, Error> {
        if buf.is_empty() {
            return Ok(0);
        }

        let tx = {
            let mut state = self.state.lock();
            let tx = tty_output_transform(state.compat.termios, buf);
            ansi::process_output(&mut state.compat, &tx);
            tx
        };
        prism_stream_write(self.term, &tx)
    }

    pub fn ioctl_ex(
        &self,
        cmd: u32,
        input: Option<&[u8]>,
        out_len: usize,
    ) -> Result<(usize, Vec<u8>), Error> {
        let cmd = decode_tty_cmd(cmd).ok_or(Error::InvalidType)?;
        match cmd {
            TtyCmd::Tiocgwinsz => {
                let ws = {
                    let state = self.state.lock();
                    host_window_size_to_linux_winsize(state.compat.winsize)
                };
                let ws_bytes = unsafe {
                    core::slice::from_raw_parts(
                        (&ws as *const winsize) as *const u8,
                        size_of::<winsize>(),
                    )
                };
                let mut out = Vec::new();
                out.extend_from_slice(&ws_bytes[..min(out_len, ws_bytes.len())]);
                Ok((0, out))
            }
            TtyCmd::Tiocswinsz => {
                let payload = input.ok_or(Error::InvalidArgs)?;
                if payload.len() < size_of::<winsize>() {
                    return Err(Error::InvalidArgs);
                }
                let ws = unsafe { (payload.as_ptr() as *const winsize).read_unaligned() };
                let host_ws = linux_winsize_to_host_window_size(ws);
                {
                    let mut state = self.state.lock();
                    state.compat.winsize = host_ws;
                }
                prism_set_winsize(self.term.endpoint(), host_ws)?;
                Ok((0, Vec::new()))
            }
            TtyCmd::Tcgets => {
                let termios = self.state.lock().compat.termios;
                let mut out = Vec::new();
                out.extend_from_slice(&termios[..min(out_len, termios.len())]);
                Ok((0, out))
            }
            TtyCmd::Tcsets | TtyCmd::Tcsetsw | TtyCmd::Tcsetsf => {
                let payload = input.ok_or(Error::InvalidArgs)?;
                let mut termios = [0u8; TTY_TERMIOS_SIZE];
                let n = min(TTY_TERMIOS_SIZE, payload.len());
                termios[..n].copy_from_slice(&payload[..n]);
                self.state.lock().compat.termios = termios;
                Ok((0, Vec::new()))
            }
            TtyCmd::Tiocgpgrp | TtyCmd::Tiocgsid => {
                let pgrp = self.state.lock().compat.pgrp;
                let raw = pgrp.to_ne_bytes();
                let mut out = Vec::new();
                out.extend_from_slice(&raw[..min(out_len, raw.len())]);
                Ok((0, out))
            }
            TtyCmd::Tiocspgrp => {
                let payload = input.ok_or(Error::InvalidArgs)?;
                if payload.len() < size_of::<i32>() {
                    return Err(Error::InvalidArgs);
                }
                let pgrp = i32::from_ne_bytes(payload[..4].try_into().map_err(|_| Error::InvalidArgs)?);
                self.state.lock().compat.pgrp = pgrp;
                Ok((0, Vec::new()))
            }
            TtyCmd::Tiocsctty | TtyCmd::Tiocnotty => Ok((0, Vec::new())),
        }
    }
}

fn read_u32(raw: &[u8; TTY_TERMIOS_SIZE], off: usize) -> u32 {
    let mut bytes = [0u8; 4];
    bytes.copy_from_slice(&raw[off..off + 4]);
    u32::from_ne_bytes(bytes)
}

fn tty_output_transform(termios: [u8; TTY_TERMIOS_SIZE], input: &[u8]) -> Vec<u8> {
    let oflag = read_u32(&termios, OFLAG_OFFSET);
    let opost = (oflag & OFLAG_OPOST) != 0;
    let onlcr = (oflag & OFLAG_ONLCR) != 0;
    let ocrnl = (oflag & OFLAG_OCRNL) != 0;
    if !opost || (!onlcr && !ocrnl) {
        return input.to_vec();
    }

    let nl_count = if onlcr { input.iter().filter(|&&b| b == b'\n').count() } else { 0 };
    let mut out = Vec::with_capacity(input.len().saturating_add(nl_count));
    for &b in input {
        if onlcr && b == b'\n' {
            out.push(b'\r');
            out.push(b'\n');
        } else if ocrnl && b == b'\r' {
            out.push(b'\n');
        } else {
            out.push(b);
        }
    }
    out
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

fn ensure_prism_stream_mode(term: TerminalClient) {
    let mut utcb = unsafe { UTCB::new() };
    utcb.clear();
    utcb.set_msg_tag(MsgTag::new(
        glenda::protocol::TERMINAL_PROTO,
        glenda::protocol::terminal::TERM_STREAM_SET_MODE,
        MsgFlags::NONE,
    ));
    utcb.set_mr(0, 0);
    let _ = term.endpoint().call(utcb);
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
    utcb.error_check()?;
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

fn prism_set_winsize(term: Endpoint, winsize: WindowSize) -> Result<(), Error> {
    let mut utcb = unsafe { UTCB::new() };
    utcb.clear();
    utcb.set_msg_tag(MsgTag::new(
        glenda::protocol::TERMINAL_PROTO,
        glenda::protocol::terminal::TERM_SET_WINSIZE,
        MsgFlags::HAS_BUFFER,
    ));
    unsafe {
        utcb.write_postcard(&winsize)?;
    }
    term.call(utcb)?;
    Ok(())
}
