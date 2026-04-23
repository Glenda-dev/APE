use crate::ape::tty::state::{TTY_TERMIOS_SIZE, TtyCompatState};
use alloc::vec::Vec;

const LFLAG_OFFSET: usize = 12;
const CC_OFFSET: usize = 17;
const IFLAG_OFFSET: usize = 0;
const IFLAG_IGNCR: u32 = 0x00080;
const IFLAG_ICRNL: u32 = 0x00100;
const IFLAG_INLCR: u32 = 0x00040;
const LFLAG_ICANON: u32 = 0x00002;
const LFLAG_ECHO: u32 = 0x00008;
const VERASE: usize = 2;
const VKILL: usize = 3;
const VEOF: usize = 4;
const VTIME: usize = 5;
const VMIN: usize = 6;

fn read_u32(termios: &[u8; TTY_TERMIOS_SIZE], off: usize) -> u32 {
    let mut raw = [0u8; 4];
    raw.copy_from_slice(&termios[off..off + 4]);
    u32::from_ne_bytes(raw)
}

fn read_cc(termios: &[u8; TTY_TERMIOS_SIZE], idx: usize, default: u8) -> u8 {
    termios.get(CC_OFFSET + idx).copied().unwrap_or(default)
}

fn is_igncr(termios: &[u8; TTY_TERMIOS_SIZE]) -> bool {
    (read_u32(termios, IFLAG_OFFSET) & IFLAG_IGNCR) != 0
}

fn is_icrnl(termios: &[u8; TTY_TERMIOS_SIZE]) -> bool {
    (read_u32(termios, IFLAG_OFFSET) & IFLAG_ICRNL) != 0
}

fn is_inlcr(termios: &[u8; TTY_TERMIOS_SIZE]) -> bool {
    (read_u32(termios, IFLAG_OFFSET) & IFLAG_INLCR) != 0
}

fn is_icanon(termios: &[u8; TTY_TERMIOS_SIZE]) -> bool {
    (read_u32(termios, LFLAG_OFFSET) & LFLAG_ICANON) != 0
}

fn is_echo(termios: &[u8; TTY_TERMIOS_SIZE]) -> bool {
    (read_u32(termios, LFLAG_OFFSET) & LFLAG_ECHO) != 0
}

fn canonical_erase(state: &mut TtyCompatState, echo: &mut Vec<u8>) {
    if state.canonical_line_buf.pop_back().is_some() {
        echo.extend_from_slice(b"\x08 \x08");
    }
}

fn canonical_kill(state: &mut TtyCompatState, echo: &mut Vec<u8>) {
    while state.canonical_line_buf.pop_back().is_some() {
        echo.extend_from_slice(b"\x08 \x08");
    }
}

fn flush_canonical_to_readable(state: &mut TtyCompatState) {
    while let Some(b) = state.canonical_line_buf.pop_front() {
        state.readable_buf.push_back(b);
    }
}

pub fn feed_input(state: &mut TtyCompatState, input: &[u8]) -> Vec<u8> {
    let mut echo = Vec::new();
    let icanon = is_icanon(&state.termios);
    let do_echo = is_echo(&state.termios);

    let verase = read_cc(&state.termios, VERASE, 0x7f);
    let vkill = read_cc(&state.termios, VKILL, 0x15);
    let veof = read_cc(&state.termios, VEOF, 0x04);
    let igncr = is_igncr(&state.termios);
    let icrnl = is_icrnl(&state.termios);
    let inlcr = is_inlcr(&state.termios);

    for &raw in input {
        let b = match raw {
            b'\r' if igncr => continue,
            b'\r' if icrnl => b'\n',
            b'\n' if inlcr => b'\r',
            _ => raw,
        };

        if icanon {
            match b {
                x if x == verase => {
                    if do_echo {
                        canonical_erase(state, &mut echo);
                    } else {
                        state.canonical_line_buf.pop_back();
                    }
                }
                x if x == vkill => {
                    if do_echo {
                        canonical_kill(state, &mut echo);
                    } else {
                        state.canonical_line_buf.clear();
                    }
                }
                x if x == veof => {
                    flush_canonical_to_readable(state);
                }
                b'\n' => {
                    state.canonical_line_buf.push_back(b);
                    flush_canonical_to_readable(state);
                    if do_echo {
                        echo.push(b);
                    }
                }
                _ => {
                    state.canonical_line_buf.push_back(b);
                    if do_echo {
                        echo.push(b);
                    }
                }
            }
        } else {
            state.readable_buf.push_back(b);
            if do_echo {
                echo.push(b);
            }
        }
    }

    echo
}

pub fn can_read_now(state: &TtyCompatState) -> bool {
    if state.readable_buf.is_empty() {
        return false;
    }

    if is_icanon(&state.termios) {
        return true;
    }

    let vmin = read_cc(&state.termios, VMIN, 1) as usize;
    let _vtime = read_cc(&state.termios, VTIME, 0);
    if vmin == 0 { !state.readable_buf.is_empty() } else { state.readable_buf.len() >= vmin }
}

pub fn take_readable(state: &mut TtyCompatState, max_len: usize) -> Vec<u8> {
    if max_len == 0 || !can_read_now(state) {
        return Vec::new();
    }

    let n = core::cmp::min(max_len, state.readable_buf.len());
    let mut out = Vec::with_capacity(n);
    for _ in 0..n {
        if let Some(b) = state.readable_buf.pop_front() {
            out.push(b);
        } else {
            break;
        }
    }
    out
}
