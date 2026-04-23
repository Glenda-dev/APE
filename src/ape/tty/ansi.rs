use crate::ape::tty::state::TtyCompatState;
use anstyle_parse::{Params, Parser, Perform};

#[inline]
fn rows_max(state: &TtyCompatState) -> u16 {
    state.winsize.rows.max(1)
}

#[inline]
fn cols_max(state: &TtyCompatState) -> u16 {
    state.winsize.cols.max(1)
}

#[inline]
fn clamp_row(state: &TtyCompatState, row: u16) -> u16 {
    core::cmp::min(row.max(1), rows_max(state))
}

#[inline]
fn clamp_col(state: &TtyCompatState, col: u16) -> u16 {
    core::cmp::min(col.max(1), cols_max(state))
}

#[inline]
fn param_raw(params: &Params, idx: usize) -> u16 {
    params.iter().nth(idx).and_then(|p| p.first().copied()).unwrap_or(0)
}

#[inline]
fn param_or(params: &Params, idx: usize, default: u16) -> u16 {
    match param_raw(params, idx) {
        0 => default,
        v => v,
    }
}

struct TtyPerformer<'a> {
    state: &'a mut TtyCompatState,
}

impl<'a> TtyPerformer<'a> {
    #[inline]
    fn respond(&mut self, s: &str) {
        for &b in s.as_bytes() {
            self.state.readable_buf.push_back(b);
        }
    }

    #[inline]
    fn handle_printable(&mut self) {
        self.state.cursor_col = self.state.cursor_col.saturating_add(1);
        if self.state.cursor_col > cols_max(self.state) {
            self.state.cursor_col = 1;
            self.state.cursor_row = clamp_row(self.state, self.state.cursor_row.saturating_add(1));
        }
    }
}

impl Perform for TtyPerformer<'_> {
    fn print(&mut self, _c: char) {
        self.handle_printable();
    }

    fn execute(&mut self, byte: u8) {
        match byte {
            b'\n' => {
                self.state.cursor_row =
                    clamp_row(self.state, self.state.cursor_row.saturating_add(1));
                self.state.cursor_col = 1;
            }
            b'\r' => self.state.cursor_col = 1,
            0x08 => {
                self.state.cursor_col =
                    clamp_col(self.state, self.state.cursor_col.saturating_sub(1));
            }
            0x09 => {
                let next_tab = ((self.state.cursor_col - 1) / 8 + 1) * 8 + 1;
                self.state.cursor_col = clamp_col(self.state, next_tab);
            }
            _ => {}
        }
    }

    fn hook(&mut self, _params: &Params, _intermediates: &[u8], _ignore: bool, _action: u8) {}

    fn put(&mut self, _byte: u8) {}

    fn unhook(&mut self) {}

    fn osc_dispatch(&mut self, _params: &[&[u8]], _bell_terminated: bool) {}

    fn csi_dispatch(&mut self, params: &Params, intermediates: &[u8], _ignore: bool, action: u8) {
        let prefix = intermediates.first().copied().unwrap_or(0);
        match action {
            b'n' => {
                // Stream TTY backend: consume DSR/CPR queries but do not synthesize
                // replies into readable input. Injected ESC[...R bytes can pollute
                // shell input state when no dedicated terminal emulator is present.
                let _ = prefix;
                let _ = params;
            }
            b'c' => {
                // DA / Secondary DA
                if prefix == b'>' {
                    self.respond("\x1b[>0;0;0c");
                } else {
                    self.respond("\x1b[?1;2c");
                }
            }
            b't' => match param_raw(params, 0) {
                14 => {
                    let buf = alloc::format!(
                        "\x1b[4;{};{}t",
                        self.state.winsize.ypixel.max(1),
                        self.state.winsize.xpixel.max(1)
                    );
                    self.respond(&buf);
                }
                18 => {
                    let buf =
                        alloc::format!("\x1b[8;{};{}t", rows_max(self.state), cols_max(self.state));
                    self.respond(&buf);
                }
                _ => {}
            },
            b'H' | b'f' => {
                let row = param_or(params, 0, 1);
                let col = param_or(params, 1, 1);
                self.state.cursor_row = clamp_row(self.state, row);
                self.state.cursor_col = clamp_col(self.state, col);
            }
            b'A' => {
                let n = param_or(params, 0, 1);
                self.state.cursor_row =
                    clamp_row(self.state, self.state.cursor_row.saturating_sub(n));
            }
            b'B' => {
                let n = param_or(params, 0, 1);
                self.state.cursor_row =
                    clamp_row(self.state, self.state.cursor_row.saturating_add(n));
            }
            b'C' => {
                let n = param_or(params, 0, 1);
                self.state.cursor_col =
                    clamp_col(self.state, self.state.cursor_col.saturating_add(n));
            }
            b'D' => {
                let n = param_or(params, 0, 1);
                self.state.cursor_col =
                    clamp_col(self.state, self.state.cursor_col.saturating_sub(n));
            }
            b'E' => {
                let n = param_or(params, 0, 1);
                self.state.cursor_row =
                    clamp_row(self.state, self.state.cursor_row.saturating_add(n));
                self.state.cursor_col = 1;
            }
            b'F' => {
                let n = param_or(params, 0, 1);
                self.state.cursor_row =
                    clamp_row(self.state, self.state.cursor_row.saturating_sub(n));
                self.state.cursor_col = 1;
            }
            b'G' => {
                let col = param_or(params, 0, 1);
                self.state.cursor_col = clamp_col(self.state, col);
            }
            b'd' => {
                let row = param_or(params, 0, 1);
                self.state.cursor_row = clamp_row(self.state, row);
            }
            b's' => {
                self.state.saved_cursor_row = self.state.cursor_row;
                self.state.saved_cursor_col = self.state.cursor_col;
            }
            b'u' => {
                self.state.cursor_row = clamp_row(self.state, self.state.saved_cursor_row);
                self.state.cursor_col = clamp_col(self.state, self.state.saved_cursor_col);
            }
            b'm' | b'J' | b'K' | b'X' | b'@' | b'P' | b'L' | b'M' | b'S' | b'T' | b'h' | b'l' => {
                // No-op for cursor tracker.
            }
            _ => {}
        }
    }

    fn esc_dispatch(&mut self, intermediates: &[u8], _ignore: bool, byte: u8) {
        match byte {
            b'7' => {
                self.state.saved_cursor_row = self.state.cursor_row;
                self.state.saved_cursor_col = self.state.cursor_col;
            }
            b'8' => {
                self.state.cursor_row = clamp_row(self.state, self.state.saved_cursor_row);
                self.state.cursor_col = clamp_col(self.state, self.state.saved_cursor_col);
            }
            b'D' => {
                // IND
                self.state.cursor_row =
                    clamp_row(self.state, self.state.cursor_row.saturating_add(1));
            }
            b'E' => {
                // NEL
                self.state.cursor_row =
                    clamp_row(self.state, self.state.cursor_row.saturating_add(1));
                self.state.cursor_col = 1;
            }
            b'M' => {
                // RI
                self.state.cursor_row =
                    clamp_row(self.state, self.state.cursor_row.saturating_sub(1));
            }
            b'Z' => {
                // DECID
                self.respond("\x1b[?1;2c");
            }
            b'c' => {
                // RIS
                self.state.cursor_row = 1;
                self.state.cursor_col = 1;
                self.state.saved_cursor_row = 1;
                self.state.saved_cursor_col = 1;
            }
            _ => {
                // Charset designators etc are ignored for tracker.
                let _ = intermediates;
            }
        }
    }
}

pub fn process_output(state: &mut TtyCompatState, output: &[u8]) {
    let mut parser = core::mem::replace(
        &mut state.ansi_parser,
        Parser::<anstyle_parse::DefaultCharAccumulator>::new(),
    );
    {
        let mut performer = TtyPerformer { state };
        for &b in output {
            parser.advance(&mut performer, b);
        }
    }
    state.ansi_parser = parser;
}
