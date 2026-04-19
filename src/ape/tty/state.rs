use alloc::collections::BTreeMap;
use alloc::collections::VecDeque;
use glenda::client::TerminalClient;
use glenda::protocol::terminal::WindowSize;

pub const TTY_TERMIOS_SIZE: usize = 44;

const LFLAG_OFFSET: usize = 12;
const CC_OFFSET: usize = 17;
const LFLAG_ISIG: u32 = 0x00001;
const LFLAG_ICANON: u32 = 0x00002;
const LFLAG_ECHO: u32 = 0x00008;
const VINTR: usize = 0;
const VQUIT: usize = 1;
const VERASE: usize = 2;
const VKILL: usize = 3;
const VEOF: usize = 4;
const VTIME: usize = 5;
const VMIN: usize = 6;

fn default_termios() -> [u8; TTY_TERMIOS_SIZE] {
    let mut t = [0u8; TTY_TERMIOS_SIZE];

    let lflag = (LFLAG_ISIG | LFLAG_ICANON | LFLAG_ECHO).to_ne_bytes();
    t[LFLAG_OFFSET..LFLAG_OFFSET + 4].copy_from_slice(&lflag);

    t[CC_OFFSET + VINTR] = 0x03; // ^C
    t[CC_OFFSET + VQUIT] = 0x1c; // ^\
    t[CC_OFFSET + VERASE] = 0x7f;
    t[CC_OFFSET + VKILL] = 0x15; // ^U
    t[CC_OFFSET + VEOF] = 0x04; // ^D
    t[CC_OFFSET + VTIME] = 0;
    t[CC_OFFSET + VMIN] = 1;

    t
}

pub struct TtyCompatState {
    pub termios: [u8; TTY_TERMIOS_SIZE],
    pub winsize: WindowSize,
    pub pgrp: i32,
    pub canonical_line_buf: VecDeque<u8>,
    pub readable_buf: VecDeque<u8>,
    pub cursor_row: u16,
    pub cursor_col: u16,
    pub saved_cursor_row: u16,
    pub saved_cursor_col: u16,
    pub ansi_parser: anstyle_parse::Parser<anstyle_parse::DefaultCharAccumulator>,
}

impl Default for TtyCompatState {
    fn default() -> Self {
        Self {
            termios: default_termios(),
            winsize: WindowSize { rows: 25, cols: 80, xpixel: 800, ypixel: 600 },
            pgrp: 0,
            canonical_line_buf: VecDeque::new(),
            readable_buf: VecDeque::new(),
            cursor_row: 1,
            cursor_col: 1,
            saved_cursor_row: 1,
            saved_cursor_col: 1,
            ansi_parser: anstyle_parse::Parser::<anstyle_parse::DefaultCharAccumulator>::new(),
        }
    }
}

pub struct TtyRegistry {
    states: BTreeMap<usize, TtyCompatState>,
}

impl TtyRegistry {
    pub fn new() -> Self {
        Self { states: BTreeMap::new() }
    }

    #[inline]
    fn key(term: TerminalClient) -> usize {
        term.endpoint().cap().bits()
    }

    pub fn get(&self, term: TerminalClient) -> Option<&TtyCompatState> {
        self.states.get(&Self::key(term))
    }

    pub fn get_mut(&mut self, term: TerminalClient) -> Option<&mut TtyCompatState> {
        self.states.get_mut(&Self::key(term))
    }

    pub fn has_readable(&self, term: TerminalClient) -> bool {
        self.states.get(&Self::key(term)).map(|s| !s.readable_buf.is_empty()).unwrap_or(false)
    }

    pub fn insert(&mut self, term: TerminalClient, state: TtyCompatState) {
        self.states.insert(Self::key(term), state);
    }

    pub fn update_termios(&mut self, term: TerminalClient, termios: [u8; TTY_TERMIOS_SIZE]) {
        let entry = self.states.entry(Self::key(term)).or_default();
        entry.termios = termios;
    }

    pub fn update_winsize(&mut self, term: TerminalClient, winsize: WindowSize) {
        let entry = self.states.entry(Self::key(term)).or_default();
        entry.winsize = winsize;
    }

    pub fn update_pgrp(&mut self, term: TerminalClient, pgrp: i32) {
        let entry = self.states.entry(Self::key(term)).or_default();
        entry.pgrp = pgrp;
    }

    pub fn remove(&mut self, term: TerminalClient) {
        self.states.remove(&Self::key(term));
    }
}
