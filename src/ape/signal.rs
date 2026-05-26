use alloc::collections::BTreeMap;
use core::sync::atomic::{AtomicU64, Ordering};
use glenda::sync::mutex::Mutex;
use linux_raw_sys::general::{SIGKILL, SIGSTOP};

pub const SIGNAL_MIN: usize = 1;
pub const SIGNAL_MAX: usize = 64;
pub const SIGNAL_UNBLOCKABLE_MASK: u64 =
    (1u64 << (SIGKILL as usize - 1)) | (1u64 << (SIGSTOP as usize - 1));

#[derive(Debug, Clone, Copy, Default)]
pub struct SignalAction {
    pub handler: usize,
    pub flags: usize,
    pub restorer: usize,
    pub mask: u64,
}

#[inline]
pub fn signal_bit(signum: usize) -> Option<u64> {
    if (SIGNAL_MIN..=SIGNAL_MAX).contains(&signum) { Some(1u64 << (signum - 1)) } else { None }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Wait4BlockRequest {
    pub target_pid: isize,
    pub caller_pgid: usize,
}

pub struct SignalState {
    pub sigsuspend_saved_mask: Option<u64>,
    pub wait4_blocked: Option<Wait4BlockRequest>,
    pub clear_child_tid: usize,
}

pub struct SignalStruct {
    pub signal_blocked: AtomicU64,
    pub signal_pending: AtomicU64,
    pub state: Mutex<SignalState>,
}

pub struct SighandStruct {
    pub signal_actions: Mutex<BTreeMap<usize, SignalAction>>,
}

impl SignalStruct {
    pub fn new() -> Self {
        Self {
            signal_blocked: AtomicU64::new(0),
            signal_pending: AtomicU64::new(0),
            state: Mutex::new(SignalState {
                sigsuspend_saved_mask: None,
                wait4_blocked: None,
                clear_child_tid: 0,
            }),
        }
    }

    pub fn set_blocked(&self, mut mask: u64) {
        mask &= !SIGNAL_UNBLOCKABLE_MASK;
        self.signal_blocked.store(mask, Ordering::SeqCst);
    }

    pub fn get_blocked(&self) -> u64 {
        self.signal_blocked.load(Ordering::SeqCst)
    }

    pub fn signal_action(&self, sighand: &SighandStruct, signum: usize) -> SignalAction {
        sighand.signal_actions.lock().get(&signum).copied().unwrap_or_default()
    }

    pub fn queue_signal(&self, signum: usize) -> bool {
        if let Some(bit) = signal_bit(signum) {
            self.signal_pending.fetch_or(bit, Ordering::SeqCst);
            true
        } else {
            false
        }
    }

    pub fn arm_sigsuspend_wait(&self, old_mask: u64) {
        self.state.lock().sigsuspend_saved_mask = Some(old_mask);
    }

    pub fn is_waiting_sigsuspend(&self) -> bool {
        self.state.lock().sigsuspend_saved_mask.is_some()
    }

    pub fn restore_mask_from_sigsuspend_wait(&self) -> bool {
        let mut state = self.state.lock();
        if let Some(old_mask) = state.sigsuspend_saved_mask.take() {
            let mask = old_mask & !SIGNAL_UNBLOCKABLE_MASK;
            self.signal_blocked.store(mask, Ordering::SeqCst);
            true
        } else {
            false
        }
    }

    pub fn arm_wait4_block(&self, target_pid: isize, caller_pgid: usize) {
        self.state.lock().wait4_blocked = Some(Wait4BlockRequest { target_pid, caller_pgid });
    }

    pub fn clear_wait4_block(&self) {
        self.state.lock().wait4_blocked = None;
    }

    fn matches_wait4_target(child_pid: usize, child_pgid: usize, req: Wait4BlockRequest) -> bool {
        if req.target_pid == -1 {
            return true;
        }
        if req.target_pid > 0 {
            return child_pid == req.target_pid as usize;
        }
        if req.target_pid == 0 {
            return child_pgid == req.caller_pgid;
        }
        child_pgid == req.target_pid.unsigned_abs()
    }

    pub fn wait4_block_matches(&self, child_pid: usize, child_pgid: usize) -> bool {
        self.state
            .lock()
            .wait4_blocked
            .map(|req| Self::matches_wait4_target(child_pid, child_pgid, req))
            .unwrap_or(false)
    }

    pub fn pop_pending_signal_from_mask(&self, mask: u64) -> Option<usize> {
        loop {
            let pending = self.signal_pending.load(Ordering::SeqCst);
            let ready = pending & mask;
            if ready == 0 {
                return None;
            }

            let idx = ready.trailing_zeros() as usize;
            let bit = 1u64 << idx;
            if self.signal_pending.fetch_and(!bit, Ordering::SeqCst) & bit != 0 {
                return Some(idx + 1);
            }
        }
    }
}

impl SighandStruct {
    pub fn new() -> Self {
        Self { signal_actions: Mutex::new(BTreeMap::new()) }
    }
}
