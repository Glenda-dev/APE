use crate::ape::cred::CredStruct;
use crate::ape::files::FilesStruct;
use crate::ape::fs::FsStruct;
use crate::ape::mm::MmStruct;
use crate::ape::signal::{SighandStruct, SignalStruct};
use alloc::sync::Arc;
use core::sync::atomic::{AtomicBool, AtomicI32, AtomicUsize, Ordering};
use glenda::cap::{CNode, TCB};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(i32)]
pub enum TaskLifecycleState {
    Running = 0,
    Stopped = 1,
    Exiting = 2,
    Exited = 3,
}

impl From<i32> for TaskLifecycleState {
    fn from(v: i32) -> Self {
        match v {
            0 => Self::Running,
            1 => Self::Stopped,
            2 => Self::Exiting,
            3 => Self::Exited,
            _ => Self::Running,
        }
    }
}

pub struct TaskStruct {
    pub pid: usize,
    pub parent_pid: AtomicUsize,
    pub session_id: AtomicUsize,
    pub process_group_id: AtomicUsize,
    pub controlling_tty: AtomicUsize,

    pub tcb: TCB,
    pub cspace: CNode,

    pub lifecycle: AtomicI32,
    pub stopped: AtomicBool,

    pub mm: Arc<MmStruct>,
    pub files: Arc<FilesStruct>,
    pub fs: Arc<FsStruct>,
    pub sighand: Arc<SighandStruct>,
    pub signal: Arc<SignalStruct>,
    pub cred: Arc<CredStruct>,
}

impl TaskStruct {
    pub fn new(
        pid: usize,
        parent_pid: usize,
        tcb: TCB,
        cspace: CNode,
        mm: Arc<MmStruct>,
        files: Arc<FilesStruct>,
        fs: Arc<FsStruct>,
        sighand: Arc<SighandStruct>,
        signal: Arc<SignalStruct>,
        cred: Arc<CredStruct>,
    ) -> Self {
        Self {
            pid,
            parent_pid: AtomicUsize::new(parent_pid),
            session_id: AtomicUsize::new(pid),
            process_group_id: AtomicUsize::new(pid),
            controlling_tty: AtomicUsize::new(0),
            tcb,
            cspace,
            lifecycle: AtomicI32::new(TaskLifecycleState::Running as i32),
            stopped: AtomicBool::new(false),
            mm,
            files,
            fs,
            sighand,
            signal,
            cred,
        }
    }

    pub fn get_lifecycle(&self) -> TaskLifecycleState {
        TaskLifecycleState::from(self.lifecycle.load(Ordering::SeqCst))
    }

    pub fn set_lifecycle(&self, state: TaskLifecycleState) {
        self.lifecycle.store(state as i32, Ordering::SeqCst);
    }

    pub fn is_stopped(&self) -> bool {
        self.stopped.load(Ordering::SeqCst)
    }

    pub fn mark_stopped(&self) {
        self.stopped.store(true, Ordering::SeqCst);
        self.set_lifecycle(TaskLifecycleState::Stopped);
    }

    pub fn mark_running(&self) {
        self.stopped.store(false, Ordering::SeqCst);
        self.set_lifecycle(TaskLifecycleState::Running);
    }

    pub fn mark_exiting(&self) {
        self.set_lifecycle(TaskLifecycleState::Exiting);
    }

    pub fn mark_exited(&self) {
        self.stopped.store(false, Ordering::SeqCst);
        self.set_lifecycle(TaskLifecycleState::Exited);
    }

    pub fn cspace(&self) -> CNode {
        self.cspace.clone()
    }

    pub fn vspace(&self) -> glenda::cap::VSpace {
        self.mm.vspace.clone()
    }

    pub fn tcb(&self) -> TCB {
        self.tcb.clone()
    }
}

impl Drop for TaskStruct {
    fn drop(&mut self) {}
}
