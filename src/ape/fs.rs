use alloc::string::String;
use glenda::sync::rwlock::RwLock;
use crate::layout::DEFAULT_PROCESS_ROOT;

pub struct FsState {
    pub root_dir: String,
    pub cwd: String,
}

pub struct FsStruct {
    pub state: RwLock<FsState>,
}

impl FsStruct {
    pub fn new() -> Self {
        Self {
            state: RwLock::new(FsState {
                root_dir: String::from(DEFAULT_PROCESS_ROOT),
                cwd: String::from(DEFAULT_PROCESS_ROOT),
            }),
        }
    }
}
