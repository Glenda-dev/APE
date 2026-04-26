use alloc::collections::BTreeMap;
use alloc::string::String;
use glenda::cap::CapPtr;
use glenda::client::FsClient;
use glenda::io::uring::IoUringClient;
use glenda::ipc::Badge;
use glenda::interface::FileHandleService;
use glenda::sync::rwlock::RwLock;
use glenda::error::Error;

#[derive(Debug, Clone, Copy)]
pub struct AsyncIoRegion {
    pub id: usize,
    pub frame_slot: CapPtr,
    pub vaddr: usize,
    pub size: usize,
}

#[derive(Debug, Clone, Copy)]
pub struct AsyncIoState {
    pub region_id: usize,
    pub ring: IoUringClient,
    pub data_vaddr: usize,
    pub data_len: usize,
    pub next_user_data: usize,
}

#[derive(Debug, Clone, Copy)]
pub enum NormalHandleBackend {
    Fs,
}

#[derive(Debug, Clone, Copy)]
pub struct NormalFileHandle {
    pub backend: NormalHandleBackend,
    pub fs_client: FsClient,
    pub fs_ep_slot: CapPtr,
    pub offset: usize,
    pub async_io: Option<AsyncIoState>,
}

impl NormalFileHandle {
    pub fn poll(&mut self, events: u32) -> Result<u32, Error> {
        match self.backend {
            NormalHandleBackend::Fs => self.fs_client.poll(Badge::null(), events),
        }
    }
}

#[derive(Debug, Clone, Copy)]
pub enum FileType {
    Normal(NormalFileHandle),
}

#[derive(Debug, Clone)]
pub struct FileHandle {
    pub file_type: FileType,
}

pub struct FilesState {
    pub fds: BTreeMap<u32, FileHandle>,
    pub fd_paths: BTreeMap<u32, String>,
    pub fd_cloexec: BTreeMap<u32, bool>,
    pub next_fd: u32,
}

pub struct FilesStruct {
    pub state: RwLock<FilesState>,
}

impl FilesStruct {
    pub fn new() -> Self {
        Self {
            state: RwLock::new(FilesState {
                fds: BTreeMap::new(),
                fd_paths: BTreeMap::new(),
                fd_cloexec: BTreeMap::new(),
                next_fd: 0,
            }),
        }
    }
}

impl Drop for FilesStruct {
    fn drop(&mut self) {
        // Automatically close all file descriptors.
    }
}
