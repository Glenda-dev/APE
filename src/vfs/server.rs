//! APE VFS namespace adapters.

use alloc::sync::Arc;

use glenda::error::Error;
use glenda::ipc::Badge;
use glenda::protocol::fs;
use glenda::sync::mutex::Mutex;
use glenda::vfs::FsNamespace;

use super::devtmpfs::{DevTmpFs, DevTmpFsHandle};
use super::pipe::{PipeEnd, PipeHandle, PipeRegistry};
use super::tmpfs::{TmpFs, TmpFsHandle};

pub(crate) struct DevTmpFsNamespace {
    inner: Arc<DevTmpFs>,
}

impl DevTmpFsNamespace {
    pub(crate) fn new() -> Self {
        Self { inner: Arc::new(DevTmpFs::new()) }
    }
}

impl Default for DevTmpFsNamespace {
    fn default() -> Self {
        Self::new()
    }
}

impl FsNamespace for DevTmpFsNamespace {
    type Handle = DevTmpFsHandle;

    fn open(
        &mut self,
        path: &str,
        flags: fs::OpenFlags,
        mode: u32,
        _badge: Badge,
    ) -> Result<Self::Handle, Error> {
        self.inner.open(path, flags, mode)
    }

    fn mkdir(&mut self, path: &str, mode: u32, _badge: Badge) -> Result<(), Error> {
        self.inner.mkdir(path, mode)
    }

    fn unlink(&mut self, path: &str, _badge: Badge) -> Result<(), Error> {
        self.inner.unlink(path)
    }

    fn stat_path(&mut self, path: &str, _badge: Badge) -> Result<fs::Stat, Error> {
        self.inner.stat(path)
    }

    fn readlink_path(&mut self, path: &str, _badge: Badge) -> Result<alloc::string::String, Error> {
        self.inner.readlink(path)
    }
}

pub(crate) struct TmpFsNamespace {
    inner: Arc<TmpFs>,
}

impl TmpFsNamespace {
    pub(crate) fn new() -> Self {
        Self { inner: Arc::new(TmpFs::new()) }
    }
}

impl Default for TmpFsNamespace {
    fn default() -> Self {
        Self::new()
    }
}

impl FsNamespace for TmpFsNamespace {
    type Handle = TmpFsHandle;

    fn open(
        &mut self,
        path: &str,
        flags: fs::OpenFlags,
        mode: u32,
        _badge: Badge,
    ) -> Result<Self::Handle, Error> {
        self.inner.open(path, flags, mode)
    }

    fn mkdir(&mut self, path: &str, mode: u32, _badge: Badge) -> Result<(), Error> {
        self.inner.mkdir(path, mode)
    }

    fn unlink(&mut self, path: &str, _badge: Badge) -> Result<(), Error> {
        self.inner.unlink(path)
    }

    fn stat_path(&mut self, path: &str, _badge: Badge) -> Result<fs::Stat, Error> {
        self.inner.stat(path)
    }

    fn readlink_path(&mut self, path: &str, _badge: Badge) -> Result<alloc::string::String, Error> {
        self.inner.readlink(path)
    }
}

pub(crate) struct PipeFsNamespace {
    reg: Arc<Mutex<PipeRegistry>>,
}

impl PipeFsNamespace {
    pub(crate) fn new() -> Self {
        Self { reg: Arc::new(Mutex::new(PipeRegistry::new())) }
    }
}

impl Default for PipeFsNamespace {
    fn default() -> Self {
        Self::new()
    }
}

impl FsNamespace for PipeFsNamespace {
    type Handle = PipeHandle;

    fn open(
        &mut self,
        path: &str,
        _flags: fs::OpenFlags,
        _mode: u32,
        _badge: Badge,
    ) -> Result<Self::Handle, Error> {
        let p = path.trim_start_matches('/');
        let mut parts = p.split('/');
        let Some(id_part) = parts.next() else {
            return Err(Error::InvalidArgs);
        };
        let Some(end_part) = parts.next() else {
            return Err(Error::InvalidArgs);
        };
        if parts.next().is_some() {
            return Err(Error::InvalidArgs);
        }
        let pipe_id = id_part.parse::<usize>().map_err(|_| Error::InvalidArgs)?;
        let end = match end_part {
            "r" | "read" => PipeEnd::Read,
            "w" | "write" => PipeEnd::Write,
            _ => return Err(Error::InvalidArgs),
        };
        if !self.reg.lock().open_pipe(pipe_id, end) {
            return Err(Error::NotFound);
        }
        Ok(PipeHandle::new(self.reg.clone(), pipe_id, end))
    }

    fn mkdir(&mut self, _path: &str, _mode: u32, _badge: Badge) -> Result<(), Error> {
        Err(Error::NotSupported)
    }

    fn unlink(&mut self, _path: &str, _badge: Badge) -> Result<(), Error> {
        Err(Error::NotSupported)
    }

    fn stat_path(&mut self, _path: &str, _badge: Badge) -> Result<fs::Stat, Error> {
        Err(Error::NotSupported)
    }

    fn readlink_path(
        &mut self,
        _path: &str,
        _badge: Badge,
    ) -> Result<alloc::string::String, Error> {
        Err(Error::NotSupported)
    }

    fn create_pipe(&mut self, _badge: Badge) -> Result<usize, Error> {
        Ok(self.reg.lock().create_pipe())
    }
}
