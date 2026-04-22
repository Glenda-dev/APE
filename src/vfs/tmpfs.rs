use alloc::vec::Vec;
use glenda::error::Error;
use glenda::interface::FileHandleService;
use glenda::ipc::Badge;
use glenda::protocol::fs::{DEntry, OpenFlags, Stat};

#[derive(Default)]
pub struct TmpFs;

impl TmpFs {
    pub fn new() -> Self {
        Self
    }

    pub fn open(&self, _path: &str, _flags: OpenFlags, _mode: u32) -> Result<TmpFsHandle, Error> {
        Err(Error::NotSupported)
    }

    pub fn mkdir(&self, _path: &str, _mode: u32) -> Result<(), Error> {
        Err(Error::NotSupported)
    }

    pub fn unlink(&self, _path: &str) -> Result<(), Error> {
        Err(Error::NotSupported)
    }

    pub fn stat(&self, _path: &str) -> Result<Stat, Error> {
        Err(Error::NotSupported)
    }

    pub fn readlink(&self, _path: &str) -> Result<alloc::string::String, Error> {
        Err(Error::NotSupported)
    }
}

pub struct TmpFsHandle;

impl FileHandleService for TmpFsHandle {
    fn close(&mut self, _pid: Badge) -> Result<(), Error> {
        Ok(())
    }

    fn stat(&self, _pid: Badge) -> Result<Stat, Error> {
        Err(Error::NotSupported)
    }

    fn read(&mut self, _pid: Badge, _offset: usize, _buf: &mut [u8]) -> Result<usize, Error> {
        Err(Error::NotSupported)
    }

    fn write(&mut self, _pid: Badge, _offset: usize, _buf: &[u8]) -> Result<usize, Error> {
        Err(Error::NotSupported)
    }

    fn getdents(&mut self, _pid: Badge, _count: usize) -> Result<Vec<DEntry>, Error> {
        Err(Error::NotSupported)
    }

    fn seek(&mut self, _pid: Badge, _offset: i64, _whence: usize) -> Result<usize, Error> {
        Err(Error::NotSupported)
    }

    fn sync(&mut self, _pid: Badge) -> Result<(), Error> {
        Ok(())
    }

    fn truncate(&mut self, _pid: Badge, _size: usize) -> Result<(), Error> {
        Err(Error::NotSupported)
    }
}
