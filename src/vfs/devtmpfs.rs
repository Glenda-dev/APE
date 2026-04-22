use crate::drivers::tty::TtyDevice;
use alloc::collections::BTreeMap;
use alloc::string::String;
use alloc::sync::Arc;
use alloc::vec;
use alloc::vec::Vec;
use core::mem::size_of;
use glenda::error::Error;
use glenda::interface::FileHandleService;
use glenda::ipc::Badge;
use glenda::protocol::fs::{DEntry, FileType, OpenFlags, Stat};

use super::tmpfs::TmpFsHandle;

const DEFAULT_DEV_MODE: u32 = 0o666;

#[derive(Clone, Copy)]
struct LinuxDeviceNumber {
    major: u16,
    minor: u32,
}

impl LinuxDeviceNumber {
    const fn new(major: u16, minor: u32) -> Self {
        Self { major, minor }
    }

    fn as_dev_t(self) -> usize {
        linux_mkdev(self.major as u32, self.minor)
    }
}

const fn linux_mkdev(major: u32, minor: u32) -> usize {
    // Linux new-style dev_t encoding.
    (((major & 0x0fff) << 8) | (minor & 0x00ff) | ((minor & 0xffff_ff00) << 12)) as usize
}

#[derive(Clone, Copy)]
struct LinuxCharDeviceMeta {
    mode: u32,
    devno: LinuxDeviceNumber,
}

pub trait LinuxFileOperations: Send + Sync {
    fn read(&self, _offset: usize, _buf: &mut [u8]) -> Result<usize, Error> {
        Err(Error::NotSupported)
    }

    fn write(&self, _offset: usize, _buf: &[u8]) -> Result<usize, Error> {
        Err(Error::NotSupported)
    }

    fn unlocked_ioctl(&self, _cmd: u32, _arg: usize) -> Result<usize, Error> {
        Err(Error::NotSupported)
    }

    fn ioctl_ex(
        &self,
        cmd: u32,
        arg: usize,
        input: Option<&[u8]>,
        out_len: usize,
    ) -> Result<(usize, Vec<u8>), Error> {
        if input.map(|b| !b.is_empty()).unwrap_or(false) || out_len != 0 {
            return Err(Error::NotSupported);
        }
        Ok((self.unlocked_ioctl(cmd, arg)?, Vec::new()))
    }
}

struct LinuxCharDevice {
    meta: LinuxCharDeviceMeta,
    fops: Arc<dyn LinuxFileOperations>,
}

impl LinuxCharDevice {
    fn new(mode: u32, devno: LinuxDeviceNumber, fops: Arc<dyn LinuxFileOperations>) -> Self {
        Self {
            meta: LinuxCharDeviceMeta { mode, devno },
            fops,
        }
    }
}

struct NullFileOps;
impl LinuxFileOperations for NullFileOps {
    fn read(&self, _offset: usize, _buf: &mut [u8]) -> Result<usize, Error> {
        Ok(0)
    }

    fn write(&self, _offset: usize, buf: &[u8]) -> Result<usize, Error> {
        Ok(buf.len())
    }
}

struct ZeroFileOps;
impl LinuxFileOperations for ZeroFileOps {
    fn read(&self, _offset: usize, buf: &mut [u8]) -> Result<usize, Error> {
        buf.fill(0);
        Ok(buf.len())
    }

    fn write(&self, _offset: usize, buf: &[u8]) -> Result<usize, Error> {
        Ok(buf.len())
    }
}

struct RandomFileOps;
impl LinuxFileOperations for RandomFileOps {
    fn read(&self, _offset: usize, buf: &mut [u8]) -> Result<usize, Error> {
        // TODO: wire to kernel RNG service.
        buf.fill(0);
        Ok(buf.len())
    }

    fn write(&self, _offset: usize, buf: &[u8]) -> Result<usize, Error> {
        Ok(buf.len())
    }
}

struct FullFileOps;
impl LinuxFileOperations for FullFileOps {
    fn read(&self, _offset: usize, buf: &mut [u8]) -> Result<usize, Error> {
        buf.fill(0);
        Ok(buf.len())
    }

    fn write(&self, _offset: usize, _buf: &[u8]) -> Result<usize, Error> {
        Err(Error::IoError)
    }
}

struct TtyFileOps;
impl LinuxFileOperations for TtyFileOps {
    fn read(&self, _offset: usize, buf: &mut [u8]) -> Result<usize, Error> {
        TtyDevice::global().read(buf)
    }

    fn write(&self, _offset: usize, buf: &[u8]) -> Result<usize, Error> {
        TtyDevice::global().write(buf)
    }

    fn ioctl_ex(
        &self,
        cmd: u32,
        _arg: usize,
        input: Option<&[u8]>,
        out_len: usize,
    ) -> Result<(usize, Vec<u8>), Error> {
        TtyDevice::global().ioctl_ex(cmd, input, out_len)
    }
}

pub struct DeviceHandle {
    device: Arc<LinuxCharDevice>,
}

impl DeviceHandle {
    fn new(device: Arc<LinuxCharDevice>) -> Self {
        Self { device }
    }
}

impl FileHandleService for DeviceHandle {
    fn close(&mut self, _pid: Badge) -> Result<(), Error> {
        Ok(())
    }

    fn stat(&self, _pid: Badge) -> Result<Stat, Error> {
        Ok(Stat {
            mode: (FileType::S_IFCHR.bits() as u32) | self.device.meta.mode,
            nlink: 1,
            rdev: self.device.meta.devno.as_dev_t(),
            blksize: 4096,
            ..Stat::default()
        })
    }

    fn read(&mut self, _pid: Badge, offset: usize, buf: &mut [u8]) -> Result<usize, Error> {
        self.device.fops.read(offset, buf)
    }

    fn write(&mut self, _pid: Badge, offset: usize, buf: &[u8]) -> Result<usize, Error> {
        self.device.fops.write(offset, buf)
    }

    fn getdents(&mut self, _pid: Badge, _count: usize) -> Result<Vec<DEntry>, Error> {
        Err(Error::InvalidType)
    }

    fn seek(&mut self, _pid: Badge, _offset: i64, _whence: usize) -> Result<usize, Error> {
        Ok(0)
    }

    fn sync(&mut self, _pid: Badge) -> Result<(), Error> {
        Ok(())
    }

    fn truncate(&mut self, _pid: Badge, _size: usize) -> Result<(), Error> {
        Err(Error::InvalidType)
    }

    fn ioctl(&mut self, _pid: Badge, cmd: u32, arg: usize) -> Result<usize, Error> {
        self.device.fops.unlocked_ioctl(cmd, arg)
    }

    fn ioctl_ex(
        &mut self,
        _pid: Badge,
        cmd: u32,
        arg: usize,
        input: Option<&[u8]>,
        out_len: usize,
    ) -> Result<(usize, Vec<u8>), Error> {
        self.device.fops.ioctl_ex(cmd, arg, input, out_len)
    }
}

pub struct DevTmpFs {
    devices: BTreeMap<String, Arc<LinuxCharDevice>>,
}

impl DevTmpFs {
    pub fn new() -> Self {
        let mut devices = BTreeMap::new();

        devices.insert(
            String::from("null"),
            Arc::new(LinuxCharDevice::new(
                DEFAULT_DEV_MODE,
                LinuxDeviceNumber::new(1, 3),
                Arc::new(NullFileOps),
            )),
        );
        devices.insert(
            String::from("zero"),
            Arc::new(LinuxCharDevice::new(
                DEFAULT_DEV_MODE,
                LinuxDeviceNumber::new(1, 5),
                Arc::new(ZeroFileOps),
            )),
        );
        devices.insert(
            String::from("random"),
            Arc::new(LinuxCharDevice::new(
                DEFAULT_DEV_MODE,
                LinuxDeviceNumber::new(1, 8),
                Arc::new(RandomFileOps),
            )),
        );
        devices.insert(
            String::from("urandom"),
            Arc::new(LinuxCharDevice::new(
                DEFAULT_DEV_MODE,
                LinuxDeviceNumber::new(1, 9),
                Arc::new(RandomFileOps),
            )),
        );
        devices.insert(
            String::from("full"),
            Arc::new(LinuxCharDevice::new(
                DEFAULT_DEV_MODE,
                LinuxDeviceNumber::new(1, 7),
                Arc::new(FullFileOps),
            )),
        );
        devices.insert(
            String::from("tty"),
            Arc::new(LinuxCharDevice::new(
                DEFAULT_DEV_MODE,
                LinuxDeviceNumber::new(5, 0),
                Arc::new(TtyFileOps),
            )),
        );

        Self { devices }
    }

    pub fn open(&self, path: &str, _flags: OpenFlags, _mode: u32) -> Result<DevTmpFsHandle, Error> {
        let p = path.trim_start_matches('/');
        if p.is_empty() {
            return Err(Error::InvalidType);
        }

        let dev = self.devices.get(p).cloned().ok_or(Error::NotFound)?;
        Ok(DevTmpFsHandle::Device(DeviceHandle::new(dev)))
    }

    pub fn mkdir(&self, _path: &str, _mode: u32) -> Result<(), Error> {
        Err(Error::NotSupported)
    }

    pub fn unlink(&self, _path: &str) -> Result<(), Error> {
        Err(Error::NotSupported)
    }

    pub fn stat(&self, path: &str) -> Result<Stat, Error> {
        let p = path.trim_start_matches('/');
        if p.is_empty() {
            return Ok(Stat {
                mode: (FileType::S_IFDIR.bits() as u32) | 0o755,
                nlink: 2,
                blksize: 4096,
                ..Stat::default()
            });
        }

        if let Some(dev) = self.devices.get(p) {
            return Ok(Stat {
                mode: (FileType::S_IFCHR.bits() as u32) | dev.meta.mode,
                nlink: 1,
                rdev: dev.meta.devno.as_dev_t(),
                blksize: 4096,
                ..Stat::default()
            });
        }

        Err(Error::NotFound)
    }

    pub fn readlink(&self, _path: &str) -> Result<String, Error> {
        Err(Error::InvalidType)
    }
}

impl Default for DevTmpFs {
    fn default() -> Self {
        Self::new()
    }
}

pub enum DevTmpFsHandle {
    File(TmpFsHandle),
    Device(DeviceHandle),
}

impl FileHandleService for DevTmpFsHandle {
    fn close(&mut self, pid: Badge) -> Result<(), Error> {
        match self {
            Self::File(h) => h.close(pid),
            Self::Device(h) => h.close(pid),
        }
    }

    fn stat(&self, pid: Badge) -> Result<Stat, Error> {
        match self {
            Self::File(h) => h.stat(pid),
            Self::Device(h) => h.stat(pid),
        }
    }

    fn read(&mut self, pid: Badge, offset: usize, buf: &mut [u8]) -> Result<usize, Error> {
        match self {
            Self::File(h) => h.read(pid, offset, buf),
            Self::Device(h) => h.read(pid, offset, buf),
        }
    }

    fn write(&mut self, pid: Badge, offset: usize, buf: &[u8]) -> Result<usize, Error> {
        match self {
            Self::File(h) => h.write(pid, offset, buf),
            Self::Device(h) => h.write(pid, offset, buf),
        }
    }

    fn getdents(&mut self, pid: Badge, count: usize) -> Result<Vec<DEntry>, Error> {
        match self {
            Self::File(h) => h.getdents(pid, count),
            Self::Device(h) => h.getdents(pid, count),
        }
    }

    fn seek(&mut self, pid: Badge, offset: i64, whence: usize) -> Result<usize, Error> {
        match self {
            Self::File(h) => h.seek(pid, offset, whence),
            Self::Device(h) => h.seek(pid, offset, whence),
        }
    }

    fn sync(&mut self, pid: Badge) -> Result<(), Error> {
        match self {
            Self::File(h) => h.sync(pid),
            Self::Device(h) => h.sync(pid),
        }
    }

    fn truncate(&mut self, pid: Badge, size: usize) -> Result<(), Error> {
        match self {
            Self::File(h) => h.truncate(pid, size),
            Self::Device(h) => h.truncate(pid, size),
        }
    }

    fn ioctl(&mut self, pid: Badge, cmd: u32, arg: usize) -> Result<usize, Error> {
        match self {
            Self::File(h) => h.ioctl(pid, cmd, arg),
            Self::Device(h) => h.ioctl(pid, cmd, arg),
        }
    }

    fn ioctl_ex(
        &mut self,
        pid: Badge,
        cmd: u32,
        arg: usize,
        input: Option<&[u8]>,
        out_len: usize,
    ) -> Result<(usize, Vec<u8>), Error> {
        match self {
            Self::File(h) => h.ioctl_ex(pid, cmd, arg, input, out_len),
            Self::Device(h) => h.ioctl_ex(pid, cmd, arg, input, out_len),
        }
    }
}
