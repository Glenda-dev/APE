use alloc::collections::BTreeMap;
use alloc::collections::VecDeque;
use alloc::vec::Vec;
use glenda::error::Error;
use glenda::interface::FileHandleService;
use glenda::ipc::Badge;
use glenda::protocol::fs::{DEntry, FileType, Stat};

const PIPE_DEFAULT_CAPACITY: usize = 64 * 1024;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum PipeEnd {
    Read,
    Write,
}

pub(crate) struct PipeHandle {
    pipe_id: usize,
    end: PipeEnd,
    registry: alloc::sync::Arc<glenda::sync::mutex::Mutex<PipeRegistry>>,
}

impl PipeHandle {
    pub(crate) fn new(
        registry: alloc::sync::Arc<glenda::sync::mutex::Mutex<PipeRegistry>>,
        pipe_id: usize,
        end: PipeEnd,
    ) -> Self {
        Self { pipe_id, end, registry }
    }
}

impl FileHandleService for PipeHandle {
    fn close(&mut self, _pid: Badge) -> Result<(), Error> {
        let mut reg = self.registry.lock();
        match self.end {
            PipeEnd::Read => reg.close_pipe_read_end(self.pipe_id),
            PipeEnd::Write => reg.close_pipe_write_end(self.pipe_id),
        }
        Ok(())
    }

    fn stat(&self, _pid: Badge) -> Result<Stat, Error> {
        Ok(Stat {
            mode: (FileType::S_IFCHR.bits() as u32) | 0o666,
            nlink: 1,
            blksize: 4096,
            ..Stat::default()
        })
    }

    fn read(&mut self, _pid: Badge, _offset: usize, buf: &mut [u8]) -> Result<usize, Error> {
        if self.end != PipeEnd::Read {
            return Err(Error::InvalidType);
        }
        let (n, _writers_closed) = self
            .registry
            .lock()
            .pipe_read(self.pipe_id, buf)
            .ok_or(Error::NotFound)?;
        Ok(n)
    }

    fn write(&mut self, _pid: Badge, _offset: usize, buf: &[u8]) -> Result<usize, Error> {
        if self.end != PipeEnd::Write {
            return Err(Error::InvalidType);
        }
        let (n, no_readers) = self
            .registry
            .lock()
            .pipe_write(self.pipe_id, buf)
            .ok_or(Error::NotFound)?;
        if no_readers {
            return Err(Error::IoError);
        }
        Ok(n)
    }

    fn getdents(&mut self, _pid: Badge, _count: usize) -> Result<Vec<DEntry>, Error> {
        Err(Error::InvalidType)
    }

    fn seek(&mut self, _pid: Badge, _offset: i64, _whence: usize) -> Result<usize, Error> {
        Err(Error::InvalidArgs)
    }

    fn sync(&mut self, _pid: Badge) -> Result<(), Error> {
        Ok(())
    }

    fn truncate(&mut self, _pid: Badge, _size: usize) -> Result<(), Error> {
        Err(Error::InvalidType)
    }
}

struct PipeState {
    buf: VecDeque<u8>,
    readers: usize,
    writers: usize,
}

pub(crate) struct PipeRegistry {
    pipes: BTreeMap<usize, PipeState>,
    next_pipe_id: usize,
}

impl PipeRegistry {
    pub(crate) fn new() -> Self {
        Self { pipes: BTreeMap::new(), next_pipe_id: 1 }
    }

    pub(crate) fn create_pipe(&mut self) -> usize {
        let pipe_id = self.next_pipe_id;
        self.next_pipe_id = self.next_pipe_id.wrapping_add(1);
        self.pipes.insert(
            pipe_id,
            PipeState {
                buf: VecDeque::with_capacity(PIPE_DEFAULT_CAPACITY),
                readers: 0,
                writers: 0,
            },
        );
        pipe_id
    }

    pub(crate) fn open_pipe(&mut self, pipe_id: usize, end: PipeEnd) -> bool {
        let Some(pipe) = self.pipes.get_mut(&pipe_id) else {
            return false;
        };
        match end {
            PipeEnd::Read => pipe.readers = pipe.readers.saturating_add(1),
            PipeEnd::Write => pipe.writers = pipe.writers.saturating_add(1),
        }
        true
    }

    pub(crate) fn pipe_read(&mut self, pipe_id: usize, dst: &mut [u8]) -> Option<(usize, bool)> {
        let pipe = self.pipes.get_mut(&pipe_id)?;
        let mut n = 0usize;
        while n < dst.len() {
            if let Some(b) = pipe.buf.pop_front() {
                dst[n] = b;
                n += 1;
            } else {
                break;
            }
        }
        Some((n, pipe.writers == 0))
    }

    pub(crate) fn pipe_write(&mut self, pipe_id: usize, src: &[u8]) -> Option<(usize, bool)> {
        let pipe = self.pipes.get_mut(&pipe_id)?;
        if pipe.readers == 0 {
            return Some((0, true));
        }

        let free = PIPE_DEFAULT_CAPACITY.saturating_sub(pipe.buf.len());
        let write_len = core::cmp::min(free, src.len());
        for &b in &src[..write_len] {
            pipe.buf.push_back(b);
        }
        Some((write_len, false))
    }

    pub(crate) fn close_pipe_read_end(&mut self, pipe_id: usize) {
        let mut remove = false;
        if let Some(pipe) = self.pipes.get_mut(&pipe_id) {
            pipe.readers = pipe.readers.saturating_sub(1);
            remove = pipe.readers == 0 && pipe.writers == 0;
        }
        if remove {
            let _ = self.pipes.remove(&pipe_id);
        }
    }

    pub(crate) fn close_pipe_write_end(&mut self, pipe_id: usize) {
        let mut remove = false;
        if let Some(pipe) = self.pipes.get_mut(&pipe_id) {
            pipe.writers = pipe.writers.saturating_sub(1);
            remove = pipe.readers == 0 && pipe.writers == 0;
        }
        if remove {
            let _ = self.pipes.remove(&pipe_id);
        }
    }

    pub(crate) fn clone_pipe_read_end(&mut self, pipe_id: usize) {
        if let Some(pipe) = self.pipes.get_mut(&pipe_id) {
            pipe.readers = pipe.readers.saturating_add(1);
        }
    }

    pub(crate) fn clone_pipe_write_end(&mut self, pipe_id: usize) {
        if let Some(pipe) = self.pipes.get_mut(&pipe_id) {
            pipe.writers = pipe.writers.saturating_add(1);
        }
    }
}
