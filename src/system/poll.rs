use crate::ApeManager;
use crate::ape::process::FileType as ApeFileType;
use crate::io::tty::terminal_poll_readable;
use core::mem::size_of;
use glenda::error::Error;
use linux_raw_sys::general::{POLLIN, POLLNVAL, POLLOUT, POLLPRI, pollfd};

fn pollin_ready_for_fd(mgr: &mut ApeManager<'_>, pid: usize, fd: u32) -> Result<bool, Error> {
    let term = {
        let process = mgr.get_process(pid).ok_or(Error::NotFound)?;
        let handle = process.fds.get(&fd).ok_or(Error::InvalidSlot)?;
        match handle.file_type {
            ApeFileType::Terminal(term) => Some(term),
            ApeFileType::PtyMaster(master) => Some(master.term),
            ApeFileType::PtySlave(slave) => Some(slave.term),
            _ => None,
        }
    };

    if let Some(term) = term { terminal_poll_readable(mgr, term) } else { Ok(true) }
}

pub(crate) fn do_ppoll(
    mgr: &mut ApeManager<'_>,
    pid: usize,
    fds_ptr: usize,
    nfds: usize,
    timeout: usize,
    _sigmask: usize,
    _sigsetsize: usize,
) -> Result<isize, Error> {
    if nfds == 0 {
        return Ok(0);
    }
    if fds_ptr == 0 {
        return Err(Error::InvalidAddress);
    }
    if nfds > 4096 {
        return Err(Error::InvalidArgs);
    }

    let block_forever = timeout == 0;
    loop {
        let mut ready_count = 0usize;

        for i in 0..nfds {
            let p = fds_ptr
                .checked_add(i.checked_mul(size_of::<pollfd>()).ok_or(Error::InvalidAddress)?)
                .ok_or(Error::InvalidAddress)?;

            let mut raw = [0u8; size_of::<pollfd>()];
            mgr.copy_from_user(pid, p, &mut raw)?;
            let mut pfd = unsafe { (raw.as_ptr() as *const pollfd).read_unaligned() };

            pfd.revents = 0;
            if pfd.fd >= 0 {
                let fd = pfd.fd as u32;
                let valid = {
                    let process = mgr.get_process(pid).ok_or(Error::NotFound)?;
                    process.fds.contains_key(&fd)
                };
                if !valid {
                    pfd.revents = POLLNVAL as i16;
                    ready_count += 1;
                } else {
                    let mut revents = 0i16;
                    if ((pfd.events as u32) & (POLLIN | POLLPRI)) != 0
                        && pollin_ready_for_fd(mgr, pid, fd)?
                    {
                        revents |= POLLIN as i16;
                    }
                    if ((pfd.events as u32) & POLLOUT) != 0 {
                        revents |= POLLOUT as i16;
                    }
                    pfd.revents = revents;
                    if revents != 0 {
                        ready_count += 1;
                    }
                }
            }

            let out = unsafe {
                core::slice::from_raw_parts((&pfd as *const pollfd) as *const u8, size_of::<pollfd>())
            };
            mgr.copy_to_user(pid, p, out)?;
        }

        if ready_count > 0 || !block_forever {
            return Ok(ready_count as isize);
        }

        core::hint::spin_loop();
    }
}
