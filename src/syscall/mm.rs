use crate::ApeManager;
use glenda::error::Error;

pub fn sys_brk<'a>(mgr: &mut ApeManager<'a>, pid: usize, addr: usize) -> Result<isize, Error> {
    Ok(crate::mm::do_brk(mgr, pid, addr)? as isize)
}

pub fn sys_mmap<'a>(
    mgr: &mut ApeManager<'a>,
    pid: usize,
    addr: usize,
    len: usize,
    prot: u32,
    flags: u32,
    fd: usize,
    offset: usize,
) -> Result<isize, Error> {
    Ok(crate::mm::do_mmap(mgr, pid, addr, len, prot, flags, fd, offset)? as isize)
}

pub fn sys_munmap<'a>(
    mgr: &mut ApeManager<'a>,
    pid: usize,
    addr: usize,
    len: usize,
) -> Result<isize, Error> {
    crate::mm::do_munmap(mgr, pid, addr, len)
}

pub fn sys_mprotect<'a>(
    mgr: &mut ApeManager<'a>,
    pid: usize,
    addr: usize,
    len: usize,
    prot: u32,
) -> Result<isize, Error> {
    crate::mm::do_mprotect(mgr, pid, addr, len, prot)
}

pub fn sys_mremap<'a>(
    mgr: &mut ApeManager<'a>,
    pid: usize,
    old_addr: usize,
    old_size: usize,
    new_size: usize,
    flags: u32,
    new_addr: usize,
) -> Result<isize, Error> {
    Ok(crate::mm::do_mremap(mgr, pid, old_addr, old_size, new_size, flags, new_addr)? as isize)
}