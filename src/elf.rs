use core::mem::size_of;
use linux_raw_sys::elf::{
    ELFMAG, ET_DYN, Elf_Ehdr, Elf_Phdr, PF_R, PF_W, PF_X, PT_INTERP, PT_LOAD, PT_PHDR, PT_TLS,
};
use linux_raw_sys::elf_uapi::ET_EXEC;

pub struct ElfFile<'a> {
    data: &'a [u8],
    header: Elf_Ehdr,
}

impl<'a> ElfFile<'a> {
    pub fn new(data: &'a [u8]) -> Result<Self, &'static str> {
        if data.len() < size_of::<Elf_Ehdr>() {
            return Err("Buffer too small for ELF header");
        }
        let header = unsafe { core::ptr::read_unaligned(data.as_ptr() as *const Elf_Ehdr) };
        if header.e_ident[0..4] != ELFMAG {
            return Err("Invalid ELF magic");
        }
        Ok(Self { data, header })
    }

    pub fn entry_point(&self) -> usize {
        self.header.e_entry as usize
    }

    pub fn file_type(&self) -> u16 {
        self.header.e_type
    }

    pub fn ph_offset(&self) -> usize {
        self.header.e_phoff as usize
    }

    pub fn ph_entry_size(&self) -> usize {
        self.header.e_phentsize as usize
    }

    pub fn ph_num(&self) -> usize {
        self.header.e_phnum as usize
    }

    pub fn interpreter_path(&self) -> Option<&'a str> {
        for phdr in self.program_headers() {
            if phdr.p_type != PT_INTERP {
                continue;
            }

            let start = phdr.p_offset as usize;
            let end = start.checked_add(phdr.p_filesz as usize)?;
            if end > self.data.len() || start >= end {
                return None;
            }

            let bytes = &self.data[start..end];
            let nul_pos = bytes.iter().position(|b| *b == 0).unwrap_or(bytes.len());
            return core::str::from_utf8(&bytes[..nul_pos]).ok();
        }
        None
    }

    pub fn program_headers(&self) -> ProgramHeaders<'a> {
        ProgramHeaders {
            data: self.data,
            ph_off: self.header.e_phoff as usize,
            ph_num: self.header.e_phnum as usize,
            ph_size: self.header.e_phentsize as usize,
            current: 0,
        }
    }
}

pub struct ProgramHeaders<'a> {
    data: &'a [u8],
    ph_off: usize,
    ph_num: usize,
    ph_size: usize,
    current: usize,
}

impl<'a> Iterator for ProgramHeaders<'a> {
    type Item = Elf_Phdr;

    fn next(&mut self) -> Option<Self::Item> {
        if self.current >= self.ph_num {
            return None;
        }

        let off = self.ph_off + self.current * self.ph_size;
        if off + size_of::<Elf_Phdr>() > self.data.len() {
            return None;
        }

        let ph =
            unsafe { core::ptr::read_unaligned(self.data.as_ptr().add(off) as *const Elf_Phdr) };
        self.current += 1;
        Some(ph)
    }
}
