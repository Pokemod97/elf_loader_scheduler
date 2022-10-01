use binread::{BinRead, Error};
use std::{fmt, fmt::Display};

#[derive(Clone, Copy, BinRead, Debug)]
#[br(repr=u32)]
#[non_exhaustive]
enum SHFLAGS32 {
    SHF_WRITE = 1,
    SHF_ALLOC,
    SHF_EXECINSTR,
    SHF_MERGE,
    SHF_STRINGS,
    SHF_INFO_LINK,
    SHF_LINK_ORDER,
    SHF_OS_NONCONFORMING,
    SHF_GROUP,
    SHF_TLS,
    SHF_MASKOS,
    SHF_MASKPROC,
    SHF_ORDERED,
    SHF_EXCLUDE,
}
#[derive(Clone, Copy, BinRead, Debug)]
#[br(repr=u64)]
#[non_exhaustive]
enum SHFLAGS64 {
    SHF_WRITE = 1,
    SHF_ALLOC,
    SHF_EXECINSTR,
    SHF_MERGE,
    SHF_STRINGS,
    SHF_INFO_LINK,
    SHF_LINK_ORDER,
    SHF_OS_NONCONFORMING,
    SHF_GROUP,
    SHF_TLS,
    SHF_MASKOS,
    SHF_MASKPROC,
    SHF_ORDERED,
    SHF_EXCLUDE,
}

#[derive(Clone, Copy, BinRead, Debug, PartialEq, Eq)]
#[br(repr=u32)]
#[non_exhaustive]
pub enum SHTYPE {
    SHT_NULL,
    SHT_PROGBITS,
    SHT_SYMTAB,
    SHT_STRTAB,
    SHT_RELA,
    SHT_HASH,
    SHT_DYNAMIC,
    SHT_NOTE,
    SHT_NOBITS,
    SHT_REL,
    SHT_SHLIB,
    SHT_DYNSYM,
    SHT_INIT_ARRAY,
    SHT_FINI_ARRAY,
    SHT_PREINIT_ARRAY,
    SHT_GROUP,
    SHT_SYMTAB_SHNDX,
    SHT_NUM,
    SHT_LOOS = 0x60000000,
    SHT_GNU_HASH = 0x6fff_fff6,
    VERSYM = 0x6fffffff,
    VERNEED = 0x6ffffffe,
}

#[derive(Clone, Copy, BinRead, Debug, PartialEq, Eq)]
#[br(repr=u32)]
#[non_exhaustive]

pub enum PTYPE {
    PT_NULL,
    PT_LOAD,
    PT_DYNAMIC,
    PT_INTERP,
    PT_NOTE,
    PT_SHLIB,
    PT_PHDR,
    PT_TLS,
    PT_LOOS = 0x60000000,
    PT_HIOS = 0x6FFFFFFF,
    PT_LOPROC = 0x70000000,
    PT_HIPROC = 0x7FFFFFFF,
    PT_GNU_EH_FRAME = 0x6474e550,
    PT_GNU_STACK = 0x6474e551,
    PT_GNU_RELRO = 0x6474e552,
    GNU_PROPERTY = 0x46474e553,
}

#[derive(Clone, Copy, BinRead, Debug)]
#[br(repr=u16)]
#[non_exhaustive]
pub enum ETYPE {
    ET_NONE,
    ET_REL,
    ET_EXEC,
    ET_DYN,
    ET_CORE,
    ET_LOOS,
    ET_HIOS = 0xFE00,
    ET_LOPROC = 0xFF00,
    ET_HIPROC = 0xFFFF,
}

#[derive(Clone, Copy, BinRead, Debug)]
#[br(repr=u8)]
#[non_exhaustive]
pub enum EIOSABI {
    SystemV,
    HPUX,
    NetBSD,
    Linux,
    GNUHurd,
    Solaris,
    AIX,
    IRIX,
    FreeBSD,
    Tru64,
    NovellModesto,
    OpenBSD,
    OpenVMS,
    NonStopKernel,
    AROS,
    FenixOS,
    NuxiCloudABI,
    StratusTechnologiesOpenVOS,
    UNKNOWN = 0xbf,
}

#[derive(BinRead, Debug)]
pub struct ElfHeader {
    magic: [u8; 4],
    ei_class: u8,
    ei_version: u8,
    ei_data: u8,
    ei_osabi: EIOSABI,
    ei_abiversion: u8,
    ei_pad: [u8; 7],
    e_type: ETYPE,
    e_machine: u16,
    e_version: u32,
    #[br(count = ei_class *4)]
    e_entry: Vec<u8>,
    #[br(count = ei_class *4)]
    e_phoff: Vec<u8>,
    #[br(count = ei_class *4)]
    e_shoff: Vec<u8>,
    e_flags: u32,
    e_ehsize: u16,
    e_phentsize: u16,
    e_phnum: u16,
    e_shentsize: u16,
    pub e_shnum: u16,
    pub e_shstrndx: u16,
}
impl ElfHeader {
    pub fn convert64(&self) -> Result<ElfHeader64, Error> {
        let mut array: [u8; 8] = [0; 8];
        array.clone_from_slice(&self.e_entry);
        let entry = u64::from_le_bytes(array);
        array.clone_from_slice(&self.e_phoff);
        let e_phoff = u64::from_le_bytes(array);
        array.clone_from_slice(&self.e_shoff);
        let e_shoff = u64::from_le_bytes(array);
        let header: ElfHeader64 = ElfHeader64 {
            magic: self.magic,
            ei_class: self.ei_class,
            ei_version: self.ei_version,
            ei_data: self.ei_data,
            ei_osabi: self.ei_osabi,
            ei_abiversion: self.ei_abiversion,
            ei_pad: self.ei_pad,
            e_type: self.e_type,
            e_machine: self.e_machine,
            e_version: self.e_version,
            e_entry: entry,
            e_phoff: e_phoff,
            e_shoff: e_shoff,
            e_flags: self.e_flags,
            e_ehsize: self.e_ehsize,
            e_phentsize: self.e_phentsize,
            e_phnum: self.e_phnum,
            e_shentsize: self.e_shentsize,
            e_shnum: self.e_shnum,
            e_shstrndx: self.e_shstrndx,
        };

        Ok(header)
    }
}

#[derive(BinRead, Debug)]
pub struct ElfHeader64 {
    magic: [u8; 4],
    pub ei_class: u8,
    pub ei_version: u8,
    pub ei_data: u8,
    pub ei_osabi: EIOSABI,
    pub ei_abiversion: u8,
    pub ei_pad: [u8; 7],
    pub e_type: ETYPE,
    pub e_machine: u16,
    pub e_version: u32,
    pub e_entry: u64,
    pub e_phoff: u64,
    pub e_shoff: u64,
    pub e_flags: u32,
    pub e_ehsize: u16,
    pub e_phentsize: u16,
    pub e_phnum: u16,
    pub e_shentsize: u16,
    pub e_shnum: u16,
    pub e_shstrndx: u16,
}

#[derive(BinRead, Debug)]
pub struct ProgramHeader64 {
    pub p_type: PTYPE,
    pub p_flags: i32,
    pub p_offset: u64,
    pub p_vaddr: u64,
    pub p_paddr: u64,
    pub p_filesz: u64,
    pub p_memsz: u64,
    pub p_align: u64,
}
#[derive(BinRead, Debug)]
struct ProgramHeader32 {
    p_type: PTYPE,
    p_offset: i32,
    p_vaddr: u32,
    p_paddr: u32,
    p_filesz: u32,
    p_flags: u32,
    p_memsz: u32,
    p_align: u32,
}

#[derive(BinRead, Debug, Clone, Copy)]
pub struct SectionHeader64 {
    pub sh_name: u32,
    pub sh_type: SHTYPE,
    pub sh_flags: u64,
    sh_addr: u64,
    pub sh_offset: u64,
    pub sh_size: u64,
    sh_link: u32,
    sh_info: u32,
    sh_addralign: u64,
    sh_entsize: u64,
}

#[derive(BinRead, Debug)]
pub struct SectionHeader32 {
    sh_name: u32,
    sh_type: SHTYPE,
    sh_flags: u32,
    sh_addr: u32,
    sh_size: u32,
    sh_link: u32,
    sh_info: u32,
    sh_addralign: u32,
    sh_entsize: u32,
}
