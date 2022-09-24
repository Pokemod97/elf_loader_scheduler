use binread::{BinRead, Error};
use std::{fmt, fmt::Display};

#[derive(Clone, Copy, BinRead)]
#[br(repr=u32)]
enum PTYPE {
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
}

#[derive(Clone, Copy, BinRead)]
#[br(repr=u16)]
enum ETYPE {
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
impl Display for ETYPE {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match *self {
            ETYPE::ET_NONE => f.write_str("ET_NONE"),
            ETYPE::ET_REL => f.write_str("ET_REL"),
            ETYPE::ET_EXEC => f.write_str("ET_EXEC"),
            ETYPE::ET_DYN => f.write_str("ET_DYN"),
            ETYPE::ET_CORE => f.write_str("ET_CORE"),
            ETYPE::ET_LOOS => f.write_str("ET_LOOS"),
            ETYPE::ET_HIOS => f.write_str("ET_HIOS"),
            ETYPE::ET_LOPROC => f.write_str("ET_LOPROC"),
            ETYPE::ET_HIPROC => f.write_str("ET_HIPROC"),
        }
    }
}

#[derive(Clone, Copy, BinRead)]
#[br(repr=u8)]
enum EIOSABI {
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
}
impl fmt::Display for EIOSABI {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match *self {
            EIOSABI::SystemV => f.write_str("SystemV"),
            EIOSABI::HPUX => f.write_str("HPUX"),
            EIOSABI::NetBSD => f.write_str("NetBSD"),
            EIOSABI::Linux => f.write_str("Linux"),
            EIOSABI::GNUHurd => f.write_str("GNUHurd"),
            EIOSABI::Solaris => f.write_str("Solaris"),
            EIOSABI::AIX => f.write_str("AIX"),
            EIOSABI::IRIX => f.write_str("IRIX"),
            EIOSABI::FreeBSD => f.write_str("FreeBSD"),
            EIOSABI::Tru64 => f.write_str("Tru64"),
            EIOSABI::NovellModesto => f.write_str("NovellModesto"),
            EIOSABI::OpenBSD => f.write_str("OpenBSD"),
            EIOSABI::OpenVMS => f.write_str("OpenVMS"),
            EIOSABI::NonStopKernel => f.write_str("NonStopKernel"),
            EIOSABI::AROS => f.write_str("AROS"),
            EIOSABI::FenixOS => f.write_str("FenixOS"),
            EIOSABI::NuxiCloudABI => f.write_str("NuxiCloudABI"),
            EIOSABI::StratusTechnologiesOpenVOS => f.write_str("StratusTechnologiesOpenVOS"),
        }
    }
}

#[derive(BinRead)]
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
        };

        Ok(header)
    }
}
impl fmt::Display for ElfHeader {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "magic: {:#x?},
        ei_class: {},
        ei_version: {:#x},
        ei_data:{},
        ei_osabi: {},
        ei_abiversion: {:#x},
        e_type: {},
        e_machine: {:#x},
        e_version: {},
        e_entry: {:#x?},
        e_phoff: {:#x?},
        e_shoff:{:#x?},
        e_flags: {:#x},
        e_ehsize: {:#x},
        e_phentsize: {:#x},
        e_phnum: {:#x},
        e_shentsize: {:#x},",
            self.magic,
            self.ei_class,
            self.ei_version,
            self.ei_data,
            self.ei_osabi,
            self.ei_abiversion,
            self.e_type,
            self.e_machine,
            self.e_version,
            self.e_entry,
            self.e_phoff,
            self.e_shoff,
            self.e_flags,
            self.e_ehsize,
            self.e_phentsize,
            self.e_phnum,
            self.e_shentsize
        )
    }
}
pub struct ElfHeader64 {
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
    e_entry: u64,
    e_phoff: u64,
    e_shoff: u64,
    e_flags: u32,
    e_ehsize: u16,
    e_phentsize: u16,
    e_phnum: u16,
    e_shentsize: u16,
}

impl fmt::Display for ElfHeader64 {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "magic: {:#x?},
        ei_class: {},
        ei_version: {:#x},
        ei_data:{},
        ei_osabi: {},
        ei_abiversion: {:#x},
        e_type: {},
        e_machine: {:#x},
        e_version: {},
        e_entry: {:#x},
        e_phoff: {:#x},
        e_shoff:{:#x},
        e_flags: {:#x},
        e_ehsize: {:#x},
        e_phentsize: {:#x},
        e_phnum: {:#x},
        e_shentsize: {:#x},",
            self.magic,
            self.ei_class,
            self.ei_version,
            self.ei_data,
            self.ei_osabi,
            self.ei_abiversion,
            self.e_type,
            self.e_machine,
            self.e_version,
            self.e_entry,
            self.e_phoff,
            self.e_shoff,
            self.e_flags,
            self.e_ehsize,
            self.e_phentsize,
            self.e_phnum,
            self.e_shentsize
        )
    }
}
