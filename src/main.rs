use binread::{io::StreamPosition, BinReaderExt};
use mman::{ProtFlags, MapFlags};
use nix::unistd::{fork, ForkResult};
use nix::sys::mman;
use std::ffi::c_void;
use std::ptr::null;
use std::slice::from_raw_parts_mut;
use std::{
    env,
    fs::File,
    io::{Read, Seek, SeekFrom},
    path::Path, os::unix::prelude::{AsFd, IntoRawFd, AsRawFd}, arch::asm,
};

use crate::elf_handler::{ElfHeader, ElfHeader64, ProgramHeader64, SectionHeader64, SHTYPE::*, PTYPE};
mod elf_handler;
const MAGIC_HEADER: [u8; 4] = [0x7f, 0x45, 0x4c, 0x46];
use binread::NullString;
fn main() {
    let args: Vec<String> = env::args().collect();
    let args: Vec<String> = args[1..args.len()].to_vec();
    for file in args {
        print_elf(Path::new(&file));
        launch_elf(Path::new(&file));
    }
}
fn launch_elf(file_path: &Path){
    let mut file: File;
    match File::open(file_path) {
        Ok(a) => file = a,
        Err(a) => {
            println!("Error no file. {a}");
            return;
        }
    }
    let header64 = get_file_header(&mut file);
    let program_headers = get_program_header(&mut file, &header64);
    unsafe{
        match fork() {
            Ok(ForkResult::Child) => {
                let fd = file.as_raw_fd();
                let mut addr: Vec<*mut c_void> = Vec::new();
                let mut stack: u64 = 0;
                for x in program_headers{
                    if (x.p_type == PTYPE::PT_LOAD || x.p_type == PTYPE::PT_PHDR ) && x.p_filesz == x.p_memsz{
                  match mman::mmap(x.p_vaddr as *mut c_void, x.p_memsz as usize, ProtFlags::from_bits_truncate(x.p_flags), MapFlags::MAP_PRIVATE, fd, x.p_offset as i64) {
                       Ok(a) => addr.push(a),
                       Err(a) => println!("{:#?} {:#?}", a, x),
                   } 
                } else if x.p_type == PTYPE::PT_GNU_STACK {
                    match mman::mmap(0u64 as *mut c_void,  81920 ,  ProtFlags::PROT_READ | ProtFlags::PROT_WRITE, MapFlags::MAP_PRIVATE | MapFlags::MAP_GROWSDOWN | MapFlags::MAP_STACK | MapFlags::MAP_ANONYMOUS, -1, 0) {
                        Ok(a) => {
                            let a: u64 = a as u64 + 81820;
                            stack = (a)+ ((x.p_align - ((a) % x.p_align)) % x.p_align);},
                        Err(a) => println!("{:#?} {:#?}", a, x),
                    }
                }else if x.p_type == PTYPE::PT_LOAD && x.p_filesz != x.p_memsz{
                    match mman::mmap(x.p_vaddr as *mut c_void, x.p_memsz as usize * 2, ProtFlags::from_bits_truncate(x.p_flags), MapFlags::MAP_PRIVATE | MapFlags::MAP_ANONYMOUS, -1, 0) {
                        Ok(a) => {addr.push(a);
                        file.seek(SeekFrom::Start(x.p_offset)).expect("dksaj");
                        let memblock: &mut [u8] = from_raw_parts_mut(x.p_vaddr as *mut u8, x.p_filesz as usize);
                        file.read(memblock).expect("msg");
                        },
                        Err(a) => println!("{:#?} {:#?}", a, x),
                    } 
                    } 
                
            }

                asm!("mov rsp, {0}; xor rax, rax; xor rbx, rbx; xor rdx, rdx; jmp rcx;", in(reg) stack, in("rcx")header64.e_entry);
            },
        _ => {

        }
        }
    }
}
fn print_elf(file_path: &Path) {
    let mut file: File;
    match File::open(file_path) {
        Ok(a) => file = a,
        Err(a) => {
            println!("Error no file. {a}");
            return;
        }
    }
    let header64 = get_file_header(&mut file);
    println!("{:#x?}", header64);
    let program_headers = get_program_header(&mut file, &header64);
    println!("{:#x?}", program_headers);
    /*let sections = get_sections(&mut file, header64);
    println!("{:#x?}", sections);
    let mut strs: Vec<String> = Vec::new();

    for x in sections {
        if x.sh_type == SHT_STRTAB{
            let start = file.seek(SeekFrom::Start(x.sh_offset)).unwrap();
            while file.stream_position().unwrap() <= (start + x.sh_size) {
                let stra: NullString = file.read_ne().unwrap();
                strs.push(stra.into_string());
            }
        }
    }
    println!("{:#?}", strs);*/
}

fn get_file_header(file: &mut File) -> ElfHeader64 {
    let mut magic: [u8; 4] = [0; 4];
    while magic != MAGIC_HEADER {
        file.read(&mut magic).unwrap();
    }
    let seek_pos = file.stream_position().expect("can't seek") - 4;
    file.rewind().expect("rewind");
    file.seek(SeekFrom::Start(seek_pos)).expect("no seek");
    let header: ElfHeader = file.read_ne().unwrap();
    header.convert64().expect("ok")
}
fn get_program_header(file: &mut File, header64: &ElfHeader64) -> Vec<ProgramHeader64> {
    file.seek(SeekFrom::Start(header64.e_phoff)).expect("error");
    let mut program_headers: Vec<ProgramHeader64> = Vec::new();
    for i in 0..header64.e_phnum {
        match file.read_ne::<ProgramHeader64>() {
            Ok(a) => {
                program_headers.push(a)
            }
            Err(b) => {
                let mut buf = [0u8; 8];
                file.read(&mut buf);
                println!("{b} {:#x?}", buf);
            }
        }
    }
    program_headers
}
fn get_sections(file: &mut File, header64: ElfHeader64) -> Vec<SectionHeader64> {
    let mut sections: Vec<SectionHeader64> = Vec::new();
    let addr = file.seek(SeekFrom::Start(header64.e_shoff)).expect("error");
    println!("{:x}", addr);
    for i in 0..header64.e_shnum {
        match file.read_ne::<SectionHeader64>() {
            Ok(a) => {
                sections.push(a);
            }
            Err(b) => {
                file.seek(SeekFrom::Current(4));
                println!("{b} {:#x?}", file.read_ne::<u32>().unwrap());
            }
        }
    }
    sections
}
