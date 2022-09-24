use binread::{BinReaderExt};
use std::{
    env,
    fs::File,
    io::{Read, Seek, SeekFrom},
    path::Path,
};

use crate::elf_handler::{ElfHeader, ElfHeader64};
mod elf_handler;
const MAGIC_HEADER: [u8; 4] = [0x7f, 0x45, 0x4c, 0x46];

fn main() {
    let args: Vec<String> = env::args().collect();
    let args: Vec<String> = args[1..args.len()].to_vec();
    for file in args {
        print_elf(Path::new(&file));
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
    let mut magic: [u8; 4] = [0; 4];
    while magic != MAGIC_HEADER {
        match file.read(&mut magic) {
            Ok(_) => (),
            Err(a) => {
                eprintln!("{a}");
                return;
            }
        }
    }
    let seek_pos = file.stream_position().expect("can't seek") - 4;
    file.rewind().expect("rewind");
    file.seek(SeekFrom::Start(seek_pos)).expect("no seek");
    let header: ElfHeader = file.read_ne().unwrap();
    let header64: ElfHeader64 = header.convert64().expect("ok");
    println!("{header64}");
}
