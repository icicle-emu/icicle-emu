//! Module for manipulating the auxillary vector

use target_lexicon::{Endianness, PointerWidth};

pub const AT_NULL: u32 = 0;
pub const AT_IGNORE: u32 = 1;
pub const AT_EXECFD: u32 = 2;
pub const AT_PHDR: u32 = 3;
pub const AT_PHENT: u32 = 4;
pub const AT_PHNUM: u32 = 5;
pub const AT_PAGESZ: u32 = 6;
pub const AT_BASE: u32 = 7;
pub const AT_FLAGS: u32 = 8;
pub const AT_ENTRY: u32 = 9;
pub const AT_NOTELF: u32 = 10;
pub const AT_UID: u32 = 11;
pub const AT_EUID: u32 = 12;
pub const AT_GID: u32 = 13;
pub const AT_EGID: u32 = 14;
pub const AT_PLATFORM: u32 = 15;
pub const AT_HWCAP: u32 = 16;
pub const AT_CLKTCK: u32 = 17;
pub const AT_SECURE: u32 = 23;
pub const AT_BASE_PLATFORM: u32 = 24;
pub const AT_RANDOM: u32 = 25;
pub const AT_EXECFN: u32 = 31;
pub const AT_SYSINFO: u32 = 32;
pub const AT_SYSINFO_EHDR: u32 = 33;

pub fn setup_auxv(triple: &target_lexicon::Triple, image: &crate::LoadedImage, auxv: &mut Vec<u8>) {
    let is_le = triple.endianness().map_or(true, |endian| endian == Endianness::Little);

    if is_le {
        match triple.pointer_width().unwrap() {
            PointerWidth::U16 => panic!("16-bit LE architectures are not supported"),
            PointerWidth::U32 => setup_auxv_inner::<Elf32LeAuxWriter>(image, auxv),
            PointerWidth::U64 => setup_auxv_inner::<Elf64LeAuxWriter>(image, auxv),
        }
    }
    else {
        match triple.pointer_width().unwrap() {
            PointerWidth::U16 => panic!("16-bit LE architectures are not supported"),
            PointerWidth::U32 => setup_auxv_inner::<Elf32BeAuxWriter>(image, auxv),
            PointerWidth::U64 => panic!("32-bit BE architectures are not supported"),
        }
    }
}

trait AuxWriter {
    /// The size (in bytes of the program header)
    const PROGRAM_HEADER_SIZE: usize;

    fn add(buf: &mut Vec<u8>, key: u32, value: u64);
}

pub struct Elf32BeAuxWriter;

impl AuxWriter for Elf32BeAuxWriter {
    const PROGRAM_HEADER_SIZE: usize =
        std::mem::size_of::<object::elf::ProgramHeader32<object::endian::Endianness>>();

    fn add(buf: &mut Vec<u8>, key: u32, value: u64) {
        buf.extend_from_slice(&key.to_be_bytes());
        buf.extend_from_slice(&(value as u32).to_be_bytes());
    }
}

pub struct Elf32LeAuxWriter;

impl AuxWriter for Elf32LeAuxWriter {
    const PROGRAM_HEADER_SIZE: usize =
        std::mem::size_of::<object::elf::ProgramHeader32<object::endian::Endianness>>();

    fn add(buf: &mut Vec<u8>, key: u32, value: u64) {
        buf.extend_from_slice(&key.to_le_bytes());
        buf.extend_from_slice(&(value as u32).to_le_bytes());
    }
}

pub struct Elf64LeAuxWriter;

impl AuxWriter for Elf64LeAuxWriter {
    const PROGRAM_HEADER_SIZE: usize =
        std::mem::size_of::<object::elf::ProgramHeader64<object::endian::Endianness>>();

    fn add(buf: &mut Vec<u8>, key: u32, value: u64) {
        buf.extend_from_slice(&(key as u64).to_le_bytes());
        buf.extend_from_slice(&value.to_le_bytes());
    }
}

fn setup_auxv_inner<A: AuxWriter>(image: &crate::LoadedImage, auxv: &mut Vec<u8>) {
    A::add(auxv, AT_SYSINFO_EHDR, 0x0); // @fixme:[vdso] Emulator vDSO format is not correct.
    A::add(auxv, AT_HWCAP, 0x0); // @fixme[hwcap]: not supported yet
    A::add(auxv, AT_PAGESZ, 4096); // @fixme[pagesize]: allow this to change
    A::add(auxv, AT_CLKTCK, 100);
    A::add(auxv, AT_PHDR, image.phdr_ptr);
    A::add(auxv, AT_PHENT, A::PROGRAM_HEADER_SIZE as u64);
    A::add(auxv, AT_PHNUM, image.phdr_num);
    A::add(auxv, AT_BASE, image.base_ptr);
    A::add(auxv, AT_FLAGS, 0x0);
    A::add(auxv, AT_ENTRY, image.entry_ptr);
    A::add(auxv, AT_UID, 0);
    A::add(auxv, AT_EUID, 0);
    A::add(auxv, AT_GID, 0);
    A::add(auxv, AT_EGID, 0);
    A::add(auxv, AT_SECURE, 0);
    A::add(auxv, AT_RANDOM, image.rand_ptr);
    A::add(auxv, AT_EXECFN, image.pathname_ptr);
    A::add(auxv, AT_PLATFORM, image.platform_ptr);
    A::add(auxv, AT_NULL, 0);
}
