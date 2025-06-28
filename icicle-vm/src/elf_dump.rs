use icicle_cpu::debug_info::SymbolKind;
use object::{
    elf,
    write::{elf::SectionIndex, StringId},
};

use crate::{
    cpu::{
        lifter::BlockExit,
        mem::{perm, MemoryMapping},
    },
    Vm,
};

pub fn dump_elf(vm: &mut Vm, path: impl AsRef<std::path::Path>) -> anyhow::Result<()> {
    let entry = vm.env.entry_point();

    let mut regions: Vec<MemoryRegion> = vec![];
    for (start, len, entry) in vm.cpu.mem.get_mapping().iter() {
        let len = len as usize;
        match entry {
            MemoryMapping::Physical(entry) => {
                let offset = vm.cpu.mem.page_offset(start);
                let page = vm.cpu.mem.get_physical(entry.index);

                // Assume that all permissions are the same for the region of memory.
                // @fixme: this is not always the case.
                let perm = page.data().perm[offset];
                let data = &page.data().data[offset..][..len];

                let writable = perm & perm::WRITE != 0;
                let executable = perm & perm::EXEC != 0;

                // Check if we can just extend the previous region with the new data.
                match regions.last_mut() {
                    Some(prev)
                        if start == prev.addr + prev.len as u64
                            && prev.writeable == writable
                            && prev.executable == executable =>
                    {
                        // Pad data to the correct size if needed.
                        let prev_data = match &mut prev.data {
                            Some(data) if data.len() == prev.len => data,
                            Some(data) => {
                                data.resize(prev.len, 0);
                                data
                            }
                            None => {
                                prev.data = Some(vec![0; prev.len]);
                                prev.data.as_mut().unwrap()
                            }
                        };
                        // Then extend the previous region.
                        prev_data.extend_from_slice(data);
                        prev.len += len;
                    }
                    _ => {
                        regions.push(MemoryRegion {
                            addr: start,
                            len,
                            writeable: perm & perm::WRITE != 0,
                            executable: perm & perm::EXEC != 0,
                            data: Some(data.to_vec()),
                            file_offset: 0,
                        });
                    }
                }
            }
            MemoryMapping::Unallocated(entry) => {
                let perm = entry.perm;
                regions.push(MemoryRegion {
                    addr: start,
                    len,
                    writeable: perm & perm::WRITE != 0,
                    executable: perm & perm::EXEC != 0,
                    data: None,
                    file_offset: 0,
                });
            }
            MemoryMapping::Io(_) => continue,
        };
    }

    let data = build_elf(vm, entry, &mut regions)?;
    std::fs::write(path, data)?;

    Ok(())
}

struct MemoryRegion {
    addr: u64,
    len: usize,
    writeable: bool,
    executable: bool,
    data: Option<Vec<u8>>,
    file_offset: usize,
}

impl std::fmt::Debug for MemoryRegion {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("MemoryRegion")
            .field("addr", &self.addr)
            .field("len", &self.len)
            .field("writeable", &self.writeable)
            .field("executable", &self.executable)
            .field("data", &format_args!("{:#x} bytes", self.data.as_ref().map_or(0, |x| x.len())))
            .field("file_offset", &self.file_offset)
            .finish()
    }
}

impl MemoryRegion {
    pub fn file_size(&self) -> usize {
        self.data.as_ref().map_or(0, |x| x.len())
    }
}

pub struct Symbol {
    pub name: Vec<u8>,
    pub addr: u64,
    pub kind: SymbolKind,
    pub binding: u8,
}

struct SymbolOffset {
    _index: object::write::elf::SymbolIndex,
    section: Option<object::write::elf::SectionIndex>,
    str_id: object::write::StringId,
}

pub fn all_known_functions(vm: &Vm) -> Vec<Symbol> {
    // @fixme: allow for mixed mode.
    let is_arm = matches!(vm.cpu.arch.triple.architecture, target_lexicon::Architecture::Arm(_));
    let thumb_bit = if is_arm && vm.cpu.isa_mode() == 1 { 1 } else { 0 };

    let mut symbols = vec![];

    for block in &vm.code.blocks {
        if let BlockExit::Call { target, .. } = &block.exit {
            match target {
                pcode::Value::Const(addr, _) => {
                    let sym = Symbol {
                        name: format!("FUN_{:0x}", addr).into_bytes(),
                        addr: *addr | thumb_bit,
                        kind: SymbolKind::Function,
                        binding: elf::STB_LOCAL, // All functions are treated as local for now.
                    };
                    symbols.push(sym);
                }
                // @fixme: handle indirect calls
                _ => {}
            }
        }
    }

    symbols
}

#[derive(Default)]
struct Section {
    index: Option<SectionIndex>,
    name: Option<StringId>,
    file_offset: u64,
    start: u64,
    end: u64,
}

#[derive(Default)]
struct SectionGroup {
    sections: Vec<Section>,
}

impl SectionGroup {
    pub fn add(&mut self, offset: usize, addr: u64, len: usize) {
        match self.sections.last_mut() {
            Some(prev) if prev.end == addr => {
                prev.file_offset = prev.file_offset.min(offset as u64);
                prev.end += len as u64;
            }
            _ => self.sections.push(Section {
                index: None,
                name: None,
                file_offset: offset as u64,
                start: addr,
                end: addr + len as u64,
            }),
        }
    }
}

fn build_elf(vm: &Vm, entry: u64, mem: &mut [MemoryRegion]) -> anyhow::Result<Vec<u8>> {
    use target_lexicon::Architecture;

    // @todo: get other known symbols here.
    let mut symbols = all_known_functions(vm);
    if let Some(debug_info) = vm.env.debug_info() {
        for (addr, _, name, kind) in debug_info.symbols_iter() {
            symbols.push(Symbol {
                name: name.as_bytes().to_vec(),
                addr,
                kind,
                binding: elf::STB_LOCAL,
            });
        }
    }

    // Local symbols must come first.
    symbols.sort_by_key(|x| if x.binding == elf::STB_LOCAL { 0 } else { 1 });

    let machine = match vm.cpu.arch.triple.architecture {
        Architecture::Arm(_) => elf::EM_ARM,
        Architecture::Aarch64(_) => elf::EM_AARCH64,
        Architecture::Avr => elf::EM_AVR,
        Architecture::Bpfeb | Architecture::Bpfel => elf::EM_BPF,
        Architecture::Hexagon => elf::EM_HEXAGON,
        Architecture::X86_32(_) => elf::EM_386,
        Architecture::Mips32(_) => elf::EM_MIPS,
        Architecture::Mips64(_) => elf::EM_MIPS,
        Architecture::Msp430 => elf::EM_MSP430,
        Architecture::Powerpc => elf::EM_PPC,
        Architecture::Powerpc64 | Architecture::Powerpc64le => elf::EM_PPC64,
        Architecture::Riscv32(_) => elf::EM_RISCV,
        Architecture::Riscv64(_) => elf::EM_RISCV,
        Architecture::S390x => elf::EM_S390,
        Architecture::Sparc | Architecture::Sparcv9 | Architecture::Sparc64 => elf::EM_SPARCV9,
        Architecture::X86_64 => elf::EM_X86_64,
        other => anyhow::bail!("{:?} not supported for export", other),
    };

    let endian = match vm.cpu.arch.sleigh.big_endian {
        true => object::Endianness::Big,
        false => object::Endianness::Little,
    };

    let min_align = vm.cpu.arch.triple.architecture.pointer_width().map_or(4, |x| x.bytes());

    let is_64 = min_align == 8;
    let mut out = vec![];
    let mut writer = object::write::elf::Writer::new(endian, is_64, &mut out);
    writer.reserve_file_header();

    // Reserve program headers, note: we need one program header for each memory region.
    writer.reserve_program_headers(mem.len() as u32);

    let mut text_sections = SectionGroup::default();
    let mut rodata_sections = SectionGroup::default();
    let mut data_sections = SectionGroup::default();
    let mut bss_sections = SectionGroup::default();

    // Reserve file ranges for each memory region.
    for region in &mut *mem {
        match region.file_size() {
            0 => region.file_offset = writer.reserved_len(),
            len => region.file_offset = writer.reserve(len, 0x2),
        }

        match (region.executable, region.writeable, region.file_size() != 0) {
            (true, _, true) => text_sections.add(region.file_offset, region.addr, region.len),
            (false, true, true) => data_sections.add(region.file_offset, region.addr, region.len),
            (false, true, false) => bss_sections.add(region.file_offset, region.addr, region.len),
            (false, false, true) => {
                rodata_sections.add(region.file_offset, region.addr, region.len)
            }
            (_, _, false) => {} // Uninitialized data
        }
    }

    // Reserve sections and section headers.
    let mut sections = vec![];
    macro_rules! add_section {
        ($group:expr, $label:expr) => {
            // Note: the lifetime of `names` extends to end of this function.
            let mut names = vec![$label.as_bytes().to_vec()];
            for i in 1..$group.sections.len() {
                names.push(format!("{}.{i}", $label).into_bytes());
            }
            for (i, section) in $group.sections.iter_mut().enumerate() {
                section.index = Some(writer.reserve_section_index());
                section.name = Some(writer.add_section_name(&names[i]));
            }
            sections.extend($group.sections.iter());
        };
    }

    add_section!(text_sections, ".text");
    add_section!(rodata_sections, ".rodata");
    add_section!(data_sections, ".data");
    add_section!(bss_sections, ".bss");

    // Reserve entries in the symbol table
    let mut symbol_offsets = Vec::with_capacity(symbols.len());
    let mut local_symbols = 1; // note: null symbol is treated as a local symbol
    for symbol in &symbols {
        if symbol.binding == elf::STB_LOCAL {
            local_symbols += 1;
        }

        let section_idx = sections
            .iter()
            .find(|section| section.start <= symbol.addr && symbol.addr < section.end)
            .and_then(|section| section.index);

        symbol_offsets.push(SymbolOffset {
            _index: writer.reserve_symbol_index(section_idx),
            section: section_idx,
            str_id: writer.add_string(&symbol.name),
        });
    }

    writer.reserve_symtab_section_index();
    writer.reserve_symtab();
    if writer.symtab_shndx_needed() {
        writer.reserve_symtab_shndx();
    }
    writer.reserve_symtab_shndx();
    writer.reserve_strtab_section_index();
    writer.reserve_strtab();

    writer.reserve_shstrtab_section_index();
    writer.reserve_shstrtab();
    writer.reserve_section_headers();

    // Start writing the content of the file to memory.
    writer.write_file_header(&object::write::elf::FileHeader {
        os_abi: elf::ELFOSABI_NONE,
        abi_version: 0,
        e_type: elf::ET_EXEC,
        e_machine: machine,
        e_entry: entry,
        e_flags: 0,
    })?;

    // Write program headers
    writer.write_align_program_headers();
    for region in &*mem {
        let mut flags = elf::PF_R;
        if region.writeable {
            flags |= elf::PF_W;
        }
        if region.executable {
            flags |= elf::PF_X;
        }

        writer.write_program_header(&object::write::elf::ProgramHeader {
            p_type: elf::PT_LOAD,
            p_flags: flags,
            p_offset: region.file_offset as u64,
            p_vaddr: region.addr,
            p_paddr: region.addr,
            p_filesz: region.file_size() as u64,
            p_memsz: region.len as u64,
            p_align: min_align as u64,
        });
    }

    // Write file data
    for region in &*mem {
        eprintln!("region@{:#0x} will be written to: {:#0x}", region.addr, region.file_offset);

        writer.pad_until(region.file_offset);
        if let Some(data) = &region.data {
            writer.write(data);
        }
    }

    writer.write_null_symbol();
    for (offset, symbol) in symbol_offsets.iter().zip(&symbols) {
        let st_type = match symbol.kind {
            SymbolKind::Function => elf::STT_FUNC,
            SymbolKind::Label => elf::STT_NOTYPE,
            SymbolKind::Unknown => elf::STT_NOTYPE,
            SymbolKind::File => elf::STT_FILE,
            SymbolKind::Object => elf::STT_OBJECT,
            SymbolKind::Null => elf::STT_NOTYPE,
        };
        let st_bind = symbol.binding;

        let (section, st_shndx) = match offset.section {
            Some(section) => (Some(section), 0),
            None => (None, elf::SHN_ABS),
        };

        writer.write_symbol(&object::write::elf::Sym {
            name: Some(offset.str_id),
            section,
            st_info: (st_bind << 4) | st_type,
            st_other: elf::STV_DEFAULT,
            st_shndx,
            st_value: symbol.addr,
            st_size: 0x0,
        });
    }

    writer.write_symtab_shndx();
    writer.write_strtab();

    // Write dynamic symbols
    writer.write_shstrtab();

    // Write section headers
    writer.write_null_section_header();

    for section in text_sections.sections {
        writer.write_section_header(&object::write::elf::SectionHeader {
            name: section.name,
            sh_type: elf::SHT_PROGBITS,
            sh_flags: (elf::SHF_ALLOC | elf::SHF_EXECINSTR) as u64,
            sh_addr: section.start,
            sh_offset: section.file_offset,
            sh_size: section.end - section.start,
            sh_link: 0,
            sh_info: 0,
            sh_addralign: 0,
            sh_entsize: 0,
        });
    }
    for section in rodata_sections.sections {
        writer.write_section_header(&object::write::elf::SectionHeader {
            name: section.name,
            sh_type: elf::SHT_PROGBITS,
            sh_flags: elf::SHF_ALLOC as u64,
            sh_addr: section.start,
            sh_offset: section.file_offset,
            sh_size: section.end - section.start,
            sh_link: 0,
            sh_info: 0,
            sh_addralign: 0,
            sh_entsize: 0,
        });
    }
    for section in data_sections.sections {
        writer.write_section_header(&object::write::elf::SectionHeader {
            name: section.name,
            sh_type: elf::SHT_PROGBITS,
            sh_flags: (elf::SHF_ALLOC | elf::SHF_WRITE) as u64,
            sh_addr: section.start,
            sh_offset: section.file_offset,
            sh_size: section.end - section.start,
            sh_link: 0,
            sh_info: 0,
            sh_addralign: 0,
            sh_entsize: 0,
        });
    }
    for section in bss_sections.sections {
        writer.write_section_header(&object::write::elf::SectionHeader {
            name: section.name,
            sh_type: elf::SHT_NOBITS,
            sh_flags: (elf::SHF_ALLOC | elf::SHF_WRITE) as u64,
            sh_addr: section.start,
            sh_offset: section.file_offset,
            sh_size: section.end - section.start,
            sh_link: 0,
            sh_info: 0,
            sh_addralign: 0,
            sh_entsize: 0,
        });
    }

    writer.write_symtab_section_header(local_symbols);
    writer.write_symtab_shndx_section_header();
    writer.write_strtab_section_header();
    writer.write_shstrtab_section_header();

    Ok(out)
}
