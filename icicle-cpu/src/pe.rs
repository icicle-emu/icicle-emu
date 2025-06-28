use crate::{
    debug_info::DebugInfo,
    mem::{perm, AllocLayout, Mapping},
    utils, Cpu,
};

use object::{
    coff::SectionTable,
    pe::{
        self, ImageDosHeader, ImageNtHeaders32, ImageNtHeaders64, ImageSectionHeader,
        IMAGE_REL_BASED_DIR64, IMAGE_REL_BASED_HIGH, IMAGE_REL_BASED_HIGHLOW, IMAGE_REL_BASED_LOW,
        IMAGE_SIZEOF_FILE_HEADER,
    },
    read::pe::{DataDirectories, ImageOptionalHeader},
};

enum RelocationError {
    Access(icicle_mem::MemError),
    Unsupported(u16),
}

impl std::fmt::Display for RelocationError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Access(err) => write!(f, "Failed to access relocation data: {err:?}"),
            Self::Unsupported(typ) => write!(f, "Relocation type {typ:#06x} not supported"),
        }
    }
}

impl From<icicle_mem::MemError> for RelocationError {
    fn from(value: icicle_mem::MemError) -> Self {
        Self::Access(value)
    }
}

#[derive(Debug, Clone, Default)]
pub struct PeMetadata {
    /// The offset the binary has been relocated by.
    pub relocation_offset: u64,

    /// The program entry point.
    pub entry_ptr: u64,

    /// The address the PE file was loaded at (equal to the requested base address + offset).
    pub base_ptr: u64,

    /// The total length of the file.
    pub length: u64,
}

#[derive(Clone)]
pub struct LoadedPe {
    pub binary: PeMetadata,
    pub debug_info: DebugInfo,
}

pub trait PeLoader {
    fn load_pe32(&mut self, cpu: &mut Cpu, data: &[u8]) -> Result<LoadedPe, String> {
        use object::read::pe::ImageNtHeaders;
        tracing::info!("Loading 32-bit PE file");

        let dos_header =
            ImageDosHeader::parse(data).map_err(|e| format!("Error parsing DosHeader: {e}"))?;
        let mut offset = dos_header.nt_headers_offset().into();

        let (nt_headers, data_directories) = ImageNtHeaders32::parse(data, &mut offset)
            .map_err(|e| format!("Unable to parse Nt Headers for x86 binary: {e:?}"))?;
        let sections = nt_headers.sections(data, offset).unwrap();
        load_pe(cpu, data, dos_header, nt_headers, &sections, &data_directories)
    }

    fn load_pe64(&mut self, cpu: &mut Cpu, data: &[u8]) -> Result<LoadedPe, String> {
        use object::read::pe::ImageNtHeaders;
        tracing::info!("Loading 64-bit PE file");

        let dos_header = ImageDosHeader::parse(data).unwrap();
        let mut offset = dos_header.nt_headers_offset().into();

        let (nt_headers, data_directories) = ImageNtHeaders64::parse(data, &mut offset)
            .map_err(|e| format!("Unable to parse Nt Headers for x64 binary: {e:?}"))?;
        let sections = nt_headers.sections(data, offset).unwrap();
        load_pe(cpu, data, dos_header, nt_headers, &sections, &data_directories)
    }
}

fn load_pe<H>(
    cpu: &mut Cpu,
    data: &[u8],
    dos_header: &ImageDosHeader,
    nt_headers: &H,
    sections: &SectionTable<'_>,
    data_directories: &DataDirectories<'_>,
) -> Result<LoadedPe, String>
where
    H: object::read::pe::ImageNtHeaders,
{
    let sec_alignment = nt_headers.optional_header().section_alignment() as u64;
    let (requested_base_addr, layout) = get_layout(nt_headers);
    let dll_characteristics = nt_headers.optional_header().dll_characteristics();

    // find memory
    let (base_addr, relocation_offset) =
        if dll_characteristics & pe::IMAGE_DLLCHARACTERISTICS_DYNAMIC_BASE == 0 {
            (requested_base_addr, 0)
        }
        else {
            let base_addr = cpu
                .mem
                .find_free_memory(layout)
                .map_err(|e| format!("Failed to find memory: {e:?}"))?;
            (base_addr, base_addr - requested_base_addr)
        };

    tracing::info!(
        "base_addr={base_addr:0x}, relocation_offset={relocation_offset:0x}, size={:0x}",
        layout.size
    );

    // map PE header
    tracing::info!("Map PE HEader");
    let optionl_header_size: usize =
        nt_headers.file_header().size_of_optional_header.get(object::LittleEndian).into();
    let nt_header_size = std::mem::size_of_val(&nt_headers.signature())
        + IMAGE_SIZEOF_FILE_HEADER
        + optionl_header_size;
    let total_header_size = dos_header.nt_headers_offset() + nt_header_size as u32;
    let aligned_size = utils::align_up(total_header_size as u64, sec_alignment);

    let bytes = &data[0..total_header_size as usize];
    cpu.mem.map_memory_len(base_addr, aligned_size, Mapping {
        perm: perm::MAP | perm::READ,
        value: 0x00,
    });
    cpu.mem.write_bytes(base_addr, bytes, perm::READ).unwrap();

    // map all sections
    for section in sections.iter() {
        tracing::info!("Map section: {:?}", section.name);

        let rva = section.virtual_address.get(object::LittleEndian) as u64;
        let vsize = section.virtual_size.get(object::LittleEndian) as u64;
        let bytes =
            section.pe_data(data).map_err(|e| format!("Failed to read section data: {e:?}"))?;

        let section_base = base_addr + rva;
        let aligned_size = utils::align_up(vsize, sec_alignment);
        let permission = get_permission(section);
        cpu.mem
            .map_memory_len(section_base, aligned_size, Mapping { perm: permission, value: 0x00 });
        cpu.mem.write_bytes(section_base, bytes, permission).unwrap();
    }

    // relocate PE
    if relocation_offset != 0 {
        tracing::info!("Relocate PE");
        match data_directories.relocation_blocks(data, sections) {
            Ok(reloc_opt) => {
                if let Some(mut reloc) = reloc_opt {
                    while let Some(reloc) = reloc
                        .next()
                        .map_err(|e| format!("Failed to read relocation data: {e:?}"))?
                    {
                        for reloc in reloc {
                            let addr = base_addr + reloc.virtual_address as u64;
                            handle_relocation(cpu, reloc, addr, relocation_offset)
                                .map_err(|e| e.to_string())?;
                        }
                    }
                }
            }
            Err(e) => {
                return Err(e.to_string());
            }
        }
    }

    // create result object
    let binary = PeMetadata {
        relocation_offset,
        entry_ptr: nt_headers.optional_header().address_of_entry_point() as u64 + base_addr,
        length: layout.size,
        base_ptr: base_addr,
    };

    let mut debug_info = DebugInfo::default();
    debug_info.add_file(data, relocation_offset)?;
    Ok(LoadedPe { binary, debug_info })
}

fn handle_relocation(
    cpu: &mut Cpu,
    reloc: object::read::pe::Relocation,
    addr: u64,
    relocation_offset: u64,
) -> Result<(), RelocationError> {
    match reloc.typ {
        IMAGE_REL_BASED_HIGH => {
            let old = cpu.mem.read_u16(addr, perm::NONE)?;
            let new = old.wrapping_add((relocation_offset >> 16) as u16);
            cpu.mem.write_u16(addr, new, perm::NONE)?;
        }
        IMAGE_REL_BASED_LOW => {
            let old = cpu.mem.read_u16(addr, perm::NONE)?;
            let new = old.wrapping_add(relocation_offset as u16);
            cpu.mem.write_u16(addr, new, perm::NONE)?;
        }
        IMAGE_REL_BASED_HIGHLOW => {
            let old = cpu.mem.read_u32(addr, perm::NONE)?;
            let new = old.wrapping_add(relocation_offset as u32);
            cpu.mem.write_u32(addr, new, perm::NONE)?;
        }
        IMAGE_REL_BASED_DIR64 => {
            let old = cpu.mem.read_u64(addr, perm::NONE)?;
            let new = old.wrapping_add(relocation_offset);
            cpu.mem.write_u64(addr, new, perm::NONE)?;
        }
        typ => return Err(RelocationError::Unsupported(typ)),
    }
    Ok(())
}

// Retrives the base address and layout requirements of the PE when it is loaded into memory.
fn get_layout<H>(nt_headers: &H) -> (u64, AllocLayout)
where
    H: object::read::pe::ImageNtHeaders,
{
    let optional_header = nt_headers.optional_header();
    let image_base = optional_header.image_base();
    let size = optional_header.size_of_image() as u64;
    let align = optional_header.section_alignment() as u64;
    (image_base, AllocLayout { addr: Some(image_base), size, align })
}

fn get_permission(section: &ImageSectionHeader) -> u8 {
    let flags: u32 = section.characteristics.get(object::LittleEndian).into();
    let mut perm = perm::MAP;
    perm |= if (flags & pe::IMAGE_SCN_MEM_READ) == 0 { perm::NONE } else { perm::READ };
    perm |= if (flags & pe::IMAGE_SCN_MEM_WRITE) == 0 { perm::NONE } else { perm::WRITE };
    perm |= if (flags & pe::IMAGE_SCN_MEM_EXECUTE) == 0 { perm::NONE } else { perm::EXEC };
    perm
}
