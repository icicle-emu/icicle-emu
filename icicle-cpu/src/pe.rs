use crate::{
    debug_info::DebugInfo,
    mem::{perm, AllocLayout, Mapping},
    utils, Cpu,
};

use object::{
    pe::{self, ImageDosHeader, ImageNtHeaders64, ImageNtHeaders32, ImageSectionHeader, 
        IMAGE_REL_BASED_HIGHLOW, IMAGE_REL_BASED_HIGH, IMAGE_REL_BASED_LOW, IMAGE_REL_BASED_DIR64 }, 
    read::pe::{DataDirectories, ImageOptionalHeader}, coff::SectionTable
};

const NT_HEADER_SIGNATURE_SIZE: u32 = 0x04;
const FILE_HEADER_SIZE: u32 = 0x14;

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

        let (nt_headers, data_directories) = ImageNtHeaders32::parse(data, &mut offset).unwrap();
        let sections = nt_headers.sections(data, offset).unwrap();
        load_pe(cpu, data, dos_header, nt_headers, &sections, &data_directories)
    }

    fn load_pe64(&mut self, cpu: &mut Cpu, data: &[u8]) -> Result<LoadedPe, String> {
        use object::read::pe::ImageNtHeaders;
        tracing::info!("Loading 64-bit PE file");

        let dos_header = ImageDosHeader::parse(data).unwrap();
        let mut offset = dos_header.nt_headers_offset().into();

        let (nt_headers, data_directories) = ImageNtHeaders64::parse(data, &mut offset).unwrap();
        let sections = nt_headers.sections(data, offset).unwrap();
        load_pe(cpu, data, dos_header, nt_headers, &sections, &data_directories)
    }
}

fn load_pe<H>(cpu: &mut Cpu, data: &[u8], dos_header: &ImageDosHeader, 
    nt_headers: &H, sections: &SectionTable<'_>, data_directories: &DataDirectories<'_>) -> Result<LoadedPe, String>
where
    H: object::read::pe::ImageNtHeaders
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
            let base_addr = cpu.mem.find_free_memory(layout)
                .map_err(|e| format!("Failed to find memory: {e:?}"))?;
            (base_addr, base_addr - requested_base_addr)        
        };

    tracing::info!(
        "base_addr={base_addr:0x}, relocation_offset={relocation_offset:0x}, size={:0x}",
        layout.size
    );

    // map PE header
    tracing::info!("Map PE HEader");
    let optionl_header_size: u32 = nt_headers.file_header().size_of_optional_header.get(object::LittleEndian).into();
    let nt_header_size = NT_HEADER_SIGNATURE_SIZE + FILE_HEADER_SIZE + optionl_header_size;
    let total_header_size = dos_header.nt_headers_offset() + nt_header_size;
    let aligned_size = utils::align_up(total_header_size as u64, sec_alignment);

    let bytes = &data[0..total_header_size as usize];
    cpu.mem.map_memory_len(base_addr, aligned_size, Mapping { perm: perm::MAP | perm::READ, value: 0x00 });
    cpu.mem.write_bytes(base_addr, bytes, perm::READ).unwrap();

    // map all sections
    for section in sections.iter() {        
        tracing::info!("Map section: {:?}", section.name);

        let rva = section.virtual_address.get(object::LittleEndian) as u64;
        let vsize = section.virtual_size.get(object::LittleEndian) as u64;
        let bytes = section.pe_data(data)
            .map_err(|e| format!("Failed to read section data: {e:?}"))?;
        
        let section_base = base_addr + rva;
        let aligned_size = utils::align_up(vsize, sec_alignment);
        let permission = get_permission(section);
        cpu.mem.map_memory_len(section_base, aligned_size, Mapping { perm: permission, value: 0x00 });
        cpu.mem.write_bytes(section_base, bytes, permission).unwrap();
    }

    // relocate PE
    if relocation_offset != 0 {
        tracing::info!("Relocate PE");
        if let Ok(Some(mut reloc)) = data_directories.relocation_blocks(data, sections) {
            while let Some(reloc) = reloc.next().map_err(|e| format!("Failed to read relocation data: {e:?}"))? {
                for reloc in reloc {
                    let addr = base_addr + reloc.virtual_address as u64;
                    match reloc.typ {                        
                        IMAGE_REL_BASED_HIGH => {
                            let mut buf = vec![0_u8; 2];
                            cpu.mem.read_bytes(addr, &mut buf[..], perm::READ)
                                .map_err(|e| format!("Failed to read relocation data: {e:?}"))?;                            
                            let old_val = u16::from_le_bytes(buf.try_into().unwrap());
                            let new_val = old_val.wrapping_add((relocation_offset >> 16) as u16);
                            cpu.mem.write_bytes(addr, &new_val.to_le_bytes(), perm::READ)
                                .map_err(|e| format!("Failed to write relocation data: {e:?}"))?;
                        },
                        IMAGE_REL_BASED_LOW => {
                            let mut buf = vec![0_u8; 2];
                            cpu.mem.read_bytes(addr, &mut buf[..], perm::READ)
                                .map_err(|e| format!("Failed to read relocation data: {e:?}"))?;                            
                            let old_val = u16::from_le_bytes(buf.try_into().unwrap());
                            let new_val = old_val.wrapping_add(relocation_offset as u16);
                            cpu.mem.write_bytes(addr, &new_val.to_le_bytes(), perm::READ)
                                .map_err(|e| format!("Failed to write relocation data: {e:?}"))?;
                        },
                        IMAGE_REL_BASED_HIGHLOW => {
                            let mut buf = vec![0_u8; 4];
                            cpu.mem.read_bytes(addr, &mut buf[..], perm::READ)
                                .map_err(|e| format!("Failed to read relocation data: {e:?}"))?;                            
                            let old_val = u32::from_le_bytes(buf.try_into().unwrap());
                            let new_val = old_val.wrapping_add(relocation_offset as u32);
                            cpu.mem.write_bytes(addr, &new_val.to_le_bytes(), perm::READ)
                                .map_err(|e| format!("Failed to write relocation data: {e:?}"))?;                            
                        },
                        IMAGE_REL_BASED_DIR64 => {
                            let mut buf = vec![0_u8; 8];
                            cpu.mem.read_bytes(addr, &mut buf[..], perm::READ)
                                .map_err(|e| format!("Failed to read relocation data: {e:?}"))?;                            
                            let old_val = u64::from_le_bytes(buf.try_into().unwrap());
                            let new_val = old_val.wrapping_add(relocation_offset);                            
                            cpu.mem.write_bytes(addr, &new_val.to_le_bytes(), perm::READ)
                                .map_err(|e| format!("Failed to write relocation data: {e:?}"))?;
                        },
                        _ => {
                            return Err(String::from(format!("Relocation type {:#06x} not supported", reloc.typ)));
                        }
                    }
                }
            }
        }
        else {
            return Err(String::from("PE file does not contain relocation data, unable to relocate file"));
        }
    }
    

    // create result object
    let binary = PeMetadata {
        relocation_offset: relocation_offset,
        entry_ptr: nt_headers.optional_header().address_of_entry_point() as u64 + base_addr,
        length: layout.size,
        base_ptr: base_addr
    };
    
    let mut debug_info = DebugInfo::default();
    debug_info.add_file(data, relocation_offset)?;
    Ok(LoadedPe { binary, debug_info })
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
    perm |= if (flags & pe::IMAGE_SCN_MEM_READ) == 0 { perm::NONE } else { perm::EXEC };
    perm
}