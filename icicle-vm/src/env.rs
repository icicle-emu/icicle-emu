use object::read::FileKind;
use std::{any::Any, path::PathBuf};

use icicle_cpu::{
    debug_info::{DebugInfo, SourceLocation},
    elf::ElfLoader,
    pe::PeLoader,
    Cpu, Environment, EnvironmentAny, VmExit,
};

use crate::{BuildError, Vm};

struct GenericEmbedded {
    debug_info: DebugInfo,
}

impl GenericEmbedded {
    fn new() -> Self {
        Self { debug_info: DebugInfo::default() }
    }
}

impl ElfLoader for GenericEmbedded {
    const DYNAMIC_MEMORY: bool = true;
}

impl PeLoader for GenericEmbedded {}

fn read_file(path: &[u8]) -> Result<Vec<u8>, String> {
    let path = std::str::from_utf8(path)
        .map_err(|e| format!("@fixme: only utf-8 paths are supported: {e}"))?;
    std::fs::read(path).map_err(|e| format!("Failed to read {path}: {e}"))
}

impl Environment for GenericEmbedded {
    fn load(&mut self, cpu: &mut Cpu, path: &[u8]) -> Result<(), String> {
        let file_content = read_file(path)?;

        let file_kind = FileKind::parse(&file_content[..]);
        match file_kind {
            Ok(FileKind::Elf32) | Ok(FileKind::Elf64) => {
                let metadata = self.load_elf(cpu, path)?;
                if metadata.interpreter.is_some() {
                    return Err(
                        "Dynamically linked binaries are not supported for generic embedded".into(),
                    );
                }

                if metadata.binary.offset != 0 {
                    return Err(format!(
                        "Expected no relocations for generic embedded (offset={:#x})",
                        metadata.binary.offset
                    ));
                }

                self.debug_info = metadata.debug_info;
                self.debug_info.entry_ptr = metadata.binary.entry_ptr;

                (cpu.arch.on_boot)(cpu, metadata.binary.entry_ptr);

                Ok(())
            }
            Ok(FileKind::Pe32) | Ok(FileKind::Pe64) => {
                let metadata = match file_kind {
                    Ok(FileKind::Pe32) => self.load_pe32(cpu, &file_content[..])?,
                    Ok(FileKind::Pe64) => self.load_pe64(cpu, &file_content[..])?,
                    _ => return Err(format!("Unrecognized PE type")),
                };

                self.debug_info = metadata.debug_info;
                self.debug_info.entry_ptr = metadata.binary.entry_ptr;
                (cpu.arch.on_boot)(cpu, metadata.binary.entry_ptr);
                Ok(())
            }
            Ok(other) => return Err(format!("unsupported file type: {:?}", other)),
            Err(e) => return Err(format!("failed to parse file: {}", e)),
        }
    }

    fn handle_exception(&mut self, _: &mut Cpu) -> Option<VmExit> {
        None
    }

    fn symbolize_addr(&mut self, _: &mut Cpu, addr: u64) -> Option<SourceLocation> {
        self.debug_info.symbolize_addr(addr)
    }

    fn lookup_symbol(&mut self, symbol: &str) -> Option<u64> {
        self.debug_info.symbols.resolve_sym(symbol)
    }

    fn snapshot(&mut self) -> Box<dyn Any> {
        Box::new(())
    }

    fn restore(&mut self, _: &Box<dyn Any>) {}
}

pub fn build_auto(vm: &mut Vm) -> Result<Box<dyn EnvironmentAny>, BuildError> {
    match vm.cpu.arch.triple.operating_system {
        target_lexicon::OperatingSystem::Linux => {
            let config = icicle_linux::KernelConfig::default();
            let sysroot = std::env::var_os("ICICLE_SYSROOT")
                .map_or_else(|| std::path::PathBuf::from("/"), std::path::PathBuf::from);
            Ok(Box::new(build_linux_env(vm, &config, sysroot, true)?))
        }
        target_lexicon::OperatingSystem::None_ | target_lexicon::OperatingSystem::Unknown => {
            Ok(Box::new(build_machine_env(vm)?))
        }
        _ => Err(BuildError::UnsupportedOperatingSystem),
    }
}

pub fn build_linux_env(
    vm: &mut Vm,
    config: &icicle_linux::KernelConfig,
    sysroot: PathBuf,
    mount_stddev: bool,
) -> Result<icicle_linux::Kernel, BuildError> {
    let mut kernel = icicle_linux::Kernel::new(&vm.cpu.arch, config);

    kernel.init_vfs(sysroot).map_err(BuildError::FailedToInitEnvironment)?;
    if mount_stddev {
        kernel
            .mount_stddev(
                icicle_linux::fs::devices::WriteOnlyDevice(std::io::stdout()),
                icicle_linux::fs::devices::WriteOnlyDevice(std::io::stderr()),
                None,
            )
            .map_err(BuildError::FailedToInitEnvironment)?;
    }

    Ok(kernel)
}

fn build_machine_env(vm: &mut Vm) -> Result<GenericEmbedded, BuildError> {
    match vm.cpu.arch.triple.architecture {
        _ => Ok(GenericEmbedded::new()),
    }
}
