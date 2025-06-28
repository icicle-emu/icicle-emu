use std::{any::Any, path::PathBuf};

use icicle_cpu::{
    debug_info::DebugInfo, elf::ElfLoader, pe::PeLoader, Cpu, Environment, EnvironmentAny, VmExit,
};
use object::read::FileKind;

use crate::{msp430::Msp430, BuildError, Vm};

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
    tracing::debug!("loading binary from host path: {path}");
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

    fn debug_info(&self) -> Option<&DebugInfo> {
        Some(&self.debug_info)
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
            build_machine_env(vm)
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

fn build_machine_env(vm: &mut Vm) -> Result<Box<dyn EnvironmentAny>, BuildError> {
    match vm.cpu.arch.triple.architecture {
        target_lexicon::Architecture::Msp430 => {
            let msp430_config = match std::env::var("MSP430_MCU") {
                Ok(path) => crate::msp430::Config { mcu: path, ..crate::msp430::Config::default() },
                Err(_) => crate::msp430::Config::default(),
            };
            Ok(Box::new(Msp430::new(&vm.cpu, msp430_config)?))
        }
        _ => Ok(Box::new(GenericEmbedded::new())),
    }
}
