use std::path::Path;

use icicle_cpu::{cpu::CallCov, exec::helpers, lifter, Arch, Config, Cpu};
use sleigh_compile::ldef::SleighLanguage;

use crate::Vm;

#[derive(Debug)]
pub enum BuildError {
    UnsupportedArchitecture,
    SpecNotFound(std::path::PathBuf),
    SpecCompileError(String),
    FailedToParsePspec(String),
    FailedToInitEnvironment(String),
    UnknownContextField(String),
    UnsupportedOperatingSystem,
    InvalidConfig,
}

impl std::fmt::Display for BuildError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::UnsupportedArchitecture => write!(f, "Unsupported architecture"),
            Self::SpecNotFound(path) => write!(f, "Sleigh spec not found: {}", path.display()),
            Self::SpecCompileError(err) => write!(f, "Sleigh spec compile error: {err}"),
            Self::FailedToParsePspec(err) => write!(f, "Failed to parse pspec file: {err}"),
            Self::FailedToInitEnvironment(err) => {
                write!(f, "Failed to initialize environment: {err}")
            }
            Self::UnknownContextField(name) => {
                write!(f, "Unknown context field found in pspec: {name}")
            }
            Self::UnsupportedOperatingSystem => write!(f, "Unsupported operating system"),
            Self::InvalidConfig => write!(f, "Invalid config"),
        }
    }
}

impl std::error::Error for BuildError {}

pub fn build(config: &Config) -> Result<Vm, BuildError> {
    build_with_path(config, &get_default_processors_path())
}

pub fn build_with_lang(config: &Config, mut lang: SleighLanguage) -> Result<Vm, BuildError> {
    let reg_next_pc = lang
        .sleigh
        .add_custom_reg("NEXT_PC", 8)
        .ok_or(BuildError::SpecCompileError("failed to add varnode for `NEXT_PC`".into()))?;

    let reg_isa_mode = lang.sleigh.get_varnode("ISAModeSwitch");

    // Set initial context values for architectures that support mode switching.
    //
    // @todo: Support other architectures.
    // @todo: Determine resolve using ldef if possible.
    let isa_mode_context = match config.triple.architecture {
        target_lexicon::Architecture::Arm(inner) => match inner.is_thumb() {
            true => vec![lang.initial_ctx],
            false => vec![arm::ARM_MODE_CTX, arm::THUMB_MODE_CTX],
        },
        _ => vec![lang.initial_ctx],
    };

    let get_reg = |name: &str| lang.sleigh.get_varnode(name).ok_or(BuildError::InvalidConfig);

    let mut reg_init = vec![];
    for &(name, value) in get_boot_values(config.triple.architecture) {
        reg_init.push((get_reg(name)?, value));
    }

    let temporaries = get_temporary_varnodes(config.triple.architecture)
        .iter()
        .map(|name| Ok(get_reg(name)?.id))
        .collect::<Result<Vec<_>, _>>()?;

    let arch = Arch {
        triple: config.triple.clone(),
        reg_pc: lang.pc,
        reg_next_pc,
        reg_sp: lang.sp,
        reg_isa_mode,
        isa_mode_context,
        reg_init,
        temporaries,
        calling_cov: CallCov {
            integers: lang.default_calling_cov.int_args,
            stack_align: 4,
            stack_offset: 0,
        },
        on_boot: get_boot_action(config.triple.architecture),
        sleigh: lang.sleigh,
    };

    build_vm(config, arch)
}


pub fn build_with_path(config: &Config, processors: &Path) -> Result<Vm, BuildError> {
    let lang = sleigh_init_with_path(&config.triple, processors)?;
    build_with_lang(config, lang)
}

fn build_vm(config: &Config, arch: Arch) -> Result<Vm, BuildError> {
    let mut cpu = Cpu::new_boxed(arch);
    cpu.enable_shadow_stack = config.enable_shadow_stack;
    cpu.mem.track_uninitialized = config.track_uninitialized;

    let settings = lifter::Settings {
        optimize: config.optimize_instructions,
        optimize_block: config.optimize_block,
        ..Default::default()
    };
    let instruction_lifter = lifter::InstructionLifter::new();
    let mut lifter = lifter::BlockLifter::new(settings, instruction_lifter);
    for var in &cpu.arch.temporaries {
        lifter.mark_as_temporary(*var);
    }

    let mut vm = Vm::new(cpu, lifter);
    vm.enable_jit = config.enable_jit;
    register_helpers_for(&mut vm, config.triple.architecture);

    Ok(vm)
}

pub fn register_helpers(vm: &mut Vm, helpers: &[(&str, helpers::PcodeOpHelper)]) {
    for &(name, func) in helpers {
        let id = match vm.cpu.arch.sleigh.get_userop(name) {
            Some(id) => id,
            None => continue,
        };
        vm.cpu.set_helper(id, func);
    }
}

fn patch_instruction_pointer_access(vm: &mut Vm, use_next_pc: bool) {
    let pc = vm.cpu.arch.reg_pc;
    let tmp_pc = vm.cpu.arch.sleigh.add_custom_reg("tmp_pc", pc.size).unwrap();
    vm.lifter.mark_as_temporary(tmp_pc.id);
    vm.lifter.patchers.push(icicle_cpu::lifter::read_pc_patcher(pc, tmp_pc, use_next_pc));
}

fn register_helpers_for(vm: &mut Vm, arch: target_lexicon::Architecture) {
    use target_lexicon::Architecture;

    lifter::get_injectors(&mut vm.cpu, &mut vm.lifter.op_injectors);

    register_helpers(vm, helpers::HELPERS);
    match arch {
        Architecture::Arm(_) => {
            register_helpers(vm, helpers::arm::HELPERS);
            // Fixes `pop {..., pc}`
            patch_instruction_pointer_access(vm, false);
        }
        Architecture::Aarch64(_) => register_helpers(vm, helpers::aarch64::HELPERS),
        Architecture::X86_32(_) | Architecture::X86_64 => {
            register_helpers(vm, helpers::x86::HELPERS);
            patch_instruction_pointer_access(vm, false);
        }
        Architecture::Msp430 => {
            // If the SLEIGH specification is configured to use individual registers instead of the
            // status register, handle reads and writes from the emulator here.
            if vm.cpu.arch.sleigh.get_reg("CF").is_some() {
                let reg_handler = crate::msp430::StatusRegHandler::new(&vm.cpu.arch.sleigh);
                vm.cpu.add_reg_handler(reg_handler.sr.id, Box::new(reg_handler))
            }

            lifter::msp430::status_register_control_patch(&mut vm.cpu, &mut vm.lifter);
            // Fixes RETI, RETA, CALLA
            patch_instruction_pointer_access(vm, true);
        }
        _ => {}
    }
}

fn get_temporary_varnodes(arch: target_lexicon::Architecture) -> &'static [&'static str] {
    use target_lexicon::Architecture;
    match arch {
        Architecture::Arm(_) => &[
            "tmpCY",
            "tmpOV",
            "tmpNG",
            "tmpZR",
            "shift_carry",
            "mult_addr",
            "mult_dat8",
            "mult_dat16",
        ],
        Architecture::Aarch64(_) => {
            &["tmpCY", "tmpOV", "tmpNG", "tmpZR", "shift_carry", "tmp_ldXn", "TMPS1", "TMPD1"]
        }
        Architecture::X86_32(_) | Architecture::X86_64 | Architecture::X86_64h => {
            &["xmmTmp1", "xmmTmp2"]
        }
        _ => &[],
    }
}

fn get_boot_values(arch: target_lexicon::Architecture) -> &'static [(&'static str, u128)] {
    use target_lexicon::Architecture;
    match arch {
        Architecture::Aarch64(_) => &[("dczid_el0", 0x10)], // disable DC ZVA instructions
        _ => &[],
    }
}

fn get_boot_action(arch: target_lexicon::Architecture) -> fn(&mut Cpu, u64) {
    use target_lexicon::Architecture;
    match arch {
        Architecture::Arm(_) => arm::on_boot,
        _ => generic::on_boot,
    }
}

pub fn sleigh_init(target: &target_lexicon::Triple) -> Result<SleighLanguage, BuildError> {
    sleigh_init_with_path(target, &get_default_processors_path())
}

pub fn sleigh_init_with_path(target: &target_lexicon::Triple, processors: &Path) -> Result<SleighLanguage, BuildError> {
    use target_lexicon::{
        Aarch64Architecture, Architecture, ArmArchitecture, Mips32Architecture,
        Riscv32Architecture, Riscv64Architecture,
    };

    let (ldef, id) = match target.architecture {
        Architecture::Arm(variant) => {
            let ldef = "ARM/data/languages/ARM.ldefs";
            let id = match variant {
                ArmArchitecture::Arm => "ARM:LE:32:v8",
                ArmArchitecture::Armeb => "ARM:BE:32:v8",

                ArmArchitecture::Armv4 => "ARM:LE:32:v4",
                ArmArchitecture::Armv4t => "ARM:LE:32:v4t",
                ArmArchitecture::Armv5t | ArmArchitecture::Armv5te | ArmArchitecture::Armv5tej => {
                    "ARM:LE:32:v5t"
                }
                ArmArchitecture::Armv6
                | ArmArchitecture::Armv6j
                | ArmArchitecture::Armv6k
                | ArmArchitecture::Armv6z
                | ArmArchitecture::Armv6kz
                | ArmArchitecture::Armv6t2
                | ArmArchitecture::Armv6m => "ARM:LE:32:v6",

                ArmArchitecture::Armv7
                | ArmArchitecture::Armv7a
                | ArmArchitecture::Armv7k
                | ArmArchitecture::Armv7ve
                | ArmArchitecture::Armv7m
                | ArmArchitecture::Armv7r
                | ArmArchitecture::Armv7s => "ARM:LE:32:v7",

                ArmArchitecture::Armebv7r => "ARM:BE:32:v7",

                ArmArchitecture::Armv8
                | ArmArchitecture::Armv8a
                | ArmArchitecture::Armv8_1a
                | ArmArchitecture::Armv8_2a
                | ArmArchitecture::Armv8_3a
                | ArmArchitecture::Armv8_4a
                | ArmArchitecture::Armv8_5a
                | ArmArchitecture::Armv8mBase
                | ArmArchitecture::Armv8mMain
                | ArmArchitecture::Armv8r => "ARM:LE:32:v8",

                ArmArchitecture::Thumbv4t => "ARM:LE:32:v8T",
                ArmArchitecture::Thumbv5te => "ARM:LE:32:v8T",
                ArmArchitecture::Thumbv6m => "ARM:LE:32:v8T",

                // No specific v7 thumb target
                ArmArchitecture::Thumbv7a
                | ArmArchitecture::Thumbv7em
                | ArmArchitecture::Thumbv7m
                | ArmArchitecture::Thumbv7neon => "ARM:LE:32:v8T",

                ArmArchitecture::Thumbv8mBase | ArmArchitecture::Thumbv8mMain => "ARM:LE:32:v8T",

                ArmArchitecture::Thumbeb => "ARM:BE:32:v8T",
                _ => return Err(BuildError::UnsupportedArchitecture),
            };
            (ldef, id)
        }
        Architecture::Aarch64(variant) => {
            let ldef = "AARCH64/data/languages/AARCH64.ldefs";
            let id = match variant {
                Aarch64Architecture::Aarch64 => "AARCH64:LE:64:v8A",
                Aarch64Architecture::Aarch64be => "AARCH64:BE:64:v8A",
                _ => return Err(BuildError::UnsupportedArchitecture),
            };
            (ldef, id)
        }
        Architecture::M68k => ("68000/data/languages/68000.ldefs", "68000:BE:32:Coldfire"),
        Architecture::Mips32(variant) => {
            let ldef = "MIPS/data/languages/mips.ldefs";
            let id = match variant {
                Mips32Architecture::Mips => "MIPS:BE:32:default",
                Mips32Architecture::Mipsel => "MIPS:LE:32:default",
                Mips32Architecture::Mipsisa32r6 => "MIPS:BE:32:R6",
                Mips32Architecture::Mipsisa32r6el => "MIPS:LE:32:R6",
                _ => return Err(BuildError::UnsupportedArchitecture),
            };
            (ldef, id)
        }
        Architecture::Msp430 => {
            ("TI_MSP430/data/languages/TI_MSP430.ldefs", "TI_MSP430X:LE:32:default")
        }
        Architecture::Powerpc => ("PowerPC/data/languages/ppc.ldefs", "PowerPC:BE:32:default"),
        Architecture::Powerpc64 => ("PowerPC/data/languages/ppc.ldefs", "PowerPC:BE:64:default"),
        Architecture::Powerpc64le => ("PowerPC/data/languages/ppc.ldefs", "PowerPC:LE:64:default"),
        Architecture::Riscv32(variant) => {
            let ldef = "RISCV/data/languages/riscv.ldefs";
            let id = match variant {
                Riscv32Architecture::Riscv32 => "RISCV:LE:32:default",
                Riscv32Architecture::Riscv32gc => "RISCV:LE:32:RV32GC",
                Riscv32Architecture::Riscv32i => "RISCV:LE:32:RV32I",
                Riscv32Architecture::Riscv32imc => "RISCV:LE:32:RV32IMC",
                _ => return Err(BuildError::UnsupportedArchitecture),
            };
            (ldef, id)
        }
        Architecture::Riscv64(variant) => {
            let ldef = "RISCV/data/languages/riscv.ldefs";
            let id = match variant {
                Riscv64Architecture::Riscv64 => "RISCV:LE:64:default",
                Riscv64Architecture::Riscv64gc => "RISCV:LE:64:RV64GC",
                _ => return Err(BuildError::UnsupportedArchitecture),
            };
            (ldef, id)
        }
        Architecture::X86_32(_) => ("x86/data/languages/x86.ldefs", "x86:LE:32:default"),
        Architecture::X86_64h | Architecture::X86_64 => {
            ("x86/data/languages/x86.ldefs", "x86:LE:64:default")
        }
        Architecture::XTensa => ("xtensa/data/languages/xtensa.ldefs", "Xtensa:LE:32:default"),
        _ => return Err(BuildError::UnsupportedArchitecture),
    };

    let ldef_path = processors.join(ldef);
    if !ldef_path.exists() {
        return Err(BuildError::SpecNotFound(ldef_path));
    }

    let mut builder = sleigh_compile::SleighLanguageBuilder::new(ldef_path, id);
    if matches!(target.architecture, Architecture::Msp430) {
        builder = builder.define("SPLITFLAGS");
    }

    // @todo: use compiler specific variants for cspec when available.
    builder.build().map_err(|e| BuildError::SpecCompileError(e.to_string()))
}

fn get_default_processors_path() -> std::path::PathBuf {
    std::env::var_os("GHIDRA_SRC")
        .map_or_else(|| ".".into(), std::path::PathBuf::from)
        .join("Ghidra/Processors")
}

// @fixme: avoid making this pub when we refactor architecture specific CPU state.
mod generic {
    use icicle_cpu::ValueSource;

    use super::*;

    pub fn on_boot(cpu: &mut Cpu, entry: u64) {
        cpu.reset();
        cpu.regs.write_trunc(cpu.arch.reg_pc, entry);
    }
}

pub mod x86 {
    use icicle_cpu::ValueSource;

    /// Initial context register state (Ghidra 10.3) for `x86_64` processor running in long mode.
    ///
    /// * longMode(0, 0)       = 1 (64-bit mode)
    /// * bit64(4, 4)          = 1 (64-bit mode)
    /// * opsize(6, 7)         = 1 (32-bit operands)
    pub const LONG_MODE_CTX: u64 = 0b_0000_0000_0000_0000_0000_0000_1001_0001_u64.reverse_bits();

    /// Initial context register state (Ghidra 10.3)  for `x86_64` processor running `x32`
    /// compatability mode.
    ///
    /// * longMode(0, 0)       = 0 (32-bit mode)
    /// * addrSize(4, 5)       = 1 (32-bit addresses)
    /// * bit64(4, 4)          = 0 (32-bit mode)
    /// * opsize(6, 7)         = 1 (32-bit operands)
    pub const COMPAT_MODE_CTX: u64 = 0b_0000_0000_0000_0000_0000_0000_1010_0000_u64.reverse_bits();

    /// Get merged flags from internal registers
    // @todo: This could possibly be implemented as a Sleigh extension.
    #[allow(clippy::erasing_op, clippy::identity_op)]
    pub fn eflags(cpu: &icicle_cpu::Cpu) -> u32 {
        let read_bit = |name: &str| {
            let var = cpu.arch.sleigh.get_varnode(name).unwrap();
            (cpu.read_var::<u8>(var) as u32) & 0x1
        };

        (0x0001 * read_bit("CF"))
            | (0x0002 * 0x1)
            | (0x0004 * read_bit("PF"))
            | (0x0080 * 0x0)
            | (0x0010 * read_bit("AF"))
            | (0x0020 * 0x0)
            | (0x0040 * read_bit("ZF"))
            | (0x0080 * read_bit("SF"))
            | (0x0100 * read_bit("TF"))
            | (0x0200 * read_bit("IF"))
            | (0x0400 * read_bit("DF"))
            | (0x0800 * read_bit("OF"))
            | (0x4000 * read_bit("NT"))
            | (0x8000 * 0x0)
    }

    #[derive(Copy, Clone, Eq, PartialEq, Ord, PartialOrd, Default)]
    pub struct EFlags(pub u32);

    impl std::fmt::Display for EFlags {
        fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            let extract_bit = |field: u32| ((self.0 >> field.trailing_zeros()) & 0x1) as u64;

            f.debug_struct("eflags")
                .field("CF", &extract_bit(0x0001))
                .field("PF", &extract_bit(0x0004))
                .field("AF", &extract_bit(0x0010))
                .field("ZF", &extract_bit(0x0040))
                .field("SF", &extract_bit(0x0080))
                .field("TF", &extract_bit(0x0100))
                .field("IF", &extract_bit(0x0200))
                .field("DF", &extract_bit(0x0400))
                .field("OF", &extract_bit(0x0800))
                .field("NT", &extract_bit(0x4000))
                .finish()
        }
    }

    impl std::fmt::Debug for EFlags {
        fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            <EFlags as std::fmt::Display>::fmt(self, f)
        }
    }

    /// Set internal flag registers based on merged flag bits
    // @todo: This could possibly be implemented as a Sleigh extension.
    pub fn set_eflags(cpu: &mut icicle_cpu::Cpu, eflags: u32) {
        let extract_bit = |field: u32| ((eflags >> field.trailing_zeros()) & 0x1) as u8;

        let mut write = |name: &str, value: u8| {
            cpu.write_var(cpu.arch.sleigh.get_varnode(name).unwrap(), value);
        };

        write("CF", extract_bit(0x0001));
        // extract_bit(0x0002) (always 1)
        write("PF", extract_bit(0x0004));
        // extract_bit(0x0080) (always 0)
        write("AF", extract_bit(0x0010));
        // extract_bit(0x0020) (always 0)
        write("ZF", extract_bit(0x0040));
        write("SF", extract_bit(0x0080));
        write("TF", extract_bit(0x0100));
        write("IF", extract_bit(0x0200));
        write("DF", extract_bit(0x0400));
        write("OF", extract_bit(0x0800));
        write("NT", extract_bit(0x4000));
        // extract_bit(0x8000) (always 0)
    }
}

mod arm {
    use super::*;

    /// Context register value for ARM mode.
    pub const ARM_MODE_CTX: u64 = 0;

    /// Context register value for Thumb mode.
    pub const THUMB_MODE_CTX: u64 = 1_u64.reverse_bits();

    #[repr(u8)]
    pub enum IsaMode {
        Arm = 0,
        Thumb = 1,
    }

    pub fn on_boot(cpu: &mut Cpu, mut entry: u64) {
        cpu.reset();

        // Update ISA mode if we are booting into Thumb mode.
        if entry & 1 == 1 {
            cpu.set_isa_mode(IsaMode::Thumb as u8);
            entry &= !1;
        }
        else {
            cpu.set_isa_mode(IsaMode::Arm as u8);
        }

        cpu.write_pc(entry);
    }
}
