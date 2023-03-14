use icicle_cpu::{cpu::CallCov, exec::helpers, lifter, Arch, Config, Cpu};

use crate::Vm;

#[derive(Debug)]
pub enum BuildError {
    UnsupportedArchitecture,
    SpecNotFound(std::path::PathBuf),
    SpecCompileError(String),
    FailedToInitEnvironment(String),
    UnsupportedOperatingSystem,
    InvalidConfig,
}

impl std::fmt::Display for BuildError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::UnsupportedArchitecture => write!(f, "Unsupported architecture"),
            Self::SpecNotFound(path) => write!(f, "Sleigh spec not found: {}", path.display()),
            Self::SpecCompileError(err) => write!(f, "Sleigh spec compile error: {err}"),
            Self::FailedToInitEnvironment(err) => {
                write!(f, "Failed to initialize environment: {err}")
            }
            Self::UnsupportedOperatingSystem => write!(f, "Unsupported operating system"),
            Self::InvalidConfig => write!(f, "Invalid config"),
        }
    }
}

impl std::error::Error for BuildError {}

pub fn build(config: &Config) -> Result<Vm, BuildError> {
    let spec_config =
        get_spec_config(config.triple.architecture).ok_or(BuildError::UnsupportedArchitecture)?;
    let sleigh = build_sleigh(&spec_config)?;

    let arch = build_arch(&config.triple, sleigh, &spec_config)?;
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

    for name in spec_config.temp_registers {
        let var = cpu.arch.sleigh.get_reg(name).ok_or(BuildError::InvalidConfig)?.var;
        lifter.mark_as_temporary(var.id);
    }

    let mut vm = Vm::new(cpu, lifter);
    vm.enable_jit = config.enable_jit;
    register_helpers_for(&mut vm, config.triple.architecture);

    Ok(vm)
}

fn build_arch(
    triple: &target_lexicon::Triple,
    mut sleigh: sleigh_runtime::SleighData,
    config: &SpecConfig,
) -> Result<Arch, BuildError> {
    let get_reg = |sleigh: &sleigh_runtime::SleighData, name: &str| {
        sleigh.get_reg(name).ok_or(BuildError::InvalidConfig).map(|reg| reg.var)
    };

    let mut reg_init = vec![];
    for &(name, value) in &config.init_registers {
        reg_init.push((get_reg(&sleigh, name)?, value));
    }

    // NEXT_PC is used to keep track of the address following the current instruction, this is
    // useful for handling situations such as syscalls that may need to skip the current
    // instruction, without needing to manually know the length of the current instruction.
    let reg_next_pc = sleigh
        .add_custom_reg("NEXT_PC", 8)
        .ok_or(BuildError::SpecCompileError("failed to add varnode for `NEXT_PC`".into()))?;

    let reg_pc = get_reg(&sleigh, config.reg_pc)?;
    let reg_sp = get_reg(&sleigh, config.reg_sp)?;

    let calling_cov = CallCov {
        integers: config
            .calling_cov
            .integers
            .iter()
            .map(|name| get_reg(&sleigh, name))
            .collect::<Result<_, _>>()?,
        stack_align: config.calling_cov.stack_align,
        stack_offset: config.calling_cov.stack_offset,
    };

    Ok(Arch {
        triple: triple.clone(),
        reg_pc,
        reg_sp,
        reg_next_pc,
        reg_isa_mode: sleigh.get_reg("ISAModeSwitch").map(|x| x.var),
        reg_init,
        on_boot: config.on_boot,
        isa_mode_context: config.context.clone(),
        calling_cov,
        sleigh,
    })
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

fn register_helpers_for(vm: &mut Vm, arch: target_lexicon::Architecture) {
    use target_lexicon::Architecture;

    lifter::get_injectors(&mut vm.cpu, &mut vm.lifter.op_injectors);

    register_helpers(vm, helpers::HELPERS);
    match arch {
        Architecture::Arm(_) => {
            register_helpers(vm, helpers::arm::HELPERS);
            // Fixes `pop {..., pc}`
            let pc = vm.cpu.arch.sleigh.get_reg("pc").unwrap().var;
            let tmp_pc = vm.cpu.arch.sleigh.add_custom_reg("tmp_pc", pc.size).unwrap();
            icicle_cpu::lifter::register_read_pc_patcher(&mut vm.lifter, pc, tmp_pc);
        }
        Architecture::Aarch64(_) => register_helpers(vm, helpers::aarch64::HELPERS),
        Architecture::X86_32(_) | Architecture::X86_64 => {
            register_helpers(vm, helpers::x86::HELPERS)
        }
        Architecture::Msp430 => {
            lifter::msp430::status_register_control_patch(&mut vm.cpu, &mut vm.lifter);
            // Fixes RETI, RETA, CALLA
            let pc = vm.cpu.arch.sleigh.get_reg("PC").unwrap().var;
            let tmp_pc = vm.cpu.arch.sleigh.add_custom_reg("TMP_PC", pc.size).unwrap();
            icicle_cpu::lifter::register_read_pc_patcher(&mut vm.lifter, pc, tmp_pc);
        }
        _ => {}
    }
}

// @todo: load this from Ghidra's compiler spec?
struct CallingCovSpec {
    /// Represents registers used for passing integers to functions, these will be chosen before
    /// parameters on the stack
    integers: Vec<&'static str>,
    /// The alignment of parameters passed on the stack,
    stack_align: u64,
    /// The offset (relative to the stack pointer) of the parameters on the stack.
    stack_offset: u64,
}

struct SpecConfig {
    /// The path to the root level sleigh specification for this architecture.
    path: &'static str,
    /// The name of the varnode this architecture uses as the program counter.
    reg_pc: &'static str,
    /// The name of the varnode this architecture uses as the stack pointer.
    reg_sp: &'static str,
    /// Values to use for context register in different ISA modes.
    context: Vec<u64>,
    /// Values to set for registers on reset.
    init_registers: Vec<(&'static str, u128)>,
    /// Extra registers to mark as temporaries (used to improve the optimizer).
    ///
    /// @fixme: It would be nice if there are a standardized way of doing this as part of the
    /// sleigh specification.
    temp_registers: Vec<&'static str>,
    /// A specification of the default calling convention for this architecture.
    // @fixme: This can differ even for the same CPU architecture (e.g. for different compilers).
    calling_cov: CallingCovSpec,
    /// Boot function for the VM to use.
    on_boot: fn(&mut Cpu, u64),
}

fn get_spec_config(arch: target_lexicon::Architecture) -> Option<SpecConfig> {
    use target_lexicon::{Aarch64Architecture, Architecture, ArmArchitecture, Mips32Architecture};

    Some(match arch {
        Architecture::Arm(variant) => {
            let path = match variant {
                ArmArchitecture::Armv7
                | ArmArchitecture::Thumbv7m
                | ArmArchitecture::Thumbv7a
                | ArmArchitecture::Thumbv7em
                | ArmArchitecture::Thumbv7neon => "ARM/data/languages/ARM7_le.slaspec",
                ArmArchitecture::Armv8
                | ArmArchitecture::Arm
                | ArmArchitecture::Thumbv8mBase
                | ArmArchitecture::Thumbv8mMain => "ARM/data/languages/ARM8_le.slaspec",
                _ => return None,
            };
            let context = match variant.is_thumb() {
                false => vec![arm::ARM_MODE_CTX, arm::THUMB_MODE_CTX],
                true => vec![arm::THUMB_MODE_CTX, arm::THUMB_MODE_CTX],
            };
            SpecConfig {
                path,
                reg_pc: "pc",
                reg_sp: "sp",
                context,
                init_registers: vec![],
                temp_registers: vec![
                    "tmpCY",
                    "tmpOV",
                    "tmpNG",
                    "tmpZR",
                    "shift_carry",
                    "mult_addr",
                    "mult_dat8",
                    "mult_dat16",
                ],
                calling_cov: CallingCovSpec {
                    integers: vec!["r0", "r1", "r2", "r3", "r4", "r5", "r6", "r7"],
                    stack_align: 4,
                    stack_offset: 0,
                },
                on_boot: arm::on_boot,
            }
        }
        Architecture::Aarch64(Aarch64Architecture::Aarch64) => SpecConfig {
            path: "AARCH64/data/languages/AARCH64.slaspec",
            reg_pc: "pc",
            reg_sp: "sp",
            context: vec![generic::CTX],
            init_registers: vec![
                ("dczid_el0", 0x10), // disable DC ZVA instructions
            ],
            temp_registers: vec!["tmpCY", "tmpOV", "tmpNG", "tmpZR", "shift_carry"],
            calling_cov: CallingCovSpec {
                integers: vec!["x0", "x1", "x2", "x3", "x4", "x5", "x6", "x7"],
                stack_align: 8,
                stack_offset: 0,
            },
            on_boot: generic::on_boot,
        },
        Architecture::Mips32(variant) => {
            let path = match variant {
                Mips32Architecture::Mips => "MIPS/data/languages/mips32be.slaspec",
                Mips32Architecture::Mipsel => "MIPS/data/languages/mips32le.slaspec",
                Mips32Architecture::Mipsisa32r6 => "MIPS/data/languages/mips32R6be.slaspec",
                Mips32Architecture::Mipsisa32r6el => "MIPS/data/languages/mips32R6le.slaspec",
                _ => return None,
            };
            SpecConfig {
                path,
                reg_pc: "pc",
                reg_sp: "sp",
                context: vec![generic::CTX],
                init_registers: vec![],
                temp_registers: vec![],
                calling_cov: CallingCovSpec {
                    integers: vec!["a0", "a1", "a2", "a3"],
                    stack_align: 4,
                    stack_offset: 0,
                },
                on_boot: generic::on_boot,
            }
        }
        Architecture::Msp430 => SpecConfig {
            path: "TI_MSP430/data/languages/TI_MSP430X.slaspec",
            reg_pc: "PC",
            reg_sp: "SP",
            context: vec![generic::CTX],
            init_registers: vec![],
            temp_registers: vec![],
            calling_cov: CallingCovSpec {
                integers: vec!["R12", "R13", "R14", "R15"],
                stack_align: 2,
                stack_offset: 0,
            },
            on_boot: generic::on_boot,
        },
        Architecture::Powerpc => SpecConfig {
            path: "PowerPC/data/languages/ppc_32_be.slaspec",
            reg_pc: "pc",
            reg_sp: "r1",
            context: vec![generic::CTX],
            init_registers: vec![],
            temp_registers: vec![],
            calling_cov: CallingCovSpec {
                integers: vec!["r0", "r1", "r2", "r3", "r4", "r5", "r6", "r7"],
                stack_align: 4,
                stack_offset: 0,
            },
            on_boot: generic::on_boot,
        },
        Architecture::Riscv32(_) => SpecConfig {
            path: "RISCV/data/languages/riscv.ilp32d.slaspec",
            reg_pc: "pc",
            reg_sp: "sp",
            context: vec![generic::CTX],
            init_registers: vec![],
            temp_registers: vec![],
            calling_cov: CallingCovSpec {
                integers: vec!["a0", "a1", "a2", "a3", "a4", "a5", "a6", "a7"],
                stack_align: 4,
                stack_offset: 0,
            },
            on_boot: generic::on_boot,
        },
        Architecture::Riscv64(_) => SpecConfig {
            path: "RISCV/data/languages/riscv.lp64d.slaspec",
            reg_pc: "pc",
            reg_sp: "sp",
            context: vec![generic::CTX],
            init_registers: vec![],
            temp_registers: vec![],
            calling_cov: CallingCovSpec {
                integers: vec!["a0", "a1", "a2", "a3", "a4", "a5", "a6", "a7"],
                stack_align: 8,
                stack_offset: 0,
            },
            on_boot: generic::on_boot,
        },
        Architecture::X86_32(_) => SpecConfig {
            path: "x86/data/languages/x86-64.slaspec",
            reg_pc: "EIP",
            reg_sp: "ESP",
            context: vec![x86::COMPAT_MODE_CTX],
            init_registers: vec![],
            temp_registers: vec![],
            calling_cov: CallingCovSpec { integers: vec![], stack_align: 4, stack_offset: 0 },
            on_boot: generic::on_boot,
        },
        Architecture::X86_64 => SpecConfig {
            path: "x86/data/languages/x86-64.slaspec",
            reg_pc: "RIP",
            reg_sp: "RSP",
            context: vec![x86::LONG_MODE_CTX],
            init_registers: vec![],
            temp_registers: vec![],
            calling_cov: CallingCovSpec {
                integers: vec!["RDI", "RSI", "RDX", "RCX", "R8", "R9"],
                stack_align: 8,
                stack_offset: 0,
            },
            on_boot: generic::on_boot,
        },
        Architecture::XTensa => SpecConfig {
            path: "xtensa/data/languages/xtensa.slaspec",
            reg_pc: "pc",
            reg_sp: "a1",
            context: vec![generic::CTX],
            init_registers: vec![],
            temp_registers: vec![],
            calling_cov: CallingCovSpec {
                integers: vec!["a2", "a3", "a4", "a5", "a6", "a7"],
                stack_align: 4,
                stack_offset: 0,
            },
            on_boot: generic::on_boot,
        },
        _ => return None,
    })
}

pub fn build_sleigh_for(
    arch: target_lexicon::Architecture,
) -> Result<(sleigh_runtime::SleighData, u64), BuildError> {
    let config = get_spec_config(arch).ok_or(BuildError::UnsupportedArchitecture)?;
    Ok((build_sleigh(&config)?, config.context[0]))
}

fn build_sleigh(config: &SpecConfig) -> Result<sleigh_runtime::SleighData, BuildError> {
    let path = std::env::var_os("GHIDRA_SRC")
        .map_or_else(|| ".".into(), std::path::PathBuf::from)
        .join("Ghidra/Processors")
        .join(config.path);
    if !path.exists() {
        return Err(BuildError::SpecNotFound(path));
    }
    sleigh_compile::from_path(&path).map_err(|e| BuildError::SpecCompileError(e))
}

// @fixme: avoid making this pub when we refactor architecture specific CPU state.
mod generic {
    use icicle_cpu::ValueSource;

    use super::*;

    pub fn on_boot(cpu: &mut Cpu, entry: u64) {
        cpu.reset();
        cpu.regs.write_trunc(cpu.arch.reg_pc, entry);
    }

    pub const CTX: u64 = 0;
}

pub mod x86 {
    use icicle_cpu::ValueSource;

    /// Initial context register state for `x86_64` processor running in long mode.
    ///
    /// * longMode(0, 0)       = 1 (64-bit mode)
    /// * bit64(4, 4)          = 1 (64-bit mode)
    /// * opsize(6, 7)         = 1 (32-bit operands)
    pub const LONG_MODE_CTX: u64 =
        0b_0000_0000_0000_0000_0000_0000_1001_0001_u32.reverse_bits() as u64;

    /// Initial context register state for `x86_64` processor running `x32` compatability mode.
    ///
    /// * longMode(0, 0)       = 0 (32-bit mode)
    /// * addrSize(4, 5)       = 1 (32-bit addresses)
    /// * bit64(4, 4)          = 0 (32-bit mode)
    /// * opsize(6, 7)         = 1 (32-bit operands)
    pub const COMPAT_MODE_CTX: u64 =
        0b_0000_0000_0000_0000_0000_0000_1010_0000_u32.reverse_bits() as u64;

    /// Get merged flags from internal registers
    // @todo: This could possibly be implemented as a Sleigh extension.
    #[allow(clippy::erasing_op, clippy::identity_op)]
    pub fn eflags(cpu: &icicle_cpu::Cpu) -> u32 {
        let read_bit = |name: &str| {
            let var = cpu.arch.sleigh.get_reg(name).unwrap().var;
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
            cpu.write_var(cpu.arch.sleigh.get_reg(name).unwrap().var, value);
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
