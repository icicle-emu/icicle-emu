//! Fuzzing extensions and utilities for the emulator

pub mod linux;
pub mod log;
pub mod msp430;
pub mod trace;
pub mod utils;

mod config;
mod instrumentation;

use std::{
    collections::{BTreeMap, HashSet},
    path::PathBuf,
};

use anyhow::Context;
use icicle_vm::{cpu::ExceptionCode, VmExit};

pub use crate::{config::CustomSetup, instrumentation::*};

#[derive(Copy, Clone, PartialEq, Eq)]
pub enum CoverageMode {
    /// Store a bit whenever a block is hit.
    Blocks,
    /// Store a bit whenever an edge is hit.
    Edges,
    /// Increment a counter whenever an edge is hit.
    HitCounts,
}

pub struct FuzzConfig {
    /// Configures whether crashes should be saved internally.
    pub save_crashes: bool,

    /// Configures whether the slowest input executed so far should be saved.
    pub save_slowest: bool,

    /// Whether the JIT should be disabled.
    pub disable_jit: bool,

    /// Configures whether we should attempt to read inputs from shared memory.
    pub shared_mem_inputs: bool,

    /// The path where the 'CmpLog' map should be saved to. If [None] the map is not saved.
    pub cmplog_path: Option<PathBuf>,

    /// Whether we should perform a dry run before telling AFL++ that we are running. (Avoids
    /// timeouts due to JIT performance).
    pub enable_dry_run: bool,

    /// Controls what instrumentation strategy to use for
    pub coverage_mode: CoverageMode,

    /// The number of bits to use for context when context coverage is enabled.
    pub context_bits: u8,

    /// Changes cmplog instrumentation to not log call paramters.
    pub no_cmplog_return: bool,

    /// Keep track of the exact path taken by the program.
    pub track_path: bool,

    /// The architecture to configure the VM for.
    pub arch: target_lexicon::Triple,

    /// Configures the fuzzer to run the VM until it reaches `start_addr` before taking a snapshot.
    pub start_addr: Option<u64>,

    /// The maximum number of instructions to execute before exiting.
    pub icount_limit: u64,

    /// Additional arguments passed to the emulator.
    pub icicle_args: Vec<String>,

    /// Arguments passed to the target
    pub guest_args: Vec<String>,

    /// Additional linux only configuration.
    pub linux: linux::LinuxConfig,

    /// MSP430 only configuration.
    pub msp430: Msp430Config,

    /// Config for targets with a custom startup.
    pub custom_setup: CustomSetup,
}

impl FuzzConfig {
    pub fn load() -> anyhow::Result<Self> {
        let (icicle_args, guest_args) = get_args()?;
        tracing::info!("guest args: {:?}", guest_args);

        FuzzConfig::load_with_args(icicle_args, guest_args)
    }

    pub fn load_with_args(
        icicle_args: Vec<String>,
        guest_args: Vec<String>,
    ) -> anyhow::Result<Self> {
        let icount_limit: u64 = match std::env::var("ICICLE_ICOUNT_LIMIT") {
            Ok(count) => {
                parse_u64_with_prefix(&count).context("error parsing `ICICLE_ICOUNT_LIMIT`")?
            }
            Err(_) => 10_000_000_000,
        };

        let start_addr: Option<u64> = match std::env::var("ICICLE_START_ADDR") {
            Ok(count) => {
                Some(parse_u64_with_prefix(&count).context("error parsing `ICICLE_START_ADDR`")?)
            }
            Err(_) => None,
        };

        let arch_string = std::env::var("ICICLE_ARCH").unwrap_or_else(|_| "x86_64-linux".into());
        let arch =
            arch_string.parse().map_err(|e| anyhow::format_err!("{}: {}", arch_string, e))?;

        let custom_setup = match std::env::var("ICICLE_CUSTOM_SETUP") {
            Ok(setup) => ron::from_str(&setup).context("error parsing `ICICLE_CUSTOM_SETUP`")?,
            Err(_) => match std::env::var("ICICLE_CUSTOM_SETUP_PATH") {
                Ok(path) => {
                    let setup = std::fs::read_to_string(&path).with_context(|| {
                        format!("error reading `ICICLE_CUSTOM_SETUP_PATH: {path}")
                    })?;
                    ron::from_str(&setup).with_context(|| {
                        format!("error parsing ICICLE_CUSTOM_SETUP_PATH: {path}")
                    })?
                }
                Err(_) => CustomSetup::default(),
            },
        };

        let coverage_mode = match (
            std::env::var_os("ICICLE_BLOCK_COVERAGE_ONLY").is_some(),
            std::env::var_os("ICICLE_EDGE_HITS_ONLY").is_some(),
        ) {
            (false, false) => CoverageMode::HitCounts,
            (false, true) => CoverageMode::Edges,
            (true, false) => CoverageMode::Blocks,
            (true, true) => {
                anyhow::bail!(
                    "ICICLE_BLOCK_COVERAGE_ONLY is incompatible with ICICLE_EDGE_HITS_ONLY"
                )
            }
        };

        let context_bits = match std::env::var("ICICLE_CONTEXT_BITS") {
            Ok(count) => {
                let bits = count.parse::<u8>().context("error parsing `ICICLE_CONTEXT_BITS`")?;
                anyhow::ensure!(bits <= 16, "A maximum of 16 bits for context is allowed");
                bits
            }
            Err(_) => 0,
        };

        Ok(Self {
            save_crashes: std::env::var_os("ICICLE_SAVE_CRASH").is_some(),
            save_slowest: std::env::var_os("ICICLE_SAVE_SLOWEST").is_some(),
            disable_jit: std::env::var_os("ICICLE_DISABLE_JIT").is_some(),
            shared_mem_inputs: std::env::var_os("ICICLE_DISABLE_SHMEM_INPUT").is_none(),
            cmplog_path: std::env::var_os("ICICLE_SAVE_CMPLOG_MAP").map(|x| x.into()),
            enable_dry_run: std::env::var_os("ICICLE_DRY_RUN").is_some(),
            track_path: std::env::var_os("ICICLE_TRACK_PATH").is_some(),
            arch,
            linux: linux::LinuxConfig::from_env(),
            coverage_mode,
            context_bits,
            no_cmplog_return: std::env::var_os("ICICLE_NO_CMPLOG_RTN").is_some(),
            start_addr,
            msp430: Msp430Config::from_env()?,
            icount_limit,
            icicle_args,
            guest_args,
            custom_setup,
        })
    }

    pub fn get_instrumentation_range(&self, vm: &mut icicle_vm::Vm) -> Option<(u64, u64)> {
        if !self.linux.instrument_libs {
            if let Some(kernel) = vm.env.as_any().downcast_ref::<icicle_vm::linux::Kernel>() {
                return Some((kernel.process.image.start_addr, kernel.process.image.end_addr));
            }
        }
        None
    }

    fn cpu_config(&self) -> icicle_vm::cpu::Config {
        icicle_vm::cpu::Config {
            triple: self.arch.clone(),
            enable_jit: !self.disable_jit,
            // Disable automatically recompilation, since this causes AFL to think the emulator
            // hangs.
            enable_recompilation: false,
            ..Default::default()
        }
    }
}

pub struct Msp430Config {
    /// How many instructions to execute between triggering interrupts.
    // @fixme: have a better way of configuring this, default is ~10ms of device time assuming
    // 16 MHz clock
    pub interrupt_interval: u64,

    /// Addresses of peripherals to use to read from the input string. Other peripherals are read
    /// from a RNG seeded from the input string. If [None] all peripheral reads are taken from the
    /// input string (MSP430 only).
    pub fuzz_addrs: Option<HashSet<u64>>,

    /// The name (or path) of the MCU config to use.
    pub mcu: Option<String>,

    /// Configures whether a fixed value should be used to initialize the RNGs instead of using the
    /// first byte of the input.
    pub fixed_seed: Option<u64>,

    /// Address the binary should be loaded at (for raw binaries)
    pub load_addr: Option<u64>,
}

impl Msp430Config {
    pub fn from_env() -> anyhow::Result<Self> {
        let fuzz_addrs = match std::env::var("MSP430_FUZZ_ADDR") {
            Ok(filter) => {
                let mut fuzz_addrs = std::collections::HashSet::new();
                for entry in filter.split(',') {
                    let addr = parse_u64_with_prefix(entry)
                        .ok_or_else(|| anyhow::format_err!("Invalid fuzz addresses"))?;
                    fuzz_addrs.insert(addr);
                }
                Some(fuzz_addrs)
            }
            Err(_) => None,
        };

        let interrupt_interval = match std::env::var("MSP430_INTERRUPT_INTERVAL") {
            Ok(interval) => parse_u64_with_prefix(&interval)
                .context("error parsing `MSP430_INTERRUPT_INTERVAL`")?,
            Err(_) => 0x8_0000,
        };

        let load_addr = match std::env::var("MSP430_LOAD_ADDR") {
            Ok(interval) => {
                Some(parse_u64_with_prefix(&interval).context("error parsing `MSP430_LOAD_ADDR`")?)
            }
            Err(_) => None,
        };

        let fixed_seed = match std::env::var("MSP430_FIXED_SEED") {
            Ok(seed) => {
                Some(parse_u64_with_prefix(&seed).context("error parsing `MSP430_FIXED_SEED`")?)
            }
            Err(_) => None,
        };

        Ok(Self {
            interrupt_interval,
            fuzz_addrs,
            fixed_seed,
            mcu: std::env::var("MSP430_MCU").ok(),
            load_addr,
        })
    }
}

fn get_args() -> anyhow::Result<(Vec<String>, Vec<String>)> {
    let args: Vec<_> = std::env::args().collect();
    tracing::info!("afl-icicle-trace invoked with: {:?}", args);

    if args.is_empty() {
        anyhow::bail!("Invalid arguments");
    }

    if !args.iter().any(|arg| *arg == "--") {
        let (icicle_args, guest_args) = args.split_at(1);
        return Ok((icicle_args.to_vec(), guest_args.to_vec()));
    }

    let (icicle_args, guest_args) = {
        let mut iter = args.splitn(2, |arg| arg == "--");
        (
            iter.next().ok_or_else(|| anyhow::format_err!("invalid arguments"))?,
            iter.next().ok_or_else(|| anyhow::format_err!("invalid arguments"))?,
        )
    };
    Ok((icicle_args.to_vec(), guest_args.to_vec()))
}

pub trait Runnable {
    /// Configure the VM to use `input` as the input.
    fn set_input(&mut self, vm: &mut icicle_vm::Vm, input: &[u8]) -> anyhow::Result<()>;

    /// Restore the VM to before the first input interaction, configure `input` to be the input then
    /// run it until it exits.
    fn run_vm(
        &mut self,
        vm: &mut icicle_vm::Vm,
        input: &[u8],
        max_instructions: u64,
    ) -> anyhow::Result<VmExit> {
        self.set_input(vm, input)?;
        vm.icount_limit = vm.cpu.icount.saturating_add(max_instructions);
        Ok(vm.run())
    }

    fn input_buf(&self) -> Option<&icicle_vm::linux::fs::devices::ReadableSharedBufDevice> {
        None
    }
}

pub trait FuzzTarget: Runnable {
    /// Create a new VM instance ready for fuzzing.
    fn initialize_vm<I, F>(
        &mut self,
        config: &mut FuzzConfig,
        instrument_vm: F,
    ) -> anyhow::Result<(icicle_vm::Vm, I)>
    where
        F: FnOnce(&mut icicle_vm::Vm, &FuzzConfig) -> anyhow::Result<I>;
}

pub trait Fuzzer {
    type Output;
    fn run<T: FuzzTarget + Clone>(
        self,
        target: T,
        config: FuzzConfig,
    ) -> anyhow::Result<Self::Output>;
}

/// Run `run` configured for an inbuilt fuzzing target architecture.
pub fn run_auto<T, F: Fuzzer<Output = T>>(config: FuzzConfig, fuzzer: F) -> anyhow::Result<T> {
    use target_lexicon::{Architecture, OperatingSystem};

    match (config.arch.operating_system, config.arch.architecture) {
        (OperatingSystem::Linux, _) => {
            let target = linux::Target::new();
            fuzzer.run(target, config)
        }
        (OperatingSystem::None_, Architecture::Msp430) => {
            let target = msp430::RandomIoTarget::new();
            fuzzer.run(target, config)
        }
        (OperatingSystem::None_, _) => {
            let target = HookedTarget::new(config.custom_setup.clone());
            fuzzer.run(target, config)
        }
        _ => anyhow::bail!("unsupported target: {}", config.arch),
    }
}

/// Prepare a VM instance for fuzzing.
pub fn initialize_vm_auto<I, F>(
    config: &mut FuzzConfig,
    instrument_vm: F,
) -> anyhow::Result<((icicle_vm::Vm, I), Box<dyn Runnable>)>
where
    F: FnOnce(&mut icicle_vm::Vm, &FuzzConfig) -> anyhow::Result<I>,
{
    use target_lexicon::{Architecture, OperatingSystem};

    match (config.arch.operating_system, config.arch.architecture) {
        (OperatingSystem::Linux, _) => {
            let mut target = linux::Target::new();
            Ok((target.initialize_vm(config, instrument_vm)?, Box::new(target)))
        }
        (OperatingSystem::None_, Architecture::Msp430) => {
            let mut target = msp430::RandomIoTarget::new();
            Ok((target.initialize_vm(config, instrument_vm)?, Box::new(target)))
        }
        (OperatingSystem::None_, _) => {
            let mut target = HookedTarget::new(config.custom_setup.clone());
            Ok((target.initialize_vm(config, instrument_vm)?, Box::new(target)))
        }
        _ => anyhow::bail!("unsupported target: {}", config.arch),
    }
}

pub struct CrashEntry {
    /// The symbolised call stack when the crash occured.
    pub call_stack_string: String,

    /// The exit condition at the crash
    pub exit: VmExit,

    /// The exit code of the crash translated for AFL
    pub exit_code: u32,

    /// The list of all inputs that crashed at this location.
    pub inputs: Vec<PathBuf>,
}

pub type CrashMap = BTreeMap<String, CrashEntry>;

/// Resolves and captures deduplicated stack-traces for all inputs in `dir`.
pub fn resolve_crashes(config: &mut FuzzConfig, dir: &std::path::Path) -> anyhow::Result<CrashMap> {
    let ((mut vm, path_tracer), mut runner) =
        initialize_vm_auto(config, |vm, _| trace::add_path_tracer(vm))?;

    let snapshot = vm.snapshot();
    let mut map = BTreeMap::new();
    utils::input_visitor(&dir, |path, input| {
        path_tracer.clear(&mut vm);
        vm.restore(&snapshot);

        tracing::info!("resolving crashes for {}", path.display());
        let exit = runner.run_vm(&mut vm, &input, u64::MAX)?;
        let exit_code = utils::get_afl_exit_code(&mut vm, exit);

        let pc = vm.cpu.read_pc();
        let stack = vm.get_callstack();
        let stack_hash = stack.iter().rev().skip(1).take(3).fold(0x0, |acc, x| acc ^ x);
        let last_blocks = path_tracer.get_last_blocks(&mut vm);

        // Choose a de-duplication strategy depending on how the program crashed.
        let key = match exit {
            VmExit::Running
            | VmExit::InstructionLimit
            | VmExit::Interrupted
            | VmExit::AllocFailure => {
                // Caused by timeouts or resource exhaustion. Since the detection is based on
                // heuristics, the final PC frequently changes. To reduce duplicates we just use
                // the parent function (if avaliable).
                format!("{:#x}_hang", stack.iter().rev().skip(1).next().unwrap_or(&pc))
            }

            VmExit::Breakpoint | VmExit::Unimplemented => {
                // Generally only caused by either a bug in the emulator, or a handcrafted error
                // exit condition, so generate a key based on the current pc
                format!("{pc:#x}_internal")
            }

            VmExit::UnhandledException((
                ExceptionCode::InvalidInstruction
                | ExceptionCode::InvalidTarget
                | ExceptionCode::ShadowStackInvalid
                | ExceptionCode::ExecViolation,
                _,
            )) => {
                // If we ended up at an invalid instruction then assume that the last jump was bad.
                let last_block =
                    last_blocks.iter().rev().skip(1).next().map_or(pc, |(addr, _)| *addr);

                // Try to deduplicate cases where multiple blocks end at the same place by using the
                // address at the end of the block.
                let key = vm.get_block_key(last_block);
                let last_addr = vm.code.map.get(&key).map_or(last_block, |group| group.end);

                match pc {
                    0 => format!("{stack_hash:#x}_{last_addr:#x}_jump_null"),
                    _ => format!("{stack_hash:#x}_{last_addr:#x}_jump_invalid"),
                }
            }

            VmExit::UnhandledException((code, addr)) if code.is_memory_error() => {
                // Separate any errors from different kinds of memory exceptions.
                let kind = match code {
                    ExceptionCode::ReadUnmapped
                    | ExceptionCode::ReadPerm
                    | ExceptionCode::ReadUnaligned
                    | ExceptionCode::ReadWatch
                    | ExceptionCode::ReadUninitialized => "read_violation",

                    ExceptionCode::WriteUnmapped
                    | ExceptionCode::WritePerm
                    | ExceptionCode::WriteWatch
                    | ExceptionCode::WriteUnaligned => "write_violation",

                    _ => "unknown_mem_error",
                };
                match addr {
                    0 => format!("{stack_hash:#x}_{kind}_null"),
                    _ => format!("{stack_hash:#x}_{kind}"),
                }
            }

            VmExit::Deadlock | VmExit::Halt => format!("{stack_hash:#x}_halt"),
            VmExit::UnhandledException(..) => format!("{stack_hash:#x}_unknown"),
        };

        map.entry(key)
            .or_insert_with(|| CrashEntry {
                call_stack_string: icicle_vm::debug::backtrace(&mut vm),
                exit,
                exit_code,
                inputs: vec![],
            })
            .inputs
            .push(path.to_owned());

        Ok(())
    })?;
    Ok(map)
}

#[derive(Clone)]
pub struct HookedTarget {
    setup: CustomSetup,
    buf: Vec<u8>,
}

impl HookedTarget {
    pub fn new(setup: CustomSetup) -> Self {
        Self { setup, buf: vec![] }
    }
}

impl Runnable for HookedTarget {
    fn set_input(&mut self, vm: &mut icicle_vm::Vm, input: &[u8]) -> anyhow::Result<()> {
        self.setup.input.clear();
        self.setup.input.extend_from_slice(input);
        self.setup.init(vm, &mut self.buf)?;
        Ok(())
    }
}

impl FuzzTarget for HookedTarget {
    fn initialize_vm<I, F>(
        &mut self,
        config: &mut FuzzConfig,
        instrument_vm: F,
    ) -> anyhow::Result<(icicle_vm::Vm, I)>
    where
        F: FnOnce(&mut icicle_vm::Vm, &FuzzConfig) -> anyhow::Result<I>,
    {
        let mut vm = icicle_vm::build(&config.cpu_config())?;
        let mut env = icicle_vm::env::build_auto(&mut vm)?;
        env.load(&mut vm.cpu, config.guest_args[0].as_bytes())
            .map_err(|e| anyhow::format_err!("{}", e))?;
        vm.env = env;
        self.setup.configure(&mut vm)?;

        let instrumentation = instrument_vm(&mut vm, config)?;
        Ok((vm, instrumentation))
    }
}

/// Parse a u64 with either no prefix (decimal), '0x' prefix (hex), or '0b' (binary)
pub fn parse_u64_with_prefix(value: &str) -> Option<u64> {
    if value.len() < 2 {
        return value.parse().ok();
    }

    let (value, radix) = match &value[0..2] {
        "0x" => (&value[2..], 16),
        "0b" => (&value[2..], 2),
        _ => (value, 10),
    };

    u64::from_str_radix(value, radix).ok()
}

// A string of the format `<name>=<address>:<size>`.
pub fn parse_write_hook(entry: &str) -> Option<(&str, u64, u8)> {
    let entry = entry.trim();
    if entry.is_empty() {
        return None;
    }
    let (name, addr_size) = entry.split_once('=')?;
    let (addr, size) = addr_size.split_once(':')?;

    let addr = parse_u64_with_prefix(addr)?;
    let size: u8 = size.parse().ok()?;

    Some((name, addr, size))
}
