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
use icicle_vm::{cpu::ExceptionCode, Vm, VmExit};

pub use crate::{config::CustomSetup, instrumentation::*};
pub use icicle_vm::cpu::utils::parse_u64_with_prefix;

#[derive(Copy, Clone, PartialEq, Eq)]
pub enum CoverageMode {
    /// Store a bit whenever a block is hit.
    Blocks,
    /// Store a bit whenever an edge is hit.
    Edges,
    /// Increment a counter whenever a block is hit.
    BlockCounts,
    /// Increment a counter whenever an edge is hit.
    EdgeCounts,
}

impl std::str::FromStr for CoverageMode {
    type Err = anyhow::Error;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        if s.eq_ignore_ascii_case("blocks") {
            return Ok(Self::Blocks);
        }
        if s.eq_ignore_ascii_case("edges") {
            return Ok(Self::Edges);
        }
        if s.eq_ignore_ascii_case("blockcounts") {
            return Ok(Self::BlockCounts);
        }
        if s.eq_ignore_ascii_case("edgecounts") {
            return Ok(Self::EdgeCounts);
        }

        Err(anyhow::format_err!("Unknown coverage mode: {s}"))
    }
}

#[derive(Clone)]
pub struct FuzzConfig {
    /// Whether the fuzzer should try to resume from a previous run.
    pub resume: bool,

    /// Configures whether the fuzzer should save de-duplicated crashes.
    pub save_crashes: bool,

    /// Configures whether the fuzzer should save de-duplicated hanging inputs.
    pub save_hangs: bool,

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

    /// The level to to use for ComparisonCoverage instrumentation.
    pub compcov_level: Option<u8>,

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

    /// The number of workers to use for fuzzing.
    pub workers: u16,

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

        let coverage_mode = if let Ok(mode) = std::env::var("COVERAGE_MODE") {
            mode.parse()?
        }
        else {
            match (
                parse_bool_env("ICICLE_BLOCK_COVERAGE_ONLY")?.unwrap_or(false),
                parse_bool_env("ICICLE_EDGE_HITS_ONLY")?.unwrap_or(false),
            ) {
                (false, false) => CoverageMode::EdgeCounts,
                (false, true) => CoverageMode::Edges,
                (true, false) => CoverageMode::Blocks,
                (true, true) => {
                    anyhow::bail!(
                        "ICICLE_BLOCK_COVERAGE_ONLY is incompatible with ICICLE_EDGE_HITS_ONLY"
                    )
                }
            }
        };

        let compcov_level = match std::env::var("AFL_COMPCOV_LEVEL") {
            Ok(level) => Some(
                level
                    .parse::<u8>()
                    .with_context(|| format!("Invalid value for AFL_COMPCOV_LEVEL: {level}"))?,
            ),
            Err(_) => None,
        };

        let context_bits = match std::env::var("ICICLE_CONTEXT_BITS") {
            Ok(count) => {
                let bits = count.parse::<u8>().context("error parsing `ICICLE_CONTEXT_BITS`")?;
                anyhow::ensure!(bits <= 16, "A maximum of 16 bits for context is allowed");
                bits
            }
            Err(_) => 0,
        };

        let workers = match std::env::var("WORKERS") {
            Ok(workers) => workers
                .parse::<u16>()
                .with_context(|| format!("Invalid value for WORKERS: {workers}"))?,
            Err(_) => 1,
        };

        Ok(Self {
            resume: parse_bool_env("RESUME")?.unwrap_or(false),
            save_crashes: parse_bool_env("SAVE_CRASHES")?.unwrap_or(true),
            save_hangs: parse_bool_env("SAVE_HANGS")?.unwrap_or(true),
            save_slowest: parse_bool_env("SAVE_SLOWEST")?.unwrap_or(false),
            disable_jit: parse_bool_env("ICICLE_DISABLE_JIT")?.unwrap_or(false),
            shared_mem_inputs: parse_bool_env("ICICLE_SHMEM_INPUT")?.unwrap_or(true),
            cmplog_path: std::env::var_os("ICICLE_SAVE_CMPLOG_MAP").map(|x| x.into()),
            enable_dry_run: parse_bool_env("ICICLE_DRY_RUN")?.unwrap_or(false),
            track_path: parse_bool_env("ICICLE_TRACK_PATH")?.unwrap_or(false),
            arch,
            linux: linux::LinuxConfig::from_env(),
            coverage_mode,
            compcov_level,
            context_bits,
            workers,
            no_cmplog_return: parse_bool_env("ICICLE_CMPLOG_RTN")?.unwrap_or(false),
            start_addr,
            msp430: Msp430Config::from_env()?,
            icount_limit,
            icicle_args,
            guest_args,
            custom_setup,
        })
    }

    pub fn get_instrumentation_range(&self, vm: &mut Vm) -> Option<(u64, u64)> {
        if !self.linux.instrument_libs {
            if let Some(kernel) = vm.env.as_any().downcast_ref::<icicle_vm::linux::Kernel>() {
                return Some((kernel.process.image.start_addr, kernel.process.image.end_addr));
            }
        }
        None
    }

    pub fn get_target(&mut self) -> anyhow::Result<Box<dyn FuzzTarget>> {
        use target_lexicon::{Architecture, OperatingSystem};

        Ok(match (self.arch.operating_system, self.arch.architecture) {
            (OperatingSystem::Linux, _) => Box::new(linux::Target::new()),
            (OperatingSystem::None_, Architecture::Msp430) => {
                Box::new(msp430::RandomIoTarget::new())
            }
            (OperatingSystem::None_, _) => Box::new(HookedTarget::new(self.custom_setup.clone())),
            _ => anyhow::bail!("unsupported target: {}", self.arch),
        })
    }

    pub fn cpu_config(&self) -> icicle_vm::cpu::Config {
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

#[derive(Clone)]
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
    fn set_input(&mut self, vm: &mut Vm, input: &[u8]) -> anyhow::Result<()>;

    /// Modify the current input.
    fn modify_input(&mut self, _vm: &mut Vm, _offset: u64, _input: &[u8]) -> anyhow::Result<()> {
        anyhow::bail!("Not supported by this target")
    }

    /// Get the current input offset from the target.
    fn get_input_cursor(&mut self, _vm: &mut Vm) -> u64 {
        panic!("Not supported by this target")
    }

    /// Run a single fuzzing trial with the current input.
    fn run(&mut self, vm: &mut Vm) -> anyhow::Result<VmExit> {
        Ok(vm.run())
    }

    /// Configure `input` to be the input then run it until it exits.
    #[deprecated]
    fn run_vm(&mut self, vm: &mut Vm, input: &[u8]) -> anyhow::Result<VmExit> {
        self.set_input(vm, input)?;
        Ok(vm.run())
    }

    #[deprecated]
    fn input_buf(&self) -> Option<&icicle_vm::linux::fs::devices::ReadableSharedBufDevice> {
        None
    }
}

pub trait FuzzTarget: Runnable {
    /// Create a new VM instance configured for the target.
    fn create_vm(&mut self, config: &mut FuzzConfig) -> anyhow::Result<Vm>;

    /// Initialize the VM to a state ready for fuzzing.
    ///
    /// This should be performed after configuring instrumentation, since this may involve executing
    /// code.
    fn initialize_vm(&mut self, _config: &FuzzConfig, _vm: &mut Vm) -> anyhow::Result<()> {
        Ok(())
    }

    /// Returns a user understandable exit string
    fn exit_string(&self, exit: VmExit) -> String {
        format!("{exit:?}")
    }
}

pub trait Fuzzer {
    type Output;
    fn run<T: FuzzTarget>(self, target: T, config: FuzzConfig) -> anyhow::Result<Self::Output>;
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
) -> anyhow::Result<((Vm, I), Box<dyn FuzzTarget>)>
where
    F: FnOnce(&mut Vm, &FuzzConfig) -> anyhow::Result<I>,
{
    let mut target = config.get_target()?;

    let mut vm = target.create_vm(config)?;
    let instrumentation = instrument_vm(&mut vm, config)?;
    target.initialize_vm(config, &mut vm)?;

    Ok(((vm, instrumentation), target))
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
pub fn resolve_crashes<T>(
    mut target: T,
    config: &mut FuzzConfig,
    dir: &std::path::Path,
) -> anyhow::Result<CrashMap>
where
    T: FuzzTarget,
{
    let mut vm = target.create_vm(config)?;
    target.initialize_vm(config, &mut vm)?;

    let snapshot = vm.snapshot();
    let mut map = BTreeMap::new();
    utils::input_visitor(dir, |path, input| {
        vm.restore(&snapshot);

        tracing::info!("resolving crashes for {}", path.display());
        target.set_input(&mut vm, &input)?;
        let exit = vm.run();
        let exit_code = utils::get_afl_exit_code(&vm, exit);

        map.entry(gen_crash_key(&mut vm, exit))
            .or_insert_with(|| CrashEntry {
                call_stack_string: icicle_vm::debug::backtrace(&mut vm),
                exit,
                exit_code,
                inputs: vec![],
            })
            .inputs
            .push(path);

        Ok(())
    })?;

    tracing::info!("{} crash groups found", map.len());

    Ok(map)
}

pub fn gen_crash_key(vm: &mut Vm, exit: VmExit) -> String {
    let pc = vm.cpu.read_pc();
    let last_addr = vm.code.blocks.get(vm.cpu.block_id as usize).map_or(pc, |x| x.end);

    let stack = vm.get_callstack();
    let stack_hash = match vm.cpu.enable_shadow_stack {
        true => stack.iter().rev().skip(1).take(3).fold(0x0, |acc, x| acc ^ x),
        false => match pc == last_addr {
            true => pc,
            false => pc ^ last_addr,
        },
    };

    // Choose a de-duplication strategy depending on how the program crashed.
    match CrashKind::from(exit) {
        CrashKind::Custom(code) => format!("{code:#05x}_{pc:#x}_custom"),
        CrashKind::Halt => format!("{stack_hash:#x}_halt"),
        CrashKind::Hang | CrashKind::OutOfMemory => {
            // Caused by timeouts or resource exhaustion. Since the detection is based on
            // heuristics, the final PC frequently changes. To reduce duplicates we just use
            // the parent function (if avaliable).
            format!("{:#x}_hang", stack.iter().rev().nth(1).unwrap_or(&pc))
        }
        CrashKind::Killed => format!("{stack_hash:#x}_killed"),
        CrashKind::ExecViolation => {
            // When we have an execution violation, then the final address is invalid. To
            // deduplicate cases where this is caused by the corruption of a function pointer, we
            // save inputs based on the previous address instead of usign pc.
            match pc {
                0 => format!("{stack_hash:#x}_{last_addr:#x}_jump_null"),
                _ => format!("{stack_hash:#x}_{last_addr:#x}_jump_invalid"),
            }
        }
        CrashKind::ReadViolation(addr) => match addr {
            0 => format!("{stack_hash:#x}_{pc:#x}_read_error_null"),
            _ => format!("{stack_hash:#x}_{pc:#x}_read_error"),
        },
        CrashKind::WriteViolation(addr) => match addr {
            0 => format!("{stack_hash:#x}_{pc:#x}_write_error_null"),
            _ => format!("{stack_hash:#x}_{pc:#x}_write_error"),
        },
        CrashKind::Unknown => format!("{pc:#x}_unknown"),
    }
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
    fn set_input(&mut self, vm: &mut Vm, input: &[u8]) -> anyhow::Result<()> {
        self.setup.input.clear();
        self.setup.input.extend_from_slice(input);
        self.setup.init(vm, &mut self.buf)?;
        Ok(())
    }
}

impl FuzzTarget for HookedTarget {
    fn create_vm(&mut self, config: &mut FuzzConfig) -> anyhow::Result<Vm> {
        let mut vm = icicle_vm::build(&config.cpu_config())?;
        let mut env = icicle_vm::env::build_auto(&mut vm)?;
        env.load(&mut vm.cpu, config.guest_args[0].as_bytes())
            .map_err(|e| anyhow::format_err!("{}", e))?;
        vm.env = env;
        self.setup.configure(&mut vm)?;

        Ok(vm)
    }
}

/// Adds debug instrumentation to `vm` based on environment variables.
pub fn add_debug_instrumentation(vm: &mut icicle_vm::Vm) {
    if let Ok(entries) = std::env::var("ICICLE_LOG_WRITES") {
        // A `;` separated list of locations to instrument writes to, e.g:
        // "applet=0x1c00:2;jumptarget=0x1c02:2"
        for entry in entries.split(';') {
            match parse_write_hook(entry) {
                Some((name, addr, size)) => {
                    tracing::info!("Logging writes to {name}@{addr:#x} ({size} bytes)");
                    icicle_vm::debug::log_write(vm, name.to_string(), addr, size);
                }
                _ => tracing::error!("Invalid write hook format: {entry}"),
            }
        }
    }
    if let Ok(entries) = std::env::var("ICICLE_LOG_REGS") {
        for entry in entries.split(';') {
            match parse_reg_print_hook(entry) {
                Some((name, addr, reglist)) => {
                    icicle_vm::debug::log_regs(vm, name.to_string(), addr, &reglist);
                }
                _ => tracing::error!("Invalid write hook format: {entry}"),
            }
        }
    }
    if let Ok(entries) = std::env::var("BREAKPOINTS") {
        // A comma separated list of addresses to stop execution at.
        for entry in entries.split(',') {
            match parse_u64_with_prefix(entry) {
                Some(addr) => {
                    vm.add_breakpoint(addr);
                }
                _ => tracing::error!("Invalid breakpoint: {entry}"),
            }
        }
    }
}

/// A string of the format `<name>=<address>:<size>`.
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

/// A string of the format `<name>@<address>=<reglist>`
pub fn parse_reg_print_hook(entry: &str) -> Option<(&str, u64, Vec<&str>)> {
    let entry = entry.trim();
    if entry.is_empty() {
        return None;
    }

    let (target, reglist) = entry.split_once('=')?;
    let (name, pc) = target.split_once('@')?;

    let pc = parse_u64_with_prefix(pc)?;

    Some((name, pc, reglist.split(',').map(str::trim).collect()))
}

/// Parse a string of the format `<address>(<reglist>)` and return a tuple with the address and
/// register.
pub fn parse_func_hook(entry: &str) -> Option<(u64, Vec<&str>)> {
    let entry = entry.trim();
    if entry.is_empty() {
        return None;
    }

    let (pc, reg) = entry.split_once('(')?;
    let pc = parse_u64_with_prefix(pc)?;
    let reglist = reg.trim_end_matches(')');

    Some((pc, reglist.split(',').map(str::trim).collect()))
}

/// Parse a boolean environment varialbe
pub fn parse_bool_env(name: &str) -> anyhow::Result<Option<bool>> {
    match std::env::var_os(name) {
        Some(var) => {
            let x =
                var.to_str().ok_or_else(|| anyhow::format_err!("{name} was not a valid string"))?;
            Ok(Some(x.trim() != "0"))
        }
        None => Ok(None),
    }
}

/// Groups VmExits into different crash kinds.
#[derive(Debug, PartialEq, Eq)]
pub enum CrashKind {
    /// The VM halted execution.
    Halt,

    /// Caused by timeouts or resource exhaustion.
    Hang,

    /// The program running in the VM exceeded memory limits.
    OutOfMemory,

    /// Killed by an environment specific mechanism.
    Killed,

    /// Attempted to execute an invalid instruction or memory with the incorrect permissions.
    ExecViolation,

    /// Attempted to read from an invalid address.
    ReadViolation(u64),

    /// Attempted to write to an invalid address.
    WriteViolation(u64),

    /// Custom environment defined error.
    Custom(u64),

    /// Generally only caused by either a bug in the emulator, or a handcrafted error exit
    /// condition
    Unknown,
}

impl CrashKind {
    pub fn is_crash(&self) -> bool {
        !matches!(self, CrashKind::Halt | CrashKind::Hang)
    }

    pub fn is_hang(&self) -> bool {
        matches!(self, CrashKind::Hang)
    }

    pub fn is_ok(&self) -> bool {
        matches!(self, CrashKind::Halt)
    }
}

impl From<VmExit> for CrashKind {
    fn from(exit: VmExit) -> Self {
        match exit {
            VmExit::UnhandledException((ExceptionCode::Environment, value)) => Self::Custom(value),

            VmExit::Halt
            | VmExit::UnhandledException((
                ExceptionCode::ReadWatch | ExceptionCode::WriteWatch,
                _,
            )) => Self::Halt,

            VmExit::Running | VmExit::InstructionLimit | VmExit::Interrupted | VmExit::Deadlock => {
                Self::Hang
            }

            VmExit::OutOfMemory => Self::OutOfMemory,

            VmExit::Killed => Self::Killed,

            VmExit::UnhandledException((
                ExceptionCode::InvalidInstruction
                | ExceptionCode::InvalidTarget
                | ExceptionCode::ShadowStackInvalid
                | ExceptionCode::ExecViolation,
                _,
            )) => Self::ExecViolation,

            VmExit::UnhandledException((code, addr)) if code.is_memory_error() => match code {
                ExceptionCode::ReadUnmapped
                | ExceptionCode::ReadPerm
                | ExceptionCode::ReadUnaligned
                | ExceptionCode::ReadUninitialized => Self::ReadViolation(addr),

                ExceptionCode::WriteUnmapped
                | ExceptionCode::WritePerm
                | ExceptionCode::WriteUnaligned => Self::WriteViolation(addr),

                // @fixme: change the error type for this address?
                ExceptionCode::SelfModifyingCode => Self::WriteViolation(addr),

                _ => Self::Unknown,
            },

            VmExit::Breakpoint
            | VmExit::Unimplemented
            | VmExit::UnhandledException((ExceptionCode::InternalError, _)) => Self::Unknown,

            VmExit::UnhandledException(..) => Self::Unknown,
        }
    }
}
