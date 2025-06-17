use std::{
    cell::UnsafeCell,
    io::{Read, Write},
    path::Path,
};

use anyhow::Context;
use icicle_fuzzing::{
    utils::{get_afl_exit_code, BlockCoverageTracker},
    FuzzConfig, FuzzTarget,
};
use icicle_vm::{
    cpu::ExceptionCode,
    linux::{Kernel, TerminationReason},
    VmExit,
};

pub use crate::{instrumentation::instrument_vm, shared_mem::is_afl_connected};

pub mod afl;
mod instrumentation;
mod shared_mem;

static IS_CMPLOG: std::sync::atomic::AtomicBool = std::sync::atomic::AtomicBool::new(false);

fn is_cmplog_server() -> bool {
    IS_CMPLOG.load(std::sync::atomic::Ordering::Acquire)
}

pub fn forkserver_init() {
    if std::env::var_os("ICICLE_HANG_ME").is_some() {
        let mut buf = [0; 1];
        let _ = std::io::stdin().read_exact(&mut buf);
        std::process::exit(0);
    }

    if std::env::var_os(shared_mem::IS_CMPLOG_FORK_SERVER).is_some() {
        IS_CMPLOG.store(true, std::sync::atomic::Ordering::Release);
    }
}

pub struct ForkserverFuzzer;

impl icicle_fuzzing::Fuzzer for ForkserverFuzzer {
    type Output = ();

    fn run<T: FuzzTarget>(self, target: T, mut config: FuzzConfig) -> anyhow::Result<()> {
        if let Some(dir) = std::env::var_os("ICICLE_RESOLVE_CRASHES") {
            match icicle_fuzzing::resolve_crashes(target, &mut config, dir.as_ref()) {
                Ok(crashes) => save_crashes(&crashes, std::fs::File::create("crashes.json")?)?,
                Err(e) => log_error_and_exit(e),
            }
            return Ok(());
        }

        if !shared_mem::is_afl_connected() {
            config.linux.mount_stdout = true;
            if let Err(e) = run_without_parent::<T>(target, config) {
                log_error_and_exit(e);
            }
            return Ok(());
        }

        let span = match is_cmplog_server() {
            true => tracing::info_span!("afl_icicle_cmplog"),
            false => tracing::info_span!("afl_icicle_trace"),
        };

        let _guard = span.enter();

        // Safety: this is the only place that we call this function, and we "trust" that we have
        // been invoked correctly.
        //
        // Note: we open this here instead of inside of `run` to avoid closing the file descriptors
        // before exiting (which will result in us being killed by AFL).
        let mut afl = unsafe { afl::Comms::open() };

        if let Err(e) = run_afl::<T>(target, config, &mut afl) {
            // Last chance to print errors before we will be killed by AFL.
            tracing::error!("{:?}", e);
            eprintln!("[icicle] {:?}", e);
        }
        Ok(())
    }
}

pub fn save_crashes<W>(crashes: &icicle_fuzzing::CrashMap, mut writer: W) -> std::io::Result<()>
where
    W: std::io::Write,
{
    let mut output = vec![];
    for (key, metadata) in crashes {
        if metadata.exit_code == 0 {
            tracing::warn!("{} does not crash: {key}", metadata.inputs[0].display());
        }

        let inputs: Vec<_> = metadata.inputs.iter().map(|x| x.to_string_lossy()).collect();
        output.push(serde_json::json!({
            "inputs": inputs,
            "exit": format!("{:?}", metadata.exit),
            "exit_code": metadata.exit_code,
            "key": key,
            "call_stack": metadata.call_stack_string,
        }));
    }
    write!(writer, "{}", serde_json::json!(output))
}

pub fn log_error_and_exit(error: anyhow::Error) -> ! {
    eprintln!("[icicle] {error:?}");
    std::process::exit(1);
}

pub fn run_without_parent<T: FuzzTarget>(
    mut target: T,
    mut config: FuzzConfig,
) -> anyhow::Result<()> {
    let mut vm = target.create_vm(&mut config).context("Failed to initialize VM")?;
    let tracer = icicle_fuzzing::trace::add_path_tracer(&mut vm)?;
    target.initialize_vm(&config, &mut vm)?;
    icicle_fuzzing::add_debug_instrumentation(&mut vm);

    let max_input_size = match std::env::var("INPUT_SIZE") {
        Ok(size) => icicle_fuzzing::parse_u64_with_prefix(&size)
            .with_context(|| format!("invalid input size: {size}"))? as usize,
        _ => usize::MAX,
    };

    let input = read_input(config)?;
    let truncated_input = &input[..max_input_size.min(input.len())];
    if input.len() != truncated_input.len() {
        tracing::info!(
            "input truncated to {max_input_size:#x} bytes (last byte = {:#x})",
            truncated_input.last().unwrap_or(&0)
        );
    }

    target.set_input(&mut vm, truncated_input)?;

    let mut cmplog_trace = None;
    if let Some(path) = std::env::var_os("ICICLE_SAVE_CMP_MAP") {
        let map = gen_cmplog_map(&mut vm);
        cmplog_trace = Some((path, map));
    }

    if let Ok(addr) = std::env::var("GDB_BIND") {
        icicle_gdb::listen_auto(&addr, &mut vm)?;
        return Ok(());
    }

    let exit = target.run(&mut vm)?;
    eprintln!("\n[icicle] exited with: {:?}", exit);

    if std::env::var_os("ICICLE_SAVE_DISASM").is_some() {
        std::fs::write("disasm.asm", icicle_vm::debug::dump_disasm(&vm)?.as_bytes())?;
    }
    if std::env::var_os("ICICLE_SAVE_SEMANTICS").is_some() {
        std::fs::write("disasm.pcode", icicle_vm::debug::dump_semantics(&vm)?.as_bytes())?;
    }
    if std::env::var_os("ICICLE_SAVE_TRACE").is_some() {
        let mut output = std::io::BufWriter::new(std::fs::File::create("trace.txt")?);
        for (addr, icount) in &tracer.get_last_blocks(&mut vm) {
            writeln!(output, "{addr:#x},{icount}").unwrap();
        }
    }
    if let Some((path, cmp_map)) = cmplog_trace {
        unsafe { (*cmp_map.get()).save(path.as_ref())? };
    }

    let exit_code = get_afl_exit_code(&vm, exit);
    if exit_code == 0 {
        // Consider adding an exit here for quiet mode.
    }

    eprintln!("[icicle] callstack:\n{}", icicle_vm::debug::backtrace(&mut vm));

    let block_count = match std::env::var("PRINT_LAST_BLOCKS") {
        Ok(count) => count
            .parse()
            .with_context(|| format!("invalid value for PRINT_LAST_BLOCKS: {count}"))?,
        Err(_) => 10,
    };
    eprintln!("[icicle] last blocks:\n{}", tracer.print_last_blocks(&mut vm, block_count));
    eprintln!(
        "[icicle] registers:\n{}",
        icicle_vm::debug::print_regs(&vm, &icicle_vm::debug::get_debug_regs(&vm.cpu))
    );

    let exit_reason = match exit {
        VmExit::Halt => vm.env_ref::<Kernel>().and_then(|kernel| kernel.process.termination_reason),
        VmExit::UnhandledException((code, _))
            if code.is_memory_error() && code != ExceptionCode::ReadWatch =>
        {
            Some(TerminationReason::Killed(icicle_vm::linux::sys::signal::SIGSEGV as u64))
        }
        _ => None,
    };

    drop(vm);
    drop(target);

    if std::env::var_os("EXIT_WITH_SIGNAL").is_some() {
        match exit_reason {
            Some(TerminationReason::Exit(exit)) => std::process::exit(exit as i32),
            Some(TerminationReason::Killed(sig)) => exit_with_signal(sig as libc::c_int),
            None => std::process::exit(exit_code as i32),
        }
    }

    Ok(())
}

fn read_input(config: FuzzConfig) -> anyhow::Result<Vec<u8>> {
    let input = match config.icicle_args.get(1) {
        Some(path) => std::fs::read(path).with_context(|| format!("Failed to read: {path}"))?,
        None => {
            let mut input = vec![];
            std::io::stdin().read_to_end(&mut input)?;
            input
        }
    };
    Ok(input)
}

#[inline(never)]
fn gen_cmplog_map(vm: &mut icicle_vm::Vm) -> &'static UnsafeCell<icicle_fuzzing::cmplog::CmpMap> {
    let map = Box::leak(Box::new(UnsafeCell::new(icicle_fuzzing::cmplog::CmpMap::new())));
    icicle_fuzzing::cmplog::CmpLogBuilder::new().finish(vm, &*map);
    map
}

#[cfg(unix)]
fn exit_with_signal(id: libc::c_int) -> ! {
    // Note: we call kill twice to avoid rust's builtin exception handler.
    unsafe { libc::kill(std::process::id() as libc::pid_t, id as libc::c_int) };
    unsafe { libc::kill(std::process::id() as libc::pid_t, id as libc::c_int) };
    std::process::exit(-1)
}

#[cfg(not(unix))]
fn exit_with_signal(_id: libc::c_int) -> ! {
    std::process::exit(-1)
}

fn run_afl<T: FuzzTarget>(
    mut target: T,
    mut config: FuzzConfig,
    afl: &mut afl::Comms,
) -> anyhow::Result<()> {
    let mut input_source = InputSource::new(&config);

    let mut slowest_exec = std::time::Duration::from_secs(0);
    let mut stats_logger = icicle_fuzzing::log::StatsLogger::init();

    let mut vm = target.create_vm(&mut config).context("Failed to initialize VM")?;
    vm.icount_limit = config.icount_limit;
    let mut instrumentation = instrument_vm(&mut vm, &config)?;

    let mut coverage_tracker = BlockCoverageTracker::new();

    target.initialize_vm(&config, &mut vm)?;
    let snapshot = vm.snapshot();

    if config.enable_dry_run {
        // Perform a dry-run so the first execution we report to AFL isn't really slow. Note:
        // `input` hasn't been initialized yet so use a dummy input.
        //
        // Ideally we would either make the start up time much faster, or make AFL++ aware that the
        // first run of the input will take extra time.
        static DUMMY_INPUT: [u8; 4 + 27] = [
            21, 0, 0, 0, // 32-bit length
            b'a', b'b', b'c', b'd', b'e', b'f', b'g', b'h', b'i', b'j', b'k', b'l', b'm', b'n',
            b'o', b'p', b'q', b'r', b's', b't', b'u', b'v', b'z', b'x', b'y', b'z', b'\n',
        ];
        let now = std::time::Instant::now();
        target.set_input(&mut vm, &DUMMY_INPUT[..]).context("Failed to set input for dry run")?;
        let result = target.run(&mut vm)?;
        tracing::info!("Dry run exited with: {:0x?} ({} us)", result, now.elapsed().as_micros());
    }

    afl.setup(&config)?;
    coverage_tracker.add_new(&vm.code, 0);

    // The main fuzzing loop
    let mut crashes = icicle_fuzzing::log::CrashLogger::default();
    while afl.is_alive() {
        instrumentation.clear(&mut vm);

        let input = input_source.read_next()?;
        afl.start_fuzz_case(&vm.interrupt_flag)?;

        // For performance monitoring we keep track of the slowest input that we have seen so far
        // that involve no compilation.
        let start = std::time::Instant::now();
        let compiled_blocks = vm.compiled_blocks;

        // Run the fuzz case
        let exit = match std::panic::catch_unwind::<_, anyhow::Result<_>>(
            std::panic::AssertUnwindSafe(|| {
                vm.restore(&snapshot);
                target.set_input(&mut vm, input)?;
                target.run(&mut vm)
            }),
        ) {
            Ok(run_result) => run_result?,
            Err(e) => {
                std::fs::write("internal_emulator_crash.bin", input).unwrap();
                anyhow::bail!("Internal emulator panic: {:?}", e)
            }
        };

        let elapsed = start.elapsed();
        if compiled_blocks == vm.compiled_blocks && elapsed > slowest_exec {
            slowest_exec = elapsed;
            tracing::info!("Slowest execution: {} ms", elapsed.as_secs_f64() * 1000.0);
            if config.save_slowest {
                std::fs::write("slowest_input.bin", input).unwrap()
            }
        }

        let afl_exit_kind = get_afl_exit_code(&vm, exit);
        if afl_exit_kind != 0 && crashes.check_crash(&mut vm, exit) {
            let backtrace = icicle_vm::debug::backtrace(&mut vm);
            tracing::info!("New crash ({:0x?}): \n{}", exit, backtrace);

            if config.save_crashes {
                let pc = vm.cpu.read_pc();
                std::fs::write(&format!("crash_pc_{:0x}.bin", pc), input).unwrap()
            }
        }

        if let Some(path) = config.cmplog_path.as_ref() {
            instrumentation
                .save_cmplog_map(path)
                .with_context(|| format!("failed to save cmplog map to: {}", path.display()))?;
        }

        // Send child exit response to AFL
        afl.write(afl_exit_kind).context("failed to send child exit code to AFL")?;

        if let Some(logger) = stats_logger.as_mut() {
            logger.log_exec(input.len())
        }

        coverage_tracker.add_new(&vm.code, 0);
        if let Err(e) = coverage_tracker.maybe_save("cur_coverage.txt".as_ref()) {
            tracing::error!("error saving coverage file: {e:?}");
        }

        // Check if we should recompile here, note we do this before the next iteration so that AFL
        // doesn't count the recompilation time as part of the fuzzing time.
        if vm.should_recompile() {
            vm.recompile();
        }
    }

    Ok(())
}

pub enum InputSource {
    File(std::path::PathBuf, Vec<u8>),
    SharedMemory(*mut u8),
}

impl InputSource {
    pub fn new(config: &FuzzConfig) -> Self {
        let shm_input = match config.shared_mem_inputs {
            true => unsafe { shared_mem::input().ok() },
            false => None,
        };
        if let Some(ptr) = shm_input {
            return Self::SharedMemory(ptr);
        }
        Self::File(Path::new(&config.icicle_args[1]).into(), vec![])
    }

    pub fn read_next(&mut self) -> anyhow::Result<&[u8]> {
        match self {
            Self::File(path, buf) => {
                buf.clear();
                std::fs::File::open(path)
                    .context("failed to open input file")?
                    .read_to_end(buf)
                    .context("failed to read input file")?;
                Ok(buf)
            }
            Self::SharedMemory(ptr) => {
                // Safety: it is required when creating an instance of this type that `ptr` points
                // to a valid AFL style shared memory buffer.
                Ok(unsafe { afl::input_from_ptr(*ptr) })
            }
        }
    }
}

/// Typically AFL++ sends a kill signal to the child process to stop execution in the case of a
/// timeout. However, in icicle the child process exists in the same process as the forkserver so
/// instead we create a dummy process and let AFL++ kill that in order to trigger a timeout.
pub fn spawn_killable_process(is_killed: std::sync::Arc<std::sync::atomic::AtomicBool>) -> u32 {
    use std::process::{Command, Stdio};

    let mut child = Command::new(std::env::current_exe().unwrap())
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .env("ICICLE_HANG_ME", "1")
        .spawn()
        .unwrap();

    let id = child.id();

    std::thread::spawn(move || {
        // Steal the stdin handle, to avoid it being dropped in the `wait` call (killing the child).
        // This will ensure that we will block until either the child or the forkserver is killed.
        let _stdin = child.stdin.take();
        match child.wait() {
            Ok(result) => tracing::info!("Dummy process exited with: {result:?}"),
            Err(e) => tracing::error!("Error waiting for dummy process to exit: {e:?}"),
        }
        is_killed.store(true, std::sync::atomic::Ordering::Release);

        let _ = child.kill();
        let _ = child.try_wait();
    });

    tracing::info!("Spawned kill handler process with pid={}", id);
    id
}
