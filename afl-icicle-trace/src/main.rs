use std::{
    cell::UnsafeCell,
    convert::TryInto,
    io::{Read, Write},
};

use anyhow::Context;
use icicle_fuzzing::{utils::get_afl_exit_code, FuzzConfig, FuzzTarget};
use icicle_vm::{
    cpu::ExceptionCode, get_linux_termination_reason, linux::TerminationReason, VmExit,
};

use crate::instrumentation::{instrument_vm, path_tracer};

mod afl;
mod instrumentation;
mod shared_mem;

static IS_CMPLOG: std::sync::atomic::AtomicBool = std::sync::atomic::AtomicBool::new(false);

pub fn is_cmplog_server() -> bool {
    IS_CMPLOG.load(std::sync::atomic::Ordering::Acquire)
}

fn main() {
    if std::env::var_os("ICICLE_HANG_ME").is_some() {
        let mut buf = [0; 1];
        let _ = std::io::stdin().read_exact(&mut buf);
        return;
    }

    eprintln!("[icicle] icicle started");

    let logger = tracing_subscriber::fmt()
        .with_env_filter(tracing_subscriber::EnvFilter::from_env("ICICLE_LOG"))
        .without_time();

    match std::env::var("ICICLE_LOG_ADDR").ok() {
        Some(addr) => {
            let addr = std::sync::Arc::new(addr);
            logger
                .with_writer(move || {
                    let socket = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
                    socket.connect(addr.as_ref()).unwrap();
                    std::io::BufWriter::new(icicle_vm::cpu::utils::UdpWriter::new(socket))
                })
                .init()
        }
        None => logger.with_writer(std::io::stderr).init(),
    }

    let config = FuzzConfig::load().expect("Invalid config");

    if let Some(dir) = std::env::var_os("ICICLE_RESOLVE_CRASHES") {
        if let Err(e) = resolve_crashes(config, dir.as_ref()) {
            log_error_and_exit(e);
        }
        return;
    }

    if let Some(dir) = std::env::var_os("ICICLE_BLOCK_COVERAGE") {
        if let Err(e) = collect_coverage(config, dir.as_ref()) {
            log_error_and_exit(e);
        }
        return;
    }

    if let Err(e) = icicle_fuzzing::run_auto(config, ForkserverFuzzer) {
        log_error_and_exit(e);
    }
}

fn collect_coverage(mut config: FuzzConfig, dir: &std::path::Path) -> anyhow::Result<()> {
    let (_total, entries) =
        icicle_fuzzing::trace::resolve_block_coverage(&mut config, dir.to_path_buf())?;

    let mut output = vec![];
    for entry in entries {
        let mut cov: Vec<_> = entry.new.into_iter().collect();
        cov.sort_unstable();
        output.push(serde_json::json!({
            "input": entry.tag.to_string_lossy(),
            "new_coverage": cov
        }));
    }

    write!(std::io::stdout(), "{}", serde_json::json!(output))?;
    Ok(())
}

fn resolve_crashes(mut config: FuzzConfig, dir: &std::path::Path) -> anyhow::Result<()> {
    let crashes = icicle_fuzzing::resolve_crashes(&mut config, dir)?;
    let mut output = vec![];
    for (key, metadata) in crashes {
        if metadata.exit_code == 0 {
            continue;
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
    write!(std::io::stdout(), "{}", serde_json::json!(output))?;
    Ok(())
}

struct ForkserverFuzzer;

impl icicle_fuzzing::Fuzzer for ForkserverFuzzer {
    type Output = ();

    fn run<T: FuzzTarget>(self, target: T, mut config: FuzzConfig) -> anyhow::Result<()> {
        if !shared_mem::is_afl_connected() {
            config.linux.mount_stdout = true;
            if let Err(e) = run_without_parent::<T>(target, config) {
                log_error_and_exit(e);
            }
            return Ok(());
        }
        if std::env::var_os(shared_mem::IS_CMPLOG_FORK_SERVER).is_some() {
            IS_CMPLOG.store(true, std::sync::atomic::Ordering::Release);
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
            eprintln!("[icicle]: {:?}", e);
        }
        Ok(())
    }
}

fn log_error_and_exit(error: anyhow::Error) -> ! {
    tracing::error!("{:?}", error);
    eprintln!("[icicle]: {:?}", error);
    std::process::exit(1);
}

fn run_without_parent<T: FuzzTarget>(mut target: T, mut config: FuzzConfig) -> anyhow::Result<()> {
    let (mut vm, tracer) =
        target.initialize_vm(&mut config, path_tracer).context("Failed to initialize VM")?;

    let input = match config.icicle_args.get(1) {
        Some(path) => std::fs::read(path).with_context(|| format!("Failed to read: {path}"))?,
        None => {
            let mut input = vec![];
            std::io::stdin().read_to_end(&mut input)?;
            input
        }
    };

    let max_input_size = match std::env::var("INPUT_SIZE") {
        Ok(size) => icicle_fuzzing::parse_u64_with_prefix(&size)
            .with_context(|| format!("invalid input size: {size}"))? as usize,
        _ => usize::MAX,
    };

    let truncated_input = &input[..max_input_size.min(input.len())];
    if input.len() != truncated_input.len() {
        tracing::info!(
            "input truncated to {max_input_size:#x} bytes (last byte = {:#x})",
            truncated_input.last().unwrap_or(&0)
        );
    }

    target.set_input(&mut vm, truncated_input)?;

    if let Ok(entries) = std::env::var("ICICLE_LOG_WRITES") {
        // A comma separated list of locations to instrument writes to, e.g:
        // "applet=0x1c00:2,jumptarget=0x1c02:2"
        for entry in entries.split(",") {
            match icicle_fuzzing::parse_write_hook(entry) {
                Some((name, addr, size)) => {
                    icicle_vm::debug::log_write(&mut vm, name.to_string(), addr, size);
                }
                _ => tracing::error!("Invalid write hook format: {entry}"),
            }
        }
    }

    if let Ok(entries) = std::env::var("BREAKPOINTS") {
        // A comma separated list of addresses to stop execution at.
        for entry in entries.split(",") {
            match icicle_fuzzing::parse_u64_with_prefix(entry) {
                Some(addr) => {
                    vm.add_breakpoint(addr);
                }
                _ => tracing::error!("Invalid breakpoint: {entry}"),
            }
        }
    }

    let mut cmplog_trace = None;
    if let Some(path) = std::env::var_os("ICICLE_SAVE_CMP_MAP") {
        let map = Box::leak(Box::new(UnsafeCell::new(icicle_fuzzing::cmplog::CmpMap::new())));
        icicle_fuzzing::cmplog::CmpLogBuilder::new().finish(&mut vm, &*map);
        cmplog_trace = Some((path, &*map));
    }

    let exit = vm.step(config.icount_limit);
    eprintln!("[icicle] exited with: {:?}", exit);

    if std::env::var_os("ICICLE_SAVE_DISASM").is_some() {
        std::fs::write("disasm.asm", icicle_vm::debug::dump_disasm(&vm)?.as_bytes())?;
    }
    if std::env::var_os("ICICLE_SAVE_SEMANTICS").is_some() {
        std::fs::write("disasm.pcode", icicle_vm::debug::dump_semantics(&vm)?.as_bytes())?;
    }
    if let Some((path, cmp_map)) = cmplog_trace {
        unsafe { (*cmp_map.get()).save(path.as_ref())?; };
    }

    let exit_code = get_afl_exit_code(&mut vm, exit);
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
        VmExit::Halt => get_linux_termination_reason(&mut vm),
        VmExit::UnhandledException((code, _))
            if code.is_memory_error() && code != ExceptionCode::ReadWatch =>
        {
            Some(TerminationReason::Killed(icicle_vm::linux::sys::signal::SIGSEGV as u64))
        }
        _ => None,
    };

    drop(vm);
    drop(target);

    match exit_reason {
        Some(TerminationReason::Exit(exit)) => std::process::exit(exit as i32),
        Some(TerminationReason::Killed(sig)) => exit_with_signal(sig as libc::c_int),
        None => std::process::exit(exit_code as i32),
    }
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
    let mut file_input = vec![];
    let shm_input = match config.shared_mem_inputs {
        true => unsafe { shared_mem::input().ok() },
        false => None,
    };

    let mut slowest_exec = std::time::Duration::from_secs(0);
    let mut stats_logger = icicle_fuzzing::log::StatsLogger::init();

    let (mut vm, mut instrumentation) =
        target.initialize_vm(&mut config, instrument_vm).context("Failed to initialize VM")?;

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
        let result = target
            .run_vm(&mut vm, &DUMMY_INPUT[..], config.icount_limit)
            .context("Dry run failed")?;
        tracing::info!("Dry run exited with: {:0x?} ({} us)", result, now.elapsed().as_micros());
    }

    let mut killable_process = spawn_killable_process(vm.interrupt_flag.clone());

    afl.setup(&config)?;

    // The main fuzzing loop
    let mut crashes = icicle_fuzzing::log::CrashLogger::default();
    while afl.is_alive() {
        instrumentation.clear(&mut vm);

        let input_ptr = match shm_input {
            Some(ptr) => ptr,
            None => {
                // If we are not running in shared memory mode, then the first argument should
                // contain the path to the file AFL++ will write to, this will be mapped to the
                // target specific input location in the emulator
                file_input.clear();

                // Reserve space for the length of the file
                file_input.extend(0_u32.to_le_bytes());

                // Read file and upstaed length.
                std::fs::File::open(&config.icicle_args[1])
                    .context("failed to open input file")?
                    .read_to_end(&mut file_input)
                    .context("failed to read input file")?;
                let len: u32 = (file_input.len() - 4).try_into().expect("Input was too large");
                file_input[0..4].copy_from_slice(&len.to_le_bytes());

                file_input.as_mut_ptr()
            }
        };
        // @fixme: `ptr` potentially has a non-static lifetime
        let input = unsafe { afl::input_from_ptr(input_ptr) };

        if vm.interrupt_flag.swap(false, std::sync::atomic::Ordering::AcqRel) {
            tracing::info!("Killed by AFL++ due to timeout");
            killable_process = spawn_killable_process(vm.interrupt_flag.clone());
        }

        // For performance monitoring we keep track of the slowest input that we have seen so far
        // that involve no compilation.
        let start = std::time::Instant::now();
        let compiled_blocks = vm.compiled_blocks;

        // Run the fuzz case
        afl.write(killable_process).context("failed to send fuzzer PID to AFL")?;
        let exit = match std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            vm.restore(&snapshot);
            target.run_vm(&mut vm, input, config.icount_limit)
        })) {
            Ok(run_result) => run_result?,
            Err(e) => {
                std::fs::write(&"internal_emulator_crash.bin", input).unwrap();
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

        let afl_exit_kind = get_afl_exit_code(&mut vm, exit);
        if afl_exit_kind != 0 {
            if crashes.check_crash(&mut vm, exit) {
                let backtrace = icicle_vm::debug::backtrace(&mut vm);
                tracing::info!("New crash ({:0x?}): \n{}", exit, backtrace);

                if config.save_crashes {
                    let pc = vm.cpu.read_pc();
                    std::fs::write(&format!("crash_pc_{:0x}.bin", pc), input).unwrap()
                }
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

        // Check if we should recompile here, note we do this before the next iteration so that AFL
        // doesn't count the recompilation time as part of the fuzzing time.
        if vm.should_recompile() {
            vm.recompile();
        }
    }

    return Ok(());
}

struct ChildWrapper(std::process::Child);

impl Drop for ChildWrapper {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

/// Typically AFL++ sends a kill signal to the child process to stop execution in the case of a
/// timeout. However, in icicle the child process exists in the same process as the forkserver so
/// instead we create a dummy process and let AFL++ kill that in order to trigger a timeout.
fn spawn_killable_process(is_killed: std::sync::Arc<std::sync::atomic::AtomicBool>) -> u32 {
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
        let mut handle = ChildWrapper(child);
        let result = handle.0.wait().unwrap();
        tracing::info!("Dummy process exited with: {:?}", result);
        is_killed.store(true, std::sync::atomic::Ordering::Release);
    });

    tracing::info!("Spawned kill handler process with pid={}", id);
    id
}
