use std::net::TcpListener;

use anyhow::Context;
use icicle_gdb::run;
use target_lexicon::Architecture;
use tracing::{error, info, warn};

/// Controls whether we should run the VM to the entry point of the binary before accepting the GDB
/// connection.
///
/// WARNING: If this takes to long GDB will fail to connect.
const RUN_TO_ENTRY: bool = false;

fn main() {
    let log_filter = match std::env::var("ICICLE_LOG").ok() {
        Some(filter) => dbg!(filter),
        None => "warn".to_string(),
    };
    tracing_subscriber::fmt().with_env_filter(log_filter).init();
    let args: Vec<_> = std::env::args().collect();

    let target = args.get(1).expect("Expected target triple");

    if let Err(e) = start(target, &args[2..]) {
        error!("{}", e);
    }
}

fn start(target: &str, args: &[String]) -> anyhow::Result<()> {
    let addr = std::env::var("GDB_SERVER_ADDR").unwrap_or_else(|_| "127.0.0.1:9999".into());

    let target: target_lexicon::Triple =
        target.parse().map_err(|e| anyhow::format_err!("{}: {}", target, e))?;

    let server = TcpListener::bind(&addr)
        .with_context(|| format!("Failed to bind to TCP listener to: {}", addr))?;

    info!("Started tcp server at: {}", addr);

    for stream in server.incoming() {
        let stream = match stream {
            Ok(stream) => stream,
            Err(e) => {
                warn!("Client error: {}", e);
                continue;
            }
        };

        info!("New client connection: {:?}", stream);
        let mut vm = icicle_vm::build(&icicle_vm::cpu::Config {
            triple: target.clone(),
            ..Default::default()
        })?;
        vm.env = icicle_vm::env::build_auto(&mut vm)?;

        if let Some(env) = vm.env_mut::<icicle_vm::linux::Kernel>() {
            let envs: &[(&[u8], &[u8])] = &[];
            env.process.args.set(&args[0], &args[1..], envs);
        }
        vm.env.load(&mut vm.cpu, args[0].as_bytes()).map_err(|e| anyhow::format_err!("{e}"))?;

        // Create an initial snapshot for reverse execution.
        vm.save_snapshot();

        if RUN_TO_ENTRY {
            if let Some(kernel) = vm.env.as_any().downcast_ref::<icicle_vm::linux::Kernel>() {
                let entry = kernel.process.image.entry_ptr;
                vm.add_breakpoint(entry);
                vm.run();
                vm.remove_breakpoint(entry);
            }
        }

        match target.architecture {
            Architecture::X86_64 => run(stream, &mut icicle_gdb::X64Stub::new(&mut vm))?,
            Architecture::Mips32(target_lexicon::Mips32Architecture::Mipsel) => {
                run(stream, &mut icicle_gdb::Mips32Stub::new(&mut vm))?
            }
            Architecture::Msp430 => run(stream, &mut icicle_gdb::Msp430Stub::new(&mut vm))?,
            other => anyhow::bail!("Unsupported architecture: {}", other),
        }
    }
    Ok(())
}
