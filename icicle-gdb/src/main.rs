use std::net::TcpListener;

use anyhow::Context;
use gdbstub::{
    common::Signal,
    conn::ConnectionExt,
    stub::{run_blocking, DisconnectReason, GdbStub, SingleThreadStopReason},
};
use target_lexicon::Architecture;
use tracing::{error, info, warn};

mod stub;

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
    tracing_subscriber::fmt().with_env_filter(&log_filter).init();

    let handle = std::thread::Builder::new()
        .stack_size(1024 * 1024 * 1024)
        .name("VmThread".into())
        .spawn(move || {
            let args: Vec<_> = std::env::args().collect();

            let target = args.get(1).expect("Expected target triple");

            if let Err(e) = start(target, &args[2..]) {
                error!("{}", e);
            }
        })
        .unwrap();
    handle.join().unwrap();
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

        if let Some(env) = vm.env.as_any().downcast_mut::<icicle_vm::linux::Kernel>() {
            let envs: &[(&[u8], &[u8])] = &[];
            env.process.args.set(&args[0], &args[1..], envs);
        }
        vm.env.load(&mut vm.cpu, args[0].as_bytes()).map_err(|e| anyhow::format_err!("{e}"))?;

        if RUN_TO_ENTRY {
            if let Some(kernel) = vm.env.as_any().downcast_ref::<icicle_vm::linux::Kernel>() {
                let entry = kernel.process.image.entry_ptr;
                vm.add_breakpoint(entry);
                vm.run();
                vm.remove_breakpoint(entry);
            }
        }

        match target.architecture {
            Architecture::X86_64 => run(stream, stub::VmState::<stub::IcicleX64>::new(vm))?,
            Architecture::Mips32(target_lexicon::Mips32Architecture::Mipsel) => {
                run(stream, stub::VmState::<stub::IcicleMips32>::new(vm))?
            }
            Architecture::Msp430 => run(stream, stub::VmState::<stub::IcicleMsp430>::new(vm))?,
            other => anyhow::bail!("Unsupported architecture: {}", other),
        }
    }
    Ok(())
}

fn run<T>(stream: std::net::TcpStream, mut target: stub::VmState<T>) -> anyhow::Result<()>
where
    T: stub::DynamicTarget,
{
    match GdbStub::new(stream).run_blocking::<GdbStubEventLoop<T>>(&mut target)? {
        DisconnectReason::TargetExited(status) => {
            info!("Target exited: {}", status);
        }
        DisconnectReason::TargetTerminated(signal) => {
            info!("Target terminated: {}", signal);
        }
        DisconnectReason::Disconnect => {
            info!("Client disconnected");
        }
        DisconnectReason::Kill => {
            info!("Process killed");
        }
    }
    Ok(())
}

struct GdbStubEventLoop<T> {
    _target: std::marker::PhantomData<T>,
}

impl<T> run_blocking::BlockingEventLoop for GdbStubEventLoop<T>
where
    T: stub::DynamicTarget,
{
    type Target = stub::VmState<T>;
    type Connection = std::net::TcpStream;
    type StopReason =
        gdbstub::stub::SingleThreadStopReason<<T::Arch as gdbstub::arch::Arch>::Usize>;

    fn wait_for_stop_reason(
        target: &mut Self::Target,
        conn: &mut Self::Connection,
    ) -> Result<
        run_blocking::Event<Self::StopReason>,
        run_blocking::WaitForStopReasonError<
            <Self::Target as gdbstub::target::Target>::Error,
            <Self::Connection as gdbstub::conn::Connection>::Error,
        >,
    > {
        if conn.peek().map(|b| b.is_some()).unwrap_or(true) {
            let byte = conn.read().map_err(run_blocking::WaitForStopReasonError::Connection)?;
            return Ok(run_blocking::Event::IncomingData(byte));
        }

        let exit = target.run();
        Ok(run_blocking::Event::TargetStopped(exit))
    }

    fn on_interrupt(
        _target: &mut Self::Target,
    ) -> Result<Option<Self::StopReason>, <Self::Target as gdbstub::target::Target>::Error> {
        Ok(Some(SingleThreadStopReason::Signal(Signal::SIGINT)))
    }
}
