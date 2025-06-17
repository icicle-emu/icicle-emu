use std::{
    collections::HashMap,
    net::{SocketAddr, TcpListener},
};

use anyhow::Context;
use gdbstub::{
    common::Signal,
    conn::ConnectionExt,
    stub::{DisconnectReason, GdbStub, SingleThreadStopReason, run_blocking},
};
use icicle_vm::Vm;
use target_lexicon::Architecture;

mod arch;
mod stub;

pub use crate::stub::ExePath;

pub type X64Stub<'a> = stub::VmState<'a, arch::IcicleX64>;
pub type Mips32Stub<'a> = stub::VmState<'a, arch::IcicleMips32>;
pub type Msp430Stub<'a> = stub::VmState<'a, arch::IcicleMsp430>;
pub type ArmStub<'a> = stub::VmState<'a, arch::IcicleArm>;

pub fn listen_auto(addr: &str, vm: &mut Vm) -> anyhow::Result<()> {
    let commands = CustomCommands::default();
    match vm.cpu.arch.triple.architecture {
        Architecture::X86_64 => listen(addr, X64Stub::new(vm), commands),
        Architecture::Mips32(_) => listen(addr, Mips32Stub::new(vm), commands),
        Architecture::Msp430 => listen(addr, Msp430Stub::new(vm), commands),
        Architecture::Arm(_) => listen(addr, ArmStub::new(vm), commands),
        other => anyhow::bail!("Unsupported architecture: {other}"),
    }
}

#[derive(Default)]
pub struct CustomCommands {
    pub commands: HashMap<String, Box<dyn FnMut(Vm, &str) -> anyhow::Result<()>>>,
}

#[cfg(not(unix))]
pub fn listen<T>(addr: &str, target: stub::VmState<T>, commands: CustomCommands) -> anyhow::Result<()>
where
    T: stub::DynamicTarget,
{
    listen_tcp(addr.parse()?, target, commands)
}

#[cfg(unix)]
pub fn listen<T>(addr: &str, target: stub::VmState<T>, commands: CustomCommands) -> anyhow::Result<()>
where
    T: stub::DynamicTarget,
{
    match addr.parse() {
        Ok(addr) => listen_tcp(addr, target, commands),
        _ => listen_unix(addr, target, commands),
    }
}

fn listen_tcp<T>(
    addr: SocketAddr,
    mut target: stub::VmState<T>,
    // TODO: add support for injecting custom monitor commands in the stub.
    _commands: CustomCommands,
) -> anyhow::Result<()>
where
    T: stub::DynamicTarget,
{
    let server = TcpListener::bind(addr)
        .with_context(|| format!("Failed to bind to TCP listener to: {addr}"))?;
    for stream in server.incoming() {
        let stream = match stream {
            Ok(stream) => stream,
            Err(e) => {
                tracing::warn!("Client error: {}", e);
                continue;
            }
        };
        if let Err(e) = run(stream, &mut target) {
            tracing::error!("Stub error: {e}");
        }
    }

    Ok(())
}

#[cfg(unix)]
fn listen_unix<T>(
    path: &str,
    mut target: stub::VmState<T>,
    _commands: CustomCommands,
) -> anyhow::Result<()>
where
    T: stub::DynamicTarget,
{
    let server = std::os::unix::net::UnixListener::bind(path)
        .with_context(|| format!("Failed to bind to Unix listener to: {path}"))?;
    for stream in server.incoming() {
        let stream = match stream {
            Ok(stream) => stream,
            Err(e) => {
                tracing::warn!("Client error: {}", e);
                continue;
            }
        };
        if let Err(e) = run(stream, &mut target) {
            tracing::error!("Stub error: {e}");
        }
    }

    Ok(())
}

pub fn run<T, S>(stream: S, target: &mut stub::VmState<T>) -> anyhow::Result<()>
where
    T: stub::DynamicTarget,
    S: ConnectionExt,
    S::Error: Send + Sync + std::fmt::Debug + std::fmt::Display + 'static,
{
    // The default packet buffer size is 4096 bytes, which is quite small we significantly increase
    // it to accommodate larger packets, especially for `vFile` operations.
    let stub = GdbStub::builder(stream).packet_buffer_size(0x4000).build()?;
    match stub.run_blocking::<GdbStubEventLoop<T, S>>(target)? {
        DisconnectReason::TargetExited(status) => {
            tracing::info!("Target exited: {}", status);
        }
        DisconnectReason::TargetTerminated(signal) => {
            tracing::info!("Target terminated: {}", signal);
        }
        DisconnectReason::Disconnect => {
            tracing::info!("Client disconnected");
        }
        DisconnectReason::Kill => {
            tracing::info!("Process killed");
        }
    }
    Ok(())
}

struct GdbStubEventLoop<'a, T, S> {
    _target: std::marker::PhantomData<fn(&'a (), T, S)>,
}

impl<'a, T, S> run_blocking::BlockingEventLoop for GdbStubEventLoop<'a, T, S>
where
    T: stub::DynamicTarget,
    S: ConnectionExt,
{
    type Target = stub::VmState<'a, T>;
    type Connection = S;
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
