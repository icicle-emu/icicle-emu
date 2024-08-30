use std::{collections::HashMap, net::TcpListener};

use anyhow::Context;
use gdbstub::{
    common::Signal,
    conn::ConnectionExt,
    stub::{run_blocking, DisconnectReason, GdbStub, SingleThreadStopReason},
};
use icicle_vm::Vm;
use target_lexicon::Architecture;

mod arch;
mod stub;

pub type X64Stub = stub::VmState<arch::IcicleX64>;
pub type Mips32Stub = stub::VmState<arch::IcicleMips32>;
pub type Msp430Stub = stub::VmState<arch::IcicleMsp430>;
pub type ArmStub = stub::VmState<arch::IcicleArm>;

pub fn listen_auto(addr: &str, vm: Vm) -> anyhow::Result<()> {
    let commands = CustomCommands::default();
    match vm.cpu.arch.triple.architecture {
        Architecture::X86_64 => listen(addr, X64Stub::new(vm), commands),
        Architecture::Mips32(target_lexicon::Mips32Architecture::Mipsel) => {
            listen(addr, Mips32Stub::new(vm), commands)
        }
        Architecture::Msp430 => listen(addr, Msp430Stub::new(vm), commands),
        Architecture::Arm(_) => listen(addr, ArmStub::new(vm), commands),
        other => anyhow::bail!("Unsupported architecture: {other}"),
    }
}

#[derive(Default)]
pub struct CustomCommands {
    pub commands: HashMap<String, Box<dyn FnMut(Vm, &str) -> anyhow::Result<()>>>,
}

fn listen<T>(
    addr: &str,
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
        run(stream, &mut target)?
    }

    Ok(())
}

pub fn run<T>(stream: std::net::TcpStream, target: &mut stub::VmState<T>) -> anyhow::Result<()>
where
    T: stub::DynamicTarget,
{
    match GdbStub::new(stream).run_blocking::<GdbStubEventLoop<T>>(target)? {
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
