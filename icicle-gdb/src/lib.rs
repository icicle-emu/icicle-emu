use std::{
    collections::{HashMap, VecDeque},
    net::{SocketAddr, TcpListener},
};

use anyhow::Context;
use gdbstub::{
    common::Signal,
    conn::{Connection, ConnectionExt},
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
pub fn listen<T>(
    addr: &str,
    target: stub::VmState<T>,
    commands: CustomCommands,
) -> anyhow::Result<()>
where
    T: stub::DynamicTarget,
{
    listen_tcp(addr.parse()?, target, commands)
}

#[cfg(unix)]
pub fn listen<T>(
    addr: &str,
    target: stub::VmState<T>,
    commands: CustomCommands,
) -> anyhow::Result<()>
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
            Ok(stream) => BufferedConnection::new(stream),
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
    use std::os::unix::fs::FileTypeExt;

    let server = match std::os::unix::net::UnixListener::bind(path) {
        Ok(server) => server,
        Err(e)
            if e.kind() == std::io::ErrorKind::AddrInUse
                && std::fs::metadata(path).map_or(false, |x| x.file_type().is_socket()) =>
        {
            std::fs::remove_file(path)
                .with_context(|| format!("Failed to remove socket file: {path}"))?;

            std::os::unix::net::UnixListener::bind(path)
                .with_context(|| format!("Failed to bind to Unix listener to: {path}"))?
        }
        Err(e) => {
            return Err(e).with_context(|| format!("Failed to bind to Unix listener to: {path}"));
        }
    };

    for stream in server.incoming() {
        let stream = match stream {
            Ok(stream) => BufferedConnection::new(stream),
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

struct BufferedConnection<S> {
    inner: S,
    rx_buffer: VecDeque<u8>,
    tx_buffer: Vec<u8>,
    buffer_size: usize,
}

impl<S> BufferedConnection<S> {
    fn new(inner: S) -> Self {
        let buffer_size = 8 * 1024;
        Self {
            inner,
            rx_buffer: VecDeque::with_capacity(buffer_size),
            tx_buffer: Vec::with_capacity(buffer_size),
            buffer_size,
        }
    }
}

impl<S: Connection<Error = std::io::Error>> Connection for BufferedConnection<S> {
    type Error = std::io::Error;

    fn write(&mut self, byte: u8) -> Result<(), Self::Error> {
        self.write_all(&[byte])
    }

    fn write_all(&mut self, buf: &[u8]) -> Result<(), Self::Error> {
        // Either just add the buf to the tx_buffer or fully write everything to the underlying
        // connection if the buffer is full.
        if self.tx_buffer.len() + buf.len() > self.buffer_size {
            self.inner.write_all(&self.tx_buffer)?;
            self.tx_buffer.clear();
            self.inner.write_all(buf)?;
        }
        else {
            self.tx_buffer.extend_from_slice(buf);
        }
        Ok(())
    }

    fn flush(&mut self) -> Result<(), Self::Error> {
        if !self.tx_buffer.is_empty() {
            self.inner.write_all(&self.tx_buffer)?;
            self.tx_buffer.clear();
        }
        self.inner.flush()
    }

    fn on_session_start(&mut self) -> Result<(), Self::Error> {
        self.inner.on_session_start()
    }
}

impl<S: ConnectionExt<Error = std::io::Error> + std::io::Read> ConnectionExt
    for BufferedConnection<S>
{
    fn read(&mut self) -> Result<u8, Self::Error> {
        if let Some(byte) = self.rx_buffer.pop_front() {
            return Ok(byte);
        }

        // @todo: use an improved buffer type to avoid needing to zeroing and coalesce the buffer.
        self.rx_buffer.resize(self.buffer_size, 0);
        let buf = self.rx_buffer.make_contiguous();

        match std::io::Read::read(&mut self.inner, buf) {
            Ok(0) => {
                self.rx_buffer.clear();
                return ConnectionExt::read(&mut self.inner);
            }
            Ok(bytes_read) => {
                tracing::trace!("Read {bytes_read} bytes from connection");
                self.rx_buffer.truncate(bytes_read);
            }
            Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                // The inner connection will handle actually waiting for data to be available.
                self.rx_buffer.clear();
                return ConnectionExt::read(&mut self.inner);
            }
            Err(e) => {
                self.rx_buffer.clear();
                return Err(e);
            }
        }

        Ok(self.rx_buffer.pop_front().unwrap())
    }

    fn peek(&mut self) -> Result<Option<u8>, Self::Error> {
        if let Some(byte) = self.rx_buffer.front() {
            return Ok(Some(*byte));
        }
        self.inner.peek()
    }
}

pub fn run<T, S>(stream: S, target: &mut stub::VmState<T>) -> anyhow::Result<()>
where
    T: stub::DynamicTarget,
    S: ConnectionExt,
    S::Error: Send + Sync + std::fmt::Debug + std::fmt::Display + 'static,
{
    let stub = GdbStub::builder(stream).packet_buffer_size(8 * 1024).build()?;
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
