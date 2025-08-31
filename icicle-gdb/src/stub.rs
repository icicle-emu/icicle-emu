use std::{
    collections::HashMap,
    io::Read,
    path::PathBuf,
    sync::{Arc, atomic::AtomicBool},
};

use gdbstub::{
    arch::Arch,
    common::Signal,
    stub::SingleThreadStopReason,
    target::{
        TargetError, TargetResult,
        ext::{
            self,
            base::{
                reverse_exec::{ReverseStep, ReverseStepOps},
                singlethread::{
                    SingleThreadBase, SingleThreadResume, SingleThreadResumeOps,
                    SingleThreadSingleStep,
                },
            },
            breakpoints::WatchKind,
            catch_syscalls::CatchSyscallPosition,
        },
    },
};
use icicle_vm::{
    Vm, VmExit,
    cpu::{Cpu, Exception, ExceptionCode, mem::perm},
    injector::PathTracerRef,
    linux::TerminationReason,
};
use tracing::warn;

pub trait DynamicTarget {
    type Arch: Arch;
    fn new(cpu: &Cpu) -> Self;
    fn read_registers(&self, cpu: &Cpu, regs: &mut <Self::Arch as Arch>::Registers);
    fn write_registers(&self, cpu: &mut Cpu, regs: &<Self::Arch as Arch>::Registers);
}

enum ExecMode {
    Continue,
    Step,
    ReverseStep,
}

struct Snapshot {
    trace: Option<Vec<(u64, u64)>>,
    vm: icicle_vm::Snapshot,
}

struct WatchPoint {
    start: u64,
    len: u64,
    kind: WatchKind,
    id: u32,
}

enum FileSource {
    Native(std::fs::File),
}

#[derive(Debug, Clone)]
pub enum ExePath {
    Remote(PathBuf),
    Local(PathBuf),
    Unknown,
}

pub struct VmState<'a, T: DynamicTarget> {
    tracer: Option<PathTracerRef>,
    snapshots: HashMap<Option<String>, Snapshot>,
    vm: &'a mut Vm,
    target: T,
    exec_mode: ExecMode,
    exe_path: ExePath,
    // A hack to allow the GDB client to run in WSL while the VM runs in Windows.
    wsl_remap: bool,
    watchpoints: Vec<WatchPoint>,
    single_stepping: Arc<AtomicBool>,
    open_files: HashMap<u32, FileSource>,
    next_fd: u32,
}

impl<'a, T: DynamicTarget> VmState<'a, T> {
    pub fn new(vm: &'a mut Vm) -> Self {
        let target = T::new(&vm.cpu);
        // Create an initial snapshot for reverse execution.
        vm.save_snapshot();

        let wsl_remap =
            std::env::var("ICICLE_GDB_WSL_REMAP").map_or(false, |v| v == "1" || v == "true");

        Self {
            tracer: None,
            snapshots: HashMap::new(),
            vm,
            target,
            exec_mode: ExecMode::Continue,
            watchpoints: vec![],
            exe_path: ExePath::Unknown,
            wsl_remap,
            single_stepping: Arc::new(AtomicBool::new(false)),
            open_files: HashMap::new(),
            next_fd: 0,
        }
    }

    pub fn set_exe_path(&mut self, path: ExePath) {
        self.exe_path = path;
    }

    pub fn run(&mut self) -> SingleThreadStopReason<<T::Arch as Arch>::Usize> {
        let exit = match self.exec_mode {
            ExecMode::Continue => self.vm.run(),
            ExecMode::Step => {
                self.single_stepping.store(true, std::sync::atomic::Ordering::Release);
                let result = self.vm.step(1);
                self.single_stepping.store(false, std::sync::atomic::Ordering::Release);
                result
            }
            ExecMode::ReverseStep => {
                self.single_stepping.store(true, std::sync::atomic::Ordering::Release);
                let result = self.vm.step_back(1);
                self.single_stepping.store(false, std::sync::atomic::Ordering::Release);

                match result {
                    Some(exit) => exit,
                    None => {
                        return SingleThreadStopReason::ReplayLog {
                            tid: None,
                            pos: ext::base::reverse_exec::ReplayLogPosition::Begin,
                        };
                    }
                }
            }
        };
        tracing::debug!("VmExit: {exit:?} at pc={:#x}", self.vm.cpu.read_pc());
        self.single_stepping.store(true, std::sync::atomic::Ordering::Release);
        let result = translate_stop_reason(self.vm, exit);
        self.single_stepping.store(false, std::sync::atomic::Ordering::Release);
        result
    }
}

impl<T: DynamicTarget> gdbstub::target::Target for VmState<'_, T> {
    type Arch = <T as DynamicTarget>::Arch;
    type Error = anyhow::Error;

    fn base_ops(&mut self) -> ext::base::BaseOps<'_, Self::Arch, Self::Error> {
        ext::base::BaseOps::SingleThread(self)
    }

    fn support_breakpoints(&mut self) -> Option<ext::breakpoints::BreakpointsOps<'_, Self>> {
        Some(self)
    }

    fn support_monitor_cmd(&mut self) -> Option<ext::monitor_cmd::MonitorCmdOps<'_, Self>> {
        Some(self)
    }

    fn support_section_offsets(
        &mut self,
    ) -> Option<ext::section_offsets::SectionOffsetsOps<'_, Self>> {
        match self.vm.env.as_any().is::<icicle_vm::linux::Kernel>() {
            true => Some(self),
            false => None,
        }
    }

    fn support_catch_syscalls(
        &mut self,
    ) -> Option<ext::catch_syscalls::CatchSyscallsOps<'_, Self>> {
        match self.vm.env.as_any().is::<icicle_vm::linux::Kernel>() {
            true => Some(self),
            false => None,
        }
    }

    fn support_exec_file(&mut self) -> Option<ext::exec_file::ExecFileOps<'_, Self>> {
        match &self.exe_path {
            ExePath::Unknown => None,
            _ => Some(self),
        }
    }

    fn support_host_io(&mut self) -> Option<ext::host_io::HostIoOps<'_, Self>> {
        Some(self)
    }
}

impl<T: DynamicTarget> SingleThreadBase for VmState<'_, T> {
    fn read_registers(
        &mut self,
        regs: &mut <Self::Arch as Arch>::Registers,
    ) -> TargetResult<(), Self> {
        self.target.read_registers(&self.vm.cpu, regs);
        Ok(())
    }

    fn write_registers(
        &mut self,
        regs: &<Self::Arch as Arch>::Registers,
    ) -> TargetResult<(), Self> {
        self.target.write_registers(&mut self.vm.cpu, regs);
        Ok(())
    }

    fn read_addrs(
        &mut self,
        start_addr: <Self::Arch as Arch>::Usize,
        data: &mut [u8],
    ) -> TargetResult<usize, Self> {
        let start: u64 = num_traits::cast(start_addr).unwrap();
        if !self.vm.cpu.mem.is_regular_region(start, data.len() as u64) {
            return Err(TargetError::NonFatal);
        }
        self.vm.cpu.mem.read_bytes(start, data, perm::NONE).map_err(|_| TargetError::NonFatal)?;
        Ok(data.len())
    }

    fn write_addrs(
        &mut self,
        start_addr: <Self::Arch as Arch>::Usize,
        data: &[u8],
    ) -> TargetResult<(), Self> {
        let start: u64 = num_traits::cast(start_addr).unwrap();
        if !self.vm.cpu.mem.is_regular_region(start, data.len() as u64) {
            return Err(TargetError::NonFatal);
        }
        self.vm.cpu.mem.write_bytes(start, data, perm::NONE).map_err(|_| TargetError::NonFatal)
    }

    fn support_resume(&mut self) -> Option<SingleThreadResumeOps<'_, Self>> {
        Some(self)
    }
}

impl<T: DynamicTarget> SingleThreadResume for VmState<'_, T> {
    fn support_single_step(
        &mut self,
    ) -> Option<ext::base::singlethread::SingleThreadSingleStepOps<'_, Self>> {
        if matches!(self.vm.cpu.arch.triple.architecture, target_lexicon::Architecture::Riscv64(_))
        {
            return None;
        }
        Some(self)
    }

    fn support_reverse_step(&mut self) -> Option<ReverseStepOps<'_, (), Self>> {
        Some(self)
    }

    fn resume(&mut self, signal: Option<gdbstub::common::Signal>) -> Result<(), Self::Error> {
        if let Some(signal) = signal {
            // @todo
            let _signal = signal;
        }
        self.exec_mode = ExecMode::Continue;
        Ok(())
    }
}

impl<T: DynamicTarget> SingleThreadSingleStep for VmState<'_, T> {
    fn step(&mut self, signal: Option<Signal>) -> Result<(), Self::Error> {
        if let Some(signal) = signal {
            // @todo
            let _signal = signal;
        }
        self.exec_mode = ExecMode::Step;
        Ok(())
    }
}

impl<T: DynamicTarget> ReverseStep<()> for VmState<'_, T> {
    fn reverse_step(&mut self, _tid: ()) -> Result<(), Self::Error> {
        self.exec_mode = ExecMode::ReverseStep;
        Ok(())
    }
}

impl<T: DynamicTarget> ext::breakpoints::Breakpoints for VmState<'_, T> {
    fn support_sw_breakpoint(&mut self) -> Option<ext::breakpoints::SwBreakpointOps<'_, Self>> {
        Some(self)
    }

    fn support_hw_watchpoint(&mut self) -> Option<ext::breakpoints::HwWatchpointOps<'_, Self>> {
        Some(self)
    }
}

impl<T: DynamicTarget> ext::breakpoints::SwBreakpoint for VmState<'_, T> {
    fn add_sw_breakpoint(
        &mut self,
        addr: <Self::Arch as Arch>::Usize,
        _kind: <Self::Arch as Arch>::BreakpointKind,
    ) -> TargetResult<bool, Self> {
        let addr: u64 = num_traits::cast(addr).unwrap();
        self.vm.add_breakpoint(addr);
        Ok(true)
    }

    fn remove_sw_breakpoint(
        &mut self,
        addr: <Self::Arch as Arch>::Usize,
        _kind: <Self::Arch as Arch>::BreakpointKind,
    ) -> TargetResult<bool, Self> {
        let addr: u64 = num_traits::cast(addr).unwrap();
        Ok(self.vm.remove_breakpoint(addr))
    }
}

impl<T: DynamicTarget> ext::breakpoints::HwWatchpoint for VmState<'_, T> {
    fn add_hw_watchpoint(
        &mut self,
        addr: <Self::Arch as Arch>::Usize,
        len: <Self::Arch as Arch>::Usize,
        kind: ext::breakpoints::WatchKind,
    ) -> TargetResult<bool, Self> {
        if !matches!(
            kind,
            ext::breakpoints::WatchKind::Write | ext::breakpoints::WatchKind::ReadWrite
        ) {
            return Err(TargetError::NonFatal);
        }

        let start: u64 = num_traits::cast(addr).unwrap();
        let len: u64 = num_traits::cast(len).unwrap();
        if self.watchpoints.iter().any(|x| x.start == start && x.len == len && x.kind == kind) {
            return Ok(false);
        }

        tracing::trace!("setting watchpoint at: addr={start:#x}, len={len:#x}");
        let cpu_ptr = self.vm.cpu.as_mut() as *mut Cpu;
        let single_stepping = self.single_stepping.clone();
        let id = self
            .vm
            .cpu
            .mem
            .add_write_hook(
                start,
                start + len,
                Box::new(move |_mem: &mut icicle_vm::cpu::Mmu, _addr: u64, _value: &[u8]| {
                    if single_stepping.load(std::sync::atomic::Ordering::Acquire) {
                        return;
                    }

                    // FIXME: rework memory subsystem to pass the CPU struct to the hook instead of
                    // requiring us to smuggle the pointer in here.
                    let cpu = unsafe { &mut *cpu_ptr };
                    cpu.exception = Exception::new(ExceptionCode::WriteWatch, start);
                }),
            )
            .ok_or_else(|| TargetError::NonFatal)?;
        self.watchpoints.push(WatchPoint { start, len, kind, id });

        Ok(true)
    }

    fn remove_hw_watchpoint(
        &mut self,
        addr: <Self::Arch as Arch>::Usize,
        len: <Self::Arch as Arch>::Usize,
        kind: ext::breakpoints::WatchKind,
    ) -> TargetResult<bool, Self> {
        if !matches!(
            kind,
            ext::breakpoints::WatchKind::Write | ext::breakpoints::WatchKind::ReadWrite
        ) {
            return Err(TargetError::NonFatal);
        }
        let start: u64 = num_traits::cast(addr).unwrap();
        let len: u64 = num_traits::cast(len).unwrap();
        tracing::trace!("removing watchpoint at: addr={start:#x}, len={len:#x}");
        let Some(pos) = self
            .watchpoints
            .iter()
            .position(|x| x.start == start && x.len == len && x.kind == kind)
        else {
            return Ok(false);
        };
        let entry = self.watchpoints.remove(pos);

        Ok(self.vm.cpu.mem.remove_write_hook(entry.id))
    }
}

impl<T: DynamicTarget> ext::monitor_cmd::MonitorCmd for VmState<'_, T> {
    fn handle_monitor_cmd(
        &mut self,
        cmd: &[u8],
        mut out: ext::monitor_cmd::ConsoleOutput<'_>,
    ) -> Result<(), Self::Error> {
        let msg = match std::str::from_utf8(cmd) {
            Ok(msg) => msg,
            Err(e) => {
                warn!("monitor command: {}", e);
                return Ok(());
            }
        };

        let mut parts = msg.split_whitespace();
        match parts.next() {
            Some("attach-tracer") => {
                if self.tracer.is_some() {
                    gdbstub::outputln!(out, "path tracer already attached");
                    return Ok(());
                }
                match icicle_vm::injector::add_path_tracer(self.vm) {
                    Ok(tracer) => {
                        self.tracer = Some(tracer);
                        gdbstub::outputln!(out, "path tracer attached");
                    }
                    Err(e) => {
                        gdbstub::outputln!(out, "Error attaching path tracer: {e:?}")
                    }
                }
            }
            Some("pcode") => {
                let pcode = icicle_vm::debug::current_disasm(self.vm);
                gdbstub::outputln!(out, "{}", pcode);
            }
            Some("save-trace") => {
                let path = parts.next().unwrap_or("trace.txt");
                let tracer = match self.tracer {
                    Some(tracer) => tracer,
                    None => {
                        gdbstub::outputln!(out, "path tracer not attached");
                        return Ok(());
                    }
                };
                if let Err(e) = tracer.save_trace(self.vm, path.as_ref()) {
                    gdbstub::outputln!(out, "failed to save trace to {path}: {e:?}");
                    return Ok(());
                }
                gdbstub::outputln!(out, "trace saved to {path}");
            }
            Some("lookup-varnode") => {
                if let Some(name) = parts.next() {
                    match self.vm.cpu.arch.sleigh.get_varnode(name) {
                        Some(var) => gdbstub::outputln!(out, "{:?}", var),
                        None => gdbstub::outputln!(out, "unknown register"),
                    }
                }
                else {
                    warn!("Expected register name");
                    return Ok(());
                }
            }

            Some("varnode") => {
                if let Some(name) = parts.next() {
                    match self.vm.cpu.arch.sleigh.get_varnode(name) {
                        Some(var) => {
                            let value = self.vm.cpu.read_reg(var);
                            gdbstub::outputln!(out, "{name} = {value:#x}")
                        }
                        None => gdbstub::outputln!(out, "unknown register"),
                    }
                }
                else {
                    warn!("Expected register name");
                    return Ok(());
                }
            }
            Some("snapshot") => {
                self.vm.save_snapshot();
                let snapshot = Snapshot {
                    trace: self.tracer.map(|tracer| tracer.get_last_blocks(self.vm)),
                    vm: self.vm.snapshot(),
                };
                self.snapshots.insert(None, snapshot);
                gdbstub::outputln!(out, "created snapshot");
            }
            Some("restore") => match self.snapshots.get(&None) {
                Some(snapshot) => {
                    self.vm.restore(&snapshot.vm);
                    if let Some(trace) = snapshot.trace.as_ref() {
                        self.tracer.unwrap().restore(self.vm, trace);
                        gdbstub::outputln!(out, "state restored from snapshot");
                    }
                }
                None => gdbstub::outputln!(out, "snapshot does not exist"),
            },
            Some("back") => {
                let _ = self.vm.step_back(1);
            }
            Some("step") => {
                let Some(inner) = parts.next()
                else {
                    warn!("Expected count");
                    return Ok(());
                };

                let count = inner.parse().map_err(|e| anyhow::format_err!("{}", e))?;
                let _ = self.vm.step(count);
            }
            Some("goto") => {
                let Some(inner) = parts.next()
                else {
                    warn!("Expected icount");
                    return Ok(());
                };

                let icount = inner.parse().map_err(|e| anyhow::format_err!("{}", e))?;
                let _ = self.vm.goto_icount(icount);
                gdbstub::outputln!(
                    out,
                    "reached icount={}, pc={:#x}",
                    self.vm.cpu.icount(),
                    self.vm.cpu.read_pc()
                );
            }
            Some("backtrace" | "bt") => {
                let backtrace = icicle_vm::debug::backtrace(self.vm);
                out.write_raw(backtrace.as_bytes());
            }
            Some("icount") => {
                gdbstub::outputln!(out, "icount = {}", self.vm.cpu.icount());
            }
            Some("memory-map") => {
                gdbstub::outputln!(out, "{:#x?}", self.vm.cpu.mem.get_mapping());
            }
            Some("ensure-exec") => {
                let (Some(addr), Some(len)) = (parts.next(), parts.next())
                else {
                    warn!("Expected address and length ");
                    return Ok(());
                };

                let addr = icicle_vm::cpu::utils::parse_u64_with_prefix(addr)
                    .ok_or_else(|| anyhow::format_err!("invalid address: {addr}"))?;
                let len = icicle_vm::cpu::utils::parse_u64_with_prefix(len)
                    .ok_or_else(|| anyhow::format_err!("invalid length: {len}"))?;

                let is_exec = self.vm.cpu.mem.ensure_executable(addr, len);
                gdbstub::outputln!(
                    out,
                    "{addr:#x}:{len} is {}",
                    if is_exec { "exec" } else { "not exec" }
                );
            }
            _ => {
                let msg = std::str::from_utf8(cmd).unwrap_or("<not utf8-encoded>");
                warn!("unimplemented monitor command: {}", msg)
            }
        }

        Ok(())
    }
}

impl<T: DynamicTarget> ext::section_offsets::SectionOffsets for VmState<'_, T> {
    fn get_section_offsets(
        &mut self,
    ) -> Result<ext::section_offsets::Offsets<<Self::Arch as Arch>::Usize>, Self::Error> {
        let offset = match self.vm.env.as_any().downcast_ref::<icicle_vm::linux::Kernel>() {
            Some(k) => k.process.image.relocation_offset,
            None => 0,
        };
        let text = num_traits::cast(offset).unwrap();
        Ok(ext::section_offsets::Offsets::Sections { text, data: text, bss: None })
    }
}

impl<T: DynamicTarget> ext::catch_syscalls::CatchSyscalls for VmState<'_, T> {
    fn enable_catch_syscalls(
        &mut self,
        filter: Option<ext::catch_syscalls::SyscallNumbers<<Self::Arch as Arch>::Usize>>,
    ) -> TargetResult<(), Self> {
        let kernel = self.vm.env_mut::<icicle_vm::linux::Kernel>().unwrap();
        kernel.syscall_breakpoints.clear();
        match filter {
            Some(filter) => {
                kernel.catch_syscalls = icicle_vm::linux::CatchSyscalls::Filtered;
                for entry in filter {
                    let id: u64 = num_traits::cast(entry).unwrap();
                    kernel.syscall_breakpoints.insert(id);
                }
            }
            None => {
                kernel.catch_syscalls = icicle_vm::linux::CatchSyscalls::All;
            }
        }

        Ok(())
    }

    fn disable_catch_syscalls(&mut self) -> TargetResult<(), Self> {
        let kernel = self.vm.env_mut::<icicle_vm::linux::Kernel>().unwrap();
        kernel.syscall_breakpoints.clear();
        kernel.catch_syscalls = icicle_vm::linux::CatchSyscalls::None;
        Ok(())
    }
}

impl<T: DynamicTarget> ext::exec_file::ExecFile for VmState<'_, T> {
    fn get_exec_file(
        &self,
        _pid: Option<gdbstub::common::Pid>,
        offset: u64,
        length: usize,
        buf: &mut [u8],
    ) -> TargetResult<usize, Self> {
        let path = match &self.exe_path {
            ExePath::Remote(path) => {
                format!("remote:{}", path.to_str().ok_or(TargetError::NonFatal)?)
            }
            ExePath::Local(path) => {
                let mut path = std::path::absolute(path).unwrap_or_else(|_| path.clone());
                if self.wsl_remap {
                    path = remap_windows_path_to_wsl(path);
                    tracing::debug!("remapped path: {path:?}");
                }
                path.to_str().ok_or(TargetError::NonFatal)?.to_string()
            }
            ExePath::Unknown => return Err(TargetError::NonFatal),
        };

        let bytes = path.as_bytes();
        let len = length.min(bytes.len().saturating_sub(offset as usize)).min(buf.len());
        if len == 0 {
            return Ok(0);
        }
        buf[..len].copy_from_slice(&bytes[offset as usize..offset as usize + len]);

        Ok(len)
    }
}

fn remap_windows_path_to_wsl(path: PathBuf) -> PathBuf {
    #[cfg(target_os = "windows")]
    {
        remap_windows_path_to_wsl_impl(&path).unwrap_or(path)
    }

    #[cfg(not(target_os = "windows"))]
    {
        // On non-Windows platforms, return the path as is.
        path
    }
}

/// Remaps Windows paths to WSL paths.
#[cfg(target_os = "windows")]
fn remap_windows_path_to_wsl_impl(path: &std::path::Path) -> Option<PathBuf> {
    let mut iter = path.components();
    let Some(std::path::Component::Prefix(prefix)) = iter.next()
    else {
        tracing::debug!("failed to get prefix from path: {path:?}");
        return None;
    };

    let disk = match prefix.kind() {
        std::path::Prefix::VerbatimDisk(disk) => Some(disk),
        std::path::Prefix::Disk(disk) => Some(disk),
        std::path::Prefix::Verbatim(_) => None,
        _ => return None,
    };

    let push_drive = |wsl_path: &mut String| {
        if let Some(disk) = disk {
            wsl_path.push_str("/mnt/");
            wsl_path.push(disk.to_ascii_lowercase() as char);
        }
    };

    let mut wsl_path = String::new();
    push_drive(&mut wsl_path);

    for component in iter {
        match component {
            std::path::Component::Normal(part) => {
                wsl_path.push('/');
                wsl_path.push_str(part.to_str()?);
            }
            std::path::Component::RootDir => {
                wsl_path.clear();
                push_drive(&mut wsl_path);
            }
            std::path::Component::CurDir => continue,
            std::path::Component::ParentDir => {
                if let Some(last_slash) = wsl_path.rfind('/') {
                    wsl_path.truncate(last_slash);
                }
            }
            _ => return None,
        }
    }

    Some(PathBuf::from(wsl_path))
}

pub fn translate_stop_reason<U>(vm: &mut Vm, exit: VmExit) -> SingleThreadStopReason<U>
where
    U: num_traits::Unsigned + num_traits::NumCast,
{
    match exit {
        VmExit::Running | VmExit::InstructionLimit => SingleThreadStopReason::DoneStep,
        VmExit::Halt => {
            // @fixme get last status code
            match vm
                .env_ref::<icicle_vm::linux::Kernel>()
                .and_then(|k| k.process.termination_reason)
            {
                Some(TerminationReason::Exit(exit)) => SingleThreadStopReason::Exited(exit as u8),
                Some(TerminationReason::Killed(sig)) => {
                    let signal = match sig as u8 {
                        icicle_vm::linux::sys::signal::SIGKILL => Signal::SIGKILL,
                        icicle_vm::linux::sys::signal::SIGSEGV => Signal::SIGSEGV,
                        icicle_vm::linux::sys::signal::SIGALRM => Signal::SIGALRM,
                        icicle_vm::linux::sys::signal::SIGCHLD => Signal::SIGCHLD,
                        _ => Signal::UNKNOWN,
                    };
                    SingleThreadStopReason::Terminated(signal)
                }
                None => SingleThreadStopReason::Exited(0),
            }
        }
        VmExit::Breakpoint => SingleThreadStopReason::SwBreak(()),
        VmExit::UnhandledException((ExceptionCode::Environment, code)) => {
            if code == EnvironmentCode::SyscallEntry as u64 {
                // @fixme get syscall number
                let id = 0_u64;
                let number = num_traits::cast(id).unwrap();
                SingleThreadStopReason::CatchSyscall {
                    tid: None,
                    number,
                    position: CatchSyscallPosition::Entry,
                }
            }
            else if code == EnvironmentCode::SyscallExit as u64 {
                // @fixme get syscall number
                let id = 0_u64;
                let number = num_traits::cast(id).unwrap();
                SingleThreadStopReason::CatchSyscall {
                    tid: None,
                    number,
                    position: CatchSyscallPosition::Return,
                }
            }
            else {
                SingleThreadStopReason::SwBreak(())
            }
        }
        VmExit::UnhandledException((ExceptionCode::ReadWatch, addr)) => {
            let addr = num_traits::cast(addr).unwrap();
            vm.step_back(1);
            SingleThreadStopReason::Watch { tid: (), kind: ext::breakpoints::WatchKind::Read, addr }
        }
        VmExit::UnhandledException((ExceptionCode::WriteWatch, addr)) => {
            let addr = num_traits::cast(addr).unwrap();
            vm.step_back(1);
            SingleThreadStopReason::Watch {
                tid: (),
                kind: ext::breakpoints::WatchKind::Write,
                addr,
            }
        }
        VmExit::UnhandledException((code, addr)) if code.is_memory_error() => {
            warn!("Unhandled exception: {code:?}, addr={addr:#0x}");
            SingleThreadStopReason::Signal(Signal::SIGSEGV)
        }
        VmExit::UnhandledException((code, addr)) => {
            warn!("Unhandled exception: ({code:?}, {addr:#0x})");
            SingleThreadStopReason::Signal(Signal::SIGILL)
        }
        other => {
            warn!("Unknown error: {:?}", other);
            SingleThreadStopReason::Signal(Signal::SIGILL)
        }
    }
}

// @fixme: these are not actually generated by the VM.
#[repr(u64)]
pub enum EnvironmentCode {
    SyscallEntry,
    SyscallExit,
}

impl<T: DynamicTarget> ext::host_io::HostIo for VmState<'_, T> {
    fn support_open(&mut self) -> Option<ext::host_io::HostIoOpenOps<'_, Self>> {
        Some(self)
    }

    fn support_close(&mut self) -> Option<ext::host_io::HostIoCloseOps<'_, Self>> {
        Some(self)
    }

    fn support_pread(&mut self) -> Option<ext::host_io::HostIoPreadOps<'_, Self>> {
        Some(self)
    }

    fn support_pwrite(&mut self) -> Option<ext::host_io::HostIoPwriteOps<'_, Self>> {
        None
    }

    fn support_fstat(&mut self) -> Option<ext::host_io::HostIoFstatOps<'_, Self>> {
        Some(self)
    }

    fn support_unlink(&mut self) -> Option<ext::host_io::HostIoUnlinkOps<'_, Self>> {
        None
    }

    fn support_readlink(&mut self) -> Option<ext::host_io::HostIoReadlinkOps<'_, Self>> {
        None
    }

    fn support_setfs(&mut self) -> Option<ext::host_io::HostIoSetfsOps<'_, Self>> {
        Some(self)
    }
}

impl<T: DynamicTarget> ext::host_io::HostIoOpen for VmState<'_, T> {
    fn open(
        &mut self,
        filename: &[u8],
        _flags: ext::host_io::HostIoOpenFlags,
        _mode: ext::host_io::HostIoOpenMode,
    ) -> ext::host_io::HostIoResult<u32, Self> {
        eprintln!("Opening file: {:?}", std::str::from_utf8(filename));
        let mut file =
            std::fs::File::open(std::str::from_utf8(filename).map_err(|_| {
                ext::host_io::HostIoError::Errno(ext::host_io::HostIoErrno::EINVAL)
            })?)?;

        let mut data = Vec::new();
        file.read_to_end(&mut data)?;
        let fd = self.next_fd;
        self.next_fd += 1;
        self.open_files.insert(fd, FileSource::Native(file));

        Ok(fd)
    }
}

impl<T: DynamicTarget> ext::host_io::HostIoClose for VmState<'_, T> {
    fn close(&mut self, fd: u32) -> ext::host_io::HostIoResult<(), Self> {
        let handle = self
            .open_files
            .remove(&fd)
            .ok_or(ext::host_io::HostIoError::Errno(ext::host_io::HostIoErrno::EBADF))?;
        match handle {
            FileSource::Native(file) => file.sync_all()?,
        }
        Ok(())
    }
}

impl<T: DynamicTarget> ext::host_io::HostIoPread for VmState<'_, T> {
    fn pread(
        &mut self,
        fd: u32,
        count: usize,
        offset: u64,
        buf: &mut [u8],
    ) -> ext::host_io::HostIoResult<usize, Self> {
        let handle = self
            .open_files
            .get_mut(&fd)
            .ok_or(ext::host_io::HostIoError::Errno(ext::host_io::HostIoErrno::EBADF))?;
        match handle {
            FileSource::Native(file) => {
                use std::io::{Read, Seek};

                file.seek(std::io::SeekFrom::Start(offset))?;
                let len = buf.len().min(count);
                Ok(file.read(&mut buf[..len])?)
            }
        }
    }
}

impl<T: DynamicTarget> ext::host_io::HostIoFstat for VmState<'_, T> {
    fn fstat(&mut self, fd: u32) -> ext::host_io::HostIoResult<ext::host_io::HostIoStat, Self> {
        let handle = self
            .open_files
            .get(&fd)
            .ok_or(ext::host_io::HostIoError::Errno(ext::host_io::HostIoErrno::EBADF))?;

        match handle {
            FileSource::Native(file) => {
                let metadata = file.metadata()?;

                let get_time = |t: std::io::Result<std::time::SystemTime>| {
                    let Some(t) = t.ok()
                    else {
                        return 0;
                    };
                    t.duration_since(std::time::UNIX_EPOCH).unwrap_or_default().as_secs() as u32
                };

                Ok(ext::host_io::HostIoStat {
                    st_dev: 0,
                    st_ino: 0,
                    st_mode: get_mode(&metadata),
                    st_nlink: 1,
                    st_uid: 100,
                    st_gid: 100,
                    st_rdev: 0,
                    st_size: metadata.len(),
                    st_blksize: 512,
                    st_blocks: metadata.len().div_ceil(512),
                    st_atime: get_time(metadata.accessed()),
                    st_mtime: get_time(metadata.modified()),
                    // Not available on all platforms, but we can use modified time as a fallback.
                    st_ctime: get_time(metadata.modified()),
                })
            }
        }
    }
}

impl<T: DynamicTarget> ext::host_io::HostIoSetfs for VmState<'_, T> {
    fn setfs(&mut self, fs: ext::host_io::FsKind) -> ext::host_io::HostIoResult<(), Self> {
        match fs {
            ext::host_io::FsKind::Pid(_) => tracing::warn!("setfs pid not implemented"),
            ext::host_io::FsKind::Stub => {}
        }
        Ok(())
    }
}

fn get_mode(m: &std::fs::Metadata) -> ext::host_io::HostIoOpenMode {
    let mut mode = ext::host_io::HostIoOpenMode::empty();
    if m.file_type().is_file() {
        mode |= ext::host_io::HostIoOpenMode::S_IFREG;
    }
    else if m.file_type().is_dir() {
        mode |= ext::host_io::HostIoOpenMode::S_IFDIR;
    }

    if m.permissions().readonly() {
        mode |= ext::host_io::HostIoOpenMode::S_IRUSR;
    }
    else {
        mode |= ext::host_io::HostIoOpenMode::S_IRUSR
            | ext::host_io::HostIoOpenMode::S_IWUSR
            | ext::host_io::HostIoOpenMode::S_IXUSR;
    }
    mode
}
