use std::collections::HashMap;

use gdbstub::{
    arch::Arch,
    common::Signal,
    stub::SingleThreadStopReason,
    target::{
        ext::{
            self,
            base::{
                reverse_exec::{ReverseStep, ReverseStepOps},
                singlethread::{SingleThreadBase, SingleThreadResume, SingleThreadSingleStep},
            },
        },
        ext::{base::singlethread::SingleThreadResumeOps, catch_syscalls::CatchSyscallPosition},
        TargetError, TargetResult,
    },
};
use icicle_vm::{
    cpu::{mem::perm, Cpu, ExceptionCode},
    injector::PathTracerRef,
    linux::TerminationReason,
    Vm, VmExit,
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

pub struct VmState<T: DynamicTarget> {
    tracer: Option<PathTracerRef>,
    snapshots: HashMap<Option<String>, Snapshot>,
    vm: Vm,
    target: T,
    exec_mode: ExecMode,
    #[allow(unused)]
    write_hooks: HashMap<(u64, u64), u64>,
    #[allow(unused)]
    read_hooks: HashMap<(u64, u64), u64>,
}

impl<T: DynamicTarget> VmState<T> {
    pub fn new(mut vm: Vm) -> Self {
        let target = T::new(&vm.cpu);
        // Create an initial snapshot for reverse execution.
        vm.save_snapshot();
        Self {
            tracer: None,
            snapshots: HashMap::new(),
            vm,
            target,
            exec_mode: ExecMode::Continue,
            read_hooks: HashMap::new(),
            write_hooks: HashMap::new(),
        }
    }

    pub fn run(&mut self) -> SingleThreadStopReason<<T::Arch as Arch>::Usize> {
        let exit = match self.exec_mode {
            ExecMode::Continue => self.vm.run(),
            ExecMode::Step => self.vm.step(1),
            ExecMode::ReverseStep => match self.vm.step_back(1) {
                Some(exit) => exit,
                None => {
                    return SingleThreadStopReason::ReplayLog {
                        tid: None,
                        pos: ext::base::reverse_exec::ReplayLogPosition::Begin,
                    };
                }
            },
        };
        tracing::debug!("VmExit: {exit:?}");
        translate_stop_reason(&mut self.vm, exit)
    }
}

impl<T: DynamicTarget> gdbstub::target::Target for VmState<T> {
    type Arch = <T as DynamicTarget>::Arch;
    type Error = anyhow::Error;

    fn base_ops(&mut self) -> ext::base::BaseOps<Self::Arch, Self::Error> {
        ext::base::BaseOps::SingleThread(self)
    }

    fn support_breakpoints(&mut self) -> Option<ext::breakpoints::BreakpointsOps<Self>> {
        Some(self)
    }

    fn support_monitor_cmd(&mut self) -> Option<ext::monitor_cmd::MonitorCmdOps<Self>> {
        Some(self)
    }

    fn support_section_offsets(&mut self) -> Option<ext::section_offsets::SectionOffsetsOps<Self>> {
        match self.vm.env.as_any().is::<icicle_vm::linux::Kernel>() {
            true => Some(self),
            false => None,
        }
    }

    fn support_catch_syscalls(&mut self) -> Option<ext::catch_syscalls::CatchSyscallsOps<Self>> {
        match self.vm.env.as_any().is::<icicle_vm::linux::Kernel>() {
            true => Some(self),
            false => None,
        }
    }
}

impl<T: DynamicTarget> SingleThreadBase for VmState<T> {
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
    ) -> TargetResult<(), Self> {
        let start: u64 = num_traits::cast(start_addr).unwrap();
        if !self.vm.cpu.mem.is_regular_region(start, data.len() as u64) {
            return Err(TargetError::NonFatal);
        }
        self.vm.cpu.mem.read_bytes(start, data, perm::NONE).map_err(|_| TargetError::NonFatal)
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

    fn support_resume(&mut self) -> Option<SingleThreadResumeOps<Self>> {
        Some(self)
    }
}

impl<T: DynamicTarget> SingleThreadResume for VmState<T> {
    fn support_single_step(
        &mut self,
    ) -> Option<ext::base::singlethread::SingleThreadSingleStepOps<'_, Self>> {
        if matches!(
            self.vm.cpu.arch.triple.architecture,
            target_lexicon::Architecture::Riscv64(_) | target_lexicon::Architecture::Mips32(_)
        ) {
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

impl<T: DynamicTarget> SingleThreadSingleStep for VmState<T> {
    fn step(&mut self, signal: Option<Signal>) -> Result<(), Self::Error> {
        if let Some(signal) = signal {
            // @todo
            let _signal = signal;
        }
        self.exec_mode = ExecMode::Step;
        Ok(())
    }
}

impl<T: DynamicTarget> ReverseStep<()> for VmState<T> {
    fn reverse_step(&mut self, _tid: ()) -> Result<(), Self::Error> {
        self.exec_mode = ExecMode::ReverseStep;
        Ok(())
    }
}

impl<T: DynamicTarget> ext::breakpoints::Breakpoints for VmState<T> {
    fn support_sw_breakpoint(&mut self) -> Option<ext::breakpoints::SwBreakpointOps<Self>> {
        Some(self)
    }

    fn support_hw_watchpoint(&mut self) -> Option<ext::breakpoints::HwWatchpointOps<'_, Self>> {
        Some(self)
    }
}

impl<T: DynamicTarget> ext::breakpoints::SwBreakpoint for VmState<T> {
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

impl<T: DynamicTarget> ext::breakpoints::HwWatchpoint for VmState<T> {
    fn add_hw_watchpoint(
        &mut self,
        addr: <Self::Arch as Arch>::Usize,
        len: <Self::Arch as Arch>::Usize,
        _kind: ext::breakpoints::WatchKind,
    ) -> TargetResult<bool, Self> {
        let addr: u64 = num_traits::cast(addr).unwrap();
        let len: u64 = num_traits::cast(len).unwrap();

        self.vm.cpu.mem.add_write_hook(
            addr,
            addr + len,
            Box::new(|_mem: &mut icicle_vm::cpu::Mmu, _addr: u64, _value: &[u8]| todo!()),
        );

        Ok(true)
    }

    fn remove_hw_watchpoint(
        &mut self,
        _addr: <Self::Arch as Arch>::Usize,
        _len: <Self::Arch as Arch>::Usize,
        _kind: ext::breakpoints::WatchKind,
    ) -> TargetResult<bool, Self> {
        todo!()
    }
}

impl<T: DynamicTarget> ext::monitor_cmd::MonitorCmd for VmState<T> {
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
                match icicle_vm::injector::add_path_tracer(&mut self.vm) {
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
                let pcode = icicle_vm::debug::current_disasm(&self.vm);
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
                if let Err(e) = tracer.save_trace(&mut self.vm, path.as_ref()) {
                    gdbstub::outputln!(out, "failed to save trace to {path}: {e:?}");
                    return Ok(());
                }
                gdbstub::outputln!(out, "trace saved to {path}");
            }
            Some("lookup-varnode") => {
                if let Some(name) = parts.next() {
                    match self.vm.cpu.arch.sleigh.get_reg(name) {
                        Some(var) => gdbstub::outputln!(out, "{:?}", var.var),
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
                    match self.vm.cpu.arch.sleigh.get_reg(name) {
                        Some(var) => {
                            let value = self.vm.cpu.read_reg(var.var);
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
                    trace: self.tracer.map(|tracer| tracer.get_last_blocks(&mut self.vm)),
                    vm: self.vm.snapshot(),
                };
                self.snapshots.insert(None, snapshot);
                gdbstub::outputln!(out, "created snapshot");
            }
            Some("restore") => match self.snapshots.get(&None) {
                Some(snapshot) => {
                    self.vm.restore(&snapshot.vm);
                    if let Some(trace) = snapshot.trace.as_ref() {
                        self.tracer.unwrap().restore(&mut self.vm, trace);
                        gdbstub::outputln!(out, "state restored from snapshot");
                    }
                }
                None => gdbstub::outputln!(out, "snapshot does not exist"),
            },
            Some("back") => {
                let _ = self.vm.step_back(1);
            }
            Some("step") => {
                let Some(inner) = parts.next() else {
                    warn!("Expected count");
                    return Ok(());
                };

                let count = inner.parse().map_err(|e| anyhow::format_err!("{}", e))?;
                let _ = self.vm.step(count);
            }
            Some("backtrace") => {
                let backtrace = icicle_vm::debug::backtrace(&mut self.vm);
                out.write_raw(backtrace.as_bytes());
            }
            Some("icount") => {
                gdbstub::outputln!(out, "icount = {}", self.vm.cpu.icount());
            }
            Some("memory-map") => {
                gdbstub::outputln!(out, "{:#x?}", self.vm.cpu.mem.get_mapping());
            }
            Some("ensure-exec") => {
                let (Some(addr), Some(len)) = (parts.next(), parts.next()) else {
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

impl<T: DynamicTarget> ext::section_offsets::SectionOffsets for VmState<T> {
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

impl<T: DynamicTarget> ext::catch_syscalls::CatchSyscalls for VmState<T> {
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
        VmExit::UnhandledException((ExceptionCode::ReadWatch | ExceptionCode::WriteWatch, _)) => {
            SingleThreadStopReason::Signal(Signal::SIGSTOP)
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
