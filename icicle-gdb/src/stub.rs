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
    cpu::{mem::perm, Cpu, ExceptionCode, ValueSource},
    linux::TerminationReason,
    Snapshot, Vm, VmExit,
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

pub struct VmState<T: DynamicTarget> {
    trace: bool,
    snapshots: HashMap<Option<String>, Snapshot>,
    vm: Vm,
    target: T,
    exec_mode: ExecMode,
}

impl<T: DynamicTarget> VmState<T> {
    pub fn new(vm: Vm) -> Self {
        let target = T::new(&vm.cpu);
        Self { trace: false, snapshots: HashMap::new(), vm, target, exec_mode: ExecMode::Continue }
    }

    pub fn run(&mut self) -> SingleThreadStopReason<<T::Arch as Arch>::Usize> {
        let exit = match self.exec_mode {
            ExecMode::Continue => self.vm.run(),
            ExecMode::Step => self.vm.step(1),
            ExecMode::ReverseStep => self.vm.step_back(1),
        };
        translate_stop_reason(&mut self.vm, exit)
    }
}

pub struct IcicleX64SegmentRegs {
    pub cs: pcode::VarNode,
    pub ss: pcode::VarNode,
    pub ds: pcode::VarNode,
    pub es: pcode::VarNode,
    pub fs: pcode::VarNode,
    pub gs: pcode::VarNode,
}

pub struct IcicleX64 {
    /// RAX, RBX, RCX, RDX, RSI, RDI, RBP, RSP, r8-r15
    pub regs: [pcode::VarNode; 16],
    /// Status register
    pub eflags: pcode::VarNode,
    /// Instruction pointer
    pub rip: pcode::VarNode,
    /// Segment registers: CS, SS, DS, ES, FS, GS
    pub segments: IcicleX64SegmentRegs,
    /// FPU registers: ST0 through ST7
    pub st: [pcode::VarNode; 8],
    /// FPU internal registers
    pub fpu: (),
    /// SIMD Registers: XMM0 through XMM15
    pub xmm: [pcode::VarNode; 0x10],
    /// SSE Status/Control Register
    pub mxcsr: pcode::VarNode,
}

impl DynamicTarget for IcicleX64 {
    type Arch = gdbstub_arch::x86::X86_64_SSE;

    #[rustfmt::skip]
    fn new(cpu: &Cpu) -> Self {
        let r = |name: &str| cpu.arch.sleigh.get_reg(name).unwrap().var;
        Self {
            regs: [
                r("RAX"), r("RBX"), r("RCX"), r("RDX"), r("RSI"), r("RDI"),
                r("RBP"), r("RSP"), r("R8"),  r("R9"),  r("R10"), r("R11"),
                r("R12"), r("R13"), r("R14"), r("R15"),
            ],
            eflags: r("eflags"),
            rip: r("RIP"),
            segments: IcicleX64SegmentRegs {
                cs: r("CS"),
                ss: r("SS"),
                ds: r("DS"),
                es: r("ES"),
                fs: r("FS"),
                gs: r("GS")
            },
            st: [r("ST0"), r("ST1"), r("ST2"), r("ST3"), r("ST4"), r("ST5"), r("ST6"), r("ST7")],
            fpu: (),
            xmm: [
                r("XMM0"),  r("XMM1"),  r("XMM2"),  r("XMM3"),  r("XMM4"),
                r("XMM5"),  r("XMM6"),  r("XMM7"),  r("XMM8"),  r("XMM9"),
                r("XMM10"), r("XMM11"), r("XMM12"), r("XMM13"), r("XMM14"),
                r("XMM15"),
            ],
            mxcsr: r("MXCSR"),
        }
    }

    fn read_registers(&self, cpu: &Cpu, regs: &mut gdbstub_arch::x86::reg::X86_64CoreRegs) {
        regs.regs.iter_mut().zip(&self.regs).for_each(|(dst, var)| *dst = cpu.read_var(*var));
        regs.eflags = icicle_vm::x86::eflags(cpu);
        regs.rip = cpu.read_var(self.rip);

        regs.segments.cs = cpu.read_var(self.segments.cs);
        regs.segments.ss = cpu.read_var(self.segments.ss);
        regs.segments.ds = cpu.read_var(self.segments.ds);
        regs.segments.es = cpu.read_var(self.segments.es);
        regs.segments.fs = cpu.read_var(self.segments.fs);
        regs.segments.gs = cpu.read_var(self.segments.gs);

        regs.st.iter_mut().zip(&self.st).for_each(|(dst, var)| *dst = cpu.read_var(*var));
        regs.fpu = gdbstub_arch::x86::reg::X87FpuInternalRegs::default();
        regs.xmm.iter_mut().zip(&self.xmm).for_each(|(dst, var)| *dst = cpu.read_var(*var));
        regs.mxcsr = cpu.read_var(self.mxcsr);
    }

    fn write_registers(&self, cpu: &mut Cpu, regs: &gdbstub_arch::x86::reg::X86_64CoreRegs) {
        let _cpu = cpu;
        let _regs = regs;
    }
}

pub struct IcicleMips32 {
    pub r: [pcode::VarNode; 32],
    pub lo: pcode::VarNode,
    pub hi: pcode::VarNode,
    pub pc: pcode::VarNode,
    pub cop0: (),
    pub fpu_r: [pcode::VarNode; 32],
    pub fcsr: pcode::VarNode,
    pub fir: pcode::VarNode,
}

impl DynamicTarget for IcicleMips32 {
    type Arch = gdbstub_arch::mips::Mips;

    #[rustfmt::skip]
    fn new(cpu: &Cpu) -> Self {
        let r = |name: &str| cpu.arch.sleigh.get_reg(name).unwrap().var;
        Self {
            r: [
                r("zero"), r("at"), r("v0"), r("v1"),
                r("a0"), r("a1"), r("a2"), r("a3"),
                r("t0"), r("t1"), r("t2"), r("t3"),
                r("t4"), r("t5"), r("t6"), r("t7"),
                r("s0"), r("s1"), r("s2"), r("s3"),
                r("s4"), r("s5"), r("s6"), r("s7"),
                r("t8"), r("t9"), r("k0"), r("k1"),
                r("gp"), r("sp"), r("s8"), r("ra"),
            ],
            lo: r("lo"),
            hi: r("hi"),
            pc: r("pc"),
            cop0: (),
            fpu_r: [
                r("f0"),  r("f1"),  r("f2"),  r("f3"),  r("f4"),  r("f5"),  r("f6"),
                r("f7"),  r("f8"),  r("f9"),  r("f10"), r("f11"), r("f12"), r("f13"),
                r("f14"), r("f15"), r("f16"), r("f17"), r("f18"), r("f19"), r("f20"),
                r("f21"), r("f22"), r("f23"), r("f24"), r("f25"), r("f26"), r("f27"),
                r("f28"), r("f29"), r("f30"), r("f31"),
            ],
            fcsr: r("fcsr"),
            fir: r("fir"),
        }
    }

    fn read_registers(&self, cpu: &Cpu, regs: &mut gdbstub_arch::mips::reg::MipsCoreRegs<u32>) {
        regs.r.iter_mut().zip(&self.r).for_each(|(dst, var)| *dst = cpu.read_var(*var));
        regs.lo = cpu.read_var(self.lo);
        regs.hi = cpu.read_var(self.hi);
        regs.pc = cpu.read_var(self.pc);
        regs.fpu.r.iter_mut().zip(&self.fpu_r).for_each(|(dst, var)| *dst = cpu.read_var(*var));
        regs.fpu.fcsr = cpu.read_var(self.fcsr);
        regs.fpu.fir = cpu.read_var(self.fir);
    }

    fn write_registers(&self, cpu: &mut Cpu, regs: &gdbstub_arch::mips::reg::MipsCoreRegs<u32>) {
        let _cpu = cpu;
        let _regs = regs;
    }
}

pub struct IcicleMsp430 {
    pc: pcode::VarNode,
    sp: pcode::VarNode,
    sr: pcode::VarNode,
    r: [pcode::VarNode; 12],
}

impl DynamicTarget for IcicleMsp430 {
    type Arch = gdbstub_arch::msp430::Msp430X;

    #[rustfmt::skip]
    fn new(cpu: &Cpu) -> Self {
        let r = |name: &str| cpu.arch.sleigh.get_reg(name).unwrap().var;
        Self {
            pc: r("PC"),
            sp: r("SP"),
            sr: r("SR"),
            r: [
                r("R4"),  r("R5"),  r("R6"),  r("R7"),  r("R8"),  r("R9"),
                r("R10"), r("R11"), r("R12"), r("R13"), r("R14"), r("R15"),
            ],
        }
    }

    fn read_registers(&self, cpu: &Cpu, regs: &mut gdbstub_arch::msp430::reg::Msp430Regs<u32>) {
        regs.pc = cpu.read_var(self.pc);
        regs.sp = cpu.read_var(self.sp);
        regs.sr = cpu.read_var(self.sr);
        regs.r.iter_mut().zip(&self.r).for_each(|(dst, var)| *dst = cpu.read_var(*var));
    }

    fn write_registers(&self, cpu: &mut Cpu, regs: &gdbstub_arch::msp430::reg::Msp430Regs<u32>) {
        let _ = cpu;
        let _ = regs;
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
        self.vm
            .cpu
            .mem
            .read_bytes(num_traits::cast(start_addr).unwrap(), data, perm::NONE)
            .map_err(|_| TargetError::NonFatal)
    }

    fn write_addrs(
        &mut self,
        start_addr: <Self::Arch as Arch>::Usize,
        data: &[u8],
    ) -> TargetResult<(), Self> {
        self.vm
            .cpu
            .mem
            .write_bytes(num_traits::cast(start_addr).unwrap(), data, perm::NONE)
            .map_err(|_| TargetError::NonFatal)
    }

    fn support_resume(&mut self) -> Option<SingleThreadResumeOps<Self>> {
        Some(self)
    }
}

impl<T: DynamicTarget> SingleThreadResume for VmState<T> {
    fn support_single_step(
        &mut self,
    ) -> Option<ext::base::singlethread::SingleThreadSingleStepOps<'_, Self>> {
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
            Some("trace") => {
                self.trace ^= true;
            }
            Some("snapshot") => {
                let snapshot = self.vm.snapshot();
                self.snapshots.insert(None, snapshot);
                gdbstub::outputln!(out, "created snapshot");
            }
            Some("restore") => match self.snapshots.get(&None) {
                Some(snapshot) => {
                    self.vm.restore(snapshot);
                    gdbstub::outputln!(out, "state restored from snapshot");
                }
                None => gdbstub::outputln!(out, "snapshot does not exist"),
            },
            Some("back") => {
                let _ = self.vm.step_back(1);
            }
            Some("step") => {
                if let Some(inner) = parts.next() {
                    let count = inner.parse().map_err(|e| anyhow::format_err!("{}", e))?;
                    let _ = self.vm.step(count);
                }
                else {
                    warn!("Expected count");
                    return Ok(());
                }
            }
            Some("backtrace") => {
                let backtrace = icicle_vm::debug::backtrace(&mut self.vm);
                out.write_raw(backtrace.as_bytes());
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
        let mut kernel = self.vm.env.as_any().downcast_mut::<icicle_vm::linux::Kernel>().unwrap();
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
        let mut kernel = self.vm.env.as_any().downcast_mut::<icicle_vm::linux::Kernel>().unwrap();
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
                .env
                .as_any()
                .downcast_ref::<icicle_vm::linux::Kernel>()
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
            if code == 0 {
                // @fixme get syscall number
                let id = 0_u64;
                let number = num_traits::cast(id).unwrap();
                SingleThreadStopReason::CatchSyscall {
                    tid: None,
                    number,
                    position: CatchSyscallPosition::Entry,
                }
            }
            else if code == 1 {
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
        VmExit::UnhandledException((code, addr)) if code.is_memory_error() => {
            warn!("{code:?} addr={addr:#0x}");
            SingleThreadStopReason::Signal(Signal::SIGSEGV)
        }

        other => {
            warn!("{:?}", other);
            SingleThreadStopReason::SwBreak(())
        }
    }
}
