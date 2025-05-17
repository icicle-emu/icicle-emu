use icicle_vm::cpu::{Cpu, ValueSource};
use pcode::VarNode;

use gdbstub_arch::{
    arm::reg::ArmCoreRegs, mips::reg::MipsCoreRegs, msp430::reg::Msp430Regs,
    x86::reg::X86_64CoreRegs,
};

use crate::stub::DynamicTarget;

pub struct IcicleX64SegmentRegs {
    pub cs: VarNode,
    pub ss: VarNode,
    pub ds: VarNode,
    pub es: VarNode,
    pub fs: VarNode,
    pub gs: VarNode,
}

pub struct IcicleX64 {
    /// RAX, RBX, RCX, RDX, RSI, RDI, RBP, RSP, r8-r15
    pub regs: [VarNode; 16],
    /// Status register
    pub eflags: VarNode,
    /// Instruction pointer
    pub rip: VarNode,
    /// Segment registers: CS, SS, DS, ES, FS, GS
    pub segments: IcicleX64SegmentRegs,
    /// FPU registers: ST0 through ST7
    pub st: [VarNode; 8],
    /// FPU internal registers
    pub fpu: (),
    /// SIMD Registers: XMM0 through XMM15
    pub xmm: [VarNode; 0x10],
    /// SSE Status/Control Register
    pub mxcsr: VarNode,
}

impl DynamicTarget for IcicleX64 {
    type Arch = gdbstub_arch::x86::X86_64_SSE;

    #[rustfmt::skip]
    fn new(cpu: &Cpu) -> Self {
        let r = |name: &str| cpu.arch.sleigh.get_varnode(name).unwrap();
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

    fn read_registers(&self, cpu: &Cpu, regs: &mut X86_64CoreRegs) {
        regs.regs.iter_mut().zip(&self.regs).for_each(|(dst, var)| *dst = cpu.read_var(*var));
        regs.eflags = icicle_vm::x86::eflags(cpu);
        regs.rip = cpu.read_var(self.rip);

        regs.segments.cs = cpu.read_var::<u16>(self.segments.cs) as u32;
        regs.segments.ss = cpu.read_var::<u16>(self.segments.ss) as u32;
        regs.segments.ds = cpu.read_var::<u16>(self.segments.ds) as u32;
        regs.segments.es = cpu.read_var::<u16>(self.segments.es) as u32;
        regs.segments.fs = cpu.read_var::<u16>(self.segments.fs) as u32;
        regs.segments.gs = cpu.read_var::<u16>(self.segments.gs) as u32;

        regs.st.iter_mut().zip(&self.st).for_each(|(dst, var)| *dst = cpu.read_var(*var));
        regs.fpu = gdbstub_arch::x86::reg::X87FpuInternalRegs::default();
        regs.xmm.iter_mut().zip(&self.xmm).for_each(|(dst, var)| *dst = cpu.read_var(*var));
        regs.mxcsr = cpu.read_var(self.mxcsr);
    }

    fn write_registers(&self, cpu: &mut Cpu, regs: &X86_64CoreRegs) {
        let _cpu = cpu;
        let _regs = regs;
    }
}

pub struct IcicleMips32 {
    pub r: [VarNode; 32],
    pub lo: VarNode,
    pub hi: VarNode,
    pub pc: VarNode,
    pub cop0: (),
    pub fpu_r: [VarNode; 32],
    pub fcsr: VarNode,
    pub fir: VarNode,
}

impl DynamicTarget for IcicleMips32 {
    type Arch = gdbstub_arch::mips::Mips;

    #[rustfmt::skip]
    fn new(cpu: &Cpu) -> Self {
        let r = |name: &str| cpu.arch.sleigh.get_varnode(name).unwrap();
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

    fn read_registers(&self, cpu: &Cpu, regs: &mut MipsCoreRegs<u32>) {
        regs.r.iter_mut().zip(&self.r).for_each(|(dst, var)| *dst = cpu.read_var(*var));
        regs.lo = cpu.read_var(self.lo);
        regs.hi = cpu.read_var(self.hi);
        regs.pc = cpu.read_var(self.pc);
        regs.fpu.r.iter_mut().zip(&self.fpu_r).for_each(|(dst, var)| *dst = cpu.read_var(*var));
        regs.fpu.fcsr = cpu.read_var(self.fcsr);
        regs.fpu.fir = cpu.read_var(self.fir);
    }

    fn write_registers(&self, cpu: &mut Cpu, regs: &MipsCoreRegs<u32>) {
        let _cpu = cpu;
        let _regs = regs;
    }
}

pub struct IcicleArm {
    pub r: [VarNode; 13],
    pub sp: VarNode,
    pub lr: VarNode,
    pub pc: VarNode,
    pub cpsr: VarNode,
}

impl DynamicTarget for IcicleArm {
    type Arch = gdbstub_arch::arm::Armv4t;

    #[rustfmt::skip]
    fn new(cpu: &Cpu) -> Self {
        let r = |name: &str| cpu.arch.sleigh.get_varnode(name).unwrap();
        Self {
            r: [
                r("r0"), r("r1"), r("r2"), r("r3"), r("r4"), r("r5"), r("r6"), r("r7"),
                r("r8"), r("r9"), r("r10"), r("r11"), r("r12"),
            ],
            sp: r("sp"),
            lr: r("lr"),
            pc: r("pc"),
            cpsr: r("cpsr"),
        }
    }

    fn read_registers(&self, cpu: &Cpu, regs: &mut ArmCoreRegs) {
        regs.r.iter_mut().zip(&self.r).for_each(|(dst, var)| *dst = cpu.read_var(*var));
        regs.sp = cpu.read_var(self.sp);
        regs.lr = cpu.read_var(self.lr);
        regs.pc = cpu.read_var(self.pc);
        regs.cpsr = cpu.read_var(self.cpsr);
    }

    fn write_registers(&self, cpu: &mut Cpu, regs: &ArmCoreRegs) {
        let _cpu = cpu;
        let _regs = regs;
    }
}

pub struct IcicleMsp430 {
    pc: VarNode,
    sp: VarNode,
    sr: VarNode,
    r: [VarNode; 12],
}

impl DynamicTarget for IcicleMsp430 {
    type Arch = gdbstub_arch::msp430::Msp430X;

    #[rustfmt::skip]
    fn new(cpu: &Cpu) -> Self {
        let r = |name: &str| cpu.arch.sleigh.get_varnode(name).unwrap();
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

    fn read_registers(&self, cpu: &Cpu, regs: &mut Msp430Regs<u32>) {
        regs.pc = cpu.read_var(self.pc);
        regs.sp = cpu.read_var(self.sp);
        regs.sr = cpu.read_var(self.sr);
        regs.r.iter_mut().zip(&self.r).for_each(|(dst, var)| *dst = cpu.read_var(*var));
    }

    fn write_registers(&self, cpu: &mut Cpu, regs: &Msp430Regs<u32>) {
        let _ = cpu;
        let _ = regs;
    }
}
