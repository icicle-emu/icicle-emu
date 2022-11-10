use icicle_mem::{perm, MemResult, Mmu};

use crate::{
    exec::{
        helpers::{self, PcodeOpHelper},
        interpreter::{interpret, PcodeExecutor},
    },
    lifter::{BlockExit, Target},
    regs::{RegValue, Regs, ValueSource},
    trace::Trace,
    ExceptionCode, VarSource,
};

pub const SHADOW_STACK_SIZE: usize = 0x1000;

#[repr(C, align(16))]
pub struct ShadowStack {
    pub stack: [ShadowStackEntry; SHADOW_STACK_SIZE],
    pub offset: usize,
}

impl Clone for ShadowStack {
    fn clone(&self) -> Self {
        Self { stack: self.stack.clone(), offset: self.offset }
    }

    fn clone_from(&mut self, source: &Self) {
        self.stack[..source.offset].clone_from_slice(&source.stack[..source.offset]);
        self.offset = source.offset;
    }
}

impl ShadowStack {
    pub fn new() -> Self {
        Self { stack: [ShadowStackEntry::default(); SHADOW_STACK_SIZE], offset: 0 }
    }

    #[inline(always)]
    pub fn as_slice(&self) -> &[ShadowStackEntry] {
        &self.stack[..self.offset]
    }
}

#[derive(Default, Copy, Clone)]
pub struct ShadowStackEntry {
    pub addr: u64,
    pub block: u64,
}

impl std::fmt::Debug for ShadowStackEntry {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{:#x}", self.addr)
    }
}

#[derive(Default, Debug, Copy, Clone)]
#[repr(C)]
pub struct Exception {
    pub code: u32,
    pub value: u64,
}

impl Exception {
    #[inline]
    pub fn new(code: ExceptionCode, value: u64) -> Self {
        Self { code: code as u32, value }
    }

    #[inline]
    pub fn none() -> Self {
        Self::new(ExceptionCode::None, 0)
    }

    #[inline]
    pub fn clear(&mut self) {
        self.code = ExceptionCode::None as u32;
        self.value = 0;
    }
}

#[derive(Clone)]
pub struct CallCov {
    /// Represents registers used for passing integers to functions, these will be chosen before
    /// parameters on the stack
    pub integers: Vec<pcode::VarNode>,

    /// The alignment of parameters passed on the stack,
    pub stack_align: u64,

    /// The offset (relative to the stack pointer) of the parameters on the stack.
    pub stack_offset: u64,
}

impl Default for CallCov {
    fn default() -> Self {
        Self { integers: vec![], stack_align: 1, stack_offset: 0 }
    }
}

/// Architecture specific CPU state.
pub struct Arch {
    /// Target triple for the current architecture.
    pub triple: target_lexicon::Triple,

    /// The VarNode that represents the program's instruction pointer / PC.
    pub reg_pc: pcode::VarNode,

    /// The VarNode that represents address of the next instruction. This is neccessary for
    /// handling instructions that resume on the next instruction (e.g. syscalls) in an
    /// architecture independent way.
    ///
    /// Note: guaranteed to be 64-bits, and is only set after certain instructions.
    pub reg_next_pc: pcode::VarNode,

    /// The VarNode that represents the program's stack pointer.
    pub reg_sp: pcode::VarNode,

    /// The VarNode that contains the program's decoding mode.
    pub reg_isa_mode: Option<pcode::VarNode>,

    /// Context values for the decoder when running in different ISA modes.
    pub isa_mode_context: Vec<u64>,

    /// Values to initialize registers with on reset.
    pub reg_init: Vec<(pcode::VarNode, u128)>,

    /// Registers that represent arguments for the current calling convention.
    pub calling_cov: CallCov,

    /// The function to call when the VM boots.
    pub on_boot: fn(&mut Cpu, u64),

    /// The sleigh specification for the current architecture.
    pub sleigh: sleigh_runtime::SleighData,
}

impl Arch {
    /// A generic architecture used for testing.
    pub fn none() -> Self {
        let mut sleigh = sleigh_runtime::SleighData::default();
        sleigh.add_custom_reg("INVALID_VARNODE", 0);
        let reg_pc = sleigh.add_custom_reg("pc", 8).unwrap();
        let reg_next_pc = sleigh.add_custom_reg("next_pc", 8).unwrap();
        let reg_sp = sleigh.add_custom_reg("sp", 8).unwrap();

        sleigh.add_custom_reg("a", 8).unwrap();
        sleigh.add_custom_reg("b", 8).unwrap();
        sleigh.add_custom_reg("c", 8).unwrap();

        Self {
            triple: target_lexicon::Triple::unknown(),
            reg_pc,
            reg_next_pc,
            reg_sp,
            reg_isa_mode: None,
            isa_mode_context: vec![0],
            reg_init: vec![],
            calling_cov: CallCov::default(),
            on_boot: |_, _| {},
            sleigh,
        }
    }
}

/// Used to control where the CPU should stop executing.
///
/// Currently, 1 unit of fuel is consumed for each instruction executed.
#[derive(Copy, Clone, Default)]
pub struct Fuel {
    /// The number of units of fuel remaining.
    pub remaining: u64,

    /// The amount of fuel we started with.
    ///
    /// This is required so that we know how much fuel we consumed when the VM exits, in order to
    /// adjust the instruction count.
    pub start: u64,
}

enum MemSize {
    U8,
    U16,
    U32,
    U64,
}

impl MemSize {
    fn bytes(bytes: u8) -> Self {
        match bytes {
            1 => Self::U8,
            2 => Self::U16,
            4 => Self::U32,
            8 => Self::U64,
            _ => panic!("invalid mem size"),
        }
    }
}

pub struct Cpu {
    pub regs: Regs,
    pub args: [u128; 8],
    pub shadow_stack: ShadowStack,
    pub enable_shadow_stack: bool,

    pub mem: Mmu,

    pub icount: u64,
    pub fuel: Fuel,

    pub exception: Exception,
    pub pending_exception: Option<Exception>,
    pub block_id: u64,
    pub block_offset: u64,

    pub helpers: Vec<PcodeOpHelper>,
    pub arch: Arch,

    pub trace: Trace,

    pc_offset: isize,
    pc_size: MemSize,
}

impl Cpu {
    pub fn new_boxed(arch: Arch) -> Box<Self> {
        if !([1, 2, 4, 8].contains(&arch.reg_pc.size))
            || !Regs::check_bounds(arch.reg_pc, arch.reg_pc.size as usize)
            || arch.reg_pc.offset != 0
        {
            panic!("invalid varnode for `reg_pc`");
        }

        let pc_offset = Regs::var_offset(arch.reg_pc);
        let pc_size = MemSize::bytes(arch.reg_pc.size);

        box Cpu {
            regs: Regs::new(),
            args: [0; 8],
            shadow_stack: ShadowStack::new(),
            enable_shadow_stack: false,

            mem: Mmu::new(),

            icount: 0,
            fuel: Fuel::default(),

            exception: Exception::default(),
            pending_exception: None,
            block_id: u64::MAX,
            block_offset: 0,

            helpers: Vec::new(),
            arch,

            trace: Trace::default(),

            pc_offset,
            pc_size,
        }
    }

    pub fn reset(&mut self) {
        self.regs.fill(0);
        for &(var, value) in &self.arch.reg_init {
            self.regs.write_trunc(var, value);
        }

        self.args.fill(0);
        self.shadow_stack.offset = 0;

        self.icount = 0;
        self.fuel = Fuel::default();

        self.exception.code = ExceptionCode::None as u32;
        self.exception.value = 0;
        self.block_id = u64::MAX;
        self.block_offset = 0;
    }

    #[inline]
    pub fn update_fuel(&mut self, new: u64) {
        // Update the instruction count based on the amount of fuel consumed.
        self.icount += self.fuel.start - self.fuel.remaining;

        // Set new fuel amount.
        self.fuel.remaining = new;
        self.fuel.start = new;
    }

    pub fn set_helper(&mut self, idx: u16, helper: PcodeOpHelper) {
        if self.helpers.len() <= idx as usize {
            let new_size = idx.checked_add(1).unwrap() as usize;
            self.helpers.resize(new_size, helpers::unknown_operation);
        }
        self.helpers[idx as usize] = helper;
    }

    /// Safety: this should not be called while the CPU is running.
    pub fn add_hook(&mut self, hook: Box<dyn Hook>) -> pcode::HookId {
        self.trace.add_hook(hook)
    }

    /// Gets a mutable reference to a block hook.
    pub fn get_hook_mut(&mut self, id: pcode::HookId) -> &mut dyn Hook {
        let hooks = self.trace.hooks.get_mut();
        &mut *hooks[id as usize]
    }

    pub fn get_hooks(&mut self) -> &[Box<dyn Hook>] {
        self.trace.hooks.get_mut()
    }

    #[inline]
    pub fn icount(&self) -> u64 {
        self.icount + self.fuel.start - self.fuel.remaining
    }

    #[inline(always)]
    pub fn read_reg<R: RegValue>(&self, var: pcode::VarNode) -> R {
        R::read(&self.regs, var)
    }

    #[inline(always)]
    pub fn write_reg<R: RegValue>(&mut self, var: pcode::VarNode, val: R) {
        R::write(&mut self.regs, var, val);
    }

    #[inline(always)]
    pub fn read_pc(&self) -> u64 {
        // Safety: We ensure that `pc_offset` and `pc_size` are valid during construction
        let offset = self.pc_offset;
        unsafe {
            match self.pc_size {
                MemSize::U8 => u8::from_le_bytes(self.regs.read_at(offset)) as u64,
                MemSize::U16 => u16::from_le_bytes(self.regs.read_at(offset)) as u64,
                MemSize::U32 => u32::from_le_bytes(self.regs.read_at(offset)) as u64,
                MemSize::U64 => u64::from_le_bytes(self.regs.read_at(offset)) as u64,
            }
        }
    }

    #[inline(always)]
    pub fn write_pc(&mut self, val: u64) {
        // Safety: We ensure that `pc_offset` and `pc_size` are valid during construction
        let offset = self.pc_offset;
        unsafe {
            match self.pc_size {
                MemSize::U8 => self.regs.write_at(offset, (val as u8).to_le_bytes()),
                MemSize::U16 => self.regs.write_at(offset, (val as u16).to_le_bytes()),
                MemSize::U32 => self.regs.write_at(offset, (val as u32).to_le_bytes()),
                MemSize::U64 => self.regs.write_at(offset, (val as u64).to_le_bytes()),
            }
        }

        // Ensure that the block id is set to an invalid value to avoid copying context after the PC
        // is modified.
        self.block_id = u64::MAX;
        self.block_offset = 0;
    }

    #[inline(always)]
    pub fn set_isa_mode(&mut self, mode: u8) {
        if let Some(isa) = self.arch.reg_isa_mode {
            self.write(isa, mode);
        }
    }

    #[inline(always)]
    pub fn isa_mode(&self) -> u8 {
        self.arch.reg_isa_mode.map(|var| self.read_reg(var)).unwrap_or(0)
    }

    /// Validates that `stmt` can be executed safely.
    pub fn validate(&self, stmt: &pcode::Instruction) -> bool {
        let inputs = stmt.inputs.get();
        if let pcode::Value::Var(var) = inputs[0] {
            if !self.regs.is_valid(var, var.size as usize) {
                return false;
            }
        }
        if let pcode::Value::Var(var) = inputs[1] {
            if !self.regs.is_valid(var, var.size as usize) {
                return false;
            }
        }
        if !self.regs.is_valid(stmt.output, stmt.output.size as usize) {
            return false;
        }
        true
    }

    /// Interprets operations in `block`, starting from `offset`. If an exception is generated as
    /// part of the block, this function returns the offset of the operation that generated the
    /// exception. Otherwise the function returns None.
    ///
    /// Safety: This function assumes that `stmt` has been validated.
    pub unsafe fn interpret_block_unchecked(
        &mut self,
        block: &pcode::Block,
        offset: usize,
    ) -> Option<usize> {
        for (i, inst) in block.instructions.iter().enumerate().skip(offset) {
            self.interpret_unchecked(*inst);
            if self.exception.code != ExceptionCode::None as u32 {
                return Some(i);
            }
        }
        None
    }

    /// Safety: This function assumes that `stmt` has been validated.
    #[inline]
    pub unsafe fn interpret_unchecked(&mut self, stmt: pcode::Instruction) {
        interpret(&mut UncheckedExecutor { cpu: self }, stmt)
    }

    pub fn block_exit(&mut self, exit: BlockExit) -> Target {
        match exit {
            BlockExit::Jump { target } => target,
            BlockExit::Branch { cond, target, fallthrough } => match self.read::<u8>(cond) {
                0 => fallthrough,
                _ => target,
            },
            BlockExit::Call { target, fallthrough } => {
                if self.enable_shadow_stack {
                    self.push_shadow_stack(fallthrough);
                }
                Target::External(target)
            }
            BlockExit::Return { target } => {
                if self.enable_shadow_stack {
                    let target_pc = self.read_dynamic(target).zxt();
                    self.pop_shadow_stack(target_pc);
                }
                Target::External(target)
            }
        }
    }

    #[inline]
    pub fn push_shadow_stack(&mut self, addr: u64) {
        if self.shadow_stack.offset >= SHADOW_STACK_SIZE {
            self.exception.code = ExceptionCode::ShadowStackOverflow as u32;
            self.exception.value = addr;
            return;
        }

        self.shadow_stack.stack[self.shadow_stack.offset] =
            ShadowStackEntry { addr, block: u64::MAX };
        self.shadow_stack.offset += 1;
    }

    #[inline]
    pub fn pop_shadow_stack(&mut self, target: u64) {
        for (i, entry) in self.shadow_stack.as_slice().iter().enumerate().rev() {
            if target == entry.addr {
                self.shadow_stack.offset = i;
                return;
            }
        }
        self.exception.code = ExceptionCode::ShadowStackInvalid as u32;
        self.exception.value = target;
    }

    #[inline]
    pub fn call_hook(&mut self, id: pcode::HookId, addr: u64) {
        // @fixme(Safety): we need a mechanism to ensure that that the `hooks` field is never
        // touched by the hook we are calling. (e.g., consider using a `Lens` type?).
        unsafe {
            let hooks = self.trace.hooks.get();
            (*hooks)[id as usize].call(self, addr);
        }
    }

    /// Read a pointer-like argument according to the configured calling convention
    pub fn read_ptr_arg(&mut self, n: usize) -> MemResult<u64> {
        if let Some(&var) = self.arch.calling_cov.integers.get(n) {
            return Ok(self.read_dynamic(var.into()).zxt());
        }

        // @fixme: this might not be correct because alignment can be smaller than `ptr_size`
        let ptr_size = self.arch.reg_pc.size as u64;
        let stack_ptr: u64 = self.read_dynamic(self.arch.reg_sp.into()).zxt();
        let addr = stack_ptr
            + self.arch.calling_cov.stack_offset
            + ptr_size * (n - self.arch.calling_cov.integers.len()) as u64;

        let mut buf = [0; 8];
        self.mem.read_bytes(addr, &mut buf[..ptr_size as usize], perm::READ)?;

        Ok(match self.arch.triple.endianness().unwrap() {
            target_lexicon::Endianness::Little => u64::from_le_bytes(buf),
            target_lexicon::Endianness::Big => u64::from_be_bytes(buf),
        })
    }
}

impl ValueSource for Cpu {
    fn read_var<R: RegValue>(&self, var: pcode::VarNode) -> R {
        R::read(&self.regs, var)
    }

    fn write<R: RegValue>(&mut self, var: pcode::VarNode, value: R) {
        R::write(&mut self.regs, var, value)
    }
}

struct UncheckedExecutor<'a> {
    cpu: &'a mut Cpu,
}

impl<'a> ValueSource for UncheckedExecutor<'a> {
    fn read_var<R: RegValue>(&self, var: pcode::VarNode) -> R {
        unsafe { R::read_unchecked(&self.cpu.regs, var) }
    }

    fn write<R: RegValue>(&mut self, var: pcode::VarNode, value: R) {
        unsafe { R::write_unchecked(&mut self.cpu.regs, var, value) }
    }
}

impl<'a> PcodeExecutor for UncheckedExecutor<'a> {
    fn exception(&mut self, code: ExceptionCode, value: u64) {
        self.cpu.exception.code = code as u32;
        self.cpu.exception.value = value;
    }

    fn next_instruction(&mut self, addr: u64, _len: u64) {
        self.cpu.write_pc(addr);
        match self.cpu.fuel.remaining.checked_sub(1) {
            Some(fuel) => self.cpu.fuel.remaining = fuel,
            None => {
                self.cpu.exception.code = ExceptionCode::InstructionLimit as u32;
                self.cpu.exception.value = addr;
            }
        }
    }

    fn load_mem<const N: usize>(&mut self, id: pcode::MemId, addr: u64) -> MemResult<[u8; N]> {
        match id {
            0 => self.cpu.mem.read::<N>(addr, perm::READ),
            _ => {
                let offset = addr as usize;
                let mut value = [0; N];
                value.copy_from_slice(
                    &self.cpu.trace.storage[id as usize - 1].data()[offset..offset + N],
                );
                Ok(value)
            }
        }
    }

    fn store_mem<const N: usize>(
        &mut self,
        id: pcode::MemId,
        addr: u64,
        value: [u8; N],
    ) -> MemResult<()> {
        match id {
            0 => self.cpu.mem.write(addr, value, perm::WRITE),
            _ => {
                let offset = addr as usize;
                self.cpu.trace.storage[id as usize - 1].data_mut()[offset..offset + N]
                    .copy_from_slice(&value);
                Ok(())
            }
        }
    }

    fn set_arg(&mut self, idx: u16, value: u128) {
        self.cpu.args[idx as usize] = value;
    }

    fn call_helper(&mut self, idx: u16, output: pcode::VarNode, inputs: [pcode::Value; 2]) {
        let helper =
            &self.cpu.helpers.get(idx as usize).copied().unwrap_or(helpers::unknown_operation);
        (helper)(self.cpu, output, inputs)
    }

    fn call_hook(&mut self, hook: pcode::HookId) {
        let addr = self.cpu.read_pc();
        self.cpu.call_hook(hook, addr);
    }

    fn is_big_endian(&self) -> bool {
        self.cpu.arch.sleigh.big_endian
    }
}

pub struct CpuSnapshot {
    pub regs: Regs,
    pub args: [u128; 8],
    pub shadow_stack: ShadowStack,
    pub exception: Exception,
    pub pending_exception: Option<Exception>,
    pub icount: u64,
    pub block_id: u64,
    pub block_offset: u64,
}

impl Cpu {
    pub fn snapshot(&self) -> CpuSnapshot {
        CpuSnapshot {
            regs: self.regs.clone(),
            args: self.args.clone(),
            shadow_stack: self.shadow_stack.clone(),
            exception: self.exception,
            pending_exception: self.pending_exception,
            icount: self.icount,
            block_id: self.block_id,
            block_offset: self.block_offset,
        }
    }

    pub fn restore(&mut self, snapshot: &CpuSnapshot) {
        let valid_regs = self.arch.sleigh.num_registers();
        self.regs.restore_from(&snapshot.regs, valid_regs);

        self.args = snapshot.args;
        self.shadow_stack.clone_from(&snapshot.shadow_stack);
        self.exception = snapshot.exception;
        self.pending_exception = snapshot.pending_exception;
        self.icount = snapshot.icount;
        self.fuel = Fuel::default();

        // @fixme: Check if we can avoiding needing to save/restore these values.
        self.block_id = snapshot.block_id;
        self.block_offset = snapshot.block_offset;
    }
}

pub trait Hook {
    fn call(&mut self, cpu: &mut Cpu, pc: u64);
    fn as_ptr(&self) -> Option<(extern "sysv64" fn(*mut Cpu, u64, *mut ()), *mut ())> {
        None
    }
    fn as_any(&mut self) -> &mut dyn std::any::Any;
}

impl<F> Hook for F
where
    F: FnMut(&mut Cpu, u64) + 'static,
{
    fn call(&mut self, cpu: &mut Cpu, pc: u64) {
        self(cpu, pc)
    }

    fn as_any(&mut self) -> &mut dyn std::any::Any {
        self
    }
}

pub mod read_pc {
    use super::*;

    pub fn uninitialized(_: &Cpu) -> u64 {
        panic!("architecture not initialized");
    }

    macro_rules! impl_read_pc {
        ($ty:ident) => {
            pub fn $ty(cpu: &Cpu) -> u64 {
                debug_assert!(cpu.regs.is_valid(cpu.arch.reg_pc, std::mem::size_of::<$ty>()));
                unsafe { <$ty>::from_le_bytes(cpu.regs.read_var_unchecked(cpu.arch.reg_pc)) as u64 }
            }
        };
    }

    impl_read_pc!(u8);
    impl_read_pc!(u16);
    impl_read_pc!(u32);
    impl_read_pc!(u64);
}

pub fn generic_on_boot(cpu: &mut Cpu, entry: u64) {
    cpu.reset();
    cpu.write_pc(entry);
}
