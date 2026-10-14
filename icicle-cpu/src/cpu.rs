use std::cell::UnsafeCell;

use icicle_mem::{MemResult, Mmu, perm, tlb::TranslationCache};
use pcode::PcodeDisplay;

use crate::{
    ExceptionCode, InstHook, InternalError, VarSource,
    exec::{
        helpers::{self, PcodeOpHelper},
        interpreter::{PcodeExecutor, interpret},
    },
    lifter::{BlockExit, BlockKey, Target},
    regs::{DynamicValue, RegValue, Regs, ValueSource},
    trace::{self, Trace},
};

pub use crate::arch::Arch;

#[derive(Default, Debug, Copy, Clone, PartialEq)]
#[repr(C)]
pub struct Exception {
    pub code: u32,
    pub value: u64,
}

impl From<(ExceptionCode, u64)> for Exception {
    fn from((code, value): (ExceptionCode, u64)) -> Self {
        Self::new(code, value)
    }
}

impl From<(ExceptionCode, InternalError)> for Exception {
    fn from((code, value): (ExceptionCode, InternalError)) -> Self {
        Self::new(code, value as u64)
    }
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
    pub const fn internal_error(error: crate::InternalError) -> Self {
        Self { code: ExceptionCode::InternalError as u32, value: error as u64 }
    }

    #[inline]
    pub fn clear(&mut self) {
        self.code = ExceptionCode::None as u32;
        self.value = 0;
    }

    pub const SWITCH_TO_INTERPRETER: Self =
        Self::internal_error(InternalError::SwitchToInterpreter);
}

/// Used to control where the CPU should stop executing.
///
/// Currently, 1 unit of fuel is consumed for each instruction executed.
#[derive(Copy, Clone, Default)]
pub struct Fuel {
    /// The number of units of fuel remaining. Can be negative if we requested to exit immediately
    /// (without an exception) but still had instructions left in the block.
    pub remaining: i64,

    /// The amount of fuel we started with.
    ///
    /// This is required so that we know how much fuel we consumed when the VM exits, in order to
    /// adjust the instruction count.
    pub start: u64,
}

pub trait RegHandler {
    fn read(&mut self, cpu: &mut Cpu);
    fn write(&mut self, cpu: &mut Cpu);
}

pub struct Cpu {
    pub regs: Regs,
    pub args: [u128; 8],
    pub shadow_stack: ShadowStack,
    pub shadow_stack_state: ShadowStackState,

    pub mem: Mmu,
    pub jit_ctx: JitContext,

    pub icount: u64,
    pub fuel: Fuel,

    pub exception: Exception,
    pub pending_exception: Option<Exception>,
    pub block_id: u64,
    pub block_offset: u64,

    pub helpers: Vec<PcodeOpHelper>,
    pub arch: Arch,

    pub trace: Trace,

    /// Handlers perform special operations when reading / writing to registers. Currently we
    /// simply check each handler sequentially, since we expect very few handlers and this allows
    /// us to avoid code bloat.
    ///
    /// Optimization note: In the future we could reassign register IDs such that those with
    /// handlers associated are contiguous allowing for an easy lookup.
    reg_handlers: UnsafeCell<Vec<(i16, Box<dyn RegHandler>)>>,

    /// Cached copy of the PC offset that has already been validated.
    pc_offset: isize,
    /// Mask used to ensure that PC value is truncated to the correct size.
    pc_mask: u64,
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
        let pc_mask = pcode::mask(arch.reg_pc.size as u64 * 8);
        let address_mask = pcode::mask(arch.triple.pointer_width().map_or(64, |x| x.bits() as u64));

        Box::new(Cpu {
            regs: Regs::new(),
            args: [0; 8],
            shadow_stack: ShadowStack::new(),
            shadow_stack_state: ShadowStackState::Disabled,

            mem: Mmu::with_mask(address_mask),
            jit_ctx: JitContext::default(),

            icount: 0,
            fuel: Fuel::default(),

            exception: Exception::default(),
            pending_exception: None,
            block_id: u64::MAX,
            block_offset: 0,

            helpers: Vec::new(),
            arch,

            trace: Trace::default(),
            reg_handlers: UnsafeCell::new(vec![]),

            pc_offset,
            pc_mask,
        })
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
        self.icount = self.icount.strict_add_signed(self.fuel.start as i64 - self.fuel.remaining);

        // Set new fuel amount.
        self.fuel.remaining = new as i64;
        self.fuel.start = new;
    }

    pub fn add_reg_handler(&mut self, id: pcode::VarId, handler: Box<dyn RegHandler>) {
        self.reg_handlers.get_mut().push((id, handler));
    }

    pub fn set_helper(&mut self, idx: u16, helper: PcodeOpHelper) {
        if self.helpers.len() <= idx as usize {
            let new_size = idx.checked_add(1).unwrap() as usize;
            self.helpers.resize(new_size, helpers::unknown_operation);
        }
        self.helpers[idx as usize] = helper;
    }

    /// Safety: this should not be called while the CPU is running.
    pub fn add_hook(&mut self, hook: impl Into<InstHook>) -> pcode::HookId {
        self.trace.add_hook(hook.into())
    }

    /// Gets a mutable reference to a block hook.
    #[inline]
    pub fn get_hook_mut(&mut self, id: pcode::HookId) -> &mut InstHook {
        let hooks = self.trace.hooks.get_mut();
        &mut hooks[id as usize]
    }

    #[inline]
    pub fn get_hooks(&mut self) -> &mut [InstHook] {
        self.trace.hooks.get_mut()
    }

    #[inline]
    pub fn icount(&self) -> u64 {
        self.icount.strict_add_signed(self.fuel.start as i64 - self.fuel.remaining)
    }

    /// Translate a SLEIGH register offset to an Icicle varnode.
    pub fn var_for_offset(&self, offset: u32, size: u8) -> Option<pcode::VarNode> {
        let (reg, reg_offset) = self.arch.sleigh.map_sleigh_reg(offset, size)?;
        // @todo: check behaviour of big-endian dynamic accesses.
        reg.slice_var(reg_offset, size)
    }

    /// Reads the register represented by `var`. For special registers, this may perform additional
    /// operations.
    pub fn read_dyn_reg(&mut self, var: pcode::VarNode) -> DynamicValue {
        if let Some((_, handler)) =
            unsafe { (*self.reg_handlers.get()).iter_mut().find(|x| x.0 == var.id) }
        {
            handler.read(self);
        }
        self.read_dynamic(var.into())
    }

    /// Reads the register represented by `var`, truncating or zero-extending the value to 64 bits.
    /// For special registers, this may perform additional operations.
    pub fn read_reg(&mut self, var: pcode::VarNode) -> u64 {
        self.read_dyn_reg(var).zxt()
    }

    /// Reads the register represented by `var` without performing any special operations, and
    /// without checking that the register is valid.
    pub unsafe fn read_var_unchecked<R: RegValue>(&self, var: pcode::VarNode) -> R {
        unsafe { R::read_unchecked(&self.regs, var) }
    }

    /// Writes `val` to the register represented by `var`. For special registers, this may perform
    /// additional operations.
    pub fn write_reg(&mut self, var: pcode::VarNode, val: u64) {
        self.write_trunc(var, val);
        if let Some((_, handler)) =
            unsafe { (*self.reg_handlers.get()).iter_mut().find(|x| x.0 == var.id) }
        {
            handler.write(self);
        }
    }

    /// Like `write_reg` but supports writing 128-bit values.
    pub fn write_reg_u128(&mut self, var: pcode::VarNode, val: u128) {
        self.write_trunc(var, val);
        if let Some((_, handler)) =
            unsafe { (*self.reg_handlers.get()).iter_mut().find(|x| x.0 == var.id) }
        {
            handler.write(self);
        }
    }

    #[inline(always)]
    pub fn read_pc(&self) -> u64 {
        // Safety: We ensure that `pc_offset` is valid during construction
        let raw_pc = u64::from_le_bytes(unsafe { self.regs.read_at(self.pc_offset) });
        raw_pc & self.pc_mask
    }

    #[inline(always)]
    pub fn write_pc(&mut self, val: u64) {
        // Safety: We ensure that `pc_offset` is valid during construction
        unsafe { self.regs.write_at(self.pc_offset, (val & self.pc_mask).to_le_bytes()) }
        // Ensure that the block id is reset to avoid copying context after the PC is modified.
        self.block_id = u64::MAX;
        self.block_offset = 0;
    }

    /// Configure the emulator to resume execution at the next instruction (i.e., the current value
    /// of NEXT_PC)
    #[inline(always)]
    pub fn resume_next(&mut self) {
        let next = self.read_var::<u64>(self.arch.reg_next_pc);
        self.write_pc(next);
    }

    #[inline(always)]
    pub fn set_isa_mode(&mut self, mode: u8) {
        if let Some(isa) = self.arch.reg_isa_mode {
            self.write_var(isa, mode);
        }
    }

    #[inline(always)]
    pub fn isa_mode(&self) -> u8 {
        self.arch.reg_isa_mode.map(|var| self.read_var(var)).unwrap_or(0)
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
    /// # Safety
    ///
    /// This function assumes that every statement in `block` is valid.
    pub unsafe fn interpret_block_unchecked(
        &mut self,
        block: &pcode::Block,
        offset: usize,
    ) -> Option<usize> {
        let remaining = block.instructions.get(offset..)?;
        for inst in remaining {
            unsafe { self.interpret_unchecked(inst) };
            if self.exception.code != ExceptionCode::None as u32 {
                return block.instructions.element_offset(inst);
            }
        }
        None
    }

    /// # Safety
    ///
    /// This function assumes that `stmt` is valid.
    #[inline]
    pub unsafe fn interpret_unchecked(&mut self, stmt: &pcode::Instruction) {
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
                self.push_shadow_stack(fallthrough);
                Target::External(target)
            }
            BlockExit::Return { target } => {
                if self.shadow_stack_state != ShadowStackState::Disabled {
                    let target_pc = self.read_dynamic(target).zxt();
                    self.pop_shadow_stack(target_pc);
                }
                Target::External(target)
            }
        }
    }

    #[inline]
    pub fn push_shadow_stack(&mut self, addr: u64) {
        if self.shadow_stack_state != ShadowStackState::Disabled {
            self.force_push_shadow_stack(addr);
        }
    }

    #[inline]
    pub fn force_push_shadow_stack(&mut self, addr: u64) {
        if self.shadow_stack.offset >= SHADOW_STACK_SIZE {
            if self.shadow_stack_state == ShadowStackState::Enabled {
                self.exception.code = ExceptionCode::ShadowStackOverflow as u32;
                self.exception.value = addr;
            }
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
        if self.shadow_stack_state == ShadowStackState::Enabled {
            self.exception.code = ExceptionCode::ShadowStackInvalid as u32;
            self.exception.value = target;
        }
    }

    #[inline]
    pub fn call_hook(&mut self, id: pcode::HookId, addr: u64) {
        // @fixme(Safety): we need a mechanism to ensure that the `hooks` field is never
        // touched by the hook we are calling. (e.g., consider using a `Lens` type?).
        unsafe {
            let hooks = self.trace.hooks.get();
            (&mut *hooks)[id as usize].call(self, addr);
        }
    }

    /// Read a pointer-like argument according to the configured calling convention
    pub fn read_ptr_arg(&mut self, n: usize) -> MemResult<u64> {
        if let Some(&var) = self.arch.call_cov.integers.get(n) {
            return Ok(self.read_dynamic(var.into()).zxt());
        }

        // @fixme: this might not be correct because alignment can be smaller than `ptr_size`
        let ptr_size = self.arch.reg_pc.size as u64;
        let stack_ptr: u64 = self.read_dynamic(self.arch.reg_sp.into()).zxt();
        let addr = stack_ptr
            + self.arch.call_cov.stack_offset
            + ptr_size * (n - self.arch.call_cov.integers.len()) as u64;
        if !self.mem.is_regular_region(addr, ptr_size) {
            return Err(crate::mem::MemError::Unmapped);
        }

        let mut buf = [0; 8];
        self.mem.read_bytes(addr, &mut buf[..ptr_size as usize], perm::READ)?;
        Ok(self.arch.bytes_to_pointer(buf))
    }

    pub fn get_block_key(&self, vaddr: u64) -> BlockKey {
        let isa_mode = self.isa_mode() as u64;
        BlockKey { vaddr, isa_mode }
    }

    /// Update pointers used directly in the JIT.
    ///
    /// Safety: This must be called before entering the JIT, but not called from within the JIT.
    // @todo: optimize: this doesn't need to be done every time we enter the JIT.
    pub fn update_jit_context(&mut self) {
        self.jit_ctx.tlb_ptr = self.mem.tlb.as_mut();
        for (dst, src) in self.jit_ctx.tracer_mem.iter_mut().zip(self.trace.storage_ptr()) {
            *dst = src;
        }
        for (dst, hook) in self.jit_ctx.hooks.iter_mut().zip(self.trace.hooks.get_mut()) {
            (dst.fn_ptr, dst.data_ptr) = hook.get_ptr();
        }
    }
}

impl ValueSource for Cpu {
    #[inline(always)]
    fn read_var<R: RegValue>(&self, var: pcode::VarNode) -> R {
        if cfg!(debug_assertions) && var.size as usize != std::mem::size_of::<R>() {
            eprintln!("invalid read to register: {}", var.display(&self.arch.sleigh));
        }
        R::read(&self.regs, var)
    }

    #[inline(always)]
    fn write_var<R: RegValue>(&mut self, var: pcode::VarNode, value: R) {
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

    fn write_var<R: RegValue>(&mut self, var: pcode::VarNode, value: R) {
        unsafe { R::write_unchecked(&mut self.cpu.regs, var, value) }
    }
}

impl<'a> PcodeExecutor for UncheckedExecutor<'a> {
    fn exception(&mut self, code: ExceptionCode, value: u64) {
        self.cpu.exception.code = code as u32;
        self.cpu.exception.value = value;
    }

    fn invalid_instruction(&mut self) {
        self.exception(ExceptionCode::InvalidInstruction, self.cpu.read_pc());
    }

    fn next_instruction(&mut self, addr: u64, _len: u64) {
        self.cpu.write_pc(addr);
        if self.cpu.fuel.remaining == 0 {
            self.cpu.exception.code = ExceptionCode::InstructionLimit as u32;
            self.cpu.exception.value = addr;
            return;
        }
        self.cpu.fuel.remaining -= 1;
    }

    fn load_mem<const N: usize>(&mut self, id: pcode::MemId, addr: u64) -> Option<[u8; N]> {
        match id {
            pcode::RAM_SPACE => match self.cpu.mem.read::<N>(addr, perm::READ) {
                Ok(val) => Some(val),
                Err(err) => {
                    self.exception(ExceptionCode::from_load_error(err), addr);
                    None
                }
            },
            pcode::REGISTER_SPACE => {
                let Some(var) = self.cpu.var_for_offset(addr as u32, N as u8)
                else {
                    self.exception(ExceptionCode::UnmappedRegister, addr);
                    return None;
                };
                Some(self.cpu.read_var(var))
            }
            pcode::RESERVED_SPACE_END.. => {
                let offset = addr as usize;
                let Some(slice) = self.cpu.trace.storage
                    [id as usize - pcode::RESERVED_SPACE_END as usize]
                    .data()
                    .get(offset..offset + N)
                else {
                    self.exception(ExceptionCode::ReadUnmapped, addr);
                    return None;
                };

                let mut value = [0; N];
                value.copy_from_slice(slice);
                Some(value)
            }
        }
    }

    fn store_mem<const N: usize>(
        &mut self,
        id: pcode::MemId,
        addr: u64,
        value: [u8; N],
    ) -> Option<()> {
        match id {
            pcode::RAM_SPACE => {
                if let Err(err) = self.cpu.mem.write(addr, value, perm::WRITE) {
                    self.exception(ExceptionCode::from_store_error(err), addr);
                    return None;
                }
            }
            pcode::REGISTER_SPACE => {
                let Some(var) = self.cpu.var_for_offset(addr as u32, N as u8)
                else {
                    self.exception(ExceptionCode::UnmappedRegister, addr);
                    return None;
                };
                self.cpu.write_var(var, value);
            }
            pcode::RESERVED_SPACE_END.. => {
                let offset = addr as usize;
                let Some(dst) = self.cpu.trace.storage
                    [id as usize - pcode::RESERVED_SPACE_END as usize]
                    .data_mut()
                    .get_mut(offset..offset + N)
                else {
                    self.exception(ExceptionCode::ReadUnmapped, addr);
                    return None;
                };
                dst.copy_from_slice(&value);
            }
        }

        Some(())
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

#[derive(Clone, Default)]
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

impl ValueSource for CpuSnapshot {
    fn write_var<R: RegValue>(&mut self, var: pcode::VarNode, value: R) {
        R::write(&mut self.regs, var, value)
    }

    fn read_var<R: RegValue>(&self, var: pcode::VarNode) -> R {
        R::read(&self.regs, var)
    }
}

impl CpuSnapshot {
    pub fn write_u64(&mut self, var: pcode::VarNode, value: u64) {
        self.regs.write_trunc(var, value);
    }

    pub fn read_u64(&self, var: impl Into<pcode::Value>) -> u64 {
        self.regs.read_dynamic(var.into()).zxt()
    }
}

impl Cpu {
    pub fn snapshot(&self) -> Box<CpuSnapshot> {
        Box::new(CpuSnapshot {
            regs: self.regs.clone(),
            args: self.args,
            shadow_stack: self.shadow_stack.clone(),
            exception: self.exception,
            pending_exception: self.pending_exception,
            icount: self.icount,
            block_id: self.block_id,
            block_offset: self.block_offset,
        })
    }

    pub fn snapshot_into(&self, store: &mut CpuSnapshot) {
        store.regs.clone_from(&self.regs);
        store.args = self.args;
        store.shadow_stack.clone_from(&self.shadow_stack);
        store.exception = self.exception;
        store.pending_exception = self.pending_exception;
        store.icount = self.icount;
        store.block_id = self.block_id;
        store.block_offset = self.block_offset;
    }

    pub fn restore(&mut self, snapshot: &CpuSnapshot) {
        let valid_regs = self.arch.sleigh.num_registers();
        tracing::trace!("restoring: {valid_regs} registers");
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

pub const SHADOW_STACK_SIZE: usize = 0x1000;

#[repr(C, align(16))]
pub struct ShadowStack {
    pub stack: [ShadowStackEntry; SHADOW_STACK_SIZE],
    offset: usize,
}

impl Clone for ShadowStack {
    fn clone(&self) -> Self {
        Self { stack: self.stack, offset: self.offset }
    }

    fn clone_from(&mut self, source: &Self) {
        self.stack[..source.offset].clone_from_slice(&source.stack[..source.offset]);
        self.offset = source.offset;
    }
}

impl Default for ShadowStack {
    fn default() -> Self {
        Self::new()
    }
}

impl ShadowStack {
    pub fn new() -> Self {
        Self { stack: [ShadowStackEntry::default(); SHADOW_STACK_SIZE], offset: 0 }
    }

    #[inline(always)]
    pub fn as_slice(&self) -> &[ShadowStackEntry] {
        // Safety: we always ensure that `self.offset` is in bounds.
        unsafe { self.stack.get_unchecked(..self.offset) }
    }

    #[inline(always)]
    pub fn depth(&self) -> usize {
        self.offset
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

#[derive(Copy, Clone, PartialEq, Eq, Debug)]
pub enum ShadowStackState {
    /// Disable all shadow stack related operations.
    Disabled,
    /// Maintain a shadow stack, but do not check for invalid states.
    Debug,
    /// Enable shadow stack operations, and check for invalid states.
    Enabled,
}

#[repr(C)]
pub struct JitContext {
    pub tlb_ptr: *mut TranslationCache,
    pub tracer_mem: [*mut u8; trace::MAX_TRACER_MEM],
    pub hooks: [trace::HookData; trace::MAX_HOOKS],
}

impl Default for JitContext {
    fn default() -> Self {
        Self::new()
    }
}

impl JitContext {
    pub fn new() -> Self {
        const NULL_HOOK: trace::HookData = trace::HookData::null();

        Self {
            tlb_ptr: std::ptr::null_mut(),
            tracer_mem: [std::ptr::null_mut(); trace::MAX_TRACER_MEM],
            hooks: [NULL_HOOK; trace::MAX_HOOKS],
        }
    }
}
