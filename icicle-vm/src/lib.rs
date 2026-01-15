mod builder;
pub mod debug;
pub mod elf_dump;
pub mod env;
pub mod hw;
pub mod injector;
pub mod msp430;

#[cfg(test)]
mod tests;

pub use icicle_cpu as cpu;
pub use icicle_cpu::VmExit;
pub use icicle_linux as linux;

pub use crate::{
    builder::{BuildError, build, build_with_path, sleigh_init, x86},
    injector::{CodeInjector, InjectorRef},
};
pub use icicle_cpu::BlockTable;

use std::{
    collections::{BTreeMap, HashSet},
    rc::Rc,
};

use icicle_cpu::{
    BlockKey, Cpu, CpuSnapshot, Environment, Exception, ExceptionCode, InternalError, ValueSource,
    lifter::{self, DecodeError, Target, count_instructions},
    mem,
};
use pcode::PcodeDisplay;

use crate::{cpu::EnvironmentAny, injector::CodeInjectorAny};

const TRACE_EXEC: bool = false;

pub struct Vm {
    pub cpu: Box<Cpu>,
    pub env: Box<dyn EnvironmentAny>,
    pub lifter: lifter::BlockLifter,
    pub icount_limit: u64,
    pub next_timer: u64,
    pub interrupt_flag: std::sync::Arc<std::sync::atomic::AtomicBool>,
    pub code: BlockTable,
    pub jit: icicle_jit::JIT,
    pub enable_jit: bool,
    pub enable_recompilation: bool,
    prev_isa_mode: u8,

    /// The number of new blocks that have been compiled since the last full recompilation step.
    pub compiled_blocks: u64,

    injectors: Vec<Box<dyn CodeInjectorAny>>,

    /// The last time the JIT was recompiled.
    last_recompile: std::time::Instant,

    /// The offset to recompile from for block chaining.
    recompile_offset: usize,

    /// Snapshots at different icounts for reverse execution.
    snapshots: BTreeMap<u64, Rc<Snapshot>>,
}

impl Drop for Vm {
    fn drop(&mut self) {
        // Safety: After the Vm instance is destroyed there is no way to access the JIT code.
        unsafe { self.jit.reset() }
    }
}

impl Vm {
    pub fn new(cpu: Box<Cpu>, lifter: lifter::BlockLifter) -> Self {
        let jit = icicle_jit::JIT::new(&cpu);
        Self {
            cpu,
            env: Box::new(()),
            lifter,
            injectors: Vec::new(),
            icount_limit: u64::MAX,
            next_timer: 0,
            interrupt_flag: std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false)),
            code: BlockTable::default(),
            jit,
            enable_jit: true,
            enable_recompilation: true,
            prev_isa_mode: u8::MAX,

            compiled_blocks: 0,
            last_recompile: std::time::Instant::now(),
            recompile_offset: 0,
            snapshots: BTreeMap::new(),
        }
    }

    /// Set the current execution environment for the VM.
    pub fn set_env(&mut self, env: impl Environment + 'static) {
        self.env = Box::new(env)
    }

    /// Gets a reference to the execution environment managed by the VM.
    pub fn env_ref<T: Environment + 'static>(&self) -> Option<&T> {
        self.env.as_any().downcast_ref::<T>()
    }

    /// Gets a mutable reference to the execution environment managed by the VM.
    pub fn env_mut<T: Environment + 'static>(&mut self) -> Option<&mut T> {
        self.env.as_mut_any().downcast_mut::<T>()
    }

    /// Registers a [CodeInjector] in the VM which is invoked whenever the emulator lifts a new
    /// block of code.
    ///
    /// Returns a reference that can be later used to obtain mutable access to the injector using
    /// `get_injector_mut`.
    ///
    /// Note: the injector is only executed on newly lifted blocks.
    pub fn add_injector<C>(&mut self, injector: C) -> InjectorRef
    where
        C: CodeInjector + 'static,
    {
        // @todo: consider running the injector over all current blocks.
        let injector_id = self.injectors.len();
        self.injectors.push(Box::new(injector));
        injector_id
    }

    /// Gets a mutable reference previously registered injector using `id`.
    ///
    /// Note: Be wary of changing the behavior of the injector, sine it will _not_ re-executed on
    /// existing blocks.
    pub fn get_injector_mut<C>(&mut self, id: InjectorRef) -> Option<&mut C>
    where
        C: CodeInjector + 'static,
    {
        self.injectors[id].as_mut_any().downcast_mut::<C>()
    }

    /// Registers a function `hook` to called before the instruction at `addr` is executed.
    pub fn hook_address(&mut self, addr: u64, hook: impl FnMut(&mut Cpu, u64) + 'static) {
        let hook_id = self.cpu.add_hook(hook);
        injector::register_instruction_hook_injector(self, vec![addr], hook_id);
    }

    /// Registers a function `hook` that called whenever any of the addresses in `addrs` are about
    /// to be executed.
    pub fn hook_many_addresses(
        &mut self,
        addrs: &[u64],
        hook: impl FnMut(&mut Cpu, u64) + 'static,
    ) {
        let hook_id = self.cpu.add_hook(hook);
        injector::register_instruction_hook_injector(self, addrs.into(), hook_id);
    }

    /// Registers an injector that is called whenever the p-code operation `name` is translated.
    pub fn add_op_injector(
        &mut self,
        name: &str,
        injector: impl lifter::PcodeOpInjector + Sized + 'static,
    ) -> bool {
        let idx = match self.cpu.arch.sleigh.get_userop(name) {
            Some(idx) => idx,
            None => return false,
        };
        self.lifter.op_injectors.insert(idx, Box::new(injector));
        true
    }

    /// Runs the VM until it encounters an exit condition.
    pub fn run(&mut self) -> VmExit {
        if self.should_recompile() && self.enable_recompilation {
            self.recompile();
        }

        if self.cpu.block_id == u64::MAX {
            if let Some((block, _)) = self.get_current_block() {
                self.cpu.block_id = block;
                self.cpu.block_offset = 0;
            }
        }

        self.update_timer();
        loop {
            if let Some(exception) = self.cpu.pending_exception.take() {
                self.cpu.exception = exception;
                match self.handle_exception() {
                    VmExit::Running => {}
                    exit => return exit,
                }
            }

            let instructions_to_exec = self.next_timer.saturating_sub(self.cpu.icount);
            if instructions_to_exec > 0 {
                self.cpu.update_fuel(instructions_to_exec);

                self.run_block_jit();

                // At the beginning of a block we might decide that we need to switch to the
                // interpreter. This happens if there is not enough fuel, or a breakpoint is set
                // inside the block.
                if self.cpu.exception
                    == (ExceptionCode::InternalError, InternalError::SwitchToInterpreter).into()
                {
                    self.run_block_interpreter();
                }

                // Clear fuel so `icount` is correct.
                self.cpu.update_fuel(0);
            }
            else {
                self.cpu.exception.code = ExceptionCode::InstructionLimit as u32;
            }

            match self.handle_exception() {
                VmExit::Running => {}
                exit => return exit,
            }
        }
    }

    pub(crate) fn get_block_key(&self, vaddr: u64) -> BlockKey {
        let isa_mode = self.cpu.isa_mode() as u64;
        BlockKey { vaddr, isa_mode }
    }

    fn handle_exception(&mut self) -> VmExit {
        if let Some(exit) = self.env.handle_exception(&mut self.cpu) {
            return exit;
        }

        let code = ExceptionCode::from_u32(self.cpu.exception.code);
        tracing::trace!("{code:?}: icount={}, next_timer={}", self.cpu.icount, self.next_timer);
        match code {
            ExceptionCode::None | ExceptionCode::InstructionLimit => {
                if self.interrupt_flag.load(std::sync::atomic::Ordering::Relaxed) {
                    return VmExit::Interrupted;
                }
                if self.cpu.icount >= self.icount_limit {
                    return VmExit::InstructionLimit;
                }
                if self.code.breakpoints.contains(&self.cpu.read_pc()) {
                    return VmExit::Breakpoint;
                }
                self.update_timer();
                VmExit::Running
            }
            ExceptionCode::SoftwareBreakpoint => VmExit::Breakpoint,

            ExceptionCode::ExternalAddr => self.handle_external_address(self.cpu.exception.value),
            ExceptionCode::CodeNotTranslated => self.handle_code_not_translated(),
            ExceptionCode::UnimplementedOp => self.handle_unimplemented_op(),
            ExceptionCode::ShadowStackInvalid | ExceptionCode::ShadowStackOverflow => {
                // The block offset is wrong on shadow stack errors so fix it here.
                self.cpu.block_offset =
                    self.code.blocks[self.cpu.block_id as usize].pcode.instructions.len() as u64;
                VmExit::UnhandledException((code, self.cpu.exception.value))
            }
            ExceptionCode::Halt | ExceptionCode::Sleep => VmExit::Halt,
            ExceptionCode::OutOfMemory => VmExit::OutOfMemory,
            code => VmExit::UnhandledException((code, self.cpu.exception.value)),
        }
    }

    fn handle_external_address(&mut self, addr: u64) -> VmExit {
        self.cpu.write_pc(addr);

        let key = self.get_block_key(addr);
        match self.code.map.get(&key) {
            Some(group) => {
                self.cpu.block_id = group.blocks.0 as u64;
                self.cpu.block_offset = 0;
                VmExit::Running
            }
            None => self.handle_code_not_translated(),
        }
    }

    #[cold]
    fn handle_code_not_translated(&mut self) -> VmExit {
        let pc = self.cpu.read_pc();
        // Check for internal errors (e.g. if code map is invalid).
        let key = self.get_block_key(pc);
        if self.code.map.contains_key(&key) {
            tracing::error!(
                "Internal error: `self.code.map` is invalid, \
                        expected block at {key:x?} to be missing",
            );
            return VmExit::UnhandledException((
                ExceptionCode::InternalError,
                InternalError::CorruptedBlockMap as u64,
            ));
        }

        match self.lift(pc) {
            Ok(group) => {
                self.cpu.block_id = group.blocks.0 as u64;
                self.cpu.block_offset = 0;
                VmExit::Running
            }
            Err(e) => {
                tracing::trace!("DecodeError at {pc:#x}: {e:?}");
                self.cpu.exception = cpu::Exception::new(ExceptionCode::from(e), pc);
                self.cpu.block_id = u64::MAX;
                if self.cpu.icount >= self.icount_limit {
                    return VmExit::InstructionLimit;
                }
                self.handle_exception()
            }
        }
    }

    /// Handles the case where we encounter an unhandled user-defined pcode operation or unsupported
    /// pcode operation during execution.
    ///
    /// Note: Handlers for many of the commonly used operations are mapped in
    /// icicle-cpu/src/exec/helpers.rs.
    #[cold]
    fn handle_unimplemented_op(&mut self) -> VmExit {
        if let Some(stmt) = self
            .code
            .blocks
            .get(self.cpu.block_id as usize)
            .and_then(|block| block.pcode.instructions.get(self.cpu.block_offset as usize))
        {
            tracing::error!(
                "[{:#0x}] unknown pcode operation: {}",
                self.cpu.read_pc(),
                stmt.display(&self.cpu.arch.sleigh)
            );
        }
        VmExit::UnhandledException((ExceptionCode::UnimplementedOp, self.cpu.exception.value))
    }

    #[cold]
    #[inline(never)]
    fn corrupted_block_map(&mut self, id: u64) {
        self.cpu.exception.code = ExceptionCode::InternalError as u32;
        self.cpu.exception.value = InternalError::CorruptedBlockMap as u64;
        let pc = self.cpu.read_pc();
        eprintln!(
            "Block map corrupted at: pc={pc:#x} id={id}\n{}",
            std::backtrace::Backtrace::force_capture()
        );
    }

    fn update_timer(&mut self) {
        /// The number of instructions to wait before checking `vm.interrupt_flag`. Should be set
        /// quite high since it causes a full VM exit to check.
        #[cfg(debug_assertions)]
        const CHECK_FOR_INTERRUPT_FLAG_TIMER: u64 = 0x1_0000;
        #[cfg(not(debug_assertions))]
        const CHECK_FOR_INTERRUPT_FLAG_TIMER: u64 = 0x10_0000;

        let user_exit = self.icount_limit;
        let env_exit = self.env.next_timer();
        self.next_timer =
            user_exit.min(env_exit).min(CHECK_FOR_INTERRUPT_FLAG_TIMER + self.cpu.icount);
    }

    #[cold]
    fn run_block_interpreter(&mut self) {
        self.cpu.exception.clear();

        let (mut block_id, mut offset) = match self.get_current_block() {
            Some(value) => value,
            None => {
                self.cpu.exception.code = ExceptionCode::CodeNotTranslated as u32;
                self.cpu.exception.value = self.cpu.read_pc();
                return;
            }
        };
        if TRACE_EXEC {
            print_interpreter_enter(self, block_id, offset);
        }
        self.cpu.block_offset = 0;
        let Some(mut block) = self.code.blocks.get(block_id as usize)
        else {
            self.corrupted_block_map(block_id);
            return;
        };

        // The interpreter decrements the fuel counter at the start of each instruction (i.e., at
        // the `Op::InstructionMarker` and when the fuel counter reaches zero, the interpreter stops
        // at the next instruction marker.
        //
        // There are two corner cases to consider here:
        // The first is when we enter the interpreter at the start of a block that has pcode
        // instructions injected before the first instruction marker. In this case we should not
        // decrement the fuel counter before executing the first instruction marker.
        // However, there are cases where we enter the interpreter in the middle of a block (e.g.,
        // resuming after a fault). To account for the missing instruction marker, we need to
        // decrement the fuel counter here.
        let first_imark_offset =
            block.pcode.first_addr().and_then(|addr| block.pcode.offset_of(addr)).unwrap_or(0);
        if offset >= first_imark_offset as u64 {
            if let Some(inst) = block.pcode.instructions.get(offset as usize) {
                if !matches!(inst.op, pcode::Op::InstructionMarker) {
                    self.cpu.fuel.remaining = self.cpu.fuel.remaining.saturating_sub(1);
                }
            }
        }

        loop {
            if block.has_breakpoint() {
                // Determine how many steps to execute before we hit the first breakpoint in this
                // block.
                for (i, inst) in block.pcode.instructions[offset as usize..]
                    .iter()
                    .filter(|inst| matches!(inst.op, pcode::Op::InstructionMarker))
                    .enumerate()
                {
                    if self.code.breakpoints.contains(&inst.inputs.first().as_u64()) {
                        self.cpu.update_fuel(self.cpu.fuel.remaining.min(i as u64));
                        break;
                    }
                }
            }

            // Safety: we validate each block as part of `lift`.
            unsafe {
                if let Some(offset) =
                    self.cpu.interpret_block_unchecked(&block.pcode, offset as usize)
                {
                    // We exited early due to an exception, so keep track of the offset where the
                    // CPU exited from.
                    self.cpu.block_id = block_id;
                    self.cpu.block_offset = offset as u64;
                    break;
                }
            }

            match self.cpu.block_exit(block.exit) {
                Target::Internal(id) => {
                    block_id = id as u64;
                    offset = 0;
                }
                Target::External(addr) => {
                    let addr: u64 = self.cpu.read_dynamic(addr).zxt();
                    self.cpu.write_pc(addr);

                    match self.code.map.get(&self.get_block_key(addr)) {
                        Some(group) => {
                            self.cpu.block_id = group.blocks.0 as u64;
                            self.cpu.block_offset = 0;

                            if self.enable_jit {
                                // We are now at the start of a new block, break out of the
                                // interpreter and try and re-enter the JIT.
                                break;
                            }
                            else {
                                block_id = group.blocks.0 as u64;
                                offset = 0;
                            }
                        }
                        None => {
                            self.cpu.block_id = block_id;
                            self.cpu.exception.code = ExceptionCode::CodeNotTranslated as u32;
                            self.cpu.exception.value = addr;
                            break;
                        }
                    }
                }
                Target::Invalid(e, addr) => {
                    tracing::debug!(
                        "End of block has invalid target\n{}\n{e:?} @ {addr:#x}, PC: {:#x}",
                        debug::debug_addr(self, block.start).unwrap(),
                        self.cpu.read_pc()
                    );

                    // Synchronize the RIP (this is necessary if an invalid instruction occurs in
                    // the middle of a block).
                    self.cpu.write_pc(addr);

                    // Since the invalid instruction does not have a marker, we need to check if we
                    // ran out of fuel and raise the appropriate exception first. The next step will
                    // raise the actual exception related to the DecodeError.
                    let code = if self.cpu.fuel.remaining == 0 {
                        ExceptionCode::InstructionLimit
                    }
                    else {
                        ExceptionCode::from(e)
                    };
                    self.cpu.exception = Exception::new(code, addr);
                    break;
                }
            }

            block = match self.code.blocks.get(block_id as usize) {
                Some(block) => block,
                None => return self.corrupted_block_map(block_id),
            };
        }

        if TRACE_EXEC {
            print_interpreter_exit(self);
        }
    }

    #[inline]
    fn can_enter_jit(&mut self) -> bool {
        // Avoid entering the JIT if: the jit is disabled, we are in the middle of a block, or we
        // are at the start of an internal block.
        self.cpu.block_offset == 0
            && self.code.blocks.get(self.cpu.block_id as usize).map_or(false, |x| x.entry.is_some())
            && self.enable_jit
    }

    fn run_block_jit(&mut self) {
        if !self.can_enter_jit() {
            self.cpu.exception =
                (ExceptionCode::InternalError, InternalError::SwitchToInterpreter).into();
            return;
        }

        self.cpu.exception.clear();

        self.cpu.update_jit_context();

        let mut next_addr = self.cpu.read_pc();
        if TRACE_EXEC {
            print_jit_enter(self, next_addr);
        }
        while self.cpu.exception.code == ExceptionCode::None as u32 {
            let jit_func = match self.jit.lookup_fast(next_addr) {
                Some(func) => {
                    self.jit.jit_hit += 1;
                    func
                }
                None => self.get_or_compile_jit_block(next_addr),
            };

            // Safety: the JIT must generate code that is safe to execute.
            unsafe {
                next_addr = jit_func(self.cpu.as_mut(), next_addr);
            }
        }

        if self.cpu.block_offset != 0 {
            self.jit_exit_before_end_of_block();
        }

        if TRACE_EXEC {
            print_jit_exit(self, next_addr);
        }
    }

    #[cold]
    fn jit_exit_before_end_of_block(&mut self) {
        // Since we exited before we reached the end of a block, we need to check how many
        // instructions we executed in the block to adjust the consumed fuel.
        let block = match self.code.blocks.get(self.cpu.block_id as usize) {
            Some(block) => block,
            None => return self.corrupted_block_map(self.cpu.block_id),
        };
        let executed_instructions =
            count_instructions(&block.pcode.instructions[..self.cpu.block_offset as usize]);
        self.cpu.fuel.remaining -= executed_instructions as u64;
    }

    /// Return the currently active block and offset. If no block is active, retrieve the next block
    /// based on the current program counter.
    pub fn get_current_block(&self) -> Option<(u64, u64)> {
        match self.cpu.block_id != u64::MAX {
            true => Some((self.cpu.block_id, self.cpu.block_offset)),
            false => {
                let key = self.get_block_key(self.cpu.read_pc());
                let id = self.code.map.get(&key).map(|group| group.blocks.0)?;
                Some((id as u64, 0))
            }
        }
    }

    pub fn reset(&mut self) {
        self.cpu.reset();
        self.cpu.mem.clear();
        self.code.flush_code();
        if self.enable_jit {
            self.jit.clear();
        }
        self.prev_isa_mode = u8::MAX;
    }

    pub fn get_disasm(&self, addr: u64) -> Option<&str> {
        self.code.disasm.get(&addr).map(|s| s.as_str())
    }

    pub fn get_block_info(&self, addr: u64) -> Option<cpu::BlockInfoRef<'_>> {
        let key = self.get_block_key(addr);
        self.code.get_info(key)
    }

    pub fn lift(&mut self, addr: u64) -> Result<lifter::BlockGroup, DecodeError> {
        self.update_context();

        let mut ctx = lifter::Context::new(&mut *self.cpu, &mut self.code, addr);
        let group = self.lifter.lift_block(&mut ctx)?;

        // Add breakpoints to the lifted code.
        if self.code.breakpoints.len() > 0 {
            for block in &mut self.code.blocks[group.range()] {
                for inst in &block.pcode.instructions {
                    if matches!(inst.op, pcode::Op::InstructionMarker)
                        && self.code.breakpoints.contains(&inst.inputs.first().as_u64())
                    {
                        block.breakpoints += 1;
                    }
                }
            }
        }

        for injector in &mut self.injectors {
            injector.inject(&mut self.cpu, &group, &mut self.code);
        }

        self.code.modified.extend(group.range());

        // Validate that all modified code is valid, and invalidate any jitted code that is now
        // modified.
        for id in self.code.modified.drain() {
            let block = &mut self.code.blocks[id];
            for inst in &block.pcode.instructions {
                if !self.cpu.validate(inst) {
                    panic!(
                        "block {:#x} contains invalid instruction {} ({:?})",
                        block.start,
                        inst.display(&self.cpu.arch.sleigh),
                        inst,
                    );
                }
            }
            self.jit.invalidate(id);
        }

        let key = self.get_block_key(addr);
        self.code.map.insert(key, group);

        tracing::trace!(
            "lifted: {key:x?} => {}",
            group.to_string(&self.code.blocks, &self.cpu.arch.sleigh, false).unwrap()
        );

        Ok(group)
    }

    fn update_context(&mut self) {
        // Use the context from the last block.
        if let Some(block) = self.code.blocks.get(self.cpu.block_id as usize) {
            self.lifter.set_context(block.context);
        }

        // Check for ISA mode changes.
        let isa_mode = self.cpu.isa_mode();
        if self.prev_isa_mode != isa_mode {
            tracing::debug!("ISA mode change {} -> {isa_mode}", self.prev_isa_mode);
            self.jit.clear_fast_lookup();
            self.prev_isa_mode = isa_mode;
            match self.cpu.arch.isa_mode_context.get(isa_mode as usize) {
                Some(ctx) => self.lifter.set_context(*ctx),
                None => self.invalid_isa_mode(),
            }
        }
    }

    #[inline(never)]
    #[cold]
    fn invalid_isa_mode(&mut self) {
        tracing::error!("Unknown or unsupported ISA mode: {}", self.prev_isa_mode);
        self.cpu.exception.code = ExceptionCode::InternalError as u32;
        self.cpu.exception.value = InternalError::CorruptedBlockMap as u64;
    }

    #[inline(never)]
    #[cold]
    fn get_or_compile_jit_block(&mut self, addr: u64) -> icicle_jit::JitFunction {
        // Try to find the block corresponding to the target address.
        let key = self.get_block_key(addr);
        let group = match self.code.map.get(&key) {
            Some(group) => group,
            None => return icicle_jit::runtime::address_not_translated,
        };

        if self.prev_isa_mode != key.isa_mode as u8 {
            // ISA mode has changed so we need to prevent addresses from the previous ISA mode from
            // being included in the fast look up table (which doesn't check the ISA mode).
            self.prev_isa_mode = key.isa_mode as u8;
            self.jit.clear_fast_lookup();
        }

        self.cpu.block_id = group.blocks.0 as u64;
        self.jit.jit_miss += 1;

        // Check if there is a breakpoint set on any of the blocks in the group.
        for block in &self.code.blocks[group.range()] {
            if block.breakpoints > 0 {
                return icicle_jit::runtime::switch_to_interpreter;
            }
        }

        // See if we already have compile the block, but it was inactive.
        if let Some(&fn_ptr) = self.jit.entry_points.get(&addr) {
            self.jit.add_fast_lookup(addr, fn_ptr);
            return fn_ptr;
        }

        // The block needs to be compiled
        self.compiled_blocks += 1;
        tracing::trace!("compile_block: key={key:x?} ({} new)", self.compiled_blocks);
        let blocks = group.range().collect::<Vec<_>>();
        let target = icicle_jit::CompilationTarget::new(&self.code.blocks, &blocks);
        if let Err(e) = self.jit.compile(&target) {
            tracing::error!("JIT compilation failed: {:?}", e);
            return icicle_jit::runtime::jit_compilation_error;
        }

        let fn_ptr = self.jit.entry_points[&addr];
        self.jit.add_fast_lookup(addr, fn_ptr);

        fn_ptr
    }

    pub fn should_recompile(&self) -> bool {
        self.compiled_blocks > 10 && self.last_recompile.elapsed().as_secs() > 60
    }

    /// Attempt to recompile all code in the code-cache, potentially improving performance by
    /// increasing cache locality, and allowing for block-chaining.
    #[inline(never)]
    #[cold]
    pub fn recompile(&mut self) {
        let start = std::time::Instant::now();

        if self.jit.should_purge() {
            // Safety: The only way functions from the JIT can be executed is through the Vm struct
            // which we have a unique reference to.
            unsafe { self.jit.reset() }
            self.recompile_offset = 0;
        }

        let mut visited: HashSet<usize> = HashSet::new();

        // Attempt to group blocks that share direct jumps.
        //
        // @fixme: currently the group is done based on the order the blocks were first hit, this is
        // not optimal.
        let mut stack = vec![];
        let mut compilation_group = vec![];

        // @fixme: this is broken if a jump performs a context switch.
        let isa_mode = self.cpu.isa_mode() as u64;

        for (i, block) in self.code.blocks.iter().enumerate().skip(self.recompile_offset) {
            let entry = match block.entry {
                Some(entry) => entry,
                // Internal blocks are only accessible from another block that has a valid entry
                // address. We can skip them here, since they will be compiled with the entry block.
                None => continue,
            };

            stack.push((i, block));
            while let Some((id, block)) = stack.pop() {
                // Avoid compiling blocks that are compiled as part of other block groups.
                if !visited.insert(id) || id < self.recompile_offset {
                    continue;
                }
                compilation_group.push(id);

                let mut add_target = |target: &lifter::Target| match target {
                    Target::Internal(id) => stack.push((*id, &self.code.blocks[*id])),
                    Target::External(pcode::Value::Const(addr, _)) => {
                        let key = BlockKey { vaddr: *addr, isa_mode };
                        if let Some(group) = self.code.map.get(&key) {
                            let entry_block = group.blocks.0;
                            stack.push((entry_block, &self.code.blocks[entry_block]));
                        }
                    }
                    _ => {}
                };

                match block.exit {
                    lifter::BlockExit::Jump { target } => add_target(&target),
                    lifter::BlockExit::Branch { target, fallthrough, .. } => {
                        add_target(&target);
                        add_target(&fallthrough);
                    }
                    lifter::BlockExit::Call { .. } | lifter::BlockExit::Return { .. } => {}
                }
            }

            if !compilation_group.is_empty() {
                tracing::trace!("[{entry:#x}] compiled: {compilation_group:?}");
                let target =
                    icicle_jit::CompilationTarget::new(&self.code.blocks, &compilation_group);
                if let Err(e) = self.jit.compile(&target) {
                    tracing::error!("JIT compilation failed: {:?}", e);
                }
                compilation_group.clear();
            }
        }

        tracing::info!(
            "Recompiled {} blocks in {:?} ({} entrypoints now dead)",
            self.code.blocks.len() - self.recompile_offset,
            start.elapsed(),
            self.jit.dead,
        );

        self.compiled_blocks = 0;
        self.recompile_offset = self.code.blocks.len();
        self.last_recompile = std::time::Instant::now();
    }
}

#[inline(never)]
fn print_interpreter_enter(vm: &mut Vm, block_id: u64, offset: u64) {
    let pcode = &vm.code.blocks[block_id as usize].pcode;
    let addr = pcode.address_of(offset as usize).unwrap_or(0);
    eprintln!(
        "interpreter_enter: next_addr={addr:#x}, block.id={block_id}, block.offset={offset}\n{}",
        pcode.display(&vm.cpu.arch.sleigh)
    );
}

fn print_interpreter_exit(vm: &mut Vm) {
    eprintln!(
        "interpreter_exit: (code={:?}, value={:x}), block={}, offset={}, fuel={}, icount={}",
        ExceptionCode::from_u32(vm.cpu.exception.code),
        vm.cpu.exception.value,
        vm.cpu.block_id,
        vm.cpu.block_offset,
        vm.cpu.fuel.remaining,
        vm.cpu.icount(),
    );
}

#[inline(never)]
fn print_jit_enter(vm: &mut Vm, next_addr: u64) {
    eprintln!(
        "jit_enter: next_addr={next_addr:#x}, fuel={}, icount={}",
        vm.cpu.fuel.remaining,
        vm.cpu.icount()
    );
}

#[inline(never)]
fn print_jit_exit(vm: &mut Vm, next_addr: u64) {
    eprintln!(
        "jit_exit: (code={:?}, value={:x}), block={}, offset={}, next_addr={next_addr:#x}, fuel={}, icount={}",
        ExceptionCode::from_u32(vm.cpu.exception.code),
        vm.cpu.exception.value,
        vm.cpu.block_id,
        vm.cpu.block_offset,
        vm.cpu.fuel.remaining,
        vm.cpu.icount(),
    );
}

// Helper functions
impl Vm {
    pub fn step(&mut self, steps: u64) -> VmExit {
        let old_limit = self.icount_limit;

        self.icount_limit = self.cpu.icount.saturating_add(steps);
        let exit = self.run();

        self.icount_limit = old_limit;
        exit
    }

    /// Step backward `count` instructions by first restoring a nearby snapshot then continuing
    /// execution until reaching correct address
    pub fn step_back(&mut self, count: u64) -> Option<VmExit> {
        match self.cpu.icount().checked_sub(count) {
            Some(target) => self.goto_icount(target),
            None => None,
        }
    }

    /// Goto a specific icount, stepping either backwards or fowards as required.
    pub fn goto_icount(&mut self, target: u64) -> Option<VmExit> {
        let old_limit = self.icount_limit;

        // Check if we need to restore a snapshot
        if self.cpu.icount() > target {
            // Find and restore a snapshot that was created before the target offset
            match self.snapshots.range(..target).rev().next() {
                Some((_, snapshot)) => self.restore(&snapshot.clone()),
                None => return None,
            }
            tracing::debug!("Restored snapshot icount={} and stepping forward", self.cpu.icount());
        }

        let steps = target - self.cpu.icount();

        // If the snapshot was far away, create a new snapshot closer to improve performance if we
        // need to step back again.
        if steps > 500 {
            self.icount_limit = target - 100;
            tracing::debug!("Creating nearby snapshot at icount={}", self.icount_limit);
            match self.run() {
                VmExit::InstructionLimit => {}
                other => {
                    tracing::warn!("Hit unexpected exit when stepping backwards: {other:?}");
                    return Some(other);
                }
            }
            self.save_snapshot();
        }

        // Execute forward until we reach the target address
        self.icount_limit = target;
        let exit = self.run();
        self.icount_limit = old_limit;

        Some(exit)
    }

    pub fn run_until(&mut self, addr: u64) -> VmExit {
        let added_bp = self.add_breakpoint(addr);
        let exit = self.run();
        if added_bp {
            self.remove_breakpoint(addr);
        }
        exit
    }

    /// Adds a breakpoint at `addr`.
    ///
    /// Returns a boolean representing whether a new breakpoint was added.
    pub fn add_breakpoint(&mut self, addr: u64) -> bool {
        if !self.code.breakpoints.insert(addr) {
            // There is already a breakpoint at the target address.
            return false;
        }

        for block in self.code.blocks.iter_mut().filter(|x| x.start <= addr && addr < x.end) {
            block.breakpoints += 1;
            // Make sure that any JIT blocks containing this address are removed from fast lookup.
            self.jit.remove_fast_lookup(block.start);
        }

        true
    }

    /// Removes the breakpoint at `addr`.
    ///
    /// Returns a boolean representing whether a breakpoint was remove.
    pub fn remove_breakpoint(&mut self, addr: u64) -> bool {
        if !self.code.breakpoints.remove(&addr) {
            // The breakpoint we are trying to remove does not exist.
            return false;
        }

        for block in self.code.blocks.iter_mut().filter(|x| x.start <= addr && addr < x.end) {
            block.breakpoints -= 1;
        }

        true
    }

    pub fn toggle_breakpoint(&mut self, addr: u64) -> bool {
        if self.add_breakpoint(addr) {
            return true;
        }
        self.remove_breakpoint(addr);
        false
    }

    pub fn get_callstack(&self) -> Vec<u64> {
        let pc = self.cpu.read_pc();
        self.cpu.shadow_stack.as_slice().iter().map(|entry| entry.addr).chain(Some(pc)).collect()
    }

    /// Like `get_callstack` returns callstack based on heuristics or debug info if shadow stack is
    /// not available.
    pub fn get_debug_callstack(&mut self) -> Vec<u64> {
        if self.cpu.enable_shadow_stack {
            return self.get_callstack();
        }

        // Use experimental backtrace collector using debug info or frame pointer.
        // @fixme: we should prefer frame pointer base backtrace if available.
        debug::callstack_from_debug_info(self)
            .or_else(|| debug::callstack_from_frame_pointer(self))
            .unwrap_or_else(|| vec![self.cpu.read_pc()])
    }

    pub fn save_snapshot(&mut self) {
        let snapshot = Rc::new(self.snapshot());
        self.snapshots.insert(self.cpu.icount(), snapshot);
    }

    pub fn snapshot(&mut self) -> Snapshot {
        Snapshot {
            cpu: self.cpu.snapshot(),
            mem: self.cpu.mem.snapshot(),
            env: self.env.snapshot(),
        }
    }

    pub fn restore(&mut self, snapshot: &Snapshot) {
        self.cpu.restore(&snapshot.cpu);
        self.cpu.mem.restore(snapshot.mem.clone());
        self.env.restore(&snapshot.env);
        self.update_context();

        tracing::trace!(
            "VM state restored: pc = {:#x}, block.id={}, block.offset={}",
            self.cpu.read_pc(),
            self.cpu.block_id,
            self.cpu.block_offset
        );
    }
}

pub struct Snapshot {
    pub cpu: Box<CpuSnapshot>,
    pub mem: mem::Snapshot,
    pub env: Box<dyn std::any::Any>,
}
