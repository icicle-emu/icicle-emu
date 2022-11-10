#![feature(backtrace)]

mod builder;
pub mod debug;
pub mod elf_dump;
pub mod env;
pub mod hw;
pub mod injector;

pub use builder::{build, build_sleigh_for, x86, BuildError};
pub use icicle_cpu as cpu;
pub use icicle_cpu::VmExit;
pub use icicle_linux as linux;

use std::collections::HashSet;

use icicle_cpu::{
    exec::helpers,
    lifter::{self, count_instructions, Target},
    mem, BlockKey, BlockTable, Cpu, CpuSnapshot, Environment, ExceptionCode, InternalError,
    ValueSource,
};
use pcode::PcodeDisplay;

pub use crate::injector::CodeInjector;

/// The number of instructions to wait before checking `vm.interrupt_flag`. Should be set quite high
/// since it causes a full VM exit to check.
#[cfg(debug_assertions)]
const CHECK_FOR_INTERRUPT_FLAG_TIMER: u64 = 0x1_0000;
#[cfg(not(debug_assertions))]
const CHECK_FOR_INTERRUPT_FLAG_TIMER: u64 = 0x10_0000;

const PRINT_EXITS: bool = false;

pub struct Vm {
    pub cpu: Box<Cpu>,
    pub env: Box<dyn Environment>,
    pub lifter: lifter::BlockLifter,
    pub injectors: Vec<Box<dyn CodeInjector>>,
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

    /// The last time the JIT was recompiled.
    last_recompile: std::time::Instant,

    /// The offset to recompile from for block chaining.
    recompile_offset: usize,

    /// Cached pointers that are used inside of the JIT
    jit_ctx: icicle_jit::VmCtx,
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
            jit_ctx: icicle_jit::VmCtx::new(),
        }
    }

    pub fn add_injector(&mut self, injector: Box<dyn CodeInjector>) -> usize {
        // @todo: consider running the injector over all current blocks.
        let injector_id = self.injectors.len();
        self.injectors.push(injector);
        injector_id
    }

    pub fn hook_address(&mut self, addr: u64, hook: impl FnMut(&mut Cpu, u64) + 'static) {
        let hook_id = self.cpu.add_hook(Box::new(hook));
        injector::register_instruction_hook_injector(self, addr, hook_id);
    }

    pub fn register_helpers(&mut self, helpers: &[(&str, helpers::PcodeOpHelper)]) {
        for &(name, func) in helpers {
            let id = match self.cpu.arch.sleigh.get_userop(name) {
                Some(id) => id,
                None => continue,
            };
            self.cpu.set_helper(id, func);
        }
    }

    pub fn add_breakpoint(&mut self, addr: u64) -> bool {
        if !self.code.breakpoints.insert(addr) {
            // There is already a breakpoint at the target address.
            return false;
        }

        for block in self.code.blocks.iter_mut().filter(|x| x.start <= addr && addr < x.end) {
            block.breakpoints += 1;
        }

        // Make sure that any JIT blocks containing this address are removed from fast lookup.
        self.jit.remove_fast_lookup(addr);

        true
    }

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
                if self.cpu.exception.code == ExceptionCode::InstructionLimit as u32 {
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

    pub fn get_block_key(&self, vaddr: u64) -> BlockKey {
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
                if self.interrupt_flag.swap(false, std::sync::atomic::Ordering::Relaxed) {
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

            ExceptionCode::ExternalAddr => {
                self.handle_external_addess(self.cpu.exception.value, u64::MAX)
            }
            ExceptionCode::CodeNotTranslated => self.handle_code_not_translated(),
            ExceptionCode::UnimplementedOp => self.handle_unimplemented_op(),
            ExceptionCode::ShadowStackInvalid | ExceptionCode::ShadowStackOverflow => {
                // The block offset is wrong on shadow stack errors so fix it here.
                self.cpu.block_offset =
                    self.code.blocks[self.cpu.block_id as usize].pcode.instructions.len() as u64;
                VmExit::UnhandledException((code, self.cpu.exception.value))
            }
            ExceptionCode::Halt => VmExit::Halt,
            code => VmExit::UnhandledException((code, self.cpu.exception.value)),
        }
    }

    fn handle_external_addess(&mut self, addr: u64, prev_block: u64) -> VmExit {
        self.cpu.write_pc(addr);

        let key = self.get_block_key(addr);
        match self.code.map.get(&key) {
            Some(group) => {
                self.cpu.block_id = group.blocks.0 as u64;
                self.cpu.block_offset = 0;
                VmExit::Running
            }
            None => {
                self.cpu.block_id = prev_block;
                self.handle_code_not_translated()
            }
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
            Some(group) => {
                self.cpu.block_id = group.blocks.0 as u64;
                self.cpu.block_offset = 0;
                VmExit::Running
            }
            None => {
                self.cpu.exception = cpu::Exception::new(ExceptionCode::InvalidInstruction, pc);
                if self.cpu.icount >= self.icount_limit {
                    return VmExit::InstructionLimit;
                }
                self.handle_exception()
            }
        }
    }

    #[cold]
    fn handle_unimplemented_op(&mut self) -> VmExit {
        let block = &self.code.blocks[self.cpu.block_id as usize];
        let stmt = block.pcode.instructions[self.cpu.block_offset as usize];
        tracing::error!(
            "[{:#0x}] unknown pcode operation: {}",
            self.cpu.read_pc(),
            stmt.display(&self.cpu.arch.sleigh)
        );
        VmExit::UnhandledException((ExceptionCode::UnimplementedOp, self.cpu.exception.value))
    }

    fn update_timer(&mut self) {
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
                return;
            }
        };
        self.cpu.block_offset = 0;
        loop {
            let block = match self.code.blocks.get(block_id as usize) {
                Some(block) => block,
                None => {
                    corrupted_block_map(self, block_id);
                    return;
                }
            };

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
                    // Keep track of the offset where the CPU exited from.
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
                        }
                        None => {
                            self.cpu.block_id = block_id;
                            self.cpu.exception.code = ExceptionCode::CodeNotTranslated as u32;
                        }
                    }

                    // We always break here even if we know which block to execute next to allow the
                    // emulator to re-enter the JIT.
                    break;
                }
                Target::Invalid => {
                    let addr = block.start;
                    self.cpu.exception.code = ExceptionCode::InvalidTarget as u32;
                    self.cpu.exception.value = addr;
                    tracing::error!("{}", debug::debug_addr(self, addr).unwrap());
                    break;
                }
            }
        }

        if PRINT_EXITS {
            eprintln!(
                "interpreter_exit: (code={:?}, value={:x}), block={}, offset={}, fuel={}",
                ExceptionCode::from_u32(self.cpu.exception.code),
                self.cpu.exception.value,
                self.cpu.block_id,
                self.cpu.block_offset,
                self.cpu.fuel.remaining,
            );
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
            self.cpu.exception.code = ExceptionCode::InstructionLimit as u32;
            self.cpu.exception.value = 0;
            return;
        }

        self.cpu.exception.clear();

        // Update pointers stored in the JIT.
        // @todo: optimize: this doesn't need to be done every time we enter the JIT.
        self.jit_ctx.tlb_ptr = self.cpu.mem.tlb.as_mut();
        for (dst, src) in self.jit_ctx.tracer_mem.iter_mut().zip(self.cpu.trace.storage_ptr()) {
            *dst = src;
        }

        for (id, (dst, hook)) in self.jit_ctx.hooks.iter_mut().zip(self.cpu.get_hooks()).enumerate()
        {
            let (fn_ptr, data_ptr) = hook
                .as_ptr()
                .unwrap_or((icicle_jit::runtime::run_dynamic_hook, (id as u64) as *mut ()));
            dst.fn_ptr = fn_ptr;
            dst.data_ptr = data_ptr;
        }

        let mut next_addr = self.cpu.read_pc();
        // tracing::info!("jit_enter: next_addr={next_addr:#x}, fuel={}", self.cpu.fuel.remaining);
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
                next_addr = jit_func(self.cpu.as_mut(), &mut self.jit_ctx, next_addr);
            }
        }

        if PRINT_EXITS {
            eprintln!(
                "jit_exit: (code={:?}, value={:x}), block={}, offset={}, next_addr={next_addr:#x}, fuel={}",
                ExceptionCode::from_u32(self.cpu.exception.code),
                self.cpu.exception.value,
                self.cpu.block_id,
                self.cpu.block_offset,
                self.cpu.fuel.remaining,
            );
        }

        if self.cpu.block_offset != 0 {
            // Since we exited before we reached the end of a block, we need to check how many
            // instructions we executed in the block adjust the consumed fuel.
            let block = match self.code.blocks.get(self.cpu.block_id as usize) {
                Some(block) => block,
                None => {
                    corrupted_block_map(self, self.cpu.block_id);
                    return;
                }
            };
            let unexecuted_instructions =
                count_instructions(&block.pcode.instructions[self.cpu.block_offset as usize..]);
            self.cpu.fuel.remaining += unexecuted_instructions as u64;
        }
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

    pub fn disasm(&mut self, addr: u64) -> &str {
        self.update_context();
        self.lifter.instruction_lifter.disasm(&mut *self.cpu, addr).unwrap_or("invalid_instruction")
    }

    pub fn decode(&mut self, addr: u64) -> Option<&sleigh_runtime::Instruction> {
        self.update_context();
        self.lifter.instruction_lifter.decode(&mut *self.cpu, addr)
    }

    pub fn lift(&mut self, addr: u64) -> Option<lifter::BlockGroup> {
        self.update_context();

        let mut ctx = lifter::Context::new(&mut *self.cpu, &mut self.code, addr);
        let group = self.lifter.lift_block(&mut ctx)?;

        // Add breakpoints to the lifted code.
        for block in &mut self.code.blocks[group.range()] {
            for inst in &block.pcode.instructions {
                if matches!(inst.op, pcode::Op::InstructionMarker) {
                    if self.code.breakpoints.contains(&inst.inputs.first().as_u64()) {
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
        for id in group.range() {
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
            group.to_string(&mut self.code.blocks, &self.cpu.arch.sleigh, false).unwrap()
        );

        Some(group)
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
            self.lifter.set_context(self.cpu.arch.isa_mode_context[isa_mode as usize]);
        }
    }

    pub fn get_callstack(&self) -> Vec<u64> {
        let pc = self.cpu.read_pc();
        self.cpu.shadow_stack.as_slice().iter().map(|entry| entry.addr).chain(Some(pc)).collect()
    }

    #[inline(never)]
    #[cold]
    fn get_or_compile_jit_block(&mut self, addr: u64) -> icicle_jit::JitFunction {
        // Try to find the block corresponding to the target address.
        let key = self.get_block_key(addr);
        let group = match self.code.map.get(&key) {
            Some(group) => group,
            None => return icicle_jit::runtime::call_address_not_translated(),
        };

        if self.prev_isa_mode != key.isa_mode as u8 {
            // ISA mode has changed so we need to prevent addresses from the previous ISA mode from
            // being inclused in the fast look up table (which doesn't check the ISA mode).
            self.prev_isa_mode = key.isa_mode as u8;
            self.jit.clear_fast_lookup();
        }

        self.cpu.block_id = group.blocks.0 as u64;
        self.jit.jit_miss += 1;

        // Check if there is a breakpoint set on any of the blocks in the group.
        for block in &self.code.blocks[group.range()] {
            if block.breakpoints > 0 {
                return icicle_jit::runtime::call_block_contains_breakpoint();
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
            return icicle_jit::runtime::call_jit_compilation_error();
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

// Helper functions
impl Vm {
    pub fn step(&mut self, steps: u64) -> VmExit {
        let old_limit = self.icount_limit;

        self.icount_limit = self.cpu.icount.saturating_add(steps);
        let exit = self.run();

        self.icount_limit = old_limit;
        exit
    }

    pub fn step_back(&mut self, _steps: u64) -> VmExit {
        todo!()
    }

    pub fn run_until(&mut self, addr: u64) -> VmExit {
        let had_bp = self.code.breakpoints.contains(&addr);
        if !had_bp {
            self.code.breakpoints.insert(addr);
        }
        let exit = self.run();
        if !had_bp {
            self.code.breakpoints.remove(&addr);
        }
        exit
    }
}

#[cold]
#[inline(never)]
fn corrupted_block_map(vm: &mut Vm, id: u64) {
    vm.cpu.exception.code = ExceptionCode::InternalError as u32;
    vm.cpu.exception.value = InternalError::CorruptedBlockMap as u64;
    let pc = vm.cpu.read_pc();
    eprintln!(
        "Block map corrupted at: pc={pc:#x} id={id}\n{}",
        std::backtrace::Backtrace::force_capture()
    );
}

pub struct Snapshot {
    cpu: CpuSnapshot,
    mem: mem::Snapshot,
    env: Box<dyn std::any::Any>,
}

impl Vm {
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
    }
}

pub fn get_linux_termination_reason(vm: &mut Vm) -> Option<linux::TerminationReason> {
    vm.env
        .as_any()
        .downcast_ref::<crate::linux::Kernel>()
        .and_then(|env| env.process.termination_reason)
}
