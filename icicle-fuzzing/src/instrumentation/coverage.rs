use std::collections::HashMap;

use icicle_vm::{
    cpu::{lifter::Block, BlockGroup, BlockKey, BlockTable, Cpu, StoreRef},
    CodeInjector, Vm,
};
use pcode::Op;

use crate::{fnv_hash, fnv_hash_with};

pub fn register_afl_hit_counts_all(vm: &mut Vm, bitmap: *mut u8, size: u32) -> StoreRef {
    register_afl_hit_counts(vm, bitmap, size, |_block: &Block| true)
}

pub fn register_afl_hit_counts(
    vm: &mut Vm,
    bitmap: *mut u8,
    size: u32,
    filter: impl FnMut(&Block) -> bool + 'static,
) -> StoreRef {
    AFLHitCountsBuilder::new().filter(filter).finish(vm, bitmap, size)
}

pub struct AFLHitCountsBuilder<F> {
    filter: F,
    context_bits: u8,
}

impl AFLHitCountsBuilder<fn(&Block) -> bool> {
    pub fn new() -> Self {
        Self { filter: |_| true, context_bits: 0 }
    }
}

impl<F> AFLHitCountsBuilder<F> {
    pub fn filter<NF>(self, filter: NF) -> AFLHitCountsBuilder<NF>
    where
        NF: for<'r> FnMut(&Block) -> bool + 'static,
    {
        AFLHitCountsBuilder { filter, context_bits: self.context_bits }
    }

    /// Configures instrument to include calling context when determining coverage. Panics if `bits`
    /// is > 16.
    pub fn with_context(mut self, bits: u8) -> Self {
        assert!(bits <= 16);
        self.context_bits = bits;
        self
    }

    pub fn finish(self, vm: &mut Vm, bitmap: *mut u8, size: u32) -> StoreRef
    where
        F: for<'r> FnMut(&Block) -> bool + 'static,
    {
        assert!(size.is_power_of_two());
        assert!(
            self.context_bits as u32 <= size,
            "number of context bits must be less than map size"
        );
        let size_mask = size - 1;

        tracing::debug!("registering hit counts: map={bitmap:#p}, {size:#x} bytes");

        let prev_pc_var = vm
            .cpu
            .arch
            .sleigh
            .add_custom_reg("afl.prev_pc", 2)
            .expect("AFL hit counts have already been registered");

        let mut context = None;
        if self.context_bits != 0 {
            tracing::debug!("context enable: {} bits", self.context_bits);
            context = Some(ContextState::new(&mut vm.cpu, self.context_bits));
        }

        let bitmap_mem_id = vm.cpu.trace.register_store(Box::new((bitmap, size as usize)));

        let injector = AFLHitCountsInjector {
            bitmap_mem_id,
            size_mask,
            prev_pc_var,
            tmp_block: pcode::Block::default(),
            context,
            filter: self.filter,
        };
        vm.add_injector(Box::new(injector));

        bitmap_mem_id
    }
}

struct ContextState {
    /// The varnode that is storing the current context.
    var: pcode::VarNode,
    /// The number of bits to use for representing the context state.
    context_bits: u8,
    /// The a mapping from a fallthrough address to the context values we have
    mapping: HashMap<u64, (u16, u16)>,
    /// The ID for the next context value.
    next: u16,
    /// The location to save context to.
    context_store: StoreRef,
}

impl ContextState {
    fn new(cpu: &mut Cpu, context_bits: u8) -> Self {
        let var = cpu
            .arch
            .sleigh
            .add_custom_reg("afl.context", 2)
            .expect("AFL hit counts have already been registered");

        let store = vec![0_u8; u16::MAX as usize];
        let context_store = cpu.trace.register_store(Box::new(store.into_boxed_slice()));
        Self { var, context_bits, mapping: HashMap::new(), next: 0, context_store }
    }

    fn get_context(&mut self, addr: u64) -> (u64, u16) {
        let (id, value) = self.mapping.entry(addr).or_insert_with(|| {
            let id = self.next;
            self.next = self.next.wrapping_add(1);
            let value = fnv_hash_with(0x3653287c, addr) & ((1 << self.context_bits) - 1);
            (id, value as u16)
        });
        (*id as u64 * 2, *value)
    }

    fn inject_update(&mut self, addr: u64, block: &mut Block) {
        let (index, value) = self.get_context(addr);
        tracing::trace!(
            "context update at {:#x}: addr={addr:#x}, index={index:#x}, value={value:#x}",
            block.start
        );

        // context ^= <generate const>
        block.pcode.push((self.var, Op::IntXor, self.var, value));

        // Keep track of the modification we made so we can undo it when we return from the
        // function.
        //
        // saved_contexts[id] ^= <generate const>
        let store_id = self.context_store.get_store_id();
        let tmp = block.pcode.alloc_tmp(2);
        block.pcode.push((tmp, Op::Load(store_id), index));
        block.pcode.push((tmp, Op::IntXor, tmp, value));
        block.pcode.push((Op::Store(store_id), (index, tmp)));
    }

    fn inject_restore(&mut self, addr: u64, block: &mut Block) {
        let (index, value) = self.get_context(addr);
        tracing::trace!(
            "context restore at {:#x}: addr={addr:#x}, index={index:#x}, value={value:#x}",
            block.end
        );

        // context ^= saved_contexts[id]
        // saved_contexts[id] = 0;
        let store_id = self.context_store.get_store_id();
        let saved = block.pcode.alloc_tmp(2);
        block.pcode.instructions.insert(0, (saved, Op::Load(store_id), index).into());
        block.pcode.instructions.insert(1, (self.var, Op::IntXor, self.var, value).into());
        block.pcode.instructions.insert(2, (Op::Store(store_id), (index, 0_u16)).into());
    }

    fn maybe_inject(&mut self, cpu: &mut Cpu, code: &mut BlockTable, block_id: usize) {
        let block = &mut code.blocks[block_id];
        if self.mapping.contains_key(&block.start) {
            self.inject_restore(block.start, block);
        }

        if let icicle_vm::cpu::lifter::BlockExit::Call { fallthrough, .. } = block.exit {
            if let Some(fallthrough_group) =
                code.map.get(&BlockKey { vaddr: fallthrough, isa_mode: cpu.isa_mode() as u64 })
            {
                self.inject_restore(fallthrough, block);
                code.modified.insert(fallthrough_group.blocks.0);
            }
            self.inject_update(fallthrough, block);
        }
    }
}

struct AFLHitCountsInjector<F> {
    bitmap_mem_id: StoreRef,
    size_mask: u32,
    prev_pc_var: pcode::VarNode,
    tmp_block: pcode::Block,
    context: Option<ContextState>,
    filter: F,
}

impl<F> AFLHitCountsInjector<F> {
    fn inject_update_hit_count(&mut self, block: &mut Block) {
        self.tmp_block.clear();
        let key: u16 = (fnv_hash(block.start) & self.size_mask) as u16;

        // index = key ^ prev
        let index = self.tmp_block.alloc_tmp(2);
        self.tmp_block.push((index, Op::IntXor, key, self.prev_pc_var));
        if let Some(context) = self.context.as_ref() {
            // index = index ^ context
            self.tmp_block.push((index, Op::IntXor, index, context.var));
        }

        // bitmap[index] += 1
        let bitmap_id = self.bitmap_mem_id.get_store_id();
        let count = self.tmp_block.alloc_tmp(1);
        self.tmp_block.push((count, Op::Load(bitmap_id), index));
        self.tmp_block.push((count, Op::IntAdd, count, 1_u8));
        self.tmp_block.push((Op::Store(bitmap_id), (index, count)));

        // prev = key >> 1
        self.tmp_block.push((self.prev_pc_var, Op::Copy, key >> 1_u8));

        // Add the rest of the instructions in the block
        self.tmp_block.instructions.extend(block.pcode.instructions.iter().cloned());
        std::mem::swap(&mut self.tmp_block.instructions, &mut block.pcode.instructions);
    }
}

impl<F: FnMut(&Block) -> bool> CodeInjector for AFLHitCountsInjector<F> {
    fn inject(&mut self, cpu: &mut Cpu, group: &BlockGroup, code: &mut BlockTable) {
        if !(self.filter)(&code.blocks[group.blocks.0]) {
            return;
        }

        // Inject code to handle context updates.
        if let Some(context) = self.context.as_mut() {
            context.maybe_inject(cpu, code, group.blocks.0);
        }

        // Inject code to track hit counts.
        self.inject_update_hit_count(&mut code.blocks[group.blocks.0]);
        code.modified.insert(group.blocks.0);
    }
}

pub fn register_block_coverage(
    vm: &mut Vm,
    bitmap: *mut u8,
    size: u32,
    filter: impl FnMut(&Block) -> bool + 'static,
) -> StoreRef {
    BlockCoverageBuilder::new().filter(filter).finish(vm, bitmap, size)
}

pub struct BlockCoverageBuilder<F> {
    filter: F,
    enable_context: bool,
}

impl BlockCoverageBuilder<fn(&Block) -> bool> {
    pub fn new() -> Self {
        Self { filter: |_| true, enable_context: false }
    }
}

impl<F> BlockCoverageBuilder<F> {
    pub fn filter<NF>(self, filter: NF) -> BlockCoverageBuilder<NF>
    where
        NF: for<'r> FnMut(&Block) -> bool + 'static,
    {
        BlockCoverageBuilder { filter, enable_context: self.enable_context }
    }

    /// Configures instrumentation to include calling context when determining coverage.
    pub fn enable_context(mut self, value: bool) -> Self {
        self.enable_context = value;
        self
    }

    pub fn finish(self, vm: &mut Vm, bitmap: *mut u8, size: u32) -> StoreRef
    where
        F: for<'r> FnMut(&Block) -> bool + 'static,
    {
        assert!(size.is_power_of_two());
        let size_mask = size - 1;

        tracing::debug!("registering block coverage: map={bitmap:#p}, {size:#x} bytes");

        let bitmap_mem_id = vm.cpu.trace.register_store(Box::new((bitmap, size as usize)));

        let mut context = None;
        if self.enable_context {
            tracing::debug!("context enabled");
            context = Some(ContextState::new(&mut vm.cpu, 8));
        }

        let injector =
            BlockCoverageInjector { bitmap_mem_id, size_mask, context, filter: self.filter };
        vm.add_injector(Box::new(injector));

        bitmap_mem_id
    }
}

struct BlockCoverageInjector<F> {
    bitmap_mem_id: StoreRef,
    size_mask: u32,
    context: Option<ContextState>,
    filter: F,
}

impl<F: FnMut(&Block) -> bool> CodeInjector for BlockCoverageInjector<F> {
    fn inject(&mut self, cpu: &mut Cpu, group: &BlockGroup, code: &mut BlockTable) {
        if !(self.filter)(&mut code.blocks[group.blocks.0]) {
            return;
        }

        let bitmap_id = self.bitmap_mem_id.get_store_id();
        let index: u16 = (fnv_hash(code.blocks[group.blocks.0].start) & self.size_mask) as u16;

        if let Some(context) = &mut self.context {
            context.maybe_inject(cpu, code, group.blocks.0);

            let block = &mut code.blocks[group.blocks.0];
            let tmp = block.pcode.alloc_tmp(1);
            let ctx = context.var.slice(0, 1);
            block.pcode.instructions.insert(0, (tmp, Op::IntXor, (ctx, 1_u8)).into());
            block.pcode.instructions.insert(1, (Op::Store(bitmap_id), (index, tmp)).into());
        }
        else {
            // Note: currently we are wasting 7 bits here which is not ideal, however it allows
            // us to remain compatible with existing fuzzing frontends.
            let block = &mut code.blocks[group.blocks.0];
            block.pcode.instructions.insert(0, (Op::Store(bitmap_id), (index, 1_u8)).into());
        }

        code.modified.insert(group.blocks.0);
    }
}

pub fn register_block_hook_injector(
    vm: &mut Vm,
    start: u64,
    end: u64,
    hook: pcode::HookId,
) -> usize {
    let injector = BlockHookInjector { hook, start, end };
    vm.add_injector(Box::new(injector))
}

struct BlockHookInjector {
    hook: pcode::HookId,
    start: u64,
    end: u64,
}

impl CodeInjector for BlockHookInjector {
    fn inject(&mut self, _cpu: &mut Cpu, group: &BlockGroup, code: &mut BlockTable) {
        let block = &mut code.blocks[group.blocks.0];
        if block.start < self.start || block.start >= self.end {
            return;
        }
        block.pcode.instructions.insert(0, Op::Hook(self.hook).into());
        code.modified.insert(group.blocks.0);
    }
}

pub fn register_instruction_hook_injector(vm: &mut Vm, addr: u64, hook: pcode::HookId) -> usize {
    let injector = InstructionHookInjection { hook, addr, tmp_block: pcode::Block::new() };
    vm.add_injector(Box::new(injector))
}

struct InstructionHookInjection {
    hook: pcode::HookId,
    addr: u64,
    tmp_block: pcode::Block,
}

impl CodeInjector for InstructionHookInjection {
    fn inject(&mut self, _cpu: &mut Cpu, group: &BlockGroup, code: &mut BlockTable) {
        for id in group.range() {
            let block = &mut code.blocks[id];
            if !(block.start <= self.addr && self.addr < block.end) {
                return;
            }

            self.tmp_block.clear();
            for stmt in block.pcode.instructions.drain(..) {
                if let Op::InstructionMarker = stmt.op {
                    if stmt.inputs.first().as_u64() == self.addr {
                        self.tmp_block.push(Op::Hook(self.hook));
                        code.modified.insert(id);
                    }
                }
                self.tmp_block.push(stmt);
            }

            std::mem::swap(&mut self.tmp_block.instructions, &mut block.pcode.instructions);
        }
    }
}
