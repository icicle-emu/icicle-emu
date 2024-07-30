use ahash::{AHashMap as HashMap, AHashSet as HashSet};

use icicle_vm::{
    cpu::{
        lifter::Block, BlockGroup, BlockKey, BlockTable, Cpu, HookHandler, StoreRef, ValueSource,
    },
    CodeInjector, InjectorRef, Vm,
};
use pcode::{HookId, Op};

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
    block_only: bool,
    trampoline: bool,
}

impl AFLHitCountsBuilder<fn(&Block) -> bool> {
    pub fn new() -> Self {
        Self { filter: |_| true, context_bits: 0, block_only: false, trampoline: false }
    }
}

impl<F> AFLHitCountsBuilder<F> {
    pub fn filter<NF>(self, filter: NF) -> AFLHitCountsBuilder<NF>
    where
        NF: for<'r> FnMut(&Block) -> bool + 'static,
    {
        AFLHitCountsBuilder {
            filter,
            context_bits: self.context_bits,
            block_only: self.block_only,
            trampoline: self.trampoline,
        }
    }

    /// Configures instrument to include calling context when determining coverage. Panics if `bits`
    /// is > 16.
    pub fn with_context(mut self, bits: u8) -> Self {
        assert!(bits <= 16);
        self.context_bits = bits;
        self
    }

    pub fn set_block_only(mut self, block_only: bool) -> Self {
        self.block_only = block_only;
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

        let bitmap_mem_id = vm.cpu.trace.register_store((bitmap, size as usize));

        let trampoline_hook = self.trampoline.then(|| {
            vm.cpu.add_hook(move |cpu: &mut icicle_vm::cpu::Cpu, addr: u64| {
                let key: u16 = (fnv_hash(addr) & size_mask) as u16;
                let prev_pc = cpu.read_var::<u16>(prev_pc_var);
                let index = key ^ prev_pc;
                let data = cpu.trace[bitmap_mem_id].data_mut();
                data[index as usize] = data[index as usize].wrapping_add(1);
                cpu.write_var::<u16>(prev_pc_var, key >> 1);
            })
        });

        let injector = AFLHitCountsInjector {
            bitmap_mem_id,
            size_mask,
            prev_pc_var,
            tmp_block: pcode::Block::default(),
            context,
            filter: self.filter,
            block_only: self.block_only,
            trampoline_hook,
        };
        vm.add_injector(injector);

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
        let context_store = cpu.trace.register_store(store.into_boxed_slice());
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
    block_only: bool,
    context: Option<ContextState>,
    trampoline_hook: Option<HookId>,
    filter: F,
}

impl<F> AFLHitCountsInjector<F> {
    fn inject_update_hit_count(&mut self, block: &mut Block) {
        self.tmp_block.clear();
        let key: u16 = (fnv_hash(block.start) & self.size_mask) as u16;

        // index = key ^ prev
        let index = self.tmp_block.alloc_tmp(2);
        if self.block_only {
            self.tmp_block.push((index, Op::Copy, key));
        }
        else {
            self.tmp_block.push((index, Op::IntXor, key, self.prev_pc_var));
        }
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
        if !self.block_only {
            self.tmp_block.push((self.prev_pc_var, Op::Copy, key >> 1_u8));
        }

        // Add the rest of the instructions in the block
        self.tmp_block.instructions.extend(block.pcode.instructions.iter().cloned());
        std::mem::swap(&mut self.tmp_block.instructions, &mut block.pcode.instructions);
    }
}

impl<F: FnMut(&Block) -> bool + 'static> CodeInjector for AFLHitCountsInjector<F> {
    fn inject(&mut self, cpu: &mut Cpu, group: &BlockGroup, code: &mut BlockTable) {
        if !(self.filter)(&code.blocks[group.blocks.0]) {
            return;
        }

        // Inject code to handle context updates.
        if let Some(context) = self.context.as_mut() {
            context.maybe_inject(cpu, code, group.blocks.0);
        }

        // Inject code to track hit counts.
        if let Some(hook) = self.trampoline_hook {
            code.blocks[group.blocks.0].pcode.instructions.insert(0, pcode::Op::Hook(hook).into());
        }
        else {
            self.inject_update_hit_count(&mut code.blocks[group.blocks.0]);
        }
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

/// A builder struct for adding block coverage instrumentation, compatible with an AFL-style
/// frontend.
///
/// If AFL compatability is not required, then [ExactBlockCoverageInjector] will likely perform
/// better.
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

        let bitmap_mem_id = vm.cpu.trace.register_store((bitmap, size as usize));

        let mut context = None;
        if self.enable_context {
            tracing::debug!("context enabled");
            context = Some(ContextState::new(&mut vm.cpu, 8));
        }

        let injector =
            BlockCoverageInjector { bitmap_mem_id, size_mask, context, filter: self.filter };
        vm.add_injector(injector);

        bitmap_mem_id
    }
}

struct BlockCoverageInjector<F> {
    bitmap_mem_id: StoreRef,
    size_mask: u32,
    context: Option<ContextState>,
    filter: F,
}

impl<F: FnMut(&Block) -> bool + 'static> CodeInjector for BlockCoverageInjector<F> {
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

/// A coverage instrumentation technique that avoids collisions.
pub struct ExactBlockCoverageInjector {
    /// The bitmap that stores the block coverage.
    pub store: StoreRef,
    /// A mapping from block address to the bit allocated in the store for the block.
    pub mapping: HashMap<u64, usize>,
}

impl ExactBlockCoverageInjector {
    pub fn register(vm: &mut Vm) -> (InjectorRef, StoreRef) {
        let store = vm.cpu.trace.register_store(vec![0_u64; 128]);
        let injector = vm.add_injector(Self { store, mapping: HashMap::new() });
        (injector, store)
    }
}

impl CodeInjector for ExactBlockCoverageInjector {
    fn inject(&mut self, cpu: &mut Cpu, group: &BlockGroup, code: &mut BlockTable) {
        let addr = group.start;
        let next_index = self.mapping.len();
        let index = *self.mapping.entry(addr).or_insert(next_index);

        let (byte, bit) = (index / 8, index % 8);

        // Resize the underlying storage if required to store the bit for this block.
        let store = &mut cpu.trace[self.store];
        if store.data().len() <= byte {
            let inner = store.as_mut_any().downcast_mut::<Vec<u64>>().unwrap();
            inner.resize(icicle_vm::cpu::utils::align_up(byte as u64, 16) as usize, 0);
        }

        // Inject code to set the target bit.
        let block = &mut code.blocks[group.blocks.0];
        let bitmap_id = self.store.get_store_id();
        let tmp = block.pcode.alloc_tmp(1);
        block.pcode.instructions.insert(0, (tmp, Op::Load(bitmap_id), byte as u64).into());
        block.pcode.instructions.insert(1, (tmp, Op::IntOr, (tmp, 1_u8 << bit)).into());
        block.pcode.instructions.insert(2, (Op::Store(bitmap_id), (byte as u64, tmp)).into());
    }
}

/// A coverage instrumentation technique that avoids collisions while maintaining hit-counts for
/// each block.
pub struct ExactBlockCountCoverageInjector {
    /// The bitmap that stores the block coverage.
    pub store: StoreRef,
    /// A mapping from block address to the byte allocated in the store for the block.
    pub mapping: HashMap<u64, usize>,
    /// Whether to track block hit counts.
    pub capture_counts: bool,
}

impl ExactBlockCountCoverageInjector {
    pub fn register(vm: &mut Vm) -> (InjectorRef, StoreRef) {
        Self::register_with(vm, true)
    }

    pub fn register_with(vm: &mut Vm, capture_counts: bool) -> (InjectorRef, StoreRef) {
        let store = vm.cpu.trace.register_store(vec![0_u64; 128]);
        let injector = vm.add_injector(Self { store, mapping: HashMap::new(), capture_counts });
        (injector, store)
    }
}

impl CodeInjector for ExactBlockCountCoverageInjector {
    fn inject(&mut self, cpu: &mut Cpu, group: &BlockGroup, code: &mut BlockTable) {
        let addr = group.start;
        let next_index = self.mapping.len();
        let index = *self.mapping.entry(addr).or_insert(next_index);

        // Resize the underlying storage if required to store the counter for this block.
        let store = &mut cpu.trace[self.store];
        if store.data().len() <= index {
            let inner = store.as_mut_any().downcast_mut::<Vec<u64>>().unwrap();
            inner.resize(icicle_vm::cpu::utils::align_up(index as u64 / 8, 16) as usize, 0);
        }

        let block = &mut code.blocks[group.blocks.0];
        let bitmap_id = self.store.get_store_id();
        if self.capture_counts {
            // bitmap[index] += 1
            let tmp = block.pcode.alloc_tmp(1);
            block.pcode.instructions.insert(0, (tmp, Op::Load(bitmap_id), index as u64).into());
            block.pcode.instructions.insert(1, (tmp, Op::IntAdd, (tmp, 1_u8)).into());
            block.pcode.instructions.insert(2, (Op::Store(bitmap_id), (index as u64, tmp)).into());
        }
        else {
            // bitmap[index] = 1
            block.pcode.instructions.insert(0, (Op::Store(bitmap_id), (index as u64, 1_u8)).into());
        }
    }
}

#[derive(Copy, Clone)]
pub struct ExactEdgeCoverageRef(pcode::HookId);

impl ExactEdgeCoverageRef {
    pub fn data_mut<'a>(&self, vm: &'a mut Vm) -> &'a mut EdgeHookData {
        vm.cpu.get_hook_mut(self.0).data_mut::<EdgeHookData>().unwrap()
    }

    pub fn snapshot(&self, vm: &mut Vm) -> EdgeHookData {
        self.data_mut(vm).clone()
    }

    pub fn restore(&self, vm: &mut Vm, snapshot: &EdgeHookData) {
        let data = self.data_mut(vm);
        data.prev = snapshot.prev;
        data.edges.clear();
        data.edges.extend(&snapshot.edges);
    }

    pub fn reset(&self, vm: &mut Vm) {
        let data = self.data_mut(vm);
        data.prev = 0;
        data.edges.clear();
    }
}

/// An exact edge-coverage technique that avoids collisions by using a hashmap. Since the
/// instrumentation cannot be injected directly this is generally slower than AFL-style edge
/// coverage.
pub struct ExactEdgeCoverageInjector {
    hook: pcode::HookId,
}

impl ExactEdgeCoverageInjector {
    pub fn register(vm: &mut Vm) -> ExactEdgeCoverageRef {
        let hook = vm.cpu.trace.add_hook(EdgeHookData::default().into());
        vm.add_injector(Self { hook });
        ExactEdgeCoverageRef(hook)
    }
}

impl CodeInjector for ExactEdgeCoverageInjector {
    fn inject(&mut self, _cpu: &mut Cpu, group: &BlockGroup, code: &mut BlockTable) {
        code.blocks[group.blocks.0].pcode.instructions.insert(0, Op::Hook(self.hook).into());
    }
}

#[derive(Default, Clone)]
pub struct EdgeHookData {
    pub prev: u64,
    pub edges: HashSet<(u64, u64)>,
}

impl HookHandler for EdgeHookData {
    fn call(data: &mut Self, _cpu: &mut Cpu, addr: u64) {
        data.edges.insert((data.prev, addr));
        data.prev = addr;
    }
}
