//! Module for translating p-code to cranelift IL

mod mem;
mod ops;

use std::collections::HashMap;

use cranelift::{
    codegen::ir::{AliasRegion, Endianness, FuncRef, Function, SigRef},
    frontend::Switch,
    prelude::*,
};
use cranelift_jit::JITModule;
use cranelift_module::{FuncId, Module};

use icicle_cpu::{
    Arch, Cpu, Exception, ExceptionCode, InternalError, Regs,
    cpu::{Fuel, JitContext},
    lifter::{Block as IcicleBlock, BlockExit, Target},
};
use memoffset::offset_of;

use crate::{CompilationTarget, MemHandler, translate::ops::Ctx};

impl MemHandler<FuncRef> {
    fn import(module: &mut JITModule, current: &mut Function, funcs: &MemHandler<FuncId>) -> Self {
        Self {
            load8: module.declare_func_in_func(funcs.load8, current),
            load16: module.declare_func_in_func(funcs.load16, current),
            load32: module.declare_func_in_func(funcs.load32, current),
            load64: module.declare_func_in_func(funcs.load64, current),
            load128: module.declare_func_in_func(funcs.load128, current),
            store8: module.declare_func_in_func(funcs.store8, current),
            store16: module.declare_func_in_func(funcs.store16, current),
            store32: module.declare_func_in_func(funcs.store32, current),
            store64: module.declare_func_in_func(funcs.store64, current),
            store128: module.declare_func_in_func(funcs.store128, current),
        }
    }

    fn load(&self, size: u8) -> FuncRef {
        match size {
            1 => self.load8,
            2 => self.load16,
            4 => self.load32,
            8 => self.load64,
            16 => self.load128,
            _ => panic!("Invalid size {size}"),
        }
    }

    fn store(&self, size: u8) -> FuncRef {
        match size {
            1 => self.store8,
            2 => self.store16,
            4 => self.store32,
            8 => self.store64,
            16 => self.store128,
            _ => panic!("Invalid size {size}"),
        }
    }
}

pub const TRAP_UNREACHABLE: TrapCode = TrapCode::unwrap_user(1);

/// Checks whether the size of a value is a size that the JIT can handle natively.
fn is_jit_supported_size(size_in_bytes: u8) -> bool {
    [1, 2, 4, 8, 16].contains(&size_in_bytes)
}

struct Symbols {
    mmu: MemHandler<FuncRef>,

    push_shadow_stack: FuncRef,
    pop_shadow_stack: FuncRef,

    run_interpreter: FuncRef,
}

impl Symbols {
    fn import(
        module: &mut JITModule,
        current: &mut Function,
        funcs: &crate::RuntimeFunctions,
    ) -> Self {
        Self {
            mmu: MemHandler::import(module, current, &funcs.mmu),
            push_shadow_stack: module.declare_func_in_func(funcs.push_shadow_stack, current),
            pop_shadow_stack: module.declare_func_in_func(funcs.pop_shadow_stack, current),
            run_interpreter: module.declare_func_in_func(funcs.run_interpreter, current),
        }
    }
}

enum ValueOrConst<T> {
    Value(Value),
    Const(T),
}

impl<T: IConst> ValueOrConst<T> {
    fn get_value(self, builder: &mut FunctionBuilder) -> Value {
        match self {
            Self::Value(v) => v,
            Self::Const(c) => c.iconst(builder),
        }
    }
}

impl<T> From<Value> for ValueOrConst<T> {
    fn from(v: Value) -> Self {
        Self::Value(v)
    }
}

impl<T: IConst> From<T> for ValueOrConst<T> {
    fn from(v: T) -> Self {
        Self::Const(v)
    }
}

trait IConst {
    fn clif_type() -> Type;
    fn iconst(self, builder: &mut FunctionBuilder) -> Value;
}

macro_rules! impl_iconst {
    ($ty:ty) => {
        impl IConst for $ty {
            fn clif_type() -> Type {
                types::Type::int(<$ty>::BITS as u16).unwrap()
            }

            fn iconst(self, builder: &mut FunctionBuilder) -> Value {
                builder.ins().iconst(<$ty>::clif_type(), self as i64)
            }
        }
    };

    ($ty:ty, $($tys:ty),+) => {
        impl_iconst!($ty);
        impl_iconst!($($tys),+);
    };
}
impl_iconst! { u8, u16, u32, u64, i8, i16, i32, i64 }

struct VmPtr(pub Value);

impl VmPtr {
    fn exception_code_offset() -> i32 {
        (offset_of!(Cpu, exception) + offset_of!(Exception, code)).try_into().unwrap()
    }

    fn exception_value_offset() -> i32 {
        (offset_of!(Cpu, exception) + offset_of!(Exception, value)).try_into().unwrap()
    }

    fn var_offset(var: pcode::VarNode) -> i32 {
        (offset_of!(Cpu, regs) + Regs::var_offset(var) as usize).try_into().unwrap()
    }

    fn jit_ctx_offset() -> i32 {
        offset_of!(Cpu, jit_ctx).try_into().unwrap()
    }

    fn store_arg(&self, builder: &mut FunctionBuilder, id: u16, value: Value) {
        let arg_offset = id as usize * std::mem::size_of::<u128>();
        let offset: i32 = (offset_of!(Cpu, args) + arg_offset).try_into().unwrap();
        builder.ins().store(
            MemFlags::trusted().with_alias_region(Some(AliasRegion::Vmctx)),
            value,
            self.0,
            offset,
        );
    }

    fn load_var(
        &self,
        builder: &mut FunctionBuilder,
        var: pcode::VarNode,
        ty: types::Type,
    ) -> Value {
        let offset = VmPtr::var_offset(var);
        if var.offset == 0 {
            builder.ins().load(
                ty,
                MemFlags::trusted().with_alias_region(Some(AliasRegion::Vmctx)),
                self.0,
                offset,
            )
        } else {
            builder.ins().load(
                ty,
                MemFlags::new().with_alias_region(Some(AliasRegion::Vmctx)).with_notrap(),
                self.0,
                offset,
            )
        }
    }

    fn store_var(&self, builder: &mut FunctionBuilder, var: pcode::VarNode, value: Value) {
        let offset = VmPtr::var_offset(var);
        if var.offset == 0 {
            builder.ins().store(
                MemFlags::trusted().with_alias_region(Some(AliasRegion::Vmctx)),
                value,
                self.0,
                offset,
            );
        } else {
            builder.ins().store(
                MemFlags::new().with_alias_region(Some(AliasRegion::Vmctx)).with_notrap(),
                value,
                self.0,
                offset,
            );
        }
    }
}

macro_rules! gen_load_store {
    ($load_ident:ident, $store_ident:ident, $offset:expr, $ty:ty) => {
        impl VmPtr {
            fn $load_ident(&self, builder: &mut FunctionBuilder) -> Value {
                let offset: i32 = ($offset).try_into().unwrap();
                builder.ins().load(
                    <$ty>::clif_type(),
                    MemFlags::trusted().with_alias_region(Some(AliasRegion::Vmctx)),
                    self.0,
                    offset,
                )
            }

            fn $store_ident(
                &self,
                builder: &mut FunctionBuilder,
                value: impl Into<ValueOrConst<$ty>>,
            ) {
                let offset: i32 = ($offset).try_into().unwrap();
                let value = value.into().get_value(builder);
                builder.ins().store(
                    MemFlags::trusted().with_alias_region(Some(AliasRegion::Vmctx)),
                    value,
                    self.0,
                    offset,
                );
            }
        }
    };
}

gen_load_store!(load_exception_code, store_exception_code, VmPtr::exception_code_offset(), u32);
gen_load_store!(_load_exception_value, store_exception_value, VmPtr::exception_value_offset(), u64);
gen_load_store!(_load_block_offset, store_block_offset, offset_of!(Cpu, block_offset), u64);
gen_load_store!(_load_block_id, store_block_id, offset_of!(Cpu, block_id), u64);
gen_load_store!(load_fuel, store_fuel, offset_of!(Cpu, fuel) + offset_of!(Fuel, remaining), u64);

#[derive(Copy, Clone, Debug)]
struct WriteState {
    value: Value,
    dirty: bool,
    size: u8,
}

#[derive(Default, Debug)]
struct VarState {
    /// The last value written for each power of two.
    values: [Option<WriteState>; 5],
    last_size: u8,
}

impl VarState {
    fn flush_to_mem(
        &mut self,
        builder: &mut FunctionBuilder,
        vm_ptr: &VmPtr,
        var_id: pcode::VarId,
        clear_dirty_flag: bool,
    ) {
        for (i, value) in self.values.iter_mut().enumerate().rev() {
            let Some(write) = value else {
                continue;
            };

            let var_size = 1 << i;
            if write.dirty && write.size == var_size {
                vm_ptr.store_var(builder, pcode::VarNode::new(var_id, var_size), write.value);
            }

            if clear_dirty_flag {
                write.dirty = false;
            }
        }
    }
}

pub(crate) struct TranslatorCtx {
    /// Configures whether inline address translation in JIT'ed code is attempted.
    pub disable_jit_mem: bool,
    /// Configures whether varnodes are always _read_ from memory whenever they are accessed.
    pub disable_jit_reg: bool,
    /// Configures whether varnodes are immediately flushed to memory whenever they are modified in
    /// the JIT.
    pub always_flush_vars: bool,
    /// Flush all registers before memory accesses are performed. This must be true if memory hooks
    /// want to _read_ the current value of CPU registers.
    pub flush_before_mem: bool,
    /// Discard any live varnodes after any memory access is performed. This must be true if memory
    /// hooks want to _modify_ the current value of CPU registers.
    pub reload_after_mem: bool,
    /// Configures whether calls to push/pop shadow-stack are injected in the JIT.
    pub enable_shadow_stack: bool,
    page_size: u64,
    reg_pc: pcode::VarNode,
    endianness: Endianness,
    local_blocks: HashMap<usize, Block>,
    entry_points: Vec<(u64, Block)>,
    active_vars: HashMap<pcode::VarId, VarState>,
    temporaries: Vec<pcode::VarId>,
}

impl TranslatorCtx {
    pub(crate) fn new(arch: &Arch) -> Self {
        let endianness = match arch.sleigh.big_endian {
            false => Endianness::Little,
            true => Endianness::Big,
        };

        Self {
            reg_pc: arch.reg_pc,
            disable_jit_mem: false,
            disable_jit_reg: false,
            always_flush_vars: true,
            flush_before_mem: true,
            reload_after_mem: false,
            enable_shadow_stack: true,
            page_size: icicle_cpu::mem::physical::PAGE_SIZE as u64,
            endianness,
            local_blocks: HashMap::new(),
            entry_points: vec![],
            active_vars: HashMap::new(),
            temporaries: arch.temporaries.clone(),
        }
    }

    pub(crate) fn declare_block(
        &mut self,
        builder: &mut FunctionBuilder,
        id: usize,
        guest_block: &IcicleBlock,
    ) {
        let block = builder.create_block();
        self.local_blocks.insert(id, block);
        if let Some(entry) = guest_block.entry {
            self.entry_points.push((entry, block));
        }
    }

    pub(crate) fn clear(&mut self) {
        self.local_blocks.clear();
        self.entry_points.clear();
        self.active_vars.clear();
    }
}

pub(crate) fn translate<'a>(
    module: &'a mut JITModule,
    mut builder: FunctionBuilder<'a>,
    ctx: &'a mut TranslatorCtx,
    functions: &crate::RuntimeFunctions,
    target: &CompilationTarget,
) {
    let symbols = Symbols::import(module, builder.func, functions);
    let hook_sig = builder.import_signature(functions.hook_signature.clone());

    builder.func.signature.params.push(AbiParam::new(types::I64)); // cpu_ptr
    builder.func.signature.params.push(AbiParam::new(types::I64)); // addr

    builder.func.signature.returns.push(AbiParam::new(types::I64)); // next_addr

    let (vm_ptr, tlb_ptr) = define_jit_entry(&mut builder, ctx);

    let exit_block = builder.create_block();
    builder.append_block_param(exit_block, types::I64); // block_id
    builder.append_block_param(exit_block, types::I64); // block_offset
    builder.append_block_param(exit_block, types::I64); // next_addr

    let mut translator = Translator {
        builder,
        ctx,

        vm_ptr: VmPtr(vm_ptr),
        tlb_ptr,
        hook_sig,
        symbols,
        srcloc: 0,

        last_addr: 0,
        instruction_len: 0,
        block_id: 0,
        block_offset: 0,

        exit_block,
    };

    for (id, block) in target.iter() {
        translator.translate_block(id, block);
    }

    translator.finalize();
}

fn define_jit_entry(builder: &mut FunctionBuilder, ctx: &mut TranslatorCtx) -> (Value, Value) {
    let entry_block = builder.create_block();

    builder.append_block_params_for_function_params(entry_block);
    builder.switch_to_block(entry_block);
    builder.seal_block(entry_block);

    let (cpu_ptr, addr) = match builder.block_params(entry_block) {
        &[x0, x1] => (x0, x1),
        params => unreachable!("expected 3 params for entry block (got {})", params.len()),
    };

    // We always load the TLB ptr ahead of time here since it is likely to be used in almost every
    // block, and Cranelift's redundant load analysis isn't good enough to avoid reloading it.
    let tlb_ptr = builder.ins().load(
        types::I64,
        MemFlags::trusted().with_alias_region(Some(AliasRegion::Vmctx)),
        cpu_ptr,
        offset_of!(Cpu, jit_ctx) as i32 + offset_of!(JitContext, tlb_ptr) as i32,
    );

    match &ctx.entry_points[..] {
        &[] => unreachable!("no entry points"),
        &[(_, block)] => {
            // There is only a single entry point to the blocks in the group, so we can just
            // jump directly to it.
            builder.ins().jump(block, &[]);
        }
        entries => {
            let trap_block = builder.create_block();

            // Otherwise generate a switch statement.
            let mut switch = Switch::new();
            for &(addr, block) in entries {
                switch.set_entry(addr as u128, block);
            }
            switch.emit(builder, addr, trap_block);

            // Define trap block
            builder.set_cold_block(trap_block);
            builder.switch_to_block(trap_block);
            builder.seal_block(trap_block);
            builder.ins().trap(TRAP_UNREACHABLE);
        }
    }

    (cpu_ptr, tlb_ptr)
}

struct Translator<'a> {
    ctx: &'a mut TranslatorCtx,
    builder: FunctionBuilder<'a>,

    vm_ptr: VmPtr,
    tlb_ptr: Value,
    hook_sig: SigRef,
    symbols: Symbols,
    srcloc: u32,

    last_addr: u64,
    instruction_len: u64,
    block_id: u64,
    block_offset: u64,

    exit_block: Block,
}

impl<'a> Translator<'a> {
    fn finalize(mut self) {
        for (_, block) in self.ctx.local_blocks.drain() {
            self.builder.seal_block(block);
        }

        // Define the exit block
        self.builder.switch_to_block(self.exit_block);
        self.builder.seal_block(self.exit_block);

        let (block_id, block_offset, next_addr) = match self.builder.block_params(self.exit_block) {
            &[x0, x1, x2] => (x0, x1, x2),
            params => unreachable!(
                "unexpected number of parameters for exit block (got {})",
                params.len()
            ),
        };

        self.vm_ptr.store_block_id(&mut self.builder, block_id);
        self.vm_ptr.store_block_offset(&mut self.builder, block_offset);

        let pc = self.resize_int(next_addr, 8, self.ctx.reg_pc.size);
        self.vm_ptr.store_var(&mut self.builder, self.ctx.reg_pc, pc);

        self.builder.ins().return_(&[next_addr]);

        self.builder.finalize();
    }

    /// Branches to `block` if `cond != 0`, creating a new block and switching to it and sealing it
    /// to handle the fallthrough case.
    fn branch_non_zero(&mut self, cond: Value, then_block: Block) -> Block {
        let else_block = self.builder.create_block();
        self.builder.ins().brif(cond, then_block, &[], else_block, &[]);
        self.builder.switch_to_block(else_block);
        self.builder.seal_block(else_block);
        else_block
    }

    /// Branches to `block` if `cond == 0`, creating a new block and switching to it and sealing it
    /// to handle the fallthrough case.
    fn branch_zero(&mut self, cond: Value, then_block: Block) -> Block {
        let else_block = self.builder.create_block();
        self.builder.ins().brif(cond, else_block, &[], then_block, &[]);
        self.builder.switch_to_block(else_block);
        self.builder.seal_block(else_block);
        else_block
    }

    /// Exit the JIT with the current interrupt code, value and block offset.
    fn goto_jit_exit_err(&mut self) {
        // Ensure that any live state is written to registers before we exit.
        self.flush_state(false);
        let block_id = self.builder.ins().iconst(types::I64, self.block_id as i64);
        let block_offset = self.builder.ins().iconst(types::I64, self.block_offset as i64);
        let next_addr = self.builder.ins().iconst(types::I64, self.last_addr as i64);
        self.builder.ins().jump(self.exit_block, &[block_id, block_offset, next_addr]);
    }

    /// Exit the JIT with a specific interrupt code, value and block offset.
    fn exit_with_exception(&mut self, code: ExceptionCode, value: u64) {
        self.vm_ptr.store_exception_code(&mut self.builder, code as u32);
        self.vm_ptr.store_exception_value(&mut self.builder, value);
        self.goto_jit_exit_err();
    }

    fn goto_jit_exit_external_addr(&mut self, addr: Value) {
        // Ensure that any live state is written to registers before we exit.
        self.flush_state(false);
        let block_id = self.builder.ins().iconst(types::I64, self.block_id as i64);
        let block_offset = self.builder.ins().iconst(types::I64, 0_i64);
        self.builder.ins().jump(self.exit_block, &[block_id, block_offset, addr]);
    }

    /// Generates code that exits the JIT if there is an active exception. Returns the block
    /// associated with the `ok` case.
    fn maybe_exit_jit(&mut self, ok_block: Option<Block>) -> Block {
        let exception_code = self.vm_ptr.load_exception_code(&mut self.builder);

        let ok_block = ok_block.unwrap_or_else(|| self.builder.create_block());

        let err_block = self.builder.create_block();
        self.builder.set_cold_block(err_block);

        assert_eq!(ExceptionCode::None as u32, 0);
        self.builder.ins().brif(exception_code, err_block, &[], ok_block, &[]);

        // error:
        {
            self.builder.switch_to_block(err_block);
            self.builder.seal_block(err_block);
            self.goto_jit_exit_err();
        }

        // ok:
        {
            self.builder.switch_to_block(ok_block);
            self.builder.seal_block(ok_block);
        }

        ok_block
    }

    /// Ensure that any live variables are flushed to memory.
    pub fn flush_state(&mut self, clear_dirty_flag: bool) {
        if self.ctx.always_flush_vars {
            // Already flushed when updated.
            return;
        }

        for (var, state) in self.ctx.active_vars.iter_mut() {
            state.flush_to_mem(&mut self.builder, &self.vm_ptr, *var, clear_dirty_flag);
        }
    }

    /// Indicates that cached copies of varnodes cannot be forwarded past this point.
    pub fn varnode_fence(&mut self) {
        self.flush_state(false);
        self.ctx.active_vars.clear();

        // Note: currently we do not prevent load forwarding optimizations in Cranelift. Ideally we
        // would introduce a compiler fence here but this isn't currently supported (a full MFENCE
        // has too high of a performance impact to be used here). In practice, this fence is only
        // needed when calling into the emulator runtime, which currently appears to act as a
        // compiler fence to Cranelift.
        //
        // self.builder.ins().fence();
    }

    fn read_int(&mut self, var: pcode::Value) -> Value {
        self.read_typed(var, sized_int(var.size()))
    }

    fn read_zxt(&mut self, var: pcode::Value, size: u8) -> Value {
        let value = self.read_typed(var, sized_int(var.size()));
        self.resize_int(value, var.size(), size)
    }

    fn read_float(&mut self, var: pcode::Value) -> Value {
        let ty = sized_float(var.size());
        let mut value = self.read_typed(var, ty);
        if var.size() == 10 {
            value = self.builder.ins().ireduce(types::I64, value);
        }
        self.bitcast(ty, value)
    }

    fn read_bool(&mut self, var: pcode::Value) -> Value {
        // @fixme: cannot load a bool from cranelift.
        // self.read_typed(var, types::B1)
        let x = self.read_int(var);
        self.builder.ins().icmp_imm(IntCC::NotEqual, x, 0)
    }

    /// Resizes value to an integer with `size` bytes, truncating or zero-extending as needed.
    fn resize_int(&mut self, value: Value, in_size: u8, out_size: u8) -> Value {
        resize_int(&mut self.builder, value, in_size, out_size)
    }

    /// Casts a value to a different type.
    fn bitcast(&mut self, to_ty: Type, value: Value) -> Value {
        self.builder.ins().bitcast(to_ty, MemFlags::new(), value)
    }

    fn load_const(&mut self, ty: types::Type, value: u64) -> Value {
        match ty {
            types::F32 => self.builder.ins().f32const(f32::from_bits(value as u32)),
            types::F64 => self.builder.ins().f64const(f64::from_bits(value)),
            _ if ty.bits() > 64 => {
                let tmp = self.builder.ins().iconst(types::I64, value as i64);
                self.builder.ins().uextend(ty, tmp)
            }
            _ => self.builder.ins().iconst(ty, value as i64),
        }
    }

    fn read_var(&mut self, var: pcode::VarNode) -> Value {
        if self.ctx.disable_jit_reg {
            return self.vm_ptr.load_var(&mut self.builder, var, sized_int(var.size));
        }

        let state = self.ctx.active_vars.entry(var.id).or_default();

        let required_size = (var.offset + var.size).next_power_of_two();
        assert!(required_size <= 16);
        let size_idx = required_size.trailing_zeros() as usize;

        let active_value = state.values[size_idx];
        let base_value = match active_value {
            Some(entry) if state.last_size >= required_size => {
                resize_int(&mut self.builder, entry.value, entry.size, required_size)
            }
            _ => {
                state.flush_to_mem(&mut self.builder, &self.vm_ptr, var.id, true);

                let var = pcode::VarNode::new(var.id, required_size);
                if var.is_temp() {
                    // @todo: we should validate that the temporary was previously written to within
                    // this instruction.
                }
                let value = self.vm_ptr.load_var(&mut self.builder, var, sized_int(required_size));

                for i in 0..=size_idx {
                    state.values[i] = Some(WriteState { value, size: required_size, dirty: false });
                }
                state.last_size = required_size;
                value
            }
        };

        // Extract the part of the value we need.
        let value = match var.offset {
            0 => base_value,
            offset => self.builder.ins().ushr_imm(base_value, 8 * offset as i64),
        };
        self.resize_int(value, required_size, var.size)
    }

    /// Generates code for reading the value of a [pcode::Value].
    //
    // @fixme: check handling of non-natively sized integers.
    fn read_typed(&mut self, value: pcode::Value, ty: types::Type) -> Value {
        match value {
            pcode::Value::Var(var) => self.read_var(var),
            pcode::Value::Const(value, _) => self.load_const(ty, value),
        }
    }

    /// Generates code for write a value to a [pcode::Value].
    //
    // @fixme: avoid generating stores every time we write to a VarNode (stores should only be
    // required on state flush).
    //
    // @fixme: check handling of of non-natively sized integers.
    fn write(&mut self, var: pcode::VarNode, value: Value) {
        if self.ctx.disable_jit_reg {
            self.vm_ptr.store_var(&mut self.builder, var, value);
            return;
        }

        let flush = self.ctx.always_flush_vars;
        match var.offset {
            0 if is_jit_supported_size(var.size) => {
                let state = self.ctx.active_vars.entry(var.id).or_default();
                for i in 0..=var.size.trailing_zeros() as usize {
                    state.values[i] = Some(WriteState { value, size: var.size, dirty: !flush });
                }
                state.last_size = var.size
            }
            // Just invalidate any cached value if the offset is not zero or this is not a natively
            // sized value.
            _ => {
                self.invalidate_var(var);
                self.vm_ptr.store_var(&mut self.builder, var, value);
                return;
            }
        }

        if flush {
            self.vm_ptr.store_var(&mut self.builder, var, value);
        }
    }

    fn invalidate_var(&mut self, var: pcode::VarNode) {
        if let Some(mut entry) = self.ctx.active_vars.remove(&var.id) {
            entry.flush_to_mem(&mut self.builder, &self.vm_ptr, var.id, false);
        }
    }

    /// Write the PC value of the current instruction to memory so it is visible in the CPU state.
    ///
    /// Note: this does not update the PC register that we use for normal codegen since this happens
    /// off of the main block path (so the value will not be written in all blocks).
    fn flush_current_pc(&mut self) {
        let reg_pc = self.ctx.reg_pc;
        let current_pc = self.builder.ins().iconst(sized_int(reg_pc.size), self.last_addr as i64);
        self.vm_ptr.store_var(&mut self.builder, reg_pc, current_pc);
    }

    /// Run an operation in the interpreter.
    fn interpret(&mut self, inst: pcode::Instruction) {
        tracing::debug!("interpreter will run for: pc={:#0x} {inst:?}", self.last_addr);

        if inst.output != pcode::VarNode::NONE {
            if let Some(mut entry) = self.ctx.active_vars.remove(&inst.output.id) {
                entry.flush_to_mem(&mut self.builder, &self.vm_ptr, inst.output.id, false);
            }
        }

        for input in inst.inputs.get() {
            if let pcode::Value::Var(var) = input {
                if let Some(entry) = self.ctx.active_vars.get_mut(&var.id) {
                    entry.flush_to_mem(&mut self.builder, &self.vm_ptr, var.id, true);
                }
            }
        }

        // @fixme: check flags to see if we need to flush additional CPU state here.
        self.flush_current_pc();

        let inst_bytes = crate::runtime::pack_instruction(inst);
        let args = [
            self.vm_ptr.0,
            self.builder.ins().iconst(types::I64, inst_bytes[0] as i64),
            self.builder.ins().iconst(types::I64, inst_bytes[1] as i64),
            self.builder.ins().iconst(types::I64, inst_bytes[2] as i64),
            self.builder.ins().iconst(types::I64, inst_bytes[3] as i64),
        ];
        self.builder.ins().call(self.symbols.run_interpreter, &args);
    }

    fn next_instruction(&mut self, addr: u64, len: u64) {
        self.last_addr = addr;
        self.instruction_len = len;
        self.builder.ins().nop();

        // All temporaries are dead at this point. So they can purged at this point without flushing
        // them to memory.
        self.ctx.active_vars.retain(|id, _| *id > 0 && !self.ctx.temporaries.contains(id));
    }

    fn translate_block(&mut self, block_id: usize, block: &IcicleBlock) {
        use pcode::Op;

        self.last_addr = block.start;
        self.block_id = block_id as u64;
        self.block_offset = 0;
        self.ctx.active_vars.clear();

        let clif_block = self.ctx.local_blocks.get(&block_id).unwrap();
        self.builder.switch_to_block(*clif_block);

        if block.num_instructions > 0 {
            self.check_for_fuel(block.num_instructions);
        }

        for (i, stmt) in block.pcode.instructions.iter().enumerate() {
            tracing::trace!("translating: [{:04x}] {:?}", i, stmt);
            self.block_offset = i as u64;

            self.builder.set_srcloc(codegen::ir::SourceLoc::new(self.srcloc));
            self.srcloc += 1;

            let output = stmt.output;
            let inputs = stmt.inputs.get();

            let mut ctx = Ctx { trans: self, instruction: *stmt };
            match stmt.op {
                Op::Copy => ctx.emit_copy(),
                Op::ZeroExtend => ctx.emit_zero_extend(),
                Op::SignExtend => ctx.emit_sign_extend(),
                Op::IntToFloat => ctx.emit_int_to_float(),
                Op::UintToFloat => ctx.emit_uint_to_float(),
                Op::FloatToFloat => ctx.emit_float_to_float(),
                Op::FloatToInt => ctx.emit_float_to_int(),

                Op::IntAdd => ctx.emit_int_op(ops::int_add),
                Op::IntSub => ctx.emit_int_op(ops::int_sub),
                Op::IntXor => ctx.emit_int_op(ops::int_xor),
                Op::IntOr => ctx.emit_int_op(ops::int_or),
                Op::IntAnd => ctx.emit_int_op(ops::int_and),
                Op::IntMul => ctx.emit_int_op(ops::int_mul),

                Op::IntDiv => ctx.emit_div_op(ops::int_div, false),
                Op::IntSignedDiv => ctx.emit_div_op(ops::int_signed_div, true),
                Op::IntRem => ctx.emit_div_op(ops::int_rem, false),
                Op::IntSignedRem => ctx.emit_div_op(ops::int_signed_rem, true),

                Op::IntLeft => ctx.emit_shift_op(ops::int_left),
                Op::IntRight => ctx.emit_shift_op(ops::int_right),
                Op::IntSignedRight => ctx.emit_shift_op(ops::int_signed_right),
                Op::IntRotateLeft => ctx.emit_int_op(ops::int_rotate_left),
                Op::IntRotateRight => ctx.emit_int_op(ops::int_rotate_right),

                Op::IntEqual => ctx.emit_int_cmp(ops::int_equal),
                Op::IntNotEqual => ctx.emit_int_cmp(ops::int_not_equal),
                Op::IntLess => ctx.emit_int_cmp(ops::int_less),
                Op::IntSignedLess => ctx.emit_int_cmp(ops::int_signed_less),
                Op::IntLessEqual => ctx.emit_int_cmp(ops::int_less_equal),
                Op::IntSignedLessEqual => ctx.emit_int_cmp(ops::int_signed_less_equal),
                Op::IntCarry => ctx.emit_int_cmp(ops::int_carry),
                Op::IntSignedCarry => ctx.emit_int_cmp(ops::int_signed_carry),
                Op::IntSignedBorrow => ctx.emit_int_cmp(ops::int_signed_borrow),

                Op::IntNot => ctx.emit_int_unary_op(ops::int_not),
                Op::IntNegate => ctx.emit_int_unary_op(ops::int_negate),
                Op::IntCountOnes => ctx.emit_count_ones(),
                Op::IntCountLeadingZeroes => ctx.emit_count_leading_zeroes(),

                Op::BoolAnd => ctx.emit_bool_op(ops::bool_and),
                Op::BoolOr => ctx.emit_bool_op(ops::bool_or),
                Op::BoolXor => ctx.emit_bool_op(ops::bool_xor),
                Op::BoolNot => ctx.emit_int_unary_op(ops::bool_not),

                Op::FloatAdd => ctx.emit_float_op(ops::float_add),
                Op::FloatSub => ctx.emit_float_op(ops::float_sub),
                Op::FloatMul => ctx.emit_float_op(ops::float_mul),
                Op::FloatDiv => ctx.emit_float_op(ops::float_div),

                Op::FloatNegate => ctx.emit_float_unary_op(ops::float_negate),
                Op::FloatAbs => ctx.emit_float_unary_op(ops::float_abs),
                Op::FloatSqrt => ctx.emit_float_unary_op(ops::float_sqrt),
                Op::FloatCeil => ctx.emit_float_unary_op(ops::float_ceil),
                Op::FloatFloor => ctx.emit_float_unary_op(ops::float_floor),
                Op::FloatRound => ctx.emit_float_unary_op(ops::float_round),
                Op::FloatIsNan => ctx.emit_float_is_nan(),

                Op::FloatEqual => ctx.emit_float_cmp(ops::float_equal),
                Op::FloatNotEqual => ctx.emit_float_cmp(ops::float_not_equal),
                Op::FloatLess => ctx.emit_float_cmp(ops::float_less),
                Op::FloatLessEqual => ctx.emit_float_cmp(ops::float_less_equal),

                Op::Load(id) => match id {
                    pcode::RAM_SPACE => mem::load_ram(self, inputs[0], output),
                    pcode::REGISTER_SPACE => {
                        // The target register needs to be resolved dynamically using SLEIGH data,
                        // so we defer this to the interpreter.
                        ctx.trans.interpret(ctx.instruction);
                    }
                    pcode::RESERVED_SPACE_END.. => {
                        if !is_jit_supported_size(output.size) {
                            ctx.trans.interpret(ctx.instruction);
                            continue;
                        }
                        let ptr =
                            ctx.get_trace_store_ptr(id - pcode::RESERVED_SPACE_END, inputs[0]);

                        let load_flags = MemFlags::new()
                            .with_notrap()
                            .with_alias_region(Some(AliasRegion::Heap));
                        let ty = sized_int(output.size);
                        let value = ctx.trans.builder.ins().load(ty, load_flags, ptr, 0);
                        self.write(output, value);
                    }
                },
                Op::Store(id) => match id {
                    pcode::RAM_SPACE => mem::store_ram(self, inputs[0], inputs[1]),
                    pcode::REGISTER_SPACE => {
                        // The target register needs to be resolved dynamically using SLEIGH data,
                        // so we defer this to the interpreter.
                        ctx.trans.interpret(ctx.instruction);
                    }
                    pcode::RESERVED_SPACE_END.. => {
                        if !is_jit_supported_size(inputs[1].size()) {
                            ctx.trans.interpret(ctx.instruction);
                            continue;
                        }
                        let ptr =
                            ctx.get_trace_store_ptr(id - pcode::RESERVED_SPACE_END, inputs[0]);
                        let value = ctx.trans.read_int(inputs[1]);

                        let store_flags = MemFlags::new()
                            .with_notrap()
                            .with_alias_region(Some(AliasRegion::Heap));
                        ctx.trans.builder.ins().store(store_flags, value, ptr, 0);
                    }
                },

                Op::Arg(id) => {
                    let value = self.read_zxt(inputs[0], 16);
                    self.vm_ptr.store_arg(&mut self.builder, id, value);
                }
                Op::PcodeOp(_id) => {
                    ctx.trans.interpret(ctx.instruction);
                    // The pcode operation may set an interupt, so check it here.
                    // @fixme: avoid checking all helpers.
                    self.maybe_exit_jit(None);
                }
                Op::Hook(id) => {
                    ctx.call_hook(id);
                    ctx.trans.maybe_exit_jit(None);
                }
                Op::HookIf(id) => {
                    // Need to flush the JIT state here to prevent the live variables differing
                    // between the true/false states.
                    ctx.trans.flush_state(true);
                    ctx.trans.varnode_fence();

                    let hook_block = ctx.trans.builder.create_block();
                    // Typically the only reason to use a conditional hook (instead of just checking
                    // the condition inside of the hook) is because we expect the condition to be
                    // false most of the time, and we want to stay on the hot path. So mark the hook
                    // as cold.
                    ctx.trans.builder.set_cold_block(hook_block);

                    let continue_block = ctx.trans.builder.create_block();

                    let cond = ctx.trans.read_int(inputs[0]);
                    ctx.trans.builder.ins().brif(cond, hook_block, &[], continue_block, &[]);

                    // hook_block:
                    {
                        ctx.trans.builder.switch_to_block(hook_block);
                        ctx.trans.builder.seal_block(hook_block);
                        ctx.call_hook(id);
                        ctx.trans.maybe_exit_jit(Some(continue_block));
                    }
                }

                Op::TracerLoad(_) | Op::TracerStore(_) => {
                    unreachable!("tracer operations are now performed as part of load/store")
                }

                Op::InstructionMarker => {
                    self.next_instruction(inputs[0].as_u64(), inputs[1].as_u64())
                }

                Op::Exception => {
                    let code = self.read_int(inputs[0]);
                    let value = self.read_int(inputs[1]);
                    self.vm_ptr.store_exception_code(&mut self.builder, code);
                    self.vm_ptr.store_exception_value(&mut self.builder, value);
                    self.goto_jit_exit_err();
                    return;
                }

                // These operations should be removed during lifting, and IR-graph construction.
                Op::Subpiece(_)
                | Op::Branch(_)
                | Op::PcodeBranch(_)
                | Op::PcodeLabel(_)
                | Op::Invalid => {
                    let msg = u64::from_be_bytes(*b"bad op  ");
                    self.exit_with_exception(ExceptionCode::InvalidInstruction, msg);
                    return;
                }

                Op::Select(cond_var) => {
                    let cond = ctx.trans.read_bool(pcode::VarNode::new(cond_var, 1).into());
                    let a = ctx.trans.read_int(inputs[0]);
                    let b = ctx.trans.read_int(inputs[1]);
                    let value = ctx.trans.builder.ins().select(cond, a, b);
                    self.write(output, value);
                }
                Op::MultiEqual | Op::Indirect => {
                    unreachable!("MultiEqual/Indirect ops should not reach the JIT");
                }
            }
        }

        // Flush any live registers at the end of the block.
        //
        // @todo: it should be possible to avoid flushing temporary values here. This would
        // require special handling of the incoming state for internal blocks, which is yet to be
        // done.
        self.flush_state(true);

        self.builder.set_srcloc(codegen::ir::SourceLoc::new(self.srcloc));
        self.srcloc += 1;

        let remaining_fuel = self.vm_ptr.load_fuel(&mut self.builder);
        let new = self.builder.ins().iadd_imm(remaining_fuel, -(block.num_instructions as i64));
        self.vm_ptr.store_fuel(&mut self.builder, new);

        // Since we are exiting the block, reset the block offset and set the last address to after
        // the completed instruction. This ensures that the runtime does not try to run clean up
        // code for handling partially executed blocks and will resume at the correct location.
        self.block_offset = 0;
        self.last_addr += self.instruction_len;

        self.translate_block_exit(&block.exit);
    }

    /// If this block contains any _real_ instructions, then check that we have enough remaining
    /// fuel to fully execute it.
    fn check_for_fuel(&mut self, num_instructions: u32) {
        // @fixme: make `fuel` a variable.
        let remaining_fuel = self.vm_ptr.load_fuel(&mut self.builder);
        let required_fuel = num_instructions as i64;
        let switch_to_interpreter = self.builder.ins().icmp_imm(
            IntCC::SignedLessThanOrEqual,
            remaining_fuel,
            required_fuel,
        );

        let ok_block = self.builder.create_block();
        let err_block = self.builder.create_block();
        self.builder.set_cold_block(err_block);

        self.builder.ins().brif(switch_to_interpreter, err_block, &[], ok_block, &[]);

        // err:
        {
            self.builder.switch_to_block(err_block);
            self.builder.seal_block(err_block);
            self.exit_with_exception(
                ExceptionCode::InternalError,
                InternalError::SwitchToInterpreter as u64,
            );
        }

        // ok:
        {
            self.builder.switch_to_block(ok_block);
            self.builder.seal_block(ok_block);
        }
    }

    fn translate_block_exit(&mut self, exit: &BlockExit) {
        match exit {
            BlockExit::Jump { target } => {
                self.goto_jump_target(target);
            }
            BlockExit::Branch { cond, target, fallthrough } => {
                let true_block = self.builder.create_block();
                let false_block = self.builder.create_block();

                let cond = self.read_int(*cond);
                self.builder.ins().brif(cond, true_block, &[], false_block, &[]);

                // true:
                {
                    self.builder.switch_to_block(true_block);
                    self.builder.seal_block(true_block);
                    self.goto_jump_target(target);
                }

                // false:
                {
                    self.builder.switch_to_block(false_block);
                    self.builder.seal_block(false_block);
                    self.goto_jump_target(fallthrough);
                }
            }
            BlockExit::Call { target, fallthrough, .. } => {
                if self.ctx.enable_shadow_stack {
                    let fallthrough = self.builder.ins().iconst(types::I64, *fallthrough as i64);
                    self.builder
                        .ins()
                        .call(self.symbols.push_shadow_stack, &[self.vm_ptr.0, fallthrough]);
                }
                let addr = self.read_zxt(*target, 8);
                self.goto_jit_exit_external_addr(addr);
            }
            BlockExit::Return { target } => {
                let addr = self.read_zxt(*target, 8);
                if self.ctx.enable_shadow_stack {
                    self.builder.ins().call(self.symbols.pop_shadow_stack, &[self.vm_ptr.0, addr]);
                }
                self.goto_jit_exit_external_addr(addr);
            }
        }
    }

    fn goto_jump_target(&mut self, jump: &Target) {
        match jump {
            Target::Internal(block_id) => match self.ctx.local_blocks.get(block_id) {
                Some(block) => {
                    self.builder.ins().jump(*block, &[]);
                }
                None => {
                    let msg = u64::from_be_bytes(*b"bad jump");
                    self.exit_with_exception(ExceptionCode::JitError, msg);
                }
            },
            Target::External(target) => {
                // Try to directly jump to the target if it is defined in the current function.
                if let pcode::Value::Const(addr, _) = target {
                    if let Some((_, block)) =
                        self.ctx.entry_points.iter().find(|entry| entry.0 == *addr)
                    {
                        self.builder.ins().jump(*block, &[]);
                        return;
                    }
                }

                let addr = self.read_zxt(*target, 8);
                self.goto_jit_exit_external_addr(addr);
            }
            Target::Invalid(e, addr) => {
                self.exit_with_exception(ExceptionCode::from(*e), *addr);
            }
        }
    }
}

fn sized_int(size: u8) -> types::Type {
    match size {
        1 => types::I8,
        2 => types::I16,
        3 | 4 => types::I32,
        5 | 6 | 7 | 8 => types::I64,
        9..=16 => types::I128,
        _ => {
            tracing::error!("Invalid int size: {}", size);
            types::INVALID
        }
    }
}

fn sized_float(size: u8) -> types::Type {
    match size {
        4 => types::F32,
        8 => types::F64,
        10 => types::F64, // Treat 80-bit floats as 64-bit floats (for now)
        _ => {
            tracing::error!("Invalid float size: {}", size);
            types::INVALID
        }
    }
}

fn resize_int(builder: &mut FunctionBuilder, value: Value, in_size: u8, out_size: u8) -> Value {
    let input_ty = sized_int(in_size);
    let output_ty = sized_int(out_size);

    match input_ty.bits().cmp(&output_ty.bits()) {
        std::cmp::Ordering::Less => builder.ins().uextend(output_ty, value),
        std::cmp::Ordering::Equal => value,
        std::cmp::Ordering::Greater => builder.ins().ireduce(output_ty, value),
    }
}
