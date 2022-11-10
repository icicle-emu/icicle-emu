//! Module for translating p-code to cranelift IL

mod mem;
mod ops;

use std::{collections::HashMap, convert::TryInto};

use cranelift::{
    codegen::ir::{Endianness, FuncRef, Function, SigRef},
    frontend::Switch,
    prelude::*,
};
use cranelift_jit::JITModule;
use cranelift_module::{FuncId, Module};

use icicle_cpu::{
    cpu::Fuel,
    lifter::{Block as IcicleBlock, BlockExit, Target},
    Cpu, Exception, ExceptionCode, Regs,
};
use memoffset::offset_of;

use crate::{translate::ops::Ctx, CompilationTarget, MemHandler, VmCtx};

impl MemHandler<FuncRef> {
    fn import(module: &JITModule, current: &mut Function, funcs: &MemHandler<FuncId>) -> Self {
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

/// Checks whether the size of a value is a size that the JIT can handle natively
fn is_native_size(bytes: u8) -> bool {
    [1, 2, 4, 8, 16].contains(&bytes)
}

struct Symbols {
    mmu: MemHandler<FuncRef>,

    push_shadow_stack: FuncRef,
    pop_shadow_stack: FuncRef,

    run_interpreter: FuncRef,
}

impl Symbols {
    fn import(module: &JITModule, current: &mut Function, funcs: &crate::RuntimeFunctions) -> Self {
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

    fn store_arg(&self, builder: &mut FunctionBuilder, id: u16, value: Value) {
        let arg_offset = id as usize * std::mem::size_of::<u128>();
        let offset: i32 = (offset_of!(Cpu, args) + arg_offset).try_into().unwrap();
        builder.ins().store(MemFlags::trusted(), value, self.0, offset);
    }

    fn load_var(
        &self,
        builder: &mut FunctionBuilder,
        var: pcode::VarNode,
        ty: types::Type,
    ) -> Value {
        let offset = VmPtr::var_offset(var);
        if var.offset == 0 {
            builder.ins().load(ty, MemFlags::trusted(), self.0, offset)
        }
        else {
            let mut flags = MemFlags::new();
            flags.set_notrap();
            builder.ins().load(ty, flags, self.0, offset)
        }
    }

    fn store_var(&self, builder: &mut FunctionBuilder, var: pcode::VarNode, value: Value) {
        let offset = VmPtr::var_offset(var);
        if var.offset == 0 {
            builder.ins().store(MemFlags::trusted(), value, self.0, offset);
        }
        else {
            let mut flags = MemFlags::new();
            flags.set_notrap();
            builder.ins().store(flags, value, self.0, offset);
        }
    }
}

macro_rules! gen_load_store {
    ($load_ident:ident, $store_ident:ident, $offset:expr, $ty:ty) => {
        impl VmPtr {
            fn $load_ident(&self, builder: &mut FunctionBuilder) -> Value {
                let offset: i32 = ($offset).try_into().unwrap();
                builder.ins().load(<$ty>::clif_type(), MemFlags::trusted(), self.0, offset)
            }

            fn $store_ident(
                &self,
                builder: &mut FunctionBuilder,
                value: impl Into<ValueOrConst<$ty>>,
            ) {
                let offset: i32 = ($offset).try_into().unwrap();
                let value = value.into().get_value(builder);
                builder.ins().store(MemFlags::trusted(), value, self.0, offset);
            }
        }
    };
}

gen_load_store!(load_exception_code, store_exception_code, VmPtr::exception_code_offset(), u32);
gen_load_store!(_load_exception_value, store_exception_value, VmPtr::exception_value_offset(), u64);
gen_load_store!(_load_block_offset, store_block_offset, offset_of!(Cpu, block_offset), u64);
gen_load_store!(_load_block_id, store_block_id, offset_of!(Cpu, block_id), u64);
gen_load_store!(load_fuel, store_fuel, offset_of!(Cpu, fuel) + offset_of!(Fuel, remaining), u64);

fn load_const(builder: &mut FunctionBuilder, value: u64, ty: types::Type) -> Value {
    match ty {
        types::F32 => builder.ins().f32const(f32::from_bits(value as u32)),
        types::F64 => builder.ins().f64const(f64::from_bits(value)),
        _ if ty.bits() > 64 => {
            let tmp = builder.ins().iconst(types::I64, value as i64);
            builder.ins().uextend(ty, tmp)
        }
        _ => builder.ins().iconst(ty, value as i64),
    }
}

#[derive(Copy, Clone)]
struct WriteState {
    value: Value,
    dirty: bool,
    size: u8,
}

#[derive(Default)]
struct VarState {
    /// The last value written for each power of two.
    values: [Option<WriteState>; 5],
    last_size: u8,
}

impl VarState {
    fn flush_to_mem(&self, builder: &mut FunctionBuilder, vm_ptr: &VmPtr, var_id: pcode::VarId) {
        for (i, value) in self.values.iter().enumerate().rev() {
            let var_size = 1 << i;
            if let Some(write) = *value {
                if write.dirty && write.size == var_size {
                    vm_ptr.store_var(builder, pcode::VarNode::new(var_id, var_size), write.value);
                }
            }
        }
    }
}

pub(crate) struct TranslatorCtx {
    pub disable_jit_mem: bool,
    pub disable_jit_reg: bool,
    pub always_flush_vars: bool,
    pub enable_shadow_stack: bool,
    reg_pc: pcode::VarNode,
    endianness: Endianness,
    local_blocks: HashMap<usize, Block>,
    entry_points: Vec<(u64, Block)>,
    active_vars: HashMap<pcode::VarId, VarState>,
}

impl TranslatorCtx {
    pub(crate) fn new(reg_pc: pcode::VarNode, endianness: Endianness) -> Self {
        Self {
            reg_pc,
            disable_jit_mem: false,
            disable_jit_reg: false,
            always_flush_vars: true,
            enable_shadow_stack: true,
            endianness,
            local_blocks: HashMap::new(),
            entry_points: vec![],
            active_vars: HashMap::new(),
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
    module: &'a JITModule,
    mut builder: FunctionBuilder<'a>,
    ctx: &'a mut TranslatorCtx,
    functions: &crate::RuntimeFunctions,
    target: &CompilationTarget,
) {
    let symbols = Symbols::import(module, &mut builder.func, functions);
    let hook_sig = builder.import_signature(functions.hook_signature.clone());

    builder.func.signature.params.push(AbiParam::new(types::I64)); // cpu_ptr
    builder.func.signature.params.push(AbiParam::new(types::I64)); // jit_ctx
    builder.func.signature.params.push(AbiParam::new(types::I64)); // addr

    builder.func.signature.returns.push(AbiParam::new(types::I64)); // next_addr

    let (vm_ptr, jit_ctx, tlb_ptr) = define_jit_entry(&mut builder, ctx);

    let exit_block = builder.create_block();
    builder.append_block_param(exit_block, types::I64); // block_id
    builder.append_block_param(exit_block, types::I64); // block_offset
    builder.append_block_param(exit_block, types::I64); // next_addr

    let mut translator = Translator {
        builder,
        ctx,

        vm_ptr: VmPtr(vm_ptr),
        jit_ctx,
        tlb_ptr,
        hook_sig,
        symbols,
        srcloc: 0,

        last_addr: 0,
        block_id: 0,
        block_offset: 0,

        exit_block,
    };

    for (id, block) in target.iter() {
        translator.translate_block(id, block);
    }

    translator.finalize();
}

fn define_jit_entry(
    builder: &mut FunctionBuilder,
    ctx: &mut TranslatorCtx,
) -> (Value, Value, Value) {
    let entry_block = builder.create_block();

    builder.append_block_params_for_function_params(entry_block);
    builder.switch_to_block(entry_block);
    builder.seal_block(entry_block);

    let (cpu_ptr, jit_ctx, addr) = match builder.block_params(entry_block) {
        &[x0, x1, x2] => (x0, x1, x2),
        params => unreachable!("expected 3 params for entry block (got {})", params.len()),
    };

    // We always load the TLB ptr ahead of time here since it is likely to be used in almost every
    // block, and Cranelift's redundant load analysis isn't good enough to avoid reloading it.
    let tlb_ptr = builder.ins().load(
        types::I64,
        MemFlags::trusted().with_vmctx(),
        jit_ctx,
        offset_of!(VmCtx, tlb_ptr) as i32,
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
            builder.ins().trap(TrapCode::UnreachableCodeReached);
        }
    }

    (cpu_ptr, jit_ctx, tlb_ptr)
}

struct Translator<'a> {
    ctx: &'a mut TranslatorCtx,
    builder: FunctionBuilder<'a>,

    vm_ptr: VmPtr,
    jit_ctx: Value,
    tlb_ptr: Value,
    hook_sig: SigRef,
    symbols: Symbols,
    srcloc: u32,

    last_addr: u64,
    block_id: u64,
    block_offset: u64,

    exit_block: Block,
}

impl<'a> Translator<'a> {
    fn finalize(&mut self) {
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
        self.write(self.ctx.reg_pc, pc);

        self.builder.ins().return_(&[next_addr]);

        self.builder.finalize();
    }

    /// Creates a new block, jumps to it, switches to it, then seals it.
    fn jump_next_block(&mut self) -> Block {
        let next = self.builder.create_block();
        self.builder.ins().jump(next, &[]);
        self.builder.switch_to_block(next);
        self.builder.seal_block(next);
        next
    }

    /// Exit the JIT with the current interrupt code, value and block offset.
    fn goto_jit_exit_err(&mut self) {
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
        let block_id = self.builder.ins().iconst(types::I64, self.block_id as i64);
        let block_offset = self.builder.ins().iconst(types::I64, 0 as i64);
        self.builder.ins().jump(self.exit_block, &[block_id, block_offset, addr]);
    }

    /// Generates code that exits the JIT if there is an active exception. Returns the block
    /// associated with the `ok` case.
    fn maybe_exit_jit(&mut self) -> Block {
        let exception_code = self.vm_ptr.load_exception_code(&mut self.builder);

        let ok_block = self.builder.create_block();

        let err_block = self.builder.create_block();
        self.builder.set_cold_block(err_block);

        assert_eq!(ExceptionCode::None as u32, 0);
        self.builder.ins().brnz(exception_code, err_block, &[]);
        self.builder.ins().jump(ok_block, &[]);

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
        self.builder.ins().bitcast(ty, value)
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
                state.flush_to_mem(&mut self.builder, &self.vm_ptr, var.id);

                let var = pcode::VarNode::new(var.id, required_size);
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
            pcode::Value::Const(value, _) => load_const(&mut self.builder, value, ty),
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

        let flush = !var.is_temp() || self.ctx.always_flush_vars;
        match var.offset {
            0 => {
                let state = self.ctx.active_vars.entry(var.id).or_default();
                for i in 0..=var.size.trailing_zeros() as usize {
                    state.values[i] = Some(WriteState { value, size: var.size, dirty: !flush });
                }
                state.last_size = var.size
            }
            _ => {
                // Just invalidate any cached value if the offset is not zero.
                if let Some(entry) = self.ctx.active_vars.remove(&var.id) {
                    entry.flush_to_mem(&mut self.builder, &self.vm_ptr, var.id);
                }
            }
        }

        if flush {
            self.vm_ptr.store_var(&mut self.builder, var, value);
        }
    }

    fn flush_current_pc(&mut self) {
        let reg_pc = self.ctx.reg_pc;
        let current_pc = self.builder.ins().iconst(sized_int(reg_pc.size), self.last_addr as i64);
        self.write(reg_pc, current_pc)
    }

    /// Run an operation in the interpreter.
    fn interpret(&mut self, inst: pcode::Instruction) {
        tracing::debug!("interpreter will run for: pc={:#0x} {inst:?}", self.last_addr);

        if inst.output != pcode::VarNode::NONE {
            if let Some(entry) = self.ctx.active_vars.remove(&inst.output.id) {
                entry.flush_to_mem(&mut self.builder, &self.vm_ptr, inst.output.id);
            }
        }

        for input in inst.inputs.get() {
            if let pcode::Value::Var(var) = input {
                if let Some(entry) = self.ctx.active_vars.get(&var.id) {
                    entry.flush_to_mem(&mut self.builder, &self.vm_ptr, var.id);
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

    fn next_instruction(&mut self, addr: u64, _len: u64) {
        self.last_addr = addr;
        self.builder.ins().nop();
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

            let mut ctx = Ctx { trans: self, instruction: stmt.clone() };

            match stmt.op {
                Op::Copy => ctx.emit_copy(),
                Op::ZeroExtend => ctx.emit_zero_extend(),
                Op::SignExtend => ctx.emit_sign_extend(),
                Op::IntToFloat => ctx.emit_int_to_float(),
                Op::FloatToFloat => ctx.emit_float_to_float(),
                Op::FloatToInt => ctx.emit_float_to_int(),

                Op::IntAdd => ctx.emit_int_op(ops::int_add),
                Op::IntSub => ctx.emit_int_op(ops::int_sub),
                Op::IntXor => ctx.emit_int_op(ops::int_xor),
                Op::IntOr => ctx.emit_int_op(ops::int_or),
                Op::IntAnd => ctx.emit_int_op(ops::int_and),
                Op::IntMul => ctx.emit_int_op(ops::int_mul),

                Op::IntDiv => ctx.emit_div_op(ops::int_div),
                Op::IntSignedDiv => ctx.emit_div_op(ops::int_signed_div),
                Op::IntRem => ctx.emit_div_op(ops::int_rem),
                Op::IntSignedRem => ctx.emit_div_op(ops::int_signed_rem),

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
                    0 => mem::load_ram(self, inputs[0], output),
                    _ => {
                        if !is_native_size(output.size) {
                            ctx.trans.interpret(ctx.instruction);
                            continue;
                        }
                        let ptr = ctx.get_trace_store_ptr(id - 1, inputs[0]);
                        let value = mem::load_host(ctx.trans, ptr, output.size);
                        self.write(output, value);
                    }
                },
                Op::Store(id) => match id {
                    0 => mem::store_ram(self, inputs[0], inputs[1]),
                    _ => {
                        if !is_native_size(inputs[1].size()) {
                            ctx.trans.interpret(ctx.instruction);
                            continue;
                        }
                        let ptr = ctx.get_trace_store_ptr(id - 1, inputs[0]);
                        let value = ctx.trans.read_int(inputs[1]);
                        mem::store_host(ctx.trans, ptr, value, inputs[1].size());
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
                    self.maybe_exit_jit();
                }
                Op::Hook(id) => {
                    let current_pc =
                        ctx.trans.builder.ins().iconst(types::I64, ctx.trans.last_addr as i64);

                    // Fuzzware assumes PC is flushed to memory before calling the hook (even though
                    // the correct value is available as a parameter), so write it here now.
                    let reg_pc = ctx.trans.ctx.reg_pc;
                    let pc_sized = ctx.trans.resize_int(current_pc, 8, reg_pc.size);
                    ctx.trans.write(reg_pc, pc_sized);

                    let (fn_ptr, data_ptr) = ctx.get_hook(id);
                    let args = [self.vm_ptr.0, current_pc, data_ptr];
                    self.builder.ins().call_indirect(self.hook_sig, fn_ptr, &args);
                    self.maybe_exit_jit();
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

                // They operations should be removed during lifting, and IR-graph construction.
                Op::Subpiece(_)
                | Op::Branch(_)
                | Op::PcodeBranch(_)
                | Op::PcodeLabel(_)
                | Op::Invalid => {
                    let msg = u64::from_be_bytes(*b"bad op  ");
                    self.exit_with_exception(ExceptionCode::InvalidInstruction, msg);
                    return;
                }
            }

            if self.builder.is_filled() {
                tracing::error!("current block is filled (likely a JIT error)");
                return;
            }
        }

        self.builder.set_srcloc(codegen::ir::SourceLoc::new(self.srcloc));
        self.srcloc += 1;
        self.translate_block_exit(&block.exit);
    }

    /// If this block contains any _real_ instructions, then check that we have enough remaining
    /// fuel to fully execute it.
    fn check_for_fuel(&mut self, num_instructions: u32) {
        // @fixme: make `fuel` a variable.
        let remaining_fuel = self.vm_ptr.load_fuel(&mut self.builder);
        let required_fuel = num_instructions as i64;
        let insufficient_fuel =
            self.builder.ins().icmp_imm(IntCC::SignedLessThan, remaining_fuel, required_fuel);

        let ok_block = self.builder.create_block();
        let err_block = self.builder.create_block();
        self.builder.set_cold_block(err_block);

        self.builder.ins().brnz(insufficient_fuel, err_block, &[]);
        self.builder.ins().jump(ok_block, &[]);

        // err:
        {
            self.builder.switch_to_block(err_block);
            self.builder.seal_block(err_block);
            self.exit_with_exception(ExceptionCode::InstructionLimit, 0);
        }

        // ok:
        {
            self.builder.switch_to_block(ok_block);
            self.builder.seal_block(ok_block);

            let new = self.builder.ins().iadd_imm(remaining_fuel, -required_fuel);
            self.vm_ptr.store_fuel(&mut self.builder, new);
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
                self.builder.ins().brz(cond, false_block, &[]);
                self.builder.ins().jump(true_block, &[]);

                // true:
                {
                    self.builder.switch_to_block(true_block);
                    self.builder.seal_block(true_block);
                    self.goto_jump_target(&target);
                }

                // false:
                {
                    self.builder.switch_to_block(false_block);
                    self.builder.seal_block(false_block);
                    self.goto_jump_target(&fallthrough);
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
                // Check try to directly jump to the target, if it is defined in the current
                // function.
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
            Target::Invalid => {
                let msg = u64::from_be_bytes(*b"inv_exit");
                self.exit_with_exception(ExceptionCode::InvalidInstruction, msg);
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
