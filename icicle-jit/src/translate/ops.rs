use std::mem::size_of;

use cranelift::codegen::ir::AliasRegion;
use cranelift::prelude::*;
use icicle_cpu::{cpu::JitContext, Cpu, ExceptionCode, HookData};
use memoffset::offset_of;

use crate::translate::{is_jit_supported_size, sized_float, sized_int, Translator, VmPtr};

pub enum Overflow {
    True,
    False,
    Unknown(Value),
}

pub(super) struct Ctx<'a, 'b> {
    pub trans: &'a mut Translator<'b>,
    pub instruction: pcode::Instruction,
}

impl<'a, 'b> Ctx<'a, 'b> {
    fn load_tracer_mem_ptr(&mut self, id: u16) -> Value {
        let ptr_type = Type::int_with_byte_size(size_of::<*mut *mut u8>() as u16).unwrap();
        let offset: i32 = VmPtr::jit_ctx_offset()
            + offset_of!(JitContext, tracer_mem) as i32
            + id as i32 * ptr_type.bytes() as i32;
        self.trans.builder.ins().load(
            ptr_type,
            MemFlags::trusted().with_alias_region(Some(AliasRegion::Vmctx)),
            self.trans.vm_ptr.0,
            offset,
        )
    }

    pub fn get_trace_store_ptr(&mut self, id: u16, offset: pcode::Value) -> Value {
        let base = self.load_tracer_mem_ptr(id);
        if offset.const_eq(0) {
            return base;
        }
        let offset = self.trans.read_zxt(offset, 8);
        self.trans.builder.ins().iadd(base, offset)
    }

    pub fn get_hook(&mut self, id: u16) -> (Value, Value) {
        let base: i32 = VmPtr::jit_ctx_offset()
            + offset_of!(JitContext, hooks) as i32
            + (id as usize * size_of::<HookData>()) as i32;

        let fn_ptr = self.trans.builder.ins().load(
            Type::int_with_byte_size(size_of::<fn(*mut Cpu, u64, *mut ())>() as u16).unwrap(),
            MemFlags::trusted().with_alias_region(Some(AliasRegion::Vmctx)),
            self.trans.vm_ptr.0,
            base + offset_of!(HookData, fn_ptr) as i32,
        );

        let data_ptr = self.trans.builder.ins().load(
            Type::int_with_byte_size(size_of::<fn(*mut ())>() as u16).unwrap(),
            MemFlags::trusted().with_alias_region(Some(AliasRegion::Vmctx)),
            self.trans.vm_ptr.0,
            base + offset_of!(HookData, data_ptr) as i32,
        );

        (fn_ptr, data_ptr)
    }

    pub fn call_hook(&mut self, id: pcode::HookId) {
        // Currently we assume all hooks need state to be flushed to memory.
        //
        // @fixme: allow some hooks to only flush some variables.
        self.trans.varnode_fence();

        let current_pc = self.trans.builder.ins().iconst(types::I64, self.trans.last_addr as i64);

        // Some hooks assumes PC is flushed to memory before the call (even though the correct value
        // is available as a parameter), so write it here now.
        let reg_pc = self.trans.ctx.reg_pc;
        let pc_sized = self.trans.resize_int(current_pc, 8, reg_pc.size);
        self.trans.vm_ptr.store_var(&mut self.trans.builder, reg_pc, pc_sized);

        let (fn_ptr, data_ptr) = self.get_hook(id);
        let args = [data_ptr, self.trans.vm_ptr.0, current_pc];
        self.trans.builder.ins().call_indirect(self.trans.hook_sig, fn_ptr, &args);
    }

    /// Calls a hook function with lower overhead, but with potentially stale state (register
    /// flushing is skipped).
    #[allow(unused)] // @todo: expose this to pcode ops.
    pub fn call_thin_hook(&mut self, id: pcode::HookId) {
        let current_pc = self.trans.builder.ins().iconst(types::I64, self.trans.last_addr as i64);
        let (fn_ptr, data_ptr) = self.get_hook(id);
        let args = [data_ptr, self.trans.vm_ptr.0, current_pc];
        self.trans.builder.ins().call_indirect(self.trans.hook_sig, fn_ptr, &args);
    }

    fn read_int_inputs(&mut self) -> (Value, Value) {
        let a = self.trans.read_int(self.instruction.inputs.first());
        let b = self.trans.read_int(self.instruction.inputs.second());
        (a, b)
    }

    pub fn emit_copy(&mut self) {
        let input = self.instruction.inputs.first();

        if !is_jit_supported_size(input.size()) {
            for i in 0..input.size() {
                let x = self.trans.read_int(input.slice(i, 1));
                self.trans.write(self.instruction.output.slice(i, 1), x);
            }
            return;
        }
        let x = self.trans.read_int(input);
        self.trans.write(self.instruction.output, x);
    }

    pub fn emit_zero_extend(&mut self) {
        let input = self.instruction.inputs.first();
        let output = self.instruction.output;

        if output.size <= input.size() {
            unreachable!("Expected ZXT to larger type to be converted to copy operation.");
        }

        let x = self.trans.read_int(input);
        let result = self.trans.resize_int(x, input.size(), output.size);
        self.trans.write(output, result);
    }

    pub fn emit_sign_extend(&mut self) {
        let input = self.instruction.inputs.first();
        let output = self.instruction.output;

        if output.size <= input.size() {
            unreachable!("Expected SXT to larger type to be converted to copy operation.");
        }

        let value = self.trans.read_int(input);
        let result = sign_extend(self.trans, value, input.size(), output.size);
        self.trans.write(output, result);
    }

    pub fn emit_int_op(&mut self, op: fn(&mut Translator, Value, Value) -> Value) {
        let (a, b) = self.read_int_inputs();
        let result = op(self.trans, a, b);
        self.trans.write(self.instruction.output, result);
    }

    pub fn emit_int_unary_op(&mut self, op: fn(&mut Translator, Value) -> Value) {
        let x = self.trans.read_int(self.instruction.inputs.first());
        let result = op(self.trans, x);
        self.trans.write(self.instruction.output, result);
    }

    pub fn emit_count_ones(&mut self) {
        let input = self.instruction.inputs.first();
        let x = self.trans.read_int(input);
        let result = {
            let tmp = self.trans.builder.ins().popcnt(x);
            self.trans.resize_int(tmp, input.size(), self.instruction.output.size)
        };
        self.trans.write(self.instruction.output, result);
    }

    pub fn emit_count_leading_zeroes(&mut self) {
        let input = self.instruction.inputs.first();
        let x = self.trans.read_int(input);
        let result = {
            let tmp = self.trans.builder.ins().clz(x);
            self.trans.resize_int(tmp, input.size(), self.instruction.output.size)
        };
        self.trans.write(self.instruction.output, result);
    }

    pub fn emit_div_op(&mut self, op: fn(&mut Translator, Value, Value) -> Value, signed: bool) {
        if self.instruction.output.size > 8 {
            // 128-bit division is not currently supported in cranelift
            self.trans.interpret(self.instruction);
            // Check for div by 0 exception
            self.trans.maybe_exit_jit(None);
            return;
        }

        let (a, b) = self.read_int_inputs();

        // Check for division by zero.
        let ok_block = self.trans.builder.create_block();

        let err_block = self.trans.builder.create_block();
        self.trans.builder.set_cold_block(err_block);

        if signed {
            // Overflow only occurs when `a = -2^{bits-1} and b = -1`
            let overflow = {
                let a_val: u64 = 1 << ((self.instruction.output.size as u32 * 8) - 1);
                let a_cond = self.trans.builder.ins().icmp_imm(IntCC::Equal, a, a_val as i64);
                let b_val = u64::MAX >> (u64::BITS - self.instruction.output.size as u32 * 8);
                let b_cond = self.trans.builder.ins().icmp_imm(IntCC::Equal, b, b_val as i64);
                self.trans.builder.ins().band(a_cond, b_cond)
            };

            let next_block = self.trans.builder.create_block();

            self.trans.builder.ins().brif(overflow, err_block, &[], next_block, &[]);

            // next:
            self.trans.builder.switch_to_block(next_block);
            self.trans.builder.seal_block(next_block);
        }

        self.trans.builder.ins().brif(b, ok_block, &[], err_block, &[]);

        // err:
        {
            self.trans.builder.switch_to_block(err_block);
            self.trans.builder.seal_block(err_block);
            self.trans.exit_with_exception(ExceptionCode::DivisionException, 0);
        }

        // ok:
        {
            self.trans.builder.switch_to_block(ok_block);
            self.trans.builder.seal_block(ok_block);

            let result = op(self.trans, a, b);
            self.trans.write(self.instruction.output, result);
        }
    }

    pub fn emit_shift_op(
        &mut self,
        op: fn(&mut Translator, Type, Value, Value, Overflow) -> Value,
    ) {
        let inputs = self.instruction.inputs.get();

        let output = self.instruction.output;
        let ty = sized_int(output.size);

        let x = {
            let tmp = self.trans.read_int(inputs[0]);
            self.trans.resize_int(tmp, inputs[0].size(), output.size)
        };

        let raw_shift = self.trans.read_int(inputs[1]);

        // Oversized shifts are not masked in p-code, so check whether this shift will overflow, and
        // correct the result.
        //
        // @todo: consider handling during p-code lifting.
        let max_shift = ty.bits() - 1;
        let overflow = match inputs[1] {
            pcode::Value::Var(_) => {
                let max_shift =
                    self.trans.load_const(sized_int(inputs[1].size()), max_shift as u64);
                let overflow =
                    self.trans.builder.ins().icmp(IntCC::UnsignedGreaterThan, raw_shift, max_shift);
                Overflow::Unknown(overflow)
            }
            pcode::Value::Const(value, _) => match value as u32 > max_shift {
                true => Overflow::True,
                false => Overflow::False,
            },
        };

        // Some backends may not like oversized shift operands and we never use this value if the
        // upper bits are set so it is safe to truncate here.
        let truncated_shift = self.trans.resize_int(raw_shift, inputs[1].size(), 2);

        let result = op(self.trans, ty, x, truncated_shift, overflow);
        self.trans.write(output, result);
    }

    pub fn emit_int_cmp(&mut self, op: fn(&mut Translator, Value, Value) -> Value) {
        let (a, b) = self.read_int_inputs();
        let result = op(self.trans, a, b);
        self.trans.write(self.instruction.output, result);
    }

    pub fn emit_bool_op(&mut self, op: fn(&mut Translator, Value, Value) -> Value) {
        let inputs = self.instruction.inputs.get();
        let a = self.trans.read_bool(inputs[0]);
        let b = self.trans.read_bool(inputs[1]);
        let result = op(self.trans, a, b);
        self.trans.write(self.instruction.output, result);
    }

    pub fn emit_float_op(&mut self, op: fn(&mut Translator, Value, Value) -> Value) {
        let inputs = self.instruction.inputs.get();
        let a = self.trans.read_float(inputs[0]);
        let b = self.trans.read_float(inputs[1]);
        let result = op(self.trans, a, b);
        let result = self.trans.bitcast(sized_int(self.instruction.output.size), result);
        self.trans.write(self.instruction.output, result);
    }

    pub fn emit_float_unary_op(&mut self, op: fn(&mut Translator, Value) -> Value) {
        let x = self.trans.read_float(self.instruction.inputs.first());
        let result = op(self.trans, x);
        let result = self.trans.bitcast(sized_int(self.instruction.output.size), result);
        self.trans.write(self.instruction.output, result);
    }

    pub fn emit_float_is_nan(&mut self) {
        let input = self.instruction.inputs.first();

        let tmp = match input.size() {
            4 => self.trans.builder.ins().f32const(0.0),
            8 => self.trans.builder.ins().f64const(0.0),
            _ => return self.trans.interpret(self.instruction),
        };

        let x = self.trans.read_float(input);
        let result = self.trans.builder.ins().fcmp(FloatCC::Unordered, x, tmp);
        self.trans.write(self.instruction.output, result);
    }

    pub fn emit_float_cmp(&mut self, op: fn(&mut Translator, Value, Value) -> Value) {
        let inputs = self.instruction.inputs.get();
        let a = self.trans.read_float(inputs[0]);
        let b = self.trans.read_float(inputs[1]);
        let result = op(self.trans, a, b);
        self.trans.write(self.instruction.output, result);
    }

    pub fn emit_float_to_float(&mut self) {
        let input = self.instruction.inputs.first();
        let output = self.instruction.output;

        if ![4, 8].contains(&input.size()) || ![4, 8].contains(&output.size) {
            // Cranelift currently only supports f32 and f64 conversions.
            return self.trans.interpret(self.instruction);
        }

        let x = self.trans.read_float(input);
        let result = match input.size() < output.size {
            true => self.trans.builder.ins().fpromote(sized_float(output.size), x),
            false => self.trans.builder.ins().fdemote(sized_float(output.size), x),
        };
        let result = self.trans.bitcast(sized_int(output.size), result);
        self.trans.write(output, result);
    }

    pub fn emit_int_to_float(&mut self) {
        let input = self.instruction.inputs.first();
        let output = self.instruction.output;

        if ![4, 8].contains(&output.size) || ![4, 8].contains(&input.size()) {
            // Should be unreachable, currently we rewrite these operations to use f32/f64 then
            // perform a float-to-float cast to get the final value, but we might want to support
            // direct conversions in the future.
            return self.trans.interpret(self.instruction);
        }
        let x = self.trans.read_int(input);
        let result = self.trans.builder.ins().fcvt_from_sint(sized_float(output.size), x);
        let result = self.trans.bitcast(sized_int(output.size), result);
        self.trans.write(output, result);
    }

    pub fn emit_uint_to_float(&mut self) {
        let input = self.instruction.inputs.first();
        let output = self.instruction.output;

        if ![4, 8].contains(&output.size) || ![4, 8].contains(&input.size()) {
            // Should be unreachable (see above).
            return self.trans.interpret(self.instruction);
        }
        let x = self.trans.read_int(input);
        let result = self.trans.builder.ins().fcvt_from_uint(sized_float(output.size), x);
        let result = self.trans.bitcast(sized_int(output.size), result);
        self.trans.write(output, result);
    }

    pub fn emit_float_to_int(&mut self) {
        let input = self.instruction.inputs.first();
        let output = self.instruction.output;

        if ![4, 8].contains(&input.size()) {
            // Should be unreachable (see above).
            return self.trans.interpret(self.instruction);
        }
        let x = self.trans.read_float(input);
        let result = match output.size {
            4 | 8 => self.trans.builder.ins().fcvt_to_sint_sat(sized_int(output.size), x),
            size => {
                let tmp = self.trans.builder.ins().fcvt_to_sint_sat(types::I32, x);
                self.trans.resize_int(tmp, 8, size)
            }
        };
        self.trans.write(output, result);
    }
}

pub(super) fn sign_extend(
    trans: &mut Translator,
    value: Value,
    in_size: u8,
    out_size: u8,
) -> Value {
    if is_jit_supported_size(in_size) && is_jit_supported_size(out_size) {
        return trans.builder.ins().sextend(sized_int(out_size), value);
    }
    if !is_jit_supported_size(out_size) {
        tracing::warn!("[{:#x}] sign extend to a non-natively sized integer", trans.last_addr);
    }

    let x = trans.resize_int(value, in_size, out_size);
    let shift = (out_size - in_size) as i64 * 8;
    let x = trans.builder.ins().ishl_imm(x, shift);
    trans.builder.ins().sshr_imm(x, shift)
}

pub(super) fn float_div(trans: &mut Translator, a: Value, b: Value) -> Value {
    trans.builder.ins().fdiv(a, b)
}

pub(super) fn float_mul(trans: &mut Translator, a: Value, b: Value) -> Value {
    trans.builder.ins().fmul(a, b)
}

pub(super) fn float_add(trans: &mut Translator, a: Value, b: Value) -> Value {
    trans.builder.ins().fadd(a, b)
}

pub(super) fn float_sub(trans: &mut Translator, a: Value, b: Value) -> Value {
    trans.builder.ins().fsub(a, b)
}

pub(super) fn bool_xor(trans: &mut Translator, a: Value, b: Value) -> Value {
    trans.builder.ins().bxor(a, b)
}

pub(super) fn bool_and(trans: &mut Translator, a: Value, b: Value) -> Value {
    trans.builder.ins().band(a, b)
}

pub(super) fn bool_or(trans: &mut Translator, a: Value, b: Value) -> Value {
    trans.builder.ins().bor(a, b)
}

pub(super) fn int_mul(trans: &mut Translator, a: Value, b: Value) -> Value {
    trans.builder.ins().imul(a, b)
}

pub(super) fn int_add(trans: &mut Translator, a: Value, b: Value) -> Value {
    trans.builder.ins().iadd(a, b)
}

pub(super) fn int_sub(trans: &mut Translator, a: Value, b: Value) -> Value {
    trans.builder.ins().isub(a, b)
}

pub(super) fn int_and(trans: &mut Translator, a: Value, b: Value) -> Value {
    trans.builder.ins().band(a, b)
}

pub(super) fn int_xor(trans: &mut Translator, a: Value, b: Value) -> Value {
    trans.builder.ins().bxor(a, b)
}

pub(super) fn int_or(trans: &mut Translator, a: Value, b: Value) -> Value {
    trans.builder.ins().bor(a, b)
}

pub(super) fn int_div(trans: &mut Translator, a: Value, b: Value) -> Value {
    trans.builder.ins().udiv(a, b)
}

pub(super) fn int_signed_div(trans: &mut Translator, a: Value, b: Value) -> Value {
    trans.builder.ins().sdiv(a, b)
}

pub(super) fn int_rem(trans: &mut Translator, a: Value, b: Value) -> Value {
    trans.builder.ins().urem(a, b)
}

pub(super) fn int_signed_rem(trans: &mut Translator, a: Value, b: Value) -> Value {
    trans.builder.ins().srem(a, b)
}

// x.checked_shl(shift).unwrap_or(0)
pub(super) fn int_left(
    trans: &mut Translator,
    ty: Type,
    x: Value,
    shift: Value,
    of: Overflow,
) -> Value {
    match of {
        Overflow::True => trans.load_const(ty, 0),
        Overflow::False => trans.builder.ins().ishl(x, shift),
        Overflow::Unknown(overflow) => {
            let x = trans.builder.ins().ishl(x, shift);
            let zero = trans.load_const(ty, 0);
            trans.builder.ins().select(overflow, zero, x)
        }
    }
}

// x.rotate_left(n)
pub(super) fn int_rotate_left(trans: &mut Translator, x: Value, n: Value) -> Value {
    trans.builder.ins().rotl(x, n)
}

// x.checked_shr(shift).unwrap_or(0)
pub(super) fn int_right(
    trans: &mut Translator,
    ty: Type,
    x: Value,
    shift: Value,
    of: Overflow,
) -> Value {
    match of {
        Overflow::True => trans.load_const(ty, 0),
        Overflow::False => trans.builder.ins().ushr(x, shift),
        Overflow::Unknown(overflow) => {
            let x = trans.builder.ins().ushr(x, shift);
            let zero = trans.load_const(ty, 0);
            trans.builder.ins().select(overflow, zero, x)
        }
    }
}

// x s>> shift.min(max_shift)
pub(super) fn int_signed_right(
    trans: &mut Translator,
    ty: Type,
    x: Value,
    shift: Value,
    of: Overflow,
) -> Value {
    let max_shift = (ty.bits() - 1) as i64;
    match of {
        Overflow::True => trans.builder.ins().sshr_imm(x, max_shift),
        Overflow::False => trans.builder.ins().sshr(x, shift),
        Overflow::Unknown(overflow) => {
            let max_shift = trans.builder.ins().iconst(types::I16, max_shift);
            let shift = trans.builder.ins().select(overflow, max_shift, shift);
            trans.builder.ins().sshr(x, shift)
        }
    }
}

// x.rotate_right(n)
pub(super) fn int_rotate_right(trans: &mut Translator, x: Value, n: Value) -> Value {
    trans.builder.ins().rotr(x, n)
}

pub(super) fn int_equal(trans: &mut Translator, a: Value, b: Value) -> Value {
    trans.builder.ins().icmp(IntCC::Equal, a, b)
}

pub(super) fn int_not_equal(trans: &mut Translator, a: Value, b: Value) -> Value {
    trans.builder.ins().icmp(IntCC::NotEqual, a, b)
}

pub(super) fn int_less(trans: &mut Translator, a: Value, b: Value) -> Value {
    trans.builder.ins().icmp(IntCC::UnsignedLessThan, a, b)
}

pub(super) fn int_signed_less(trans: &mut Translator, a: Value, b: Value) -> Value {
    trans.builder.ins().icmp(IntCC::SignedLessThan, a, b)
}

pub(super) fn int_less_equal(trans: &mut Translator, a: Value, b: Value) -> Value {
    trans.builder.ins().icmp(IntCC::UnsignedLessThanOrEqual, a, b)
}

pub(super) fn int_signed_less_equal(trans: &mut Translator, a: Value, b: Value) -> Value {
    trans.builder.ins().icmp(IntCC::SignedLessThanOrEqual, a, b)
}

pub(super) fn int_carry(trans: &mut Translator, a: Value, b: Value) -> Value {
    // @fixme: this is broken in cranelift
    // let (_, carry) = trans.builder.ins().iadd_cout(a, b);
    // carry

    let a = trans.builder.ins().iadd(a, b);
    trans.builder.ins().icmp(IntCC::UnsignedLessThan, a, b)
}

/// Overflow on addition.
pub(super) fn int_signed_carry(trans: &mut Translator, a: Value, b: Value) -> Value {
    // let b = trans.builder.ins().ineg(b);
    // trans.builder.ins().icmp(IntCC::Overflow, a, b)

    // Check that we end up with the correct sign assuming signed addition.
    // @fixme: Cranelift removed `IntCC::Overflow` so this results in sub-optimal codegen.
    let result = trans.builder.ins().iadd(a, b);
    let result_lt_a = trans.builder.ins().icmp(IntCC::SignedLessThan, result, a);
    let b_is_neg = trans.builder.ins().icmp_imm(IntCC::SignedLessThan, b, 0);
    trans.builder.ins().bxor(result_lt_a, b_is_neg)
}

/// Overflow on subtraction
pub(super) fn int_signed_borrow(trans: &mut Translator, a: Value, b: Value) -> Value {
    // trans.builder.ins().icmp(IntCC::Overflow, a, b)

    // Check that we end up with the correct sign assuming signed subtraction.
    // @fixme: Cranelift removed `IntCC::Overflow` so this results in sub-optimal codegen.
    let result = trans.builder.ins().isub(a, b);
    let result_gt_a = trans.builder.ins().icmp(IntCC::SignedGreaterThan, result, a);
    let b_is_neg = trans.builder.ins().icmp_imm(IntCC::SignedLessThan, b, 0);
    trans.builder.ins().bxor(result_gt_a, b_is_neg)
}

pub(super) fn float_negate(trans: &mut Translator, x: Value) -> Value {
    trans.builder.ins().fneg(x)
}

pub(super) fn float_abs(trans: &mut Translator, x: Value) -> Value {
    trans.builder.ins().fabs(x)
}

pub(super) fn float_sqrt(trans: &mut Translator, x: Value) -> Value {
    trans.builder.ins().sqrt(x)
}

pub(super) fn float_ceil(trans: &mut Translator, x: Value) -> Value {
    trans.builder.ins().ceil(x)
}

pub(super) fn float_floor(trans: &mut Translator, x: Value) -> Value {
    trans.builder.ins().floor(x)
}

pub(super) fn float_round(trans: &mut Translator, x: Value) -> Value {
    trans.builder.ins().nearest(x)
}

pub(super) fn int_not(trans: &mut Translator, x: Value) -> Value {
    trans.builder.ins().bnot(x)
}

pub(super) fn int_negate(trans: &mut Translator, x: Value) -> Value {
    trans.builder.ins().ineg(x)
}

pub(super) fn bool_not(trans: &mut Translator, input: Value) -> Value {
    let x = trans.builder.ins().bnot(input);
    trans.builder.ins().band_imm(x, 0b1)
}

pub(super) fn float_less(trans: &mut Translator, a: Value, b: Value) -> Value {
    trans.builder.ins().fcmp(FloatCC::LessThan, a, b)
}

pub(super) fn float_less_equal(trans: &mut Translator, a: Value, b: Value) -> Value {
    trans.builder.ins().fcmp(FloatCC::LessThanOrEqual, a, b)
}

pub(super) fn float_equal(trans: &mut Translator, a: Value, b: Value) -> Value {
    trans.builder.ins().fcmp(FloatCC::Equal, a, b)
}

pub(super) fn float_not_equal(trans: &mut Translator, a: Value, b: Value) -> Value {
    trans.builder.ins().fcmp(FloatCC::NotEqual, a, b)
}

#[cfg(test)]
mod test {
    use std::cell::RefCell;

    use icicle_cpu::{Arch, Cpu, ValueSource};

    fn compile_instruction(jit: &mut crate::JIT, inst: pcode::Instruction) -> crate::JitFunction {
        jit.il_dump = Some(String::new());
        jit.compile(&crate::CompilationTarget {
            blocks: &[icicle_cpu::lifter::Block {
                pcode: {
                    let mut block = pcode::Block::new();
                    block.push(inst);
                    block
                },
                entry: Some(0x0),
                start: 0x0,
                end: 0x1,
                context: 0,
                exit: icicle_cpu::lifter::BlockExit::Jump {
                    target: icicle_cpu::lifter::Target::External(0x4000_u64.into()),
                },
                breakpoints: 0,
                num_instructions: 0,
            }],
            targets: &[0],
        })
        .unwrap();

        jit.entry_points[&0]
    }

    struct Checker {
        cpu: RefCell<Box<Cpu>>,
        jit: crate::JIT,
        inst: pcode::Instruction,
        a: pcode::VarNode,
        b: pcode::VarNode,
        out: pcode::VarNode,
        jit_fn: crate::JitFunction,
    }

    impl Drop for Checker {
        fn drop(&mut self) {
            unsafe { self.jit.reset() }
        }
    }

    impl Checker {
        fn new(op: pcode::Op, out_size: u8) -> Self {
            let cpu = Cpu::new_boxed(Arch::none());
            let mut jit = crate::JIT::new(&cpu);

            let a = cpu.arch.sleigh.get_reg("a").unwrap().var.slice(0, 4);
            let b = cpu.arch.sleigh.get_reg("b").unwrap().var.slice(0, 4);
            let out = cpu.arch.sleigh.get_reg("c").unwrap().var.slice(0, out_size);

            let inst = pcode::Instruction::from((out, op, (a, b)));
            let jit_fn = compile_instruction(&mut jit, inst);

            Self { cpu: RefCell::new(cpu), jit, inst, a, b, out, jit_fn }
        }

        fn eval_binop(&self, a: u32, b: u32) -> (u32, u32) {
            let mut cpu = self.cpu.borrow_mut();

            cpu.write_var(self.a, a);
            cpu.write_var(self.b, b);
            cpu.write_trunc(self.out, 0xaaaa_aaaa_u32);
            unsafe { cpu.interpret_unchecked(self.inst) };
            let interpreter_out = cpu.read_dynamic(self.out.into()).zxt();

            cpu.write_var(self.a, a);
            cpu.write_var(self.b, b);
            cpu.write_trunc(self.out, 0xaaaa_aaaa_u32);

            cpu.jit_ctx.tlb_ptr = cpu.mem.tlb.as_mut();
            unsafe {
                (self.jit_fn)((*cpu).as_mut() as *mut Cpu, 0x0);
            }
            let jit_out = cpu.read_dynamic(self.out.into()).zxt();
            (interpreter_out, jit_out)
        }
    }

    impl quickcheck::Testable for Checker {
        fn result(&self, gen: &mut quickcheck::Gen) -> quickcheck::TestResult {
            let a: u32 = quickcheck::Arbitrary::arbitrary(gen);
            let b: u32 = quickcheck::Arbitrary::arbitrary(gen);

            let (interpreter_out, jit_out) = self.eval_binop(a, b);

            if interpreter_out != jit_out {
                quickcheck::TestResult::error(format!(
                    "{a:#x} {:?} {b:#x}: Interpreter: {interpreter_out:#x}, JIT: {jit_out:#x}\nclif: {}",
                    self.inst.op,
                    self.jit.il_dump.as_ref().map_or("", String::as_str)
                ))
            }
            else {
                quickcheck::TestResult::passed()
            }
        }
    }

    fn test_binop(op: pcode::Op) {
        quickcheck::QuickCheck::new().quickcheck(Checker::new(op, 4));
    }

    fn test_cmp_op(op: pcode::Op) {
        quickcheck::QuickCheck::new().quickcheck(Checker::new(op, 1));
    }

    #[test]
    fn test_simple_int_binop() {
        test_binop(pcode::Op::IntAdd);
        test_binop(pcode::Op::IntSub);
        test_binop(pcode::Op::IntXor);
        test_binop(pcode::Op::IntOr);
        test_binop(pcode::Op::IntAnd);
        test_binop(pcode::Op::IntMul);
        test_binop(pcode::Op::IntDiv);
        test_binop(pcode::Op::IntSignedDiv);
    }

    #[test]
    fn carry() {
        test_cmp_op(pcode::Op::IntCarry);
    }

    #[test]
    fn signed_carry() {
        test_cmp_op(pcode::Op::IntSignedCarry);
    }

    #[test]
    fn signed_borrow() {
        test_cmp_op(pcode::Op::IntSignedBorrow);
    }

    #[test]
    fn sshr() {
        test_binop(pcode::Op::IntSignedRight);
    }

    #[test]
    fn ushr() {
        // Regression test
        let checker = Checker::new(pcode::Op::IntRight, 4);
        let (int, jit) = checker.eval_binop(0x67879a2f, 0xe29e001b);
        assert_eq!(int, jit);

        test_binop(pcode::Op::IntRight);
    }

    #[test]
    fn shl() {
        test_binop(pcode::Op::IntLeft);
    }
}
