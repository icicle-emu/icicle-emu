//! Helpers for rewriting pcode instructions to use native sizes and workarounds for SLEIGH bugs.

use crate::lifter::PcodePatcher;

/// Apply rewrites to the given instructions writing the results to `out`.
///
/// Note: `out` will be cleared before the instructions are rewritten.
pub fn apply_rewrites(block: &pcode::Block, out: &mut pcode::Block) {
    out.clear();
    out.next_tmp = block.next_tmp();
    for i in 0..block.instructions.len() {
        rewrite_one(i, &block.instructions, out);
    }
}

/// Rewrites the instruction at `i` appending one or more operations necessary to emulate the
/// instruction using native operations to `out`.
fn rewrite_one(i: usize, instructions: &[pcode::Instruction], out: &mut pcode::Block) {
    use pcode::Op;

    let inst = instructions[i];
    let x = inst.output;
    let [a, b] = inst.inputs.get();

    // SLEIGH uses zero-extended int-to-float conversions to support _unsigned_ integer to
    // float conversions. Instead we directly support unsigned float conversions to allow them to be
    // emulated with native conversion instructions.
    if matches!(inst.op, Op::IntToFloat) && a.size() > 8 {
        if i == 0 {
            out.push(pcode::Op::Invalid);
            return;
        }
        let Some(src) = zxt_from(instructions[i - 1], a)
        else {
            out.push(pcode::Op::Invalid);
            return;
        };

        if [4, 8].contains(&x.size) {
            out.push((x, pcode::Op::UintToFloat, src));
            return;
        }

        // Handle casts to 16 bit floats.
        let tmp = out.alloc_tmp(8);
        out.push((tmp, pcode::Op::UintToFloat, src));
        let result = emit_cast_float(out, tmp.into(), x.size);
        out.push((x, pcode::Op::Copy, result));
        return;
    }

    // Ensure that the operation uses supported varnode sizes.
    let (x_size, (a_size, b_size)) = inst.op.native_var_sizes();
    if x_size.contains(&x.size) && a_size.contains(&a.size()) && b_size.contains(&b.size()) {
        out.push(inst);
        return;
    }

    // Rewrite operations on non-natively sized inputs/outputs
    match inst.op {
        // Copy/Load/Store operations have special cases for non-native sizes.
        Op::Copy | Op::Load(_) | Op::Store(_) => out.push(inst),

        // Convert a ZXT instruction to a zero then copy instruction.
        Op::ZeroExtend => {
            let value = emit_non_native_zxt(out, a, x.size);
            out.push((x, pcode::Op::Copy, value));
        }

        // Convert a SXT instruction to copy and shift operations.
        Op::SignExtend => {
            let value = emit_non_native_sxt(out, a, x.size);
            out.push((x, pcode::Op::Copy, value));
        }

        // Handle integer operations by sign-extending, executing the op, then copying the lower
        // bits. (@todo: add extra operations here).
        Op::IntAdd | Op::IntSub | Op::IntMul => {
            let widened = a.size().next_power_of_two();
            let a_sxt = emit_non_native_sxt(out, a, widened);
            let b_sxt = emit_non_native_sxt(out, b, widened);
            let result = out.alloc_tmp(widened);
            out.push((result, inst.op, (a_sxt, b_sxt)));
            out.push((x, pcode::Op::Copy, result.truncate(x.size)));
        }

        // Handle unsigned comparisions by widening inputs
        Op::IntEqual | Op::IntNotEqual | Op::IntLess | Op::IntLessEqual => {
            let widened = a.size().next_power_of_two();
            let a_zxt = emit_non_native_zxt(out, a, widened);
            let b_zxt = emit_non_native_zxt(out, b, widened);
            out.push((x, inst.op, (a_zxt, b_zxt)));
        }

        // Handle signed comparisions by sign-extending inputs
        Op::IntSignedLess | Op::IntSignedLessEqual => {
            let widened = a.size().next_power_of_two();
            let a_sxt = emit_non_native_sxt(out, a, widened);
            let b_sxt = emit_non_native_sxt(out, b, widened);
            out.push((x, inst.op, (a_sxt, b_sxt)));
        }

        Op::FloatToFloat => out.push(inst),

        // @fixme: 80-bit floats need to be handled manually to avoid losing precision.
        //
        // Handle 16-bit and 80-bit floating operations using native float operations.
        Op::FloatToInt => {
            let a = emit_cast_float_to_native(out, a);
            out.push((x, pcode::Op::FloatToInt, a));
        }
        Op::IntToFloat => {
            // Handle casts to 16-bit and 80-bit floats.
            let tmp = match x.size {
                2 => out.alloc_tmp(4),
                10 => out.alloc_tmp(8),
                _ => {
                    out.push(Op::Invalid);
                    return;
                }
            };
            out.push((tmp, pcode::Op::IntToFloat, a));
            let result = emit_cast_float(out, tmp.into(), x.size);
            out.push((x, pcode::Op::Copy, result));
        }

        Op::FloatAdd | Op::FloatSub | Op::FloatMul | Op::FloatDiv => {
            let a = emit_cast_float_to_native(out, a);
            let b = emit_cast_float_to_native(out, b);
            let result = out.alloc_tmp(a.size());
            out.push((result, inst.op, (a, b)));
            let result = emit_cast_float(out, result.into(), x.size);
            out.push((x, pcode::Op::Copy, result));
        }
        Op::FloatNegate
        | Op::FloatAbs
        | Op::FloatSqrt
        | Op::FloatCeil
        | Op::FloatFloor
        | Op::FloatRound => {
            let a = emit_cast_float_to_native(out, a);
            let result = out.alloc_tmp(a.size());
            out.push((result, inst.op, a));
            let result = emit_cast_float(out, result.into(), x.size);
            out.push((x, pcode::Op::Copy, result));
        }
        Op::FloatEqual | Op::FloatNotEqual | Op::FloatLess | Op::FloatLessEqual => {
            let a = emit_cast_float_to_native(out, a);
            let b = emit_cast_float_to_native(out, b);
            out.push((x, inst.op, (a, b)));
        }
        Op::FloatIsNan => {
            let a = emit_cast_float_to_native(out, a);
            out.push((x, inst.op, a));
        }

        // Pcode operations do not declare valid operand size (they will be force to check
        // internally).
        Op::PcodeOp(_) => out.push(inst),

        // Other operations are not supported.
        _ => out.push(Op::Invalid),
    }
}

/// Returns non zero extended copy of `a` if `instr` is a zero extension operation.
fn zxt_from(instr: pcode::Instruction, a: pcode::Value) -> Option<pcode::Value> {
    if matches!(instr.op, pcode::Op::ZeroExtend) && pcode::Value::Var(instr.output) == a {
        return Some(instr.inputs.get()[0]);
    }
    None
}

fn emit_non_native_zxt(block: &mut pcode::Block, a: pcode::Value, size: u8) -> pcode::Value {
    let widened = size.next_power_of_two();
    let tmp = block.alloc_tmp(widened);
    block.push((tmp, pcode::Op::Copy, pcode::Value::Const(0, widened)));
    block.push((tmp.truncate(a.size()), pcode::Op::Copy, a));
    tmp.truncate(size).into()
}

fn emit_non_native_sxt(block: &mut pcode::Block, a: pcode::Value, size: u8) -> pcode::Value {
    let widened = size.next_power_of_two();
    let tmp = block.alloc_tmp(widened);
    block.push((tmp, pcode::Op::Copy, pcode::Value::Const(0, widened)));
    block.push((tmp.truncate(a.size()), pcode::Op::Copy, a));

    let shift_size = 8 * (widened - a.size());
    block.push((tmp, pcode::Op::IntLeft, (tmp, shift_size)));
    block.push((tmp, pcode::Op::IntSignedRight, (tmp, shift_size)));

    tmp.truncate(size).into()
}

fn emit_cast_float_to_native(block: &mut pcode::Block, a: pcode::Value) -> pcode::Value {
    if a.size() == 2 {
        // 16-bit floats
        let tmp = block.alloc_tmp(4);
        block.push((tmp, pcode::Op::FloatToFloat, a));
        tmp.into()
    }
    else if a.size() == 10 {
        // 80-bit floats
        let tmp = block.alloc_tmp(8);
        block.push((tmp, pcode::Op::FloatToFloat, a));
        tmp.into()
    }
    else {
        pcode::Value::invalid()
    }
}

fn emit_cast_float(block: &mut pcode::Block, a: pcode::Value, size: u8) -> pcode::Value {
    if size == 2 {
        let tmp = block.alloc_tmp(2);
        block.push((tmp, pcode::Op::FloatToFloat, a));
        tmp.into()
    }
    else if size == 10 {
        let tmp = block.alloc_tmp(10);
        block.push((tmp, pcode::Op::FloatToFloat, a));
        tmp.into()
    }
    else {
        pcode::Value::invalid()
    }
}

/// Some of the specifications (e.g. MSP430, ARM), read/write to the PC directly (instead of using a
/// disassembly time constant).
///
/// This breaks instrumentation expecting the PC register to only be modified as part of control
/// flow. To avoid this we convert writes to PC to a write to a tmp register first, and reads to PC
/// to use the address of the current instruction.
///
/// @todo: Consider fixing this in the appropriate SLEIGH specifications instead.
pub fn read_pc_patcher(
    pc: pcode::VarNode,
    tmp_pc: pcode::VarNode,
    use_next_pc: bool,
) -> PcodePatcher {
    Box::new(move |block: &mut pcode::Block| {
        let mut pc_written = false;
        let mut last_pc = 0;
        let mut next_pc = 0;
        for inst in &mut block.instructions {
            if let pcode::Op::InstructionMarker = inst.op {
                last_pc = inst.inputs.first().as_u64();
                next_pc = last_pc + inst.inputs.second().as_u64()
            }

            let mut inputs = inst.inputs.get();
            for input in &mut inputs {
                if let pcode::Value::Var(var) = input {
                    if var.id == pc.id {
                        if pc_written {
                            var.id = tmp_pc.id;
                        }
                        else {
                            let addr = if use_next_pc { next_pc } else { last_pc };
                            *input = pcode::Value::Const(addr, pc.size).slice(var.offset, var.size);
                        }
                    }
                }
            }
            inst.inputs = inputs.into();
            if inst.output.id == pc.id {
                inst.output.id = tmp_pc.id;
                pc_written = true;
            }
        }
    })
}
