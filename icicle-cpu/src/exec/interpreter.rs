use half::f16;
use pcode::{MemId, Value, VarNode};

use crate::{
    ExceptionCode,
    regs::{ValueSource, resize_sxt},
};

pub trait PcodeExecutor: ValueSource {
    fn exception(&mut self, code: ExceptionCode, value: u64);
    fn next_instruction(&mut self, addr: u64, len: u64);
    fn load_mem<const N: usize>(&mut self, id: MemId, addr: u64) -> Option<[u8; N]>;
    fn store_mem<const N: usize>(&mut self, id: MemId, addr: u64, value: [u8; N]) -> Option<()>;
    fn set_arg(&mut self, id: u16, value: u128);
    fn call_helper(&mut self, id: u16, output: VarNode, inputs: [Value; 2]);
    fn call_hook(&mut self, hook: pcode::HookId);
    fn is_big_endian(&self) -> bool;

    #[cold]
    fn invalid_op_size(&mut self, size: u8) {
        self.exception(ExceptionCode::InvalidOpSize, size as u64);
    }
}

pub fn interpret<E>(exec: &mut E, stmt: pcode::Instruction)
where
    E: PcodeExecutor,
{
    use pcode::Op;

    let output = stmt.output;
    let [a, b] = stmt.inputs.get();

    macro_rules! copy {
        ($ty:ty) => {
            exec.write_var(output, exec.read::<$ty>(a))
        };
    }
    macro_rules! zext {
        ($in_ty:ty, $out_ty:ty) => {{
            let value = exec.read::<$in_ty>(a) as $out_ty;
            exec.write_var(output, value);
        }};
    }
    macro_rules! sext {
        ($in_ty:ty, $out_ty:ty) => {{
            let value = <$out_ty>::from_ne_bytes(resize_sxt(exec.read::<$in_ty>(a).to_ne_bytes()));
            exec.write_var(output, value);
        }};
    }
    macro_rules! to_float {
        ($in:ty) => {{
            let value = exec.read::<$in>(a);
            match output.size {
                4 => exec.write_var::<u32>(output, FromFloat::from_float(value as f32)),
                8 => exec.write_var::<u64>(output, FromFloat::from_float(value as f64)),
                10 => exec.write_var::<[u8; 10]>(output, FromFloat::from_float(value as f64)),
                size => exec.exception(ExceptionCode::InvalidFloatSize, size as u64),
            }
        }};
    }
    macro_rules! float_cast {
        ($value:ident: $in_ty:ty => $cast:expr) => {{
            let $value = exec.read::<$in_ty>(a);
            let result = $cast;
            exec.write_var(output, result.to_bits());
        }};
    }
    macro_rules! float_to_int {
        ($val:expr) => {{
            let val = $val;
            match output.size {
                2 => exec.write_var::<u16>(output, val as u16),
                4 => exec.write_var::<u32>(output, val as u32),
                8 => exec.write_var::<u64>(output, val as u64),
                size => return exec.exception(ExceptionCode::InvalidFloatSize, size as u64),
            }
        }};
    }
    macro_rules! binary_op {
        ($op:ty, $ty:ty) => {{
            let a: $ty = exec.read(a);
            let b: $ty = exec.read(b);
            exec.write_var(output, <$op>::eval(a, b));
        }};
    }
    macro_rules! div_op {
        ($op:ty, $ty:ty) => {{
            let a: $ty = exec.read(a);
            let b: $ty = exec.read(b);
            if b == 0 {
                exec.exception(ExceptionCode::DivisionException, 0);
                return;
            }
            exec.write_var(output, <$op>::eval(a, b));
        }};
    }
    macro_rules! sdiv_op {
        ($op:ty, $ty:ty) => {{
            let a: $ty = exec.read(a);
            let b: $ty = exec.read(b);
            if b == 0 || (a == (1 << (<$ty>::BITS - 1)) && b == <$ty>::MAX) {
                exec.exception(ExceptionCode::DivisionException, 0);
                return;
            }
            exec.write_var(output, <$op>::eval(a, b));
        }};
    }
    macro_rules! cmp_op {
        ($op:ty, $ty:ty) => {{
            let a: $ty = exec.read(a);
            let b: $ty = exec.read(b);
            exec.write_var(output, <$op>::eval(a, b) as u8);
        }};
    }
    macro_rules! unary_op {
        ($op:ty, $ty:ty) => {{
            let input: $ty = exec.read(a);
            exec.write_var(output, <$op>::eval(input));
        }};
    }
    macro_rules! count_ones {
        ($ty:ty) => {{
            exec.write_trunc(output, exec.read::<$ty>(a).count_ones());
        }};
    }
    macro_rules! count_leading_zeros {
        ($ty:ty) => {{
            exec.write_trunc(output, exec.read::<$ty>(a).leading_zeros());
        }};
    }
    macro_rules! bool_binary_op {
        ($op:ty) => {{
            let a: u8 = exec.read(a);
            let b: u8 = exec.read(b);
            exec.write_var(output, <$op>::eval(a, b) as u8);
        }};
    }
    macro_rules! float_is_nan {
        ($ty:ty) => {{
            let result = exec.read::<$ty>(a).to_float().is_nan();
            exec.write_var(output, pcode::cast_bool(result));
        }};
    }

    // @todo: consider simplifying generation of this table using a macro.
    match (stmt.op, output.size, (a.size(), b.size())) {
        (Op::Copy, 1, (1, 0)) => copy!(u8),
        (Op::Copy, 2, (2, 0)) => copy!(u16),
        (Op::Copy, 4, (4, 0)) => copy!(u32),
        (Op::Copy, 8, (8, 0)) => copy!(u64),
        (Op::Copy, 16, (16, 0)) => copy!(u128),
        (Op::Copy, ..) => copy_cold(exec, a, output),

        (Op::ZeroExtend, 2, (1, 0)) => zext!(u8, u16),
        (Op::ZeroExtend, 4, (1, 0)) => zext!(u8, u32),
        (Op::ZeroExtend, 4, (2, 0)) => zext!(u16, u32),
        (Op::ZeroExtend, 8, (1, 0)) => zext!(u8, u64),
        (Op::ZeroExtend, 8, (2, 0)) => zext!(u16, u64),
        (Op::ZeroExtend, 8, (4, 0)) => zext!(u32, u64),
        (Op::ZeroExtend, 16, (1, 0)) => zext!(u8, u128),
        (Op::ZeroExtend, 16, (2, 0)) => zext!(u16, u128),
        (Op::ZeroExtend, 16, (4, 0)) => zext!(u32, u128),
        (Op::ZeroExtend, 16, (8, 0)) => zext!(u64, u128),
        (Op::ZeroExtend, ..) => zext_cold(exec, a, output),

        (Op::SignExtend, 2, (1, 0)) => sext!(u8, u16),
        (Op::SignExtend, 4, (1, 0)) => sext!(u8, u32),
        (Op::SignExtend, 4, (2, 0)) => sext!(u16, u32),
        (Op::SignExtend, 8, (1, 0)) => sext!(u8, u64),
        (Op::SignExtend, 8, (2, 0)) => sext!(u16, u64),
        (Op::SignExtend, 8, (4, 0)) => sext!(u32, u64),
        (Op::SignExtend, 16, (1, 0)) => sext!(u8, u128),
        (Op::SignExtend, 16, (2, 0)) => sext!(u16, u128),
        (Op::SignExtend, 16, (4, 0)) => sext!(u32, u128),
        (Op::SignExtend, 16, (8, 0)) => sext!(u64, u128),
        (Op::SignExtend, ..) => sext_cold(exec, a, output),

        (Op::IntToFloat, _, (1, 0)) => to_float!(i8),
        (Op::IntToFloat, _, (2, 0)) => to_float!(i16),
        (Op::IntToFloat, _, (4, 0)) => to_float!(i32),
        (Op::IntToFloat, _, (8, 0)) => to_float!(i64),
        (Op::IntToFloat, ..) => exec.invalid_op_size(0),

        (Op::UintToFloat, _, (1, 0)) => to_float!(u8),
        (Op::UintToFloat, _, (2, 0)) => to_float!(u16),
        (Op::UintToFloat, _, (4, 0)) => to_float!(u32),
        (Op::UintToFloat, _, (8, 0)) => to_float!(u64),
        (Op::UintToFloat, ..) => exec.invalid_op_size(0),

        (Op::FloatToFloat, 2, (2, 0)) => float_cast!(a: u16 => f16::from_bits(a)),
        (Op::FloatToFloat, 4, (2, 0)) => float_cast!(a: u16 => f16::from_bits(a).to_f32()),
        (Op::FloatToFloat, 8, (2, 0)) => float_cast!(a: u16 => f16::from_bits(a).to_f64()),
        (Op::FloatToFloat, 10, (2, 0)) => float_cast!(a: u16 => f16::from_bits(a).to_f80()),

        (Op::FloatToFloat, 2, (4, 0)) => float_cast!(a: u32 => f16::from_f32(f32::from_bits(a))),
        (Op::FloatToFloat, 4, (4, 0)) => float_cast!(a: u32 => f32::from_bits(a)),
        (Op::FloatToFloat, 8, (4, 0)) => float_cast!(a: u32 => f32::from_bits(a) as f64),
        (Op::FloatToFloat, 10, (4, 0)) => float_cast!(a: u32 => f32::from_bits(a).to_f80()),

        (Op::FloatToFloat, 2, (8, 0)) => float_cast!(a: u64 => f16::from_f64(f64::from_bits(a))),
        (Op::FloatToFloat, 4, (8, 0)) => float_cast!(a: u64 => f64::from_bits(a) as f32),
        (Op::FloatToFloat, 8, (8, 0)) => float_cast!(a: u64 => f64::from_bits(a)),
        (Op::FloatToFloat, 10, (8, 0)) => float_cast!(a: u64 => f64::from_bits(a).to_f80()),

        (Op::FloatToFloat, 4, (10, 0)) => float_cast!(a: [u8; 10] => a.to_f64() as f32),
        (Op::FloatToFloat, 8, (10, 0)) => float_cast!(a: [u8; 10] => a.to_f64()),
        (Op::FloatToFloat, 10, (10, 0)) => float_cast!(a: [u8; 10] => a),
        (Op::FloatToFloat, ..) => exec.invalid_op_size(0),

        (Op::FloatToInt, _, (4, 0)) => float_to_int!(exec.read::<u32>(a).to_float() as i32),
        (Op::FloatToInt, _, (8, 0)) => float_to_int!(exec.read::<u64>(a).to_float() as i64),
        (Op::FloatToInt, _, (10, 0)) => float_to_int!(exec.read::<[u8; 10]>(a).to_float() as i64),
        (Op::FloatToInt, ..) => exec.invalid_op_size(0),

        (Op::IntAdd, 1, (1, 1)) => binary_op!(IntAdd, u8),
        (Op::IntAdd, 2, (2, 2)) => binary_op!(IntAdd, u16),
        (Op::IntAdd, 4, (4, 4)) => binary_op!(IntAdd, u32),
        (Op::IntAdd, 8, (8, 8)) => binary_op!(IntAdd, u64),
        (Op::IntAdd, 16, (16, 16)) => binary_op!(IntAdd, u128),
        (Op::IntAdd, ..) => exec.invalid_op_size(0),

        (Op::IntSub, 1, (1, 1)) => binary_op!(IntSub, u8),
        (Op::IntSub, 2, (2, 2)) => binary_op!(IntSub, u16),
        (Op::IntSub, 4, (4, 4)) => binary_op!(IntSub, u32),
        (Op::IntSub, 8, (8, 8)) => binary_op!(IntSub, u64),
        (Op::IntSub, 16, (16, 16)) => binary_op!(IntSub, u128),
        (Op::IntSub, ..) => exec.invalid_op_size(0),

        (Op::IntXor, 1, (1, 1)) => binary_op!(IntXor, u8),
        (Op::IntXor, 2, (2, 2)) => binary_op!(IntXor, u16),
        (Op::IntXor, 4, (4, 4)) => binary_op!(IntXor, u32),
        (Op::IntXor, 8, (8, 8)) => binary_op!(IntXor, u64),
        (Op::IntXor, 16, (16, 16)) => binary_op!(IntXor, u128),
        (Op::IntXor, ..) => exec.invalid_op_size(0),

        (Op::IntOr, 1, (1, 1)) => binary_op!(IntOr, u8),
        (Op::IntOr, 2, (2, 2)) => binary_op!(IntOr, u16),
        (Op::IntOr, 4, (4, 4)) => binary_op!(IntOr, u32),
        (Op::IntOr, 8, (8, 8)) => binary_op!(IntOr, u64),
        (Op::IntOr, 16, (16, 16)) => binary_op!(IntOr, u128),
        (Op::IntOr, ..) => exec.invalid_op_size(0),

        (Op::IntAnd, 1, (1, 1)) => binary_op!(IntAnd, u8),
        (Op::IntAnd, 2, (2, 2)) => binary_op!(IntAnd, u16),
        (Op::IntAnd, 4, (4, 4)) => binary_op!(IntAnd, u32),
        (Op::IntAnd, 8, (8, 8)) => binary_op!(IntAnd, u64),
        (Op::IntAnd, 16, (16, 16)) => binary_op!(IntAnd, u128),
        (Op::IntAnd, ..) => exec.invalid_op_size(0),

        (Op::IntMul, 1, (1, 1)) => binary_op!(IntMul, u8),
        (Op::IntMul, 2, (2, 2)) => binary_op!(IntMul, u16),
        (Op::IntMul, 4, (4, 4)) => binary_op!(IntMul, u32),
        (Op::IntMul, 8, (8, 8)) => binary_op!(IntMul, u64),
        (Op::IntMul, 16, (16, 16)) => binary_op!(IntMul, u128),
        (Op::IntMul, ..) => exec.invalid_op_size(0),

        (Op::IntDiv, 1, (1, 1)) => div_op!(IntDiv, u8),
        (Op::IntDiv, 2, (2, 2)) => div_op!(IntDiv, u16),
        (Op::IntDiv, 4, (4, 4)) => div_op!(IntDiv, u32),
        (Op::IntDiv, 8, (8, 8)) => div_op!(IntDiv, u64),
        (Op::IntDiv, 16, (16, 16)) => div_op!(IntDiv, u128),
        (Op::IntDiv, ..) => exec.invalid_op_size(0),

        (Op::IntSignedDiv, 1, (1, 1)) => sdiv_op!(IntSignedDiv, u8),
        (Op::IntSignedDiv, 2, (2, 2)) => sdiv_op!(IntSignedDiv, u16),
        (Op::IntSignedDiv, 4, (4, 4)) => sdiv_op!(IntSignedDiv, u32),
        (Op::IntSignedDiv, 8, (8, 8)) => sdiv_op!(IntSignedDiv, u64),
        (Op::IntSignedDiv, 16, (16, 16)) => sdiv_op!(IntSignedDiv, u128),
        (Op::IntSignedDiv, ..) => exec.invalid_op_size(0),

        (Op::IntRem, 1, (1, 1)) => div_op!(IntRem, u8),
        (Op::IntRem, 2, (2, 2)) => div_op!(IntRem, u16),
        (Op::IntRem, 4, (4, 4)) => div_op!(IntRem, u32),
        (Op::IntRem, 8, (8, 8)) => div_op!(IntRem, u64),
        (Op::IntRem, 16, (16, 16)) => div_op!(IntRem, u128),
        (Op::IntRem, ..) => exec.invalid_op_size(0),

        (Op::IntSignedRem, 1, (1, 1)) => sdiv_op!(IntSignedRem, u8),
        (Op::IntSignedRem, 2, (2, 2)) => sdiv_op!(IntSignedRem, u16),
        (Op::IntSignedRem, 4, (4, 4)) => sdiv_op!(IntSignedRem, u32),
        (Op::IntSignedRem, 8, (8, 8)) => sdiv_op!(IntSignedRem, u64),
        (Op::IntSignedRem, 16, (16, 16)) => sdiv_op!(IntSignedRem, u128),
        (Op::IntSignedRem, ..) => exec.invalid_op_size(0),

        (Op::IntLeft, ..) => {
            let x: u128 = exec.read_dynamic(a).zxt();
            let y: u32 = exec.read_dynamic(b).zxt();
            let result = if y >= output.size as u32 * 8 { 0 } else { x << y };
            exec.write_trunc(output, result);
        }

        (Op::IntRight, ..) => {
            let x: u128 = exec.read_dynamic(a).zxt();
            let y: u32 = exec.read_dynamic(b).zxt();
            let result = if y >= output.size as u32 * 8 { 0 } else { x >> y };
            exec.write_trunc(output, result);
        }

        (Op::IntSignedRight, ..) => {
            let x: u128 = exec.read_dynamic(stmt.inputs.get()[0]).sxt();
            let y: u32 = exec.read_dynamic(stmt.inputs.get()[1]).zxt();
            let shift = y.min(output.size as u32 * 8 - 1);
            exec.write_trunc(output, x >> shift);
        }

        (Op::IntRotateLeft, 1, (1, 1)) => binary_op!(IntRotateLeft, u8),
        (Op::IntRotateLeft, 2, (2, 2)) => binary_op!(IntRotateLeft, u16),
        (Op::IntRotateLeft, 4, (4, 4)) => binary_op!(IntRotateLeft, u32),
        (Op::IntRotateLeft, 8, (8, 8)) => binary_op!(IntRotateLeft, u64),
        (Op::IntRotateLeft, 16, (16, 16)) => binary_op!(IntRotateLeft, u128),
        (Op::IntRotateLeft, ..) => exec.invalid_op_size(0),

        (Op::IntRotateRight, 1, (1, 1)) => binary_op!(IntRotateRight, u8),
        (Op::IntRotateRight, 2, (2, 2)) => binary_op!(IntRotateRight, u16),
        (Op::IntRotateRight, 4, (4, 4)) => binary_op!(IntRotateRight, u32),
        (Op::IntRotateRight, 8, (8, 8)) => binary_op!(IntRotateRight, u64),
        (Op::IntRotateRight, 16, (16, 16)) => binary_op!(IntRotateRight, u128),
        (Op::IntRotateRight, ..) => exec.invalid_op_size(0),

        (Op::IntEqual, 1, (1, 1)) => cmp_op!(IntEqual, u8),
        (Op::IntEqual, 1, (2, 2)) => cmp_op!(IntEqual, u16),
        (Op::IntEqual, 1, (4, 4)) => cmp_op!(IntEqual, u32),
        (Op::IntEqual, 1, (8, 8)) => cmp_op!(IntEqual, u64),
        (Op::IntEqual, 1, (16, 16)) => cmp_op!(IntEqual, u128),
        (Op::IntEqual, ..) => exec.invalid_op_size(0),

        (Op::IntNotEqual, 1, (1, 1)) => cmp_op!(IntNotEqual, u8),
        (Op::IntNotEqual, 1, (2, 2)) => cmp_op!(IntNotEqual, u16),
        (Op::IntNotEqual, 1, (4, 4)) => cmp_op!(IntNotEqual, u32),
        (Op::IntNotEqual, 1, (8, 8)) => cmp_op!(IntNotEqual, u64),
        (Op::IntNotEqual, 1, (16, 16)) => cmp_op!(IntNotEqual, u128),
        (Op::IntNotEqual, ..) => exec.invalid_op_size(0),

        (Op::IntLess, 1, (1, 1)) => cmp_op!(IntLess, u8),
        (Op::IntLess, 1, (2, 2)) => cmp_op!(IntLess, u16),
        (Op::IntLess, 1, (4, 4)) => cmp_op!(IntLess, u32),
        (Op::IntLess, 1, (8, 8)) => cmp_op!(IntLess, u64),
        (Op::IntLess, 1, (16, 16)) => cmp_op!(IntLess, u128),
        (Op::IntLess, ..) => exec.invalid_op_size(0),

        (Op::IntSignedLess, 1, (1, 1)) => cmp_op!(IntSignedLess, u8),
        (Op::IntSignedLess, 1, (2, 2)) => cmp_op!(IntSignedLess, u16),
        (Op::IntSignedLess, 1, (4, 4)) => cmp_op!(IntSignedLess, u32),
        (Op::IntSignedLess, 1, (8, 8)) => cmp_op!(IntSignedLess, u64),
        (Op::IntSignedLess, 1, (16, 16)) => cmp_op!(IntSignedLess, u128),
        (Op::IntSignedLess, ..) => exec.invalid_op_size(0),

        (Op::IntLessEqual, 1, (1, 1)) => cmp_op!(IntLessEqual, u8),
        (Op::IntLessEqual, 1, (2, 2)) => cmp_op!(IntLessEqual, u16),
        (Op::IntLessEqual, 1, (4, 4)) => cmp_op!(IntLessEqual, u32),
        (Op::IntLessEqual, 1, (8, 8)) => cmp_op!(IntLessEqual, u64),
        (Op::IntLessEqual, 1, (16, 16)) => cmp_op!(IntLessEqual, u128),
        (Op::IntLessEqual, ..) => exec.invalid_op_size(0),

        (Op::IntSignedLessEqual, 1, (1, 1)) => cmp_op!(IntSignedLessEqual, u8),
        (Op::IntSignedLessEqual, 1, (2, 2)) => cmp_op!(IntSignedLessEqual, u16),
        (Op::IntSignedLessEqual, 1, (4, 4)) => cmp_op!(IntSignedLessEqual, u32),
        (Op::IntSignedLessEqual, 1, (8, 8)) => cmp_op!(IntSignedLessEqual, u64),
        (Op::IntSignedLessEqual, 1, (16, 16)) => cmp_op!(IntSignedLessEqual, u128),
        (Op::IntSignedLessEqual, ..) => exec.invalid_op_size(0),

        (Op::IntCarry, 1, (1, 1)) => cmp_op!(IntCarry, u8),
        (Op::IntCarry, 1, (2, 2)) => cmp_op!(IntCarry, u16),
        (Op::IntCarry, 1, (4, 4)) => cmp_op!(IntCarry, u32),
        (Op::IntCarry, 1, (8, 8)) => cmp_op!(IntCarry, u64),
        (Op::IntCarry, 1, (16, 16)) => cmp_op!(IntCarry, u128),
        (Op::IntCarry, ..) => exec.invalid_op_size(0),

        (Op::IntSignedCarry, 1, (1, 1)) => cmp_op!(IntSignedCarry, u8),
        (Op::IntSignedCarry, 1, (2, 2)) => cmp_op!(IntSignedCarry, u16),
        (Op::IntSignedCarry, 1, (4, 4)) => cmp_op!(IntSignedCarry, u32),
        (Op::IntSignedCarry, 1, (8, 8)) => cmp_op!(IntSignedCarry, u64),
        (Op::IntSignedCarry, 1, (16, 16)) => cmp_op!(IntSignedCarry, u128),
        (Op::IntSignedCarry, ..) => exec.invalid_op_size(0),

        (Op::IntSignedBorrow, 1, (1, 1)) => cmp_op!(IntSignedBorrow, u8),
        (Op::IntSignedBorrow, 1, (2, 2)) => cmp_op!(IntSignedBorrow, u16),
        (Op::IntSignedBorrow, 1, (4, 4)) => cmp_op!(IntSignedBorrow, u32),
        (Op::IntSignedBorrow, 1, (8, 8)) => cmp_op!(IntSignedBorrow, u64),
        (Op::IntSignedBorrow, 1, (16, 16)) => cmp_op!(IntSignedBorrow, u128),
        (Op::IntSignedBorrow, ..) => exec.invalid_op_size(0),

        (Op::IntNot, 1, (1, 0)) => unary_op!(IntNot, u8),
        (Op::IntNot, 2, (2, 0)) => unary_op!(IntNot, u16),
        (Op::IntNot, 4, (4, 0)) => unary_op!(IntNot, u32),
        (Op::IntNot, 8, (8, 0)) => unary_op!(IntNot, u64),
        (Op::IntNot, 16, (16, 0)) => unary_op!(IntNot, u128),
        (Op::IntNot, ..) => exec.invalid_op_size(0),

        (Op::IntNegate, 1, (1, 0)) => unary_op!(IntNegate, u8),
        (Op::IntNegate, 2, (2, 0)) => unary_op!(IntNegate, u16),
        (Op::IntNegate, 4, (4, 0)) => unary_op!(IntNegate, u32),
        (Op::IntNegate, 8, (8, 0)) => unary_op!(IntNegate, u64),
        (Op::IntNegate, 16, (16, 0)) => unary_op!(IntNegate, u128),
        (Op::IntNegate, ..) => exec.invalid_op_size(0),

        (Op::IntCountOnes, _, (1, 0)) => count_ones!(u8),
        (Op::IntCountOnes, _, (2, 0)) => count_ones!(u16),
        (Op::IntCountOnes, _, (4, 0)) => count_ones!(u32),
        (Op::IntCountOnes, _, (8, 0)) => count_ones!(u64),
        (Op::IntCountOnes, _, (16, 0)) => count_ones!(u128),
        (Op::IntCountOnes, ..) => exec.invalid_op_size(0),

        (Op::IntCountLeadingZeroes, _, (1, 0)) => count_leading_zeros!(u8),
        (Op::IntCountLeadingZeroes, _, (2, 0)) => count_leading_zeros!(u16),
        (Op::IntCountLeadingZeroes, _, (4, 0)) => count_leading_zeros!(u32),
        (Op::IntCountLeadingZeroes, _, (8, 0)) => count_leading_zeros!(u64),
        (Op::IntCountLeadingZeroes, _, (16, 0)) => count_leading_zeros!(u128),
        (Op::IntCountLeadingZeroes, ..) => exec.invalid_op_size(0),

        (Op::BoolAnd, 1, (1, 1)) => bool_binary_op!(BoolAnd),
        (Op::BoolAnd, ..) => exec.invalid_op_size(0),

        (Op::BoolOr, 1, (1, 1)) => bool_binary_op!(BoolOr),
        (Op::BoolOr, ..) => exec.invalid_op_size(0),

        (Op::BoolXor, 1, (1, 1)) => bool_binary_op!(BoolXor),
        (Op::BoolXor, ..) => exec.invalid_op_size(0),

        (Op::BoolNot, 1, (1, 0)) => {
            exec.write_var(output, pcode::cast_bool(exec.read::<u8>(a) == 0));
        }
        (Op::BoolNot, ..) => exec.invalid_op_size(0),

        // (Op::FloatAdd, 2, (2, 2)) => binary_op!(FloatAdd, u16), // TODO: 16-bit floats
        (Op::FloatAdd, 4, (4, 4)) => binary_op!(FloatAdd, u32),
        (Op::FloatAdd, 8, (8, 8)) => binary_op!(FloatAdd, u64),
        (Op::FloatAdd, 10, (10, 10)) => binary_op!(FloatAdd, [u8; 10]),
        (Op::FloatAdd, ..) => exec.invalid_op_size(0),

        (Op::FloatSub, 4, (4, 4)) => binary_op!(FloatSub, u32),
        (Op::FloatSub, 8, (8, 8)) => binary_op!(FloatSub, u64),
        (Op::FloatSub, 10, (10, 10)) => binary_op!(FloatSub, [u8; 10]),
        (Op::FloatSub, ..) => exec.invalid_op_size(0),

        (Op::FloatMul, 4, (4, 4)) => binary_op!(FloatMul, u32),
        (Op::FloatMul, 8, (8, 8)) => binary_op!(FloatMul, u64),
        (Op::FloatMul, 10, (10, 10)) => binary_op!(FloatMul, [u8; 10]),
        (Op::FloatMul, ..) => exec.invalid_op_size(0),

        (Op::FloatDiv, 4, (4, 4)) => binary_op!(FloatDiv, u32),
        (Op::FloatDiv, 8, (8, 8)) => binary_op!(FloatDiv, u64),
        (Op::FloatDiv, 10, (10, 10)) => binary_op!(FloatDiv, [u8; 10]),
        (Op::FloatDiv, ..) => exec.invalid_op_size(0),

        (Op::FloatNegate, 4, (4, _)) => unary_op!(FloatNegate, u32),
        (Op::FloatNegate, 8, (8, _)) => unary_op!(FloatNegate, u64),
        (Op::FloatNegate, 10, (10, _)) => unary_op!(FloatNegate, [u8; 10]),
        (Op::FloatNegate, ..) => exec.invalid_op_size(0),

        (Op::FloatAbs, 4, (4, _)) => unary_op!(FloatAbs, u32),
        (Op::FloatAbs, 8, (8, _)) => unary_op!(FloatAbs, u64),
        (Op::FloatAbs, 10, (10, _)) => unary_op!(FloatAbs, [u8; 10]),
        (Op::FloatAbs, ..) => exec.invalid_op_size(0),

        (Op::FloatSqrt, 4, (4, _)) => unary_op!(FloatSqrt, u32),
        (Op::FloatSqrt, 8, (8, _)) => unary_op!(FloatSqrt, u64),
        (Op::FloatSqrt, 10, (10, _)) => unary_op!(FloatSqrt, [u8; 10]),
        (Op::FloatSqrt, ..) => exec.invalid_op_size(0),

        (Op::FloatCeil, 4, (4, _)) => unary_op!(FloatCeil, u32),
        (Op::FloatCeil, 8, (8, _)) => unary_op!(FloatCeil, u64),
        (Op::FloatCeil, 10, (10, _)) => unary_op!(FloatCeil, [u8; 10]),
        (Op::FloatCeil, ..) => exec.invalid_op_size(0),

        (Op::FloatFloor, 4, (4, _)) => unary_op!(FloatFloor, u32),
        (Op::FloatFloor, 8, (8, _)) => unary_op!(FloatFloor, u64),
        (Op::FloatFloor, 10, (10, _)) => unary_op!(FloatFloor, [u8; 10]),
        (Op::FloatFloor, ..) => exec.invalid_op_size(0),

        (Op::FloatRound, 4, (4, _)) => unary_op!(FloatRound, u32),
        (Op::FloatRound, 8, (8, _)) => unary_op!(FloatRound, u64),
        (Op::FloatRound, 10, (10, _)) => unary_op!(FloatRound, [u8; 10]),
        (Op::FloatRound, ..) => exec.invalid_op_size(0),

        (Op::FloatIsNan, 1, (4, _)) => float_is_nan!(u32),
        (Op::FloatIsNan, 1, (8, _)) => float_is_nan!(u64),
        (Op::FloatIsNan, 1, (10, _)) => float_is_nan!([u8; 10]),
        (Op::FloatIsNan, ..) => exec.invalid_op_size(0),

        (Op::FloatEqual, 1, (4, 4)) => cmp_op!(FloatEqual, u32),
        (Op::FloatEqual, 1, (8, 8)) => cmp_op!(FloatEqual, u64),
        (Op::FloatEqual, 1, (10, 10)) => cmp_op!(FloatEqual, [u8; 10]),
        (Op::FloatEqual, ..) => exec.invalid_op_size(0),

        (Op::FloatNotEqual, 1, (4, 4)) => cmp_op!(FloatNotEqual, u32),
        (Op::FloatNotEqual, 1, (8, 8)) => cmp_op!(FloatNotEqual, u64),
        (Op::FloatNotEqual, 1, (10, 10)) => cmp_op!(FloatNotEqual, [u8; 10]),
        (Op::FloatNotEqual, ..) => exec.invalid_op_size(0),

        (Op::FloatLess, 1, (4, 4)) => cmp_op!(FloatLess, u32),
        (Op::FloatLess, 1, (8, 8)) => cmp_op!(FloatLess, u64),
        (Op::FloatLess, 1, (10, 10)) => cmp_op!(FloatLess, [u8; 10]),
        (Op::FloatLess, ..) => exec.invalid_op_size(0),

        (Op::FloatLessEqual, 1, (4, 4)) => cmp_op!(FloatLessEqual, u32),
        (Op::FloatLessEqual, 1, (8, 8)) => cmp_op!(FloatLessEqual, u64),
        (Op::FloatLessEqual, 1, (10, 10)) => cmp_op!(FloatLessEqual, [u8; 10]),
        (Op::FloatLessEqual, ..) => exec.invalid_op_size(0),

        (Op::Select(cond_var), ..) => {
            let cond = exec.read_var::<u8>(VarNode::new(cond_var, 1));
            let input = if cond != 0 { a } else { b };
            copy(exec, input, output)
        }

        (Op::Load(id), ..) => {
            let addr: u64 = exec.read_dynamic(stmt.inputs.get()[0]).zxt();
            load(exec, id, output, addr);
        }
        (Op::Store(id), ..) => {
            let addr: u64 = exec.read_dynamic(stmt.inputs.get()[0]).zxt();
            store(exec, id, addr, stmt.inputs.get()[1]);
        }

        (Op::Arg(id), ..) => {
            let value = exec.read_dynamic(stmt.inputs.get()[0]).zxt();
            exec.set_arg(id, value);
        }
        (Op::PcodeOp(id), ..) => exec.call_helper(id, output, stmt.inputs.get()),
        (Op::Hook(id), ..) => exec.call_hook(id),
        (Op::HookIf(id), ..) => {
            let cond: u8 = exec.read(stmt.inputs.get()[0]);
            if cond != 0 {
                exec.call_hook(id);
            }
        }

        (Op::InstructionMarker, 0, (8, 8)) => {
            exec.next_instruction(stmt.inputs.get()[0].as_u64(), stmt.inputs.get()[1].as_u64())
        }
        (Op::InstructionMarker, ..) => exec.invalid_op_size(0),

        (Op::Exception, ..) => {
            let a: u32 = exec.read_dynamic(stmt.inputs.get()[0]).zxt();
            let b: u64 = exec.read_dynamic(stmt.inputs.get()[1]).zxt();
            exec.exception(ExceptionCode::from_u32(a), b);
        }
        (Op::Invalid, ..) => exec.exception(ExceptionCode::InvalidInstruction, 0),

        (
            Op::Subpiece(_)
            | Op::Branch(_)
            | Op::PcodeBranch(_)
            | Op::PcodeLabel(_)
            | Op::TracerLoad(_)
            | Op::TracerStore(_)
            | Op::MultiEqual
            | Op::Indirect,
            ..,
        ) => panic!("Unexpected operation in interpreter: {stmt:?}"),
    }
}

#[inline(never)]
#[cold]
fn copy_cold<E: ValueSource>(exec: &mut E, input: Value, output: VarNode) {
    for i in 0..output.size {
        let byte = exec.read::<u8>(input.slice(i, 1));
        exec.write_var(output.slice(i, 1), byte);
    }
}

fn copy<E: ValueSource>(exec: &mut E, input: Value, output: VarNode) {
    macro_rules! copy {
        ($ty:ty) => {{
            let value = exec.read::<$ty>(input);
            exec.write_var(output, value);
        }};
    }

    match output.size {
        1 => copy!(u8),
        2 => copy!(u16),
        4 => copy!(u32),
        8 => copy!(u64),
        16 => copy!(u128),
        _ => copy_cold(exec, input, output),
    }
}

#[inline(never)]
#[cold]
fn zext_cold<E: ValueSource>(exec: &mut E, input: Value, output: VarNode) {
    // Copy value
    for i in 0..input.size() {
        let byte = exec.read::<u8>(input.slice(i, 1));
        exec.write_var(output.slice(i, 1), byte);
    }

    // Zero extend
    for i in input.size()..output.size {
        exec.write_var(output.slice(i, 1), 0_u8);
    }
}

#[inline(never)]
#[cold]
fn sext_cold<E>(exec: &mut E, input: Value, output: VarNode)
where
    E: ValueSource,
{
    if input.size() == output.size {
        return copy(exec, input, output);
    }

    // Copy value
    let mut byte = 0;
    for i in 0..input.size() {
        byte = exec.read::<u8>(input.slice(i, 1));
        exec.write_var(output.slice(i, 1), byte);
    }

    // Sign-extend
    let fill: u8 = if byte >> 7 == 0 { 0x00 } else { 0xff };
    for i in input.size()..output.size {
        exec.write_var::<u8>(output.slice(i, 1), fill);
    }
}

fn load<E: PcodeExecutor>(exec: &mut E, id: MemId, dst: VarNode, addr: u64) {
    macro_rules! load {
        ($dst:expr, $addr:expr, $ty:ty) => {{
            let Some(tmp) = exec.load_mem(id, $addr) else {
                return;
            };
            let value = match exec.is_big_endian() && id == pcode::RAM_SPACE {
                true => <$ty>::from_be_bytes(tmp),
                false => <$ty>::from_le_bytes(tmp),
            };
            exec.write_var($dst, value);
        }};
    }

    match dst.size {
        1 => load!(dst, addr, u8),
        2 => load!(dst, addr, u16),
        4 => load!(dst, addr, u32),
        8 => load!(dst, addr, u64),
        16 => {
            if exec.is_big_endian() && id == pcode::RAM_SPACE {
                load!(dst.slice(8, 8), addr, u64);
                load!(dst.slice(0, 8), addr.wrapping_add(8), u64);
            } else {
                load!(dst.slice(0, 8), addr, u64);
                load!(dst.slice(8, 8), addr.wrapping_add(8), u64);
            }
        }
        size => {
            if exec.is_big_endian() && id == pcode::RAM_SPACE {
                for i in 0..size {
                    load!(dst.slice(size - 1 - i, 1), addr.wrapping_add(i as u64), u8);
                }
            } else {
                for i in 0..size {
                    load!(dst.slice(i, 1), addr.wrapping_add(i as u64), u8);
                }
            }
        }
    }
}

fn store<E: PcodeExecutor>(exec: &mut E, id: MemId, addr: u64, value: Value) {
    macro_rules! writer {
        ($addr:expr, $value:expr) => {{
            let val = $value;
            let bytes = match exec.is_big_endian() && id == pcode::RAM_SPACE {
                true => val.to_be_bytes(),
                false => val.to_le_bytes(),
            };
            if exec.store_mem(id, $addr, bytes).is_none() {
                return;
            }
        }};
    }

    match value.size() {
        1 => writer!(addr, exec.read::<u8>(value)),
        2 => writer!(addr, exec.read::<u16>(value)),
        4 => writer!(addr, exec.read::<u32>(value)),
        8 => writer!(addr, exec.read::<u64>(value)),
        16 => {
            if exec.is_big_endian() && id == pcode::RAM_SPACE {
                writer!(addr, exec.read::<u64>(value.slice(8, 8)));
                writer!(addr.wrapping_add(8), exec.read::<u64>(value.slice(0, 8)));
            } else {
                writer!(addr, exec.read::<u64>(value.slice(0, 8)));
                writer!(addr.wrapping_add(8), exec.read::<u64>(value.slice(8, 8)));
            }
        }
        size => {
            if exec.is_big_endian() && id == pcode::RAM_SPACE {
                for i in 0..size {
                    writer!(
                        addr.wrapping_add(size as u64 - 1 - i as u64),
                        exec.read::<u8>(value.slice(i, 1))
                    );
                }
            } else {
                for i in 0..size {
                    writer!(addr.wrapping_add(i as u64), exec.read::<u8>(value.slice(i, 1)));
                }
            }
        }
    }
}

trait Signed {
    type Signed;
    fn to_signed(self) -> Self::Signed;
}

trait ToUnsigned {
    type Unsigned;
    fn to_unsigned(self) -> Self::Unsigned;
}

macro_rules! impl_primitive {
    ($unsigned:ty, $signed:ty) => {
        impl Signed for $unsigned {
            type Signed = $signed;
            #[inline(always)]
            fn to_signed(self) -> Self::Signed {
                self as Self::Signed
            }
        }

        impl ToUnsigned for $signed {
            type Unsigned = $unsigned;
            #[inline(always)]
            fn to_unsigned(self) -> Self::Unsigned {
                self as Self::Unsigned
            }
        }
    };
}

impl_primitive!(u8, i8);
impl_primitive!(u16, i16);
impl_primitive!(u32, i32);
impl_primitive!(u64, i64);
impl_primitive!(u128, i128);

/// Represents an operation taking two integers as input and producing an output where the input and
/// output sizes are the type.
trait IntOp<T>: Sized {
    fn eval(a: T, b: T) -> T;
}

macro_rules! impl_eval_int_op {
    ($struct:ident, ($a:ident, $b:ident, $impl:expr)) => {
        impl_eval_int_op! { $struct, ($a, $b, $impl), u8, u16, u32, u64, u128 }
    };

    ($struct:ident, ($a:ident, $b:ident, $impl:expr), $( $ty:ty ),*) => {
        struct $struct;

        $(
            impl IntOp<$ty> for $struct {
                #[inline(always)]
                fn eval($a: $ty, $b: $ty) -> $ty {
                    $impl
                }
            }
        )*
    };
}

impl_eval_int_op! { IntAdd,         (a, b, a.wrapping_add(b)) }
impl_eval_int_op! { IntSub,         (a, b, a.wrapping_sub(b))}
impl_eval_int_op! { IntXor,         (a, b, a ^ b) }
impl_eval_int_op! { IntOr,          (a, b, a | b) }
impl_eval_int_op! { IntAnd,         (a, b, a & b) }
impl_eval_int_op! { IntMul,         (a, b, a.wrapping_mul(b)) }

impl_eval_int_op! { IntRotateLeft,  (a, b, a.rotate_left(b as u32)) }
impl_eval_int_op! { IntRotateRight, (a, b, a.rotate_right(b as u32)) }

impl_eval_int_op! { IntDiv,         (a, b, a / b) }
impl_eval_int_op! { IntSignedDiv,   (a, b, (a.to_signed() / b.to_signed()).to_unsigned()) }
impl_eval_int_op! { IntRem,         (a, b, a % b) }
impl_eval_int_op! { IntSignedRem,   (a, b, a.to_signed().wrapping_rem(b.to_signed()).to_unsigned()) }

/// Represents an operation taking two inputs of the same size producing a boolean output
trait CmpOp<T>: Sized {
    fn eval(a: T, b: T) -> bool;
}

macro_rules! impl_cmp_op {
    ($struct:ident, ($a:ident, $b:ident, $impl:expr)) => {
        impl_cmp_op! { $struct, ($a, $b, $impl), u8, u16, u32, u64, u128 }
    };

    ($struct:ident, ($a:ident, $b:ident, $impl:expr), $( $ty:ty ),*) => {
        struct $struct;
        $(
            impl CmpOp<$ty> for $struct {
                #[inline(always)]
                fn eval($a: $ty, $b: $ty) -> bool {
                    $impl
                }
            }
        )*
    };
}

impl_cmp_op! { IntEqual,            (a, b, a == b) }
impl_cmp_op! { IntNotEqual,         (a, b, a != b) }
impl_cmp_op! { IntLess,             (a, b, a < b) }
impl_cmp_op! { IntLessEqual,        (a, b, a <= b) }
impl_cmp_op! { IntSignedLess,       (a, b, a.to_signed() < b.to_signed()) }
impl_cmp_op! { IntSignedLessEqual,  (a, b, a.to_signed() <= b.to_signed()) }
impl_cmp_op! { IntCarry,            (a, b, a.checked_add(b).is_none()) }
impl_cmp_op! { IntSignedCarry,      (a, b, a.to_signed().checked_add(b.to_signed()).is_none()) }
impl_cmp_op! { IntSignedBorrow,     (a, b, a.to_signed().checked_sub(b.to_signed()).is_none()) }

trait IntSingleOp<T>: Sized {
    fn eval(a: T) -> T;
}

macro_rules! impl_eval_int_single_op {
    ($struct:ident, ($a:ident, $impl:expr)) => {
        impl_eval_int_single_op! { $struct, ($a, $impl), u8, u16, u32, u64, u128 }
    };

    ($struct:ident, ($a:ident, $impl:expr), $( $ty:ty ),*) => {
        struct $struct;
        $(
            impl IntSingleOp<$ty> for $struct {
                #[inline(always)]
                fn eval($a: $ty) -> $ty {
                    $impl
                }
            }
        )*
    };
}

impl_eval_int_single_op! { IntNegate, (a, (-a.to_signed()).to_unsigned()) }
impl_eval_int_single_op! { IntNot, (a, !a) }

/// Represents an operation taking two inputs of the same size producing a boolean output
trait BoolOp: Sized {
    fn eval(a: u8, b: u8) -> bool;
}

macro_rules! impl_bool_op {
    ($struct:ident, ($a:ident, $b:ident, $impl:expr)) => {
        struct $struct;
        impl BoolOp for $struct {
            #[inline(always)]
            fn eval($a: u8, $b: u8) -> bool {
                $impl
            }
        }
    };
}

impl_bool_op! { BoolAnd,    (a, b, a & b != 0) }
impl_bool_op! { BoolOr,     (a, b, a | b != 0) }
impl_bool_op! { BoolXor,    (a, b, a ^ b != 0) }

trait ToFloat {
    type FloatType;
    fn to_float(self) -> Self::FloatType;
}

trait FromFloat<T> {
    fn from_float(self) -> T;
}

impl ToFloat for u16 {
    type FloatType = f16;
    #[inline(always)]
    fn to_float(self) -> f16 {
        f16::from_bits(self)
    }
}

impl FromFloat<u16> for half::f16 {
    #[inline(always)]
    fn from_float(self) -> u16 {
        self.to_bits()
    }
}

impl ToFloat for u32 {
    type FloatType = f32;
    #[inline(always)]
    fn to_float(self) -> f32 {
        f32::from_bits(self)
    }
}

impl FromFloat<u32> for f32 {
    #[inline(always)]
    fn from_float(self) -> u32 {
        self.to_bits()
    }
}

impl ToFloat for u64 {
    type FloatType = f64;
    #[inline(always)]
    fn to_float(self) -> f64 {
        f64::from_bits(self)
    }
}

impl FromFloat<u64> for f64 {
    #[inline(always)]
    fn from_float(self) -> u64 {
        self.to_bits()
    }
}

impl ToFloat for [u8; 10] {
    type FloatType = f64;
    #[inline(always)]
    fn to_float(self) -> f64 {
        f64::from_bits(u64::from_le_bytes(self[..8].try_into().unwrap()))
    }
}

impl FromFloat<[u8; 10]> for f64 {
    #[inline(always)]
    fn from_float(self) -> [u8; 10] {
        let mut v = [0u8; 10];
        v[..8].copy_from_slice(&self.to_bits().to_le_bytes());
        v
    }
}

#[allow(bad_style)]
pub type f80 = [u8; 10];

trait Float80Ext {
    fn to_bits(&self) -> [u8; 10];
    fn to_f64(&self) -> f64;
}

impl Float80Ext for f80 {
    fn to_bits(&self) -> [u8; 10] {
        *self
    }

    fn to_f64(&self) -> f64 {
        // @fixme: not implement correctly
        f64::from_bits(u64::from_le_bytes(self[..8].try_into().unwrap()))
    }
}

pub trait ToFloat80 {
    fn to_f80(&self) -> f80;
}

impl ToFloat80 for f16 {
    fn to_f80(&self) -> f80 {
        self.to_f64().to_f80()
    }
}

impl ToFloat80 for f32 {
    fn to_f80(&self) -> f80 {
        (*self as f64).to_f80()
    }
}

impl ToFloat80 for f64 {
    fn to_f80(&self) -> f80 {
        // @fixme: not implement correctly.
        let mut v = [0u8; 10];
        v[..8].copy_from_slice(&self.to_bits().to_le_bytes());
        v
    }
}

/// Represents an operation taking two inputs of the same size producing a float output
trait FloatOp<T>: Sized {
    fn eval(a: T, b: T) -> T;
}

macro_rules! impl_float_op {
    ($struct:ident, ($a:ident, $b:ident, $impl:expr)) => {
        impl_float_op! { $struct, ($a, $b, $impl), u32, u64, [u8; 10] }
    };

    ($struct:ident, ($a:ident, $b:ident, $impl:expr), $( $ty:ty ),*) => {
        struct $struct;
        $(
            impl FloatOp<$ty> for $struct {
                #[inline(always)]
                fn eval($a: $ty, $b: $ty) -> $ty {
                    let $a = $a.to_float();
                    let $b = $b.to_float();
                    ($impl).from_float()
                }
            }
        )*
    };
}

impl_float_op! { FloatAdd,    (a, b, a + b) }
impl_float_op! { FloatSub,    (a, b, a - b) }
impl_float_op! { FloatMul,    (a, b, a * b) }
impl_float_op! { FloatDiv,    (a, b, a / b) }

/// Represents an operation that takes a single input producing a float output of the same size
trait FloatSingleOp<T>: Sized {
    fn eval(a: T) -> T;
}

macro_rules! impl_float_single_op {
    ($struct:ident, ($a:ident, $impl:expr)) => {
        struct $struct;
        impl FloatSingleOp<u32> for $struct {
            #[inline(always)]
            fn eval($a: u32) -> u32 {
                let $a = $a.to_float();
                ($impl).from_float()
            }
        }
        impl FloatSingleOp<u64> for $struct {
            #[inline(always)]
            fn eval($a: u64) -> u64 {
                let $a = $a.to_float();
                ($impl).from_float()
            }
        }
        impl FloatSingleOp<[u8; 10]> for $struct {
            #[inline(always)]
            fn eval($a: [u8; 10]) -> [u8; 10] {
                let $a = $a.to_float();
                ($impl).from_float()
            }
        }
    };
}

impl_float_single_op! { FloatNegate, (a, -a) }
impl_float_single_op! { FloatAbs,    (a, a.abs()) }
impl_float_single_op! { FloatSqrt,   (a, a.sqrt()) }
impl_float_single_op! { FloatCeil,   (a, a.ceil()) }
impl_float_single_op! { FloatFloor,  (a, a.floor()) }
impl_float_single_op! { FloatRound,  (a, a.round()) }

trait FloatCmpOp<T>: Sized {
    fn eval(a: T, b: T) -> bool;
}

macro_rules! impl_float_cmp_op {
    ($struct:ident, ($a:ident, $b:ident, $impl:expr)) => {
        struct $struct;
        impl FloatCmpOp<u32> for $struct {
            fn eval($a: u32, $b: u32) -> bool {
                let $a = $a.to_float();
                let $b = $b.to_float();
                $impl
            }
        }
        impl FloatCmpOp<u64> for $struct {
            fn eval($a: u64, $b: u64) -> bool {
                let $a = $a.to_float();
                let $b = $b.to_float();
                $impl
            }
        }
        impl FloatCmpOp<[u8; 10]> for $struct {
            fn eval($a: [u8; 10], $b: [u8; 10]) -> bool {
                let $a = $a.to_float();
                let $b = $b.to_float();
                $impl
            }
        }
    };
}

impl_float_cmp_op! { FloatEqual,     (a, b, a == b) }
impl_float_cmp_op! { FloatNotEqual,  (a, b, a != b) }
impl_float_cmp_op! { FloatLess,      (a, b, a <  b) }
impl_float_cmp_op! { FloatLessEqual, (a, b, a <= b) }
