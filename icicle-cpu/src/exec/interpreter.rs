use icicle_mem::MemResult;
use pcode::{MemId, Value, VarNode};

use crate::{
    regs::{resize_sxt, ValueSource},
    ExceptionCode,
};

pub trait PcodeExecutor: ValueSource {
    fn exception(&mut self, code: ExceptionCode, value: u64);
    fn next_instruction(&mut self, addr: u64, len: u64);
    fn load_mem<const N: usize>(&mut self, id: MemId, addr: u64) -> MemResult<[u8; N]>;
    fn store_mem<const N: usize>(&mut self, id: MemId, addr: u64, value: [u8; N]) -> MemResult<()>;
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
    let inputs = stmt.inputs.get();

    match stmt.op {
        Op::Copy => copy(exec, inputs[0], output),
        Op::ZeroExtend => zero_extend(exec, inputs[0], output),
        Op::SignExtend => sign_extend(exec, inputs[0], output),
        Op::IntToFloat => int_to_float(exec, inputs[0], output),
        Op::FloatToFloat => float_to_float(exec, inputs[0], output),
        Op::FloatToInt => float_to_int(exec, inputs[0], output),

        Op::IntAdd => int_op::<IntAdd, _>(exec, inputs, output),
        Op::IntSub => int_op::<IntSub, _>(exec, inputs, output),
        Op::IntXor => int_op::<IntXor, _>(exec, inputs, output),
        Op::IntOr => int_op::<IntOr, _>(exec, inputs, output),
        Op::IntAnd => int_op::<IntAnd, _>(exec, inputs, output),
        Op::IntMul => int_op::<IntMul, _>(exec, inputs, output),
        Op::IntDiv => div_op::<IntDiv, _>(exec, inputs, output),
        Op::IntSignedDiv => div_op::<IntSignedDiv, _>(exec, inputs, output),
        Op::IntRem => div_op::<IntRem, _>(exec, inputs, output),
        Op::IntSignedRem => div_op::<IntSignedRem, _>(exec, inputs, output),

        Op::IntLeft => {
            let x: u128 = exec.read_dynamic(inputs[0]).zxt();
            let y: u32 = exec.read_dynamic(inputs[1]).zxt();
            let result = if y >= output.size as u32 * 8 { 0 } else { x << y };
            exec.write_trunc(output, result);
        }
        Op::IntRotateLeft => int_op::<IntRotLeft, _>(exec, inputs, output),
        Op::IntRight => {
            let x: u128 = exec.read_dynamic(inputs[0]).zxt();
            let y: u32 = exec.read_dynamic(inputs[1]).zxt();
            let result = if y >= output.size as u32 * 8 { 0 } else { x >> y };
            exec.write_trunc(output, result);
        }
        Op::IntSignedRight => {
            let x: u128 = exec.read_dynamic(inputs[0]).sxt();
            let y: u32 = exec.read_dynamic(inputs[1]).zxt();
            let shift = y.min(output.size as u32 * 8 - 1);
            exec.write_trunc(output, x >> shift);
        }
        Op::IntRotateRight => int_op::<IntRotLeft, _>(exec, inputs, output),

        Op::IntEqual => cmp_op::<IntEqual, _>(exec, inputs, output),
        Op::IntNotEqual => cmp_op::<IntNotEqual, _>(exec, inputs, output),
        Op::IntLess => cmp_op::<IntLess, _>(exec, inputs, output),
        Op::IntSignedLess => cmp_op::<IntSignedLess, _>(exec, inputs, output),
        Op::IntLessEqual => cmp_op::<IntLessEqual, _>(exec, inputs, output),
        Op::IntSignedLessEqual => cmp_op::<IntSignedLessEqual, _>(exec, inputs, output),
        Op::IntCarry => cmp_op::<IntCarry, _>(exec, inputs, output),
        Op::IntSignedCarry => cmp_op::<IntSignedCarry, _>(exec, inputs, output),
        Op::IntSignedBorrow => cmp_op::<IntSignedBorrow, _>(exec, inputs, output),

        Op::IntNot => int_single_op::<IntNot, _>(exec, inputs[0], output),
        Op::IntNegate => int_single_op::<IntNeg, _>(exec, inputs[0], output),
        Op::IntCountOnes => count_ones(exec, inputs[0], output),

        Op::BoolAnd => bool_op::<BoolAnd, _>(exec, inputs, output),
        Op::BoolOr => bool_op::<BoolOr, _>(exec, inputs, output),
        Op::BoolXor => bool_op::<BoolXor, _>(exec, inputs, output),
        Op::BoolNot => bool_not(exec, inputs[0], output),

        Op::FloatAdd => float_op::<FloatAdd, _>(exec, inputs, output),
        Op::FloatSub => float_op::<FloatSub, _>(exec, inputs, output),
        Op::FloatMul => float_op::<FloatMul, _>(exec, inputs, output),
        Op::FloatDiv => float_op::<FloatDiv, _>(exec, inputs, output),

        Op::FloatNegate => float_single_op::<FloatNeg, _>(exec, inputs[0], output),
        Op::FloatAbs => float_single_op::<FloatAbs, _>(exec, inputs[0], output),
        Op::FloatSqrt => float_single_op::<FloatSqrt, _>(exec, inputs[0], output),
        Op::FloatCeil => float_single_op::<FloatCeil, _>(exec, inputs[0], output),
        Op::FloatFloor => float_single_op::<FloatFloor, _>(exec, inputs[0], output),
        Op::FloatRound => float_single_op::<FloatRound, _>(exec, inputs[0], output),
        Op::FloatIsNan => is_nan(exec, inputs[0], output),

        Op::FloatEqual => float_cmp_op::<FloatEq, _>(exec, inputs, output),
        Op::FloatNotEqual => float_cmp_op::<FloatNe, _>(exec, inputs, output),
        Op::FloatLess => float_cmp_op::<FloatLt, _>(exec, inputs, output),
        Op::FloatLessEqual => float_cmp_op::<FloatLe, _>(exec, inputs, output),

        Op::Load(id) => {
            let addr: u64 = exec.read_dynamic(inputs[0]).zxt();
            if let Err(e) = load(exec, id, output, addr) {
                exec.exception(ExceptionCode::from_load_error(e), addr)
            }
        }
        Op::Store(id) => {
            let addr: u64 = exec.read_dynamic(inputs[0]).zxt();
            if let Err(e) = store(exec, id, addr, inputs[1]) {
                exec.exception(ExceptionCode::from_store_error(e), addr)
            }
        }

        Op::Arg(id) => {
            let value = exec.read_dynamic(inputs[0]).zxt();
            exec.set_arg(id, value);
        }
        Op::PcodeOp(id) => exec.call_helper(id, output, inputs),
        Op::Hook(id) => exec.call_hook(id),
        Op::Exception => {
            let a: u32 = exec.read_dynamic(inputs[0]).zxt();
            let b: u64 = exec.read_dynamic(inputs[1]).zxt();
            exec.exception(ExceptionCode::from_u32(a), b);
        }

        Op::InstructionMarker => exec.next_instruction(inputs[0].as_u64(), inputs[1].as_u64()),
        Op::Invalid => exec.exception(ExceptionCode::InvalidInstruction, 0),

        _ => panic!("Unexpected operation in interpreter: {stmt:?}"),
    }
}

fn copy<E: ValueSource>(exec: &mut E, input: Value, output: VarNode) {
    #[inline(never)]
    #[cold]
    fn cold<E: ValueSource>(exec: &mut E, input: Value, output: VarNode) {
        for i in 0..output.size {
            let byte = exec.read::<u8>(input.slice(i, 1));
            exec.write_var(output.slice(i, 1), byte);
        }
    }

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
        _ => cold(exec, input, output),
    }
}

fn zero_extend<E: ValueSource>(exec: &mut E, input: Value, output: VarNode) {
    #[inline(never)]
    #[cold]
    fn cold<E: ValueSource>(exec: &mut E, input: Value, output: VarNode) {
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

    macro_rules! eval {
        ($in_ty:ty, $out_ty:ty) => {{
            let value = exec.read::<$in_ty>(input) as $out_ty;
            exec.write_var(output, value);
        }};

        ($in_ty:ty) => {
            match output.size {
                1 => eval!($in_ty, u8),
                2 => eval!($in_ty, u16),
                4 => eval!($in_ty, u32),
                8 => eval!($in_ty, u64),
                16 => eval!($in_ty, u128),
                _ => cold(exec, input, output),
            }
        };
    }

    match input.size() {
        1 => eval!(u8),
        2 => eval!(u16),
        4 => eval!(u32),
        8 => eval!(u64),
        16 => eval!(u128),
        _ => cold(exec, input, output),
    }
}

pub fn sign_extend<E>(exec: &mut E, input: Value, output: VarNode)
where
    E: ValueSource,
{
    #[inline(never)]
    #[cold]
    fn cold<E>(exec: &mut E, input: Value, output: VarNode)
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

    macro_rules! eval {
        ($in_ty:ty, $out_ty:ty) => {{
            let value =
                <$out_ty>::from_ne_bytes(resize_sxt(exec.read::<$in_ty>(input).to_ne_bytes()));
            exec.write_var(output, value);
        }};

        ($in_ty:ty) => {
            match output.size {
                1 => eval!($in_ty, u8),
                2 => eval!($in_ty, u16),
                4 => eval!($in_ty, u32),
                8 => eval!($in_ty, u64),
                16 => eval!($in_ty, u128),
                _ => cold(exec, input, output),
            }
        };
    }
    match input.size() {
        1 => eval!(u8),
        2 => eval!(u16),
        4 => eval!(u32),
        8 => eval!(u64),
        16 => eval!(u128),
        _ => cold(exec, input, output),
    }
}

fn load<E: PcodeExecutor>(exec: &mut E, id: MemId, dst: VarNode, addr: u64) -> MemResult<()> {
    macro_rules! load {
        ($dst:expr, $addr:expr, $ty:ty) => {{
            let tmp = exec.load_mem(id, $addr)?;
            let value = match exec.is_big_endian() {
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
            if exec.is_big_endian() {
                load!(dst.slice(8, 8), addr, u64);
                load!(dst.slice(0, 8), addr.wrapping_add(8), u64);
            }
            else {
                load!(dst.slice(0, 8), addr, u64);
                load!(dst.slice(8, 8), addr.wrapping_add(8), u64);
            }
        }
        size => {
            if exec.is_big_endian() {
                for i in 0..size {
                    load!(dst.slice(size - 1 - i, 1), addr.wrapping_add(i as u64), u8);
                }
            }
            else {
                for i in 0..size {
                    load!(dst.slice(i, 1), addr.wrapping_add(i as u64), u8);
                }
            }
        }
    }

    Ok(())
}

fn store<E: PcodeExecutor>(exec: &mut E, id: MemId, addr: u64, value: Value) -> MemResult<()> {
    macro_rules! writer {
        ($addr:expr, $value:expr) => {{
            let val = $value;
            let bytes = match exec.is_big_endian() {
                true => val.to_be_bytes(),
                false => val.to_le_bytes(),
            };
            exec.store_mem(id, $addr, bytes)
        }};
    }

    match value.size() {
        1 => writer!(addr, exec.read::<u8>(value))?,
        2 => writer!(addr, exec.read::<u16>(value))?,
        4 => writer!(addr, exec.read::<u32>(value))?,
        8 => writer!(addr, exec.read::<u64>(value))?,
        16 => {
            if exec.is_big_endian() {
                writer!(addr, exec.read::<u64>(value.slice(8, 8)))?;
                writer!(addr.wrapping_add(8), exec.read::<u64>(value.slice(0, 8)))?;
            }
            else {
                writer!(addr, exec.read::<u64>(value.slice(0, 8)))?;
                writer!(addr.wrapping_add(8), exec.read::<u64>(value.slice(8, 8)))?;
            }
        }
        size => {
            if exec.is_big_endian() {
                for i in 0..size {
                    writer!(
                        addr.wrapping_add(size as u64 - 1 - i as u64),
                        exec.read::<u8>(value.slice(i, 1))
                    )?;
                }
            }
            else {
                for i in 0..size {
                    writer!(addr.wrapping_add(i as u64), exec.read::<u8>(value.slice(i, 1)))?;
                }
            }
        }
    }

    Ok(())
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
            fn to_signed(self) -> Self::Signed {
                self as Self::Signed
            }
        }

        impl ToUnsigned for $signed {
            type Unsigned = $unsigned;
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

#[inline(always)]
fn int_op<O, E>(exec: &mut E, inputs: [Value; 2], output: VarNode)
where
    O: IntOp<u8>,
    O: IntOp<u16>,
    O: IntOp<u32>,
    O: IntOp<u64>,
    O: IntOp<u128>,
    E: PcodeExecutor,
{
    let [a, b] = inputs;
    macro_rules! eval {
        ($ty:ty) => {{
            let a: $ty = exec.read(a);
            let b: $ty = exec.read(b);
            exec.write_var(output, O::eval(a, b));
        }};
    }

    match output.size {
        1 => eval!(u8),
        2 => eval!(u16),
        4 => eval!(u32),
        8 => eval!(u64),
        16 => eval!(u128),
        size => exec.invalid_op_size(size),
    }
}

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

impl_eval_int_op! { IntRotLeft,     (a, b, a.rotate_left(b as u32)) }
impl_eval_int_op! { IntRotRight,    (a, b, a.rotate_right(b as u32)) }

#[inline(always)]
fn div_op<O, E>(exec: &mut E, inputs: [Value; 2], output: VarNode)
where
    O: IntOp<u8>,
    O: IntOp<u16>,
    O: IntOp<u32>,
    O: IntOp<u64>,
    O: IntOp<u128>,
    E: PcodeExecutor,
{
    let [a, b] = inputs;
    macro_rules! eval {
        ($ty:ty) => {{
            let a: $ty = exec.read(a);
            let b: $ty = exec.read(b);
            if b == 0 {
                exec.exception(ExceptionCode::DivideByZero, 0);
                return;
            }
            exec.write_var(output, O::eval(a, b));
        }};
    }

    match output.size {
        1 => eval!(u8),
        2 => eval!(u16),
        4 => eval!(u32),
        8 => eval!(u64),
        16 => eval!(u128),
        size => exec.invalid_op_size(size),
    }
}

impl_eval_int_op! { IntDiv,         (a, b, a / b) }
impl_eval_int_op! { IntSignedDiv,   (a, b, a.to_signed().wrapping_div(b.to_signed()).to_unsigned()) }
impl_eval_int_op! { IntRem,         (a, b, a % b) }
impl_eval_int_op! { IntSignedRem,   (a, b, a.to_signed().wrapping_rem(b.to_signed()).to_unsigned()) }

#[inline(always)]
fn cmp_op<O, E>(exec: &mut E, inputs: [Value; 2], output: VarNode)
where
    O: CmpOp<u8>,
    O: CmpOp<u16>,
    O: CmpOp<u32>,
    O: CmpOp<u64>,
    O: CmpOp<u128>,
    E: PcodeExecutor,
{
    let [a, b] = inputs;
    macro_rules! eval {
        ($ty:ty) => {{
            let a: $ty = exec.read(a);
            let b: $ty = exec.read(b);
            exec.write_var(output, O::eval(a, b) as u8);
        }};
    }

    match a.size() {
        1 => eval!(u8),
        2 => eval!(u16),
        4 => eval!(u32),
        8 => eval!(u64),
        16 => eval!(u128),
        size => exec.invalid_op_size(size),
    }
}

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

#[inline(always)]
fn int_single_op<O, E>(exec: &mut E, input: Value, output: VarNode)
where
    O: IntSingleOp<u8>,
    O: IntSingleOp<u16>,
    O: IntSingleOp<u32>,
    O: IntSingleOp<u64>,
    O: IntSingleOp<u128>,
    E: PcodeExecutor,
{
    macro_rules! eval {
        ($ty:ty) => {{
            let input: $ty = exec.read(input);
            exec.write_var(output, O::eval(input));
        }};
    }

    match input.size() {
        1 => eval!(u8),
        2 => eval!(u16),
        4 => eval!(u32),
        8 => eval!(u64),
        16 => eval!(u128),
        size => exec.invalid_op_size(size),
    }
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

impl_eval_int_single_op! { IntNeg, (a, (-a.to_signed()).to_unsigned()) }
impl_eval_int_single_op! { IntNot, (a, !a) }

pub fn count_ones<E>(exec: &mut E, input: Value, output: VarNode)
where
    E: PcodeExecutor,
{
    let result = match input.size() {
        1 => exec.read::<u8>(input).count_ones(),
        2 => exec.read::<u16>(input).count_ones(),
        4 => exec.read::<u32>(input).count_ones(),
        8 => exec.read::<u64>(input).count_ones(),
        16 => exec.read::<u128>(input).count_ones(),
        size => return exec.invalid_op_size(size),
    };
    exec.write_trunc(output, result);
}

#[inline(always)]
fn bool_op<O, E>(exec: &mut E, inputs: [Value; 2], output: VarNode)
where
    O: BoolOp,
    E: PcodeExecutor,
{
    let [a, b] = inputs;
    let a: u8 = exec.read(a);
    let b: u8 = exec.read(b);
    exec.write_var(output, O::eval(a, b) as u8);
}

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

pub fn bool_not<E>(exec: &mut E, input: Value, output: VarNode)
where
    E: PcodeExecutor,
{
    let x = exec.read::<u8>(input);
    exec.write_var(output, pcode::cast_bool(x == 0));
}

#[inline(always)]
fn float_op<O, E>(exec: &mut E, inputs: [Value; 2], output: VarNode)
where
    O: FloatOp<u32>,
    O: FloatOp<u64>,
    O: FloatOp<[u8; 10]>,
    E: PcodeExecutor,
{
    let [a, b] = inputs;
    macro_rules! eval {
        ($ty:ty) => {{
            let a: $ty = exec.read(a);
            let b: $ty = exec.read(b);
            exec.write_var(output, O::eval(a, b));
        }};
    }

    match a.size() {
        4 => eval!(u32),
        8 => eval!(u64),
        10 => eval!([u8; 10]),
        size => exec.invalid_op_size(size),
    }
}

trait ToFloat {
    type FloatType;
    fn to_float(self) -> Self::FloatType;
}

trait FromFloat<T> {
    fn from_float(self) -> T;
}

impl ToFloat for u32 {
    type FloatType = f32;
    fn to_float(self) -> f32 {
        f32::from_bits(self)
    }
}

impl FromFloat<u32> for f32 {
    fn from_float(self) -> u32 {
        self.to_bits()
    }
}

impl ToFloat for u64 {
    type FloatType = f64;
    fn to_float(self) -> f64 {
        f64::from_bits(self)
    }
}

impl FromFloat<u64> for f64 {
    fn from_float(self) -> u64 {
        self.to_bits()
    }
}

impl ToFloat for [u8; 10] {
    type FloatType = f64;
    fn to_float(self) -> f64 {
        f64::from_bits(u64::from_le_bytes(self[..8].try_into().unwrap()))
    }
}

impl FromFloat<[u8; 10]> for f64 {
    fn from_float(self) -> [u8; 10] {
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
impl_float_op! { FloatMod,    (a, b, a % b) }

#[inline(always)]
fn float_single_op<O, E>(exec: &mut E, input: Value, output: VarNode)
where
    O: FloatSingleOp<u32>,
    O: FloatSingleOp<u64>,
    O: FloatSingleOp<[u8; 10]>,
    E: PcodeExecutor,
{
    macro_rules! eval {
        ($ty:ty) => {{
            let input: $ty = exec.read(input);
            exec.write_var(output, O::eval(input));
        }};
    }

    match input.size() {
        4 => eval!(u32),
        8 => eval!(u64),
        10 => eval!([u8; 10]),
        size => exec.invalid_op_size(size),
    }
}

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

impl_float_single_op! { FloatNeg,    (a, -a) }
impl_float_single_op! { FloatAbs,    (a, a.abs()) }
impl_float_single_op! { FloatSqrt,   (a, a.sqrt()) }
impl_float_single_op! { FloatCeil,   (a, a.ceil()) }
impl_float_single_op! { FloatFloor,  (a, a.floor()) }
impl_float_single_op! { FloatRound,  (a, a.round()) }

pub fn is_nan<E>(exec: &mut E, input: Value, output: VarNode)
where
    E: PcodeExecutor,
{
    macro_rules! eval {
        ($ty:ty) => {
            exec.read::<$ty>(input).to_float().is_nan()
        };
    }

    let result = match input.size() {
        4 => eval!(u32),
        8 => eval!(u64),
        10 => eval!([u8; 10]),
        size => return exec.invalid_op_size(size),
    };
    exec.write_var(output, pcode::cast_bool(result));
}

#[inline(always)]
fn float_cmp_op<O, E>(exec: &mut E, inputs: [Value; 2], output: VarNode)
where
    O: FloatCmpOp<u32>,
    O: FloatCmpOp<u64>,
    O: FloatCmpOp<[u8; 10]>,
    E: PcodeExecutor,
{
    let [a, b] = inputs;
    macro_rules! eval {
        ($ty:ty) => {{
            let a: $ty = exec.read(a);
            let b: $ty = exec.read(b);
            exec.write_var(output, O::eval(a, b) as u8);
        }};
    }

    match a.size() {
        4 => eval!(u32),
        8 => eval!(u64),
        10 => eval!([u8; 10]),
        size => exec.invalid_op_size(size),
    }
}

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

impl_float_cmp_op! { FloatEq,    (a, b, a == b) }
impl_float_cmp_op! { FloatNe,    (a, b, a != b) }
impl_float_cmp_op! { FloatLt,    (a, b, a < b) }
impl_float_cmp_op! { FloatLe,    (a, b, a <= b) }

fn int_to_float<E>(exec: &mut E, input: Value, output: VarNode)
where
    E: PcodeExecutor,
{
    macro_rules! to_float {
        ($in:ty) => {{
            let value = exec.read::<$in>(input).to_signed();
            match output.size {
                4 => exec.write_var::<u32>(output, FromFloat::from_float(value as f32)),
                8 => exec.write_var::<u64>(output, FromFloat::from_float(value as f64)),
                10 => exec.write_var::<[u8; 10]>(output, FromFloat::from_float(value as f64)),
                size => exec.exception(ExceptionCode::InvalidFloatSize, size as u64),
            }
        }};
    }

    match input.size() {
        1 => to_float!(u8),
        2 => to_float!(u16),
        4 => to_float!(u32),
        8 => to_float!(u64),
        size => exec.invalid_op_size(size),
    }
}

fn float_to_float<E>(exec: &mut E, input: Value, output: VarNode)
where
    E: PcodeExecutor,
{
    macro_rules! cast {
        ($val:expr) => {{
            let val = $val;
            match output.size {
                4 => exec.write_var::<u32>(output, FromFloat::from_float(val as f32)),
                8 => exec.write_var::<u64>(output, FromFloat::from_float(val as f64)),
                10 => exec.write_var::<[u8; 10]>(output, FromFloat::from_float(val as f64)),
                size => return exec.exception(ExceptionCode::InvalidFloatSize, size as u64),
            }
        }};
    }

    match input.size() {
        4 => cast!(exec.read::<u32>(input).to_float()),
        8 => cast!(exec.read::<u64>(input).to_float()),
        10 => cast!(exec.read::<[u8; 10]>(input).to_float()),
        size => exec.exception(ExceptionCode::InvalidFloatSize, size as u64),
    }
}

fn float_to_int<E>(exec: &mut E, input: Value, output: VarNode)
where
    E: PcodeExecutor,
{
    macro_rules! cast {
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

    match input.size() {
        4 => cast!(exec.read::<u32>(input).to_float() as i32),
        8 => cast!(exec.read::<u64>(input).to_float() as i64),
        10 => cast!(exec.read::<[u8; 10]>(input).to_float() as i64),
        size => exec.exception(ExceptionCode::InvalidFloatSize, size as u64),
    }
}
