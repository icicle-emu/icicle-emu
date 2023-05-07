use std::collections::HashSet;

use icicle_vm::cpu::{
    exec::const_eval::BitVecExt,
    lifter::{Block, BlockExit},
};
use pcode::{Op, PcodeDisplay, Value};

bitflags::bitflags! {
    #[derive(Copy, Clone, PartialEq, Eq, Debug)]
    pub struct CmpAttr: u8 {
        const NOT_EQUAL     = 1;
        const IS_EQUAL      = 1 << 1;
        const IS_GREATER    = 1 << 2;
        const IS_LESSER     = 1 << 3;
        const IS_FLOAT      = 1 << 4;
        const IS_OVERFLOW   = 1 << 5;
        const IS_MASKED     = 1 << 6;
    }
}

impl CmpAttr {
    pub fn from_u8(value: u8) -> Self {
        Self::from_bits(value).unwrap_or_else(Self::empty)
    }

    fn invert(self) -> Self {
        let mut inverted = Self::NOT_EQUAL;
        if !self.contains(Self::IS_EQUAL) {
            inverted |= Self::IS_EQUAL;
        }

        if self.contains(CmpAttr::IS_LESSER) {
            inverted |= Self::IS_GREATER;
        }
        if self.contains(CmpAttr::IS_GREATER) {
            inverted |= Self::IS_LESSER;
        }
        inverted
    }

    fn invert_if(self, should_invert: bool) -> Self {
        match should_invert {
            true => self.invert(),
            false => self,
        }
    }
}

impl From<Op> for CmpAttr {
    fn from(op: Op) -> Self {
        match op {
            Op::IntSignedLess | Op::IntLess => Self::IS_LESSER,
            Op::IntSignedLessEqual | Op::IntLessEqual => Self::IS_LESSER | Self::IS_EQUAL,

            Op::IntEqual => Self::IS_EQUAL,
            Op::IntNotEqual => Self::NOT_EQUAL,

            Op::IntCarry | Op::IntSignedCarry | Op::IntSignedBorrow => Self::IS_OVERFLOW,

            Op::FloatLess => Self::IS_LESSER | Self::IS_FLOAT,
            Op::FloatLessEqual => Self::IS_LESSER | Self::IS_EQUAL | Self::IS_FLOAT,
            Op::FloatEqual => Self::IS_EQUAL | Self::IS_FLOAT,
            Op::FloatNotEqual => Self::NOT_EQUAL | Self::IS_FLOAT,

            _ => Self::empty(),
        }
    }
}

#[derive(Copy, Clone, PartialEq, Eq)]
pub struct CmpOp {
    pub kind: CmpAttr,
    pub arg1: pcode::Value,
    pub arg2: pcode::Value,
    pub offset: usize,
}

impl pcode::PcodeDisplay<sleigh_runtime::SleighData> for CmpOp {
    fn fmt(
        &self,
        f: &mut std::fmt::Formatter,
        ctx: &sleigh_runtime::SleighData,
    ) -> std::fmt::Result {
        f.debug_struct("CmpOp")
            .field("kind", &format_args!("{:?}", self.kind))
            .field("arg1", &format_args!("{}", self.arg1.display(ctx)))
            .field("arg2", &format_args!("{}", self.arg2.display(ctx)))
            .field("offset", &self.offset)
            .finish()
    }
}

pub struct CmpFinder {
    buf: Vec<CmpOp>,
    const_eval: icicle_vm::cpu::exec::const_eval::ConstEval,
    find_cmov: bool,
    find_adds: bool,
}

impl CmpFinder {
    pub fn new() -> Self {
        Self {
            buf: vec![],
            const_eval: icicle_vm::cpu::exec::const_eval::ConstEval::new(),
            find_cmov: true,
            find_adds: true,
        }
    }

    pub fn with_arch(arch: &icicle_vm::cpu::Arch) -> Self {
        // Currently the sleigh specification doesn't implement conditional moves consistently so
        // we only enable the cmov finder on x86_64.
        let find_cmov = matches!(arch.triple.architecture, target_lexicon::Architecture::X86_64);

        Self {
            buf: vec![],
            const_eval: icicle_vm::cpu::exec::const_eval::ConstEval::new(),
            find_cmov,
            find_adds: false,
        }
    }

    pub fn find_cmp(&mut self, block: &Block) -> &[CmpOp] {
        self.buf.clear();

        if let BlockExit::Branch { cond: pcode::Value::Var(cond), .. } = block.exit {
            find_comparisons(&mut CmpProp {
                inverted: false,
                cmp_zero: None,
                dst: cond,
                block: &block.pcode,
                offset: block.pcode.instructions.len(),
                out: &mut self.buf,
                bit: 0,
                find_adds: self.find_adds,
            });
        }
        else if self.find_cmov {
            let (dst, offset) = match find_cmov(block) {
                Some(value) => value,
                None => return &[],
            };
            find_comparisons(&mut CmpProp {
                inverted: false,
                cmp_zero: Some(CmpAttr::IS_EQUAL),
                dst,
                block: &block.pcode,
                offset,
                out: &mut self.buf,
                bit: 0,
                find_adds: self.find_adds,
            });
        };
        self.buf.sort_by_key(|x| x.offset);

        // Filter uninteresting comparisons after applying bit-level constant propagation.
        // @fixme: Move this inside of CmpFinder.
        self.buf.retain_mut(|cmp| {
            self.const_eval.clear();
            for stmt in &block.pcode.instructions[..cmp.offset] {
                let _ = self.const_eval.eval(*stmt);
            }
            let arg1 = self.const_eval.get_value(cmp.arg1);
            let arg2 = self.const_eval.get_value(cmp.arg2);

            let extended_bytes = arg1.num_extended_bits().min(arg2.num_extended_bits()) / 8;
            if extended_bytes != 0 {
                let new_size = cmp.arg1.size() - extended_bytes as u8;
                cmp.arg1 = cmp.arg1.slice(0, new_size);
                cmp.arg2 = cmp.arg2.slice(0, new_size);
            }

            if let Some(x) = arg1.get_const() {
                cmp.arg1 = pcode::Value::Const(x, cmp.arg1.size());
            }
            if let Some(x) = arg2.get_const() {
                cmp.arg2 = pcode::Value::Const(x, cmp.arg2.size());
            }

            // Since `&` is symmetric, CmpFinder identifies 2 comparisons for comparisons that
            // involve a mask (one for both the target operand and the mask). If possible we try to
            // remove the comparisons with the mask which is often constant.
            if cmp.kind.contains(CmpAttr::IS_MASKED) && cmp.arg2.is_const() {
                return false;
            }

            // Ignore comparisons that involve a small number of variable bits.
            let variable_bits = arg1.non_constant_bits().max(arg2.non_constant_bits());
            if variable_bits <= 4 {
                return false;
            }

            // Ignore comparisons with zero (frequently used for loop counters).
            if cmp.arg1.const_eq(0) || cmp.arg2.const_eq(0) {
                return false;
            }

            true
        });

        &self.buf
    }
}

fn find_cmov(block: &Block) -> Option<(pcode::VarNode, usize)> {
    for (i, stmt) in block.pcode.instructions.iter().enumerate() {
        if let pcode::Op::IntMul = stmt.op {
            // @fixme: Currently multiply is frequently used as a "bad" conditional move
            // in sleigh, this should be instead handled by the optimizer.
            return Some((stmt.output, i + 1));
        }
    }
    None
}

struct CmpProp<'a> {
    /// Set if the comparison is inverted after it was computed.
    inverted: bool,

    /// Set if the (used for determining whether a subtraction is a comparison op).
    cmp_zero: Option<CmpAttr>,

    /// The destination that we are looking for propagations for.
    dst: pcode::VarNode,

    /// The block we are inspecting inside of.
    block: &'a pcode::Block,

    /// The instruction offset to search (in reverse) from
    offset: usize,

    /// The offset of the bit that is being checked.
    bit: u32,

    // Whether to also consider add operations for comparisons
    find_adds: bool,

    /// Any comparison operation that is eventually propagated to the exit condition.
    out: &'a mut Vec<CmpOp>,
}

impl<'a> CmpProp<'a> {
    fn prop_both(&mut self, a: pcode::Value, b: pcode::Value, invert_b: bool) -> usize {
        let mut found = 0;

        let inverted = self.inverted;
        let cmp_zero = self.cmp_zero;
        let offset = self.offset;

        if let pcode::Value::Var(var) = a {
            self.dst = var;
            if recursive_find_comparisons(self) {
                found += 1;
            }

            self.inverted = inverted ^ invert_b;
            self.cmp_zero = cmp_zero;
            self.offset = offset;
        }

        if let pcode::Value::Var(var) = b {
            self.dst = var;
            if recursive_find_comparisons(self) {
                found += 1;
            }

            self.inverted = inverted;
            self.offset = offset;
            self.cmp_zero = cmp_zero;
        }

        found
    }

    fn add(&mut self, kind: impl Into<CmpAttr>, arg1: pcode::Value, arg2: pcode::Value) {
        if arg2.const_eq(0) || arg1.const_eq(0) {
            return;
        }

        let kind = kind.into();
        // eprintln!("add: {:?}, inverted = {}", kind, self.inverted);
        self.out.push(CmpOp {
            kind: kind.invert_if(self.inverted),
            arg1,
            arg2,
            offset: self.offset,
        });
    }
}

const USE_DATALOG: bool = true;

fn find_comparisons(prop: &mut CmpProp) -> bool {
    if USE_DATALOG { datalog_find_comparisons(prop) } else { recursive_find_comparisons(prop) }
}

// @todo: Improve this code:
//      - Dependency analysis should be handled by `const_eval::ConstEval`.
//      - Merge complex constraints (e.g. CF == ZF).
//      - Introduce proper conditional move operation.
//      - Support multi-block analysis.
//      - Support storing comparison results to memory.
fn recursive_find_comparisons(prop: &mut CmpProp) -> bool {
    let before = prop.out.len();

    // eprintln!("-----------");
    for i in (0..prop.offset).rev() {
        prop.offset = i;

        let stmt = &prop.block.instructions[i];
        if stmt.output.id != prop.dst.id {
            // This statement does not involve the current varnode that we are inspecting.
            continue;
        }

        let inputs = stmt.inputs.get();
        match stmt.op {
            Op::Copy
            | Op::Subpiece(_)
            | Op::ZeroExtend
            | Op::SignExtend
            | Op::IntToFloat
            | Op::FloatToFloat
            | Op::FloatToInt => match inputs[0] {
                Value::Var(var) => prop.dst = var,
                _ => break,
            },

            Op::IntAdd => {
                if prop.find_adds {
                    if let Some(cmp) = prop.cmp_zero.take() {
                        prop.add(cmp, inputs[0], inputs[1]);
                    }
                }
                break;
            }
            Op::IntSub => {
                if let Some(cmp) = prop.cmp_zero.take() {
                    prop.add(cmp, inputs[0], inputs[1]);
                }
                break;
            }
            Op::IntXor => {
                prop.add(CmpAttr::IS_EQUAL, inputs[0], inputs[1]);
                break;
            }
            Op::IntOr => match (inputs[0], inputs[1]) {
                (Value::Const(..), Value::Var(var)) | (Value::Var(var), Value::Const(..)) => {
                    prop.dst = var;
                }
                (Value::Var(_), Value::Var(_)) => {
                    prop.prop_both(inputs[0], inputs[1], false);
                    break;
                }
                _ => break,
            },

            Op::IntAnd => {
                let (dst, mask) = match (inputs[0], inputs[1]) {
                    (Value::Var(dst), Value::Const(mask, _)) => (dst, mask),
                    (Value::Const(mask, _), Value::Var(dst)) => (dst, mask),
                    (Value::Var(_), Value::Var(_)) => {
                        // @fixme: The comparisons should be merged here
                        prop.prop_both(inputs[0], inputs[1], false);
                        break;
                    }
                    (Value::Const(_, _), Value::Const(_, _)) => break,
                };

                // The mask must not clear the bit we are interested in.
                if mask & (1 << prop.bit) == 0 {
                    break;
                }
                prop.dst = dst;
            }
            Op::IntMul => {
                // Multiply is sometimes used as a conditional move, so try and determine
                // whether any operand is used in a boolean expression earlier.
                //
                // @todo: ideally this would be resolved by an optimisation path that
                // converts multiplication with a boolean to a conditional move.
                prop.prop_both(inputs[0], inputs[1], false);
                break;
            }

            Op::IntLeft => match (inputs[0], inputs[1]) {
                (Value::Var(src), Value::Const(shift, _)) if prop.bit == shift as u32 => {
                    prop.bit = 0;
                    prop.dst = src;
                }
                _ => break,
            },
            Op::IntRight => match (inputs[0], inputs[1]) {
                (Value::Var(src), Value::Const(shift, _)) if prop.bit == 0 => {
                    prop.bit = shift as u32;
                    prop.dst = src;
                }
                _ => break,
            },

            Op::IntDiv | Op::IntSignedDiv | Op::IntRem | Op::IntSignedRem => {
                if let Value::Var(var) = inputs[1] {
                    prop.inverted ^= false;
                    // Try to trigger division by zero
                    prop.cmp_zero = Some(CmpAttr::IS_EQUAL);
                    prop.dst = var;
                }
                break;
            }

            Op::BoolAnd | Op::BoolOr | Op::BoolXor => {
                // For all boolean operations try resolve the inputs of both operands
                prop.cmp_zero = None;
                prop.prop_both(inputs[0], inputs[1], false);
                break;
            }

            Op::FloatAdd | Op::FloatSub | Op::FloatMul | Op::FloatDiv => {
                // @todo: better float support
                break;
            }

            Op::FloatAbs
            | Op::FloatSqrt
            | Op::FloatCeil
            | Op::FloatFloor
            | Op::FloatRound
            | Op::FloatIsNan => {
                break;
            }

            Op::FloatNegate | Op::IntNegate | Op::IntNot | Op::BoolNot => match inputs[0] {
                Value::Var(var) => {
                    prop.inverted ^= true;
                    prop.dst = var;
                }
                _ => break,
            },

            op @ (Op::IntEqual
            | Op::IntNotEqual
            | Op::IntLess
            | Op::IntSignedLess
            | Op::IntLessEqual
            | Op::IntSignedLessEqual
            | Op::IntCarry
            | Op::IntSignedCarry
            | Op::IntSignedBorrow) => match (inputs[0], inputs[1]) {
                (Value::Const(0, _), Value::Var(y)) => {
                    prop.inverted ^= true;
                    prop.cmp_zero = Some(op.into());
                    prop.dst = y;
                }
                (Value::Var(x), Value::Const(0, _)) => {
                    prop.cmp_zero = Some(op.into());
                    prop.dst = x;
                }
                (x, y) => {
                    if x.is_const() || y.is_const() || !matches!(op, Op::IntEqual | Op::IntNotEqual)
                    {
                        prop.add(op, x, y);
                        break;
                    }

                    // Check whether the inputs are computed from a previous condition. Handles
                    // cases like CF == OF.
                    prop.cmp_zero = None;
                    if prop.prop_both(inputs[0], inputs[1], false) < 2 {
                        // This was the first time one of the input was involved in a comparision
                        prop.add(op, x, y);
                    }
                    break;
                }
            },

            op @ (Op::FloatEqual | Op::FloatNotEqual | Op::FloatLess | Op::FloatLessEqual) => {
                match (inputs[0], inputs[1]) {
                    (Value::Var(x), Value::Const(0, _)) | (Value::Const(0, _), Value::Var(x)) => {
                        prop.cmp_zero = Some(op.into());
                        prop.dst = x;
                    }
                    (x, y) => {
                        prop.add(op, x, y);
                        break;
                    }
                }
            }

            Op::Load(_) => {
                // @todo: add support for propgating though memory
                break;
            }

            Op::PcodeOp(_) => {
                if !inputs[0].is_invalid() && !inputs[1].is_invalid() {
                    prop.add(CmpAttr::IS_EQUAL, inputs[0], inputs[1]);
                }
                break;
            }

            _ => break,
        }
    }

    if let Some(cmp) = prop.cmp_zero.take() {
        prop.add(cmp, prop.dst.into(), Value::Const(0, prop.dst.size));
    }

    before != prop.out.len()
}

fn is_const_mask_for_size(value: Value) -> bool {
    match value {
        Value::Const(u64::MAX, _) => true,
        Value::Const(x, _) if x >= 0xff && (x + 1).count_ones() == 1 => true,
        _ => false,
    }
}

fn is_all_ones(value: Value) -> bool {
    match value {
        Value::Const(u64::MAX, _) => true,
        Value::Const(x, size) => {
            let ones = pcode::mask(8 * size as u64);
            x & ones == ones
        }
        _ => false,
    }
}

#[derive(Debug, Copy, Clone, Eq, PartialEq, Hash)]
enum CmpKind {
    Eq,
    Ne,
    Lt,
    Gt,
    Le,
    Ge,
    Slt,
    Borrow,
    Carry,
    MaskedEq(Value),
}

impl CmpKind {
    fn flip_operands(&self) -> Option<Self> {
        match self {
            Eq => Some(Eq),
            Ne => Some(Ne),
            Lt => Some(Gt),
            Gt => Some(Lt),
            Le => Some(Ge),
            Ge => Some(Le),
            Slt => None,
            Borrow => None,
            Carry => None,
            MaskedEq(x) => Some(MaskedEq(*x)),
        }
    }

    fn inv(&self) -> Self {
        match self {
            Eq => Ne,
            Ne => Eq,
            Lt => Ge,
            Gt => Le,
            Le => Gt,
            Ge => Lt,
            Slt => Ge,
            // @fixme? add inverses of these operations.
            Borrow => Borrow,
            Carry => Carry,
            MaskedEq(_) => Ne,
        }
    }
}

impl From<CmpKind> for CmpAttr {
    fn from(x: CmpKind) -> Self {
        match x {
            CmpKind::Eq => CmpAttr::IS_EQUAL,
            CmpKind::Ne => CmpAttr::NOT_EQUAL,
            CmpKind::Lt | CmpKind::Slt => CmpAttr::IS_LESSER,
            CmpKind::Gt => CmpAttr::IS_GREATER,
            CmpKind::Le => CmpAttr::IS_LESSER | CmpAttr::IS_EQUAL,
            CmpKind::Ge => CmpAttr::IS_GREATER | CmpAttr::IS_EQUAL,
            CmpKind::Borrow | CmpKind::Carry => CmpAttr::IS_OVERFLOW,
            CmpKind::MaskedEq(_) => CmpAttr::IS_EQUAL | CmpAttr::IS_MASKED,
        }
    }
}

use CmpKind::*;

use crepe::crepe;

use crate::SSARewriter;

crepe! {
    @input
    struct Cond(Value);
    @input
    struct Statement(usize, Op, Value, Value, Value);

    // Basic logical operators
    struct And(Value, Value, Value);
    struct Not(Value, Value);

    And(x, a, b) <- Statement(_, and_op, x, a, b), (matches!(and_op, Op::IntAnd | Op::BoolAnd));
    And(x, a, b) <- And(x, b, a);
    Not(cond, not_cond) <- Statement(_, not_op, cond, not_cond, _), (matches!(not_op, Op::IntNot | Op::BoolNot));

    struct Alias(Value, Value);

    // There exists a value `x`, if `x` appears as the destination operand of statement.
    Alias(x, x) <- Statement(_, _, x, _, _);

    // `b` is an alias of `a` if it is the destination of a copy-like operation involving `a`.
    Alias(a, b) <- Statement(_, Op::Copy, b, a, _);
    Alias(a, b) <- Statement(_, Op::SignExtend, b, a, _);
    Alias(a, b) <- Statement(_, Op::ZeroExtend, b, a, _);
    Alias(a, b) <- And(b, a, mask), (is_all_ones(mask));

    // Assume that two loads from the same memory address alias.
    Alias(a, b) <- Statement(i, Op::Load(0), a, addr, _), Statement(j, Op::Load(0), b, addr, _), (j < i);

    // `b` is an alias of `a` if `x` is an alias of `a` and `b` is an alias of `x`.
    Alias(a, b) <- Alias(a, x), Alias(x, b);

    // Allow partially masked values to be treated as alias to the full size values.
    struct TruncatedAlias(Value, Value);

    TruncatedAlias(a, b) <- Alias(a, b);
    TruncatedAlias(a, b) <- And(b, a, mask), (is_const_mask_for_size(mask));

    // Identity operations for booleans
    struct BoolAlias(Value, Value);

    BoolAlias(a, b) <- Alias(a, b);
    // `(a << n) >> n == n`
    BoolAlias(a, b) <- Statement(_, Op::IntRight, b, x, n), Statement(_, Op::IntLeft, x, a, n);
    // `!!a == a`
    BoolAlias(a, b) <- Not(a, x), Not(x, b);

    struct Cmp(usize, CmpKind, Value, Value, Value);

    // Direct comparisons:
    Cmp(offset, Eq, cond, a, b)     <- Statement(offset, Op::IntEqual, cond, a, b);
    Cmp(offset, Ne, cond, a, b)     <- Statement(offset, Op::IntNotEqual, cond, a, b);
    Cmp(offset, Lt, cond, a, b)     <- Statement(offset, Op::IntLess, cond, a, b);
    Cmp(offset, Le, cond, a, b)     <- Statement(offset, Op::IntLessEqual, cond, a, b);
    Cmp(offset, Slt, cond, a, b)    <- Statement(offset, Op::IntSignedLess, cond, a, b);
    Cmp(offset, Borrow, cond, a, b) <- Statement(offset, Op::IntSignedBorrow, cond, a, b);
    Cmp(offset, Carry, cond, a, b)  <- Statement(offset, Op::IntSignedCarry, cond, a, b);

    // Allow substitution of signed comparisons with unsigned comparisons
    Cmp(offset, Lt, cond, a, b) <- Cmp(offset, Slt, cond, a, b);

    // Comparing `a` and `b` is the same as comparing their aliases.
    Cmp(offset, op, cond, a, b) <- Alias(a_, a), Cmp(offset, op, cond, a_, b);
    Cmp(offset, op, cond, a, b) <- Alias(b_, b), Cmp(offset, op, cond, a, b_);

    // (a == b) <=> (b == a)
    Cmp(offset, Eq, cond, a, b) <- Cmp(offset, Eq, cond, b, a);
    // (a != b) <=> (b != a)
    Cmp(offset, Ne, cond, a, b) <- Cmp(offset, Ne, cond, b, a);

    // Allow comparisons to comparisons to be calculated using subtraction.
    // `a [op] b` => `(a - b) [op] 0`
    Cmp(offset, op, cond, a, b) <-
        Statement(offset, Op::IntSub, tmp, a, b),
        TruncatedAlias(tmp, result),
        Cmp(_, op, cond, result, x), (x.const_eq(0));
    // `a [op] b` => `(a + (-b)) [op] 0`
    Cmp(offset, op, cond, a, (Value::Const(0_u64.wrapping_sub(b), size))) <-
        Statement(offset, Op::IntAdd, tmp, a, b), let Value::Const(b, size) = b,
        TruncatedAlias(tmp, result),
        Cmp(_, op, cond, result, x), (x.const_eq(0));

    // Allow propagation of booleans through zero and one
    // `x = a [op] b; c = (x == 1) ==> c = a [op] b`
    Cmp(offset, op, cond, a, b) <-
        Cmp(_, Eq, cond, tmp, const_one), (const_one.const_eq(1)),
        TruncatedAlias(tmp, result),
        Cmp(offset, op, result, a, b);
    // `x = a [op] b; c = (x == 0) ==> c = a [inv(op)] b`
    Cmp(offset, op.inv(), cond, a, b) <-
        Cmp(_, Eq, cond, tmp, const_one), (const_one.const_eq(0)),
        TruncatedAlias(tmp, result),
        Cmp(offset, op, result, a, b);

    // Define unsigned comparison operations in terms of signed comparisons and borrows.
    Cmp(offset, Lt, cond, a, b) <-
        Cmp(_, Ne, cond, borrow, signed_lt),
        Cmp(_, Borrow, borrow, a, b),
        Cmp(offset, Slt, signed_lt, a, b);
    Cmp(offset, Ge, cond, a, b) <-
        Cmp(_, Eq, cond, borrow, signed_lt),
        Cmp(_, Borrow, borrow, a, b),
        Cmp(offset, Slt, signed_lt, a, b);

    // `a >= b AND a != b` => `a > b`
    Cmp(offset, Gt, cond, a, b) <-
        And(cond, not_eq, is_ge),
        Cmp(_, Ne, not_eq, a, b),
        Cmp(offset, Ge, is_ge, a, b);

    // Handle masked equality: `c == a & b`
    Cmp(offset, MaskedEq(c), cond, a, b) <- Statement(_, Op::IntAnd, x, a, b), Cmp(offset, Eq, cond, x, c);
    Cmp(offset, MaskedEq(c), cond, a, b) <- Statement(_, Op::IntAnd, x, a, b), Cmp(offset, Eq, cond, c, x);

    // Allow comparisons to be defined in terms of their inverse
    struct Inv(CmpKind, CmpKind);

    Inv(a, b) <- Inv(b, a);
    Inv(Eq, Ne);
    Inv(Le, Gt);
    Inv(Lt, Ge);

    struct InvCmp(usize, CmpKind, Value, Value, Value);

    InvCmp(offset, op, cond, a, b) <- Not(cond, not_cond), Cmp(offset, op, not_cond, a, b);
    InvCmp(offset, op, cond, a, b) <- Inv(op, inv_op), Cmp(offset, inv_op, cond, a, b);
    Cmp(offset, op, cond, a, b)    <- Inv(op, inv_op), InvCmp(offset, inv_op, cond, a, b);

    struct Mul(usize, Value, Value, Value);

    Mul(offset, result, y, x) <- Statement(offset, Op::IntMul, result, y, x);
    Mul(offset, result, x, y) <- Mul(offset, result, y, x) ;

    struct Cmov(usize, CmpKind, Value, Value, Value);

    // cond = (a == b)
    // mask = cond * 0xffff_ffff
    // z = (x & mask) | (y & !mask)
    Cmov(offset, op, result, a, b) <-
        Cmp(offset, op, cond, a, b), Mul(_, result, cond, mask), (is_all_ones(mask));

    // cond = zext(a == b)
    // z = x*cond | y*!cond
    Cmov(offset, op, result, a, b) <-
        Cmp(offset, op, cond, a, b), BoolAlias(cond, x), Mul(_, result, _, x);

    @output
    struct Output(usize, CmpKind, Value, Value);

    // Output all comparisons that flow into the branch condition.
    Output(offset, op, a, b) <- Cmp(offset, op, cond, a, b), BoolAlias(cond, x), Cond(x);

    // Output all conditional moves that flow into the destination value.
    Output(offset, op, a, b) <-
        Cmov(offset, op, result, a, b),
        TruncatedAlias(result, x),
        Cond(x),
        (!(a.const_eq(0) || b.const_eq(0)));
}

/// A comparison between two operands might be defined in terms of multiple subcomparisons. This is
/// common on architectures that implement comparisons using status flags. For example,
/// `a <= 0` can be implemented as `SF == 1 || ZR == 0`.
///
/// The datalog based comparison finder will output both the individual comparisons and the merged
/// comparisons. This function defines a ranking that prefers merged comparisons which we use to
/// filter the output of the datalog finder.
fn comparison_rank(Output(offset, _, a, b): &Output) -> impl Ord {
    let value_ordering = |value: &Value| -> i16 {
        match value {
            // Prefer comparisons with operands that have smaller IDs to prefer comparisons to the
            // original value to comparisons with aliases.
            Value::Var(x) => x.id,
            // Always prefer comparisons involving constants to those that involve values.
            Value::Const(_, _) => i16::MIN,
        }
    };

    let a = value_ordering(a);
    let b = value_ordering(b);
    (*offset, a.min(b), a.max(b))
}

fn datalog_find_comparisons(prop: &mut CmpProp) -> bool {
    let mut runtime = Crepe::new();

    let mut rw = SSARewriter::new();
    for (i, stmt) in prop.block.instructions[..prop.offset].iter().enumerate() {
        let [a, b] = stmt.inputs.get();
        let a = rw.get_input(a);
        let b = rw.get_input(b);
        let output = rw.set_output(i, stmt.output);
        runtime.extend(&[Statement(i, stmt.op, output.into(), a, b)]);

        tracing::trace!(
            "[{i}] {}",
            pcode::Instruction::from((output, stmt.op, (a, b))).display(&())
        );
    }

    let cond = rw.get_input(prop.dst.into());
    tracing::trace!("finding flow to {}", cond.display(&()));

    runtime.extend(&[Cond(cond)]);

    let (output,): (HashSet<Output>,) = runtime.run();

    if let Some(Output(offset, kind, a_, b_)) = output.into_iter().min_by_key(comparison_rank) {
        let (_, a) = rw.get_original(a_);
        let (_, b) = rw.get_original(b_);

        // Flip the operands to match the original instruction.
        let (kind, a, b) = match kind.flip_operands() {
            Some(flipped)
                if b == prop.block.instructions[offset].inputs.first()
                    || a == prop.block.instructions[offset].inputs.second() =>
            {
                (flipped, b, a)
            }
            _ => (kind, a, b),
        };

        match kind {
            MaskedEq(c) => {
                let (_, c) = rw.get_original(c);
                // Apply a heuristic to order comparisons based on the observation that the mask is
                // typically loaded after the value.
                match (a, b) {
                    (Value::Var(a), Value::Var(b)) => {
                        let (a, b) = if a.id < b.id { (a, b) } else { (b, a) };
                        prop.out.push(CmpOp { kind: kind.into(), arg1: c, arg2: a.into(), offset });
                        prop.out.push(CmpOp { kind: kind.into(), arg1: c, arg2: b.into(), offset });
                    }
                    (Value::Var(x), _) | (_, Value::Var(x)) => {
                        prop.out.push(CmpOp { kind: kind.into(), arg1: c, arg2: x.into(), offset })
                    }
                    _ => {}
                }
            }
            _ => prop.out.push(CmpOp { kind: kind.into(), arg1: a, arg2: b, offset }),
        }

        return true;
    }

    false
}

#[cfg(test)]
mod test {
    use icicle_vm::cpu::lifter::{Context, Settings};
    use pcode::PcodeDisplay;

    use crate::instrumentation::cmp_finder::USE_DATALOG;

    fn mipsel_ops(input: &[u8]) -> String {
        ops("mipsel-linux", input)
    }

    fn x86_ops(input: &[u8]) -> String {
        ops("x86_64-linux", input)
    }

    fn msp430x_ops(input: &[u8]) -> String {
        ops("msp430-none", input)
    }

    fn thumb_ops(input: &[u8]) -> String {
        ops("thumbv7m-none", input)
    }

    fn ops(arch_name: &str, input: &[u8]) -> String {
        use std::fmt::Write;

        let target: target_lexicon::Triple = arch_name.parse().unwrap();
        let (sleigh, context) = icicle_vm::build_sleigh_for(target.architecture).unwrap();

        let mut lifter = icicle_vm::cpu::lifter::InstructionLifter::new();
        lifter.set_context(context);
        let mut block_lifter =
            icicle_vm::cpu::lifter::BlockLifter::new(Settings::default(), lifter);

        let mut source = icicle_vm::cpu::utils::BasicInstructionSource::new(sleigh);
        source.set_inst(0x0, input);

        let mut code = icicle_vm::cpu::BlockTable::default();
        let group =
            block_lifter.lift_block(&mut Context::new(&mut source, &mut code, 0x0)).unwrap();
        let block = &code.blocks[group.blocks.0];
        eprintln!("{}", block.pcode.display(&source.arch.sleigh));
        eprintln!("{}", block.exit.display(&source.arch.sleigh));

        if let Some((dst, _)) = crate::instrumentation::cmp_finder::find_cmov(block) {
            eprintln!("finding flow to: {}", dst.display(&source.arch.sleigh))
        }

        let mut finder = super::CmpFinder::new();
        let out = finder.find_cmp(block);

        let mut display = String::new();

        for entry in out {
            writeln!(display, "{}", entry.display(&source.arch.sleigh)).unwrap();
        }

        display
    }

    fn test_generic(cond: pcode::VarNode, block: pcode::Block) -> String {
        use super::{datalog_find_comparisons, CmpProp};
        use std::fmt::Write;

        let sleigh = sleigh_runtime::SleighData::default();

        eprintln!("finding flow to: {}", cond.display(&sleigh));
        let mut out = vec![];
        datalog_find_comparisons(&mut CmpProp {
            inverted: false,
            cmp_zero: None,
            dst: cond,
            block: &block,
            offset: block.instructions.len(),
            out: &mut out,
            bit: 0,
            find_adds: false,
        });

        let mut display = String::new();
        for entry in out {
            writeln!(display, "{}", entry.display(&sleigh)).unwrap();
        }
        display
    }

    #[test]
    fn with_copy() {
        let mut block = pcode::Block::new();

        let x = block.alloc_tmp(4);
        let y = block.alloc_tmp(4);

        let tmp = block.alloc_tmp(1);
        let cond = block.alloc_tmp(1);

        block.push((tmp, pcode::Op::IntEqual, (x, y)));
        block.push((cond, pcode::Op::Copy, tmp));

        assert_eq!(
            test_generic(cond, block),
            "CmpOp { kind: CmpAttr(IS_EQUAL), arg1: $U1:4, arg2: $U2:4, offset: 0 }\n"
        );
    }

    #[test]
    fn with_mask() {
        let mut block = pcode::Block::new();

        let x = block.alloc_tmp(4);
        let y = block.alloc_tmp(4);
        let z = block.alloc_tmp(4);

        let tmp = block.alloc_tmp(4);
        let cond = block.alloc_tmp(1);

        block.push((z, pcode::Op::IntSub, (x, y)));
        block.push((tmp, pcode::Op::IntAnd, (z, 0xffff_ffff_u32)));
        block.push((cond, pcode::Op::IntEqual, (tmp, 0_u32)));

        assert_eq!(
            test_generic(cond, block),
            "CmpOp { kind: CmpAttr(IS_EQUAL), arg1: $U1:4, arg2: $U2:4, offset: 0 }\n"
        );
    }

    #[test]
    fn with_const() {
        let mut block = pcode::Block::new();

        let x = block.alloc_tmp(4);
        let cond = block.alloc_tmp(1);
        block.push((cond, pcode::Op::IntEqual, (x, 0xaa_u32)));

        assert_eq!(
            test_generic(cond, block),
            "CmpOp { kind: CmpAttr(IS_EQUAL), arg1: $U1:4, arg2: 0xaa:4, offset: 0 }\n"
        );
    }

    #[test]
    fn cmov_with_mul() {
        let mut block = pcode::Block::new();

        let x = block.alloc_tmp(4);
        let y = block.alloc_tmp(4);

        let tmp = block.alloc_tmp(4);
        let cond = block.alloc_tmp(1);

        block.push((cond, pcode::Op::IntEqual, (x, y)));
        block.select(tmp, cond, 0x1_u32, 0x2_u32);

        assert_eq!(
            test_generic(cond, block),
            "CmpOp { kind: CmpAttr(IS_EQUAL), arg1: $U1:4, arg2: $U2:4, offset: 0 }\n"
        );
    }

    #[test]
    fn x86_cmp_jz_const() {
        let input = [
            0x3d, 0x4f, 0x75, 0x61, 0x6c, // CMP EAX,0x6c61754f
            0x74, 0x18, // JZ RIP+0x18
        ];
        assert_eq!(
            x86_ops(&input),
            "CmpOp { kind: CmpAttr(IS_EQUAL), arg1: EAX, arg2: 0x6c61754f:4, offset: 3 }\n"
        );
    }

    #[test]
    fn x86_cmp_jz() {
        let input = [
            0x39, 0xd8, // CMP EAX,EBX
            0x74, 0x18, // JZ RIP+0x18
        ];
        assert_eq!(
            x86_ops(&input),
            "CmpOp { kind: CmpAttr(IS_EQUAL), arg1: EAX, arg2: EBX, offset: 3 }\n"
        );
    }

    #[test]
    fn x86_cmp_with_mem() {
        // We don't directly support comparisons with memory, however the analysis should be able to
        // find a temporary with the loaded value.
        let input = [
            0x81, 0x3b, 0x77, 0x7a, 0x66, 0x63, // CMP dword ptr [RBX], 0x63667a77
            0x75, 0x18, // JNZ RIP+0x18
        ];
        if USE_DATALOG {
            assert_eq!(
                x86_ops(&input),
                "CmpOp { kind: CmpAttr(NOT_EQUAL), arg1: $U5:4, arg2: 0x63667a77:4, offset: 6 }\n"
            );
        }
        else {
            assert_eq!(
                x86_ops(&input),
                "CmpOp { kind: CmpAttr(NOT_EQUAL), arg1: $U7:4, arg2: 0x63667a77:4, offset: 6 }\n"
            );
        }
    }

    #[test]
    fn x86_cmp_jl_const() {
        let input = [
            0x3d, 0x4f, 0x75, 0x61, 0x6c, // CMP EAX,0x6c61754f
            0x0f, 0x8c, 0x00, 0x00, 0x00, 0x00, // JL +0x0
        ];

        let result = x86_ops(&input);
        if USE_DATALOG {
            assert_eq!(
                result,
                "CmpOp { kind: CmpAttr(IS_LESSER), arg1: EAX, arg2: 0x6c61754f:4, offset: 3 }\n"
            )
        }
        else {
            // The the manual is unable to merge the constraints properly.
        }
    }

    #[test]
    fn x86_cmp_jg_const() {
        let input = [
            0x3d, 0x4f, 0x75, 0x61, 0x6c, // CMP EAX,0x6c61754f
            0x0f, 0x8f, 0x00, 0x00, 0x00, 0x00, // JG +0x0
        ];

        let result = x86_ops(&input);
        if USE_DATALOG {
            assert_eq!(
                result,
                "CmpOp { kind: CmpAttr(IS_GREATER), arg1: EAX, arg2: 0x6c61754f:4, offset: 3 }\n"
            )
        }
        else {
            // @fixme: The datalog implementation can merge these constraints, but the manual
            // approach currently doesn't do any merging.
            assert_eq!(
                result,
                "CmpOp { kind: CmpAttr(IS_OVERFLOW), arg1: EAX, arg2: 0x6c61754f:4, offset: 2 }\n\
            CmpOp { kind: CmpAttr(NOT_EQUAL), arg1: EAX, arg2: 0x6c61754f:4, offset: 3 }\n\
            CmpOp { kind: CmpAttr(IS_LESSER), arg1: EAX, arg2: 0x6c61754f:4, offset: 3 }\n"
            )
        }
    }

    #[test]
    fn x86_sub() {
        // Sub operation can be used in place of a comparison
        let input = [
            0x29, 0xd8, // SUB EAX,EBX
            0x75, 0x18, // JNZ RIP+0x18
        ];
        assert_eq!(
            x86_ops(&input),
            "CmpOp { kind: CmpAttr(NOT_EQUAL), arg1: EAX, arg2: EBX, offset: 3 }\n"
        );
    }

    #[test]
    fn x86_cmov_const() {
        let input = [
            0x3d, 0x4f, 0x75, 0x61, 0x6c, // CMP EAX,0x6c61754f
            0x41, 0x0f, 0x44, 0xd4, // CMOVZ EDX,R12D
        ];
        assert_eq!(
            x86_ops(&input),
            "CmpOp { kind: CmpAttr(NOT_EQUAL), arg1: EAX, arg2: 0x6c61754f:4, offset: 3 }\n"
        );
    }

    #[test]
    fn x86_cmov() {
        let input = [
            0x39, 0xd8, // CMP EAX,EBX
            0x41, 0x0f, 0x44, 0xd4, // CMOVZ EDX,R12D
        ];
        assert_eq!(
            x86_ops(&input),
            "CmpOp { kind: CmpAttr(NOT_EQUAL), arg1: EAX, arg2: EBX, offset: 3 }\n"
        );
    }

    #[test]
    fn x86_imul() {
        // Check that we generate instrumentation when a multiply depends on a comparison.
        let input = [
            0x3d, 0x6c, 0x61, 0x74, 0xa3, // CMP EAX,0xa374616c
            0x0f, 0x94, 0xc2, // SETZ DL
            0x48, 0x0f, 0xb6, 0xd2, // MOVZX RDX,DL
            0x41, 0x0f, 0xaf, 0xd4, // IMUL EDX,R12D
            0xff, 0x25, 0x00, 0x00, 0x00, 0x00, // JMP [RIP + 0x0]
        ];
        assert_eq!(
            x86_ops(&input),
            "CmpOp { kind: CmpAttr(IS_EQUAL), arg1: EAX, arg2: 0xa374616c:4, offset: 3 }\n"
        );

        // But avoid adding instrumentation if the multiply doesn't depend on a comparison.
        let input = [
            0x3d, 0x6c, 0x61, 0x74, 0xa3, // CMP EAX,0xa374616c
            0x41, 0x0f, 0xaf, 0xd4, // IMUL EDX,R12D
            0xff, 0x25, 0x00, 0x00, 0x00, 0x00, // JMP [RIP + 0x0]
        ];
        assert_eq!(x86_ops(&input), "");
    }

    #[test]
    fn x86_with_extra_instructions() {
        let input = [
            0x41, 0x39, 0xec, // CMP  R12D,EBP
            0x4c, 0x8d, 0x6e, 0x01, 0x44, 0x88, 0x26, // ...
            0x0f, 0x84, 0xfd, 0x01, 0x00, 0x00, // JZ   [RIP + 0x20d],
        ];
        assert_eq!(
            x86_ops(&input),
            "CmpOp { kind: CmpAttr(IS_EQUAL), arg1: R12D, arg2: EBP, offset: 3 }\n"
        );
    }

    #[test]
    fn x86_after_zxt() {
        // Check that correct sizes are set when zero extension occurs.
        let input = [
            0x8b, 0x04, 0x25, 0x00, 0x00, 0x00, 0x00, // MOV EAX,dword ptr [0x0]
            0x48, 0x3d, 0xff, 0xff, 0xff, 0x0f, // CMP RAX,0xfffffff
            0x74, 0x18, // JZ RIP+0x18
        ];
        assert_eq!(
            x86_ops(&input),
            "CmpOp { kind: CmpAttr(IS_EQUAL), arg1: EAX, arg2: 0xfffffff:4, offset: 6 }\n"
        );
    }

    #[test]
    fn x86_after_sxt() {
        // Check that correct sizes are set when zero extension occurs.
        let input = [
            0x48, 0x63, 0xc2, // MOVSXD RAX,EDX
            0x48, 0x3d, 0xff, 0xff, 0xff, 0x0f, // CMP RAX,-0x1
            0x74, 0x18, // JZ RIP+0x18
        ];
        assert_eq!(
            x86_ops(&input),
            "CmpOp { kind: CmpAttr(IS_EQUAL), arg1: EAX, arg2: 0xfffffff:4, offset: 5 }\n"
        );
    }

    #[test]
    fn mipsel_bne_const() {
        let input = [
            0x66, 0x63, 0x01, 0x3c, // lui  at,0x6366
            0x77, 0x7a, 0x21, 0x34, // ori  at,at,0x7a77
            0x04, 0x00, 0x41, 0x14, // bne  v0,at,0x0
            0x00, 0x00, 0x00, 0x00, // (delay slot)
        ];
        assert_eq!(
            mipsel_ops(&input),
            "CmpOp { kind: CmpAttr(NOT_EQUAL), arg1: v0, arg2: 0x63667a77:4, offset: 5 }\n"
        );
    }

    #[test]
    fn mipsel_mul_const() {
        let input = [
            0x66, 0x63, 0x01, 0x3c, // lui  at,0x6366
            0x77, 0x7a, 0x21, 0x34, // ori  at,at,0x7a77
            0x2a, 0x18, 0x41, 0x00, // slt  v1,v0,at
            0x02, 0x10, 0x23, 0x70, // mul  v0,at,v1
            0x08, 0x00, 0x00, 0x00, // j    0x0
        ];
        assert_eq!(
            mipsel_ops(&input),
            "CmpOp { kind: CmpAttr(IS_LESSER), arg1: v0, arg2: 0x63667a77:4, offset: 5 }\n"
        );
    }

    #[test]
    fn msp430x_cmp_jeq() {
        let input = [
            0x3f, 0x90, 0x16, 0x00, // CMP.W #0x16,R15
            0x3f, 0x24, // JEQ 0x86
        ];
        assert_eq!(
            msp430x_ops(&input),
            "CmpOp { kind: CmpAttr(IS_EQUAL), arg1: R15_16, arg2: 0x16:2, offset: 10 }\n"
        );
    }

    #[test]
    fn msp430x_sub_jeq() {
        let input = [
            0x3c, 0x80, 0x80, 0x00, // SUB.W #0x80,R12
            0x3f, 0x24, // JEQ 0x86
        ];
        assert_eq!(
            msp430x_ops(&input),
            "CmpOp { kind: CmpAttr(IS_EQUAL), arg1: R12_16, arg2: 0x80:2, offset: 10 }\n"
        );
    }

    #[test]
    fn msp430x_cmp_jge() {
        let input = [
            0x3f, 0x90, 0x16, 0x00, // CMP.W #0x16,R15
            0x07, 0x34, // JGE
        ];
        if USE_DATALOG {
            assert_eq!(
                msp430x_ops(&input),
                "CmpOp { kind: CmpAttr(IS_EQUAL | IS_GREATER), arg1: R15_16, arg2: 0x16:2, offset: 10 }\n"
            );
        }
        else {
            assert_eq!(
                msp430x_ops(&input),
                "CmpOp { kind: CmpAttr(IS_OVERFLOW), arg1: R15_16, arg2: 0x16:2, offset: 5 }\n\
                CmpOp { kind: CmpAttr(IS_LESSER), arg1: R15_16, arg2: 0x16:2, offset: 10 }\n"
            );
        }
    }

    #[test]
    fn msp430x_cmp_mem_jge() {
        let input = [
            0x82, 0x9c, 0x16, 0x1f, // CMP.W R12,&1f16
            0x07, 0x34, // JGE
        ];
        if USE_DATALOG {
            assert_eq!(
                msp430x_ops(&input),
                "CmpOp { kind: CmpAttr(IS_EQUAL | IS_GREATER), arg1: $U14:2, arg2: R12_16, offset: 13 }\n"
            );
        }
        else {
            assert_eq!(
                msp430x_ops(&input),
                "CmpOp { kind: CmpAttr(IS_OVERFLOW), arg1: $U15:2, arg2: R12_16, offset: 7 }\n\
                CmpOp { kind: CmpAttr(IS_LESSER), arg1: $U16:2, arg2: R12_16, offset: 13 }\n"
            );
        }
    }

    #[test]
    fn msp430x_cmp_jne() {
        let input = [
            0x3f, 0x90, 0x16, 0x00, // CMP.W #0x16,R15
            0x09, 0x20, // JNE
        ];
        assert_eq!(
            msp430x_ops(&input),
            "CmpOp { kind: CmpAttr(NOT_EQUAL), arg1: R15_16, arg2: 0x16:2, offset: 10 }\n"
        );
    }

    #[test]
    fn msp430x_cmp_jl() {
        let input = [
            0x0d, 0x9a, // CMP.W R10,R13
            0xf7, 0x34, // JL
        ];
        if USE_DATALOG {
            assert_eq!(
                msp430x_ops(&input),
                "CmpOp { kind: CmpAttr(IS_EQUAL | IS_GREATER), arg1: R13_16, arg2: R10_16, offset: 10 }\n"
            );
        }
        else {
            assert_eq!(
                msp430x_ops(&input),
                "CmpOp { kind: CmpAttr(IS_OVERFLOW), arg1: R13_16, arg2: R10_16, offset: 5 }\n\
                CmpOp { kind: CmpAttr(IS_LESSER), arg1: R13_16, arg2: R10_16, offset: 10 }\n"
            );
        }
    }

    #[test]
    #[ignore = "We currently hide comparisons with zero"]
    fn msp430x_cmp_zero_jl() {
        let input = [
            0x4d, 0x43, // MOV.B #0,R13
            0x0d, 0x9a, // CMP.W R10,R13
            0xf7, 0x34, // JL
        ];
        assert_eq!(
            msp430x_ops(&input),
            "CmpOp { kind: CmpAttr(IS_EQUAL | IS_GREATER), arg1: 0x0:2, arg2: R10_16, offset: 10 }\n"
        );
    }

    #[test]
    fn msp430x_cmpb_jeq() {
        let input = [
            0x7c, 0x90, 0x80, 0xff, // CMP.B #0x8,R12
            0x3f, 0x24, // JEQ 0x86
        ];
        assert_eq!(
            msp430x_ops(&input),
            "CmpOp { kind: CmpAttr(IS_EQUAL), arg1: R12_lo, arg2: 0x80:1, offset: 10 }\n"
        );
    }

    #[test]
    fn msp430x_cmpa_jeq() {
        let input = [
            0xd3, 0x05, // CMPA R5,R3
            0x3f, 0x24, // JEQ 0x86
        ];
        assert_eq!(
            msp430x_ops(&input),
            "CmpOp { kind: CmpAttr(IS_EQUAL), arg1: R3, arg2: R5, offset: 1 }\n"
        );
    }

    #[test]
    fn msp430x_cmpb_mem_jeq() {
        let input = [
            0xd2, 0x93, 0x11, 0x02, // CMP.B #0x1,&0x0211
            0x3f, 0x24, // JEQ 0x86
        ];
        if USE_DATALOG {
            assert_eq!(
                msp430x_ops(&input),
                "CmpOp { kind: CmpAttr(IS_EQUAL), arg1: $U14:1, arg2: 0x1:1, offset: 13 }\n"
            );
        }
        else {
            assert_eq!(
                msp430x_ops(&input),
                "CmpOp { kind: CmpAttr(IS_EQUAL), arg1: $U16:1, arg2: 0x1:1, offset: 13 }\n"
            );
        }
    }

    #[test]
    fn msp430x_bit_eq() {
        let input = [
            0x1c, 0xb3, // BIT #1, R12
            0x3f, 0x24, // JEQ
        ];
        // Avoid generating instrumentation when we are only comparing a small number of bits.
        assert_eq!(msp430x_ops(&input), "");
    }

    #[test]
    #[ignore = "We currently hide comparisons with zero"]
    fn msp430x_cmp_zero() {
        let input = [
            0x0f, 0x93, // TST.W R15
            0x3f, 0x24, // JEQ
        ];
        assert_eq!(
            msp430x_ops(&input),
            "CmpOp { kind: CmpAttr(IS_EQUAL), arg1: R15_16, arg2: 0x0:2, offset: 9 }\n"
        );
    }

    #[test]
    fn msp430x_unknown_mul() {
        let input = [
            0xcd, 0x4c, 0x18, 0x1f, // MOV.B R12,0x1f18(R13)
            0x1d, 0x53, // INC.W R13
            0x3f, 0x3c, // JMP
        ];
        assert_eq!(msp430x_ops(&input), "");
    }

    #[test]
    fn thumb_cmp_bge() {
        let input = [
            0xbc, 0x42, // cmp r4, r7
            0x4e, 0xda, // bge
        ];
        assert_eq!(
            thumb_ops(&input),
            "CmpOp { kind: CmpAttr(IS_EQUAL | IS_GREATER), arg1: r4, arg2: r7, offset: 3 }\n"
        );
    }

    #[test]
    fn thumb_and_cmp_beq() {
        let input = [
            0x0b, 0x40, // ands r3, r1
            0x9a, 0x42, // cmp r2,r3
            0x2c, 0xd0, // beq
        ];
        assert_eq!(
            thumb_ops(&input),
            "CmpOp { kind: CmpAttr(IS_EQUAL | IS_MASKED), arg1: r2, arg2: r1, offset: 9 }\n\
            CmpOp { kind: CmpAttr(IS_EQUAL | IS_MASKED), arg1: r2, arg2: r3, offset: 9 }\n"
        );

        let input = [
            0x03, 0xf0, 0x3f, 0x03, // and     r3,r3,#0x3f
            0xb4, 0xf8, 0x62, 0x20, // ldrh.w  r2,[r4,#0x62]
            0x93, 0x42, // cmp r3,r2
            0x09, 0xd0, // beq
        ];
        assert_eq!(
            thumb_ops(&input),
            "CmpOp { kind: CmpAttr(IS_EQUAL | IS_MASKED), arg1: r2:2, arg2: r3:2, offset: 12 }\n"
        );
    }

    #[test]
    fn thumb_and_cmp_bne() {
        let input = [
            0x79, 0x29, // cmp r1,0x79
            0x2e, 0xd1, // bne
        ];
        assert_eq!(
            thumb_ops(&input),
            "CmpOp { kind: CmpAttr(NOT_EQUAL), arg1: r1, arg2: 0x79:4, offset: 3 }\n"
        );
    }
}
