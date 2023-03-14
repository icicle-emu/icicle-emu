//! A bit-level constant evaluator for pcode.

use std::{cell::Cell, collections::HashMap, convert::TryInto};

const DEBUG: bool = false;

pub type OutputExprId = u32;

#[derive(Clone)]
pub struct ConstEval {
    /// The value written to the output in each expression.
    pub values: Vec<(pcode::VarNode, Value)>,

    /// Keeps track of the index in `values` for each input register.
    inputs: HashMap<i16, usize>,

    /// Keeps track which values are already stored in VarNodes.
    results: HashMap<Value, pcode::VarNode>,

    /// Keeps track of whether any error has been encountered while performing const propagation.
    error: Cell<bool>,
}

impl ConstEval {
    pub fn new() -> Self {
        Self {
            inputs: HashMap::new(),
            values: vec![],
            results: HashMap::new(),
            error: Cell::new(false),
        }
    }

    pub fn eval(&mut self, stmt: pcode::Instruction) -> Result<OutputExprId, ()> {
        let a = self.get_value(stmt.inputs.first());
        let b = self.get_value(stmt.inputs.second());

        // Reserve slot for the output of the current operation.
        let id = self.values.len().try_into().unwrap();
        self.values.push((pcode::VarNode::NONE, Value::empty()));

        let mut out = self.get_value_mut(stmt.output);

        if DEBUG {
            eprintln!("[{id}] {stmt:?}");
        }

        eval(stmt.op, &a, &b, &mut out);

        if DEBUG && !out.is_empty() {
            eprintln!("a = {} {:?}", a, a);
            if !b.is_empty() {
                eprintln!("b = {} {:?}", b, b);
            }
            eprintln!("x = {} {:?}", out.display(), out.display());
        }

        // Keep track of the unknown bits that are modified as part of this expression.
        for (i, bit) in out.iter_mut().enumerate() {
            if matches!(bit, Bit::Unknown) {
                *bit = Bit::Expr(Expr { id, offset: i as u8, invert: false })
            }
        }

        let value = Value::from_bits(out);
        if self.matches_existing(&value).is_none() {
            self.results.insert(value.clone(), stmt.output);
        }
        self.values[id as usize] = (stmt.output, value);

        if self.error.take() {
            return Err(());
        }
        Ok(id)
    }

    fn add_input_var(&mut self, var: pcode::VarNode) -> usize {
        if var == pcode::VarNode::NONE {
            return 0;
        }

        let id = self.values.len().try_into().unwrap();
        *self.inputs.entry(var.id).or_insert_with(|| {
            self.values.push((pcode::VarNode::new(var.id, MAX_BYTES as u8), Value::new(id)));
            self.results.insert(Value::new(id).slice_to(var.offset * 8, var.size * 8), var);
            id as usize
        })
    }

    fn get_value_mut(&mut self, var: pcode::VarNode) -> &mut [Bit] {
        if var == pcode::VarNode::NONE {
            return &mut [];
        }
        let idx = match self.inputs.get(&var.id) {
            Some(idx) => *idx,
            None => self.add_input_var(var),
        };
        self.values[idx].1.slice_mut(var.offset * 8, var.size * 8)
    }

    pub fn get_value(&mut self, var: pcode::Value) -> Value {
        match var {
            pcode::Value::Var(pcode::VarNode::NONE) => Value::empty(),
            pcode::Value::Var(var) => {
                let id = match self.inputs.get(&var.id) {
                    Some(id) => *id,
                    None => self.add_input_var(var),
                };
                let value = self.values[id].1.clone();
                value.slice_to(var.offset * 8, var.size * 8)
            }
            pcode::Value::Const(value, size) => Value::from_const(value).slice_to(0, size * 8),
        }
    }

    /// Get the statement index associated with an expression ID.
    pub fn get_stmt_index(&self, id: OutputExprId) -> Option<u32> {
        let start: u32 = self.values.len().try_into().unwrap();
        id.checked_sub(start)
    }

    /// Get the value of the output at a particular expression ID.
    pub fn get_value_at_expr_id(&self, id: OutputExprId) -> Value {
        self.values[id as usize].1.clone()
    }

    /// Get the VarNode associated with the output at a particular expression ID.
    pub fn get_output_of(&self, id: OutputExprId) -> pcode::VarNode {
        self.values[id as usize].0
    }

    pub fn get_const(&mut self, var: pcode::Value) -> Option<u64> {
        self.get_value(var.into()).get_const()
    }

    pub fn set_const(&mut self, var: pcode::VarNode, value: u64) {
        self.get_value_mut(var).set_const(value)
    }

    pub fn matches_existing(&mut self, bits: &[Bit]) -> Option<pcode::VarNode> {
        // Check if there is an exact match for these bits already stored in an earlier varnode.
        // (This aids later dead-code elimination.)
        if let Some(&var) = self.results.get(&Value::from_bits(bits)) {
            if &*self.get_value(var.into()) == bits {
                return Some(var);
            }
        }
        None
    }

    pub fn clear(&mut self) {
        self.values.clear();
        self.inputs.clear();
        self.results.clear();

        if DEBUG {
            eprintln!();
        }
    }
}

const MAX_BITS: usize = 128;
const MAX_BYTES: usize = 128 / 8;

#[derive(Clone, Eq)]
pub struct Value {
    offset: u8,
    len: u8,
    bits: [Bit; MAX_BITS],
}

impl PartialEq for Value {
    fn eq(&self, other: &Self) -> bool {
        let bits: &[Bit] = &*self;
        bits.eq(&**other)
    }
}

impl std::hash::Hash for Value {
    fn hash<H: std::hash::Hasher>(&self, state: &mut H) {
        let bits: &[Bit] = &*self;
        bits.hash(state);
    }
}

impl std::ops::Deref for Value {
    type Target = [Bit];

    fn deref(&self) -> &Self::Target {
        &self.bits[self.offset as usize..][..self.len as usize]
    }
}

impl std::ops::DerefMut for Value {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.bits[self.offset as usize..][..self.len as usize]
    }
}

impl std::fmt::Debug for Value {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        debug_bits(&*self, f)
    }
}

impl std::fmt::Display for Value {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        display_bits(&*self, f)
    }
}

impl Value {
    fn new(id: u32) -> Self {
        let mut out = Self::unknown();
        out.bits[..].fill_expr(id);
        out
    }

    fn unknown() -> Self {
        Self { offset: 0, len: MAX_BITS as u8, bits: [Bit::Unknown; 128] }
    }

    fn zero() -> Self {
        Self { offset: 0, len: MAX_BITS as u8, bits: [Bit::Zero; 128] }
    }

    fn empty() -> Self {
        Self { offset: 0, len: 0, bits: [Bit::Zero; 128] }
    }

    fn from_bits(input: &[Bit]) -> Self {
        let mut bits = Self::zero();
        for (input, output) in input.iter().zip(&mut bits.bits) {
            *output = *input;
        }
        bits.len = input.len() as u8;
        bits
    }

    fn from_const(value: u64) -> Self {
        let mut tmp = Self::zero().slice_to(0, 64);
        tmp.as_mut().set_const(value);
        tmp
    }

    fn slice_to(mut self, offset: u8, len: u8) -> Self {
        self.offset = offset;
        self.len = len;
        self
    }

    fn slice_mut(&mut self, offset: u8, len: u8) -> &mut [Bit] {
        &mut self.bits[offset as usize..][..len as usize]
    }
}

pub trait BitVecExt {
    fn slice(&self) -> &[Bit];
    fn slice_mut(&mut self) -> &mut [Bit];

    fn fill_expr(&mut self, id: u32) {
        self.slice_mut().iter_mut().enumerate().for_each(|(offset, bit)| {
            *bit = Bit::Expr(Expr { id, offset: offset as u8, invert: false })
        });
    }

    /// Copy the bits from `other` into `self`.
    fn copy(&mut self, other: &[Bit]) {
        self.slice_mut().copy_from_slice(other);
    }

    /// Checks whether the current expression is a simple copy of an existing expression.
    // @fixme: This doesn't handle constant bits that were copied.
    fn is_simple_copy(&self) -> bool {
        let mut id = None;
        for (i, bit) in self.slice().iter().enumerate() {
            match bit {
                Bit::Expr(expr)
                    if (id == None || id == Some(expr.id)) && i == expr.offset as usize =>
                {
                    id = Some(expr.id);
                }
                _ => return false,
            }
        }

        true
    }

    /// Returns the low bit of of the BitVec, if all high bits are zero.
    fn as_bool(&self) -> Option<Bit> {
        if self.slice().iter().skip(1).all(|x| *x == Bit::Zero) {
            return Some(self.slice()[0]);
        }
        None
    }

    /// Copy and zero extend `other` to `self`
    ///
    /// # Panics
    ///
    /// Panics if `other.len() > self.len()`.
    fn zero_extend(&mut self, other: &[Bit]) {
        let (low, high) = self.slice_mut().split_at_mut(other.len());
        low.copy(other);
        high.fill(Bit::Zero);
    }

    /// Counts the number of leading bits that are const equal to zero.
    fn known_leading_zeros(&self) -> usize {
        self.slice().iter().rev().take_while(|x| **x == Bit::Zero).count()
    }

    /// Counts the number of leading bits that are either zero or equal to the sign bit
    fn num_extended_bits(&self) -> usize {
        let first = self.slice().last().unwrap_or(&Bit::Unknown);
        let sign_bits =
            self.slice().iter().rev().take_while(|x| *x == first).count().saturating_sub(1);
        sign_bits.max(self.known_leading_zeros())
    }

    /// Counts the number of non-constant bits.
    fn non_constant_bits(&self) -> usize {
        self.slice().iter().filter(|x| x.const_value().is_none()).count()
    }

    /// Copy `other` to `self` zero extending or truncating as necessary.
    fn copy_any(&mut self, other: &[Bit]) {
        if self.slice().len() > other.len() {
            self.zero_extend(other);
        }
        else {
            self.copy(&other[..self.slice().len() as usize]);
        }
    }

    /// Return the sign bit of `self`
    fn sign(&self) -> Bit {
        *self.slice().last().unwrap()
    }

    /// Counts the number of bits that are set to 1, returning None if there are any unknown bits.
    fn count_ones(&self) -> Option<u32> {
        let mut count = 0;
        for bit in self.slice() {
            count += bit.const_value()? as u32;
        }
        Some(count)
    }

    /// Set the bit vector to be equal to `value`.
    fn set_const(&mut self, mut value: u64) {
        for bit in self.slice_mut().iter_mut() {
            *bit = if value & 1 == 1 { Bit::One } else { Bit::Zero };
            value >>= 1;
        }
    }

    /// Returns the value of the bits as a number, if the underlying bits are not entierly constant
    /// this returns [None].
    fn get_const(&self) -> Option<u64> {
        if self.slice().len() > 64 {
            return None;
        }

        let mut output = 0;
        for bit in self.slice().iter().rev() {
            output = (output << 1) | bit.const_value()?;
        }
        Some(output)
    }

    /// Returns the minimum value the bit vector can take (i.e. assuming all unknown bits are zero)
    fn min(&self) -> u64 {
        let mut output = 0;
        for bit in self.slice().iter().rev() {
            output = (output << 1) | if matches!(bit, Bit::One) { 1 } else { 0 };
        }
        output
    }

    /// Returns the maximum value the bit vector can take (i.e. assuming all unknown bits are zero)
    fn max(&self) -> u64 {
        let mut output = 0;
        for bit in self.slice().iter().rev() {
            output = (output << 1) | if matches!(bit, Bit::Zero) { 0 } else { 1 };
        }
        output
    }

    /// Converts the value to a boolean, zeroing the upper bits and returning a mutable reference to
    /// the boolean bit.
    fn bool_mut(&mut self) -> &mut Bit {
        let (bit, high) = self.slice_mut().split_first_mut().unwrap();
        high.fill(Bit::Zero);
        bit
    }

    /// Perform a bitwise operation between the current bit-vector an another bit-vector.
    fn bitwise_op(&mut self, other: &[Bit], func: impl Fn(Bit, Bit) -> Bit) {
        self.slice_mut().iter_mut().zip(other).for_each(|(a, b)| *a = func(*a, *b));
    }

    /// Perform a bitwise NOT operation on the current bit-vector.
    fn not(&mut self) {
        for bit in self.slice_mut().iter_mut() {
            *bit = bit.not();
        }
    }

    /// Perform a bitwise AND operation with `other`.
    fn and(&mut self, other: &[Bit]) {
        self.bitwise_op(other, Bit::and);
    }

    /// Perform a bitwise OR operation with `other`.
    fn or(&mut self, other: &[Bit]) {
        self.bitwise_op(other, Bit::or);
    }

    /// Perform a bitwise XOR operation with `other`.
    fn xor(&mut self, other: &[Bit]) {
        self.bitwise_op(other, Bit::xor);
    }

    /// Perform an ADD operation with `other`.
    fn add(&mut self, other: &[Bit]) -> Bit {
        let mut carry = Bit::Zero;

        for (a, b) in self.slice_mut().iter_mut().zip(other) {
            // a + b
            let half = a.xor(*b);
            let half_carry = a.and(*b);

            // (a + b) + carry
            let value = half.xor(carry);
            let full_carry = half.and(carry);

            *a = value;
            carry = half_carry.or(full_carry);
        }

        carry
    }

    /// Perform a SUB operation with `other`.
    fn sub(&mut self, other: &[Bit]) -> Bit {
        let mut borrow = Bit::Zero;

        for (a, b) in self.slice_mut().iter_mut().zip(other) {
            let half = a.xor(*b);
            let borrow_half = a.not().and(*b);

            let difference = half.xor(borrow);
            let borrow_diff = half.not().and(borrow);

            *a = difference;
            borrow = borrow_half.or(borrow_diff);
        }

        borrow
    }

    /// Shift the bit-vector left by the bits in `shift`.
    fn shift_left(&mut self, shift: &[Bit]) {
        // Note: The sleigh specification defines overflowing shifts to saturate -- this differs
        // from most typical architectures which perform wrapping shifts.
        if shift.min() as usize >= self.slice().len() {
            self.slice_mut().fill(Bit::Zero);
            return;
        }

        match shift.get_const() {
            Some(shift) => {
                let tmp = Value::from_bits(self.slice());
                let (value, _) = tmp.split_at(tmp.len() - shift as usize);
                let (low, high) = self.slice_mut().split_at_mut(shift as usize);
                low.fill(Bit::Zero);
                high.copy(value);
            }
            None => {
                self.slice_mut().fill(Bit::Unknown);
                let (low, _) = self.slice_mut().split_at_mut(shift.min() as usize);
                low.fill(Bit::Zero)
            }
        }
    }

    /// Rotate the bit-vector left by the bits in `shift`.
    fn rotate_left(&mut self, shift: &[Bit]) {
        match shift.get_const() {
            Some(shift) => self.slice_mut().rotate_left(shift as usize),
            None => self.slice_mut().fill(Bit::Unknown),
        }
    }

    /// Shift the bit-vector right by the bits in `shift`.
    fn shift_right(&mut self, shift: &[Bit]) {
        // Overflowing shifts must saturate.
        if shift.min() as usize >= self.slice().len() {
            self.slice_mut().fill(Bit::Zero);
            return;
        }

        match shift.get_const() {
            Some(shift) => {
                let tmp = Value::from_bits(self.slice());
                let (_, value) = tmp.split_at(shift as usize);
                let (low, high) = self.slice_mut().split_at_mut(value.len());
                low.copy(value);
                high.fill(Bit::Zero);
            }
            None => {
                self.slice_mut().fill(Bit::Unknown);
                let high_bits = self.slice().len() - shift.min() as usize;
                let (_, high) = self.slice_mut().split_at_mut(high_bits);
                high.fill(Bit::Zero)
            }
        }
    }

    /// Shift the bit-vector right arithmetically by the bits in `shift`.
    fn shift_right_signed(&mut self, value: &[Bit], shift: &[Bit]) {
        // Overflowing shifts must saturate.
        if shift.min() as usize >= self.slice().len() {
            self.slice_mut().fill(value.sign());
            return;
        }

        match shift.get_const() {
            Some(shift) => {
                // @fixme: handle case where shift is larger than size of value.
                let tmp = Value::from_bits(value).slice_to(0, self.slice().len() as u8);
                let (_, value) = tmp.split_at(shift as usize);
                let (low, high) = self.slice_mut().split_at_mut(value.len());
                low.copy(value);
                high.fill(value.sign());
            }
            None => {
                self.slice_mut().fill(Bit::Unknown);
                let high_bits = self.slice().len() - shift.min() as usize;
                let (_, high) = self.slice_mut().split_at_mut(high_bits);
                high.fill(value.sign())
            }
        }
    }

    /// Rotate the bit-vector right by the bits in `shift`.
    fn rotate_right(&mut self, shift: &[Bit]) {
        match shift.get_const() {
            Some(shift) => self.slice_mut().rotate_right(shift as usize),
            None => self.slice_mut().fill(Bit::Unknown),
        }
    }

    /// Compute the addition of two values, returning the result and the overflow bit.
    fn add_overflow(&self, other: &[Bit]) -> (Value, Bit) {
        let mut result = Value::from_bits(self.slice());
        result.add(other);

        let a = self.sign();
        let b = other.sign();
        let c = result.sign();
        let overflow = ((a.or(b).not()).and(c)).or(a.and(b).and(c.not()));

        (result, overflow)
    }

    /// Compute the subtraction of two values, returning the result and the overflow bit.
    fn sub_overflow(&self, other: &[Bit]) -> (Value, Bit) {
        let mut result = Value::from_bits(self.slice());
        result.sub(other);

        let overflow = self.sign().xor(other.sign()).and(result.sign().xor(self.sign()));

        (result, overflow)
    }

    fn is_eq(&self, other: &[Bit]) -> Bit {
        let mut unknown_count = 0;
        let mut cmp_bit = Bit::One;

        for (a, b) in self.slice().iter().zip(other) {
            match a.is_eq(*b) {
                Bit::Zero => return Bit::Zero,
                Bit::One => {}
                x => {
                    cmp_bit = x;
                    unknown_count += 1
                }
            }
        }

        match unknown_count <= 1 {
            true => cmp_bit,
            false => Bit::Unknown,
        }
    }

    fn display(&self) -> BitVecDisplay {
        BitVecDisplay(self.slice())
    }
}

pub struct BitVecDisplay<'a>(&'a [Bit]);

impl<'a> std::fmt::Debug for BitVecDisplay<'a> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        debug_bits(self.0, f)
    }
}

impl<'a> std::fmt::Display for BitVecDisplay<'a> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        display_bits(self.0, f)
    }
}

impl BitVecExt for [Bit] {
    fn slice(&self) -> &[Bit] {
        self
    }

    fn slice_mut(&mut self) -> &mut [Bit] {
        self
    }
}

#[derive(Copy, Clone, PartialEq, Eq, Debug, Hash)]
pub struct Expr {
    pub id: u32,
    pub offset: u8,
    pub invert: bool,
}

impl Expr {
    /// Gets whether two expressions are guarenteed to be the same value.
    pub fn is_same(&self, other: Expr) -> bool {
        self == &other
    }

    /// Gets whether two expressions are guarenteed to be different values.
    pub fn is_different(&self, other: Expr) -> bool {
        self.id == other.id && self.offset == other.offset && self.invert != other.invert
    }
}

#[derive(Copy, Clone, Debug, PartialEq, Eq, Hash)]
pub enum Bit {
    /// The bit depends on the result of a previous expression.
    Expr(Expr),

    /// This bit depends on the result of the current expression.
    Unknown,

    /// The bit is equal to zero.
    Zero,

    /// The bit is equal to one.
    One,
}

impl Bit {
    pub fn const_value(&self) -> Option<u64> {
        match self {
            Self::Zero => Some(0),
            Self::One => Some(1),
            _ => None,
        }
    }

    fn xor(self, other: Bit) -> Self {
        match (self, other) {
            (Bit::Zero, x) | (x, Bit::Zero) => x,
            (Bit::One, x) | (x, Bit::One) => x.not(),
            (Bit::Expr(a), Bit::Expr(b)) if a.is_same(b) => Bit::Zero,
            (Bit::Expr(a), Bit::Expr(b)) if a.is_different(b) => Bit::One,
            _ => Bit::Unknown,
        }
    }

    fn and(self, other: Bit) -> Self {
        match (self, other) {
            (Bit::Zero, _) | (_, Bit::Zero) => Bit::Zero,
            (Bit::One, x) | (x, Bit::One) => x,
            (Bit::Expr(a), Bit::Expr(b)) if a.is_same(b) => self,
            (Bit::Expr(a), Bit::Expr(b)) if a.is_different(b) => Bit::Zero,
            _ => Bit::Unknown,
        }
    }

    fn or(self, other: Bit) -> Self {
        match (self, other) {
            (Bit::One, _) | (_, Bit::One) => Bit::One,
            (Bit::Zero, x) | (x, Bit::Zero) => x,
            (Bit::Expr(a), Bit::Expr(b)) if a.is_same(b) => self,
            (Bit::Expr(a), Bit::Expr(b)) if a.is_different(b) => Bit::One,
            _ => Bit::Unknown,
        }
    }

    fn not(self) -> Self {
        match self {
            Bit::Zero => Bit::One,
            Bit::One => Bit::Zero,
            Bit::Expr(expr) => Bit::Expr(Expr { invert: !expr.invert, ..expr }),
            Bit::Unknown => Bit::Unknown,
        }
    }

    fn is_eq(self, other: Bit) -> Self {
        match (self, other) {
            (Bit::Zero, x) | (x, Bit::Zero) => x.not(),
            (Bit::One, x) | (x, Bit::One) => x,
            (Bit::Expr(a), Bit::Expr(b)) if a.is_same(b) => Bit::One,
            (Bit::Expr(a), Bit::Expr(b)) if a.is_different(b) => Bit::Zero,
            _ => Bit::Unknown,
        }
    }
}

fn eval(op: pcode::Op, a: &[Bit], b: &[Bit], output: &mut [Bit]) {
    use pcode::Op;

    // If there is no output, we don't evaluate anything.
    if output.is_empty() {
        return;
    }

    match op {
        Op::Copy => output.copy(a),
        Op::Subpiece(offset) => {
            let (_, value) = a.split_at(offset as usize * 8);
            let subpiece_len = output.len().min(value.len());
            let (low, high) = output.split_at_mut(subpiece_len);
            low.copy(&value[..subpiece_len]);
            high.fill(Bit::Zero);
        }
        Op::ZeroExtend => output.zero_extend(a),
        Op::SignExtend => {
            let (low, high) = output.split_at_mut(a.len());
            low.copy(a);
            high.fill(a.sign());
        }

        Op::IntAdd => {
            output.copy(a);
            output.add(b);
        }
        Op::IntSub => {
            output.copy(a);
            output.sub(b);
        }
        Op::IntAnd => {
            output.copy(a);
            output.and(b);
        }
        Op::IntOr => {
            output.copy(a);
            output.or(b);
        }
        Op::IntXor => {
            output.copy(a);
            output.xor(b);
        }

        Op::IntMul => match (a.get_const(), b.get_const()) {
            (Some(a), Some(b)) => {
                let x = Value::from_const((a as u128 * b as u128) as u64)
                    .slice_to(0, output.len() as u8);
                output.copy(&x);
            }
            (Some(0), None) | (None, Some(0)) => output.fill(Bit::Zero),
            (Some(x), None) if x.count_ones() == 1 => {
                output.copy(&b);
                output.shift_left(&Value::from_const((63 - x.leading_zeros()) as u64));
            }
            (None, Some(x)) if x.count_ones() == 1 => {
                output.copy(&a);
                output.shift_left(&Value::from_const((63 - x.leading_zeros()) as u64));
            }
            _ => output.fill(Bit::Unknown),
        },

        Op::IntDiv => output.fill(Bit::Unknown),
        Op::IntSignedDiv => output.fill(Bit::Unknown),
        Op::IntRem => output.fill(Bit::Unknown),
        Op::IntSignedRem => output.fill(Bit::Unknown),

        Op::IntNot => {
            output.copy(a);
            output.not();
        }
        Op::IntNegate => {
            output.fill(Bit::Zero);
            output.sub(a);
        }
        Op::IntCountOnes => match a.count_ones() {
            Some(count) => output.set_const(count as u64),
            None => output.fill(Bit::Unknown),
        },

        Op::IntSignedLess => {
            let (result, overflow) = a.sub_overflow(b);
            *output.bool_mut() = result.sign().xor(overflow);
        }
        Op::IntSignedLessEqual => {
            let (result, overflow) = a.sub_overflow(b);
            let equal = a.is_eq(&b);
            *output.bool_mut() = result.sign().xor(overflow).or(equal);
        }
        Op::IntLess => {
            let borrow = Value::from_bits(a).sub(b);
            *output.bool_mut() = borrow;
        }
        Op::IntLessEqual => {
            let borrow = Value::from_bits(a).sub(b);
            let equal = a.is_eq(b);
            *output.bool_mut() = borrow.or(equal);
        }
        Op::IntEqual => {
            *output.bool_mut() = a.is_eq(b);
        }
        Op::IntNotEqual => {
            *output.bool_mut() = a.is_eq(b).not();
        }
        Op::IntCarry => {
            let carry = Value::from_bits(a).add(&b);
            *output.bool_mut() = carry;
        }
        Op::IntSignedCarry => {
            *output.bool_mut() = a.add_overflow(b).1;
        }
        Op::IntSignedBorrow => {
            *output.bool_mut() = a.sub_overflow(b).1;
        }

        Op::IntLeft => {
            output.copy_any(a);
            output.shift_left(b);
        }
        Op::IntRotateLeft => {
            output.copy(a);
            BitVecExt::rotate_left(output, b);
        }
        Op::IntRight => {
            output.copy_any(a);
            output.shift_right(b);
        }
        Op::IntSignedRight => {
            output.shift_right_signed(a, b);
        }
        Op::IntRotateRight => {
            output.copy(a);
            BitVecExt::rotate_right(output, b);
        }
        Op::BoolXor => *output.bool_mut() = a[0].xor(b[0]),
        Op::BoolAnd => *output.bool_mut() = a[0].and(b[0]),
        Op::BoolOr => *output.bool_mut() = a[0].or(b[0]),
        Op::BoolNot => *output.bool_mut() = a[0].not(),

        Op::FloatAdd
        | Op::FloatSub
        | Op::FloatMul
        | Op::FloatDiv
        | Op::FloatNegate
        | Op::FloatAbs
        | Op::FloatSqrt
        | Op::FloatCeil
        | Op::FloatFloor
        | Op::FloatRound
        | Op::FloatIsNan
        | Op::FloatEqual
        | Op::FloatNotEqual
        | Op::FloatLess
        | Op::FloatLessEqual
        | Op::IntToFloat
        | Op::FloatToFloat
        | Op::FloatToInt => output.fill(Bit::Unknown),

        // These expressions always result in an unknown output.
        Op::TracerLoad(_) | Op::Load(_) | Op::PcodeOp(_) | Op::Hook(_) => output.fill(Bit::Unknown),

        // These expressions do not modify the output.
        Op::TracerStore(_)
        | Op::Store(_)
        | Op::Branch(_)
        | Op::PcodeBranch(_)
        | Op::PcodeLabel(_)
        | Op::Arg(_)
        | Op::Exception
        | Op::InstructionMarker
        | Op::Invalid => {}
    }
}

fn display_bits(bits: &[Bit], f: &mut std::fmt::Formatter) -> std::fmt::Result {
    if bits.is_empty() {
        return f.write_str("<none>");
    }
    for bit in bits.iter().rev() {
        let x = match bit {
            Bit::Unknown | Bit::Expr(_) => 'x',
            Bit::Zero => '0',
            Bit::One => '1',
        };
        write!(f, "{}", x)?;
    }

    Ok(())
}

fn debug_bits(bits: &[Bit], f: &mut std::fmt::Formatter) -> std::fmt::Result {
    if bits.is_empty() {
        return f.write_str("<none>");
    }

    if let Some(x) = bits.get_const() {
        write!(f, " ({:#0x})", x)?;
    }
    else {
        write!(f, " (")?;
        for bit in bits.iter().rev() {
            match bit {
                Bit::Expr(e) => write!(f, "{}.{} ", e.id, e.offset)?,
                Bit::Zero => write!(f, "0 ")?,
                Bit::One => write!(f, "1 ")?,
                Bit::Unknown => write!(f, "? ")?,
            }
        }
        write!(f, ")")?;
    }

    Ok(())
}

#[allow(unused)]
pub fn diff_bits(old: &[Bit], new: &[Bit]) {
    for (old, new) in old.iter().zip(new).rev() {
        match new {
            _ if old == new => eprint!("."),
            Bit::Zero => eprint!("0"),
            Bit::One => eprint!("1"),
            _ => eprint!("?"),
        }
    }
}

#[cfg(test)]
mod test {
    use super::*;

    fn eval_op(op: impl Into<pcode::Op>, inputs: &[pcode::Value], output: pcode::VarNode) -> Value {
        let mut block = pcode::Block::new();
        block.push((output, op.into(), pcode::Inputs::from(inputs)));

        let mut optimizer = ConstEval::new();
        for stmt in block.instructions.iter() {
            optimizer.eval(stmt.clone()).unwrap();
        }

        optimizer.get_value(output.into())
    }

    #[test]
    fn shift_left() {
        fn do_shift(value: u16, shift: u16) -> bool {
            let shift = shift & 0xf;

            let tmp = pcode::VarNode::new(1, 2);
            let result = eval_op(pcode::Op::IntLeft, &[value.into(), shift.into()], tmp);

            result.get_const() == Some((value << shift) as u64)
        }
        assert!(do_shift(1, 0));
        assert!(do_shift(1, 1));
        assert!(do_shift(0, 1));

        quickcheck::quickcheck(do_shift as fn(u16, u16) -> bool)
    }

    #[test]
    fn shift_right() {
        fn do_shift(value: u16, shift: u16) -> bool {
            let shift = shift & 0xf;

            let tmp = pcode::VarNode::new(1, 2);
            let result = eval_op(pcode::Op::IntRight, &[value.into(), shift.into()], tmp);

            result.get_const() == Some((value >> shift) as u64)
        }
        assert!(do_shift(1, 0));
        assert!(do_shift(1, 1));
        assert!(do_shift(0, 1));

        quickcheck::quickcheck(do_shift as fn(u16, u16) -> bool)
    }

    #[test]
    fn shift_signed_right() {
        fn do_shift(value: u16, shift: u16) -> bool {
            let shift = shift & 0xf;

            let tmp = pcode::VarNode::new(1, 2);
            let result = eval_op(pcode::Op::IntSignedRight, &[value.into(), shift.into()], tmp);

            result.get_const() == Some((value as i16 >> shift) as u16 as u64)
        }
        assert!(do_shift(1, 0));
        assert!(do_shift(1, 1));
        assert!(do_shift(0, 1));

        quickcheck::quickcheck(do_shift as fn(u16, u16) -> bool)
    }

    #[test]
    fn sign_extend() {
        fn do_sxt(value: u16) -> bool {
            let tmp = pcode::VarNode::new(1, 4);
            let result = eval_op(pcode::Op::SignExtend, &[value.into()], tmp);
            result.get_const() == Some(value as i16 as i32 as u32 as u64)
        }

        assert!(do_sxt(-1_i16 as u16));
        assert!(do_sxt(1_i16 as u16));

        quickcheck::quickcheck(do_sxt as fn(u16) -> bool)
    }

    #[test]
    fn add() {
        fn do_add(a: u16, b: u16) -> bool {
            let tmp = pcode::VarNode::new(1, 2);
            let result = eval_op(pcode::Op::IntAdd, &[a.into(), b.into()], tmp);
            result.get_const() == Some(a.wrapping_add(b) as u64)
        }
        assert!(do_add(0x1234, (-0x1234_i16) as u16));

        quickcheck::quickcheck(do_add as fn(u16, u16) -> bool)
    }

    #[test]
    fn sub() {
        fn do_sub(a: u16, b: u16) -> bool {
            let tmp = pcode::VarNode::new(1, 2);
            let result = eval_op(pcode::Op::IntSub, &[a.into(), b.into()], tmp);
            result.get_const() == Some(a.wrapping_sub(b) as u64)
        }
        assert!(do_sub(0, 1));
        assert!(do_sub(0x1234, 0x1234));

        quickcheck::quickcheck(do_sub as fn(u16, u16) -> bool)
    }

    #[test]
    fn mul() {
        fn do_mul(a: u16, b: u16) -> bool {
            let tmp = pcode::VarNode::new(1, 2);
            let result = eval_op(pcode::Op::IntMul, &[a.into(), b.into()], tmp);
            result.get_const() == Some((a as u32 * b as u32) as u16 as u64)
        }

        assert!(do_mul(2, 0x8000));
        assert!(do_mul(-1_i16 as u16, -1_i16 as u16));
        quickcheck::quickcheck(do_mul as fn(u16, u16) -> bool)
    }

    #[test]
    fn less_than() {
        fn do_less_than(a: u16, b: u16) -> bool {
            let tmp = pcode::VarNode::new(1, 2);
            let result = eval_op(pcode::Op::IntLess, &[a.into(), b.into()], tmp);
            result.get_const() == Some((a < b) as u64)
        }
        quickcheck::quickcheck(do_less_than as fn(u16, u16) -> bool)
    }

    #[test]
    fn signed_less_than() {
        fn do_signed_less_than(a: u16, b: u16) -> bool {
            let tmp = pcode::VarNode::new(1, 2);
            let result = eval_op(pcode::Op::IntSignedLess, &[a.into(), b.into()], tmp);
            result.get_const() == Some(((a as i16) < (b as i16)) as u64)
        }
        assert!(do_signed_less_than(0x0, 0x1));
        assert!(do_signed_less_than(0x8000, 0x0));
        assert!(do_signed_less_than(0x8000, 0x1));
        quickcheck::quickcheck(do_signed_less_than as fn(u16, u16) -> bool)
    }

    #[test]
    fn signed_carry() {
        fn do_signed_carry(a: u16, b: u16) -> bool {
            let tmp = pcode::VarNode::new(1, 2);
            let result = eval_op(pcode::Op::IntSignedCarry, &[a.into(), b.into()], tmp);
            result.get_const() == Some((a as i16).checked_add(b as i16).is_none() as u64)
        }
        assert!(do_signed_carry(1, 1));
        assert!(do_signed_carry(1, (-1_i16) as u16));
        assert!(do_signed_carry((-1_i16) as u16, (-1_i16) as u16));
        assert!(do_signed_carry(0x7fff, 1));
        assert!(do_signed_carry(0x7fff, 0x7fff));
        quickcheck::quickcheck(do_signed_carry as fn(u16, u16) -> bool)
    }

    #[test]
    fn signed_borrow() {
        fn do_signed_borrow(a: u16, b: u16) -> bool {
            let tmp = pcode::VarNode::new(1, 2);
            let result = eval_op(pcode::Op::IntSignedBorrow, &[a.into(), b.into()], tmp);
            result.get_const() == Some((a as i16).checked_sub(b as i16).is_none() as u64)
        }
        quickcheck::quickcheck(do_signed_borrow as fn(u16, u16) -> bool)
    }

    #[test]
    fn sub_self() {
        let tmp = pcode::VarNode::new(1, 2);
        let result = eval_op(pcode::Op::IntSub, &[tmp.into(), tmp.into()], tmp);
        assert!(result.get_const() == Some(0))
    }

    #[test]
    fn borrow_self() {
        let tmp = pcode::VarNode::new(1, 2);
        let result = eval_op(pcode::Op::IntSignedBorrow, &[tmp.into(), tmp.into()], tmp);
        assert!(result.get_const() == Some(0))
    }

    #[test]
    fn carry_self() {
        let tmp = pcode::VarNode::new(1, 2);
        let result = eval_op(pcode::Op::IntCarry, &[tmp.into(), tmp.into()], tmp);

        // Carry equal to MSB
        let mut expected = Value::zero();
        expected[0] = Bit::Expr(Expr { id: 0, invert: false, offset: 15 });
        assert_eq!(result, expected.slice_to(0, 16));
    }
}
