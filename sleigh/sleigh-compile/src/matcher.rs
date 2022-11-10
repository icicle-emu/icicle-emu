use std::cmp::Ordering;

use sleigh_parse::ast::{self, ParserDisplay};
use sleigh_runtime::{
    matcher::{Constraint, ConstraintOperand, MatchCase, SequentialMatcher},
    ConstructorId,
};

use crate::{
    symbols::{SymbolTable, Table},
    Context,
};

pub(crate) fn build_sequential_matcher(
    symbols: &SymbolTable,
    table: &Table,
    ctx: &Context,
) -> Result<SequentialMatcher, String> {
    let mut max_token_bytes = 0;
    let mut cases = vec![];
    for &id in &table.constructors {
        let constructor = &symbols.constructors[id as usize];

        let mut has_valid_constraint = false;
        let mut constraint_err = None;
        for entry in &constructor.constraints {
            let (case, required_bytes) = match build_case_matcher(id, entry, ctx.data.big_endian) {
                Ok(entry) => entry,
                Err(err) => {
                    // Skip this constraint if it is impossible to satisfy.
                    //
                    // This is neccessary to support the $(THCC) constraint in
                    // `ARMTHUMBInstructions.sinc`
                    constraint_err = Some(err);
                    continue;
                }
            };
            max_token_bytes = max_token_bytes.max(required_bytes);
            cases.push(case);
            has_valid_constraint = true;
        }

        if !has_valid_constraint {
            if let Some(err) = constraint_err {
                // All constraints for this constructor were invalid making it impossible to match.
                return Err(format!(
                    "No valid constraints for {} constructor {}: {}",
                    table.name.display(&symbols.parser),
                    symbols.format_span(&constructor.span),
                    err,
                ));
            }
        }
    }

    // Ensure that cases are sorted in the correct order for matching.
    cases.sort_by(|a, b| order_case(a, b).reverse());
    Ok(SequentialMatcher { cases, token_size: max_token_bytes as usize })
}

fn build_case_matcher(
    constructor: ConstructorId,
    constraint_list: &[Constraint],
    is_be: bool,
) -> Result<(MatchCase, u8), String> {
    let mut tokens = BitMatcher::default();
    let mut context = BitMatcher::default();
    let mut complex = vec![];
    for constraint in constraint_list {
        let context_token = sleigh_runtime::Token::new(8);
        match constraint {
            Constraint::Context { field, cmp, operand } => match (cmp, &operand) {
                (ast::ConstraintCmp::Equal, &ConstraintOperand::Constant(value)) => {
                    context.add_constraint(context_token, *field, *value as u64, false)?;
                }
                _ => complex.push(*constraint),
            },
            Constraint::Token { token, field, cmp, operand } => match (cmp, operand) {
                (ast::ConstraintCmp::Equal, &ConstraintOperand::Constant(value)) => {
                    tokens.add_constraint(*token, *field, value as u64, is_be)?;
                }
                _ => complex.push(*constraint),
            },
        }
    }

    let token_bytes = tokens.bits.len() as u8 / 8;
    if token_bytes > 8 {
        return Err(format!("Constraint requires matching {} bytes", token_bytes));
    }

    let case = MatchCase {
        constructor,
        context: context.pattern(),
        token: tokens.pattern(),
        constraints: complex,
    };
    Ok((case, token_bytes))
}

/// The specification requires that the most constrained constructors should be matched first
/// so sort them here.
///
/// (actual specification seems to be slightly more subtle, but I haven't been able to find
/// any concrete case where this doesn't work).
fn order_case(a: &MatchCase, b: &MatchCase) -> Ordering {
    match compare_bits_set(a.token.mask, b.token.mask) {
        Some(Ordering::Equal) | None => {}
        Some(x) => return x,
    }

    match a.constraints.len().cmp(&b.constraints.len()) {
        Ordering::Equal => {}
        x => return x,
    }

    match compare_bits_set(a.context.mask, b.context.mask) {
        Some(Ordering::Equal) | None => {}
        Some(x) => return x,
    }

    // @fixme: this attempts to avoid breaking sorting when there are cases that cannot be compared.
    a.token.mask.count_ones().cmp(&b.token.mask.count_ones())
}

/// Compares the bits set in self with other.
///
/// Possible results:
///
/// - [Some(Ordering::Equal)]: both self and other set the same bits.
/// - [Some(Ordering::Less)]: every bit in self is set in other, but other contains bits not set in
///   self.
/// - [Some(Ordering::Greater)]: every bit in other is set in self, but self contains bits not set
///   in other.
/// - [None]: both self and other contains bits not set by the other.
fn compare_bits_set(a: u64, b: u64) -> Option<Ordering> {
    let extra_a = a & (!b) != 0;
    let extra_b = b & (!a) != 0;
    match (extra_a, extra_b) {
        (true, true) => None,
        (false, false) => Some(Ordering::Equal),
        (true, false) => Some(Ordering::Greater),
        (false, true) => Some(Ordering::Less),
    }
}

#[derive(Clone, Default)]
struct BitMatcher {
    bits: BitVec,
    mask: BitVec,
}

impl BitMatcher {
    fn add_constraint(
        &mut self,
        token: sleigh_runtime::Token,
        field: sleigh_runtime::Field,
        value: u64,
        is_be: bool,
    ) -> Result<(), String> {
        let token_offset = token.offset as usize * 8;
        let token_bits = (token.size * 8) as usize;
        self.grow(token_offset + token_bits);

        // When matching constraints, we always read token bits as LE-encoded bytes as this greatly
        // simplifies what happens when we have overlapping token types. This means we need to swap
        // the bytes in the value and mask before we build the final pattern.
        //
        // @fixme: Ghidra is more restrictive when checking overlapping tokens.
        let mut mask = pcode::mask(field.num_bits as u64) << field.offset;
        let mut shifted = value << field.offset;

        if is_be {
            mask = byteswap_value(mask, token_bits as u64);
            shifted = byteswap_value(shifted, token_bits as u64);
        }

        let new_mask = BitVec::from_u64(mask, token_bits).shift_start(token_offset);
        let bits = BitVec::from_u64(shifted, token_bits).shift_start(token_offset);

        // Check whether the new constraint is incompatible with an existing constraint
        let in_both = new_mask.and(&self.mask);
        if bits.and(&in_both) != self.bits.and(&in_both) {
            let mut isolated = BitMatcher::default();
            isolated.add_constraint(token, field, value, is_be).unwrap();
            return Err(format!(
                "merging ({:?}):\n\tcurrent: {:?}\n\t    new: {:?}",
                field, self, isolated
            ));
        }

        self.bits = self.bits.or(&bits);
        self.mask = self.mask.or(&new_mask);

        Ok(())
    }

    fn grow(&mut self, new_len: usize) {
        self.bits.grow(new_len, false);
        self.mask.grow(new_len, false);
    }

    fn pattern(&self) -> sleigh_runtime::matcher::Pattern {
        sleigh_runtime::matcher::Pattern {
            bits: self.bits.value as u64,
            mask: self.mask.value as u64,
        }
    }

    #[cfg(test)]
    fn from_str(value: &str) -> Self {
        let mut bits = BitVec::default();
        let mut mask = BitVec::default();
        for x in value.chars() {
            let (value_bit, mask_bit) = match x {
                '0' => (false, true),
                '1' => (true, true),
                '_' => (false, false),
                _ => panic!("Invalid char: {}", x),
            };
            bits.push_bit(value_bit);
            mask.push_bit(mask_bit);
        }
        Self { bits, mask }
    }
}

fn byteswap_value(value: u64, bits: u64) -> u64 {
    assert!(bits % 8 == 0 && bits <= 64);
    let mut bytes = value.to_le_bytes();
    bytes[0..(bits / 8) as usize].reverse();
    u64::from_le_bytes(bytes)
}

impl std::fmt::Debug for BitMatcher {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("\"")?;
        for (bit, mask) in self.bits.bit_iter().zip(self.mask.bit_iter()) {
            let value = match (mask, bit) {
                (true, true) => "1",
                (true, false) => "0",
                (false, _) => "_",
            };
            f.write_str(value)?;
        }
        f.write_str("\"")?;
        Ok(())
    }
}

#[derive(Default, Clone, PartialOrd, Ord, Hash, PartialEq, Eq)]
pub(crate) struct BitVec {
    pub value: u128,
    len: u8,
}

impl BitVec {
    #[cfg(test)]
    pub fn from_str(value: &str) -> Self {
        let mut bit_vec = Self::default();
        for x in value.chars() {
            match x {
                '0' => bit_vec.push_bit(false),
                '1' => bit_vec.push_bit(true),
                _ => panic!("Invalid char: {}", x),
            }
        }
        bit_vec
    }

    /// Creates a new bit vector from a u64 value
    pub fn from_u64(value: u64, len: usize) -> Self {
        let mut bit_vec = Self::default();
        for &byte in &value.to_le_bytes() {
            let mut byte = byte;
            for _ in 0..8 {
                if bit_vec.len as usize >= len {
                    break;
                }
                bit_vec.push_bit(byte & 1 == 1);
                byte >>= 1;
            }
        }
        bit_vec.grow(len, false);
        bit_vec
    }

    /// Returns an iterator over each bit in the bit vector.
    fn bit_iter(&self) -> impl Iterator<Item = bool> {
        let value = self.value;
        (0..self.len).map(move |i| (value >> i) & 1 == 1)
    }

    /// Returns the number of bits in this bit vector.
    pub fn len(&self) -> usize {
        self.len as usize
    }

    pub fn push_bit(&mut self, bit: bool) {
        if self.len == 128 {
            panic!("insufficient capacity");
        }
        if bit {
            self.value |= 1 << self.len
        }
        self.len += 1;
    }

    /// Shifts the bit vector by inserting `shift` false values at the start of the vector
    pub fn shift_start(self, shift: usize) -> Self {
        std::iter::repeat(false).take(shift).chain(self.bit_iter()).collect()
    }

    /// Grow the bit vector to contain at least `len` bits, initializing new bits with `value`. Does
    /// nothing if `len` is less than the current length (never truncates).
    fn grow(&mut self, len: usize, value: bool) {
        while self.len() < len {
            self.push_bit(value);
        }
    }

    /// Counts the number of `true` bits in the bit vector.
    fn count_ones(&self) -> usize {
        self.value.count_ones() as usize
    }

    #[allow(unused)]
    pub fn select(&self, mask: &Self) -> Self {
        let mut base: BitVec = self
            .bit_iter()
            .zip(mask.bit_iter())
            .filter(|(_, mask)| *mask)
            .map(|(bit, _)| bit)
            .collect();
        base.grow(mask.count_ones(), false);
        base
    }

    /// Performs a bit-wise `not` operation (invert).
    #[allow(unused)]
    fn not(&self) -> Self {
        self.bit_iter().map(|x| !x).collect()
    }

    /// Perform an `and` operation with another BitVec.
    ///
    /// If the inputs are of different length, the result will be resized with `false` to the size
    /// of the largest input.
    fn and(&self, other: &Self) -> Self {
        let len = self.len().max(other.len()) as u8;
        Self { value: self.value & other.value, len }
    }

    /// Performs a bit-wise 'or' operation between two inputs, if the inputs are of different
    /// length, then the result will be the length of the largest input.
    fn or(&self, other: &Self) -> Self {
        let len = self.len().max(other.len()) as u8;
        Self { value: self.value | other.value, len }
    }
}

impl<const N: usize> From<[bool; N]> for BitVec {
    fn from(bits: [bool; N]) -> Self {
        bits.into_iter().collect()
    }
}

impl std::iter::FromIterator<bool> for BitVec {
    fn from_iter<T: IntoIterator<Item = bool>>(iter: T) -> Self {
        let mut value = Self::default();
        iter.into_iter().for_each(|bit| value.push_bit(bit));
        value
    }
}

impl std::fmt::Debug for BitVec {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("\"")?;
        for bit in self.bit_iter() {
            f.write_str(if bit { "1" } else { "0" })?;
        }
        f.write_str("\"")?;
        Ok(())
    }
}

#[test]
fn bit_vec() {
    let a = BitVec::from([true, true, true, true]);
    let b = BitVec::from([true, true, true, true, true]);
    assert_eq!(a.select(&b), BitVec::from([true, true, true, true, false]));

    assert_eq!(a.count_ones(), 4);
    assert_eq!(b.count_ones(), 5);

    let a = BitVec::from([true, true, false, true]);
    let b = BitVec::from([false, false, true, true, false]);
    assert_eq!(a.select(&b), BitVec::from([false, true]));

    let a = BitVec::from([true, true, true, true]);
    let b = BitVec::from([true, true, true]);
    assert_eq!(a.and(&b), BitVec::from([true, true, true, false]));
    assert_eq!(a.or(&b), BitVec::from([true, true, true, true]));
}

#[test]
fn test_compare_bits_set() {
    let a = 0b1111;
    let b = 0b11111;
    assert_eq!(compare_bits_set(a, a), Some(std::cmp::Ordering::Equal));
    assert_eq!(compare_bits_set(a, b), Some(std::cmp::Ordering::Less));
    assert_eq!(compare_bits_set(b, a), Some(std::cmp::Ordering::Greater));

    let c = 0b10000;
    assert_eq!(compare_bits_set(c, a), None);
    assert_eq!(compare_bits_set(c, b), Some(std::cmp::Ordering::Less));

    let ands = 0b11111111100000000000000000000000;
    let tst = 0b11111111100000000000000000011111;

    assert_eq!(compare_bits_set(ands, tst), Some(std::cmp::Ordering::Less));
    assert_eq!(compare_bits_set(tst, ands), Some(std::cmp::Ordering::Greater));
}

#[test]
fn compare_pattern() {
    let ands = MatchCase {
        context: BitMatcher::from_str("_______________________________1").pattern(),
        token: BitMatcher::from_str("_______________________001001111").pattern(),
        constraints: vec![],
        constructor: 0,
    };
    let tst = MatchCase {
        context: BitMatcher::from_str("_______________________________1").pattern(),
        token: BitMatcher::from_str("11111__________________001001111").pattern(),
        constraints: vec![],
        constructor: 0,
    };
    assert_eq!(order_case(&tst, &ands), std::cmp::Ordering::Greater);

    // Tokens constrains should be checked before context constraints
    let a = MatchCase {
        context: BitMatcher::from_str("___").pattern(),
        token: BitMatcher::from_str("_110").pattern(),
        constraints: vec![],
        constructor: 0,
    };
    let b = MatchCase {
        context: BitMatcher::from_str("__1").pattern(),
        token: BitMatcher::from_str("__10").pattern(),
        constraints: vec![],
        constructor: 0,
    };
    assert_eq!(order_case(&a, &b), std::cmp::Ordering::Greater);
}
