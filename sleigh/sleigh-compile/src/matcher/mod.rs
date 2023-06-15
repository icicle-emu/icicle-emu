mod cases;

use sleigh_runtime::matcher::{
    Constraint, ConstraintCmp, ConstraintOperand, MatchCase, SequentialMatcher,
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
    let (mut cases, token_size) = cases::collect_constraints(table, symbols)?;
    //debug_cases("before.md", symbols, table, &cases);
    sort_overlaps(symbols, ctx, &mut cases, token_size as u8);
    //debug_cases("after.md", symbols, table, &cases);
    Ok(SequentialMatcher { cases, token_size })
}

/// Constructors are allowed to have overlapping constraints where the constructor with highest
/// number of constrained bits is matched first. Here we take care of sorting the match cases so
/// that to ensure the most constrained constructors are matched first.
fn sort_overlaps(_symbols: &SymbolTable, _ctx: &Context, cases: &mut [MatchCase], _token_size: u8) {
    if cases.len() < 2 {
        //nothing to order
        return;
    }
    let mut head = 0usize;
    // pseudo index double linked list, obs never empty
    let mut order_list: Vec<Option<usize>> = Vec::with_capacity(cases.len());
    order_list.push(None);

    // insert sort all the cases in the "linked-list"
    for add in cases.iter().skip(1) {
        // find it's position on the list
        let mut current = Some(head);
        let mut prev = None;
        let pos = loop {
            let Some(i) = current else {
                break None;
            };
            match compare_number_of_constrained_bits(add, &cases[i]) {
                MatcherOrdering::Equal(_) => {}
                // @todo check if a solver pattern is available
                MatcherOrdering::Conflict(true) => {}
                MatcherOrdering::Conflict(false) => {}
                MatcherOrdering::Contained(_) => {}
                MatcherOrdering::Contain(false) => {}
                // add is contained in case, including the value
                MatcherOrdering::Contain(true) => break Some(i),
            }
            prev = Some(i);
            current = order_list[i];
        };
        let next_pos = order_list.len();
        if let Some(pos) = pos {
            // found a position, add the element before it
            if let Some(prev) = prev {
                order_list[prev] = Some(next_pos);
            } else {
                head = next_pos;
            }
            order_list.push(Some(pos));
        } else {
            // just add at the end of the list
            // prev will always be the last element
            let tail = prev.unwrap();
            order_list[tail] = Some(next_pos);
            order_list.push(None);
        }
    }

    // assigned ranks based on the linked list position
    let mut next = Some(head);
    let mut counter = 0;
    while let Some(i) = next {
        cases[i].rank = counter;
        counter += 1;
        next = order_list[i];
    }

    // Sort cases according to their ranking.
    cases.sort_unstable_by_key(|x| x.rank);
}

/// The specification requires that the most constrained constructors should be matched first so we
/// check here the ordering.
fn compare_number_of_constrained_bits(a: &MatchCase, b: &MatchCase) -> MatcherOrdering {
    let (a_value, a_mask) = pattern_mask(a);
    let (b_value, b_mask) = pattern_mask(b);
    compare_bits_set(a_value, a_mask, b_value, b_mask)
}

/// Returns a mask for token and context fields representing the bits with constraints.
fn pattern_mask(case: &MatchCase) -> (u128, u128) {
    let mut token_mask = case.token.mask;
    let mut context_mask = case.context.mask;
    let mut token_value = case.token.bits;
    let mut context_value = case.context.bits;

    // Add bits constrained by complex constraints to each mask.
    for constraint in &case.constraints {
        match constraint {
            Constraint::Token {
                field,
                cmp: ConstraintCmp::Equal,
                operand: ConstraintOperand::Constant(value),
                ..
            } => {
                token_mask |= field.mask();
                field.set(&mut token_value, *value);
            }
            Constraint::Context {
                field,
                cmp: ConstraintCmp::Equal,
                operand: ConstraintOperand::Constant(value),
                ..
            } => {
                context_mask |= field.mask();
                field.set(&mut context_value, *value);
            }
            _ => {}
        }
    }
    let mask = (token_mask as u128) << u64::BITS | context_mask as u128;
    let value = (token_value as u128) << u64::BITS | context_value as u128;
    (value, mask)
}

pub(crate) enum MatcherOrdering {
    // Restrict diferent bits, bool if the intersection, if any, have the same value.
    Conflict(bool),
    // Equal mask, bool if have the same value.
    Equal(bool),
    // Contains, bool if is a specialization.
    Contain(bool),
    // Contained, bool if is a specialization.
    Contained(bool),
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
fn compare_bits_set(value_a: u128, mask_a: u128, value_b: u128, mask_b: u128) -> MatcherOrdering {
    let extra_a = mask_a & (!mask_b) != 0;
    let extra_b = mask_b & (!mask_a) != 0;
    match (extra_a, extra_b) {
        // Same mask
        (false, false) => MatcherOrdering::Equal(value_a == value_b),
        // Intersection,
        (true, true) => MatcherOrdering::Conflict(value_a & mask_b == value_b & mask_a),
        (true, false) => MatcherOrdering::Contain(value_a & mask_b == value_b),
        (false, true) => MatcherOrdering::Contained(value_b & mask_a == value_a),
    }
}

#[allow(unused)]
fn bit_to_string(value: u64, mask: u64) -> String {
    (0..64)
        .into_iter()
        .map(|bit| match (mask >> bit & 1 != 0, value >> bit & 1 != 0) {
            (true, true) => '1',
            (true, false) => '0',
            (false, true) => unreachable!(),
            (false, false) => '_',
        })
        .collect()
}

#[allow(unused)]
fn debug_cases(file: &str, symbols: &SymbolTable, table: &Table, cases: &[MatchCase]) {
    use std::io::Write;

    let mut out = std::fs::File::options().append(true).create(true).open(file).unwrap();

    let table_name = symbols.parser.get_ident_str(table.name);
    let _ = writeln!(out, "{table_name}:");
    let _ = writeln!(out, "| id | src | context | token |");
    let _ = writeln!(out, "|----|-----|---------|-------|");

    for case in cases {
        let _ = writeln!(
            out,
            "| {} | {} | {} | {} |",
            case.constructor,
            symbols.format_constructor_line(case.constructor),
            bit_to_string(case.context.bits, case.context.mask),
            bit_to_string(case.token.bits, case.token.mask),
        );
    }
    let _ = out.write_all(b"\n");
}

#[test]
fn test_compare_bits_set() {
    let a = 0b01111;
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

    let asr = 0x8030_ffef;
    let orr = 0x8000_ffe0;
    assert_eq!(compare_bits_set(asr, orr), Some(std::cmp::Ordering::Greater));
}

#[test]
fn compare_pattern() {
    use cases::BitMatcher;

    let ands = MatchCase {
        context: BitMatcher::from_str("_______________________________1").pattern(),
        token: BitMatcher::from_str("_______________________001001111").pattern(),
        constraints: vec![],
        constructor: 0,
        rank: 0,
    };
    let tst = MatchCase {
        context: BitMatcher::from_str("_______________________________1").pattern(),
        token: BitMatcher::from_str("11111__________________001001111").pattern(),
        constraints: vec![],
        constructor: 0,
        rank: 0,
    };
    assert_eq!(compare_number_of_constrained_bits(&tst, &ands), Some(std::cmp::Ordering::Greater));

    // Tokens constrains should _NOT_ be checked before context constraints.
    //
    // (previously we assumed that this was the case because of ordering cycles in the x86
    // specification. However, these were addressed by only considering overlaps for the shared part
    // of each token -- see test below.)
    let a = MatchCase {
        context: BitMatcher::from_str("___").pattern(),
        token: BitMatcher::from_str("_110").pattern(),
        constraints: vec![],
        constructor: 0,
        rank: 0,
    };
    let b = MatchCase {
        context: BitMatcher::from_str("__1").pattern(),
        token: BitMatcher::from_str("__10").pattern(),
        constraints: vec![],
        constructor: 0,
        rank: 0,
    };
    assert_eq!(compare_number_of_constrained_bits(&a, &b), None);
}
