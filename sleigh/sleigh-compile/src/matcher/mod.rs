mod cases;

use std::cmp::Ordering;

use sleigh_runtime::matcher::{Constraint, MatchCase, SequentialMatcher};

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
    sort_overlaps(symbols, ctx, &mut cases, token_size as u8);
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
    let mut tail = 0usize;
    // pseudo index double linked list
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
            if compare_number_of_constrained_bits(add, &cases[i]) == Some(Ordering::Greater) {
                break Some(i);
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
            order_list[tail] = Some(next_pos);
            tail = next_pos;
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
fn compare_number_of_constrained_bits(a: &MatchCase, b: &MatchCase) -> Option<Ordering> {
    let (a_token, a_context) = pattern_mask(a);
    let (b_token, b_context) = pattern_mask(b);
    match (compare_bits_set(a_token, b_token), compare_bits_set(a_context, b_context)) {
        // context or tokens contains bits not set by the other
        (None, _) | (_, None) => None,
        // context/tokens contains bits not set by the other and vise-versa.
        (Some(Ordering::Greater), Some(Ordering::Less))
        | (Some(Ordering::Less), Some(Ordering::Greater)) => None,
        // if context/token are equal, just return the other (token/context) result
        (Some(Ordering::Equal), x) | (x, Some(Ordering::Equal)) => x,
        // both have the same result
        (Some(x @ Ordering::Greater), Some(Ordering::Greater))
        | (Some(x @ Ordering::Less), Some(Ordering::Less)) => Some(x),
    }
}

/// Returns a mask for token and context fields representing the bits with constraints.
fn pattern_mask(case: &MatchCase) -> (u64, u64) {
    let mut token_mask = case.token.mask;
    let mut context_mask = case.context.mask;

    // Add bits constrained by complex constraints to each mask.
    for constraint in &case.constraints {
        match constraint {
            Constraint::Token { field, .. } => token_mask |= field.mask(),
            Constraint::Context { field, .. } => context_mask |= field.mask(),
        }
    }
    (token_mask, context_mask)
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

#[allow(unused)]
fn debug_cases(symbols: &SymbolTable, table: &Table, cases: &[MatchCase]) {
    use std::io::Write;

    let mut out = std::fs::File::options().append(true).create(true).open("cases.txt").unwrap();

    let table_name = symbols.parser.get_ident_str(table.name);
    let _ = writeln!(out, "{table_name}:");

    for case in cases {
        let _ = writeln!(
            out,
            "\t[{}] {}",
            case.constructor,
            symbols.format_constructor_line(case.constructor)
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
