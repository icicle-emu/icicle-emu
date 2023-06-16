mod cases;

use std::cmp::Ordering;

use sleigh_runtime::matcher::{Constraint, MatchCase, Pattern, SequentialMatcher};

use crate::{
    symbols::{SymbolTable, Table},
    Context,
};

use self::cases::byteswap_value;

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
fn sort_overlaps(symbols: &SymbolTable, ctx: &Context, cases: &mut [MatchCase], _token_size: u8) {
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
            let cmp = compare_match_cases(add, &cases[i]);
            match cmp.ord {
                Some(Ordering::Equal) if cmp.same_intersection => {
                    if add.constructor != cases[i].constructor {
                        if ctx.verbose {
                            eprintln!(
                                "[warning] diferent constructor, same pattern: {} {}",
                                symbols.format_constructor_line(cases[i].constructor),
                                symbols.format_constructor_line(add.constructor),
                            );
                        }
                    }
                }
                None if cmp.same_intersection => {
                    if ctx.verbose && !solver_conflict(add, &cases[i], cases) {
                        eprintln!(
                            "[warning] unsolved conflict between: {} {}",
                            symbols.format_constructor_line(cases[i].constructor),
                            symbols.format_constructor_line(add.constructor),
                        );
                    }
                }
                Some(Ordering::Greater) if cmp.same_intersection => break Some(i),
                _ => {}
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

#[derive(Debug, PartialEq, Eq)]
pub(crate) struct MatcherOrdering {
    /// If the intersection is equal (same value)
    same_intersection: bool,
    /// The kind of intersection
    ord: Option<Ordering>,
}

fn pattern_mask_value_simple(case: &MatchCase) -> (u128, u128) {
    let mask = (case.token.mask as u128) << u64::BITS | case.context.mask as u128;
    let value = (case.token.bits as u128) << u64::BITS | case.context.bits as u128;
    //NOTE value & mask is important because of the complex constraint
    (mask, value & mask)
}

fn pattern_mask_complex(case: &MatchCase) -> u128 {
    let mask = (case.token.mask as u128) << u64::BITS | case.context.mask as u128;
    let value = (case.token.bits as u128) << u64::BITS | case.context.bits as u128;
    !mask & value
}

/// Compares the bits set in self with other.
fn compare_simple_match(case_a: &MatchCase, case_b: &MatchCase) -> MatcherOrdering {
    // restricted bit, but value is not known
    let (mask_a, value_a) = pattern_mask_value_simple(case_a);
    let (mask_b, value_b) = pattern_mask_value_simple(case_b);
    let extra_a = mask_a & !mask_b != 0;
    let extra_b = mask_b & !mask_a != 0;
    match (extra_a, extra_b) {
        // Same mask
        (false, false) => {
            let same_intersection = value_a == value_b;
            MatcherOrdering { same_intersection, ord: Some(Ordering::Equal) }
        }
        // Intersection,
        (true, true) => {
            let same_intersection = value_a & mask_b == value_b & mask_a;
            MatcherOrdering { same_intersection, ord: None }
        }
        (true, false) => {
            let same_intersection = value_a & mask_b == value_b;
            MatcherOrdering { same_intersection, ord: Some(Ordering::Greater) }
        }
        (false, true) => {
            let same_intersection = value_b & mask_a == value_a;
            MatcherOrdering { same_intersection, ord: Some(Ordering::Less) }
        }
    }
}

/// Compares the bits set in self with other.
fn complex_mask(case_a: &MatchCase, case_b: &MatchCase) -> Option<Ordering> {
    let mask_complex_a = pattern_mask_complex(case_a);
    let mask_complex_b = pattern_mask_complex(case_b);
    let extra_a = mask_complex_a & !mask_complex_b != 0;
    let extra_b = mask_complex_b & !mask_complex_a != 0;
    match (extra_a, extra_b) {
        (false, false) => Some(Ordering::Equal),
        (true, true) => None,
        (true, false) => Some(Ordering::Greater),
        (false, true) => Some(Ordering::Less),
    }
}

fn complex_same_intersection(case_a: &MatchCase, case_b: &MatchCase) -> bool {
    // TODO can a complex constraint be duplicated, or this is filtered previously?
    // mark all constraints that have a equivalent constraint at the other
    //TODO don't use equality, use equivalency.
    //eg: `unsigned_field > 0 => unsigned_field != 0`
    let mask_complex_a = pattern_mask_complex(case_a);
    let mask_complex_b = pattern_mask_complex(case_b);
    let intersection = mask_complex_a & mask_complex_b;
    let constraints_a: Vec<_> =
        case_a.constraints.iter().filter(|a| constraint_in_mask(a, intersection)).collect();
    let constraints_b: Vec<_> =
        case_b.constraints.iter().filter(|b| constraint_in_mask(b, intersection)).collect();
    let mut equivalent_a = vec![false; constraints_a.len()];
    let mut equivalent_b = vec![false; constraints_b.len()];
    for (i_a, complex_a) in constraints_a.iter().enumerate() {
        for (i_b, complex_b) in constraints_b.iter().enumerate() {
            if complex_a == complex_b {
                equivalent_a[i_a] = true;
                equivalent_b[i_b] = true;
                break;
            }
        }
    }

    // TODO check if the unmatched constraint are always true on the simple
    // pattern of the other.
    // eg: case_a: simple: 0000, no complex
    //     case_b: simple: ____, complex: `b0001 == b0203`
    !equivalent_a.contains(&false) && !equivalent_b.contains(&false)
}

fn constraint_in_mask(constraint: &Constraint, mask: u128) -> bool {
    match constraint {
        Constraint::Token { token, field, .. } => {
            let mut bits = field.mask();
            if token.big_endian {
                bits = byteswap_value(bits, token.size as u64 * 8);
            }
            bits & (mask as u64) == bits
        }
        Constraint::Context { field, .. } => {
            let bits = field.mask();
            bits & ((mask >> 64) as u64) == bits
        }
    }
}

/// Compares the bits set in self with other.
fn compare_match_cases(case_a: &MatchCase, case_b: &MatchCase) -> MatcherOrdering {
    let simple = compare_simple_match(case_a, case_b);
    let ord = simple.ord.and_then(|cmp| match (cmp, complex_mask(case_a, case_b)) {
        // equal mask, if same value, it all depends on the complex comparison
        (Ordering::Equal, other) => other,
        // with greater and less, we need to compare both
        (Ordering::Less, Some(Ordering::Less | Ordering::Equal))
        | (Ordering::Greater, Some(Ordering::Greater | Ordering::Equal)) => Some(cmp),
        _ => None,
    });
    // avoid calling complex_same_intersection if unecessary
    let same_intersection = simple.same_intersection && complex_same_intersection(case_a, case_b);
    MatcherOrdering { ord, same_intersection }
}

fn solver_conflict(conflict_a: &MatchCase, conflict_b: &MatchCase, cases: &[MatchCase]) -> bool {
    let (mask_value_a, value_a) = pattern_mask_value_simple(conflict_a);
    let (mask_value_b, value_b) = pattern_mask_value_simple(conflict_b);
    let mask_value_solver = mask_value_a | mask_value_b;
    let value_solver = value_a | value_b;

    //TODO multiple constructors solve this case, probably not allowed anyway...
    for case in cases.iter() {
        let (mask_value_case, value_case) = pattern_mask_value_simple(case);
        if mask_value_case == mask_value_solver && value_case == value_solver {
            return true;
        }
    }
    //TODO check the complex too
    false
}

#[allow(unused)]
fn bit_to_string(case: &Pattern) -> String {
    (0..64)
        .into_iter()
        .map(|bit| match (case.mask >> bit & 1 != 0, case.bits >> bit & 1 != 0) {
            (true, true) => '1',
            (true, false) => '0',
            (false, true) => 'X',
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
    let _ = writeln!(out, "| mneumonic | src | context | token |");
    let _ = writeln!(out, "|----|-----|---------|-------|");

    for case in cases {
        let constructor = &symbols.constructors[case.constructor as usize];
        let _ = writeln!(
            out,
            "| {} | {} | `{}` | `{}` |",
            constructor.mnemonic.as_ref().map(String::as_str).unwrap_or("∅"),
            symbols.format_constructor_line(case.constructor),
            bit_to_string(&case.context),
            bit_to_string(&case.token),
        );
    }
    let _ = out.write_all(b"\n");
}

#[test]
fn test_compare_bits_set() {
    let default_match = MatchCase {
        constructor: 0,
        rank: 0,
        token: Pattern { bits: 0, mask: 0 },
        context: Pattern { bits: 0, mask: 0 },
        constraints: vec![],
    };
    let a = MatchCase { context: Pattern { bits: 0, mask: 0b01111 }, ..default_match.clone() };
    let b = MatchCase { context: Pattern { bits: 0, mask: 0b11111 }, ..default_match.clone() };
    assert_eq!(compare_match_cases(&a, &a).ord, Some(std::cmp::Ordering::Equal));
    assert_eq!(compare_match_cases(&a, &b).ord, Some(std::cmp::Ordering::Less));
    assert_eq!(compare_match_cases(&b, &a).ord, Some(std::cmp::Ordering::Greater),);

    let c = MatchCase { context: Pattern { bits: 0, mask: 0b10000 }, ..default_match.clone() };
    assert_eq!(compare_match_cases(&c, &a).ord, None);
    assert_eq!(compare_match_cases(&c, &b).ord, Some(std::cmp::Ordering::Less));

    let ands = MatchCase {
        context: Pattern { bits: 0, mask: 0b11111111100000000000000000000000 },
        ..default_match.clone()
    };
    let tst = MatchCase {
        context: Pattern { bits: 0, mask: 0b11111111100000000000000000011111 },
        ..default_match.clone()
    };
    assert_eq!(compare_match_cases(&ands, &tst).ord, Some(std::cmp::Ordering::Less),);
    assert_eq!(compare_match_cases(&tst, &ands).ord, Some(std::cmp::Ordering::Greater),);

    let asr =
        MatchCase { context: Pattern { bits: 0, mask: 0x8030_ffef }, ..default_match.clone() };
    let orr =
        MatchCase { context: Pattern { bits: 0, mask: 0x8000_ffe0 }, ..default_match.clone() };
    assert_eq!(compare_match_cases(&asr, &orr).ord, Some(std::cmp::Ordering::Greater),);
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
    assert_eq!(compare_match_cases(&tst, &ands).ord, Some(std::cmp::Ordering::Greater));

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
    assert_eq!(compare_match_cases(&a, &b).ord, None);
}
