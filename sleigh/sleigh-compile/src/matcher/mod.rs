mod cases;

use std::cmp::Ordering;

use sleigh_runtime::matcher::{Constraint, MatchCase, Pattern, SequentialMatcher};

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

enum Index {
    Token(u8),
    Context(u8),
}

struct BitConstraint {
    index: Index,
    ones: u32,
    zeroes: u32,
    unconstrained: u32,
}

/// Constructors are allowed to have overlapping constraints where the constructor with highest
/// number of constrained bits is matched first. Here we take care of sorting the match cases so
/// that to ensure the most constrained constructors are matched first.
fn sort_overlaps(symbols: &SymbolTable, ctx: &Context, cases: &mut [MatchCase], token_size: u8) {
    let order_graph = build_order_graph(cases, symbols, token_size);

    // Assign ranking to cases based on topological ordering (lower ranks will be matched before
    // higher ranks)
    let mut scc_topological_rev = petgraph::algo::tarjan_scc(&order_graph);
    let mut rank = 0;
    for scc in scc_topological_rev.iter_mut().rev() {
        if scc.len() == 1 {
            cases[scc[0].index()].rank = rank;
            rank += 1;
        }
        else {
            if ctx.verbose {
                eprintln!("Unable to determine ordering for {} cases:", scc.len());
            }

            // Prioritize more specific matches over constructors that appear first based on the
            // heuristic that constructors that appear later should only appear as part of a cycle
            // if they constrain more bits than an earlier constructor).
            //
            // @fixme: Determine if there is a better rule to use for sorting constraint cycles.
            scc.sort_by_key(|idx| std::cmp::Reverse(idx.index()));

            for idx in scc {
                let case = &mut cases[idx.index()];
                case.rank = rank;
                rank += 1;
                if ctx.verbose {
                    eprintln!(
                        "\t[{}] {}",
                        case.constructor,
                        symbols.format_constructor_line(case.constructor)
                    )
                }
            }
        }
    }

    // Sort cases according to their ranking.
    cases.sort_by_key(|x| x.rank);
}

/// Builds a graph of the ordering constraints implied by the SLEIGH specification. Nodes encode
/// cases, while edges encode that the source case needs to be ordered before the target case.
fn build_order_graph<'a>(
    cases: &'a [MatchCase],
    symbols: &SymbolTable,
    token_size: u8,
) -> petgraph::Graph<&'a MatchCase, ()> {
    // Iterate each possibly constrained bit so we can compute states that let us split the
    // constraints into overlapping/non-overlapping more efficiently.
    let token_bits = (0..token_size * 8).map(|i| {
        let (ones, zeroes, unconstrained) = count_constraints(i, cases.iter().map(|x| &x.token));
        BitConstraint { index: Index::Token(i), ones, zeroes, unconstrained }
    });
    let context_bits = (0..64).map(|i| {
        let (ones, zeroes, unconstrained) = count_constraints(i, cases.iter().map(|x| &x.context));
        BitConstraint { index: Index::Context(i), ones, zeroes, unconstrained }
    });

    let mut bit_stats: Vec<_> = token_bits.chain(context_bits).collect();

    // Remove any bits that are not constrained by any constructor.
    bit_stats.retain(|bit| bit.ones != 0 || bit.zeroes != 0);

    // We want to first split cases by the bits that are constrained in the most number of cases
    // (since cases with unconstrained bits need to be checked in both splits), then split the bits
    // with the highest splitting factor. This strategy reduces the number of cases that we need to
    // check deeper in the tree.
    bit_stats.sort_by_key(|x| (x.unconstrained, u32::max(x.ones, x.zeroes)));

    let mut remaining_cases = Vec::with_capacity(cases.len());
    let mut order_graph = petgraph::Graph::with_capacity(cases.len(), 8);
    for case in cases.iter() {
        remaining_cases.push(order_graph.add_node(case));
    }
    let mut visitor = BitVisitor { state: Vec::new(), order_graph, symbols };
    visitor.split_next(&bit_stats, &mut remaining_cases);

    visitor.order_graph
}

/// The specification requires that the most constrained constructors should be matched first so we
/// check here the ordering.
fn compare_number_of_constrained_bits(a: &MatchCase, b: &MatchCase) -> Option<Ordering> {
    let (a_token, a_context) = pattern_mask(a);
    let (b_token, b_context) = pattern_mask(b);
    match (compare_bits_set(a_token, b_token), compare_bits_set(a_context, b_context)) {
        (Some(Ordering::Equal), Some(Ordering::Equal)) => Some(Ordering::Equal),
        (Some(x), Some(Ordering::Equal)) | (Some(Ordering::Equal), Some(x)) => Some(x),
        (Some(a), Some(b)) if a == b => Some(a),
        _ => None,
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

#[derive(Debug, Copy, Clone, PartialEq, Eq)]
enum Bit {
    One,
    Zero,
    Unconstrained,
}

fn display_bits(bits: &[Bit]) -> String {
    bits.iter()
        .rev()
        .map(|x| match x {
            Bit::Unconstrained => '_',
            Bit::Zero => '0',
            Bit::One => '1',
        })
        .collect()
}

struct BitVisitor<'a, 'b> {
    /// The bits set in the current subtree, used for generating error messages to the user.
    state: Vec<Bit>,
    /// Keeps track of the ordering requirements of match cases.
    order_graph: petgraph::Graph<&'a MatchCase, ()>,
    /// Used for debug info.
    symbols: &'b SymbolTable,
}

impl<'a, 'b> BitVisitor<'a, 'b> {
    fn split_next(
        &mut self,
        remaining_bits: &[BitConstraint],
        cases: &mut [petgraph::graph::NodeIndex],
    ) {
        if cases.len() < 2 {
            // There is at most one cases so no splitting is required.
            return;
        }

        let Some((bit, remaining_bits)) = remaining_bits.split_first() else {
            // No more bits to split any remaining cases fully overlap.
            return self.add_ordering(cases);
        };

        let (zero, one, unconstrained) = match bit.index {
            Index::Token(i) => {
                partition_by_bit(cases, |case| check_bit(&self.order_graph[*case].token, i))
            }
            Index::Context(i) => {
                partition_by_bit(cases, |case| check_bit(&self.order_graph[*case].context, i))
            }
        };

        if one.is_empty() && zero.is_empty() {
            self.state.push(Bit::Unconstrained);
            self.split_next(remaining_bits, unconstrained);
            self.state.pop();
        }
        else {
            if !zero.is_empty() {
                let mut zeroes =
                    zero.iter().copied().chain(unconstrained.iter().copied()).collect::<Vec<_>>();
                self.state.push(Bit::Zero);
                self.split_next(remaining_bits, &mut zeroes);
                self.state.pop();
            }
            if !one.is_empty() {
                self.state.push(Bit::One);
                let mut ones =
                    one.iter().copied().chain(unconstrained.iter().copied()).collect::<Vec<_>>();
                self.split_next(remaining_bits, &mut ones);
                self.state.pop();
            }
        }
    }

    fn add_ordering(&mut self, cases: &[petgraph::graph::NodeIndex]) {
        // Warn when the ordering depends on the declaration order of the constructors (this set
        // to false, because it is frequently triggered by the x86-64 specification).
        const WARN_ON_DECLARATION_ORDERING: bool = false;

        for i in 0..cases.len() {
            let a_idx = cases[i];
            let a = self.order_graph[a_idx];
            for j in i..cases.len() {
                let b_idx = cases[j];
                let b = self.order_graph[b_idx];

                // A single constructor can have multiple associated match cases due to `|`
                // conditions. We do not care which case matches to constructor so the ordering
                // doesn't matter.
                if a.constructor == b.constructor {
                    continue;
                }

                match compare_number_of_constrained_bits(a, b) {
                    Some(Ordering::Greater) => {
                        self.order_graph.update_edge(a_idx, b_idx, ());
                    }
                    Some(Ordering::Less) => {
                        self.order_graph.update_edge(b_idx, a_idx, ());
                    }
                    Some(Ordering::Equal) | None => {
                        // No ordering implied by the number of bits constrained, so try to order
                        // the constructors based on the declaration order in the original file.
                        let (before, after) = match a.constructor < b.constructor {
                            true => (a_idx, b_idx),
                            false => (b_idx, a_idx),
                        };
                        self.order_graph.update_edge(before, after, ());

                        if WARN_ON_DECLARATION_ORDERING {
                            eprintln!(
                                "At: {}, using declaration order for: {} and {}",
                                display_bits(&self.state),
                                self.symbols.format_constructor_line(a.constructor),
                                self.symbols.format_constructor_line(b.constructor)
                            );
                        }
                    }
                }
            }
        }
    }
}

fn count_constraints<'a>(bit: u8, patterns: impl Iterator<Item = &'a Pattern>) -> (u32, u32, u32) {
    let mut zeroes = 0;
    let mut ones = 0;
    let mut unconstrained = 0;
    for pattern in patterns {
        match check_bit(pattern, bit) {
            Bit::Zero => zeroes += 1,
            Bit::One => ones += 1,
            Bit::Unconstrained => unconstrained += 1,
        }
    }
    (zeroes, ones, unconstrained)
}

fn check_bit(pattern: &Pattern, bit: u8) -> Bit {
    let value = 1 << bit;
    match (pattern.mask & value != 0, pattern.bits & value != 0) {
        (false, _) => Bit::Unconstrained,
        (true, true) => Bit::One,
        (true, false) => Bit::Zero,
    }
}

/// Partitions `arr` into 3 arrays (zeroes, ones, unconstrained) depending on the value returned by
/// `selector`
fn partition_by_bit<T>(
    arr: &mut [T],
    mut selector: impl FnMut(&T) -> Bit,
) -> (&mut [T], &mut [T], &mut [T]) {
    // First partition the array into constrained and unconstrained elements.
    let idx = partition_in_place(arr, |case| selector(case) != Bit::Unconstrained);
    let (constrained, unconstrained) = arr.split_at_mut(idx);

    // Then split constrained bits by value.
    let idx = partition_in_place(constrained, |case| selector(case) != Bit::One);
    let (zeroes, ones) = constrained.split_at_mut(idx);

    (zeroes, ones, unconstrained)
}

/// Split an array into two parts based on `pred`. This is done in place, returning the index of the
/// split point.
fn partition_in_place<T>(arr: &mut [T], mut pred: impl FnMut(&T) -> bool) -> usize {
    let mut split = 0;
    let mut iter = arr.iter_mut();

    while let Some(front) = iter.next() {
        if pred(front) {
            // The current element is already in the correct position.
            split += 1;
            continue;
        }

        // Find an element starting from the back of the array to swap with.
        while let Some(back) = iter.next_back() {
            if pred(back) {
                std::mem::swap(front, back);
                split += 1;
                break;
            }
        }
    }
    split
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

// @debugging: print the order we are going to visit the bits in.
#[allow(unused)]
fn debug_bit_stats(bit_stats: &Vec<BitConstraint>) {
    use std::io::Write;

    let mut stdout = std::io::stdout().lock();
    for bit in bit_stats {
        let (prefix, index) = match bit.index {
            Index::Token(i) => ('t', i),
            Index::Context(i) => ('c', i),
        };
        let _ = write!(stdout, "{prefix}{index:02} ");
    }
    let _ = stdout.write_all(b"\n");
}

#[test]
fn test_bit_partition() {
    let mut a = [
        Bit::One,
        Bit::Zero,
        Bit::Unconstrained,
        Bit::Unconstrained,
        Bit::One,
        Bit::Zero,
        Bit::One,
    ];
    assert_eq!(
        partition_by_bit(&mut a, |x| *x),
        (
            &mut [Bit::Zero, Bit::Zero][..],
            &mut [Bit::One, Bit::One, Bit::One][..],
            &mut [Bit::Unconstrained, Bit::Unconstrained][..]
        )
    );
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
