use crate::{decoder::Decoder, ConstructorId, Field, Token};

pub type ConstraintOp = sleigh_parse::ast::ConstraintOp;
pub type ConstraintCmp = sleigh_parse::ast::ConstraintCmp;

// @fixme: Currently we only support matching instructions using a linear scan. It should be
// possible to implement this more efficiently (e.g., using a mask & match strategy), however due to
// the way the Sleigh specification is designed sometimes a linear search is necessary (e.g., for
// handling cases where there are multiple matching constructors) so we need this matcher anyway.
//
// For current use cases this linear search is "fast enough".
pub enum Matcher {
    SequentialMatcher(SequentialMatcher),
}

/// A matcher for finding the correct constructor using a linear scan.
///
/// Note: The matcher checks constructor constraints in the order they are defined, therefore if
/// there are multiple matching constructors the most specific one should be ordered first.
pub struct SequentialMatcher {
    /// The set of constructor constraints that can be matched at the current position.
    pub cases: Vec<MatchCase>,

    /// The size of the largest token checked by the matcher.
    pub token_size: usize,
}

impl SequentialMatcher {
    /// Find the first constructor that matches the current context
    pub fn match_constructor(&self, state: &Decoder) -> Option<ConstructorId> {
        let context = state.context;
        let token = state.get_raw_token(Token::new(self.token_size as u8));
        self.cases
            .iter()
            .find(|case| case.matches(state, context, token))
            .map(|case| case.constructor)
    }
}

pub struct MatchCase {
    /// The constructor id of the matched constructor.
    pub constructor: ConstructorId,

    /// Constraints on the token bits at the current offset.
    pub token: Pattern,

    /// Constraints on the current value of the context register.
    pub context: Pattern,

    /// Additional constraints that cannot be represented as a pattern (uncommon).
    pub constraints: Vec<Constraint>,
}

impl MatchCase {
    fn matches(&self, state: &Decoder, context_reg: u64, token: u64) -> bool {
        self.context.matches(context_reg)
            && self.token.matches(token)
            && (self.constraints.is_empty() || self.matches_complex(state))
    }

    #[cold]
    fn matches_complex(&self, state: &Decoder) -> bool {
        self.constraints.iter().all(|x| x.matches(state))
    }
}

#[derive(Debug, Copy, Clone, Default)]
pub struct Pattern {
    pub bits: u64,
    pub mask: u64,
}

impl Pattern {
    fn matches(&self, other: u64) -> bool {
        self.mask & self.bits == self.mask & other
    }
}

#[derive(Debug, Copy, Clone)]
pub enum ConstraintOperand {
    Constant(i64),
    Field(Field),
}

#[derive(Debug, Copy, Clone)]
pub enum Constraint {
    Token { token: Token, field: Field, cmp: ConstraintCmp, operand: ConstraintOperand },
    Context { field: Field, cmp: ConstraintCmp, operand: ConstraintOperand },
}

impl Constraint {
    pub fn matches(&self, state: &Decoder) -> bool {
        match *self {
            Self::Token { token, field, cmp, operand } => {
                let lhs = field.extract(state.get_token(token));
                let rhs = match operand {
                    ConstraintOperand::Constant(x) => x,
                    ConstraintOperand::Field(field) => field.extract(state.get_token(token)),
                };
                cmp_constraints(lhs, cmp, rhs)
            }
            Self::Context { field, cmp, operand } => {
                let lhs = field.extract(state.context);
                let rhs = match operand {
                    ConstraintOperand::Constant(x) => x,
                    ConstraintOperand::Field(field) => field.extract(state.context),
                };
                cmp_constraints(lhs, cmp, rhs)
            }
        }
    }
}

fn cmp_constraints(lhs: i64, op: ConstraintCmp, rhs: i64) -> bool {
    match op {
        ConstraintCmp::Equal => lhs == rhs,
        ConstraintCmp::NotEqual => lhs != rhs,
        ConstraintCmp::Less => lhs < rhs,
        ConstraintCmp::LessOrEqual => lhs <= rhs,
        ConstraintCmp::Greater => lhs > rhs,
        ConstraintCmp::GreaterOrEqual => lhs >= rhs,
    }
}
