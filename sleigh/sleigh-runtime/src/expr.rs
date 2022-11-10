pub type DisasmExprRange = (u32, u32);

/// The operations allowed in the disassembly section.
pub type DisasmOp = sleigh_parse::ast::PatternOp;

/// Encodes an operation part disassembly expression for either a context modification or a
/// disassembly constant.
#[derive(Clone)]
pub enum DisasmExprOp<T> {
    Value(T),
    Constant(u64),
    Not,
    Negate,
    Op(DisasmOp),
}

/// Disassembly expressions are mostly the same between context modifications and disassembly-time
/// constants. However since context modifications need to be evaluated _before_ the instruction has
/// been fully decoded `inst_next` is not valid, and the offsets for token fields needs to be
/// adjusted.
///
/// To share code we use a common trait to represent the two types of expressions.
pub(crate) trait EvalDisasmValue {
    type Value;
    fn eval(&self, value: &Self::Value) -> i64;
}

pub(crate) fn eval_disasm_expr<E>(
    stack: &mut Vec<i64>,
    eval: E,
    expr: &[DisasmExprOp<E::Value>],
) -> Option<i64>
where
    E: EvalDisasmValue,
{
    // Reserve space for worst case stack usage to avoid reallocation check on the hot path.
    stack.clear();
    stack.reserve(expr.len() / 2 + 1);

    for op in expr {
        let value = match op {
            DisasmExprOp::Value(x) => eval.eval(x),
            DisasmExprOp::Constant(x) => *x as i64,
            DisasmExprOp::Not => !stack.pop()?,
            DisasmExprOp::Negate => -stack.pop()?,
            DisasmExprOp::Op(op) => {
                let rhs = stack.pop()?;
                let lhs = stack.pop()?;
                match op {
                    DisasmOp::Add => lhs + rhs,
                    DisasmOp::Sub => lhs - rhs,
                    DisasmOp::And => lhs & rhs,
                    DisasmOp::Or => lhs | rhs,
                    DisasmOp::Xor => lhs ^ rhs,
                    DisasmOp::IntLeft => lhs.checked_shl(rhs as u32).unwrap_or(0),
                    DisasmOp::IntRight => {
                        let shift = (rhs as u32).min(std::mem::size_of::<i64>() as u32 * 8 - 1);
                        lhs >> shift
                    }
                    DisasmOp::Mult => lhs.wrapping_mul(rhs),
                    DisasmOp::Div => lhs / rhs,
                }
            }
        };

        if stack.capacity() == stack.len() {
            // Hint to the optimizer that we have enough space
            unreachable!();
        }
        stack.push(value);
    }

    stack.pop()
}
