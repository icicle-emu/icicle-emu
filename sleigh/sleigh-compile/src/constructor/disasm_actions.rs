use sleigh_parse::ast;
use sleigh_runtime::{semantics::Local, ContextModValue, DisasmConstantValue, DisasmExprOp, Field};

use crate::{
    constructor::{FieldIndex, Scope},
    symbols::{ContextFieldId, Symbol, SymbolKind},
};

#[derive(Clone, Default)]
pub(crate) struct DisasmActions {
    /// Fields assigned to in the disassembly expression
    pub fields: Vec<(FieldIndex, Vec<DisasmExprOp<DisasmConstantValue>>)>,

    /// The context fields modified in this section
    pub context_mod: Vec<(ContextFieldId, Vec<DisasmExprOp<ContextModValue>>)>,

    /// The context fields globally set by this section
    pub global_set: Vec<u32>,
}

pub(crate) fn resolve(
    scope: &mut Scope,
    disasm_actions: &[ast::DisasmAction],
) -> Result<DisasmActions, String> {
    let mut section = DisasmActions::default();

    for action in disasm_actions {
        match action {
            ast::DisasmAction::Assignment { ident, expr } => {
                let field_id = scope.fields.len().try_into().unwrap();

                match scope.globals.lookup(*ident) {
                    // An expression that modifies the decoder context.
                    Ok(Symbol { kind: SymbolKind::ContextField, id }) => {
                        let field = scope.globals.context_fields[id as usize].field;
                        scope.add_field(*ident, field)?;

                        let mut out = vec![];
                        resolve_disasm_expr(scope, expr, &mut out)?;
                        section.context_mod.push((id, out));
                    }

                    // An expression that sets a disassembly constant.
                    // @todo: check which symbol types are allowed to be shadowed.
                    Err(_) | Ok(Symbol { kind: SymbolKind::TokenField, .. }) => {
                        let field_id = scope.add_field(*ident, Field::i64())?;

                        let mut out = vec![];
                        resolve_disasm_expr(scope, expr, &mut out)?;
                        section.fields.push((field_id, out));
                    }

                    Ok(Symbol { kind, .. }) => {
                        return Err(format!(
                            "{:?}<{}> is not allowed in a disassembly action expression",
                            kind,
                            scope.debug(ident)
                        ));
                    }
                }

                scope.mapping.insert(*ident, Local::Field(field_id));
            }
            ast::DisasmAction::GlobalSet { start_sym, context_sym } => {
                let resolved = match DisasmConstantValue::resolve_ident(scope, *start_sym).ok() {
                    Some(DisasmConstantValue::InstNext) => DisasmConstantValue::InstNext,
                    Some(DisasmConstantValue::InstStart) => DisasmConstantValue::InstStart,
                    // @fixme: unsupported target for globalset
                    _ => continue,
                };

                let id = scope.globals.lookup_kind(*context_sym, SymbolKind::ContextField)?;
                if !scope.globals.context_fields[id as usize].flow
                    && matches!(resolved, DisasmConstantValue::InstStart)
                {
                    return Err(format!(
                        "globalset(inst_start,{}) does nothing",
                        scope.debug(context_sym)
                    ));
                }
                section.global_set.push(id);
            }
        }
    }

    Ok(section)
}

fn resolve_disasm_expr<T>(
    scope: &Scope,
    expr: &ast::PatternExpr,
    out: &mut Vec<DisasmExprOp<T>>,
) -> Result<(), String>
where
    T: ResolveIdent,
{
    let op = match expr {
        ast::PatternExpr::Ident(ident) => DisasmExprOp::Value(T::resolve_ident(scope, *ident)?),
        ast::PatternExpr::Integer(value) => DisasmExprOp::Constant(*value),
        ast::PatternExpr::Op(a, op, b) => {
            resolve_disasm_expr::<T>(scope, a, out)?;
            resolve_disasm_expr::<T>(scope, b, out)?;
            DisasmExprOp::Op(*op)
        }
        ast::PatternExpr::Not(inner) => {
            resolve_disasm_expr::<T>(scope, inner, out)?;
            DisasmExprOp::Not
        }
        ast::PatternExpr::Negate(inner) => {
            resolve_disasm_expr::<T>(scope, inner, out)?;
            DisasmExprOp::Negate
        }
    };
    out.push(op);
    Ok(())
}

trait ResolveIdent: Sized {
    fn resolve_ident(scope: &Scope, ident: ast::Ident) -> Result<Self, String>;
}

impl ResolveIdent for DisasmConstantValue {
    fn resolve_ident(scope: &Scope, ident: ast::Ident) -> Result<Self, String> {
        match scope.lookup(ident) {
            Some(Local::Field(id)) => Ok(Self::LocalField(id)),
            Some(Local::InstStart) => Ok(Self::InstStart),
            Some(Local::InstNext) => Ok(Self::InstNext),
            Some(other) => Err(format!("{:?}<{}> in disasm expr", other, scope.debug(&ident))),
            None => {
                // Some SLEIGH specifications use context fields in disassembly expressions without
                // first declaring them in the constraint expression.
                let sym = scope
                    .globals
                    .lookup_kind(ident, SymbolKind::ContextField)
                    .map_err(|err| format!("Unexpected symbol kind in disasm expr: {}", err))?;
                Ok(Self::ContextField(scope.globals.context_fields[sym as usize].field))
            }
        }
    }
}

impl ResolveIdent for ContextModValue {
    fn resolve_ident(scope: &Scope, ident: ast::Ident) -> Result<Self, String> {
        match scope.lookup(ident) {
            Some(Local::Field(id)) => {
                // Context modification expression are evaluated before local fields so the runtime
                // needs to know the original source of the field to evalaute them correctly.
                let field = scope.fields[id as usize];
                match scope.tokens.get(&id) {
                    Some(token) => Ok(Self::TokenField(*token, field)),
                    None => Ok(Self::ContextField(field)),
                }
            }
            Some(Local::InstStart) => Ok(Self::InstStart),
            Some(other) => {
                Err(format!("{:?}<{}> in context modification", other, scope.debug(&ident)))
            }
            None => {
                // Some SLEIGH specifications use context fields in context modifications
                // expressions without first declaring them in the constraint expression.
                let sym =
                    scope.globals.lookup_kind(ident, SymbolKind::ContextField).map_err(|err| {
                        format!("Unexpected symbol kind in disasm context write expr: {}", err)
                    })?;
                Ok(Self::ContextField(scope.globals.context_fields[sym as usize].field))
            }
        }
    }
}
