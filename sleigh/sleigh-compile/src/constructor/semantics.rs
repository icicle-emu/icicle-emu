use std::{
    collections::{HashMap, HashSet},
    convert::TryInto,
};

use sleigh_parse::ast;
use sleigh_runtime::semantics::{Export, Local, SemanticAction, Value, ValueSize};

use crate::{
    constructor::Scope,
    symbols::{Symbol, SymbolKind, TableId, RAM_SPACE, REGISTER_SPACE},
};

pub(crate) fn resolve(
    scope: &mut Scope,
    statements: &[ast::Statement],
) -> Result<Semantics, String> {
    use std::fmt::Write;

    let mut builder = Builder::new(scope);
    builder.resolve_all(statements)?;

    let mut actions = std::mem::take(&mut builder.semantics.actions);

    apply_size_inference(&mut builder, &mut actions);

    let mut final_actions = Vec::with_capacity(
        actions.len() + builder.scope.subtables.len().saturating_sub(builder.build_actions.len()),
    );

    // Add build statements for any subtables that are not referenced by an explicit build action.
    for i in 0..builder.scope.subtables.len() {
        let index = i as u32;
        if !builder.build_actions.contains(&index) {
            final_actions.push(SemanticAction::Build(index))
        }
    }

    // Add the rest of the actions, making sure to fix value sizes
    for mut action in actions {
        if let SemanticAction::Op { op, inputs, output } = &mut action {
            inputs.iter_mut().for_each(|value| *value = builder.fix_size(*value));
            output.iter_mut().for_each(|value| *value = builder.fix_size(*value));

            // Try to resolve subpiece operations by adjusting the input offset.
            if let pcode::Op::Subpiece(offset) = op {
                let output = output.as_mut().unwrap();
                let size = output
                    .size
                    .ok_or_else(|| format!("output size for subpiece not known: {output:?}"))?;

                inputs[0] = inputs[0].slice_bytes(*offset as u16, size);
                *op = pcode::Op::Copy;
            }
        }
        final_actions.push(action);
    }

    // Ensure that the export statement as a fixed size
    if let Some(mut export) = builder.semantics.export.take() {
        match &mut export {
            Export::Value(value) => *value = builder.fix_size(*value),
            Export::Pointer(value, _) => *value = builder.fix_size(*value),
            Export::Register(value, _) => *value = builder.fix_size(*value),
        }
        builder.semantics.export = Some(export);
    }

    builder.semantics.actions = final_actions;
    let semantics = builder.semantics;

    // Report any errors that occured during construction
    let mut out = String::new();
    for (statement, error) in &builder.errors {
        writeln!(&mut out, "error in \"{}\": {}", builder.scope.debug(*statement), error).unwrap();
    }
    if !out.is_empty() {
        for op in &semantics.actions {
            writeln!(&mut out, "\t{op:?}").unwrap();
        }
        return Err(out);
    }

    Ok(semantics)
}

/// The SLEIGH specification expects some basic size inference to work. Currently, we address this
/// in the following way:
///
///  1. We apply any local size inference as we add operations to `actions`.
///  2. We perform a backwards pass to propagate sizes back to intermediate temporaries.
///  3. We perform a final forward pass using fallback sizes for constants and casting operations.
fn apply_size_inference(builder: &mut Builder, actions: &mut Vec<SemanticAction>) {
    for mut action in actions.iter_mut().rev() {
        if let SemanticAction::Op { op, inputs, output } = &mut action {
            builder.update_operand_sizes(*op, inputs, output);
        }
    }

    builder.use_fallback_sizes = true;
    for mut action in actions.iter_mut() {
        if let SemanticAction::Op { op, inputs, output } = &mut action {
            builder.update_operand_sizes(*op, inputs, output);
        }
    }
}

#[derive(Default, Debug, Clone)]
pub struct Semantics {
    /// The actions that are performed as part of this semantic section.
    pub actions: Vec<SemanticAction>,

    /// The value exported by the constructor (or None if there is no export statement)
    pub export: Option<Export>,

    /// The total number of temporaries used in this statement
    pub temporaries: usize,
}

enum Destination {
    Local(Value),
    Pointer(Value, ValueSize),
    SliceBits(Value, ast::Range),
}

struct Builder<'a, 'b> {
    scope: &'a mut Scope<'b>,
    macro_params: HashMap<ast::Ident, Value>,
    build_actions: HashSet<TableId>,
    semantics: Semantics,
    current_statement: &'a ast::Statement,
    /// The size (in bytes) of a pointer to an address in memory.
    pointer_size: ValueSize,
    /// Keeps track of whether we are performing should use fallback sizes during size inference.
    use_fallback_sizes: bool,
    errors: Vec<(&'a ast::Statement, String)>,
}

impl<'a, 'b> Builder<'a, 'b> {
    fn build(&mut self, index: u32) {
        self.semantics.actions.push(SemanticAction::Build(index));
    }

    fn push_op(
        &mut self,
        op: pcode::Op,
        mut inputs: Vec<Value>,
        mut output: Option<Value>,
    ) -> Option<Value> {
        self.update_operand_sizes(op, &mut inputs, &mut output);
        self.semantics.actions.push(SemanticAction::Op { op, inputs, output });
        output
    }

    /// SLEIGH allows operand sizes to be inferred based on their use. This function checks and
    /// updates the sizes of operands based on the opcode.
    fn update_operand_sizes(
        &mut self,
        op: pcode::Op,
        inputs: &mut [Value],
        output: &mut Option<Value>,
    ) {
        macro_rules! get_inputs {
            () => {
                match inputs {
                    [a, b] => (a, b),
                    _ => panic!("expected 2 inputs"),
                }
            };
        }

        match op {
            // input[0].size == output.size
            pcode::Op::Copy
            | pcode::Op::IntNot
            | pcode::Op::IntNegate
            | pcode::Op::FloatNegate
            | pcode::Op::FloatAbs
            | pcode::Op::FloatSqrt => {
                self.set_size_of_pair(&mut inputs[0], output.as_mut().unwrap());
            }

            // Input/output sizes are generally unconstrained, but force them to be equal if the
            // size is unknown after the initial inference pass.
            pcode::Op::Subpiece(_)
            | pcode::Op::ZeroExtend
            | pcode::Op::SignExtend
            | pcode::Op::IntToFloat
            | pcode::Op::UintToFloat
            | pcode::Op::FloatToFloat
            | pcode::Op::FloatToInt
            | pcode::Op::FloatCeil
            | pcode::Op::FloatFloor
            | pcode::Op::FloatRound
            | pcode::Op::IntCountOnes
            | pcode::Op::IntCountLeadingZeroes => {
                let output = output.as_mut().unwrap();
                if self.use_fallback_sizes
                    && (self.size_of(inputs[0]).is_none() || self.size_of(*output).is_none())
                {
                    self.set_size_of_pair(&mut inputs[0], output);
                }
            }

            // Unconstrained input/output size.
            pcode::Op::Arg(_)
            | pcode::Op::PcodeOp(_)
            | pcode::Op::Hook(_)
            | pcode::Op::HookIf(_) => {}

            // Shift operations: input[0].size == output.size
            pcode::Op::IntLeft | pcode::Op::IntRight | pcode::Op::IntSignedRight => {
                self.set_size_of_pair(&mut inputs[0], output.as_mut().unwrap());
            }

            // Rotate operations (Icicle extension): input[0].size == output.size
            pcode::Op::IntRotateLeft | pcode::Op::IntRotateRight => {
                self.set_size_of_pair(&mut inputs[0], output.as_mut().unwrap());
            }

            // Select operation (Icicle extension): input[0].size == input[1].size == output.size
            pcode::Op::Select(_) => {
                self.set_size(&mut inputs[0], 1);
                self.set_size_of_pair(&mut inputs[1], output.as_mut().unwrap());
            }

            // input[0].size == input[1].size == output.size
            pcode::Op::IntAdd
            | pcode::Op::IntSub
            | pcode::Op::IntXor
            | pcode::Op::IntOr
            | pcode::Op::IntAnd
            | pcode::Op::IntMul
            | pcode::Op::IntDiv
            | pcode::Op::IntSignedDiv
            | pcode::Op::IntRem
            | pcode::Op::IntSignedRem
            | pcode::Op::FloatAdd
            | pcode::Op::FloatSub
            | pcode::Op::FloatMul
            | pcode::Op::FloatDiv => {
                let (a, b) = get_inputs!();
                self.set_size_of_triple(a, b, output.as_mut().unwrap());
            }

            // input[0].size == input[1].size, output: boolean
            pcode::Op::IntCarry | pcode::Op::IntSignedCarry | pcode::Op::IntSignedBorrow => {
                let (a, b) = get_inputs!();
                self.set_size_of_pair(a, b);
                self.set_size(output.as_mut().unwrap(), 1);
            }

            // input[0]: bool, input[1]: bool, output: bool
            pcode::Op::BoolAnd | pcode::Op::BoolOr | pcode::Op::BoolXor => {
                self.set_size(&mut inputs[0], 1);
                self.set_size(&mut inputs[1], 1);
                self.set_size(output.as_mut().unwrap(), 1);
            }

            // input[0]: bool, output[0]: bool
            pcode::Op::BoolNot => {
                self.set_size(&mut inputs[0], 1);
                self.set_size(output.as_mut().unwrap(), 1);
            }

            // output: bool
            pcode::Op::FloatIsNan => {
                self.set_size(output.as_mut().unwrap(), 1);
            }

            // Comparison operators
            // input[0].size == input[1].size, output: bool
            pcode::Op::IntEqual
            | pcode::Op::IntNotEqual
            | pcode::Op::IntLess
            | pcode::Op::IntSignedLess
            | pcode::Op::IntLessEqual
            | pcode::Op::IntSignedLessEqual
            | pcode::Op::FloatEqual
            | pcode::Op::FloatNotEqual
            | pcode::Op::FloatLess
            | pcode::Op::FloatLessEqual => {
                let (a, b) = get_inputs!();
                self.set_size_of_pair(a, b);
                self.set_size(output.as_mut().unwrap(), 1);
            }

            // input[0] (address): ptr
            pcode::Op::Load(_) | pcode::Op::Store(_) => {
                self.set_size(&mut inputs[0], self.pointer_size);
            }

            // input[0] (condition): bool, input[1] (destination): ptr
            pcode::Op::Branch(_) => {
                self.set_size(&mut inputs[0], 1);

                // Though we expected pointer-sized branch destinations, Ghidra doesn't enforce this
                // in SLEIGH so we allow any size, and zero-extend it at runtime, so we only set the
                // size here if it is unknown.
                if inputs[0].size.is_none() {
                    self.set_size(&mut inputs[1], self.pointer_size);
                }
            }

            // input[0] (condition): bool
            pcode::Op::PcodeBranch(_) => {
                self.set_size(&mut inputs[0], 1);
            }

            // No inputs / outputs
            pcode::Op::PcodeLabel(_) | pcode::Op::InstructionMarker | pcode::Op::Invalid => {}

            // Internal operations not allowed in SLEIGH
            pcode::Op::TracerLoad(_) | pcode::Op::TracerStore(_) | pcode::Op::Exception => {}
        }
    }

    fn op(&mut self, op: impl Into<pcode::Op>, inputs: &[Value], output: Option<Value>) -> Value {
        let output = output.unwrap_or_else(|| self.scope.add_tmp(None).into());
        self.push_op(op.into(), inputs.to_vec(), Some(output)).unwrap()
    }

    fn op_no_output(&mut self, op: impl Into<pcode::Op>, inputs: &[Value]) {
        let _ = self.push_op(op.into(), inputs.to_vec(), None);
    }

    fn copy(&mut self, from: Value, to: Value) -> Value {
        self.push_op(pcode::Op::Copy, vec![from], Some(to)).unwrap()
    }

    fn load(&mut self, size: ValueSize, ptr: Value, output: Option<Value>) -> Value {
        let mut output = output.unwrap_or_else(|| self.scope.add_tmp(None).into());
        if size != 0 {
            // Note: we force the size here, to workaround the sizes used for the
            // `FPUInstructionPointer` and `FPUDataPointer` in the x86 SLEIGH spec.
            //
            // @todo: check whether this is a bug in the spec or not.
            // @todo: check whether we should insert an implicit zero extend here.
            if self.size_of(output).is_some() {
                output.size = Some(size);
            }
            self.set_size(&mut output, size);
        }
        self.op(pcode::Op::Load(0), &[ptr], Some(output))
    }

    fn store(&mut self, size: ValueSize, ptr: Value, mut value: Value) {
        if size != 0 {
            // See note for `load`
            if self.size_of(value).is_some() {
                value.size = Some(size);
            }
            self.set_size(&mut value, size);
        }
        self.op_no_output(pcode::Op::Store(0), &[ptr, value]);
    }

    fn unimplemented(&mut self) {
        self.op_no_output(pcode::Op::Invalid, &[]);
    }
}

impl<'a, 'b> Builder<'a, 'b> {
    fn new(scope: &'a mut Scope<'b>) -> Self {
        let pointer_size =
            scope.globals.default_space.map(|x| scope.globals.spaces[x as usize].size).unwrap_or(8);
        Self {
            scope,
            semantics: Semantics::default(),
            build_actions: HashSet::new(),
            macro_params: HashMap::new(),
            current_statement: &ast::Statement::Unimplemented,
            pointer_size,
            use_fallback_sizes: false,
            errors: vec![],
        }
    }

    fn error(&mut self, msg: impl Into<String>) {
        self.errors.push((self.current_statement, msg.into()));
    }

    fn size_of(&self, value: Value) -> Option<ValueSize> {
        value.size.or_else(|| self.scope.size_of(value.local))
    }

    /// Set the size of a value. An error is set the value already has a fixed size that is not the
    /// same as the new size.
    fn set_size(&mut self, value: &mut Value, size: ValueSize) {
        if let Some(x) = self.size_of(*value) {
            if x != size {
                // This could be a load/store operations through a subtable copy/load. So overwrite
                // the sizes like we do for loads and stores above. (e.g., see `Mem`
                // operand in `PEXTRB` of the x64 SLEIGH spec).
                if matches!(value.local, Local::Subtable(_)) {
                    value.size = Some(size);
                    return;
                }
                self.error(format!("error setting size of {:?} to: {} (was: {})", value, size, x));
            }
            return;
        }
        value.size = Some(size);

        // If this is a temporary, then the temporary is now fixed to this size.
        if let Local::PcodeTmp(id) = value.local {
            self.scope.temporaries[id as usize].size = Some(size);
        }
    }

    fn get_fallback_size(&self, a: &Value) -> Option<u16> {
        match a.local {
            Local::InstStart | Local::InstNext | Local::Constant(_) | Local::Field(_) => {
                Some(self.pointer_size)
            }
            _ => None,
        }
    }

    /// Sets two values to the same size, returning an error if this was not possible.
    fn set_size_of_pair(&mut self, a: &mut Value, b: &mut Value) {
        match (self.size_of(*a), self.size_of(*b)) {
            (None, None) => {
                if self.use_fallback_sizes {
                    if let Some(size) =
                        self.get_fallback_size(a).or_else(|| self.get_fallback_size(b))
                    {
                        self.set_size(a, size);
                        self.set_size(b, size);
                    }
                }
            }
            (Some(a), Some(b)) if a == b => {}
            (Some(size), _) => self.set_size(b, size),
            (_, Some(size)) => self.set_size(a, size),
        }
    }

    /// Sets three values to the same size, returning an error if this was not possible.
    fn set_size_of_triple(&mut self, a: &mut Value, b: &mut Value, c: &mut Value) {
        match (self.size_of(*a), self.size_of(*b), self.size_of(*c)) {
            (None, None, None) => {
                if self.use_fallback_sizes {
                    if let Some(size) = self
                        .get_fallback_size(a)
                        .or_else(|| self.get_fallback_size(b))
                        .or_else(|| self.get_fallback_size(c))
                    {
                        self.set_size(a, size);
                        self.set_size(b, size);
                        self.set_size(c, size);
                    }
                }
            }
            (Some(a), Some(b), Some(c)) if a == b && b == c => {}
            (Some(size), _, _) => {
                self.set_size(b, size);
                self.set_size(c, size);
            }
            (_, Some(size), _) => {
                self.set_size(a, size);
                self.set_size(c, size);
            }
            (_, _, Some(size)) => {
                self.set_size(a, size);
                self.set_size(b, size);
            }
        }
    }

    /// Attempts to assign a final concrete size to a value, an error is generated if the size is
    /// still unknown at this point.
    fn fix_size(&mut self, mut value: Value) -> Value {
        match self.size_of(value).or_else(|| self.get_fallback_size(&value)) {
            Some(size) => value.size = Some(size),
            None => self.error(format!("Unable to resolve size of value: {:?}", value)),
        }
        value
    }

    fn resolve_all(&mut self, statements: &'a [ast::Statement]) -> Result<(), String> {
        for statement in statements {
            self.current_statement = statement;
            self.resolve_statement(statement)?;
        }
        Ok(())
    }

    fn resolve_statement(&mut self, stmt: &'a ast::Statement) -> Result<(), String> {
        if self.semantics.export.is_some() {
            return Err("Export statement must be the last statement".into());
        }

        match stmt {
            ast::Statement::Unimplemented => {
                self.unimplemented();
            }
            ast::Statement::Export { value } => {
                let export = match value {
                    ast::PcodeExpr::Deref { space, size, pointer } => {
                        if space
                            .as_ref()
                            .map_or(false, |&space| space == self.scope.globals.const_ident)
                        {
                            Export::Value(self.resolve_expr(pointer)?.maybe_set_size(*size))
                        }
                        else {
                            let (space_id, addr_size, _word_size) = self.resolve_space(space)?;
                            let (mut pointer, size) = self.resolve_ptr(space, *size, pointer)?;
                            if pointer.size.is_none() {
                                pointer.size = Some(addr_size);
                            }

                            match space_id {
                                REGISTER_SPACE => Export::Register(pointer, size),
                                RAM_SPACE => Export::Pointer(pointer, size),
                                _ => panic!("unknown space_id: {}", space_id),
                            }
                        }
                    }
                    expr => Export::Value(self.resolve_expr(expr)?),
                };
                self.semantics.export = Some(export);
            }
            ast::Statement::Local { name, size } => {
                self.scope.named_tmp(*name, *size)?;
            }
            ast::Statement::LocalAssignment { name, size, expr } => {
                let dst = self.scope.named_tmp(*name, *size)?.into();
                self.resolve_expr_with_out(expr, Some(dst))?;
            }
            ast::Statement::Build { name } => {
                let subtable_id = self.scope.globals.lookup_kind(*name, SymbolKind::Table)?;
                let index: u32 = self.scope.subtables.iter().position(|id| *id == subtable_id)
                    .ok_or_else(|| format!("Table '{}' referenced in 'build' statement without being declared in constraint expression", self.scope.debug(name)))?
                    .try_into().unwrap();
                self.build_actions.insert(index);
                self.build(index);
            }
            ast::Statement::Copy { from, to } => {
                match self.resolve_dst(to)? {
                    Destination::Local(dst) => {
                        self.resolve_expr_with_out(from, Some(dst))?;
                    }
                    Destination::Pointer(ptr, size) => {
                        let value = self.resolve_expr(from)?;
                        self.store(size, ptr, value);
                    }
                    Destination::SliceBits(dst, (bit_offset, num_bits)) => {
                        let value = self.resolve_expr(from)?;
                        let mask_bits = pcode::mask(num_bits as u64);

                        // Get untouched bits from the existing value stored in the `dst`
                        let mask = Value::constant(!(mask_bits << bit_offset));
                        let prev = self.scope.add_tmp(self.size_of(dst)).into();
                        self.op(pcode::Op::IntAnd, &[dst, mask], Some(prev));

                        // Shift and mask the appropriate bits from `value` into a temporary
                        let mask = Value::constant(mask_bits);
                        let shift = Value::constant(bit_offset as u64);

                        let tmp = self.scope.add_tmp(self.size_of(dst)).into();
                        self.op(pcode::Op::ZeroExtend, &[value], Some(tmp));
                        self.op(pcode::Op::IntAnd, &[tmp, mask], Some(tmp));
                        self.op(pcode::Op::IntLeft, &[tmp, shift], Some(tmp));

                        // Merge results
                        self.op(pcode::Op::IntOr, &[prev, tmp], Some(dst));
                    }
                };
            }
            ast::Statement::Store { space, size, pointer, value } => {
                let (ptr, size) = self.resolve_ptr(space, *size, pointer)?;
                let value = self.resolve_expr(value)?;
                self.store(size, ptr, value);
            }
            ast::Statement::Call(ast::PcodeCall { name, args }) => {
                if *name == self.scope.globals.delay_slot_ident {
                    if args != &[ast::PcodeExpr::Integer { value: 1 }] {
                        return Err("expected delayslot(1)".into());
                    }
                    self.semantics.actions.push(SemanticAction::DelaySlot);
                    return Ok(());
                }

                match self.scope.globals.lookup(*name)? {
                    Symbol { kind: SymbolKind::UserOp, id } => {
                        let inputs = self.resolve_args(args)?;
                        let op = pcode::Op::PcodeOp(id.try_into().unwrap());
                        self.op_no_output(op, &inputs)
                    }
                    Symbol { kind: SymbolKind::Macro, id } => {
                        let args = self.resolve_args(args)?;

                        let macro_def = &self.scope.globals.macros[id as usize];
                        if macro_def.params.len() != args.len() {
                            return Err(format!(
                                "argument mismatch for macro {}",
                                self.scope.debug(&macro_def.name)
                            ));
                        }

                        // Crate a new namespace to define macro identifiers inside of, then the
                        // macro's parameters to the arguments passed to the macro.
                        let old_mapping = std::mem::take(&mut self.scope.mapping);
                        let old_macro = std::mem::take(&mut self.macro_params);
                        for (param, arg) in macro_def.params.iter().zip(args) {
                            self.macro_params.insert(*param, arg);
                        }

                        self.resolve_all(&macro_def.body)?;

                        // Restore previous namespace
                        self.macro_params = old_macro;
                        self.scope.mapping = old_mapping;
                    }
                    other => {
                        return Err(format!(
                            "unexpected symbol {:?}<{}>",
                            other.kind,
                            self.scope.debug(name)
                        ));
                    }
                }
            }
            ast::Statement::Branch { dst, hint } => {
                let hint = translate_hint(hint);
                let const_true = Value::constant(1);
                self.resolve_branch(const_true, dst, hint)?;
            }
            ast::Statement::CondBranch { cond, dst, hint } => {
                let hint = translate_hint(hint);
                let cond = self.resolve_expr(cond)?;
                self.resolve_branch(cond, dst, hint)?;
            }
            ast::Statement::Label { label } => {
                let id = self.resolve_label(label)?;
                self.op_no_output(pcode::Op::PcodeLabel(id), &[]);
            }
        }

        Ok(())
    }

    fn resolve_branch(
        &mut self,
        cond: Value,
        dst: &ast::BranchDst,
        hint: pcode::BranchHint,
    ) -> Result<(), String> {
        let is_direct = matches!(dst, ast::BranchDst::Direct(_));
        match dst {
            ast::BranchDst::Direct(dst) | ast::BranchDst::Indirect(dst) => {
                let dst = match *dst {
                    ast::JumpLabel::Ident(ident) => self.resolve_ident(ident)?,
                    ast::JumpLabel::Integer(value, size) => Value::constant(value).truncate(size),
                };
                let dst = match is_direct {
                    true => address_of(dst, Value::constant(0), self.size_of(dst))?,
                    false => dst,
                };
                self.op_no_output(pcode::Op::Branch(hint), &[cond, dst]);
            }
            ast::BranchDst::Label(label) => {
                let label = self.resolve_jump_label(label);
                let zero = Value::constant(0);
                self.op_no_output(pcode::Op::PcodeBranch(label), &[cond, zero]);
            }
        }

        Ok(())
    }

    fn resolve_jump_label(&mut self, name: &ast::Ident) -> u16 {
        let label = self.scope.get_or_insert_label(name);
        // If label was already defined then the jump must correspond to a back edge
        label.back_edge = label.defined;
        label.id
    }

    fn resolve_label(&mut self, name: &ast::Ident) -> Result<u16, String> {
        let label = self.scope.get_or_insert_label(name);
        if label.defined {
            return Err(format!("Redeclaration of existing label: {}", self.scope.debug(name)));
        }
        label.defined = true;
        Ok(label.id)
    }

    fn resolve_expr(&mut self, expr: &ast::PcodeExpr) -> Result<Value, String> {
        self.resolve_expr_with_out(expr, None)
    }

    fn resolve_expr_with_out(
        &mut self,
        expr: &ast::PcodeExpr,
        out: Option<Value>,
    ) -> Result<Value, String> {
        match expr {
            ast::PcodeExpr::Ident { value } => {
                let value = self.resolve_ident(*value)?;
                Ok(out.map_or(value, |out| self.copy(value, out)))
            }
            ast::PcodeExpr::Integer { value } => {
                let value = Value::constant(*value);
                Ok(out.map_or(value, |out| self.copy(value, out)))
            }
            ast::PcodeExpr::AddressOf { size, value, offset } => {
                let value = self.resolve_ident(*value)?;
                let offset = self.resolve_expr(offset)?;
                let value = address_of(value, offset, *size)?;
                Ok(out.map_or(value, |out| self.copy(value, out)))
            }
            ast::PcodeExpr::Truncate { value, size } => {
                let value = self.resolve_expr(value)?.truncate(*size);
                Ok(out.map_or(value, |out| self.copy(value, out)))
            }
            ast::PcodeExpr::SliceBits { value, range } => {
                let value = self.resolve_expr(value)?;
                let value = self.slice(value, *range)?;
                Ok(out.map_or(value, |out| self.copy(value, out)))
            }
            ast::PcodeExpr::Op { a, op, b } => {
                let (a, op, b) = translate_pcode_op(a, op, b);

                let lhs = self.resolve_expr(a)?;
                let rhs = self.resolve_expr(b)?;

                Ok(self.op(op, &[lhs, rhs], out))
            }
            ast::PcodeExpr::Deref { space, size, pointer } => {
                if space.as_ref().map_or(false, |space| *space == self.scope.globals.const_ident) {
                    let value = self.resolve_expr(pointer)?.maybe_set_size(*size);
                    Ok(out.map_or(value, |out| self.copy(value, out)))
                }
                else {
                    let (pointer, size) = self.resolve_ptr(space, *size, pointer)?;
                    Ok(self.load(size, pointer, out))
                }
            }
            ast::PcodeExpr::ConstantPoolRef { .. } => Err("constpoolref unimplemented".into()),
            ast::PcodeExpr::Call(ast::PcodeCall { name, args }) => {
                if let Some((op, n_inputs)) =
                    translate_inbuilt_func(self.scope.globals.parser.get_ident_str(*name))
                {
                    if args.len() != n_inputs {
                        return Err(format!(
                            "Error {:?} with {} arguments (expected: {})",
                            op,
                            args.len(),
                            n_inputs
                        ));
                    }
                    return self.resolve_inbuilt(op, args, out);
                }

                match self.scope.globals.lookup(*name) {
                    Ok(Symbol { kind: SymbolKind::UserOp, id }) => {
                        // @fixme: copy excess arguments to `pcode::Arg` slots (instead of in
                        // `get_runtime_inputs`)
                        let inputs = self.resolve_args(args)?;
                        let op = pcode::Op::PcodeOp(id.try_into().unwrap());
                        Ok(self.op(op, &inputs, out))
                    }
                    Ok(Symbol { kind: SymbolKind::Macro, .. }) => {
                        Err("macros are not allowed as expressions".into())
                    }
                    _ => {
                        // No matching global so treat this operation as a `SUBPIECE` on a local
                        // operation
                        let input = self.resolve_ident(*name)?;
                        let offset: u8 = match args[..] {
                            [ast::PcodeExpr::Integer { value }] => value
                                .try_into()
                                .map_err(|_| format!("SUBPIECE offset too large: {value}"))?,
                            _ => return Err("expected SUBPIECE(<const>)".into()),
                        };
                        Ok(self.op(pcode::Op::Subpiece(offset), &[input], out))
                    }
                }
            }
        }
    }

    fn resolve_inbuilt(
        &mut self,
        op: pcode::Op,
        args: &[ast::PcodeExpr],
        out: Option<Value>,
    ) -> Result<Value, String> {
        match args {
            [input] => {
                let input = self.resolve_expr(input)?;
                Ok(self.op(op, &[input], out))
            }
            [a, b] => {
                let a = self.resolve_expr(a)?;
                let b = self.resolve_expr(b)?;
                Ok(self.op(op, &[a, b], out))
            }
            _ => unreachable!(),
        }
    }

    fn resolve_dst(&mut self, expr: &ast::PcodeExpr) -> Result<Destination, String> {
        match expr {
            ast::PcodeExpr::Ident { value } => {
                let value = match self.resolve_ident(*value) {
                    Ok(local) => local,
                    Err(_) => self.scope.named_tmp(*value, None)?.into(),
                };
                Ok(Destination::Local(value))
            }
            ast::PcodeExpr::Truncate { value, size } => match value.as_ref() {
                &ast::PcodeExpr::Ident { value } => {
                    let value = match self.resolve_ident(value) {
                        Ok(local) => local.truncate(*size),
                        Err(_) => self.scope.named_tmp(value, Some(*size))?.into(),
                    };
                    Ok(Destination::Local(value))
                }
                _ => Err(format!("cannot assign to expression: {:?}", expr)),
            },
            ast::PcodeExpr::SliceBits { value, range: (bit_offset, num_bits) } => {
                let dst = self.resolve_expr(value)?;
                match dst.try_slice(*bit_offset, *num_bits) {
                    Some(dst) => Ok(Destination::Local(dst)),
                    None => Ok(Destination::SliceBits(dst, (*bit_offset, *num_bits))),
                }
            }
            ast::PcodeExpr::Deref { space, size, pointer } => {
                let (pointer, size) = self.resolve_ptr(space, *size, pointer)?;
                Ok(Destination::Pointer(pointer, size))
            }
            _ => Err(format!("cannot assign to expression: {:?}", expr)),
        }
    }

    fn slice(&mut self, value: Value, (bit_offset, num_bits): ast::Range) -> Result<Value, String> {
        if let Some(value) = value.try_slice(bit_offset, num_bits) {
            return Ok(value);
        }

        let mask = Value::constant(pcode::mask(num_bits as u64));
        let shift = Value::constant(bit_offset as u64);

        let tmp = self.scope.add_tmp(self.size_of(value)).into();
        self.op(pcode::Op::IntRight, &[value, shift], Some(tmp));
        self.op(pcode::Op::IntAnd, &[tmp, mask], Some(tmp));
        Ok(tmp.truncate(needed_bytes(num_bits)))
    }

    fn resolve_ident(&mut self, ident: ast::Ident) -> Result<Value, String> {
        // First try to resolve `ident` as a macro parameter or symbol in the local scope
        if let Some(var) = self.macro_params.get(&ident) {
            return Ok(*var);
        }
        if let Some(local) = self.scope.lookup(ident) {
            return Ok(local.into());
        }

        // A subset of globals are also allowed inside the constructor
        let global = self.scope.globals.lookup(ident)?;
        let local = match global.kind {
            SymbolKind::Register => Local::Register(global.id),
            SymbolKind::BitRange => return Err("@fixme: handle bitrange symbols".into()),
            _ => {
                return Err(format!(
                    "{:?}<{}> is not allowed in this scope",
                    global.kind,
                    self.scope.debug(&ident)
                ));
            }
        };

        Ok(local.into())
    }

    fn resolve_space(
        &mut self,
        space: &Option<ast::Ident>,
    ) -> Result<(u64, ValueSize, ValueSize), String> {
        let space = match space {
            Some(ident) => self.scope.globals.lookup_kind(*ident, SymbolKind::Space)?,
            None => self.scope.globals.default_space.ok_or("no default space")?,
        };
        let id = self.scope.globals.spaces[space as usize].space_id;
        let word_size = self.scope.globals.spaces[space as usize].word_size;
        let addr_size = self.scope.globals.spaces[space as usize].size;
        Ok((id, addr_size, word_size))
    }

    fn resolve_ptr(
        &mut self,
        space: &Option<ast::Ident>,
        size: Option<ast::VarSize>,
        pointer: &ast::PcodeExpr,
    ) -> Result<(Value, ValueSize), String> {
        let (_space, _addr_size, _word_size) = self.resolve_space(space)?;
        Ok((self.resolve_expr(pointer)?, size.unwrap_or(0)))
    }

    fn resolve_args(&mut self, args: &[ast::PcodeExpr]) -> Result<Vec<Value>, String> {
        args.iter().map(|x| self.resolve_expr(x)).collect::<Result<Vec<_>, _>>()
    }
}

fn address_of(value: Value, offset: Value, size: Option<ValueSize>) -> Result<Value, String> {
    let offset: u16 = match offset.local {
        Local::Constant(x) => x.try_into().map_err(|_| format!("offset to large: {x}"))?,
        _ => return Err(format!("{:?} is unsupported in address of operation", value.local)),
    };

    Ok(match value.local {
        Local::Subtable(index) => {
            Value { local: Local::SubtableAddr(index), offset: offset + value.offset, size }
        }
        _ => Value { local: value.local, offset: offset + value.offset, size: size.or(value.size) },
    })
}

/// Translate an input symbol to a P-code opcode, returning the name of the Opcode and the expected
/// number of arguments
fn translate_inbuilt_func(name: &str) -> Option<(pcode::Op, usize)> {
    use pcode::Op;

    Some(match name {
        "!" => (Op::BoolNot, 1),
        "~" => (Op::IntNot, 1),
        "-" => (Op::IntNegate, 1),
        "nan" => (Op::FloatIsNan, 1),

        "carry" => (Op::IntCarry, 2),
        "scarry" => (Op::IntSignedCarry, 2),
        "sborrow" => (Op::IntSignedBorrow, 2),

        "zext" => (Op::ZeroExtend, 1),
        "sext" => (Op::SignExtend, 1),

        "f-" => (Op::FloatNegate, 1),
        "abs" => (Op::FloatAbs, 1),
        "sqrt" => (Op::FloatSqrt, 1),
        "ceil" => (Op::FloatCeil, 1),
        "floor" => (Op::FloatFloor, 1),
        "round" => (Op::FloatRound, 1),
        "trunc" => (Op::FloatToInt, 1),

        "int2float" => (Op::IntToFloat, 1),
        "uint2float" => (Op::UintToFloat, 1),
        "float2float" => (Op::FloatToFloat, 1),

        "popcount" => (Op::IntCountOnes, 1),
        "lzcount" => (Op::IntCountLeadingZeroes, 1),
        _ => return None,
    })
}

/// Translates the ast operation representation to a pcode op (which may involve swapping the order
/// of `a` and `b` in the case of an emulated operation)
fn translate_pcode_op<T>(a: T, op: &ast::PcodeOp, b: T) -> (T, pcode::Op, T) {
    use pcode::Op;

    let mut swap = false;
    let op = match op {
        ast::PcodeOp::IntMult => Op::IntMul,
        ast::PcodeOp::IntDiv => Op::IntDiv,
        ast::PcodeOp::IntSignedDiv => Op::IntSignedDiv,
        ast::PcodeOp::IntRem => Op::IntRem,
        ast::PcodeOp::IntSignedRem => Op::IntSignedRem,
        ast::PcodeOp::IntAdd => Op::IntAdd,
        ast::PcodeOp::IntSub => Op::IntSub,
        ast::PcodeOp::IntLeft => Op::IntLeft,
        ast::PcodeOp::IntRight => Op::IntRight,
        ast::PcodeOp::IntSignedRight => Op::IntSignedRight,
        ast::PcodeOp::IntAnd => Op::IntAnd,
        ast::PcodeOp::IntXor => Op::IntXor,
        ast::PcodeOp::IntOr => Op::IntOr,

        ast::PcodeOp::IntCarry => Op::IntCarry,
        ast::PcodeOp::IntSignedCarry => Op::IntSignedCarry,
        ast::PcodeOp::IntSignedBorrow => Op::IntSignedBorrow,
        ast::PcodeOp::IntLess => Op::IntLess,
        ast::PcodeOp::IntLessEqual => Op::IntLessEqual,
        ast::PcodeOp::IntSignedLess => Op::IntSignedLess,
        ast::PcodeOp::IntSignedLessEqual => Op::IntSignedLessEqual,
        ast::PcodeOp::IntEqual => Op::IntEqual,
        ast::PcodeOp::IntNotEqual => Op::IntNotEqual,
        ast::PcodeOp::IntGreater => {
            swap = true;
            Op::IntLess
        }
        ast::PcodeOp::IntGreaterEqual => {
            swap = true;
            Op::IntLessEqual
        }
        ast::PcodeOp::IntSignedGreater => {
            swap = true;
            Op::IntSignedLess
        }
        ast::PcodeOp::IntSignedGreaterEqual => {
            swap = true;
            Op::IntSignedLessEqual
        }

        ast::PcodeOp::FloatDiv => Op::FloatDiv,
        ast::PcodeOp::FloatMult => Op::FloatMul,
        ast::PcodeOp::FloatAdd => Op::FloatAdd,
        ast::PcodeOp::FloatSub => Op::FloatSub,

        ast::PcodeOp::FloatLess => Op::FloatLess,
        ast::PcodeOp::FloatLessEqual => Op::FloatLessEqual,
        ast::PcodeOp::FloatEqual => Op::FloatEqual,
        ast::PcodeOp::FloatNotEqual => Op::FloatNotEqual,
        ast::PcodeOp::FloatGreater => {
            swap = true;
            Op::FloatLess
        }
        ast::PcodeOp::FloatGreaterEqual => {
            swap = true;
            Op::FloatLessEqual
        }

        ast::PcodeOp::BoolXor => Op::BoolXor,
        ast::PcodeOp::BoolAnd => Op::BoolAnd,
        ast::PcodeOp::BoolOr => Op::BoolOr,
    };

    match swap {
        true => (b, op, a),
        false => (a, op, b),
    }
}

fn translate_hint(hint: &ast::BranchHint) -> pcode::BranchHint {
    match hint {
        ast::BranchHint::Jump => pcode::BranchHint::Jump,
        ast::BranchHint::Call => pcode::BranchHint::Call,
        ast::BranchHint::Return => pcode::BranchHint::Return,
    }
}

/// Computes the smallest number of bytes necessary to store `num_bits`
fn needed_bytes(num_bits: ValueSize) -> ValueSize {
    (num_bits / 8) + (if num_bits % 8 == 0 { 0 } else { 1 })
}
