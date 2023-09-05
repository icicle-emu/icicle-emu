use std::collections::HashMap;

use crate::{
    decoder::SubtableCtx,
    semantics::{Export, Local, SemanticAction, Value, ValueSize},
    AttachmentId, ConstructorId, Instruction, SleighData,
};

/// The size (in bytes) of the largest supported register for the runtime.
const MAX_REG_SIZE: u8 = 16;

#[derive(Clone, Debug)]
pub enum Error {
    WriteToConstant,
    InvalidVarNode,
    UnknownVarNode(u32, u8),
    AddressOfTemporary,
    VarNodeOffsetIsNotConstant,
    TooManyTemporaries,
    UnsupportedVarNodeSize(ValueSize),
    InvalidExport(ConstructorId),
    Internal(&'static str),
}

impl std::error::Error for Error {}

impl std::fmt::Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Error::WriteToConstant => {
                f.write_str("Sub-expression attempted to write to a constant")
            }
            Error::InvalidVarNode => {
                f.write_str("Attempted to perform an operation on an invalid VarNode.")
            }
            Error::UnknownVarNode(offset, size) => {
                write!(f, "Attempted use an unknown varnode (offset: {offset:#0x}, size: {size})")
            }
            Error::AddressOfTemporary => {
                f.write_str("Attempted to take the address of a temporary varnode")
            }
            Error::VarNodeOffsetIsNotConstant => {
                f.write_str("Failed to resolve varnode offset as a constant")
            }
            Error::TooManyTemporaries => {
                f.write_str("Exceeded the maximum number of temporaries allowed by the runtime")
            }
            Error::UnsupportedVarNodeSize(size) => write!(f, "Unsupported varnode size: {size}"),
            Error::InvalidExport(id) => {
                write!(f, "Constructor has an invalid export statement (Constructor={id})")
            }
            Error::Internal(str) => write!(f, "sleigh-runtime internal error: {str}"),
        }
    }
}

pub type Result<T> = std::result::Result<T, Error>;

#[derive(Copy, Clone, Debug)]
enum Operand {
    Value(ResolvedValue),
    Pointer(ResolvedValue, u64, u16),
}

impl Operand {
    fn slice(self, offset: u16, size: u16) -> Self {
        match self {
            Self::Value(value) => Self::Value(value.slice(offset, size)),
            Self::Pointer(value, base, _) => Self::Pointer(value, base + offset as u64, size),
        }
    }
}

impl From<VarNode> for Operand {
    fn from(node: VarNode) -> Self {
        Self::Value(ResolvedValue::Var(node))
    }
}

impl From<ResolvedValue> for Operand {
    fn from(value: ResolvedValue) -> Self {
        Self::Value(value)
    }
}

/// Represents a variable a variable with an explicit offset in the SLEIGH specification.
#[derive(Copy, Clone, Debug)]
struct VarNode {
    offset: u32,
    size: u16,
    is_tmp: bool,
}

impl VarNode {
    fn register(offset: u32, size: u16) -> Self {
        Self { offset, size, is_tmp: false }
    }

    fn tmp(offset: u32, size: u16) -> Self {
        Self { offset, size, is_tmp: true }
    }

    fn slice(self, offset: u16, size: u16) -> Self {
        Self { offset: self.offset + offset as u32, size, ..self }
    }
}

#[derive(Copy, Clone, Debug)]
enum ResolvedValue {
    Const(u64, u16),
    Var(VarNode),
}

impl ResolvedValue {
    fn slice(self, offset: u16, size: u16) -> Self {
        match self {
            Self::Const(value, _) => {
                Self::Const((value >> offset) & pcode::mask(size as u64 * 8), size)
            }
            Self::Var(var) => Self::Var(var.slice(offset, size)),
        }
    }

    fn size(&self) -> u16 {
        match self {
            Self::Const(_, size) => *size,
            Self::Var(var) => var.size,
        }
    }
}

impl From<VarNode> for ResolvedValue {
    fn from(node: VarNode) -> Self {
        Self::Var(node)
    }
}

#[derive(Copy, Clone, Debug)]
enum Output {
    Var(VarNode),
    Pointer(ResolvedValue, u64, u16),
}

pub struct Lifter {
    /// The block of operations that have been lifted.
    block: pcode::Block,

    /// Values exported by subtables.
    exports: Vec<Option<Operand>>,

    /// The base index for named temporaries in the active subtable.
    tmp_offset: usize,

    /// The maximum number of temporaries allowed by the runtime.
    tmp_max: usize,

    /// The varnodes allocated to temporaries.
    temps: Vec<VarNode>,

    /// The default size to use for variables that don't specify a size.
    default_size: u16,

    /// Keeps track of temporaries that have a constant value during disassembly time.
    disassembly_constants: HashMap<pcode::VarId, u64>,
}

impl Lifter {
    pub fn new() -> Self {
        Self {
            block: pcode::Block::new(),
            exports: Vec::new(),
            tmp_offset: 0,
            tmp_max: 256,
            temps: Vec::new(),
            default_size: 0,
            disassembly_constants: HashMap::new(),
        }
    }

    pub fn lift(&mut self, sleigh: &SleighData, inst: &Instruction) -> Result<&pcode::Block> {
        self.block.clear();
        self.exports.clear();
        self.exports.resize(inst.subtables.len(), None);

        self.tmp_offset = 0;
        self.temps.clear();
        self.disassembly_constants.clear();

        self.default_size = sleigh.default_space_size;

        self.block.push((pcode::Op::InstructionMarker, (inst.inst_start, inst.num_bytes())));
        self.build_subtable(inst.root(sleigh))?;

        Ok(&self.block)
    }

    fn named_tmp(&mut self, id: u32) -> VarNode {
        self.temps[self.tmp_offset + id as usize]
    }

    fn alloc_tmp(&mut self, size: u16) -> Result<VarNode> {
        if self.temps.len() >= self.tmp_max {
            return Err(Error::TooManyTemporaries);
        }
        let id: u32 = self.temps.len().try_into().unwrap();
        let var = VarNode::tmp(MAX_REG_SIZE as u32 * id, size);
        self.temps.push(var);
        Ok(var)
    }

    fn build_subtable(&mut self, subtable: SubtableCtx) -> Result<Option<Operand>> {
        LifterCtx { lifter: self, subtable }.build_subtable()
    }
}

struct LifterCtx<'a, 'b> {
    lifter: &'a mut Lifter,
    subtable: SubtableCtx<'a, 'b>,
}

impl<'a, 'b> LifterCtx<'a, 'b> {
    fn subtable_export(&self, idx: u32) -> Option<Operand> {
        let export_index = idx + self.subtable.constructor.subtables.0;
        self.lifter.exports[export_index as usize]
    }

    fn subtable_export_mut(&mut self, idx: u32) -> &mut Option<Operand> {
        let export_index = idx + self.subtable.constructor.subtables.0;
        &mut self.lifter.exports[export_index as usize]
    }

    fn build_subtable(&mut self) -> Result<Option<Operand>> {
        // Temporary buffer to store the inputs of an operation before it is emitted.
        let mut resolved_inputs = Vec::new();
        let semantics = self.subtable.semantics();

        let prev_tmp_offset = self.lifter.tmp_offset;
        self.lifter.tmp_offset = self.lifter.temps.len();

        // Reserve space for temporaries that are named in the original sleigh specification.
        for _ in 0..self.subtable.constructor_info().temporaries {
            self.lifter.alloc_tmp(MAX_REG_SIZE as ValueSize)?;
        }

        for action in semantics {
            match action {
                SemanticAction::Op { op, inputs, output } => {
                    let resolved_output = match output {
                        Some(output) => Some(self.resolve_output(output)?),
                        None => None,
                    };
                    // Special case for copy operation to avoid an extra temporary if the input
                    // involves a subtable memory location.
                    if let (pcode::Op::Copy, Some(Output::Var(dst))) = (op, resolved_output) {
                        match self.resolve_operand(inputs[0])? {
                            Operand::Value(value) => self.emit_copy(value, dst)?,
                            Operand::Pointer(addr, offset, _) => {
                                self.emit_load(addr, offset, dst)?
                            }
                        }
                        continue;
                    }

                    resolved_inputs.clear();
                    for input in inputs {
                        resolved_inputs.push(self.resolve_value(*input)?);
                    }

                    match resolved_output {
                        Some(Output::Var(dst)) => self.emit(*op, &resolved_inputs, Some(dst))?,
                        Some(Output::Pointer(addr, offset, size)) => {
                            let dst = self.lifter.alloc_tmp(size)?;
                            self.emit(*op, &resolved_inputs, Some(dst))?;
                            self.emit_store(addr, offset, dst.into())?;
                        }
                        None => self.emit(*op, &resolved_inputs, None)?,
                    }

                    if matches!(op, pcode::Op::PcodeBranch(_) | pcode::Op::PcodeLabel(_)) {
                        self.lifter.disassembly_constants.clear()
                    }
                }
                SemanticAction::AddressOf { output, base, offset } => {
                    let base = match base {
                        Local::Subtable(idx) => {
                            match self.subtable_export(*idx).ok_or(Error::InvalidVarNode)? {
                                Operand::Value(value) => match value {
                                    ResolvedValue::Const(x, _) => x,
                                    ResolvedValue::Var(x) if !x.is_tmp => x.offset as u64,
                                    _ => return Err(Error::AddressOfTemporary),
                                },
                                Operand::Pointer(value, offset, _) => match value {
                                    ResolvedValue::Const(x, _) => x + offset,
                                    ResolvedValue::Var(x) if !x.is_tmp => x.offset as u64 + offset,
                                    _ => return Err(Error::AddressOfTemporary),
                                },
                            }
                        }
                        Local::InstStart => self.subtable.inst_start,
                        Local::InstNext => self.subtable.inst_next,
                        _ => return Err(Error::Internal("dynamic address of non subtable")),
                    };
                    let offset = match self.resolve_value(*offset)? {
                        ResolvedValue::Const(x, _) => x,
                        ResolvedValue::Var(_) => return Err(Error::VarNodeOffsetIsNotConstant),
                    };

                    let address = offset + base;
                    match self.resolve_output(output)? {
                        Output::Var(dst) => {
                            self.emit_copy(ResolvedValue::Const(address, dst.size), dst)?
                        }
                        Output::Pointer(dst, offset, size) => {
                            self.emit_store(dst, offset, ResolvedValue::Const(address, size))?
                        }
                    };
                }
                SemanticAction::LoadRegister { pointer, output, size } => {
                    let var = self.resolve_dynamic_varnode(pointer, *size)?;
                    match self.resolve_output(output)? {
                        Output::Var(dst) => self.emit_copy(var.into(), dst)?,
                        Output::Pointer(addr, offset, size) => {
                            self.emit_store(addr, offset, var.slice(0, size).into())?;
                        }
                    }
                }
                SemanticAction::StoreRegister { pointer, value, size } => {
                    let var = self.resolve_dynamic_varnode(pointer, *size)?;
                    let value = self.resolve_value(*value)?;
                    self.emit_copy(value, var.into())?;
                }
                SemanticAction::DelaySlot => {
                    // @todo: do we want an instruction marker here?
                    //
                    // Without it, single stepping will execute both the branch and the delay slot
                    // at -- but having it complicates the emulator design (since the instruction
                    // marker will reference the wrong PC)
                    let constructor = self.subtable.visit_constructor(
                        self.subtable.delay_slot.expect("sleigh-runtime: expected delayslot"),
                    );
                    self.lifter.build_subtable(constructor)?;
                }
                SemanticAction::Build(idx) => {
                    let constructor =
                        self.subtable.visit_constructor(self.subtable.subtables()[*idx as usize]);

                    let export = self.lifter.build_subtable(constructor)?;
                    *self.subtable_export_mut(*idx) = export;
                }
            }
        }

        let export = match self.subtable.constructor_info().export {
            Some(inner) => Some(self.resolve_export(inner)?),
            None => None,
        };
        self.lifter.tmp_offset = prev_tmp_offset;
        Ok(export)
    }

    fn resolve_dynamic_varnode(&mut self, pointer: &Value, size: u16) -> Result<VarNode> {
        let value = self.resolve_value(*pointer)?;
        match self.get_runtime_value(value)? {
            pcode::Value::Const(offset, _) => Ok(VarNode::register(offset as u32, size)),
            pcode::Value::Var(_) => Err(Error::VarNodeOffsetIsNotConstant),
        }
    }

    /// Returns the runtime register associated with the provided variable.
    fn get_runtime_var(&mut self, var: VarNode) -> Result<pcode::VarNode> {
        let size = self.resolve_var_size(var.size)?;
        if var.is_tmp {
            let (tmp_id, offset) =
                (var.offset / MAX_REG_SIZE as u32, var.offset % MAX_REG_SIZE as u32);
            let id = -i16::try_from(tmp_id + 1).unwrap();
            return Ok(pcode::VarNode::new(id, MAX_REG_SIZE).slice(offset as u8, size));
        }

        match self.subtable.data.register_mapping.get(&var.offset) {
            Some(&(id, offset)) => Ok(pcode::VarNode::new(id, MAX_REG_SIZE).slice(offset, size)),
            None => Err(Error::UnknownVarNode(var.offset, size)),
        }
    }

    fn get_runtime_value(&mut self, value: ResolvedValue) -> Result<pcode::Value> {
        match value {
            ResolvedValue::Var(var) => {
                let varnode = self.get_runtime_var(var)?;
                Ok(match self.lifter.disassembly_constants.get(&varnode.id) {
                    Some(x) => pcode::Value::Const(varnode.extract_from_const(*x), varnode.size),
                    None => varnode.into(),
                })
            }
            ResolvedValue::Const(value, size) => {
                Ok(pcode::Value::Const(value, self.resolve_var_size(size)?))
            }
        }
    }

    fn resolve_export(&mut self, inner: Export) -> Result<Operand> {
        match inner {
            Export::Value(value) => Ok(self.resolve_value(value)?.into()),
            Export::RamRef(ptr, size) => Ok(Operand::Pointer(self.resolve_value(ptr)?, 0, size)),
            Export::RegisterRef(offset, size) => match self.resolve_value(offset)? {
                ResolvedValue::Var(_) => Err(Error::InvalidExport(self.subtable.constructor.id)),
                ResolvedValue::Const(x, _) => Ok(VarNode::register(x as u32, size).into()),
            },
        }
    }

    fn resolve_operand(&mut self, value: Value) -> Result<Operand> {
        macro_rules! constant {
            ($value:expr) => {{
                if value.offset != 0 {
                    return Err(Error::InvalidVarNode);
                }
                let size = value.size.unwrap_or(self.lifter.default_size);
                ResolvedValue::Const($value, size).into()
            }};
        }

        let value_offset = value.offset;
        let value_size = value.size.unwrap_or(self.lifter.default_size);

        Ok(match value.local {
            Local::InstStart => constant!(self.subtable.inst.inst_start),
            Local::InstNext => constant!(self.subtable.inst.inst_next),
            Local::Register(id) => {
                let base_offset = self.subtable.data.named_registers[id as usize].offset;
                VarNode::register(base_offset + value_offset as u32, value_size).into()
            }
            Local::Field(idx) => {
                let field = self.subtable.fields()[idx as usize];
                let local = self.subtable.locals()[idx as usize];
                match field.attached {
                    Some(attachment) => {
                        let var = self.evaluate_attachment(local, attachment)?;
                        var.slice(value.offset, value_size)
                    }
                    None => constant!(local as u64),
                }
            }
            Local::Subtable(idx) => {
                let var = self.subtable_export(idx).ok_or(Error::InvalidVarNode)?;
                var.slice(value.offset, value_size)
            }
            Local::SubtableRef(idx) => {
                match self.subtable_export(idx).ok_or(Error::InvalidVarNode)? {
                    Operand::Value(value) => value.slice(value_offset, value_size).into(),
                    Operand::Pointer(var, base, size) => {
                        let offset = base.try_into().map_err(|_| Error::InvalidVarNode)?;
                        var.slice(offset, size).into()
                    }
                }
            }
            Local::PcodeTmp(id) => {
                let var = self.lifter.named_tmp(id);
                var.slice(value.offset, value_size).into()
            }
            Local::Constant(x) => constant!(x),
        })
    }

    fn evaluate_attachment(&mut self, value: i64, id: AttachmentId) -> Result<Operand> {
        use crate::AttachmentRef;

        Ok(match self.subtable.data.get_attachment(id) {
            AttachmentRef::Name(_) => {
                ResolvedValue::Const(value as u64, self.lifter.default_size).into()
            }
            AttachmentRef::Value(values) => {
                let value = *values.get(value as usize).ok_or(Error::InvalidVarNode)?;
                ResolvedValue::Const(value as u64, self.lifter.default_size).into()
            }
            AttachmentRef::Register(regs, size) => {
                let reg = regs.get(value as usize).and_then(|x| *x).ok_or(Error::InvalidVarNode)?;
                VarNode::register(reg.offset, size).into()
            }
        })
    }

    fn resolve_value(&mut self, value: Value) -> Result<ResolvedValue> {
        Ok(match self.resolve_operand(value)? {
            Operand::Value(value) => value,
            Operand::Pointer(addr, offset, size) => {
                let dst = self.lifter.alloc_tmp(size)?;
                self.emit_load(addr, offset, dst)?;
                dst.into()
            }
        })
    }

    fn resolve_output(&mut self, output: &Value) -> Result<Output> {
        match self.resolve_operand(*output)? {
            // Workaround for bug in RISC-V spec: Treat writing to a constant zero as discarding the
            // output.
            Operand::Value(ResolvedValue::Const(0, _)) => {
                // Discard the input by writing to a temporary (const-eval will remove the dead
                // operation if it has no other side-effects).
                let size = output.size.unwrap_or(self.lifter.default_size);
                let var = self.lifter.alloc_tmp(size)?;
                Ok(Output::Var(var))
            }
            // Non-zero constants are treated as errors to catch bugs.
            Operand::Value(ResolvedValue::Const(..)) => Err(Error::WriteToConstant),
            Operand::Value(ResolvedValue::Var(var)) => Ok(Output::Var(var)),
            Operand::Pointer(base, offset, size) => Ok(Output::Pointer(base, offset, size)),
        }
    }

    fn emit(
        &mut self,
        op: pcode::Op,
        inputs: &[ResolvedValue],
        output: Option<VarNode>,
    ) -> Result<()> {
        if let Some(output) = output {
            // Handle special cases to support operating on large varnodes.
            if output.size > MAX_REG_SIZE as ValueSize {
                return match op {
                    pcode::Op::Copy => self.emit_copy(inputs[0], output),
                    pcode::Op::ZeroExtend => {
                        self.emit_copy(inputs[0], output.slice(0, inputs[0].size()))?;
                        self.emit_copy(
                            ResolvedValue::Const(0, 8),
                            output.slice(inputs[0].size(), output.size - inputs[0].size()),
                        )
                    }
                    pcode::Op::Load(_) => self.emit_load(inputs[0], 0, output),

                    // Varnode size too large for this operation.
                    _ => Err(Error::UnsupportedVarNodeSize(output.size)),
                };
            }

            // If there were any subpiece operations that were not able to be resolved statically
            // then handle them here:
            //
            // @remove? All tested specifications appear to not need this.
            if let pcode::Op::Subpiece(offset) = op {
                return self.emit_copy(inputs[0].slice(offset as ValueSize, output.size), output);
            }

            // Rewrite sign/zero extension to the same or smaller sized output to a copy operation.
            if matches!(op, pcode::Op::SignExtend | pcode::Op::ZeroExtend)
                && output.size <= inputs[0].size()
            {
                return self.emit_copy(inputs[0].slice(0, output.size), output);
            }

            // Rewrite float-to-float casts to same sized values to copy operations.
            if matches!(op, pcode::Op::FloatToFloat) && output.size == inputs[0].size() {
                return self.emit_copy(inputs[0], output);
            }
        }

        let inputs = self.get_runtime_inputs(inputs)?;
        match output {
            Some(output) => {
                let dst = self.get_runtime_var(output)?;
                self.push((dst, op, inputs))
            }
            None => self.push((op, inputs)),
        }

        Ok(())
    }

    fn get_runtime_inputs(&mut self, inputs: &[ResolvedValue]) -> Result<pcode::Inputs> {
        Ok(match inputs {
            [] => pcode::Inputs::none(),
            [a] => pcode::Inputs::one(self.get_runtime_value(*a)?),
            [a, b, rest @ ..] => {
                let inputs =
                    pcode::Inputs::new(self.get_runtime_value(*a)?, self.get_runtime_value(*b)?);

                // If there are additional inputs then add them as additional arguments.
                for (i, input) in rest.iter().enumerate() {
                    let value = self.get_runtime_value(*input)?;
                    self.push((pcode::Op::Arg(i as u16), pcode::Inputs::one(value)));
                }

                inputs
            }
        })
    }

    fn emit_copy(&mut self, src: ResolvedValue, dst: VarNode) -> Result<()> {
        self.split_large_op(dst, |this, i, dst| {
            let src = this.get_runtime_value(src.slice(i, dst.size))?;
            let dst = this.get_runtime_var(dst)?;
            this.push(src.copy_to(dst));
            if dst.is_temp() && src.is_const() {
                this.lifter.disassembly_constants.insert(dst.id, src.as_u64());
            }
            Ok(())
        })
    }

    fn emit_load(&mut self, addr: ResolvedValue, offset: u64, dst: VarNode) -> Result<()> {
        self.split_large_op(dst, |this, i, dst| {
            let addr = this.emit_add_offset(addr, offset + i as u64)?;
            let dst = this.get_runtime_var(dst)?;
            this.push((dst, pcode::Op::Load(0), addr));
            Ok(())
        })
    }

    fn emit_store(&mut self, addr: ResolvedValue, offset: u64, value: ResolvedValue) -> Result<()> {
        match value {
            ResolvedValue::Const(value, size) => {
                let addr = self.emit_add_offset(addr, offset)?;
                let value = pcode::Value::Const(value, self.resolve_var_size(size)?);
                self.push((pcode::Op::Store(0), pcode::Inputs::new(addr, value)));
            }
            ResolvedValue::Var(var) => self.split_large_op(var, |this, i, value| {
                let addr = this.emit_add_offset(addr, offset + i as u64)?;
                let var = this.get_runtime_var(value)?;
                this.push((pcode::Op::Store(0), pcode::Inputs::new(addr, var)));
                Ok(())
            })?,
        }
        Ok(())
    }

    /// Adjust a base address by an offset, either by folding the offset into the address if `base`
    /// is constant, or by using a temporary variable.
    fn emit_add_offset(&mut self, base: ResolvedValue, offset: u64) -> Result<pcode::Value> {
        if offset == 0 {
            return self.get_runtime_value(base);
        }
        if let ResolvedValue::Const(base, size) = base {
            return Ok(pcode::Value::Const(base + offset, self.resolve_var_size(size)?));
        }

        let addr = {
            let tmp = self.lifter.alloc_tmp(self.lifter.default_size)?;
            self.get_runtime_var(tmp)?
        };
        let base = self.get_runtime_value(base)?;
        self.push((addr, pcode::Op::IntAdd, pcode::Inputs::new(base, offset)));
        Ok(addr.into())
    }

    /// Operations on values >128 bits not supported natively by the emulator so we need to split
    /// them into operations on 128 bit chunks.
    ///
    /// This helper method handles splitting `var` into chunks and calling `func` on each chunk.
    fn split_large_op(
        &mut self,
        var: VarNode,
        mut func: impl FnMut(&mut Self, ValueSize, VarNode) -> Result<()>,
    ) -> Result<()> {
        if var.size > MAX_REG_SIZE as ValueSize {
            if var.size % MAX_REG_SIZE as ValueSize != 0 {
                return Err(Error::UnsupportedVarNodeSize(var.size));
            }
            for i in (0..var.size).step_by(MAX_REG_SIZE as usize) {
                func(self, i, var.slice(i, MAX_REG_SIZE as ValueSize))?;
            }
        }
        else {
            func(self, 0, var)?;
        }

        Ok(())
    }

    pub fn push(&mut self, instruction: impl Into<pcode::Instruction>) {
        let inst = instruction.into();
        self.lifter.disassembly_constants.remove(&inst.output.id);
        self.lifter.block.instructions.push(inst);
    }

    fn resolve_var_size(&self, size: ValueSize) -> Result<pcode::VarSize> {
        let size: u8 = size.try_into().map_err(|_| Error::UnsupportedVarNodeSize(size))?;
        if size > MAX_REG_SIZE {
            return Err(Error::UnsupportedVarNodeSize(size as ValueSize));
        }
        Ok(size)
    }
}
