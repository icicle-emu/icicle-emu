use crate::{
    decoder::SubtableCtx,
    semantics::{Export, SemanticAction, Value, ValueSize},
    ConstructorId, Instruction, SleighData,
};

/// The size (in bytes) of the largest supported register for the runtime.
const MAX_REG_SIZE: u8 = 16;

#[derive(Clone, Debug)]
pub enum Error {
    /// The specification contained an operation that attempted to write to a constant.
    WriteToConstant,

    /// Attempted to perform an operation on an invalid VarNode.
    InvalidVarNode,

    /// Attempted to resolve an unknown VarNode.
    UnknownVarNode(u32, u8),

    /// Exceeded the maximum number of temporaries allowed by the runtime.
    TooManyTemporaries,

    /// Tried to handle a varnode with an unexpected size.
    UnsupportedVarNodeSize(ValueSize),

    /// The constructor had an invalid export statement.
    InvalidExport(ConstructorId),

    /// We encounted an a currently unsupported sleigh feature.
    Unimplemented(&'static str),
}

impl std::error::Error for Error {}

impl std::fmt::Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Error::WriteToConstant => f.write_str("Attempted to write to a constant"),
            Error::InvalidVarNode => f.write_str("Invalid varnode"),
            Error::UnknownVarNode(offset, size) => {
                write!(f, "Unknown varnode offset: {:#0x}, size: {}", offset, size)
            }
            Error::TooManyTemporaries => f.write_str("Too many temporaries"),
            Error::UnsupportedVarNodeSize(size) => write!(f, "Unsupported varnode size: {}", size),
            Error::InvalidExport(id) => write!(f, "Invalid export: Constructor({})", id),
            Error::Unimplemented(str) => write!(f, "Unimplemented: {}", str),
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
    None,
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
        }
    }

    pub fn lift(&mut self, sleigh: &SleighData, inst: &Instruction) -> Result<&pcode::Block> {
        self.block.clear();
        self.exports.clear();
        self.exports.resize(inst.subtables.len(), None);

        self.tmp_offset = 0;
        self.temps.clear();

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
        self.lifter.exports[export_index as usize].clone()
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

        // Reserve space for "named" temporaries.
        for _ in 0..self.subtable.constructor_info().temporaries {
            self.lifter.alloc_tmp(MAX_REG_SIZE as ValueSize)?;
        }

        for action in semantics {
            match action {
                SemanticAction::Op { op, inputs, output } => {
                    let resolved_output = self.resolve_output(output)?;
                    // Special case for copy operation to avoid an extra temporary if the input
                    // involves a subtable memory location.
                    if let (pcode::Op::Copy, Output::Var(dst)) = (op, resolved_output) {
                        match self.resolve_operand(inputs[0])? {
                            Operand::Value(value) => self.emit_copy(value, dst)?,
                            Operand::Pointer(addr, offset, _) => {
                                self.emit_load(addr, offset, dst)?;
                            }
                        }
                        continue;
                    }

                    resolved_inputs.clear();
                    for input in inputs {
                        resolved_inputs.push(self.resolve_value(*input)?);
                    }

                    match resolved_output {
                        Output::Var(dst) => self.emit(*op, &resolved_inputs, Some(dst))?,
                        Output::Pointer(addr, offset, size) => {
                            let dst = self.lifter.alloc_tmp(size)?;
                            self.emit(*op, &resolved_inputs, Some(dst))?;
                            self.emit_store(addr, offset, dst.into())?;
                        }
                        Output::None => self.emit(*op, &resolved_inputs, None)?,
                    }
                }
                SemanticAction::DelaySlot => {
                    // @todo: do we want an instruction marker here?
                    //
                    // Without it, single stepping will execute both the branch and the delay slot
                    // at -- but having it complicates the emulator design (since the instruction
                    // marker will reference the wrong PC)
                    let constructor = self.subtable.visit_constructor(
                        self.subtable.delay_slot.expect("sleigh-runtime error: expected delayslot"),
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
            ResolvedValue::Var(var) => Ok(self.get_runtime_var(var)?.into()),
            ResolvedValue::Const(value, size) => {
                Ok(pcode::Value::Const(value, self.resolve_var_size(size)?))
            }
        }
    }

    fn resolve_export(&mut self, inner: Export) -> Result<Operand> {
        match inner {
            Export::Value(value) => Ok(self.resolve_value(value)?.into()),
            Export::Pointer(ptr, size) => Ok(Operand::Pointer(self.resolve_value(ptr)?, 0, size)),
            Export::Register(offset, size) => match self.resolve_value(offset)? {
                ResolvedValue::Var(_) => Err(Error::InvalidExport(self.subtable.constructor.id)),
                ResolvedValue::Const(offset, _) => {
                    Ok(VarNode::register(offset as u32, size).into())
                }
            },
        }
    }

    fn resolve_operand(&mut self, value: Value) -> Result<Operand> {
        use crate::semantics::Local;

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
        let value_size = value.size.map(|x| x).unwrap_or(self.lifter.default_size);

        Ok(match value.local {
            Local::InstStart => constant!(self.subtable.inst.inst_start as u64),
            Local::InstNext => constant!(self.subtable.inst.inst_next as u64),
            Local::Register(id) => {
                let base_offset = self.subtable.data.named_registers[id as usize].offset as u32;
                VarNode::register(base_offset + value_offset as u32, value_size).into()
            }
            Local::Field(idx) => {
                let field = self.subtable.fields()[idx as usize];
                let local = self.subtable.locals()[idx as usize];
                match field.attached {
                    Some(attachment) => {
                        let var = self.evaluate_attachment(local, attachment)?;
                        var.slice(value.offset, value_size).into()
                    }
                    None => constant!(local as u64),
                }
            }
            Local::Subtable(idx) => {
                let var = self.subtable_export(idx).ok_or(Error::InvalidVarNode)?;
                var.slice(value.offset, value_size)
            }
            Local::SubtableAddr(idx) => {
                match self.subtable_export(idx).ok_or(Error::InvalidVarNode)? {
                    Operand::Value(value) => value.slice(value_offset, value_size).into(),
                    Operand::Pointer(var, offset, size) => {
                        let offset = offset.try_into().map_err(|_| Error::InvalidVarNode)?;
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

    fn evaluate_attachment(&mut self, value: i64, id: u32) -> Result<Operand> {
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

    fn resolve_output(&mut self, output: &Option<Value>) -> Result<Output> {
        let value = match output {
            Some(value) => *value,
            None => return Ok(Output::None),
        };

        match self.resolve_operand(value)? {
            // Workaround for bug in RISC-V spec: Treat writing to a constant zero as discarding the
            // output.
            Operand::Value(ResolvedValue::Const(0, _)) => {
                // Discard the input by writing to a temporary.
                let size = value.size.unwrap_or(self.lifter.default_size);
                let var = self.lifter.alloc_tmp(size)?;
                return Ok(Output::Var(var));
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
            // Handle special cases to support operating on large varnodes
            if output.size > MAX_REG_SIZE as ValueSize {
                return match op {
                    pcode::Op::Copy => self.emit_copy(inputs[0], output),
                    pcode::Op::Subpiece(_) => {
                        Err(Error::Unimplemented("Subpiece operation on large varnode"))
                    }
                    pcode::Op::ZeroExtend => {
                        self.emit_copy(inputs[0], output.slice(0, inputs[0].size()))?;
                        self.emit_copy(
                            ResolvedValue::Const(0, 8),
                            output.slice(inputs[0].size(), output.size - inputs[0].size()),
                        )
                    }
                    pcode::Op::Load(_) => self.emit_load(inputs[0], 0, output),

                    // Varnode size too large for this operations
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

            if matches!(op, pcode::Op::SignExtend | pcode::Op::ZeroExtend)
                && output.size <= inputs[0].size()
            {
                return self.emit_copy(inputs[0].slice(0, output.size), output);
            }
        }

        let inputs = self.get_runtime_inputs(inputs)?;
        match output {
            Some(output) => {
                let dst = self.get_runtime_var(output)?;
                self.lifter.block.push((dst, op, inputs))
            }
            None => self.lifter.block.push((op, inputs)),
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
                    self.lifter.block.push((pcode::Op::Arg(i as u16), pcode::Inputs::one(value)));
                }

                inputs
            }
        })
    }

    fn emit_copy(&mut self, src: ResolvedValue, dst: VarNode) -> Result<()> {
        self.split_large_op(dst, |this, i, dst| {
            let src = this.get_runtime_value(src.slice(i, dst.size))?;
            let dst = this.get_runtime_var(dst)?;
            this.lifter.block.push(src.copy_to(dst));
            Ok(())
        })
    }

    fn emit_load(&mut self, addr: ResolvedValue, offset: u64, dst: VarNode) -> Result<()> {
        self.split_large_op(dst, |this, i, dst| {
            let addr = this.emit_add_offset(addr, offset + i as u64)?;
            let dst = this.get_runtime_var(dst)?;
            this.lifter.block.push((dst, pcode::Op::Load(0), addr));
            Ok(())
        })
    }

    fn emit_store(&mut self, addr: ResolvedValue, offset: u64, value: ResolvedValue) -> Result<()> {
        match value {
            ResolvedValue::Const(value, size) => {
                let addr = self.emit_add_offset(addr, offset)?;
                let value = pcode::Value::Const(value, self.resolve_var_size(size)?);
                self.lifter.block.push((pcode::Op::Store(0), pcode::Inputs::new(addr, value)));
            }
            ResolvedValue::Var(var) => self.split_large_op(var, |this, i, value| {
                let addr = this.emit_add_offset(addr, offset + i as u64)?;
                let var = this.get_runtime_var(value)?;
                this.lifter.block.push((pcode::Op::Store(0), pcode::Inputs::new(addr, var)));
                Ok(())
            })?,
        }
        Ok(())
    }

    /// Adjust a base address by an offset, either by folding the offset into the address if `base`
    /// is constant, or by using a temporary variable.
    fn emit_add_offset(&mut self, base: ResolvedValue, offset: u64) -> Result<pcode::Value> {
        if offset == 0 {
            return Ok(self.get_runtime_value(base)?);
        }
        if let ResolvedValue::Const(base, size) = base {
            return Ok(pcode::Value::Const(base + offset, self.resolve_var_size(size)?));
        }

        let addr = {
            let tmp = self.lifter.alloc_tmp(self.lifter.default_size)?;
            self.get_runtime_var(tmp)?
        };
        let base = self.get_runtime_value(base)?;
        self.lifter.block.push((addr, pcode::Op::IntAdd, pcode::Inputs::new(base, offset)));
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

    fn resolve_var_size(&self, size: ValueSize) -> Result<pcode::VarSize> {
        let size: u8 = size.try_into().map_err(|_| Error::UnsupportedVarNodeSize(size))?;
        if size > MAX_REG_SIZE {
            return Err(Error::UnsupportedVarNodeSize(size as ValueSize));
        }
        Ok(size)
    }
}
