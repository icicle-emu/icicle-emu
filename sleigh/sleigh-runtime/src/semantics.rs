pub type ValueSize = u16;

#[derive(Debug, Clone)]
pub enum SemanticAction {
    Op { op: pcode::Op, inputs: Vec<Value>, output: Option<Value> },
    CopyFromDynamicRegister { pointer: Value, output: Value, size: ValueSize },
    CopyToDynamicRegister { pointer: Value, value: Value, size: ValueSize },
    DelaySlot,
    Build(u32),
}

#[derive(Debug, Copy, Clone, PartialEq, Eq)]
pub struct Value {
    /// The underlying local variable that the value is derived from.
    pub local: Local,

    /// The byte offset of the value from the start of the local.
    pub offset: ValueSize,

    /// If not None, this value represents an address with the offset stored the saved local.
    pub address_offset: Option<Local>,

    /// The size of the value in bytes.
    pub size: Option<ValueSize>,
}

impl Value {
    pub fn constant(value: u64) -> Self {
        Self { local: Local::Constant(value), offset: 0, address_offset: None, size: None }
    }

    pub fn truncate(self, size: ValueSize) -> Self {
        Self { size: Some(size), ..self }
    }

    pub fn maybe_set_size(self, size: Option<ValueSize>) -> Self {
        Self { size: size.or(self.size), ..self }
    }

    pub fn slice_bytes(mut self, offset: ValueSize, size: ValueSize) -> Self {
        self.offset += offset;
        self.truncate(size)
    }
}

impl From<Local> for Value {
    fn from(local: Local) -> Self {
        Self { local, offset: 0, size: None, address_offset: None }
    }
}

/// Encodes the value exported by the constructor.
#[derive(Debug, Copy, Clone, PartialEq, Eq)]
pub enum Export {
    /// A statically computed value.
    Value(Value),

    /// A pointer to an address in the RAM space.
    Pointer(Value, ValueSize),

    /// A dynamically computed register.
    Register(Value, ValueSize),
}

impl Export {
    pub fn size(&self) -> Option<ValueSize> {
        match self {
            Self::Value(inner) => inner.size,
            Self::Pointer(_, size) => Some(*size),
            Self::Register(_, size) => Some(*size),
        }
    }
}

#[derive(Debug, Copy, Clone, PartialEq, Eq)]
pub enum Local {
    /// The address of the current instruction.
    InstStart,

    /// The address of the next instruction.
    InstNext,

    /// A reference to a register
    Register(u32),

    /// A field declared in either the constraint expression or disassembly actions section
    Field(u32),

    /// A reference to the exported value of a subtable.
    ///
    /// Note: this represents the offset into `constructor.subtables` not the TableId.
    Subtable(u32),

    /// Represents a temporary inside of the semantics section
    PcodeTmp(u32),

    /// Represents a constant inside of the semantics section
    Constant(u64),
}
