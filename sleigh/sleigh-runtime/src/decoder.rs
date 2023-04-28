use crate::{
    semantics::SemanticAction, Constructor, DecodeAction, DisplaySegment, EvalKind, LocalIndex,
    SleighData, DEBUG, ROOT_TABLE_ID,
};

use crate::{
    expr::{eval_disasm_expr, DisasmExprRange, EvalDisasmValue},
    ConstructorId, Field, TableId, Token,
};

/// The Non-mutable data from the Decoder
#[derive(Default)]
pub(crate) struct DecoderData {
    /// The bytes in the instruction stream.
    bytes: Vec<u8>,

    /// Configures whether token fields should be decoded as big endian.
    pub big_endian: bool,

    /// The base address of the instruction stream.
    base_addr: u64,
}

/// The Mutable data from the Decoder
#[derive(Default)]
pub(crate) struct DecoderState {
    /// The global decoder context.
    pub global_context: u64,

    /// The local context value.
    pub(crate) context: u64,

    /// The offset of the current token in instruction stream.
    offset: usize,

    /// The offset of the next token in instruction stream.
    next_offset: usize,

    /// The stack of token offsets for storing parent token positions.
    token_stack: Vec<usize>,

    /// A stack for storing intermediate values used for evaluating expressions.
    eval_stack: Vec<i64>,
}

/// The decoder context for the current instruction.
#[derive(Default)]
pub struct Decoder {
    pub(crate) data: DecoderData,
    pub(crate) state: DecoderState,
}

impl Decoder {
    pub fn new(bytes: Vec<u8>, big_endian: bool, base_addr: u64) -> Self {
        Self {
            data: DecoderData {
                bytes,
                big_endian,
                base_addr,
            },
            state: DecoderState::default(),
        }
    }
    /// Decode the current instruction storing the result in `inst`.
    pub fn decode_into(&mut self, sleigh: &SleighData, inst: &mut Instruction) -> Option<()> {
        self.data.big_endian = sleigh.big_endian;
        let mut inner = InnerDecoder {
            data: &self.data,
            state: &mut self.state,
        };
        inner.decode_into(sleigh, inst)
    }

    pub fn set_inst(&mut self, base_addr: u64, bytes: &[u8]) {
        self.state.context = 0;
        self.data.base_addr = base_addr;
        self.state.offset = 0;
        self.state.next_offset = 0;
        self.data.bytes.clear();
        self.data.bytes.extend_from_slice(bytes);
    }

    pub fn context(&self) -> u64 {
        self.state.global_context
    }

    pub fn set_context(&mut self, context: u64) {
        self.state.global_context = context;
    }
}

pub(crate) struct InnerDecoder<'a, 'b> {
    pub data: &'a DecoderData,
    pub state: &'b mut DecoderState,
}

impl<'a, 'b> InnerDecoder<'a, 'b> {
    /// Decode the current instruction storing the result in `inst`.
    pub fn decode_into(&mut self, sleigh: &SleighData, inst: &mut Instruction) -> Option<()> {
        // Clear any noflow fields from `global_context`
        for entry in sleigh.context_fields.iter().filter(|entry| !entry.flow) {
            entry.field.set(&mut self.state.global_context, 0);
        }

        let root = inst.init();

        let constructor = self.decode_subtable(sleigh, inst, ROOT_TABLE_ID)?;
        inst.subtables[root as usize] = constructor;

        inst.root_mut(sleigh).eval_disasm_expr(self);

        // Delay slots need to be decoded _before_ the semantic section is evaluated because the
        // specification requires that `inst_next` refers to the address after the delay slot.
        //
        // Note: this differs from the behaviour of the disassembly section, where `inst_next`
        // refers to the address immediately after the first instruction.
        if let Some(_) = inst.delay_slot {
            self.state.offset = self.state.next_offset;
            inst.delay_slot = Some(self.decode_subtable(sleigh, inst, ROOT_TABLE_ID)?);
        }

        inst.inst_start = self.data.base_addr;
        inst.inst_next = self.data.base_addr + self.state.next_offset as u64;

        Some(())
    }

    fn decode_subtable(
        &mut self,
        sleigh: &SleighData,
        inst: &mut Instruction,
        table: TableId,
    ) -> Option<DecodedConstructor> {
        let constructors = sleigh.match_constructors_with(
            self.bytes_offset(),
            self.data.big_endian,
            self.state.context,
            table,
        );
        // info required to rever the decoder to the initial state
        let initial_offset = self.state.offset;
        let initial_next_offset = self.state.next_offset;
        let initial_context = self.state.context;
        let initial_global_context = self.state.global_context;
        let initial_token_stack_len = self.state.token_stack.len();
        // try all the constructors
        for constructor_id in constructors {
            match self.decode_subtable_constructor(sleigh, inst, table, constructor_id) {
                Some(decoded) => return Some(decoded),
                //just backtrack and try with the next constructor
                None => {
                    self.state.offset = initial_offset;
                    self.state.next_offset = initial_next_offset;
                    self.state.context = initial_context;
                    self.state.global_context = initial_global_context;
                    self.state.token_stack.truncate(initial_token_stack_len);
                }
            }
        }
        inst.last_subtable = table;
        None
    }

    fn decode_subtable_constructor(
        &mut self,
        sleigh: &SleighData,
        inst: &mut Instruction,
        table: TableId,
        constructor_id: ConstructorId,
    ) -> Option<DecodedConstructor> {
        let mut ctx = inst.alloc_constructor(sleigh, constructor_id).ok()?;
        let mut next = self.state.next_offset;

        if DEBUG {
            eprintln!(
                "[{:>2}] constructor={}, offset={}, next={next} actions={:?}",
                table,
                constructor_id,
                self.state.offset,
                ctx.as_ref().decode_actions()
            );
        }

        self.state.next_offset = self.state.offset;
        for action in ctx.as_ref().decode_actions() {
            match action {
                DecodeAction::ModifyContext(field, expr) => {
                    let value = self.eval_context_expr(*expr, sleigh);
                    field.set(&mut self.state.context, value);
                }
                DecodeAction::SaveContext(field) => {
                    let value = field.extract(self.state.context);
                    field.set(&mut self.state.global_context, value);
                }
                DecodeAction::Eval(idx, kind) => {
                    ctx.locals_mut()[*idx as usize] = match kind {
                        EvalKind::ContextField(field) => field.extract(self.state.context),
                        EvalKind::TokenField(token, field) => field.extract(self.get_token(*token)),
                    };
                }
                DecodeAction::Subtable(idx, id) => {
                    let constructor = self.decode_subtable(sleigh, ctx.inst, *id)?;
                    ctx.subtables_mut()[*idx as usize] = constructor;
                }
                DecodeAction::NextToken(size) => {
                    // Most of the time the sleigh spec uses explicit expand tokens (i.e. `...`) to
                    // handle the case where a previous token expands to a longer token, however the
                    // MSP430X spec seems not to do this (e.g. `MOVX.W &0, R10`).
                    //
                    // To work around this we always perform an implicit `ExpandStart` on every
                    // token.
                    //
                    //@todo: check this behaviour.
                    next = next.max(self.state.next_offset);
                    self.state.next_offset = self.state.offset + *size as usize;
                }
                DecodeAction::GroupStart => self.group_start(),
                DecodeAction::GroupEnd => self.group_end(),
                DecodeAction::ExpandStart => next = next.max(self.state.next_offset),
                DecodeAction::ExpandEnd => self.state.next_offset = self.state.next_offset.max(next),
            }
        }
        self.state.next_offset = next.max(self.state.next_offset);

        Some(ctx.constructor)
    }

    fn eval_context_expr(&mut self, expr: DisasmExprRange, sleigh: &SleighData) -> i64 {
        let mut stack = std::mem::take(&mut self.state.eval_stack);
        let expr = sleigh.get_context_mod_expr(expr);
        let result =
            eval_disasm_expr(&mut stack, &*self, expr).expect("invalid disassembly expression");
        self.state.eval_stack = stack;
        result
    }

    fn group_start(&mut self) {
        self.state.token_stack.push(self.state.offset);
        self.state.offset = self.state.next_offset;
    }

    fn group_end(&mut self) {
        self.state.offset = self.state.token_stack.pop().unwrap();
    }

    pub fn bytes_offset(&self) -> &'a [u8] {
        &self.data.bytes[self.state.offset..]
    }

    pub(crate) fn get_token(&self, token: Token) -> u64 {
        token.get_token(self.bytes_offset(), self.data.big_endian)
    }
}

pub type LocalsSlice = (u32, u32);
pub type SubtablesSlice = (u32, u32);

#[derive(Debug, Default, Clone)]
pub struct Instruction {
    /// The values of local fields references by the instruction.
    pub(crate) locals: Vec<i64>,

    /// The decoded constructors for each subtable reference by the instruction including subtables
    /// referenced by a potential delay slot.
    pub(crate) subtables: Vec<DecodedConstructor>,

    /// The root level constructor for the instruction in the delay slot (if present).
    pub(crate) delay_slot: Option<DecodedConstructor>,

    /// The address of the instruction.
    pub inst_start: u64,

    /// The address of the next instruction.
    pub inst_next: u64,

    /// Keeps track of the last subtable that we failed to find a constructor for.
    pub last_subtable: u32,
}

impl Instruction {
    pub fn init(&mut self) -> u32 {
        self.locals.clear();
        self.subtables.clear();
        self.delay_slot = None;
        self.last_subtable = 0;
        self.reserve_subtables(1).0
    }

    /// Returns the length of the instruction in bytes.
    pub fn num_bytes(&self) -> u64 {
        self.inst_next.checked_sub(self.inst_start).unwrap_or(0)
    }

    /// Reserve `count` local parameters, returning the range of the reserved parameters.
    fn reserve_locals(&mut self, count: u32) -> LocalsSlice {
        let start = self.locals.len();
        self.locals.resize(start + count as usize, 0);
        (start as u32, self.locals.len() as u32)
    }

    /// Reserve `count` subtables, returning the range of the reserved subtables.
    fn reserve_subtables(&mut self, count: u32) -> SubtablesSlice {
        let start = self.subtables.len();
        self.subtables.resize(start + count as usize, DecodedConstructor::default());
        (start as u32, self.subtables.len() as u32)
    }

    fn alloc_constructor<'a, 'b>(
        &'a mut self,
        data: &'b SleighData,
        id: ConstructorId,
    ) -> Result<SubtableCtxMut<'a, 'b>, ()> {
        let constructor = &data.constructors[id as usize];

        if constructor.delay_slot {
            if self.delay_slot.is_some() {
                // @todo: return a proper error message.
                eprintln!("[sleigh]: Nested delay slots are not allowed");
                return Err(());
            }
            self.delay_slot = Some(DecodedConstructor::default());
        }

        let locals = self.reserve_locals(constructor.fields.1 - constructor.fields.0);
        let subtables = self.reserve_subtables(constructor.subtables);
        Ok(SubtableCtxMut {
            inst: self,
            data,
            constructor: DecodedConstructor { id, locals, subtables },
        })
    }

    fn subtable<'a, 'b>(&'a self, data: &'b SleighData, idx: u32) -> SubtableCtx<'a, 'b> {
        let constructor = self.subtables[idx as usize];
        SubtableCtx { inst: self, data, constructor }
    }

    pub fn root_mut<'a, 'b>(&'a mut self, data: &'b SleighData) -> SubtableCtxMut<'a, 'b> {
        let constructor = self.subtables[0];
        SubtableCtxMut { inst: self, data, constructor }
    }

    pub fn root<'a, 'b>(&'a self, data: &'b SleighData) -> SubtableCtx<'a, 'b> {
        self.subtable(data, 0)
    }
}

#[derive(Debug, Default, Copy, Clone)]
pub struct DecodedConstructor {
    /// The ID of the constructor.
    pub id: ConstructorId,

    /// The range of local fields defined by the constructor.
    pub locals: LocalsSlice,

    /// The range of subtable fields defined by the constructor.
    pub subtables: SubtablesSlice,
}

pub struct SubtableCtx<'a, 'b> {
    pub(crate) data: &'b SleighData,
    pub(crate) inst: &'a Instruction,
    pub(crate) constructor: DecodedConstructor,
}

impl std::ops::Deref for SubtableCtx<'_, '_> {
    type Target = Instruction;

    fn deref(&self) -> &Self::Target {
        self.inst
    }
}

impl<'a, 'b> SubtableCtx<'a, 'b> {
    pub fn visit_constructor(&self, constructor: DecodedConstructor) -> Self {
        SubtableCtx { data: self.data, inst: self.inst, constructor }
    }

    pub fn constructor_info(&self) -> &'b Constructor {
        &self.data.constructors[self.constructor.id as usize]
    }

    pub fn decode_actions(&self) -> &'b [DecodeAction] {
        let (start, end) = self.data.constructors[self.constructor.id as usize].decode_actions;
        &self.data.decode_actions[start as usize..end as usize]
    }

    pub fn post_decode_actions(&self) -> &'b [(LocalIndex, DisasmExprRange)] {
        let (start, end) = self.data.constructors[self.constructor.id as usize].post_decode_actions;
        &self.data.post_decode_actions[start as usize..end as usize]
    }

    pub fn display_segments(&self) -> &'b [DisplaySegment] {
        let (start, end) = self.data.constructors[self.constructor.id as usize].display;
        &self.data.display_segments[start as usize..end as usize]
    }

    pub fn fields(&self) -> &'b [Field] {
        let (start, end) = self.data.constructors[self.constructor.id as usize].fields;
        &self.data.fields[start as usize..end as usize]
    }

    pub fn locals(&self) -> &[i64] {
        &self.inst.locals[self.constructor.locals.0 as usize..self.constructor.locals.1 as usize]
    }

    pub fn subtables(&self) -> &[DecodedConstructor] {
        &self.inst.subtables
            [self.constructor.subtables.0 as usize..self.constructor.subtables.1 as usize]
    }

    pub fn semantics(&self) -> &'b [SemanticAction] {
        let (start, end) = self.data.constructors[self.constructor.id as usize].semantics;
        &self.data.semantics[start as usize..end as usize]
    }
}

pub struct SubtableCtxMut<'a, 'b> {
    pub(crate) data: &'b SleighData,
    pub(crate) inst: &'a mut Instruction,
    pub(crate) constructor: DecodedConstructor,
}

impl std::ops::Deref for SubtableCtxMut<'_, '_> {
    type Target = Instruction;

    fn deref(&self) -> &Self::Target {
        self.inst
    }
}

impl std::ops::DerefMut for SubtableCtxMut<'_, '_> {
    fn deref_mut(&mut self) -> &mut Self::Target {
        self.inst
    }
}

impl<'a, 'b> SubtableCtxMut<'a, 'b> {
    fn as_ref(&'a self) -> SubtableCtx<'a, 'b> {
        SubtableCtx { data: self.data, inst: self.inst, constructor: self.constructor }
    }

    pub fn visit_constructor(&mut self, constructor: DecodedConstructor) -> SubtableCtxMut<'_, 'b> {
        SubtableCtxMut { data: self.data, inst: self.inst, constructor }
    }

    fn eval_disasm_expr(&mut self, state: &mut InnerDecoder) {
        for subtable in self.constructor.subtables.0..self.constructor.subtables.1 {
            let constructor = self.inst.subtables[subtable as usize];
            let mut ctx = SubtableCtxMut { data: self.data, inst: self.inst, constructor };
            ctx.eval_disasm_expr(state);
        }

        for (local, expr) in self.as_ref().post_decode_actions() {
            let mut stack = std::mem::take(&mut state.state.eval_stack);

            let value = eval_disasm_expr(
                &mut stack,
                DisasmLocalEval { state, ctx: self.as_ref() },
                self.data.get_disasm_expr(*expr),
            )
            .expect("invalid disasm expr");
            self.locals_mut()[*local as usize] = value;

            state.state.eval_stack = stack;
        }
    }

    fn locals_mut(&mut self) -> &mut [i64] {
        &mut self.inst.locals
            [self.constructor.locals.0 as usize..self.constructor.locals.1 as usize]
    }

    fn subtables_mut(&mut self) -> &mut [DecodedConstructor] {
        &mut self.inst.subtables
            [self.constructor.subtables.0 as usize..self.constructor.subtables.1 as usize]
    }
}

#[derive(Debug, Copy, Clone)]
pub enum ContextModValue {
    TokenField(Token, Field),
    ContextField(Field),
    InstStart,
}

impl EvalDisasmValue for &'_ InnerDecoder<'_, '_> {
    type Value = ContextModValue;

    fn eval(&self, value: &Self::Value) -> i64 {
        match value {
            ContextModValue::ContextField(field) => field.extract(self.state.context),
            ContextModValue::TokenField(token, field) => field.extract(self.get_token(*token)),
            ContextModValue::InstStart => self.data.base_addr as i64,
        }
    }
}

#[derive(Debug, Clone)]
pub enum DisasmConstantValue {
    LocalField(u32),
    ContextField(Field),
    InstStart,
    InstNext,
}

struct DisasmLocalEval<'a, 'b, 'c, 'd, 'e> {
    state: &'c InnerDecoder<'d, 'e>,
    ctx: SubtableCtx<'a, 'b>,
}

impl EvalDisasmValue for DisasmLocalEval<'_, '_, '_, '_, '_> {
    type Value = DisasmConstantValue;

    fn eval(&self, value: &Self::Value) -> i64 {
        match value {
            DisasmConstantValue::LocalField(idx) => self.ctx.locals()[*idx as usize],
            DisasmConstantValue::ContextField(field) => field.extract(self.state.state.context),
            DisasmConstantValue::InstStart => self.state.data.base_addr as i64,
            DisasmConstantValue::InstNext => {
                (self.state.data.base_addr + self.state.state.next_offset as u64) as i64
            }
        }
    }
}
