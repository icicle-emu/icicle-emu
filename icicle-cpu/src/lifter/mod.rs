pub mod msp430;
mod optimize;
mod pcodeops;

use hashbrown::{HashMap, HashSet};

use pcode::PcodeDisplay;

use crate::{cpu::Arch, lifter::optimize::Optimizer, BlockTable};

pub use self::pcodeops::{get_injectors, PcodeOpInjector};

pub trait InstructionSource {
    fn arch(&self) -> &Arch;
    fn read_bytes(&mut self, vaddr: u64, buf: &mut [u8]);
    fn ensure_exec(&mut self, vaddr: u64, size: usize) -> bool;
}

impl InstructionSource for crate::Cpu {
    fn arch(&self) -> &Arch {
        &self.arch
    }

    fn read_bytes(&mut self, vaddr: u64, buf: &mut [u8]) {
        let _ = self.mem.read_bytes(vaddr, buf, icicle_mem::perm::NONE);
    }

    fn ensure_exec(&mut self, vaddr: u64, len: usize) -> bool {
        self.mem.ensure_executable(vaddr, len as u64)
    }
}

pub struct InstructionLifter {
    lifter: sleigh_runtime::Lifter,
    decoder: sleigh_runtime::Decoder,

    /// The most recently decoded instruction.
    pub decoded: sleigh_runtime::Instruction,

    /// The p-code operations for the most recently lifted instruction.
    pub lifted: pcode::Block,

    /// A buffer to hold the disassembly for the lifted instruction.
    pub disasm: String,

    /// Controls whether we should also generate disassembly for the lifted instruction.
    generate_disassembly: bool,

    /// Buffer used for keeping track of temporaries that cross block boundaries.
    live_tmps: HashMap<i16, u16>,

    /// Buffer used for tracking which temporaries have been written to in the current block.
    written_tmps: HashSet<i16>,
}

impl InstructionLifter {
    pub fn new() -> Self {
        Self {
            lifter: sleigh_runtime::Lifter::new(),
            decoder: sleigh_runtime::Decoder::default(),
            decoded: sleigh_runtime::Instruction::default(),
            lifted: pcode::Block::new(),
            generate_disassembly: true,
            disasm: String::new(),
            live_tmps: HashMap::new(),
            written_tmps: HashSet::new(),
        }
    }

    pub fn set_context(&mut self, context: u64) {
        self.decoder.set_context(context);
    }

    /// Lift a single instruction starting at `vaddr` returning the address of the next instruction,
    /// or `None` if no instruction could be fetched from `vaddr`.
    pub fn lift<S>(&mut self, src: &mut S, vaddr: u64) -> Option<u64>
    where
        S: InstructionSource,
    {
        let next = self.decode(src, vaddr)?.inst_next;
        if self.generate_disassembly {
            self.disasm_current(src);
            tracing::trace!("disasm: {vaddr:#x} \"{}\"", self.disasm)
        }
        let block = self.lifter.lift(&src.arch().sleigh, &self.decoded).ok()?;
        self.lifted.clone_from(&block);

        tracing::trace!("lift:   {vaddr:#x}\n{}", block.display(&src.arch().sleigh));

        Some(next)
    }

    /// Disassemble the instruction at `vaddr`.
    pub fn disasm<S>(&mut self, src: &mut S, vaddr: u64) -> Option<&str>
    where
        S: InstructionSource,
    {
        self.decode(src, vaddr)?;
        self.disasm_current(src);
        Some(&self.disasm)
    }

    /// Disassemble the current decoded instruction.
    pub fn disasm_current<S>(&mut self, src: &S)
    where
        S: InstructionSource,
    {
        self.disasm.clear();
        if src.arch().sleigh.disasm_into(&self.decoded, &mut self.disasm).is_none() {
            self.disasm.clear();
            self.disasm.push_str("invalid_instruction");
        }
    }

    /// Decode the instruction at `vaddr` from `src`. If the instruction is invalid, return `None`.
    pub fn decode<S>(&mut self, src: &mut S, vaddr: u64) -> Option<&sleigh_runtime::Instruction>
    where
        S: InstructionSource,
    {
        let alignment_mask = !(src.arch().sleigh.alignment as u64 - 1);
        if vaddr & alignment_mask != vaddr {
            return None;
        }

        // A buffer large enough to hold the largest decodable instruction for any supported
        // architecture.
        let mut buf = [0u8; 16];

        // Read the instruction at `vaddr` into `buf`, we ignore errors here because we want to be
        // able to handle instructions that occur on permission boundaries, and we don't currently
        // know the length of the instruction.
        src.read_bytes(vaddr, &mut buf);

        self.decoder.set_inst(vaddr, &buf);
        self.decoder.decode_into(&src.arch().sleigh, &mut self.decoded)?;

        // Now that we know the length of the instruction, ensure that every decoded byte is valid.
        let len = self.decoded.num_bytes() as usize;
        let is_valid = len <= buf.len() && src.ensure_exec(vaddr, len);
        if !is_valid {
            return None;
        }
        tracing::trace!("decode: {vaddr:#x} {:02x?}", &buf[..len]);

        Some(&self.decoded)
    }

    /// Promotes temporaries that cross internal branches/labels to registers.
    fn promote_live_tempories<S>(&mut self, src: &S)
    where
        S: InstructionSource,
    {
        self.live_tmps.clear();
        self.written_tmps.clear();

        let mut next_saved_tmp: u16 = 0;

        for inst in &self.lifted.instructions {
            if matches!(
                inst.op,
                pcode::Op::PcodeLabel(_) | pcode::Op::PcodeBranch(_) | pcode::Op::Branch(_)
            ) {
                // Start of a new basic block.
                self.written_tmps.clear();
                continue;
            }

            // If there is an input temporary that has not been written to in this block then keep
            // track of it.
            for input in inst.inputs.get() {
                if let pcode::Value::Var(x) = input {
                    if x.is_temp() && !self.written_tmps.contains(&x.id) {
                        self.live_tmps.entry(x.id).or_insert_with(|| {
                            next_saved_tmp += 1;
                            next_saved_tmp - 1
                        });
                    }
                }
            }

            if inst.output.is_temp() {
                self.written_tmps.insert(inst.output.id);
            }
        }

        if next_saved_tmp as usize > src.arch().sleigh.saved_tmps.len() {
            panic!("Too many saved temporaries");
        }

        // Now we know all temporaries that we need to promote, so do the promotion.
        for inst in &mut self.lifted.instructions {
            let mut inputs = inst.inputs.get();
            for input in &mut inputs {
                if let pcode::Value::Var(var) = input {
                    if let Some(&x) = self.live_tmps.get(&var.id) {
                        *var = src.arch().sleigh.saved_tmps[x as usize].slice(var.offset, var.size);
                    }
                }
            }
            inst.inputs = inputs.into();

            if let Some(&x) = self.live_tmps.get(&inst.output.id) {
                inst.output = src.arch().sleigh.saved_tmps[x as usize]
                    .slice(inst.output.offset, inst.output.size);
            }
        }
    }
}

#[inline]
pub fn count_instructions<'a, T>(ops: T) -> usize
where
    T: IntoIterator<Item = &'a pcode::Instruction>,
{
    ops.into_iter().filter(|inst| matches!(inst.op, pcode::Op::InstructionMarker)).count()
}

#[derive(Clone)]
pub struct Block {
    pub pcode: pcode::Block,
    pub entry: Option<u64>,
    pub start: u64,
    pub end: u64,
    pub context: u64,
    pub exit: BlockExit,
    pub breakpoints: u32,
    pub num_instructions: u32,
}

impl Block {
    #[inline]
    pub fn has_breakpoint(&self) -> bool {
        self.breakpoints != 0
    }

    #[inline]
    pub fn contains_addr(&self, addr: u64) -> bool {
        self.start <= addr && addr < self.end
    }

    /// Returns the address and length of each instruction in the block
    pub fn instructions(&self) -> impl Iterator<Item = (u64, u64)> + '_ {
        self.pcode
            .instructions
            .iter()
            .filter(|inst| matches!(inst.op, pcode::Op::InstructionMarker))
            .map(|x| (x.inputs.first().as_u64(), x.inputs.second().as_u64()))
    }
}

#[derive(Default)]
pub struct BlockState {
    /// The pcode operations for the current block.
    pub pcode: pcode::Block,

    /// Keeps track of all the blocks that exited with a jump to a previously unknown label.
    forward_jumps: Vec<(BlockId, pcode::PcodeLabel)>,

    /// Keeps track of which block each label defined in the current instruction represents.
    labels: HashMap<pcode::PcodeLabel, BlockId>,

    /// Keeps track of the entry point to the block (if it has one).
    entry: Option<u64>,

    /// The address of the first instruction in the current block.
    start: u64,

    /// The address of the instruction we are currently decoding.
    current_addr: u64,

    /// The address of the next instruction in the block.
    next: u64,

    /// The context to use for the next instruction.
    context: u64,
}

impl BlockState {
    fn is_empty(&self) -> bool {
        self.pcode.instructions.is_empty()
    }

    fn finish(&mut self, exit: BlockExit) -> Block {
        let pcode = std::mem::take(&mut self.pcode);
        let num_instructions = count_instructions(&pcode.instructions).try_into().unwrap();
        let block = Block {
            pcode,
            entry: self.entry.take(),
            start: self.start,
            end: self.next,
            context: self.context,
            exit,
            breakpoints: 0,
            num_instructions,
        };
        self.start = self.current_addr;
        block
    }

    pub fn gen_set_pc(&mut self, src: &dyn InstructionSource) {
        let r = src.arch().reg_pc;
        self.pcode.push((r, pcode::Op::Copy, pcode::Value::Const(self.current_addr, r.size)));
    }

    pub fn gen_set_next_pc(&mut self, src: &dyn InstructionSource) {
        let r = src.arch().reg_next_pc;
        self.pcode.push((r, pcode::Op::Copy, pcode::Value::Const(self.next, r.size)));
    }
}

#[derive(Debug)]
enum BlockResult {
    /// The next instruction is part of the current block.
    Continue(u64),
    /// The next instruction is not part of the current block..
    Exit(u64),
    /// There was an error lifting the instruction, in the current block.
    Invalid,
}

pub type BlockId = usize;

/// Constant to use for unknown labels.
const UNKNOWN_BLOCK: usize = 0xbadbadbadbad;

/// Constant to use for labels that point to the next address
const NEXT_ADDR_LABEL: u16 = u16::MAX;

/// Represents a group of blocks that are connected with internal jumps.
#[derive(Clone, Copy, Debug)]
pub struct BlockGroup {
    /// The range of blocks that this entry covers.
    pub blocks: (BlockId, BlockId),

    /// The starting address of the group.
    pub start: u64,

    /// The ending address of the group.
    pub end: u64,
}

impl BlockGroup {
    pub fn range(&self) -> std::ops::Range<usize> {
        self.blocks.0..self.blocks.1
    }

    pub fn contains(&self, addr: u64) -> bool {
        self.start <= addr && addr <= self.end
    }

    pub fn to_string(
        &self,
        blocks: &[Block],
        sleigh: &sleigh_runtime::SleighData,
        ignore_trival_exit: bool,
    ) -> Result<String, std::fmt::Error> {
        self.to_string_with_disasm(blocks, sleigh, ignore_trival_exit, &HashMap::new())
    }

    pub fn to_string_with_disasm(
        &self,
        blocks: &[Block],
        sleigh: &sleigh_runtime::SleighData,
        ignore_trival_exit: bool,
        disasm: &HashMap<u64, String>,
    ) -> Result<String, std::fmt::Error> {
        use std::fmt::Write;

        let has_multiple_instructions =
            blocks[self.range()].iter().map(|x| x.num_instructions).sum::<u32>() > 1;
        let mut out = String::new();
        for (idx, block_id) in self.range().into_iter().enumerate() {
            let block = &blocks[block_id];

            match idx {
                0 => writeln!(out, "<L0> (entry={:#0x}):", self.start)?,
                idx => writeln!(out, "<L{}>:", idx)?,
            }

            for op in &block.pcode.instructions {
                if matches!(op.op, pcode::Op::InstructionMarker) {
                    if has_multiple_instructions {
                        let addr = op.inputs.first().as_u64();
                        match disasm.get(&addr) {
                            Some(disasm) => writeln!(out, "[{addr:#0x}] {disasm}")?,
                            None => writeln!(out, "\t{}", op.display(sleigh))?,
                        }
                    }
                }
                else {
                    writeln!(out, "\t{}", op.display(sleigh))?
                }
            }

            let trivial_exit = match block.exit {
                BlockExit::Jump { target } => match target {
                    Target::Internal(id) => id == block_id + 1,
                    Target::External(addr) => {
                        addr.const_eq(self.end) && block_id == self.range().end - 1
                    }
                    _ => false,
                },
                _ => false,
            };
            if !trivial_exit || !ignore_trival_exit {
                writeln!(out, "\t{:?}", block.exit.display(sleigh))?;
            }
        }
        Ok(out)
    }
}

pub struct Settings {
    /// The maximum number of instructions to include in each block
    pub max_instructions_per_block: usize,

    /// Whether to perform instruction local optimizations.
    pub optimize: bool,

    /// Whether to perform block level optimizations.
    pub optimize_block: bool,
}

impl Default for Settings {
    fn default() -> Self {
        Self { max_instructions_per_block: 128, optimize: true, optimize_block: true }
    }
}

pub struct Context<'a, 'b, S> {
    src: &'a mut S,
    code: &'b mut BlockTable,
    vaddr: u64,
}

impl<'a, 'b, S> Context<'a, 'b, S> {
    pub fn new(src: &'a mut S, code: &'b mut BlockTable, vaddr: u64) -> Self {
        Self { src, code, vaddr }
    }

    fn current_block_id(&self) -> BlockId {
        self.code.blocks.len()
    }

    fn next_block(&self) -> Target {
        Target::Internal(self.code.blocks.len() + 1)
    }

    /// Finalize the current block, exiting due to `exit`.
    fn finalize_block(&mut self, state: &mut BlockState, exit: BlockExit) {
        self.code.blocks.push(state.finish(exit))
    }
}

/// Represents a function that is called before adding a function to the current block (this is
/// currently used for working around bugs / missing functionality in sleigh specs).
pub type PcodePatcher = Box<dyn FnMut(&mut pcode::Block) + 'static>;

pub struct BlockLifter {
    pub settings: Settings,
    pub instruction_lifter: InstructionLifter,
    pub op_injectors: HashMap<u16, Box<dyn PcodeOpInjector>>,
    pub patchers: Vec<PcodePatcher>,
    current: BlockState,
    optimizer: Optimizer,
}

impl BlockLifter {
    pub fn new(settings: Settings, instruction_lifter: InstructionLifter) -> Self {
        Self {
            settings,
            op_injectors: HashMap::new(),
            instruction_lifter,
            current: Default::default(),
            optimizer: Optimizer::new(),
            patchers: vec![],
        }
    }

    pub fn set_context(&mut self, context: u64) {
        self.instruction_lifter.set_context(context);
    }

    pub fn mark_as_temporary(&mut self, var_id: pcode::VarId) {
        self.optimizer.mark_as_temporary(var_id);
    }

    pub fn lift_block<S>(&mut self, ctx: &mut Context<S>) -> Option<BlockGroup>
    where
        S: InstructionSource,
    {
        let group_start = ctx.current_block_id();

        // Lift all instructions that are part of the same block, or until we reach a maximum number
        // of instructions.
        let mut icount = 0;
        self.current.start = ctx.vaddr;
        self.current.entry = Some(ctx.vaddr);
        let exit_target = loop {
            ctx.vaddr = match self.lift_and_add_next_inst(ctx) {
                BlockResult::Continue(next_addr) => {
                    icount += 1;
                    if icount >= self.settings.max_instructions_per_block {
                        break Target::External(next_addr.into());
                    }
                    next_addr
                }
                BlockResult::Exit(addr) => break Target::External(addr.into()),
                BlockResult::Invalid => break Target::Invalid,
            };
        };

        // Finalize the current block if we exited the loop before the block was complete.
        if !self.current.is_empty() {
            ctx.finalize_block(&mut self.current, BlockExit::Jump { target: exit_target });
        }
        else {
            // Fix any jumps that reference the next block.
            let next = Target::Internal(ctx.code.blocks.len());
            for block in &mut ctx.code.blocks[group_start..] {
                block.exit.patch_target(next, exit_target);
            }
        }

        if self.settings.optimize_block {
            for block in &mut ctx.code.blocks[group_start..] {
                if self.optimizer.const_prop(&mut block.pcode).is_err() {
                    break;
                }
            }
        }

        let group_end = ctx.current_block_id();
        if group_start == group_end {
            return None;
        }

        Some(BlockGroup {
            blocks: (group_start, group_end),
            start: ctx.code.blocks[group_start].start,
            end: self.current.next,
        })
    }

    /// Lifts the next instruction from `ctx` and adds the pcode operations the current block.
    ///
    /// Returns either the next address in the block or `None` on an external branch.
    fn lift_and_add_next_inst<S>(&mut self, ctx: &mut Context<S>) -> BlockResult
    where
        S: InstructionSource,
    {
        let next_vaddr = match self.lift_next_inst(ctx) {
            Some(addr) => addr,
            None => return BlockResult::Invalid,
        };

        let mut label_to_next = false;
        let mut block_exit = false;
        for stmt in &self.instruction_lifter.lifted.instructions {
            match stmt.op {
                pcode::Op::Branch(pcode::BranchHint::Jump) => {
                    let [cond, target] = stmt.inputs.get();

                    if target.const_eq(next_vaddr) {
                        // Treat a branch to the next address as an internal branch (this
                        // is used for the pcode encoding of instructions like CMOV).
                        self.current.forward_jumps.push((ctx.current_block_id(), NEXT_ADDR_LABEL));
                        label_to_next = true;

                        let target = Target::Internal(UNKNOWN_BLOCK);
                        ctx.finalize_block(
                            &mut self.current,
                            BlockExit::new(cond, target, ctx.next_block()),
                        );
                    }
                    else {
                        ctx.finalize_block(
                            &mut self.current,
                            BlockExit::new(cond, Target::External(target), ctx.next_block()),
                        );
                        block_exit = true;
                    }
                }
                pcode::Op::Branch(pcode::BranchHint::Call) => {
                    let [cond, target] = stmt.inputs.get();
                    assert!(cond.const_eq(1), "conditional calls are not supported");
                    ctx.finalize_block(&mut self.current, BlockExit::Call {
                        target,
                        fallthrough: next_vaddr.into(),
                    });
                    block_exit = true;
                }
                pcode::Op::Branch(pcode::BranchHint::Return) => {
                    let [cond, target] = stmt.inputs.get();
                    assert!(cond.const_eq(1), "conditional returns are not supported");
                    ctx.finalize_block(&mut self.current, BlockExit::Return { target });
                    block_exit = true;
                }
                pcode::Op::PcodeBranch(label) => {
                    let label_block = match self.current.labels.get(&label) {
                        Some(block) => *block,
                        None => {
                            self.current.forward_jumps.push((ctx.current_block_id(), label));
                            UNKNOWN_BLOCK
                        }
                    };
                    let cond = stmt.inputs.first();
                    let target = Target::Internal(label_block);
                    let fallthrough = ctx.next_block();
                    ctx.finalize_block(
                        &mut self.current,
                        BlockExit::new(cond, target, fallthrough),
                    );
                }
                pcode::Op::PcodeLabel(id) => {
                    if !self.current.is_empty() {
                        let target = ctx.next_block();
                        ctx.finalize_block(&mut self.current, BlockExit::Jump { target });
                    }
                    self.current.labels.insert(id, ctx.current_block_id());
                }
                pcode::Op::PcodeOp(id) => match self.op_injectors.get_mut(&id) {
                    Some(injector) => {
                        block_exit = injector.inject_ops(
                            ctx.src,
                            id,
                            stmt.inputs,
                            stmt.output,
                            &mut self.current,
                        );
                    }
                    None => self.current.pcode.instructions.push(stmt.clone()),
                },
                pcode::Op::Exception => {
                    self.current.pcode.instructions.push(stmt.clone());
                    block_exit = true;
                }
                pcode::Op::Invalid => {
                    // Hit an invalid instruction (or a fetch error), so make sure we finalize the
                    // block after this instruction.
                    self.current.pcode.instructions.push(stmt.clone());
                    block_exit = true;
                }
                _ => {
                    // This is a normal instruction (so add it to the block)
                    self.current.pcode.instructions.push(stmt.clone());
                }
            }
        }

        if label_to_next {
            if !self.current.is_empty() {
                let target = ctx.next_block();
                ctx.finalize_block(&mut self.current, BlockExit::Jump { target });
            }
            self.current.labels.insert(NEXT_ADDR_LABEL, ctx.current_block_id());
        }

        // Resolve any forward jumps.
        for (src_block, label) in self.current.forward_jumps.drain(..) {
            if let Some(target) = ctx.code.blocks[src_block].exit.target_mut() {
                *target = Target::Internal(self.current.labels[&label]);
            }
        }
        self.current.labels.clear();

        match block_exit {
            true => BlockResult::Exit(next_vaddr),
            false => BlockResult::Continue(next_vaddr),
        }
    }

    fn lift_next_inst<S>(&mut self, ctx: &mut Context<S>) -> Option<u64>
    where
        S: InstructionSource,
    {
        self.current.current_addr = ctx.vaddr;
        self.current.next = self.instruction_lifter.lift(ctx.src, ctx.vaddr)?;

        for patcher in &mut self.patchers {
            (patcher)(&mut self.instruction_lifter.lifted);
        }

        if self.settings.optimize {
            let block = &mut self.instruction_lifter.lifted;
            self.optimizer.const_prop(block).ok()?;
            self.optimizer.dead_store_elimination(block);
        }
        self.instruction_lifter.promote_live_tempories(ctx.src);
        self.instruction_lifter.lifted.recompute_next_tmp();

        if self.instruction_lifter.generate_disassembly {
            let new_disasm = &self.instruction_lifter.disasm;
            match ctx.code.disasm.entry(ctx.vaddr) {
                hashbrown::hash_map::Entry::Occupied(old) => {
                    let old_disasm = old.get();
                    if old_disasm != new_disasm {
                        tracing::error!(
                            "disassembly changed at {:#0x} (from {old_disasm} to {new_disasm})",
                            ctx.vaddr
                        );
                        return None;
                    }
                }
                hashbrown::hash_map::Entry::Vacant(slot) => {
                    slot.insert(new_disasm.clone());
                }
            }
        }

        self.current.context = self.instruction_lifter.decoder.context();
        Some(self.current.next)
    }
}

#[derive(Copy, Clone, PartialEq, Eq)]
pub enum Target {
    Invalid,
    Internal(usize),
    External(pcode::Value),
}

impl<T> pcode::PcodeDisplay<T> for Target
where
    pcode::VarNode: pcode::PcodeDisplay<T>,
{
    fn fmt(&self, f: &mut std::fmt::Formatter, ctx: &T) -> std::fmt::Result {
        match self {
            Self::Invalid => write!(f, "<INVALID>"),
            Self::Internal(block) => write!(f, "<L{}>", block),
            Self::External(value) => write!(f, "{}", value.display(ctx)),
        }
    }
}

#[derive(Copy, Clone)]
pub enum BlockExit {
    Jump { target: Target },
    Branch { cond: pcode::Value, target: Target, fallthrough: Target },
    Call { target: pcode::Value, fallthrough: u64 },
    Return { target: pcode::Value },
}

impl BlockExit {
    pub fn new(cond: pcode::Value, target: Target, fallthrough: Target) -> Self {
        match cond {
            x if x.const_eq(1) => Self::Jump { target },
            x if x.const_eq(0) => Self::Jump { target: fallthrough },
            _ => Self::Branch { cond, target, fallthrough },
        }
    }

    fn target_mut(&mut self) -> Option<&mut Target> {
        match self {
            Self::Jump { target } | Self::Branch { target, .. } => Some(target),
            _ => None,
        }
    }

    /// Update any targets in the exit to `to` if they match `from`.
    fn patch_target(&mut self, from: Target, to: Target) {
        match self {
            Self::Jump { target } if *target == from => *target = to,
            Self::Branch { target, fallthrough, .. } => {
                if *target == from {
                    *target = to;
                }
                if *fallthrough == from {
                    *fallthrough = to;
                }
            }
            _ => {}
        }
    }

    pub fn targets(&self) -> impl Iterator<Item = Target> {
        let mut exits = [Target::Invalid, Target::Invalid];
        match self {
            BlockExit::Jump { target } => {
                exits[0] = *target;
            }
            BlockExit::Branch { target, fallthrough, .. } => {
                exits[0] = *target;
                exits[1] = *fallthrough;
            }
            BlockExit::Call { target, fallthrough } => {
                exits[0] = Target::External(*target);
                exits[1] = Target::External(pcode::Value::Const(*fallthrough, 8));
            }
            BlockExit::Return { target } => {
                exits[0] = Target::External(*target);
            }
        }

        exits.into_iter().filter(|x| *x != Target::Invalid)
    }

    /// Returns the condition for the block exit (if it has one).
    pub fn cond(&self) -> Option<pcode::Value> {
        match self {
            BlockExit::Branch { cond, .. } => Some(*cond),
            _ => None,
        }
    }

    /// Returns a p-code operation equivalent to the exit.
    pub fn to_pcode(&self) -> pcode::Instruction {
        let to_inst = |cond: pcode::Value, hint: pcode::BranchHint, target: &Target| match target {
            Target::Invalid => pcode::Op::Invalid.into(),
            Target::Internal(_) => (pcode::Op::PcodeBranch(0), cond).into(),
            Target::External(var) => (pcode::Op::Branch(hint), (cond, *var)).into(),
        };

        match self {
            Self::Jump { target } => to_inst(1_u8.into(), pcode::BranchHint::Jump, target),
            Self::Branch { cond, target, .. } => to_inst(*cond, pcode::BranchHint::Jump, target),
            Self::Call { target, .. } => {
                to_inst(1_u8.into(), pcode::BranchHint::Call, &Target::External(*target))
            }
            Self::Return { target } => {
                to_inst(1_u8.into(), pcode::BranchHint::Return, &Target::External(*target))
            }
        }
    }
}

impl<T> pcode::PcodeDisplay<T> for BlockExit
where
    pcode::VarNode: pcode::PcodeDisplay<T>,
{
    fn fmt(&self, f: &mut std::fmt::Formatter, ctx: &T) -> std::fmt::Result {
        match self {
            Self::Jump { target: Target::Invalid } => f.write_str("invalid_instruction"),
            Self::Jump { target } => write!(f, "jump {}", target.display(ctx)),
            Self::Branch { cond, target, .. } => {
                write!(f, "if {} jump {}", cond.display(ctx), target.display(ctx))
            }
            Self::Call { target, .. } => write!(f, "call {}", target.display(ctx)),
            Self::Return { target } => write!(f, "return {}", target.display(ctx)),
        }
    }
}

impl std::fmt::Debug for BlockExit {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        pcode::PcodeDisplay::fmt(self, f, &())
    }
}

pub fn register_halt_patcher(lifter: &mut BlockLifter) {
    lifter.patchers.push(Box::new(|block: &mut pcode::Block| {
        if let &[marker, jump] = &block.instructions[..] {
            if matches!(
                (marker.op, jump.op),
                (pcode::Op::InstructionMarker, pcode::Op::Branch(pcode::BranchHint::Jump))
            ) {
                let current_addr = marker.inputs.first().as_u64();
                let [cond, next_addr] = jump.inputs.get();
                if cond.const_eq(1) && next_addr.const_eq(current_addr) {
                    block.instructions.truncate(1);
                    block.push((pcode::Op::Exception, (crate::ExceptionCode::Halt as u32, 0_u64)));
                    return;
                }
            }
        }
    }));
}

/// Some of the specifications (e.g. MSP430, ARM), read/write to the PC directly (instead of using a
/// disassembly time constant).
///
/// This breaks instrumentation expecting the PC register to only be modified as part of control
/// flow. To avoid this we convert writes to PC to a write to a tmp register first, and reads to PC
/// to use the address of the current instruction.
///
/// @todo: Consider fixing this in the appropriate SLEIGH specifications instead.
pub fn register_read_pc_patcher(
    lifter: &mut BlockLifter,
    pc: pcode::VarNode,
    tmp_pc: pcode::VarNode,
) {
    lifter.mark_as_temporary(tmp_pc.id);

    let handler = move |block: &mut pcode::Block| {
        let mut pc_written = false;
        let mut last_pc = 0;
        for inst in &mut block.instructions {
            if let pcode::Op::InstructionMarker = inst.op {
                last_pc = inst.inputs.first().as_u64();
            }

            let mut inputs = inst.inputs.get();
            for input in &mut inputs {
                if let pcode::Value::Var(var) = input {
                    if var.id == pc.id {
                        if pc_written {
                            var.id = tmp_pc.id;
                        }
                        else {
                            *input =
                                pcode::Value::Const(last_pc, pc.size).slice(var.offset, var.size);
                        }
                    }
                }
            }
            inst.inputs = inputs.into();
            if inst.output.id == pc.id {
                inst.output.id = tmp_pc.id;
                pc_written = true;
            }
        }
    };

    lifter.patchers.push(Box::new(handler));
}
