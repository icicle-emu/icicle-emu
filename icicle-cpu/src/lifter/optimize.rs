use ahash::{AHashMap as HashMap, AHashSet as HashSet};

use pcode::{Instruction, Op, PcodeLabel, VarId, VarNode};

use crate::exec::const_eval::{self, BitVecExt, ConstEval};

pub struct Optimizer {
    /// Configures whether the optimzer is operating on a block representing a single instruction
    /// only. Within an instruction boundary we allow redundant loads/stores to be removed.
    single_instruction_only: bool,

    /// Structure for performing dead code elimination.
    dead_store_detector: DeadStoreDetector,

    /// Keeps track of the offset within the block each label is located at.
    labels: HashMap<PcodeLabel, usize>,

    /// Keeps track of which of the labels are reachable.
    reachable_labels: HashSet<PcodeLabel>,

    /// Keeps track of label that a const jump is jumping to.
    jump_target: Option<PcodeLabel>,

    /// A temporary block to write the optimized instructions into.
    block: pcode::Block,

    /// Constant propagated state for the outputs of `block`.
    state: Vec<(usize, pcode::VarNode, const_eval::Value)>,

    /// The optimizer state used for evaluating an instruction.
    const_eval: std::cell::RefCell<ConstEval>,
}

impl Optimizer {
    pub fn new() -> Self {
        Self {
            single_instruction_only: true,
            dead_store_detector: DeadStoreDetector::default(),
            labels: HashMap::new(),
            reachable_labels: HashSet::new(),
            jump_target: None,
            block: pcode::Block::new(),
            state: vec![],
            const_eval: std::cell::RefCell::new(ConstEval::new()),
        }
    }

    pub fn mark_as_temporary(&mut self, var: VarId) {
        self.dead_store_detector.additional_tmps.insert(var);
    }

    /// Simplifies the target block by propagating constants.
    pub fn const_prop(&mut self, block: &mut pcode::Block) {
        self.block.clear();
        self.state.clear();
        self.const_eval.get_mut().clear();
        self.jump_target = None;

        // Precompute the location of all labels within the block.
        self.labels.clear();
        for (offset, stmt) in block.instructions.iter().enumerate() {
            if let Op::PcodeLabel(id) = stmt.op {
                self.labels.insert(id, offset);
            }
        }

        // Assume labels with back edges are reachable.
        //
        // (Theoretically the label could not be reachable, however in practice this is rare and it
        // is safe to ignore this case).
        self.reachable_labels.clear();
        for (idx, stmt) in block.instructions.iter().enumerate() {
            if let Op::PcodeBranch(label) = stmt.op {
                // The `None` case here corresponds to jumps to invalid labels, these will trigger
                // an `InvalidTarget` exception at runtime.
                if self.labels.get(&label).map_or(false, |target| *target < idx) {
                    self.reachable_labels.insert(label);
                }
            }
        }

        for stmt in &block.instructions {
            if matches!(stmt.op, Op::InstructionMarker) {
                // Prevent temporaries from being propagated across instruction boundaries.
                let mut const_eval = self.const_eval.borrow_mut();
                const_eval.results.clear();
                const_eval.inputs.retain(|id, _| self.dead_store_detector.should_persist(*id));
            }

            // Check whether we are at a new label.
            if let Op::PcodeLabel(id) = stmt.op {
                if self.reachable_labels.contains(&id) {
                    if let Some(jump_target) = self.jump_target.take() {
                        if jump_target != id {
                            // This label isn't the destination that the current jump was looking
                            // for, however the jump is still active at this point, so inject a
                            // branch to the jump's true location here.
                            self.block.push((Op::PcodeBranch(jump_target), 1_u8));
                            self.reachable_labels.insert(jump_target);
                        }
                    }

                    // Since this label is reachable elsewhere we need to flush the current state
                    // and add the label.
                    self.const_eval.get_mut().clear();
                    self.block.push(Op::PcodeLabel(id));
                }
                else if self.jump_target == Some(id) {
                    // Reached the sub-block that we are jumping to.
                    self.jump_target = None;
                }
                continue;
            }

            // Skip the current instruction if we are jumping over the current sub-block.
            if self.jump_target.is_some() {
                continue;
            }

            if let Some((mut inst, const_state)) = simplify(self, stmt) {
                if !inst.output.is_invalid() {
                    // Check if this is a write to the lower bytes of register where the upper bits
                    // are zero. If this is the case then store the output to a temporary, then
                    // zero-extend it into the full register. This adds an extra op, but simplifies
                    // later analysis.
                    match zero_extended_output(inst.output, const_state.clone()) {
                        Some(extended_output) => {
                            self.block.recompute_next_tmp();
                            let tmp = self.block.alloc_tmp(inst.output.size);
                            inst.output = tmp;
                            self.block.push(inst);

                            let id = self.block.instructions.len();
                            self.block.push((extended_output, pcode::Op::ZeroExtend, tmp));
                            self.state.push((id, extended_output, const_state));
                        }
                        None => {
                            let id = self.block.instructions.len();
                            self.block.push(inst);
                            self.state.push((id, inst.output, const_state));
                        }
                    }
                }
                else {
                    let id = self.block.instructions.len();
                    self.block.push(inst);
                    self.state.push((id, inst.output, const_state));
                }
            }
        }

        // If we never reached the label that a constant jump was jumping to, then it must have been
        // a back-edge, so add the jump here.
        if let Some(jump_target) = self.jump_target {
            self.block.push((Op::PcodeBranch(jump_target), 1_u8));
        }

        self.barrier();

        // Replace the current block with the optimized one.
        std::mem::swap(&mut self.block, block);
    }

    pub fn const_prop_values(
        &self,
    ) -> impl Iterator<Item = &(usize, pcode::VarNode, const_eval::Value)> {
        self.state.iter()
    }

    /// Removes all instructions that write to a variable that is never read.
    pub fn dead_store_elimination(&mut self, block: &mut pcode::Block) {
        let dead_code = self.dead_store_detector.get_dead_code(block, self.single_instruction_only);
        if dead_code.is_empty() {
            return;
        }

        self.block.clear();
        for (_, stmt) in
            block.instructions.iter().enumerate().filter(|(i, _)| !dead_code.contains(i))
        {
            self.block.push(*stmt);
        }

        std::mem::swap(&mut self.block, block);
    }

    /// Indicates to the optimizers that this location is an optimization barrier, and all unwritten
    /// registers/memory locations should be flushed.
    fn barrier(&mut self) {
        // @todo: implement this.
    }
}

/// Simplifies an instruction based information from const propagation
fn simplify(exec: &mut Optimizer, stmt: &Instruction) -> Option<(Instruction, const_eval::Value)> {
    let state = exec.const_eval.get_mut();

    // Perform const propagation on the inputs of the current instruction.
    let inputs =
        [state.const_prop_value(stmt.inputs.first()), state.const_prop_value(stmt.inputs.second())];
    let input_values = [state.get_value(inputs[0]), state.get_value(inputs[1])];
    let updated_instruction = Instruction::from((stmt.output, stmt.op, inputs));

    let prev_output = state.get_base_value(stmt.output.into());
    state.eval(updated_instruction);

    // If the instruction is an internal branch, then we need to keep track of the label that we are
    // jumping to.
    if let Op::PcodeBranch(label) = stmt.op {
        match state.get_const(inputs[0]) {
            Some(0) => {
                // The branch is always false, so skip the branch.
                return None;
            }
            Some(1) => {
                exec.jump_target = Some(label);
                return None;
            }
            _ => {}
        }
        // We know know we can reach the target label is reachable.
        exec.reachable_labels.insert(label);

        // @todo: add a barrier here?
        // exec.barrier();
    }

    if let Op::Branch(_) = stmt.op {
        if state.get_const(inputs[0]) == Some(0) {
            // The branch is always false, so skip the branch.
            return None;
        }
        // @todo: add a barrier here?
        // exec.barrier();
    }

    if external_state_modifications(stmt.op) {
        // Need to flush const evaluation state, since the target operation may modify any register.
        state.clear();
    }

    let full_output = state.get_base_value(stmt.output.into());
    if stmt.op.has_side_effects() {
        // If the instruction has side-effects then we need to retain the original instruction.
        return Some((updated_instruction, full_output));
    }

    let output = state.get_value(stmt.output.into());
    if output == prev_output.clone().slice_to(stmt.output.offset * 8, stmt.output.size * 8) {
        // If the instruction has no side-effects and the output value hasn't changed then we can
        // safely remove ignore this instruction.
        return None;
    }

    let known_output = if let Some(value) = output.get_const() {
        // Copy from constant.
        Some(pcode::Value::Const(value, stmt.output.size))
    }
    else if output == input_values[0] {
        // Copy from first input.
        Some(inputs[0])
    }
    else if output == input_values[1] {
        // Copy from second input.
        Some(inputs[1])
    }
    else {
        None
    };

    if let Some(value) = known_output {
        match zero_extended_output(stmt.output, prev_output) {
            Some(extended_output) => Some((extended_output.zext_from(value), full_output)),
            None => Some((stmt.output.copy_from(value), full_output)),
        }
    }
    else {
        // Unable to simplify the instruction.
        Some((updated_instruction, full_output))
    }
}

/// Returns a larger varnode for `output` if the bits above the `output` slice are all zeroes.
fn zero_extended_output(
    output: pcode::VarNode,
    prev_output: const_eval::Value,
) -> Option<pcode::VarNode> {
    if output.offset != 0 {
        // Avoid handling inner slices.
        return None;
    }

    let new_bitsize = (output.size * 8) as usize;
    let full_length = prev_output.len();
    let upper_zeros = prev_output
        .slice_to(new_bitsize as u8, (full_length - new_bitsize) as u8)
        .known_trailing_zeros();

    let zero_bytes = upper_zeros / 8;
    if zero_bytes != 0 && (output.size as usize + zero_bytes).is_power_of_two() {
        Some(pcode::VarNode::new(output.id, output.size + zero_bytes as u8))
    }
    else {
        None
    }
}

#[derive(Copy, Clone, Default)]
struct LiveBytes {
    set: u64,
}

impl LiveBytes {
    fn new(var: VarNode) -> Self {
        let mut value = Self { set: 0 };
        value.add(var);
        value
    }

    fn add(&mut self, var: VarNode) {
        for byte in var.offset..var.offset + var.size {
            self.set |= 1 << byte;
        }
    }

    fn subtract(&mut self, var: VarNode) {
        for byte in var.offset..var.offset + var.size {
            self.set &= !(1 << byte);
        }
    }

    fn any_set(&self, var: VarNode) -> bool {
        for byte in var.offset..var.offset + var.size {
            if self.set & (1 << byte) != 0 {
                return true;
            }
        }
        false
    }

    fn empty(&self) -> bool {
        self.set == 0
    }
}

#[derive(Default)]
struct DeadStoreDetector {
    /// Keeps track of the final bytes written to a variable.
    last_write: HashMap<VarId, LiveBytes>,

    /// Keeps track of the variables that still need to be written in the current block.
    live_reads: HashMap<VarId, LiveBytes>,

    /// Keeps track of the variables that are live across a block boundary.
    live_across_block: HashMap<VarId, LiveBytes>,

    /// Keeps track of all instructions in the block that write to a unused variable.
    dead_code: HashSet<usize>,

    /// Additional variables that do not need to be persisted across blocks.
    additional_tmps: HashSet<VarId>,

    /// Buffer used for keeping track of temporaries that cross block boundaries.
    live_tmps: HashSet<i16>,

    /// Buffer used for tracking which temporaries have been written to in the current block.
    written_tmps: HashSet<i16>,
}

impl DeadStoreDetector {
    fn get_dead_code(
        &mut self,
        block: &pcode::Block,
        single_instruction_only: bool,
    ) -> &HashSet<usize> {
        self.live_tmps.clear();
        self.written_tmps.clear();

        // Identify any temporaries that are used in multiple blocks.
        for inst in &block.instructions {
            if matches!(inst.op, pcode::Op::PcodeLabel(_)) {
                // Start of a new block.
                self.written_tmps.clear();
                continue;
            }

            // If there is an input temporary that has not been written to in this block then keep
            // track of it.
            for input in inst.inputs.get() {
                if let pcode::Value::Var(x) = input {
                    if !self.written_tmps.contains(&x.id) {
                        self.live_tmps.insert(x.id);
                    }
                }
            }
            self.written_tmps.insert(inst.output.id);
        }

        self.dead_code.clear();
        self.live_reads.clear();
        self.live_across_block.clear();
        self.last_write.clear();

        for (i, stmt) in block.instructions.iter().enumerate().rev() {
            if matches!(stmt.op, Op::PcodeBranch(_) | Op::PcodeLabel(_) | Op::Branch(_)) {
                // Handle cases where writes to registers in this block are not overwritten by the
                // block we just finished.
                self.last_write.clear();

                // Handle variables that cross block boundaries.
                for (id, entry) in &self.live_across_block {
                    self.live_reads.entry(*id).and_modify(|x| x.set |= entry.set).or_insert(*entry);
                }
                self.live_across_block.clone_from(&self.live_reads);
            }

            if single_instruction_only && matches!(stmt.op, Op::InstructionMarker) {
                // Reset liveness tracking across instruction boundaries.
                self.live_reads.clear();
                self.live_across_block.clear();
                self.last_write.clear();
            }

            let is_live = self.is_live(stmt.output) || stmt.op.has_side_effects();
            if !is_live {
                self.dead_code.insert(i);
                continue;
            }

            // Remove any live reads if the current write fully overwrites the read value.
            if let Some(mut prev) = self.live_reads.remove(&stmt.output.id) {
                prev.subtract(stmt.output);
                if !prev.empty() {
                    self.live_reads.insert(stmt.output.id, prev);
                }
            }

            for input in stmt.inputs.get() {
                if let pcode::Value::Var(var) = input {
                    if var != VarNode::NONE {
                        self.mark_as_read(var);
                    }
                }
            }
        }

        &self.dead_code
    }

    fn mark_as_read(&mut self, var: VarNode) {
        self.live_reads.entry(var.id).and_modify(|x| x.add(var)).or_insert(LiveBytes::new(var));
    }

    fn is_live(&mut self, var: pcode::VarNode) -> bool {
        use std::collections::hash_map::Entry;

        if self.should_persist(var.id) || self.live_tmps.contains(&var.id) {
            match self.last_write.entry(var.id) {
                Entry::Occupied(mut prev) => {
                    let mut merged = *prev.get();
                    merged.add(var);
                    if prev.get().set != merged.set {
                        prev.insert(merged);
                        return true;
                    }
                }
                Entry::Vacant(entry) => {
                    entry.insert(LiveBytes::new(var));
                    return true;
                }
            }
        }

        // Check if there is any read that uses this write.
        if self.live_reads.get(&var.id).map_or(false, |read| read.any_set(var)) {
            return true;
        }

        false
    }

    /// Returns whether the variable needs to be persisted at the end of the block.
    fn should_persist(&self, id: pcode::VarId) -> bool {
        id > 0 && !self.additional_tmps.contains(&id)
    }
}

fn external_state_modifications(op: Op) -> bool {
    matches!(op, Op::Hook(_) | Op::HookIf(_))
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn convert_op_to_copy() {
        let mut opt = Optimizer::new();
        let mut block = pcode::Block::new();

        let a = VarNode::new(1, 8);
        let b = VarNode::new(2, 8);

        block.push((b, Op::IntLeft, a, 0_u64));

        opt.const_prop(&mut block);
        opt.dead_store_elimination(&mut block);

        assert_eq!(block.instructions.len(), 1);
        assert_eq!(block.instructions[0], Instruction::from((b, Op::Copy, a)));
    }

    #[test]
    fn test_const_prop() {
        let mut opt = Optimizer::new();
        let mut block = pcode::Block::new();

        let a = VarNode::new(1, 8);
        let b = VarNode::new(2, 8);
        let tmp = block.alloc_tmp(8);

        block.push((tmp, Op::Copy, a));
        block.push((b, Op::Copy, tmp));

        opt.const_prop(&mut block);
        eprintln!("{:?}", block);
        opt.dead_store_elimination(&mut block);

        eprintln!("{:?}", block);
        assert_eq!(block.instructions.len(), 1);
        assert_eq!(block.instructions[0], Instruction::from((b, Op::Copy, a)));
    }

    #[test]
    fn avoid_const_prop_of_invalid_varnodes() {
        let mut opt = Optimizer::new();
        let mut block = pcode::Block::new();

        let a = VarNode::new(1, 8);
        let b = VarNode::new(2, 8);

        block.push((b, Op::PcodeOp(0), a));
        opt.const_prop(&mut block);
        eprintln!("{:?}", block);
        opt.dead_store_elimination(&mut block);

        eprintln!("{:?}", block);
        assert_eq!(block.instructions[0], Instruction::from((b, Op::PcodeOp(0), a)));
    }
}
