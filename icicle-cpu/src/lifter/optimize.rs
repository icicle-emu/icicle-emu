use std::collections::{HashMap, HashSet};

use pcode::{Instruction, Op, PcodeLabel, VarId, VarNode};

use crate::exec::const_eval::{BitVecExt, ConstEval};

struct OptimizerState {
    /// Whether the const evaluator had to bail on the current instruction.
    const_valid: bool,

    /// Bit-level const evaluator.
    const_eval: ConstEval,
}

impl OptimizerState {
    fn reset(&mut self) {
        self.const_valid = false;
        self.const_eval.clear();
    }

    /// Const propagates a single value.
    fn const_prop_value(&mut self, value: pcode::Value) -> pcode::Value {
        if value.is_invalid() {
            return value;
        }

        match self.const_eval.get_const(value.into()) {
            Some(x) => pcode::Value::Const(x, value.size()),
            None => {
                let existing = self.const_eval.get_value(value);
                self.const_eval.matches_existing(&existing).map_or(value, |x| x.into())
            }
        }
    }
}

pub struct Optimizer {
    /// Configures whether the optimzer is operating on a block representing a single instruction
    /// only. Within an instruction boundary we allow redundant loads/stores to be removed.
    _single_instruction_only: bool,

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

    /// The optimizer state used for evaluating an instruction.
    state: std::cell::RefCell<OptimizerState>,
}

impl Optimizer {
    pub fn new() -> Self {
        Self {
            _single_instruction_only: true,
            dead_store_detector: DeadStoreDetector::default(),
            labels: HashMap::new(),
            reachable_labels: HashSet::new(),
            jump_target: None,
            block: pcode::Block::new(),
            state: std::cell::RefCell::new(OptimizerState {
                const_valid: false,
                const_eval: ConstEval::new(),
            }),
        }
    }

    pub fn mark_as_temporary(&mut self, var: VarId) {
        self.dead_store_detector.additional_tmps.insert(var);
    }

    /// Simplifies the target block by propagating constants.
    pub fn const_prop(&mut self, block: &mut pcode::Block) -> Result<(), ()> {
        self.block.clear();
        self.state.get_mut().reset();
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
                if self.labels[&label] < idx {
                    self.reachable_labels.insert(label);
                }
            }
        }

        for stmt in &block.instructions {
            // Assume that the current instruction can be const evaluated.
            self.state.get_mut().const_valid = true;

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
                    self.state.get_mut().const_eval.clear();
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

            if let Some(inst) = simplify(self, stmt)? {
                self.block.push(inst);
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

        Ok(())
    }

    /// Removes all instructions that write to a variable that is never read.
    pub fn dead_store_elimination(&mut self, block: &mut pcode::Block) {
        let dead_code = self.dead_store_detector.get_dead_code(block);

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
fn simplify(exec: &mut Optimizer, stmt: &Instruction) -> Result<Option<Instruction>, ()> {
    let state = exec.state.get_mut();

    // Perform const propagation on the inputs of the current instruction.
    let inputs =
        [state.const_prop_value(stmt.inputs.first()), state.const_prop_value(stmt.inputs.second())];
    let input_values =
        [state.const_eval.get_value(inputs[0]), state.const_eval.get_value(inputs[1])];
    let updated_instruction = Instruction::from((stmt.output, stmt.op, inputs));

    let prev_output = state.const_eval.get_value(stmt.output.into());
    state.const_eval.eval(updated_instruction)?;

    // If the instruction is an internal branch, then we need to keep track of the label that we are
    // jumping to.
    if let Op::PcodeBranch(label) = stmt.op {
        match state.const_eval.get_const(inputs[0]) {
            Some(0) => {
                // The branch is always false, so skip the branch.
                return Ok(None);
            }
            Some(1) => {
                exec.jump_target = Some(label);
                return Ok(None);
            }
            _ => {}
        }
        // We know know we can reach the target label is reachable.
        exec.reachable_labels.insert(label);

        // @todo: add a barrier here?
        // exec.barrier();
    }

    if let Op::Branch(_) = stmt.op {
        if state.const_eval.get_const(inputs[0]) == Some(0) {
            // The branch is always false, so skip the branch.
            return Ok(None);
        }
        // @todo: add a barrier here?
        // exec.barrier();
    }

    if external_state_modifications(stmt.op) {
        // Need to flush const evaluation state, since the target operation may modify any register.
        state.const_eval.clear();
    }

    if stmt.op.has_side_effects() {
        // If the instruction has side-effects then we need to retain the original instruction.
        return Ok(Some(updated_instruction));
    }

    let output = state.const_eval.get_value(stmt.output.into());
    if output == prev_output {
        // If the instruction has no side-effects and the output value hasn't changed then we can
        // safely remove ignore this instruction.
        return Ok(None);
    }

    if let Some(value) = output.get_const() {
        // Copy from constant.
        return Ok(Some(stmt.output.copy_from(pcode::Value::Const(value, stmt.output.size))));
    }
    else if output == input_values[0] {
        // Copy from first input.
        Ok(Some(stmt.output.copy_from(inputs[0])))
    }
    else if output == input_values[1] {
        // Copy from second input.
        Ok(Some(stmt.output.copy_from(inputs[1])))
    }
    else {
        // Unable to simplify the instruction.
        Ok(Some(updated_instruction))
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
}

impl DeadStoreDetector {
    fn get_dead_code(&mut self, block: &pcode::Block) -> &HashSet<usize> {
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

        if self.should_persist(var) {
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
    fn should_persist(&self, var: VarNode) -> bool {
        !var.is_temp() && !self.additional_tmps.contains(&var.id)
    }
}

fn external_state_modifications(op: Op) -> bool {
    match op {
        Op::Hook(_) => true,
        _ => false,
    }
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

        opt.const_prop(&mut block).unwrap();
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

        opt.const_prop(&mut block).unwrap();
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
        opt.const_prop(&mut block).unwrap();
        eprintln!("{:?}", block);
        opt.dead_store_elimination(&mut block);

        eprintln!("{:?}", block);
        assert_eq!(block.instructions[0], Instruction::from((b, Op::PcodeOp(0), a)));
    }
}
