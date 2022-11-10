use std::collections::HashMap;

use crate::{
    lifter::{BlockState, InstructionSource},
    Cpu, ExceptionCode,
};

pub trait PcodeOpInjector {
    fn inject_ops(
        &mut self,
        src: &dyn InstructionSource,
        id: pcode::PcodeOpId,
        inputs: pcode::Inputs,
        output: pcode::VarNode,
        state: &mut BlockState,
    ) -> bool;
}

impl<F> PcodeOpInjector for F
where
    F: FnMut(
        &dyn InstructionSource,
        pcode::PcodeOpId,
        pcode::Inputs,
        pcode::VarNode,
        &mut BlockState,
    ) -> bool,
{
    fn inject_ops(
        &mut self,
        src: &dyn InstructionSource,
        id: pcode::PcodeOpId,
        inputs: pcode::Inputs,
        output: pcode::VarNode,
        state: &mut BlockState,
    ) -> bool {
        self(src, id, inputs, output, state)
    }
}

fn invalid_instruction(
    _: &dyn InstructionSource,
    _: pcode::PcodeOpId,
    inputs: pcode::Inputs,
    _: pcode::VarNode,
    state: &mut BlockState,
) -> bool {
    let value = if !inputs.first().is_invalid() { inputs.first() } else { 0.into() };
    state.pcode.push((pcode::Op::Exception, (ExceptionCode::InvalidInstruction as u32, value)));
    true
}

fn halt(
    _: &dyn InstructionSource,
    _: pcode::PcodeOpId,
    inputs: pcode::Inputs,
    _: pcode::VarNode,
    state: &mut BlockState,
) -> bool {
    let value = if !inputs.first().is_invalid() { inputs.first() } else { 0.into() };
    state.pcode.push((pcode::Op::Exception, (ExceptionCode::Halt as u32, value)));
    true
}

fn syscall(
    src: &dyn InstructionSource,
    _: pcode::PcodeOpId,
    inputs: pcode::Inputs,
    _: pcode::VarNode,
    state: &mut BlockState,
) -> bool {
    state.gen_set_next_pc(src);
    let value = if !inputs.first().is_invalid() { inputs.first() } else { 0.into() };
    state.pcode.push((pcode::Op::Exception, (ExceptionCode::Syscall as u32, value)));
    true
}

fn ignored_hint(
    _: &dyn InstructionSource,
    _: pcode::PcodeOpId,
    _: pcode::Inputs,
    _: pcode::VarNode,
    _: &mut BlockState,
) -> bool {
    false
}

pub fn get_injectors(
    cpu: &Cpu,
    injectors: &mut HashMap<pcode::PcodeOpId, Box<dyn PcodeOpInjector>>,
) {
    /// All the different ways that various SLEIGH specifications refer to syscalls/traps.
    const SYSCALL_OPS: &[&str] =
        &["syscall", "ecall", "software_interrupt", "swi", "CallSupervisor", "software_bkpt"];

    for id in SYSCALL_OPS.iter().filter_map(|name| cpu.arch.sleigh.get_userop(name)) {
        injectors.insert(id, Box::new(syscall));
    }

    /// Names for barrier-like operations
    const BARRIER_OPS: &[&str] = &[
        "barrier",
        "fence",
        "sync",
        "SYNC",
        "DataMemoryBarrier",
        "InstructionSynchronizationBarrier",
        "DataSynchronizationBarrier",
    ];
    for id in BARRIER_OPS.iter().filter_map(|name| cpu.arch.sleigh.get_userop(name)) {
        // We don't currently emulate caches so we ignore barrier-like operations.
        injectors.insert(id, Box::new(ignored_hint));
    }

    /// Names for hints
    const HINT_OPS: &[&str] = &["prefetch", "Hint_Prefetch"];
    for id in HINT_OPS.iter().filter_map(|name| cpu.arch.sleigh.get_userop(name)) {
        injectors.insert(id, Box::new(ignored_hint));
    }

    /// Names for invalid instructions
    const INVALID_INSTRUCTION_OPS: &[&str] = &["invalidInstructionException", "software_udf"];
    for id in INVALID_INSTRUCTION_OPS.iter().filter_map(|name| cpu.arch.sleigh.get_userop(name)) {
        injectors.insert(id, Box::new(invalid_instruction));
    }

    /// Names for halts
    const HALT_OPS: &[&str] = &["software_hlt"];
    for id in HALT_OPS.iter().filter_map(|name| cpu.arch.sleigh.get_userop(name)) {
        injectors.insert(id, Box::new(halt));
    }

    if matches!(cpu.arch.triple.architecture, target_lexicon::Architecture::Aarch64(_)) {
        aarch64::get_injectors(cpu, injectors);
    }

    if matches!(cpu.arch.triple.architecture, target_lexicon::Architecture::Mips32(_)) {
        mips32::get_injectors(cpu, injectors);
    }
}

pub mod aarch64 {
    use super::*;

    pub fn get_injectors(
        cpu: &Cpu,
        injectors: &mut HashMap<pcode::PcodeOpId, Box<dyn PcodeOpInjector>>,
    ) {
        if let Some(id) = cpu.arch.sleigh.get_userop("ExclusiveMonitorPass") {
            injectors.insert(
                id,
                Box::new(|_: &dyn InstructionSource, _, _, dst, state: &mut BlockState| {
                    state.pcode.push((dst, pcode::Op::Copy, 1_u8));
                    false
                }),
            );
        }

        if let Some(id) = cpu.arch.sleigh.get_userop("ExclusiveMonitorsStatus") {
            injectors.insert(
                id,
                Box::new(|_: &dyn InstructionSource, _, _, dst, state: &mut BlockState| {
                    state.pcode.push((dst, pcode::Op::Copy, 0_u8));
                    false
                }),
            );
        }
    }
}

pub mod mips32 {
    use super::*;

    pub fn get_injectors(
        cpu: &Cpu,
        injectors: &mut HashMap<pcode::PcodeOpId, Box<dyn PcodeOpInjector>>,
    ) {
        if let Some(id) = cpu.arch.sleigh.get_userop("getHWRegister") {
            injectors.insert(
                id,
                Box::new(|_: &dyn InstructionSource, _, input, dst, state: &mut BlockState| {
                    state.pcode.push((dst, pcode::Op::Copy, input));
                    false
                }),
            );
        }
    }
}
