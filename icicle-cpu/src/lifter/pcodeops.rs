use hashbrown::HashMap;

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

fn gen_exception(
    src: &dyn InstructionSource,
    inputs: pcode::Inputs,
    state: &mut BlockState,
    code: ExceptionCode,
) -> bool {
    state.gen_set_next_pc(src);
    let value = if !inputs.first().is_invalid() { inputs.first() } else { 0.into() };
    state.pcode.push((pcode::Op::Exception, (code as u32, value)));
    true
}

fn invalid_instruction(
    src: &dyn InstructionSource,
    _: pcode::PcodeOpId,
    inputs: pcode::Inputs,
    _: pcode::VarNode,
    state: &mut BlockState,
) -> bool {
    gen_exception(src, inputs, state, ExceptionCode::InvalidInstruction)
}

fn halt(
    src: &dyn InstructionSource,
    _: pcode::PcodeOpId,
    inputs: pcode::Inputs,
    _: pcode::VarNode,
    state: &mut BlockState,
) -> bool {
    gen_exception(src, inputs, state, ExceptionCode::Halt)
}

fn sleep(
    src: &dyn InstructionSource,
    _: pcode::PcodeOpId,
    inputs: pcode::Inputs,
    _: pcode::VarNode,
    state: &mut BlockState,
) -> bool {
    gen_exception(src, inputs, state, ExceptionCode::Sleep)
}

fn breakpoint(
    src: &dyn InstructionSource,
    _: pcode::PcodeOpId,
    inputs: pcode::Inputs,
    _: pcode::VarNode,
    state: &mut BlockState,
) -> bool {
    gen_exception(src, inputs, state, ExceptionCode::SoftwareBreakpoint)
}

fn syscall(
    src: &dyn InstructionSource,
    _: pcode::PcodeOpId,
    inputs: pcode::Inputs,
    _: pcode::VarNode,
    state: &mut BlockState,
) -> bool {
    gen_exception(src, inputs, state, ExceptionCode::Syscall)
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

fn barrier(
    _: &dyn InstructionSource,
    _: pcode::PcodeOpId,
    _: pcode::Inputs,
    _: pcode::VarNode,
    _: &mut BlockState,
) -> bool {
    // @fixme: convert barriers to block boundaries (currently not done for compatibility reasons).
    false
}

pub fn get_injectors(
    cpu: &mut Cpu,
    injectors: &mut HashMap<pcode::PcodeOpId, Box<dyn PcodeOpInjector>>,
) {
    /// All the different ways that various SLEIGH specifications refer to syscalls/traps.
    const SYSCALL_OPS: &[&str] =
        &["syscall", "ecall", "software_interrupt", "swi", "CallSupervisor"];

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
        injectors.insert(id, Box::new(barrier));
    }

    /// Names for hints
    const HINT_OPS: &[&str] = &["prefetch", "Hint_Prefetch", "HintPreloadData"];
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

    /// Names for software breakpoint instructions.
    const BREAKPOINT_OPS: &[&str] = &["software_bkpt"];
    for id in BREAKPOINT_OPS.iter().filter_map(|name| cpu.arch.sleigh.get_userop(name)) {
        injectors.insert(id, Box::new(breakpoint));
    }
    if matches!(cpu.arch.triple.architecture, target_lexicon::Architecture::Aarch64(_)) {
        aarch64::get_injectors(cpu, injectors);
    }

    if matches!(cpu.arch.triple.architecture, target_lexicon::Architecture::Arm(_)) {
        arm::get_injectors(cpu, injectors);
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

pub mod arm {
    use pcode::Inputs;

    use super::*;

    pub fn get_injectors(
        cpu: &mut Cpu,
        injectors: &mut HashMap<pcode::PcodeOpId, Box<dyn PcodeOpInjector>>,
    ) {
        if let Some(id) = cpu.arch.sleigh.get_userop("WaitForInterrupt") {
            injectors.insert(id, Box::new(sleep));
        }
        if let Some(id) = cpu.arch.sleigh.get_userop("WaitForEvent") {
            injectors.insert(id, Box::new(sleep));
        }

        let ex_addr = match cpu.arch.sleigh.get_reg("exclusive_addr") {
            Some(reg) => reg.var,
            None => cpu.arch.sleigh.add_custom_reg("exclusive_addr", 4).unwrap(),
        };

        if let Some(id) = cpu.arch.sleigh.get_userop("ExclusiveAccess") {
            injectors.insert(
                id,
                Box::new(
                    move |_: &dyn InstructionSource,
                          _,
                          input: Inputs,
                          _,
                          state: &mut BlockState| {
                        state.pcode.push(ex_addr.copy_from(input.first()));
                        false
                    },
                ),
            );
        }

        if let Some(id) = cpu.arch.sleigh.get_userop("hasExclusiveAccess") {
            injectors.insert(
                id,
                Box::new(
                    move |_: &dyn InstructionSource,
                          _,
                          inputs: Inputs,
                          dst,
                          state: &mut BlockState| {
                        state.pcode.push((dst, pcode::Op::IntEqual, ex_addr, inputs.first()));
                        false
                    },
                ),
            );
        }

        if let Some(id) = cpu.arch.sleigh.get_userop("ClearExclusiveLocal") {
            injectors.insert(
                id,
                Box::new(move |_: &dyn InstructionSource, _, _, _, state: &mut BlockState| {
                    state.pcode.push(ex_addr.copy_from(u32::MAX));
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
