//! A workaround for missing functionality in the SLEIGH spec for MSP430X.

use crate::{exec::const_eval, lifter::BlockLifter, Arch, Cpu, Exception, ExceptionCode, ValueSource};

use super::BlockState;

pub fn status_register_control_patch(cpu: &mut Cpu, lifter: &mut BlockLifter) {
    let check = cpu.arch.sleigh.register_user_op(Some("check_sr_control_bits"));
    cpu.set_helper(check, check_sr_control_bits);
    lifter.op_injectors.insert(
        check,
        Box::new(|_: &Arch, op, inputs, dst: pcode::VarNode, state: &mut BlockState| {
            state.pcode.push((dst, pcode::Op::PcodeOp(op), inputs));
            // Ensure that the block is terminated when the status register is checked.
            true
        }),
    );

    let check_async = cpu.arch.sleigh.register_user_op(Some("check_sr_control_bits_async"));
    cpu.set_helper(check_async, check_sr_control_bits);

    let status_reg = cpu.arch.sleigh.get_reg("SR").unwrap().var;
    let mut const_prop = const_eval::ConstEval::new();
    let handler = move |block: &mut pcode::Block| {
        block.recompute_next_tmp();
        const_prop.clear();

        let old = const_prop.get_value(status_reg.into());
        for stmt in &block.instructions {
            const_prop.eval(*stmt);
        }
        let new = const_prop.get_value(status_reg.into());

        // Bits 3 to 7 change the behaviour of the CPU, so we inject a custom checker function to
        // allow use to handle the change if a bit was potentially changed.
        let control_bits_changed =
            old.iter().zip(&*new).skip(3).take(5).any(|(before, after)| before != after);
        if !control_bits_changed {
            // Impossible for the control registers to change, so we can just return.
            return;
        }

        // At the start of ths instruction save the current value of the status register.
        let start =
            block.instructions.iter().position(|x| x.op == pcode::Op::InstructionMarker).unwrap();
        let old_status_reg = block.alloc_tmp(4);
        block.instructions.insert(start + 1, (old_status_reg, pcode::Op::Copy, status_reg).into());

        let last = block.instructions.last().unwrap();
        match last.op {
            // If the last operation is a branch then we need to defer exits for sleep mode
            // until after the block exit.
            pcode::Op::Branch(_) | pcode::Op::PcodeBranch(_) => {
                let branch_op = block.instructions.pop().unwrap();
                block.push((pcode::Op::PcodeOp(check_async), (old_status_reg, status_reg)));
                block.push(branch_op);
            }

            // If this a non-branching operation then we can just handle a potential sleep event
            // directly after the instruction has been executed.
            _ => block.push((pcode::Op::PcodeOp(check), (old_status_reg, status_reg))),
        }
    };

    lifter.patchers.push(Box::new(handler));
}

/// The bit in the status register representing whether interrupts are currently enabled.
const GIE_BIT: u32 = 0b0000_1000;

/// The bit in the status register representing whether the CPU is off.
const CPUOFF_BIT: u32 = 0b0001_0000;

fn check_sr_control_bits(cpu: &mut Cpu, _dst: pcode::VarNode, args: [pcode::Value; 2]) {
    let old = cpu.read::<u32>(args[0]);
    let new = cpu.read::<u32>(args[1]);
    if (old & GIE_BIT) != (new & GIE_BIT) || (old & CPUOFF_BIT) != (new & CPUOFF_BIT) {
        cpu.pending_exception = Some(Exception::new(ExceptionCode::CpuStateChanged, 0));
        cpu.update_fuel(0);
    }
}
