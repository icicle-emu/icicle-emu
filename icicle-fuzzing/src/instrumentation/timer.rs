use icicle_vm::{
    cpu::{BlockGroup, BlockTable, Cpu},
    CodeInjector, Vm,
};
use pcode::Op;

pub fn add_block_timer<F>(vm: &mut Vm, mut hook: F) -> BlockTimerRef
where
    F: FnMut(&mut Cpu, u64) + 'static,
{
    // @fixme: allow more than one timer.
    let counter = vm
        .cpu
        .arch
        .sleigh
        .add_custom_reg("counter", 8)
        .expect("failed to create varnode for timer");

    let hook_id = vm.cpu.add_hook(Box::new(move |cpu: &mut Cpu, addr: u64| {
        hook(cpu, addr);
    }));

    vm.add_injector(BlockTimerInjector { hook: hook_id, counter });

    BlockTimerRef { _hook: hook_id, counter }
}

#[derive(Copy, Clone)]
pub struct BlockTimerRef {
    _hook: pcode::HookId,
    counter: pcode::VarNode,
}

impl BlockTimerRef {
    #[inline]
    pub fn set_countdown(&self, cpu: &mut Cpu, value: u64) {
        use icicle_vm::cpu::RegValue;
        unsafe { u64::write_unchecked(&mut cpu.regs, self.counter, value) }
    }

    #[inline]
    pub fn get_countdown(&self, cpu: &mut Cpu) -> u64 {
        use icicle_vm::cpu::RegValue;
        // Safety: `self.counter` is guaranteed to be during created initialization.
        unsafe { u64::read_unchecked(&cpu.regs, self.counter) }
    }
}

struct BlockTimerInjector {
    hook: pcode::HookId,
    counter: pcode::VarNode,
}

impl CodeInjector for BlockTimerInjector {
    fn inject(&mut self, _cpu: &mut Cpu, group: &BlockGroup, code: &mut BlockTable) {
        let block = &mut code.blocks[group.blocks.0];
        block
            .pcode
            .instructions
            .insert(0, (self.counter, Op::IntSub, (self.counter, 1_u64)).into());

        let cond = block.pcode.alloc_tmp(1);
        block.pcode.instructions.insert(1, (cond, Op::IntEqual, (self.counter, 0_u64)).into());
        block.pcode.instructions.insert(2, (Op::HookIf(self.hook), cond).into());

        code.modified.insert(group.blocks.0);
    }
}
