use icicle_cpu::{BlockGroup, BlockTable, Cpu};

use crate::Vm;

pub trait CodeInjector {
    fn inject(&mut self, cpu: &mut Cpu, group: &BlockGroup, code: &mut BlockTable);
}

pub fn register_block_hook_injector(
    vm: &mut Vm,
    start: u64,
    end: u64,
    hook: pcode::HookId,
) -> usize {
    let injector = BlockHookInjector { hook, start, end };
    vm.add_injector(Box::new(injector))
}

struct BlockHookInjector {
    hook: pcode::HookId,
    start: u64,
    end: u64,
}

impl CodeInjector for BlockHookInjector {
    fn inject(&mut self, _cpu: &mut Cpu, group: &BlockGroup, code: &mut BlockTable) {
        let block = &mut code.blocks[group.blocks.0];
        if block.start < self.start || block.start >= self.end {
            return;
        }
        block.pcode.instructions.insert(0, pcode::Op::Hook(self.hook).into());
        code.modified.insert(group.blocks.0);
    }
}

pub fn register_instruction_hook_injector(vm: &mut Vm, addr: u64, hook: pcode::HookId) -> usize {
    let injector = InstructionHookInjection { hook, addr, tmp_block: pcode::Block::new() };
    vm.add_injector(Box::new(injector))
}

struct InstructionHookInjection {
    hook: pcode::HookId,
    addr: u64,
    tmp_block: pcode::Block,
}

impl CodeInjector for InstructionHookInjection {
    fn inject(&mut self, _cpu: &mut Cpu, group: &BlockGroup, code: &mut BlockTable) {
        for id in group.range() {
            let block = &mut code.blocks[id];
            if !(block.start <= self.addr && self.addr < block.end) {
                continue;
            }

            self.tmp_block.clear();
            for stmt in block.pcode.instructions.drain(..) {
                if let pcode::Op::InstructionMarker = stmt.op {
                    if stmt.inputs.first().as_u64() == self.addr {
                        self.tmp_block.push(pcode::Op::Hook(self.hook));
                        code.modified.insert(id);
                    }
                }
                self.tmp_block.push(stmt);
            }

            std::mem::swap(&mut self.tmp_block.instructions, &mut block.pcode.instructions);
        }
    }
}
