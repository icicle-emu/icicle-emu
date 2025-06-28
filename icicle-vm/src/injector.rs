use std::any::Any;

use icicle_cpu::{BlockGroup, BlockTable, Cpu};

use crate::Vm;

pub type InjectorRef = usize;

pub trait CodeInjector {
    fn inject(&mut self, cpu: &mut Cpu, group: &BlockGroup, code: &mut BlockTable);
}

pub trait CodeInjectorAny: CodeInjector + 'static {
    fn as_mut_any(&mut self) -> &mut dyn Any;
}

impl<I: CodeInjector + 'static> CodeInjectorAny for I {
    fn as_mut_any(&mut self) -> &mut dyn Any {
        self
    }
}

pub fn register_block_hook_injector(
    vm: &mut Vm,
    start: u64,
    end: u64,
    hook: pcode::HookId,
) -> usize {
    let injector = BlockHookInjector { hook, start, end };
    vm.add_injector(injector)
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

pub fn register_instruction_hook_injector(
    vm: &mut Vm,
    addrs: Vec<u64>,
    hook: pcode::HookId,
) -> usize {
    let injector = InstructionHookInjection { hook, addrs, tmp_block: pcode::Block::new() };
    vm.add_injector(injector)
}

struct InstructionHookInjection {
    hook: pcode::HookId,
    addrs: Vec<u64>,
    tmp_block: pcode::Block,
}

impl CodeInjector for InstructionHookInjection {
    fn inject(&mut self, _cpu: &mut Cpu, group: &BlockGroup, code: &mut BlockTable) {
        if !self.addrs.iter().any(|&addr| group.start <= addr && addr < group.end) {
            return;
        }

        for id in group.range() {
            let block = &mut code.blocks[id];

            self.tmp_block.clear();
            self.tmp_block.next_tmp = block.pcode.next_tmp;

            for stmt in block.pcode.instructions.drain(..) {
                self.tmp_block.push(stmt);
                if let pcode::Op::InstructionMarker = stmt.op {
                    if self.addrs.iter().any(|&addr| addr == stmt.inputs.first().as_u64()) {
                        self.tmp_block.push(pcode::Op::Hook(self.hook));
                        code.modified.insert(id);
                    }
                }
            }

            std::mem::swap(&mut self.tmp_block.instructions, &mut block.pcode.instructions);
        }
    }
}

struct PathTracer {
    /// A list of (block address, icount) pairs tracking all blocks hit by the emulator.
    blocks: Vec<(u64, u64)>,
}

impl PathTracer {
    fn new() -> Self {
        Self { blocks: vec![] }
    }
}

impl crate::cpu::HookHandler for PathTracer {
    fn call(data: &mut Self, cpu: &mut Cpu, addr: u64) {
        // Avoid using up too much memory if we end up with an extremely long execution.
        if data.blocks.len() > 0x100_0000 {
            data.blocks.truncate(0);
        }

        data.blocks.push((addr, cpu.icount()))
    }
}

pub fn add_path_tracer(vm: &mut Vm) -> anyhow::Result<PathTracerRef> {
    let hook = vm.cpu.add_hook(PathTracer::new());
    register_block_hook_injector(vm, 0, u64::MAX, hook);
    Ok(PathTracerRef(hook))
}

#[derive(Copy, Clone)]
pub struct PathTracerRef(pcode::HookId);

impl PathTracerRef {
    pub fn print_last_blocks(&self, vm: &mut Vm, count: usize) -> String {
        use std::fmt::Write;

        let mut output = String::new();

        for (addr, _) in self.get_last_blocks(vm).iter().rev().take(count) {
            let location = vm
                .env
                .symbolize_addr(&mut vm.cpu, *addr)
                .unwrap_or(crate::cpu::debug_info::SourceLocation::default());
            writeln!(output, "{addr:#x}: {location}").unwrap();
        }

        output
    }

    pub fn get_last_blocks(&self, vm: &mut Vm) -> Vec<(u64, u64)> {
        let path_tracer = vm.cpu.get_hook_mut(self.0);
        path_tracer.data_mut::<PathTracer>().unwrap().blocks.clone()
    }

    pub fn clear(&self, vm: &mut Vm) {
        let path_tracer = vm.cpu.get_hook_mut(self.0);
        path_tracer.data_mut::<PathTracer>().unwrap().blocks.clear();
    }

    pub fn restore(&self, vm: &mut Vm, snapshot: &Vec<(u64, u64)>) {
        let path_tracer = vm.cpu.get_hook_mut(self.0);
        let blocks = &mut path_tracer.data_mut::<PathTracer>().unwrap().blocks;
        blocks.clear();
        blocks.extend_from_slice(snapshot)
    }

    pub fn save_trace(&self, vm: &mut Vm, path: &std::path::Path) -> anyhow::Result<()> {
        use std::io::Write;

        let mut output = std::io::BufWriter::new(std::fs::File::create(path)?);
        for (addr, icount) in self.get_last_blocks(vm) {
            writeln!(output, "{addr:#x},{icount}")?;
        }

        Ok(())
    }
}
