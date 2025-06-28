use std::collections::HashSet;

use cranelift::{codegen::Context as CodeContext, prelude::*};

use crate::CompilationTarget;

pub(crate) fn debug_il(code_ctx: &CodeContext, target: &CompilationTarget) -> String {
    let mut out = String::new();
    let mut decorator = IcicleDecorator { seen: HashSet::new(), target };
    codegen::write::decorate_function(&mut decorator, &mut out, &code_ctx.func).unwrap();
    out
}

struct IcicleDecorator<'a> {
    seen: HashSet<u32>,
    target: &'a CompilationTarget<'a>,
}

enum Location<'a> {
    Instruction(&'a pcode::Instruction),
    BlockExit(&'a icicle_cpu::lifter::BlockExit),
    End,
}

impl<'a> IcicleDecorator<'a> {
    fn get_pcode(&self, mut id: u32) -> Location {
        for (_, block) in self.target.iter() {
            let locations = block.pcode.instructions.len() + 1;
            if locations <= id as usize {
                id -= locations as u32;
                continue;
            }
            if id == block.pcode.instructions.len() as u32 {
                return Location::BlockExit(&block.exit);
            }
            return Location::Instruction(&block.pcode.instructions[id as usize]);
        }
        Location::End
    }
}

impl<'a> codegen::write::FuncWriter for IcicleDecorator<'a> {
    fn write_block_header(
        &mut self,
        w: &mut dyn std::fmt::Write,
        func: &codegen::ir::Function,
        block: Block,
        indent: usize,
    ) -> std::fmt::Result {
        codegen::write::write_block_header(w, func, block, indent)
    }

    fn write_instruction(
        &mut self,
        w: &mut dyn std::fmt::Write,
        func: &codegen::ir::Function,
        aliases: &codegen::entity::SecondaryMap<Value, Vec<Value>>,
        inst: codegen::ir::Inst,
        indent: usize,
    ) -> std::fmt::Result {
        let srcloc = func.srcloc(inst);
        if !srcloc.is_default() && self.seen.insert(srcloc.bits()) {
            match self.get_pcode(srcloc.bits()) {
                Location::Instruction(stmt) => w.write_fmt(format_args!("    ; {:?}\n", stmt))?,
                Location::BlockExit(exit) => w.write_fmt(format_args!("    ; {:?}\n", exit))?,
                Location::End => w.write_str("    ; jit_exit\n")?,
            }
        }
        codegen::write::PlainWriter.write_instruction(w, func, aliases, inst, indent)
    }
}
