use icicle_vm::cpu::{
    mem::{self, perm},
    utils, ValueSource,
};

use crate::{Assignment, TestCase};

pub trait Tester {
    fn init(&mut self, test: &TestCase) -> anyhow::Result<()>;
    fn check_decode_and_lift(&mut self, test: &TestCase) -> anyhow::Result<String>;
    fn start_at(&mut self, inst_ptr: u64);
    fn step(&mut self, steps: u64) -> anyhow::Result<()>;
    fn write_assignment(&mut self, assignment: &Assignment) -> anyhow::Result<()>;
    fn check_assignment(&mut self, assignment: &Assignment) -> anyhow::Result<()>;
}

impl Tester for icicle_vm::Vm {
    fn init(&mut self, test: &TestCase) -> anyhow::Result<()> {
        self.reset();
        self.lifter.settings.max_instructions_per_block = test.instructions.len();

        let start = test.load_addr;
        let end = test.load_addr.checked_add(0x1000).unwrap();
        self.cpu.mem.map_memory(start, end, mem::Mapping { perm: perm::NONE, value: 0x00 });
        self.cpu.mem.write_bytes(test.load_addr, &[0; 0x1000], perm::NONE)?;

        let mut addr = test.load_addr;
        for entry in &test.instructions {
            self.cpu.mem.write_bytes(addr, &entry.bytes, perm::NONE)?;
            addr += entry.bytes.len() as u64;
        }
        self.cpu.mem.update_perm(
            test.load_addr,
            addr - test.load_addr,
            perm::READ | perm::INIT | perm::EXEC,
        )?;

        (self.cpu.arch.on_boot)(&mut self.cpu, test.load_addr);
        self.cpu.set_isa_mode(test.isa_mode);

        Ok(())
    }

    fn check_decode_and_lift(&mut self, test: &TestCase) -> anyhow::Result<String> {
        self.cpu.set_isa_mode(test.isa_mode);

        let group = self.lift(test.load_addr);
        let mut decoded = vec![];
        if let Some(group) = group {
            for block in &self.code.blocks[group.range()] {
                for stmt in &block.pcode.instructions {
                    if let pcode::Op::InstructionMarker = stmt.op {
                        let addr = stmt.inputs.first().as_u64();
                        let len = stmt.inputs.second().as_u64();
                        let disasm = self
                            .code
                            .disasm
                            .get(&addr)
                            .map_or("invalid_instruction", |x| x.as_str());
                        decoded.push((addr, len, disasm));
                    }
                }
            }
            decoded.sort_by_key(|x| x.0);
        }

        if decoded.len() != test.instructions.len()
            && !(test.instructions.len() == 1
                && test.instructions[0].disasm == "invalid_instruction")
        {
            anyhow::bail!(
                "decoded instruction count {} != expected {} group {:?}",
                decoded.len(),
                test.instructions.len(),
                group,
            );
        }

        let mut output = String::new();
        for ((_, len, disasm), expected) in decoded.into_iter().zip(&test.instructions) {
            if len != expected.expected_len as u64 {
                anyhow::bail!(
                    "line {}: decoded instruction length {len} != expected {}",
                    expected.line,
                    expected.expected_len
                );
            }

            if disasm.replace(" ", "") != expected.disasm.replace(" ", "") {
                anyhow::bail!(
                    "line {}: decoded instruction disasm {disasm} != expected {}",
                    expected.line,
                    expected.disasm
                );
            }

            output.push_str(disasm);
            output.push_str("\n");
        }

        if let Some(group) = group {
            let lifted = icicle_vm::debug::debug_block_group(self, &group)?;
            output.push_str(&lifted);
        }
        output.push_str("\n");

        Ok(output)
    }

    fn start_at(&mut self, inst_ptr: u64) {
        self.cpu.icount = 0;
        self.cpu.exception.clear();
        self.cpu.write_pc(inst_ptr);
    }

    fn step(&mut self, steps: u64) -> anyhow::Result<()> {
        use icicle_vm::{cpu::ExceptionCode, VmExit};

        let exit = self.step(steps);

        // Note we also allow exits where the shadow stack is invalid to allow testing "return"
        // operations.
        //
        // @fixme: Add support in the tester for configuring shadow stack.
        if !matches!(
            exit,
            VmExit::InstructionLimit
                | VmExit::UnhandledException((ExceptionCode::ShadowStackInvalid, _))
        ) {
            anyhow::bail!("Unexpected exit: {exit:?}");
        }

        Ok(())
    }

    fn write_assignment(&mut self, assignment: &Assignment) -> anyhow::Result<()> {
        match assignment {
            Assignment::Mem { addr, perm, value } => {
                let start = utils::align_down(*addr, 0x1000);
                let end = utils::align_up(start + value.len() as u64, 0x1000);
                self.cpu.mem.unmap_memory(start, end);
                let mapping = mem::Mapping { perm: *perm, value: 0x0 };
                self.cpu.mem.map_memory(*addr, end, mapping);
                self.cpu.mem.write_bytes(*addr, value, perm::NONE)?;
            }
            &Assignment::Register { name, value } => {
                let varnode = self.cpu.arch.sleigh.get_reg(name).unwrap().var;
                self.cpu.write_trunc(varnode, value);
            }
        }
        Ok(())
    }

    fn check_assignment(&mut self, assignment: &Assignment) -> anyhow::Result<()> {
        match assignment {
            Assignment::Mem { addr, perm: _, value } => {
                let mut tmp = vec![0; value.len()];
                self.cpu.mem.read_bytes(*addr, &mut tmp, perm::NONE)?;
                anyhow::ensure!(
                    &tmp == value,
                    "expected: {assignment} (got {})",
                    utils::format_bytes(&tmp)
                );
            }
            &Assignment::Register { name, value } => {
                let varnode = self.cpu.arch.sleigh.get_reg(name).unwrap().var;
                let tmp: u128 = self.cpu.read_dynamic(varnode.into()).zxt();
                let value =
                    if varnode.size < 16 { value & ((1 << (varnode.size * 8)) - 1) } else { value };
                anyhow::ensure!(tmp == value, "expected: {} (got {:#0x})", assignment, tmp);
            }
        }
        Ok(())
    }
}
