use icicle_cpu::debug_info::SourceLocation;
use pcode::PcodeDisplay;

use crate::{lifter::BlockGroup, ValueSource, Vm};

pub fn dump_disasm(vm: &Vm) -> Result<String, std::fmt::Error> {
    let sorted_groups = {
        let mut groups: Vec<_> = vm.code.map.values().copied().collect();
        groups.sort_by_key(|x| x.start);
        groups
    };

    let mut out = String::new();
    for group in sorted_groups {
        dump_group_disasm(vm, group, &mut out, true)?;
        out.push('\n');
    }

    Ok(out)
}

pub fn dump_group_disasm(
    vm: &Vm,
    group: BlockGroup,
    out: &mut String,
    print_block_id: bool,
) -> std::fmt::Result {
    use std::fmt::Write;

    for i in group.range() {
        let block = &vm.code.blocks[i];
        if print_block_id {
            writeln!(out, "<{i}> (exit_ctx={:0b}):", block.context.reverse_bits())?;
        }
        for op in &block.pcode.instructions {
            if matches!(op.op, pcode::Op::InstructionMarker) {
                let addr = op.inputs.first().as_u64();
                match vm.code.disasm.get(&addr) {
                    Some(disasm) => writeln!(out, "[{addr:#0x}] {disasm}")?,
                    None => writeln!(out, "[{addr:#0x}] <unavailable>")?,
                }
            }
        }
    }
    Ok(())
}

pub fn debug_block_group(vm: &Vm, group: &BlockGroup) -> Result<String, std::fmt::Error> {
    group.to_string(&vm.code.blocks, &vm.cpu.arch.sleigh, true)
}

pub fn dump_semantics(vm: &Vm) -> Result<String, std::fmt::Error> {
    let sorted_groups = {
        let mut groups: Vec<_> = vm.code.map.values().copied().collect();
        groups.sort_by_key(|x| x.blocks);
        groups
    };

    let mut out = String::new();
    for group in sorted_groups {
        out.push_str(&group.to_string_with_disasm(
            &vm.code.blocks,
            &vm.cpu.arch.sleigh,
            false,
            &vm.code.disasm,
        )?);
        out.push('\n');
    }

    Ok(out)
}

pub fn debug_addr(vm: &mut Vm, addr: u64) -> Result<String, std::fmt::Error> {
    let key = vm.get_block_key(addr);
    match vm.code.map.get(&key) {
        Some(group) => debug_block_group(vm, group),
        None => Ok(format!("no block at {:#x}", addr)),
    }
}

pub fn current_disasm(vm: &Vm) -> String {
    use std::fmt::Write;

    let (block_id, block_offset) = match vm.get_current_block() {
        Some(state) => state,
        None => return "<no active block>".to_string(),
    };

    let mut out = String::new();

    let block = &vm.code.blocks[block_id as usize];
    for (i, op) in block.pcode.instructions.iter().enumerate() {
        if matches!(op.op, pcode::Op::InstructionMarker) {
            let addr = op.inputs.first().as_u64();
            match vm.code.disasm.get(&addr) {
                Some(disasm) => write!(out, "[{addr:#0x}] {disasm}").unwrap(),
                None => write!(out, "[{addr:#0x}] <unavailable>").unwrap(),
            }
        }
        else {
            write!(out, "\t{}", op.display(&vm.cpu.arch.sleigh)).unwrap();
        }
        if i == block_offset as usize {
            write!(out, " <-- next instruction").unwrap();
        }
        out.push('\n');
    }

    write!(out, "\t{}", block.exit.display(&vm.cpu.arch.sleigh)).unwrap();
    if block_offset == block.pcode.instructions.len() as u64 {
        write!(out, " <-- next instruction").unwrap();
    }
    out.push('\n');

    out
}

pub fn backtrace(vm: &mut Vm) -> String {
    use std::fmt::Write;

    let mut buf = String::new();
    for addr in vm.get_callstack().into_iter().rev() {
        let location =
            vm.env.symbolize_addr(&mut vm.cpu, addr).unwrap_or(SourceLocation::default());
        writeln!(buf, "{addr:#012x}: {location}").unwrap();
    }

    buf
}

pub fn print_regs(vm: &Vm, regs: &[pcode::VarNode]) -> String {
    use std::fmt::Write;

    // Determine the maximum width of the register name.
    let name_width = regs
        .iter()
        .map(|reg| vm.cpu.arch.sleigh.name_of_varnode(*reg).unwrap_or("").len())
        .max()
        .unwrap_or(8);

    let mut tmp = String::new();
    let mut output = String::new();
    let mut count = 0;
    let mut prev_size = regs.first().map_or(0, |reg| reg.size);
    for &var in regs {
        if count != 0 && prev_size != var.size {
            output.pop();
            output.push('\n');
            count = 0;
        }
        prev_size = var.size;

        count += 1;

        tmp.clear();
        write!(tmp, "{}", var.display(&vm.cpu.arch.sleigh)).unwrap();
        write!(output, "{tmp:<name_width$} = 0x").unwrap();

        let value: [u8; 32] = vm.cpu.read_dynamic(var.into()).zxt();
        for byte in (0..var.size).rev() {
            write!(output, "{:02x}", value[byte as usize]).unwrap();
        }

        if count == 4 {
            output.push('\n');
            count = 0;
        }
        else {
            output.push(' ');
        }
    }
    output
}

pub fn get_debug_regs(cpu: &crate::Cpu) -> Vec<pcode::VarNode> {
    use target_lexicon::Architecture;

    let names = match cpu.arch.triple.architecture {
        Architecture::Arm(_) => &[
            "r0", "r1", "r2", "r3", "r4", "r5", "r6", "r7", "r8", "r9", "r10", "r11", "r12", "sp",
            "lr", "pc", "cpsr", "CY", "ZR", "NG", "OV",
        ][..],
        Architecture::Aarch64(_) => &[
            "pc", "sp", "x0", "x1", "x2", "x3", "x4", "x5", "x6", "x7", "x8", "x9", "x10", "x11",
            "x12", "x13", "x14", "x15", "x16", "x17", "x18", "x19", "x20", "x21", "x22", "x23",
            "x24", "x25", "x26", "x27", "x28", "x29", "x30", "xzr", "NG", "ZR", "CY", "OV",
        ][..],
        Architecture::X86_64 => &[
            "RAX", "RBX", "RCX", "RDX", "RSI", "RDI", "RBP", "RSP", "R8", "R9", "R10", "R11",
            "R12", "R13", "R14", "R15", "RIP", "ZF", "CF", "SF", "OF",
        ][..],
        Architecture::Mips32(_) => &[
            "at", "v0", "v1", "a0", "a1", "a2", "a3", "t0", "t1", "t2", "t3", "t4", "t5", "t6",
            "t7", "s0", "s1", "s2", "s3", "s4", "s5", "s6", "s7", "t8", "t9", "k0", "k1", "gp",
            "sp", "s8", "ra", "pc",
        ][..],
        Architecture::Riscv64(_) => &[
            "ra", "sp", "gp", "tp", "t0", "t1", "t2", "s0", "s1", "a0", "a1", "a2", "a3", "a4",
            "a5", "a6", "a7", "s2", "s3", "s4", "s5", "s6", "s7", "s8", "s9", "s10", "s11", "t3",
            "t4", "t5", "t6",
        ][..],
        Architecture::Msp430 => &[
            "PC", "SP", "SR", "R3", "R4", "R5", "R6", "R7", "R8", "R9", "R10", "R11", "R12", "R13",
            "R14", "R15",
        ][..],
        Architecture::Powerpc => &[
            "r0", "r1", "r2", "r3", "r4", "r5", "r6", "r7", "r8", "r9", "r10", "r11", "r12", "r13",
            "r14", "r15", "r16", "r17", "r18", "r19", "r20", "r21", "r22", "r23", "r24", "r25",
            "r26", "r27", "r28", "r29", "r30", "r31",
        ][..],
        Architecture::XTensa => &[
            "a0", "a1", "a2", "a3", "a4", "a5", "a6", "a7", "a8", "a9", "a10", "a11", "a12", "a13",
            "a14", "a15", "i2", "i3", "i4", "i5", "i6", "i7", "o2", "o3", "o4", "o5", "o6", "o7",
            "b0", "b1", "b2", "b3", "b4", "b5", "b6", "b7", "b8", "b9", "b10", "b11", "b12", "b13",
            "b14", "b15", "pc",
        ][..],
        _ => &[][..],
    };
    names.iter().map(|name| cpu.arch.sleigh.get_reg(name).unwrap().var).collect()
}

pub fn log_write(
    vm: &mut Vm,
    label: impl Into<std::borrow::Cow<'static, str>>,
    addr: u64,
    size: u8,
) {
    // @fixme: safety, make memory subsystem take CPU as a parameter.
    let cpu_ptr = vm.cpu.as_mut() as *const crate::Cpu;
    let label = label.into();
    vm.cpu.mem.add_write_hook(
        addr,
        addr + size as u64,
        Box::new(move |_mem: &mut crate::mem::Mmu, addr: u64, value: &[u8]| {
            let value = crate::cpu::utils::get_u64(value);
            let pc = unsafe { &mut (*cpu_ptr).read_pc() };
            let icount = unsafe { &mut (*cpu_ptr).icount() };
            eprintln!("[{pc:#0x}] {label}@{addr:#x} = {value:#x} (icount={icount})");
        }),
    );
}
