use std::collections::HashSet;

use icicle_cpu::{debug_info::SourceLocation, utils::get_u64};
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
    let pc_valid = block.contains_addr(vm.cpu.read_pc());
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
        if i == block_offset as usize && pc_valid {
            write!(out, " <-- next instruction").unwrap();
        }
        out.push('\n');
    }

    write!(out, "\t{}", block.exit.display(&vm.cpu.arch.sleigh)).unwrap();
    if block_offset == block.pcode.instructions.len() as u64 || !pc_valid {
        write!(out, " <-- next instruction").unwrap();
    }
    out.push('\n');

    out
}

pub fn backtrace(vm: &mut Vm) -> String {
    backtrace_with_limit(vm, 64)
}

pub fn backtrace_with_limit(vm: &mut Vm, max_frames: usize) -> String {
    use std::fmt::Write;

    let mut buf = String::new();
    let callstack = vm.get_debug_callstack();
    let is_truncated = max_frames < callstack.len();

    for (i, addr) in callstack.into_iter().rev().enumerate().take(max_frames) {
        // For all return address subtract 1 so we get the address of the call not the return for
        // the symbol.
        let symbol_addr = if i == 0 { addr } else { addr - 1 };
        let location =
            vm.env.symbolize_addr(&mut vm.cpu, symbol_addr).unwrap_or(SourceLocation::default());
        writeln!(buf, "{addr:#012x}: {location}").unwrap();
    }

    if is_truncated {
        writeln!(buf, "<callstack truncated after {max_frames} frames>").unwrap();
    }
    buf
}

pub fn callstack_from_debug_info(vm: &mut Vm) -> Option<Vec<u64>> {
    let debug_info = vm.env.debug_info()?;
    // @todo: use proper dwarf based unwinding.

    // Find the end of all known blocks in the program. Every returning address must point to the
    // next address after a block.
    // @fixme: this could be slow if this function is frequently called and there are lot of blocks.
    let known_block_ends: HashSet<u64> = vm.code.blocks.iter().map(|x| x.end).collect();

    // Fallback mode: just look for values that look like addresses.
    let sp = vm.cpu.read_reg(vm.cpu.arch.reg_sp);

    // @fixme: we assume stack grows downwards here.
    // @fixme: we assume we can read a full page of data.
    // @fixme: check stack alignment.
    if !vm.cpu.mem.is_regular_region(sp, 0x1000) {
        // Stack pointer is corrupted.
        tracing::debug!("Failed to resolve callstack because stack pointer is corrupted");
        return None;
    }

    tracing::debug!("Trying to resolve callstack by reading: 0x1000 bytes from {sp:#x}");
    let mut stack = [0; 0x1000];
    vm.cpu.mem.read_bytes(sp, &mut stack, icicle_cpu::mem::perm::READ).ok()?;

    let mut callstack = vec![vm.cpu.read_reg(vm.cpu.arch.reg_pc)];
    if let Some(reg_lr) = get_link_register(vm) {
        callstack.push(vm.cpu.read_reg(reg_lr));
    }

    let known_start_symbols = ["main", "reset", "start", "main_trampoline"];
    for chunk in stack.chunks_exact(vm.cpu.arch.reg_pc.size as usize) {
        let mut slot = get_u64(chunk);

        if matches!(vm.cpu.arch.triple.architecture, target_lexicon::Architecture::Arm(_)) {
            // Check if this matches a possible exception handler frame.
            //
            // DISABLED: This is too easily mistaken due to negative return values.
            //
            // const ARM_EXC_RETURN: u64 = 0xf000_0000;
            // if (slot & ARM_EXC_RETURN) == ARM_EXC_RETURN {
            //     callstack.push(slot);
            //     continue;
            // }

            // Remove thumb bit.
            slot &= !1;
        }

        // Ensure that the instruction before the return address is at the end of a known code
        // block.
        if !known_block_ends.contains(&slot) {
            continue;
        }

        if let Some((name, _addr, kind)) = debug_info.symbols.resolve_addr(slot) {
            if matches!(kind, icicle_cpu::debug_info::SymbolKind::Function) {
                callstack.push(slot);
                if known_start_symbols
                    .iter()
                    .any(|x| name.trim_matches('_').eq_ignore_ascii_case(*x))
                {
                    break;
                }
            }
        }
    }

    callstack.reverse();
    Some(callstack)
}

pub fn callstack_from_frame_pointer(vm: &mut Vm) -> Option<Vec<u64>> {
    let reg_sp = vm.cpu.arch.reg_sp;
    let reg_pc = vm.cpu.arch.reg_pc;
    let reg_bp = match vm.cpu.arch.triple.architecture {
        target_lexicon::Architecture::X86_64 => vm.cpu.arch.sleigh.get_reg("RBP")?.var,
        target_lexicon::Architecture::Arm(_) => vm.cpu.arch.sleigh.get_reg("r11")?.var,
        _ => return None,
    };

    let sp = vm.cpu.read_reg(reg_sp);
    let mut bp = vm.cpu.read_reg(reg_bp);

    // @fixme: we assume stack grows downwards here.
    if bp < sp {
        // Invalid stack layout
        return None;
    }

    if !vm.cpu.mem.is_regular_region(sp, 0x1000) {
        // Stack pointer is corrupted.
        return None;
    }

    let mut stack = [0; 0x100];
    vm.cpu.mem.read_bytes(sp, &mut stack, icicle_cpu::mem::perm::READ).ok()?;

    let mut callstack = vec![vm.cpu.read_reg(reg_pc)];
    if let Some(reg_lr) = get_link_register(vm) {
        callstack.push(vm.cpu.read_reg(reg_lr));
    }

    while bp >= sp
        && ((bp - sp) as usize) < stack.len() + (reg_pc.size as usize + reg_bp.size as usize)
    {
        let offset = (bp - sp) as usize;
        // @fixme: endianness.
        bp = get_u64(&stack[offset..offset + 4]);
        let pc = get_u64(&stack[offset + 4..offset + 8]);
        callstack.push(pc);
    }

    callstack.reverse();
    Some(callstack)
}

fn get_link_register(vm: &Vm) -> Option<pcode::VarNode> {
    match vm.cpu.arch.triple.architecture {
        target_lexicon::Architecture::Arm(_) => Some(vm.cpu.arch.sleigh.get_reg("lr")?.var),
        // @todo: add other architectures.
        _ => None,
    }
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
        Architecture::M68k => &[
            "D0", "D1", "D2", "D3", "D4", "D5", "D6", "D7", // Data Registers
            "A0", "A1", "A2", "A3", "A4", "A5", "A6", "SP", // Address Registers
            "SR", "ZF", "NF", "VF", // Status Register and Zero Flag
            "PC", // Program Counter
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

pub fn log_regs(
    vm: &mut Vm,
    label: impl Into<std::borrow::Cow<'static, str>>,
    pc: u64,
    reglist: &[impl AsRef<str>],
) {
    use std::io::Write;

    let regs: Vec<_> = reglist
        .iter()
        .map(AsRef::as_ref)
        .flat_map(|reg| match vm.cpu.arch.sleigh.get_reg(reg) {
            Some(reg) => Some(reg.var),
            None => {
                tracing::error!("Unknown register: {reg}");
                None
            }
        })
        .collect();

    let label = label.into();
    vm.hook_address(pc, move |cpu: &mut icicle_cpu::Cpu, addr| {
        let mut stdout = std::io::stdout().lock();

        let _ = write!(&mut stdout, "[{addr:#0x}] {label}: ");
        for reg in &regs {
            let value = cpu.read_reg(*reg);
            let _ = write!(&mut stdout, "{} = {value:#x} ", reg.display(&cpu.arch.sleigh));
        }

        let icount = cpu.icount();
        let _ = writeln!(&mut stdout, "({icount})");
        let _ = stdout.flush();
    });
}
