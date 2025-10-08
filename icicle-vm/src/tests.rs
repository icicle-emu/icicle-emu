use icicle_cpu::{
    Config, ExceptionCode, VmExit,
    mem::{Mapping, perm},
};

#[test]
fn branch_exception_delivery_on_single_step() {
    let mut vm = crate::build(&Config {
        triple: "riscv64-none".parse().unwrap(),
        enable_jit: false,
        enable_shadow_stack: false,
        ..Config::default()
    })
    .unwrap();
    vm.cpu.mem.map_memory_len(0x1000, 0x100, Mapping { perm: perm::READ | perm::EXEC, value: 0 });

    // Map some code that jumps to the target location.
    static CODE: &[u8] = &[
        0xb7, 0x10, 0x00, 0x00, // lui      ra,0x1
        0x9b, 0x80, 0x00, 0x01, // addiw    ra,ra,0x10
        0x67, 0x80, 0x00, 0x00, // ret
    ];
    vm.cpu.mem.write_bytes(0x1000, CODE, perm::NONE).unwrap();

    // Ensure decode will fail at the jump destination.
    vm.cpu.mem.update_perm(0x1010, 4, perm::NONE).unwrap();

    vm.cpu.write_pc(0x1000);
    vm.step(3);
    assert_eq!(vm.cpu.read_pc(), 0x1010);
    // At this point there is a pending 'ExecViolation' exception for the next instruction, however
    // this is suppressed because we reached the instruction limit.

    // If we try to step from this point we should then see the missing exception.
    assert_eq!(vm.step(1), VmExit::UnhandledException((ExceptionCode::ExecViolation, 0x1010)));
    // And the PC should remain the same.
    assert_eq!(vm.cpu.read_pc(), 0x1010);
}

#[test]
fn prioritize_instruction_limit_over_decode_error() {
    let mut vm =
        crate::build(&Config { triple: "riscv64-none".parse().unwrap(), ..Config::default() })
            .unwrap();
    vm.cpu.mem.map_memory_len(0x1000, 0x100, Mapping { perm: perm::READ | perm::EXEC, value: 0 });

    // Map two nops followed by an invalid instruction.
    static CODE: &[u8] = &[
        0x13, 0x00, 0x00, 0x00, // nop
        0x13, 0x00, 0x00, 0x00, // nop
        0x00, 0x00, 0x00, 0x00, // invalid
    ];
    vm.cpu.mem.write_bytes(0x1000, CODE, perm::NONE).unwrap();

    vm.cpu.write_pc(0x1000);
    assert_eq!(vm.step(2), VmExit::InstructionLimit);
    assert_eq!(vm.step(1), VmExit::UnhandledException((ExceptionCode::InvalidInstruction, 0x1008)));
}

#[test]
fn execute_only_memory() {
    let mut vm =
        crate::build(&Config { triple: "riscv64-none".parse().unwrap(), ..Config::default() })
            .unwrap();
    vm.cpu.mem.map_memory_len(0x1000, 0x100, Mapping { perm: perm::EXEC, value: 0 });

    // Map some code that jumps to the target location.
    static CODE: &[u8] = &[
        0xb7, 0x10, 0x00, 0x00, // lui      ra,0x1
    ];
    vm.cpu.mem.write_bytes(0x1000, CODE, perm::NONE).unwrap();

    vm.cpu.write_pc(0x1000);
    assert_eq!(vm.step(1), VmExit::InstructionLimit);
}

#[test]
fn single_step_after_fault() {
    let mut vm = crate::build(&Config::from_target_triple("i686-none")).unwrap();
    vm.cpu.mem.map_memory_len(0, 0x100, Mapping { perm: perm::READ | perm::EXEC, value: 0 });

    let reg_eax = vm.cpu.arch.sleigh.get_varnode("EAX").unwrap();

    static CODE: &[u8] = &[
        0xA1, 0xFF, 0xFF, 0x01, 0x00, // 0x00: mov eax, [0x1FFFF]
        0xB8, 0x02, 0x00, 0x00, 0x00, // 0x05: mov eax, 2
        0x90, // 0x0A: nop
    ];
    vm.cpu.mem.write_bytes(0x0, CODE, perm::NONE).unwrap();

    vm.cpu.write_pc(0x00);
    assert_eq!(vm.step(1), VmExit::UnhandledException((ExceptionCode::ReadUnmapped, 0x1FFFF)));
    assert_eq!(vm.cpu.read_pc(), 0x00);

    // Map the missing memory and single step again.
    assert!(vm.cpu.mem.map_memory_len(0x1FF00, 0x200, Mapping { perm: perm::READ, value: 0xaa }));
    vm.cpu.exception.clear();
    assert_eq!(vm.step(1), VmExit::InstructionLimit);
    assert_eq!(vm.cpu.read_reg(reg_eax), 0xAAAA_AAAA);
    assert_eq!(vm.cpu.read_pc(), 0x05);

    assert_eq!(vm.step(1), VmExit::InstructionLimit);
    assert_eq!(vm.cpu.read_pc(), 0x0A);
}

#[test]
fn build_arm() {
    let _ = crate::build(&Config::from_target_triple("arm-none")).unwrap();
}

#[test]
fn build_aarch64() {
    let _ = crate::build(&Config::from_target_triple("aarch64-none")).unwrap();
}

#[test]
fn build_m68k() {
    let _ = crate::build(&Config::from_target_triple("m68k-none")).unwrap();
}

#[test]
fn build_mips32() {
    let _ = crate::build(&Config::from_target_triple("mips-none")).unwrap();
}

#[test]
fn build_msp430x() {
    let _ = crate::build(&Config::from_target_triple("msp430-none")).unwrap();
}

#[test]
fn build_powerpc() {
    let _ = crate::build(&Config::from_target_triple("powerpc-none")).unwrap();
}

#[test]
fn build_riscv64() {
    let _ = crate::build(&Config::from_target_triple("riscv64-none")).unwrap();
}

#[test]
fn build_x86_64() {
    let _ = crate::build(&Config::from_target_triple("x86_64-none")).unwrap();
}
