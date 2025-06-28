use icicle_cpu::{
    mem::{perm, Mapping},
    Config, ExceptionCode, VmExit,
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
