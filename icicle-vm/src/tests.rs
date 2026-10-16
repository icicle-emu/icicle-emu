use icicle_cpu::{
    Config, ExceptionCode, ShadowStackState, VmExit,
    mem::{Mapping, perm},
};

#[test]
fn branch_exception_delivery_on_single_step() {
    let mut vm = crate::build(&Config {
        triple: "riscv64-none".parse().unwrap(),
        enable_jit: false,
        shadow_stack: ShadowStackState::Disabled,
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

static I686_TEST_CODE: &[u8] = &[
    0xA1, 0xFF, 0xFF, 0x01, 0x00, // 0x00: mov eax, [0x1FFFF]
    0xB8, 0x02, 0x00, 0x00, 0x00, // 0x05: mov eax, 2
    0x90, // 0x0A: nop
    0xF4, // 0x0B: hlt
];

fn i686_test_vm() -> crate::Vm {
    let mut vm = crate::build(&Config::from_target_triple("i686-none")).unwrap();
    vm.cpu.mem.map_memory_len(0x0, 0x100, Mapping { perm: perm::READ | perm::EXEC, value: 0x00 });
    vm.cpu.mem.write_bytes(0x0, I686_TEST_CODE, perm::NONE).unwrap();
    vm.cpu.write_pc(0x00);
    vm.add_breakpoint(0xb);
    vm
}

#[test]
fn single_step_after_fault() {
    let mut vm = i686_test_vm();

    let reg_eax = vm.cpu.arch.sleigh.get_varnode("EAX").unwrap();

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
fn multi_step_after_fault_matches_single_steps() {
    let fault_and_fixup = || {
        let mut vm = i686_test_vm();
        assert_eq!(vm.step(1), VmExit::UnhandledException((ExceptionCode::ReadUnmapped, 0x1FFFF)));
        assert!(vm.cpu.mem.map_memory_len(0x1FF00, 0x200, Mapping {
            perm: perm::READ | perm::EXEC,
            value: 0xaa
        }));
        vm.cpu.exception.clear();
        vm
    };

    let mut single = fault_and_fixup();
    assert_eq!(single.step(1), VmExit::InstructionLimit);
    assert_eq!(single.step(1), VmExit::InstructionLimit);

    let mut multi = fault_and_fixup();
    assert_eq!(multi.step(2), VmExit::InstructionLimit);

    assert_eq!(single.cpu.read_pc(), 0x0A);
    assert_eq!(multi.cpu.read_pc(), 0x0A);
    assert_eq!(single.cpu.icount(), multi.cpu.icount());
}

#[test]
fn disasm_change_check_distinguishes_isa_modes() {
    // The same bytes decode differently per instruction-set mode: `0x00000000` is `andeq r0,r0,r0`
    // in ARM and `movs r0,r0` in Thumb. On interworking targets one address can legitimately be
    // lifted in both modes, so the disassembly-change check keeps its baseline per (vaddr,
    // isa_mode) and does not treat the second decode as self-modifying code. Lift a padding address
    // in Thumb then ARM and confirm the second lift is accepted.
    let mut vm =
        crate::build(&Config { triple: "arm".parse().unwrap(), ..Config::default() }).unwrap();

    let addr = 0x1000;
    vm.cpu.mem.map_memory_len(addr, 0x1000, Mapping { perm: perm::NONE, value: 0 });
    vm.cpu.mem.write_bytes(addr, &[0u8; 0x1000], perm::NONE).unwrap();
    vm.cpu.mem.update_perm(addr, 0x1000, perm::READ | perm::INIT | perm::EXEC).unwrap();

    vm.cpu.set_isa_mode(1);
    assert!(vm.lift(addr).is_ok(), "thumb lift of padding should succeed");

    vm.cpu.set_isa_mode(0);
    assert!(
        vm.lift(addr).is_ok(),
        "arm lift of the same padding must not be flagged as self-modifying code"
    );

    // Check that we still identify potential self modifying code.
    assert_eq!(
        vm.cpu.mem.write_bytes(addr, &[0x02, 0x00, 0x81, 0xE0], perm::NONE),
        Err(perm::MemError::SelfModifyingCode)
    );
}

#[test]
fn fault_fixup_preserves_icount() {
    let missing_mapping = Mapping { perm: perm::READ | perm::INIT, value: 0x0 };

    println!("Clean run:");
    let icount_clean = {
        let mut vm = i686_test_vm();
        vm.cpu.mem.map_memory_len(0x1FFFF, 0x200, missing_mapping);
        assert_eq!(vm.step(1000), VmExit::Breakpoint);
        vm.cpu.icount()
    };

    println!("\n\nFaulting run:");
    let icount_with_fault = {
        let mut vm = i686_test_vm();
        assert_eq!(
            vm.step(1000),
            VmExit::UnhandledException((ExceptionCode::ReadUnmapped, 0x1FFFF))
        );
        vm.cpu.mem.map_memory_len(0x1FFFF, 0x200, missing_mapping);
        vm.cpu.exception.clear();
        assert_eq!(vm.step(1000), VmExit::Breakpoint);
        vm.cpu.icount()
    };
    assert_eq!(icount_clean, icount_with_fault, "icount mismatch with snapshot");

    println!("\n\nSnapshot run:");
    let icount_with_snapshot = {
        let mut vm = i686_test_vm();
        assert_eq!(
            vm.step(1000),
            VmExit::UnhandledException((ExceptionCode::ReadUnmapped, 0x1FFFF))
        );
        let snap = vm.snapshot();
        vm.restore(&snap);

        vm.cpu.mem.map_memory_len(0x1FFFF, 0x200, missing_mapping);
        vm.cpu.exception.clear();
        assert_eq!(vm.step(1000), VmExit::Breakpoint);
        vm.cpu.icount()
    };
    assert_eq!(icount_clean, icount_with_snapshot, "icount mismatch with clean run");
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
