use icicle_cpu::{mem::perm, Cpu, ExceptionCode};

use crate::{JitFunction, VmCtx};

pub fn call_jit_compilation_error() -> JitFunction {
    unsafe extern "sysv64" fn jit_compilation_error_fn(
        cpu: *mut Cpu,
        _: &mut VmCtx,
        addr: u64,
    ) -> u64 {
        (*cpu).exception.code = ExceptionCode::JitError as u32;
        addr
    }
    jit_compilation_error_fn
}

pub fn call_bad_lookup_error() -> JitFunction {
    unsafe extern "sysv64" fn bad_lookup_error_fn(cpu: *mut Cpu, _: &mut VmCtx, addr: u64) -> u64 {
        (*cpu).exception.code = ExceptionCode::JitError as u32;
        (*cpu).exception.value = 0x1;
        addr
    }
    bad_lookup_error_fn
}

pub fn call_address_not_translated() -> JitFunction {
    unsafe extern "sysv64" fn address_not_translated_fn(
        cpu: *mut Cpu,
        _: &mut VmCtx,
        addr: u64,
    ) -> u64 {
        (*cpu).exception.code = ExceptionCode::CodeNotTranslated as u32;
        addr
    }
    address_not_translated_fn
}

pub fn call_block_contains_breakpoint() -> JitFunction {
    unsafe extern "sysv64" fn block_contains_breakpoint_fn(
        cpu: *mut Cpu,
        _: &mut VmCtx,
        addr: u64,
    ) -> u64 {
        // Exit with the `InstructionLimit` exit code this results in us exiting to the interpreter
        // which will single step the CPU until the correct instruction.
        (*cpu).exception.code = ExceptionCode::InstructionLimit as u32;
        addr
    }
    block_contains_breakpoint_fn
}

fn load<const N: usize>(cpu_ptr: *mut Cpu, addr: u64) -> [u8; N] {
    let result = unsafe { (*cpu_ptr).mem.read(addr, perm::READ | perm::INIT) };
    match result {
        Ok(v) => v,
        Err(e) => {
            unsafe {
                (*cpu_ptr).exception.code = ExceptionCode::from_load_error(e) as u32;
                (*cpu_ptr).exception.value = addr;
            }
            [0; N]
        }
    }
}

macro_rules! load_ty {
    ($name:ident, $ty:ty) => {
        #[allow(improper_ctypes_definitions)] // Needed because u128 does have a stable ABI
        pub extern "sysv64" fn $name(cpu_ptr: *mut Cpu, addr: u64) -> $ty {
            let value = load(cpu_ptr, addr);
            // @fixme: avoid this branch by calling a different function during code gen.
            match unsafe { (*cpu_ptr).arch.sleigh.big_endian } {
                false => <$ty>::from_le_bytes(value),
                true => <$ty>::from_be_bytes(value),
            }
        }
    };
}

load_ty!(load8, u8);
load_ty!(load16, u16);
load_ty!(load32, u32);
load_ty!(load64, u64);
load_ty!(load128, u128);

fn store<const N: usize>(cpu_ptr: *mut Cpu, addr: u64, value: [u8; N]) {
    let result = unsafe { (*cpu_ptr).mem.write(addr, value, perm::WRITE) };
    if let Err(e) = result {
        unsafe {
            (*cpu_ptr).exception.code = ExceptionCode::from_store_error(e) as u32;
            (*cpu_ptr).exception.value = addr;
        }
    }
}

macro_rules! store_ty {
    ($name:ident, $ty:ty) => {
        #[allow(improper_ctypes_definitions)] // Needed because u128 does have a stable ABI
        pub extern "sysv64" fn $name(cpu_ptr: *mut Cpu, addr: u64, value: $ty) {
            // @fixme: avoid this branch by calling a different function during code gen.
            let value = match unsafe { (*cpu_ptr).arch.sleigh.big_endian } {
                true => value.to_be_bytes(),
                false => value.to_le_bytes(),
            };
            store(cpu_ptr, addr, value)
        }
    };
}

store_ty!(store8, u8);
store_ty!(store16, u16);
store_ty!(store32, u32);
store_ty!(store64, u64);
store_ty!(store128, u128);

pub extern "sysv64" fn run_dynamic_hook(cpu_ptr: *mut Cpu, addr: u64, data_ptr: *mut ()) {
    unsafe {
        let id: u64 = std::mem::transmute(data_ptr);
        let cpu = &mut *cpu_ptr;
        cpu.call_hook(id as u16, addr)
    }
}

pub fn pack_instruction(inst: pcode::Instruction) -> [u64; 4] {
    assert!(std::mem::size_of::<pcode::Instruction>() == std::mem::size_of::<[u64; 4]>());
    unsafe { std::mem::transmute_copy(&inst) }
}

pub fn unpack_instruction(op_bytes: [u64; 4]) -> pcode::Instruction {
    assert!(std::mem::size_of::<pcode::Instruction>() == std::mem::size_of::<[u64; 4]>());
    unsafe { std::mem::transmute_copy(&op_bytes) }
}

pub extern "sysv64" fn run_interpreter(cpu_ptr: *mut Cpu, a: u64, b: u64, c: u64, d: u64) {
    unsafe {
        let cpu = &mut (*cpu_ptr);
        cpu.interpret_unchecked(unpack_instruction([a, b, c, d]));
    }
}

pub extern "sysv64" fn push_shadow_stack(cpu_ptr: *mut Cpu, addr: u64) {
    unsafe {
        let cpu = &mut (*cpu_ptr);
        cpu.push_shadow_stack(addr);
    }
}

pub extern "sysv64" fn pop_shadow_stack(cpu_ptr: *mut Cpu, target: u64) {
    unsafe {
        let cpu = &mut (*cpu_ptr);
        cpu.pop_shadow_stack(target);
    }
}

#[test]
fn pack_unpack_instruction() {
    use pcode::{Inputs, Instruction, Op, VarNode};

    macro_rules! check_roundtrip {
        ($value:expr) => {
            assert_eq!(unpack_instruction(pack_instruction($value)), $value)
        };
    }

    check_roundtrip!(Instruction::from((
        VarNode::new(1, 8),
        Op::PcodeOp(10),
        Inputs::new(0_u64, VarNode::new(2, 8))
    )));

    check_roundtrip!(Instruction::from((
        VarNode::new(1, 10),
        Op::FloatToFloat,
        Inputs::one(VarNode::new(2, 8))
    )));
}
