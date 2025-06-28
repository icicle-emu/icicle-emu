use icicle_cpu::{mem::perm, Cpu, ExceptionCode, InternalError};

pub unsafe extern "C" fn jit_compilation_error(cpu: *mut Cpu, addr: u64) -> u64 {
    (*cpu).exception.code = ExceptionCode::JitError as u32;
    addr
}

pub unsafe extern "C" fn bad_lookup_error(cpu: *mut Cpu, addr: u64) -> u64 {
    (*cpu).exception.code = ExceptionCode::JitError as u32;
    (*cpu).exception.value = 0x1;
    addr
}

pub unsafe extern "C" fn address_not_translated(cpu: *mut Cpu, addr: u64) -> u64 {
    (*cpu).exception.code = ExceptionCode::CodeNotTranslated as u32;
    (*cpu).exception.value = addr;
    addr
}

pub unsafe extern "C" fn switch_to_interpreter(cpu: *mut Cpu, addr: u64) -> u64 {
    (*cpu).exception = (ExceptionCode::InternalError, InternalError::SwitchToInterpreter).into();
    addr
}

#[inline(always)]
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
    ($namele:ident, $namebe:ident, $ty:ty) => {
        pub extern "C" fn $namele(cpu_ptr: *mut Cpu, addr: u64) -> $ty {
            <$ty>::from_le_bytes(load(cpu_ptr, addr))
        }

        pub extern "C" fn $namebe(cpu_ptr: *mut Cpu, addr: u64) -> $ty {
            <$ty>::from_be_bytes(load(cpu_ptr, addr))
        }
    };
}

pub extern "C" fn load8(cpu_ptr: *mut Cpu, addr: u64) -> u8 {
    load::<1>(cpu_ptr, addr)[0]
}

load_ty!(load16le, load16be, u16);
load_ty!(load32le, load32be, u32);
load_ty!(load64le, load64be, u64);

pub extern "C" fn load128le(cpu_ptr: *mut Cpu, addr: u64, out: &mut u128) {
    *out = <u128>::from_le_bytes(load(cpu_ptr, addr));
}

pub extern "C" fn load128be(cpu_ptr: *mut Cpu, addr: u64, out: &mut u128) {
    *out = <u128>::from_be_bytes(load(cpu_ptr, addr));
}

#[inline(always)]
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
    ($namele:ident, $namebe:ident, $ty:ty) => {
        pub extern "C" fn $namele(cpu_ptr: *mut Cpu, addr: u64, value: $ty) {
            store(cpu_ptr, addr, value.to_le_bytes())
        }

        pub extern "C" fn $namebe(cpu_ptr: *mut Cpu, addr: u64, value: $ty) {
            store(cpu_ptr, addr, value.to_be_bytes())
        }
    };
}

pub extern "C" fn store8(cpu_ptr: *mut Cpu, addr: u64, value: u8) {
    store(cpu_ptr, addr, [value])
}

store_ty!(store16le, store16be, u16);
store_ty!(store32le, store32be, u32);
store_ty!(store64le, store64be, u64);

pub extern "C" fn store128le(cpu_ptr: *mut Cpu, addr: u64, low: u64, high: u64) {
    let value = ((high as u128) << 64) | low as u128;
    store(cpu_ptr, addr, value.to_le_bytes())
}

pub extern "C" fn store128be(cpu_ptr: *mut Cpu, addr: u64, low: u64, high: u64) {
    let value = ((high as u128) << 64) | low as u128;
    store(cpu_ptr, addr, value.to_be_bytes())
}

pub fn pack_instruction(inst: pcode::Instruction) -> [u64; 4] {
    assert!(std::mem::size_of::<pcode::Instruction>() == std::mem::size_of::<[u64; 4]>());
    unsafe { std::mem::transmute_copy(&inst) }
}

pub fn unpack_instruction(op_bytes: [u64; 4]) -> pcode::Instruction {
    assert!(std::mem::size_of::<pcode::Instruction>() == std::mem::size_of::<[u64; 4]>());
    unsafe { std::mem::transmute_copy(&op_bytes) }
}

/// Interprets the instruction packed in the input arguments.
///
/// # Safety
///
/// The input arguments must represent a valid instruction.
pub unsafe extern "C" fn run_interpreter(cpu: &mut Cpu, a: u64, b: u64, c: u64, d: u64) {
    cpu.interpret_unchecked(unpack_instruction([a, b, c, d]));
}

pub extern "C" fn push_shadow_stack(cpu: &mut Cpu, addr: u64) {
    cpu.push_shadow_stack(addr);
}

pub extern "C" fn pop_shadow_stack(cpu: &mut Cpu, target: u64) {
    cpu.pop_shadow_stack(target);
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
