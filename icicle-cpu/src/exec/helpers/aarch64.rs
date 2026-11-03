use super::*;

pub const HELPERS: &[(&str, PcodeOpHelper)] = &[
    ("NEON_cmeq", neon_cmeq),
    ("NEON_cmhs", neon_cmhs),
    ("NEON_cmhi", neon_cmhi),
    ("NEON_cmge", neon_cmge),
    ("NEON_cmgt", neon_cmgt),
    ("NEON_uminv", neon_uminv),
    ("NEON_sminv", neon_sminv),
    ("NEON_umaxv", neon_umaxv),
    ("NEON_smaxv", neon_smaxv),
];

//
// NEON implementations
//
// These use the software SIMD implementation shared with the ARM helpers. In each case
// `cpu.args[0]` (or `args[1]` for the reductions) is the lane size in bytes.
//

fn neon_compare(
    cpu: &mut Cpu,
    dst: VarNode,
    args: [Value; 2],
    is_unsigned: bool,
    cmp: fn(i128, i128) -> bool,
) {
    let esize = cpu.args[0] as u8;
    call_checked(cpu, dst, args, |cpu, dst, args| {
        simd::vector_compare(cpu, dst, args, esize, is_unsigned, cmp)
    })
}

fn neon_cmeq(cpu: &mut Cpu, dst: VarNode, args: [Value; 2]) {
    neon_compare(cpu, dst, args, true, |a, b| a == b)
}

fn neon_cmhs(cpu: &mut Cpu, dst: VarNode, args: [Value; 2]) {
    neon_compare(cpu, dst, args, true, |a, b| a >= b)
}

fn neon_cmhi(cpu: &mut Cpu, dst: VarNode, args: [Value; 2]) {
    neon_compare(cpu, dst, args, true, |a, b| a > b)
}

fn neon_cmge(cpu: &mut Cpu, dst: VarNode, args: [Value; 2]) {
    neon_compare(cpu, dst, args, false, |a, b| a >= b)
}

fn neon_cmgt(cpu: &mut Cpu, dst: VarNode, args: [Value; 2]) {
    neon_compare(cpu, dst, args, false, |a, b| a > b)
}

/// Reduces all lanes of `args[0]` to a single value, which is zero extended to `dst`.
fn neon_reduce(
    cpu: &mut Cpu,
    dst: VarNode,
    args: [Value; 2],
    signed: bool,
    op: fn(i128, i128) -> i128,
) -> Result {
    let esize = cpu.read::<u8>(args[1]);
    let src = simd::Simd::read(cpu, args[0], esize)?;
    let result = match signed {
        true => src.reduce_signed(op) as u128,
        false => src.reduce(|a, b| op(a as i128, b as i128) as u128),
    };
    cpu.write_trunc(dst, result);
    Ok(())
}

fn neon_uminv(cpu: &mut Cpu, dst: VarNode, args: [Value; 2]) {
    call_checked(cpu, dst, args, |cpu, dst, args| neon_reduce(cpu, dst, args, false, i128::min))
}

fn neon_sminv(cpu: &mut Cpu, dst: VarNode, args: [Value; 2]) {
    call_checked(cpu, dst, args, |cpu, dst, args| neon_reduce(cpu, dst, args, true, i128::min))
}

fn neon_umaxv(cpu: &mut Cpu, dst: VarNode, args: [Value; 2]) {
    call_checked(cpu, dst, args, |cpu, dst, args| neon_reduce(cpu, dst, args, false, i128::max))
}

fn neon_smaxv(cpu: &mut Cpu, dst: VarNode, args: [Value; 2]) {
    call_checked(cpu, dst, args, |cpu, dst, args| neon_reduce(cpu, dst, args, true, i128::max))
}
