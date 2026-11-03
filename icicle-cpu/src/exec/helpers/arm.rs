#![allow(unused)]

use super::{simd::Simd, *};

pub const HELPERS: &[(&str, PcodeOpHelper)] = &[
    ("enableIRQinterrupts", enable_interrupts),
    ("disableIRQinterrupts", disable_interrupts),
    ("coprocessor_movefromRt", coprocessor_move_from_rt),
    ("coprocessor_movefromRt2", coprocessor_move_from_rt2),
    // NEONv7
    ("ArmV7NeonProbe", arm_v7_neon_probe),
    ("VectorCompareEqual", checked!(vector_compare_equal)),
    ("VectorCompareGreaterThanOrEqual", checked!(vector_compare_greater_than_or_equal)),
    ("VectorCompareGreaterThan", checked!(vector_compare_greater_than)),
    ("VectorPairwiseAdd", checked!(vector_pairwise_add)),
    ("VectorAdd", checked!(vector_add)),
    ("VectorSub", checked!(vector_sub)),
    ("vrev", vrev),
    ("VectorCopyLong", checked!(vector_copy_long)),
    ("VectorCopyNarrow", checked!(vector_copy_narrow)),
    ("VectorShiftRight", checked!(vector_shift_right)),
    ("VectorShiftRightInsert", checked!(vector_shift_right_insert)),
    ("VectorShiftLeftInsert", checked!(vector_shift_left_insert)),
    ("VectorBitwiseSelect", vector_bitwise_select),
    ("VectorZip", checked!(vector_zip)),
    ("VectorGetElement", checked!(vector_get_element)),
    ("VectorMultiplyAccumulate", checked!(vector_multiply_accumulate)),
    ("VectorMultiply", checked!(vector_multiply)),
    ("VectorMultiplyLong", checked!(vector_multiply_long)),
    ("PolynomialMultiply", checked!(polynomial_multiply)),
    // SHA/AES extensions.
    ("SHA1HashUpdateChoose", sha1_hash_update_choose),
    ("SHA1HashUpdateMajority", sha1_hash_update_majority),
    ("SHA1HashUpdateParity", sha1_hash_update_parity),
    ("SHA256ScheduleUpdate0", sha256_schedule_update_0),
    ("SHA256ScheduleUpdate1", sha256_schedule_update_1),
    ("SHA256hash", sha256_hash),
    ("FixedToFP", fpu_fixed_to_fp),
];

fn arm_v7_neon_probe(cpu: &mut Cpu, dst: VarNode, args: [Value; 2]) {
    // Can be set to make OpenSSL think NEON ops are not available
    // cpu.exception.code = ExceptionCode::UnimplementedOp as u32;
}

fn ensure_matching_vector_args(cpu: &mut Cpu, dst: VarNode, args: [Value; 2], esize: u8) -> bool {
    if esize == 0 || dst.size % esize != 0 {
        cpu.exception.code = ExceptionCode::InvalidOpSize as u32;
        cpu.exception.value = esize as u64;
        return false;
    }
    if args[0].size() != dst.size || args[1].size() != dst.size {
        cpu.exception.code = ExceptionCode::InvalidOpSize as u32;
        cpu.exception.value = dst.size as u64;
        return false;
    }
    true
}

fn vector_compare_equal(cpu: &mut Cpu, dst: VarNode, args: [Value; 2]) -> Result {
    simd::vector_compare(cpu, dst, args, cpu.args[0] as u8, true, |a, b| a == b)
}

/// cpu.args[1] = whether the elements are unsigned.
///
/// Note: the forms that compare against zero (which do not set `cpu.args[1]`) are not supported.
fn vector_compare_greater_than_or_equal(cpu: &mut Cpu, dst: VarNode, args: [Value; 2]) -> Result {
    let is_unsigned = cpu.args[1] == 1;
    simd::vector_compare(cpu, dst, args, cpu.args[0] as u8, is_unsigned, |a, b| a >= b)
}

/// See [`vector_compare_greater_than_or_equal`].
fn vector_compare_greater_than(cpu: &mut Cpu, dst: VarNode, args: [Value; 2]) -> Result {
    let is_unsigned = cpu.args[1] == 1;
    simd::vector_compare(cpu, dst, args, cpu.args[0] as u8, is_unsigned, |a, b| a > b)
}

// Note: SLEIGH uses this for both widening and non-widening vector adds, but we only implement
// the non-widening version for now.
//
//  [a, b] + [c, d] = [a + c, b + d]
fn vector_add(cpu: &mut Cpu, dst: VarNode, args: [Value; 2]) -> Result {
    if dst.size != args[0].size() {
        // Widening adds (vaddl / vaddw), not currently supported
        return Err(ExceptionCode::InvalidOpSize);
    }

    let esize = cpu.args[0] as u8;
    let a = Simd::read(cpu, args[0], esize)?;
    let b = Simd::read(cpu, args[1], esize)?;

    let is_signed = cpu.args[1] == 0;
    let result = match is_signed {
        true => simd::packed_signed(&a, &b, |a, b| a.wrapping_add(b))?,
        false => simd::packed(&a, &b, |a, b| a.wrapping_add(b))?,
    };
    simd::simd_set(cpu, dst, result)
}

// [a, b] - [c, d] = [a - c, b - d]
fn vector_sub(cpu: &mut Cpu, dst: VarNode, args: [Value; 2]) -> Result {
    let esize = cpu.args[0] as u8;
    let a = Simd::read(cpu, args[0], esize)?;
    let b = Simd::read(cpu, args[1], esize)?;
    let result = simd::packed(&a, &b, |a, b| a.wrapping_sub(b))?;
    simd::simd_set(cpu, dst, result)
}

// [a, b][c, d] = [a + b, c + d]
fn vector_pairwise_add(cpu: &mut Cpu, dst: VarNode, args: [Value; 2]) -> Result {
    let esize = cpu.args[0] as u8;
    let a = Simd::read(cpu, args[0], esize)?;
    let b = Simd::read(cpu, args[1], esize)?;
    let low = simd::pairwise(&a, |a, b| a.wrapping_add(b))?;
    let high = simd::pairwise(&b, |a, b| a.wrapping_add(b))?;
    simd::simd_set(cpu, dst, low.concat(&high)?)
}

// arg[0] = source, arg[1] = element size (bytes), cpu.args[0] = group_size (bytes)
fn vrev(cpu: &mut Cpu, dst: VarNode, args: [Value; 2]) {
    let esize: u8 = cpu.read_dynamic(args[1]).zxt();
    let esize_bytes = esize as usize;
    let group_size = cpu.args[0] as usize;

    if ![1, 2, 4, 8].contains(&esize) || ![2, 4, 8].contains(&group_size) {
        warn_once!("vrev: group size or esize is invalid (unpatched SLEIGH spec?)");
        cpu.exception.code = ExceptionCode::InvalidOpSize as u32;
        cpu.exception.value = esize as u64;
        return;
    }

    let source: u128 = cpu.read_dynamic(args[0]).zxt();
    let lane_mask = simd::ones(esize as u32 * 8);
    for chunk in (0..dst.size as usize).step_by(group_size) {
        for i in 0..(group_size / esize_bytes) {
            let src_offset = chunk + i * esize_bytes;
            let dst_offset = chunk + (group_size - (i + 1) * esize_bytes);
            let a = (source >> (src_offset * 8)) & lane_mask;
            cpu.write_trunc(dst.slice(dst_offset as u8, esize), a);
        }
    }
}

/// Sign or zero extend each element of a doubleword vector to twice the size (`vmovl`).
/// arg[0] = source, arg[1] = element size, cpu.args[0] = whether the elements are unsigned
fn vector_copy_long(cpu: &mut Cpu, dst: VarNode, args: [Value; 2]) -> Result {
    let esize = cpu.read::<u8>(args[1]);
    let is_unsigned = cpu.args[0] == 1;
    let src = Simd::read(cpu, args[0], esize)?;
    let result = match is_unsigned {
        true => src.resize_lanes(2 * esize),
        false => src.resize_sxt(2 * esize),
    };
    simd::simd_set(cpu, dst, result)
}

/// Copy the lower bits of a quadword vector to a doubleword vector.
/// arg[0] = source, arg[1] = element size
///
/// e.g., for element size = 4:
/// arg[0] [a:u32, b:32, c:u32, d:u32], dst=[a:u16, b:u16, c:u16, d:u16]
fn vector_copy_narrow(cpu: &mut Cpu, dst: VarNode, args: [Value; 2]) -> Result {
    let esize = cpu.read::<u8>(args[1]);
    let result = Simd::read(cpu, args[0], esize)?.resize_lanes(esize / 2);
    simd::simd_set(cpu, dst, result)
}

/// Take each element of a vector and shift it right by an immediate value storing the truncated
/// result.
///
/// arg[0] = source, arg[1] = imm, cpu.args[0] = element size (bytes)
fn vector_shift_right(cpu: &mut Cpu, dst: VarNode, args: [Value; 2]) -> Result {
    let esize = cpu.args[0] as u8;
    let imm: u32 = cpu.read_dynamic(args[1]).zxt();
    let x = Simd::read(cpu, args[0], esize)?;
    simd::simd_set(cpu, dst, x.apply(|x| x >> imm))
}

/// Shift each element in source right by imm and insert into destination.
///
/// arg[0] = destination, arg[1] = source, cpu.args[0] = shift, cpu.args[1] = element size (bytes)
fn vector_shift_right_insert(cpu: &mut Cpu, dst: VarNode, args: [Value; 2]) -> Result {
    let shift = cpu.args[0] as u32;
    let esize = cpu.args[1] as u8;

    let a = Simd::read(cpu, args[0], esize)?;
    let b = Simd::read(cpu, args[1], esize)?;

    let mask = simd::ones(esize as u32 * 8) >> shift;
    let result = simd::packed(&a, &b, |x, y| (x & !mask) | (y >> shift))?;
    simd::simd_set(cpu, dst, result)
}

/// Shift each element in source left by imm and insert into destination.
///
/// arg[0] = destination, arg[1] = source, cpu.args[0] = shift, cpu.args[1] = element size
fn vector_shift_left_insert(cpu: &mut Cpu, dst: VarNode, args: [Value; 2]) -> Result {
    let shift = cpu.args[0] as u32;
    let esize = cpu.args[1] as u8;

    let a = Simd::read(cpu, args[0], esize)?;
    let b = Simd::read(cpu, args[1], esize)?;

    let mask = simd::ones(esize as u32 * 8) << shift;
    let result = simd::packed(&a, &b, |x, y| (x & !mask) | (y << shift))?;
    simd::simd_set(cpu, dst, result)
}

/// For each bit, copy the corresponding bit from source_d if the original destination was 1
/// otherwise copy the corresponding bit from source_m.
fn vector_bitwise_select(cpu: &mut Cpu, dst: VarNode, args: [Value; 2]) {
    let src_d = args[0];
    let src_n = args[1];
    let src_m = cpu.args[0];

    if dst.size == 16 {
        let src_d: u128 = cpu.read(src_d);
        let src_n: u128 = cpu.read(src_n);
        cpu.write_trunc(dst, (src_d & src_n) | !src_d & src_m);
    }
    else if dst.size == 8 {
        let src_d: u64 = cpu.read(src_d);
        let src_n: u64 = cpu.read(src_n);
        let src_m: u64 = src_m as u64;
        cpu.write_trunc(dst, (src_d & src_n) | !src_d & src_m);
    }
    else {
        cpu.exception.code = ExceptionCode::InvalidOpSize as u32;
        cpu.exception.value = dst.size as u64;
        return;
    }
}

/// Interleave the elements of the two vectors:
///
/// [a0, a1, ...], [b0, b1, ...] => [a0, b0, a1, b1, ...]
///
/// To avoid the need for a 256 bit output, this needs to be called twice, once for the low half and
/// a second time for the high half.
///
/// arg[0] = Vd, arg[1] = Vm, cpu.args[0] = element size, cpu.args[1] = half (0 = low, 1 = high)
fn vector_zip(cpu: &mut Cpu, dst: VarNode, args: [Value; 2]) -> Result {
    let esize = cpu.args[0] as u8;
    let half = cpu.args[1] as u8;

    let a = Simd::read(cpu, args[0], esize)?;
    let b = Simd::read(cpu, args[1], esize)?;
    simd::check_size_match(&a, &b)?;

    let n_lanes = a.n_lanes();
    let mut out = Simd::new(0, a.size, esize);
    for i in 0..n_lanes {
        let index = half * n_lanes + i;
        let value = match index % 2 {
            0 => a.get_lane(index / 2),
            _ => b.get_lane(index / 2),
        };
        out.set_lane(i, value);
    }
    simd::simd_set(cpu, dst, out)
}

/// Gets a dynamic element from a vector.
fn vector_get_element(cpu: &mut Cpu, dst: VarNode, args: [Value; 2]) -> Result {
    let index = cpu.read::<u8>(args[1]);
    let element = Simd::read(cpu, args[0], dst.size)?.get_lane(index);
    cpu.write_trunc(dst, element);
    Ok(())
}

/// Multiple all elements of src1 by a scalar then add them to dest.
///
/// In SLEIGH this is used when there is a long destination, when multiplying scalar elements by a
/// scalar, and packed multiplication.
fn vector_multiply_accumulate(cpu: &mut Cpu, dst: VarNode, args: [Value; 2]) -> Result {
    let esize = cpu.args[0] as u8;
    let dst_esize = if dst.size == 2 * args[0].size() { esize * 2 } else { esize };

    let a = Simd::read(cpu, args[0], esize)?.resize_lanes(dst_esize);
    let scalar_mul = args[1].size() != args[0].size();
    let b = match scalar_mul {
        true => Simd::broadcast(cpu.read_dynamic(args[1]).zxt(), dst.size, dst_esize),
        false => Simd::read(cpu, args[1], esize)?.resize_lanes(dst_esize),
    };
    let product = simd::packed(&a, &b, |a, b| a.wrapping_mul(b))?;

    let prev = Simd::read(cpu, dst.into(), dst_esize)?;
    simd::simd_set(cpu, dst, simd::packed(&prev, &product, |a, b| a.wrapping_add(b))?)
}

// Note: even though there is a separate VectorMultipleLong op, this is still is used for some vmull
// cases (when there a scalar), the VectorMultipleLong supports potentially signed operations.
fn vector_multiply(cpu: &mut Cpu, dst: VarNode, args: [Value; 2]) -> Result {
    let esize = cpu.args[0] as u8;
    let dst_esize = if dst.size == 2 * args[0].size() { esize * 2 } else { esize };

    let a = Simd::read(cpu, args[0], esize)?.resize_lanes(dst_esize);
    let scalar_mul = args[1].size() != args[0].size();
    let b = match scalar_mul {
        true => Simd::broadcast(cpu.read_dynamic(args[1]).zxt(), dst.size, dst_esize),
        false => Simd::read(cpu, args[1], esize)?.resize_lanes(dst_esize),
    };

    simd::simd_set(cpu, dst, simd::packed(&a, &b, |a, b| a.wrapping_mul(b))?)
}

fn vector_multiply_long(cpu: &mut Cpu, dst: VarNode, args: [Value; 2]) -> Result {
    let esize = cpu.args[0] as u8;
    let is_unsigned = cpu.args[1] == 1;
    let dst_esize = 2 * esize;

    let product = match is_unsigned {
        true => {
            let a = Simd::read(cpu, args[0], esize)?.resize_lanes(dst_esize);
            let b = Simd::read(cpu, args[1], esize)?.resize_lanes(dst_esize);
            simd::packed(&a, &b, |a, b| a.wrapping_mul(b))?
        }
        false => {
            let a = Simd::read(cpu, args[0], esize)?.resize_sxt(dst_esize);
            let b = Simd::read(cpu, args[1], esize)?.resize_sxt(dst_esize);
            simd::packed(&a, &b, |a, b| a.wrapping_mul(b))?
        }
    };
    simd::simd_set(cpu, dst, product)
}

/// Implements polynomial multiplication.
///
/// ```text
/// 0 * 0 = 0 * 1 = 1 * 0 = 0
/// 1 * 1 = 1
/// ```
fn polynomial_multiply(cpu: &mut Cpu, dst: VarNode, args: [Value; 2]) -> Result {
    let esize = cpu.args[0] as u8;
    let dst_esize = if dst.size == 2 * args[0].size() { esize * 2 } else { esize };

    let a = Simd::read(cpu, args[0], esize)?.resize_lanes(dst_esize);
    let scalar_mul = args[1].size() != args[0].size();
    let b = match scalar_mul {
        true => Simd::broadcast(cpu.read_dynamic(args[1]).zxt(), dst.size, dst_esize),
        false => Simd::read(cpu, args[1], esize)?.resize_lanes(dst_esize),
    };

    fn poly_mult(a: u128, b: u128, bits: u8) -> u128 {
        let mut result = 0;
        for i in 0..bits {
            if (a >> i) & 1 == 1 {
                result ^= (b << i);
            }
        }
        result
    }

    let product = match esize {
        1 => simd::packed(&a, &b, |x, y| poly_mult(x, y, esize * 8))?,
        8 => simd::packed(&a, &b, |x, y| poly_mult(x, y, esize * 8))?,
        _ => return Err(ExceptionCode::InvalidOpSize),
    };
    simd::simd_set(cpu, dst, product)
}

fn sha256_hash(cpu: &mut Cpu, dst: VarNode, args: [Value; 2]) {
    let x: u128 = cpu.read(args[0]);
    let y: u128 = cpu.read(args[1]);
    let w = cpu.args[0];
    let part1 = cpu.args[1] == 1;
    let result = sha256_hash_impl(x, y, w, part1);
    cpu.write_var(dst, result);
}

// @todo: use std::simd when stable.
fn to_u32x4(x: u128) -> [u32; 4] {
    [x as u32, (x >> 32) as u32, (x >> 64) as u32, (x >> 96) as u32]
}
fn from_u32x4(x: [u32; 4]) -> u128 {
    x[0] as u128 | (x[1] as u128) << 32 | (x[2] as u128) << 64 | (x[3] as u128) << 96
}

fn sha256_hash_impl(x: u128, y: u128, w: u128, part1: bool) -> u128 {
    let mut x = to_u32x4(x);
    let mut y = to_u32x4(y);
    let w = to_u32x4(w);

    for e in 0..4 {
        let chs = sha_choose(y[0], y[1], y[2]);
        let maj = sha_majority(x[0], x[1], x[2]);
        let t = y[3].wrapping_add(sha_hash_sigma1(y[0])).wrapping_add(chs).wrapping_add(w[e]);

        let x_high = t.wrapping_add(x[3]);
        let y_high = t.wrapping_add(sha_hash_sigma0(x[0])).wrapping_add(maj);

        x = [y_high, x[0], x[1], x[2]];
        y = [x_high, y[0], y[1], y[2]];
    }
    let result = if part1 { x } else { y };
    from_u32x4(result)
}

fn sha1_hash_update_choose(cpu: &mut Cpu, dst: VarNode, args: [Value; 2]) {
    let x: u128 = cpu.read(args[0]);
    let y: u32 = cpu.read(args[1]);
    let w = cpu.args[0];
    let result = sha1_hash_update_impl(x, y, w, sha_choose);
    cpu.write_var(dst, result);
}

fn sha1_hash_update_impl(
    mut x: u128,
    mut y: u32,
    w: u128,
    round_function: fn(u32, u32, u32) -> u32,
) -> u128 {
    for e in 0..4 {
        let t = round_function((x >> 32) as u32, (x >> 64) as u32, (x >> 96) as u32);
        y = y
            .wrapping_add((x as u32).rotate_left(5))
            .wrapping_add(t)
            .wrapping_add((w >> (e * 32)) as u32);

        // x<63:32> = ROL(x<63:32>, 30);
        let mut x_high = (x >> 32) as u32;
        x_high = x_high.rotate_left(30);
        x = (x & !0xffff_ffff_0000_0000) | ((x_high as u128) << 32);

        // <y,x> = ROL(<y,x>, 32);
        let y_tmp: u32 = y;
        y = x.rotate_left(32) as u32;
        x = (x << 32) | (y_tmp as u128);
    }
    x
}

fn sha_choose(x: u32, y: u32, z: u32) -> u32 {
    ((y ^ z) & x) ^ z
}

fn sha_majority(x: u32, y: u32, z: u32) -> u32 {
    (x & y) | (z & (x | y))
}

fn sha_hash_sigma0(x: u32) -> u32 {
    x.rotate_right(2) ^ x.rotate_right(13) ^ x.rotate_right(22)
}

fn sha_hash_sigma1(x: u32) -> u32 {
    x.rotate_right(6) ^ x.rotate_right(11) ^ x.rotate_right(25)
}

fn sha1_hash_update_majority(cpu: &mut Cpu, dst: VarNode, args: [Value; 2]) {
    let x: u128 = cpu.read(args[0]);
    let y: u32 = cpu.read(args[1]);
    let w = cpu.args[0];
    let result = sha1_hash_update_impl(x, y, w, sha_majority);
    cpu.write_var(dst, result);
}

fn sha1_hash_update_parity(cpu: &mut Cpu, dst: VarNode, args: [Value; 2]) {
    let x: u128 = cpu.read(args[0]);
    let y: u32 = cpu.read(args[1]);
    let w = cpu.args[0];
    let result = sha1_hash_update_impl(x, y, w, |x, y, z| x ^ y ^ z);
    cpu.write_var(dst, result);
}

fn sha256_schedule_update_0(cpu: &mut Cpu, dst: VarNode, args: [Value; 2]) {
    let x: u128 = cpu.read(args[0]);
    let y: u128 = cpu.read(args[1]);
    // t = operand2[31:0] : operand1[127:32].
    let t = (x >> 32) | (y << 96);
    let mut result = 0;
    for lane in 0..4 {
        let shift = lane * 32;
        let value = (x >> shift) as u32;
        let value = value.wrapping_add(sha256_schedule_sigma0((t >> shift) as u32));
        result |= (value as u128) << shift;
    }
    cpu.write_var(dst, result);
}

fn sha256_schedule_update_1(cpu: &mut Cpu, dst: VarNode, args: [Value; 2]) {
    let x: u128 = cpu.read(args[0]);
    let y: u128 = cpu.read(args[1]);
    let w = cpu.args[0];
    // t0 = operand3[31:0] : operand2[127:32].
    let t0 = (y >> 32) | (w << 96);
    let t1_0 = (w >> 64) as u32;
    let t1_1 = (w >> 96) as u32;
    let x0 = x as u32;
    let x1 = (x >> 32) as u32;
    let r0 = x0.wrapping_add(sha256_schedule_sigma1(t1_0)).wrapping_add(t0 as u32);
    let r1 = x1.wrapping_add(sha256_schedule_sigma1(t1_1)).wrapping_add((t0 >> 32) as u32);
    let r2 =
        ((x >> 64) as u32).wrapping_add(sha256_schedule_sigma1(r0)).wrapping_add((t0 >> 64) as u32);
    let r3 =
        ((x >> 96) as u32).wrapping_add(sha256_schedule_sigma1(r1)).wrapping_add((t0 >> 96) as u32);
    let result = r0 as u128 | (r1 as u128) << 32 | (r2 as u128) << 64 | (r3 as u128) << 96;
    cpu.write_var(dst, result);
}

fn sha256_schedule_sigma0(x: u32) -> u32 {
    x.rotate_right(7) ^ x.rotate_right(18) ^ (x >> 3)
}

fn sha256_schedule_sigma1(x: u32) -> u32 {
    x.rotate_right(17) ^ x.rotate_right(19) ^ (x >> 10)
}

fn coprocessor_move_from_rt(cpu: &mut Cpu, dst: VarNode, args: [Value; 2]) {
    let coproc = cpu.read::<u32>(args[0]);
    let opc1 = cpu.read::<u32>(args[1]);
    let crm = cpu.args[0] as u32;
    let result = coprocessor_read(cpu, coproc, opc1, crm) as u32;
    cpu.write_var(dst, result);
}

fn coprocessor_move_from_rt2(cpu: &mut Cpu, dst: VarNode, args: [Value; 2]) {
    let coproc = cpu.read::<u32>(args[0]);
    let opc1 = cpu.read::<u32>(args[1]);
    let crm = cpu.args[0] as u32;
    let result = (coprocessor_read(cpu, coproc, opc1, crm) >> 32) as u32;
    cpu.write_var(dst, result);
}

fn coprocessor_read(cpu: &mut Cpu, coproc: u32, opc1: u32, crm: u32) -> u64 {
    match (coproc, crm, opc1) {
        // CNTVCT: Virtual count register
        (0b1111, 0b1110, 0b0001) => cpu.icount(),
        _ => {
            tracing::warn!("Unknown MSR: coproc=p{coproc}, opc1={opc1}, crm=c{crm}");
            cpu.exception.code = ExceptionCode::UnimplementedOp as u32;
            0
        }
    }
}

// Pseudocode from https://developer.arm.com/documentation/ddi0597/2023-09/Shared-Pseudocode/shared-functions-float
//
// SLEIGH signature: FixedToFP(fp, M, N, fbits, unsigned, rounding)
fn fpu_fixed_to_fp(cpu: &mut Cpu, dst: VarNode, args: [Value; 2]) {
    let m = cpu.read::<u32>(args[1]);
    let n = cpu.args[0];
    let fbits = cpu.args[1];
    let is_unsigned = cpu.args[2] != 0;
    let rounding = cpu.args[3];

    assert!(m == 16 || m == 32, "fixed-point size must be 16 or 32 bits");
    assert!(n == 32 || n == 64, "floating-point size must be 32 or 64 bits");
    assert!(fbits <= u128::from(m), "fractional bits must fit in the fixed-point value");
    assert!(rounding == 0, "only the default ARM rounding mode is implemented");

    // Read the source register at its native VarNode size, then truncate to
    // the fixed-point width `m`.
    let raw: u64 = cpu.read_dynamic(args[0]).zxt();
    let value: i64 = match (is_unsigned, m) {
        (false, 16) => (raw as i16).into(),
        (false, 32) => (raw as i32).into(),
        (true, 16) => (raw as u16).into(),
        (true, 32) => (raw as u32).into(),
        _ => unreachable!(),
    };

    // Scaling by a power of two is exact, so convert-then-divide rounds
    // once, matching the single FPRound in the ARM pseudocode.
    let scale = (1u64 << fbits) as f64;
    match n {
        32 => cpu.write_trunc(dst, (value as f32 / scale as f32).to_bits()),
        64 => cpu.write_trunc(dst, (value as f64 / scale).to_bits()),
        _ => unreachable!(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_fpu_fixed_to_fp_8byte_varnode_n32() {
        let arch = crate::Arch::none();
        let mut cpu = crate::Cpu::new_boxed(arch);

        // Source register "a" (8 bytes) and destination register "b" (8 bytes).
        let reg_a = cpu.arch.sleigh.get_varnode("a").unwrap();
        let reg_b = cpu.arch.sleigh.get_varnode("b").unwrap();

        // Write a fixed-point value into the 8-byte source register.
        // Using 0x0001_0000 which represents 1.0 with 16 fractional bits.
        cpu.write_var::<u64>(reg_a, 0x0001_0000);

        // args[1] = m (fixed-point size in bits); pass via a const Value.
        let m_value = pcode::Value::Const(32, 4);
        let src_value = pcode::Value::Var(reg_a);

        // cpu.args: [0]=n (float size), [1]=fbits, [2]=unsigned flag (0 = signed), [3]=rounding
        cpu.args[0] = 32; // n = 32-bit float output
        cpu.args[1] = 16; // fbits = 16 fractional bits
        cpu.args[2] = 0; // signed
        cpu.args[3] = 0; // default rounding

        // Call through the public HELPERS table (same path as the interpreter).
        let helper = arm::HELPERS.iter().find(|(name, _)| *name == "FixedToFP").unwrap().1;
        // This panicked before the fix because the 8-byte VarNode was read as i32.
        helper(&mut cpu, reg_b, [src_value, m_value]);

        // Result should be 1.0f32 written into the lower bytes of reg_b.
        let result: u64 = cpu.read_var(reg_b);
        let float_val = f32::from_bits(result as u32);
        assert!((float_val - 1.0).abs() < f32::EPSILON, "expected 1.0, got {float_val}");
    }

    /// `fbits == 32` is encodable (`vcvt.f32.s32 d0, d0, #32`: fbits = 64 - imm6)
    /// and is the boundary case for the scale-factor shift.
    #[test]
    fn test_fpu_fixed_to_fp_fbits_32() {
        let arch = crate::Arch::none();
        let mut cpu = crate::Cpu::new_boxed(arch);

        let reg_a = cpu.arch.sleigh.get_varnode("a").unwrap();
        let reg_b = cpu.arch.sleigh.get_varnode("b").unwrap();

        // 0x8000_0000 as a signed 32-bit fixed-point value with 32 fractional
        // bits represents -2^31 / 2^32 = -0.5.
        cpu.write_var::<u64>(reg_a, 0x8000_0000);

        let m_value = pcode::Value::Const(32, 4);
        let src_value = pcode::Value::Var(reg_a);

        cpu.args[0] = 32; // n = 32-bit float output
        cpu.args[1] = 32; // fbits = 32 fractional bits
        cpu.args[2] = 0; // signed
        cpu.args[3] = 0; // default rounding

        let helper = arm::HELPERS.iter().find(|(name, _)| *name == "FixedToFP").unwrap().1;
        helper(&mut cpu, reg_b, [src_value, m_value]);

        let result: u64 = cpu.read_var(reg_b);
        let float_val = f32::from_bits(result as u32);
        assert!((float_val + 0.5).abs() < f32::EPSILON, "expected -0.5, got {float_val}");
    }
}
