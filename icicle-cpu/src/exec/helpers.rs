use pcode::{Value, VarNode};

use crate::{Cpu, ExceptionCode, ValueSource};

pub type PcodeOpHelper = fn(&mut Cpu, VarNode, [Value; 2]);

pub fn unknown_operation(cpu: &mut Cpu, _: VarNode, _: [Value; 2]) {
    cpu.exception = ExceptionCode::UnimplementedOp.into();
}

pub const HELPERS: &[(&str, PcodeOpHelper)] = &[
    ("count_leading_zeros", count_leading_zeros),
    ("count_leading_zeroes", count_leading_zeros),
    ("countLeadingZeros", count_leading_zeros),
    ("count_leading_ones", count_leading_ones),
    ("countLeadingOnes", count_leading_ones),
    ("bcd_add", bcd_add),
    ("UnsignedSaturate", unsigned_saturate),
    ("UnsignedDoesSaturate", unsigned_does_saturate),
    ("SignedSaturate", signed_saturate),
    ("SignedDoesSaturate", signed_does_saturate),
    ("setISAMode", set_isa_mode),
];

fn set_isa_mode(_cpu: &mut Cpu, _: VarNode, _: [Value; 2]) {
    // Icicle checks for ISA mode switches on every block so does not need this function to be
    // called explicitly.
}

fn enable_interrupts(_cpu: &mut Cpu, _: VarNode, _: [Value; 2]) {
    // @todo
}

fn disable_interrupts(_cpu: &mut Cpu, _: VarNode, _: [Value; 2]) {
    // @todo
}

fn count_leading_zeros(cpu: &mut Cpu, dst: VarNode, args: [Value; 2]) {
    let input = args[0];
    let result = match args[0].size() {
        1 => cpu.read::<u8>(input).leading_zeros(),
        2 => cpu.read::<u16>(input).leading_zeros(),
        4 => cpu.read::<u32>(input).leading_zeros(),
        8 => cpu.read::<u64>(input).leading_zeros(),
        16 => cpu.read::<u128>(input).leading_zeros(),
        size => {
            cpu.exception = (ExceptionCode::InvalidOpSize, size as u64).into();
            return;
        }
    };
    cpu.write_trunc(dst, result);
}

fn count_leading_ones(cpu: &mut Cpu, dst: VarNode, args: [Value; 2]) {
    let input = args[0];
    let result = match args[0].size() {
        1 => cpu.read::<u8>(input).leading_ones(),
        2 => cpu.read::<u16>(input).leading_ones(),
        4 => cpu.read::<u32>(input).leading_ones(),
        8 => cpu.read::<u64>(input).leading_ones(),
        16 => cpu.read::<u128>(input).leading_ones(),
        size => {
            cpu.exception = (ExceptionCode::InvalidOpSize, size as u64).into();
            return;
        }
    };
    cpu.write_trunc(dst, result);
}

fn bcd_add(cpu: &mut Cpu, dst: VarNode, args: [Value; 2]) {
    let size = dst.size;

    if args[0].size() != size || args[1].size() != size {
        cpu.exception = (ExceptionCode::InvalidOpSize, args[0].size() as u64).into();
        return;
    }

    match size {
        1 => {
            let a = cpu.read::<u8>(args[0]);
            let b = cpu.read::<u8>(args[1]);
            let result = bcd_add8(a, b);
            cpu.write_var(dst, result);
        }
        2 => {
            let a = cpu.read::<u16>(args[0]);
            let b = cpu.read::<u16>(args[1]);
            let result = bcd_add16(a, b);
            cpu.write_var(dst, result);
        }
        _ => {
            cpu.exception = (ExceptionCode::InvalidOpSize, args[0].size() as u64).into();
        }
    }
}

fn bcd_add8(a: u8, b: u8) -> u8 {
    let mut result = 0;
    let mut carry = 0;
    for digit in 0..2 {
        let (result_digit, next_carry) =
            bcd_add_digit((a >> (4 * digit)) & 0xF, (b >> (4 * digit)) & 0xF, carry);
        carry = next_carry;
        result |= result_digit << (4 * digit);
    }
    result
}

fn bcd_add16(a: u16, b: u16) -> u16 {
    let mut result = 0;
    let mut carry = 0;
    for digit in 0..4 {
        let (result_digit, next_carry) = bcd_add_digit(
            ((a >> (4 * digit)) & 0xF) as u8,
            ((b >> (4 * digit)) & 0xF) as u8,
            carry,
        );
        carry = next_carry;
        result |= (result_digit as u16) << (4 * digit);
    }

    result
}

fn bcd_add_digit(a: u8, b: u8, carry: u8) -> (u8, u8) {
    match a + b + carry {
        x if x < 10 => (x, 0),
        x => (x % 10, 1),
    }
}

fn unsigned_saturate_impl(value: i64, bits: u32) -> (i64, bool) {
    let max: i64 = (1 << bits) - 1;
    if value < 0 {
        (0, true)
    }
    else if value > max {
        (max, true)
    }
    else {
        (value, false)
    }
}

fn unsigned_saturate(cpu: &mut Cpu, dst: pcode::VarNode, args: [Value; 2]) {
    let bits: u32 = cpu.read_dynamic(args[1]).zxt();
    // Some uses of `UnsignedSaturate` in SLEIGH do nothing because the bits have already been
    // truncated. Here we try to detect bugs in the spec by returning an error if the result would
    // never change.
    if bits >= (args[0].size() as u32 * 8) || bits >= 64 {
        cpu.exception = (ExceptionCode::InvalidOpSize, args[0].size() as u64).into();
        return;
    }

    let value: i64 = cpu.read_dynamic(args[0]).sxt();
    let (value, _) = unsigned_saturate_impl(value, bits);
    cpu.write_trunc(dst, value as u64);
}

fn unsigned_does_saturate(cpu: &mut Cpu, dst: pcode::VarNode, args: [Value; 2]) {
    let bits: u32 = cpu.read_dynamic(args[1]).zxt();
    if bits >= (args[0].size() as u32 * 8) || bits >= 64 {
        cpu.exception = (ExceptionCode::InvalidOpSize, args[0].size() as u64).into();
        return;
    }

    let value: i64 = cpu.read_dynamic(args[0]).sxt();
    let (_, saturates) = unsigned_saturate_impl(value, bits);
    cpu.write_var::<u8>(dst, saturates as u8);
}

fn signed_saturate_impl(value: i64, bits: u32) -> (i64, bool) {
    let max = (1 << (bits - 1)) - 1;
    let min = -(1 << (bits - 1));
    if value < min {
        (min, true)
    }
    else if value > max {
        (max, true)
    }
    else {
        (value, false)
    }
}

fn signed_saturate(cpu: &mut Cpu, dst: pcode::VarNode, args: [Value; 2]) {
    let bits: u32 = cpu.read_dynamic(args[1]).zxt();
    if bits >= (args[0].size() as u32 * 8) || bits >= 64 {
        cpu.exception = (ExceptionCode::InvalidOpSize, args[0].size() as u64).into();
        return;
    }

    let value: i64 = cpu.read_dynamic(args[0]).sxt();
    let (value, _) = signed_saturate_impl(value, bits);
    cpu.write_trunc(dst, value as u64);
}

fn signed_does_saturate(cpu: &mut Cpu, dst: pcode::VarNode, args: [Value; 2]) {
    let bits: u32 = cpu.read_dynamic(args[1]).zxt();
    if bits >= (args[0].size() as u32 * 8) || bits >= 64 {
        cpu.exception = (ExceptionCode::InvalidOpSize, args[0].size() as u64).into();
        return;
    }
    let value: i64 = cpu.read_dynamic(args[0]).sxt();
    let (_, saturates) = unsigned_saturate_impl(value, bits);
    cpu.write_var::<u8>(dst, saturates as u8);
}

#[allow(unused)]
fn saturating_sub(cpu: &mut Cpu, dst: pcode::VarNode, args: [Value; 2]) {
    let size = dst.size;

    if args[0].size() != size || args[1].size() != size {
        cpu.exception = (ExceptionCode::InvalidOpSize, args[0].size() as u64).into();
        return;
    }

    match size {
        1 => {
            let a = cpu.read::<u8>(args[0]);
            let b = cpu.read::<u8>(args[1]);
            cpu.write_var(dst, a.saturating_sub(b))
        }
        2 => {
            let a = cpu.read::<u16>(args[0]);
            let b = cpu.read::<u16>(args[1]);
            cpu.write_var(dst, a.saturating_sub(b))
        }
        4 => {
            let a = cpu.read::<u32>(args[0]);
            let b = cpu.read::<u32>(args[1]);
            cpu.write_var(dst, a.saturating_sub(b))
        }
        8 => {
            let a = cpu.read::<u64>(args[0]);
            let b = cpu.read::<u64>(args[1]);
            cpu.write_var(dst, a.saturating_sub(b))
        }
        _ => {
            cpu.exception = (ExceptionCode::InvalidOpSize, args[0].size() as u64).into();
        }
    }
}

pub mod x86 {
    use super::*;

    pub const HELPERS: &[(&str, PcodeOpHelper)] = &[
        ("rdtsc", rdtsc),
        ("cpuid_basic_info", cpuid_basic_info),
        ("cpuid_Version_info", cpuid_version_info),
        ("cpuid_Extended_Feature_Enumeration_info", cpuid_extended_feature_enumeration_info),
        ("cpuid", cpuid),
        ("movmskpd", movmskpd),
        ("pinsrw", pinsrw), // Note: implemented in SLEIGH in Ghidra 10.3.
        ("pshuflw", pshuflw),
        ("pshufhw", pshufhw),
        ("shufpd", shufpd), // Note: implemented in SLEIGH in Ghidra 10.3.
        ("pmaddwd", pmaddwd),
        ("in", in_io),
        ("out", out_io),
        ("LOCK", lock),
        ("UNLOCK", unlock),
        // Legacy float operations
        ("fsin", fsin),
        ("fcos", fcos),
        ("fptan", fptan),
        ("f2xm1", f2xm1),
        ("fscale", fscale),
    ];

    fn rdtsc(cpu: &mut Cpu, dst: VarNode, _: [Value; 2]) {
        cpu.write_var(dst, 0_u64);
    }

    // Basic processor information
    fn cpuid_basic_info(cpu: &mut Cpu, dst: VarNode, _: [Value; 2]) {
        if dst.size != 16 {
            tracing::warn!(
                "Using unpatched SLEIGH specification, CPUID instruction will behave incorrectly"
            );
            return;
        }
        tracing::debug!("cpuid(BASIC_INFO)");
        if true {
            // Pretend to be an Intel CPU
            cpu.write_var(dst.slice(0, 4), 0_u32);
            cpu.write_var(dst.slice(4, 4), u32::from_le_bytes(*b"Genu"));
            cpu.write_var(dst.slice(8, 4), u32::from_le_bytes(*b"ineI"));
            cpu.write_var(dst.slice(12, 4), u32::from_le_bytes(*b"ntel"));
        }
        else {
            cpu.write_var(dst.slice(0, 4), 0_u32);
            cpu.write_var(dst.slice(4, 4), u32::from_le_bytes(*b"Icic"));
            cpu.write_var(dst.slice(8, 4), u32::from_le_bytes(*b"leCo"));
            cpu.write_var(dst.slice(12, 4), u32::from_le_bytes(*b"reVm"));
        }
    }

    // Processor info and feature bits
    fn cpuid_version_info(cpu: &mut Cpu, dst: VarNode, _: [Value; 2]) {
        if dst.size != 16 {
            tracing::warn!(
                "Using unpatched SLEIGH specification, CPUID instruction will behave incorrectly"
            );
            return;
        }
        tracing::debug!("cpuid(VERSION_INFO)");
        // Copied from `Coffee Lake` microarchitecture
        let extended_family = 0x0;
        let family = 0x6;
        let extended_model = 0x9;
        let model = 0xe;

        let eax: u32 =
            (extended_family << 20) | (extended_model << 16) | (family << 8) | (model << 4);

        use cpuid::FeatureInformationEcx as Feature;

        let ecx: u32 = (Feature::sse3
            | Feature::tm2
            | Feature::pdcm
            | Feature::popcnt
            | Feature::tsc_deadline
            | Feature::aesni
            | Feature::xsave)
            .bits();

        cpu.write_var(dst.slice(0, 4), eax);
        cpu.write_var(dst.slice(4, 4), 0_u32);
        cpu.write_var(dst.slice(8, 4), ecx);
        cpu.write_var(dst.slice(12, 4), 0_u32);
    }

    // Return structured extended feature enumeration info leaf
    fn cpuid_extended_feature_enumeration_info(cpu: &mut Cpu, dst: VarNode, args: [Value; 2]) {
        if dst.size != 16 {
            tracing::warn!(
                "Using unpatched SLEIGH specification, CPUID instruction will behave incorrectly"
            );
            return;
        }
        let count: u32 = cpu.read(args[1]);
        tracing::debug!("cpuid(EXTENDED_FEATURE_ENUMERATION_INFO, {:#0x})", count);

        match count {
            // Returns extended feature flags in EBX, ECX, and EDX
            0x0 => {
                cpu.write_var(dst.slice(0, 4), u32::MAX);
                cpu.write_var(dst.slice(4, 4), cpuid::EXTENDED_FEATURES_EBX);
                cpu.write_var(dst.slice(8, 4), cpuid::EXTENDED_FEATURES_EDX);
                cpu.write_var(dst.slice(12, 4), cpuid::EXTENDED_FEATURES_ECX);
            }

            // Returns extended feature flags in EAX
            0x1 => {
                // We don't support AVX-512 BFLOAT16 operations
                cpu.write_var(dst.slice(0, 4), 0_u32);
                cpu.write_var(dst.slice(4, 4), 0_u32);
                cpu.write_var(dst.slice(8, 4), 0_u32);
                cpu.write_var(dst.slice(12, 4), 0_u32);
            }
            _ => {
                cpu.write_var(dst.slice(0, 4), 0_u32);
                cpu.write_var(dst.slice(4, 4), 0_u32);
                cpu.write_var(dst.slice(8, 4), 0_u32);
                cpu.write_var(dst.slice(12, 4), 0_u32);
            }
        }
    }

    fn cpuid(cpu: &mut Cpu, dst: VarNode, args: [Value; 2]) {
        if dst.size != 16 {
            tracing::warn!(
                "Using unpatched SLEIGH specification, CPUID instruction will behave incorrectly"
            );
            return;
        }
        let index: u32 = cpu.read(args[0]);
        let count: u32 = cpu.read(args[1]);
        tracing::debug!("cpuid({:#0x}, {:#0x})", index, count);
        match index {
            // Hypervisor
            0x4000_0000 => {
                cpu.write_var(dst.slice(0, 4), 0_u32);
                cpu.write_var(dst.slice(4, 4), 0_u32);
                cpu.write_var(dst.slice(8, 4), 0_u32);
                cpu.write_var(dst.slice(12, 4), 0_u32);
            }

            // Get Highest Extended Function Implemented
            0x8000_0000 => {
                cpu.write_var(dst.slice(0, 4), 0_u32);
                cpu.write_var(dst.slice(4, 4), 0_u32);
                cpu.write_var(dst.slice(8, 4), 0_u32);
                cpu.write_var(dst.slice(12, 4), 0_u32);
            }
            unknown => {
                tracing::warn!("Unknown CPUID index: {:0x}", unknown);
                cpu.exception = (ExceptionCode::UnknownCpuID, unknown as u64).into();
            }
        }
    }

    /// Extract Packed Double-Precision Floating-Point Sign Mask
    fn movmskpd(cpu: &mut Cpu, dst: VarNode, args: [Value; 2]) {
        let src = cpu.read::<u128>(args[1]);
        let result = ((src >> 63) & 0b01) as u32 | ((src >> 126) & 0b10) as u32;

        // workaround SLEIGH bug? should zero extend to 64-bits
        cpu.write_var(VarNode::new(dst.id, 8), result as u64);
    }

    /// Insert word
    #[allow(unused)]
    fn pinsrw(cpu: &mut Cpu, dst: VarNode, args: [Value; 2]) {
        // The byte offset to insert the word at
        let offset = 2 * (cpu.args[0] as u64).min(7);
        let src: u64 = cpu.read_dynamic(args[1]).zxt();

        cpu.write_var(dst.slice(offset as u8, 2), src as u16);
    }

    /// Shuffle packed low words
    fn pshuflw(cpu: &mut Cpu, dst: VarNode, args: [Value; 2]) {
        let src = cpu.read::<u64>(args[1].slice(0, 8));
        let count = cpu.args[0] as u64;

        // Shuffle low bits
        for offset in 0..4 {
            let shift = (count >> (offset * 2) & 0b11) * 16;
            let value = (src >> shift) & 0xffff;
            cpu.write_var(dst.slice(offset * 2, 2), value as u16);
        }

        // Copy high bits
        let src_hi = cpu.read::<u64>(args[1].slice(8, 8));
        cpu.write_var(dst.slice(8, 8), src_hi)
    }

    /// Shuffle packed high words
    fn pshufhw(cpu: &mut Cpu, dst: VarNode, args: [Value; 2]) {
        let src = cpu.read::<u64>(args[1].slice(8, 8));
        let count = cpu.args[0] as u64;

        // Copy low bits
        let src_low = cpu.read::<u64>(args[1].slice(0, 8));
        cpu.write_var(dst.slice(0, 8), src_low);

        // Shuffle high bits
        for offset in 0..4 {
            let shift = (count >> (offset * 2) & 0b11) * 16;
            let value = (src >> shift) & 0xffff;
            cpu.write_var(dst.slice(8 + offset * 2, 2), value as u16);
        }
    }

    /// Packed interleave shuffle
    #[allow(unused)]
    fn shufpd(cpu: &mut Cpu, dst: VarNode, args: [Value; 2]) {
        let index = cpu.args[0] as u64;

        let a = if index & 0b01 == 0 { 0 } else { 8 };
        let b = if index & 0b10 == 0 { 0 } else { 8 };

        let lo = cpu.read::<u64>(args[0].slice(a, 8));
        let hi = cpu.read::<u64>(args[1].slice(b, 8));

        cpu.write_var(dst.slice(0, 8), lo);
        cpu.write_var(dst.slice(8, 8), hi);
    }

    // Multiply and Add Packed Integers
    fn pmaddwd(cpu: &mut Cpu, dst: VarNode, args: [Value; 2]) {
        for i in (0..dst.size).step_by(std::mem::size_of::<u32>()) {
            let lo = cpu.read::<i16>(args[0].slice(i, 2)) as i32
                * cpu.read::<i16>(args[1].slice(i, 2)) as i32;

            let hi = cpu.read::<i16>(args[0].slice(i + 2, 2)) as i32
                * cpu.read::<i16>(args[1].slice(i + 2, 2)) as i32;

            cpu.write_var(dst.slice(i, 4), lo.wrapping_add(hi));
        }
    }

    fn in_io(cpu: &mut Cpu, dst: VarNode, _: [Value; 2]) {
        cpu.write_trunc(dst, 0_u32);
    }
    fn out_io(_: &mut Cpu, _: VarNode, _: [Value; 2]) {}
    fn lock(_: &mut Cpu, _: VarNode, _: [Value; 2]) {}
    fn unlock(_: &mut Cpu, _: VarNode, _: [Value; 2]) {}

    /// Compute the approximate of the sine of the source operand and store it in the destination
    fn fsin(cpu: &mut Cpu, dst: VarNode, args: [Value; 2]) {
        // Input is an 80-bit floating point number, but we treat it as a f64.
        let x = f64::from_bits(cpu.read::<u64>(args[0].slice(0, 8)));
        let result = x.sin();
        cpu.write_var(dst.truncate(8), result.to_bits());
    }

    /// Compute the approximate of the cosine of the source operand and store it in the destination
    fn fcos(cpu: &mut Cpu, dst: VarNode, args: [Value; 2]) {
        // Input is an 80-bit floating point number, but we treat it as a f64.
        let x = f64::from_bits(cpu.read::<u64>(args[0].truncate(8)));
        let result = x.cos();
        cpu.write_var(dst.truncate(8), result.to_bits());
    }

    /// Compute the approximate of the tangent of the source operand and store it in the destination
    fn fptan(cpu: &mut Cpu, dst: VarNode, args: [Value; 2]) {
        // Input is an 80-bit floating point number, but we treat it as a f64.
        let x = f64::from_bits(cpu.read::<u64>(args[0].truncate(8)));
        let result = x.tan();
        cpu.write_var(dst.truncate(8), result.to_bits());
    }

    /// Compute ST0 = 2^(ST0) - 1
    fn f2xm1(cpu: &mut Cpu, dst: VarNode, args: [Value; 2]) {
        // Input is an 80-bit floating point number, but we treat it as a f64.
        let st0 = f64::from_bits(cpu.read::<u64>(args[0].truncate(8)));
        let result = st0.exp2() - 1.0;
        cpu.write_var(dst.truncate(8), result.to_bits());
    }

    /// Compute ST0 = ST0 * 2^(trunc(ST1))
    fn fscale(cpu: &mut Cpu, dst: VarNode, args: [Value; 2]) {
        // Input is an 80-bit floating point number, but we treat it as a f64.
        let st0 = f64::from_bits(cpu.read::<u64>(args[0].truncate(8)));
        let st1 = f64::from_bits(cpu.read::<u64>(args[1].truncate(8)));
        let result = st0 * st1.trunc().exp2();
        cpu.write_var(dst.truncate(8), result.to_bits());
    }

    pub mod cpuid {
        #![allow(non_upper_case_globals)]

        use bitflags::bitflags;

        bitflags! {
            pub struct FeatureInformationEcx: u32 {
                const sse3         = 1 << 0;
                const pclmulqdq    = 1 << 1;
                const dtes64       = 1 << 2;
                const monitor      = 1 << 3;
                const ds_cpl       = 1 << 4;
                const vmx          = 1 << 5;
                const smx          = 1 << 6;
                const eist         = 1 << 7;
                const tm2          = 1 << 8;
                const ssse3        = 1 << 9;
                const cnxt_id      = 1 << 10;
                const sdbg         = 1 << 11;
                const fma          = 1 << 12;
                const cmpxchg16b   = 1 << 13;
                const xtpr         = 1 << 14;
                const pdcm         = 1 << 15;
                const _reserved    = 1 << 16;
                const pcid         = 1 << 17;
                const dca          = 1 << 18;
                const sse4_1       = 1 << 19;
                const sse4_2       = 1 << 20;
                const x2apic       = 1 << 21;
                const movbe        = 1 << 22;
                const popcnt       = 1 << 23;
                const tsc_deadline = 1 << 24;
                const aesni        = 1 << 25;
                const xsave        = 1 << 26;
                const osxsave      = 1 << 27;
                const avx          = 1 << 28;
                const f16c         = 1 << 29;
                const rdrand       = 1 << 30;
                const _unused      = 1 << 31;
            }
        }

        bitflags! {
            pub struct ExtendedFeaturesEbx: u32 {
                const fsgsbase   = 1 << 0;
                const tscadjust  = 1 << 1;
                const sgx        = 1 << 2;
                const bmi1       = 1 << 3;
                const hle        = 1 << 4;
                const avx2       = 1 << 5;
                const _invalid0  = 1 << 6;
                const smep       = 1 << 7;
                const bmi2       = 1 << 8;
                const erms       = 1 << 9;
                const invpcid    = 1 << 10;
                const rtm        = 1 << 11;
                const pqm        = 1 << 12;
                const _invalid1  = 1 << 13;
                const mpx        = 1 << 14;
                const pqe        = 1 << 15;
                const avx512f    = 1 << 16;
                const avx512dq   = 1 << 17;
                const rdseed     = 1 << 18;
                const adx        = 1 << 19;
                const smap       = 1 << 20;
                const avx512ifma = 1 << 21;
                const pcommit    = 1 << 22;
                const clflushopt = 1 << 23;
                const clwb       = 1 << 24;
                const intel_pt   = 1 << 25;
                const avx512pf   = 1 << 26;
                const avx512er   = 1 << 27;
                const avx412cd   = 1 << 28;
                const sha        = 1 << 29;
                const avx512bw   = 1 << 30;
                const avx512vl   = 1 << 31;
            }
        }

        pub const EXTENDED_FEATURES_EBX: u32 = 0;
        pub const EXTENDED_FEATURES_ECX: u32 = 0;
        pub const EXTENDED_FEATURES_EDX: u32 = 0;
    }
}

pub mod aarch64 {
    use super::*;

    pub const HELPERS: &[(&str, PcodeOpHelper)] = &[
        ("NEON_cmeq", neon_cmeq),
        ("NEON_uminv", neon_uminv),
        ("NEON_sminv", neon_sminv),
        ("NEON_umaxv", neon_umaxv),
        ("NEON_smaxv", neon_smaxv),
    ];

    //
    // NEON implementations
    // @todo: implement these in pcode
    //

    fn neon_cmeq(cpu: &mut Cpu, dst: VarNode, args: [Value; 2]) {
        let size = cpu.args[0] as u8;
        if size == 0 {
            // This only occurs as a result of a SLEIGH bug.
            cpu.exception = ExceptionCode::InvalidOpSize.into();
            return;
        }

        let a = args[0];
        let b = args[1];
        for i in (0..a.size()).step_by(size as usize) {
            let a: u64 = cpu.read_dynamic(a.slice(i, size)).zxt();
            let b: u64 = cpu.read_dynamic(b.slice(i, size)).zxt();
            cpu.write_trunc(dst.slice(i, size), if a == b { u64::MAX } else { 0 })
        }
    }

    fn neon_uminv(cpu: &mut Cpu, dst: VarNode, args: [Value; 2]) {
        let value = args[0];
        let size = cpu.read::<u8>(args[1]);

        let mut min = u64::MAX;
        for i in (0..value.size()).step_by(size as usize) {
            let a: u64 = cpu.read_dynamic(value.slice(i, size)).zxt();
            min = u64::min(min, a);
        }
        cpu.write_trunc(dst, min);
    }

    fn neon_sminv(cpu: &mut Cpu, dst: VarNode, args: [Value; 2]) {
        let value = args[0];
        let size = cpu.read::<u8>(args[1]);

        let mut min = i64::MAX;
        for i in (0..value.size()).step_by(size as usize) {
            let a: u64 = cpu.read_dynamic(value.slice(i, size)).sxt();
            min = i64::min(min, a as i64);
        }
        cpu.write_trunc(dst, min as u64);
    }

    fn neon_umaxv(cpu: &mut Cpu, dst: VarNode, args: [Value; 2]) {
        let value = args[0];
        let size = cpu.read::<u8>(args[1]);

        let mut max = u64::MIN;
        for i in (0..value.size()).step_by(size as usize) {
            let a = cpu.read_dynamic(value.slice(i, size)).zxt();
            max = u64::max(max, a);
        }
        cpu.write_trunc(dst, max);
    }

    fn neon_smaxv(cpu: &mut Cpu, dst: VarNode, args: [Value; 2]) {
        let value = args[0];
        let size = cpu.read::<u8>(args[1]);

        let mut max = i64::MIN;
        for i in (0..value.size()).step_by(size as usize) {
            let a: u64 = cpu.read_dynamic(value.slice(i, size)).sxt();
            max = i64::max(max, a as i64);
        }
        cpu.write_trunc(dst, max as u64);
    }
}

pub mod arm {
    use super::*;

    pub const HELPERS: &[(&str, PcodeOpHelper)] = &[
        ("enableIRQinterrupts", enable_interrupts),
        ("disableIRQinterrupts", disable_interrupts),
        // NEON
        ("VectorCompareEqual", vector_compare_equal),
        ("VectorPairwiseAdd", vector_pairwise_add),
        ("VectorAdd", vector_add),
        ("VectorSub", vector_sub),
        ("vrev", vrev),
        ("VectorCopyNarrow", vector_copy_narrow),
    ];

    fn vector_compare_equal(cpu: &mut Cpu, dst: VarNode, args: [Value; 2]) {
        let esize = cpu.args[0] as u8;
        for i in 0..(dst.size / esize) {
            let a: u64 = cpu.read_dynamic(args[0].slice(i * esize, esize)).zxt();
            let b: u64 = cpu.read_dynamic(args[1].slice(i * esize, esize)).zxt();
            cpu.write_trunc(dst.slice(i * esize, esize), if a == b { u64::MAX } else { 0 });
        }
    }

    // [a, b] + [c, d] = [a + c, b + d]
    fn vector_add(cpu: &mut Cpu, dst: VarNode, args: [Value; 2]) {
        let esize = cpu.args[0] as u8;
        for i in 0..(dst.size / esize) {
            let a: u64 = cpu.read_dynamic(args[0].slice(i * esize, esize)).zxt();
            let b: u64 = cpu.read_dynamic(args[1].slice(i * esize, esize)).zxt();
            cpu.write_trunc(dst.slice(i * esize, esize), a.wrapping_add(b));
        }
    }

    // [a, b] - [c, d] = [a - c, b - d]
    fn vector_sub(cpu: &mut Cpu, dst: VarNode, args: [Value; 2]) {
        let esize = cpu.args[0] as u8;
        for i in 0..(dst.size / esize) {
            let a: u64 = cpu.read_dynamic(args[0].slice(i * esize, esize)).zxt();
            let b: u64 = cpu.read_dynamic(args[1].slice(i * esize, esize)).zxt();
            cpu.write_trunc(dst.slice(i * esize, esize), a.wrapping_sub(b));
        }
    }

    // [a, b][c, d] = [a + b, c + d]
    fn vector_pairwise_add(cpu: &mut Cpu, dst: VarNode, args: [Value; 2]) {
        let esize = cpu.args[0] as u8;

        let dst_low = dst.slice(0, dst.size / 2);
        for i in 0..(dst_low.size / esize) {
            let a: u64 = cpu.read_dynamic(args[0].slice((i * 2) * esize, esize)).zxt();
            let b: u64 = cpu.read_dynamic(args[0].slice(((i * 2) + 1) * esize, esize)).zxt();
            cpu.write_trunc(dst_low.slice(i * esize, esize), a.wrapping_add(b));
        }
        let dst_high = dst.slice(dst.size / 2, dst.size / 2);
        for i in 0..(dst_high.size / esize) {
            let a: u64 = cpu.read_dynamic(args[1].slice((i * 2) * esize, esize)).zxt();
            let b: u64 = cpu.read_dynamic(args[1].slice(((i * 2) + 1) * esize, esize)).zxt();
            cpu.write_trunc(dst_high.slice(i * esize, esize), a.wrapping_add(b));
        }
    }

    fn vrev(cpu: &mut Cpu, dst: VarNode, args: [Value; 2]) {
        let esize: u8 = cpu.read_dynamic(args[1]).zxt();
        for i in 0..(dst.size / esize) {
            let a: u64 = cpu.read_dynamic(args[0].slice(i * esize, esize)).zxt();
            cpu.write_trunc(dst.slice(dst.size - (i + 1) * esize, esize), a);
        }
    }

    /// Copy the lower bits of a quadword vector to a doubleword vector.
    /// arg[0] = source, arg[1] = element size
    ///
    /// e.g., for element size = 4:
    /// arg[0] [a:u32, b:32, c:u32, d:u32], dst=[a:u16, b:u16, c:u16, d:u16]
    fn vector_copy_narrow(cpu: &mut Cpu, dst: VarNode, args: [Value; 2]) {
        let src = args[0];
        let esize = cpu.read::<u8>(args[1]);
        let dst_esize = esize / 2;
        for i in 0..(src.size() / esize) {
            let value: u64 = cpu.read_dynamic(src.slice(i * esize, esize)).zxt();
            cpu.write_trunc(dst.slice(i * dst_esize, dst_esize), value);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_bcd_add16() {
        assert_eq!(bcd_add16(0x0001, 0x0009), 0x0010);
        assert_eq!(bcd_add16(0x0001, 0x0019), 0x0020);
        assert_eq!(bcd_add16(0x0001, 0x0099), 0x0100);
        assert_eq!(bcd_add16(0x0001, 0x0199), 0x0200);
        assert_eq!(bcd_add16(0x0001, 0x0999), 0x1000);

        assert_eq!(bcd_add16(0x1234, 0x1234), 0x2468);
        assert_eq!(bcd_add16(0x0555, 0x5555), 0x6110);
    }
}
