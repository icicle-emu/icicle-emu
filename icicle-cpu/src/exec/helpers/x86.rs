use super::*;

pub const HELPERS: &[(&str, PcodeOpHelper)] = &[
    ("rdtsc", rdtsc),
    ("cpuid_basic_info", cpuid_basic_info),
    ("cpuid_Version_info", cpuid_version_info),
    ("cpuid_Extended_Feature_Enumeration_info", cpuid_extended_feature_enumeration_info),
    ("cpuid", cpuid),
    ("movmskpd", movmskpd),
    ("divpd", divpd),
    ("pinsrw", pinsrw), // Note: implemented in SLEIGH in Ghidra 10.3.
    ("pshuflw", pshuflw),
    ("pshufhw", pshufhw),
    ("shufpd", shufpd), // Note: implemented in SLEIGH in Ghidra 10.3.
    ("pmaddwd", pmaddwd),
    ("psadbw", psadbw),
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

// Unpatched SLEIGH spec models CPUID as writing to memory which breaks emulation.
fn is_cpuid_patched(dst: VarNode) -> bool {
    if dst.size != 16 {
        warn_once!(
            "Using unpatched SLEIGH specification, CPUID instruction will behave incorrectly"
        );
        return false;
    }
    true
}

// Basic processor information
fn cpuid_basic_info(cpu: &mut Cpu, dst: VarNode, _: [Value; 2]) {
    if !is_cpuid_patched(dst) {
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
    if !is_cpuid_patched(dst) {
        return;
    }
    tracing::debug!("cpuid(VERSION_INFO)");
    // Copied from `Coffee Lake` microarchitecture
    let extended_family = 0x0;
    let family = 0x6;
    let extended_model = 0x9;
    let model = 0xe;

    let eax: u32 = (extended_family << 20) | (extended_model << 16) | (family << 8) | (model << 4);

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
    if !is_cpuid_patched(dst) {
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
            cpu.exception.code = ExceptionCode::UnknownCpuID as u32;
            cpu.exception.value = unknown as u64;
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

/// Divide packed double-precision floating-point values.
fn divpd(cpu: &mut Cpu, dst: VarNode, args: [Value; 2]) {
    for offset in (0..dst.size).step_by(std::mem::size_of::<f64>()) {
        let lhs = f64::from_bits(cpu.read::<u64>(args[0].slice(offset, 8)));
        let rhs = f64::from_bits(cpu.read::<u64>(args[1].slice(offset, 8)));
        cpu.write_var(dst.slice(offset, 8), (lhs / rhs).to_bits());
    }
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

/// Compute Sum of Absolute Differences of 8 unsigned byte integers summed to a word
fn psadbw(cpu: &mut Cpu, dst: VarNode, args: [Value; 2]) {
    for i in (0..dst.size).step_by(std::mem::size_of::<u64>()) {
        let a = cpu.read::<u64>(args[0].slice(i, 8));
        let b = cpu.read::<u64>(args[1].slice(i, 8));

        let mut sum = 0_u32;
        for (a, b) in a.to_ne_bytes().iter().zip(b.to_ne_bytes()) {
            sum += a.abs_diff(b) as u32;
        }
        // Note: upper bits are zeroed
        cpu.write_var(dst.slice(i, 8), sum as u64);
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
