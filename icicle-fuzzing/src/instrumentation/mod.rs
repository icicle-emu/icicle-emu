use icicle_vm::cpu::{mem::perm, Cpu};

pub mod cmp_finder;
pub mod cmplog;
pub mod compcov;
pub mod coverage;

/// Computes the hash of an integer using the FNV-1a algorithm.
pub fn fnv_hash(value: u64) -> u32 {
    fnv_hash_with(0x811c9dc5_u32, value)
}

pub fn fnv_hash_with(mut hash: u32, value: u64) -> u32 {
    for i in 0..8 {
        hash = hash.wrapping_mul(0x1000193_u32);
        hash ^= (value >> (i * 8)) as u8 as u32;
    }
    hash
}

pub(crate) fn get_pointer_perm(cpu: &mut Cpu, addr: u64, len: u64) -> u8 {
    // @fixme: we only check the first and last byte of the region for performance reasons.
    cpu.mem.get_perm(addr) & cpu.mem.get_perm(addr + len)
}

/// Read 32-bytes from memory starting at `addr`. Returns [None] if the memory is not readable, or
/// is IO mapped.
pub(crate) fn try_read_mem(cpu: &mut Cpu, addr: u64) -> Option<[u8; 31]> {
    if get_pointer_perm(cpu, addr, 31) & perm::READ == 0 {
        return None;
    }

    let mut a = [0; 31];
    if cpu.mem.read_bytes(addr, &mut a, perm::READ).is_err() {
        return None;
    }

    Some(a)
}
