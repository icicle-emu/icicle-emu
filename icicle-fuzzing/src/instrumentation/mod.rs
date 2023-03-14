use std::collections::HashMap;

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

/// Read N-bytes from memory starting at `addr`. Returns [None] if the memory is not readable, or
/// is IO mapped.
pub(crate) fn try_read_mem<const N: usize>(cpu: &mut Cpu, addr: u64) -> Option<[u8; N]> {
    if get_pointer_perm(cpu, addr, N as u64) & perm::READ == 0 {
        return None;
    }

    let mut a = [0; N];
    if cpu.mem.read_bytes(addr, &mut a, perm::READ).is_err() {
        return None;
    }

    Some(a)
}

pub struct SSARewriter {
    new_to_old: HashMap<i16, (usize, pcode::VarNode)>,
    old_to_new: HashMap<i16, pcode::VarNode>,
    next_id: i16,
}

impl SSARewriter {
    pub fn new() -> Self {
        Self { new_to_old: HashMap::new(), old_to_new: HashMap::new(), next_id: 1 }
    }

    pub fn get_input(&mut self, x: pcode::Value) -> pcode::Value {
        match x {
            pcode::Value::Var(x) if !x.is_invalid() => match self.old_to_new.get(&x.id) {
                Some(x) => pcode::Value::Var(*x),
                None => self.set_output(0, x).into(),
            },
            _ => x,
        }
    }

    pub fn set_output(&mut self, offset: usize, var: pcode::VarNode) -> pcode::VarNode {
        if var == pcode::VarNode::NONE {
            return pcode::VarNode::NONE;
        }
        let output = pcode::VarNode::new(self.next_id, var.size);
        self.new_to_old.insert(self.next_id, (offset, var));
        self.old_to_new.insert(var.id, output);
        self.next_id += 1;
        output
    }

    pub fn get_original(&mut self, new: pcode::Value) -> (usize, pcode::Value) {
        match new {
            pcode::Value::Var(var) => {
                let (offset, x) = *self.new_to_old.get(&var.id).unwrap_or(&(0, var));
                (offset, x.into())
            }
            pcode::Value::Const(_, _) => (0, new),
        }
    }
}
