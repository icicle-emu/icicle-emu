//! CompareCoverage instrumentation, aka laf-intel (inspired by the implementation from qemuafl)

use hashbrown::{HashMap, HashSet};
use icicle_vm::{
    cpu::{
        lifter::{Block, BlockExit},
        mem::perm,
        BlockGroup, BlockTable, Cpu, StoreRef,
    },
    CodeInjector, Vm,
};
use pcode::PcodeDisplay;

use crate::{
    fnv_hash, fnv_hash_with, get_pointer_perm,
    instrumentation::cmp_finder::{CmpAttr, CmpFinder},
};

pub struct CompCovBuilder<F> {
    filter: F,
    level: u8,
}

impl CompCovBuilder<fn(&Block) -> bool> {
    pub fn new() -> Self {
        Self { filter: |_| true, level: 2 }
    }
}

impl<F> CompCovBuilder<F> {
    pub fn filter<NF>(self, filter: NF) -> CompCovBuilder<NF>
    where
        NF: for<'r> Fn(&Block) -> bool + 'static,
    {
        CompCovBuilder { filter, level: self.level }
    }

    pub fn level(self, level: u8) -> Self {
        Self { level, ..self }
    }

    pub fn finish(self, vm: &mut Vm, coverage_map: StoreRef)
    where
        F: for<'r> Fn(&Block) -> bool + 'static,
    {
        CompareCov::register(vm, self.filter, self.level, coverage_map)
    }
}

#[derive(Debug)]
struct FunctionHook {
    addr: u64,
    hook: pcode::HookId,
}

impl FunctionHook {
    pub fn add<F>(vm: &mut Vm, name: &str, hook: F) -> Option<Self>
    where
        F: FnMut(&mut Cpu, u64) + 'static,
    {
        let addr = vm.env.lookup_symbol(name)?;
        tracing::info!("found {name} at: {addr:#x}");
        let hook = vm.cpu.add_hook(Box::new(hook));
        Some(Self { addr, hook })
    }
}

pub struct CompareCov<F> {
    coverage_map: StoreRef,
    size_mask: u32,
    instrumented: HashSet<u64>,
    cmp_finder: CmpFinder,
    hooks: Vec<FunctionHook>,
    level: u8,
    filter: F,
}

impl<F> CompareCov<F>
where
    F: FnMut(&Block) -> bool + 'static,
{
    fn register(vm: &mut Vm, filter: F, level: u8, cov: StoreRef) {
        tracing::info!("CompCov enable at level = {level}");

        let map_size = vm.cpu.trace[cov].data().len();
        assert!(map_size < u32::MAX as usize && map_size.is_power_of_two());

        let mut hooks = vec![];
        let mut tracer = Tracer::new(cov);
        if let Some(entry) =
            FunctionHook::add(vm, "memcmp", move |cpu, addr| tracer.memcmp(cpu, addr))
        {
            hooks.push(entry);
        }

        let mut tracer = Tracer::new(cov);
        if let Some(entry) =
            FunctionHook::add(vm, "strcmp", move |cpu, addr| tracer.strcmp(cpu, addr))
        {
            hooks.push(entry);
        }

        let mut tracer = Tracer::new(cov);
        if let Some(entry) =
            FunctionHook::add(vm, "strncmp", move |cpu, addr| tracer.strncmp(cpu, addr))
        {
            hooks.push(entry);
        }

        vm.add_injector(CompareCov {
            coverage_map: cov,
            size_mask: map_size as u32 - 1,
            cmp_finder: CmpFinder::with_arch(&vm.cpu.arch),
            instrumented: HashSet::new(),
            hooks,
            level,
            filter,
        });
    }

    /// Adds instrumentation to keep track of the PC value of any callers to hooked functions.
    fn instrument_hooked_callers(&mut self, block: &mut Block) -> bool {
        let callee = match block.exit {
            BlockExit::Call { target: pcode::Value::Const(target, _), .. } => target,

            // Currently we assume there are no indirect calls to hooked functions
            BlockExit::Call { target: pcode::Value::Var(_), .. } => return false,

            // Not a call
            _ => return false,
        };

        let mut found = false;
        for entry in self.hooks.iter().filter(|x| x.addr == callee) {
            tracing::debug!("[{:#x}] hooking call to {callee:#x}", block.start);
            block.pcode.push(pcode::Op::Hook(entry.hook));
            found = true;
        }

        found
    }

    fn instrument_cmp(&mut self, cpu: &Cpu, block: &mut Block) -> bool {
        let cmps = self.cmp_finder.find_cmp(block);
        if cmps.is_empty() {
            return false;
        }

        let mut tmp_block = pcode::Block::new();
        block.pcode.recompute_next_tmp();
        tmp_block.next_tmp = block.pcode.next_tmp;

        // Allocate temporaries
        let is_eq = tmp_block.alloc_tmp(1);
        let tmp = tmp_block.alloc_tmp(1);
        let count = tmp_block.alloc_tmp(1);

        let mut inject_iter = cmps.iter().peekable();

        let mut pc = 0;
        for (i, stmt) in block.pcode.instructions.iter().enumerate() {
            if let pcode::Op::InstructionMarker = stmt.op {
                pc = stmt.inputs.first().as_u64();
            }
            tmp_block.push(*stmt);

            while let Some(entry) = inject_iter.next_if(|entry| entry.offset <= i) {
                let size = entry.arg1.size().min(entry.arg2.size());
                if size == 1 {
                    // Avoid adding extra instrumentation for byte-level comparisons
                    continue;
                }

                if self.level < 2 && !(entry.arg1.is_const() || entry.arg2.is_const()) {
                    // At level 1 ignore non-constant comparisons.
                    continue;
                }
                if self.level < 3
                    && (entry.kind.contains(CmpAttr::IS_FLOAT)
                        || entry.kind.contains(CmpAttr::IS_LESSER)
                        || entry.kind.contains(CmpAttr::IS_OVERFLOW)
                        || entry.kind.contains(CmpAttr::IS_GREATER))
                {
                    // At level 2 or lower, ignore floating-point operations and
                    // less-than/greater-than operations.
                    continue;
                }

                if !self.instrumented.insert(pc) {
                    // Only generate instrumentation once per instruction
                    continue;
                }

                tracing::debug!(
                    "[{pc:#x}] adding coverage for {} {:?} {}",
                    entry.arg1.display(&cpu.arch.sleigh),
                    entry.kind,
                    entry.arg2.display(&cpu.arch.sleigh)
                );

                tmp_block.push(is_eq.copy_from(1_u8));
                for i in 0..size {
                    // is_eq &= arg1[i] == arg2[i]
                    let arg1 = entry.arg1.slice(i, 1);
                    let arg2 = entry.arg2.slice(i, 1);
                    tmp_block.push((tmp, pcode::Op::IntEqual, (arg1, arg2)));
                    tmp_block.push((is_eq, pcode::Op::IntAnd, (is_eq, tmp)));

                    // bitmap[key + i] += is_eq
                    let bitmap_id = self.coverage_map.get_store_id();
                    let index = (fnv_hash(pc) + i as u32) & self.size_mask;
                    tmp_block.push((count, pcode::Op::Load(bitmap_id), index));
                    tmp_block.push((count, pcode::Op::IntAdd, (count, is_eq)));
                    tmp_block.push((pcode::Op::Store(bitmap_id), (index, count)));
                }
            }
        }

        let result = !self.instrumented.is_empty();
        self.instrumented.clear();
        block.pcode = tmp_block;

        result
    }
}

impl<F> CodeInjector for CompareCov<F>
where
    F: FnMut(&Block) -> bool + 'static,
{
    fn inject(&mut self, cpu: &mut Cpu, group: &BlockGroup, code: &mut BlockTable) {
        let block = &mut code.blocks[group.blocks.0];
        if !(self.filter)(block) {
            return;
        }

        let mut instrumented = false;

        instrumented |= self.instrument_hooked_callers(block);
        if self.level > 0 {
            instrumented |= self.instrument_cmp(cpu, block);
        }

        if instrumented {
            code.modified.insert(group.blocks.0);
        }
    }
}

const MAX_CMP_LENGTH: usize = 32;

#[derive(Clone)]
struct Tracer {
    cov_map: StoreRef,
    best: HashMap<u64, u32>,
    max_length: usize,
}

impl Tracer {
    fn new(cov_map: StoreRef) -> Self {
        Self { cov_map, best: HashMap::new(), max_length: MAX_CMP_LENGTH }
    }

    fn memcmp(&mut self, cpu: &mut Cpu, addr: u64) {
        let (mem1, mem2, len) =
            match (cpu.read_ptr_arg(0), cpu.read_ptr_arg(1), cpu.read_ptr_arg(2)) {
                (Ok(x), Ok(y), Ok(z)) => (x, y, z),
                _ => return,
            };

        let (mem1, mem2) = match read_pointers(cpu, mem1, mem2) {
            Some(data) => data,
            None => return,
        };

        let key = fnv_hash(addr);
        let cov = cpu.trace[self.cov_map].data_mut();
        let mask = (cov.len() - 1) as u32;
        for i in 0..(len as usize).min(self.max_length) {
            if mem1[i] != mem2[i] {
                break;
            }
            cov[((key + i as u32) & mask) as usize] += 1;
        }

        tracing::trace!(
            "[{addr:#x}] memcmp({}, {}, {len})",
            mem1.escape_ascii(),
            mem2.escape_ascii()
        );
    }

    fn strcmp(&mut self, cpu: &mut Cpu, addr: u64) {
        if let (Ok(str1), Ok(str2)) = (cpu.read_ptr_arg(0), cpu.read_ptr_arg(1)) {
            self.trace_strncmp_with(cpu, addr, str1, str2, self.max_length as u64);
        }
    }

    fn strncmp(&mut self, cpu: &mut Cpu, addr: u64) {
        if let (Ok(str1), Ok(str2), Ok(len)) =
            (cpu.read_ptr_arg(0), cpu.read_ptr_arg(1), cpu.read_ptr_arg(2))
        {
            self.trace_strncmp_with(cpu, addr, str1, str2, len);
        }
    }

    fn trace_strncmp_with(&mut self, cpu: &mut Cpu, addr: u64, str1: u64, str2: u64, len: u64) {
        let (str1, str2) = match read_pointers(cpu, str1, str2) {
            Some(data) => data,
            None => return,
        };

        let mut check_new_best_match = |idx: u32| {
            let entry = self.best.entry(addr).or_default();
            if *entry < idx {
                tracing::debug!(
                    "[{addr:#x}] new best match: idx={idx} (a=\"{}\", b=\"{}\")",
                    display_str(&str1[..((idx / 2) + 1) as usize]),
                    display_str(&str2[..((idx / 2) + 1) as usize]),
                );
                *entry = idx;
            }
        };

        let key = fnv_hash(addr);
        let cov = cpu.trace[self.cov_map].data_mut();
        let mask = (cov.len() - 1) as u32;
        let mut best_match = 0;
        for i in 0..(len as usize).min(MAX_CMP_LENGTH) {
            if str1[i] == 0 || str2[i] == 0 {
                break;
            }

            let idx = fnv_hash_with(key, (2 * i) as u64) & mask;
            cov[idx as usize] += 1;
            best_match = (2 * i) as u32;

            if str1[i] != str2[i] {
                break;
            }
            let idx = fnv_hash_with(key, (2 * i + 1) as u64) & mask;
            cov[idx as usize] += 1;

            best_match = (2 * i + 1) as u32;
        }
        check_new_best_match(best_match);

        tracing::trace!(
            "[{addr:#x}] strncmp(\"{}\",\"{}\",{len})",
            display_str(&str1),
            display_str(&str2)
        );
    }
}

fn display_str(bytes: &[u8]) -> impl std::fmt::Display + '_ {
    let len = bytes.iter().position(|x| *x == 0).unwrap_or(bytes.len());
    bytes[..len].escape_ascii()
}

#[inline(always)]
fn read_pointers(
    cpu: &mut Cpu,
    a_ptr: u64,
    b_ptr: u64,
) -> Option<([u8; MAX_CMP_LENGTH], [u8; MAX_CMP_LENGTH])> {
    // @todo: support filtering only constant comparisons for cmplog level 1
    if get_pointer_perm(cpu, a_ptr, MAX_CMP_LENGTH as u64) & perm::READ == 0
        || get_pointer_perm(cpu, b_ptr, MAX_CMP_LENGTH as u64) & perm::READ == 0
    {
        // Pointer is invalid
        return None;
    }

    let mut a = [0; MAX_CMP_LENGTH];
    let _ = cpu.mem.read_bytes(a_ptr, &mut a[..], perm::NONE);

    let mut b = [0; MAX_CMP_LENGTH];
    let _ = cpu.mem.read_bytes(b_ptr, &mut b[..], perm::NONE);

    Some((a, b))
}
