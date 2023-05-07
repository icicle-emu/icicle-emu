//! A comparison logging technique that can be disabled at runtime and avoids hash collisions by
//! reserving unique slots whenever a new comparison is found.

use icicle_vm::{
    cpu::{
        lifter::{Block, BlockExit},
        BlockGroup, BlockTable, Cpu, HookHandler, ValueSource,
    },
    CodeInjector, Vm,
};
use pcode::PcodeDisplay;
use std::collections::HashMap;

use crate::{instrumentation::cmp_finder::CmpFinder, try_read_mem};

pub use crate::instrumentation::cmp_finder::{CmpAttr, CmpOp};

pub struct CmpLog2Builder<F> {
    filter: F,
    enable_rtn: bool,
    check_indirect: bool,
}

impl CmpLog2Builder<fn(&Block) -> bool> {
    pub fn new() -> Self {
        Self { filter: |_| true, enable_rtn: false, check_indirect: false }
    }
}

impl<F> CmpLog2Builder<F> {
    pub fn filter<NF>(self, filter: NF) -> CmpLog2Builder<NF>
    where
        NF: for<'r> Fn(&Block) -> bool + 'static,
    {
        CmpLog2Builder { filter, enable_rtn: self.enable_rtn, check_indirect: self.check_indirect }
    }

    pub fn instrument_calls(mut self, value: bool) -> Self {
        self.enable_rtn = value;
        self
    }

    pub fn check_indirect_pointers(mut self, value: bool) -> Self {
        self.check_indirect = value;
        self
    }

    pub fn finish(self, vm: &mut Vm) -> CmpLog2Ref
    where
        F: for<'r> Fn(&Block) -> bool + 'static,
    {
        CmpLog2::register(vm, self.filter, self.enable_rtn, self.check_indirect)
    }
}

#[derive(Clone)]
pub struct CmpInstData {
    pub addr: u64,
    pub op: CmpOp,
    pub values: Vec<(i64, i64)>,
}

#[derive(Default)]
struct CmpInstTable {
    entries: Vec<CmpInstData>,
}

impl CmpInstTable {
    fn clear(&mut self) {
        self.entries.iter_mut().for_each(|x| x.values.clear());
    }
}

impl HookHandler for CmpInstTable {
    fn call(data: &mut Self, cpu: &mut Cpu, _addr: u64) {
        let entry = &mut data.entries[cpu.args[0] as usize];
        let a = icicle_vm::cpu::read_value_sxt(cpu, entry.op.arg1);
        let b = icicle_vm::cpu::read_value_sxt(cpu, entry.op.arg2);
        entry.values.push((a, b));
    }
}

pub struct CmpCallData {
    pub addr: u64,
    pub values: Vec<([u8; 64], [u8; 64])>,
    pub has_invalid: bool,
    pub is_indirect: bool,
}

impl CmpCallData {
    pub fn new(addr: u64) -> Self {
        Self { addr, values: vec![], has_invalid: false, is_indirect: false }
    }
}

struct CmpCallTable {
    entries: Vec<CmpCallData>,
    /// A flag that can be enable to also save values from indirect pointers. This occurs with
    /// certain operations on some C++ string representations.
    check_indirect_pointers: bool,
}

impl CmpCallTable {
    fn new(check_indirect_pointers: bool) -> Self {
        Self { entries: vec![], check_indirect_pointers }
    }

    fn clear(&mut self) {
        self.entries.iter_mut().for_each(|x| {
            x.values.clear();
            x.has_invalid = false;
            x.is_indirect = false;
        });
    }
}

impl HookHandler for CmpCallTable {
    fn call(data: &mut Self, cpu: &mut Cpu, _addr: u64) {
        // Read the first two parameters of the function according to the current calling
        // convention.
        let ptr0 = match cpu.read_ptr_arg(0) {
            Ok(x) => x,
            Err(_) => return,
        };
        let ptr1 = match cpu.read_ptr_arg(1) {
            Ok(x) => x,
            Err(_) => return,
        };

        let index = cpu.args[0] as usize;
        let slot = &mut data.entries[index];

        // Ignore pointers near zero (these are likely to be integers).
        // Note: in most cases memory at zero should not be mapped, but this handles the rare case
        // that it is (e.g., embedded platforms).
        if (ptr0 as i64).abs_diff(0) < 0xff || (ptr1 as i64).abs_diff(0) < 0xff {
            slot.has_invalid = true;
            return;
        }

        // Treat the two parameters as pointers and read the first 32 bytes. If they were not
        // pointers then we expect the read to fail and we will return without updating the
        // compare map.
        let a = match try_read_mem::<64>(cpu, ptr0) {
            Some(x) => x,
            None => {
                slot.has_invalid = true;
                return;
            }
        };
        let b = match try_read_mem::<64>(cpu, ptr1) {
            Some(x) => x,
            None => {
                slot.has_invalid = true;
                return;
            }
        };

        if a != b {
            slot.values.push((a, b));

            // Check whether the arguments were indirect pointers.
            if data.check_indirect_pointers {
                if let Some(a) = try_read_mem::<64>(cpu, cpu.arch.bytes_to_pointer(a)) {
                    if let Some(b) = try_read_mem::<64>(cpu, cpu.arch.bytes_to_pointer(b)) {
                        if a != b {
                            slot.values.push((a, b));
                            slot.is_indirect |= true;
                        }
                    }
                }
            }
        }
    }
}

#[derive(Copy, Clone)]
pub struct CmpLog2Ref {
    /// The hook responsible for logging instruction-level comparisons.
    inst: pcode::HookId,
    /// The hook responsible for logging call-level comparisons.
    call: pcode::HookId,
    /// The varnode that controls whether the cmplog hooks should be invoked or not.
    enabled: pcode::VarNode,
}

impl CmpLog2Ref {
    pub fn set_enabled(&self, cpu: &mut Cpu, enable: bool) {
        cpu.write_var(self.enabled, if enable { 1_u8 } else { 0_u8 });
    }

    pub fn get_inst_log<'a>(&self, cpu: &'a mut Cpu) -> &'a mut [CmpInstData] {
        &mut cpu.get_hook_mut(self.inst).data_mut::<CmpInstTable>().unwrap().entries
    }

    pub fn get_call_log<'a>(&self, cpu: &'a mut Cpu) -> &'a mut [CmpCallData] {
        &mut cpu.get_hook_mut(self.call).data_mut::<CmpCallTable>().unwrap().entries
    }

    pub fn clear_data(&self, cpu: &mut Cpu) {
        cpu.get_hook_mut(self.inst).data_mut::<CmpInstTable>().unwrap().clear();
        cpu.get_hook_mut(self.call).data_mut::<CmpCallTable>().unwrap().clear();
    }
}

pub struct CmpLog2<F> {
    hooks: CmpLog2Ref,
    cmp_finder: CmpFinder,
    equal_only: bool,
    enable_cmplog_return: bool,
    inst_mapping: HashMap<u64, (CmpOp, u64)>,
    call_mapping: HashMap<u64, u64>,
    filter: F,
}

impl<F> CmpLog2<F>
where
    F: FnMut(&Block) -> bool + 'static,
{
    fn register(
        vm: &mut Vm,
        filter: F,
        enable_cmplog_return: bool,
        check_indirect_pointers: bool,
    ) -> CmpLog2Ref {
        let enabled_var = vm.cpu.arch.sleigh.add_custom_reg("cmplog2.enabled", 1)
            .expect("failed to create `cmplog2.enabled` VarNode, CmpLog2 instrumentation might already be enabled");

        let hooks = CmpLog2Ref {
            inst: vm.cpu.add_hook(CmpInstTable::default()),
            call: vm.cpu.add_hook(CmpCallTable::new(check_indirect_pointers)),
            enabled: enabled_var,
        };
        let tracer = Self {
            hooks,
            cmp_finder: CmpFinder::with_arch(&vm.cpu.arch),
            equal_only: false,
            enable_cmplog_return,
            inst_mapping: HashMap::new(),
            call_mapping: HashMap::new(),
            filter,
        };
        vm.add_injector(tracer);
        hooks
    }

    /// Attempts to instrument any comparisons that occur in `block`.
    ///
    /// Returns the list of addresses that were instrumented.
    fn instrument_cmp(&mut self, cpu: &mut Cpu, block: &mut Block) -> Vec<u64> {
        let cmps = self.cmp_finder.find_cmp(block);
        if cmps.is_empty() {
            return vec![];
        }

        let mut tmp_block = pcode::Block::new();
        tmp_block.next_tmp = block.pcode.next_tmp;

        let mut inject_iter = cmps.iter().peekable();

        let mut instrumented = vec![];
        let mut pc = 0;
        for (i, stmt) in block.pcode.instructions.iter().enumerate() {
            if let pcode::Op::InstructionMarker = stmt.op {
                pc = stmt.inputs.first().as_u64();
            }
            tmp_block.push(*stmt);

            while let Some(op) = inject_iter.next_if(|entry| entry.offset <= i) {
                if self.equal_only && !(op.kind == CmpAttr::IS_EQUAL || op.kind.is_empty()) {
                    continue;
                }

                // Create a new entry for this slot if one doesn't already exist.
                let id = match self.inst_mapping.entry(pc) {
                    std::collections::hash_map::Entry::Occupied(entry) => {
                        if entry.get().0 != *op {
                            tracing::debug!(
                                "multiple comparison operations found at: {pc:#x}, skipping: {}",
                                op.display(&cpu.arch.sleigh)
                            );
                            continue;
                        }
                        entry.get().1
                    }
                    std::collections::hash_map::Entry::Vacant(slot) => {
                        let hook =
                            cpu.get_hook_mut(self.hooks.inst).data_mut::<CmpInstTable>().unwrap();
                        let id = hook.entries.len() as u64;
                        hook.entries.push(CmpInstData { addr: pc, op: *op, values: vec![] });
                        slot.insert((*op, id));
                        id
                    }
                };

                instrumented.push(pc);
                // Inject the call to the hook.
                tmp_block.push((pcode::Op::Arg(0), id));
                tmp_block.push((pcode::Op::HookIf(self.hooks.inst), self.hooks.enabled));
            }
        }

        block.pcode = tmp_block;
        instrumented
    }

    fn instrument_call(&mut self, cpu: &mut Cpu, block: &mut Block) -> Option<u64> {
        if !self.enable_cmplog_return {
            return None;
        }

        let caller = block.instructions().last().map_or(0, |(addr, _)| addr);
        let id = *self.call_mapping.entry(caller).or_insert_with(|| {
            let hook = cpu.get_hook_mut(self.hooks.call).data_mut::<CmpCallTable>().unwrap();
            let id = hook.entries.len() as u64;
            hook.entries.push(CmpCallData::new(caller));
            id
        });

        block.pcode.push((pcode::Op::Arg(0), id));

        // @fixme: at some point we want to avoid flushing active registers before running hooks
        //         so we want to ensure that the state needed to handle the instrumentation is
        //         flushed before we run the hook.
        block.pcode.push((pcode::Op::HookIf(self.hooks.call), self.hooks.enabled));

        Some(caller)
    }
}

impl<F: FnMut(&Block) -> bool + 'static> CodeInjector for CmpLog2<F> {
    fn inject(&mut self, cpu: &mut Cpu, group: &BlockGroup, code: &mut BlockTable) {
        for block_id in group.range() {
            let block = &mut code.blocks[block_id];
            if !(self.filter)(block) {
                continue;
            }

            let cmps = self.instrument_cmp(cpu, block);
            let mut modified = !cmps.is_empty();

            if matches!(block.exit, BlockExit::Call { .. }) {
                if let Some(caller) = self.instrument_call(cpu, block) {
                    tracing::debug!(
                        "instrumenting call at {caller:#x}: {}",
                        code.disasm.get(&caller).map_or("", String::as_str)
                    );
                    modified |= true;
                }
            }

            for addr in cmps {
                tracing::debug!(
                    "instrumenting comparison at {addr:#x}: {}",
                    code.disasm.get(&addr).map_or("", String::as_str)
                );
            }

            if modified {
                code.modified.insert(block_id);
            }
        }
    }
}
