//! CmpLog instrumentation (inspired by the implementation from qemuafl)

use std::{cell::UnsafeCell, collections::HashMap};

use icicle_vm::{
    cpu::{
        lifter::{Block, BlockExit},
        BlockGroup, BlockTable, Cpu, StoreRef,
    },
    CodeInjector, Vm,
};

use crate::{
    fnv_hash,
    instrumentation::cmp_finder::{CmpAttr, CmpFinder, CmpOp},
    try_read_mem,
};

#[derive(Copy, Clone, Debug)]
pub struct CmpLogOp {
    pub kind: CmpAttr,
    pub size: usize,
    pub v0: u128,
    pub v1: u128,
}

#[derive(Copy, Clone, Debug)]
pub struct CmpLogRtn {
    pub v0: [u8; 31],
    pub v0_len: u8,
    pub v1: [u8; 31],
    pub v1_len: u8,
}

impl From<CmpCallOperands> for CmpLogRtn {
    fn from(log: CmpCallOperands) -> Self {
        Self { v0: log.v0, v0_len: log.v0_len, v1: log.v1, v1_len: log.v1_len }
    }
}

#[derive(Copy, Clone, Debug)]
pub enum CmpLogEntry {
    Op(CmpLogOp),
    Rtn(CmpLogRtn),
}

const CMPLOG_TYPE_INS: u8 = 1;
const CMPLOG_TYPE_RTN: u8 = 2;

pub const CMP_MAP_W: usize = 65536;
pub const CMP_MAP_H: usize = 32;

pub const CMP_MAP_RTN_H: usize = CMP_MAP_H / 4;

macro_rules! bits {
    ($dst:expr, [$range:expr] = $value:expr) => {{
        let mask = ((1 << $range.len()) - 1) as u64;
        $dst = ($dst & !(mask << $range.start)) | (($value as u64 & mask) << $range.start);
    }};

    ($dst:expr, [$range:expr]) => {{
        let mask = ((1 << $range.len()) - 1) as u64;
        ($dst >> $range.start) & mask
    }};
}

#[derive(Copy, Clone, Default)]
#[repr(transparent)]
pub struct CmpHeader(u64);

macro_rules! bit_field {
    ($struct:ident, $getter:ident, $setter:ident, $ty:ty, [$range:expr]) => {
        impl $struct {
            #[allow(unused)]
            pub fn $getter(&self) -> $ty {
                bits!(self.0, [$range]) as $ty
            }

            #[allow(unused)]
            pub fn $setter(&mut self, value: $ty) {
                bits!(self.0, [$range] = value);
            }
        }
    };
}

bit_field!(CmpHeader, hits, set_hits, u32, [0..24]);
bit_field!(CmpHeader, id, set_id, u32, [24..48]);
bit_field!(CmpHeader, shape, set_shape, u8, [48..53]);
bit_field!(CmpHeader, ty, set_ty, u8, [53..55]);
bit_field!(CmpHeader, attr, set_attr, u8, [55..59]);
bit_field!(CmpHeader, overflow, set_overflow, u8, [60..61]);

impl CmpHeader {
    fn size(&self) -> usize {
        self.shape() as usize + 1
    }
}

#[derive(Copy, Clone, Default, PartialEq, Eq)]
#[repr(C)]
struct CmpOperands {
    v0: u64,
    v1: u64,
    v0_128: u64,
    v1_128: u64,
}

impl CmpOperands {
    fn v0(&self) -> u128 {
        self.v0 as u128 | ((self.v0_128 as u128) << 64)
    }

    fn set_v0(&mut self, value: u128) {
        self.v0 = value as u64;
        self.v0_128 = (value >> 64) as u64;
    }

    fn v1(&self) -> u128 {
        self.v1 as u128 | ((self.v1_128 as u128) << 64)
    }

    fn set_v1(&mut self, value: u128) {
        self.v1 = value as u64;
        self.v1_128 = (value >> 64) as u64;
    }
}

#[derive(Copy, Clone, Default, PartialEq, Eq, bytemuck::Pod, bytemuck::Zeroable)]
#[repr(C)]
struct CmpCallOperands {
    v0: [u8; 31],
    v0_len: u8,
    v1: [u8; 31],
    v1_len: u8,
}

#[derive(Copy, Clone)]
#[repr(C)]
pub struct CmpMap {
    pub headers: [CmpHeader; CMP_MAP_W],
    pub log: [CmpLogData; CMP_MAP_W],
}

impl CmpMap {
    pub fn save(&self, path: &std::path::Path) -> std::io::Result<()> {
        use std::io::Write;

        let mut out = std::io::BufWriter::new(std::fs::File::create(path)?);

        let entries = self.entries_all();
        for ((index, hit), value) in entries {
            write!(out, "({:#06x}, {:#04x}) = ", index, hit)?;
            match value {
                CmpLogEntry::Op(inner) => writeln!(out, "{:0x?}", inner)?,
                CmpLogEntry::Rtn(inner) => writeln!(
                    out,
                    "v0: {:?}, v1: {:?}",
                    inner.v0.escape_ascii(),
                    inner.v1.escape_ascii()
                )?,
            }
        }

        Ok(())
    }
}

unsafe impl bytemuck::Pod for CmpMap {}
unsafe impl bytemuck::Zeroable for CmpMap {}

impl Default for CmpMap {
    fn default() -> Self {
        Self::new()
    }
}

impl CmpMap {
    #[inline]
    pub fn new() -> Self {
        Self {
            headers: [CmpHeader::default(); CMP_MAP_W],
            log: [CmpLogData { compares: [CmpOperands::default(); CMP_MAP_H] }; CMP_MAP_W],
        }
    }

    /// Retrieve a single CmpLog entry given a index and a hit count.
    pub fn get(&self, index: usize, hit: u32) -> Option<CmpLogEntry> {
        let header = self.headers[index];

        if header.hits() == 0 {
            return None;
        }

        let size = header.size();
        let kind = CmpAttr::from_u8(header.attr());

        match header.ty() {
            CMPLOG_TYPE_INS => {
                let log = &self.log[index].cmp_operands(hit);
                Some(CmpLogEntry::Op(CmpLogOp { size, kind, v0: log.v0(), v1: log.v1() }))
            }
            CMPLOG_TYPE_RTN => {
                let log = &self.log[index].rtn_operands(hit);
                Some(CmpLogEntry::Rtn(CmpLogRtn {
                    v0: log.v0,
                    v0_len: log.v0_len,
                    v1: log.v1,
                    v1_len: log.v1_len,
                }))
            }
            _ => None,
        }
    }

    pub fn entries_all(&self) -> Vec<((usize, usize), CmpLogEntry)> {
        let mut entries = vec![];

        for (index, header) in
            self.headers.iter().enumerate().filter(|(_, header)| header.hits() > 0)
        {
            let kind = CmpAttr::from_u8(header.attr());
            let size = header.size();

            if header.ty() == CMPLOG_TYPE_INS {
                let n_entries = header.hits().min(CMP_MAP_H as u32);
                entries.extend((0..n_entries).map(move |hit| {
                    let log = &self.log[index].cmp_operands(hit);
                    let entry =
                        CmpLogEntry::Op(CmpLogOp { size, kind, v0: log.v0(), v1: log.v1() });
                    ((index, hit as usize), entry)
                }));
            }
            else if header.ty() == CMPLOG_TYPE_RTN {
                let n_entries = header.hits().min(CMP_MAP_RTN_H as u32);
                entries.extend((0..n_entries).map(move |hit| {
                    let log = &self.log[index].rtn_operands(hit);
                    let entry = CmpLogEntry::Rtn((**log).into());
                    ((index, hit as usize), entry)
                }));
            }
        }
        entries
    }

    /// Get an iterator over all active CmpLogOp entries in the map.
    // @todo: add support for cmplog_rtn
    pub fn entries(&self) -> impl Iterator<Item = ((usize, usize), CmpLogOp)> + '_ {
        self.headers
            .iter()
            .enumerate()
            .filter(|(_, header)| header.hits() > 0 && header.ty() == CMPLOG_TYPE_INS)
            .flat_map(move |(index, header)| {
                let kind = CmpAttr::from_u8(header.attr());
                let size = header.size();
                let n_entries = header.hits().min(CMP_MAP_H as u32);

                (0..n_entries).map(move |hit| {
                    let log = &self.log[index].cmp_operands(hit);
                    ((index, hit as usize), CmpLogOp { size, kind, v0: log.v0(), v1: log.v1() })
                })
            })
    }

    pub fn to_map(&self) -> HashMap<(usize, usize), CmpLogOp> {
        self.entries().collect()
    }

    /// Record that `arg1` and `arg1` were used as arguments for a compare of kind `attr`.
    fn ins_hook(&mut self, meta: Metadata, arg1: u128, arg2: u128) {
        let header = &mut self.headers[meta.index as usize];
        let hit = header.hits();

        header.set_ty(CMPLOG_TYPE_INS);
        header.set_attr(meta.kind.bits());
        header.set_hits(hit + 1);
        if hit >= ((1 << 24) - 1) {
            header.set_overflow(1);
        }

        let size = meta.size as usize;

        // Due to collisions, multiple instrumentation locations may have the same index. Multiple
        // results are recorded in different locations (indexed by the current hit count), however
        // the shape metadata for operands is shared. Here we just take the largest (smaller
        // operands will be zero extended).
        if size - 1 > header.shape() as usize {
            header.set_shape((size - 1) as u8);
        }

        let entry = self.log[meta.index as usize].cmp_operands_mut(hit);
        entry.set_v0(arg1);
        entry.set_v1(arg2);
    }

    /// Record that `arg1` and `arg1` were used as arguments for a call
    fn rtn_hook(&mut self, index: u32, arg1: [u8; 31], arg2: [u8; 31]) {
        let header = &mut self.headers[index as usize];
        let hit = header.hits();

        header.set_ty(CMPLOG_TYPE_RTN);
        header.set_hits(hit + 1);
        if hit >= ((1 << 24) - 1) {
            header.set_overflow(1);
        }
        header.set_shape(30);

        let entry = self.log[index as usize].rtn_operands_mut(hit);
        entry.v0 = arg1;
        entry.v1 = arg2;
    }
}

#[derive(Copy, Clone)]
#[repr(C)]
pub union CmpLogData {
    compares: [CmpOperands; CMP_MAP_H],
    functions: [CmpCallOperands; CMP_MAP_RTN_H],
}

impl CmpLogData {
    fn cmp_operands(&self, hit: u32) -> &CmpOperands {
        unsafe { &self.compares[hit as usize & (CMP_MAP_H - 1)] }
    }

    fn cmp_operands_mut(&mut self, hit: u32) -> &mut CmpOperands {
        unsafe { &mut self.compares[hit as usize & (CMP_MAP_H - 1)] }
    }

    fn rtn_operands(&self, hit: u32) -> &CmpCallOperands {
        unsafe { &self.functions[hit as usize & (CMP_MAP_RTN_H - 1)] }
    }

    fn rtn_operands_mut(&mut self, hit: u32) -> &mut CmpCallOperands {
        unsafe { &mut self.functions[hit as usize & (CMP_MAP_RTN_H - 1)] }
    }
}

#[derive(Copy, Clone, Debug)]
struct Metadata {
    index: u32,
    kind: CmpAttr,
    size: u8,
}

impl Metadata {
    fn encode(self) -> u64 {
        self.index as u64 | ((self.kind.bits() as u64) << 32) | ((self.size as u64) << 40)
    }

    fn decode(value: u64) -> Self {
        Self {
            index: (value & 0xffff_ffff) as u32,
            kind: CmpAttr::from_u8(((value >> 32) & 0xff) as u8),
            size: (value >> 40) as u8,
        }
    }
}

pub struct CmpLogBuilder<F> {
    filter: F,
    enable_rtn: bool,
}

impl CmpLogBuilder<fn(&Block) -> bool> {
    pub fn new() -> Self {
        Self { filter: |_| true, enable_rtn: false }
    }
}

impl<F> CmpLogBuilder<F> {
    pub fn filter<NF>(self, filter: NF) -> CmpLogBuilder<NF>
    where
        NF: for<'r> Fn(&Block) -> bool + 'static,
    {
        CmpLogBuilder { filter, enable_rtn: self.enable_rtn }
    }

    pub fn instrument_calls(mut self, value: bool) -> Self {
        self.enable_rtn = value;
        self
    }

    pub fn finish(self, vm: &mut Vm, map: &'static UnsafeCell<CmpMap>) -> StoreRef
    where
        F: for<'r> Fn(&Block) -> bool + 'static,
    {
        CmpLog::register(vm, self.filter, map, self.enable_rtn)
    }
}

pub struct CmpLog<F> {
    pub cmp_map: StoreRef,
    ins_hook_id: u16,
    rtn_hook_id: u16,
    cmp_finder: CmpFinder,
    equal_only: bool,
    enable_cmplog_return: bool,
    filter: F,
}

impl<F> CmpLog<F>
where
    F: FnMut(&Block) -> bool + 'static,
{
    fn register(
        vm: &mut Vm,
        filter: F,
        map: &'static UnsafeCell<CmpMap>,
        enable_cmplog_return: bool,
    ) -> StoreRef {
        let cmp_map = vm.cpu.trace.register_store(Box::new(map));

        // The function that is called to copy comparison functions into the CmpMap.
        let ins_hook = move |cpu: &mut Cpu, _addr: u64| {
            let meta = Metadata::decode(cpu.args[0] as u64);
            let a1 = cpu.args[1];
            let a2 = cpu.args[2];

            let map: &mut &'static UnsafeCell<CmpMap> =
                cpu.trace[cmp_map].as_any().downcast_mut().unwrap();

            unsafe { map.get().as_mut().unwrap() }.ins_hook(meta, a1, a2);
        };

        // The function that is called to copy call parameters into the CmpMap.
        let rtn_hook = move |cpu: &mut Cpu, addr: u64| {
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

            // Treat the two parameters as pointers and read the first 32 bytes. If they were not
            // pointers then we expect the read to fail and we will return without updating the
            // compare map.
            let a = match try_read_mem(cpu, ptr0) {
                Some(x) => x,
                None => return,
            };
            let b = match try_read_mem(cpu, ptr1) {
                Some(x) => x,
                None => return,
            };

            if a == b {
                // Operands are already equal so ignore them from the map.
                return;
            }

            let index = fnv_hash(addr ^ 0x1dd0b3aeef90cd97) & (CMP_MAP_W - 1) as u32;

            let map: &mut &'static UnsafeCell<CmpMap> =
                cpu.trace[cmp_map].as_any().downcast_mut().unwrap();
            unsafe { map.get().as_mut().unwrap() }.rtn_hook(index, a, b);
        };

        let tracer = Self {
            ins_hook_id: vm.cpu.add_hook(Box::new(ins_hook)),
            rtn_hook_id: vm.cpu.add_hook(Box::new(rtn_hook)),
            cmp_map,
            cmp_finder: CmpFinder::with_arch(&vm.cpu.arch),
            equal_only: false,
            enable_cmplog_return,
            filter,
        };
        vm.add_injector(Box::new(tracer));

        cmp_map
    }

    /// Returns whether any modification was made to the block.
    fn instrument_cmp(&mut self, block: &mut Block) -> bool {
        let cmps = self.cmp_finder.find_cmp(block);
        if cmps.is_empty() {
            return false;
        }

        let mut tmp_block = pcode::Block::new();
        tmp_block.next_tmp = block.pcode.next_tmp;

        let mut inject_iter = cmps.iter().peekable();

        let mut pc = 0;
        for (i, stmt) in block.pcode.instructions.iter().enumerate() {
            if let pcode::Op::InstructionMarker = stmt.op {
                pc = stmt.inputs.first().as_u64();
            }
            tmp_block.push(*stmt);

            while let Some(entry) = inject_iter.next_if(|entry| entry.offset <= i) {
                if self.equal_only && !(entry.kind == CmpAttr::IS_EQUAL || entry.kind.is_empty()) {
                    continue;
                }

                copy_cmp_args(entry, pc, &mut tmp_block);
                tmp_block.push(pcode::Op::Hook(self.ins_hook_id));
            }
        }

        block.pcode = tmp_block;
        true
    }

    fn instrument_call(&mut self, block: &mut Block) -> bool {
        if !self.enable_cmplog_return {
            return false;
        }

        // @fixme: at some point we want to avoid flushing active registers before running hooks
        //         so we want to ensure that the state needed to handle the instrumentation is
        //         flushed before we run the hook.
        block.pcode.push(pcode::Op::Hook(self.rtn_hook_id));

        true
    }
}

impl<F: FnMut(&Block) -> bool + 'static> CodeInjector for CmpLog<F> {
    fn inject(&mut self, _cpu: &mut Cpu, group: &BlockGroup, code: &mut BlockTable) {
        let block = &mut code.blocks[group.blocks.0];
        if !(self.filter)(block) {
            return;
        }

        let mut modified = self.instrument_cmp(block);

        if matches!(block.exit, BlockExit::Call { .. }) {
            modified |= self.instrument_call(block);
        }

        if modified {
            code.modified.insert(group.blocks.0);
        }
    }
}

fn copy_cmp_args(op: &CmpOp, pc: u64, block: &mut pcode::Block) {
    let key = fnv_hash((pc << 4) + op.offset as u64);
    let index = key & (CMP_MAP_W - 1) as u32;
    tracing::trace!("{pc:#x} -> {index:#x}");
    let meta = Metadata { index, kind: op.kind, size: op.arg1.size() };

    block.push((pcode::Op::Arg(0), pcode::Inputs::one(meta.encode())));
    block.push((pcode::Op::Arg(1), pcode::Inputs::one(op.arg1)));
    block.push((pcode::Op::Arg(2), pcode::Inputs::one(op.arg2)));
}
