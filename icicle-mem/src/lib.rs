pub mod perm;
pub mod physical;
pub mod tlb;

mod mmu;
pub mod range_map;

#[cfg(test)]
mod tests;

use std::any::Any;

use crate::range_map::RangeMap;

/// The value used to fill uninitalized memory
pub const UNINIT_VALUE: u8 = 0xaa;

pub use crate::{
    mmu::{Mmu, ReadAfterHook, ReadHook, WriteHook},
    perm::{MemError, MemResult},
};

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Addr {
    /// The virtual address of the instruction, used for determining the next instruction and
    /// setting the instruction pointer.
    pub virt: u64,

    /// The physical address of the instruction, used for managing the instruction cache.
    pub phys: physical::PhysicalAddr,
}

impl std::fmt::Display for Addr {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "0x{:016x} ({})", self.virt, self.phys)
    }
}

pub trait Memory {
    fn read<const N: usize>(&mut self, addr: u64, perm: u8) -> MemResult<[u8; N]>;
    fn write<const N: usize>(&mut self, addr: u64, value: [u8; N], perm: u8) -> MemResult<()>;
}

pub trait Resettable {
    fn new() -> Self;
    fn reset(&mut self);
}

#[derive(Debug, Copy, Clone, PartialEq, Eq)]
pub struct PhysicalMapping {
    /// The starting address to prevent two distinct virtual mappings to the same physical address
    /// from being merged.
    // @todo: consider specializing the RangeMap data structure to avoid the need for this field.
    pub addr: u64,

    /// The physical index of this page associated with the mapping.
    pub index: physical::Index,
}

#[derive(Clone, PartialEq, Eq)]
pub enum MemoryMapping {
    /// Represents a region of memory backed by a physical page.
    Physical(PhysicalMapping),

    /// Represents a region of memory where all data is stored inline.
    Unallocated(UnallocatedMemory),

    /// Represents a region of memory handled externally.
    Io(usize),
}

impl std::fmt::Debug for MemoryMapping {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Physical(inner) => write!(f, "{:?}", inner.index),
            Self::Unallocated(inner) => write!(f, "{}", inner),
            Self::Io(i) => write!(f, "io[{}]", i),
        }
    }
}

/// Used for regions of memory that need custom behaviour for every read/write.
pub trait IoMemory {
    fn read(&mut self, addr: u64, buf: &mut [u8]) -> MemResult<()>;
    fn write(&mut self, addr: u64, value: &[u8]) -> MemResult<()>;

    fn snapshot(&mut self) -> Box<dyn Any> {
        Box::new(())
    }

    fn restore(&mut self, snapshot: &Box<dyn Any>) {
        let _ = snapshot;
    }
}

pub trait IoMemoryAny: IoMemory {
    fn as_any(&self) -> &dyn Any;
    fn as_mut_any(&mut self) -> &mut dyn Any;
}

impl<T: IoMemory + 'static> IoMemoryAny for T {
    fn as_any(&self) -> &dyn Any {
        self
    }

    fn as_mut_any(&mut self) -> &mut dyn Any {
        self
    }
}

pub struct NullMemory;

impl IoMemory for NullMemory {
    fn read(&mut self, _addr: u64, _buf: &mut [u8]) -> MemResult<()> {
        Ok(())
    }

    fn write(&mut self, _addr: u64, _value: &[u8]) -> MemResult<()> {
        Ok(())
    }
}

#[derive(Debug, Copy, Clone)]
pub struct IoHandler(usize);

impl From<IoHandler> for MemoryMapping {
    fn from(value: IoHandler) -> Self {
        MemoryMapping::Io(value.0)
    }
}

pub type Mapping = UnallocatedMemory;

/// Represents a region of memory that has no physical backing, and does not need to be page
/// aligned.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct UnallocatedMemory {
    pub perm: u8,
    pub value: u8,
}

impl UnallocatedMemory {
    /// Gets whether this region of memory could be replaced with the zero page for reads.
    pub fn is_zero(self) -> bool {
        self.value == 0x00 && perm::check(self.perm | perm::MAP, perm::READ | perm::INIT).is_ok()
    }
}

impl std::fmt::Display for UnallocatedMemory {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "Unallocated {{ perm: {} ({:#0b}), value: {:#0x} }}",
            perm::display(self.perm),
            self.perm,
            self.value
        )
    }
}

impl From<UnallocatedMemory> for MemoryMapping {
    fn from(v: UnallocatedMemory) -> Self {
        Self::Unallocated(v)
    }
}

pub type Snapshot = std::sync::Arc<SnapshotData>;

pub type VirtualMemoryMap = RangeMap<MemoryMapping>;

pub struct SnapshotData {
    /// The virtual address mapping of the snapshot.
    pub mapping: VirtualMemoryMap,

    /// A snapshot of the physical memory state.
    pub physical: physical::PhysicalMemory,

    /// The parent of this snapshot.
    pub parent: Option<Snapshot>,

    /// The snapshot state of all peripherals.
    // @todo: need to handle dynamic adding of I/O handlers.
    pub io: Vec<Box<dyn Any>>,
}

impl SnapshotData {
    pub fn new() -> Self {
        Self {
            mapping: VirtualMemoryMap::new(),
            physical: physical::PhysicalMemory::new(0),
            parent: None,
            io: vec![],
        }
    }
}

impl Default for SnapshotData {
    fn default() -> Self {
        Self::new()
    }
}

#[derive(Copy, Clone, Default, Debug)]
pub struct AllocLayout {
    /// The preferred address of the allocation
    pub addr: Option<u64>,

    /// The size of the allocation
    pub size: u64,

    /// The required alignment of the allocation
    pub align: u64,
}

impl AllocLayout {
    pub const fn from_size_align(size: u64, align: u64) -> Self {
        Self { addr: None, size, align }
    }
}

pub fn align_up(value: u64, alignment: u64) -> u64 {
    assert_eq!(alignment.count_ones(), 1, "Alignment must be a non-zero power of 2");
    let mask = alignment.wrapping_sub(1);
    value + ((alignment - (value & mask)) & mask)
}

pub fn align_down(value: u64, alignment: u64) -> u64 {
    assert_eq!(alignment.count_ones(), 1, "Alignment must be a non-zero power of 2");
    let mask = !alignment.wrapping_sub(1);
    value & mask
}
