//! A software address translation cache that acts similar to a translation lookaside buffer (TLB)

use std::ptr::NonNull;

use crate::{
    physical::{PageData, PageRef, OFFSET_BITS, PAGE_MASK, PAGE_SIZE},
    MemError, MemResult,
};

/// The number of bits required to represent any address.
pub const ADDRESS_BITS: usize = 64;

/// The number of bits required use for indexing into the TLB. The more bits, the more storage is
/// required but the fewer number of potential collections.
pub const TLB_INDEX_BITS: usize = 10;
pub const TLB_ENTRIES: usize = 1 << TLB_INDEX_BITS;

pub const TLB_TAG_BITS: usize = ADDRESS_BITS - (OFFSET_BITS + TLB_INDEX_BITS);

/// A direct-mapped cache for keeping track of known translation addresses (TLB). Addresses for
/// reading/writing are translated separately to allow efficient tracking of modified pages.
#[repr(C)]
pub struct TranslationCache {
    pub read: [TLBEntry; TLB_ENTRIES],
    pub write: [TLBEntry; TLB_ENTRIES],
}

impl Default for TranslationCache {
    fn default() -> Self {
        Self { read: [TLBEntry::default(); TLB_ENTRIES], write: [TLBEntry::default(); TLB_ENTRIES] }
    }
}

impl std::fmt::Debug for TranslationCache {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        writeln!(f, "read:")?;
        for (i, entry) in self.read.iter().enumerate() {
            fmt_tlb_entry(i, entry, f)?;
        }

        writeln!(f, "write:")?;
        for (i, entry) in self.write.iter().enumerate() {
            fmt_tlb_entry(i, entry, f)?;
        }

        Ok(())
    }
}

fn fmt_tlb_entry(
    index: usize,
    entry: &TLBEntry,
    f: &mut std::fmt::Formatter,
) -> Result<(), std::fmt::Error> {
    match entry.tag == u64::MAX {
        true => write!(f, "\ttag=<INVALID_TAG>, ")?,
        false => write!(f, "\ttag={:#013x}, ", entry.tag & ((1 << TLB_TAG_BITS) - 1))?,
    }
    match entry.get_page(0) {
        Some(page) => writeln!(f, "index={index:#05x}, page={:p}", page.ptr),
        _ => writeln!(f, "index={index:#05x}, page=null"),
    }
}

impl TranslationCache {
    pub fn new() -> Self {
        Self::default()
    }

    /// Extracts the offset within the translation cache to lookup the address at.
    #[inline(always)]
    pub fn index(addr: u64) -> usize {
        ((addr >> OFFSET_BITS) & ((1 << TLB_INDEX_BITS) - 1)).try_into().unwrap()
    }

    pub fn clear(&mut self) {
        tracing::trace!("Clearing TLB");
        self.read.fill(TLBEntry::default());
        self.write.fill(TLBEntry::default());
    }

    pub fn clear_write(&mut self) {
        self.write.fill(TLBEntry::default());
    }

    #[inline]
    pub fn remove(&mut self, addr: u64) {
        self.remove_read(addr);
        self.remove_write(addr);
    }

    #[inline]
    pub fn remove_read(&mut self, addr: u64) {
        self.read[Self::index(addr)].clear(addr);
    }

    #[inline]
    pub fn remove_write(&mut self, addr: u64) {
        self.write[Self::index(addr)].clear(addr);
    }

    pub fn remove_range(&mut self, start: u64, len: u64) {
        if len == 0 {
            return;
        }
        let end =
            start.checked_add(len - 1).expect("Overflowed ending address in TLB remove range");
        tracing::trace!("Clearing {start:#x} to {end:#x} in TLB",);

        // Check if the range we are removing covers a large enough address space that it will clear
        // the entire TLB.
        //
        // If that is the case, perform a single optimized clear of the entire TLB (this avoids
        // performance issues where we end up iterating over the entire TLB address space
        // multiple times for extremely large address space changes).
        if (len >> OFFSET_BITS) > TLB_ENTRIES as u64 {
            self.clear();
            return;
        }

        for addr in (start & !(PAGE_SIZE - 1) as u64..=end).step_by(PAGE_SIZE) {
            self.remove(addr);
        }
    }

    #[inline]
    pub fn insert_read(&mut self, addr: u64, page: PageRef) {
        self.read[Self::index(addr)].set(addr, page);
    }

    #[inline]
    pub fn insert_write(&mut self, addr: u64, page: PageRef) {
        self.write[Self::index(addr)].set(addr, page);
    }

    #[inline]
    pub fn translate_read(&self, addr: u64) -> Option<PageRef> {
        self.read[Self::index(addr)].get_page(addr)
    }

    #[inline]
    pub fn translate_write(&self, addr: u64) -> Option<PageRef> {
        self.write[Self::index(addr)].get_page(addr)
    }

    /// Attempt to read from the virtual address `addr` with `perm` using a pre-translated address.
    ///
    /// # Safety
    ///
    /// The underlying memory referenced by the translated address must be valid.
    #[inline]
    pub unsafe fn read<const N: usize>(&self, addr: u64, perm: u8) -> MemResult<[u8; N]> {
        match self.translate_read(addr) {
            Some(page) => page.read(addr, perm),
            None => Err(MemError::Unmapped),
        }
    }

    /// Attempt to write `value` to the virtual address `addr` with `perm` using a pre-translated
    /// address.
    ///
    /// # Safety
    ///
    /// The underlying memory referenced by the translated address must be valid.
    #[inline]
    pub unsafe fn write<const N: usize>(
        &mut self,
        addr: u64,
        value: [u8; N],
        perm: u8,
    ) -> MemResult<()> {
        match self.translate_write(addr) {
            Some(mut page) => page.write(addr, value, perm),
            None => Err(MemError::Unmapped),
        }
    }
}

#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct TLBEntry {
    tag: u64,
    guest_to_host_offset: u64,
}

impl Default for TLBEntry {
    fn default() -> Self {
        Self { tag: u64::MAX, guest_to_host_offset: 0 }
    }
}

impl TLBEntry {
    pub const fn tag_mask() -> u64 {
        ((1_u64 << TLB_TAG_BITS) - 1) << (OFFSET_BITS + TLB_INDEX_BITS)
    }

    #[inline(always)]
    pub fn tag(addr: u64) -> u64 {
        addr & Self::tag_mask()
    }

    #[inline(always)]
    fn clear(&mut self, addr: u64) {
        if Self::tag(addr) == self.tag {
            self.tag = u64::MAX;
            self.guest_to_host_offset = 0;
        }
    }

    #[inline(always)]
    fn set(&mut self, addr: u64, page: PageRef) {
        self.tag = Self::tag(addr);
        let base = addr & !PAGE_MASK;
        self.guest_to_host_offset = (page.ptr.as_ptr() as u64).wrapping_sub(base);
    }

    /// Get the page data associated the address at this TLB entry, returning `None` if the entry is
    /// invalid or matches a different page.
    #[inline(always)]
    fn get_page(&self, addr: u64) -> Option<PageRef> {
        if Self::tag(addr) == self.tag {
            let base = addr & !PAGE_MASK;
            let page = PageRef::new(NonNull::new(
                base.wrapping_add(self.guest_to_host_offset) as *mut PageData
            )?);
            return Some(page);
        }
        None
    }
}

#[allow(dead_code)]
fn debug_tlb_lookup(addr: u64) {
    let tag = TLBEntry::tag(addr);
    let index = TranslationCache::index(addr);
    let offset = addr & PAGE_MASK;
    eprintln!("tag={tag:#0x}, index={index:#0x}, offset={offset:#0x}");
}
