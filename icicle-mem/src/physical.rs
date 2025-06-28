use std::{cell::UnsafeCell, ptr::NonNull, rc::Rc};

use crate::{perm, MemError, MemResult};

/// The number of bits required to represent any offset within a page.
pub const OFFSET_BITS: usize = 12;

/// The number of bytes in a single page
// @todo: for now every physical memory instance has the same page alignment requirements. In the
// future this may not be the case, so limit the use of this constant where possible to ease future
// refactoring (use the `page_size` and `page_aligned` methods on PhysicalMemory instead).
pub const PAGE_SIZE: usize = 1 << OFFSET_BITS;

pub const PAGE_MASK: u64 = (PAGE_SIZE - 1) as u64;

/// For testing it is useful to have a limit on the maximum number of pages that we allow, to catch
/// memory leaks during development (we may want to make this configurable in the future)
///
/// Currently this limit is set so that the maximum corresponds to ~400 MB of host memory.
pub const MAX_PAGES: usize = 50_000;

/// Represents an opaque index into physical memory.
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct Index(u32);

impl std::fmt::Debug for Index {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self.0 {
            0 => f.write_str("ReadOnlyZeroPage"),
            1 => f.write_str("ZeroPage"),
            x => f.debug_tuple("Index").field(&x).finish(),
        }
    }
}

impl Index {
    pub fn is_zero_page(&self) -> bool {
        self.0 == 0 || self.0 == 1
    }
}

/// Represents an address in the guests physical memory.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct PhysicalAddr(u64);

impl std::fmt::Display for PhysicalAddr {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "PhysicalAddr({:#0x})", self.0)
    }
}

pub struct PhysicalMemory {
    /// The maxmum number of pages that can be allocated.
    capacity: usize,
    allocated: Vec<Page>,
    free: Vec<Index>,
}

impl PhysicalMemory {
    const READ_ONLY_ZERO_PERM: u8 = perm::MAP | perm::READ | perm::INIT;

    const READ_WRITE_ZERO_PERM: u8 = perm::MAP | perm::READ | perm::WRITE | perm::INIT;

    pub fn new(capacity: usize) -> Self {
        let zero_page_read_only = Page::zero_page(Self::READ_ONLY_ZERO_PERM, false);
        let zero_page_read_write = Page::zero_page(Self::READ_WRITE_ZERO_PERM, true);
        Self { capacity, allocated: vec![zero_page_read_only, zero_page_read_write], free: vec![] }
    }

    #[inline]
    pub fn allocated_pages(&self) -> usize {
        self.allocated.len() - self.free.len()
    }

    /// Get size (in bytes) of a single page in physical memory.
    #[inline]
    pub fn page_size(&self) -> u64 {
        PAGE_SIZE as u64
    }

    /// Align `addr` to a page boundary for the current physical memory configuration.
    #[inline]
    pub fn page_aligned(&self, addr: u64) -> u64 {
        addr & !(self.page_size() - 1)
    }

    /// Allocate a new page and return its index
    pub fn alloc(&mut self) -> Option<Index> {
        let index = match self.free.pop() {
            Some(index) => index,
            None => {
                if self.allocated.len() >= self.capacity {
                    tracing::warn!("Guest exceeded memory limit {}", self.capacity);
                    return None;
                }
                self.allocated.push(Page::new());
                Index((self.allocated.len() - 1).try_into().unwrap())
            }
        };
        self.allocated[index.0 as usize].clear();
        Some(index)
    }

    pub fn capacity(&self) -> usize {
        self.capacity
    }

    pub fn set_capacity(&mut self, new_capacity: usize) -> bool {
        if self.allocated.len() >= new_capacity {
            tracing::warn!("Failed to reduce capacity below allocated size");
            return false;
        }
        self.capacity = new_capacity;
        true
    }

    #[allow(unused)] // @fixme: This should be called when we unmap pages
    pub fn free(&mut self, index: Index) {
        self.free.push(index);
    }

    #[inline]
    pub fn get_zero_page(&self, perm: u8) -> Option<Index> {
        match perm {
            PhysicalMemory::READ_ONLY_ZERO_PERM => Some(Index(0)),
            PhysicalMemory::READ_WRITE_ZERO_PERM => Some(Index(1)),
            _ => None,
        }
    }

    #[inline]
    pub fn get(&self, index: Index) -> &Page {
        &self.allocated[index.0 as usize]
    }

    #[inline]
    pub fn get_mut(&mut self, index: Index) -> &mut Page {
        &mut self.allocated[index.0 as usize]
    }

    #[inline]
    pub fn address_of(&self, vaddr: u64, index: Index) -> PhysicalAddr {
        let base = (index.0 << OFFSET_BITS) as u64;
        let offset = vaddr & ((1_u64 << OFFSET_BITS) - 1);
        PhysicalAddr(base | offset)
    }

    /// Allocate a copy of a page.
    pub fn clone_page(&mut self, index: Index) -> Option<Index> {
        let new_index = self.alloc()?;
        let (new, existing) = self.get_pair_mut(new_index, index);
        *new.data_mut() = existing.data().clone();
        Some(new_index)
    }

    /// Return mutable references to two distict pages
    pub fn get_pair_mut(&mut self, a: Index, b: Index) -> (&mut Page, &mut Page) {
        let end = self.allocated.len() as u32;
        assert!(a.0 != b.0 && a.0 < end && b.0 <= end);

        // Safety: we have ensured that both indices are inbounds and are distinct.
        unsafe {
            let ptr = self.allocated.as_mut_ptr();
            (ptr.add(a.0 as usize).as_mut().unwrap(), ptr.add(b.0 as usize).as_mut().unwrap())
        }
    }

    pub fn clear(&mut self) {
        // Remove all allocated memory except the zero page.
        self.allocated.truncate(2);
        self.free.clear();
    }

    pub fn snapshot(&self) -> Self {
        Self { capacity: self.capacity, allocated: self.allocated.clone(), free: self.free.clone() }
    }

    pub fn restore(&mut self, snapshot: &Self) {
        self.allocated.clone_from(&snapshot.allocated);
        self.free.clone_from(&snapshot.free);
    }
}

// @todo: make: copy_on_write, modified, and executed bitflags
pub struct Page {
    /// The content of the page.
    data: UnsafeCell<Rc<PageData>>,

    /// Keeps track of whether this page implements 'copy-on-write' semantics. (i.e. if true, then
    /// modifications to this page are should not be visible to other virtual address spaces
    /// referencing the same page).
    pub copy_on_write: bool,

    /// Keeps track of whether this page has been written to.
    pub modified: bool,

    /// Keeps track of whether code within this page has been lifted.
    pub executed: bool,
}

impl Clone for Page {
    fn clone(&self) -> Self {
        Self {
            // Safety: this method invalidates any active `PageRef` used for writing.
            data: Rc::clone(unsafe { self.data.get().as_ref().unwrap() }).into(),
            copy_on_write: self.copy_on_write,
            modified: self.modified,
            executed: self.executed,
        }
    }
}

impl Page {
    fn new() -> Self {
        Self {
            data: UnsafeCell::new(Rc::default()),
            modified: false,
            copy_on_write: false,
            executed: false,
        }
    }

    fn zero_page(perm: u8, copy_on_write: bool) -> Self {
        let mut page = Self::new();
        page.copy_on_write = copy_on_write;

        let data = page.data_mut();
        data.data.fill(0);
        data.perm.fill(perm);

        page
    }

    /// Clear the state of the page, without reallocating.
    pub fn clear(&mut self) {
        self.modified = false;
        self.copy_on_write = false;
        self.executed = false;
    }

    #[inline(always)]
    pub fn data(&self) -> &PageData {
        // Safety: Either we have a unique copy of `self.data` or there are no active mutable
        // references.
        //
        // @todo: check this
        unsafe { self.data.get().as_ref().unwrap() }
    }

    #[inline(always)]
    pub fn data_mut(&mut self) -> &mut PageData {
        Rc::make_mut(self.data.get_mut())
    }

    /// Returns a pointer that can be used for reading/writing.
    ///
    /// # Safety
    ///
    /// The returned pointer is only valid while `data` is valid and unique (e.g., the pointer must
    /// not be used after a call to [Page::clone] or [Drop::drop]).
    #[inline(always)]
    pub unsafe fn write_ptr(&mut self) -> PageRef {
        PageRef::new(self.data_mut().into())
    }

    /// Returns a pointer that should only be used for reading.
    ///
    /// # Safety
    ///
    /// The returned pointer is only valid while `data` is valid (e.g., the pointer must not be used
    /// after a call to [Drop::drop]).
    #[inline(always)]
    pub unsafe fn read_ptr(&mut self) -> PageRef {
        PageRef::new(NonNull::new(Rc::as_ptr(self.data.get_mut()) as *mut _).unwrap())
    }
}

#[derive(Clone)]
#[repr(C)]
pub struct PageData {
    /// The actual data stored in this page.
    pub data: [u8; PAGE_SIZE],

    /// The permissions associated with each byte in the page
    pub perm: [u8; PAGE_SIZE],
}

impl Default for PageData {
    fn default() -> Self {
        Self { data: [0; PAGE_SIZE], perm: [0; PAGE_SIZE] }
    }
}

impl PageData {
    #[allow(unused)]
    pub fn from_bytes(bytes: &[u8]) -> Self {
        assert_eq!(bytes.len(), 2 * PAGE_SIZE);
        let mut data = Self { data: [0; PAGE_SIZE], perm: [0; PAGE_SIZE] };
        data.data.copy_from_slice(&bytes[..PAGE_SIZE]);
        data.perm[..PAGE_SIZE].copy_from_slice(&bytes[PAGE_SIZE..]);
        data
    }

    #[allow(unused)]
    pub fn as_bytes(&self) -> Vec<u8> {
        let mut bytes = Vec::with_capacity(2 * PAGE_SIZE);
        bytes.extend_from_slice(&self.data);
        bytes.extend_from_slice(&self.perm[..PAGE_SIZE]);
        bytes
    }

    /// Retrieves the intersection of all permision bits within a range
    ///
    /// # Safety
    ///
    /// The range `offset .. offset + len` must be entirely in-bounds
    #[inline(always)]
    pub unsafe fn get_perm_unchecked(&self, offset: usize, len: usize) -> u8 {
        let mut check = perm::ALL;
        for i in 0..len {
            check &= *self.perm.as_ptr().add(offset + i);
        }
        check
    }

    /// Add permission bits to a specified range by 'or'ing the new permission value with the
    /// existing value
    #[inline(always)]
    pub fn add_perm(&mut self, offset: usize, len: usize, perm: u8) {
        assert!(offset.checked_add(len).map_or(false, |x| x <= PAGE_SIZE));
        unsafe { self.add_perm_unchecked(offset, len, perm) }
    }

    /// Add permission bits to a specified range by 'or'ing the new permission value with the
    /// existing value.
    ///
    /// # Safety
    ///
    /// The range `offset .. offset + len` must be entirely in-bounds
    #[inline]
    pub unsafe fn add_perm_unchecked(&mut self, offset: usize, len: usize, perm: u8) {
        #[cold]
        #[inline(never)]
        unsafe fn slow(data: &mut PageData, offset: usize, len: usize, perm: u8) {
            for byte in data.perm.get_unchecked_mut(offset..offset + len) {
                *byte |= perm
            }
        }

        // Note: we specialize this for fixed sized values as it appears that the optimiser is
        // unable to do this automatically.
        let perm_ptr = self.perm.as_mut_ptr();
        match len {
            1 => {
                *perm_ptr.add(offset) |= perm;
            }
            2 => {
                let ptr = perm_ptr.add(offset).cast::<u16>();
                let old = ptr.read_unaligned();
                ptr.write_unaligned(old | u16::from_le_bytes([perm; 2]));
            }
            4 => {
                let ptr = perm_ptr.add(offset).cast::<u32>();
                let old = ptr.read_unaligned();
                ptr.write_unaligned(old | u32::from_le_bytes([perm; 4]));
            }
            8 => {
                let ptr = perm_ptr.add(offset).cast::<u64>();
                let old = ptr.read_unaligned();
                ptr.write_unaligned(old | u64::from_le_bytes([perm; 8]));
            }
            _ => slow(self, offset, len, perm),
        }
    }

    /// Computes the offset within the page and the length of the memory region between `start` and
    /// `end`, checking that region is in bounds.
    #[inline(always)]
    pub fn offset_and_len(start: u64, end: u64) -> (usize, usize) {
        let offset = Self::offset(start);
        let len = (end - start) as usize;

        debug_assert!(offset + len <= PAGE_SIZE);
        (offset, len)
    }

    /// Extracts the offset component of an address.
    #[inline(always)]
    pub fn offset(addr: u64) -> usize {
        (addr & ((1 << OFFSET_BITS) - 1)).try_into().unwrap()
    }

    #[inline(always)]
    pub fn read<const N: usize>(&self, addr: u64, perm: u8) -> MemResult<[u8; N]> {
        assert!([1, 2, 4, 8, 16].contains(&N));

        if !is_aligned::<N>(addr) {
            // If `addr` is not aligned the read might cross a page boundary.
            return Err(MemError::Unaligned);
        }

        let mut buf = [0_u8; N];
        let offset = PageData::offset(addr);
        // Safety: `offset..offset + N` is always in-bounds.
        unsafe {
            perm::check_bytes::<N>(
                self.perm.get_unchecked(offset..offset + N).try_into().unwrap(),
                perm | perm::MAP,
            )?;
            buf.copy_from_slice(self.data.get_unchecked(offset..offset + N));
        }
        Ok(buf)
    }

    #[inline(always)]
    pub fn write<const N: usize>(&mut self, addr: u64, value: [u8; N], perm: u8) -> MemResult<()> {
        assert!([1, 2, 4, 8, 16].contains(&N));

        if !is_aligned::<N>(addr) {
            // If `addr` is not aligned the write might cross a page boundary.
            return Err(MemError::Unaligned);
        }

        let offset = PageData::offset(addr);
        // Safety: `offset..offset + N` is always in-bounds.
        unsafe {
            perm::check_bytes::<N>(
                self.perm.get_unchecked(offset..offset + N).try_into().unwrap(),
                perm | perm::MAP,
            )?;
            self.add_perm_unchecked(offset, N, perm::INIT);
            self.data.get_unchecked_mut(offset..offset + N).copy_from_slice(&value);
        }

        Ok(())
    }
}

#[repr(transparent)]
#[derive(Copy, Clone, Debug)]
pub struct PageRef {
    pub ptr: NonNull<PageData>,
}

impl PageRef {
    /// Creates a new page structure from a pointer to memory
    ///
    /// # Safety
    ///
    /// Methods on this struct can only be used while `ptr` is valid.
    pub const fn new(ptr: NonNull<PageData>) -> Self {
        Self { ptr }
    }

    /// # Safety
    ///
    /// The underlying pointer must be valid.
    #[inline]
    pub unsafe fn read<const N: usize>(&self, addr: u64, perm: u8) -> MemResult<[u8; N]> {
        self.ptr.as_ref().read::<N>(addr, perm)
    }

    /// # Safety
    ///
    /// The underlying pointer must be valid.
    #[inline]
    pub unsafe fn write<const N: usize>(
        &mut self,
        addr: u64,
        value: [u8; N],
        perm: u8,
    ) -> MemResult<()> {
        self.ptr.as_mut().write::<N>(addr, value, perm)
    }
}

#[inline(always)]
pub fn is_aligned<const N: usize>(value: u64) -> bool {
    (value & (N - 1) as u64) == 0
}
