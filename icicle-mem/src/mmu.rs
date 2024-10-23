use std::collections::HashSet;

use tracing::debug;

use crate::{
    perm::{self, MemError, MemResult},
    physical::{self, PageData, PhysicalAddr},
    range_map::RangeMap,
    tlb, Addr, AllocLayout, IoHandler, IoMemory, IoMemoryAny, MemoryMapping, PhysicalMapping,
    Snapshot, SnapshotData, VirtualMemoryMap,
};

pub const DETECT_SELF_MODIFYING_CODE: bool = true;
pub const ENABLE_ZERO_PAGE_OPTIMIZATION: bool = true;
pub const ENABLE_MEMORY_HOOKS: bool = true;

pub trait ReadHook {
    fn read(&mut self, mem: &mut Mmu, addr: u64, size: u8) -> Option<u64>;
}

impl ReadHook for () {
    fn read(&mut self, _: &mut Mmu, _: u64, _: u8) -> Option<u64> {
        None
    }
}

impl<T> ReadHook for T
where
    T: FnMut(&mut Mmu, u64, u8) -> Option<u64>,
{
    fn read(&mut self, mem: &mut Mmu, addr: u64, size: u8) -> Option<u64> {
        self(mem, addr, size)
    }
}

pub trait ReadAfterHook {
    fn read(&mut self, mem: &mut Mmu, addr: u64, value: &[u8]);
}

pub trait WriteHook {
    fn write(&mut self, mem: &mut Mmu, addr: u64, value: &[u8]);
}

impl WriteHook for () {
    fn write(&mut self, _: &mut Mmu, _: u64, _: &[u8]) {}
}

impl<T> WriteHook for T
where
    T: FnMut(&mut Mmu, u64, &[u8]),
{
    fn write(&mut self, mem: &mut Mmu, addr: u64, value: &[u8]) {
        self(mem, addr, value);
    }
}

struct HookEntry<T> {
    start: u64,
    end: u64,
    handler: T,
    dead: bool,
}

macro_rules! active_hooks {
    ($addr:expr, $list:expr, $action:expr) => {{
        if !$list.is_empty() {
            let addr = $addr;
            let mut hooks = std::mem::take(&mut $list);
            for hook in &mut hooks {
                if hook.start <= addr && addr < hook.end {
                    ($action)(&mut *hook.handler);
                }
            }
            debug_assert!($list.is_empty());
            $list = hooks;
        }
    }};
}

pub struct Mmu {
    // @fixme: actually keep track of memory that has currently been translated.
    pub invalidate_icache: bool,

    // @fixme: this currently triggers to many false positives (e.g. due to vectorized loads which
    // are later masked)
    pub track_uninitialized: bool,

    /// @fixme: handle self-modifying code more carefully.
    pub detect_self_modifying_code: bool,

    pub tlb_hit_count: u64,
    pub tlb_miss_count: u64,
    pub mapping_changed: bool,

    /// The set of virtual (page-aligned) addresses that have been modified since this was last
    /// cleared.
    pub modified: HashSet<u64>,

    /// The translation lookahead buffer for the MMU.
    ///
    /// Note: care needs to be taken to ensure that the relevant entries in this cache are cleared
    /// when the mapping is changed otherwise we may end up with memory safety issues.
    pub tlb: Box<tlb::TranslationCache>,

    /// The current virtual address mapping.
    // @fixme: This should not be public, since changes to this require that the `tlb` is flushed.
    pub mapping: RangeMap<MemoryMapping>,

    /// Unicorn style memory hooks.
    // @fixme: allow deleting old hooks.
    read_hooks: Vec<HookEntry<Box<dyn ReadHook>>>,
    read_after_hooks: Vec<HookEntry<Box<dyn ReadAfterHook>>>,
    uncacheable_reads: Vec<(u64, u64)>,
    write_hooks: Vec<HookEntry<Box<dyn WriteHook>>>,
    uncacheable_writes: Vec<(u64, u64)>,

    /// The underlying physical memory.
    physical: physical::PhysicalMemory,

    /// The parent snapshot for the MMU.
    parent_state: Snapshot,

    /// Registed handlers for I/O memory
    io: Vec<Box<dyn IoMemoryAny>>,

    /// Last IO memory region read -- IO reads are not currently translatable in the JIT, so always
    /// trigger tlb misses. To mitigate some of the performance impact of repeat accesses to the
    /// same address, we keep track of the last IO handler used and check if it matches the address
    /// before doing a search for the region.
    last_io_handler: Option<(u64, u64, IoHandler)>,
}

impl crate::Resettable for Mmu {
    fn new() -> Self {
        Self::new()
    }

    fn reset(&mut self) {
        self.clear();
    }
}

impl Default for Mmu {
    fn default() -> Self {
        Self::new()
    }
}

impl Mmu {
    pub fn new() -> Self {
        Self {
            invalidate_icache: false,
            track_uninitialized: false,
            detect_self_modifying_code: DETECT_SELF_MODIFYING_CODE,
            tlb_hit_count: 0,
            tlb_miss_count: 0,
            mapping_changed: false,
            modified: HashSet::new(),
            tlb: Box::new(tlb::TranslationCache::new()),
            mapping: RangeMap::new(),
            physical: physical::PhysicalMemory::new(physical::MAX_PAGES),
            parent_state: Snapshot::new(SnapshotData::new()),
            io: vec![],

            uncacheable_reads: vec![],
            read_hooks: vec![],
            read_after_hooks: vec![],

            uncacheable_writes: vec![],
            write_hooks: vec![],
            last_io_handler: None,
        }
    }

    pub fn add_write_hook(
        &mut self,
        start: u64,
        end: u64,
        hook: Box<dyn WriteHook>,
    ) -> Option<u32> {
        // Find the first removed slot, or create a new slot.
        let (id, slot) = match self.write_hooks.iter_mut().enumerate().find(|(_, x)| x.dead) {
            Some(x) => x,
            None => {
                let next_id = self.write_hooks.len();
                self.write_hooks.push(HookEntry {
                    start: 0,
                    end: 0,
                    handler: Box::new(()),
                    dead: true,
                });
                (next_id, self.write_hooks.last_mut().unwrap())
            }
        };

        slot.start = start;
        slot.end = end;
        slot.handler = hook;
        slot.dead = false;

        let aligned_start = self.page_aligned(start);
        let aligned_end = self.page_aligned(end + self.page_size());
        self.uncacheable_writes.push((aligned_start, aligned_end));
        self.tlb.clear();

        Some(id.try_into().expect("too many hooks"))
    }

    pub fn remove_write_hook(&mut self, id: u32) -> bool {
        let hook = &mut self.write_hooks[id as usize];
        hook.handler = Box::new(());
        hook.start = 0;
        hook.end = 0;
        hook.dead = true;
        true
    }

    pub fn add_read_hook(&mut self, start: u64, end: u64, hook: Box<dyn ReadHook>) -> Option<u32> {
        // @fixme: reuse hook ids
        let next_id = self.read_hooks.len().try_into().unwrap();

        let aligned_start = self.page_aligned(start);
        let aligned_end = self.page_aligned(end + self.page_size());
        self.uncacheable_reads.push((aligned_start, aligned_end));
        self.tlb.clear();

        self.read_hooks.push(HookEntry { start, end, handler: hook, dead: false });
        Some(next_id)
    }

    pub fn remove_read_hook(&mut self, id: u32) -> bool {
        // @todo: actually remove the hook.
        let hook = &mut self.read_hooks[id as usize];
        hook.handler = Box::new(());
        hook.start = 0;
        hook.end = 0;
        true
    }

    pub fn add_read_after_hook(
        &mut self,
        start: u64,
        end: u64,
        hook: Box<dyn ReadAfterHook>,
    ) -> Option<u32> {
        // @fixme: reuse hook ids
        let next_id = self.read_after_hooks.len().try_into().unwrap();

        let aligned_start = self.page_aligned(start);
        let aligned_end = self.page_aligned(end + self.page_size());
        self.uncacheable_reads.push((aligned_start, aligned_end));
        self.tlb.clear();

        self.read_after_hooks.push(HookEntry { start, end, handler: hook, dead: false });
        Some(next_id)
    }

    pub fn clear(&mut self) {
        self.tlb.clear();
        self.mapping = RangeMap::new();
        self.physical.clear();
        self.last_io_handler = None;
    }

    /// Get size (in bytes) of a single page in physical memory.
    #[inline]
    pub fn page_size(&self) -> u64 {
        self.physical.page_size()
    }

    /// Get the offset within a page of an address
    #[inline]
    pub fn page_offset(&self, addr: u64) -> usize {
        physical::PageData::offset(addr)
    }

    /// Align `addr` to a page boundary for the current physical memory configuration.
    #[inline]
    pub fn page_aligned(&self, addr: u64) -> u64 {
        self.physical.page_aligned(addr)
    }

    /// Returns the total number of allocated pages (includes pages referenced by snapshots)
    pub fn total_pages(&self) -> usize {
        self.physical.allocated_pages()
    }

    /// Gets the current physical memory page limit.
    pub fn capacity(&self) -> usize {
        self.physical.capacity()
    }

    /// Sets the maximum number of physical pages the mmu is allowed to allocate.
    ///
    /// Note: If `new_capacity` is smaller than the current number of allocated pages, then the
    /// capacity is set to the number of allocated pages.
    pub fn set_capacity(&mut self, new_capacity: usize) -> bool {
        self.physical.set_capacity(new_capacity)
    }

    /// Read bytes from `addr` checking that the permissions specified by `perm` are set
    pub fn read_bytes(&mut self, mut addr: u64, buf: &mut [u8], perm: u8) -> MemResult<()> {
        if buf.len() > 16 {
            return self.read_bytes_large(addr, buf, perm);
        }

        for byte in buf {
            *byte = self.read::<1>(addr, perm)?[0];
            addr = addr.wrapping_add(1);
        }
        Ok(())
    }

    /// Read bytes from `addr` checking that the permissions specified by `perm` are set
    #[cold]
    pub fn read_bytes_large(&mut self, mut addr: u64, buf: &mut [u8], perm: u8) -> MemResult<()> {
        // Read unaligned bytes at the start
        let aligned_addr = crate::align_up(addr, 16); // @fixme: possible integer overflow
        let (start, buf) = buf.split_at_mut(((aligned_addr - addr) as usize).min(buf.len()));
        for byte in start {
            *byte = self.read::<1>(addr, perm)?[0];
            addr = addr.wrapping_add(1);
        }

        // Read aligned chunks
        let mut chunks = buf.chunks_exact_mut(16);
        for chunk in &mut chunks {
            chunk.copy_from_slice(&self.read::<16>(addr, perm)?);
            addr = addr.wrapping_add(16);
        }

        // Read unaligned bytes at the end
        for byte in chunks.into_remainder() {
            *byte = self.read::<1>(addr, perm)?[0];
            addr = addr.wrapping_add(1);
        }

        Ok(())
    }

    /// Write bytes bytes `addr` checking that the permission specified by `perm` are set and
    /// marking the range written with the `INIT` permission bit.
    pub fn write_bytes(&mut self, mut addr: u64, buf: &[u8], perm: u8) -> MemResult<()> {
        if buf.len() > 16 {
            return self.write_bytes_large(addr, buf, perm);
        }

        for byte in buf {
            self.write(addr, [*byte], perm)?;
            addr = addr.wrapping_add(1);
        }
        Ok(())
    }

    /// Write bytes bytes `addr` checking that the permission specified by `perm` are set and
    /// marking the range written with the `INIT` permission bit.
    #[cold]
    pub fn write_bytes_large(&mut self, mut addr: u64, buf: &[u8], perm: u8) -> MemResult<()> {
        // Write unaligned bytes at the start
        let aligned_addr = crate::align_up(addr, 16); // @fixme: possible integer overflow
        let (start, buf) = buf.split_at(((aligned_addr - addr) as usize).min(buf.len()));
        for byte in start {
            self.write(addr, [*byte], perm)?;
            addr = addr.wrapping_add(1);
        }

        // Write aligned chunks
        let mut chunks = buf.chunks_exact(16);
        for chunk in &mut chunks {
            self.write::<16>(addr, chunk.try_into().unwrap(), perm)?;
            addr = addr.wrapping_add(16);
        }

        // Write unaligned bytes at the end
        for byte in chunks.remainder() {
            self.write(addr, [*byte], perm)?;
            addr = addr.wrapping_add(1);
        }

        Ok(())
    }

    /// Register a handler function that can be mapped to memory locations
    pub fn register_io_handler(&mut self, handler: impl IoMemory + 'static) -> IoHandler {
        let id = self.io.len();
        self.io.push(Box::new(handler));
        IoHandler(id)
    }

    /// Get the memory associated with an I/O handle
    pub fn get_io_memory_mut(&mut self, handler: IoHandler) -> &mut dyn IoMemoryAny {
        &mut *self.io[handler.0]
    }

    #[deprecated(
        note = "The behavior of this function may change in the future. Use `map_memory_len"
    )]
    pub fn map_memory(&mut self, start: u64, end: u64, mapping: impl Into<MemoryMapping>) -> bool {
        self.map_memory_len(start, end - start, mapping)
    }

    /// Attempts to maps a region of memory starting between `start` and `start + len` to `mapping`.
    /// If `start + len` is greater than u64::MAX, memory will wrap around to zero.
    ///
    /// Returns `true` if the memory was succesfully mapped.
    pub fn map_memory_len(
        &mut self,
        start: u64,
        len: u64,
        mapping: impl Into<MemoryMapping>,
    ) -> bool {
        if len == 0 {
            return false; // @todo: should mapping nothing count as being valid?
        }
        let Some(end) = start.checked_add(len - 1)
        else {
            return false;
        };
        let mapping = mapping.into();
        debug!("map_memory: start={:#0x}, end={:#0x}, mapping={:?}", start, end, mapping);

        if let Err(e) = self.mapping.insert(start..=end, mapping) {
            debug!("map_memory: failed: {:0x?}", e);
            return false;
        }
        self.mapping_changed = true;
        self.tlb.remove_range(start, len);
        self.last_io_handler = None;

        true
    }

    pub fn map_physical(&mut self, addr: u64, index: physical::Index) -> bool {
        self.map_memory_len(
            addr,
            self.page_size(),
            MemoryMapping::Physical(PhysicalMapping { index, addr }),
        )
    }

    /// Unmaps the region of memory between `start` and `start+len`
    #[deprecated(
        note = "The behavior of this function may change in the future. Use `unmap_memory_len`"
    )]
    pub fn unmap_memory(&mut self, start: u64, end: u64) -> bool {
        self.unmap_memory_len(start, start - end)
    }

    /// Unmaps the region of memory between `start` and `start+len`
    pub fn unmap_memory_len(&mut self, start: u64, len: u64) -> bool {
        if len == 0 {
            return false; // @todo: should unmapping nothing count as being valid?
        }
        let Some(end) = start.checked_add(len - 1)
        else {
            return false;
        };

        debug!("unmap_memory: start={:#0x}, end={:#0x}", start, end);
        self.mapping_changed = true;

        let physical = &mut self.physical;
        let tlb = &mut self.tlb;
        let mut partially_unmapped = false;
        let _ = self.mapping.overlapping_mut::<_, ()>(start..=end, |start, len, entry| {
            tracing::trace!("unmap: ({:#0x}, {:#0x}): {:0x?}", start, len, entry);
            match entry.take() {
                Some(MemoryMapping::Physical(inner)) => {
                    tlb.remove_range(start, len);
                    if len == physical.page_size() {
                        return Ok(());
                    }

                    // Clear permissions for the unmapped region.
                    //
                    // @fixme: this page could potentially be mapped in multiple locations,
                    // resulting in mapping issues.
                    let page = physical.get_mut(inner.index);
                    assert!(!page.executed, "Unmapped cached code page. Currently unsupported");

                    let offset = PageData::offset(start);
                    page.data_mut().perm[offset..offset + len as usize].fill(perm::NONE);
                }
                Some(_) => {}

                // Attempted to unmap region that wasn't mapped
                None => partially_unmapped = true,
            }

            Ok(())
        });

        !partially_unmapped
    }

    /// Allocates `count` physical pages, returning an error if we are out of memory.
    pub fn alloc_physical(&mut self, count: usize) -> MemResult<Vec<physical::Index>> {
        debug!("alloc_physical: count={count}");
        (0..count).map(|_| self.physical.alloc().ok_or(MemError::OutOfMemory)).collect()
    }

    /// Finds a free region of memory satisfying `layout` then map it to `mapping`
    pub fn alloc_memory(
        &mut self,
        layout: AllocLayout,
        mapping: impl Into<MemoryMapping>,
    ) -> MemResult<u64> {
        let mapping = mapping.into();
        debug!("alloc_memory: layout={layout:0x?}, mapping={mapping:?}");

        let start = self.find_free_memory(layout)?;
        self.map_memory_len(start, layout.size, mapping);
        Ok(start)
    }

    /// Finds a free region of memory satisfying `layout`
    pub fn find_free_memory(&self, layout: AllocLayout) -> MemResult<u64> {
        // Compute the length that we will end up with if we add the padding necessary to meet
        // alignment constraints
        let align = layout.align.checked_next_power_of_two().unwrap();
        let aligned_length = crate::align_up(layout.size, align);

        // Either use the preferred address specified in the layout or start at the lowest address
        // available.
        let mut start_addr = crate::align_up(layout.addr.unwrap_or(0), align);

        while let Some((_, end)) = self.mapping.get_range(
            start_addr..=start_addr.checked_add(aligned_length - 1).ok_or(MemError::OutOfMemory)?,
        ) {
            start_addr = crate::align_up(end + 1, align);
        }

        Ok(start_addr)
    }

    /// Updates the mapping value associated with a region of memory
    pub fn update_perm(&mut self, addr: u64, count: u64, perm: u8) -> MemResult<()> {
        let end = addr.checked_add(count - 1).ok_or(MemError::AddressOverflow)?;
        let perm =
            perm | perm::MAP | if self.track_uninitialized { perm::NONE } else { perm::INIT };
        debug!("update_perm: addr={addr:#0x}, count={count:#0x}, perm={}", perm::display(perm));

        self.mapping_changed = true;

        let physical = &mut self.physical;
        let tlb = &mut self.tlb;
        self.mapping.overlapping_mut(addr..=end, |start, len, entry| {
            match entry.as_mut().ok_or(MemError::Unmapped)? {
                MemoryMapping::Physical(entry) => {
                    tlb.remove_range(start, len);
                    let page = physical.get_mut(entry.index);
                    if page.executed {
                        tracing::error!("Changed perms of code page. JIT cache may now be invalid");
                    }

                    let offset = PageData::offset(start);
                    let len = len as usize;

                    if offset == 0
                        && len == physical::PAGE_SIZE
                        && entry.index.is_zero_page()
                        && perm::check(perm, perm::READ | perm::INIT | perm::MAP).is_ok()
                    {
                        // Switch to zero-page with the correct permissions.
                        let zero_page = match perm & perm::WRITE != 0 {
                            true => physical.zero_page(),
                            false => physical.read_only_zero_page(),
                        };
                        debug!("updating zero page: {:?} -> {zero_page:?}", entry.index);
                        entry.index = zero_page;
                    }
                    else {
                        page.data_mut().perm[offset..offset + len].fill(perm);
                    }
                }
                MemoryMapping::Unallocated(entry) => entry.perm = perm,
                MemoryMapping::Io(_) => {
                    unimplemented!("attempted to update permission of I/O region")
                }
            }

            Ok(())
        })
    }

    /// Fill a region of memory with `value`
    pub fn fill_mem(&mut self, addr: u64, count: u64, value: u8) -> MemResult<()> {
        if count == 0 {
            return Ok(());
        }
        let end = addr.checked_add(count - 1).ok_or(MemError::AddressOverflow)?;
        debug!("fill_mem: addr={:#0x}, count={:#0x}, value={:#0x}", addr, count, value);

        let physical = &mut self.physical;
        let tlb = &mut self.tlb;
        self.mapping.overlapping_mut(addr..=end, |start, len, entry| {
            match entry.as_mut().ok_or(MemError::Unmapped)? {
                MemoryMapping::Physical(entry) => {
                    tlb.remove_range(start, len);
                    let page = physical.get_mut(entry.index);
                    if page.executed && self.detect_self_modifying_code {
                        check_self_modifying_memset(page.data(), start, len, value)?;
                    }

                    let offset = PageData::offset(start);

                    // Check whether we a simply overwritting a zero page with zeros.
                    let write_zero_to_zero_page = value == 0
                        && offset == 0
                        && len as usize == physical::PAGE_SIZE
                        && entry.index.is_zero_page();

                    if !write_zero_to_zero_page {
                        let page = page.data_mut();
                        page.data[offset..offset + len as usize].fill(value);
                        page.add_perm(offset, len as usize, perm::INIT);
                    }
                }
                MemoryMapping::Unallocated(entry) => {
                    entry.value = value;
                    entry.perm |= perm::INIT;
                }
                MemoryMapping::Io(_) => {
                    unimplemented!("attempted to memset an I/O region")
                }
            }
            Ok(())
        })
    }

    #[deprecated(
        note = "The behavior of this function may change in the future. Use `move_region_len`"
    )]
    pub fn move_region(&mut self, start: u64, end: u64, dst: u64) -> MemResult<()> {
        self.move_region_len(start, end - start, dst)
    }

    pub fn move_region_len(&mut self, start: u64, len: u64, dst: u64) -> MemResult<()> {
        let offset = dst as i64 - start as i64;
        let mut end = start.checked_add(len - 1).ok_or(MemError::AddressOverflow)?;

        while start < end {
            let (prev, (overlap_start, overlap_end)) =
                self.mapping.remove_last(start..=end).ok_or(MemError::Unmapped)?;

            if overlap_end < end {
                return Err(MemError::Unmapped);
            }

            self.tlb.remove_range(overlap_start, (overlap_end - overlap_start) + 1);
            self.last_io_handler = None;

            let shifted_start = (overlap_start as i64 + offset) as u64;
            let shifted_end = (overlap_end as i64 + offset) as u64;
            self.mapping.insert((shifted_start, shifted_end), prev).unwrap();

            end = overlap_start
        }
        Ok(())
    }

    /// Clear the translation lookahead buffer.
    pub fn clear_tlb(&mut self) {
        self.tlb.clear();
        self.last_io_handler = None;
    }

    /// Obtain a raw pointer to the translation lookahead buffer.
    ///
    /// Safety: Avoid any operation except reading/writing to initialized memory locations while
    /// this pointer is active.
    pub fn tlb_ptr(&mut self) -> *const tlb::TranslationCache {
        self.tlb.as_ref() as *const _
    }

    /// Invalidate an entry in the TLB.
    pub fn invalidate_page(&mut self, addr: u64) {
        self.tlb.remove(addr);
    }

    /// Create a full snapshot of memory that can later be restored
    pub fn snapshot(&mut self) -> Snapshot {
        // TLB is invalidated whenever we clone the physical memory state.
        self.tlb.clear();

        let snapshot = SnapshotData {
            mapping: self.mapping.clone(),
            physical: self.physical.snapshot(),
            parent: Some(self.parent_state.clone()),
            io: self.io.iter_mut().map(|x| x.snapshot()).collect(),
        };

        // Reconfigure the current modification state to be tracked based on the new snapshot
        self.parent_state = std::sync::Arc::new(snapshot);
        self.parent_state.clone()
    }

    /// Restore the full memory state from `snapshot`
    pub fn restore(&mut self, snapshot: Snapshot) {
        self.tlb.clear();
        self.last_io_handler = None;

        self.modified.clear();
        self.mapping_changed = true;

        self.physical.restore(&snapshot.physical);
        self.io.iter_mut().zip(&snapshot.io).for_each(|(io, snapshot)| io.restore(snapshot));

        // Configure our state to match the snapshot
        self.mapping.clone_from(&snapshot.mapping);
        self.parent_state = snapshot;
    }

    /// Create a snapshot of just the virtual address space
    pub fn snapshot_virtual_mapping(&mut self) -> VirtualMemoryMap {
        // Clear the TLB to ensure that no writes will be missed.
        self.tlb.clear();
        self.last_io_handler = None;

        // Mark all physical pages in the mapping as copy-on-write.
        for (_, _, entry) in self.mapping.iter() {
            if let MemoryMapping::Physical(mapping) = entry {
                self.physical.get_mut(mapping.index).copy_on_write = true;
            }
        }

        self.mapping.clone()
    }

    /// Take the underlying virtual address space.
    pub fn take_virtual_mapping(&mut self) -> VirtualMemoryMap {
        self.tlb.clear();
        self.last_io_handler = None;
        self.mapping_changed = true;
        std::mem::take(&mut self.mapping)
    }

    /// Restore just the virtual address space
    pub fn restore_virtual_mapping(&mut self, mapping: VirtualMemoryMap) {
        self.mapping = mapping;
        self.tlb.clear();
        self.last_io_handler = None;

        self.modified.clear();
        self.mapping_changed = true;
    }

    /// Reset the the virtual address space
    pub fn reset_virtual(&mut self) {
        self.mapping.clear();
        self.tlb.clear();
        self.last_io_handler = None;

        self.modified.clear();
        self.mapping_changed = true;
    }

    /// Clear the page modification log
    pub fn clear_page_modification_log(&mut self) {
        self.tlb.clear_write();
        self.last_io_handler = None;
        self.modified.clear();
    }

    /// Get the permission bits associated with the byte at `addr`
    pub fn get_perm(&self, addr: u64) -> u8 {
        let entry = match self.mapping.get(addr) {
            Some(entry) => entry,
            None => return perm::NONE,
        };
        match entry {
            MemoryMapping::Physical(entry) => {
                let page = self.physical.get(entry.index).data();
                let (offset, _) = PageData::offset_and_len(addr, addr + 1);
                page.perm[offset]
            }
            MemoryMapping::Unallocated(metadata) => metadata.perm,
            MemoryMapping::Io(_) => {
                // @fixme?
                perm::NONE
            }
        }
    }

    /// Check that the region of memory between addr..addr+len is initialized and executable, and
    /// ensure that if it is ever written to in the future it will be detected.
    pub fn ensure_executable(&mut self, start: u64, len: u64) -> bool {
        let Some(end) = start.checked_add(len - 1)
        else {
            return false;
        };

        let tlb = &mut self.tlb;
        let physical = &mut self.physical;
        self.mapping
            .overlapping_mut::<_, MemError>(start..=end, |start, len, entry| match entry {
                Some(MemoryMapping::Physical(mapping)) => {
                    let page = physical.get_mut(mapping.index);
                    page.executed = true;

                    // Check whether the code is actually executable.
                    let offset = PageData::offset(start);
                    let len = len as usize;
                    let perm =
                        unsafe { page.write_ptr().ptr.as_mut().get_perm_unchecked(offset, len) };
                    perm::check(perm, perm::READ | perm::INIT | perm::EXEC)?;

                    // Prevent writes to the region we are executing (we don't currently support
                    // self modifying code).
                    if self.detect_self_modifying_code {
                        unsafe {
                            page.write_ptr().ptr.as_mut().perm[offset..offset + len].fill(
                                perm::IN_CODE_CACHE
                                    | perm::READ
                                    | perm::INIT
                                    | perm::EXEC
                                    | perm::MAP,
                            )
                        };
                    }

                    tlb.remove_write(mapping.addr);
                    Ok(())
                }
                _ => Err(MemError::ExecViolation),
            })
            .is_ok()
    }

    /// Clears the executable bit from uninitialized memory.
    ///
    /// @fixme: this was used a workaround for `track_uninitialized` returning to many false
    /// positives in some cases.
    pub fn clear_uninitialized_exec_bytes(&mut self) {
        let physical = &mut self.physical;
        for (start, end, entry) in self.mapping.iter_mut() {
            match entry {
                MemoryMapping::Physical(entry) => {
                    let (offset, len) = PageData::offset_and_len(start, end + 1);
                    let page = physical.get_mut(entry.index);
                    page.data_mut().perm[offset..offset + len].iter_mut().for_each(|p| {
                        if *p & perm::INIT == 0 {
                            *p &= !perm::EXEC;
                        }
                    });
                }
                MemoryMapping::Unallocated(x) => x.perm &= !perm::EXEC,
                MemoryMapping::Io(_) => {}
            }
        }
    }

    /// Initialize a new physical page and map it such that it contains `addr`.
    ///
    /// Returns the index of the new page in physical memory (or `None` if we are out of memory)
    fn init_physical(&mut self, addr: u64, is_write: bool) -> Option<physical::Index> {
        let page_start = self.page_aligned(addr);
        let page_size = self.page_size();
        let page_end = page_start + (page_size - 1);

        let range = page_start..=page_end;
        // If we are only reading from this page and the entire region is entirely zero, then map it
        // to a zero page.
        if ENABLE_ZERO_PAGE_OPTIMIZATION && !is_write {
            if let Some(perm) = self.is_zero_region(page_start, page_size) {
                let zero_page = match perm & perm::WRITE != 0 {
                    true => self.physical.zero_page(),
                    false => self.physical.read_only_zero_page(),
                };
                tracing::trace!("init_physical: addr={page_start:#0x}, index={zero_page:?}");

                let _ = self.mapping.overlapping_mut::<_, ()>(range, |_, _, entry| {
                    *entry = Some(MemoryMapping::Physical(PhysicalMapping {
                        index: zero_page,
                        addr: page_start,
                    }));
                    Ok(())
                });
                return Some(zero_page);
            }
        }

        let index = self.physical.alloc()?;
        self.tlb.remove(page_start);

        tracing::trace!("init_physical: addr={:#0x}, index={:?}", page_start, index);
        let new_mapping = PhysicalMapping { index, addr: page_start };

        let init_perm = if self.track_uninitialized { perm::NONE } else { perm::INIT };

        let physical = &mut self.physical;
        let _ = self.mapping.overlapping_mut::<_, ()>(range, |start, len, entry| {
            let len = len as usize;

            // Determine how this region of the page should be initalized.
            let (value, perm) = match entry {
                Some(MemoryMapping::Unallocated(x)) => {
                    tracing::trace!("Replacing unallocated region (start={start:#x}, len={len:#x}) with physical mapping.");
                    let init = (x.value, x.perm | perm::MAP | init_perm);
                    *entry = Some(MemoryMapping::Physical(new_mapping));
                    init
                }
                Some(MemoryMapping::Physical(existing)) => {
                    // Rare case where there was an existing page map at this location. This should
                    // only occur when a page is partially mapped. Copy any memory that could be
                    // lost when we replace this mapping.
                    //
                    // @fixme: handle this better.

                    tracing::trace!(
                        "copy {len:#0x} bytes at {start:#0x} from: {:?}",
                        existing.index
                    );

                    let offset = (start - page_start) as usize;

                    let (old_page, new_page) = physical.get_pair_mut(existing.index, index);
                    let (old, new) = (old_page.data(), new_page.data_mut());
                    new.data[offset..offset + len].copy_from_slice(&old.data[offset..offset + len]);
                    new.perm[offset..offset + len].copy_from_slice(&old.perm[offset..offset + len]);

                    *entry = Some(MemoryMapping::Physical(new_mapping));
                    return Ok(());
                }
                Some(MemoryMapping::Io(_)) => (crate::UNINIT_VALUE, perm::NONE),
                None => (crate::UNINIT_VALUE, perm::NONE),
            };

            let page = physical.get_mut(index).data_mut();
            let offset = PageData::offset(start);
            page.data[offset..offset + len].fill(value);
            page.perm[offset..offset + len].fill(perm);

            Ok(())
        });

        Some(index)
    }

    /// Checks whether the memory is zero page compatible, returning the permissions of the region.
    fn is_zero_region(&mut self, start: u64, len: u64) -> Option<u8> {
        let end = start.checked_add(len - 1)?;
        let mut perm = None;
        for (_, _, entry) in self.mapping.overlapping_iter(start..=end) {
            match entry {
                Some(MemoryMapping::Unallocated(x)) if x.is_zero() => {
                    if perm.map_or(false, |perm| x.perm != perm) {
                        return None;
                    }
                    perm = Some(x.perm);
                }
                _ => return None,
            }
        }
        perm
    }

    /// Checks whether the memory range entirely consists of mapped regular memory.
    pub fn is_regular_region(&self, start: u64, len: u64) -> bool {
        let Some(end) = start.checked_add(len - 1)
        else {
            return false;
        };
        for (_, _, entry) in self.mapping.overlapping_iter((start, end)) {
            match entry {
                Some(MemoryMapping::Physical(_) | MemoryMapping::Unallocated(_)) => {}
                _ => return false,
            }
        }
        true
    }

    /// Gets the physical address assocated with a virtual address, returning `None` if `addr` is
    /// unmapped or unallocated
    pub fn get_physical_addr(&self, addr: u64) -> Option<PhysicalAddr> {
        self.resolve_vaddr(addr).map(|entry| entry.phys)
    }

    pub fn resolve_vaddr(&self, vaddr: u64) -> Option<Addr> {
        match self.mapping.get(vaddr)? {
            MemoryMapping::Physical(entry) => {
                Some(Addr { virt: vaddr, phys: self.physical.address_of(vaddr, entry.index) })
            }
            _ => None,
        }
    }

    /// Get the index of physical page mapped at `addr`.
    pub fn get_physical_index(&self, addr: u64) -> Option<physical::Index> {
        match self.mapping.get(addr)? {
            MemoryMapping::Physical(entry) => Some(entry.index),
            _ => None,
        }
    }

    pub fn get_physical(&self, index: physical::Index) -> &physical::Page {
        self.physical.get(index)
    }

    pub fn get_physical_mut(&mut self, index: physical::Index) -> &mut physical::Page {
        // @fixme: this may invalidate the TLB
        self.physical.get_mut(index)
    }

    fn read_physical<const N: usize>(
        &mut self,
        index: physical::Index,
        addr: u64,
        perm: u8,
    ) -> MemResult<[u8; N]> {
        let page = self.physical.get_mut(index);
        let result = page.data().read(addr, perm)?;

        // If there is no memory hook set on the current page, cache the translated address in the
        // TLB.
        let uncachable =
            self.uncacheable_reads.iter().any(|&(start, end)| start <= addr && addr < end);
        if !uncachable {
            self.tlb.insert_read(addr, unsafe { page.read_ptr() });
        }
        Ok(result)
    }

    fn write_physical<const N: usize>(
        &mut self,
        index: physical::Index,
        addr: u64,
        value: [u8; N],
        perm: u8,
    ) -> MemResult<()> {
        let page_start = self.page_aligned(addr);
        let page_size = self.page_size();

        let mut page = self.physical.get_mut(index);
        if page.executed && self.detect_self_modifying_code {
            check_self_modifying_write(page.data(), addr, &value)?;
        }

        if page.copy_on_write {
            // Make a copy and update the mapping to point to the new copy.
            let copy_index = self.physical.clone_page(index).ok_or(MemError::OutOfMemory)?;
            let copy_mapping = PhysicalMapping { index: copy_index, addr: page_start };
            tracing::trace!("{:?} ({:#0x}) copy-on-write -> {copy_index:?}", index, page_start);

            let page_end = page_start + (page_size - 1);
            self.mapping.overlapping_mut(page_start..=page_end, |_start, _end, entry| {
                if let Some(mapping @ MemoryMapping::Physical(_)) = entry {
                    *mapping = MemoryMapping::Physical(copy_mapping);
                }
                Ok(())
            })?;

            page = self.physical.get_mut(copy_index);
        }

        // `data_mut` may cause a new copy of page to be created, so invalidate the read entry for
        // the TLB cache.
        self.tlb.remove_read(page_start);

        // @todo: check the overhead of this hash operation.
        self.modified.insert(page_start);
        page.data_mut().write(addr, value, perm)?;

        let uncachable =
            self.uncacheable_writes.iter().any(|&(start, end)| start <= addr && addr < end);
        if !uncachable {
            // Safety: `page.data_mut()` ensures the page is a unique copy of the underlying data.
            self.tlb.insert_write(page_start, unsafe { page.write_ptr() });
        }

        Ok(())
    }

    #[cold]
    fn read_unaligned<const N: usize>(&mut self, addr: u64, perm: u8) -> MemResult<[u8; N]> {
        let mut value = [0; N];
        for (i, byte) in value.iter_mut().enumerate() {
            *byte = self.read_u8(addr + i as u64, perm)?;
        }
        Ok(value)
    }

    #[cold]
    fn write_unaligned<const N: usize>(
        &mut self,
        addr: u64,
        value: [u8; N],
        perm: u8,
    ) -> MemResult<()> {
        for (i, &byte) in value.iter().enumerate() {
            self.write_u8(addr + i as u64, byte, perm)?;
        }
        Ok(())
    }

    #[cold]
    pub fn read_tlb_miss<const N: usize>(&mut self, addr: u64, perm: u8) -> MemResult<[u8; N]> {
        if !physical::is_aligned::<N>(addr) {
            return self.read_unaligned(addr, perm);
        }

        if perm != perm::NONE && ENABLE_MEMORY_HOOKS && !self.read_hooks.is_empty() {
            let mut hooks = std::mem::take(&mut self.read_hooks);
            for hook in &mut hooks {
                if hook.start <= addr && addr < hook.end {
                    if let Some(result) = hook.handler.read(self, addr, N as u8) {
                        let mut buf = [0; N];
                        buf.copy_from_slice(&result.to_le_bytes()[..N]);
                        self.read_hooks = hooks;
                        return Ok(buf);
                    }
                }
            }
            debug_assert!(self.read_hooks.is_empty());
            self.read_hooks = hooks;
        }

        macro_rules! handle_io {
            ($id:expr) => {
                (|| {
                    let mut buf = [0; N];
                    self.io[$id].read(addr, &mut buf)?;
                    Ok(buf)
                })()
            };
        }

        let result = match self.last_io_handler.as_ref() {
            Some((start, end, id)) if (*start..=*end).contains(&addr) => {
                handle_io!(id.0)
            }
            _ => {
                tracing::trace!("read_tlb_miss: {:#0x}", self.page_aligned(addr));
                self.tlb_miss_count += 1;
                match self.mapping.get_with_range(addr).ok_or(MemError::Unmapped)? {
                    (_, _, MemoryMapping::Physical(entry)) => {
                        self.read_physical(entry.index, addr, perm)
                    }
                    (_, _, &MemoryMapping::Unallocated(entry)) => {
                        perm::check(entry.perm | perm::MAP, perm)?;
                        let index = self.init_physical(addr, false).ok_or(MemError::OutOfMemory)?;
                        self.read_physical(index, addr, perm)
                    }
                    (start, end, MemoryMapping::Io(id)) => {
                        self.last_io_handler = Some((start, end, IoHandler(*id)));
                        handle_io!(*id)
                    }
                }
            }
        };

        // Since we allow byte-level memory memory mapping to be created, rarely we may have a read
        // that crosses a mapping boundary which will result in a `Unmapped` error. To handle this
        // case try again using `read_unaligned` which will read one byte at a time.
        if N != 1 && result == Err(MemError::Unmapped) {
            return self.read_unaligned(addr, perm);
        }

        if let Ok(value) = result {
            if perm != perm::NONE && ENABLE_MEMORY_HOOKS {
                active_hooks!(addr, self.read_after_hooks, |hook: &mut dyn ReadAfterHook| {
                    hook.read(self, addr, &value)
                })
            }
        }

        result
    }

    #[cold]
    pub fn write_tlb_miss<const N: usize>(
        &mut self,
        addr: u64,
        value: [u8; N],
        perm: u8,
    ) -> MemResult<()> {
        if !physical::is_aligned::<N>(addr) {
            return self.write_unaligned(addr, value, perm);
        }

        tracing::trace!("write_tlb_miss: {:#0x}", self.page_aligned(addr));
        self.tlb_miss_count += 1;
        let result = match self.mapping.get(addr).ok_or(MemError::Unmapped)? {
            MemoryMapping::Physical(entry) => self.write_physical(entry.index, addr, value, perm),
            &MemoryMapping::Unallocated(entry) => {
                perm::check(entry.perm | perm::MAP, perm)?;
                let index = self.init_physical(addr, true).ok_or(MemError::OutOfMemory)?;
                self.write_physical(index, addr, value, perm)
            }
            MemoryMapping::Io(id) => self.io[*id].write(addr, &value),
        };

        // Handle case where we are writing across a mapping boundary (see `read_tlb_miss`).
        if N != 1 && result == Err(MemError::Unmapped) {
            return self.write_unaligned(addr, value, perm);
        }

        if perm != perm::NONE && ENABLE_MEMORY_HOOKS {
            active_hooks!(addr, self.write_hooks, |hook: &mut dyn WriteHook| {
                hook.write(self, addr, &value)
            })
        }

        result
    }

    /// Get a reference to the virtual address space's mapping.
    pub fn get_mapping(&self) -> &VirtualMemoryMap {
        &self.mapping
    }

    /// Get a mutable reference to the virtual address space's mapping.
    pub fn get_mapping_mut(&mut self) -> &mut VirtualMemoryMap {
        &mut self.mapping
    }

    #[inline(always)]
    pub fn read<const N: usize>(&mut self, addr: u64, perm: u8) -> MemResult<[u8; N]> {
        match unsafe { self.tlb.read(addr, perm) } {
            Err(MemError::Unmapped) => self.read_tlb_miss(addr, perm),
            Err(MemError::Unaligned) if N != 1 => self.read_unaligned(addr, perm),
            x => x,
        }
    }

    #[inline(always)]
    pub fn write<const N: usize>(&mut self, addr: u64, value: [u8; N], perm: u8) -> MemResult<()> {
        match unsafe { self.tlb.write(addr, value, perm) } {
            Err(MemError::Unmapped) => self.write_tlb_miss(addr, value, perm),
            Err(MemError::Unaligned) if N != 1 => self.write_unaligned(addr, value, perm),
            x => x,
        }
    }

    pub fn read_cstr(&mut self, mut addr: u64, buf: &mut Vec<u8>) -> MemResult<u64> {
        loop {
            match self.read_u8(addr, perm::READ)? {
                0 => break,
                x => buf.push(x),
            }
            addr += 1;
        }
        Ok(addr)
    }
}

#[cold]
fn check_self_modifying_memset(page: &PageData, start: u64, len: u64, value: u8) -> MemResult<()> {
    let offset = PageData::offset(start);
    for i in offset..offset + len as usize {
        if page.perm[i] & perm::IN_CODE_CACHE != 0 && page.data[i] != value {
            let addr = start + (i - offset) as u64;
            tracing::error!("Self modifying code detected at {addr:#x}. Currently unsupported.");
            return Err(MemError::SelfModifyingCode);
        }
    }
    Ok(())
}

#[cold]
fn check_self_modifying_write(page: &PageData, addr: u64, value: &[u8]) -> MemResult<()> {
    let offset = PageData::offset(addr);
    for (i, ((old, perm), new)) in
        page.data[offset..].iter().zip(&page.perm[offset..]).zip(value).enumerate()
    {
        if perm & perm::IN_CODE_CACHE != 0 && *old != *new {
            tracing::error!(
                "Self modifying code detected at {:#x}. Currently unsupported.",
                addr + i as u64
            );
            return Err(MemError::SelfModifyingCode);
        }
    }
    Ok(())
}

macro_rules! impl_read_write {
    ($read_name:ident, $write_name:ident, $ty:ty) => {
        impl Mmu {
            #[inline(always)]
            pub fn $read_name(&mut self, addr: u64, perm: u8) -> MemResult<$ty> {
                Ok(<$ty>::from_le_bytes(self.read(addr, perm)?))
            }

            #[inline(always)]
            pub fn $write_name(&mut self, addr: u64, value: $ty, perm: u8) -> MemResult<()> {
                self.write(addr, value.to_le_bytes(), perm)
            }
        }
    };
}

impl_read_write!(read_u8, write_u8, u8);
impl_read_write!(read_u16, write_u16, u16);
impl_read_write!(read_u32, write_u32, u32);
impl_read_write!(read_u64, write_u64, u64);
