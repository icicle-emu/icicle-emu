use std::collections::BTreeMap;

/// A data structure where a range of integers is mapped to a specific value.
pub type RangeMap<T> = VecRangeMap<T>;

/// Note can't use the standard `std::ops::Range` since it is non-copiable.
#[derive(Copy, Clone, Default, Debug)]
struct Range {
    start: u64,
    end: u64,
}

impl Range {
    fn is_empty(&self) -> bool {
        self.start >= self.end
    }
}

impl From<(u64, u64)> for Range {
    fn from((start, end): (u64, u64)) -> Self {
        Self { start, end }
    }
}

pub trait RangeIndex {
    fn to_inclusive(&self) -> (u64, u64);
}

impl RangeIndex for (u64, u64) {
    fn to_inclusive(&self) -> (u64, u64) {
        (self.0, self.1)
    }
}

impl RangeIndex for std::ops::Range<u64> {
    fn to_inclusive(&self) -> (u64, u64) {
        (self.start, self.end - 1)
    }
}

impl RangeIndex for std::ops::RangeInclusive<u64> {
    fn to_inclusive(&self) -> (u64, u64) {
        (*self.start(), *self.end())
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Default)]
struct RangeMapData<T> {
    end: u64,
    data: T,
}

/// A data structure where a range of integers is mapped to a specific value based on a BTreeMap
/// data structure.
///
///
/// This allows for (relatively) efficient insertion, deletion and lookup, however involves a
/// significant amount of code, so the Vec-based implementation typically works better for most
/// emulator usecases.
pub struct BTreeRangeMap<T> {
    ranges: BTreeMap<u64, RangeMapData<T>>,
}

impl<T> Default for BTreeRangeMap<T> {
    fn default() -> Self {
        Self { ranges: Default::default() }
    }
}

impl<T: Clone> Clone for BTreeRangeMap<T> {
    fn clone(&self) -> Self {
        Self { ranges: self.ranges.clone() }
    }

    fn clone_from(&mut self, source: &Self) {
        self.ranges.clone_from(&source.ranges)
    }
}

impl<T> std::fmt::Debug for BTreeRangeMap<T>
where
    T: std::fmt::Debug,
{
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let mut map = f.debug_map();
        for entry in &self.ranges {
            map.entry(&(*entry.0..entry.1.end), &entry.1.data);
        }
        map.finish()
    }
}

#[derive(Debug)]
pub struct OverlapError<T> {
    pub data: T,
    pub overlap: (u64, u64),
}

impl<T> BTreeRangeMap<T>
where
    T: Clone + Eq + PartialEq,
{
    pub fn new() -> Self {
        Self::default()
    }

    pub fn clear(&mut self) {
        self.ranges.clear();
    }

    /// Gets the value at `index`
    pub fn get(&self, index: u64) -> Option<&T> {
        let (_, entry) = self.ranges.range(..=index).rev().next()?;
        if entry.end > index {
            return Some(&entry.data);
        }
        None
    }

    pub fn insert(&mut self, range: (u64, u64), data: T) -> Result<(), OverlapError<T>> {
        let range = Range::from(range);
        if let Some(overlap) = self.get_overlap(range) {
            return Err(OverlapError { data, overlap: (overlap.0.start, overlap.0.end) });
        }

        // If the entry comes directly before or after an entry with the same mapping, replace
        // the existing entry with one that covers both.
        //
        // To do this properly, we need to handle 3 cases:
        let mut iter = self.ranges.range_mut(..=range.end).rev();
        match iter.next() {
            // 1. The new entry comes before an existing range.
            Some((start, entry)) if entry.data == data && range.end == *start => {
                let start = *start;
                let entry = self.ranges.remove(&start).unwrap();
                return self.insert((range.start, entry.end), entry.data);
            }
            // 2. The new entry comes after an existing range, and there is nothing directly after
            //    the new range.
            Some((start, entry)) if entry.data == data && range.start == entry.end => {
                let start = *start;
                let entry = self.ranges.remove(&start).unwrap();
                return self.insert((start, range.end), entry.data);
            }

            _ => {}
        }
        match iter.next() {
            // 3. The new entry comes after an existing range, but there was an existing
            //    (non-matching) range directly after it (which was checked first).
            Some((start, entry)) if entry.data == data && range.start == entry.end => {
                let start = *start;
                let entry = self.ranges.remove(&start).unwrap();
                return self.insert((start, range.end), entry.data);
            }
            _ => {}
        }

        // No matching range to extend so treat this as a new range
        self.ranges.insert(range.start, RangeMapData { end: range.end, data });
        Ok(())
    }

    /// Removes the last overlapping entry in the mapping that overlap with `range`
    ///
    /// Returns the range removed any data associated with the removed range
    pub fn remove_last(&mut self, range: (u64, u64)) -> Option<(T, (u64, u64))> {
        let (existing, overlap, _) = self.get_overlap(range.into())?;

        match overlap {
            RangeOverlap::Partial(overlap_start, overlap_end) => {
                let entry = self.ranges.remove(&existing.start).unwrap();

                // Before the removed range
                if !Range::from((existing.start, overlap_start)).is_empty() {
                    self.ranges.insert(existing.start, RangeMapData {
                        end: overlap_start,
                        data: entry.data.clone(),
                    });
                }

                // After the removed range
                if !Range::from((overlap_end, existing.end)).is_empty() {
                    self.ranges.insert(overlap_end, RangeMapData {
                        end: existing.end,
                        data: entry.data.clone(),
                    });
                }

                Some((entry.data, (overlap_start, overlap_end)))
            }
            RangeOverlap::Full => {
                let entry = self.ranges.remove(&existing.start).unwrap();
                Some((entry.data, (existing.start, existing.end)))
            }
        }
    }

    /// Removes all entries in the mapping that overlap with `range`
    pub fn remove_all(&mut self, range: (u64, u64)) {
        self.overlapping_mut::<_, ()>(range, |_, _, entry| {
            entry.take();
            Ok(())
        })
        .unwrap();
    }

    /// Gets an iterator over all ranges in the map
    pub fn iter(&self) -> impl Iterator<Item = (u64, u64, &T)> {
        self.ranges.iter().map(|(start, entry)| (*start, entry.end, &entry.data))
    }

    /// Gets an iterator over all ranges in the map
    pub fn iter_mut(&mut self) -> impl Iterator<Item = (u64, u64, &mut T)> {
        self.ranges.iter_mut().map(|(start, entry)| (*start, entry.end, &mut entry.data))
    }

    /// Returns an iterator over all the entries in the map that overlap with `range`.
    pub fn overlapping_iter(&self, range: (u64, u64)) -> BTreeRangeIter<T> {
        BTreeRangeIter { start: range.0, end: range.1, map: self }
    }

    /// Execute `func` for each mapped entry and gap between `range`, allowing modification of each
    /// entry.
    pub fn overlapping_mut<F, E>(&mut self, range: (u64, u64), mut func: F) -> Result<(), E>
    where
        F: FnMut(u64, u64, &mut Option<T>) -> Result<(), E>,
    {
        let mut iter = BtreeRangeSplitIterMut { start: range.0, end: range.1, map: self };
        while iter.step(&mut func)? {}
        Ok(())
    }

    /// Gets the last range that overlaps with `target`
    pub fn get_range(&self, target: (u64, u64)) -> Option<(u64, u64)> {
        self.get_overlap(Range::from(target)).map(|(range, _, _)| (range.start, range.end))
    }

    /// Finds the overlap of `target` with an existing range.
    ///
    /// Note: If there is more more than one overlapping range the last one will be returned
    fn get_overlap(&self, target: Range) -> Option<(Range, RangeOverlap, &T)> {
        let (start, entry) = self.ranges.range(..target.end).rev().next()?;

        let range = Range::from((*start, entry.end));

        let overlapping = get_overlapping(range, target)?;
        Some((range, overlapping, &entry.data))
    }
}

/// An iterator over the entries that overlap with a particular range, handling partial overlaps by
/// splitting the range
struct BtreeRangeSplitIterMut<'a, T> {
    start: u64,
    end: u64,
    map: &'a mut BTreeRangeMap<T>,
}

impl<'a, T: Clone + Eq + PartialEq> BtreeRangeSplitIterMut<'a, T> {
    fn step<U>(
        &mut self,
        mut modify: impl FnMut(u64, u64, &mut Option<T>) -> Result<(), U>,
    ) -> Result<bool, U> {
        if self.start >= self.end {
            return Ok(false);
        }

        let range = (self.start, self.end);
        let (prev, (overlap_start, overlap_end)) = match self.map.remove_last(range) {
            Some((entry, overlap)) => (Some(entry), overlap),
            None => (None, (self.start, self.end)),
        };

        let map = &mut *self.map;
        let mut modify_and_insert = |start, end, mut prev| {
            let result = modify(start, end, &mut prev);
            if let Some(new) = prev {
                if map.insert((start, end), new).is_err() {
                    unreachable!("Overlap when inserting entry in region we expected to be empty");
                }
            }
            result
        };

        modify_and_insert(overlap_start, overlap_end, prev)?;
        if overlap_end < self.end {
            // There was a gap between the next entry and the previous entry, so give the caller the
            // chance to insert something here.
            modify_and_insert(overlap_end, self.end, None)?;
        }

        self.end = overlap_start;
        Ok(true)
    }
}

/// An iterator over the entries that overlap with a particular range, handling partial overlaps by
/// splitting the range
pub struct BTreeRangeIter<'a, T> {
    start: u64,
    end: u64,
    map: &'a BTreeRangeMap<T>,
}

impl<'a, T: Clone + Eq + PartialEq> Iterator for BTreeRangeIter<'a, T> {
    type Item = (u64, u64, Option<&'a T>);

    fn next(&mut self) -> Option<Self::Item> {
        if self.start >= self.end {
            return None;
        }

        let range = (self.start, self.end);
        let ((overlap_start, overlap_end), entry) = match self.map.get_overlap(Range::from(range)) {
            Some((range, overlap, entry)) => (overlap.get(range), Some(entry)),
            None => ((self.start, self.end), None),
        };

        if overlap_end < self.end {
            // There was a gap between the next entry and the previous entry, so give the caller the
            // chance to insert something here.
            let end = self.end;
            self.end = overlap_end;
            Some((overlap_end, end, None))
        }
        else {
            self.end = overlap_start;
            Some((overlap_start, overlap_end, entry))
        }
    }
}

#[derive(Debug, Clone, Copy)]
enum RangeOverlap {
    /// The range that we compared overlaps partially overlaps with the target range
    Partial(u64, u64),

    /// The range that we compared fully contains the current range
    Full,
}

impl RangeOverlap {
    pub fn get(self, range: Range) -> (u64, u64) {
        match self {
            RangeOverlap::Partial(start, end) => (start, end),
            RangeOverlap::Full => (range.start, range.end),
        }
    }

    pub fn get_with_len(self, range: (u64, u64)) -> (u64, u64) {
        match self {
            RangeOverlap::Partial(start, end) => (start, (end - start) + 1),
            RangeOverlap::Full => (range.0, (range.1 - range.0) + 1),
        }
    }
}

fn get_overlapping(a: Range, b: Range) -> Option<RangeOverlap> {
    if b.start >= a.end || b.end <= a.start {
        None
    }
    else if b.end >= a.end && b.start <= a.start {
        Some(RangeOverlap::Full)
    }
    else {
        Some(RangeOverlap::Partial(a.start.max(b.start), a.end.min(b.end)))
    }
}

fn get_overlapping_range_inclusive(
    (a_start, a_end): (u64, u64),
    (b_start, b_end): (u64, u64),
) -> Option<RangeOverlap> {
    if b_start > a_end || b_end < a_start {
        None
    }
    else if b_end >= a_end && b_start <= a_start {
        Some(RangeOverlap::Full)
    }
    else {
        Some(RangeOverlap::Partial(a_start.max(b_start), a_end.min(b_end)))
    }
}

pub struct VecRangeMap<T> {
    /// The starting value of all ranges in the map. Note: this is stored in a separate allocation
    /// to `data` to improve the cache locality of starts for the `find_range_before` method.
    starts: Vec<u64>,
    /// The ending address and metadata for each of the ranges.
    data: Vec<(u64, T)>,
}

impl<T> Default for VecRangeMap<T> {
    fn default() -> Self {
        Self { starts: vec![], data: vec![] }
    }
}

impl<T: Clone> Clone for VecRangeMap<T> {
    fn clone(&self) -> Self {
        Self { starts: self.starts.clone(), data: self.data.clone() }
    }

    fn clone_from(&mut self, source: &Self) {
        self.starts.clone_from(&source.starts);
        self.data.clone_from(&source.data);
    }
}

impl<T> std::fmt::Debug for VecRangeMap<T>
where
    T: std::fmt::Debug,
{
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let mut map = f.debug_map();
        for (start, end, data) in self.iter() {
            map.entry(&(start..=end), &data);
        }
        map.finish()
    }
}

impl<T> VecRangeMap<T> {
    fn start_end(&self, i: usize) -> (u64, u64) {
        (self.starts[i], self.data[i].0)
    }

    fn data(&self, i: usize) -> &T {
        &self.data[i].1
    }

    fn get_start_end_mut(&mut self, i: usize) -> Option<(&mut u64, &mut u64)> {
        Some((self.starts.get_mut(i)?, self.data.get_mut(i).map(|(end, _)| end)?))
    }

    /// Returns an iterator over all ranges in the map.
    pub fn iter(&self) -> impl Iterator<Item = (u64, u64, &T)> {
        self.starts.iter().zip(&self.data).map(|(start, (end, data))| (*start, *end, data))
    }

    /// Returns an iterator over all ranges in the map with mutable references to data.
    pub fn iter_mut(&mut self) -> impl Iterator<Item = (u64, u64, &mut T)> {
        self.starts.iter_mut().zip(&mut self.data).map(|(start, (end, data))| (*start, *end, data))
    }
}

impl<T> VecRangeMap<T>
where
    T: Clone + Eq + PartialEq,
{
    pub fn new() -> Self {
        Self::default()
    }

    pub fn clear(&mut self) {
        self.starts.clear();
        self.data.clear();
    }

    /// Returns the position such that all elements before this position end before `index`.
    #[inline(always)]
    fn lower_bound(&self, index: u64) -> usize {
        self.data.binary_search_by_key(&index, |(end, _)| *end).map_or_else(|x| x, |x| x)
    }

    /// Returns the position such that all elements before this position start after `index`.
    #[inline(always)]
    fn upper_bound(&self, index: u64) -> usize {
        self.starts.binary_search(&index).unwrap_or_else(|x| x)
    }

    /// Find the last range that starts before `index`. If there is no range before `index` then
    /// this function returns `None`.
    #[inline(always)]
    fn find_range_before(&self, index: u64) -> Option<usize> {
        match self.starts.binary_search(&index) {
            Ok(idx) => Some(idx),
            Err(insertion_idx) => insertion_idx.checked_sub(1),
        }
    }

    /// Gets the data associated with range containing `index`.
    pub fn get(&self, index: u64) -> Option<&T> {
        let (_, _, data) = self.get_with_range(index)?;
        Some(data)
    }

    pub fn get_with_range(&self, index: u64) -> Option<(u64, u64, &T)> {
        let i = self.find_range_before(index)?;
        // Saftey: `find_range_before` always returns either `None` or a in-bounds index.
        let (start, (end, data)) =
            unsafe { (self.starts.get_unchecked(i), self.data.get_unchecked(i)) };
        debug_assert!(*start <= index);
        if *end < index {
            return None;
        }
        Some((*start, *end, data))
    }

    pub fn insert(&mut self, range: impl RangeIndex, data: T) -> Result<(), OverlapError<T>> {
        self.insert_inclusive(range.to_inclusive(), data)
    }

    pub fn insert_inclusive(
        &mut self,
        (start, end): (u64, u64),
        data: T,
    ) -> Result<(), OverlapError<T>> {
        let i = self.find_range_before(start);
        let mut merged = false;

        // Check for overlap with the range before the insertion.
        if let Some(i) = i {
            let (prev_end, prev_data) = &self.data[i];
            match start.cmp(prev_end) {
                std::cmp::Ordering::Less | std::cmp::Ordering::Equal => {
                    return Err(OverlapError { data, overlap: (start, *prev_end) });
                }
                std::cmp::Ordering::Greater if start == *prev_end + 1 && prev_data == &data => {
                    // We can merge the region that is being inserted with the previous region in
                    // the range map. However, we need to ensure that we will succeed in checking
                    // the overlap with the next element before we modify the current range.
                    if self.starts.get(i + 1).map_or(true, |next_start| end < *next_start) {
                        merged = true;
                        self.data[i].0 = end;
                    }
                }
                std::cmp::Ordering::Greater => {
                    // The new range should be inserted after this range.
                }
            }
        }

        // Check for overlap with the range after the insertion.
        let next_i = i.map_or(0, |x| x + 1);
        if let Some(next_start) = self.starts.get(next_i) {
            debug_assert!(self.data.len() > next_i);
            // Safety: if `next_start` was found then the corresponding entry in data is valid.
            let (next_end, next_data) = unsafe { self.data.get_unchecked(next_i) };

            match next_start.cmp(&end) {
                std::cmp::Ordering::Less | std::cmp::Ordering::Equal => {
                    return Err(OverlapError { data, overlap: (*next_start, end) });
                }
                std::cmp::Ordering::Greater if *next_start == end + 1 && next_data == &data => {
                    if merged {
                        // If already merged the new range then this range joins with the
                        // previous.
                        self.data[i.unwrap()].0 = *next_end;
                        self.starts.remove(next_i);
                        self.data.remove(next_i);
                    }
                    else {
                        self.starts[next_i] = start;
                    }
                    return Ok(());
                }
                _ => {
                    // New range should be inserted before this range.
                }
            }
        }

        if !merged {
            // Insert the range here if we failed to merge it with a previous range.
            self.starts.insert(next_i, start);
            self.data.insert(next_i, (end, data));
        }

        Ok(())
    }

    /// Removes the last overlapping entry in the mapping that overlap with `range`
    ///
    /// Returns the range removed any data associated with the removed range.
    pub fn remove_last(&mut self, range: impl RangeIndex) -> Option<(T, (u64, u64))> {
        let (i, overlap) = self.get_overlap(range)?;
        self.remove_subrange(i, overlap)
    }

    fn remove_subrange(&mut self, i: usize, overlap: RangeOverlap) -> Option<(T, (u64, u64))> {
        match overlap {
            RangeOverlap::Partial(overlap_start, overlap_end) => {
                let start = &mut self.starts[i];
                let (end, data) = &mut self.data[i];
                let data = data.clone();

                if *start == overlap_start {
                    *start = overlap_end + 1;
                }
                else if *end == overlap_end {
                    *end = overlap_start - 1;
                }
                else {
                    // If removing the target range splits the removed range into two parts, we
                    // adjust the lower half and insert a new range to represent the upper half.
                    let upper_end = *end;
                    *end = overlap_start - 1;
                    self.starts.insert(i + 1, overlap_end + 1);
                    self.data.insert(i + 1, (upper_end, data.clone()));
                }

                Some((data, (overlap_start, overlap_end)))
            }
            RangeOverlap::Full => {
                let start = self.starts.remove(i);
                let (end, data) = self.data.remove(i);
                Some((data, (start, end)))
            }
        }
    }

    /// Removes all entries in the mapping that overlap with `range`
    pub fn remove_all(&mut self, range: impl RangeIndex) {
        self.remove_all_inclusive(range.to_inclusive());
    }

    pub fn remove_all_inclusive(&mut self, (target_start, target_end): (u64, u64)) {
        // Elements before this index end before the target range starts.
        let mut lower_bound = self.lower_bound(target_start);
        // Elements after this index start after the target range ends.
        let mut upper_bound = match target_end.checked_add(1) {
            Some(end) => self.upper_bound(end),
            None => self.starts.len(),
        };

        debug_assert!(
            lower_bound <= upper_bound,
            "remove all {target_start:#x}..={target_end:#x} => lower_bound={lower_bound}, upper_bound={upper_bound}"
        );

        // If the range only contains a single element then we could be removing the middle of a
        // range, so check it here and handle it as a special case.
        if lower_bound == upper_bound {
            return;
        }

        if lower_bound + 1 == upper_bound {
            let start = self.starts[lower_bound];
            let (end, _) = &self.data[lower_bound];
            if let Some(overlap) =
                get_overlapping_range_inclusive((start, *end), (target_start, target_end))
            {
                self.remove_subrange(lower_bound, overlap);
            }
            return;
        }

        // Adjust ranges that partially overlap with the range we are removing:
        if let Some((start, end)) = self.get_start_end_mut(lower_bound) {
            if *start < target_start {
                *end = target_start - 1;
                lower_bound += 1;
            }
        }
        if let Some((start, end)) = self.get_start_end_mut(upper_bound.saturating_sub(1)) {
            if target_end < *end {
                *start = target_end + 1;
                upper_bound -= 1;
            }
        }

        // Then remove all fully overlapping ranges.
        if lower_bound < upper_bound {
            let _ = self.starts.drain(lower_bound..upper_bound);
            let _ = self.data.drain(lower_bound..upper_bound);
        }
    }

    /// Returns an iterator over all the entries in the map that overlap with `range`.
    pub fn overlapping_iter(
        &self,
        range: impl RangeIndex,
    ) -> impl Iterator<Item = (u64, u64, Option<&T>)> {
        let mut cursor = VecRangeMapCursor::new(self, range.to_inclusive());
        std::iter::from_fn(move || {
            let (start, len, i) = cursor.next(self)?;
            Some((start, len, i.map(|i| &self.data[i].1)))
        })
    }

    /// Execute `func` for each mapped entry and gap between `range`, allowing modification of each
    /// entry.
    pub fn overlapping_mut<F, E>(&mut self, range: impl RangeIndex, mut func: F) -> Result<(), E>
    where
        F: FnMut(u64, u64, &mut Option<T>) -> Result<(), E>,
    {
        let mut iter = VecRangeSplitIterMut::new(self, range.to_inclusive());
        let result = loop {
            match iter.step(&mut func) {
                Ok(true) => {}
                Ok(false) => break Ok(()),
                Err(e) => break Err(e),
            }
        };
        iter.apply_updates();
        result
    }

    /// Gets the last range that overlaps with `target`
    pub fn get_range(&self, target: impl RangeIndex) -> Option<(u64, u64)> {
        self.get_overlap(target).map(|(i, _)| self.start_end(i))
    }

    /// Finds the overlap of `target` with an existing range.
    ///
    /// Note: If there is more more than one overlapping range the last one will be returned
    fn get_overlap(&self, target: impl RangeIndex) -> Option<(usize, RangeOverlap)> {
        let target = target.to_inclusive();
        let i = self.find_range_before(target.1)?;
        let (start, end) = self.start_end(i);
        let overlapping = get_overlapping_range_inclusive((start, end), target)?;
        Some((i, overlapping))
    }

    #[allow(unused)]
    fn debug_map(&self) -> String {
        let map = self
            .iter()
            .map(|(start, end, _)| format!("    range={start:#x}..={end:#x},"))
            .collect::<Vec<_>>()
            .join("\n");
        format!("{{\n{map}\n}}")
    }

    #[inline]
    pub fn len(&self) -> usize {
        self.starts.len()
    }
}

/// An iterator over the entries that overlap with a particular range, handling partial overlaps by
/// splitting the range
struct VecRangeSplitIterMut<'a, T> {
    cursor: VecRangeMapCursor,
    map: &'a mut VecRangeMap<T>,
    removals: Vec<(u64, u64)>,
    additions: Vec<(u64, u64, T)>,
}

impl<'a, T: Clone + Eq + PartialEq> VecRangeSplitIterMut<'a, T> {
    fn new(map: &'a mut VecRangeMap<T>, range: (u64, u64)) -> Self {
        let cursor = VecRangeMapCursor::new(map, range);
        Self { cursor, map, removals: vec![], additions: vec![] }
    }

    fn step<U>(
        &mut self,
        mut modify: impl FnMut(u64, u64, &mut Option<T>) -> Result<(), U>,
    ) -> Result<bool, U> {
        let Some((overlap_start, overlap_len, existing_slot)) = self.cursor.next(self.map)
        else {
            return Ok(false);
        };

        match existing_slot {
            Some(i) => {
                let mut data = Some(self.map.data(i).clone());
                modify(overlap_start, overlap_len, &mut data)?;

                if data.as_ref() != Some(&self.map.data(i)) {
                    // If data has been modified, the register a removal and insertion. (Note:
                    // currently we never perform in place modifications to so
                    // that regions are merged correctly).
                    self.removals.push((overlap_start, overlap_len));
                    if let Some(data) = data {
                        self.additions.push((overlap_start, overlap_len, data));
                    }
                }
            }
            None => {
                let mut data = None;
                modify(overlap_start, overlap_len, &mut data)?;
                if let Some(data) = data {
                    self.additions.push((overlap_start, overlap_len, data));
                }
            }
        }

        Ok(true)
    }

    fn apply_updates(self) {
        for (start, len) in self.removals {
            let end = start + (len - 1);
            self.map.remove_all(start..=end);
        }

        for (start, len, data) in self.additions {
            let end = start + (len - 1);
            if let Err(err) = self.map.insert(start..=end, data) {
                panic!(
                    "VecRangeMap insert at ({start:#x}..={end:#x}) was invalid (overlap with: {:#x}..={:#x})",
                    err.overlap.0, err.overlap.1
                );
            }
        }
    }
}

struct VecRangeMapCursor {
    start: u64,
    len: u64,
    i: usize,
}

impl VecRangeMapCursor {
    pub fn new<T>(map: &VecRangeMap<T>, (start, end): (u64, u64)) -> Self
    where
        T: Clone + Eq + PartialEq,
    {
        let i = match end.checked_add(1) {
            Some(end) => map.upper_bound(end),
            None => map.len(),
        };
        Self { start, len: (end - start) + 1, i }
    }

    pub fn next<T>(&mut self, map: &VecRangeMap<T>) -> Option<(u64, u64, Option<usize>)> {
        if self.len == 0 {
            return None;
        }
        let current_end = self.start + (self.len - 1);

        let i = match self.i.checked_sub(1) {
            Some(i) => i,
            None => {
                // Final region occurs before the start of the range.
                let rest = self.len;
                self.len = 0;
                return Some((self.start, rest, None));
            }
        };

        let entry = map.start_end(i);

        // Determine the amount we overlap with this range.
        let range = (self.start, current_end);
        let (overlap_start, overlap_len) =
            match get_overlapping_range_inclusive(range, (entry.0, entry.1)) {
                Some(overlap) => overlap.get_with_len(range),
                None => (self.start, 0),
            };

        let region_len = (current_end - overlap_start) + 1;
        let gap_len = region_len - overlap_len;

        if gap_len != 0 {
            // There was a gap between the next entry and the previous entry:
            self.len -= gap_len;
            Some((overlap_start + overlap_len, gap_len, None))
        }
        else {
            self.len -= region_len;
            self.i -= 1;
            Some((overlap_start, region_len, Some(i)))
        }
    }
}

#[test]
fn simple() {
    let mut map = RangeMap::new();
    map.insert(0x1000..0x2000, 1).unwrap();
    assert_eq!(map.get(0x1000), Some(&1));
}

#[test]
fn remove_range_all() {
    let mut map = RangeMap::new();
    map.insert(0x1000..0x1001, 1).unwrap();
    map.remove_all(0x1000..0x1001);
    assert_eq!(map.get(0x1000), None);

    let mut map = RangeMap::new();
    map.insert(0x1000..0x2000, 1).unwrap();
    map.remove_all(0x1000..0x2000);
    assert_eq!(map.get(0x1000), None);

    let mut map = RangeMap::new();
    map.insert(0x1000..0x2000, 1).unwrap();
    map.remove_all(0x1100..0x1200);
    assert_eq!(map.get(0x1000), Some(&1));
    assert_eq!(map.get(0x1100), None);
    assert_eq!(map.get(0x1200), Some(&1));

    let mut map = RangeMap::new();
    map.insert(0x1000..0x2000, 1).unwrap();
    map.remove_all(0x1000..0x1500);
    eprintln!("{:#x?}", map);
    assert_eq!(map.get(0x1000), None);
    assert_eq!(map.get(0x1100), None);
    assert_eq!(map.get(0x1500), Some(&1));
}

#[test]
fn remove_last() {
    let mut map = RangeMap::new();
    map.insert(0x1000..0x2000, 1).unwrap();
    map.insert(0x2000..0x3000, 2).unwrap();

    // Remove the first element.
    map.remove_last(0x1000..0x2000);
    assert_eq!(map.len(), 1);
    assert_eq!(map.get(0x0), None);
}

#[test]
fn overlapping_iter() {
    let mut map = RangeMap::new();
    map.insert(0x1000..0x2000, 1).unwrap();
    map.insert(0x2000..0x3000, 2).unwrap();
    map.insert(0x4000..0x5000, 3).unwrap();

    assert_eq!(map.overlapping_iter(0x0000..0x6000).collect::<Vec<_>>(), vec![
        (0x5000, 0x1000, None),
        (0x4000, 0x1000, Some(&3)),
        (0x3000, 0x1000, None),
        (0x2000, 0x1000, Some(&2)),
        (0x1000, 0x1000, Some(&1)),
        (0x0000, 0x1000, None),
    ]);

    assert_eq!(map.overlapping_iter(0x4500..0x5500).collect::<Vec<_>>(), vec![
        (0x5000, 0x500, None),
        (0x4500, 0xb00, Some(&3))
    ]);

    assert_eq!(map.overlapping_iter(0x1500..0x2500).collect::<Vec<_>>(), vec![
        (0x2000, 0x500, Some(&2)),
        (0x1500, 0xb00, Some(&1)),
    ]);
}

#[test]
fn overlapping_iter_mut() {
    let mut map = RangeMap::new();
    map.insert(0x1000..0x2000, 1).unwrap();

    // Check that we can get access to a region inside of without removing it
    map.overlapping_mut::<_, ()>(0x1100..0x1200, |start, len, entry| {
        assert_eq!(start, 0x1100);
        assert_eq!(len, 0x100);
        assert_eq!(*entry, Some(1));
        Ok(())
    })
    .unwrap();
    assert_eq!(map.get(0x1100), Some(&1));
    assert_eq!(map.len(), 1);

    // Check that handle ranges that cross multiple entries.
    map.insert(0x2000..0x3000, 2).unwrap();
    map.overlapping_mut::<_, ()>(0x1900..0x2200, |_, _, _| Ok(())).unwrap();

    eprintln!("{:#x?}", map);
    assert_eq!(map.get(0x1900), Some(&1));
    assert_eq!(map.get(0x2000), Some(&2));
    assert_eq!(map.len(), 2);

    // Check for modifications around boundary conditions
    let mut map = RangeMap::new();
    map.insert(0x10000..0x11000, 1).unwrap();
    map.insert(0x11000..0x12000, 2).unwrap();
    map.insert(0x12000..0x13000, 3).unwrap();

    map.overlapping_mut(0x10000..0x11000, |_, _, x| x.as_mut().map(|x| *x += 10).ok_or(()))
        .unwrap();
    assert_eq!(map.get(0x10000), Some(&11));

    // Check for modifications with gaps
    let mut map = RangeMap::new();
    map.insert(0x0..0x1000, 1).unwrap();
    map.insert(0x200000..0x600000, 2).unwrap();
    map.overlapping_mut(0x200000..0x400000, |_, _, x| x.as_mut().map(|x| *x += 10).ok_or(()))
        .unwrap();

    eprintln!("{:#x?}", map);
    assert_eq!(map.overlapping_iter(0x0..0x600000).collect::<Vec<_>>(), vec![
        (0x400000, 0x200000, Some(&2)),
        (0x200000, 0x200000, Some(&12)),
        (0x1000, 0x1ff000, None),
        (0x0, 0x1000, Some(&1)),
    ]);

    // Check that we can insert new elements
    let mut map = RangeMap::new();
    map.insert(0x0..0x1000, 1).unwrap();
    map.insert(0x200000..0x800000, 2).unwrap();
    map.overlapping_mut::<_, ()>(0x1000..0x2000, |_, _, x| {
        *x = Some(10);
        Ok(())
    })
    .unwrap();
    assert_eq!(map.get(0x1000), Some(&10));
}

#[test]
fn overlapping_iter_mut_insert_boundaries() {
    let mut map = RangeMap::new();
    map.insert(0x1..0x1001, 1).unwrap();

    map.overlapping_mut::<_, ()>(0x1..0x1000, |_, _, value| {
        *value = Some(2);
        Ok(())
    })
    .unwrap();
    eprintln!("{:#x?}", map);
    map.overlapping_mut::<_, ()>(0x1000..0x1001, |_, _, value| {
        *value = Some(3);
        Ok(())
    })
    .unwrap();
    assert_eq!(map.get(0xfff), Some(&2));
    assert_eq!(map.get(0x1000), Some(&3));
}

#[test]
fn overlapping_iter_mut_one() {
    let mut map = RangeMap::new();
    map.insert(0x1000..0x2000, 1).unwrap();

    map.overlapping_mut::<_, ()>(0x1000..=0x1000, |start, len, value| {
        assert_eq!(start, 0x1000);
        assert_eq!(len, 0x1);
        assert_eq!(*value, Some(1));
        Ok(())
    })
    .unwrap();
}

#[test]
fn overlapping_iter_mut_nothing() {
    let mut map = RangeMap::new();
    map.insert(0x0..0x1000, 1).unwrap();

    map.overlapping_mut::<_, ()>(0x10000..=0x10fff, |start, len, value| {
        assert_eq!(start, 0x10000);
        assert_eq!(len, 0x1000);
        assert_eq!(*value, None);
        Ok(())
    })
    .unwrap();
}

#[test]
fn modify_middle() {
    // Ensure that we can modify a subrange of an entry.
    let mut map = RangeMap::new();
    map.insert(0x1000..0x2000, 1).unwrap();
    map.overlapping_mut::<_, ()>(0x1050..0x1150, |_, _, x| x.as_mut().map(|x| *x = 2).ok_or(()))
        .unwrap();
    eprintln!("{map:#0x?}");
    assert_eq!(map.get(0x1000), Some(&1));
    assert_eq!(map.get(0x1050), Some(&2));
    assert_eq!(map.get(0x1150), Some(&1));

    // Ensure we can modify a range crossing multiple entries.
    let _ = map
        .overlapping_mut::<_, ()>(0x1000..0x2000, |_, _, x| x.as_mut().map(|x| *x += 10).ok_or(()));
    eprintln!("{map:#0x?}");

    assert_eq!(map.get(0x1000), Some(&11));
    assert_eq!(map.get(0x1050), Some(&12));
    assert_eq!(map.get(0x1150), Some(&11));
}

#[test]
fn remove_range_all_complex() {
    #[cfg(test)]
    fn init_map() -> VecRangeMap<i32> {
        let mut map = RangeMap::new();
        map.insert(0x1000..0x2000, 1).unwrap();
        map.insert(0x2000..0x3000, 2).unwrap();
        map.insert(0x4000..0x5000, 3).unwrap();
        map
    }

    // Remove none
    let mut map = init_map();
    eprintln!("{:#x?}", map);
    map.remove_all(0x0..0x1000);
    assert_eq!(map.iter().collect::<Vec<_>>(), vec![
        (0x1000, 0x1fff, &1),
        (0x2000, 0x2fff, &2),
        (0x4000, 0x4fff, &3)
    ]);

    // Remove all
    let mut map = init_map();
    map.remove_all(0x1000..0x5000);
    assert_eq!(map.iter().collect::<Vec<_>>(), vec![]);

    // Remove first
    let mut map = init_map();
    map.remove_all(0x1000..0x2000);
    assert_eq!(map.iter().collect::<Vec<_>>(), vec![(0x2000, 0x2fff, &2), (0x4000, 0x4fff, &3)]);

    // Remove last
    let mut map = init_map();
    map.remove_all(0x4000..0x5000);
    assert_eq!(map.iter().collect::<Vec<_>>(), vec![(0x1000, 0x1fff, &1), (0x2000, 0x2fff, &2)]);

    // Remove middle
    let mut map = init_map();
    map.remove_all(0x2000..0x3000);
    assert_eq!(map.iter().collect::<Vec<_>>(), vec![(0x1000, 0x1fff, &1), (0x4000, 0x4fff, &3)]);
}
