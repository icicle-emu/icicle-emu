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

pub struct VecRangeMap<T> {
    ranges: Vec<(u64, u64, T)>,
}

impl<T> Default for VecRangeMap<T> {
    fn default() -> Self {
        Self { ranges: vec![] }
    }
}

impl<T: Clone> Clone for VecRangeMap<T> {
    fn clone(&self) -> Self {
        Self { ranges: self.ranges.clone() }
    }

    fn clone_from(&mut self, source: &Self) {
        self.ranges.clone_from(&source.ranges)
    }
}

impl<T> std::fmt::Debug for VecRangeMap<T>
where
    T: std::fmt::Debug,
{
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let mut map = f.debug_map();
        for entry in &self.ranges {
            map.entry(&(entry.0..entry.1), &entry.2);
        }
        map.finish()
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
        self.ranges.clear();
    }

    /// Returns the position such that all elements before this position end before `index`.
    #[inline(always)]
    fn lower_bound(&self, index: u64) -> usize {
        self.ranges.binary_search_by_key(&index, |(_, end, _)| *end).unwrap_or_else(|x| x)
    }

    /// Returns the position such that all elements before this position start after `index`.
    #[inline(always)]
    fn upper_bound(&self, index: u64) -> usize {
        self.ranges
            .binary_search_by_key(&index, |(start, _, _)| *start)
            .map(|x| x)
            .unwrap_or_else(|x| x)
    }

    /// Find the last range that starts before `index`. If there is no range before `index` then
    /// this function returns `None`.
    #[inline(always)]
    fn find_range_before(&self, index: u64) -> Option<usize> {
        match self.ranges.binary_search_by_key(&index, |(start, _, _)| *start) {
            Ok(idx) => Some(idx),
            Err(insertion_idx) => insertion_idx.checked_sub(1),
        }
    }

    /// Gets the data associated with range containing `index`.
    pub fn get(&self, index: u64) -> Option<&T> {
        let i = self.find_range_before(index)?;
        let (start, end, data) = self.ranges.get(i)?;
        debug_assert!(*start <= index);
        if *end <= index {
            return None;
        }
        Some(data)
    }

    pub fn insert(&mut self, (start, end): (u64, u64), data: T) -> Result<(), OverlapError<T>> {
        let i = self.find_range_before(start);
        let mut merged = false;

        // Check for overlap with the range before the insertion.
        if let Some(i) = i {
            let (_, prev_end, prev_data) = &self.ranges[i];
            match start.cmp(prev_end) {
                std::cmp::Ordering::Less => {
                    return Err(OverlapError { data, overlap: (start, *prev_end) });
                }
                std::cmp::Ordering::Equal if prev_data == &data => {
                    // Ensure that we will succeed in checking the overlap with the next element
                    // before we modify the current range.
                    if self.ranges.get(i + 1).map_or(true, |(next_start, _, _)| end <= *next_start)
                    {
                        merged = true;
                        self.ranges[i].1 = end;
                    }
                }
                _ => {
                    // The new range should be inserted after this range.
                }
            }
        }

        // Check for overlap with the range after the insertion.
        let next_i = i.map_or(0, |x| x + 1);
        match self.ranges.get(next_i) {
            Some((next_start, next_end, next_data)) => {
                match next_start.cmp(&end) {
                    std::cmp::Ordering::Less => {
                        return Err(OverlapError { data, overlap: (*next_start, end) });
                    }
                    std::cmp::Ordering::Equal if next_data == &data => {
                        if merged {
                            // If already merged the new range then this range joins with the
                            // previous.
                            self.ranges[i.unwrap()].1 = *next_end;
                            self.ranges.remove(next_i);
                        }
                        else {
                            self.ranges[next_i].0 = start;
                        }
                        return Ok(());
                    }
                    _ => {
                        // New range should be inserted before this range.
                    }
                }
            }
            None => {}
        }

        if !merged {
            // Insert the range here if we failed to merge it with a previous range.
            self.ranges.insert(next_i, (start, end, data));
        }

        Ok(())
    }

    /// Removes the last overlapping entry in the mapping that overlap with `range`
    ///
    /// Returns the range removed any data associated with the removed range.
    pub fn remove_last(&mut self, range: (u64, u64)) -> Option<(T, (u64, u64))> {
        let (i, overlap) = self.get_overlap(Range::from(range))?;
        self.remove_subrange(i, overlap)
    }

    fn remove_subrange(&mut self, i: usize, overlap: RangeOverlap) -> Option<(T, (u64, u64))> {
        match overlap {
            RangeOverlap::Partial(overlap_start, overlap_end) => {
                let (start, end, data) = &mut self.ranges[i];
                let data = data.clone();

                if *start == overlap_start {
                    *start = overlap_end;
                }
                else if *end == overlap_end {
                    *end = overlap_start;
                }
                else {
                    // If removing the target range splits the removed range into two parts, we
                    // adjust the lower half and insert a new range to represent the upper half.
                    let upper_end = *end;
                    *end = overlap_start;
                    self.ranges.insert(i + 1, (overlap_end, upper_end, data.clone()));
                }

                Some((data, (overlap_start, overlap_end)))
            }
            RangeOverlap::Full => {
                let (start, end, data) = self.ranges.remove(i);
                Some((data, (start, end)))
            }
        }
    }

    /// Removes all entries in the mapping that overlap with `range`
    pub fn remove_all(&mut self, (target_start, target_end): (u64, u64)) {
        // Elements before this index end before the target range starts.
        let mut lower_bound = self.lower_bound(target_start);
        // Elements after this index start after the target range ends.
        let mut upper_bound = self.upper_bound(target_end + 1);

        debug_assert!(
            lower_bound <= upper_bound,
            "remove all {target_start:#x}..{target_end:#x} => lower_bound={lower_bound}, upper_bound={upper_bound}"
        );

        // If the range only contains a single element then we could be removing the middle of a
        // range, so check it here and handle it as a special case.
        if lower_bound == upper_bound {
            return;
        }
        else if lower_bound + 1 == upper_bound {
            let (start, end, _) = &self.ranges[lower_bound];
            if let Some(overlap) = get_overlapping(
                Range::from((*start, *end)),
                Range::from((target_start, target_end)),
            ) {
                self.remove_subrange(lower_bound, overlap);
            }
            return;
        }

        // Adjust ranges that partially overlap with the range we are removing:
        if let Some((start, end, _)) = self.ranges.get_mut(lower_bound) {
            if *start < target_start {
                *end = target_start;
                lower_bound += 1;
            }
        }
        if let Some((start, end, _)) = self.ranges.get_mut(upper_bound.saturating_sub(1)) {
            if target_end < *end {
                *start = target_end;
                upper_bound -= 1;
            }
        }

        // Then remove all fully overlapping ranges.
        if lower_bound < upper_bound {
            let _ = self.ranges.drain(lower_bound..upper_bound);
        }
    }

    /// Returns an iterator over all ranges in the map.
    pub fn iter(&self) -> impl Iterator<Item = (u64, u64, &T)> {
        self.ranges.iter().map(|(start, end, data)| (*start, *end, data))
    }

    /// Returns an iterator over all ranges in the map with mutable references to data.
    pub fn iter_mut(&mut self) -> impl Iterator<Item = (u64, u64, &mut T)> {
        self.ranges.iter_mut().map(|(start, end, data)| (*start, *end, data))
    }

    /// Returns an iterator over all the entries in the map that overlap with `range`.
    pub fn overlapping_iter(
        &self,
        (start, end): (u64, u64),
    ) -> impl Iterator<Item = (u64, u64, Option<&T>)> {
        let i = self.upper_bound(end);
        let mut cursor = VecRangeMapCursor { start, end, i };
        std::iter::from_fn(move || {
            let (start, end, i) = cursor.next(self)?;
            Some((start, end, i.map(|i| &self.ranges[i].2)))
        })
    }

    /// Execute `func` for each mapped entry and gap between `range`, allowing modification of each
    /// entry.
    pub fn overlapping_mut<F, E>(&mut self, range: (u64, u64), mut func: F) -> Result<(), E>
    where
        F: FnMut(u64, u64, &mut Option<T>) -> Result<(), E>,
    {
        let mut iter = VecRangeSplitIterMut::new(self, range);
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
    pub fn get_range(&self, target: (u64, u64)) -> Option<(u64, u64)> {
        self.get_overlap(Range::from(target)).map(|(i, _)| {
            let (start, end, _) = &self.ranges[i];
            (*start, *end)
        })
    }

    /// Finds the overlap of `target` with an existing range.
    ///
    /// Note: If there is more more than one overlapping range the last one will be returned
    fn get_overlap(&self, target: Range) -> Option<(usize, RangeOverlap)> {
        let i = self.find_range_before(target.end.saturating_sub(1))?;
        let (start, end, _) = &self.ranges[i];
        let overlapping = get_overlapping(Range::from((*start, *end)), target)?;
        Some((i, overlapping))
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
    fn new(map: &'a mut VecRangeMap<T>, (start, end): (u64, u64)) -> Self {
        let i = map.upper_bound(end);
        let cursor = VecRangeMapCursor { start, end, i };
        Self { cursor, map, removals: vec![], additions: vec![] }
    }

    fn step<U>(
        &mut self,
        mut modify: impl FnMut(u64, u64, &mut Option<T>) -> Result<(), U>,
    ) -> Result<bool, U> {
        let Some((overlap_start, overlap_end, existing_slot)) = self.cursor.next(self.map) else {
            return Ok(false);
        };

        match existing_slot {
            Some(i) => {
                let mut data = Some(self.map.ranges[i].2.clone());
                modify(overlap_start, overlap_end, &mut data)?;

                if data.as_ref() != Some(&self.map.ranges[i].2) {
                    // If data has been modified, the register a removal and insertion. (Note:
                    // currently we never perform in place modifications to so
                    // that regions are merged correctly).
                    self.removals.push((overlap_start, overlap_end));
                    if let Some(data) = data {
                        self.additions.push((overlap_start, overlap_end, data));
                    }
                }
            }
            None => {
                let mut data = None;
                modify(overlap_start, overlap_end, &mut data)?;
                if let Some(data) = data {
                    self.additions.push((overlap_start, overlap_end, data));
                }
            }
        }

        Ok(true)
    }

    fn apply_updates(self) {
        for range in self.removals {
            self.map.remove_all(range);
        }

        for (start, end, data) in self.additions {
            if let Err(err) = self.map.insert((start, end), data) {
                panic!(
                    "VecRangeMap update was invalid (overlap with: {:#x}..{:#x})",
                    err.overlap.0, err.overlap.1
                );
            }
        }
    }
}

struct VecRangeMapCursor {
    start: u64,
    end: u64,
    i: usize,
}

impl VecRangeMapCursor {
    pub fn next<T>(&mut self, map: &VecRangeMap<T>) -> Option<(u64, u64, Option<usize>)> {
        if self.start >= self.end {
            return None;
        }

        let i = match self.i.checked_sub(1) {
            Some(i) => i,
            None => {
                // Final region occurs before the start of the range.
                let end = self.end;
                self.end = self.start;
                return Some((self.start, end, None));
            }
        };

        let entry = &map.ranges[i];

        // Determine the amount we overlap with this range.
        let range = Range::from((self.start, self.end));
        let (overlap_start, overlap_end) =
            match get_overlapping(range, Range::from((entry.0, entry.1))) {
                Some(overlap) => overlap.get(range),
                None => (self.start, self.start),
            };

        if overlap_end < self.end {
            // There was a gap between the next entry and the previous entry:
            let end = self.end;
            self.end = overlap_end;
            Some((overlap_end, end, None))
        }
        else {
            self.end = overlap_start;
            self.i -= 1;
            Some((overlap_start, overlap_end, Some(i)))
        }
    }
}

#[test]
fn simple() {
    let mut map = RangeMap::new();
    map.insert((0x1000, 0x2000), 1).unwrap();
    assert_eq!(map.get(0x1000), Some(&1));
}

#[test]
fn remove_range_all() {
    let mut map = RangeMap::new();
    map.insert((0x1000, 0x2000), 1).unwrap();
    map.remove_all((0x1000, 0x2000));
    assert_eq!(map.get(0x1000), None);

    let mut map = RangeMap::new();
    map.insert((0x1000, 0x2000), 1).unwrap();
    map.remove_all((0x1100, 0x1200));
    assert_eq!(map.get(0x1000), Some(&1));
    assert_eq!(map.get(0x1100), None);
    assert_eq!(map.get(0x1200), Some(&1));

    let mut map = RangeMap::new();
    map.insert((0x1000, 0x2000), 1).unwrap();
    map.remove_all((0x1000, 0x1500));
    eprintln!("{:#x?}", map);
    assert_eq!(map.get(0x1000), None);
    assert_eq!(map.get(0x1100), None);
    assert_eq!(map.get(0x1500), Some(&1));
}

#[test]
fn remove_last() {
    let mut map = RangeMap::new();
    map.insert((0x1000, 0x2000), 1).unwrap();
    map.insert((0x2000, 0x3000), 2).unwrap();

    // Remove the first element.
    map.remove_last((0x1000, 0x2000));
    assert_eq!(map.ranges.len(), 1);
    assert_eq!(map.get(0x0), None);
}

#[test]
fn overlapping_iter() {
    let mut map = RangeMap::new();
    map.insert((0x1000, 0x2000), 1).unwrap();
    map.insert((0x2000, 0x3000), 2).unwrap();
    map.insert((0x4000, 0x5000), 3).unwrap();

    assert_eq!(map.overlapping_iter((0x0000, 0x6000)).collect::<Vec<_>>(), vec![
        (0x5000, 0x6000, None),
        (0x4000, 0x5000, Some(&3)),
        (0x3000, 0x4000, None),
        (0x2000, 0x3000, Some(&2)),
        (0x1000, 0x2000, Some(&1)),
        (0x0000, 0x1000, None),
    ]);

    assert_eq!(map.overlapping_iter((0x4500, 0x5500)).collect::<Vec<_>>(), vec![
        (0x5000, 0x5500, None),
        (0x4500, 0x5000, Some(&3))
    ]);

    assert_eq!(map.overlapping_iter((0x1500, 0x2500)).collect::<Vec<_>>(), vec![
        (0x2000, 0x2500, Some(&2)),
        (0x1500, 0x2000, Some(&1)),
    ]);
}

#[test]
fn overlapping_iter_mut() {
    let mut map = RangeMap::new();
    map.insert((0x1000, 0x2000), 1).unwrap();

    // Check that we can get access to a region inside of without removing it
    map.overlapping_mut::<_, ()>((0x1100, 0x1200), |start, end, entry| {
        assert_eq!(start, 0x1100);
        assert_eq!(end, 0x1200);
        assert_eq!(*entry, Some(1));
        Ok(())
    })
    .unwrap();
    assert_eq!(map.get(0x1100), Some(&1));
    assert_eq!(map.ranges.len(), 1);

    // Check that handle ranges that cross multiple entries.
    map.insert((0x2000, 0x3000), 2).unwrap();
    map.overlapping_mut::<_, ()>((0x1900, 0x2200), |_, _, _| Ok(())).unwrap();

    assert_eq!(map.get(0x1900), Some(&1));
    assert_eq!(map.get(0x2000), Some(&2));
    assert_eq!(map.ranges.len(), 2);

    // Check for modifications around boundary conditions
    let mut map = RangeMap::new();
    map.insert((0x10000, 0x11000), 1).unwrap();
    map.insert((0x11000, 0x12000), 2).unwrap();
    map.insert((0x12000, 0x13000), 3).unwrap();

    map.overlapping_mut((0x10000, 0x11000), |_, _, x| x.as_mut().map(|x| *x += 10).ok_or(()))
        .unwrap();
    assert_eq!(map.get(0x10000), Some(&11));

    // Check for modifications with gaps
    let mut map = RangeMap::new();
    map.insert((0x0, 0x1000), 1).unwrap();
    map.insert((0x200000, 0x600000), 2).unwrap();
    map.overlapping_mut((0x200000, 0x400000), |_, _, x| x.as_mut().map(|x| *x += 10).ok_or(()))
        .unwrap();

    eprintln!("{:#x?}", map);
    assert_eq!(map.overlapping_iter((0x0, 0x600000)).collect::<Vec<_>>(), vec![
        (0x400000, 0x600000, Some(&2)),
        (0x200000, 0x400000, Some(&12)),
        (0x1000, 0x200000, None),
        (0x0, 0x1000, Some(&1)),
    ]);

    // Check that we can insert new elements
    let mut map = RangeMap::new();
    map.insert((0x0, 0x1000), 1).unwrap();
    map.insert((0x200000, 0x600000), 2).unwrap();
    map.overlapping_mut::<_, ()>((0x1000, 0x2000), |_, _, x| {
        *x = Some(10);
        Ok(())
    })
    .unwrap();
    assert_eq!(map.get(0x1000), Some(&10));
}

#[test]
fn modify_middle() {
    // Ensure that we can modify a subrange of an entry.
    let mut map = RangeMap::new();
    map.insert((0x1000, 0x2000), 1).unwrap();
    map.overlapping_mut::<_, ()>((0x1050, 0x1150), |_, _, x| x.as_mut().map(|x| *x = 2).ok_or(()))
        .unwrap();
    eprintln!("{map:#0x?}");
    assert_eq!(map.get(0x1000), Some(&1));
    assert_eq!(map.get(0x1050), Some(&2));
    assert_eq!(map.get(0x1150), Some(&1));

    // Ensure we can modify a range crossing multiple entries.
    let _ = map.overlapping_mut::<_, ()>((0x1000, 0x2000), |_, _, x| {
        x.as_mut().map(|x| *x += 10).ok_or(())
    });
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
        map.insert((0x1000, 0x2000), 1).unwrap();
        map.insert((0x2000, 0x3000), 2).unwrap();
        map.insert((0x4000, 0x5000), 3).unwrap();
        map
    }

    // Remove none
    let mut map = init_map();
    eprintln!("{:#x?}", map);
    map.remove_all((0x0, 0x1000));
    assert_eq!(map.iter().collect::<Vec<_>>(), vec![
        (0x1000, 0x2000, &1),
        (0x2000, 0x3000, &2),
        (0x4000, 0x5000, &3)
    ]);

    // Remove all
    let mut map = init_map();
    map.remove_all((0x1000, 0x5000));
    assert_eq!(map.iter().collect::<Vec<_>>(), vec![]);

    // Remove first
    let mut map = init_map();
    map.remove_all((0x1000, 0x2000));
    assert_eq!(map.iter().collect::<Vec<_>>(), vec![(0x2000, 0x3000, &2), (0x4000, 0x5000, &3)]);

    // Remove last
    let mut map = init_map();
    map.remove_all((0x4000, 0x5000));
    assert_eq!(map.iter().collect::<Vec<_>>(), vec![(0x1000, 0x2000, &1), (0x2000, 0x3000, &2)]);

    // Remove middle
    let mut map = init_map();
    map.remove_all((0x2000, 0x3000));
    assert_eq!(map.iter().collect::<Vec<_>>(), vec![(0x1000, 0x2000, &1), (0x4000, 0x5000, &3)]);
}
