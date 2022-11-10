use std::collections::BTreeMap;

/// Note can't use the standard `std::ops::Range` since it is non-copiable
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

/// A data structure where a range of integers is mapped to a specific value
pub struct RangeMap<T> {
    ranges: BTreeMap<u64, RangeMapData<T>>,
}

impl<T> Default for RangeMap<T> {
    fn default() -> Self {
        Self { ranges: Default::default() }
    }
}

impl<T: Clone> Clone for RangeMap<T> {
    fn clone(&self) -> Self {
        Self { ranges: self.ranges.clone() }
    }

    fn clone_from(&mut self, source: &Self) {
        self.ranges.clone_from(&source.ranges)
    }
}

impl<T> std::fmt::Debug for RangeMap<T>
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

impl<T> RangeMap<T>
where
    T: Clone + Eq + PartialEq,
{
    pub fn new() -> Self {
        Self { ranges: BTreeMap::new() }
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
        let (existing, overlap) = self.get_overlap(range.into())?;

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

    /// Execute `func` for each mapped entry and gap between `range`, allowing modification of each
    /// entry.
    pub fn overlapping_mut<F, E>(&mut self, range: (u64, u64), mut func: F) -> Result<(), E>
    where
        F: FnMut(u64, u64, &mut Option<T>) -> Result<(), E>,
    {
        let mut iter = RangeSplitIterMut { start: range.0, end: range.1, map: self };
        while iter.step(&mut func)? {}
        Ok(())
    }

    /// Gets the last range that overlaps with `target`
    pub fn get_range(&self, target: (u64, u64)) -> Option<(u64, u64)> {
        self.get_overlap(Range::from(target)).map(|(range, _)| (range.start, range.end))
    }

    /// Finds the first free region of at least `size` starting at `start` with `alignment`,
    /// returning the start of the region.
    pub fn get_free(&self, mut start: u64, size: u64, alignment: u64) -> Option<u64> {
        while let Some((_, end)) = self.get_range((start, start.checked_add(size)?)) {
            start = crate::align_up(end, alignment);
        }
        Some(start)
    }

    /// Finds the overlap of `target` with an existing range.
    ///
    /// Note: If there is more more than one overlapping range the last one will be returned
    fn get_overlap(&self, target: Range) -> Option<(Range, RangeOverlap)> {
        let (start, entry) = self.ranges.range(..target.end).rev().next()?;

        let range = Range::from((*start, entry.end));

        let overlapping = get_overlapping(range, target)?;
        Some((range, overlapping))
    }
}

/// An iterator over the entries that overlap with a particular range, handling partial overlaps by
/// splitting the range
struct RangeSplitIterMut<'a, T> {
    start: u64,
    end: u64,
    map: &'a mut RangeMap<T>,
}

impl<'a, T: Clone + Eq + PartialEq> RangeSplitIterMut<'a, T> {
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

#[derive(Debug)]
enum RangeOverlap {
    /// The range that we compared overlaps partially overlaps with the target range
    Partial(u64, u64),

    /// The range that we compared fully contains the current range
    Full,
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

#[test]
fn simple() {
    let mut map = RangeMap::new();
    map.insert((0x1000, 0x2000), 1).unwrap();
    assert_eq!(map.get(0x1000), Some(&1));
}

#[test]
fn remove_and_replace() {
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

    map.insert((0x2000, 0x3000), 2).unwrap();
    map.overlapping_mut::<_, ()>((0x1900, 0x2200), |_, _, _| Ok(())).unwrap();

    assert_eq!(map.get(0x1900), Some(&1));
    assert_eq!(map.get(0x2000), Some(&2));
    assert_eq!(map.ranges.len(), 2);
}
