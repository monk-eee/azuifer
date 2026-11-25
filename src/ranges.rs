//! Storage-independent map from logical object offsets to immutable extents (ADR-0015).
//!
//! A [`RangeMap`] never touches bytes. It records which `(extent, extent offset, length)`
//! backs each allocated logical range, so a service can publish a write by streaming
//! into a new immutable extent and then applying [`RangeMap::write`] in one metadata
//! transaction. Unmapped offsets are holes that read as zeros. Page blobs, append
//! blobs, FileREST files, and DFS files share this one primitive; each decides its own
//! bounds, alignment, and ETag rules around it.
//!
//! The map is canonical: touching mappings that continue the same extent are merged,
//! so equal contents compare equal and [`RangeMap::mappings`] is a stable persisted form.

use std::{collections::BTreeMap, ops::Range};

/// Why a range operation was refused. The map is unchanged when one is returned.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum RangeError {
    /// An offset plus length does not fit in a `u64`.
    Overflow,
    /// Stored mappings overlap, are empty, or extend past the logical length.
    Inconsistent,
}

/// One allocated stretch of the logical object.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct Mapping<E> {
    pub(crate) extent: E,
    pub(crate) extent_offset: u64,
    pub(crate) length: u64,
}

/// A piece of a resolved read. Segments are contiguous and in offset order.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) enum Segment<E> {
    Data {
        offset: u64,
        extent: E,
        extent_offset: u64,
        length: u64,
    },
    /// Unallocated bytes; they read as zeros.
    Hole { offset: u64, length: u64 },
}

// Part of the shared range-map surface (ADR-0015); not every service calls each accessor.
#[allow(dead_code)]
impl<E> Segment<E> {
    pub(crate) fn offset(&self) -> u64 {
        match self {
            Self::Data { offset, .. } | Self::Hole { offset, .. } => *offset,
        }
    }

    pub(crate) fn length(&self) -> u64 {
        match self {
            Self::Data { length, .. } | Self::Hole { length, .. } => *length,
        }
    }
}

/// Ranges that differ between two maps, as Azure's incremental range listings report them.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub(crate) struct Diff {
    /// Allocated here and either unallocated or backed by different content before.
    pub(crate) changed: Vec<Range<u64>>,
    /// Allocated before and unallocated now.
    pub(crate) cleared: Vec<Range<u64>>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct RangeMap<E> {
    mappings: BTreeMap<u64, Mapping<E>>,
    length: u64,
}

impl<E> Default for RangeMap<E> {
    fn default() -> Self {
        Self {
            mappings: BTreeMap::new(),
            length: 0,
        }
    }
}

impl<E: Clone + Eq> RangeMap<E> {
    /// An entirely sparse object of `length` bytes.
    pub(crate) fn new(length: u64) -> Self {
        Self {
            mappings: BTreeMap::new(),
            length,
        }
    }

    /// Rebuilds a map from persisted mappings, validating them.
    pub(crate) fn from_mappings(
        length: u64,
        mappings: impl IntoIterator<Item = (u64, Mapping<E>)>,
    ) -> Result<Self, RangeError> {
        let mut map = Self::new(length);
        let mut previous_end = 0;
        let mut sorted: Vec<_> = mappings.into_iter().collect();
        sorted.sort_by_key(|(offset, _)| *offset);
        for (offset, mapping) in sorted {
            let end = offset
                .checked_add(mapping.length)
                .ok_or(RangeError::Overflow)?;
            if mapping.length == 0 || offset < previous_end || end > length {
                return Err(RangeError::Inconsistent);
            }
            mapping
                .extent_offset
                .checked_add(mapping.length)
                .ok_or(RangeError::Overflow)?;
            previous_end = end;
            map.mappings.insert(offset, mapping);
        }
        map.coalesce_all();
        Ok(map)
    }

    /// Logical length in bytes, including trailing holes.
    #[allow(dead_code)] // Shared surface; see `Segment`.
    pub(crate) fn len(&self) -> u64 {
        self.length
    }

    #[allow(dead_code)] // Shared surface; see `Segment`.
    pub(crate) fn is_empty(&self) -> bool {
        self.length == 0
    }

    /// Number of stored mappings, a measure of fragmentation.
    #[allow(dead_code)] // Shared surface; see `Segment`.
    pub(crate) fn mapping_count(&self) -> usize {
        self.mappings.len()
    }

    /// Allocated stretches as `(logical offset, mapping)` in offset order.
    pub(crate) fn mappings(&self) -> impl Iterator<Item = (u64, &Mapping<E>)> {
        self.mappings
            .iter()
            .map(|(offset, mapping)| (*offset, mapping))
    }

    /// Every extent that some range still references; anything else is collectable.
    pub(crate) fn extents(&self) -> impl Iterator<Item = &E> {
        self.mappings.values().map(|mapping| &mapping.extent)
    }

    /// Maps `[offset, offset + length)` to `extent` starting at `extent_offset`,
    /// replacing whatever was mapped there. The logical length grows to cover the
    /// write when it ends past the current end; callers enforce their own bounds.
    pub(crate) fn write(
        &mut self,
        offset: u64,
        length: u64,
        extent: E,
        extent_offset: u64,
    ) -> Result<(), RangeError> {
        let end = offset.checked_add(length).ok_or(RangeError::Overflow)?;
        extent_offset
            .checked_add(length)
            .ok_or(RangeError::Overflow)?;
        if length == 0 {
            return Ok(());
        }
        self.remove(offset, end);
        self.mappings.insert(
            offset,
            Mapping {
                extent,
                extent_offset,
                length,
            },
        );
        self.length = self.length.max(end);
        self.coalesce_around(offset, end);
        Ok(())
    }

    /// Deallocates `[offset, offset + length)` without writing zeros. The logical
    /// length is unchanged, and the part of the range past the end is ignored.
    pub(crate) fn clear(&mut self, offset: u64, length: u64) -> Result<(), RangeError> {
        let end = offset.checked_add(length).ok_or(RangeError::Overflow)?;
        self.remove(offset, end.min(self.length));
        Ok(())
    }

    /// Sets the logical length, trimming mappings past it or extending with a hole.
    pub(crate) fn resize(&mut self, length: u64) {
        if length < self.length {
            self.remove(length, self.length);
        }
        self.length = length;
    }

    /// Splits the stretch `[offset, offset + length)` of the object into data and holes.
    /// The request is clamped to the logical length.
    pub(crate) fn resolve(&self, offset: u64, length: u64) -> Result<Vec<Segment<E>>, RangeError> {
        let end = offset
            .checked_add(length)
            .ok_or(RangeError::Overflow)?
            .min(self.length);
        let mut segments = Vec::new();
        let mut cursor = offset;
        while cursor < end {
            match self.at(cursor) {
                Some((mapping_start, mapping)) => {
                    let skipped = cursor - mapping_start;
                    let take = (mapping.length - skipped).min(end - cursor);
                    segments.push(Segment::Data {
                        offset: cursor,
                        extent: mapping.extent.clone(),
                        extent_offset: mapping.extent_offset + skipped,
                        length: take,
                    });
                    cursor += take;
                }
                None => {
                    let next = self
                        .mappings
                        .range(cursor..)
                        .next()
                        .map_or(end, |(start, _)| (*start).min(end));
                    segments.push(Segment::Hole {
                        offset: cursor,
                        length: next - cursor,
                    });
                    cursor = next;
                }
            }
        }
        Ok(segments)
    }

    /// Allocated ranges in order, with touching mappings (even from different
    /// extents) merged, as `Get Page Ranges` and `List Ranges` report them.
    pub(crate) fn allocated_ranges(&self) -> Vec<Range<u64>> {
        self.allocated_ranges_in(0, self.length)
    }

    /// Like [`Self::allocated_ranges`] but only within `[offset, offset + length)`.
    pub(crate) fn allocated_ranges_in(&self, offset: u64, length: u64) -> Vec<Range<u64>> {
        let end = offset.saturating_add(length).min(self.length);
        let mut ranges: Vec<Range<u64>> = Vec::new();
        if offset >= end {
            return ranges;
        }
        let first = self.at(offset).map_or(offset, |(start, _)| start);
        for (start, mapping) in self.mappings.range(first..end) {
            let range = (*start).max(offset)..(*start + mapping.length).min(end);
            match ranges.last_mut() {
                Some(last) if last.end == range.start => last.end = range.end,
                _ => ranges.push(range),
            }
        }
        ranges
    }

    /// Total allocated bytes.
    pub(crate) fn allocated_bytes(&self) -> u64 {
        self.mappings.values().map(|mapping| mapping.length).sum()
    }

    /// Compares with an earlier state of the same object. Content is the same when it
    /// maps to the same extent bytes, which is exact because extents are immutable.
    pub(crate) fn diff(&self, previous: &Self) -> Diff {
        let mut points: Vec<u64> = [self, previous]
            .iter()
            .flat_map(|map| {
                map.mappings
                    .iter()
                    .flat_map(|(start, mapping)| [*start, *start + mapping.length])
            })
            .collect();
        points.sort_unstable();
        points.dedup();
        let mut diff = Diff::default();
        for pair in points.windows(2) {
            let (start, end) = (pair[0], pair[1]);
            let now = self.content_at(start);
            let before = previous.content_at(start);
            let target = match (&now, &before) {
                (Some(now), Some(before)) if now == before => None,
                (Some(_), _) => Some(&mut diff.changed),
                (None, Some(_)) => Some(&mut diff.cleared),
                (None, None) => None,
            };
            if let Some(ranges) = target {
                match ranges.last_mut() {
                    Some(last) if last.end == start => last.end = end,
                    _ => ranges.push(start..end),
                }
            }
        }
        diff
    }

    fn content_at(&self, offset: u64) -> Option<(&E, u64)> {
        self.at(offset)
            .map(|(start, mapping)| (&mapping.extent, mapping.extent_offset + (offset - start)))
    }

    /// The mapping containing `offset`, with its logical start.
    fn at(&self, offset: u64) -> Option<(u64, &Mapping<E>)> {
        let (start, mapping) = self.mappings.range(..=offset).next_back()?;
        (*start + mapping.length > offset).then_some((*start, mapping))
    }

    /// Removes `[start, end)` from the map, keeping the outside parts of boundary mappings.
    fn remove(&mut self, start: u64, end: u64) {
        if start >= end {
            return;
        }
        let first = self.at(start).map_or(start, |(offset, _)| offset);
        let touched: Vec<u64> = self.mappings.range(first..end).map(|(k, _)| *k).collect();
        for key in touched {
            let Some(mapping) = self.mappings.remove(&key) else {
                continue;
            };
            let mapping_end = key + mapping.length;
            if key < start {
                self.mappings.insert(
                    key,
                    Mapping {
                        extent: mapping.extent.clone(),
                        extent_offset: mapping.extent_offset,
                        length: start - key,
                    },
                );
            }
            if mapping_end > end {
                self.mappings.insert(
                    end,
                    Mapping {
                        extent: mapping.extent,
                        extent_offset: mapping.extent_offset + (end - key),
                        length: mapping_end - end,
                    },
                );
            }
        }
    }

    /// Merges the mapping at `start` with neighbours that continue the same extent.
    fn coalesce_around(&mut self, start: u64, end: u64) {
        let previous = self
            .mappings
            .range(..start)
            .next_back()
            .map(|(offset, _)| *offset);
        let from = previous.unwrap_or(start);
        let to = self
            .mappings
            .range(end..)
            .next()
            .map_or(end, |(offset, mapping)| *offset + mapping.length);
        self.coalesce_range(from, to);
    }

    fn coalesce_all(&mut self) {
        self.coalesce_range(0, self.length);
    }

    fn coalesce_range(&mut self, from: u64, to: u64) {
        let keys: Vec<u64> = self.mappings.range(from..to).map(|(k, _)| *k).collect();
        let mut current: Option<u64> = None;
        for key in keys {
            let Some(head) = current else {
                current = Some(key);
                continue;
            };
            let joins = match (self.mappings.get(&head), self.mappings.get(&key)) {
                (Some(left), Some(right)) => {
                    head + left.length == key
                        && left.extent == right.extent
                        && left.extent_offset + left.length == right.extent_offset
                }
                _ => false,
            };
            if joins {
                if let Some(right) = self.mappings.remove(&key)
                    && let Some(left) = self.mappings.get_mut(&head)
                {
                    left.length += right.length;
                }
            } else {
                current = Some(key);
            }
        }
    }
}

#[cfg(test)]
// Single-range expectations are the point of these tests.
#[allow(clippy::single_range_in_vec_init)]
mod tests {
    use super::*;

    type Map = RangeMap<u32>;

    fn data(offset: u64, extent: u32, extent_offset: u64, length: u64) -> Segment<u32> {
        Segment::Data {
            offset,
            extent,
            extent_offset,
            length,
        }
    }

    fn hole(offset: u64, length: u64) -> Segment<u32> {
        Segment::Hole { offset, length }
    }

    #[test]
    fn new_map_is_one_hole() {
        let map = Map::new(10);
        assert_eq!(map.resolve(0, 10).unwrap(), [hole(0, 10)]);
        assert!(map.allocated_ranges().is_empty());
        assert_eq!(map.allocated_bytes(), 0);
        assert!(Map::default().is_empty());
    }

    #[test]
    fn write_maps_a_range_and_reads_back_with_holes() {
        let mut map = Map::new(20);
        map.write(5, 5, 1, 0).unwrap();
        assert_eq!(
            map.resolve(0, 20).unwrap(),
            [hole(0, 5), data(5, 1, 0, 5), hole(10, 10)]
        );
        assert_eq!(map.allocated_ranges(), [5..10]);
    }

    #[test]
    fn write_past_the_end_extends_the_length() {
        let mut map = Map::new(4);
        map.write(10, 6, 1, 0).unwrap();
        assert_eq!(map.len(), 16);
        assert_eq!(map.resolve(0, 100).unwrap().len(), 2);
    }

    #[test]
    fn overwrite_splits_the_surrounding_mapping_and_keeps_extent_offsets() {
        let mut map = Map::new(10);
        map.write(0, 10, 1, 100).unwrap();
        map.write(3, 2, 2, 0).unwrap();
        assert_eq!(
            map.resolve(0, 10).unwrap(),
            [data(0, 1, 100, 3), data(3, 2, 0, 2), data(5, 1, 105, 5)]
        );
        assert_eq!(map.mapping_count(), 3);
    }

    #[test]
    fn overwrite_covering_several_mappings_replaces_them() {
        let mut map = Map::new(30);
        map.write(0, 10, 1, 0).unwrap();
        map.write(10, 10, 2, 0).unwrap();
        map.write(20, 10, 3, 0).unwrap();
        map.write(5, 20, 4, 0).unwrap();
        assert_eq!(
            map.resolve(0, 30).unwrap(),
            [data(0, 1, 0, 5), data(5, 4, 0, 20), data(25, 3, 5, 5)]
        );
    }

    #[test]
    fn adjacent_writes_to_different_extents_stay_separate_but_report_one_range() {
        let mut map = Map::new(8);
        map.write(0, 4, 1, 0).unwrap();
        map.write(4, 4, 2, 0).unwrap();
        assert_eq!(map.mapping_count(), 2);
        assert_eq!(map.allocated_ranges(), [0..8]);
    }

    #[test]
    fn contiguous_pieces_of_one_extent_merge() {
        let mut map = Map::new(8);
        map.write(0, 4, 1, 0).unwrap();
        map.write(4, 4, 1, 4).unwrap();
        assert_eq!(map.mapping_count(), 1);
        map.write(2, 4, 2, 0).unwrap();
        assert_eq!(map.mapping_count(), 3);
        map.write(2, 4, 1, 2).unwrap();
        assert_eq!(map.mapping_count(), 1, "rewriting the same bytes heals");
        assert_eq!(map.resolve(0, 8).unwrap(), [data(0, 1, 0, 8)]);
    }

    #[test]
    fn same_extent_at_a_non_contiguous_offset_does_not_merge() {
        let mut map = Map::new(8);
        map.write(0, 4, 1, 0).unwrap();
        map.write(4, 4, 1, 100).unwrap();
        assert_eq!(map.mapping_count(), 2);
    }

    #[test]
    fn zero_length_write_changes_nothing() {
        let mut map = Map::new(4);
        map.write(2, 0, 1, 0).unwrap();
        assert_eq!(map.mapping_count(), 0);
        map.write(100, 0, 1, 0).unwrap();
        assert_eq!(map.len(), 4);
    }

    #[test]
    fn clear_punches_holes_and_splits() {
        let mut map = Map::new(10);
        map.write(0, 10, 1, 0).unwrap();
        map.clear(3, 4).unwrap();
        assert_eq!(
            map.resolve(0, 10).unwrap(),
            [data(0, 1, 0, 3), hole(3, 4), data(7, 1, 7, 3)]
        );
        assert_eq!(map.allocated_ranges(), [0..3, 7..10]);
        assert_eq!(map.len(), 10);
        assert_eq!(map.allocated_bytes(), 6);
    }

    #[test]
    fn clear_edges_and_out_of_range_are_safe() {
        let mut map = Map::new(10);
        map.write(0, 10, 1, 0).unwrap();
        map.clear(0, 2).unwrap();
        map.clear(8, 100).unwrap();
        map.clear(50, 5).unwrap();
        map.clear(4, 0).unwrap();
        assert_eq!(map.allocated_ranges(), [2..8]);
        assert_eq!(map.clear(1, u64::MAX), Err(RangeError::Overflow));
        assert_eq!(map.allocated_ranges(), [2..8]);
        map.clear(0, 10).unwrap();
        assert!(map.allocated_ranges().is_empty());
        assert_eq!(map.mapping_count(), 0);
    }

    #[test]
    fn resize_down_trims_and_up_extends_with_a_hole() {
        let mut map = Map::new(10);
        map.write(0, 10, 1, 0).unwrap();
        map.resize(4);
        assert_eq!(map.resolve(0, 100).unwrap(), [data(0, 1, 0, 4)]);
        map.resize(8);
        assert_eq!(map.resolve(0, 100).unwrap(), [data(0, 1, 0, 4), hole(4, 4)]);
        map.resize(0);
        assert!(map.resolve(0, 100).unwrap().is_empty());
        assert_eq!(map.mapping_count(), 0);
    }

    #[test]
    fn shrinking_then_growing_does_not_resurrect_data() {
        let mut map = Map::new(10);
        map.write(0, 10, 1, 0).unwrap();
        map.resize(5);
        map.resize(10);
        assert_eq!(map.resolve(0, 10).unwrap(), [data(0, 1, 0, 5), hole(5, 5)]);
    }

    #[test]
    fn resolve_clamps_and_handles_inner_and_empty_requests() {
        let mut map = Map::new(10);
        map.write(2, 6, 1, 10).unwrap();
        assert_eq!(map.resolve(4, 2).unwrap(), [data(4, 1, 12, 2)]);
        assert_eq!(
            map.resolve(6, 100).unwrap(),
            [data(6, 1, 14, 2), hole(8, 2)]
        );
        assert!(map.resolve(10, 5).unwrap().is_empty());
        assert!(map.resolve(3, 0).unwrap().is_empty());
        assert_eq!(map.resolve(1, u64::MAX), Err(RangeError::Overflow));
        assert_eq!(map.resolve(0, u64::MAX).unwrap().len(), 3);
    }

    #[test]
    fn allocated_ranges_in_clips_to_the_window() {
        let mut map = Map::new(100);
        map.write(10, 10, 1, 0).unwrap();
        map.write(20, 10, 2, 0).unwrap();
        map.write(50, 10, 3, 0).unwrap();
        assert_eq!(map.allocated_ranges(), [10..30, 50..60]);
        assert_eq!(map.allocated_ranges_in(15, 20), [15..30]);
        assert_eq!(map.allocated_ranges_in(25, 30), [25..30, 50..55]);
        assert_eq!(map.allocated_ranges_in(30, 20), []);
        assert_eq!(map.allocated_ranges_in(0, u64::MAX), [10..30, 50..60]);
    }

    #[test]
    fn overflowing_arguments_are_rejected_without_changes() {
        let mut map = Map::new(10);
        map.write(0, 10, 1, 0).unwrap();
        let before = map.clone();
        assert_eq!(map.write(u64::MAX, 2, 2, 0), Err(RangeError::Overflow));
        assert_eq!(map.write(0, 2, 2, u64::MAX), Err(RangeError::Overflow));
        assert_eq!(map.clear(u64::MAX, 2), Err(RangeError::Overflow));
        assert_eq!(map, before);
    }

    #[test]
    fn extents_lists_only_live_references() {
        let mut map = Map::new(10);
        map.write(0, 5, 1, 0).unwrap();
        map.write(5, 5, 2, 0).unwrap();
        map.write(0, 5, 3, 0).unwrap();
        let mut live: Vec<_> = map.extents().copied().collect();
        live.sort_unstable();
        assert_eq!(live, [2, 3], "fully overwritten extent 1 is collectable");
    }

    #[test]
    fn persisted_form_round_trips_and_is_validated() {
        let mut map = Map::new(30);
        map.write(0, 10, 1, 0).unwrap();
        map.write(20, 5, 2, 7).unwrap();
        let stored: Vec<_> = map.mappings().map(|(o, m)| (o, m.clone())).collect();
        assert_eq!(Map::from_mappings(30, stored.clone()).unwrap(), map);
        let reversed: Vec<_> = stored.iter().cloned().rev().collect();
        assert_eq!(Map::from_mappings(30, reversed).unwrap(), map);
        assert_eq!(
            Map::from_mappings(24, stored.clone()),
            Err(RangeError::Inconsistent)
        );
        let overlapping = vec![
            (
                0,
                Mapping {
                    extent: 1,
                    extent_offset: 0,
                    length: 6,
                },
            ),
            (
                5,
                Mapping {
                    extent: 2,
                    extent_offset: 0,
                    length: 2,
                },
            ),
        ];
        assert_eq!(
            Map::from_mappings(10, overlapping),
            Err(RangeError::Inconsistent)
        );
        let empty = vec![(
            0,
            Mapping {
                extent: 1,
                extent_offset: 0,
                length: 0,
            },
        )];
        assert_eq!(Map::from_mappings(10, empty), Err(RangeError::Inconsistent));
    }

    #[test]
    fn diff_reports_changed_and_cleared_ranges() {
        let mut earlier = Map::new(20);
        earlier.write(0, 10, 1, 0).unwrap();
        earlier.write(15, 5, 2, 0).unwrap();
        let mut later = earlier.clone();
        later.write(3, 2, 3, 0).unwrap();
        later.clear(15, 3).unwrap();
        later.write(10, 2, 4, 0).unwrap();
        let diff = later.diff(&earlier);
        assert_eq!(diff.changed, [3..5, 10..12]);
        assert_eq!(diff.cleared, [15..18]);
        assert_eq!(earlier.diff(&earlier), Diff::default());
    }

    #[test]
    fn diff_treats_a_rewrite_into_a_new_extent_as_changed() {
        let mut earlier = Map::new(4);
        earlier.write(0, 4, 1, 0).unwrap();
        let mut later = earlier.clone();
        later.write(0, 4, 2, 0).unwrap();
        assert_eq!(later.diff(&earlier).changed, [0..4]);
    }

    #[test]
    fn diff_after_shrink_reports_the_dropped_data_as_cleared() {
        let mut earlier = Map::new(10);
        earlier.write(0, 10, 1, 0).unwrap();
        let mut later = earlier.clone();
        later.resize(6);
        assert_eq!(later.diff(&earlier).cleared, [6..10]);
        assert!(later.diff(&earlier).changed.is_empty());
    }

    #[test]
    fn diff_merges_adjacent_changes_from_different_extents() {
        let earlier = Map::new(10);
        let mut later = Map::new(10);
        later.write(0, 5, 1, 0).unwrap();
        later.write(5, 5, 2, 0).unwrap();
        assert_eq!(later.diff(&earlier).changed, [0..10]);
    }

    struct Rng(u64);

    impl Rng {
        fn next(&mut self, bound: u64) -> u64 {
            self.0 ^= self.0 << 13;
            self.0 ^= self.0 >> 7;
            self.0 ^= self.0 << 17;
            self.0 % bound
        }
    }

    /// Byte-for-byte model: each byte remembers its extent and extent offset.
    #[derive(Clone)]
    struct Model {
        bytes: Vec<Option<(u32, u64)>>,
    }

    impl Model {
        fn ranges(&self) -> Vec<Range<u64>> {
            let mut ranges: Vec<Range<u64>> = Vec::new();
            for (index, byte) in self.bytes.iter().enumerate() {
                let index = index as u64;
                if byte.is_some() {
                    match ranges.last_mut() {
                        Some(last) if last.end == index => last.end += 1,
                        _ => ranges.push(index..index + 1),
                    }
                }
            }
            ranges
        }

        fn expand(segments: &[Segment<u32>]) -> Vec<Option<(u32, u64)>> {
            let mut bytes = Vec::new();
            for segment in segments {
                for step in 0..segment.length() {
                    bytes.push(match segment {
                        Segment::Data {
                            extent,
                            extent_offset,
                            ..
                        } => Some((*extent, extent_offset + step)),
                        Segment::Hole { .. } => None,
                    });
                }
            }
            bytes
        }

        fn diff(&self, previous: &Self) -> Diff {
            let mut diff = Diff::default();
            for index in 0..self.bytes.len().max(previous.bytes.len()) {
                let now = self.bytes.get(index).copied().flatten();
                let before = previous.bytes.get(index).copied().flatten();
                let target = match (now, before) {
                    (Some(now), Some(before)) if now == before => continue,
                    (Some(_), _) => &mut diff.changed,
                    (None, Some(_)) => &mut diff.cleared,
                    (None, None) => continue,
                };
                let index = index as u64;
                match target.last_mut() {
                    Some(last) if last.end == index => last.end += 1,
                    _ => target.push(index..index + 1),
                }
            }
            diff
        }
    }

    #[test]
    fn random_operations_match_a_byte_model() {
        for seed in 1..=60u64 {
            let mut rng = Rng(seed.wrapping_mul(0x9E37_79B9_7F4A_7C15) | 1);
            let mut map = Map::new(0);
            let mut model = Model { bytes: Vec::new() };
            let mut snapshots: Vec<(Map, Model)> = Vec::new();
            for step in 0..200u32 {
                let offset = rng.next(48);
                let length = rng.next(24);
                match rng.next(10) {
                    0..=4 => {
                        let extent_offset = rng.next(1000);
                        map.write(offset, length, step, extent_offset).unwrap();
                        if length > 0 {
                            let end = (offset + length) as usize;
                            if model.bytes.len() < end {
                                model.bytes.resize(end, None);
                            }
                            for position in 0..length {
                                model.bytes[(offset + position) as usize] =
                                    Some((step, extent_offset + position));
                            }
                        }
                    }
                    5..=6 => {
                        map.clear(offset, length).unwrap();
                        for position in offset..(offset + length).min(model.bytes.len() as u64) {
                            model.bytes[position as usize] = None;
                        }
                    }
                    7 => {
                        let size = rng.next(60);
                        map.resize(size);
                        model.bytes.resize(size as usize, None);
                    }
                    _ => snapshots.push((map.clone(), model.clone())),
                }
                assert_eq!(
                    map.len(),
                    model.bytes.len() as u64,
                    "seed {seed} step {step}"
                );
                let all = map.resolve(0, u64::MAX / 2).unwrap();
                assert_eq!(Model::expand(&all), model.bytes, "seed {seed} step {step}");
                assert_eq!(map.allocated_ranges(), model.ranges(), "seed {seed}");
                let window = map.resolve(offset, length).unwrap();
                let expected: Vec<_> = model
                    .bytes
                    .iter()
                    .skip(offset as usize)
                    .take(length as usize)
                    .copied()
                    .collect();
                assert_eq!(Model::expand(&window), expected, "seed {seed} window");
                let stored: Vec<_> = map.mappings().map(|(o, m)| (o, m.clone())).collect();
                assert_eq!(Map::from_mappings(map.len(), stored).unwrap(), map);
                let mut previous = None;
                for (start, mapping) in map.mappings() {
                    assert!(mapping.length > 0);
                    if let Some((end, extent, extent_end)) = previous {
                        assert!(start >= end, "mappings overlap");
                        assert!(
                            !(start == end
                                && extent == mapping.extent
                                && extent_end == mapping.extent_offset),
                            "mappings were not coalesced (seed {seed})"
                        );
                    }
                    previous = Some((
                        start + mapping.length,
                        mapping.extent,
                        mapping.extent_offset + mapping.length,
                    ));
                }
            }
            for (old_map, old_model) in &snapshots {
                assert_eq!(map.diff(old_map), model.diff(old_model), "seed {seed} diff");
            }
        }
    }
}
