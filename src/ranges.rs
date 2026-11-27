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

#[cfg(test)]
mod tests;

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
