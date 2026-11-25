//! Page and append blob rules: blob kinds, alignment, sequence numbers, append
//! conditions, and the typed operations parsed from requests (ADR-0015).

use crate::{
    auth::header,
    blob_sas::{Need, Public},
    conditions::Guard,
    domain::{AccessTier, BlobKey, BlobWrite, ByteRange, Error, Result},
    protocol::{SourceRequest, UploadOptions},
};
use axum::http::{HeaderMap, StatusCode};
use std::ops::Range;

pub(crate) const PAGE_SIZE: u64 = 512;
pub(crate) const MAX_PAGE_BLOB_BYTES: u64 = 8 * 1024 * 1024 * 1024 * 1024;
/// The largest Put Page update.
pub(crate) const MAX_WRITE_BYTES: u64 = 4 * 1024 * 1024;
/// The largest Append Block, which API version 2022-11-02 raised from 4 MiB.
pub(crate) const MAX_APPEND_BLOCK_BYTES: u64 = 100 * 1024 * 1024;
pub(crate) const MAX_APPEND_BLOCKS: u64 = 50_000;

/// The type of a blob and the state that belongs to that type.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub(crate) enum BlobKind {
    #[default]
    Block,
    Page {
        sequence: u64,
    },
    Append {
        committed: u64,
        sealed: bool,
    },
}

impl BlobKind {
    pub(crate) fn name(self) -> &'static str {
        match self {
            Self::Block => "BlockBlob",
            Self::Page { .. } => "PageBlob",
            Self::Append { .. } => "AppendBlob",
        }
    }

    pub(crate) fn is_block(self) -> bool {
        self == Self::Block
    }

    /// Rebuilds a kind from its `blob_type`, `sequence_number`, `append_count`,
    /// and `sealed` columns.
    pub(crate) fn from_stored(kind: i64, sequence: i64, committed: i64, sealed: i64) -> Self {
        match kind {
            1 => Self::Page {
                sequence: u64::try_from(sequence).unwrap_or_default(),
            },
            2 => Self::Append {
                committed: u64::try_from(committed).unwrap_or_default(),
                sealed: sealed != 0,
            },
            _ => Self::Block,
        }
    }

    /// The `blob_type`, `sequence_number`, `append_count`, and `sealed` columns.
    pub(crate) fn columns(self) -> (i64, i64, i64, i64) {
        let number = |value: u64| i64::try_from(value).unwrap_or(i64::MAX);
        match self {
            Self::Block => (0, 0, 0, 0),
            Self::Page { sequence } => (1, number(sequence), 0, 0),
            Self::Append { committed, sealed } => (2, 0, number(committed), i64::from(sealed)),
        }
    }
}

/// Failures specific to page and append blobs.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum PageError {
    InvalidBlobType,
    InvalidPageRange,
    SequenceNumberConditionNotMet,
    SequenceNumberOverflow,
    AppendPositionConditionNotMet,
    MaxBlobSizeConditionNotMet,
    BlobIsSealed,
}

impl PageError {
    pub(crate) fn describe(self) -> (StatusCode, &'static str, &'static str) {
        use StatusCode as S;
        match self {
            Self::InvalidBlobType => (
                S::CONFLICT,
                "InvalidBlobType",
                "The blob type is invalid for this operation.",
            ),
            Self::InvalidPageRange => (
                S::RANGE_NOT_SATISFIABLE,
                "InvalidPageRange",
                "The page range specified is invalid.",
            ),
            Self::SequenceNumberConditionNotMet => (
                S::PRECONDITION_FAILED,
                "SequenceNumberConditionNotMet",
                "The sequence number condition specified was not met.",
            ),
            Self::SequenceNumberOverflow => (
                S::CONFLICT,
                "SequenceNumberIncrementTooLarge",
                "The sequence number increment cannot be performed because it would result in overflow of the sequence number.",
            ),
            Self::AppendPositionConditionNotMet => (
                S::PRECONDITION_FAILED,
                "AppendPositionConditionNotMet",
                "The append position condition specified was not met.",
            ),
            Self::MaxBlobSizeConditionNotMet => (
                S::PRECONDITION_FAILED,
                "MaxBlobSizeConditionNotMet",
                "The max blob size condition specified was not met.",
            ),
            Self::BlobIsSealed => (S::CONFLICT, "BlobIsSealed", "The blob is sealed."),
        }
    }
}

/// Fails unless the blob is a block blob (Put Block, Put Block List, Get Block List).
pub(crate) fn require_block(kind: BlobKind) -> Result<()> {
    if kind.is_block() {
        Ok(())
    } else {
        Err(Error::Page(PageError::InvalidBlobType))
    }
}

/// Premium tiers belong to page blobs; the other tiers to block blobs; append blobs have none.
pub(crate) fn check_tier(kind: BlobKind, tier: Option<AccessTier>) -> Result<()> {
    match (kind, tier) {
        (_, None) => Ok(()),
        (BlobKind::Block, Some(tier)) if !tier.is_premium() => Ok(()),
        (BlobKind::Page { .. }, Some(tier)) if tier.is_premium() => Ok(()),
        _ => Err(Error::InvalidHeader),
    }
}

pub(crate) fn sequence_number(text: &str) -> Result<u64> {
    text.parse::<u64>()
        .ok()
        .filter(|number| i64::try_from(*number).is_ok())
        .ok_or(Error::InvalidHeader)
}

fn number_header(headers: &HeaderMap, name: &str) -> Result<Option<u64>> {
    header(headers, name)?
        .map(|text| text.parse::<u64>().map_err(|_| Error::InvalidHeader))
        .transpose()
}

/// `x-ms-if-sequence-number-*`: every condition that was sent must hold.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub(crate) struct SequenceConditions {
    le: Option<u64>,
    lt: Option<u64>,
    eq: Option<u64>,
}

impl SequenceConditions {
    pub(crate) fn parse(headers: &HeaderMap) -> Result<Self> {
        let number = |name| header(headers, name)?.map(sequence_number).transpose();
        Ok(Self {
            le: number("x-ms-if-sequence-number-le")?,
            lt: number("x-ms-if-sequence-number-lt")?,
            eq: number("x-ms-if-sequence-number-eq")?,
        })
    }

    pub(crate) fn check(self, current: u64) -> Result<()> {
        let holds = self.le.is_none_or(|limit| current <= limit)
            && self.lt.is_none_or(|limit| current < limit)
            && self.eq.is_none_or(|expected| current == expected);
        if holds {
            Ok(())
        } else {
            Err(Error::Page(PageError::SequenceNumberConditionNotMet))
        }
    }
}

/// `x-ms-sequence-number-action` with its `x-ms-blob-sequence-number`.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum SequenceAction {
    Max(u64),
    Update(u64),
    Increment,
}

impl SequenceAction {
    fn parse(headers: &HeaderMap) -> Result<Option<Self>> {
        let number = header(headers, "x-ms-blob-sequence-number")?
            .map(sequence_number)
            .transpose()?;
        let Some(action) = header(headers, "x-ms-sequence-number-action")? else {
            return if number.is_some() {
                Err(Error::MissingHeader)
            } else {
                Ok(None)
            };
        };
        Ok(Some(match (action, number) {
            ("max", Some(number)) => Self::Max(number),
            ("update", Some(number)) => Self::Update(number),
            ("increment", None) => Self::Increment,
            ("max" | "update", None) => return Err(Error::MissingHeader),
            _ => return Err(Error::InvalidHeader),
        }))
    }

    pub(crate) fn apply(self, current: u64) -> Result<u64> {
        match self {
            Self::Max(number) => Ok(current.max(number)),
            Self::Update(number) => Ok(number),
            Self::Increment => current
                .checked_add(1)
                .filter(|next| i64::try_from(*next).is_ok())
                .ok_or(Error::Page(PageError::SequenceNumberOverflow)),
        }
    }
}

/// A page blob length: a multiple of 512 bytes, at most 8 TiB.
pub(crate) fn page_blob_length(text: &str) -> Result<u64> {
    text.parse::<u64>()
        .ok()
        .filter(|length| length.is_multiple_of(PAGE_SIZE) && *length <= MAX_PAGE_BLOB_BYTES)
        .ok_or(Error::InvalidHeader)
}

/// The page-blob changes Set Blob Properties can carry: resize and sequence number.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub(crate) struct PropertyChange {
    pub(crate) resize: Option<u64>,
    pub(crate) sequence: Option<SequenceAction>,
}

/// Request headers that only page blobs accept on Set Blob Properties.
pub(crate) const PROPERTY_HEADERS: &[&str] = &[
    "x-ms-blob-content-length",
    "x-ms-sequence-number-action",
    "x-ms-blob-sequence-number",
];

impl PropertyChange {
    pub(crate) fn parse(headers: &HeaderMap) -> Result<Self> {
        Ok(Self {
            resize: header(headers, "x-ms-blob-content-length")?
                .map(page_blob_length)
                .transpose()?,
            sequence: SequenceAction::parse(headers)?,
        })
    }

    pub(crate) fn is_empty(self) -> bool {
        self == Self::default()
    }
}

/// A Put Page range from `x-ms-range` or `Range`: inclusive, 512-aligned at both ends.
pub(crate) fn page_range(text: &str) -> Result<Range<u64>> {
    let (start, end) = text
        .strip_prefix("bytes=")
        .and_then(|range| range.split_once('-'))
        .ok_or(Error::InvalidHeader)?;
    let start: u64 = start.parse().map_err(|_| Error::InvalidHeader)?;
    let end: u64 = end.parse().map_err(|_| Error::InvalidHeader)?;
    if end < start {
        return Err(Error::InvalidHeader);
    }
    let end = end.checked_add(1).ok_or(Error::InvalidHeader)?;
    if !start.is_multiple_of(PAGE_SIZE) || !end.is_multiple_of(PAGE_SIZE) {
        return Err(Error::Page(PageError::InvalidPageRange));
    }
    Ok(start..end)
}

/// A page range must lie inside the blob.
pub(crate) fn check_within(range: &Range<u64>, length: u64) -> Result<()> {
    if range.end > length {
        Err(Error::Page(PageError::InvalidPageRange))
    } else {
        Ok(())
    }
}

/// `x-ms-blob-condition-maxsize` and `x-ms-blob-condition-appendpos`.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub(crate) struct AppendCondition {
    max_size: Option<u64>,
    position: Option<u64>,
}

impl AppendCondition {
    pub(crate) fn parse(headers: &HeaderMap) -> Result<Self> {
        Ok(Self {
            max_size: number_header(headers, "x-ms-blob-condition-maxsize")?,
            position: number_header(headers, "x-ms-blob-condition-appendpos")?,
        })
    }

    /// Checks a block of `adding` bytes appended to a blob of `length` bytes.
    pub(crate) fn check(self, length: u64, adding: u64) -> Result<()> {
        if self.position.is_some_and(|position| position != length) {
            return Err(Error::Page(PageError::AppendPositionConditionNotMet));
        }
        if self
            .max_size
            .is_some_and(|max| length.checked_add(adding).is_none_or(|total| total > max))
        {
            return Err(Error::Page(PageError::MaxBlobSizeConditionNotMet));
        }
        Ok(())
    }
}

/// What Put Blob creates.
pub(crate) enum Creation {
    Page { length: u64, sequence: u64 },
    Append,
}

impl Creation {
    pub(crate) fn kind(&self) -> BlobKind {
        match self {
            Self::Page { sequence, .. } => BlobKind::Page {
                sequence: *sequence,
            },
            Self::Append => BlobKind::Append {
                committed: 0,
                sealed: false,
            },
        }
    }

    pub(crate) fn length(&self) -> u64 {
        match self {
            Self::Page { length, .. } => *length,
            Self::Append => 0,
        }
    }
}

/// The conditions of a Put Page.
pub(crate) struct PageWrite {
    pub(crate) range: Range<u64>,
    pub(crate) sequence: SequenceConditions,
    pub(crate) guard: Guard,
}

/// The conditions of an Append Block or Seal.
pub(crate) struct AppendWrite {
    pub(crate) condition: AppendCondition,
    pub(crate) guard: Guard,
}

/// Get Page Ranges: an optional byte window and a page of results.
pub(crate) struct RangeQuery {
    pub(crate) window: Option<ByteRange>,
    pub(crate) marker: Option<u64>,
    pub(crate) limit: Option<u32>,
    pub(crate) guard: Guard,
}

pub(crate) enum PageOperation {
    Create(BlobKey, BlobWrite, Creation),
    /// An update carries its body options; a clear has none.
    PutPage(BlobKey, PageWrite, Option<UploadOptions>),
    PutPageFromUrl(BlobKey, PageWrite, SourceRequest),
    PageRanges(BlobKey, RangeQuery),
    AppendBlock(BlobKey, AppendWrite, UploadOptions),
    AppendBlockFromUrl(BlobKey, AppendWrite, SourceRequest),
    Seal(BlobKey, AppendWrite),
}

const fn need(service: &'static str) -> Need {
    Need {
        service: Some(service),
        account: Some(('o', service)),
        public: Public::Never,
    }
}

impl PageOperation {
    pub(crate) fn need(&self) -> Need {
        match self {
            Self::Create(..) => need("wc"),
            Self::PutPage(..) | Self::PutPageFromUrl(..) | Self::Seal(..) => need("w"),
            Self::AppendBlock(..) | Self::AppendBlockFromUrl(..) => need("aw"),
            Self::PageRanges(..) => Need {
                service: Some("r"),
                account: Some(('o', "r")),
                public: Public::Blob,
            },
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::http::HeaderValue;

    fn headers(pairs: &[(&'static str, &str)]) -> HeaderMap {
        let mut headers = HeaderMap::new();
        for (name, value) in pairs {
            headers.insert(*name, HeaderValue::from_str(value).unwrap());
        }
        headers
    }

    #[test]
    fn sequence_conditions_require_every_sent_header_to_hold() {
        let conditions = SequenceConditions::parse(&headers(&[
            ("x-ms-if-sequence-number-le", "5"),
            ("x-ms-if-sequence-number-lt", "5"),
        ]))
        .unwrap();
        assert_eq!(conditions.check(4), Ok(()));
        assert_eq!(
            conditions.check(5),
            Err(Error::Page(PageError::SequenceNumberConditionNotMet))
        );
        let equal =
            SequenceConditions::parse(&headers(&[("x-ms-if-sequence-number-eq", "7")])).unwrap();
        assert_eq!(equal.check(7), Ok(()));
        assert!(equal.check(8).is_err());
        assert_eq!(SequenceConditions::default().check(u64::MAX), Ok(()));
        assert!(
            SequenceConditions::parse(&headers(&[("x-ms-if-sequence-number-le", "-1")])).is_err()
        );
        assert!(
            SequenceConditions::parse(&headers(&[(
                "x-ms-if-sequence-number-le",
                "9223372036854775808"
            )]))
            .is_err()
        );
    }

    #[test]
    fn sequence_actions_max_update_and_increment() {
        let action = |pairs: &[(&'static str, &str)]| SequenceAction::parse(&headers(pairs));
        let with = |name: &'static str, number: &'static str| {
            action(&[
                ("x-ms-sequence-number-action", name),
                ("x-ms-blob-sequence-number", number),
            ])
        };
        assert_eq!(
            with("max", "3").unwrap().unwrap().apply(9),
            Ok(9),
            "max keeps the larger value"
        );
        assert_eq!(with("max", "12").unwrap().unwrap().apply(9), Ok(12));
        assert_eq!(with("update", "1").unwrap().unwrap().apply(9), Ok(1));
        assert_eq!(
            action(&[("x-ms-sequence-number-action", "increment")])
                .unwrap()
                .unwrap()
                .apply(9),
            Ok(10)
        );
        assert_eq!(
            SequenceAction::Increment.apply(i64::MAX as u64),
            Err(Error::Page(PageError::SequenceNumberOverflow))
        );
        assert_eq!(
            action(&[("x-ms-sequence-number-action", "update")]).err(),
            Some(Error::MissingHeader)
        );
        assert_eq!(
            action(&[("x-ms-blob-sequence-number", "1")]).err(),
            Some(Error::MissingHeader)
        );
        assert_eq!(
            with("increment", "1").err(),
            Some(Error::InvalidHeader),
            "increment takes no number"
        );
        assert_eq!(action(&[]).unwrap(), None);
    }

    #[test]
    fn page_ranges_are_inclusive_and_aligned_to_512_bytes() {
        assert_eq!(page_range("bytes=0-511"), Ok(0..512));
        assert_eq!(page_range("bytes=512-1535"), Ok(512..1536));
        for unaligned in ["bytes=1-511", "bytes=0-512", "bytes=0-1022"] {
            assert_eq!(
                page_range(unaligned),
                Err(Error::Page(PageError::InvalidPageRange)),
                "{unaligned}"
            );
        }
        for malformed in [
            "0-511",
            "bytes=0-",
            "bytes=512-0",
            "bytes=a-b",
            "bytes=0-1,2-3",
        ] {
            assert_eq!(
                page_range(malformed),
                Err(Error::InvalidHeader),
                "{malformed}"
            );
        }
        assert_eq!(check_within(&(0..1024), 1024), Ok(()));
        assert_eq!(
            check_within(&(512..1536), 1024),
            Err(Error::Page(PageError::InvalidPageRange))
        );
    }

    #[test]
    fn page_blob_lengths_are_aligned_and_bounded() {
        assert_eq!(page_blob_length("0"), Ok(0));
        assert_eq!(page_blob_length("1024"), Ok(1024));
        assert_eq!(page_blob_length("513"), Err(Error::InvalidHeader));
        assert_eq!(
            page_blob_length(&MAX_PAGE_BLOB_BYTES.to_string()),
            Ok(MAX_PAGE_BLOB_BYTES)
        );
        assert_eq!(
            page_blob_length(&(MAX_PAGE_BLOB_BYTES + PAGE_SIZE).to_string()),
            Err(Error::InvalidHeader)
        );
    }

    #[test]
    fn append_conditions_check_position_and_resulting_size() {
        let condition = AppendCondition::parse(&headers(&[
            ("x-ms-blob-condition-appendpos", "10"),
            ("x-ms-blob-condition-maxsize", "15"),
        ]))
        .unwrap();
        assert_eq!(condition.check(10, 5), Ok(()));
        assert_eq!(
            condition.check(9, 5),
            Err(Error::Page(PageError::AppendPositionConditionNotMet))
        );
        assert_eq!(
            condition.check(10, 6),
            Err(Error::Page(PageError::MaxBlobSizeConditionNotMet))
        );
        assert_eq!(AppendCondition::default().check(u64::MAX, 1), Ok(()));
        assert!(AppendCondition::parse(&headers(&[("x-ms-blob-condition-maxsize", "x")])).is_err());
    }

    #[test]
    fn kinds_round_trip_through_their_columns_and_gate_tiers() {
        for kind in [
            BlobKind::Block,
            BlobKind::Page { sequence: 7 },
            BlobKind::Append {
                committed: 3,
                sealed: true,
            },
        ] {
            let (code, sequence, committed, sealed) = kind.columns();
            assert_eq!(
                BlobKind::from_stored(code, sequence, committed, sealed),
                kind
            );
        }
        let page = BlobKind::Page { sequence: 0 };
        assert!(check_tier(page, Some(AccessTier::P10)).is_ok());
        assert!(check_tier(page, Some(AccessTier::Hot)).is_err());
        assert!(check_tier(BlobKind::Block, Some(AccessTier::P10)).is_err());
        assert!(check_tier(BlobKind::Block, Some(AccessTier::Cool)).is_ok());
        let append = BlobKind::Append {
            committed: 0,
            sealed: false,
        };
        assert!(check_tier(append, Some(AccessTier::Hot)).is_err());
        assert!(check_tier(append, None).is_ok());
        assert_eq!(
            require_block(page),
            Err(Error::Page(PageError::InvalidBlobType))
        );
    }
}
