use base64::{
    Engine as _,
    engine::general_purpose::{STANDARD, URL_SAFE_NO_PAD},
};
use std::collections::BTreeMap;
use uuid::Uuid;

pub(crate) type Result<T> = std::result::Result<T, Error>;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum Error {
    AuthenticationFailed,
    InvalidName,
    InvalidHeader,
    InvalidVersion,
    InvalidQuery,
    Unsupported,
    MissingLength,
    InvalidLength,
    TooLarge,
    Md5Mismatch,
    Crc64Mismatch,
    InvalidBlockId,
    InvalidBlockList,
    InvalidXml,
    BlockCountExceeded,
    BlockListTooLong,
    ContainerExists,
    ContainerMissing,
    BlobMissing,
    ConditionNotMet,
    NotModified,
    InvalidRange(u64),
    QuotaExceeded,
    Busy,
    Timeout,
    Internal,
}

#[derive(Clone, Eq, Hash, PartialEq)]
pub(crate) struct AccountName(String);

impl AccountName {
    pub(crate) fn parse(value: &str) -> Result<Self> {
        if !(3..=24).contains(&value.len())
            || !value
                .bytes()
                .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit())
        {
            return Err(Error::InvalidName);
        }
        Ok(Self(value.to_owned()))
    }

    pub(crate) fn as_str(&self) -> &str {
        &self.0
    }
}

pub(crate) struct ContainerName(String);

impl ContainerName {
    pub(crate) fn parse(value: &str) -> Result<Self> {
        if matches!(value, "$root" | "$web" | "$logs") {
            return Err(Error::Unsupported);
        }
        if !(3..=63).contains(&value.len())
            || value.starts_with('-')
            || value.ends_with('-')
            || value.contains("--")
            || !value
                .bytes()
                .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-')
        {
            return Err(Error::InvalidName);
        }
        Ok(Self(value.to_owned()))
    }

    pub(crate) fn as_str(&self) -> &str {
        &self.0
    }
}

pub(crate) struct BlobPath(String);

impl BlobPath {
    pub(crate) fn parse(value: String) -> Result<Self> {
        if value.is_empty() || value.chars().count() > 1024 || !xml_safe(&value) {
            return Err(Error::InvalidName);
        }
        Ok(Self(value))
    }

    pub(crate) fn as_str(&self) -> &str {
        &self.0
    }
}

pub(crate) fn xml_safe(value: &str) -> bool {
    value
        .chars()
        .all(|c| !c.is_control() && !matches!(c, '\u{fffe}' | '\u{ffff}'))
}

pub(crate) struct ContainerKey {
    pub(crate) account: AccountName,
    pub(crate) name: ContainerName,
}

pub(crate) struct BlobKey {
    pub(crate) container: ContainerKey,
    pub(crate) path: BlobPath,
}

#[derive(Eq, Ord, PartialEq, PartialOrd)]
pub(crate) struct ApiVersion(String);

impl ApiVersion {
    pub(crate) fn parse(value: &str) -> Result<Self> {
        let digits =
            |part: &str, width| part.len() == width && part.bytes().all(|b| b.is_ascii_digit());
        let (year, rest) = value.split_once('-').ok_or(Error::InvalidVersion)?;
        let (month, day) = rest.split_once('-').ok_or(Error::InvalidVersion)?;
        if !digits(year, 4) || !digits(month, 2) || !digits(day, 2) {
            return Err(Error::InvalidVersion);
        }
        let year: u16 = year.parse().map_err(|_| Error::InvalidVersion)?;
        let month: u8 = month.parse().map_err(|_| Error::InvalidVersion)?;
        let day: u8 = day.parse().map_err(|_| Error::InvalidVersion)?;
        let leap =
            year.is_multiple_of(4) && (!year.is_multiple_of(100) || year.is_multiple_of(400));
        let days = match month {
            1 | 3 | 5 | 7 | 8 | 10 | 12 => 31,
            4 | 6 | 9 | 11 => 30,
            2 if leap => 29,
            2 => 28,
            _ => return Err(Error::InvalidVersion),
        };
        if year == 0 || day == 0 || day > days {
            return Err(Error::InvalidVersion);
        }
        Ok(Self(value.to_owned()))
    }

    pub(crate) fn as_str(&self) -> &str {
        &self.0
    }
}

#[derive(Clone, Copy)]
pub(crate) struct ContentLength(pub(crate) u64);

pub(crate) struct BlockId {
    encoded: String,
    pub(crate) width: usize,
}

impl BlockId {
    pub(crate) fn parse(value: &str) -> Result<Self> {
        if value.len() > 88 {
            return Err(Error::InvalidBlockId);
        }
        let bytes = STANDARD.decode(value).map_err(|_| Error::InvalidBlockId)?;
        if !(1..=64).contains(&bytes.len()) {
            return Err(Error::InvalidBlockId);
        }
        Ok(Self {
            encoded: value.to_owned(),
            width: bytes.len(),
        })
    }

    pub(crate) fn as_str(&self) -> &str {
        &self.encoded
    }
}

#[derive(Clone, Copy, Eq, PartialEq)]
pub(crate) enum BlockSource {
    Committed,
    Uncommitted,
    Latest,
}

pub(crate) struct BlockSelection {
    pub(crate) id: BlockId,
    pub(crate) source: BlockSource,
}

#[derive(Clone, Copy, Eq, PartialEq)]
pub(crate) enum BlockListKind {
    Committed,
    Uncommitted,
    All,
}

pub(crate) struct BlockList {
    pub(crate) entity: Option<Entity>,
    pub(crate) length: ContentLength,
    pub(crate) committed: Option<Vec<(String, ContentLength)>>,
    pub(crate) uncommitted: Option<Vec<(String, ContentLength)>>,
}

pub(crate) struct ETag(String);

impl ETag {
    fn parse(value: &str) -> Result<Self> {
        let valid = value.strip_prefix('"').and_then(|v| v.strip_suffix('"'));
        if !valid.is_some_and(|v| {
            !v.is_empty()
                && v.bytes()
                    .all(|b| b.is_ascii_graphic() && b != b'"' && b != b',')
        }) {
            return Err(Error::InvalidHeader);
        }
        Ok(Self(value.to_owned()))
    }

    pub(crate) fn as_str(&self) -> &str {
        &self.0
    }
}

#[derive(Clone, Copy)]
pub(crate) struct Entity {
    pub(crate) id: Uuid,
    pub(crate) modified: u64,
}

impl Entity {
    pub(crate) fn etag(self) -> ETag {
        ETag(format!("\"{}\"", self.id.simple()))
    }
}

pub(crate) enum Condition {
    None,
    Exists,
    Absent,
    Matches(ETag),
    Differs(ETag),
}

impl Condition {
    pub(crate) fn parse(if_match: Option<&str>, if_none_match: Option<&str>) -> Result<Self> {
        match (if_match, if_none_match) {
            (None, None) => Ok(Self::None),
            (Some("*"), None) => Ok(Self::Exists),
            (None, Some("*")) => Ok(Self::Absent),
            (Some(value), None) => Ok(Self::Matches(ETag::parse(value)?)),
            (None, Some(value)) => Ok(Self::Differs(ETag::parse(value)?)),
            (Some(_), Some(_)) => Err(Error::Unsupported),
        }
    }

    pub(crate) fn check(&self, current: Option<Entity>, reading: bool) -> Result<()> {
        let matches = |tag: &ETag| current.is_some_and(|e| e.etag().as_str() == tag.as_str());
        match self {
            Self::None => Ok(()),
            Self::Exists if current.is_some() => Ok(()),
            Self::Matches(tag) if matches(tag) => Ok(()),
            Self::Absent if current.is_none() => Ok(()),
            Self::Differs(tag) if !matches(tag) => Ok(()),
            Self::Absent | Self::Differs(_) if reading => Err(Error::NotModified),
            _ => Err(Error::ConditionNotMet),
        }
    }
}

pub(crate) struct ByteRange {
    start: u64,
    end: Option<u64>,
}

impl ByteRange {
    pub(crate) fn parse(value: &str) -> Result<Self> {
        let (start, end) = value
            .strip_prefix("bytes=")
            .and_then(|v| v.split_once('-'))
            .ok_or(Error::InvalidHeader)?;
        let start = start.parse().map_err(|_| Error::InvalidHeader)?;
        let end = if end.is_empty() {
            None
        } else {
            Some(end.parse().map_err(|_| Error::InvalidHeader)?)
        };
        if end.is_some_and(|end| end < start) {
            return Err(Error::InvalidHeader);
        }
        Ok(Self { start, end })
    }

    pub(crate) fn resolve(&self, len: ContentLength) -> Result<std::ops::Range<u64>> {
        if self.start >= len.0 {
            return Err(Error::InvalidRange(len.0));
        }
        Ok(self.start..self.end.map_or(len.0, |end| end.min(len.0 - 1) + 1))
    }
}

pub(crate) struct PageRequest {
    pub(crate) prefix: String,
    pub(crate) after: String,
    pub(crate) limit: u32,
}

impl PageRequest {
    pub(crate) fn parse(
        prefix: Option<&str>,
        marker: Option<&str>,
        limit: Option<&str>,
    ) -> Result<Self> {
        let prefix = prefix.unwrap_or_default();
        let marker = marker.unwrap_or_default();
        if prefix.chars().count() > 1024 || !xml_safe(prefix) || marker.len() > 5462 {
            return Err(Error::InvalidQuery);
        }
        let after = URL_SAFE_NO_PAD
            .decode(marker)
            .map_err(|_| Error::InvalidQuery)?;
        let after = String::from_utf8(after).map_err(|_| Error::InvalidQuery)?;
        if !xml_safe(&after) || after.chars().count() > 1024 {
            return Err(Error::InvalidQuery);
        }
        let limit = limit
            .map_or(Ok(5000), |value| value.parse::<u32>())
            .map_err(|_| Error::InvalidQuery)?;
        if limit == 0 {
            return Err(Error::InvalidQuery);
        }
        Ok(Self {
            prefix: prefix.to_owned(),
            after,
            limit: limit.min(5000),
        })
    }
}

pub(crate) struct Page<T> {
    pub(crate) items: Vec<(String, T)>,
    pub(crate) next: String,
}

impl<T> Page<T> {
    pub(crate) fn from_rows(mut items: Vec<(String, T)>, limit: u32) -> Self {
        let next = if items.len() > limit as usize {
            items.truncate(limit as usize);
            items
                .last()
                .map_or_else(String::new, |(name, _)| URL_SAFE_NO_PAD.encode(name))
        } else {
            String::new()
        };
        Self { items, next }
    }
}

pub(crate) type Metadata = BTreeMap<String, String>;

pub(crate) struct BlobWrite {
    pub(crate) content_type: String,
    pub(crate) metadata: Metadata,
    pub(crate) condition: Condition,
}

pub(crate) struct BlobInfo {
    pub(crate) entity: Entity,
    pub(crate) length: ContentLength,
    pub(crate) content_type: String,
    pub(crate) md5: Option<String>,
    pub(crate) metadata: Metadata,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn conditional_writes_require_the_current_etag() {
        let current = Entity {
            id: Uuid::from_u128(17),
            modified: 0,
        };
        let other = Entity {
            id: Uuid::from_u128(19),
            modified: 0,
        };
        let tag = current.etag();
        let condition = Condition::parse(Some(tag.as_str()), None).unwrap();
        assert_eq!(condition.check(Some(current), false), Ok(()));
        assert_eq!(
            condition.check(Some(other), false),
            Err(Error::ConditionNotMet)
        );
        let none_match = Condition::parse(None, Some("*")).unwrap();
        assert_eq!(
            none_match.check(Some(current), true),
            Err(Error::NotModified)
        );
        assert_eq!(none_match.check(None, false), Ok(()));
    }

    #[test]
    fn ranges_clamp_and_reject_unsatisfiable_reads() {
        assert_eq!(
            ByteRange::parse("bytes=2-90")
                .unwrap()
                .resolve(ContentLength(5)),
            Ok(2..5)
        );
        assert_eq!(
            ByteRange::parse("bytes=5-")
                .unwrap()
                .resolve(ContentLength(5)),
            Err(Error::InvalidRange(5))
        );
        assert!(ByteRange::parse("bytes=4-1").is_err());
        assert!(ByteRange::parse("bytes=1-3,5-8").is_err());
    }

    #[test]
    fn continuation_starts_after_the_last_returned_item() {
        let page = Page::from_rows(vec![("a&b".to_owned(), ()), ("z".to_owned(), ())], 1);
        assert_eq!(page.items, vec![("a&b".to_owned(), ())]);
        assert_eq!(
            PageRequest::parse(None, Some(&page.next), Some("1"))
                .unwrap()
                .after,
            "a&b"
        );
        assert!(PageRequest::parse(None, Some("*invalid*"), None).is_err());
        assert!(PageRequest::parse(None, None, Some("0")).is_err());
    }
}
