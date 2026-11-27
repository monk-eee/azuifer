use crate::{blob_tags::Tags, conditions::Guard, lease::LeaseView, stamp::Ticks};
use base64::{
    Engine as _,
    engine::general_purpose::{STANDARD, URL_SAFE_NO_PAD},
};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use uuid::Uuid;

pub(crate) type Result<T> = std::result::Result<T, Error>;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum Error {
    AuthenticationFailed,
    InvalidAuthenticationInfo,
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
    PathConflict,
    DirectoryNotEmpty,
    ConditionNotMet,
    NotModified,
    InvalidRange(u64),
    QuotaExceeded,
    Busy,
    Timeout,
    Internal,
    ResourceNotFound,
    PermissionMismatch,
    ResourceTypeMismatch,
    ServiceMismatch,
    SourceIpMismatch,
    ProtocolMismatch,
    BlobAlreadyExists,
    BlobArchived,
    MissingHeader,
    LeaseIdMissing,
    LeaseLost,
    LeaseAlreadyPresent,
    LeaseMismatchBlob,
    LeaseMismatchContainer,
    LeaseMismatchLease,
    LeaseNotPresentBlob,
    LeaseNotPresentContainer,
    LeaseNotPresentLease,
    LeaseBreakingNoAcquire,
    LeaseBreakingNoChange,
    LeaseBrokenNoRenew,
    NoPendingCopy,
    CopyIdMismatch,
    CopySourceDenied,
    CopySourceMissing,
    CorsPreflight,
    SourceConditionNotMet,
    Page(crate::blob_page::PageError),
    Ext(crate::blob_lifecycle::LifecycleError),
    SnapshotsPresent,
    InvalidTag,
    TagsTooLarge,
    InvalidInput,
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

#[derive(Clone)]
pub(crate) struct ContainerName(String);

impl ContainerName {
    pub(crate) fn parse(value: &str) -> Result<Self> {
        if matches!(value, "$web" | "$root" | "$logs") {
            return Ok(Self(value.to_owned()));
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

#[derive(Clone)]
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

    pub(crate) fn check_hns(&self) -> Result<()> {
        let mut parts = self.0.split('/');
        if parts.clone().count() > 61 || parts.any(|part| matches!(part, "" | "." | "..")) {
            return Err(Error::InvalidName);
        }
        Ok(())
    }
}

pub(crate) fn xml_safe(value: &str) -> bool {
    value
        .chars()
        .all(|c| !c.is_control() && !matches!(c, '\u{fffe}' | '\u{ffff}'))
}

#[derive(Clone)]
pub(crate) struct ContainerKey {
    pub(crate) account: AccountName,
    pub(crate) name: ContainerName,
}

#[derive(Clone)]
pub(crate) struct BlobKey {
    pub(crate) container: ContainerKey,
    pub(crate) path: BlobPath,
}

#[derive(Eq, Ord, PartialEq, PartialOrd)]
pub(crate) struct ApiVersion(String);

impl ApiVersion {
    /// Azure serves every version since the first public one. The emulator answers
    /// older versions with its baseline behavior and newer ones only when the
    /// version check is skipped.
    pub(crate) fn is_served(&self, baseline: &Self, skip_newer: bool) -> bool {
        self.0.as_str() >= "2009-09-19" && (self <= baseline || skip_newer)
    }

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
    pub(crate) fn parse(value: &str) -> Result<Self> {
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

/// Identity and version of a stored object. `id` names the content extent;
/// `tag` is the ETag, which also changes when only properties or metadata change.
#[derive(Clone, Copy, Debug)]
pub(crate) struct Entity {
    pub(crate) id: Uuid,
    pub(crate) tag: Uuid,
    pub(crate) modified: u64,
    /// The version id of a blob in an account with versioning enabled.
    pub(crate) version: Option<Ticks>,
}

impl Entity {
    pub(crate) fn etag(self) -> ETag {
        ETag(format!("\"{}\"", self.tag.simple()))
    }
}

#[derive(Clone)]
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

    /// The `Range` header value that asks for this range.
    pub(crate) fn header_value(&self) -> String {
        match self.end {
            Some(end) => format!("bytes={}-{end}", self.start),
            None => format!("bytes={}-", self.start),
        }
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
        // A marker after a collapsed BlobPrefix is the prefix plus one sentinel character.
        if !xml_safe(&after) || after.chars().count() > 1026 {
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

/// The standard HTTP content headers of a blob. Empty strings mean "not set".
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub(crate) struct ContentHeaders {
    pub(crate) content_type: String,
    pub(crate) encoding: String,
    pub(crate) language: String,
    pub(crate) disposition: String,
    pub(crate) cache_control: String,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum AccessTier {
    Hot,
    Cool,
    Cold,
    Archive,
    /// Premium page blob tiers.
    P4,
    P6,
    P10,
    P15,
    P20,
    P30,
    P40,
    P50,
    P60,
    P70,
    P80,
}

impl AccessTier {
    pub(crate) fn parse(value: &str) -> Result<Self> {
        match value {
            "Hot" => Ok(Self::Hot),
            "Cool" => Ok(Self::Cool),
            "Cold" => Ok(Self::Cold),
            "Archive" => Ok(Self::Archive),
            "P4" => Ok(Self::P4),
            "P6" => Ok(Self::P6),
            "P10" => Ok(Self::P10),
            "P15" => Ok(Self::P15),
            "P20" => Ok(Self::P20),
            "P30" => Ok(Self::P30),
            "P40" => Ok(Self::P40),
            "P50" => Ok(Self::P50),
            "P60" => Ok(Self::P60),
            "P70" => Ok(Self::P70),
            "P80" => Ok(Self::P80),
            _ => Err(Error::InvalidHeader),
        }
    }

    pub(crate) fn name(self) -> &'static str {
        match self {
            Self::Hot => "Hot",
            Self::Cool => "Cool",
            Self::Cold => "Cold",
            Self::Archive => "Archive",
            Self::P4 => "P4",
            Self::P6 => "P6",
            Self::P10 => "P10",
            Self::P15 => "P15",
            Self::P20 => "P20",
            Self::P30 => "P30",
            Self::P40 => "P40",
            Self::P50 => "P50",
            Self::P60 => "P60",
            Self::P70 => "P70",
            Self::P80 => "P80",
        }
    }

    pub(crate) fn is_premium(self) -> bool {
        !matches!(self, Self::Hot | Self::Cool | Self::Cold | Self::Archive)
    }
}

/// How a blob came to exist by copy. Copies complete synchronously.
#[derive(Clone, Debug)]
pub(crate) struct CopyRecord {
    pub(crate) id: String,
    pub(crate) source: String,
}

#[derive(Clone, Debug)]
pub(crate) struct CopyInfo {
    pub(crate) id: String,
    pub(crate) source: String,
    pub(crate) completed: u64,
}

#[derive(Clone)]
pub(crate) struct BlobWrite {
    pub(crate) headers: ContentHeaders,
    pub(crate) metadata: Metadata,
    pub(crate) guard: Guard,
    pub(crate) tier: Option<AccessTier>,
    pub(crate) copy: Option<CopyRecord>,
    /// The `x-ms-blob-content-md5` property, which replaces the computed digest.
    pub(crate) md5: Option<[u8; 16]>,
    /// The `x-ms-tags` blob index tags; a write replaces the blob's tags with these.
    pub(crate) tags: Tags,
}

pub(crate) struct BlobInfo {
    pub(crate) entity: Entity,
    pub(crate) created: u64,
    pub(crate) length: ContentLength,
    pub(crate) headers: ContentHeaders,
    pub(crate) md5: Option<String>,
    pub(crate) metadata: Metadata,
    /// The explicitly set tier; `None` means the inferred default, Hot.
    pub(crate) tier: Option<(AccessTier, u64)>,
    pub(crate) lease: LeaseView,
    pub(crate) copy: Option<CopyInfo>,
    /// True for a blob that exists only as uncommitted blocks (listings only).
    pub(crate) uncommitted: bool,
    pub(crate) kind: crate::blob_page::BlobKind,
    /// Blob index tags of a blob read for a single-blob operation; empty in listings.
    pub(crate) tags: Tags,
    /// Expiry, immutability, and incremental copy state; loaded with the blob and by listings.
    pub(crate) lifecycle: crate::blob_lifecycle::Lifecycle,
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub(crate) enum PublicAccess {
    #[default]
    Private,
    Blob,
    Container,
}

impl PublicAccess {
    pub(crate) fn parse(value: &str) -> Result<Self> {
        match value {
            "blob" => Ok(Self::Blob),
            "container" => Ok(Self::Container),
            _ => Err(Error::InvalidHeader),
        }
    }

    pub(crate) fn name(self) -> Option<&'static str> {
        match self {
            Self::Private => None,
            Self::Blob => Some("blob"),
            Self::Container => Some("container"),
        }
    }
}

/// A stored access policy of a container ACL; times are the ISO 8601 text as sent.
#[derive(Clone, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
pub(crate) struct SignedIdentifier {
    pub(crate) id: String,
    pub(crate) start: Option<String>,
    pub(crate) expiry: Option<String>,
    pub(crate) permission: Option<String>,
}

pub(crate) struct ContainerCreate {
    pub(crate) metadata: Metadata,
    pub(crate) public_access: PublicAccess,
}

pub(crate) struct ContainerInfo {
    pub(crate) entity: Entity,
    pub(crate) metadata: Metadata,
    pub(crate) public_access: PublicAccess,
    pub(crate) identifiers: Vec<SignedIdentifier>,
    pub(crate) lease: LeaseView,
}

#[derive(Clone, Copy, Eq, PartialEq)]
pub(crate) enum RangeChecksum {
    Md5,
    Crc64,
}

pub(crate) struct BlobRead {
    pub(crate) guard: Guard,
    pub(crate) range: Option<ByteRange>,
    pub(crate) with_body: bool,
    pub(crate) range_checksum: Option<RangeChecksum>,
}

#[derive(Clone, Copy, Eq, PartialEq)]
pub(crate) enum Include {
    Metadata,
    Copy,
    Uncommitted,
    Snapshots,
    Versions,
    Deleted,
    Tags,
}

pub(crate) struct ListRequest {
    pub(crate) page: PageRequest,
    pub(crate) delimiter: Option<String>,
    pub(crate) include: Vec<Include>,
}

pub(crate) enum ListEntry {
    Blob(String, Box<BlobInfo>),
    Prefix(String),
    Directory(String, Entity),
}

pub(crate) enum PathEntry {
    File(Entity, ContentLength),
    Directory(Entity),
}

pub(crate) struct BlobListing {
    pub(crate) entries: Vec<ListEntry>,
    pub(crate) next: String,
}

#[cfg(test)]
mod tests {
    use super::*;

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
