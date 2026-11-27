//! Typed FileREST domain values shared by the request parser, the store, and the responses.

use super::{
    error::{Error, Result},
    lease::Lease,
    time::TICKS_PER_MILLI,
};
use std::collections::BTreeMap;

pub(crate) type Metadata = BTreeMap<String, String>;

const MAX_METADATA_BYTES: usize = 8 * 1024;

/// Validates metadata names (C# identifiers) and the 8 KiB total limit.
pub(crate) fn metadata(pairs: impl IntoIterator<Item = (String, String)>) -> Result<Metadata> {
    let mut result = Metadata::new();
    let mut size = 0;
    for (name, value) in pairs {
        if name.is_empty() {
            return Err(Error::EmptyMetadataKey);
        }
        let mut chars = name.chars();
        let valid = chars
            .next()
            .is_some_and(|c| c.is_ascii_alphabetic() || c == '_')
            && chars.all(|c| c.is_ascii_alphanumeric() || c == '_');
        if !valid {
            return Err(Error::InvalidMetadata);
        }
        size += name.len() + value.len();
        if result.insert(name.to_ascii_lowercase(), value).is_some() {
            return Err(Error::InvalidMetadata);
        }
    }
    if size > MAX_METADATA_BYTES {
        return Err(Error::MetadataTooLarge);
    }
    Ok(result)
}

/// A timestamp request header: `now`, `preserve`, or an explicit ISO 8601 time.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum TimeSpec {
    Now,
    Preserve,
    At(i64),
}

impl TimeSpec {
    /// `now` is Unix milliseconds; `current` and the result are 100 ns ticks.
    pub(crate) fn resolve(self, now: i64, current: i64) -> i64 {
        match self {
            Self::Now => now * TICKS_PER_MILLI,
            Self::Preserve => current,
            Self::At(ticks) => ticks,
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) enum PermissionSpec {
    /// Take the parent directory's permission (the default on create).
    Inherit,
    Preserve,
    Sddl(String),
    Key(String),
}

/// File system attribute flags in the `x-ms-file-attributes` vocabulary.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub(crate) struct Attributes(u16);

const ATTRIBUTE_NAMES: [(&str, u16); 9] = [
    ("ReadOnly", 1),
    ("Hidden", 1 << 1),
    ("System", 1 << 2),
    ("Directory", 1 << 3),
    ("Archive", 1 << 4),
    ("Temporary", 1 << 5),
    ("Offline", 1 << 6),
    ("NotContentIndexed", 1 << 7),
    ("NoScrubData", 1 << 8),
];

impl Attributes {
    pub(crate) const DIRECTORY: Self = Self(1 << 3);
    pub(crate) const ARCHIVE: Self = Self(1 << 4);
    pub(crate) const READ_ONLY: Self = Self(1);

    /// Parses `Archive|ReadOnly`; `None` is valid only on its own.
    pub(crate) fn parse(value: &str) -> Result<Self> {
        let mut bits = 0;
        let mut none = false;
        let mut count = 0;
        for token in value.split('|') {
            let token = token.trim();
            count += 1;
            if token.eq_ignore_ascii_case("none") {
                none = true;
                continue;
            }
            let (_, bit) = ATTRIBUTE_NAMES
                .iter()
                .find(|(name, _)| name.eq_ignore_ascii_case(token))
                .ok_or(Error::InvalidHeaderValue)?;
            bits |= bit;
        }
        if none && count > 1 {
            return Err(Error::InvalidHeaderValue);
        }
        Ok(Self(bits))
    }

    pub(crate) fn from_bits(bits: u16) -> Self {
        Self(bits)
    }

    pub(crate) fn bits(self) -> u16 {
        self.0
    }

    pub(crate) fn contains(self, other: Self) -> bool {
        self.0 & other.0 == other.0
    }

    pub(crate) fn with(self, other: Self) -> Self {
        Self(self.0 | other.0)
    }

    /// Files created or updated with no attributes report `Archive`, as Azure does;
    /// directories always carry `Directory`.
    pub(crate) fn normalized(self, directory: bool) -> Self {
        if directory {
            self.with(Self::DIRECTORY)
        } else if self.0 == 0 {
            Self::ARCHIVE
        } else {
            self
        }
    }
}

impl std::fmt::Display for Attributes {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        if self.0 == 0 {
            return f.write_str("None");
        }
        let names: Vec<_> = ATTRIBUTE_NAMES
            .iter()
            .filter(|(_, bit)| self.0 & bit != 0)
            .map(|(name, _)| *name)
            .collect();
        f.write_str(&names.join("|"))
    }
}

/// The SMB-flavoured properties a create or set-properties request may carry.
#[derive(Clone, Debug)]
pub(crate) struct SmbProperties {
    pub(crate) attributes: Option<Attributes>,
    pub(crate) creation: TimeSpec,
    pub(crate) last_write: TimeSpec,
    pub(crate) change: Option<TimeSpec>,
    pub(crate) permission: PermissionSpec,
}

impl SmbProperties {
    /// Defaults for create operations: new timestamps and an inherited permission.
    pub(crate) fn for_create() -> Self {
        Self {
            attributes: None,
            creation: TimeSpec::Now,
            last_write: TimeSpec::Now,
            change: None,
            permission: PermissionSpec::Inherit,
        }
    }

    /// Defaults for set-properties operations: everything unchanged.
    pub(crate) fn for_update() -> Self {
        Self {
            attributes: None,
            creation: TimeSpec::Preserve,
            last_write: TimeSpec::Preserve,
            change: None,
            permission: PermissionSpec::Preserve,
        }
    }
}

/// Standard HTTP representation properties of a file.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub(crate) struct HttpProperties {
    pub(crate) content_type: Option<String>,
    pub(crate) content_encoding: Option<String>,
    pub(crate) content_language: Option<String>,
    pub(crate) content_disposition: Option<String>,
    pub(crate) cache_control: Option<String>,
    /// Base64 MD5 stored by the client; the server never computes it.
    pub(crate) md5: Option<String>,
}

impl HttpProperties {
    pub(crate) fn is_empty(&self) -> bool {
        *self == Self::default()
    }
}

#[derive(Clone, Debug, Eq, PartialEq, serde::Deserialize, serde::Serialize)]
pub(crate) struct CopyState {
    pub(crate) id: String,
    pub(crate) source: String,
    pub(crate) length: u64,
    pub(crate) completed: i64,
}

#[derive(Clone, Debug)]
pub(crate) struct NodeInfo {
    pub(crate) file_id: i64,
    pub(crate) parent_id: Option<i64>,
    pub(crate) directory: bool,
    pub(crate) name: String,
    pub(crate) etag: String,
    pub(crate) modified: i64,
    pub(crate) attributes: Attributes,
    /// SMB timestamps in Unix 100 ns ticks.
    pub(crate) creation: i64,
    pub(crate) last_write: i64,
    pub(crate) change: i64,
    pub(crate) permission_key: String,
    pub(crate) metadata: Metadata,
    pub(crate) length: u64,
    pub(crate) http: HttpProperties,
    pub(crate) lease: Option<Lease>,
    pub(crate) copy: Option<CopyState>,
    /// POSIX properties; `Some` exactly for nodes of an NFS share (ADR-0029).
    pub(crate) nfs: Option<NfsProps>,
    /// Names the inode has: one plus its additional hard links.
    pub(crate) links: u32,
    /// The `links` row this node was reached through; `None` for the inode's first name.
    pub(crate) entry: Option<i64>,
}

/// The protocol a share was created with.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub(crate) enum Protocol {
    #[default]
    Smb,
    Nfs,
}

impl Protocol {
    pub(crate) fn as_str(self) -> &'static str {
        match self {
            Self::Smb => "SMB",
            Self::Nfs => "NFS",
        }
    }

    pub(crate) fn parse(value: &str) -> Result<Self> {
        match value.to_ascii_uppercase().as_str() {
            "SMB" => Ok(Self::Smb),
            "NFS" => Ok(Self::Nfs),
            _ => Err(Error::InvalidHeaderValue),
        }
    }
}

/// The root squash setting of an NFS share. Stored and returned, never enforced.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub(crate) enum RootSquash {
    #[default]
    Off,
    Root,
    All,
}

impl RootSquash {
    /// The value Azure uses for this setting.
    pub(crate) fn as_str(self) -> &'static str {
        match self {
            Self::Off => "NoRootSquash",
            Self::Root => "RootSquash",
            Self::All => "AllSquash",
        }
    }

    pub(crate) fn parse(value: &str) -> Result<Self> {
        [Self::Off, Self::Root, Self::All]
            .into_iter()
            .find(|known| known.as_str().eq_ignore_ascii_case(value))
            .ok_or(Error::InvalidHeaderValue)
    }
}

/// The POSIX file type of an NFS node.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum FileKind {
    Regular,
    Directory,
    SymLink,
}

impl FileKind {
    pub(crate) fn as_str(self) -> &'static str {
        match self {
            Self::Regular => "Regular",
            Self::Directory => "Directory",
            Self::SymLink => "SymLink",
        }
    }

    pub(crate) fn parse(value: &str) -> Option<Self> {
        [Self::Regular, Self::Directory, Self::SymLink]
            .into_iter()
            .find(|kind| kind.as_str().eq_ignore_ascii_case(value))
    }
}

/// Mode, owner, group, file type, and link text of a node on an NFS share.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct NfsProps {
    pub(crate) mode: u32,
    pub(crate) owner: u32,
    pub(crate) group: u32,
    pub(crate) kind: FileKind,
    pub(crate) link_text: Option<String>,
}

impl NfsProps {
    /// The documented defaults (file 0644, directory 0755, owner and group 0), with any
    /// header the request carried laid over them. A symbolic link defaults to 0777.
    pub(crate) fn create(kind: FileKind, posix: Posix, link_text: Option<String>) -> Self {
        let mode = match kind {
            FileKind::Regular => 0o644,
            FileKind::Directory => 0o755,
            FileKind::SymLink => 0o777,
        };
        Self {
            mode: posix.mode.unwrap_or(mode),
            owner: posix.owner.unwrap_or(0),
            group: posix.group.unwrap_or(0),
            kind,
            link_text,
        }
    }

    /// Set Properties semantics: a header that is absent keeps the stored value.
    pub(crate) fn update(&mut self, posix: Posix) {
        self.mode = posix.mode.unwrap_or(self.mode);
        self.owner = posix.owner.unwrap_or(self.owner);
        self.group = posix.group.unwrap_or(self.group);
    }
}

/// The POSIX request headers; each is optional.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub(crate) struct Posix {
    pub(crate) mode: Option<u32>,
    pub(crate) owner: Option<u32>,
    pub(crate) group: Option<u32>,
}

/// Parses `x-ms-mode`: up to four octal digits, or nine `rwx` characters with `s`, `S`, `t`
/// and `T` for the setuid, setgid and sticky bits.
pub(crate) fn parse_mode(value: &str) -> Result<u32> {
    let bytes = value.as_bytes();
    if (1..=4).contains(&bytes.len()) && bytes.iter().all(|b| (b'0'..=b'7').contains(b)) {
        return u32::from_str_radix(value, 8).map_err(|_| Error::InvalidHeaderValue);
    }
    if bytes.len() != 9 {
        return Err(Error::InvalidHeaderValue);
    }
    let mut mode = 0;
    for (class, triple) in bytes.chunks(3).enumerate() {
        let shift = 6 - 3 * class as u32;
        let special = [0o4000, 0o2000, 0o1000][class];
        match triple[0] {
            b'r' => mode |= 0o4 << shift,
            b'-' => (),
            _ => return Err(Error::InvalidHeaderValue),
        }
        match triple[1] {
            b'w' => mode |= 0o2 << shift,
            b'-' => (),
            _ => return Err(Error::InvalidHeaderValue),
        }
        let (execute, flag) = match (triple[2], class) {
            (b'x', _) => (true, false),
            (b'-', _) => (false, false),
            (b's', 0 | 1) | (b't', 2) => (true, true),
            (b'S', 0 | 1) | (b'T', 2) => (false, true),
            _ => return Err(Error::InvalidHeaderValue),
        };
        if execute {
            mode |= 0o1 << shift;
        }
        if flag {
            mode |= special;
        }
    }
    Ok(mode)
}

/// A mode as Azure's SDKs read it back: four octal digits.
pub(crate) fn mode_text(mode: u32) -> String {
    format!("{mode:04o}")
}

#[derive(Clone, Debug)]
pub(crate) struct ShareInfo {
    pub(crate) name: String,
    pub(crate) snapshot: Option<i64>,
    pub(crate) etag: String,
    pub(crate) modified: i64,
    /// Provisioned quota in GiB.
    pub(crate) quota: u64,
    pub(crate) access_tier: String,
    pub(crate) access_tier_changed: i64,
    pub(crate) metadata: Metadata,
    pub(crate) lease: Option<Lease>,
    /// Set when the share was listed as a soft-deleted one.
    pub(crate) deleted: Option<DeletedShare>,
    pub(crate) protocol: Protocol,
    /// Stored and returned for NFS shares; never enforced.
    pub(crate) root_squash: Option<RootSquash>,
    pub(crate) snapshot_virtual_directory_access: bool,
}

/// A soft-deleted share as listed: its restore version and how long it stays restorable.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct DeletedShare {
    pub(crate) version: String,
    pub(crate) deleted_at: i64,
    pub(crate) remaining_days: u32,
}

/// One `SignedIdentifier` of a share's stored access policies.
#[derive(Clone, Debug, Eq, PartialEq, serde::Deserialize, serde::Serialize)]
pub(crate) struct AccessPolicy {
    pub(crate) id: String,
    pub(crate) start: Option<String>,
    pub(crate) expiry: Option<String>,
    pub(crate) permission: Option<String>,
}

/// Optional HTTP preconditions on a read.
#[derive(Clone, Debug, Default)]
pub(crate) struct Conditions {
    pub(crate) if_match: Option<String>,
    pub(crate) if_none_match: Option<String>,
    pub(crate) if_modified_since: Option<i64>,
    pub(crate) if_unmodified_since: Option<i64>,
}

impl Conditions {
    /// Evaluates the conditions against a resource's ETag and last-modified time
    /// (Unix milliseconds, compared at one-second resolution as HTTP dates are).
    pub(crate) fn check(&self, etag: &str, modified: i64) -> Result<()> {
        let matches = |list: &str| {
            list.split(',')
                .map(str::trim)
                .any(|tag| tag == "*" || tag == etag)
        };
        let seconds = modified.div_euclid(1000);
        if let Some(list) = &self.if_match
            && !matches(list)
        {
            return Err(Error::ConditionNotMet);
        }
        if let Some(since) = self.if_unmodified_since
            && seconds > since.div_euclid(1000)
        {
            return Err(Error::ConditionNotMet);
        }
        if let Some(list) = &self.if_none_match
            && matches(list)
        {
            return Err(Error::NotModified);
        }
        if let Some(since) = self.if_modified_since
            && self.if_none_match.is_none()
            && seconds <= since.div_euclid(1000)
        {
            return Err(Error::NotModified);
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn metadata_names_must_be_identifiers_and_fit() {
        let pairs = |name: &str, value: &str| [(name.to_owned(), value.to_owned())];
        assert_eq!(metadata(pairs("Owner_1", "x")).unwrap()["owner_1"], "x");
        for bad in ["1abc", "a-b", "a b", "é"] {
            assert_eq!(
                metadata(pairs(bad, "v")),
                Err(Error::InvalidMetadata),
                "{bad}"
            );
        }
        assert_eq!(metadata(pairs("", "v")), Err(Error::EmptyMetadataKey));
        assert_eq!(
            metadata(pairs("big", &"v".repeat(8200))),
            Err(Error::MetadataTooLarge)
        );
        assert_eq!(
            metadata([("A".into(), "1".into()), ("a".into(), "2".into())]),
            Err(Error::InvalidMetadata)
        );
    }

    #[test]
    fn attributes_round_trip_and_normalize() {
        let attributes = Attributes::parse("readonly|Archive").unwrap();
        assert_eq!(attributes.to_string(), "ReadOnly|Archive");
        assert!(attributes.contains(Attributes::READ_ONLY));
        assert_eq!(Attributes::parse("None").unwrap().to_string(), "None");
        assert_eq!(
            Attributes::parse("None").unwrap().normalized(false),
            Attributes::ARCHIVE
        );
        assert_eq!(
            Attributes::parse("None")
                .unwrap()
                .normalized(true)
                .to_string(),
            "Directory"
        );
        assert!(Attributes::parse("None|Hidden").is_err());
        assert!(Attributes::parse("Bogus").is_err());
        assert!(Attributes::parse("").is_err());
    }

    #[test]
    fn modes_parse_from_octal_and_rwx_and_render_as_four_digits() {
        for (text, mode) in [
            ("0644", 0o644),
            ("644", 0o644),
            ("0", 0),
            ("7777", 0o7777),
            ("rw-r--r--", 0o644),
            ("rwxr-xr-x", 0o755),
            ("rwsr-sr-t", 0o7755),
            ("rwSr-Sr-T", 0o7644),
            ("---------", 0),
        ] {
            assert_eq!(parse_mode(text), Ok(mode), "{text}");
        }
        assert_eq!(mode_text(0o644), "0644");
        assert_eq!(mode_text(0o7777), "7777");
        assert_eq!(mode_text(0), "0000");
        for bad in [
            "",
            "8",
            "00644",
            "0648",
            "-644",
            "rwxrwxrw",
            "rwxrwxrwxx",
            "rwxrwxrwt-",
            "rwtrwxrwx",
            "xwxrwxrwx",
            "rwxrwxrwS",
            " 644",
        ] {
            assert_eq!(parse_mode(bad), Err(Error::InvalidHeaderValue), "{bad:?}");
        }
    }

    #[test]
    fn posix_defaults_and_updates_follow_the_documentation() {
        let file = NfsProps::create(FileKind::Regular, Posix::default(), None);
        assert_eq!((file.mode, file.owner, file.group), (0o644, 0, 0));
        let directory = NfsProps::create(FileKind::Directory, Posix::default(), None);
        assert_eq!(directory.mode, 0o755);
        let link = NfsProps::create(FileKind::SymLink, Posix::default(), Some("x".into()));
        assert_eq!((link.mode, link.link_text.as_deref()), (0o777, Some("x")));
        let mut node = NfsProps::create(
            FileKind::Regular,
            Posix {
                mode: Some(0o600),
                owner: Some(1000),
                group: None,
            },
            None,
        );
        assert_eq!((node.mode, node.owner, node.group), (0o600, 1000, 0));
        node.update(Posix {
            group: Some(7),
            ..Posix::default()
        });
        assert_eq!((node.mode, node.owner, node.group), (0o600, 1000, 7));
        assert_eq!(FileKind::parse("symlink"), Some(FileKind::SymLink));
        assert_eq!(FileKind::parse("Fifo"), None);
        assert_eq!(Protocol::parse("nfs"), Ok(Protocol::Nfs));
        assert_eq!(Protocol::parse("ext4"), Err(Error::InvalidHeaderValue));
        assert_eq!(RootSquash::parse("allsquash"), Ok(RootSquash::All));
        assert_eq!(RootSquash::parse("NoRootSquash"), Ok(RootSquash::Off));
        assert_eq!(RootSquash::Root.as_str(), "RootSquash");
    }

    #[test]
    fn time_specs_resolve_against_now_and_current() {
        assert_eq!(TimeSpec::Now.resolve(5, 1), 50_000);
        assert_eq!(TimeSpec::Preserve.resolve(5, 1), 1);
        assert_eq!(TimeSpec::At(9).resolve(5, 1), 9);
    }

    #[test]
    fn conditions_follow_http_semantics() {
        let tag = "\"0x1\"";
        let when = 10_500;
        let check = |conditions: Conditions| conditions.check(tag, when);
        assert_eq!(check(Conditions::default()), Ok(()));
        let if_match = |value: &str| Conditions {
            if_match: Some(value.into()),
            ..Conditions::default()
        };
        assert_eq!(check(if_match(tag)), Ok(()));
        assert_eq!(check(if_match("*")), Ok(()));
        assert_eq!(check(if_match("\"0x2\"")), Err(Error::ConditionNotMet));
        let none_match = Conditions {
            if_none_match: Some(tag.into()),
            ..Conditions::default()
        };
        assert_eq!(check(none_match), Err(Error::NotModified));
        let modified_since = |since| Conditions {
            if_modified_since: Some(since),
            ..Conditions::default()
        };
        assert_eq!(check(modified_since(10_000)), Err(Error::NotModified));
        assert_eq!(check(modified_since(9_000)), Ok(()));
        let unmodified_since = Conditions {
            if_unmodified_since: Some(9_000),
            ..Conditions::default()
        };
        assert_eq!(check(unmodified_since), Err(Error::ConditionNotMet));
    }
}
