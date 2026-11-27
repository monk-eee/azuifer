//! The HTTP edge of FileREST: query and path parsing, operation routing, and typed header
//! extraction. Handlers receive validated values, never raw headers.

use super::{
    auth::{Level, Needs},
    error::{Error, Result},
    lease,
    model::{
        self, Attributes, Conditions, HttpProperties, Metadata, PermissionSpec, Posix,
        SmbProperties, TimeSpec,
    },
    name::{EntryPath, ShareName},
    store::{CopyBy, NfsCopy},
    time,
};
use crate::{auth, domain::AccountName};
use axum::http::{HeaderMap, Method};
use base64::{Engine as _, engine::general_purpose::STANDARD};
use percent_encoding::percent_decode_str;
use std::collections::BTreeMap;

const MAX_QUERY_BYTES: usize = 16 * 1024;
const MAX_FILE_BYTES: u64 = 4 * 1024 * 1024 * 1024 * 1024;

/// Query parameters: names lower-cased, values percent-decoded, repeats preserved.
#[derive(Clone, Debug, Default)]
pub(super) struct Query(BTreeMap<String, Vec<String>>);

impl Query {
    pub(super) fn parse(raw: Option<&str>) -> Result<Self> {
        let mut map: BTreeMap<String, Vec<String>> = BTreeMap::new();
        let Some(raw) = raw.filter(|raw| !raw.is_empty()) else {
            return Ok(Self(map));
        };
        if raw.len() > MAX_QUERY_BYTES {
            return Err(Error::InvalidQueryParameterValue);
        }
        for pair in raw.split('&').filter(|pair| !pair.is_empty()) {
            let (name, value) = pair.split_once('=').unwrap_or((pair, ""));
            let decode = |text: &str| {
                percent_decode_str(&text.replace('+', " "))
                    .decode_utf8()
                    .map(|text| text.into_owned())
                    .map_err(|_| Error::InvalidQueryParameterValue)
            };
            map.entry(decode(name)?.to_ascii_lowercase())
                .or_default()
                .push(decode(value)?);
        }
        Ok(Self(map))
    }

    pub(super) fn get(&self, name: &str) -> Option<&str> {
        self.0
            .get(name)
            .and_then(|values| values.first())
            .map(String::as_str)
    }

    /// Each name with its sorted, comma-joined values, the form Shared Key signs.
    pub(super) fn joined(&self) -> auth::Query {
        self.0
            .iter()
            .map(|(name, values)| {
                let mut values = values.clone();
                values.sort();
                (name.clone(), values.join(","))
            })
            .collect()
    }

    /// The comma-separated `include` values, lower-cased.
    pub(super) fn includes(&self) -> Vec<String> {
        self.0
            .get("include")
            .into_iter()
            .flatten()
            .flat_map(|value| value.split(','))
            .map(|value| value.trim().to_ascii_lowercase())
            .filter(|value| !value.is_empty())
            .collect()
    }

    pub(super) fn limit(&self) -> Result<u32> {
        match self.get("maxresults") {
            None => Ok(5000),
            Some(value) => match value.parse::<u32>() {
                Ok(0) | Err(_) => Err(Error::InvalidQueryParameterValue),
                Ok(limit) => Ok(limit.min(5000)),
            },
        }
    }

    pub(super) fn snapshot(&self, name: &str) -> Result<Option<i64>> {
        self.get(name)
            .map(|value| time::parse_iso(value).ok_or(Error::InvalidQueryParameterValue))
            .transpose()
    }
}

/// The resource an HTTP path addresses.
#[derive(Clone)]
pub(super) struct Target {
    pub(super) account: AccountName,
    pub(super) share: Option<ShareName>,
    pub(super) path: EntryPath,
    /// The decoded path as sent, for SAS canonicalisation.
    pub(super) decoded: String,
}

impl Target {
    /// Parses `/{account}[/{share}[/{path}]]`.
    pub(super) fn parse(raw_path: &str, keep_trailing_dots: bool) -> Result<Self> {
        let rest = raw_path.strip_prefix('/').ok_or(Error::InvalidUri)?;
        let mut segments = rest.splitn(3, '/');
        let account = AccountName::parse(segments.next().unwrap_or_default())
            .map_err(|_| Error::InvalidUri)?;
        let share = segments.next().filter(|share| !share.is_empty());
        let path = segments.next().unwrap_or_default();
        let decoded = percent_decode_str(path)
            .decode_utf8()
            .map_err(|_| Error::InvalidUri)?
            .into_owned();
        let share = share
            .map(|share| {
                percent_decode_str(share)
                    .decode_utf8()
                    .map_err(|_| Error::InvalidResourceName)
                    .and_then(|share| ShareName::parse(&share))
            })
            .transpose()?;
        if share.is_none() && !decoded.is_empty() {
            return Err(Error::InvalidUri);
        }
        Ok(Self {
            account,
            share,
            path: EntryPath::parse(&decoded, keep_trailing_dots)?,
            decoded,
        })
    }
}

/// Every FileREST operation the router recognises, named as in the Microsoft reference.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum Operation {
    ListShares,
    GetFileServiceProperties,
    SetFileServiceProperties,
    CreateShare,
    GetShareProperties,
    SetShareProperties,
    GetShareMetadata,
    SetShareMetadata,
    DeleteShare,
    GetShareAcl,
    SetShareAcl,
    GetShareStats,
    LeaseShare,
    SnapshotShare,
    RestoreShare,
    CreatePermission,
    GetPermission,
    CreateDirectory,
    GetDirectoryProperties,
    SetDirectoryProperties,
    GetDirectoryMetadata,
    SetDirectoryMetadata,
    DeleteDirectory,
    ListFilesAndDirectories,
    RenameDirectory,
    ListDirectoryHandles,
    ForceCloseDirectoryHandles,
    CreateFile,
    GetFile,
    GetFileProperties,
    SetFileProperties,
    GetFileMetadata,
    SetFileMetadata,
    DeleteFile,
    PutRange,
    PutRangeFromUrl,
    ListRanges,
    CopyFile,
    AbortCopyFile,
    LeaseFile,
    RenameFile,
    ListFileHandles,
    ForceCloseFileHandles,
    CreateHardLink,
    CreateSymbolicLink,
    GetSymbolicLink,
}

impl Operation {
    /// Every recognised operation, for the conformance manifest consistency test.
    #[cfg(test)]
    pub(crate) const ALL: [Self; 46] = [
        Self::ListShares,
        Self::GetFileServiceProperties,
        Self::SetFileServiceProperties,
        Self::CreateShare,
        Self::GetShareProperties,
        Self::SetShareProperties,
        Self::GetShareMetadata,
        Self::SetShareMetadata,
        Self::DeleteShare,
        Self::GetShareAcl,
        Self::SetShareAcl,
        Self::GetShareStats,
        Self::LeaseShare,
        Self::SnapshotShare,
        Self::RestoreShare,
        Self::CreatePermission,
        Self::GetPermission,
        Self::CreateDirectory,
        Self::GetDirectoryProperties,
        Self::SetDirectoryProperties,
        Self::GetDirectoryMetadata,
        Self::SetDirectoryMetadata,
        Self::DeleteDirectory,
        Self::ListFilesAndDirectories,
        Self::RenameDirectory,
        Self::ListDirectoryHandles,
        Self::ForceCloseDirectoryHandles,
        Self::CreateFile,
        Self::GetFile,
        Self::GetFileProperties,
        Self::SetFileProperties,
        Self::GetFileMetadata,
        Self::SetFileMetadata,
        Self::DeleteFile,
        Self::PutRange,
        Self::PutRangeFromUrl,
        Self::ListRanges,
        Self::CopyFile,
        Self::AbortCopyFile,
        Self::LeaseFile,
        Self::RenameFile,
        Self::ListFileHandles,
        Self::ForceCloseFileHandles,
        Self::CreateHardLink,
        Self::CreateSymbolicLink,
        Self::GetSymbolicLink,
    ];

    /// The operation name in the Microsoft REST reference.
    pub(crate) fn name(self) -> &'static str {
        match self {
            Self::ListShares => "List Shares",
            Self::GetFileServiceProperties => "Get File Service Properties",
            Self::SetFileServiceProperties => "Set File Service Properties",
            Self::CreateShare => "Create Share",
            Self::GetShareProperties => "Get Share Properties",
            Self::SetShareProperties => "Set Share Properties",
            Self::GetShareMetadata => "Get Share Metadata",
            Self::SetShareMetadata => "Set Share Metadata",
            Self::DeleteShare => "Delete Share",
            Self::GetShareAcl => "Get Share ACL",
            Self::SetShareAcl => "Set Share ACL",
            Self::GetShareStats => "Get Share Stats",
            Self::LeaseShare => "Lease Share",
            Self::SnapshotShare => "Snapshot Share",
            Self::RestoreShare => "Restore Share",
            Self::CreatePermission => "Create Permission",
            Self::GetPermission => "Get Permission",
            Self::CreateDirectory => "Create Directory",
            Self::GetDirectoryProperties => "Get Directory Properties",
            Self::SetDirectoryProperties => "Set Directory Properties",
            Self::GetDirectoryMetadata => "Get Directory Metadata",
            Self::SetDirectoryMetadata => "Set Directory Metadata",
            Self::DeleteDirectory => "Delete Directory",
            Self::ListFilesAndDirectories => "List Directories and Files",
            Self::RenameDirectory => "Rename Directory",
            Self::ListDirectoryHandles | Self::ListFileHandles => "List Handles",
            Self::ForceCloseDirectoryHandles | Self::ForceCloseFileHandles => "Force Close Handles",
            Self::CreateFile => "Create File",
            Self::GetFile => "Get File",
            Self::GetFileProperties => "Get File Properties",
            Self::SetFileProperties => "Set File Properties",
            Self::GetFileMetadata => "Get File Metadata",
            Self::SetFileMetadata => "Set File Metadata",
            Self::DeleteFile => "Delete File",
            Self::PutRange => "Put Range",
            Self::PutRangeFromUrl => "Put Range From URL",
            Self::ListRanges => "List Ranges",
            Self::CopyFile => "Copy File",
            Self::AbortCopyFile => "Abort Copy File",
            Self::LeaseFile => "Lease File",
            Self::RenameFile => "Rename File",
            Self::CreateHardLink => "Create Hard Link",
            Self::CreateSymbolicLink => "Create Symbolic Link",
            Self::GetSymbolicLink => "Read Symbolic Link",
        }
    }

    /// The SAS scope and permissions the operation requires.
    pub(super) fn needs(self) -> Needs {
        let (level, types, account, service) = match self {
            Self::ListShares => (Level::Account, "s", "l", ""),
            Self::CreateShare | Self::RestoreShare => (Level::Share, "c", "cw", ""),
            Self::GetShareProperties
            | Self::GetShareMetadata
            | Self::GetShareAcl
            | Self::GetShareStats
            | Self::GetPermission => (Level::Share, "c", "r", ""),
            Self::SetShareProperties
            | Self::SetShareMetadata
            | Self::SetShareAcl
            | Self::LeaseShare
            | Self::CreatePermission => (Level::Share, "c", "w", ""),
            Self::SnapshotShare => (Level::Share, "c", "cw", ""),
            Self::DeleteShare => (Level::Share, "c", "d", ""),
            Self::CreateDirectory => (Level::Directory, "o", "cw", "cw"),
            Self::GetDirectoryProperties
            | Self::GetDirectoryMetadata
            | Self::ListDirectoryHandles => (Level::Directory, "o", "r", "r"),
            Self::SetDirectoryProperties
            | Self::SetDirectoryMetadata
            | Self::RenameDirectory
            | Self::ForceCloseDirectoryHandles => (Level::Directory, "o", "w", "w"),
            Self::DeleteDirectory => (Level::Directory, "o", "d", "d"),
            Self::ListFilesAndDirectories => (Level::Directory, "co", "l", "l"),
            Self::CreateFile | Self::CopyFile => (Level::File, "o", "cw", "cw"),
            Self::GetFile
            | Self::GetFileProperties
            | Self::GetFileMetadata
            | Self::ListRanges
            | Self::ListFileHandles => (Level::File, "o", "r", "r"),
            Self::SetFileProperties
            | Self::SetFileMetadata
            | Self::PutRange
            | Self::PutRangeFromUrl
            | Self::AbortCopyFile
            | Self::LeaseFile
            | Self::RenameFile
            | Self::ForceCloseFileHandles => (Level::File, "o", "w", "w"),
            Self::DeleteFile => (Level::File, "o", "d", "d"),
            Self::GetFileServiceProperties => (Level::Account, "s", "r", ""),
            Self::SetFileServiceProperties => (Level::Account, "s", "w", ""),
            Self::CreateHardLink | Self::CreateSymbolicLink | Self::GetSymbolicLink => {
                (Level::Account, "s", "", "")
            }
        };
        Needs {
            level,
            resource_types: types,
            account_permissions: account,
            service_permissions: service,
        }
    }
}

/// Maps an HTTP request to an operation. Pure, so every route is unit-testable.
pub(super) fn route(
    method: &Method,
    target: &Target,
    query: &Query,
    headers: &Headers<'_>,
) -> Result<Operation> {
    use Operation as O;
    let comp = query.get("comp");
    let restype = query.get("restype");
    let (get, head, put, delete) = (
        method == Method::GET,
        method == Method::HEAD,
        method == Method::PUT,
        method == Method::DELETE,
    );
    let wrong_verb = Err(Error::UnsupportedHttpVerb);
    if target.share.is_none() {
        return match (restype, comp) {
            (None, Some("list")) if get => Ok(O::ListShares),
            (Some("service"), Some("properties")) if get => Ok(O::GetFileServiceProperties),
            (Some("service"), Some("properties")) if put => Ok(O::SetFileServiceProperties),
            (None, Some("list")) | (Some("service"), Some("properties")) => wrong_verb,
            _ => Err(Error::InvalidQueryParameterValue),
        };
    }
    match restype {
        Some("share") if target.path.is_root() => match (comp, get, head, put, delete) {
            (None, _, _, true, _) => Ok(O::CreateShare),
            (None, true, _, _, _) | (None, _, true, _, _) => Ok(O::GetShareProperties),
            (None, _, _, _, true) => Ok(O::DeleteShare),
            (Some("properties"), _, _, true, _) => Ok(O::SetShareProperties),
            (Some("metadata"), _, _, true, _) => Ok(O::SetShareMetadata),
            (Some("metadata"), true, _, _, _) | (Some("metadata"), _, true, _, _) => {
                Ok(O::GetShareMetadata)
            }
            (Some("acl"), true, _, _, _) => Ok(O::GetShareAcl),
            (Some("acl"), _, _, true, _) => Ok(O::SetShareAcl),
            (Some("stats"), true, _, _, _) => Ok(O::GetShareStats),
            (Some("lease"), _, _, true, _) => Ok(O::LeaseShare),
            (Some("snapshot"), _, _, true, _) => Ok(O::SnapshotShare),
            (Some("undelete"), _, _, true, _) => Ok(O::RestoreShare),
            (Some("filepermission"), _, _, true, _) => Ok(O::CreatePermission),
            (Some("filepermission"), true, _, _, _) => Ok(O::GetPermission),
            (
                None
                | Some(
                    "properties" | "metadata" | "acl" | "stats" | "lease" | "snapshot" | "undelete"
                    | "filepermission",
                ),
                ..,
            ) => wrong_verb,
            _ => Err(Error::InvalidQueryParameterValue),
        },
        Some("directory") => match (comp, get, head, put, delete) {
            (None, _, _, true, _) => Ok(O::CreateDirectory),
            (None, true, _, _, _) | (None, _, true, _, _) => Ok(O::GetDirectoryProperties),
            (None, _, _, _, true) => Ok(O::DeleteDirectory),
            (Some("properties"), _, _, true, _) => Ok(O::SetDirectoryProperties),
            (Some("metadata"), _, _, true, _) => Ok(O::SetDirectoryMetadata),
            (Some("metadata"), true, _, _, _) | (Some("metadata"), _, true, _, _) => {
                Ok(O::GetDirectoryMetadata)
            }
            (Some("list"), true, _, _, _) => Ok(O::ListFilesAndDirectories),
            (Some("listhandles"), true, _, _, _) => Ok(O::ListDirectoryHandles),
            (Some("forceclosehandles"), _, _, true, _) => Ok(O::ForceCloseDirectoryHandles),
            (Some("rename"), _, _, true, _) => Ok(O::RenameDirectory),
            (
                None
                | Some(
                    "properties" | "metadata" | "list" | "listhandles" | "forceclosehandles"
                    | "rename",
                ),
                ..,
            ) => wrong_verb,
            _ => Err(Error::InvalidQueryParameterValue),
        },
        None if !target.path.is_root() => match (comp, get, head, put, delete) {
            (None, _, _, true, _) if headers.has("x-ms-copy-source") => Ok(O::CopyFile),
            (None, _, _, true, _) => Ok(O::CreateFile),
            (None, true, _, _, _) => Ok(O::GetFile),
            (None, _, true, _, _) => Ok(O::GetFileProperties),
            (None, _, _, _, true) => Ok(O::DeleteFile),
            (Some("properties"), _, _, true, _) => Ok(O::SetFileProperties),
            (Some("metadata"), _, _, true, _) => Ok(O::SetFileMetadata),
            (Some("metadata"), true, _, _, _) | (Some("metadata"), _, true, _, _) => {
                Ok(O::GetFileMetadata)
            }
            (Some("range"), _, _, true, _) if headers.has("x-ms-copy-source") => {
                Ok(O::PutRangeFromUrl)
            }
            (Some("range"), _, _, true, _) => Ok(O::PutRange),
            (Some("rangelist"), true, _, _, _) => Ok(O::ListRanges),
            (Some("copy"), _, _, true, _) => Ok(O::AbortCopyFile),
            (Some("lease"), _, _, true, _) => Ok(O::LeaseFile),
            (Some("rename"), _, _, true, _) => Ok(O::RenameFile),
            (Some("listhandles"), true, _, _, _) => Ok(O::ListFileHandles),
            (Some("forceclosehandles"), _, _, true, _) => Ok(O::ForceCloseFileHandles),
            (
                None
                | Some(
                    "properties" | "metadata" | "range" | "rangelist" | "copy" | "lease" | "rename"
                    | "listhandles" | "forceclosehandles",
                ),
                ..,
            ) => wrong_verb,
            _ => Err(Error::InvalidQueryParameterValue),
        },
        Some("hardlink") if !target.path.is_root() && comp.is_none() => {
            if put {
                Ok(O::CreateHardLink)
            } else {
                wrong_verb
            }
        }
        Some("symboliclink") if !target.path.is_root() && comp.is_none() => match (get, put) {
            (_, true) => Ok(O::CreateSymbolicLink),
            (true, _) => Ok(O::GetSymbolicLink),
            _ => wrong_verb,
        },
        _ => Err(Error::InvalidQueryParameterValue),
    }
}

/// Typed access to request headers.
pub(super) struct Headers<'a>(pub(super) &'a HeaderMap);

impl Headers<'_> {
    pub(super) fn has(&self, name: &str) -> bool {
        self.0.contains_key(name)
    }

    pub(super) fn get(&self, name: &str) -> Result<Option<&str>> {
        auth::header(self.0, name).map_err(|_| Error::InvalidHeaderValue)
    }

    pub(super) fn required(&self, name: &str) -> Result<&str> {
        self.get(name)?.ok_or(Error::MissingRequiredHeader)
    }

    pub(super) fn number(&self, name: &str) -> Result<Option<u64>> {
        self.get(name)?
            .map(|value| value.parse().map_err(|_| Error::InvalidHeaderValue))
            .transpose()
    }

    pub(super) fn flag(&self, name: &str) -> Result<bool> {
        match self.get(name)? {
            None => Ok(false),
            Some(value) if value.eq_ignore_ascii_case("true") => Ok(true),
            Some(value) if value.eq_ignore_ascii_case("false") => Ok(false),
            Some(_) => Err(Error::InvalidHeaderValue),
        }
    }

    pub(super) fn lease_id(&self, name: &str) -> Result<Option<String>> {
        self.get(name)?.map(lease::parse_id).transpose()
    }

    /// `x-ms-meta-*` headers as validated metadata.
    pub(super) fn metadata(&self) -> Result<Metadata> {
        let mut pairs = Vec::new();
        for (name, value) in self.0 {
            if let Some(key) = name.as_str().strip_prefix("x-ms-meta-") {
                let value = value.to_str().map_err(|_| Error::InvalidMetadata)?;
                pairs.push((key.to_owned(), value.to_owned()));
            }
        }
        model::metadata(pairs)
    }

    pub(super) fn has_metadata(&self) -> bool {
        self.0
            .keys()
            .any(|name| name.as_str().starts_with("x-ms-meta-"))
    }

    pub(super) fn md5(&self, name: &str) -> Result<Option<[u8; 16]>> {
        self.get(name)?
            .map(|value| {
                STANDARD
                    .decode(value)
                    .ok()
                    .and_then(|bytes| <[u8; 16]>::try_from(bytes).ok())
                    .ok_or(Error::InvalidMd5)
            })
            .transpose()
    }

    pub(super) fn crc64(&self, name: &str) -> Result<Option<u64>> {
        self.get(name)?
            .map(|value| {
                STANDARD
                    .decode(value)
                    .ok()
                    .and_then(|bytes| <[u8; 8]>::try_from(bytes).ok())
                    .map(u64::from_le_bytes)
                    .ok_or(Error::InvalidHeaderValue)
            })
            .transpose()
    }

    /// The five HTTP representation headers; `None` when none is present.
    pub(super) fn http_properties(&self) -> Result<Option<HttpProperties>> {
        let text = |name| self.get(name).map(|value| value.map(str::to_owned));
        let md5 = self
            .md5("x-ms-content-md5")?
            .map(|bytes| STANDARD.encode(bytes));
        let http = HttpProperties {
            content_type: text("x-ms-content-type")?,
            content_encoding: text("x-ms-content-encoding")?,
            content_language: text("x-ms-content-language")?,
            content_disposition: text("x-ms-content-disposition")?,
            cache_control: text("x-ms-cache-control")?,
            md5,
        };
        Ok((!http.is_empty()).then_some(http))
    }

    fn time_spec(&self, name: &str) -> Result<Option<TimeSpec>> {
        self.get(name)?
            .map(|value| match value.to_ascii_lowercase().as_str() {
                "now" => Ok(TimeSpec::Now),
                "preserve" => Ok(TimeSpec::Preserve),
                _ => time::parse_iso_ticks(value)
                    .map(TimeSpec::At)
                    .ok_or(Error::InvalidHeaderValue),
            })
            .transpose()
    }

    /// SMB attributes, timestamps, and permission, defaulting per create or update.
    pub(super) fn smb(&self, create: bool) -> Result<SmbProperties> {
        let mut smb = if create {
            SmbProperties::for_create()
        } else {
            SmbProperties::for_update()
        };
        smb.attributes = match self.get("x-ms-file-attributes")? {
            None | Some("preserve") => None,
            Some(value) => Some(Attributes::parse(value)?),
        };
        if let Some(spec) = self.time_spec("x-ms-file-creation-time")? {
            smb.creation = spec;
        }
        if let Some(spec) = self.time_spec("x-ms-file-last-write-time")? {
            smb.last_write = spec;
        }
        smb.change = self.time_spec("x-ms-file-change-time")?;
        smb.permission = match (
            self.get("x-ms-file-permission")?,
            self.get("x-ms-file-permission-key")?,
        ) {
            (Some(_), Some(_)) => return Err(Error::InvalidHeaderValue),
            (Some("inherit"), None) => PermissionSpec::Inherit,
            (Some("preserve"), None) => PermissionSpec::Preserve,
            (Some(sddl), None) => {
                if self.get("x-ms-file-permission-format")? == Some("binary") {
                    return Err(Error::NotImplemented);
                }
                PermissionSpec::Sddl(sddl.to_owned())
            }
            (None, Some(key)) => PermissionSpec::Key(key.to_owned()),
            (None, None) if create => PermissionSpec::Inherit,
            (None, None) => PermissionSpec::Preserve,
        };
        Ok(smb)
    }

    /// `x-ms-mode`, `x-ms-owner` and `x-ms-group`; each is optional.
    pub(super) fn posix(&self) -> Result<Posix> {
        let id = |name: &str| -> Result<Option<u32>> {
            self.get(name)?
                .map(|value| {
                    if value.is_empty() || !value.bytes().all(|b| b.is_ascii_digit()) {
                        return Err(Error::InvalidHeaderValue);
                    }
                    value.parse().map_err(|_| Error::InvalidHeaderValue)
                })
                .transpose()
        };
        Ok(Posix {
            mode: self.get("x-ms-mode")?.map(model::parse_mode).transpose()?,
            owner: id("x-ms-owner")?,
            group: id("x-ms-group")?,
        })
    }

    /// A header that is a Boolean when present and unset when absent.
    pub(super) fn optional_flag(&self, name: &str) -> Result<Option<bool>> {
        self.get(name)?
            .map(|value| match value.to_ascii_lowercase().as_str() {
                "true" => Ok(true),
                "false" => Ok(false),
                _ => Err(Error::InvalidHeaderValue),
            })
            .transpose()
    }

    /// `x-ms-file-mode-copy-mode` and `x-ms-file-owner-copy-mode`, each `source` (the
    /// default) or `override`, which requires the headers that carry the new values.
    pub(super) fn nfs_copy(&self) -> Result<NfsCopy> {
        let by = |name: &str| -> Result<CopyBy> {
            match self.get(name)? {
                None => Ok(CopyBy::Source),
                Some(value) if value.eq_ignore_ascii_case("source") => Ok(CopyBy::Source),
                Some(value) if value.eq_ignore_ascii_case("override") => Ok(CopyBy::Override),
                Some(_) => Err(Error::InvalidHeaderValue),
            }
        };
        let copy = NfsCopy {
            mode: by("x-ms-file-mode-copy-mode")?,
            owner: by("x-ms-file-owner-copy-mode")?,
            posix: self.posix()?,
        };
        if copy.mode == CopyBy::Override && copy.posix.mode.is_none() {
            return Err(Error::MissingRequiredHeader);
        }
        if copy.owner == CopyBy::Override
            && (copy.posix.owner.is_none() || copy.posix.group.is_none())
        {
            return Err(Error::MissingRequiredHeader);
        }
        Ok(copy)
    }

    /// Standard HTTP preconditions for reads.
    pub(super) fn conditions(&self) -> Result<Conditions> {
        let date = |name| -> Result<Option<i64>> {
            self.get(name)?
                .map(|value| {
                    httpdate::parse_http_date(value)
                        .ok()
                        .map(crate::clock::to_millis)
                        .ok_or(Error::InvalidHeaderValue)
                })
                .transpose()
        };
        Ok(Conditions {
            if_match: self.get("if-match")?.map(str::to_owned),
            if_none_match: self.get("if-none-match")?.map(str::to_owned),
            if_modified_since: date("if-modified-since")?,
            if_unmodified_since: date("if-unmodified-since")?,
        })
    }

    /// `x-ms-range` (preferred) or `Range` as `bytes=start-end`.
    pub(super) fn range(&self) -> Result<Option<ByteRange>> {
        let value = match self.get("x-ms-range")? {
            Some(value) => Some(value),
            None => self.get("range")?,
        };
        value.map(ByteRange::parse).transpose()
    }

    pub(super) fn content_length(&self) -> Result<u64> {
        self.number("content-length")?
            .ok_or(Error::MissingContentLengthHeader)
    }
}

/// A `bytes=start-end` range with an inclusive, optional end.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) struct ByteRange {
    pub(super) start: u64,
    pub(super) end: Option<u64>,
}

impl ByteRange {
    pub(super) fn parse(value: &str) -> Result<Self> {
        let (start, end) = value
            .strip_prefix("bytes=")
            .and_then(|range| range.split_once('-'))
            .ok_or(Error::InvalidHeaderValue)?;
        let start = start.parse().map_err(|_| Error::InvalidHeaderValue)?;
        let end = match end {
            "" => None,
            end => Some(end.parse().map_err(|_| Error::InvalidHeaderValue)?),
        };
        if end.is_some_and(|end| end < start) {
            return Err(Error::InvalidHeaderValue);
        }
        Ok(Self { start, end })
    }

    /// For writes: both ends are mandatory; returns `(offset, length)`.
    pub(super) fn exact(self) -> Result<(u64, u64)> {
        let end = self.end.ok_or(Error::InvalidHeaderValue)?;
        Ok((self.start, end - self.start + 1))
    }
}

/// The `x-ms-content-length` of a new or resized file, within the 4 TiB limit.
pub(super) fn file_length(headers: &Headers<'_>, name: &str) -> Result<Option<u64>> {
    headers
        .number(name)?
        .map(|length| {
            if length > MAX_FILE_BYTES {
                Err(Error::InvalidHeaderValue)
            } else {
                Ok(length)
            }
        })
        .transpose()
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::http::HeaderValue;

    fn target(path: &str) -> Target {
        Target::parse(path, false).unwrap()
    }

    fn route_of(
        method: Method,
        path: &str,
        query: &str,
        headers: &[(&str, &str)],
    ) -> Result<Operation> {
        let mut map = HeaderMap::new();
        for (name, value) in headers {
            map.insert(
                axum::http::HeaderName::from_bytes(name.as_bytes()).unwrap(),
                HeaderValue::from_str(value).unwrap(),
            );
        }
        route(
            &method,
            &target(path),
            &Query::parse(Some(query)).unwrap(),
            &Headers(&map),
        )
    }

    #[test]
    fn query_is_decoded_lowercased_and_keeps_repeats() {
        let query = Query::parse(Some(
            "Comp=list&include=metadata&include=snapshots&prefix=a%20b+c",
        ))
        .unwrap();
        assert_eq!(query.get("comp"), Some("list"));
        assert_eq!(query.get("prefix"), Some("a b c"));
        assert_eq!(query.includes(), ["metadata", "snapshots"]);
        assert_eq!(query.joined()["include"], "metadata,snapshots");
        assert!(Query::parse(Some("a=%ff")).is_err());
    }

    #[test]
    fn maxresults_is_clamped_and_validated() {
        let limit = |text: &str| Query::parse(Some(text)).unwrap().limit();
        assert_eq!(limit("maxresults=10"), Ok(10));
        assert_eq!(limit("maxresults=99999"), Ok(5000));
        assert_eq!(limit("a=b"), Ok(5000));
        assert!(limit("maxresults=0").is_err());
        assert!(limit("maxresults=x").is_err());
    }

    #[test]
    fn targets_split_account_share_and_path() {
        let parsed = target("/acct123/share1/Dir%20One/file.txt");
        assert_eq!(parsed.share.as_ref().map(ShareName::as_str), Some("share1"));
        assert_eq!(parsed.path.components(), ["Dir One", "file.txt"]);
        assert_eq!(parsed.decoded, "Dir One/file.txt");
        assert!(target("/acct123").share.is_none());
        assert!(target("/acct123/").share.is_none());
        assert!(Target::parse("/acct123/Share", false).is_err());
        assert!(Target::parse("acct123", false).is_err());
        assert!(Target::parse("/ab", false).is_err());
    }

    #[test]
    fn routes_cover_every_documented_form() {
        use Operation as O;
        let cases = [
            (Method::GET, "/acct123", "comp=list", O::ListShares),
            (
                Method::PUT,
                "/acct123/share1",
                "restype=share",
                O::CreateShare,
            ),
            (
                Method::HEAD,
                "/acct123/share1",
                "restype=share",
                O::GetShareProperties,
            ),
            (
                Method::DELETE,
                "/acct123/share1",
                "restype=share",
                O::DeleteShare,
            ),
            (
                Method::PUT,
                "/acct123/share1",
                "restype=share&comp=snapshot",
                O::SnapshotShare,
            ),
            (
                Method::PUT,
                "/acct123/share1",
                "restype=share&comp=lease",
                O::LeaseShare,
            ),
            (
                Method::GET,
                "/acct123/share1",
                "restype=share&comp=acl",
                O::GetShareAcl,
            ),
            (
                Method::GET,
                "/acct123/share1",
                "restype=share&comp=stats",
                O::GetShareStats,
            ),
            (
                Method::PUT,
                "/acct123/share1",
                "restype=share&comp=filepermission",
                O::CreatePermission,
            ),
            (
                Method::GET,
                "/acct123/share1",
                "restype=directory&comp=list",
                O::ListFilesAndDirectories,
            ),
            (
                Method::PUT,
                "/acct123/share1/d",
                "restype=directory",
                O::CreateDirectory,
            ),
            (
                Method::PUT,
                "/acct123/share1/d",
                "restype=directory&comp=rename",
                O::RenameDirectory,
            ),
            (
                Method::GET,
                "/acct123/share1/d",
                "restype=directory&comp=listhandles",
                O::ListDirectoryHandles,
            ),
            (Method::PUT, "/acct123/share1/f", "", O::CreateFile),
            (Method::GET, "/acct123/share1/f", "", O::GetFile),
            (Method::HEAD, "/acct123/share1/f", "", O::GetFileProperties),
            (Method::DELETE, "/acct123/share1/f", "", O::DeleteFile),
            (Method::PUT, "/acct123/share1/f", "comp=range", O::PutRange),
            (
                Method::GET,
                "/acct123/share1/f",
                "comp=rangelist",
                O::ListRanges,
            ),
            (Method::PUT, "/acct123/share1/f", "comp=lease", O::LeaseFile),
            (
                Method::PUT,
                "/acct123/share1/f",
                "comp=rename",
                O::RenameFile,
            ),
            (
                Method::PUT,
                "/acct123/share1/f",
                "comp=copy&copyid=x",
                O::AbortCopyFile,
            ),
            (
                Method::GET,
                "/acct123/share1/f",
                "comp=metadata",
                O::GetFileMetadata,
            ),
        ];
        for (method, path, query, expected) in cases {
            assert_eq!(
                route_of(method.clone(), path, query, &[]),
                Ok(expected),
                "{method} {path}?{query}"
            );
        }
        assert_eq!(
            route_of(
                Method::PUT,
                "/acct123/share1/f",
                "",
                &[("x-ms-copy-source", "http://x")]
            ),
            Ok(Operation::CopyFile)
        );
    }

    #[test]
    fn unknown_combinations_are_rejected() {
        assert_eq!(
            route_of(Method::POST, "/acct123/share1/f", "", &[]),
            Err(Error::UnsupportedHttpVerb)
        );
        assert_eq!(
            route_of(Method::GET, "/acct123/share1", "", &[]),
            Err(Error::InvalidQueryParameterValue)
        );
        assert_eq!(
            route_of(Method::GET, "/acct123", "comp=bogus", &[]),
            Err(Error::InvalidQueryParameterValue)
        );
    }

    #[test]
    fn every_operation_has_a_distinct_name_per_variant_family() {
        let mut names: Vec<_> = Operation::ALL.iter().map(|op| op.name()).collect();
        names.sort_unstable();
        names.dedup();
        assert_eq!(
            names.len(),
            44,
            "List Handles and Force Close Handles are shared"
        );
    }

    #[test]
    fn manifest_lists_every_recognised_operation_with_a_matching_state() {
        let manifest: serde_json::Value = serde_json::from_str(
            &std::fs::read_to_string(concat!(
                env!("CARGO_MANIFEST_DIR"),
                "/specs/conformance/file.json"
            ))
            .unwrap(),
        )
        .unwrap();
        let inventory = manifest["operations"].as_array().unwrap();
        let state_of = |name: &str| {
            let mut found = inventory.iter().filter(|entry| entry["name"] == name);
            let entry = found.next().unwrap_or_else(|| panic!("{name} missing"));
            assert!(found.next().is_none(), "{name} listed twice");
            entry["state"].as_str().unwrap().to_owned()
        };
        for operation in Operation::ALL {
            assert_ne!(
                state_of(operation.name()),
                "unsupported",
                "{} is implemented",
                operation.name()
            );
        }
        let names: std::collections::BTreeSet<_> = Operation::ALL
            .iter()
            .map(|operation| operation.name())
            .collect();
        assert_eq!(
            inventory.len(),
            names.len(),
            "the manifest lists nothing the router lacks"
        );
    }

    #[test]
    fn ranges_parse_strictly() {
        assert_eq!(
            ByteRange::parse("bytes=0-511").unwrap().exact(),
            Ok((0, 512))
        );
        assert_eq!(
            ByteRange::parse("bytes=5-").unwrap(),
            ByteRange {
                start: 5,
                end: None
            }
        );
        assert!(ByteRange::parse("bytes=5-").unwrap().exact().is_err());
        for bad in ["0-5", "bytes=a-b", "bytes=5-1", "bytes=-5", "bytes=1-2,3-4"] {
            assert!(ByteRange::parse(bad).is_err(), "{bad}");
        }
    }

    #[test]
    fn smb_headers_default_per_operation() {
        let map = HeaderMap::new();
        let headers = Headers(&map);
        let create = headers.smb(true).unwrap();
        assert_eq!(create.permission, PermissionSpec::Inherit);
        assert_eq!(create.creation, TimeSpec::Now);
        let update = headers.smb(false).unwrap();
        assert_eq!(update.permission, PermissionSpec::Preserve);
        assert_eq!(update.last_write, TimeSpec::Preserve);
    }

    #[test]
    fn smb_headers_reject_conflicting_permissions() {
        let mut map = HeaderMap::new();
        map.insert(
            "x-ms-file-permission",
            HeaderValue::from_static("O:SYG:SYD:"),
        );
        map.insert("x-ms-file-permission-key", HeaderValue::from_static("1*1"));
        assert_eq!(
            Headers(&map).smb(true).err(),
            Some(Error::InvalidHeaderValue)
        );
    }

    #[test]
    fn file_length_is_bounded_at_four_tib() {
        let mut map = HeaderMap::new();
        map.insert(
            "x-ms-content-length",
            HeaderValue::from_static("4398046511105"),
        );
        assert_eq!(
            file_length(&Headers(&map), "x-ms-content-length").err(),
            Some(Error::InvalidHeaderValue)
        );
        map.insert(
            "x-ms-content-length",
            HeaderValue::from_static("4398046511104"),
        );
        assert!(file_length(&Headers(&map), "x-ms-content-length").is_ok());
    }
}
