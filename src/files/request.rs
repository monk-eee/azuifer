//! The HTTP edge of FileREST: query and path parsing, operation routing, and typed header
//! extraction. Handlers receive validated values, never raw headers.

use super::{
    error::{Error, Result},
    name::{EntryPath, ShareName},
    time,
};
use crate::{auth, domain::AccountName};
use axum::http::Method;
use percent_encoding::percent_decode_str;
use std::collections::BTreeMap;

const MAX_QUERY_BYTES: usize = 16 * 1024;

mod headers;
mod operation;

pub(super) use headers::{ByteRange, Headers, file_length};
pub(crate) use operation::Operation;

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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::files::model::{PermissionSpec, TimeSpec};
    use axum::http::{HeaderMap, HeaderValue};

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
