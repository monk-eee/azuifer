use crate::{
    address,
    auth::{Query, header},
    blob_auth::{self, Credentials, Presented, Target},
    blob_copy::{CopySource, SourceBearer},
    blob_sas::{self, Need, Public},
    blob_snapshot::{Removal, Selector},
    blob_tags::TagFilter,
    checksum::Checksum,
    conditions::{Conditions, Guard},
    config::Config,
    domain::{
        AccessTier, AccountName, ApiVersion, BlobKey, BlobPath, BlobRead, BlobWrite, BlockId,
        BlockListKind, ByteRange, ContainerCreate, ContainerKey, ContainerName, ContentHeaders,
        ContentLength, Error, ListRequest, Metadata, PageRequest, PublicAccess, Result,
    },
    lease::{LeaseAction, LeaseId},
    stamp::Ticks,
};
use axum::http::{HeaderMap, Method, request::Parts};
use std::time::SystemTime;

mod lifecycle;
mod page;

mod blob;
mod headers;
mod service;
#[cfg(test)]
mod tests;

use headers::{blob_write, decode};
pub(crate) use headers::{
    check, check_hns_path, lease_action, parse_block_list, parse_query, upload_options,
};

const MAX_BLOCK_LIST_BYTES: u64 = 8 * 1024 * 1024;
const MAX_XML_BODY_BYTES: u64 = 1024 * 1024;
const MAX_COMMITTED_BLOCKS: usize = 50_000;
const MAX_BATCH_BYTES: u64 = 4 * 1024 * 1024;

const CONDITIONS: &[&str] = &[
    "if-match",
    "if-none-match",
    "if-modified-since",
    "if-unmodified-since",
];
const DATE_CONDITIONS: &[&str] = &["if-modified-since", "if-unmodified-since"];
const LEASE: &[&str] = &["x-ms-lease-id"];
const TAGS: &[&str] = &["x-ms-tags"];
const TAG_CONDITION: &[&str] = &["x-ms-if-tags"];
const CHECKSUMS: &[&str] = &["content-md5", "x-ms-content-crc64"];
const BLOB_PROPERTIES: &[&str] = &[
    "x-ms-blob-content-type",
    "x-ms-blob-content-encoding",
    "x-ms-blob-content-language",
    "x-ms-blob-content-disposition",
    "x-ms-blob-cache-control",
    "x-ms-blob-content-md5",
];
const PLAIN_PROPERTIES: &[&str] = &[
    "content-encoding",
    "content-language",
    "content-disposition",
    "cache-control",
];
const SOURCE: &[&str] = &[
    "x-ms-copy-source",
    "x-ms-source-if-match",
    "x-ms-source-if-none-match",
    "x-ms-source-if-modified-since",
    "x-ms-source-if-unmodified-since",
    "x-ms-source-lease-id",
];
const SOURCE_BEARER: &[&str] = &["x-ms-copy-source-authorization"];
/// The hash of the source bytes, which Put Blob From URL takes only as MD5.
const SOURCE_MD5: &[&str] = &["x-ms-source-content-md5"];
const SOURCE_CHECKSUMS: &[&str] = &["x-ms-source-content-md5", "x-ms-source-content-crc64"];
const LEASE_HEADERS: &[&str] = &[
    "x-ms-lease-action",
    "x-ms-lease-id",
    "x-ms-lease-duration",
    "x-ms-proposed-lease-id",
    "x-ms-lease-break-period",
];

const fn need(
    service: Option<&'static str>,
    account: Option<(char, &'static str)>,
    public: Public,
) -> Need {
    Need {
        service,
        account,
        public,
    }
}

const ANY_SAS: Need = need(Some("*"), Some(('*', "*")), Public::Never);
const LIST_CONTAINERS: Need = need(None, Some(('s', "l")), Public::Never);
const SERVICE_READ: Need = need(None, Some(('s', "r")), Public::Never);
const SERVICE_WRITE: Need = need(None, Some(('s', "w")), Public::Never);
/// Only a bearer token may ask for a user delegation key; the operation names no SAS permission.
const USER_DELEGATION_KEY: Need = need(None, None, Public::Never);
const CREATE_CONTAINER: Need = need(None, Some(('c', "wc")), Public::Never);
const DELETE_CONTAINER: Need = need(Some("d"), Some(('c', "d")), Public::Never);
const READ_CONTAINER: Need = need(Some("r"), Some(('c', "r")), Public::Container);
const READ_CONTAINER_PRIVATE: Need = need(Some("r"), Some(('c', "r")), Public::Never);
const WRITE_CONTAINER: Need = need(Some("w"), Some(('c', "w")), Public::Never);
const LIST_BLOBS: Need = need(Some("l"), Some(('c', "l")), Public::Container);
const READ_BLOB: Need = need(Some("r"), Some(('o', "r")), Public::Blob);
const CREATE_BLOB: Need = need(Some("wc"), Some(('o', "wc")), Public::Never);
const WRITE_BLOB: Need = need(Some("w"), Some(('o', "w")), Public::Never);
const DELETE_BLOB: Need = need(Some("d"), Some(('o', "d")), Public::Never);
const BLOB_TAGS: Need = need(Some("t"), Some(('o', "t")), Public::Never);
const FIND_BLOBS_ACCOUNT: Need = need(None, Some(('o', "f")), Public::Never);
const FIND_BLOBS_CONTAINER: Need = need(Some("f"), Some(('o', "f")), Public::Never);

pub(crate) enum ContainerView {
    Properties,
    Metadata,
}

pub(crate) struct SourceRequest {
    pub(crate) url: CopySource,
    pub(crate) bearer: Option<SourceBearer>,
    pub(crate) guard: Guard,
    pub(crate) range: Option<ByteRange>,
    /// The x-ms-source-content-md5 or -crc64 the bytes read from the source must match.
    pub(crate) checksum: Option<Checksum>,
    /// Copy Blob: x-ms-seal-blob sets whether an append destination is sealed.
    pub(crate) seal: Option<bool>,
    /// Put Blob From URL: take content properties from the source (the default).
    pub(crate) copy_properties: bool,
    /// Copy Blob: any `x-ms-meta-*` header replaces the source metadata.
    pub(crate) replace_metadata: bool,
    /// `x-ms-copy-source-tag-option: COPY` takes the source blob's tags.
    pub(crate) copy_tags: bool,
}

/// The parsed envelope of a Submit Batch request.
pub(crate) struct BatchRequest {
    pub(crate) boundary: String,
    pub(crate) upload: UploadOptions,
}

pub(crate) enum Operation {
    /// The flags ask for container metadata and for soft-deleted containers.
    ListContainers(AccountName, PageRequest, bool, bool),
    GetServiceProperties(AccountName),
    SetServiceProperties(AccountName, UploadOptions),
    UserDelegationKey(AccountName, UploadOptions),
    ServiceStats,
    AccountInfo,
    CreateContainer(ContainerKey, ContainerCreate),
    ContainerProperties(ContainerKey, Option<LeaseId>, ContainerView),
    SetContainerMetadata(ContainerKey, Metadata, Guard),
    GetContainerAcl(ContainerKey, Option<LeaseId>),
    SetContainerAcl(ContainerKey, UploadOptions, PublicAccess, Guard),
    LeaseContainer(ContainerKey, LeaseAction, Guard),
    DeleteContainer(ContainerKey, Guard),
    ListBlobs(ContainerKey, ListRequest, Option<LeaseId>),
    PutBlob(BlobKey, UploadOptions, BlobWrite),
    PutBlobFromUrl(BlobKey, BlobWrite, SourceRequest),
    PutBlock(BlobKey, BlockId, UploadOptions, Option<LeaseId>),
    PutBlockFromUrl(BlobKey, BlockId, Option<LeaseId>, SourceRequest),
    PutBlockList(BlobKey, UploadOptions, BlobWrite),
    GetBlockList(BlobKey, BlockListKind, Guard),
    BlocksSelected(BlobKey, Selector, BlockListKind, Guard),
    ReadBlob(BlobKey, BlobRead),
    /// A read of a snapshot or version; the flag asks for metadata only.
    ReadSelected(BlobKey, Selector, BlobRead, bool),
    /// Query Blob Contents of the blob, or of one snapshot or version.
    QueryBlob(BlobKey, Option<Selector>, UploadOptions, Guard),
    SnapshotBlob(BlobKey, Option<Metadata>, Guard),
    UndeleteBlob(BlobKey),
    SetBlobTags(BlobKey, Option<Ticks>, UploadOptions, Guard),
    GetBlobTags(BlobKey, Option<Ticks>, Guard),
    FindBlobs(AccountName, Option<ContainerKey>, TagFilter, PageRequest),
    SubmitBatch(Option<ContainerKey>, BatchRequest),
    BlobMetadata(BlobKey, Guard),
    SetBlobProperties(
        BlobKey,
        ContentHeaders,
        Option<[u8; 16]>,
        bool,
        Guard,
        crate::blob_page::PropertyChange,
    ),
    SetBlobMetadata(BlobKey, Metadata, Guard),
    SetBlobTier(BlobKey, AccessTier, Option<LeaseId>),
    LeaseBlob(BlobKey, LeaseAction, Conditions),
    CopyBlob(BlobKey, BlobWrite, SourceRequest),
    AbortCopy(BlobKey, String, Option<LeaseId>),
    DeleteBlob(BlobKey, Guard, Removal),
    Page(crate::blob_page::PageOperation),
    Lifecycle(crate::blob_lifecycle::LifecycleOperation),
}

pub(crate) struct UploadOptions {
    pub(crate) length: ContentLength,
    pub(crate) checksum: Option<Checksum>,
}

pub(crate) struct ParsedRequest {
    pub(crate) operation: Operation,
    pub(crate) requested_version: ApiVersion,
    pub(crate) target: Target,
    pub(crate) credentials: Credentials,
    pub(crate) need: Need,
}

/// The authority a client addressed, from `Host` or an HTTP/2 `:authority`.
pub(crate) fn host(parts: &Parts) -> Option<&str> {
    address::request_host(parts)
}

pub(crate) fn parse_target(path: &str) -> Result<Target> {
    let mut segments = path
        .strip_prefix('/')
        .ok_or(Error::InvalidName)?
        .splitn(3, '/');
    let account = AccountName::parse(segments.next().ok_or(Error::InvalidName)?)?;
    let label = segments.next();
    let blob = segments.next();
    Ok(match (label, blob) {
        (None | Some(""), None) => Target::Account(account),
        (Some(label), blob) => {
            // `$web` arrives percent-encoded from some SDKs.
            let label = decode(label, false).ok_or(Error::InvalidName)?;
            let key = ContainerKey {
                account,
                name: ContainerName::parse(&label)?,
            };
            if let Some(path) = blob {
                if path.is_empty() {
                    return Err(Error::InvalidName);
                }
                let value = decode(path, false).ok_or(Error::InvalidName)?;
                Target::Blob(BlobKey {
                    container: key,
                    path: BlobPath::parse(value)?,
                })
            } else {
                Target::Container(key)
            }
        }
        (None, Some(_)) => return Err(Error::InvalidName),
    })
}

/// A single path segment without `restype=container` names a blob in the `$root` container, as
/// in `https://account.blob.core.windows.net/blob.txt`; this rewrites it to the explicit form.
fn root_container_path(logical: String, query: &Query) -> String {
    let mut segments = logical.strip_prefix('/').unwrap_or("").split('/');
    let (Some(account), Some(name), None) = (segments.next(), segments.next(), segments.next())
    else {
        return logical;
    };
    if name.is_empty()
        || query.get("restype").map(String::as_str) == Some("container")
        || name.starts_with('$')
    {
        return logical;
    }
    format!("/{account}/$root/{name}")
}

struct Request<'a> {
    method: &'a Method,
    query: &'a Query,
    headers: &'a HeaderMap,
    config: &'a Config,
}

pub(crate) fn parse(parts: &Parts, config: &Config, now: SystemTime) -> Result<ParsedRequest> {
    parse_with(parts, config, now, None)
}

/// Parses a Submit Batch sub-request. It carries no `x-ms-version` of its own
/// and runs at the version of the batch request.
pub(crate) fn parse_batched(
    parts: &Parts,
    config: &Config,
    now: SystemTime,
    version: &str,
) -> Result<ParsedRequest> {
    parse_with(parts, config, now, Some(version))
}

fn parse_with(
    parts: &Parts,
    config: &Config,
    now: SystemTime,
    inherited: Option<&str>,
) -> Result<ParsedRequest> {
    let headers = &parts.headers;
    if headers.len() > 100
        || headers
            .iter()
            .map(|(name, value)| name.as_str().len() + value.len())
            .sum::<usize>()
            > 32768
    {
        return Err(Error::InvalidHeader);
    }
    let requested_version = match header(headers, "x-ms-version")? {
        Some(version) => ApiVersion::parse(version)?,
        // SAS and anonymous requests may omit the version; signed requests may not.
        None if !headers.contains_key("authorization") => {
            ApiVersion::parse(config.api_version.as_str())?
        }
        None if inherited.is_some() => ApiVersion::parse(inherited.unwrap_or_default())?,
        None => return Err(Error::InvalidVersion),
    };
    if !requested_version.is_served(&config.api_version, config.skip_api_version_check) {
        return Err(Error::InvalidVersion);
    }
    let mut query = parse_query(parts.uri.query())?;
    let host_account = address::host_account_or_secondary("blob", host(parts));
    let logical = address::logical_path(host_account.as_ref(), parts.uri.path());
    let logical = root_container_path(logical, &query);
    let target = parse_target(&logical)?;
    let keys = config
        .accounts
        .get(target.account())
        .ok_or(Error::AuthenticationFailed)?;
    let credentials = blob_auth::credentials(&Presented {
        keys,
        oauth: &config.oauth,
        delegation: &config.delegation,
        method: &parts.method,
        signing_path: parts.uri.path(),
        query: &query,
        headers,
        target: &target,
        now,
    })?;
    check_hns_path(&target, config)?;
    if matches!(credentials, Credentials::Sas(_)) {
        query.retain(|name, _| !blob_sas::is_sas_param(name));
    }
    let request = Request {
        method: &parts.method,
        query: &query,
        headers,
        config,
    };
    let operation = match target.clone() {
        Target::Account(account) => request.account_operation(account),
        Target::Container(key) => request.container_operation(key),
        Target::Blob(key) => request.blob_operation(key),
    };
    let operation = match operation {
        // An anonymous caller learns nothing about which operations exist.
        Err(Error::Unsupported) if matches!(credentials, Credentials::Anonymous) => {
            return Err(Error::AuthenticationFailed);
        }
        other => other?,
    };
    Ok(ParsedRequest {
        need: operation.need(),
        operation,
        requested_version,
        target,
        credentials,
    })
}

impl Operation {
    fn need(&self) -> Need {
        match self {
            Self::ListContainers(..) => LIST_CONTAINERS,
            Self::GetServiceProperties(_) | Self::ServiceStats => SERVICE_READ,
            Self::SetServiceProperties(..) => SERVICE_WRITE,
            Self::UserDelegationKey(..) => USER_DELEGATION_KEY,
            Self::AccountInfo => ANY_SAS,
            Self::CreateContainer(..) => CREATE_CONTAINER,
            Self::ContainerProperties(..) => READ_CONTAINER,
            Self::GetContainerAcl(..) => READ_CONTAINER_PRIVATE,
            Self::SetContainerMetadata(..)
            | Self::SetContainerAcl(..)
            | Self::LeaseContainer(..) => WRITE_CONTAINER,
            Self::DeleteContainer(..) => DELETE_CONTAINER,
            Self::ListBlobs(..) => LIST_BLOBS,
            Self::PutBlob(..)
            | Self::PutBlobFromUrl(..)
            | Self::PutBlock(..)
            | Self::PutBlockFromUrl(..)
            | Self::PutBlockList(..)
            | Self::CopyBlob(..) => CREATE_BLOB,
            Self::GetBlockList(..)
            | Self::BlocksSelected(..)
            | Self::ReadBlob(..)
            | Self::ReadSelected(..)
            | Self::QueryBlob(..)
            | Self::BlobMetadata(..) => READ_BLOB,
            Self::SnapshotBlob(..) => CREATE_BLOB,
            Self::UndeleteBlob(..) => WRITE_BLOB,
            Self::SetBlobTags(..) | Self::GetBlobTags(..) => BLOB_TAGS,
            Self::FindBlobs(_, None, ..) => FIND_BLOBS_ACCOUNT,
            Self::FindBlobs(_, Some(_), ..) => FIND_BLOBS_CONTAINER,
            Self::SubmitBatch(..) => ANY_SAS,
            Self::SetBlobProperties(..)
            | Self::SetBlobMetadata(..)
            | Self::SetBlobTier(..)
            | Self::LeaseBlob(..)
            | Self::AbortCopy(..) => WRITE_BLOB,
            Self::DeleteBlob(..) => DELETE_BLOB,
            Self::Page(operation) => operation.need(),
            Self::Lifecycle(operation) => operation.need(),
        }
    }
}

impl Request<'_> {
    fn param(&self, name: &str) -> Option<&str> {
        self.query.get(name).map(String::as_str)
    }

    fn check(&self, params: &[&str], headers: &[&[&str]], metadata: bool) -> Result<()> {
        check(self.query, self.headers, params, headers, metadata)
    }

    fn listing(&self) -> Result<PageRequest> {
        PageRequest::parse(
            self.param("prefix"),
            self.param("marker"),
            self.param("maxresults"),
        )
    }
}
