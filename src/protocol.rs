use crate::{
    address,
    auth::{Query, header},
    blob_auth::{self, Credentials, Presented, Target},
    blob_batch,
    blob_copy::CopySource,
    blob_sas::{self, Need, Public},
    blob_snapshot::{self, Removal, Selector},
    blob_tags::TagFilter,
    checksum::Checksum,
    conditions::{self, Conditions, Guard, lease_id},
    config::Config,
    domain::{
        AccessTier, AccountName, ApiVersion, BlobKey, BlobPath, BlobRead, BlobWrite, BlockId,
        BlockListKind, BlockSelection, BlockSource, ByteRange, ContainerCreate, ContainerKey,
        ContainerName, ContentHeaders, ContentLength, Error, Include, ListRequest, Metadata,
        PageRequest, PublicAccess, RangeChecksum, Result, xml_safe,
    },
    lease::{LeaseAction, LeaseDuration, LeaseId},
    stamp::Ticks,
};
use axum::http::{HeaderMap, Method, request::Parts};
use base64::{Engine as _, engine::general_purpose::STANDARD};
use percent_encoding::percent_decode_str;
use quick_xml::{Reader, events::Event};
use std::{collections::HashMap, time::SystemTime};

mod lifecycle;
mod page;

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
    pub(crate) guard: Guard,
    pub(crate) range: Option<ByteRange>,
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
            let key = ContainerKey {
                account,
                name: ContainerName::parse(label)?,
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

    fn account_operation(&self, account: AccountName) -> Result<Operation> {
        let (restype, comp) = (self.param("restype"), self.param("comp"));
        Ok(match (self.method, restype, comp) {
            (&Method::GET, None, Some("list")) => {
                self.check(
                    &["comp", "prefix", "marker", "maxresults", "include"],
                    &[],
                    false,
                )?;
                let (mut metadata, mut deleted) = (false, false);
                for item in self.param("include").unwrap_or_default().split(',') {
                    match item {
                        "" => (),
                        "metadata" => metadata = true,
                        "deleted" => deleted = true,
                        _ => return Err(Error::Unsupported),
                    }
                }
                Operation::ListContainers(account, self.listing()?, metadata, deleted)
            }
            (&Method::GET, Some("service"), Some("properties")) => {
                self.check(&["restype", "comp"], &[], false)?;
                Operation::GetServiceProperties(account)
            }
            (&Method::PUT, Some("service"), Some("properties")) => {
                self.check(&["restype", "comp"], &[CHECKSUMS], false)?;
                Operation::SetServiceProperties(
                    account,
                    upload_options(self.headers, MAX_XML_BODY_BYTES)?,
                )
            }
            (&Method::POST, Some("service"), Some("userdelegationkey")) => {
                self.check(&["restype", "comp"], &[CHECKSUMS], false)?;
                Operation::UserDelegationKey(
                    account,
                    upload_options(self.headers, MAX_XML_BODY_BYTES)?,
                )
            }
            (&Method::GET, Some("service"), Some("stats")) => {
                self.check(&["restype", "comp"], &[], false)?;
                Operation::ServiceStats
            }
            (&Method::GET | &Method::HEAD, Some("account"), Some("properties")) => {
                self.check(&["restype", "comp"], &[], false)?;
                Operation::AccountInfo
            }
            (&Method::GET, None, Some("blobs")) => {
                self.check(&["comp", "where", "marker", "maxresults"], &[], false)?;
                Operation::FindBlobs(account, None, self.filter()?, self.listing()?)
            }
            (&Method::POST, None, Some("batch")) => {
                self.check(&["comp"], &[], false)?;
                Operation::SubmitBatch(None, self.batch()?)
            }
            _ => return Err(Error::Unsupported),
        })
    }

    fn filter(&self) -> Result<TagFilter> {
        TagFilter::parse(self.param("where").ok_or(Error::InvalidQuery)?, true)
    }

    fn batch(&self) -> Result<BatchRequest> {
        let content_type = header(self.headers, "content-type")?.ok_or(Error::MissingHeader)?;
        Ok(BatchRequest {
            boundary: blob_batch::boundary(content_type)?,
            upload: upload_options(self.headers, MAX_BATCH_BYTES)?,
        })
    }

    fn container_operation(&self, key: ContainerKey) -> Result<Operation> {
        let (restype, comp) = (self.param("restype"), self.param("comp"));
        let reading = matches!(*self.method, Method::GET | Method::HEAD);
        let lease = || lease_id(self.headers, "x-ms-lease-id");
        if let Some(operation) = self.restore_container(&key)? {
            return Ok(Operation::Lifecycle(operation));
        }
        Ok(match (restype, comp) {
            (Some("container"), None) => {
                self.check(
                    &["restype"],
                    &[&["x-ms-blob-public-access"], LEASE, DATE_CONDITIONS],
                    true,
                )?;
                match *self.method {
                    Method::PUT => Operation::CreateContainer(
                        key,
                        ContainerCreate {
                            metadata: metadata(self.headers)?,
                            public_access: public_access(self.headers)?,
                        },
                    ),
                    Method::GET | Method::HEAD => {
                        Operation::ContainerProperties(key, lease()?, ContainerView::Properties)
                    }
                    Method::DELETE => Operation::DeleteContainer(key, Guard::parse(self.headers)?),
                    _ => return Err(Error::Unsupported),
                }
            }
            (Some("container"), Some("metadata")) if reading => {
                self.check(&["restype", "comp"], &[LEASE], false)?;
                Operation::ContainerProperties(key, lease()?, ContainerView::Metadata)
            }
            (Some("container"), Some("metadata")) if *self.method == Method::PUT => {
                self.check(&["restype", "comp"], &[LEASE, DATE_CONDITIONS], true)?;
                Operation::SetContainerMetadata(
                    key,
                    metadata(self.headers)?,
                    Guard::parse(self.headers)?,
                )
            }
            (Some("container"), Some("acl")) if reading => {
                self.check(&["restype", "comp"], &[LEASE], false)?;
                Operation::GetContainerAcl(key, lease()?)
            }
            (Some("container"), Some("acl")) if *self.method == Method::PUT => {
                self.check(
                    &["restype", "comp"],
                    &[
                        &["x-ms-blob-public-access"],
                        LEASE,
                        DATE_CONDITIONS,
                        CHECKSUMS,
                    ],
                    false,
                )?;
                Operation::SetContainerAcl(
                    key,
                    upload_options(self.headers, MAX_XML_BODY_BYTES)?,
                    public_access(self.headers)?,
                    Guard::parse(self.headers)?,
                )
            }
            (Some("container"), Some("lease")) if *self.method == Method::PUT => {
                self.check(
                    &["restype", "comp"],
                    &[LEASE_HEADERS, DATE_CONDITIONS],
                    false,
                )?;
                Operation::LeaseContainer(
                    key,
                    lease_action(self.headers)?,
                    Guard::parse(self.headers)?,
                )
            }
            (Some("container"), Some("list")) if *self.method == Method::GET => {
                self.check(
                    &[
                        "comp",
                        "restype",
                        "prefix",
                        "marker",
                        "maxresults",
                        "include",
                        "delimiter",
                    ],
                    &[LEASE],
                    false,
                )?;
                Operation::ListBlobs(
                    key,
                    ListRequest {
                        page: self.listing()?,
                        delimiter: self
                            .param("delimiter")
                            .filter(|delimiter| !delimiter.is_empty())
                            .map(str::to_owned),
                        include: includes(self.param("include"))?,
                    },
                    lease()?,
                )
            }
            (Some("container"), Some("blobs")) if *self.method == Method::GET => {
                self.check(
                    &["restype", "comp", "where", "marker", "maxresults"],
                    &[],
                    false,
                )?;
                // The container is the scope, so `@container` is not a valid term here.
                let filter =
                    TagFilter::parse(self.param("where").ok_or(Error::InvalidQuery)?, false)?;
                let account = key.account.clone();
                Operation::FindBlobs(account, Some(key), filter, self.listing()?)
            }
            (Some("container"), Some("batch")) if *self.method == Method::POST => {
                self.check(&["restype", "comp"], &[], false)?;
                Operation::SubmitBatch(Some(key), self.batch()?)
            }
            (Some("account"), Some("properties")) if reading => {
                self.check(&["restype", "comp"], &[], false)?;
                Operation::AccountInfo
            }
            _ => return Err(Error::Unsupported),
        })
    }

    fn blob_operation(&self, key: BlobKey) -> Result<Operation> {
        let (restype, comp) = (self.param("restype"), self.param("comp"));
        let reading = matches!(*self.method, Method::GET | Method::HEAD);
        let lease = || lease_id(self.headers, "x-ms-lease-id");
        let guard = || Guard::parse(self.headers);
        if let (Some("account"), Some("properties"), true) = (restype, comp, reading) {
            self.check(&["restype", "comp"], &[], false)?;
            return Ok(Operation::AccountInfo);
        }
        if restype.is_some() {
            return Err(Error::Unsupported);
        }
        if let Some(operation) = self.page_operation(&key)? {
            return Ok(Operation::Page(operation));
        }
        if let Some(operation) = self.lifecycle_operation(&key)? {
            return Ok(Operation::Lifecycle(operation));
        }
        let selector = blob_snapshot::selector(self.query)?;
        Ok(match (self.method, comp) {
            (&Method::PUT, None) if self.headers.contains_key("x-ms-copy-source") => {
                if header(self.headers, "x-ms-blob-type")?.is_some() {
                    self.check(
                        &[],
                        &[
                            &[
                                "x-ms-blob-type",
                                "x-ms-copy-source-blob-properties",
                                "x-ms-copy-source-tag-option",
                                "x-ms-access-tier",
                            ],
                            TAGS,
                            SOURCE,
                            CONDITIONS,
                            LEASE,
                            BLOB_PROPERTIES,
                            PLAIN_PROPERTIES,
                        ],
                        true,
                    )?;
                    require_block_blob(self.headers)?;
                    let copy_properties = header(self.headers, "x-ms-copy-source-blob-properties")?
                        .is_none_or(|value| value != "false");
                    Operation::PutBlobFromUrl(
                        key,
                        blob_write(self.headers, true)?,
                        self.source(None, copy_properties)?,
                    )
                } else {
                    self.check(
                        &[],
                        &[
                            &[
                                "x-ms-requires-sync",
                                "x-ms-access-tier",
                                "x-ms-rehydrate-priority",
                                "x-ms-copy-source-tag-option",
                            ],
                            TAGS,
                            SOURCE,
                            CONDITIONS,
                            LEASE,
                        ],
                        true,
                    )?;
                    Operation::CopyBlob(
                        key,
                        blob_write(self.headers, false)?,
                        self.source(None, true)?,
                    )
                }
            }
            (&Method::PUT, Some("copy")) => {
                self.check(&["comp", "copyid"], &[&["x-ms-copy-action"], LEASE], false)?;
                if header(self.headers, "x-ms-copy-action")? != Some("abort") {
                    return Err(Error::InvalidHeader);
                }
                Operation::AbortCopy(
                    key,
                    self.param("copyid").ok_or(Error::InvalidQuery)?.to_owned(),
                    lease()?,
                )
            }
            (&Method::PUT, Some("block")) if self.headers.contains_key("x-ms-copy-source") => {
                self.check(
                    &["comp", "blockid"],
                    &[
                        SOURCE,
                        LEASE,
                        &["x-ms-source-range", "content-md5", "x-ms-content-crc64"],
                    ],
                    false,
                )?;
                let range = header(self.headers, "x-ms-source-range")?
                    .map(ByteRange::parse)
                    .transpose()?;
                Operation::PutBlockFromUrl(
                    key,
                    BlockId::parse(self.param("blockid").ok_or(Error::InvalidQuery)?)?,
                    lease()?,
                    self.source(range, true)?,
                )
            }
            (&Method::PUT, Some("block")) => {
                self.check(&["comp", "blockid"], &[CHECKSUMS, LEASE], false)?;
                let id = BlockId::parse(self.param("blockid").ok_or(Error::InvalidQuery)?)?;
                Operation::PutBlock(
                    key,
                    id,
                    upload_options(self.headers, self.config.max_block_bytes)?,
                    lease()?,
                )
            }
            (&Method::PUT, Some("blocklist")) => {
                self.check(
                    &["comp"],
                    &[
                        CONDITIONS,
                        LEASE,
                        BLOB_PROPERTIES,
                        CHECKSUMS,
                        TAGS,
                        &["x-ms-access-tier"],
                    ],
                    true,
                )?;
                Operation::PutBlockList(
                    key,
                    upload_options(self.headers, MAX_BLOCK_LIST_BYTES)?,
                    blob_write(self.headers, false)?,
                )
            }
            (&Method::GET, Some("blocklist")) => {
                self.check(
                    &["comp", "blocklisttype", "snapshot", "versionid"],
                    &[CONDITIONS, LEASE],
                    false,
                )?;
                let list = match self.param("blocklisttype") {
                    None | Some("committed") => BlockListKind::Committed,
                    Some("uncommitted") => BlockListKind::Uncommitted,
                    Some("all") => BlockListKind::All,
                    _ => return Err(Error::InvalidQuery),
                };
                match selector {
                    Some(selector) => Operation::BlocksSelected(key, selector, list, guard()?),
                    None => Operation::GetBlockList(key, list, guard()?),
                }
            }
            (&Method::PUT, None) => {
                self.check(
                    &[],
                    &[
                        CONDITIONS,
                        LEASE,
                        BLOB_PROPERTIES,
                        PLAIN_PROPERTIES,
                        CHECKSUMS,
                        TAGS,
                        &["x-ms-blob-type", "x-ms-access-tier"],
                    ],
                    true,
                )?;
                require_block_blob(self.headers)?;
                Operation::PutBlob(
                    key,
                    upload_options(self.headers, self.config.max_blob_bytes)?,
                    blob_write(self.headers, true)?,
                )
            }
            (method @ (&Method::GET | &Method::HEAD), None | Some("metadata")) => {
                let with_body = method == Method::GET && comp.is_none();
                let ranged: &[&str] = if with_body {
                    &[
                        "range",
                        "x-ms-range",
                        "x-ms-range-get-content-md5",
                        "x-ms-range-get-content-crc64",
                    ]
                } else {
                    &[]
                };
                let params: &[&str] = if comp.is_some() {
                    &["comp", "snapshot", "versionid"]
                } else {
                    &["snapshot", "versionid"]
                };
                self.check(params, &[CONDITIONS, LEASE, ranged], false)?;
                if comp.is_some() {
                    let read = BlobRead {
                        guard: guard()?,
                        range: None,
                        with_body: false,
                        range_checksum: None,
                    };
                    return Ok(match selector {
                        Some(selector) => Operation::ReadSelected(key, selector, read, true),
                        None => Operation::BlobMetadata(key, read.guard),
                    });
                }
                let range = header(self.headers, "x-ms-range")?
                    .or(header(self.headers, "range")?)
                    .map(ByteRange::parse)
                    .transpose()?;
                let read = BlobRead {
                    guard: guard()?,
                    range,
                    with_body,
                    range_checksum: range_checksum(self.headers)?,
                };
                match selector {
                    Some(selector) => Operation::ReadSelected(key, selector, read, false),
                    None => Operation::ReadBlob(key, read),
                }
            }
            (&Method::DELETE, None) => {
                self.check(
                    &["snapshot", "versionid"],
                    &[CONDITIONS, LEASE, &["x-ms-delete-snapshots"]],
                    false,
                )?;
                let removal = blob_snapshot::removal(self.headers, self.query)?;
                Operation::DeleteBlob(key, guard()?, removal)
            }
            (&Method::PUT, Some("properties")) => {
                self.check(
                    &["comp"],
                    &[
                        CONDITIONS,
                        LEASE,
                        BLOB_PROPERTIES,
                        crate::blob_page::PROPERTY_HEADERS,
                    ],
                    false,
                )?;
                let (headers, replace) = content_headers(self.headers, false)?;
                Operation::SetBlobProperties(
                    key,
                    headers,
                    blob_content_md5(self.headers)?,
                    replace,
                    guard()?,
                    crate::blob_page::PropertyChange::parse(self.headers)?,
                )
            }
            (&Method::PUT, Some("metadata")) => {
                self.check(&["comp"], &[CONDITIONS, LEASE], true)?;
                Operation::SetBlobMetadata(key, metadata(self.headers)?, guard()?)
            }
            (&Method::PUT, Some("snapshot")) => {
                self.check(&["comp"], &[CONDITIONS, LEASE], true)?;
                let metadata = metadata(self.headers)?;
                Operation::SnapshotBlob(key, (!metadata.is_empty()).then_some(metadata), guard()?)
            }
            (&Method::PUT, Some("undelete")) => {
                self.check(&["comp"], &[], false)?;
                Operation::UndeleteBlob(key)
            }
            (&Method::PUT, Some("tags")) => {
                self.check(
                    &["comp", "versionid"],
                    &[LEASE, TAG_CONDITION, CHECKSUMS],
                    false,
                )?;
                Operation::SetBlobTags(
                    key,
                    version_only(selector)?,
                    upload_options(self.headers, MAX_XML_BODY_BYTES)?,
                    guard()?,
                )
            }
            (&Method::GET, Some("tags")) => {
                self.check(&["comp", "versionid"], &[LEASE, TAG_CONDITION], false)?;
                Operation::GetBlobTags(key, version_only(selector)?, guard()?)
            }
            (&Method::PUT, Some("tier")) => {
                self.check(
                    &["comp"],
                    &[LEASE, &["x-ms-access-tier", "x-ms-rehydrate-priority"]],
                    false,
                )?;
                if let Some(priority) = header(self.headers, "x-ms-rehydrate-priority")?
                    && !matches!(priority, "High" | "Standard")
                {
                    return Err(Error::InvalidHeader);
                }
                let tier = header(self.headers, "x-ms-access-tier")?.ok_or(Error::MissingHeader)?;
                Operation::SetBlobTier(key, AccessTier::parse(tier)?, lease()?)
            }
            (&Method::PUT, Some("lease")) => {
                self.check(&["comp"], &[LEASE_HEADERS, CONDITIONS], false)?;
                Operation::LeaseBlob(
                    key,
                    lease_action(self.headers)?,
                    Conditions::parse(self.headers, &conditions::STANDARD)?,
                )
            }
            _ => return Err(Error::Unsupported),
        })
    }

    fn source(&self, range: Option<ByteRange>, copy_properties: bool) -> Result<SourceRequest> {
        let url = header(self.headers, "x-ms-copy-source")?.ok_or(Error::MissingHeader)?;
        let copy_tags = match header(self.headers, "x-ms-copy-source-tag-option")? {
            None | Some("REPLACE") => false,
            Some("COPY") if self.headers.contains_key("x-ms-tags") => {
                return Err(Error::Ext(
                    crate::blob_lifecycle::LifecycleError::ConflictingTagOptions,
                ));
            }
            Some("COPY") => true,
            Some(_) => return Err(Error::InvalidHeader),
        };
        Ok(SourceRequest {
            url: CopySource::parse(url)?,
            guard: Guard {
                conditions: Conditions::parse(self.headers, &conditions::SOURCE)?,
                lease: lease_id(self.headers, "x-ms-source-lease-id")?,
            },
            range,
            copy_properties,
            replace_metadata: self
                .headers
                .keys()
                .any(|name| name.as_str().starts_with("x-ms-meta-")),
            copy_tags,
        })
    }
}

/// Tag operations address the current blob or a version, never a snapshot.
fn version_only(selector: Option<Selector>) -> Result<Option<Ticks>> {
    match selector {
        None => Ok(None),
        Some(Selector::Version(version)) => Ok(Some(version)),
        Some(Selector::Snapshot(_)) => Err(Error::Unsupported),
    }
}

fn require_block_blob(headers: &HeaderMap) -> Result<()> {
    match header(headers, "x-ms-blob-type")? {
        Some("BlockBlob") => Ok(()),
        Some("AppendBlob" | "PageBlob") => Err(Error::Unsupported),
        _ => Err(Error::InvalidHeader),
    }
}

fn public_access(headers: &HeaderMap) -> Result<PublicAccess> {
    header(headers, "x-ms-blob-public-access")?
        .map(PublicAccess::parse)
        .transpose()
        .map(Option::unwrap_or_default)
}

fn includes(value: Option<&str>) -> Result<Vec<Include>> {
    value
        .unwrap_or_default()
        .split(',')
        .filter(|item| !item.is_empty())
        .map(|item| match item.to_ascii_lowercase().as_str() {
            "metadata" => Ok(Include::Metadata),
            "copy" => Ok(Include::Copy),
            "uncommittedblobs" => Ok(Include::Uncommitted),
            "snapshots" => Ok(Include::Snapshots),
            "versions" => Ok(Include::Versions),
            "deleted" => Ok(Include::Deleted),
            "tags" => Ok(Include::Tags),
            _ => Err(Error::Unsupported),
        })
        .collect()
}

fn range_checksum(headers: &HeaderMap) -> Result<Option<RangeChecksum>> {
    let flag = |name| Ok(header(headers, name)? == Some("true"));
    match (
        flag("x-ms-range-get-content-md5")?,
        flag("x-ms-range-get-content-crc64")?,
    ) {
        (true, true) => Err(Error::InvalidHeader),
        (true, false) => Ok(Some(RangeChecksum::Md5)),
        (false, true) => Ok(Some(RangeChecksum::Crc64)),
        (false, false) => Ok(None),
    }
}

pub(crate) fn lease_action(headers: &HeaderMap) -> Result<LeaseAction> {
    let current = || lease_id(headers, "x-ms-lease-id")?.ok_or(Error::MissingHeader);
    match header(headers, "x-ms-lease-action")?.ok_or(Error::MissingHeader)? {
        "acquire" => Ok(LeaseAction::Acquire {
            duration: LeaseDuration::parse(
                header(headers, "x-ms-lease-duration")?.ok_or(Error::MissingHeader)?,
            )?,
            proposed: lease_id(headers, "x-ms-proposed-lease-id")?,
        }),
        "renew" => Ok(LeaseAction::Renew(current()?)),
        "change" => Ok(LeaseAction::Change {
            current: current()?,
            proposed: lease_id(headers, "x-ms-proposed-lease-id")?.ok_or(Error::MissingHeader)?,
        }),
        "release" => Ok(LeaseAction::Release(current()?)),
        "break" => Ok(LeaseAction::Break {
            period: header(headers, "x-ms-lease-break-period")?
                .map(|period| match period.parse::<u32>() {
                    Ok(seconds @ 0..=60) => Ok(seconds),
                    _ => Err(Error::InvalidHeader),
                })
                .transpose()?,
        }),
        _ => Err(Error::InvalidHeader),
    }
}

pub(crate) fn upload_options(headers: &HeaderMap, limit: u64) -> Result<UploadOptions> {
    let length: u64 = header(headers, "content-length")?
        .ok_or(Error::MissingLength)?
        .parse()
        .map_err(|_| Error::InvalidLength)?;
    if length > limit {
        return Err(Error::TooLarge);
    }
    let md5 = decode_hash(header(headers, "content-md5")?)?;
    let crc64 = decode_hash(header(headers, "x-ms-content-crc64")?)?;
    let checksum = match (md5, crc64) {
        (Some(_), Some(_)) => return Err(Error::InvalidHeader),
        (Some(md5), None) => Some(Checksum::Md5(md5)),
        (None, Some(crc64)) => Some(Checksum::Crc64(u64::from_le_bytes(crc64))),
        (None, None) => None,
    };
    Ok(UploadOptions {
        length: ContentLength(length),
        checksum,
    })
}

fn decode_hash<const N: usize>(value: Option<&str>) -> Result<Option<[u8; N]>> {
    value
        .map(|value| {
            STANDARD
                .decode(value)
                .map_err(|_| Error::InvalidHeader)?
                .try_into()
                .map_err(|_| Error::InvalidHeader)
        })
        .transpose()
}

/// `x-ms-blob-content-md5`, which AzCopy sends empty when it has no hash to set.
fn blob_content_md5(headers: &HeaderMap) -> Result<Option<[u8; 16]>> {
    decode_hash(header(headers, "x-ms-blob-content-md5")?.filter(|value| !value.is_empty()))
}

/// Reads the content headers. The `x-ms-blob-*` form wins over the plain
/// header; `plain` also accepts the plain `Content-Type` of a Put Blob request.
/// The flag reports whether any content property was supplied.
fn content_headers(headers: &HeaderMap, plain: bool) -> Result<(ContentHeaders, bool)> {
    let pick = |blob: &str, standard: Option<&str>| -> Result<Option<String>> {
        let value = match header(headers, blob)? {
            Some(value) => Some(value),
            None => match standard {
                Some(name) => header(headers, name)?,
                None => None,
            },
        };
        match value {
            Some(value) if value.len() > 1024 || !xml_safe(value) => Err(Error::InvalidHeader),
            other => Ok(other.map(str::to_owned)),
        }
    };
    let fallback = |name| plain.then_some(name);
    let content_type = pick("x-ms-blob-content-type", fallback("content-type"))?;
    if content_type
        .as_deref()
        .is_some_and(|value| value.is_empty() || value.len() > 512)
    {
        return Err(Error::InvalidHeader);
    }
    let encoding = pick("x-ms-blob-content-encoding", fallback("content-encoding"))?;
    let language = pick("x-ms-blob-content-language", fallback("content-language"))?;
    let disposition = pick(
        "x-ms-blob-content-disposition",
        fallback("content-disposition"),
    )?;
    let cache_control = pick("x-ms-blob-cache-control", fallback("cache-control"))?;
    let supplied = BLOB_PROPERTIES
        .iter()
        .any(|name| headers.contains_key(*name));
    Ok((
        ContentHeaders {
            content_type: content_type.unwrap_or_else(|| "application/octet-stream".into()),
            encoding: encoding.unwrap_or_default(),
            language: language.unwrap_or_default(),
            disposition: disposition.unwrap_or_default(),
            cache_control: cache_control.unwrap_or_default(),
        },
        supplied,
    ))
}

fn metadata(headers: &HeaderMap) -> Result<Metadata> {
    let mut metadata = Metadata::new();
    for (name, value) in headers {
        if let Some(name) = name.as_str().strip_prefix("x-ms-meta-") {
            let mut chars = name.bytes();
            if !chars
                .next()
                .is_some_and(|b| b.is_ascii_alphabetic() || b == b'_')
                || !chars.all(|b| b.is_ascii_alphanumeric() || b == b'_')
            {
                return Err(Error::InvalidHeader);
            }
            let value = value.to_str().map_err(|_| Error::InvalidHeader)?;
            if !xml_safe(value) {
                return Err(Error::InvalidHeader);
            }
            metadata.insert(name.to_owned(), value.to_owned());
        }
    }
    if metadata
        .iter()
        .map(|(key, value)| key.len() + value.len())
        .sum::<usize>()
        > 8192
    {
        return Err(Error::InvalidHeader);
    }
    Ok(metadata)
}

fn blob_write(headers: &HeaderMap, plain: bool) -> Result<BlobWrite> {
    Ok(BlobWrite {
        headers: content_headers(headers, plain)?.0,
        metadata: metadata(headers)?,
        guard: Guard::parse(headers)?,
        tier: header(headers, "x-ms-access-tier")?
            .map(AccessTier::parse)
            .transpose()?,
        copy: None,
        md5: blob_content_md5(headers)?,
        tags: header(headers, "x-ms-tags")?
            .map(crate::blob_tags::from_header)
            .transpose()?
            .unwrap_or_default(),
    })
}

pub(crate) fn parse_block_list(body: &[u8]) -> Result<Vec<BlockSelection>> {
    let text = std::str::from_utf8(body).map_err(|_| Error::InvalidXml)?;
    let mut reader = Reader::from_str(text);
    reader.config_mut().trim_text(true);
    let root = match reader.read_event().map_err(|_| Error::InvalidXml)? {
        Event::Decl(_) => reader.read_event().map_err(|_| Error::InvalidXml)?,
        event => event,
    };
    let mut selections = Vec::new();
    let mut sources = HashMap::new();
    match root {
        Event::Empty(root)
            if root.name().as_ref() == "BlockList" && root.attributes_raw().is_empty() => {}
        Event::Start(root)
            if root.name().as_ref() == "BlockList" && root.attributes_raw().is_empty() =>
        {
            loop {
                match reader.read_event().map_err(|_| Error::InvalidXml)? {
                    Event::End(end) if end.name().as_ref() == "BlockList" => break,
                    Event::Start(tag) if tag.attributes_raw().is_empty() => {
                        if selections.len() == MAX_COMMITTED_BLOCKS {
                            return Err(Error::BlockListTooLong);
                        }
                        let source = match tag.name().as_ref() {
                            "Committed" => BlockSource::Committed,
                            "Uncommitted" => BlockSource::Uncommitted,
                            "Latest" => BlockSource::Latest,
                            _ => return Err(Error::InvalidXml),
                        };
                        let value = reader
                            .read_text(tag.name())
                            .map_err(|_| Error::InvalidXml)?;
                        let id =
                            BlockId::parse(value.trim()).map_err(|_| Error::InvalidBlockList)?;
                        if selections
                            .first()
                            .is_some_and(|first: &BlockSelection| first.id.width != id.width)
                        {
                            return Err(Error::InvalidBlockList);
                        }
                        if sources
                            .insert(id.as_str().to_owned(), source)
                            .is_some_and(|prior| prior != source)
                        {
                            return Err(Error::InvalidBlockList);
                        }
                        selections.push(BlockSelection { id, source });
                    }
                    _ => return Err(Error::InvalidXml),
                }
            }
        }
        _ => return Err(Error::InvalidXml),
    }
    if !matches!(reader.read_event(), Ok(Event::Eof)) {
        return Err(Error::InvalidXml);
    }
    Ok(selections)
}

/// Rejects query parameters and `x-ms-*` or conditional headers the operation
/// does not implement, instead of silently ignoring them.
pub(crate) fn check(
    query: &Query,
    headers: &HeaderMap,
    allowed_query: &[&str],
    allowed_headers: &[&[&str]],
    metadata: bool,
) -> Result<()> {
    if query
        .keys()
        .any(|key| key != "timeout" && !allowed_query.contains(&key.as_str()))
    {
        return Err(Error::Unsupported);
    }
    for key in headers.keys() {
        let key = key.as_str();
        if allowed_headers.iter().any(|list| list.contains(&key))
            || matches!(
                key,
                "x-ms-version"
                    | "x-ms-date"
                    | "x-ms-client-request-id"
                    | "x-ms-return-client-request-id"
            )
            || metadata && key.starts_with("x-ms-meta-")
            || key == "x-ms-if-tags"
                && allowed_headers
                    .iter()
                    .any(|list| list.contains(&"if-match"))
            || key == "x-ms-source-if-tags"
                && allowed_headers
                    .iter()
                    .any(|list| list.contains(&"x-ms-source-if-match"))
        {
            continue;
        }
        if key.starts_with("x-ms-")
            || key.starts_with("if-")
            || matches!(
                key,
                "range"
                    | "content-md5"
                    | "content-encoding"
                    | "content-language"
                    | "cache-control"
                    | "content-disposition"
            )
        {
            return Err(Error::Unsupported);
        }
    }
    Ok(())
}

pub(crate) fn check_hns_path(target: &Target, config: &Config) -> Result<()> {
    if let Target::Blob(key) = target
        && config.hns_accounts.contains(&key.container.account)
    {
        key.path.check_hns()?;
    }
    Ok(())
}

pub(crate) fn parse_query(query: Option<&str>) -> Result<Query> {
    let mut result = Query::new();
    if let Some(query) = query.filter(|query| !query.is_empty()) {
        if query.len() > 16 * 1024 {
            return Err(Error::InvalidQuery);
        }
        for pair in query.split('&') {
            let (name, value) = pair.split_once('=').ok_or(Error::InvalidQuery)?;
            let name = decode(name, true)
                .ok_or(Error::InvalidQuery)?
                .to_ascii_lowercase();
            let value = decode(value, true).ok_or(Error::InvalidQuery)?;
            if name.is_empty()
                || !xml_safe(&name)
                || !xml_safe(&value)
                || result.insert(name, value).is_some()
            {
                return Err(Error::InvalidQuery);
            }
        }
    }
    Ok(result)
}

fn decode(value: &str, query: bool) -> Option<String> {
    let mut bytes = value.bytes();
    while let Some(byte) = bytes.next() {
        if byte == b'%' && !(bytes.next()?.is_ascii_hexdigit() && bytes.next()?.is_ascii_hexdigit())
        {
            return None;
        }
    }
    let prepared = if query && value.contains('+') {
        std::borrow::Cow::Owned(value.replace('+', " "))
    } else {
        std::borrow::Cow::Borrowed(value)
    };
    percent_decode_str(&prepared)
        .decode_utf8()
        .ok()
        .map(|value| value.into_owned())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn include_values_are_case_insensitive() {
        // The .NET SDK sends include=Snapshots.
        let parsed = includes(Some("Snapshots,METADATA")).unwrap();
        assert!(matches!(
            parsed[..],
            [Include::Snapshots, Include::Metadata]
        ));
        assert!(includes(Some("nonsense")).is_err());
    }
    use axum::http::HeaderValue;

    fn headers(pairs: &[(&'static str, &str)]) -> HeaderMap {
        let mut headers = HeaderMap::new();
        for (name, value) in pairs {
            headers.insert(*name, HeaderValue::from_str(value).unwrap());
        }
        headers
    }

    #[test]
    fn query_rejects_ambiguous_signature_and_literal_line_breaks() {
        assert_eq!(
            parse_query(Some("COMP=list&comp=list")),
            Err(Error::InvalidQuery)
        );
        assert_eq!(
            parse_query(Some("prefix=%0aNext:value")),
            Err(Error::InvalidQuery)
        );
        assert_eq!(parse_query(Some("prefix=%ff")), Err(Error::InvalidQuery));
        assert_eq!(parse_query(Some("prefix=%2")), Err(Error::InvalidQuery));
        assert_eq!(
            parse_query(Some("PreFix=a+%2B%2Fb"))
                .unwrap()
                .get("prefix")
                .map(String::as_str),
            Some("a +/b")
        );
        assert_eq!(decode("a+%2Fb", false).as_deref(), Some("a+/b"));
    }

    #[test]
    fn blob_headers_prefer_the_blob_specific_form_and_report_whether_any_were_sent() {
        let sent = headers(&[
            ("x-ms-blob-content-type", "text/plain"),
            ("content-type", "ignored/for-properties"),
            ("content-encoding", "gzip"),
            ("x-ms-blob-cache-control", "no-store"),
        ]);
        let (props, supplied) = content_headers(&sent, true).unwrap();
        assert!(supplied);
        assert_eq!(props.content_type, "text/plain");
        assert_eq!(
            (props.encoding.as_str(), props.cache_control.as_str()),
            ("gzip", "no-store")
        );
        let (props, supplied) = content_headers(&sent, false).unwrap();
        assert_eq!((props.encoding.as_str(), supplied), ("", true));
        let (props, supplied) = content_headers(&headers(&[]), true).unwrap();
        assert_eq!(
            (props.content_type.as_str(), supplied),
            ("application/octet-stream", false)
        );
        assert!(content_headers(&headers(&[("x-ms-blob-content-type", "")]), true).is_err());
    }

    #[test]
    fn lease_headers_map_to_actions_and_reject_invalid_values() {
        let id = "00000000-0000-0000-0000-000000000001";
        let other = "00000000-0000-0000-0000-000000000002";
        let acquire = headers(&[
            ("x-ms-lease-action", "acquire"),
            ("x-ms-lease-duration", "-1"),
        ]);
        assert!(matches!(
            lease_action(&acquire),
            Ok(LeaseAction::Acquire {
                duration: LeaseDuration::Infinite,
                proposed: None
            })
        ));
        let change = headers(&[
            ("x-ms-lease-action", "change"),
            ("x-ms-lease-id", id),
            ("x-ms-proposed-lease-id", other),
        ]);
        assert!(matches!(
            lease_action(&change),
            Ok(LeaseAction::Change { .. })
        ));
        let brk = headers(&[
            ("x-ms-lease-action", "break"),
            ("x-ms-lease-break-period", "61"),
        ]);
        assert_eq!(lease_action(&brk).err(), Some(Error::InvalidHeader));
        let renew = headers(&[("x-ms-lease-action", "renew")]);
        assert_eq!(lease_action(&renew).err(), Some(Error::MissingHeader));
        let short = headers(&[
            ("x-ms-lease-action", "acquire"),
            ("x-ms-lease-duration", "5"),
        ]);
        assert_eq!(lease_action(&short).err(), Some(Error::InvalidHeader));
    }

    #[test]
    fn unimplemented_headers_and_parameters_are_refused() {
        let query = Query::from([("snapshot".to_owned(), "x".to_owned())]);
        assert_eq!(
            check(&query, &headers(&[]), &[], &[], false),
            Err(Error::Unsupported)
        );
        let tags = headers(&[("x-ms-tags", "a=b")]);
        assert_eq!(
            check(&Query::new(), &tags, &[], &[], false),
            Err(Error::Unsupported)
        );
        let timeout = Query::from([("timeout".to_owned(), "30".to_owned())]);
        assert_eq!(
            check(
                &timeout,
                &headers(&[("origin", "https://a.test")]),
                &[],
                &[],
                false
            ),
            Ok(())
        );
    }

    #[test]
    fn listing_includes_name_what_they_support() {
        assert_eq!(
            includes(Some("metadata,copy,uncommittedblobs"))
                .unwrap()
                .len(),
            3
        );
        assert_eq!(
            includes(Some("snapshots,versions,deleted,tags"))
                .unwrap()
                .len(),
            4
        );
        assert_eq!(
            includes(Some("immutabilitypolicy")).err(),
            Some(Error::Unsupported)
        );
        assert!(includes(None).unwrap().is_empty());
    }
}
