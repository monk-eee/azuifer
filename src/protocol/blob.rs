//! Blob operations: which request each method, query and header selects.

use super::headers::{
    blob_content_md5, blob_write, content_headers, lease_action, metadata, range_checksum,
    upload_options,
};
use super::{
    BLOB_PROPERTIES, CHECKSUMS, CONDITIONS, LEASE, LEASE_HEADERS, MAX_BLOCK_LIST_BYTES,
    MAX_XML_BODY_BYTES, Operation, PLAIN_PROPERTIES, Request, SOURCE, SOURCE_BEARER, SourceRequest,
    TAG_CONDITION, TAGS,
};
use crate::{
    auth::header,
    blob_copy::CopySource,
    blob_snapshot::{self, Selector},
    conditions::{self, Conditions, Guard, lease_id},
    domain::{AccessTier, BlobKey, BlobRead, BlockId, BlockListKind, ByteRange, Error, Result},
    stamp::Ticks,
};
use axum::http::{HeaderMap, Method};

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

impl Request<'_> {
    pub(super) fn blob_operation(&self, key: BlobKey) -> Result<Operation> {
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
                            SOURCE_BEARER,
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
                        SOURCE_BEARER,
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
            (&Method::POST, Some("query")) => {
                self.check(
                    &["comp", "snapshot", "versionid"],
                    &[CONDITIONS, LEASE, CHECKSUMS],
                    false,
                )?;
                Operation::QueryBlob(
                    key,
                    selector,
                    upload_options(self.headers, MAX_XML_BODY_BYTES)?,
                    guard()?,
                )
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

    pub(super) fn source(
        &self,
        range: Option<ByteRange>,
        copy_properties: bool,
    ) -> Result<SourceRequest> {
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
            bearer: header(self.headers, "x-ms-copy-source-authorization")?
                .map(crate::blob_copy::SourceBearer::parse)
                .transpose()?,
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
