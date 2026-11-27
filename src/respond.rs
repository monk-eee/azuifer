//! Maps typed Blob outcomes to Azure responses: headers, XML bodies, and errors.

use crate::{
    blob_page::{BlobKind, PageError},
    blob_sas::Overrides,
    domain::{
        BlobInfo, BlobListing, ContainerInfo, Entity, Error, Include, ListEntry, ListRequest,
        Metadata, Page, PageRequest, PublicAccess, Result, SignedIdentifier,
    },
    lease::LeaseView,
    store::{Download, Payload},
    wire::{Xml, correlated_error_message, xml_error, xml_error_with_details},
};
use axum::{
    body::Body,
    http::{HeaderMap, HeaderName, HeaderValue, StatusCode},
    response::Response,
};
use futures_util::TryStreamExt as _;
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use tokio::io::AsyncReadExt as _;
use tokio_util::io::ReaderStream;

pub(crate) fn empty(status: StatusCode) -> Response {
    let mut response = Response::new(Body::empty());
    *response.status_mut() = status;
    response
}

pub(crate) fn http_date(seconds: u64) -> Result<String> {
    if seconds >= 253_402_300_800 {
        tracing::error!("metadata timestamp is outside the HTTP date range");
        return Err(Error::Internal);
    }
    Ok(httpdate::fmt_http_date(
        UNIX_EPOCH + Duration::from_secs(seconds),
    ))
}

pub(crate) fn set(headers: &mut HeaderMap, name: &'static str, value: &str) -> Result<()> {
    let value = HeaderValue::from_str(value).map_err(|_| {
        tracing::error!(header = name, "could not encode response header");
        Error::Internal
    })?;
    headers.insert(name, value);
    Ok(())
}

pub(crate) fn entity_response(status: StatusCode, entity: Entity) -> Result<Response> {
    let mut response = empty(status);
    entity_headers(response.headers_mut(), entity)?;
    Ok(response)
}

pub(crate) fn entity_headers(headers: &mut HeaderMap, entity: Entity) -> Result<()> {
    set(headers, "etag", entity.etag().as_str())?;
    set(headers, "last-modified", &http_date(entity.modified)?)?;
    if let Some(version) = entity.version {
        set(headers, "x-ms-version-id", &version.text())?;
    }
    Ok(())
}

/// Adds a checksum header and the encryption flag Put operations report.
pub(crate) fn write_response(
    mut response: Response,
    (name, value): (&'static str, String),
) -> Result<Response> {
    set(response.headers_mut(), name, &value)?;
    response.headers_mut().insert(
        "x-ms-request-server-encrypted",
        HeaderValue::from_static("false"),
    );
    Ok(response)
}

pub(crate) fn lease_headers(headers: &mut HeaderMap, view: LeaseView) -> Result<()> {
    set(headers, "x-ms-lease-status", view.status())?;
    set(headers, "x-ms-lease-state", view.state.name())?;
    if let Some(duration) = view.duration() {
        set(headers, "x-ms-lease-duration", duration)?;
    }
    Ok(())
}

pub(crate) fn metadata_headers(headers: &mut HeaderMap, metadata: Metadata) -> Result<()> {
    for (name, value) in metadata {
        let name =
            HeaderName::from_bytes(format!("x-ms-meta-{name}").as_bytes()).map_err(|_| {
                tracing::error!("invalid stored metadata header");
                Error::Internal
            })?;
        let value = HeaderValue::from_str(&value).map_err(|_| {
            tracing::error!("invalid stored metadata value");
            Error::Internal
        })?;
        headers.insert(name, value);
    }
    Ok(())
}

fn optional(headers: &mut HeaderMap, name: &'static str, value: &str) -> Result<()> {
    if value.is_empty() {
        Ok(())
    } else {
        set(headers, name, value)
    }
}

/// Properties shared by Get Blob and Get Blob Properties. A service SAS may
/// override the five content headers.
fn blob_headers(
    headers: &mut HeaderMap,
    info: &BlobInfo,
    overrides: Option<&Overrides>,
) -> Result<()> {
    let pick =
        |over: Option<&String>, stored: &str| over.map_or_else(|| stored.to_owned(), Clone::clone);
    let none = Overrides::default();
    let over = overrides.unwrap_or(&none);
    set(
        headers,
        "content-type",
        &pick(over.content_type.as_ref(), &info.headers.content_type),
    )?;
    optional(
        headers,
        "content-encoding",
        &pick(over.encoding.as_ref(), &info.headers.encoding),
    )?;
    optional(
        headers,
        "content-language",
        &pick(over.language.as_ref(), &info.headers.language),
    )?;
    optional(
        headers,
        "content-disposition",
        &pick(over.disposition.as_ref(), &info.headers.disposition),
    )?;
    optional(
        headers,
        "cache-control",
        &pick(over.cache_control.as_ref(), &info.headers.cache_control),
    )?;
    set(headers, "x-ms-creation-time", &http_date(info.created)?)?;
    set(headers, "x-ms-blob-type", info.kind.name())?;
    kind_headers(headers, info.kind)?;
    set(headers, "x-ms-server-encrypted", "true")?;
    if !info.tags.is_empty() {
        set(headers, "x-ms-tag-count", &info.tags.len().to_string())?;
    }
    if info.entity.version.is_some() {
        set(headers, "x-ms-is-current-version", "true")?;
    }
    headers.insert("accept-ranges", HeaderValue::from_static("bytes"));
    lease_headers(headers, info.lease)?;
    match info.tier {
        Some((tier, changed)) => {
            set(headers, "x-ms-access-tier", tier.name())?;
            set(
                headers,
                "x-ms-access-tier-change-time",
                &http_date(changed)?,
            )?;
        }
        None if info.kind.is_block() => {
            set(headers, "x-ms-access-tier", "Hot")?;
            set(headers, "x-ms-access-tier-inferred", "true")?;
        }
        None => (),
    }
    if let Some(copy) = &info.copy {
        set(headers, "x-ms-copy-id", &copy.id)?;
        set(headers, "x-ms-copy-source", &copy.source)?;
        set(headers, "x-ms-copy-status", "success")?;
        set(
            headers,
            "x-ms-copy-progress",
            &format!("{0}/{0}", info.length.0),
        )?;
        set(
            headers,
            "x-ms-copy-completion-time",
            &http_date(copy.completed)?,
        )?;
    }
    crate::blob_lifecycle::lifecycle_headers(headers, &info.lifecycle)?;
    Ok(())
}

pub(crate) fn download_response(
    download: Download,
    overrides: Option<&Overrides>,
) -> Result<Response> {
    let Download {
        info,
        range,
        payload,
        range_checksum,
    } = download;
    let status = if range.is_some() {
        StatusCode::PARTIAL_CONTENT
    } else {
        StatusCode::OK
    };
    let mut response = entity_response(status, info.entity)?;
    let headers = response.headers_mut();
    blob_headers(headers, &info, overrides)?;
    let size = if let Some(range) = range {
        set(
            headers,
            "content-range",
            &format!("bytes {}-{}/{}", range.start, range.end - 1, info.length.0),
        )?;
        range.end - range.start
    } else {
        if let Some(md5) = &info.md5 {
            set(headers, "content-md5", md5)?;
        }
        info.length.0
    };
    if let Some((name, value)) = range_checksum {
        set(headers, name, &value)?;
    }
    set(headers, "content-length", &size.to_string())?;
    metadata_headers(headers, info.metadata)?;
    *response.body_mut() = match payload {
        Some(Payload::Disk(file)) => {
            let reader = tokio::fs::File::from_std(file).take(size);
            Body::from_stream(ReaderStream::new(reader).inspect_err(|error| {
                tracing::error!(kind = ?error.kind(), "content read failed");
            }))
        }
        Some(Payload::Memory(bytes)) => Body::from(bytes),
        Some(Payload::Ranges(body)) => Body::from_stream(body.into_stream()),
        None => Body::empty(),
    };
    Ok(response)
}

/// The type-specific headers of page and append blobs.
pub(crate) fn kind_headers(headers: &mut HeaderMap, kind: BlobKind) -> Result<()> {
    match kind {
        BlobKind::Block => (),
        BlobKind::Page { sequence } => {
            set(headers, "x-ms-blob-sequence-number", &sequence.to_string())?;
        }
        BlobKind::Append { committed, sealed } => {
            set(
                headers,
                "x-ms-blob-committed-block-count",
                &committed.to_string(),
            )?;
            if sealed {
                set(headers, "x-ms-blob-sealed", "true")?;
            }
        }
    }
    Ok(())
}

/// Get Blob Metadata: the ETag, lease state, and user metadata.
pub(crate) fn blob_metadata_response(download: Download) -> Result<Response> {
    let info = download.info;
    let mut response = entity_response(StatusCode::OK, info.entity)?;
    lease_headers(response.headers_mut(), info.lease)?;
    metadata_headers(response.headers_mut(), info.metadata)?;
    Ok(response)
}
pub(crate) fn container_response(info: ContainerInfo, metadata_only: bool) -> Result<Response> {
    let mut response = entity_response(StatusCode::OK, info.entity)?;
    let headers = response.headers_mut();
    if !metadata_only {
        lease_headers(headers, info.lease)?;
        if let Some(access) = info.public_access.name() {
            set(headers, "x-ms-blob-public-access", access)?;
        }
        set(headers, "x-ms-has-immutability-policy", "false")?;
        set(headers, "x-ms-has-legal-hold", "false")?;
        set(
            headers,
            "x-ms-default-encryption-scope",
            "$account-encryption-key",
        )?;
        set(headers, "x-ms-deny-encryption-scope-override", "false")?;
    }
    metadata_headers(headers, info.metadata)?;
    Ok(response)
}

pub(crate) fn acl_response(
    entity: Entity,
    public_access: PublicAccess,
    identifiers: &[SignedIdentifier],
) -> Result<Response> {
    let mut xml = Xml::root("SignedIdentifiers", &[]);
    for identifier in identifiers {
        xml.open("SignedIdentifier");
        xml.element("Id", &identifier.id);
        xml.open("AccessPolicy");
        if let Some(start) = &identifier.start {
            xml.element("Start", start);
        }
        if let Some(expiry) = &identifier.expiry {
            xml.element("Expiry", expiry);
        }
        if let Some(permission) = &identifier.permission {
            xml.element("Permission", permission);
        }
        xml.close("AccessPolicy");
        xml.close("SignedIdentifier");
    }
    let mut response = xml.finish("SignedIdentifiers", StatusCode::OK);
    entity_headers(response.headers_mut(), entity)?;
    if let Some(access) = public_access.name() {
        set(response.headers_mut(), "x-ms-blob-public-access", access)?;
    }
    Ok(response)
}

pub(crate) fn lease_elements(xml: &mut Xml, view: LeaseView) {
    xml.element("LeaseStatus", view.status());
    xml.element("LeaseState", view.state.name());
    if let Some(duration) = view.duration() {
        xml.element("LeaseDuration", duration);
    }
}

pub(crate) fn container_list_xml(endpoint: &str, page: &PageRequest) -> Xml {
    let mut xml = Xml::root("EnumerationResults", &[("ServiceEndpoint", endpoint)]);
    paging_elements(&mut xml, page);
    xml.open("Containers");
    xml
}

fn paging_elements(xml: &mut Xml, page: &PageRequest) {
    if !page.prefix.is_empty() {
        xml.element("Prefix", &page.prefix);
    }
    if let Some(marker) = page.marker() {
        xml.element("Marker", &marker);
    }
    xml.element("MaxResults", &page.limit.to_string());
}

pub(crate) fn list_containers(
    mut xml: Xml,
    page: Page<ContainerInfo>,
    metadata: bool,
) -> Result<Response> {
    for (name, info) in page.items {
        xml.open("Container");
        xml.element("Name", &name);
        xml.open("Properties");
        xml.entity(info.entity)?;
        lease_elements(&mut xml, info.lease);
        if let Some(access) = info.public_access.name() {
            xml.element("PublicAccess", access);
        }
        xml.element("DefaultEncryptionScope", "$account-encryption-key");
        xml.element("DenyEncryptionScopeOverride", "false");
        xml.element("HasImmutabilityPolicy", "false");
        xml.element("HasLegalHold", "false");
        xml.close("Properties");
        if metadata {
            xml.metadata(info.metadata);
        }
        xml.close("Container");
    }
    xml.close("Containers");
    xml.element("NextMarker", &page.next);
    Ok(xml.finish("EnumerationResults", StatusCode::OK))
}

pub(crate) fn blob_list_xml(endpoint: &str, container: &str, request: &ListRequest) -> Xml {
    let mut xml = Xml::root(
        "EnumerationResults",
        &[("ServiceEndpoint", endpoint), ("ContainerName", container)],
    );
    paging_elements(&mut xml, &request.page);
    if let Some(delimiter) = &request.delimiter {
        xml.element("Delimiter", delimiter);
    }
    xml.open("Blobs");
    xml
}

pub(crate) fn list_blobs(
    mut xml: Xml,
    listing: BlobListing,
    include: &[Include],
    hierarchical: bool,
) -> Result<Response> {
    for entry in listing.entries {
        match entry {
            ListEntry::Prefix(name) => {
                xml.open("BlobPrefix");
                xml.element("Name", &name);
                xml.close("BlobPrefix");
            }
            ListEntry::Blob(name, info) => {
                xml.open("Blob");
                xml.element("Name", &name);
                blob_properties(
                    &mut xml,
                    &info,
                    include.contains(&Include::Copy),
                    hierarchical,
                    &[],
                )?;
                if include.contains(&Include::Metadata) && !info.uncommitted {
                    xml.metadata(info.metadata);
                }
                xml.close("Blob");
            }
            ListEntry::Directory(name, entity) => {
                xml.open("Blob");
                xml.element("Name", &name);
                xml.open("Properties");
                xml.entity(entity)?;
                xml.element("Content-Length", "0");
                xml.element("ResourceType", "directory");
                xml.close("Properties");
                xml.close("Blob");
            }
        }
    }
    xml.close("Blobs");
    xml.element("NextMarker", &listing.next);
    Ok(xml.finish("EnumerationResults", StatusCode::OK))
}

/// `extra` adds elements (such as `DeletedTime`) to the end of `Properties`.
pub(crate) fn blob_properties(
    xml: &mut Xml,
    info: &BlobInfo,
    copy: bool,
    hierarchical: bool,
    extra: &[(&str, String)],
) -> Result<()> {
    xml.open("Properties");
    if info.uncommitted {
        xml.element("Content-Length", "0");
        xml.element("BlobType", "BlockBlob");
        if hierarchical {
            xml.element("ResourceType", "file");
        }
        lease_elements(xml, info.lease);
        xml.close("Properties");
        return Ok(());
    }
    xml.element("Creation-Time", &http_date(info.created)?);
    // The XML uses the opaque value without the HTTP ETag's quotes.
    xml.entity_properties(
        info.entity.modified,
        info.entity.etag().as_str().trim_matches('"'),
    )?;
    xml.element("Content-Length", &info.length.0.to_string());
    xml.element("Content-Type", &info.headers.content_type);
    xml.element("Content-Encoding", &info.headers.encoding);
    xml.element("Content-Language", &info.headers.language);
    xml.element("Content-MD5", info.md5.as_deref().unwrap_or_default());
    xml.element("Cache-Control", &info.headers.cache_control);
    xml.element("Content-Disposition", &info.headers.disposition);
    xml.element("BlobType", info.kind.name());
    match info.kind {
        BlobKind::Block => (),
        BlobKind::Page { sequence } => {
            xml.element("x-ms-blob-sequence-number", &sequence.to_string());
        }
        BlobKind::Append { sealed: true, .. } => xml.element("Sealed", "true"),
        BlobKind::Append { .. } => (),
    }
    match info.tier {
        Some((tier, changed)) => {
            xml.element("AccessTier", tier.name());
            xml.element("AccessTierChangeTime", &http_date(changed)?);
        }
        None if info.kind.is_block() => {
            xml.element("AccessTier", "Hot");
            xml.element("AccessTierInferred", "true");
        }
        None => (),
    }
    lease_elements(xml, info.lease);
    if copy && let Some(copy) = &info.copy {
        xml.element("CopyId", &copy.id);
        xml.element("CopyStatus", "success");
        xml.element("CopySource", &copy.source);
        xml.element("CopyProgress", &format!("{0}/{0}", info.length.0));
        xml.element("CopyCompletionTime", &http_date(copy.completed)?);
    }
    xml.element("ServerEncrypted", "true");
    crate::blob_lifecycle::lifecycle_elements(xml, &info.lifecycle)?;
    for (name, value) in extra {
        xml.element(name, value);
    }
    xml.close("Properties");
    Ok(())
}

impl Xml {
    pub(crate) fn entity(&mut self, entity: Entity) -> Result<()> {
        self.entity_properties(entity.modified, entity.etag().as_str())
    }

    fn entity_properties(&mut self, modified: u64, etag: &str) -> Result<()> {
        self.element("Last-Modified", &http_date(modified)?);
        self.element("Etag", etag);
        Ok(())
    }

    pub(crate) fn metadata(&mut self, metadata: Metadata) {
        self.open("Metadata");
        for (name, value) in metadata {
            self.element(&name, &value);
        }
        self.close("Metadata");
    }
}

/// The Azure status, error code, and message for a domain error.
fn describe(error: Error) -> (StatusCode, &'static str, &'static str) {
    use StatusCode as S;
    match error {
        Error::AuthenticationFailed => (
            S::FORBIDDEN,
            "AuthenticationFailed",
            "Server failed to authenticate the request. Make sure the value of the Authorization header is formed correctly including the signature.",
        ),
        Error::InvalidAuthenticationInfo => (
            S::UNAUTHORIZED,
            "InvalidAuthenticationInfo",
            "Server failed to authenticate the request. Please refer to the information in the www-authenticate header.",
        ),
        Error::InvalidName => (
            S::BAD_REQUEST,
            "InvalidResourceName",
            "The resource name is invalid.",
        ),
        Error::InvalidHeader => (
            S::BAD_REQUEST,
            "InvalidHeaderValue",
            "A request header is invalid or missing.",
        ),
        Error::IncompatibleBlobTier => (
            S::BAD_REQUEST,
            "InvalidHeaderValue",
            "The value for one of the HTTP headers is not in the correct format.",
        ),
        Error::InvalidVersion => (
            S::BAD_REQUEST,
            "InvalidHeaderValue",
            "The requested API version is not supported.",
        ),
        Error::InvalidQuery => (
            S::BAD_REQUEST,
            "InvalidQueryParameterValue",
            "A query parameter is invalid.",
        ),
        Error::Unsupported => (
            S::NOT_IMPLEMENTED,
            "NotImplemented",
            "This operation or option is not implemented.",
        ),
        Error::MissingLength => (
            S::LENGTH_REQUIRED,
            "MissingContentLengthHeader",
            "A Content-Length header is required.",
        ),
        Error::InvalidLength => (
            S::BAD_REQUEST,
            "InvalidInput",
            "The body does not match Content-Length.",
        ),
        Error::TooLarge => (
            S::PAYLOAD_TOO_LARGE,
            "RequestBodyTooLarge",
            "The upload exceeds the configured limit.",
        ),
        Error::Md5Mismatch => (
            S::BAD_REQUEST,
            "Md5Mismatch",
            "The body checksum does not match Content-MD5.",
        ),
        Error::Crc64Mismatch => (
            S::BAD_REQUEST,
            "Crc64Mismatch",
            "The body checksum does not match x-ms-content-crc64.",
        ),
        Error::InvalidBlockId => (
            S::BAD_REQUEST,
            "InvalidBlockId",
            "The block ID is malformed or has inconsistent length.",
        ),
        Error::BlockIdWidthMismatch => (
            S::BAD_REQUEST,
            "InvalidBlobOrBlock",
            "The specified blob or block content is invalid.",
        ),
        Error::InvalidBlockList => (
            S::BAD_REQUEST,
            "InvalidBlockList",
            "The specified block list is invalid.",
        ),
        Error::InvalidXml => (
            S::BAD_REQUEST,
            "InvalidXmlDocument",
            "The request XML document is invalid.",
        ),
        Error::BlockCountExceeded => (
            S::CONFLICT,
            "BlockCountExceedsLimit",
            "The block count exceeds the limit.",
        ),
        Error::BlockListTooLong => (
            S::BAD_REQUEST,
            "BlockListTooLong",
            "The block list exceeds 50,000 entries.",
        ),
        Error::ContainerExists => (
            S::CONFLICT,
            "ContainerAlreadyExists",
            "The specified container already exists.",
        ),
        Error::ContainerMissing => (
            S::NOT_FOUND,
            "ContainerNotFound",
            "The specified container does not exist.",
        ),
        Error::BlobMissing => (
            S::NOT_FOUND,
            "BlobNotFound",
            "The specified blob does not exist.",
        ),
        Error::PathConflict => (
            S::CONFLICT,
            "BlobOperationNotSupported",
            "The path conflicts with a file or directory.",
        ),
        Error::DirectoryNotEmpty => (
            S::CONFLICT,
            "DirectoryIsNotEmpty",
            "This operation is not permitted on a non-empty directory.",
        ),
        Error::ResourceNotFound => (
            S::NOT_FOUND,
            "ResourceNotFound",
            "The specified resource does not exist.",
        ),
        Error::ConditionNotMet | Error::NotModified => (
            if error == Error::NotModified {
                S::NOT_MODIFIED
            } else {
                S::PRECONDITION_FAILED
            },
            "ConditionNotMet",
            "The condition specified using HTTP conditional header(s) is not met.",
        ),
        Error::SourceConditionNotMet => (
            S::PRECONDITION_FAILED,
            "SourceConditionNotMet",
            "The source condition specified using HTTP conditional header(s) is not met.",
        ),
        Error::InvalidRange(_) => (
            S::RANGE_NOT_SATISFIABLE,
            "InvalidRange",
            "The range specified is invalid for the current size of the resource.",
        ),
        Error::ConflictingRangeChecksums => (
            S::BAD_REQUEST,
            "BothCrc64AndMd5RangeHeaderPresent",
            "Both x-ms-range-get-content-crc64 header and x-ms-range-get-content-md5 header are present.",
        ),
        Error::QuotaExceeded => (
            S::INSUFFICIENT_STORAGE,
            "InsufficientStorage",
            "The in-memory content quota was exceeded.",
        ),
        Error::Busy => (
            S::SERVICE_UNAVAILABLE,
            "ServerBusy",
            "Too many active requests.",
        ),
        Error::Timeout => (
            S::REQUEST_TIMEOUT,
            "OperationTimedOut",
            "The upload did not finish in time.",
        ),
        Error::Internal => (
            S::INTERNAL_SERVER_ERROR,
            "InternalError",
            "The local storage operation failed.",
        ),
        Error::PermissionMismatch => (
            S::FORBIDDEN,
            "AuthorizationPermissionMismatch",
            "This request is not authorized to perform this operation using this permission.",
        ),
        Error::ResourceTypeMismatch => (
            S::FORBIDDEN,
            "AuthorizationResourceTypeMismatch",
            "This request is not authorized to perform this operation using this resource type.",
        ),
        Error::ServiceMismatch => (
            S::FORBIDDEN,
            "AuthorizationServiceMismatch",
            "This request is not authorized to perform this operation using this service.",
        ),
        Error::SourceIpMismatch => (
            S::FORBIDDEN,
            "AuthorizationSourceIPMismatch",
            "This request is not authorized to perform this operation using this source IP address.",
        ),
        Error::ProtocolMismatch => (
            S::FORBIDDEN,
            "AuthorizationProtocolMismatch",
            "This request is not authorized to perform this operation using this protocol.",
        ),
        Error::BlobAlreadyExists => (
            S::CONFLICT,
            "BlobAlreadyExists",
            "The specified blob already exists.",
        ),
        Error::BlobArchived => (
            S::CONFLICT,
            "BlobArchived",
            "This operation is not permitted on an archived blob.",
        ),
        Error::MissingHeader => (
            S::BAD_REQUEST,
            "MissingRequiredHeader",
            "An HTTP header that is mandatory for this request is not specified.",
        ),
        Error::LeaseIdMissing => (
            S::PRECONDITION_FAILED,
            "LeaseIdMissing",
            "There is currently a lease on the container and no lease ID was specified in the request.",
        ),
        Error::LeaseIdMissingBlob => (
            S::PRECONDITION_FAILED,
            "LeaseIdMissing",
            "There is currently a lease on the blob and no lease ID was specified in the request.",
        ),
        Error::LeaseLost => (
            S::PRECONDITION_FAILED,
            "LeaseLost",
            "A lease ID was specified, but the lease for the resource has expired.",
        ),
        Error::LeaseAlreadyPresent => (
            S::CONFLICT,
            "LeaseAlreadyPresent",
            "There is already a lease present.",
        ),
        Error::LeaseMismatchBlob => (
            S::PRECONDITION_FAILED,
            "LeaseIdMismatchWithBlobOperation",
            "The lease ID specified did not match the lease ID for the blob.",
        ),
        Error::LeaseMismatchContainer => (
            S::PRECONDITION_FAILED,
            "LeaseIdMismatchWithContainerOperation",
            "The lease ID specified did not match the lease ID for the container.",
        ),
        Error::LeaseMismatchLease => (
            S::CONFLICT,
            "LeaseIdMismatchWithLeaseOperation",
            "The lease ID specified did not match the lease ID for the blob.",
        ),
        Error::LeaseMismatchContainerLease => (
            S::CONFLICT,
            "LeaseIdMismatchWithLeaseOperation",
            "The lease ID specified did not match the lease ID for the container.",
        ),
        Error::LeaseNotPresentBlob => (
            S::PRECONDITION_FAILED,
            "LeaseNotPresentWithBlobOperation",
            "There is currently no lease on the blob.",
        ),
        Error::LeaseNotPresentContainer => (
            S::PRECONDITION_FAILED,
            "LeaseNotPresentWithContainerOperation",
            "There is currently no lease on the container.",
        ),
        Error::LeaseNotPresentLease => (
            S::CONFLICT,
            "LeaseNotPresentWithLeaseOperation",
            "There is currently no lease on the resource.",
        ),
        Error::LeaseBreakingNoAcquire => (
            S::CONFLICT,
            "LeaseIsBreakingAndCannotBeAcquired",
            "The lease ID matched, but the lease is currently in breaking state and cannot be acquired until it is broken.",
        ),
        Error::LeaseBreakingNoChange => (
            S::CONFLICT,
            "LeaseIsBreakingAndCannotBeChanged",
            "The lease ID matched, but the lease is currently in breaking state and cannot be changed.",
        ),
        Error::LeaseBrokenNoRenew => (
            S::CONFLICT,
            "LeaseIsBrokenAndCannotBeRenewed",
            "The lease ID matched, but the lease has been broken explicitly and cannot be renewed.",
        ),
        Error::NoPendingCopy => (
            S::CONFLICT,
            "NoPendingCopyOperation",
            "There is currently no pending copy operation.",
        ),
        Error::CopyIdMismatch => (
            S::CONFLICT,
            "CopyIdMismatch",
            "The specified copy ID did not match the copy ID for the destination blob.",
        ),
        Error::CopySourceDenied => (
            S::FORBIDDEN,
            "CannotVerifyCopySource",
            "Could not verify the copy source within the specified time.",
        ),
        Error::CopySourceMissing => (
            S::NOT_FOUND,
            "CannotVerifyCopySource",
            "Could not verify the copy source: the source does not exist.",
        ),
        Error::SnapshotsPresent => (
            S::CONFLICT,
            "SnapshotsPresent",
            "This operation is not permitted because the blob has snapshots.",
        ),
        Error::InvalidTag => (
            S::BAD_REQUEST,
            "InvalidTag",
            "The tags specified are invalid. They contain characters that are not permitted.",
        ),
        Error::TagsTooLarge => (
            S::BAD_REQUEST,
            "TagsTooLarge",
            "The tags specified exceed the permitted number or length.",
        ),
        Error::InvalidInput | Error::InvalidBatchEnvelope => (
            S::BAD_REQUEST,
            "InvalidInput",
            "One of the request inputs is not valid.",
        ),
        Error::MixedBatchOperations => (
            S::BAD_REQUEST,
            "AllBatchSubRequestsShouldBeSameApi",
            "All batch subrequests should be the same api.",
        ),
        Error::CorsPreflight => (
            S::FORBIDDEN,
            "CorsPreflightFailure",
            "CORS is not enabled or no matching rule was found for this request.",
        ),
        Error::Page(error) => error.describe(),
        Error::Ext(error) => error.describe(),
    }
}

pub(crate) fn error_response(error: Error) -> Response {
    render_error(error, None)
}

pub(crate) fn correlated_error_response(
    error: Error,
    request_id: &str,
    now: SystemTime,
) -> Response {
    render_error(error, Some((request_id, now)))
}

pub(crate) fn request_error_response(
    error: Error,
    request_headers: &HeaderMap,
    request_id: &str,
    now: SystemTime,
) -> Response {
    let rejected_header = match error {
        Error::Page(PageError::UnalignedPageRange) => Some((
            "Range",
            request_headers
                .get("x-ms-range")
                .or_else(|| request_headers.get("range")),
        )),
        Error::IncompatibleBlobTier => {
            Some(("x-ms-access-tier", request_headers.get("x-ms-access-tier")))
        }
        _ => None,
    };
    if let Some((name, value)) = rejected_header {
        let Some(value) = value.and_then(|value| value.to_str().ok()) else {
            tracing::error!(header = name, "missing rejected Blob request header");
            return error_response(Error::Internal);
        };
        let (status, code, message) = describe(error);
        return xml_error_with_details(
            status,
            code,
            &correlated_error_message(message, request_id, now),
            &[("HeaderName", name), ("HeaderValue", value)],
        );
    }
    let correlation = matches!(
        error,
        Error::PermissionMismatch
            | Error::BlobAlreadyExists
            | Error::ConditionNotMet
            | Error::BlobMissing
            | Error::ContainerExists
            | Error::ContainerMissing
            | Error::InvalidBlockList
            | Error::BlockIdWidthMismatch
            | Error::InvalidRange(_)
            | Error::ConflictingRangeChecksums
            | Error::LeaseIdMissing
            | Error::LeaseIdMissingBlob
            | Error::LeaseMismatchBlob
            | Error::LeaseMismatchLease
            | Error::LeaseMismatchContainerLease
            | Error::LeaseBreakingNoAcquire
            | Error::SnapshotsPresent
            | Error::Page(
                PageError::AppendPositionConditionNotMet
                    | PageError::SequenceNumberConditionNotMet
                    | PageError::MaxBlobSizeConditionNotMet
                    | PageError::BlobIsSealed
            )
    )
    .then_some((request_id, now));
    render_error(error, correlation)
}

fn render_error(error: Error, correlation: Option<(&str, SystemTime)>) -> Response {
    let (status, code, message) = describe(error);
    if status == StatusCode::NOT_MODIFIED {
        let mut response = empty(status);
        response
            .headers_mut()
            .insert("x-ms-error-code", HeaderValue::from_static(code));
        return response;
    }
    let mut response = match correlation {
        Some((request_id, now)) => xml_error(
            status,
            code,
            &correlated_error_message(message, request_id, now),
        ),
        None => xml_error(status, code, message),
    };
    if let Error::InvalidRange(length) = error
        && set(
            response.headers_mut(),
            "content-range",
            &format!("bytes */{length}"),
        )
        .is_err()
    {
        return error_response(Error::Internal);
    }
    response
}
