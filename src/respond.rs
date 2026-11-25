//! Maps typed Blob outcomes to Azure responses: headers, XML bodies, and errors.

use crate::{
    blob_sas::Overrides,
    domain::{
        BlobInfo, BlobListing, ContainerInfo, Entity, Error, Include, ListEntry, Metadata, Page,
        PublicAccess, Result, SignedIdentifier,
    },
    lease::LeaseView,
    store::{Download, Payload},
    wire::Xml,
};
use axum::{
    body::Body,
    http::{HeaderMap, HeaderName, HeaderValue, StatusCode},
    response::Response,
};
use futures_util::TryStreamExt as _;
use std::time::{Duration, UNIX_EPOCH};
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
    set(headers, "last-modified", &http_date(entity.modified)?)
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
    set(headers, "x-ms-blob-type", "BlockBlob")?;
    set(headers, "x-ms-server-encrypted", "true")?;
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
        None => {
            set(headers, "x-ms-access-tier", "Hot")?;
            set(headers, "x-ms-access-tier-inferred", "true")?;
        }
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
        None => Body::empty(),
    };
    Ok(response)
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
    lease_headers(headers, info.lease)?;
    if !metadata_only {
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

fn lease_elements(xml: &mut Xml, view: LeaseView) {
    xml.element("LeaseStatus", view.status());
    xml.element("LeaseState", view.state.name());
    if let Some(duration) = view.duration() {
        xml.element("LeaseDuration", duration);
    }
}

pub(crate) fn list_containers(
    endpoint: &str,
    limit: u32,
    prefix: &str,
    page: Page<ContainerInfo>,
    metadata: bool,
) -> Result<Response> {
    let mut xml = Xml::root("EnumerationResults", &[("ServiceEndpoint", endpoint)]);
    if !prefix.is_empty() {
        xml.element("Prefix", prefix);
    }
    xml.element("MaxResults", &limit.to_string());
    xml.open("Containers");
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

pub(crate) fn list_blobs(
    endpoint: &str,
    container: &str,
    (prefix, delimiter, limit): (&str, Option<&str>, u32),
    listing: BlobListing,
    include: &[Include],
) -> Result<Response> {
    let mut xml = Xml::root(
        "EnumerationResults",
        &[("ServiceEndpoint", endpoint), ("ContainerName", container)],
    );
    if !prefix.is_empty() {
        xml.element("Prefix", prefix);
    }
    xml.element("MaxResults", &limit.to_string());
    if let Some(delimiter) = delimiter {
        xml.element("Delimiter", delimiter);
    }
    xml.open("Blobs");
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
                blob_properties(&mut xml, &info, include.contains(&Include::Copy))?;
                if include.contains(&Include::Metadata) && !info.uncommitted {
                    xml.metadata(info.metadata);
                }
                xml.close("Blob");
            }
        }
    }
    xml.close("Blobs");
    xml.element("NextMarker", &listing.next);
    Ok(xml.finish("EnumerationResults", StatusCode::OK))
}

fn blob_properties(xml: &mut Xml, info: &BlobInfo, copy: bool) -> Result<()> {
    xml.open("Properties");
    if info.uncommitted {
        xml.element("Content-Length", "0");
        xml.element("BlobType", "BlockBlob");
        lease_elements(xml, info.lease);
        xml.close("Properties");
        return Ok(());
    }
    xml.element("Creation-Time", &http_date(info.created)?);
    xml.entity(info.entity)?;
    xml.element("Content-Length", &info.length.0.to_string());
    xml.element("Content-Type", &info.headers.content_type);
    xml.element("Content-Encoding", &info.headers.encoding);
    xml.element("Content-Language", &info.headers.language);
    xml.element("Content-MD5", info.md5.as_deref().unwrap_or_default());
    xml.element("Cache-Control", &info.headers.cache_control);
    xml.element("Content-Disposition", &info.headers.disposition);
    xml.element("BlobType", "BlockBlob");
    match info.tier {
        Some((tier, changed)) => {
            xml.element("AccessTier", tier.name());
            xml.element("AccessTierChangeTime", &http_date(changed)?);
        }
        None => {
            xml.element("AccessTier", "Hot");
            xml.element("AccessTierInferred", "true");
        }
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
    xml.close("Properties");
    Ok(())
}

impl Xml {
    pub(crate) fn entity(&mut self, entity: Entity) -> Result<()> {
        self.element("Last-Modified", &http_date(entity.modified)?);
        self.element("Etag", entity.etag().as_str());
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
fn describe(error: Error) -> Option<(StatusCode, &'static str, &'static str)> {
    use StatusCode as S;
    Some(match error {
        Error::AuthenticationFailed => (
            S::FORBIDDEN,
            "AuthenticationFailed",
            "Server failed to authenticate the request. Make sure the value of the Authorization header is formed correctly including the signature.",
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
            "The container already exists.",
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
        Error::ResourceNotFound => (
            S::NOT_FOUND,
            "ResourceNotFound",
            "The specified resource does not exist.",
        ),
        Error::ConditionNotMet => (
            S::PRECONDITION_FAILED,
            "ConditionNotMet",
            "The condition specified using HTTP conditional header(s) is not met.",
        ),
        Error::SourceConditionNotMet => (
            S::PRECONDITION_FAILED,
            "SourceConditionNotMet",
            "The source condition specified using HTTP conditional header(s) is not met.",
        ),
        Error::NotModified | Error::InvalidRange(_) => return None,
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
            "There is currently a lease on the resource and no lease ID was specified in the request.",
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
            "The lease ID specified did not match the lease ID for the resource.",
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
        Error::CorsPreflight => (
            S::FORBIDDEN,
            "CorsPreflightFailure",
            "CORS is not enabled or no matching rule was found for this request.",
        ),
    })
}

pub(crate) fn error_response(error: Error) -> Response {
    let Some((status, code, message)) = describe(error) else {
        return match error {
            Error::InvalidRange(length) => {
                let mut response = crate::wire::xml_error(
                    StatusCode::RANGE_NOT_SATISFIABLE,
                    "InvalidRange",
                    "The range is outside the blob.",
                );
                if set(
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
            _ => empty(StatusCode::NOT_MODIFIED),
        };
    };
    crate::wire::xml_error(status, code, message)
}
