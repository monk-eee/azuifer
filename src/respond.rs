//! Maps typed Blob outcomes to Azure responses: headers, XML bodies, and errors.

use crate::{
    blob_page::BlobKind,
    blob_sas::Overrides,
    domain::{
        BlobInfo, BlobListing, ContainerInfo, Entity, Error, Include, ListEntry, ListRequest,
        Metadata, Page, PageRequest, PublicAccess, Result, SignedIdentifier,
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

mod error;

pub(crate) use error::{
    OmitApiVersion, correlated_error_response, error_response, request_error_response,
};

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
                    include.contains(&Include::LegalHold),
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
    force_legal_hold: bool,
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
    crate::blob_lifecycle::lifecycle_elements(xml, &info.lifecycle, force_legal_hold)?;
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
