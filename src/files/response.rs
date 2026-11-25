//! Response construction: headers and XML bodies.

use super::{
    error::{Error, Result},
    lease::{self, Lease},
    model::{AccessPolicy, NodeInfo, ShareInfo},
    store::{Listing, ShareRef},
    time,
};
use crate::wire::{Xml, xml_error};
use axum::{
    body::Body,
    http::{HeaderMap, HeaderName, HeaderValue, StatusCode},
    response::Response,
};
use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use std::ops::Range;

pub(super) fn empty(status: StatusCode) -> Response {
    let mut response = Response::new(Body::empty());
    *response.status_mut() = status;
    response
}

pub(super) fn set(headers: &mut HeaderMap, name: &'static str, value: &str) -> Result<()> {
    let value = HeaderValue::from_str(value).map_err(|_| {
        tracing::error!(header = name, "could not encode response header");
        Error::Internal
    })?;
    let name = HeaderName::from_bytes(name.as_bytes()).map_err(|_| Error::Internal)?;
    headers.insert(name, value);
    Ok(())
}

pub(super) fn error_response(error: Error) -> Response {
    let (status, code, message) = error.info();
    if error == Error::NotModified {
        return empty(status);
    }
    xml_error(status, code, message)
}

pub(super) fn encode_marker(text: &str) -> String {
    URL_SAFE_NO_PAD.encode(text)
}

pub(super) fn decode_marker(marker: &str) -> Result<String> {
    URL_SAFE_NO_PAD
        .decode(marker)
        .ok()
        .and_then(|bytes| String::from_utf8(bytes).ok())
        .ok_or(Error::InvalidContinuationToken)
}

fn metadata_headers(headers: &mut HeaderMap, metadata: &super::model::Metadata) -> Result<()> {
    for (name, value) in metadata {
        let header = HeaderName::from_bytes(format!("x-ms-meta-{name}").as_bytes())
            .map_err(|_| Error::Internal)?;
        let value = HeaderValue::from_str(value).map_err(|_| Error::Internal)?;
        headers.insert(header, value);
    }
    Ok(())
}

pub(super) fn lease_headers(
    headers: &mut HeaderMap,
    lease: Option<&Lease>,
    now: i64,
) -> Result<()> {
    let summary = lease::summary(lease, now);
    set(headers, "x-ms-lease-status", summary.state.status())?;
    set(headers, "x-ms-lease-state", summary.state.name())?;
    if let Some(duration) = summary.duration {
        set(headers, "x-ms-lease-duration", duration)?;
    }
    Ok(())
}

pub(super) fn etag_headers(headers: &mut HeaderMap, etag: &str, modified: i64) -> Result<()> {
    set(headers, "etag", etag)?;
    set(headers, "last-modified", &time::http_date(modified))
}

pub(super) fn share_headers(headers: &mut HeaderMap, share: &ShareInfo, now: i64) -> Result<()> {
    etag_headers(headers, &share.etag, share.modified)?;
    metadata_headers(headers, &share.metadata)?;
    set(headers, "x-ms-share-quota", &share.quota.to_string())?;
    set(headers, "x-ms-access-tier", &share.access_tier)?;
    set(
        headers,
        "x-ms-access-tier-change-time",
        &time::http_date(share.access_tier_changed),
    )?;
    set(headers, "x-ms-enabled-protocols", "SMB")?;
    lease_headers(headers, share.lease.as_ref(), now)
}

/// The SMB-flavoured headers every file and directory response carries.
pub(super) fn node_headers(headers: &mut HeaderMap, node: &NodeInfo) -> Result<()> {
    etag_headers(headers, &node.etag, node.modified)?;
    set(headers, "x-ms-request-server-encrypted", "true")?;
    set(headers, "x-ms-file-permission-key", &node.permission_key)?;
    set(
        headers,
        "x-ms-file-attributes",
        &node.attributes.to_string(),
    )?;
    set(
        headers,
        "x-ms-file-creation-time",
        &time::iso(node.creation),
    )?;
    set(
        headers,
        "x-ms-file-last-write-time",
        &time::iso(node.last_write),
    )?;
    set(headers, "x-ms-file-change-time", &time::iso(node.change))?;
    set(headers, "x-ms-file-id", &node.file_id.to_string())?;
    if let Some(parent) = node.parent_id {
        set(headers, "x-ms-file-parent-id", &parent.to_string())?;
    }
    Ok(())
}

/// Properties of a file or directory for Get/HEAD responses.
pub(super) fn property_headers(headers: &mut HeaderMap, node: &NodeInfo, now: i64) -> Result<()> {
    node_headers(headers, node)?;
    metadata_headers(headers, &node.metadata)?;
    set(headers, "x-ms-server-encrypted", "true")?;
    if node.directory {
        return Ok(());
    }
    set(headers, "x-ms-type", "File")?;
    lease_headers(headers, node.lease.as_ref(), now)?;
    if let Some(copy) = &node.copy {
        set(headers, "x-ms-copy-id", &copy.id)?;
        set(headers, "x-ms-copy-source", &copy.source)?;
        set(headers, "x-ms-copy-status", "success")?;
        set(
            headers,
            "x-ms-copy-progress",
            &format!("{0}/{0}", copy.length),
        )?;
        set(
            headers,
            "x-ms-copy-completion-time",
            &time::http_date(copy.completed),
        )?;
    }
    Ok(())
}

pub(super) fn http_property_headers(headers: &mut HeaderMap, node: &NodeInfo) -> Result<()> {
    let http = &node.http;
    set(
        headers,
        "content-type",
        http.content_type
            .as_deref()
            .unwrap_or("application/octet-stream"),
    )?;
    for (name, value) in [
        ("content-encoding", &http.content_encoding),
        ("content-language", &http.content_language),
        ("content-disposition", &http.content_disposition),
        ("cache-control", &http.cache_control),
    ] {
        if let Some(value) = value {
            set(headers, name, value)?;
        }
    }
    Ok(())
}

pub(super) fn list_shares(
    endpoint: &str,
    request: &ListSharesView<'_>,
    shares: &[ShareInfo],
    next: Option<(String, i64)>,
    now: i64,
) -> Result<Response> {
    let mut xml = Xml::root("EnumerationResults", &[("ServiceEndpoint", endpoint)]);
    if !request.prefix.is_empty() {
        xml.element("Prefix", request.prefix);
    }
    if let Some(marker) = request.marker {
        xml.element("Marker", marker);
    }
    xml.element("MaxResults", &request.limit.to_string());
    xml.open("Shares");
    for share in shares {
        xml.open("Share");
        xml.element("Name", &share.name);
        if let Some(snapshot) = share.snapshot {
            xml.element("Snapshot", &time::iso(snapshot));
        }
        xml.open("Properties");
        xml.element("Last-Modified", &time::http_date(share.modified));
        xml.element("Etag", &share.etag);
        xml.element("Quota", &share.quota.to_string());
        xml.element("AccessTier", &share.access_tier);
        xml.element(
            "AccessTierChangeTime",
            &time::http_date(share.access_tier_changed),
        );
        let summary = lease::summary(share.lease.as_ref(), now);
        xml.element("LeaseStatus", summary.state.status());
        xml.element("LeaseState", summary.state.name());
        if let Some(duration) = summary.duration {
            xml.element("LeaseDuration", duration);
        }
        xml.element("EnabledProtocols", "SMB");
        xml.close("Properties");
        if request.metadata {
            xml.open("Metadata");
            for (name, value) in &share.metadata {
                xml.element(name, value);
            }
            xml.close("Metadata");
        }
        xml.close("Share");
    }
    xml.close("Shares");
    match next {
        Some((name, snapshot)) => {
            xml.element("NextMarker", &encode_marker(&format!("{name}\0{snapshot}")));
        }
        None => xml.element("NextMarker", ""),
    }
    Ok(xml.finish("EnumerationResults", StatusCode::OK))
}

pub(super) struct ListSharesView<'a> {
    pub(super) prefix: &'a str,
    pub(super) marker: Option<&'a str>,
    pub(super) limit: u32,
    pub(super) metadata: bool,
}

/// What a directory listing request asked to include.
pub(super) struct EntryDetail {
    pub(super) timestamps: bool,
    pub(super) etag: bool,
    pub(super) attributes: bool,
    pub(super) permission_key: bool,
}

pub(super) struct ListEntriesView<'a> {
    pub(super) endpoint: &'a str,
    pub(super) target: &'a ShareRef,
    pub(super) directory: &'a str,
    pub(super) prefix: Option<&'a str>,
    pub(super) marker: Option<&'a str>,
    pub(super) limit: Option<u32>,
    pub(super) detail: EntryDetail,
}

pub(super) fn list_entries(view: &ListEntriesView<'_>, listing: &Listing) -> Response {
    let mut attributes = vec![
        ("ServiceEndpoint", view.endpoint.to_owned()),
        ("ShareName", view.target.share.as_str().to_owned()),
    ];
    let snapshot = view.target.snapshot.map(time::iso);
    if let Some(snapshot) = &snapshot {
        attributes.push(("ShareSnapshot", snapshot.clone()));
    }
    attributes.push(("DirectoryPath", view.directory.to_owned()));
    let attributes: Vec<(&str, &str)> = attributes
        .iter()
        .map(|(name, value)| (*name, value.as_str()))
        .collect();
    let mut xml = Xml::root("EnumerationResults", &attributes);
    if let Some(marker) = view.marker {
        xml.element("Marker", marker);
    }
    if let Some(prefix) = view.prefix {
        xml.element("Prefix", prefix);
    }
    if let Some(limit) = view.limit {
        xml.element("MaxResults", &limit.to_string());
    }
    xml.element("DirectoryId", &listing.directory_id.to_string());
    xml.open("Entries");
    let detail = &view.detail;
    for node in &listing.entries {
        let tag = if node.directory { "Directory" } else { "File" };
        xml.open(tag);
        xml.element("FileId", &node.file_id.to_string());
        xml.element("Name", &node.name);
        let properties = true;
        if properties {
            xml.open("Properties");
            if !node.directory {
                xml.element("Content-Length", &node.length.to_string());
            }
            if detail.timestamps {
                xml.element("CreationTime", &time::iso(node.creation));
                xml.element("LastAccessTime", &time::iso(node.last_write));
                xml.element("LastWriteTime", &time::iso(node.last_write));
                xml.element("ChangeTime", &time::iso(node.change));
                xml.element("Last-Modified", &time::http_date(node.modified));
            }
            if detail.etag {
                xml.element("Etag", &node.etag);
            }
            xml.close("Properties");
        }
        if detail.attributes {
            xml.element("Attributes", &node.attributes.to_string());
        }
        if detail.permission_key {
            xml.element("PermissionKey", &node.permission_key);
        }
        xml.close(tag);
    }
    xml.close("Entries");
    xml.element(
        "NextMarker",
        listing
            .next
            .as_deref()
            .map_or_else(String::new, encode_marker)
            .as_str(),
    );
    xml.finish("EnumerationResults", StatusCode::OK)
}

pub(super) fn access_policies(policies: &[AccessPolicy]) -> Response {
    let mut xml = Xml::root("SignedIdentifiers", &[]);
    for policy in policies {
        xml.open("SignedIdentifier");
        xml.element("Id", &policy.id);
        xml.open("AccessPolicy");
        for (tag, value) in [
            ("Start", &policy.start),
            ("Expiry", &policy.expiry),
            ("Permission", &policy.permission),
        ] {
            if let Some(value) = value {
                xml.element(tag, value);
            }
        }
        xml.close("AccessPolicy");
        xml.close("SignedIdentifier");
    }
    xml.finish("SignedIdentifiers", StatusCode::OK)
}

pub(super) fn share_stats(bytes: u64) -> Response {
    let mut xml = Xml::root("ShareStats", &[]);
    xml.element("ShareUsageBytes", &bytes.to_string());
    xml.finish("ShareStats", StatusCode::OK)
}

pub(super) fn ranges(ranges: &[Range<u64>], cleared: &[Range<u64>]) -> Response {
    let mut xml = Xml::root("Ranges", &[]);
    for (tag, list) in [("Range", ranges), ("ClearRange", cleared)] {
        for range in list {
            xml.open(tag);
            xml.element("Start", &range.start.to_string());
            xml.element("End", &(range.end - 1).to_string());
            xml.close(tag);
        }
    }
    xml.finish("Ranges", StatusCode::OK)
}

/// Handles are recorded metadata only; there is no SMB session, so none are ever open.
pub(super) fn no_handles() -> Response {
    let mut xml = Xml::root("EnumerationResults", &[]);
    xml.open("Entries");
    xml.close("Entries");
    xml.element("NextMarker", "");
    xml.finish("EnumerationResults", StatusCode::OK)
}

pub(super) fn json(status: StatusCode, body: &serde_json::Value) -> Response {
    let mut response = Response::new(Body::from(body.to_string()));
    *response.status_mut() = status;
    response
        .headers_mut()
        .insert("content-type", HeaderValue::from_static("application/json"));
    response
}
