//! DFS response bodies and headers.

use super::{error::JSON, request::View};
use crate::{
    blob_expiry,
    domain::{ContainerInfo, Entity, Metadata, Page, PathEntry, Result},
    posix::Attributes,
    respond::{http_date, lease_headers},
    stamp::Ticks,
    store::{PathRead, PathView},
    wire::{self, entity_response, json_response, modified, set},
};
use axum::{
    http::{HeaderMap, HeaderValue, StatusCode},
    response::Response,
};
use base64::{Engine as _, engine::general_purpose::STANDARD};

/// `x-ms-properties`: `name=base64(value)` pairs in name order.
pub(super) fn properties_text(metadata: &Metadata) -> String {
    metadata
        .iter()
        .map(|(name, value)| format!("{name}={}", STANDARD.encode(value)))
        .collect::<Vec<_>>()
        .join(",")
}

fn properties_header(headers: &mut HeaderMap, metadata: &Metadata) -> Result<()> {
    if metadata.is_empty() {
        return Ok(());
    }
    set(headers, "x-ms-properties", &properties_text(metadata))
}

fn attribute_headers(
    headers: &mut HeaderMap,
    attributes: &Attributes,
    with_acl: bool,
) -> Result<()> {
    set(headers, "x-ms-owner", &attributes.owner)?;
    set(headers, "x-ms-group", &attributes.group)?;
    set(headers, "x-ms-permissions", &attributes.mode().render())?;
    if with_acl {
        set(headers, "x-ms-acl", &attributes.acl_text())?;
    }
    Ok(())
}

pub(super) fn filesystem(
    status: StatusCode,
    entity: Entity,
    metadata: Option<&Metadata>,
) -> Result<Response> {
    let mut response = entity_response(status, entity)?;
    let headers = response.headers_mut();
    headers.insert("x-ms-namespace-enabled", HeaderValue::from_static("true"));
    if let Some(metadata) = metadata {
        properties_header(headers, metadata)?;
    }
    Ok(response)
}

pub(super) fn filesystem_properties(info: ContainerInfo) -> Result<Response> {
    filesystem(StatusCode::OK, info.entity, Some(&info.metadata))
}

pub(super) fn list_filesystems(page: Page<Entity>) -> Result<Response> {
    let filesystems = page
        .items
        .into_iter()
        .map(|(name, entity)| {
            Ok(serde_json::json!({
                "name": name,
                "eTag": entity.etag().as_str(),
                "lastModified": modified(entity)?,
            }))
        })
        .collect::<Result<Vec<_>>>()?;
    list_response(
        serde_json::json!({ "filesystems": filesystems }),
        &page.next,
    )
}

pub(super) fn list_paths(entity: Entity, page: Page<(PathEntry, Attributes)>) -> Result<Response> {
    let paths = page
        .items
        .into_iter()
        .map(|(name, (entry, attributes))| {
            let (entity, directory, length, created, expires) = match entry {
                PathEntry::File {
                    entity,
                    length,
                    created,
                    expires,
                } => (entity, false, length.0, created, expires),
                PathEntry::Directory { entity, created } => (entity, true, 0, created, None),
            };
            let creation_time = Ticks::from_seconds(created).filetime()?.to_string();
            // Azure sends every number and boolean as a string, and omits isDirectory for files.
            let mut path = serde_json::json!({
                "name": name,
                "etag": entity.etag().as_str(),
                "lastModified": modified(entity)?,
                "contentLength": length.to_string(),
                "owner": attributes.owner,
                "group": attributes.group,
                "permissions": attributes.mode().render(),
                "creationTime": creation_time,
            });
            if let Some(expires) = expires {
                let expiry_time = Ticks::from_millis(expires).filetime()?.to_string();
                path["expiryTime"] = serde_json::Value::from(expiry_time);
            }
            if directory {
                path["isDirectory"] = serde_json::Value::from("true");
            }
            Ok(path)
        })
        .collect::<Result<Vec<_>>>()?;
    let mut response = list_response(serde_json::json!({ "paths": paths }), &page.next)?;
    wire::entity_headers(response.headers_mut(), entity)?;
    Ok(response)
}

pub(super) fn list_response(body: serde_json::Value, next: &str) -> Result<Response> {
    let mut response = json_response(StatusCode::OK, body, JSON);
    if !next.is_empty() {
        set(response.headers_mut(), "x-ms-continuation", next)?;
    }
    Ok(response)
}

/// The response of Read Path (`body`) or Get Path Properties for a file or directory.
pub(super) fn path_view(view: PathView, body: bool, kind: View) -> Result<Response> {
    let with_acl = kind == View::AccessControl;
    let PathView {
        read,
        attributes,
        directory_properties,
    } = view;
    match read {
        PathRead::Directory(entity, _) => {
            let mut response = wire::directory_response(StatusCode::OK, entity)?;
            let headers = response.headers_mut();
            headers.insert("x-ms-resource-type", HeaderValue::from_static("directory"));
            // Clients given a path-style (IP) endpoint cannot move to a `blob` host, so
            // AzCopy asks this listener for the Blob view and tests for a folder by metadata.
            headers.insert("x-ms-meta-hdi_isfolder", HeaderValue::from_static("true"));
            set(headers, "x-ms-creation-time", &http_date(entity.modified)?)?;
            properties_header(headers, &directory_properties)?;
            attribute_headers(headers, &attributes, with_acl)?;
            Ok(response)
        }
        PathRead::File(download) => {
            let (lease, content) = (download.info.lease, download.info.headers.clone());
            let (created, expires) = (download.info.created, download.info.lifecycle.expires);
            let range_checksum = download.range_checksum.clone();
            let (mut response, metadata) = wire::download_response(*download)?;
            let headers = response.headers_mut();
            headers.insert("x-ms-resource-type", HeaderValue::from_static("file"));
            if let Some((name, value)) = range_checksum {
                set(headers, name, &value)?;
            }
            for (name, value) in [
                ("content-encoding", &content.encoding),
                ("content-language", &content.language),
                ("content-disposition", &content.disposition),
                ("cache-control", &content.cache_control),
            ] {
                if !value.is_empty() {
                    set(headers, name, value)?;
                }
            }
            properties_header(headers, &metadata)?;
            attribute_headers(headers, &attributes, with_acl)?;
            if !body {
                lease_headers(headers, lease)?;
                set(headers, "x-ms-creation-time", &http_date(created)?)?;
                if let Some(expires) = expires {
                    set(
                        headers,
                        "x-ms-expiry-time",
                        &blob_expiry::http_time(expires)?,
                    )?;
                }
            }
            Ok(response)
        }
    }
}
