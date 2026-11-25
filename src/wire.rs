use crate::{
    domain::{Entity, Error, Metadata, Result},
    store::{Download, Payload},
};
use axum::{
    body::Body,
    http::{HeaderMap, HeaderValue, StatusCode},
    response::Response,
};
use futures_util::{StreamExt as _, TryStreamExt as _};
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use tokio::{io::AsyncReadExt as _, sync::OwnedSemaphorePermit};
use tokio_util::io::ReaderStream;

pub(crate) fn empty(status: StatusCode) -> Response {
    let mut response = Response::new(Body::empty());
    *response.status_mut() = status;
    response
}

pub(crate) fn set(headers: &mut HeaderMap, name: &'static str, value: &str) -> Result<()> {
    let value = HeaderValue::from_str(value).map_err(|_| {
        tracing::error!(header = name, "could not encode response header");
        Error::Internal
    })?;
    headers.insert(name, value);
    Ok(())
}

pub(crate) fn stamp_response(
    response: &mut Response,
    version: &HeaderValue,
    request_id: &str,
    head: bool,
) -> Result<()> {
    let headers = response.headers_mut();
    headers.insert("x-ms-version", version.clone());
    set(headers, "x-ms-request-id", request_id)?;
    set(headers, "date", &httpdate::fmt_http_date(SystemTime::now()))?;
    if head {
        *response.body_mut() = Body::empty();
    }
    Ok(())
}

pub(crate) fn modified(entity: Entity) -> Result<String> {
    if entity.modified >= 253_402_300_800 {
        tracing::error!("metadata timestamp is outside the HTTP date range");
        return Err(Error::Internal);
    }
    Ok(httpdate::fmt_http_date(
        UNIX_EPOCH + Duration::from_secs(entity.modified),
    ))
}

pub(crate) fn entity_headers(headers: &mut HeaderMap, entity: Entity) -> Result<()> {
    set(headers, "etag", entity.etag().as_str())?;
    set(headers, "last-modified", &modified(entity)?)
}

pub(crate) fn entity_response(status: StatusCode, entity: Entity) -> Result<Response> {
    let mut response = empty(status);
    entity_headers(response.headers_mut(), entity)?;
    Ok(response)
}

pub(crate) fn directory_response(status: StatusCode, entity: Entity) -> Result<Response> {
    let mut response = entity_response(status, entity)?;
    let headers = response.headers_mut();
    headers.insert("x-ms-resource-type", HeaderValue::from_static("directory"));
    headers.insert("content-length", HeaderValue::from_static("0"));
    Ok(response)
}

pub(crate) fn download_response(download: Download) -> Result<(Response, Metadata)> {
    let Download {
        info,
        range,
        payload,
        ..
    } = download;
    let status = if range.is_some() {
        StatusCode::PARTIAL_CONTENT
    } else {
        StatusCode::OK
    };
    let mut response = entity_response(status, info.entity)?;
    let headers = response.headers_mut();
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
    set(headers, "content-length", &size.to_string())?;
    set(headers, "content-type", &info.headers.content_type)?;
    headers.insert("accept-ranges", HeaderValue::from_static("bytes"));
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
    Ok((response, info.metadata))
}

pub(crate) fn retain_download_permit(response: &mut Response, permit: OwnedSemaphorePermit) {
    let body = std::mem::replace(response.body_mut(), Body::empty());
    *response.body_mut() = Body::from_stream(body.into_data_stream().map(move |item| {
        let _permit = &permit;
        item
    }));
}

pub(crate) fn unsatisfied_range(headers: &mut HeaderMap, length: u64) -> Result<()> {
    set(headers, "content-range", &format!("bytes */{length}"))
}

/// Minimal XML writer shared by every XML-speaking service.
pub(crate) struct Xml(String);

impl Xml {
    pub(crate) fn root(name: &str, attributes: &[(&str, &str)]) -> Self {
        let mut xml = Self("<?xml version=\"1.0\" encoding=\"utf-8\"?>".to_owned());
        xml.0.push('<');
        xml.0.push_str(name);
        for (key, value) in attributes {
            xml.0.push(' ');
            xml.0.push_str(key);
            xml.0.push_str("=\"");
            xml.text(value);
            xml.0.push('"');
        }
        xml.0.push('>');
        xml
    }

    pub(crate) fn open(&mut self, tag: &str) {
        self.0.push('<');
        self.0.push_str(tag);
        self.0.push('>');
    }

    pub(crate) fn close(&mut self, tag: &str) {
        self.0.push_str("</");
        self.0.push_str(tag);
        self.0.push('>');
    }

    pub(crate) fn text(&mut self, value: &str) {
        for ch in value.chars() {
            match ch {
                '&' => self.0.push_str("&amp;"),
                '<' => self.0.push_str("&lt;"),
                '>' => self.0.push_str("&gt;"),
                '"' => self.0.push_str("&quot;"),
                '\'' => self.0.push_str("&apos;"),
                _ => self.0.push(ch),
            }
        }
    }

    pub(crate) fn element(&mut self, tag: &str, value: &str) {
        self.open(tag);
        self.text(value);
        self.close(tag);
    }

    pub(crate) fn finish(mut self, root: &str, status: StatusCode) -> Response {
        self.close(root);
        let mut response = Response::new(Body::from(self.0));
        *response.status_mut() = status;
        response.headers_mut().insert(
            "content-type",
            HeaderValue::from_static("application/xml; charset=utf-8"),
        );
        response
    }
}

/// Azure-shaped XML error with the `x-ms-error-code` header.
pub(crate) fn xml_error(status: StatusCode, code: &'static str, message: &str) -> Response {
    let mut xml = Xml::root("Error", &[]);
    xml.element("Code", code);
    xml.element("Message", message);
    let mut response = xml.finish("Error", status);
    response
        .headers_mut()
        .insert("x-ms-error-code", HeaderValue::from_static(code));
    response
}

fn json_error_value(code: &str, message: &str) -> serde_json::Value {
    serde_json::json!({
        "odata.error": { "code": code, "message": { "lang": "en-US", "value": message } }
    })
}

/// The JSON error document shared by top-level and batch-part Table errors.
pub(crate) fn json_error_body(code: &str, message: &str) -> String {
    json_error_value(code, message).to_string()
}

pub(crate) fn json_response(
    status: StatusCode,
    body: serde_json::Value,
    content_type: &'static str,
) -> Response {
    let mut response = Response::new(Body::from(body.to_string()));
    *response.status_mut() = status;
    response
        .headers_mut()
        .insert("content-type", HeaderValue::from_static(content_type));
    response
}
