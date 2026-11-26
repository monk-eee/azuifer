//! Static website endpoint (ADR-0025): `{account}.web.{domain}` on the Blob listener serves the
//! `$web` container anonymously, using the index and 404 documents of the account's
//! static website service property.

use crate::{
    address,
    conditions::Guard,
    domain::{
        AccountName, BlobKey, BlobPath, BlobRead, ByteRange, ContainerKey, ContainerName, Error,
    },
    protocol,
    respond::{self, set},
    server::App,
    store::PathRead,
};
use axum::{
    body::Body,
    http::{Method, StatusCode, request::Parts},
    response::Response,
};

const WEB_CONTAINER: &str = "$web";

/// The account named by a `{account}.web.{domain}` host, if the request used one.
pub(crate) fn account_of(parts: &Parts) -> Option<AccountName> {
    address::host_account("web", protocol::host(parts))
}

pub(crate) async fn serve(
    app: &App,
    parts: &Parts,
    account: AccountName,
    request_id: &str,
) -> Result<Response, Error> {
    if parts.method != Method::GET && parts.method != Method::HEAD {
        return Ok(page(
            StatusCode::METHOD_NOT_ALLOWED,
            "Method Not Allowed",
            "UnsupportedHttpVerb",
            request_id,
        ));
    }
    if !app.config.accounts.contains_key(&account) {
        return Ok(not_found(request_id));
    }
    let site = app
        .store
        .service_properties(account.clone())
        .await?
        .static_website
        .filter(|site| site.enabled);
    let Some(site) = site else {
        return Ok(not_found(request_id));
    };
    let container = ContainerKey {
        account,
        name: ContainerName::parse(WEB_CONTAINER)?,
    };
    let path = decode(parts.uri.path());
    let wants_index = path.is_empty() || path.ends_with('/');
    let Some(index) = site
        .index_document
        .as_deref()
        .filter(|index| !index.is_empty())
    else {
        return Ok(not_found(request_id));
    };
    let name = if wants_index {
        format!("{path}{index}")
    } else {
        path.clone()
    };
    match read(app, parts, &container, &name, true).await {
        Ok(response) => return Ok(response),
        Err(Error::BlobMissing | Error::ContainerMissing) => (),
        Err(other) => return Err(other),
    }
    if !wants_index
        && read(app, parts, &container, &format!("{path}/{index}"), false)
            .await
            .is_ok()
    {
        let mut response = page(StatusCode::FOUND, "Found", "", request_id);
        let query = parts
            .uri
            .query()
            .map_or_else(String::new, |query| format!("?{query}"));
        set(
            response.headers_mut(),
            "location",
            &format!("{}/{query}", parts.uri.path()),
        )?;
        return Ok(response);
    }
    if let Some(document) = site.error_document404_path.as_deref()
        && let Ok(mut response) = read(app, parts, &container, document, true).await
    {
        *response.status_mut() = StatusCode::NOT_FOUND;
        return Ok(response);
    }
    Ok(not_found(request_id))
}

/// Reads one blob of the `$web` container; `body` is false for the redirect probe.
async fn read(
    app: &App,
    parts: &Parts,
    container: &ContainerKey,
    name: &str,
    body: bool,
) -> Result<Response, Error> {
    let key = BlobKey {
        container: container.clone(),
        path: BlobPath::parse(name.to_owned())?,
    };
    let range = parts
        .headers
        .get("range")
        .and_then(|value| value.to_str().ok())
        .map(ByteRange::parse)
        .transpose()?;
    let options = BlobRead {
        guard: Guard::parse(&parts.headers)?,
        range: if body { range } else { None },
        with_body: body && parts.method == Method::GET,
        range_checksum: None,
    };
    match app.store.read_path(key, options).await? {
        PathRead::File(download) => respond::download_response(*download, None),
        PathRead::Directory(..) => Err(Error::BlobMissing),
    }
}

/// The request path without its leading slash, percent-decoded.
fn decode(path: &str) -> String {
    let trimmed = path.strip_prefix('/').unwrap_or(path);
    let bytes = trimmed.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut index = 0;
    while index < bytes.len() {
        let hex = |byte: u8| char::from(byte).to_digit(16);
        if bytes[index] == b'%'
            && let (Some(high), Some(low)) = (
                bytes.get(index + 1).copied().and_then(hex),
                bytes.get(index + 2).copied().and_then(hex),
            )
        {
            out.push(u8::try_from(high * 16 + low).unwrap_or(b'?'));
            index += 3;
        } else {
            out.push(bytes[index]);
            index += 1;
        }
    }
    String::from_utf8_lossy(&out).into_owned()
}

fn not_found(request_id: &str) -> Response {
    page(
        StatusCode::NOT_FOUND,
        "The requested content does not exist.",
        "WebContentNotFound",
        request_id,
    )
}

fn page(status: StatusCode, title: &str, code: &str, request_id: &str) -> Response {
    let detail = if code.is_empty() {
        String::new()
    } else {
        format!("<ul><li>Code: {code}</li><li>RequestId: {request_id}</li></ul>")
    };
    let mut response = Response::new(Body::from(format!(
        "<html><head><title>{title}</title></head><body><h1>{title}</h1>{detail}</body></html>"
    )));
    *response.status_mut() = status;
    let headers = response.headers_mut();
    headers.insert(
        "content-type",
        axum::http::HeaderValue::from_static("text/html"),
    );
    if !code.is_empty() {
        let _ = set(headers, "x-ms-error-code", code);
    }
    response
}
