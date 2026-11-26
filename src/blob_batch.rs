//! Submit Batch (ADR-0019): a `multipart/mixed` body of Delete Blob or Set Blob
//! Tier sub-requests. Each sub-request is parsed, authenticated, and authorized
//! on its own through the normal operation path, so an unauthorized item fails
//! alone; the response is `multipart/mixed` with one part per item.

use crate::{
    blob_auth::{self, Authorization},
    blob_exec::{self, Context},
    domain::{ContainerKey, Error, Result},
    protocol::{self, BatchRequest, Operation},
    respond::{error_response, set},
    server::App,
};
use axum::{
    body::{Body, to_bytes},
    http::{HeaderMap, HeaderName, HeaderValue, Method, Request, StatusCode},
    response::Response,
};
use uuid::Uuid;

const MAX_SUBREQUESTS: usize = 256;
const MAX_RESPONSE_PART_BYTES: usize = 64 * 1024;

/// The boundary of a `multipart/mixed` `Content-Type`.
pub(crate) fn boundary(content_type: &str) -> Result<String> {
    let mut parts = content_type.split(';').map(str::trim);
    if !parts
        .next()
        .is_some_and(|kind| kind.eq_ignore_ascii_case("multipart/mixed"))
    {
        return Err(Error::InvalidHeader);
    }
    let boundary = parts
        .find_map(|part| {
            let (name, value) = part.split_once('=')?;
            name.trim()
                .eq_ignore_ascii_case("boundary")
                .then(|| value.trim().trim_matches('"').to_owned())
        })
        .ok_or(Error::InvalidHeader)?;
    if boundary.is_empty()
        || boundary.len() > 70
        || !boundary.bytes().all(|b| b.is_ascii_graphic() || b == b' ')
    {
        return Err(Error::InvalidHeader);
    }
    Ok(boundary)
}

/// One embedded request: its optional `Content-ID` and the request line and headers.
#[derive(Debug)]
pub(crate) struct Subrequest {
    pub(crate) content_id: Option<String>,
    pub(crate) method: Method,
    pub(crate) target: String,
    pub(crate) headers: HeaderMap,
}

fn lines(text: &str) -> impl Iterator<Item = &str> {
    text.split('\n')
        .map(|line| line.strip_suffix('\r').unwrap_or(line))
}

fn header_pairs<'a>(head: impl Iterator<Item = &'a str>) -> Result<Vec<(HeaderName, HeaderValue)>> {
    head.filter(|line| !line.is_empty())
        .map(|line| {
            let (name, value) = line.split_once(':').ok_or(Error::InvalidInput)?;
            Ok((
                HeaderName::from_bytes(name.trim().to_ascii_lowercase().as_bytes())
                    .map_err(|_| Error::InvalidInput)?,
                HeaderValue::from_str(value.trim()).map_err(|_| Error::InvalidInput)?,
            ))
        })
        .collect()
}

fn subrequest(part: &str) -> Result<Subrequest> {
    let (envelope, request) = part
        .split_once("\r\n\r\n")
        .or_else(|| part.split_once("\n\n"))
        .ok_or(Error::InvalidInput)?;
    let envelope = header_pairs(lines(envelope))?;
    let find = |name: &str| {
        envelope
            .iter()
            .find(|(candidate, _)| candidate == name)
            .and_then(|(_, value)| value.to_str().ok())
    };
    if !find("content-type").is_some_and(|kind| kind.eq_ignore_ascii_case("application/http"))
        || !find("content-transfer-encoding")
            .is_some_and(|kind| kind.eq_ignore_ascii_case("binary"))
    {
        return Err(Error::InvalidInput);
    }
    let content_id = find("content-id").map(str::to_owned);
    let request = request.trim_start_matches(['\r', '\n']);
    let mut request_lines = lines(request);
    let mut line = request_lines.next().ok_or(Error::InvalidInput)?.split(' ');
    let (method, target, version) = (line.next(), line.next(), line.next());
    let (Some(method), Some(target), Some(version), None) = (method, target, version, line.next())
    else {
        return Err(Error::InvalidInput);
    };
    // The .NET SDK sends the target without its leading slash.
    let target = if target.starts_with('/') {
        target.to_owned()
    } else {
        format!("/{target}")
    };
    if !version.starts_with("HTTP/1.") || target.starts_with("//") || target.contains("://") {
        return Err(Error::InvalidInput);
    }
    let mut headers = HeaderMap::new();
    for (name, value) in header_pairs(request_lines.by_ref().take_while(|line| !line.is_empty()))? {
        if headers.insert(name, value).is_some() {
            return Err(Error::InvalidInput);
        }
    }
    if request_lines.any(|line| !line.is_empty()) {
        return Err(Error::InvalidInput);
    }
    Ok(Subrequest {
        content_id,
        method: Method::from_bytes(method.as_bytes()).map_err(|_| Error::InvalidInput)?,
        target,
        headers,
    })
}

/// Splits a batch body into its sub-requests.
pub(crate) fn parse_body(body: &[u8], boundary: &str) -> Result<Vec<Subrequest>> {
    let text = std::str::from_utf8(body).map_err(|_| Error::InvalidInput)?;
    let delimiter = format!("--{boundary}");
    let mut sections = text.split(delimiter.as_str());
    sections.next();
    let mut requests = Vec::new();
    for section in sections {
        if section.starts_with("--") {
            break;
        }
        if requests.len() == MAX_SUBREQUESTS {
            return Err(Error::InvalidInput);
        }
        let part = section
            .strip_prefix("\r\n")
            .or_else(|| section.strip_prefix('\n'))
            .ok_or(Error::InvalidInput)?;
        requests.push(subrequest(part)?);
    }
    if requests.is_empty() {
        return Err(Error::InvalidInput);
    }
    Ok(requests)
}

/// Delete Blob or Set Blob Tier; Azure requires every item to be the same kind.
fn kind(request: &Subrequest) -> Result<&'static str> {
    let comp = request
        .target
        .split_once('?')
        .map_or("", |(_, query)| query)
        .split('&')
        .find_map(|pair| pair.strip_prefix("comp="));
    match (&request.method, comp) {
        (&Method::DELETE, None) => Ok("delete"),
        (&Method::PUT, Some("tier")) => Ok("tier"),
        _ => Err(Error::InvalidInput),
    }
}

fn status_line(status: StatusCode) -> String {
    format!(
        "HTTP/1.1 {} {}",
        status.as_u16(),
        status.canonical_reason().unwrap_or("")
    )
}

/// Runs one sub-request through the normal parse, authorization, and execution path.
async fn run_one(
    app: &App,
    ctx: &Context<'_>,
    scope: Option<&ContainerKey>,
    version: &str,
    request: &Subrequest,
) -> Result<Response> {
    let mut builder = Request::builder()
        .method(request.method.clone())
        .uri(request.target.as_str());
    if !request.headers.contains_key("host")
        && let Some(host) = ctx.host
    {
        builder = builder.header("host", host);
    }
    let (mut parts, ()) = builder
        .body(())
        .map_err(|_| Error::InvalidInput)?
        .into_parts();
    parts.headers.extend(request.headers.clone());
    let parsed = protocol::parse_batched(&parts, &app.config, app.clock.now(), version)?;
    if parsed.target.account() != ctx.account {
        return Err(Error::AuthenticationFailed);
    }
    if let Some(scope) = scope
        && parsed
            .target
            .container()
            .is_none_or(|container| container.name.as_str() != scope.name.as_str())
    {
        return Err(Error::InvalidInput);
    }
    blob_auth::authorize(
        &app.store,
        Authorization {
            credentials: &parsed.credentials,
            target: &parsed.target,
            need: &parsed.need,
            connection: ctx.connection,
        },
    )
    .await?;
    if !matches!(
        parsed.operation,
        Operation::DeleteBlob(..) | Operation::SetBlobTier(..)
    ) {
        return Err(Error::InvalidInput);
    }
    let inner = Context {
        host: ctx.host,
        account: parsed.target.account(),
        credentials: &parsed.credentials,
        connection: ctx.connection,
        request_id: ctx.request_id,
    };
    Box::pin(blob_exec::execute(
        app,
        parsed.operation,
        Body::empty(),
        &inner,
    ))
    .await
}

async fn render_part(
    id: Option<&str>,
    outcome: Result<Response>,
    version: &str,
    boundary: &str,
) -> Result<String> {
    let response = outcome.unwrap_or_else(error_response);
    let (head, body) = response.into_parts();
    let body = to_bytes(body, MAX_RESPONSE_PART_BYTES)
        .await
        .map_err(|_| Error::Internal)?;
    let mut part = format!("--{boundary}\r\nContent-Type: application/http\r\n");
    if let Some(id) = id {
        part.push_str(&format!("Content-ID: {id}\r\n"));
    }
    part.push_str(&format!("\r\n{}\r\n", status_line(head.status)));
    let mut headers = head.headers;
    set(&mut headers, "x-ms-request-id", &Uuid::new_v4().to_string())?;
    set(&mut headers, "x-ms-version", version)?;
    if !body.is_empty() {
        set(&mut headers, "content-length", &body.len().to_string())?;
    }
    for (name, value) in &headers {
        let value = value.to_str().map_err(|_| Error::Internal)?;
        part.push_str(&format!("{}: {value}\r\n", name.as_str()));
    }
    part.push_str("\r\n");
    // Azure writes no extra line for an empty body; the Java SDK reads one as an error body.
    if !body.is_empty() {
        part.push_str(&String::from_utf8_lossy(&body));
        part.push_str("\r\n");
    }
    Ok(part)
}

pub(crate) async fn execute(
    app: &App,
    op: Operation,
    body: Body,
    ctx: &Context<'_>,
) -> Result<Response> {
    let Operation::SubmitBatch(scope, batch) = op else {
        return Err(Error::Internal);
    };
    let BatchRequest { boundary, upload } = batch;
    let (bytes, _) = blob_exec::read_bounded(app, body, &upload).await?;
    let requests = parse_body(&bytes, &boundary)?;
    let first = kind(&requests[0])?;
    for request in &requests {
        if kind(request)? != first {
            return Err(Error::InvalidInput);
        }
    }
    let version = app.config.api_version.as_str();
    let reply = format!("batchresponse_{}", Uuid::new_v4());
    let mut text = String::new();
    for request in &requests {
        let outcome = run_one(app, ctx, scope.as_ref(), version, request).await;
        text.push_str(&render_part(request.content_id.as_deref(), outcome, version, &reply).await?);
    }
    text.push_str(&format!("--{reply}--\r\n"));
    let mut response = Response::new(Body::from(text));
    *response.status_mut() = StatusCode::ACCEPTED;
    set(
        response.headers_mut(),
        "content-type",
        &format!("multipart/mixed; boundary={reply}"),
    )?;
    Ok(response)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn batch(parts: &[&str]) -> String {
        let mut text = String::new();
        for (index, part) in parts.iter().enumerate() {
            text.push_str(&format!(
                "--b1\r\nContent-Type: application/http\r\nContent-Transfer-Encoding: binary\r\nContent-ID: {index}\r\n\r\n{part}\r\n"
            ));
        }
        text.push_str("--b1--\r\n");
        text
    }

    #[test]
    fn the_boundary_is_read_from_the_content_type() {
        assert_eq!(
            boundary("multipart/mixed; boundary=batch_1").as_deref(),
            Ok("batch_1")
        );
        assert_eq!(
            boundary("Multipart/Mixed;boundary=\"a b\"").as_deref(),
            Ok("a b")
        );
        for bad in [
            "text/plain; boundary=x",
            "multipart/mixed",
            "multipart/mixed; boundary=",
        ] {
            assert_eq!(boundary(bad), Err(Error::InvalidHeader), "{bad}");
        }
    }

    #[test]
    fn sub_requests_are_split_with_their_ids_and_headers() {
        let body = batch(&[
            "DELETE /acct/box/a%20b?snapshot=x HTTP/1.1\r\nx-ms-date: today\r\nAuthorization: SharedKey acct:sig\r\nContent-Length: 0\r\n\r\n",
            "DELETE /acct/box/c HTTP/1.1\r\nContent-Length: 0\r\n\r\n",
        ]);
        let requests = parse_body(body.as_bytes(), "b1").unwrap();
        assert_eq!(requests.len(), 2);
        assert_eq!(requests[0].content_id.as_deref(), Some("0"));
        assert_eq!(requests[0].method, Method::DELETE);
        assert_eq!(requests[0].target, "/acct/box/a%20b?snapshot=x");
        assert_eq!(requests[0].headers["authorization"], "SharedKey acct:sig");
        assert_eq!(requests[1].content_id.as_deref(), Some("1"));
        assert_eq!(kind(&requests[0]), Ok("delete"));
    }

    #[test]
    fn malformed_batches_are_rejected() {
        let ok = "DELETE /a/b/c HTTP/1.1\r\n\r\n";
        assert!(parse_body(b"", "b1").is_err());
        assert!(parse_body(batch(&[]).as_bytes(), "b1").is_err());
        assert!(parse_body(batch(&["GET"]).as_bytes(), "b1").is_err());
        assert!(
            parse_body(
                batch(&["DELETE http://h/a/b HTTP/1.1\r\n\r\n"]).as_bytes(),
                "b1"
            )
            .is_err()
        );
        assert!(parse_body(batch(&["DELETE //a/b HTTP/1.1\r\n\r\n"]).as_bytes(), "b1").is_err());
        let slashless =
            parse_body(batch(&["DELETE a/b HTTP/1.1\r\n\r\n"]).as_bytes(), "b1").unwrap();
        assert_eq!(slashless[0].target, "/a/b");
        assert!(
            parse_body(
                batch(&["DELETE /a/b HTTP/1.1\r\nbroken\r\n\r\n"]).as_bytes(),
                "b1"
            )
            .is_err()
        );
        let wrong_type = "--b1\r\nContent-Type: text/plain\r\nContent-Transfer-Encoding: binary\r\n\r\nDELETE /a/b/c HTTP/1.1\r\n\r\n\r\n--b1--\r\n";
        assert!(parse_body(wrong_type.as_bytes(), "b1").is_err());
        let too_many = batch(&vec![ok; MAX_SUBREQUESTS + 1]);
        assert!(parse_body(too_many.as_bytes(), "b1").is_err());
        assert!(parse_body(batch(&vec![ok; MAX_SUBREQUESTS]).as_bytes(), "b1").is_ok());
    }

    #[test]
    fn only_deletes_and_tier_changes_form_a_batch() {
        let make = |method: Method, target: &str| Subrequest {
            content_id: None,
            method,
            target: target.to_owned(),
            headers: HeaderMap::new(),
        };
        assert_eq!(
            kind(&make(Method::DELETE, "/a/b/c?versionid=1")),
            Ok("delete")
        );
        assert_eq!(kind(&make(Method::PUT, "/a/b/c?comp=tier")), Ok("tier"));
        assert!(kind(&make(Method::PUT, "/a/b/c")).is_err());
        assert!(kind(&make(Method::GET, "/a/b/c")).is_err());
    }

    #[tokio::test]
    async fn a_failed_item_renders_its_status_and_error_body() {
        let part = render_part(Some("7"), Err(Error::BlobMissing), "2023-11-03", "resp")
            .await
            .unwrap();
        assert!(part.starts_with("--resp\r\nContent-Type: application/http\r\nContent-ID: 7\r\n\r\nHTTP/1.1 404 Not Found\r\n"));
        assert!(part.contains("x-ms-error-code: BlobNotFound\r\n"));
        assert!(part.contains("<Code>BlobNotFound</Code>"));
        let ok = render_part(
            None,
            Ok(crate::respond::empty(StatusCode::ACCEPTED)),
            "2023-11-03",
            "resp",
        )
        .await
        .unwrap();
        assert!(ok.contains("HTTP/1.1 202 Accepted\r\n"));
        assert!(!ok.contains("Content-ID"));
        // The Java SDK treats any text after the blank line as an error body.
        assert!(ok.ends_with("\r\n\r\n") && !ok.ends_with("\r\n\r\n\r\n"));
    }
}
