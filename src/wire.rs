use crate::{
    domain::{Entity, Error, Metadata, Result},
    store::{Download, Payload},
};
use axum::{
    body::{Body, BodyDataStream, Bytes, HttpBody as _},
    extract::Request,
    http::{HeaderMap, HeaderValue, StatusCode, Version, header},
    middleware::Next,
    response::Response,
};
use futures_util::{Stream, StreamExt as _, TryStreamExt as _};
use std::{
    future::Future,
    pin::Pin,
    sync::{Arc, Mutex},
    task::{Context, Poll},
    time::{Duration, SystemTime, UNIX_EPOCH},
};
use tokio::{io::AsyncReadExt as _, sync::OwnedSemaphorePermit};
use tokio_util::io::ReaderStream;

/// Maximum unread request-body bytes drained on an early response to avoid TCP RST while
/// bounding work against oversized or hostile uploads.
const EARLY_ERROR_DRAIN_LIMIT: usize = 1024 * 1024;
/// Total wall-clock budget for draining an unread request body before closing the socket.
const EARLY_ERROR_DRAIN_TIMEOUT: Duration = Duration::from_millis(250);

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

/// A directory as the Blob API shows it: the user-defined properties as metadata,
/// plus the `hdi_isfolder` marker Data Lake directories carry.
pub(crate) fn blob_directory_response(
    status: StatusCode,
    entity: Entity,
    mut metadata: Metadata,
) -> Result<Response> {
    let mut response = directory_response(status, entity)?;
    metadata.insert("hdi_isfolder".to_owned(), "true".to_owned());
    crate::respond::metadata_headers(response.headers_mut(), metadata)?;
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
    xml_error_with_details(status, code, message, &[])
}

pub(crate) fn correlated_error_message(message: &str, request_id: &str, now: SystemTime) -> String {
    format!(
        "{message}\nRequestId:{request_id}\nTime:{}",
        crate::sas::format_time(now)
    )
}

pub(crate) fn xml_error_with_details(
    status: StatusCode,
    code: &'static str,
    message: &str,
    details: &[(&str, &str)],
) -> Response {
    let mut xml = Xml::root("Error", &[]);
    xml.element("Code", code);
    xml.element("Message", message);
    for (name, value) in details {
        xml.element(name, value);
    }
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

struct UnreadBody {
    stream: BodyDataStream,
    polled: bool,
    read: usize,
}

/// Forwards chunks without locking; if dropped before EOF, hands the remaining stream back so
/// the HTTP edge middleware can perform a bounded drain before Hyper closes the socket.
struct WatchStream {
    stream: Option<BodyDataStream>,
    polled: bool,
    read: usize,
    returned: Arc<Mutex<Option<UnreadBody>>>,
}

impl Stream for WatchStream {
    type Item = std::result::Result<Bytes, axum::Error>;

    fn poll_next(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        let this = self.get_mut();
        this.polled = true;
        let Some(stream) = this.stream.as_mut() else {
            return Poll::Ready(None);
        };
        match Pin::new(stream).poll_next(cx) {
            Poll::Ready(Some(Ok(chunk))) => {
                this.read = this.read.saturating_add(chunk.len());
                Poll::Ready(Some(Ok(chunk)))
            }
            Poll::Ready(Some(Err(error))) => {
                this.stream = None;
                Poll::Ready(Some(Err(error)))
            }
            Poll::Ready(None) => {
                this.stream = None;
                Poll::Ready(None)
            }
            Poll::Pending => Poll::Pending,
        }
    }
}

impl Drop for WatchStream {
    fn drop(&mut self) {
        if let Some(stream) = self.stream.take()
            && let Ok(mut slot) = self.returned.lock()
        {
            *slot = Some(UnreadBody {
                stream,
                polled: self.polled,
                read: self.read,
            });
        }
    }
}

/// Drains bounded unread request bodies when a handler returns early (RFC 9112 §9.6) so
/// HTTP/1.1 clients receive the error response instead of a TCP reset and can reuse healthy
/// keep-alive sockets; falls back to `Connection: close` if the body exceeds the cap or stalls.
pub(crate) async fn drain_unread_body(request: Request, next: Next) -> Response {
    drain_unread_body_with(
        EARLY_ERROR_DRAIN_LIMIT,
        EARLY_ERROR_DRAIN_TIMEOUT,
        request,
        |request| next.run(request),
    )
    .await
}

async fn drain_unread_body_with<F, Fut>(
    limit: usize,
    timeout: Duration,
    request: Request,
    run: F,
) -> Response
where
    F: FnOnce(Request) -> Fut,
    Fut: Future<Output = Response>,
{
    if request.body().is_end_stream() {
        return run(request).await;
    }

    let version = request.version();
    let declared = request
        .headers()
        .get(header::CONTENT_LENGTH)
        .and_then(|value| value.to_str().ok())
        .and_then(|value| value.trim().parse::<u64>().ok());
    let expect_100_continue = request
        .headers()
        .get_all(header::EXPECT)
        .iter()
        .any(|value| {
            value.to_str().is_ok_and(|text| {
                text.split(',')
                    .any(|token| token.trim().eq_ignore_ascii_case("100-continue"))
            })
        });

    // Skip wrapping bodies declared above the drain cap so large uploads keep Hyper's native
    // Body (and exact size_hint) with zero hot-path overhead.
    if declared.is_some_and(|length| length > limit as u64) {
        let mut response = run(request).await;
        if response.status().is_client_error() || response.status().is_server_error() {
            mark_connection_close(version, &mut response);
        }
        return response;
    }

    let returned = Arc::new(Mutex::new(None));
    let (parts, body) = request.into_parts();
    let wrapped = Body::from_stream(WatchStream {
        stream: Some(body.into_data_stream()),
        polled: false,
        read: 0,
        returned: Arc::clone(&returned),
    });
    let mut response = run(Request::from_parts(parts, wrapped)).await;

    let unread = returned.lock().ok().and_then(|mut slot| slot.take());
    let Some(unread) = unread else {
        return response;
    };
    if response.status().is_informational() {
        return response;
    }

    let should_drain = !(expect_100_continue && !unread.polled) && !is_timeout_response(&response);
    let drained_cleanly = if should_drain {
        let budget = limit.saturating_sub(unread.read);
        tokio::time::timeout(timeout, drain_stream(unread.stream, budget))
            .await
            .unwrap_or(false)
    } else {
        false
    };
    if !drained_cleanly {
        mark_connection_close(version, &mut response);
    }
    response
}

async fn drain_stream(mut stream: BodyDataStream, budget: usize) -> bool {
    let mut drained = 0usize;
    while let Some(chunk) = stream.next().await {
        let Ok(chunk) = chunk else {
            return false;
        };
        drained = drained.saturating_add(chunk.len());
        if drained > budget {
            return false;
        }
    }
    true
}

fn is_timeout_response(response: &Response) -> bool {
    response.status() == StatusCode::REQUEST_TIMEOUT
        || response
            .headers()
            .get("x-ms-error-code")
            .and_then(|value| value.to_str().ok())
            .is_some_and(|code| code.eq_ignore_ascii_case("OperationTimedOut"))
}

fn mark_connection_close(version: Version, response: &mut Response) {
    if version < Version::HTTP_2 {
        response
            .headers_mut()
            .insert(header::CONNECTION, HeaderValue::from_static("close"));
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicUsize, Ordering};

    struct CountingStream {
        chunks: Vec<std::result::Result<Bytes, std::io::Error>>,
        polled: Arc<AtomicUsize>,
        pending_after_chunks: bool,
    }

    impl Stream for CountingStream {
        type Item = std::result::Result<Bytes, std::io::Error>;

        fn poll_next(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
            let this = self.get_mut();
            this.polled.fetch_add(1, Ordering::SeqCst);
            if this.chunks.is_empty() {
                if this.pending_after_chunks {
                    Poll::Pending
                } else {
                    Poll::Ready(None)
                }
            } else {
                Poll::Ready(Some(this.chunks.remove(0)))
            }
        }
    }

    fn stream_request(
        chunks: Vec<Bytes>,
        pending_after_chunks: bool,
    ) -> (Request, Arc<AtomicUsize>) {
        let polled = Arc::new(AtomicUsize::new(0));
        let body = Body::from_stream(CountingStream {
            chunks: chunks.into_iter().map(Ok).collect(),
            polled: Arc::clone(&polled),
            pending_after_chunks,
        });
        let request = Request::builder().method("PUT").uri("/test").body(body);
        (request.unwrap(), polled)
    }

    #[tokio::test]
    async fn drains_unread_body_within_cap_without_closing_connection() {
        let (request, polled) = stream_request(
            vec![Bytes::from_static(b"abcd"), Bytes::from_static(b"efgh")],
            false,
        );
        let response =
            drain_unread_body_with(64, Duration::from_millis(200), request, |_req| async {
                empty(StatusCode::BAD_REQUEST)
            })
            .await;
        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
        assert!(response.headers().get(header::CONNECTION).is_none());
        assert_eq!(polled.load(Ordering::SeqCst), 3);
    }

    #[tokio::test]
    async fn stops_draining_and_sets_connection_close_when_stream_exceeds_cap() {
        let (request, polled) = stream_request(
            vec![
                Bytes::from(vec![b'a'; 16]),
                Bytes::from(vec![b'b'; 16]),
                Bytes::from(vec![b'c'; 16]),
            ],
            false,
        );
        let response =
            drain_unread_body_with(20, Duration::from_millis(200), request, |_req| async {
                empty(StatusCode::BAD_REQUEST)
            })
            .await;
        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
        assert_eq!(
            response
                .headers()
                .get(header::CONNECTION)
                .and_then(|value| value.to_str().ok()),
            Some("close")
        );
        // Stopped as soon as cumulative drained bytes (32) exceeded the 20-byte cap.
        assert_eq!(polled.load(Ordering::SeqCst), 2);
    }

    #[tokio::test]
    async fn skips_draining_and_sets_connection_close_when_content_length_exceeds_cap() {
        let (mut request, polled) = stream_request(vec![Bytes::from(vec![b'a'; 128])], false);
        request
            .headers_mut()
            .insert(header::CONTENT_LENGTH, HeaderValue::from_static("128"));
        let response =
            drain_unread_body_with(64, Duration::from_millis(200), request, |_req| async {
                empty(StatusCode::PAYLOAD_TOO_LARGE)
            })
            .await;
        assert_eq!(response.status(), StatusCode::PAYLOAD_TOO_LARGE);
        assert_eq!(
            response
                .headers()
                .get(header::CONNECTION)
                .and_then(|value| value.to_str().ok()),
            Some("close")
        );
        assert_eq!(polled.load(Ordering::SeqCst), 0);
    }

    #[tokio::test]
    async fn does_not_close_connection_on_large_successful_upload() {
        let (mut request, polled) = stream_request(vec![Bytes::from(vec![b'a'; 128])], false);
        request
            .headers_mut()
            .insert(header::CONTENT_LENGTH, HeaderValue::from_static("128"));
        let response =
            drain_unread_body_with(64, Duration::from_millis(200), request, |req| async move {
                let mut stream = req.into_body().into_data_stream();
                while stream.next().await.is_some() {}
                empty(StatusCode::CREATED)
            })
            .await;
        assert_eq!(response.status(), StatusCode::CREATED);
        assert!(response.headers().get(header::CONNECTION).is_none());
        assert_eq!(polled.load(Ordering::SeqCst), 2);
    }

    #[tokio::test]
    async fn closes_promptly_when_stalled_unread_body_hits_timeout() {
        let (request, _polled) = stream_request(vec![Bytes::from_static(b"partial")], true);
        let started = std::time::Instant::now();
        let response =
            drain_unread_body_with(64, Duration::from_millis(40), request, |_req| async {
                empty(StatusCode::FORBIDDEN)
            })
            .await;
        assert_eq!(response.status(), StatusCode::FORBIDDEN);
        assert_eq!(
            response
                .headers()
                .get(header::CONNECTION)
                .and_then(|value| value.to_str().ok()),
            Some("close")
        );
        assert!(started.elapsed() < Duration::from_secs(1));
    }

    #[tokio::test]
    async fn does_not_poll_unpolled_expect_100_continue_on_early_rejection() {
        let (mut request, polled) = stream_request(vec![Bytes::from_static(b"never-sent")], false);
        request
            .headers_mut()
            .insert(header::EXPECT, HeaderValue::from_static("100-continue"));
        let response =
            drain_unread_body_with(64, Duration::from_millis(200), request, |_req| async {
                empty(StatusCode::FORBIDDEN)
            })
            .await;
        assert_eq!(response.status(), StatusCode::FORBIDDEN);
        assert_eq!(polled.load(Ordering::SeqCst), 0);
        assert_eq!(
            response
                .headers()
                .get(header::CONNECTION)
                .and_then(|value| value.to_str().ok()),
            Some("close")
        );
    }

    #[tokio::test]
    async fn skips_draining_timeout_responses_immediately() {
        let (request, polled) = stream_request(vec![], true);
        let started = std::time::Instant::now();
        let response = drain_unread_body_with(64, Duration::from_secs(5), request, |_req| async {
            xml_error(
                StatusCode::INTERNAL_SERVER_ERROR,
                "OperationTimedOut",
                "timed out",
            )
        })
        .await;
        assert_eq!(response.status(), StatusCode::INTERNAL_SERVER_ERROR);
        assert_eq!(polled.load(Ordering::SeqCst), 0);
        assert_eq!(
            response
                .headers()
                .get(header::CONNECTION)
                .and_then(|value| value.to_str().ok()),
            Some("close")
        );
        assert!(started.elapsed() < Duration::from_millis(200));
    }

    #[tokio::test]
    async fn accounts_for_bytes_already_read_when_handler_stops_mid_stream() {
        let (request, polled) = stream_request(
            vec![Bytes::from(vec![b'a'; 12]), Bytes::from(vec![b'b'; 12])],
            false,
        );
        let response =
            drain_unread_body_with(20, Duration::from_millis(200), request, |req| async move {
                let mut stream = req.into_body().into_data_stream();
                let first = stream.next().await.unwrap().unwrap();
                assert_eq!(first.len(), 12);
                empty(StatusCode::PAYLOAD_TOO_LARGE)
            })
            .await;
        assert_eq!(response.status(), StatusCode::PAYLOAD_TOO_LARGE);
        // 12 bytes read by handler + 12 bytes drained = 24 > 20 cap -> close connection.
        assert_eq!(polled.load(Ordering::SeqCst), 2);
        assert_eq!(
            response
                .headers()
                .get(header::CONNECTION)
                .and_then(|value| value.to_str().ok()),
            Some("close")
        );
    }

    #[tokio::test]
    async fn omits_connection_close_header_on_http2_responses() {
        let (mut request, _polled) = stream_request(vec![Bytes::from(vec![b'a'; 128])], false);
        *request.version_mut() = Version::HTTP_2;
        request
            .headers_mut()
            .insert(header::CONTENT_LENGTH, HeaderValue::from_static("128"));
        let response =
            drain_unread_body_with(64, Duration::from_millis(200), request, |_req| async {
                empty(StatusCode::FORBIDDEN)
            })
            .await;
        assert_eq!(response.status(), StatusCode::FORBIDDEN);
        assert!(response.headers().get(header::CONNECTION).is_none());
    }
}
