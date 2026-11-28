//! Azure Queue Storage data plane (ADR-0009, ADR-0010, ADR-0011, ADR-0012, ADR-0013).
//!
//! Requests flow through four separate steps: `protocol` parses the wire request
//! into a typed operation, `auth` authorizes it, `store` applies it in one SQLite
//! transaction, and `xml`/`error` map the outcome back to the Azure wire shape.

mod auth;
mod cors;
mod error;
mod model;
mod protocol;
mod store;
mod time;
mod xml;

use crate::{
    auth::header,
    clock::Clock,
    config::Config,
    domain::{ApiVersion, Page},
    telemetry,
};
use anyhow::Context as _;
use axum::{
    Router,
    body::{Body, Bytes, to_bytes},
    extract::{Request as HttpRequest, State},
    http::{HeaderName, HeaderValue, Method, StatusCode, request::Parts},
    response::Response,
};
use error::{QueueError, Result};
use model::{MAX_MESSAGE_BYTES, Metadata};
use protocol::Operation;
use serde::Deserialize;
use std::{net::SocketAddr, sync::Arc};
use store::{Created, NewMessage, QueueListing, Store};
use tracing::Instrument as _;
use uuid::Uuid;

const MANIFEST: &str = include_str!("../../specs/conformance/queue.json");

// A 64 KiB message may grow to six bytes per character once XML-escaped.
const MESSAGE_BODY_LIMIT: usize = MAX_MESSAGE_BYTES * 6 + 1024;
const SMALL_BODY_LIMIT: usize = 64 * 1024;

#[derive(Deserialize)]
struct Manifest {
    api_version: String,
}

struct App {
    config: Arc<Config>,
    store: Store,
    clock: Clock,
    baseline: ApiVersion,
    version: HeaderValue,
    address: SocketAddr,
}

pub(crate) async fn router(
    config: Arc<Config>,
    address: SocketAddr,
    clock: Clock,
) -> anyhow::Result<Router> {
    let location = config.location.clone();
    let store_clock = clock.clone();
    let store = tokio::task::spawn_blocking(move || Store::open(location.as_deref(), store_clock))
        .await
        .context("queue storage initialization did not complete")??;
    build(config, address, clock, store)
}

fn build(
    config: Arc<Config>,
    address: SocketAddr,
    clock: Clock,
    store: Store,
) -> anyhow::Result<Router> {
    let manifest: Manifest =
        serde_json::from_str(MANIFEST).context("invalid embedded Queue manifest")?;
    let baseline = ApiVersion::parse(&manifest.api_version)
        .map_err(|_| anyhow::anyhow!("invalid API version in the Queue manifest"))?;
    let version = HeaderValue::from_str(baseline.as_str())
        .context("invalid HTTP version in the Queue manifest")?;
    let app = Arc::new(App {
        config,
        store,
        clock,
        baseline,
        version,
        address,
    });
    Ok(Router::new().fallback(dispatch).with_state(app))
}

async fn dispatch(State(app): State<Arc<App>>, request: HttpRequest) -> Response {
    let request_id = Uuid::new_v4().simple().to_string();
    let (parts, body) = request.into_parts();
    let mut response = match handle(&app, &parts, body).await {
        Ok(response) => response,
        Err(error) => {
            tracing::info!(%request_id, code = error.code(), "queue request failed");
            error.into_response(&request_id, app.clock.now_millis())
        }
    };
    if parts.method != Method::OPTIONS
        && parts.headers.contains_key("origin")
        && let Some(account) = protocol::account_of(&parts)
        && let Ok(properties) = app.store.service_properties(account).await
    {
        cors::decorate(
            &properties.cors,
            &parts.headers,
            parts.method.as_str(),
            &mut response,
        );
    }
    let headers = response.headers_mut();
    headers.insert("x-ms-version", app.version.clone());
    let date = httpdate::fmt_http_date(app.clock.now());
    for (name, value) in [("x-ms-request-id", request_id.as_str()), ("date", &date)] {
        if let Ok(value) = HeaderValue::from_str(value) {
            headers.insert(HeaderName::from_static(name), value);
        }
    }
    if let Some(client_id) = parts
        .headers
        .get("x-ms-client-request-id")
        .filter(|value| value.len() <= 1024)
    {
        headers.insert("x-ms-client-request-id", client_id.clone());
    }
    if parts.method == Method::HEAD {
        *response.body_mut() = Body::empty();
    }
    tracing::info!(%request_id, status = response.status().as_u16(), "queue request");
    response
}

async fn handle(app: &App, parts: &Parts, body: Body) -> Result<Response> {
    check_version(app, parts)?;
    let request = protocol::parse(parts)?;
    if let Operation::Preflight(preflight) = &request.operation {
        let properties = app
            .store
            .service_properties(request.account.clone())
            .await?;
        return cors::preflight(&properties.cors, preflight);
    }
    auth::authorize(app, parts, &request)
        .instrument(telemetry::authenticate_span())
        .await?;
    telemetry::storage(execute(app, request, body), None).await
}

fn check_version(app: &App, parts: &Parts) -> Result<()> {
    let Some(value) = header(&parts.headers, "x-ms-version")? else {
        let key_auth = header(&parts.headers, "authorization")?
            .is_some_and(|value| value.starts_with("SharedKey"));
        return if key_auth {
            Err(QueueError::MissingHeader("x-ms-version"))
        } else {
            Ok(())
        };
    };
    let invalid = || QueueError::InvalidVersion(value.chars().take(64).collect());
    let requested = ApiVersion::parse(value).map_err(|_| invalid())?;
    if requested == app.baseline {
        return Ok(());
    }
    if !requested.is_served(&app.baseline, app.config.skip_api_version_check) {
        return Err(invalid());
    }
    if requested > app.baseline {
        tracing::info!(
            requested_api_version = requested.as_str(),
            effective_api_version = app.baseline.as_str(),
            "using the configured Queue protocol baseline"
        );
    }
    Ok(())
}

async fn read_body(app: &App, body: Body, limit: usize) -> Result<Bytes> {
    tokio::time::timeout(app.config.upload_timeout, to_bytes(body, limit))
        .await
        .map_err(|_| QueueError::Busy)?
        .map_err(|_| QueueError::BodyTooLarge(limit as u64))
}

fn empty(status: StatusCode) -> Response {
    let mut response = Response::new(Body::empty());
    *response.status_mut() = status;
    response
}

fn set(response: &mut Response, name: &str, value: &str) -> Result<()> {
    let name = HeaderName::from_bytes(name.as_bytes()).map_err(|_| QueueError::Internal)?;
    let value = HeaderValue::from_str(value).map_err(|_| QueueError::Internal)?;
    response.headers_mut().insert(name, value);
    Ok(())
}

async fn execute(app: &App, request: protocol::Request, body: Body) -> Result<Response> {
    let account = request.account;
    let host = request.host;
    let store = &app.store;
    match request.operation {
        Operation::GetServiceProperties => {
            Ok(xml::properties(&store.service_properties(account).await?))
        }
        Operation::SetServiceProperties => {
            let bytes = read_body(app, body, SMALL_BODY_LIMIT).await?;
            store
                .update_properties(account, xml::parse_properties(&bytes)?)
                .await?;
            Ok(empty(StatusCode::ACCEPTED))
        }
        Operation::GetServiceStats => xml::stats(app.clock.now_millis()),
        Operation::ListQueues(options) => {
            let limit = options.page.limit;
            let scheme = app.config.scheme();
            let endpoint = match host {
                Some(host) => format!("{scheme}://{host}/"),
                None => format!("{scheme}://{}/{}/", app.address, account.as_str()),
            };
            let rows = store
                .list_queues(
                    account,
                    QueueListing {
                        prefix: options.page.prefix.clone(),
                        after: options.page.after.clone(),
                        limit,
                    },
                )
                .await?;
            let page = Page::from_rows(rows, limit);
            Ok(xml::list_queues(xml::Listing {
                endpoint: &endpoint,
                prefix: &options.page.prefix,
                marker: &options.marker,
                limit,
                queues: page.items,
                next: &page.next,
                metadata: options.metadata,
            }))
        }
        Operation::CreateQueue(queue, metadata) => {
            let status = match store
                .create_queue(account, queue.as_str().to_owned(), metadata)
                .await?
            {
                Created::New => StatusCode::CREATED,
                Created::Existing => StatusCode::NO_CONTENT,
            };
            Ok(empty(status))
        }
        Operation::DeleteQueue(queue) => {
            store
                .delete_queue(account, queue.as_str().to_owned())
                .await?;
            Ok(empty(StatusCode::NO_CONTENT))
        }
        Operation::GetQueueMetadata(queue) => {
            let (metadata, count) = store
                .queue_metadata(account, queue.as_str().to_owned())
                .await?;
            metadata_response(&metadata, count)
        }
        Operation::SetQueueMetadata(queue, metadata) => {
            store
                .set_metadata(account, queue.as_str().to_owned(), metadata)
                .await?;
            Ok(empty(StatusCode::NO_CONTENT))
        }
        Operation::GetQueueAcl(queue) => Ok(xml::acl(
            &store.acl(account, queue.as_str().to_owned()).await?,
        )),
        Operation::SetQueueAcl(queue) => {
            let bytes = read_body(app, body, SMALL_BODY_LIMIT).await?;
            store
                .set_acl(account, queue.as_str().to_owned(), xml::parse_acl(&bytes)?)
                .await?;
            Ok(empty(StatusCode::NO_CONTENT))
        }
        Operation::PutMessage(queue, options) => {
            let bytes = read_body(app, body, MESSAGE_BODY_LIMIT).await?;
            let text = xml::message_text(&bytes)?.ok_or(QueueError::InvalidXml)?;
            let message = store
                .put_message(
                    account,
                    queue.as_str().to_owned(),
                    NewMessage {
                        text,
                        visibility_millis: options.visibility_seconds * 1000,
                        ttl_millis: options
                            .ttl_seconds
                            .map(|seconds| seconds.saturating_mul(1000)),
                    },
                )
                .await?;
            xml::messages(&[message], &xml::MessageView::Put)
        }
        Operation::GetMessages(queue, count, visibility) => {
            let messages = store
                .get_messages(account, queue.as_str().to_owned(), count, visibility * 1000)
                .await?;
            xml::messages(&messages, &xml::MessageView::Get)
        }
        Operation::PeekMessages(queue, count) => {
            let messages = store
                .peek_messages(account, queue.as_str().to_owned(), count)
                .await?;
            xml::messages(&messages, &xml::MessageView::Peek)
        }
        Operation::UpdateMessage(queue, id, receipt, visibility) => {
            let bytes = read_body(app, body, MESSAGE_BODY_LIMIT).await?;
            let text = xml::message_text(&bytes)?;
            let (receipt, visible) = store
                .update_message(
                    account,
                    queue.as_str().to_owned(),
                    id.as_str().to_owned(),
                    receipt,
                    visibility * 1000,
                    text,
                )
                .await?;
            let mut response = empty(StatusCode::NO_CONTENT);
            set(&mut response, "x-ms-popreceipt", &receipt)?;
            set(
                &mut response,
                "x-ms-time-next-visible",
                &time::http_date(visible)?,
            )?;
            Ok(response)
        }
        Operation::DeleteMessage(queue, id, receipt) => {
            store
                .delete_message(
                    account,
                    queue.as_str().to_owned(),
                    id.as_str().to_owned(),
                    receipt,
                )
                .await?;
            Ok(empty(StatusCode::NO_CONTENT))
        }
        Operation::ClearMessages(queue) => {
            store
                .clear_messages(account, queue.as_str().to_owned())
                .await?;
            Ok(empty(StatusCode::NO_CONTENT))
        }
        Operation::Preflight(_) => Err(QueueError::Internal),
    }
}

fn metadata_response(metadata: &Metadata, count: i64) -> Result<Response> {
    let mut response = empty(StatusCode::OK);
    set(
        &mut response,
        "x-ms-approximate-messages-count",
        &count.to_string(),
    )?;
    for (name, value) in metadata {
        set(&mut response, &format!("x-ms-meta-{name}"), value)?;
    }
    Ok(response)
}

#[cfg(test)]
mod tests {
    use super::*;
    use base64::{Engine as _, engine::general_purpose::STANDARD};
    use hmac::{Hmac, Mac as _};
    use sha2::Sha256;
    use std::time::Duration;

    const KEY: &str =
        "Eby8vdM02xNOcqFlqUwJPLlmEtlCDXJ1OUzFT50uSRZ6IFsuFq2UVErCz4I6tq/K1SZFPTOtr/KBHBeksoGMGw==";

    struct Server {
        base: String,
        clock: Clock,
        client: reqwest::Client,
    }

    impl Server {
        async fn start() -> Self {
            let config = Arc::new(Config::load(crate::config::Options::default()).unwrap());
            let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
            let address = listener.local_addr().unwrap();
            let clock = Clock::new();
            let store = Store::open(None, clock.clone()).unwrap();
            let router = build(config, address, clock.clone(), store).unwrap();
            tokio::spawn(async move { axum::serve(listener, router).await });
            Self {
                base: format!("http://{address}/devstoreaccount1"),
                clock,
                client: reqwest::Client::builder().no_proxy().build().unwrap(),
            }
        }

        async fn call(&self, method: &str, target: &str, body: &str) -> reqwest::Response {
            let (path, query) = target.split_once('?').unwrap_or((target, ""));
            let date = httpdate::fmt_http_date(self.clock.now());
            let content_type = if body.is_empty() {
                ""
            } else {
                "application/xml"
            };
            let length = if body.is_empty() {
                String::new()
            } else {
                body.len().to_string()
            };
            let mut pairs: Vec<_> = query.split('&').filter(|p| !p.is_empty()).collect();
            pairs.sort_unstable();
            let resource: String = pairs
                .iter()
                .map(|pair| format!("\n{}", pair.replacen('=', ":", 1)))
                .collect();
            let message = format!(
                "{method}\n\n\n{length}\n\n{content_type}\n\n\n\n\n\n\nx-ms-date:{date}\nx-ms-version:2023-11-03\n/devstoreaccount1/devstoreaccount1{path}{resource}"
            );
            let mut mac = Hmac::<Sha256>::new_from_slice(&STANDARD.decode(KEY).unwrap()).unwrap();
            mac.update(message.as_bytes());
            let signature = STANDARD.encode(mac.finalize().into_bytes());
            let mut request = self
                .client
                .request(method.parse().unwrap(), format!("{}{target}", self.base))
                .header("x-ms-date", date)
                .header("x-ms-version", "2023-11-03")
                .header(
                    "authorization",
                    format!("SharedKey devstoreaccount1:{signature}"),
                );
            if !body.is_empty() {
                request = request
                    .header("content-type", content_type)
                    .body(body.to_owned());
            }
            request.send().await.unwrap()
        }
    }

    #[tokio::test]
    async fn manual_clock_drives_visibility_and_ttl_over_http() {
        let server = Server::start().await;
        assert_eq!(server.call("PUT", "/clocked", "").await.status(), 201);
        let put = server
            .call(
                "POST",
                "/clocked/messages?messagettl=100",
                "<QueueMessage><MessageText>hello</MessageText></QueueMessage>",
            )
            .await;
        assert_eq!(put.status(), 201);
        for header in ["x-ms-request-id", "x-ms-version", "date"] {
            assert!(put.headers().contains_key(header), "{header}");
        }
        let got = server
            .call("GET", "/clocked/messages?visibilitytimeout=30", "")
            .await;
        let text = got.text().await.unwrap();
        assert!(text.contains("<DequeueCount>1</DequeueCount><MessageText>hello</MessageText>"));
        let again = server
            .call("GET", "/clocked/messages", "")
            .await
            .text()
            .await
            .unwrap();
        assert!(!again.contains("<QueueMessage>"));

        server.clock.advance(Duration::from_secs(31));
        let peek = server
            .call("GET", "/clocked/messages?peekonly=true", "")
            .await;
        assert!(
            peek.text()
                .await
                .unwrap()
                .contains("<DequeueCount>1</DequeueCount>")
        );

        server.clock.advance(Duration::from_secs(100));
        let expired = server
            .call("GET", "/clocked/messages?peekonly=true", "")
            .await;
        assert!(!expired.text().await.unwrap().contains("<QueueMessage>"));
        let metadata = server.call("HEAD", "/clocked?comp=metadata", "").await;
        assert_eq!(metadata.headers()["x-ms-approximate-messages-count"], "0");
    }

    #[tokio::test]
    async fn requests_without_credentials_or_with_a_bad_signature_are_rejected() {
        let server = Server::start().await;
        let anonymous = server
            .client
            .get(format!("{}/qqq?comp=metadata", server.base))
            .send()
            .await
            .unwrap();
        assert_eq!(anonymous.status(), 403);
        assert_eq!(
            anonymous.headers()["x-ms-error-code"],
            "AuthenticationFailed"
        );
        let forged = server
            .client
            .get(format!("{}/qqq?comp=metadata", server.base))
            .header("x-ms-date", httpdate::fmt_http_date(server.clock.now()))
            .header("x-ms-version", "2023-11-03")
            .header(
                "authorization",
                format!("SharedKey devstoreaccount1:{}", STANDARD.encode([1u8; 32])),
            )
            .send()
            .await
            .unwrap();
        assert_eq!(forged.status(), 403);
        let missing = server.call("GET", "/nothere/messages", "").await;
        assert_eq!(missing.status(), 404);
        assert_eq!(missing.headers()["x-ms-error-code"], "QueueNotFound");
        let body = missing.text().await.unwrap();
        assert!(body.contains("RequestId:") && body.contains("Time:"));
    }
}
