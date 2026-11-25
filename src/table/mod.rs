//! Azure Table Storage data plane: tables, entities, entity group transactions (ADR-0014).

mod auth;
mod batch;
mod codec;
mod datetime;
mod edm;
mod error;
mod filter;
mod handlers;
mod model;
mod protocol;
mod service;
mod store;

use crate::{auth::header, clock::Clock, config::Config, domain::ApiVersion};
use anyhow::Context as _;
use axum::{
    Router,
    body::{Body, Bytes, to_bytes},
    extract::{Request, State},
    http::{HeaderValue, header::HOST, request::Parts},
    response::Response,
};
use error::{Kind, Result, TableError};
use std::{net::SocketAddr, sync::Arc, time::SystemTime};
use store::Store;
use uuid::Uuid;

/// A batch may carry 4 MiB of operations; the rest is multipart framing.
const MAX_BODY_BYTES: usize = 5 * 1024 * 1024;

struct App {
    config: Arc<Config>,
    clock: Clock,
    store: Store,
    address: SocketAddr,
}

pub(crate) async fn router(
    config: Arc<Config>,
    address: SocketAddr,
    clock: Clock,
) -> anyhow::Result<Router> {
    let location = config.location.clone();
    let store = tokio::task::spawn_blocking(move || Store::open(location.as_deref()))
        .await
        .context("Table storage initialization did not complete")??;
    let app = Arc::new(App {
        config,
        clock,
        store,
        address,
    });
    Ok(Router::new().fallback(dispatch).with_state(app))
}

/// The version echoed in `x-ms-version`: the requested one when supported, else the baseline.
fn effective_version(parts: &Parts, config: &Config) -> Result<String> {
    let baseline = config.api_version.as_str().to_owned();
    let Some(requested) = header(&parts.headers, "x-ms-version")? else {
        return Ok(baseline);
    };
    let requested = ApiVersion::parse(requested)?;
    if requested <= config.api_version {
        return Ok(requested.as_str().to_owned());
    }
    if config.skip_api_version_check {
        return Ok(baseline);
    }
    Err(TableError::new(Kind::InvalidHeaderValue))
}

async fn dispatch(State(app): State<Arc<App>>, request: Request) -> Response {
    let request_id = Uuid::new_v4().to_string();
    let now = app.clock.now();
    let (parts, body) = request.into_parts();
    let version = effective_version(&parts, &app.config);
    let outcome = match &version {
        Ok(_) => handle(&app, &parts, body, &request_id, now).await,
        Err(error) => Err(error.clone()),
    };
    let mut response =
        outcome.unwrap_or_else(|error| handlers::error_response(&error, None, &request_id, now));
    let version = version.unwrap_or_else(|_| app.config.api_version.as_str().to_owned());
    let client_request_id = parts
        .headers
        .get("x-ms-client-request-id")
        .filter(|value| value.len() <= 1024)
        .cloned();
    let headers = response.headers_mut();
    headers.insert("dataserviceversion", HeaderValue::from_static("3.0;"));
    if let Some(value) = client_request_id {
        headers.insert("x-ms-client-request-id", value);
    }
    for (name, value) in [
        ("x-ms-request-id", request_id.as_str()),
        ("x-ms-version", version.as_str()),
        ("date", httpdate::fmt_http_date(now).as_str()),
    ] {
        if let Ok(value) = HeaderValue::from_str(value) {
            headers.insert(name, value);
        }
    }
    tracing::info!(%request_id, status = response.status().as_u16(), "table request");
    response
}

async fn read_body(app: &App, parts: &Parts, body: Body) -> Result<Bytes> {
    let too_large = || TableError::new(Kind::RequestBodyTooLarge);
    let declared =
        header(&parts.headers, "content-length")?.and_then(|value| value.parse::<u64>().ok());
    if declared.is_some_and(|length| length > MAX_BODY_BYTES as u64) {
        return Err(too_large());
    }
    tokio::time::timeout(app.config.upload_timeout, to_bytes(body, MAX_BODY_BYTES))
        .await
        .map_err(|_| TableError::new(Kind::Internal))?
        .map_err(|_| too_large())
}

async fn handle(
    app: &App,
    parts: &Parts,
    body: Body,
    request_id: &str,
    now: SystemTime,
) -> Result<Response> {
    let headers = &parts.headers;
    let query = protocol::parse_query(parts.uri.query())?;
    let (path, host_style) = protocol::logical_path(parts);
    let (account, secondary, target) = protocol::parse_path(&path)?;
    let keys = app
        .config
        .accounts
        .get(&account)
        .ok_or_else(|| TableError::new(Kind::AuthenticationFailed))?;
    let credential = auth::authenticate(
        &app.store,
        &auth::Presented {
            account: &account,
            keys,
            method: &parts.method,
            raw_path: parts.uri.path(),
            query: &query,
            headers,
            table: target.table(),
            now,
        },
    )
    .await?;
    let bytes = read_body(app, parts, body).await?;
    let method = protocol::effective_method(&parts.method, headers)?;
    if secondary && method != axum::http::Method::GET {
        return Err(TableError::new(Kind::MethodNotAllowed));
    }
    let request = match target {
        protocol::Target::Batch => {
            if method != axum::http::Method::POST {
                return Err(TableError::new(Kind::MethodNotAllowed));
            }
            match protocol::build_batch(headers, &bytes, account.as_str()) {
                Ok(request) => request,
                Err(failure) => return handlers::batch_failure(failure, request_id, now).await,
            }
        }
        target => protocol::build(&method, target, &query, headers, &bytes)?,
    };
    request
        .operation
        .check_access(&mut |access, table, key| credential.authorize(access, table, key))?;
    let host = headers
        .get(HOST)
        .and_then(|value| value.to_str().ok())
        .map_or_else(|| app.address.to_string(), str::to_owned);
    let ctx = handlers::Context {
        app,
        account: &account,
        urls: edm::Urls {
            account: account.as_str().to_owned(),
            base: if host_style {
                format!("http://{host}")
            } else {
                format!("http://{host}/{}", account.as_str())
            },
        },
        credential: &credential,
        request_id,
        now,
    };
    handlers::execute(&ctx, request).await
}
