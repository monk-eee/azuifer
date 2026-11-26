//! Azure Files (FileREST) service: its own namespace, store, leases, and handles (ADR-0016).

mod auth;
mod error;
mod lease;
mod model;
mod name;
mod ops;
mod request;
mod response;
mod service;
mod store;
mod time;
mod xml;

use crate::{
    address,
    clock::Clock,
    config::{Config, PERMIT_WAIT},
    domain::ApiVersion,
};
use anyhow::Context as _;
use auth::{Credentials, Signed};
use axum::{
    Router,
    body::Body,
    extract::{Request, State},
    http::{HeaderValue, Method, request::Parts},
    response::Response,
};
use error::{Error, Result};
use futures_util::StreamExt as _;
use request::{Headers, Query, Target};
use response::{error_response, set};
use std::{net::SocketAddr, sync::Arc};
use store::{ShareRef, Store};
use tokio::sync::Semaphore;
use uuid::Uuid;

/// The Azure Files REST API version this service implements.
pub(crate) const API_VERSION: &str = "2023-11-03";
const MAX_HEADER_COUNT: usize = 100;
const MAX_HEADER_BYTES: usize = 32 * 1024;

pub(super) struct App {
    config: Arc<Config>,
    store: Store,
    clock: Clock,
    address: SocketAddr,
    version: HeaderValue,
    baseline: ApiVersion,
    permits: Arc<Semaphore>,
}

pub(crate) async fn router(
    config: Arc<Config>,
    address: SocketAddr,
    clock: Clock,
) -> anyhow::Result<Router> {
    let version = HeaderValue::from_static(API_VERSION);
    let baseline = ApiVersion::parse(API_VERSION)
        .map_err(|_| anyhow::anyhow!("invalid Files API version constant"))?;
    let (location, limit, store_clock) =
        (config.location.clone(), config.memory_limit, clock.clone());
    let store =
        tokio::task::spawn_blocking(move || Store::open(location.as_deref(), limit, store_clock))
            .await
            .context("file storage initialization did not complete")??;
    let app = Arc::new(App {
        config,
        store,
        clock,
        address,
        version,
        baseline,
        permits: Arc::new(Semaphore::new(16)),
    });
    Ok(Router::new().fallback(dispatch).with_state(app))
}

async fn dispatch(State(app): State<Arc<App>>, request: Request) -> Response {
    let request_id = Uuid::new_v4().simple().to_string();
    let (parts, body) = request.into_parts();
    let head = parts.method == Method::HEAD;
    let mut response = match handle(&app, &parts, body).await {
        Ok(response) => response,
        Err(error) => error_response(error),
    };
    let headers = response.headers_mut();
    headers.insert("x-ms-version", app.version.clone());
    let stamped = set(headers, "x-ms-request-id", &request_id)
        .and_then(|()| set(headers, "date", &time::http_date(app.clock.now_millis())));
    if stamped.is_err() {
        return error_response(Error::Internal);
    }
    if let Some(client_id) = parts.headers.get("x-ms-client-request-id") {
        headers.insert("x-ms-client-request-id", client_id.clone());
    }
    if head {
        *response.body_mut() = Body::empty();
    }
    tracing::info!(%request_id, status = response.status().as_u16(), "file request");
    response
}

async fn handle(app: &Arc<App>, parts: &Parts, body: Body) -> Result<Response> {
    let permit = tokio::time::timeout(PERMIT_WAIT, app.permits.clone().acquire_owned())
        .await
        .map_err(|_| Error::ServerBusy)?
        .map_err(|_| Error::ServerBusy)?;
    if parts.headers.len() > MAX_HEADER_COUNT
        || parts
            .headers
            .iter()
            .map(|(name, value)| name.as_str().len() + value.len())
            .sum::<usize>()
            > MAX_HEADER_BYTES
    {
        return Err(Error::InvalidHeaderValue);
    }
    let query = Query::parse(parts.uri.query())?;
    let headers = Headers(&parts.headers);
    let (path, host) = address::resolve("file", parts);
    let target = Target::parse(&path, headers.flag("x-ms-allow-trailing-dot")?)?;
    let keys = app
        .config
        .accounts
        .get(&target.account)
        .ok_or(Error::AuthenticationFailed)?;
    let credentials = auth::credentials(&parts.headers, &query)?;
    check_version(app, &headers, matches!(credentials, Credentials::Sas))?;
    let operation = request::route(&parts.method, &target, &query, &headers)?;
    tracing::info!(operation = operation.name(), "file operation");
    let signed = Signed {
        account: &target.account,
        keys,
        method: &parts.method,
        raw_path: parts.uri.path(),
        query: &query,
        headers: &parts.headers,
        now: app.clock.now(),
        share: target.share.as_ref().map(name::ShareName::as_str),
        path: &target.decoded,
    };
    let overrides = match &credentials {
        Credentials::Sas => {
            let policy = stored_policy(app, &target, &query).await?;
            let grant = auth::verify_sas(&signed, policy.as_ref())?;
            grant.authorize(&operation.needs())?;
            grant.overrides
        }
        Credentials::Bearer(token) => {
            auth::verify_bearer(&app.config.oauth, token, &signed)?;
            auth::Overrides::default()
        }
        header => {
            auth::verify_header(header, &signed)?;
            auth::Overrides::default()
        }
    };
    if operation.is_unsupported() {
        return Err(Error::NotImplemented);
    }
    let context = ops::Context {
        app,
        operation,
        target,
        host: host.map(str::to_owned),
        query,
        headers,
        overrides,
    };
    let mut response = ops::execute(context, body).await?;
    if parts.method == Method::GET && response.headers().contains_key("x-ms-type") {
        let stream = std::mem::replace(response.body_mut(), Body::empty()).into_data_stream();
        *response.body_mut() = Body::from_stream(stream.map(move |item| {
            let _permit = &permit;
            item
        }));
    }
    Ok(response)
}

/// A service SAS may name a stored access policy of its share with `si`.
async fn stored_policy(
    app: &App,
    target: &Target,
    query: &Query,
) -> Result<Option<model::AccessPolicy>> {
    let (Some(id), Some(share)) = (query.get("si"), target.share.clone()) else {
        return Ok(None);
    };
    let live = ShareRef {
        account: target.account.clone(),
        share,
        snapshot: None,
    };
    let (_, policies) = app
        .store
        .share_acl(live)
        .await
        .map_err(|_| Error::AuthenticationFailed)?;
    Ok(policies.into_iter().find(|policy| policy.id == id))
}

/// `x-ms-version` is required except on SAS requests. Older versions get baseline
/// behavior; newer ones need `--skip-api-version-check`.
fn check_version(app: &App, headers: &Headers<'_>, sas: bool) -> Result<()> {
    let Some(value) = headers.get("x-ms-version")? else {
        return if sas {
            Ok(())
        } else {
            Err(Error::MissingRequiredHeader)
        };
    };
    let requested = ApiVersion::parse(value).map_err(|_| Error::InvalidHeaderValue)?;
    if !requested.is_served(&app.baseline, app.config.skip_api_version_check) {
        return Err(Error::InvalidHeaderValue);
    }
    Ok(())
}
