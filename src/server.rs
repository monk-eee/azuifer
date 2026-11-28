use crate::{
    address,
    blob_auth::{self, Authorization},
    blob_cors,
    blob_exec::{self, Context},
    blob_sas::Connection,
    clock::{self, Clock},
    config::{Config, PERMIT_WAIT, Service},
    dfs,
    domain::{AccountName, Error, Result},
    files, oauth, protocol, queue,
    respond::{self, error_response, set},
    store::Store,
    table,
    tls::{self, TlsListener},
};
use crate::{
    admin::{self, Admin, ServiceStatus},
    telemetry::{self, Telemetry},
};
use anyhow::Context as _;
use axum::{
    Router,
    body::Body,
    extract::{ConnectInfo, Request, State},
    http::{HeaderMap, HeaderValue, Method, StatusCode, request::Parts},
    response::Response,
};
use futures_util::StreamExt as _;
use std::{net::SocketAddr, sync::Arc};
use tokio::{net::TcpListener, sync::Semaphore};
use tokio_util::sync::CancellationToken;
use tracing::Instrument as _;
use uuid::Uuid;

pub(crate) struct App {
    pub(crate) config: Arc<Config>,
    pub(crate) version: HeaderValue,
    pub(crate) store: Store,
    pub(crate) address: SocketAddr,
    pub(crate) permits: Arc<Semaphore>,
    pub(crate) clock: Clock,
}

pub(crate) async fn serve(config: Config, shutdown_on_stdin_eof: bool) -> anyhow::Result<()> {
    let config = Arc::new(config);
    let telemetry = Telemetry::start(&config)?;
    config
        .oauth
        .load_keys()
        .await
        .context("could not load the JWKS for --oauth jwks")?;
    // Held until shutdown: an in-memory run keeps its generated certificate in a temporary directory.
    let tls = match &config.tls {
        Some(settings) => Some(tls::prepare(settings, config.location.as_deref()).await?),
        None => None,
    };
    if let Some(certificate) = tls.as_ref().and_then(|tls| tls.generated.as_ref()) {
        tracing::info!(certificate = %certificate.display(), "using the generated development certificate");
        println!("tls_cert={}", certificate.display());
    }
    let admin = TcpListener::bind(config.admin)
        .await
        .context("could not bind the admin listener")?;
    let admin_address = admin.local_addr()?;
    if config.external_copy_sources.is_enabled() {
        tracing::info!("copies from allowlisted external hosts are enabled");
    }
    let clock = Clock::new();
    let namespace =
        if config.services.contains(&Service::Blob) || config.services.contains(&Service::Dfs) {
            let location = config.location.clone();
            let memory_limit = config.memory_limit;
            let store_clock = clock.clone();
            let hns_accounts = config.hns_accounts.clone();
            let store = tokio::task::spawn_blocking(move || {
                Store::open(location.as_deref(), memory_limit, store_clock, hns_accounts)
            })
            .await
            .context("storage initialization did not complete")??;
            store
                .enable_versioning(
                    config
                        .versioning_accounts
                        .iter()
                        .map(|account| account.as_str().to_owned())
                        .collect(),
                )
                .await
                .map_err(|_| anyhow::anyhow!("could not apply the versioning settings"))?;
            Some((store, Arc::new(Semaphore::new(16))))
        } else {
            None
        };
    let mut services = Vec::new();
    let mut bound = Vec::new();
    for service in Service::ALL {
        if !config.services.contains(&service) {
            continue;
        }
        let requested = match service {
            Service::Blob => config.blob,
            Service::Queue => config.queue,
            Service::Table => config.table,
            Service::Dfs => config.dfs,
            Service::File => config.file,
        };
        let listener = TcpListener::bind(requested)
            .await
            .with_context(|| format!("could not bind the {} listener", service.name()))?;
        let address = listener.local_addr()?;
        let router = match service {
            Service::Blob | Service::Dfs => {
                let (store, permits) = namespace
                    .as_ref()
                    .context("shared namespace store was not started")?;
                if service == Service::Blob {
                    blob_router(
                        config.clone(),
                        address,
                        store.clone(),
                        permits.clone(),
                        clock.clone(),
                    )?
                } else {
                    let blob = blob_app(
                        config.clone(),
                        address,
                        store.clone(),
                        permits.clone(),
                        clock.clone(),
                    )?;
                    dfs::router(
                        config.clone(),
                        store.clone(),
                        permits.clone(),
                        clock.clone(),
                        blob,
                    )?
                }
            }
            Service::Queue => queue::router(config.clone(), address, clock.clone()).await?,
            Service::Table => table::router(config.clone(), address, clock.clone()).await?,
            Service::File => files::router(config.clone(), address, clock.clone()).await?,
        };
        let router = telemetry::instrument(router, &telemetry, service);
        tracing::info!(service = service.name(), %address, "listening");
        println!("{}_url={}://{address}", service.name(), config.scheme());
        bound.push(ServiceStatus {
            name: service.name().to_owned(),
            url: format!("{}://{address}", config.scheme()),
        });
        let acceptor = tls.as_ref().map(|tls| tls.acceptor.clone());
        let router = router.layer(axum::middleware::map_response(oauth::add_challenge));
        services.push((listener, router, acceptor));
    }
    let mut admin_router = admin::router(Admin::new(
        &config,
        bound,
        format!("http://{admin_address}"),
        &telemetry,
    )?);
    if config.test_clock {
        admin_router = admin_router.merge(clock::router(clock.clone()));
    }
    let stop = CancellationToken::new();
    tracing::info!(admin = %admin_address, "listening");
    println!("admin_url=http://{admin_address}");
    services.push((admin, admin_router, None));
    tokio::spawn(oauth::refresh_keys(config.clone(), stop.clone()));
    let tasks = futures_util::future::try_join_all(services.into_iter().map(
        |(listener, router, acceptor)| {
            let stop = stop.clone();
            async move {
                let shutdown = stop.cancelled_owned();
                match acceptor {
                    Some(acceptor) => {
                        axum::serve(TlsListener::new(listener, acceptor)?, router)
                            .with_graceful_shutdown(shutdown)
                            .await
                    }
                    None => {
                        axum::serve(listener, router)
                            .with_graceful_shutdown(shutdown)
                            .await
                    }
                }
            }
        },
    ));
    let signal = async {
        wait_for_shutdown(shutdown_on_stdin_eof).await?;
        stop.cancel();
        Ok(())
    };
    let served = tokio::try_join!(tasks, signal);
    telemetry.shutdown().await;
    served.context("HTTP server exited unexpectedly")?;
    Ok(())
}

fn blob_router(
    config: Arc<Config>,
    address: SocketAddr,
    store: Store,
    permits: Arc<Semaphore>,
    clock: Clock,
) -> anyhow::Result<Router> {
    let app = blob_app(config, address, store, permits, clock)?;
    Ok(Router::new().fallback(dispatch).with_state(app))
}

/// The Blob service state, which the DFS listener also serves for `{account}.blob.{domain}`
/// hosts: the Data Lake SDKs derive that host from the DFS URL for their Blob calls.
fn blob_app(
    config: Arc<Config>,
    address: SocketAddr,
    store: Store,
    permits: Arc<Semaphore>,
    clock: Clock,
) -> anyhow::Result<Arc<App>> {
    let version = HeaderValue::from_str(config.api_version.as_str())
        .context("invalid HTTP version in the protocol manifest")?;
    Ok(Arc::new(App {
        config,
        version,
        store,
        address,
        permits,
        clock,
    }))
}

async fn wait_for_shutdown(shutdown_on_stdin_eof: bool) -> std::io::Result<()> {
    if !shutdown_on_stdin_eof {
        return wait_for_signal().await;
    }
    let (sender, eof) = tokio::sync::oneshot::channel();
    std::thread::Builder::new()
        .name("stdin-shutdown".into())
        .spawn(move || {
            let result =
                std::io::copy(&mut std::io::stdin().lock(), &mut std::io::sink()).map(|_| ());
            let _ = sender.send(result);
        })?;
    tokio::select! {
        result = wait_for_signal() => result,
        result = eof => result.map_err(std::io::Error::other)?,
    }
}

async fn wait_for_signal() -> std::io::Result<()> {
    #[cfg(unix)]
    {
        use tokio::signal::unix::{SignalKind, signal};
        let mut terminate = signal(SignalKind::terminate())?;
        tokio::select! {
            result = tokio::signal::ctrl_c() => result,
            _ = terminate.recv() => Ok(()),
        }
    }
    #[cfg(not(unix))]
    tokio::signal::ctrl_c().await
}

pub(crate) async fn dispatch(State(app): State<Arc<App>>, request: Request) -> Response {
    let request_id = Uuid::new_v4().simple().to_string();
    let (parts, body) = request.into_parts();
    let head = parts.method == Method::HEAD;
    let client_request_id = parts.headers.get("x-ms-client-request-id").cloned();
    let mut response = if app.config.test_clock && parts.uri.path().starts_with("/_azuifer/") {
        clock::endpoint(&app.clock, &parts)
    } else if parts.method == Method::OPTIONS {
        preflight(&app, &parts).await
    } else {
        let mut response =
            match tokio::time::timeout(PERMIT_WAIT, app.permits.clone().acquire_owned()).await {
                Ok(Ok(permit)) => match handle(&app, &parts, body, &request_id).await {
                    Ok(mut response) => {
                        if parts.method == Method::GET
                            && response.headers().contains_key("x-ms-blob-type")
                        {
                            let body = std::mem::replace(response.body_mut(), Body::empty());
                            *response.body_mut() =
                                Body::from_stream(body.into_data_stream().map(move |item| {
                                    let _permit = &permit;
                                    item
                                }));
                        }
                        response
                    }
                    Err(error) => respond::request_error_response(
                        error,
                        &parts.headers,
                        &request_id,
                        app.clock.now(),
                    ),
                },
                _ => error_response(Error::Busy),
            };
        add_cors(&app, &parts, &mut response).await;
        response
    };
    if response
        .extensions()
        .get::<respond::OmitApiVersion>()
        .is_none()
    {
        response
            .headers_mut()
            .insert("x-ms-version", app.version.clone());
    }
    if let Some(id) = client_request_id {
        response.headers_mut().insert("x-ms-client-request-id", id);
    }
    if set(response.headers_mut(), "x-ms-request-id", &request_id)
        .and_then(|_| {
            set(
                response.headers_mut(),
                "date",
                &httpdate::fmt_http_date(app.clock.now()),
            )
        })
        .is_err()
    {
        return error_response(Error::Internal);
    }
    if head {
        *response.body_mut() = Body::empty();
    }
    tracing::info!(%request_id, status = response.status().as_u16(), "blob request");
    response
}

/// Authenticates, authorizes, and runs one request.
async fn handle(app: &App, parts: &Parts, body: Body, request_id: &str) -> Result<Response> {
    if let Some(account) = crate::blob_web::account_of(parts) {
        return telemetry::storage(
            crate::blob_web::serve(app, parts, account, request_id),
            None,
        )
        .await;
    }
    let now = app.clock.now();
    let connection = Connection {
        now,
        client_ip: parts
            .extensions
            .get::<ConnectInfo<SocketAddr>>()
            .map(|info| info.0.ip()),
        https: app.config.tls.is_some(),
    };
    let parsed = async {
        let parsed = protocol::parse(parts, &app.config, now, request_id)?;
        if parsed.requested_version != app.config.api_version {
            tracing::info!(
                %request_id,
                requested_api_version = parsed.requested_version.as_str(),
                effective_api_version = app.config.api_version.as_str(),
                "using the configured Blob protocol baseline"
            );
        }
        blob_auth::authorize(
            &app.store,
            Authorization {
                credentials: &parsed.credentials,
                target: &parsed.target,
                need: &parsed.need,
                connection: &connection,
            },
        )
        .await?;
        Ok::<_, Error>(parsed)
    }
    .instrument(telemetry::authenticate_span())
    .await?;
    let context = Context {
        host: protocol::host(parts),
        account: parsed.target.account(),
        credentials: &parsed.credentials,
        connection: &connection,
        request_id,
    };
    let copy = blob_exec::copy_trace(app, &parsed.operation, &context);
    telemetry::storage(
        blob_exec::execute(app, parsed.operation, body, &context),
        copy,
    )
    .await
}

/// The account a request addresses, for CORS lookups made before parsing succeeds.
fn account_of(parts: &Parts) -> Option<AccountName> {
    address::host_account("blob", protocol::host(parts)).or_else(|| {
        let segment = parts.uri.path().strip_prefix('/')?.split('/').next()?;
        AccountName::parse(segment).ok()
    })
}

fn header_text<'a>(headers: &'a HeaderMap, name: &str) -> Option<&'a str> {
    headers.get(name).and_then(|value| value.to_str().ok())
}

async fn cors_rules(app: &App, parts: &Parts) -> Option<Vec<crate::service_props::CorsRule>> {
    let account = account_of(parts)?;
    let properties = app.store.service_properties(account).await.ok()?;
    properties.cors
}

/// Answers a browser preflight from the account's stored CORS rules.
async fn preflight(app: &App, parts: &Parts) -> Response {
    let headers = &parts.headers;
    let (Some(origin), Some(method)) = (
        header_text(headers, "origin"),
        header_text(headers, "access-control-request-method"),
    ) else {
        return error_response(Error::CorsPreflight);
    };
    let requested = header_text(headers, "access-control-request-headers");
    let rules = cors_rules(app, parts).await.unwrap_or_default();
    match blob_cors::find(&rules, origin, method, requested) {
        Some(rule) => {
            let mut response = respond::empty(StatusCode::OK);
            response
                .headers_mut()
                .extend(blob_cors::preflight(rule, origin, method, requested));
            response
        }
        None => error_response(Error::CorsPreflight),
    }
}

/// Adds `Access-Control-*` headers when a rule allows the request's origin.
async fn add_cors(app: &App, parts: &Parts, response: &mut Response) {
    let Some(origin) = header_text(&parts.headers, "origin") else {
        return;
    };
    let Some(rules) = cors_rules(app, parts).await else {
        return;
    };
    if let Some(rule) = blob_cors::find(&rules, origin, parts.method.as_str(), None) {
        blob_cors::apply(rule, origin, response.headers_mut());
    }
}
