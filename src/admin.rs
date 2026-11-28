//! The admin listener: health, readiness, instance status, and optional Prometheus metrics.

use crate::{config::Config, metrics::Metrics, telemetry::Telemetry};
use anyhow::Context as _;
use axum::{
    Json, Router,
    extract::State,
    http::{HeaderValue, header},
    response::{IntoResponse as _, Response},
    routing::get,
};
use serde::{Deserialize, Serialize};
use std::{sync::Arc, time::Instant};

const PROMETHEUS_TYPE: &str = "text/plain; version=0.0.4; charset=utf-8";

#[derive(Clone, Debug, Deserialize, Serialize)]
pub(crate) struct ServiceStatus {
    pub(crate) name: String,
    pub(crate) url: String,
}

/// The JSON served at `GET /status` and read by `azuifer status`.
#[derive(Clone, Debug, Deserialize, Serialize)]
pub(crate) struct Status {
    pub(crate) version: String,
    pub(crate) uptime_seconds: u64,
    /// `in-memory` or `persistent`.
    pub(crate) storage: String,
    pub(crate) location: Option<String>,
    pub(crate) services: Vec<ServiceStatus>,
    pub(crate) admin_url: String,
    pub(crate) prometheus: bool,
    pub(crate) otlp: bool,
}

#[derive(Clone)]
pub(crate) struct Admin {
    pub(crate) started: Instant,
    pub(crate) status: Arc<Status>,
    pub(crate) metrics: Option<Arc<Metrics>>,
}

impl Admin {
    pub(crate) fn new(
        config: &Config,
        services: Vec<ServiceStatus>,
        admin_url: String,
        telemetry: &Telemetry,
    ) -> anyhow::Result<Self> {
        let location = config
            .location
            .as_ref()
            .map(std::path::absolute)
            .transpose()
            .context("could not resolve the data directory for admin status")?;
        Ok(Self {
            started: Instant::now(),
            status: Arc::new(Status {
                version: env!("CARGO_PKG_VERSION").to_owned(),
                uptime_seconds: 0,
                storage: if config.location.is_some() {
                    "persistent"
                } else {
                    "in-memory"
                }
                .to_owned(),
                location: location.map(|path| path.display().to_string()),
                services,
                admin_url,
                prometheus: config.telemetry.prometheus,
                otlp: telemetry.otlp_enabled(),
            }),
            metrics: telemetry.prometheus(),
        })
    }
}

pub(crate) fn router(admin: Admin) -> Router {
    let router = Router::new()
        .route("/healthz", get(|| async { "ok\n" }))
        .route("/readyz", get(|| async { "ready\n" }))
        .route("/status", get(status));
    let router = if admin.metrics.is_some() {
        router.route("/metrics", get(metrics))
    } else {
        router
    };
    router.with_state(admin)
}

async fn status(State(admin): State<Admin>) -> Json<Status> {
    Json(Status {
        uptime_seconds: admin.started.elapsed().as_secs(),
        ..(*admin.status).clone()
    })
}

async fn metrics(State(admin): State<Admin>) -> Response {
    let uptime = admin.started.elapsed();
    // Rendering samples the stores, which can wait for their metadata locks.
    let body = match admin.metrics.clone() {
        Some(metrics) => tokio::task::spawn_blocking(move || metrics.render(uptime))
            .await
            .unwrap_or_default(),
        None => String::new(),
    };
    (
        [(
            header::CONTENT_TYPE,
            HeaderValue::from_static(PROMETHEUS_TYPE),
        )],
        body,
    )
        .into_response()
}
