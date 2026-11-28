//! Opt-in observability: structured logs, request spans, metrics, and OTLP export (ADR-0007).
//!
//! Nothing leaves the process unless `--otlp-endpoint` is set. Request text recorded
//! on spans passes through the [`Redactor`] first.

use crate::{
    config::{Config, Service},
    metrics::{LATENCY_BUCKETS, Metrics},
    redact::Redactor,
    runtime_metrics::{self, Kind},
};
use anyhow::{Context as _, Result, bail, ensure};
use axum::{
    Router,
    body::{Body, HttpBody as _},
    extract::{Request, State},
    http::{HeaderMap, Method, header},
    middleware::Next,
    response::Response,
};
use clap::{Args, ValueEnum};
use futures_util::StreamExt as _;
use opentelemetry::{
    KeyValue,
    metrics::{AsyncInstrument, Counter, Histogram, MeterProvider as _, UpDownCounter},
    trace::TracerProvider as _,
};
use opentelemetry_otlp::{MetricExporter, Protocol, SpanExporter, WithExportConfig as _};
use opentelemetry_sdk::{Resource, metrics::SdkMeterProvider, trace::SdkTracerProvider};
use serde::Deserialize;
use std::{
    fs::OpenOptions,
    io::IsTerminal as _,
    path::PathBuf,
    sync::{Arc, Mutex},
    time::{Duration, Instant},
};
use tracing::Instrument as _;
use tracing_subscriber::{
    Layer as _, filter::LevelFilter, fmt::writer::BoxMakeWriter, layer::SubscriberExt as _,
    util::SubscriberInitExt as _,
};

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, ValueEnum)]
#[serde(rename_all = "lowercase")]
pub(crate) enum OtlpProtocol {
    Grpc,
    Http,
}

#[derive(Clone, Copy, Debug, Default, Deserialize, Eq, PartialEq, ValueEnum)]
#[serde(rename_all = "lowercase")]
pub(crate) enum LogFormat {
    #[default]
    Json,
    Text,
}

#[derive(Args, Default)]
pub(crate) struct TelemetryOptions {
    /// Export traces and metrics to this OTLP collector (plain `http://` only).
    #[arg(long, env = "AZUIFER_OTLP_ENDPOINT", global = true)]
    otlp_endpoint: Option<String>,
    /// OTLP transport: `grpc` (default) or `http` (protobuf).
    #[arg(long, env = "AZUIFER_OTLP_PROTOCOL", global = true, value_enum)]
    otlp_protocol: Option<OtlpProtocol>,
    /// Serve Prometheus metrics at `/metrics` on the admin listener.
    #[arg(long, env = "AZUIFER_PROMETHEUS", global = true, num_args = 0..=1, require_equals = true, default_missing_value = "true")]
    prometheus: Option<bool>,
    #[arg(long, env = "AZUIFER_LOG_FORMAT", global = true, value_enum)]
    log_format: Option<LogFormat>,
    /// Append logs to this file instead of writing them to standard error.
    #[arg(long, env = "AZUIFER_LOG_FILE", global = true)]
    log_file: Option<PathBuf>,
}

/// The same settings as TOML keys.
#[derive(Default)]
pub(crate) struct FileSettings {
    pub(crate) otlp_endpoint: Option<String>,
    pub(crate) otlp_protocol: Option<OtlpProtocol>,
    pub(crate) prometheus: Option<bool>,
    pub(crate) log_format: Option<LogFormat>,
    pub(crate) log_file: Option<PathBuf>,
}

pub(crate) struct Otlp {
    endpoint: String,
    pub(crate) protocol: OtlpProtocol,
}

pub(crate) struct Settings {
    pub(crate) otlp: Option<Otlp>,
    pub(crate) prometheus: bool,
    log_format: LogFormat,
    log_file: Option<PathBuf>,
}

impl Settings {
    pub(crate) fn resolve(options: TelemetryOptions, file: FileSettings) -> Result<Self> {
        let endpoint = options
            .otlp_endpoint
            .or(file.otlp_endpoint)
            .filter(|endpoint| !endpoint.trim().is_empty());
        let protocol = options.otlp_protocol.or(file.otlp_protocol);
        ensure!(
            endpoint.is_some() || protocol.is_none(),
            "otlp-protocol requires otlp-endpoint"
        );
        let otlp = endpoint
            .map(|endpoint| {
                Ok::<_, anyhow::Error>(Otlp {
                    endpoint: validate_endpoint(&endpoint)?,
                    protocol: protocol.unwrap_or(OtlpProtocol::Grpc),
                })
            })
            .transpose()?;
        Ok(Self {
            otlp,
            prometheus: options.prometheus.or(file.prometheus).unwrap_or(false),
            log_format: options.log_format.or(file.log_format).unwrap_or_default(),
            log_file: options.log_file.or(file.log_file),
        })
    }
}

fn validate_endpoint(endpoint: &str) -> Result<String> {
    let endpoint = endpoint.trim().trim_end_matches('/');
    let Some(rest) = endpoint
        .get(..7)
        .filter(|scheme| scheme.eq_ignore_ascii_case("http://"))
        .map(|_| &endpoint[7..])
    else {
        bail!("otlp-endpoint must be a plain http:// URL; TLS to collectors is not supported");
    };
    ensure!(
        !rest.is_empty() && !rest.starts_with('/') && !rest.contains('@'),
        "otlp-endpoint must be http://host[:port] without credentials"
    );
    Ok(endpoint.to_owned())
}

struct Providers {
    tracer: SdkTracerProvider,
    meter: SdkMeterProvider,
}

struct Instruments {
    requests: Counter<u64>,
    duration: Histogram<f64>,
    request_bytes: Counter<u64>,
    response_bytes: Counter<u64>,
    active: UpDownCounter<i64>,
}

/// State shared by the request middleware of every service.
pub(crate) struct Observer {
    metrics: Arc<Metrics>,
    redactor: Redactor,
    instruments: Option<Instruments>,
}

impl Observer {
    fn adjust_active(&self, service: Service, delta: i64) {
        self.metrics.adjust_active(service.name(), delta);
        if let Some(instruments) = &self.instruments {
            instruments
                .active
                .add(delta, &[KeyValue::new("service", service.name())]);
        }
    }

    fn finish(&self, service: Service, status: u16, elapsed: Duration, request_bytes: u64) {
        self.metrics
            .record(service.name(), status, elapsed, request_bytes);
        if let Some(instruments) = &self.instruments {
            let service = KeyValue::new("service", service.name());
            instruments.requests.add(
                1,
                &[service.clone(), KeyValue::new("status", i64::from(status))],
            );
            instruments
                .duration
                .record(elapsed.as_secs_f64(), std::slice::from_ref(&service));
            instruments
                .request_bytes
                .add(request_bytes, std::slice::from_ref(&service));
        }
    }

    fn add_response_bytes(&self, service: Service, bytes: u64) {
        self.metrics.add_response_bytes(service.name(), bytes);
        if let Some(instruments) = &self.instruments {
            instruments
                .response_bytes
                .add(bytes, &[KeyValue::new("service", service.name())]);
        }
    }
}

pub(crate) struct Telemetry {
    observer: Arc<Observer>,
    prometheus: bool,
    providers: Option<Providers>,
}

impl Telemetry {
    /// Installs the process-wide logger and, when configured, the OTLP exporters.
    pub(crate) fn start(config: &Config) -> Result<Self> {
        let settings = &config.telemetry;
        let redactor = Redactor::new(config.accounts.values().flatten().map(Vec::as_slice));
        let metrics = Arc::new(Metrics::new(config.services.iter().map(|s| s.name())));
        let providers = settings
            .otlp
            .as_ref()
            .map(build_providers)
            .transpose()
            .context("could not start the OTLP exporters")?;
        let instruments = providers
            .as_ref()
            .map(|providers| instruments(&providers.meter));
        if let Some(providers) = &providers {
            observe_runtime(&providers.meter);
        }
        let otel_layer = providers.as_ref().map(|providers| {
            tracing_opentelemetry::layer()
                .with_location(false)
                .with_threads(false)
                .with_tracked_inactivity(false)
                .with_tracer(providers.tracer.tracer("azuifer"))
        });
        tracing_subscriber::registry()
            .with(log_layer(settings)?)
            .with(otel_layer)
            .with(LevelFilter::INFO)
            .try_init()
            .context("could not initialize diagnostics")?;
        Ok(Self {
            observer: Arc::new(Observer {
                metrics,
                redactor,
                instruments,
            }),
            prometheus: settings.prometheus,
            providers,
        })
    }

    /// The metrics served at `/metrics`, when Prometheus is enabled.
    pub(crate) fn prometheus(&self) -> Option<Arc<Metrics>> {
        self.prometheus.then(|| self.observer.metrics.clone())
    }

    pub(crate) fn otlp_enabled(&self) -> bool {
        self.providers.is_some()
    }

    /// Flushes and stops the OTLP exporters.
    pub(crate) async fn shutdown(self) {
        let Some(providers) = self.providers else {
            return;
        };
        let flushed = tokio::task::spawn_blocking(move || {
            providers.tracer.shutdown()?;
            providers.meter.shutdown()
        })
        .await;
        if !matches!(flushed, Ok(Ok(()))) {
            tracing::warn!("the OTLP exporters did not flush completely");
        }
    }
}

/// Wraps one service router with the request span and metrics.
pub(crate) fn instrument(router: Router, telemetry: &Telemetry, service: Service) -> Router {
    router.layer(axum::middleware::from_fn_with_state(
        (telemetry.observer.clone(), service),
        observe,
    ))
}

pub(crate) fn authenticate_span() -> tracing::Span {
    tracing::info_span!("authenticate")
}

/// The operation name is chosen by the typed handler, never taken from the source URL.
pub(crate) enum CopyTrace {
    Local(&'static str),
    External(&'static str),
}

impl CopyTrace {
    fn span(self) -> tracing::Span {
        let (operation, source_kind) = match self {
            Self::Local(operation) => (operation, "local"),
            Self::External(operation) => (operation, "external"),
        };
        tracing::info_span!(
            "copy",
            "azuifer.copy.operation" = operation,
            "azuifer.copy.source_kind" = source_kind,
        )
    }
}

pub(crate) async fn storage<T>(work: impl Future<Output = T>, copy: Option<CopyTrace>) -> T {
    // Both spans are created under the request, before either is entered.
    let copy = copy.map(CopyTrace::span);
    async move {
        match copy {
            Some(span) => work.instrument(span).await,
            None => work.await,
        }
    }
    .instrument(tracing::info_span!("storage"))
    .await
}

fn log_layer(
    settings: &Settings,
) -> Result<Box<dyn tracing_subscriber::Layer<tracing_subscriber::Registry> + Send + Sync>> {
    let writer = match &settings.log_file {
        Some(path) => BoxMakeWriter::new(Mutex::new(
            OpenOptions::new()
                .create(true)
                .append(true)
                .open(path)
                .context("could not open the log file")?,
        )),
        None => BoxMakeWriter::new(std::io::stderr),
    };
    let layer = tracing_subscriber::fmt::layer().with_writer(writer);
    Ok(match settings.log_format {
        LogFormat::Json => layer.json().boxed(),
        LogFormat::Text => layer
            .with_ansi(settings.log_file.is_none() && std::io::stderr().is_terminal())
            .boxed(),
    })
}

fn resource() -> Resource {
    Resource::builder()
        .with_service_name("azuifer")
        .with_attribute(KeyValue::new("service.version", env!("CARGO_PKG_VERSION")))
        .build()
}

fn build_providers(otlp: &Otlp) -> Result<Providers> {
    let timeout = Duration::from_secs(5);
    let (spans, metrics) = match otlp.protocol {
        OtlpProtocol::Grpc => (
            SpanExporter::builder()
                .with_tonic()
                .with_endpoint(&otlp.endpoint)
                .with_timeout(timeout)
                .build()?,
            MetricExporter::builder()
                .with_tonic()
                .with_endpoint(&otlp.endpoint)
                .with_timeout(timeout)
                .build()?,
        ),
        OtlpProtocol::Http => (
            SpanExporter::builder()
                .with_http()
                .with_protocol(Protocol::HttpBinary)
                .with_endpoint(format!("{}/v1/traces", otlp.endpoint))
                .with_timeout(timeout)
                .build()?,
            MetricExporter::builder()
                .with_http()
                .with_protocol(Protocol::HttpBinary)
                .with_endpoint(format!("{}/v1/metrics", otlp.endpoint))
                .with_timeout(timeout)
                .build()?,
        ),
    };
    Ok(Providers {
        tracer: SdkTracerProvider::builder()
            .with_resource(resource())
            .with_batch_exporter(spans)
            .build(),
        meter: SdkMeterProvider::builder()
            .with_resource(resource())
            .with_periodic_exporter(metrics)
            .build(),
    })
}

fn instruments(meter: &SdkMeterProvider) -> Instruments {
    let meter = meter.meter("azuifer");
    Instruments {
        requests: meter
            .u64_counter("azuifer.http.server.requests")
            .with_description("Completed HTTP requests by service and status code.")
            .build(),
        duration: meter
            .f64_histogram("azuifer.http.server.request.duration")
            .with_unit("s")
            .with_description("Time from request receipt to the response head.")
            .with_boundaries(LATENCY_BUCKETS.to_vec())
            .build(),
        request_bytes: meter
            .u64_counter("azuifer.http.server.request.bytes")
            .with_unit("By")
            .build(),
        response_bytes: meter
            .u64_counter("azuifer.http.server.response.bytes")
            .with_unit("By")
            .build(),
        active: meter
            .i64_up_down_counter("azuifer.http.server.active_requests")
            .build(),
    }
}

/// Exports the store gauges and counters, read from the same source as /metrics.
fn observe_runtime(provider: &SdkMeterProvider) {
    let meter = provider.meter("azuifer");
    for (index, spec) in runtime_metrics::SPECS.iter().enumerate() {
        let read = move |instrument: &dyn AsyncInstrument<f64>| {
            for (labels, value) in runtime_metrics::collect(index) {
                let attributes: Vec<KeyValue> = labels
                    .into_iter()
                    .map(|(name, value)| KeyValue::new(name, value))
                    .collect();
                instrument.observe(value, &attributes);
            }
        };
        match spec.kind {
            Kind::Counter => {
                meter
                    .f64_observable_counter(spec.otel)
                    .with_description(spec.help)
                    .with_unit(spec.unit)
                    .with_callback(read)
                    .build();
            }
            Kind::Gauge => {
                meter
                    .f64_observable_gauge(spec.otel)
                    .with_description(spec.help)
                    .with_unit(spec.unit)
                    .with_callback(read)
                    .build();
            }
        }
    }
}

struct ActiveGuard {
    observer: Arc<Observer>,
    service: Service,
}

impl ActiveGuard {
    fn new(observer: Arc<Observer>, service: Service) -> Self {
        observer.adjust_active(service, 1);
        Self { observer, service }
    }
}

impl Drop for ActiveGuard {
    fn drop(&mut self) {
        self.observer.adjust_active(self.service, -1);
    }
}

async fn observe(
    State((observer, service)): State<(Arc<Observer>, Service)>,
    request: Request,
    next: Next,
) -> Response {
    let started = Instant::now();
    let _active = ActiveGuard::new(observer.clone(), service);
    let redactor = &observer.redactor;
    let method = request.method().clone();
    let query = request.uri().query().unwrap_or_default();
    let operation = redactor.text(&operation(&method, query));
    let span = tracing::info_span!(
        "request",
        otel.name = %format!("{} {operation}", service.name()),
        otel.kind = "server",
        otel.status_code = tracing::field::Empty,
        "azuifer.service" = service.name(),
        "azuifer.operation" = %operation,
        "azuifer.request_id" = tracing::field::Empty,
        "azuifer.client_request_id" = %redactor.text(header_text(request.headers(), "x-ms-client-request-id")),
        "http.request.method" = %redactor.text(method.as_str()),
        "url.path" = %redactor.text(request.uri().path()),
        "url.query" = %redactor.query(query),
        "http.response.status_code" = tracing::field::Empty,
    );
    let request_bytes = declared_length(request.headers()).unwrap_or(0);
    let mut response = next.run(request).instrument(span.clone()).await;

    let status = response.status();
    span.record("http.response.status_code", status.as_u16());
    if status.is_server_error() {
        span.record("otel.status_code", "ERROR");
    }
    let request_id = header_text(response.headers(), "x-ms-request-id");
    span.record("azuifer.request_id", request_id);
    observer.finish(service, status.as_u16(), started.elapsed(), request_bytes);

    if method == Method::HEAD {
        return response;
    }
    match declared_length(response.headers()).or_else(|| response.body().size_hint().exact()) {
        Some(bytes) => observer.add_response_bytes(service, bytes),
        None => {
            let body = std::mem::replace(response.body_mut(), Body::empty());
            *response.body_mut() =
                Body::from_stream(body.into_data_stream().inspect(move |chunk| {
                    if let Ok(chunk) = chunk {
                        observer.add_response_bytes(service, chunk.len() as u64);
                    }
                }));
        }
    }
    response
}

fn header_text<'a>(headers: &'a HeaderMap, name: &str) -> &'a str {
    headers
        .get(name)
        .and_then(|value| value.to_str().ok())
        .unwrap_or_default()
}

fn declared_length(headers: &HeaderMap) -> Option<u64> {
    header_text(headers, header::CONTENT_LENGTH.as_str())
        .parse()
        .ok()
}

/// A low-cardinality operation identity: the method plus the selector query parameters.
fn operation(method: &Method, query: &str) -> String {
    let mut operation = method.to_string();
    for selector in ["restype", "comp", "resource", "action"] {
        let value = query.split('&').find_map(|pair| {
            let (name, value) = pair.split_once('=')?;
            (name == selector).then_some(value)
        });
        if let Some(value) = value.filter(|value| {
            value.len() <= 32
                && value
                    .bytes()
                    .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-')
        }) {
            operation.push_str(&format!(" {selector}={value}"));
        }
    }
    operation
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn operation_names_the_method_and_selectors_only() {
        assert_eq!(
            operation(&Method::PUT, "comp=block&blockid=AAAA&sig=secret"),
            "PUT comp=block"
        );
        assert_eq!(
            operation(&Method::GET, "restype=container&comp=list"),
            "GET restype=container comp=list"
        );
        assert_eq!(operation(&Method::GET, "comp=a%20b"), "GET");
    }

    #[test]
    fn endpoints_must_be_plain_http_without_credentials() {
        assert_eq!(
            validate_endpoint("http://localhost:4317/").unwrap(),
            "http://localhost:4317"
        );
        for bad in [
            "https://collector:4317",
            "localhost:4317",
            "http://user:pw@host",
            "http://",
        ] {
            assert!(validate_endpoint(bad).is_err(), "{bad}");
        }
    }

    #[test]
    fn protocol_needs_an_endpoint() {
        let options = TelemetryOptions {
            otlp_protocol: Some(OtlpProtocol::Http),
            ..TelemetryOptions::default()
        };
        assert!(Settings::resolve(options, FileSettings::default()).is_err());
        let settings =
            Settings::resolve(TelemetryOptions::default(), FileSettings::default()).unwrap();
        assert!(settings.otlp.is_none() && !settings.prometheus);
    }
}
