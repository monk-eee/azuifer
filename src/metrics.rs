//! In-process request metrics, rendered in the Prometheus text format (ADR-0007).

use std::{
    collections::BTreeMap,
    fmt::Write as _,
    sync::{Mutex, MutexGuard, PoisonError},
    time::Duration,
};

/// Upper bounds, in seconds, of the request-duration histogram buckets.
pub(crate) const LATENCY_BUCKETS: [f64; 11] = [
    0.001, 0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1.0, 2.5, 10.0,
];

#[derive(Default)]
struct ServiceMetrics {
    statuses: BTreeMap<u16, u64>,
    /// Observations per bucket, plus a final overflow slot for `+Inf`.
    buckets: [u64; LATENCY_BUCKETS.len() + 1],
    duration_sum: f64,
    request_bytes: u64,
    response_bytes: u64,
    active: i64,
}

impl ServiceMetrics {
    fn requests(&self) -> u64 {
        self.statuses.values().sum()
    }
}

pub(crate) struct Metrics {
    services: Mutex<BTreeMap<&'static str, ServiceMetrics>>,
}

impl Metrics {
    pub(crate) fn new(services: impl IntoIterator<Item = &'static str>) -> Self {
        Self {
            services: Mutex::new(
                services
                    .into_iter()
                    .map(|name| (name, ServiceMetrics::default()))
                    .collect(),
            ),
        }
    }

    fn state(&self) -> MutexGuard<'_, BTreeMap<&'static str, ServiceMetrics>> {
        self.services.lock().unwrap_or_else(PoisonError::into_inner)
    }

    pub(crate) fn adjust_active(&self, service: &'static str, delta: i64) {
        self.state().entry(service).or_default().active += delta;
    }

    pub(crate) fn record(
        &self,
        service: &'static str,
        status: u16,
        elapsed: Duration,
        request_bytes: u64,
    ) {
        let seconds = elapsed.as_secs_f64();
        let slot = LATENCY_BUCKETS
            .iter()
            .position(|bound| seconds <= *bound)
            .unwrap_or(LATENCY_BUCKETS.len());
        let mut state = self.state();
        let metrics = state.entry(service).or_default();
        *metrics.statuses.entry(status).or_default() += 1;
        metrics.buckets[slot] += 1;
        metrics.duration_sum += seconds;
        metrics.request_bytes += request_bytes;
    }

    pub(crate) fn add_response_bytes(&self, service: &'static str, bytes: u64) {
        self.state().entry(service).or_default().response_bytes += bytes;
    }

    /// Renders every series in the Prometheus text exposition format.
    /// The request metrics and the store metrics.
    pub(crate) fn render(&self, uptime: Duration) -> String {
        let mut out = self.render_requests(uptime);
        crate::runtime_metrics::render(&mut out);
        out
    }

    fn render_requests(&self, uptime: Duration) -> String {
        let state = self.state();
        let mut out = String::new();
        family(
            &mut out,
            "azuifer_http_requests_total",
            "counter",
            "Completed HTTP requests by service and status code.",
        );
        for (service, metrics) in state.iter() {
            for (status, count) in &metrics.statuses {
                sample(
                    &mut out,
                    "azuifer_http_requests_total",
                    &format!("service=\"{service}\",status=\"{status}\""),
                    count,
                );
            }
        }
        family(
            &mut out,
            "azuifer_http_request_duration_seconds",
            "histogram",
            "Time from request receipt to the response head.",
        );
        for (service, metrics) in state.iter() {
            let mut cumulative = 0;
            for (bound, count) in LATENCY_BUCKETS.iter().zip(&metrics.buckets) {
                cumulative += count;
                sample(
                    &mut out,
                    "azuifer_http_request_duration_seconds_bucket",
                    &format!("service=\"{service}\",le=\"{bound}\""),
                    &cumulative,
                );
            }
            sample(
                &mut out,
                "azuifer_http_request_duration_seconds_bucket",
                &format!("service=\"{service}\",le=\"+Inf\""),
                &metrics.requests(),
            );
            let labels = format!("service=\"{service}\"");
            sample(
                &mut out,
                "azuifer_http_request_duration_seconds_sum",
                &labels,
                &metrics.duration_sum,
            );
            sample(
                &mut out,
                "azuifer_http_request_duration_seconds_count",
                &labels,
                &metrics.requests(),
            );
        }
        per_service(
            &mut out,
            &state,
            "azuifer_http_request_bytes_total",
            "counter",
            "Request body bytes declared by Content-Length.",
            |metrics| metrics.request_bytes.to_string(),
        );
        per_service(
            &mut out,
            &state,
            "azuifer_http_response_bytes_total",
            "counter",
            "Response body bytes sent.",
            |metrics| metrics.response_bytes.to_string(),
        );
        per_service(
            &mut out,
            &state,
            "azuifer_http_active_requests",
            "gauge",
            "Requests currently being handled.",
            |metrics| metrics.active.to_string(),
        );
        family(&mut out, "azuifer_build_info", "gauge", "Azuifer version.");
        sample(
            &mut out,
            "azuifer_build_info",
            &format!("version=\"{}\"", env!("CARGO_PKG_VERSION")),
            &1,
        );
        family(
            &mut out,
            "azuifer_uptime_seconds",
            "gauge",
            "Seconds since the process started serving.",
        );
        sample(&mut out, "azuifer_uptime_seconds", "", &uptime.as_secs());
        out
    }
}

pub(crate) fn family(out: &mut String, name: &str, kind: &str, help: &str) {
    let _ = writeln!(out, "# HELP {name} {help}\n# TYPE {name} {kind}");
}

pub(crate) fn sample(out: &mut String, name: &str, labels: &str, value: &dyn std::fmt::Display) {
    if labels.is_empty() {
        let _ = writeln!(out, "{name} {value}");
    } else {
        let _ = writeln!(out, "{name}{{{labels}}} {value}");
    }
}

fn per_service(
    out: &mut String,
    state: &BTreeMap<&'static str, ServiceMetrics>,
    name: &str,
    kind: &str,
    help: &str,
    value: impl Fn(&ServiceMetrics) -> String,
) {
    family(out, name, kind, help);
    for (service, metrics) in state {
        sample(
            out,
            name,
            &format!("service=\"{service}\""),
            &value(metrics),
        );
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn line<'a>(text: &'a str, prefix: &str) -> &'a str {
        text.lines()
            .find(|line| line.starts_with(prefix))
            .unwrap_or_else(|| panic!("missing `{prefix}` in:\n{text}"))
    }

    #[test]
    fn renders_per_service_counts_buckets_and_bytes() {
        let metrics = Metrics::new(["blob", "queue"]);
        metrics.adjust_active("blob", 1);
        metrics.record("blob", 200, Duration::from_millis(3), 10);
        metrics.record("blob", 200, Duration::from_millis(30), 5);
        metrics.record("blob", 404, Duration::from_secs(20), 0);
        metrics.add_response_bytes("blob", 100);
        let text = metrics.render_requests(Duration::from_secs(7));

        assert_eq!(
            line(
                &text,
                "azuifer_http_requests_total{service=\"blob\",status=\"200\"}"
            ),
            "azuifer_http_requests_total{service=\"blob\",status=\"200\"} 2"
        );
        assert!(text.contains("azuifer_http_requests_total{service=\"blob\",status=\"404\"} 1"));
        assert!(!text.contains("service=\"queue\",status"));
        assert!(text.contains(
            "azuifer_http_request_duration_seconds_bucket{service=\"blob\",le=\"0.005\"} 1"
        ));
        assert!(text.contains(
            "azuifer_http_request_duration_seconds_bucket{service=\"blob\",le=\"0.05\"} 2"
        ));
        assert!(text.contains(
            "azuifer_http_request_duration_seconds_bucket{service=\"blob\",le=\"+Inf\"} 3"
        ));
        assert!(text.contains("azuifer_http_request_duration_seconds_count{service=\"blob\"} 3"));
        assert!(text.contains("azuifer_http_request_bytes_total{service=\"blob\"} 15"));
        assert!(text.contains("azuifer_http_response_bytes_total{service=\"blob\"} 100"));
        assert!(text.contains("azuifer_http_active_requests{service=\"blob\"} 1"));
        assert!(text.contains("azuifer_http_active_requests{service=\"queue\"} 0"));
        assert!(text.contains("azuifer_uptime_seconds 7"));
        assert!(text.contains("# TYPE azuifer_http_request_duration_seconds histogram"));
    }

    #[test]
    fn active_requests_return_to_zero() {
        let metrics = Metrics::new(["table"]);
        metrics.adjust_active("table", 1);
        metrics.adjust_active("table", -1);
        let text = metrics.render_requests(Duration::ZERO);
        assert!(text.contains("azuifer_http_active_requests{service=\"table\"} 0"));
    }
}
