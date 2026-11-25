use crate::{
    domain::{Error, Result},
    respond::error_response,
};
use axum::{
    Router,
    body::Body,
    extract::{Request, State},
    http::{HeaderValue, Method, request::Parts},
    response::Response,
    routing::any,
};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

/// Time source for TTLs, visibility, leases, and SAS validity (ADR-0012).
///
/// The system clock is used unless `--test-clock` enables a manual offset.
#[derive(Clone)]
pub(crate) struct Clock(std::sync::Arc<std::sync::atomic::AtomicI64>);

impl Clock {
    pub(crate) fn new() -> Self {
        Self(std::sync::Arc::default())
    }

    pub(crate) fn now(&self) -> SystemTime {
        let offset = self.0.load(std::sync::atomic::Ordering::Relaxed);
        let base = SystemTime::now();
        let shift = Duration::from_millis(offset.unsigned_abs());
        if offset >= 0 {
            base + shift
        } else {
            base - shift
        }
    }

    /// Unix milliseconds, the form persisted in every store.
    pub(crate) fn now_millis(&self) -> i64 {
        to_millis(self.now())
    }

    pub(crate) fn advance(&self, by: Duration) {
        let millis = i64::try_from(by.as_millis()).unwrap_or(i64::MAX);
        self.0
            .fetch_add(millis, std::sync::atomic::Ordering::Relaxed);
    }
}

/// `--test-clock`: read the clock with `GET /_azuifer/clock` and move it with
/// `POST /_azuifer/clock/advance?seconds=N` (or `ms=N`), so leases, visibility,
/// TTLs, and SAS expiry can be tested without sleeping (ADR-0012).
pub(crate) fn endpoint(clock: &Clock, parts: &Parts) -> Response {
    let path = parts.uri.path();
    if parts.method == Method::POST && path == "/_azuifer/clock/advance" {
        let amount = parts
            .uri
            .query()
            .unwrap_or_default()
            .split('&')
            .find_map(|pair| {
                let (name, value) = pair.split_once('=')?;
                let value: u64 = value.parse().ok()?;
                match name {
                    "ms" => Some(Duration::from_millis(value)),
                    "seconds" => Some(Duration::from_secs(value)),
                    _ => None,
                }
            });
        match amount {
            Some(amount) => clock.advance(amount),
            None => return error_response(Error::InvalidQuery),
        }
    } else if !(parts.method == Method::GET && path == "/_azuifer/clock") {
        return error_response(Error::Unsupported);
    }
    let mut response = Response::new(Body::from(format!(
        "{{\"unix_ms\":{}}}",
        clock.now_millis()
    )));
    response
        .headers_mut()
        .insert("content-type", HeaderValue::from_static("application/json"));
    response
}

/// The test-clock endpoints for the admin listener.
pub(crate) fn router(clock: Clock) -> Router {
    async fn handle(State(clock): State<Clock>, request: Request) -> Response {
        endpoint(&clock, &request.into_parts().0)
    }
    Router::new()
        .route("/_azuifer/clock", any(handle))
        .route("/_azuifer/clock/advance", any(handle))
        .with_state(clock)
}

pub(crate) fn to_millis(time: SystemTime) -> i64 {
    match time.duration_since(UNIX_EPOCH) {
        Ok(after) => i64::try_from(after.as_millis()).unwrap_or(i64::MAX),
        Err(before) => -i64::try_from(before.duration().as_millis()).unwrap_or(i64::MAX),
    }
}

/// The inverse of [`to_millis`]. Blob stores times as milliseconds and never
/// needs the reverse; the Queue and Table services convert stored times back.
#[allow(dead_code)]
pub(crate) fn from_millis(millis: i64) -> Result<SystemTime> {
    let shift = Duration::from_millis(millis.unsigned_abs());
    if millis >= 0 {
        UNIX_EPOCH.checked_add(shift)
    } else {
        UNIX_EPOCH.checked_sub(shift)
    }
    .ok_or(Error::Internal)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn advancing_moves_now_forward() {
        let clock = Clock::new();
        let before = clock.now_millis();
        clock.advance(Duration::from_secs(60));
        assert!(clock.now_millis() >= before + 60_000);
    }

    #[test]
    fn millis_round_trip() {
        let time = from_millis(1_700_000_000_123).unwrap();
        assert_eq!(to_millis(time), 1_700_000_000_123);
        assert_eq!(to_millis(from_millis(-5).unwrap()), -5);
    }
}
