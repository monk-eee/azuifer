use crate::domain::{Error, Result};
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
