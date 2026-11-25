use super::error::{QueueError, Result};
use std::time::{Duration, UNIX_EPOCH};

/// Last representable HTTP date (9999-12-31T23:59:59Z), used for messages that never expire.
const NEVER_SECONDS: i64 = 253_402_300_799;

/// RFC 1123 date used in queue XML bodies and `x-ms-time-next-visible`.
pub(super) fn http_date(millis: i64) -> Result<String> {
    let seconds = u64::try_from(millis.div_euclid(1000).clamp(0, NEVER_SECONDS))
        .map_err(|_| QueueError::Internal)?;
    Ok(httpdate::fmt_http_date(
        UNIX_EPOCH + Duration::from_secs(seconds),
    ))
}

pub(super) fn never_expires() -> Result<String> {
    http_date(NEVER_SECONDS * 1000)
}

/// ISO 8601 UTC with seven fractional digits, the form Azure returns for
/// access policies and error timestamps.
pub(super) fn iso8601(millis: i64) -> String {
    let millis = millis.clamp(0, NEVER_SECONDS * 1000);
    let seconds = millis.div_euclid(1000);
    let (year, month, day) = civil(seconds.div_euclid(86_400));
    let rest = seconds.rem_euclid(86_400);
    format!(
        "{year:04}-{month:02}-{day:02}T{:02}:{:02}:{:02}.{:03}0000Z",
        rest / 3600,
        rest % 3600 / 60,
        rest % 60,
        millis.rem_euclid(1000)
    )
}

// Howard Hinnant's civil-from-days algorithm.
fn civil(days: i64) -> (i64, i64, i64) {
    let shifted = days + 719_468;
    let era = shifted.div_euclid(146_097);
    let day_of_era = shifted.rem_euclid(146_097);
    let year_of_era =
        (day_of_era - day_of_era / 1460 + day_of_era / 36_524 - day_of_era / 146_096) / 365;
    let day_of_year = day_of_era - (365 * year_of_era + year_of_era / 4 - year_of_era / 100);
    let month_index = (5 * day_of_year + 2) / 153;
    let day = day_of_year - (153 * month_index + 2) / 5 + 1;
    let month = if month_index < 10 {
        month_index + 3
    } else {
        month_index - 9
    };
    let year = year_of_era + era * 400 + i64::from(month <= 2);
    (year, month, day)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn formats_known_instants() {
        assert_eq!(iso8601(0), "1970-01-01T00:00:00.0000000Z");
        assert_eq!(iso8601(1_709_164_800_123), "2024-02-29T00:00:00.1230000Z");
        assert_eq!(
            http_date(1_699_014_615_000).unwrap(),
            "Fri, 03 Nov 2023 12:30:15 GMT"
        );
        assert_eq!(never_expires().unwrap(), "Fri, 31 Dec 9999 23:59:59 GMT");
        assert_eq!(iso8601(i64::MAX), "9999-12-31T23:59:59.0000000Z");
    }
}
