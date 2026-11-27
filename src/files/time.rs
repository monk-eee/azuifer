//! Wire forms of the timestamps FileREST exchanges. Share and file bookkeeping
//! times are Unix milliseconds; SMB timestamps keep 100 ns ticks.

use crate::{clock, sas};
use std::time::{Duration, UNIX_EPOCH};

pub(crate) const TICKS_PER_MILLI: i64 = 10_000;
const TICKS_PER_SECOND: i64 = 10_000_000;
const TICKS_PER_DAY: i64 = 86_400 * TICKS_PER_SECOND;

/// `2023-11-03T12:30:15.1230000Z`: the seven-digit ISO 8601 form used by share
/// snapshot identifiers.
pub(crate) fn iso(millis: i64) -> String {
    iso_ticks(millis.saturating_mul(TICKS_PER_MILLI))
}

/// The same form for SMB timestamps, which Windows clients such as AzCopy
/// compare at 100 ns precision when deciding whether a file changed.
pub(crate) fn iso_ticks(ticks: i64) -> String {
    let ticks = ticks.max(0);
    let (days, rest) = (ticks / TICKS_PER_DAY, ticks % TICKS_PER_DAY);
    let (year, month, day) = civil_from_days(days);
    let seconds = rest / TICKS_PER_SECOND;
    format!(
        "{year:04}-{month:02}-{day:02}T{:02}:{:02}:{:02}.{:07}Z",
        seconds / 3600,
        seconds % 3600 / 60,
        seconds % 60,
        rest % TICKS_PER_SECOND
    )
}

/// Parses the ISO forms [`iso`] and SDKs produce, to Unix milliseconds.
pub(crate) fn parse_iso(value: &str) -> Option<i64> {
    sas::parse_time(value).ok().map(clock::to_millis)
}

/// Parses an ISO time to Unix 100 ns ticks, keeping up to seven fraction digits.
pub(crate) fn parse_iso_ticks(value: &str) -> Option<i64> {
    let millis = parse_iso(value)?;
    let fraction = value.split_once('.').map_or("", |(_, rest)| rest);
    let padded = format!("{:0<7}", fraction.trim_end_matches('Z'));
    let sub_milli: i64 = padded.get(3..7)?.parse().ok()?;
    Some(millis * TICKS_PER_MILLI + sub_milli)
}
/// RFC 1123 date for `Last-Modified` and `Date` headers.
pub(crate) fn http_date(millis: i64) -> String {
    let millis = u64::try_from(millis).unwrap_or(0);
    httpdate::fmt_http_date(UNIX_EPOCH + Duration::from_millis(millis))
}

// Howard Hinnant's civil-from-days algorithm.
fn civil_from_days(days: i64) -> (i64, i64, i64) {
    let shifted = days + 719_468;
    let era = shifted.div_euclid(146_097);
    let day_of_era = shifted.rem_euclid(146_097);
    let year_of_era =
        (day_of_era - day_of_era / 1460 + day_of_era / 36_524 - day_of_era / 146_096) / 365;
    let day_of_year = day_of_era - (365 * year_of_era + year_of_era / 4 - year_of_era / 100);
    let month_prime = (5 * day_of_year + 2) / 153;
    let day = day_of_year - (153 * month_prime + 2) / 5 + 1;
    let month = if month_prime < 10 {
        month_prime + 3
    } else {
        month_prime - 9
    };
    let year = year_of_era + era * 400 + i64::from(month <= 2);
    (year, month, day)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn formats_seven_fraction_digits() {
        assert_eq!(iso(0), "1970-01-01T00:00:00.0000000Z");
        assert_eq!(iso(1_699_014_615_123), "2023-11-03T12:30:15.1230000Z");
        assert_eq!(iso(1_709_164_800_000), "2024-02-29T00:00:00.0000000Z");
    }

    #[test]
    fn iso_round_trips_through_the_parser() {
        for millis in [0, 999, 1_699_014_615_123, 4_102_444_800_001] {
            assert_eq!(parse_iso(&iso(millis)), Some(millis));
        }
        assert_eq!(parse_iso("not a time"), None);
        assert_eq!(parse_iso("2023-11-03T12:30:15"), None);
    }

    #[test]
    fn smb_timestamps_keep_100_nanosecond_ticks() {
        let ticks = parse_iso_ticks("2026-11-25T09:42:48.4240173Z").unwrap();
        assert_eq!(iso_ticks(ticks), "2026-11-25T09:42:48.4240173Z");
        assert_eq!(
            ticks / TICKS_PER_MILLI,
            parse_iso("2026-11-25T09:42:48.424Z").unwrap()
        );
        assert_eq!(
            parse_iso_ticks("2023-11-03T12:30:15Z"),
            Some(16_990_146_150_000_000)
        );
        assert_eq!(
            parse_iso_ticks("2023-11-03T12:30:15.5Z"),
            Some(16_990_146_155_000_000)
        );
        assert_eq!(parse_iso_ticks("not a time"), None);
    }

    #[test]
    fn http_dates_use_rfc_1123() {
        assert_eq!(
            http_date(1_699_014_615_123),
            "Fri, 03 Nov 2023 12:30:15 GMT"
        );
    }

    #[test]
    fn hostile_timestamps_are_refused_or_survive_a_round_trip() {
        crate::hostile::sweep(
            &[
                "2026-11-25T09:42:48.4240173Z",
                "9999-12-31T23:59:59.9999999Z",
            ],
            ("0", "Z"),
            |text| {
                if let Some(ticks) = parse_iso_ticks(text) {
                    assert_eq!(parse_iso_ticks(&iso_ticks(ticks)), Some(ticks), "{text:?}");
                    let _ = http_date(ticks / TICKS_PER_MILLI);
                }
            },
        );
    }
}
