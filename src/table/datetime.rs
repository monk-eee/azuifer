//! `Edm.DateTime` and `Timestamp` values as 100 ns ticks since the Unix epoch.

use std::time::{SystemTime, UNIX_EPOCH};

const TICKS_PER_SECOND: i64 = 10_000_000;
const TICKS_PER_DAY: i64 = 86_400 * TICKS_PER_SECOND;
// The Table service accepts 1601-01-01T00:00:00Z through 9999-12-31T23:59:59.9999999Z.
const MIN: i64 = -11_644_473_600 * TICKS_PER_SECOND;
const MAX: i64 = 253_402_300_799 * TICKS_PER_SECOND + 9_999_999;

#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub(super) struct Ticks(i64);

impl Ticks {
    pub(super) fn new(ticks: i64) -> Option<Self> {
        (MIN..=MAX).contains(&ticks).then_some(Self(ticks))
    }

    pub(super) fn get(self) -> i64 {
        self.0
    }

    pub(super) fn from_system(time: SystemTime) -> Self {
        let ticks = match time.duration_since(UNIX_EPOCH) {
            Ok(after) => i64::try_from(after.as_nanos() / 100).unwrap_or(MAX),
            Err(before) => -i64::try_from(before.duration().as_nanos() / 100).unwrap_or(MAX),
        };
        Self(ticks.clamp(MIN, MAX))
    }

    /// The next distinct tick, used to keep modification times strictly increasing.
    pub(super) fn after(self) -> Self {
        Self((self.0 + 1).min(MAX))
    }

    /// Parses `YYYY-MM-DDThh:mm:ss[.f{1,7}]` followed by `Z`, a `±hh:mm` offset, or nothing (UTC).
    pub(super) fn parse(text: &str) -> Option<Self> {
        let bytes = text.as_bytes();
        let digits = |range: std::ops::Range<usize>| -> Option<i64> {
            let part = bytes.get(range)?;
            if part.is_empty() || !part.iter().all(u8::is_ascii_digit) {
                return None;
            }
            std::str::from_utf8(part).ok()?.parse().ok()
        };
        if bytes.get(4) != Some(&b'-')
            || bytes.get(7) != Some(&b'-')
            || bytes.get(10) != Some(&b'T')
            || bytes.get(13) != Some(&b':')
            || bytes.get(16) != Some(&b':')
        {
            return None;
        }
        let (year, month, day) = (digits(0..4)?, digits(5..7)?, digits(8..10)?);
        let (hour, minute, second) = (digits(11..13)?, digits(14..16)?, digits(17..19)?);
        if !(1..=12).contains(&month)
            || day < 1
            || day > days_in_month(year, month)
            || hour > 23
            || minute > 59
            || second > 59
        {
            return None;
        }
        let mut position = 19;
        let mut fraction = 0;
        if bytes.get(position) == Some(&b'.') {
            let start = position + 1;
            let mut end = start;
            while bytes.get(end).is_some_and(u8::is_ascii_digit) {
                end += 1;
            }
            if end == start || end - start > 7 {
                return None;
            }
            fraction = digits(start..end)? * 10_i64.pow(u32::try_from(7 - (end - start)).ok()?);
            position = end;
        }
        let offset = match text.get(position..)? {
            "" | "Z" => 0,
            zone => {
                let sign = match zone.as_bytes().first()? {
                    b'+' => 1,
                    b'-' => -1,
                    _ => return None,
                };
                let (h, m) = zone.get(1..)?.split_once(':')?;
                if h.len() != 2 || m.len() != 2 {
                    return None;
                }
                let (h, m): (i64, i64) = (h.parse().ok()?, m.parse().ok()?);
                if h > 23 || m > 59 {
                    return None;
                }
                sign * (h * 3600 + m * 60)
            }
        };
        let seconds =
            days_from_civil(year, month, day) * 86_400 + hour * 3600 + minute * 60 + second
                - offset;
        Self::new(seconds * TICKS_PER_SECOND + fraction)
    }

    /// `YYYY-MM-DDThh:mm:ss.fffffffZ`, the form the service uses for `Timestamp`.
    pub(super) fn format(self) -> String {
        self.render(true)
    }

    /// Like [`Self::format`] but without a fraction when the value is a whole second.
    pub(super) fn format_trimmed(self) -> String {
        self.render(false)
    }

    fn render(self, always_fraction: bool) -> String {
        let days = self.0.div_euclid(TICKS_PER_DAY);
        let in_day = self.0.rem_euclid(TICKS_PER_DAY);
        let (year, month, day) = civil_from_days(days);
        let seconds = in_day / TICKS_PER_SECOND;
        let fraction = in_day % TICKS_PER_SECOND;
        let mut text = format!(
            "{year:04}-{month:02}-{day:02}T{:02}:{:02}:{:02}",
            seconds / 3600,
            seconds / 60 % 60,
            seconds % 60
        );
        if always_fraction || fraction != 0 {
            text.push_str(&format!(".{fraction:07}"));
        }
        text.push('Z');
        text
    }
}

fn days_in_month(year: i64, month: i64) -> i64 {
    let leap = year % 4 == 0 && (year % 100 != 0 || year % 400 == 0);
    match month {
        2 if leap => 29,
        2 => 28,
        4 | 6 | 9 | 11 => 30,
        _ => 31,
    }
}

// Howard Hinnant's civil-date algorithms.
fn days_from_civil(year: i64, month: i64, day: i64) -> i64 {
    let year = if month <= 2 { year - 1 } else { year };
    let era = year.div_euclid(400);
    let year_of_era = year - era * 400;
    let shifted = (month + 9) % 12;
    let day_of_year = (153 * shifted + 2) / 5 + day - 1;
    let day_of_era = year_of_era * 365 + year_of_era / 4 - year_of_era / 100 + day_of_year;
    era * 146_097 + day_of_era - 719_468
}

fn civil_from_days(days: i64) -> (i64, i64, i64) {
    let z = days + 719_468;
    let era = z.div_euclid(146_097);
    let day_of_era = z.rem_euclid(146_097);
    let year_of_era =
        (day_of_era - day_of_era / 1460 + day_of_era / 36_524 - day_of_era / 146_096) / 365;
    let day_of_year = day_of_era - (365 * year_of_era + year_of_era / 4 - year_of_era / 100);
    let shifted = (5 * day_of_year + 2) / 153;
    let day = day_of_year - (153 * shifted + 2) / 5 + 1;
    let month = if shifted < 10 {
        shifted + 3
    } else {
        shifted - 9
    };
    let year = year_of_era + era * 400 + i64::from(month <= 2);
    (year, month, day)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn formats_and_parses_round_trip_including_boundaries() {
        for text in [
            "1970-01-01T00:00:00.0000000Z",
            "2013-08-22T01:12:06.2608595Z",
            "1601-01-01T00:00:00.0000000Z",
            "9999-12-31T23:59:59.9999999Z",
            "2024-02-29T12:00:00.5000000Z",
        ] {
            assert_eq!(Ticks::parse(text).unwrap().format(), text);
        }
        assert_eq!(
            Ticks::parse("2008-07-10T00:00:00Z")
                .unwrap()
                .format_trimmed(),
            "2008-07-10T00:00:00Z"
        );
        assert_eq!(Ticks::parse("1970-01-01T00:00:00Z").unwrap().get(), 0);
    }

    #[test]
    fn accepts_offsets_and_missing_zone_and_rejects_bad_values() {
        assert_eq!(
            Ticks::parse("2008-07-10T02:00:00+02:00"),
            Ticks::parse("2008-07-10T00:00:00")
        );
        for bad in [
            "2008-07-10",
            "2008-13-01T00:00:00Z",
            "2023-02-29T00:00:00Z",
            "2008-07-10T24:00:00Z",
            "1600-12-31T23:59:59Z",
            "2008-07-10T00:00:00.12345678Z",
            "2008-07-10T00:00:00X",
        ] {
            assert!(Ticks::parse(bad).is_none(), "{bad}");
        }
    }

    #[test]
    fn system_time_conversion_keeps_100ns_resolution() {
        let time = UNIX_EPOCH + std::time::Duration::from_nanos(1_700_000_000_123_456_700);
        assert_eq!(
            Ticks::from_system(time).format(),
            "2023-11-14T22:13:20.1234567Z"
        );
    }
}
