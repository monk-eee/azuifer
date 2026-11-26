//! Timestamp identifiers (ADR-0018): snapshot times and version ids are 100 ns
//! ticks since the Unix epoch, shown as `YYYY-MM-DDThh:mm:ss.fffffffZ`.

use crate::domain::{Error, Result};

const TICKS_PER_SECOND: i64 = 10_000_000;
const TICKS_PER_MILLI: i64 = 10_000;

#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub(crate) struct Ticks(pub(crate) i64);

impl Ticks {
    pub(crate) fn from_millis(millis: i64) -> Self {
        Self(millis.saturating_mul(TICKS_PER_MILLI))
    }

    pub(crate) fn from_seconds(seconds: u64) -> Self {
        Self(i64::try_from(seconds).map_or(i64::MAX, |s| s.saturating_mul(TICKS_PER_SECOND)))
    }

    /// Parses the wire form. Fractions of one to seven digits are accepted, so a
    /// client that trims trailing zeros still addresses the same instant.
    pub(crate) fn parse(text: &str) -> Result<Self> {
        let bytes = text.as_bytes();
        let number = |range: std::ops::Range<usize>| -> Option<i64> {
            let digits = bytes.get(range)?;
            if digits.is_empty() || !digits.iter().all(u8::is_ascii_digit) {
                return None;
            }
            std::str::from_utf8(digits).ok()?.parse().ok()
        };
        let parsed = (|| {
            let separators = [(4, b'-'), (7, b'-'), (10, b'T'), (13, b':'), (16, b':')];
            if bytes.len() < 20
                || !separators
                    .iter()
                    .all(|(at, byte)| bytes.get(*at) == Some(byte))
                || bytes.last() != Some(&b'Z')
            {
                return None;
            }
            let (year, month, day) = (number(0..4)?, number(5..7)?, number(8..10)?);
            let (hour, minute, second) = (number(11..13)?, number(14..16)?, number(17..19)?);
            let fraction = match bytes.len() {
                20 => 0,
                len if (22..=28).contains(&len) && bytes[19] == b'.' => {
                    let digits = number(20..len - 1)?;
                    digits * 10_i64.pow(u32::try_from(28 - len).ok()?)
                }
                _ => return None,
            };
            let leap = year % 4 == 0 && (year % 100 != 0 || year % 400 == 0);
            let month_days = match month {
                1 | 3 | 5 | 7 | 8 | 10 | 12 => 31,
                4 | 6 | 9 | 11 => 30,
                2 if leap => 29,
                2 => 28,
                _ => return None,
            };
            if year < 1970
                || day == 0
                || day > month_days
                || hour > 23
                || minute > 59
                || second > 59
            {
                return None;
            }
            let seconds =
                days_from_civil(year, month, day) * 86_400 + hour * 3600 + minute * 60 + second;
            Some(seconds * TICKS_PER_SECOND + fraction)
        })();
        parsed.map(Self).ok_or(Error::InvalidQuery)
    }

    pub(crate) fn text(self) -> String {
        let seconds = self.0.div_euclid(TICKS_PER_SECOND);
        let fraction = self.0.rem_euclid(TICKS_PER_SECOND);
        let (year, month, day) = civil_from_days(seconds.div_euclid(86_400));
        let rest = seconds.rem_euclid(86_400);
        format!(
            "{year:04}-{month:02}-{day:02}T{:02}:{:02}:{:02}.{fraction:07}Z",
            rest / 3600,
            rest % 3600 / 60,
            rest % 60
        )
    }
}

/// Days from 1970-01-01 to a proleptic Gregorian date (Howard Hinnant's algorithm).
fn days_from_civil(year: i64, month: i64, day: i64) -> i64 {
    let year = year - i64::from(month <= 2);
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
    let day_of_era = z - era * 146_097;
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
    (year_of_era + era * 400 + i64::from(month <= 2), month, day)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ticks_round_trip_through_the_wire_form() {
        let ticks = Ticks::from_millis(1_700_000_000_123);
        assert_eq!(ticks.text(), "2023-11-14T22:13:20.1230000Z");
        assert_eq!(Ticks::parse(&ticks.text()), Ok(ticks));
        assert_eq!(
            Ticks::parse("2023-11-14T22:13:20Z"),
            Ok(Ticks::from_seconds(1_699_999_999 + 1))
        );
        assert_eq!(
            Ticks::parse("2023-11-14T22:13:20.5Z"),
            Ok(Ticks(17_000_000_005_000_000))
        );
        assert_eq!(
            Ticks::parse("2024-02-29T00:00:00.0000001Z").map(|t| t.0 % 10_000_000),
            Ok(1)
        );
    }

    #[test]
    fn malformed_times_are_rejected() {
        for bad in [
            "",
            "yesterday",
            "2023-11-14T22:13:20",
            "2023-11-14 22:13:20Z",
            "2023-13-14T22:13:20Z",
            "2023-02-29T22:13:20Z",
            "2023-11-14T24:13:20Z",
            "2023-11-14T22:13:20.Z",
            "2023-11-14T22:13:20.12345678Z",
            "1969-12-31T23:59:59Z",
        ] {
            assert_eq!(Ticks::parse(bad), Err(Error::InvalidQuery), "{bad}");
        }
    }

    #[test]
    fn ordering_follows_time() {
        assert!(
            Ticks::parse("2023-11-14T22:13:20.0000002Z").unwrap()
                > Ticks::parse("2023-11-14T22:13:20.0000001Z").unwrap()
        );
    }
}
