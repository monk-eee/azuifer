use crate::{
    auth::{self, Query},
    domain::{Error, Result},
};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

/// Service-independent view of a Shared Access Signature (ADR-0011).
///
/// Each service builds its own string-to-sign from the raw fields and then
/// calls [`Sas::verify`]; the window, permission, and signature checks are shared.
pub(crate) struct Sas {
    fields: Query,
    start: Option<SystemTime>,
    expiry: Option<SystemTime>,
}

impl Sas {
    /// Returns `None` when the query carries no `sig`, so the caller falls back
    /// to header authentication. A stored access policy may supply `se`, so its
    /// absence is only an error when [`Sas::check_window`] needs it.
    pub(crate) fn from_query(query: &Query) -> Result<Option<Self>> {
        if !query.contains_key("sig") {
            return Ok(None);
        }
        let time = |name: &str| query.get(name).map(|value| parse_time(value)).transpose();
        Ok(Some(Self {
            start: time("st")?,
            expiry: time("se")?,
            fields: query.clone(),
        }))
    }

    pub(crate) fn start(&self) -> Option<SystemTime> {
        self.start
    }

    pub(crate) fn expiry(&self) -> Option<SystemTime> {
        self.expiry
    }

    /// The field exactly as sent, or an empty string. String-to-sign values must
    /// echo the client's text, not a re-serialised form.
    pub(crate) fn field(&self, name: &str) -> &str {
        self.fields.get(name).map_or("", String::as_str)
    }

    pub(crate) fn has(&self, name: &str) -> bool {
        self.fields.contains_key(name)
    }

    /// Validity window of this token; used by the Queue and Table services.
    pub(crate) fn check_window(&self, now: SystemTime) -> Result<()> {
        check_window(self.start, self.expiry, now)
    }

    /// True when `sp` grants every letter in `required`.
    pub(crate) fn allows(&self, required: &str) -> bool {
        let granted = self.field("sp");
        required.chars().all(|letter| granted.contains(letter))
    }

    pub(crate) fn signature(&self) -> &str {
        self.field("sig")
    }

    /// Checks the signature against any configured key.
    pub(crate) fn verify(&self, keys: &[Vec<u8>], string_to_sign: &str) -> Result<()> {
        auth::verify_signature(keys, string_to_sign, self.signature())
    }
}

/// A token is valid from `start` (inclusive) until `expiry` (exclusive); an expiry is required.
pub(crate) fn check_window(
    start: Option<SystemTime>,
    expiry: Option<SystemTime>,
    now: SystemTime,
) -> Result<()> {
    let expiry = expiry.ok_or(Error::AuthenticationFailed)?;
    if start.is_some_and(|start| now < start) || now >= expiry {
        return Err(Error::AuthenticationFailed);
    }
    Ok(())
}

/// Parses the ISO 8601 UTC forms SAS tokens use: `YYYY-MM-DD`,
/// `YYYY-MM-DDThh:mmZ`, and `YYYY-MM-DDThh:mm:ss[.fff]Z`.
pub(crate) fn parse_time(value: &str) -> Result<SystemTime> {
    let bad = Error::AuthenticationFailed;
    let (date, time) = match value.split_once('T') {
        Some((date, time)) => (date, Some(time.strip_suffix('Z').ok_or(bad)?)),
        None => (value, None),
    };
    let mut parts = date.split('-');
    let mut number = |digits: usize| -> Result<i64> {
        let part = parts.next().ok_or(bad)?;
        if part.len() != digits || !part.bytes().all(|b| b.is_ascii_digit()) {
            return Err(bad);
        }
        part.parse().map_err(|_| bad)
    };
    let (year, month, day) = (number(4)?, number(2)?, number(2)?);
    if parts.next().is_some() || !(1..=12).contains(&month) || !(1..=31).contains(&day) {
        return Err(bad);
    }
    let mut seconds = days_from_civil(year, month, day) * 86_400;
    let mut millis = 0;
    if let Some(time) = time {
        let (clock, fraction) = time.split_once('.').unwrap_or((time, ""));
        let mut fields = clock.split(':');
        let hour: i64 = fields.next().and_then(|v| v.parse().ok()).ok_or(bad)?;
        let minute: i64 = fields.next().and_then(|v| v.parse().ok()).ok_or(bad)?;
        let second: i64 = match fields.next() {
            Some(value) => value.parse().map_err(|_| bad)?,
            None => 0,
        };
        if fields.next().is_some() || hour > 23 || minute > 59 || second > 59 {
            return Err(bad);
        }
        if !fraction.bytes().all(|b| b.is_ascii_digit()) {
            return Err(bad);
        }
        let padded = format!("{fraction:0<3}");
        millis = padded[..3].parse::<u64>().map_err(|_| bad)?;
        seconds += hour * 3600 + minute * 60 + second;
    }
    let seconds = u64::try_from(seconds).map_err(|_| bad)?;
    Ok(UNIX_EPOCH + Duration::from_secs(seconds) + Duration::from_millis(millis))
}

// Howard Hinnant's days-from-civil algorithm.
fn days_from_civil(year: i64, month: i64, day: i64) -> i64 {
    let year = if month <= 2 { year - 1 } else { year };
    let era = year.div_euclid(400);
    let year_of_era = year - era * 400;
    let shifted = (month + 9) % 12;
    let day_of_year = (153 * shifted + 2) / 5 + day - 1;
    let day_of_era = year_of_era * 365 + year_of_era / 4 - year_of_era / 100 + day_of_year;
    era * 146_097 + day_of_era - 719_468
}

#[cfg(test)]
mod tests {
    use super::*;

    fn secs(value: &str) -> u64 {
        parse_time(value)
            .unwrap()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs()
    }

    #[test]
    fn parses_every_sas_time_form() {
        assert_eq!(secs("1970-01-01"), 0);
        assert_eq!(secs("2023-11-03T12:30Z"), 1_699_014_600);
        assert_eq!(secs("2023-11-03T12:30:15Z"), 1_699_014_615);
        assert_eq!(secs("2024-02-29T00:00:00.123Z"), 1_709_164_800);
        assert!(parse_time("2023-11-03T12:30:15").is_err());
        assert!(parse_time("2023-13-01").is_err());
        assert!(parse_time("garbage").is_err());
    }

    #[test]
    fn window_is_enforced_and_unsigned_queries_are_not_sas() {
        let query = Query::from([
            ("se".into(), "2030-01-01T00:00:00Z".into()),
            ("st".into(), "2029-01-01T00:00:00Z".into()),
            ("sp".into(), "rw".into()),
            ("sig".into(), "x".into()),
        ]);
        let sas = Sas::from_query(&query).unwrap().unwrap();
        let window = |now| check_window(sas.start(), sas.expiry(), parse_time(now).unwrap());
        assert!(window("2028-06-01").is_err());
        assert!(window("2029-06-01").is_ok());
        assert!(window("2030-06-01").is_err());
        assert!(check_window(None, None, parse_time("2029-06-01").unwrap()).is_err());
        assert!(Sas::from_query(&Query::new()).unwrap().is_none());
    }
}
