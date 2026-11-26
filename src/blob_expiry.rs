//! Set Blob Expiry: the four expiry options and how each becomes a deadline on the
//! shared clock (ADR-0012). A blob past its deadline is removed lazily by the store.

use crate::{
    auth::header,
    domain::{Error, Result},
};
use axum::http::HeaderMap;

/// `x-ms-expiry-option` with the meaning of `x-ms-expiry-time` for that option.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum ExpiryOption {
    /// Milliseconds after the blob's creation time.
    RelativeToCreation(u64),
    /// Milliseconds after the request.
    RelativeToNow(u64),
    /// A point in time, in Unix milliseconds.
    Absolute(i64),
    NeverExpire,
}

impl ExpiryOption {
    pub(crate) fn parse(headers: &HeaderMap) -> Result<Self> {
        let option = header(headers, "x-ms-expiry-option")?.ok_or(Error::MissingHeader)?;
        let time = header(headers, "x-ms-expiry-time")?;
        let relative = |time: Option<&str>| -> Result<u64> {
            time.ok_or(Error::MissingHeader)?
                .parse()
                .map_err(|_| Error::InvalidHeader)
        };
        match option.to_ascii_lowercase().as_str() {
            "neverexpire" if time.is_none() => Ok(Self::NeverExpire),
            "neverexpire" => Err(Error::InvalidHeader),
            "relativetocreation" => Ok(Self::RelativeToCreation(relative(time)?)),
            "relativetonow" => Ok(Self::RelativeToNow(relative(time)?)),
            "absolute" => {
                let at = httpdate::parse_http_date(time.ok_or(Error::MissingHeader)?)
                    .map_err(|_| Error::InvalidHeader)?;
                Ok(Self::Absolute(crate::clock::to_millis(at)))
            }
            _ => Err(Error::InvalidHeader),
        }
    }

    /// The deadline in Unix milliseconds, or `None` to remove the expiry. A
    /// deadline that is not after `now` is refused, as Azure refuses past times.
    pub(crate) fn deadline(self, created_seconds: u64, now: i64) -> Result<Option<i64>> {
        let millis = |value: u64| i64::try_from(value).map_err(|_| Error::InvalidHeader);
        let deadline = match self {
            Self::NeverExpire => return Ok(None),
            Self::RelativeToCreation(after) => i64::try_from(created_seconds)
                .ok()
                .and_then(|created| created.checked_mul(1000))
                .and_then(|created| created.checked_add(millis(after).ok()?))
                .ok_or(Error::InvalidHeader)?,
            Self::RelativeToNow(after) => now
                .checked_add(millis(after)?)
                .ok_or(Error::InvalidHeader)?,
            Self::Absolute(at) => at,
        };
        if deadline <= now {
            return Err(Error::InvalidHeader);
        }
        Ok(Some(deadline))
    }
}

/// The `x-ms-expiry-time` and `Expiry-Time` form of a deadline.
pub(crate) fn http_time(deadline: i64) -> Result<String> {
    let seconds = u64::try_from(deadline / 1000).map_err(|_| Error::Internal)?;
    crate::respond::http_date(seconds)
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::http::HeaderValue;

    fn headers(option: &str, time: Option<&str>) -> HeaderMap {
        let mut headers = HeaderMap::new();
        headers.insert("x-ms-expiry-option", HeaderValue::from_str(option).unwrap());
        if let Some(time) = time {
            headers.insert("x-ms-expiry-time", HeaderValue::from_str(time).unwrap());
        }
        headers
    }

    #[test]
    fn options_parse_case_insensitively_with_their_time_rules() {
        assert_eq!(
            ExpiryOption::parse(&headers("RelativeToNow", Some("30000"))),
            Ok(ExpiryOption::RelativeToNow(30_000))
        );
        assert_eq!(
            ExpiryOption::parse(&headers("relativetocreation", Some("5"))),
            Ok(ExpiryOption::RelativeToCreation(5))
        );
        assert_eq!(
            ExpiryOption::parse(&headers("NeverExpire", None)),
            Ok(ExpiryOption::NeverExpire)
        );
        assert_eq!(
            ExpiryOption::parse(&headers("NeverExpire", Some("1"))),
            Err(Error::InvalidHeader)
        );
        assert_eq!(
            ExpiryOption::parse(&headers("RelativeToNow", None)),
            Err(Error::MissingHeader)
        );
        assert_eq!(
            ExpiryOption::parse(&headers("RelativeToNow", Some("soon"))),
            Err(Error::InvalidHeader)
        );
        assert_eq!(
            ExpiryOption::parse(&headers("Eventually", None)),
            Err(Error::InvalidHeader)
        );
        assert_eq!(
            ExpiryOption::parse(&HeaderMap::new()),
            Err(Error::MissingHeader)
        );
        assert_eq!(
            ExpiryOption::parse(&headers("Absolute", Some("Sun, 06 Nov 1994 08:49:37 GMT"))),
            Ok(ExpiryOption::Absolute(784_111_777_000))
        );
        assert_eq!(
            ExpiryOption::parse(&headers("Absolute", Some("tomorrow"))),
            Err(Error::InvalidHeader)
        );
    }

    #[test]
    fn deadlines_are_relative_to_creation_or_now_and_never_in_the_past() {
        let now = 1_700_000_000_000;
        assert_eq!(
            ExpiryOption::RelativeToNow(5_000).deadline(1_699_999_000, now),
            Ok(Some(now + 5_000))
        );
        assert_eq!(
            ExpiryOption::RelativeToCreation(2_000_000).deadline(1_699_999_000, now),
            Ok(Some(1_700_001_000_000))
        );
        assert_eq!(
            ExpiryOption::RelativeToCreation(1_000).deadline(1_699_999_000, now),
            Err(Error::InvalidHeader),
            "creation plus the offset is already past"
        );
        assert_eq!(
            ExpiryOption::Absolute(now).deadline(0, now),
            Err(Error::InvalidHeader)
        );
        assert_eq!(
            ExpiryOption::Absolute(now + 1).deadline(0, now),
            Ok(Some(now + 1))
        );
        assert_eq!(ExpiryOption::NeverExpire.deadline(0, now), Ok(None));
        assert_eq!(
            ExpiryOption::RelativeToNow(u64::MAX).deadline(0, now),
            Err(Error::InvalidHeader)
        );
    }

    #[test]
    fn deadlines_print_as_http_dates() {
        let time =
            std::time::SystemTime::UNIX_EPOCH + std::time::Duration::from_secs(1_700_000_000);
        assert_eq!(crate::clock::to_millis(time), 1_700_000_000_000);
        assert_eq!(
            http_time(1_700_000_000_999).unwrap(),
            "Tue, 14 Nov 2023 22:13:20 GMT"
        );
    }
}
