//! Time-based immutability policies and legal holds on a blob: the state machine
//! and the Azure errors that block writes and deletes while a blob is protected.

use crate::{
    auth::header,
    blob_lifecycle::LifecycleError,
    domain::{Error, Result},
};
use axum::http::HeaderMap;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum PolicyMode {
    Unlocked,
    Locked,
}

impl PolicyMode {
    fn parse(value: &str) -> Result<Self> {
        match value.to_ascii_lowercase().as_str() {
            "unlocked" => Ok(Self::Unlocked),
            "locked" => Ok(Self::Locked),
            _ => Err(Error::InvalidHeader),
        }
    }

    pub(crate) fn name(self) -> &'static str {
        match self {
            Self::Unlocked => "unlocked",
            Self::Locked => "locked",
        }
    }

    /// The stored form: an empty string means no policy.
    pub(crate) fn from_stored(value: &str) -> Option<Self> {
        Self::parse(value).ok()
    }
}

/// A policy request: the retain-until time (Unix milliseconds) and mode.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct PolicyRequest {
    pub(crate) until: i64,
    pub(crate) mode: PolicyMode,
}

impl PolicyRequest {
    pub(crate) fn parse(headers: &HeaderMap) -> Result<Self> {
        let until =
            header(headers, "x-ms-immutability-policy-until-date")?.ok_or(Error::MissingHeader)?;
        let until = httpdate::parse_http_date(until).map_err(|_| Error::InvalidHeader)?;
        let mode = header(headers, "x-ms-immutability-policy-mode")?
            .map_or(Ok(PolicyMode::Unlocked), PolicyMode::parse)?;
        Ok(Self {
            until: crate::clock::to_millis(until),
            mode,
        })
    }
}

pub(crate) fn parse_legal_hold(headers: &HeaderMap) -> Result<bool> {
    match header(headers, "x-ms-legal-hold")?.ok_or(Error::MissingHeader)? {
        "true" => Ok(true),
        "false" => Ok(false),
        _ => Err(Error::InvalidHeader),
    }
}

/// The immutability policy and legal hold of a blob.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub(crate) struct Protection {
    pub(crate) until: Option<i64>,
    pub(crate) mode: Option<PolicyMode>,
    pub(crate) legal_hold: bool,
}

fn policy_error() -> Error {
    Error::Ext(LifecycleError::ImmutableDueToPolicy)
}

impl Protection {
    pub(crate) fn has_policy(&self) -> bool {
        self.until.is_some() && self.mode.is_some()
    }

    fn policy_active(&self, now: i64) -> bool {
        self.until.is_some_and(|until| until > now) && self.mode.is_some()
    }

    /// A delete is refused while a legal hold or an unexpired policy applies.
    pub(crate) fn check_delete(&self, now: i64) -> Result<()> {
        if self.legal_hold {
            return Err(Error::Ext(LifecycleError::ImmutableDueToLegalHold));
        }
        if self.policy_active(now) {
            return Err(policy_error());
        }
        Ok(())
    }

    /// Sets or replaces the policy. An unlocked policy may change freely; a locked
    /// one may only be extended and can never go back to unlocked.
    pub(crate) fn set_policy(&self, request: PolicyRequest, now: i64) -> Result<Self> {
        if request.until <= now {
            return Err(Error::InvalidHeader);
        }
        if self.mode == Some(PolicyMode::Locked) && self.policy_active(now) {
            let shortened = self.until.is_some_and(|until| request.until < until);
            if request.mode != PolicyMode::Locked || shortened {
                return Err(policy_error());
            }
        }
        Ok(Self {
            until: Some(request.until),
            mode: Some(request.mode),
            ..*self
        })
    }

    /// Removes an unlocked (or expired) policy.
    pub(crate) fn clear_policy(&self, now: i64) -> Result<Self> {
        if self.mode == Some(PolicyMode::Locked) && self.policy_active(now) {
            return Err(policy_error());
        }
        Ok(Self {
            until: None,
            mode: None,
            ..*self
        })
    }

    pub(crate) fn with_legal_hold(self, legal_hold: bool) -> Self {
        Self { legal_hold, ..self }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::http::HeaderValue;

    const NOW: i64 = 1_700_000_000_000;

    fn request(until: i64, mode: PolicyMode) -> PolicyRequest {
        PolicyRequest { until, mode }
    }

    #[test]
    fn a_legal_hold_or_unexpired_policy_blocks_deletes() {
        assert_eq!(Protection::default().check_delete(NOW), Ok(()));
        let held = Protection::default().with_legal_hold(true);
        assert_eq!(
            held.check_delete(NOW),
            Err(Error::Ext(LifecycleError::ImmutableDueToLegalHold))
        );
        let timed = Protection::default()
            .set_policy(request(NOW + 1000, PolicyMode::Unlocked), NOW)
            .unwrap();
        assert_eq!(timed.check_delete(NOW), Err(policy_error()));
        assert_eq!(
            timed.check_delete(NOW + 1000),
            Ok(()),
            "expired at its time"
        );
        assert_eq!(
            timed.with_legal_hold(true).check_delete(NOW + 5000),
            Err(Error::Ext(LifecycleError::ImmutableDueToLegalHold)),
            "a hold outlives the policy"
        );
    }

    #[test]
    fn an_unlocked_policy_changes_and_clears_freely() {
        let first = Protection::default()
            .set_policy(request(NOW + 5000, PolicyMode::Unlocked), NOW)
            .unwrap();
        let shorter = first
            .set_policy(request(NOW + 1000, PolicyMode::Unlocked), NOW)
            .unwrap();
        assert_eq!(shorter.until, Some(NOW + 1000));
        assert_eq!(first.clear_policy(NOW).unwrap(), Protection::default());
        assert_eq!(
            Protection::default().set_policy(request(NOW, PolicyMode::Locked), NOW),
            Err(Error::InvalidHeader),
            "a past or present time is refused"
        );
    }

    #[test]
    fn a_locked_policy_can_only_be_extended() {
        let locked = Protection::default()
            .set_policy(request(NOW + 5000, PolicyMode::Locked), NOW)
            .unwrap();
        assert_eq!(locked.mode, Some(PolicyMode::Locked));
        assert_eq!(locked.clear_policy(NOW), Err(policy_error()));
        assert_eq!(
            locked.set_policy(request(NOW + 1000, PolicyMode::Locked), NOW),
            Err(policy_error())
        );
        assert_eq!(
            locked.set_policy(request(NOW + 9000, PolicyMode::Unlocked), NOW),
            Err(policy_error())
        );
        let longer = locked
            .set_policy(request(NOW + 9000, PolicyMode::Locked), NOW)
            .unwrap();
        assert_eq!(longer.until, Some(NOW + 9000));
        assert_eq!(
            locked.clear_policy(NOW + 5000),
            Ok(Protection::default()),
            "an expired locked policy no longer binds"
        );
    }

    #[test]
    fn unlocked_becomes_locked_but_not_back() {
        let unlocked = Protection::default()
            .set_policy(request(NOW + 5000, PolicyMode::Unlocked), NOW)
            .unwrap();
        let locked = unlocked
            .set_policy(request(NOW + 5000, PolicyMode::Locked), NOW)
            .unwrap();
        assert_eq!(locked.mode, Some(PolicyMode::Locked));
    }

    #[test]
    fn headers_parse_with_azures_defaults() {
        let mut headers = HeaderMap::new();
        headers.insert(
            "x-ms-immutability-policy-until-date",
            HeaderValue::from_static("Sun, 06 Nov 2044 08:49:37 GMT"),
        );
        let parsed = PolicyRequest::parse(&headers).unwrap();
        assert_eq!(
            parsed.mode,
            PolicyMode::Unlocked,
            "the mode defaults to unlocked"
        );
        headers.insert(
            "x-ms-immutability-policy-mode",
            HeaderValue::from_static("Locked"),
        );
        assert_eq!(
            PolicyRequest::parse(&headers).unwrap().mode,
            PolicyMode::Locked
        );
        headers.insert(
            "x-ms-immutability-policy-mode",
            HeaderValue::from_static("Mutable"),
        );
        assert_eq!(PolicyRequest::parse(&headers), Err(Error::InvalidHeader));
        assert_eq!(
            PolicyRequest::parse(&HeaderMap::new()),
            Err(Error::MissingHeader)
        );
        let mut hold = HeaderMap::new();
        assert_eq!(parse_legal_hold(&hold), Err(Error::MissingHeader));
        hold.insert("x-ms-legal-hold", HeaderValue::from_static("true"));
        assert_eq!(parse_legal_hold(&hold), Ok(true));
        hold.insert("x-ms-legal-hold", HeaderValue::from_static("yes"));
        assert_eq!(parse_legal_hold(&hold), Err(Error::InvalidHeader));
    }
}
