//! Blob and container leases as a clocked state machine (ADR-0017).
//!
//! A lease is stored on the object it protects as an id, a kind, a duration and
//! a deadline. The effective state is computed from those fields and the clock
//! whenever the object is read or written, so no timer thread is needed.

use crate::domain::{Error, Result};
use uuid::Uuid;

const MS: i64 = 1000;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct LeaseId(Uuid);

impl LeaseId {
    pub(crate) fn parse(value: &str) -> Result<Self> {
        Uuid::try_parse(value)
            .map(Self)
            .map_err(|_| Error::InvalidHeader)
    }

    pub(crate) fn generate() -> Self {
        Self(Uuid::new_v4())
    }

    pub(crate) fn text(self) -> String {
        self.0.hyphenated().to_string()
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum LeaseDuration {
    Infinite,
    Seconds(u32),
}

impl LeaseDuration {
    pub(crate) fn parse(value: &str) -> Result<Self> {
        match value.parse::<i64>().map_err(|_| Error::InvalidHeader)? {
            -1 => Ok(Self::Infinite),
            seconds @ 15..=60 => Ok(Self::Seconds(seconds as u32)),
            _ => Err(Error::InvalidHeader),
        }
    }

    fn stored(self) -> i64 {
        match self {
            Self::Infinite => -1,
            Self::Seconds(seconds) => i64::from(seconds),
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum LeaseAction {
    Acquire {
        duration: LeaseDuration,
        proposed: Option<LeaseId>,
    },
    Renew(LeaseId),
    Change {
        current: LeaseId,
        proposed: LeaseId,
    },
    Release(LeaseId),
    Break {
        period: Option<u32>,
    },
}

/// What an operation needs from the lease of the object it touches.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum LeaseNeed {
    /// A write: an active lease requires its id.
    Required,
    /// A read or a lease-tolerant change: an id is optional, but if supplied it must match.
    Optional,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum LeaseOwner {
    Blob,
    Container,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum LeaseKind {
    None,
    Leased,
    Breaking,
}

impl LeaseKind {
    pub(crate) fn code(self) -> i64 {
        match self {
            Self::None => 0,
            Self::Leased => 1,
            Self::Breaking => 2,
        }
    }

    pub(crate) fn from_code(code: i64) -> Self {
        match code {
            1 => Self::Leased,
            2 => Self::Breaking,
            _ => Self::None,
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum LeaseState {
    Available,
    Leased,
    Expired,
    Breaking,
    Broken,
}

impl LeaseState {
    pub(crate) fn name(self) -> &'static str {
        match self {
            Self::Available => "available",
            Self::Leased => "leased",
            Self::Expired => "expired",
            Self::Breaking => "breaking",
            Self::Broken => "broken",
        }
    }
}

/// The persisted lease fields. `duration` is in seconds, or -1 for infinite;
/// `deadline` is Unix milliseconds: the expiry of a fixed lease or the end of a break.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct StoredLease {
    pub(crate) id: Option<LeaseId>,
    pub(crate) kind: LeaseKind,
    pub(crate) duration: i64,
    pub(crate) deadline: i64,
}

/// A point-in-time view for response headers and listings.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct LeaseView {
    pub(crate) state: LeaseState,
    pub(crate) infinite: bool,
}

impl LeaseView {
    pub(crate) fn status(self) -> &'static str {
        if matches!(self.state, LeaseState::Leased | LeaseState::Breaking) {
            "locked"
        } else {
            "unlocked"
        }
    }

    /// `infinite` or `fixed` while a lease is held or breaking.
    pub(crate) fn duration(self) -> Option<&'static str> {
        matches!(self.state, LeaseState::Leased | LeaseState::Breaking)
            .then_some(if self.infinite { "infinite" } else { "fixed" })
    }
}

pub(crate) struct LeaseOutcome {
    pub(crate) lease: StoredLease,
    pub(crate) id: Option<LeaseId>,
    pub(crate) break_seconds: Option<u32>,
}

impl Default for StoredLease {
    fn default() -> Self {
        Self {
            id: None,
            kind: LeaseKind::None,
            duration: 0,
            deadline: 0,
        }
    }
}

impl StoredLease {
    pub(crate) fn state(&self, now: i64) -> LeaseState {
        match self.kind {
            LeaseKind::None => LeaseState::Available,
            LeaseKind::Leased if self.duration < 0 || now < self.deadline => LeaseState::Leased,
            LeaseKind::Leased => LeaseState::Expired,
            LeaseKind::Breaking if now < self.deadline => LeaseState::Breaking,
            LeaseKind::Breaking => LeaseState::Broken,
        }
    }

    pub(crate) fn view(&self, now: i64) -> LeaseView {
        LeaseView {
            state: self.state(now),
            infinite: self.duration < 0,
        }
    }

    fn held(id: LeaseId, duration: i64, now: i64) -> Self {
        Self {
            id: Some(id),
            kind: LeaseKind::Leased,
            duration,
            deadline: if duration < 0 { 0 } else { now + duration * MS },
        }
    }

    /// Applies a lease operation, returning the new stored lease or the Azure conflict.
    pub(crate) fn apply(&self, action: LeaseAction, now: i64) -> Result<LeaseOutcome> {
        use LeaseState::{Available, Breaking, Broken, Expired, Leased};
        let state = self.state(now);
        let matches = |id: LeaseId| self.id == Some(id);
        let done = |lease: StoredLease| LeaseOutcome {
            id: lease.id,
            lease,
            break_seconds: None,
        };
        match action {
            LeaseAction::Acquire { duration, proposed } => match state {
                Available | Expired | Broken => {
                    let id = proposed.unwrap_or_else(LeaseId::generate);
                    Ok(done(Self::held(id, duration.stored(), now)))
                }
                Leased if proposed.is_some_and(matches) => {
                    let id = proposed.ok_or(Error::Internal)?;
                    Ok(done(Self::held(id, duration.stored(), now)))
                }
                Breaking if proposed.is_some_and(matches) => Err(Error::LeaseBreakingNoAcquire),
                Leased | Breaking => Err(Error::LeaseAlreadyPresent),
            },
            LeaseAction::Renew(id) => match state {
                Available => Err(Error::LeaseNotPresentLease),
                _ if !matches(id) => Err(Error::LeaseMismatchLease),
                Leased | Expired => Ok(done(Self::held(id, self.duration, now))),
                Breaking | Broken => Err(Error::LeaseBrokenNoRenew),
            },
            LeaseAction::Change { current, proposed } => match state {
                Available | Expired | Broken => Err(Error::LeaseNotPresentLease),
                _ if !matches(current) => Err(Error::LeaseMismatchLease),
                Breaking => Err(Error::LeaseBreakingNoChange),
                Leased => Ok(done(Self {
                    id: Some(proposed),
                    ..*self
                })),
            },
            LeaseAction::Release(id) => match state {
                Available => Err(Error::LeaseNotPresentLease),
                _ if !matches(id) => Err(Error::LeaseMismatchLease),
                _ => Ok(done(Self::default())),
            },
            LeaseAction::Break { period } => self.break_lease(state, period, now),
        }
    }

    fn break_lease(
        &self,
        state: LeaseState,
        period: Option<u32>,
        now: i64,
    ) -> Result<LeaseOutcome> {
        let requested = period.map(|seconds| i64::from(seconds) * MS);
        let deadline = match state {
            LeaseState::Available => return Err(Error::LeaseNotPresentLease),
            LeaseState::Expired | LeaseState::Broken => now,
            LeaseState::Leased if self.duration < 0 => now + requested.unwrap_or(0),
            LeaseState::Leased => {
                let remaining = self.deadline - now;
                now + requested.map_or(remaining, |period| period.min(remaining))
            }
            LeaseState::Breaking => {
                requested.map_or(self.deadline, |period| self.deadline.min(now + period))
            }
        };
        let remaining = (deadline - now).max(0);
        Ok(LeaseOutcome {
            lease: Self {
                id: self.id,
                kind: LeaseKind::Breaking,
                duration: self.duration,
                deadline,
            },
            id: self.id,
            break_seconds: Some(u32::try_from((remaining + MS - 1) / MS).unwrap_or(u32::MAX)),
        })
    }

    /// Checks the `x-ms-lease-id` of a data operation against the effective state.
    pub(crate) fn check(
        &self,
        supplied: Option<LeaseId>,
        need: LeaseNeed,
        owner: LeaseOwner,
        now: i64,
    ) -> Result<()> {
        let state = self.state(now);
        let (mismatch, absent) = match owner {
            LeaseOwner::Blob => (Error::LeaseMismatchBlob, Error::LeaseNotPresentBlob),
            LeaseOwner::Container => (
                Error::LeaseMismatchContainer,
                Error::LeaseNotPresentContainer,
            ),
        };
        match (state, supplied) {
            (LeaseState::Leased | LeaseState::Breaking, Some(id)) if self.id == Some(id) => Ok(()),
            (LeaseState::Leased | LeaseState::Breaking, Some(_)) => Err(mismatch),
            (LeaseState::Leased | LeaseState::Breaking, None) => match need {
                LeaseNeed::Required => Err(Error::LeaseIdMissing),
                LeaseNeed::Optional => Ok(()),
            },
            (_, None) => Ok(()),
            (LeaseState::Available, Some(_)) => Err(absent),
            (_, Some(id)) if self.id == Some(id) => Err(Error::LeaseLost),
            (_, Some(_)) => Err(absent),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn id(n: u128) -> LeaseId {
        LeaseId(Uuid::from_u128(n))
    }

    fn acquire(seconds: Option<u32>, proposed: Option<LeaseId>) -> LeaseAction {
        LeaseAction::Acquire {
            duration: seconds.map_or(LeaseDuration::Infinite, LeaseDuration::Seconds),
            proposed,
        }
    }

    fn leased(now: i64, seconds: Option<u32>) -> StoredLease {
        StoredLease::default()
            .apply(acquire(seconds, Some(id(1))), now)
            .unwrap()
            .lease
    }

    fn broken(now: i64) -> StoredLease {
        let held = leased(now, None);
        let lease = held
            .apply(LeaseAction::Break { period: Some(0) }, now)
            .unwrap()
            .lease;
        assert_eq!(lease.state(now), LeaseState::Broken);
        lease
    }

    fn breaking(now: i64) -> StoredLease {
        let lease = leased(now, Some(30))
            .apply(LeaseAction::Break { period: Some(20) }, now)
            .unwrap()
            .lease;
        assert_eq!(lease.state(now), LeaseState::Breaking);
        lease
    }

    fn expired() -> StoredLease {
        let lease = leased(0, Some(15));
        assert_eq!(lease.state(20_000), LeaseState::Expired);
        lease
    }

    /// A state-by-action table covering every transition and conflict.
    #[test]
    fn transitions_follow_the_azure_state_table() {
        let now = 20_000;
        let a = id(1);
        let b = id(2);
        let none = StoredLease::default();
        let held = leased(now, Some(30));
        type Case = (
            &'static str,
            StoredLease,
            LeaseAction,
            std::result::Result<LeaseState, Error>,
        );
        let cases: Vec<Case> = vec![
            (
                "available acquire",
                none,
                acquire(Some(15), Some(a)),
                Ok(LeaseState::Leased),
            ),
            (
                "available renew",
                none,
                LeaseAction::Renew(a),
                Err(Error::LeaseNotPresentLease),
            ),
            (
                "available release",
                none,
                LeaseAction::Release(a),
                Err(Error::LeaseNotPresentLease),
            ),
            (
                "available change",
                none,
                LeaseAction::Change {
                    current: a,
                    proposed: b,
                },
                Err(Error::LeaseNotPresentLease),
            ),
            (
                "available break",
                none,
                LeaseAction::Break { period: None },
                Err(Error::LeaseNotPresentLease),
            ),
            (
                "leased acquire same id",
                held,
                acquire(Some(60), Some(a)),
                Ok(LeaseState::Leased),
            ),
            (
                "leased acquire other id",
                held,
                acquire(Some(15), Some(b)),
                Err(Error::LeaseAlreadyPresent),
            ),
            (
                "leased acquire no id",
                held,
                acquire(Some(15), None),
                Err(Error::LeaseAlreadyPresent),
            ),
            (
                "leased renew",
                held,
                LeaseAction::Renew(a),
                Ok(LeaseState::Leased),
            ),
            (
                "leased renew mismatch",
                held,
                LeaseAction::Renew(b),
                Err(Error::LeaseMismatchLease),
            ),
            (
                "leased change",
                held,
                LeaseAction::Change {
                    current: a,
                    proposed: b,
                },
                Ok(LeaseState::Leased),
            ),
            (
                "leased change mismatch",
                held,
                LeaseAction::Change {
                    current: b,
                    proposed: a,
                },
                Err(Error::LeaseMismatchLease),
            ),
            (
                "leased release",
                held,
                LeaseAction::Release(a),
                Ok(LeaseState::Available),
            ),
            (
                "leased release mismatch",
                held,
                LeaseAction::Release(b),
                Err(Error::LeaseMismatchLease),
            ),
            (
                "leased break",
                held,
                LeaseAction::Break { period: Some(5) },
                Ok(LeaseState::Breaking),
            ),
            (
                "leased break now",
                held,
                LeaseAction::Break { period: Some(0) },
                Ok(LeaseState::Broken),
            ),
            (
                "expired acquire other id",
                expired(),
                acquire(Some(15), Some(b)),
                Ok(LeaseState::Leased),
            ),
            (
                "expired renew",
                expired(),
                LeaseAction::Renew(a),
                Ok(LeaseState::Leased),
            ),
            (
                "expired renew mismatch",
                expired(),
                LeaseAction::Renew(b),
                Err(Error::LeaseMismatchLease),
            ),
            (
                "expired change",
                expired(),
                LeaseAction::Change {
                    current: a,
                    proposed: b,
                },
                Err(Error::LeaseNotPresentLease),
            ),
            (
                "expired release",
                expired(),
                LeaseAction::Release(a),
                Ok(LeaseState::Available),
            ),
            (
                "expired break",
                expired(),
                LeaseAction::Break { period: None },
                Ok(LeaseState::Broken),
            ),
            (
                "breaking acquire same id",
                breaking(now),
                acquire(Some(15), Some(a)),
                Err(Error::LeaseBreakingNoAcquire),
            ),
            (
                "breaking acquire other id",
                breaking(now),
                acquire(Some(15), Some(b)),
                Err(Error::LeaseAlreadyPresent),
            ),
            (
                "breaking renew",
                breaking(now),
                LeaseAction::Renew(a),
                Err(Error::LeaseBrokenNoRenew),
            ),
            (
                "breaking change",
                breaking(now),
                LeaseAction::Change {
                    current: a,
                    proposed: b,
                },
                Err(Error::LeaseBreakingNoChange),
            ),
            (
                "breaking release",
                breaking(now),
                LeaseAction::Release(a),
                Ok(LeaseState::Available),
            ),
            (
                "breaking break",
                breaking(now),
                LeaseAction::Break { period: Some(0) },
                Ok(LeaseState::Broken),
            ),
            (
                "broken acquire",
                broken(now),
                acquire(Some(15), Some(b)),
                Ok(LeaseState::Leased),
            ),
            (
                "broken renew",
                broken(now),
                LeaseAction::Renew(a),
                Err(Error::LeaseBrokenNoRenew),
            ),
            (
                "broken change",
                broken(now),
                LeaseAction::Change {
                    current: a,
                    proposed: b,
                },
                Err(Error::LeaseNotPresentLease),
            ),
            (
                "broken release",
                broken(now),
                LeaseAction::Release(a),
                Ok(LeaseState::Available),
            ),
            (
                "broken release mismatch",
                broken(now),
                LeaseAction::Release(b),
                Err(Error::LeaseMismatchLease),
            ),
            (
                "broken break",
                broken(now),
                LeaseAction::Break { period: None },
                Ok(LeaseState::Broken),
            ),
        ];
        for (name, lease, action, expected) in cases {
            let actual = lease
                .apply(action, now)
                .map(|outcome| outcome.lease.state(now));
            assert_eq!(actual, expected, "{name}");
        }
    }

    #[test]
    fn leases_expire_and_breaks_complete_with_the_clock() {
        let lease = leased(0, Some(15));
        assert_eq!(lease.state(14_999), LeaseState::Leased);
        assert_eq!(lease.state(15_000), LeaseState::Expired);
        let renewed = lease
            .apply(LeaseAction::Renew(id(1)), 10_000)
            .unwrap()
            .lease;
        assert_eq!(renewed.state(24_999), LeaseState::Leased);
        assert_eq!(renewed.state(25_000), LeaseState::Expired);
        let broke = lease
            .apply(LeaseAction::Break { period: Some(60) }, 5_000)
            .unwrap();
        assert_eq!(
            broke.break_seconds,
            Some(10),
            "a break never outlives the lease"
        );
        assert_eq!(broke.lease.state(14_999), LeaseState::Breaking);
        assert_eq!(broke.lease.state(15_000), LeaseState::Broken);
        let infinite = leased(0, None);
        assert_eq!(infinite.state(i64::MAX / 2), LeaseState::Leased);
        let now = infinite
            .apply(LeaseAction::Break { period: None }, 0)
            .unwrap();
        assert_eq!(now.break_seconds, Some(0));
        let shortened = breaking(0)
            .apply(LeaseAction::Break { period: Some(3) }, 0)
            .unwrap();
        assert_eq!(shortened.break_seconds, Some(3));
        let longer = breaking(0)
            .apply(LeaseAction::Break { period: Some(50) }, 0)
            .unwrap();
        assert_eq!(longer.break_seconds, Some(20));
    }

    #[test]
    fn data_operations_check_the_lease_id() {
        let held = leased(0, Some(30));
        let (a, b) = (id(1), id(2));
        let check = |lease: &StoredLease, supplied, need, now| {
            lease.check(supplied, need, LeaseOwner::Blob, now)
        };
        assert_eq!(
            check(&held, None, LeaseNeed::Required, 0),
            Err(Error::LeaseIdMissing)
        );
        assert_eq!(check(&held, None, LeaseNeed::Optional, 0), Ok(()));
        assert_eq!(check(&held, Some(a), LeaseNeed::Required, 0), Ok(()));
        assert_eq!(
            check(&held, Some(b), LeaseNeed::Optional, 0),
            Err(Error::LeaseMismatchBlob)
        );
        assert_eq!(
            held.check(Some(b), LeaseNeed::Required, LeaseOwner::Container, 0),
            Err(Error::LeaseMismatchContainer)
        );
        assert_eq!(check(&held, None, LeaseNeed::Required, 30_000), Ok(()));
        assert_eq!(
            check(&held, Some(a), LeaseNeed::Required, 30_000),
            Err(Error::LeaseLost)
        );
        assert_eq!(
            check(&held, Some(b), LeaseNeed::Required, 30_000),
            Err(Error::LeaseNotPresentBlob)
        );
        let none = StoredLease::default();
        assert_eq!(
            check(&none, Some(a), LeaseNeed::Optional, 0),
            Err(Error::LeaseNotPresentBlob)
        );
        assert_eq!(check(&none, None, LeaseNeed::Required, 0), Ok(()));
        let infinite = leased(0, None);
        assert_eq!(
            check(&infinite, None, LeaseNeed::Required, i64::MAX / 2),
            Err(Error::LeaseIdMissing)
        );
        let breaking = breaking(0);
        assert_eq!(
            check(&breaking, Some(a), LeaseNeed::Required, 1_000),
            Ok(())
        );
        assert_eq!(
            check(&breaking, None, LeaseNeed::Required, 1_000),
            Err(Error::LeaseIdMissing)
        );
        assert_eq!(
            check(&breaking, Some(a), LeaseNeed::Required, 20_000),
            Err(Error::LeaseLost)
        );
    }

    #[test]
    fn views_report_status_and_duration() {
        let held = leased(0, Some(15)).view(0);
        assert_eq!((held.status(), held.duration()), ("locked", Some("fixed")));
        assert_eq!(leased(0, None).view(0).duration(), Some("infinite"));
        let expired = leased(0, Some(15)).view(20_000);
        assert_eq!(
            (expired.state.name(), expired.status(), expired.duration()),
            ("expired", "unlocked", None)
        );
        assert_eq!(StoredLease::default().view(0).state.name(), "available");
    }

    #[test]
    fn ids_and_durations_are_validated() {
        assert!(LeaseId::parse("not-a-guid").is_err());
        assert_eq!(
            LeaseId::parse("00000000-0000-0000-0000-000000000001").map(LeaseId::text),
            Ok("00000000-0000-0000-0000-000000000001".to_owned())
        );
        assert_eq!(LeaseDuration::parse("-1"), Ok(LeaseDuration::Infinite));
        assert_eq!(LeaseDuration::parse("15"), Ok(LeaseDuration::Seconds(15)));
        assert!(LeaseDuration::parse("14").is_err());
        assert!(LeaseDuration::parse("61").is_err());
        assert!(LeaseDuration::parse("0").is_err());
    }
}
