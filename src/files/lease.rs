//! Share and file leases as a clocked state machine (ADR-0017, ADR-0016).
//!
//! A lease is stored on the object it protects as `Option<Lease>`. The effective state is
//! computed from the stored fields and the current time, so no timer is needed. File
//! leases are infinite and are never `Breaking`; share leases follow the full table.

use super::error::{Error, Result};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

pub(crate) const INFINITE: i64 = -1;
const MIN_FIXED: i64 = 15;
const MAX_FIXED: i64 = 60;
pub(crate) const MAX_BREAK_PERIOD: i64 = 60;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum Kind {
    File,
    Share,
}

/// Stored lease record. `id` stays after expiry or break so the holder can still renew
/// or release it until someone acquires the object again.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub(crate) struct Lease {
    pub(crate) id: String,
    /// Seconds, or [`INFINITE`].
    pub(crate) duration: i64,
    /// Unix milliseconds when a fixed lease lapses; unused when infinite.
    pub(crate) expires: i64,
    /// Unix milliseconds when a requested break completes.
    pub(crate) broken_at: Option<i64>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum State {
    Available,
    Leased,
    Expired,
    Breaking,
    Broken,
}

impl State {
    pub(crate) fn name(self) -> &'static str {
        match self {
            Self::Available => "available",
            Self::Leased => "leased",
            Self::Expired => "expired",
            Self::Breaking => "breaking",
            Self::Broken => "broken",
        }
    }

    /// `locked` while the lease still excludes other writers.
    pub(crate) fn status(self) -> &'static str {
        if matches!(self, Self::Leased | Self::Breaking) {
            "locked"
        } else {
            "unlocked"
        }
    }
}

/// What a lease-aware resource reports in `x-ms-lease-*` headers and listings.
pub(crate) struct Summary {
    pub(crate) state: State,
    /// `infinite` or `fixed`, only while the lease is in force.
    pub(crate) duration: Option<&'static str>,
}

pub(crate) fn state(lease: Option<&Lease>, now: i64) -> State {
    let Some(lease) = lease else {
        return State::Available;
    };
    if let Some(broken_at) = lease.broken_at {
        return if now < broken_at {
            State::Breaking
        } else {
            State::Broken
        };
    }
    if lease.duration == INFINITE || now < lease.expires {
        State::Leased
    } else {
        State::Expired
    }
}

pub(crate) fn summary(lease: Option<&Lease>, now: i64) -> Summary {
    let state = state(lease, now);
    let duration = match (state, lease) {
        (State::Leased | State::Breaking, Some(lease)) => Some(if lease.duration == INFINITE {
            "infinite"
        } else {
            "fixed"
        }),
        _ => None,
    };
    Summary { state, duration }
}

/// Normalises any accepted GUID spelling to lower-case hyphenated form.
pub(crate) fn parse_id(value: &str) -> Result<String> {
    Uuid::parse_str(value)
        .map(|id| id.hyphenated().to_string())
        .map_err(|_| Error::InvalidHeaderValue)
}

pub(crate) enum Action<'a> {
    Acquire {
        duration: i64,
        proposed: Option<&'a str>,
    },
    Renew {
        id: &'a str,
    },
    Change {
        id: &'a str,
        proposed: &'a str,
    },
    Release {
        id: &'a str,
    },
    Break {
        period: Option<i64>,
    },
}

#[derive(Debug, Eq, PartialEq)]
pub(crate) enum Outcome {
    Acquired(String),
    Renewed(String),
    Changed(String),
    Released,
    /// Seconds until the lease is fully broken, rounded up.
    Broken(i64),
}

fn not_present(kind: Kind) -> Error {
    match kind {
        Kind::File => Error::LeaseNotPresentWithFileLeaseOperation,
        Kind::Share => Error::LeaseNotPresentWithFileShareLeaseOperation,
    }
}

fn mismatch(kind: Kind) -> Error {
    match kind {
        Kind::File => Error::LeaseIdMismatchWithFileLeaseOperation,
        Kind::Share => Error::LeaseIdMismatchWithFileShareLeaseOperation,
    }
}

/// Applies one lease action and returns the new stored lease with its outcome. The
/// `generate` closure supplies an ID when an acquire proposes none.
pub(crate) fn apply(
    kind: Kind,
    current: Option<&Lease>,
    now: i64,
    action: Action<'_>,
    generate: impl FnOnce() -> String,
) -> Result<(Option<Lease>, Outcome)> {
    let current_state = state(current, now);
    match action {
        Action::Acquire { duration, proposed } => {
            let valid = match kind {
                Kind::File => duration == INFINITE,
                Kind::Share => duration == INFINITE || (MIN_FIXED..=MAX_FIXED).contains(&duration),
            };
            if !valid {
                return Err(Error::InvalidHeaderValue);
            }
            let held = match current_state {
                State::Leased | State::Breaking => current.map(|lease| lease.id.as_str()),
                _ => None,
            };
            if let Some(held) = held {
                if current_state == State::Breaking {
                    return Err(if proposed == Some(held) {
                        Error::LeaseIsBreakingAndCannotBeAcquired
                    } else {
                        Error::LeaseAlreadyPresent
                    });
                }
                if proposed != Some(held) {
                    return Err(Error::LeaseAlreadyPresent);
                }
            }
            let id = proposed.map_or_else(generate, str::to_owned);
            Ok((
                Some(fresh(id.clone(), duration, now)),
                Outcome::Acquired(id),
            ))
        }
        Action::Renew { id } => {
            if kind == Kind::File {
                return Err(Error::InvalidHeaderValue);
            }
            let lease = current.ok_or_else(|| not_present(kind))?;
            if lease.id != id {
                return Err(mismatch(kind));
            }
            match current_state {
                State::Leased | State::Expired => Ok((
                    Some(fresh(lease.id.clone(), lease.duration, now)),
                    Outcome::Renewed(lease.id.clone()),
                )),
                _ => Err(Error::LeaseIsBrokenAndCannotBeRenewed),
            }
        }
        Action::Change { id, proposed } => {
            let lease = current.ok_or_else(|| not_present(kind))?;
            match current_state {
                State::Leased if lease.id == proposed || lease.id == id => {
                    let changed = Lease {
                        id: proposed.to_owned(),
                        ..lease.clone()
                    };
                    Ok((Some(changed), Outcome::Changed(proposed.to_owned())))
                }
                State::Leased => Err(mismatch(kind)),
                State::Breaking if lease.id == id => Err(Error::LeaseIsBreakingAndCannotBeChanged),
                State::Breaking => Err(mismatch(kind)),
                _ => Err(not_present(kind)),
            }
        }
        Action::Release { id } => {
            let lease = current.ok_or_else(|| not_present(kind))?;
            if lease.id != id {
                return Err(mismatch(kind));
            }
            Ok((None, Outcome::Released))
        }
        Action::Break { period } => {
            let lease = current.ok_or_else(|| not_present(kind))?;
            let period = period.map(|p| p.clamp(0, MAX_BREAK_PERIOD) * 1000);
            let broken_at = match current_state {
                State::Leased => {
                    let remaining = if lease.duration == INFINITE || kind == Kind::File {
                        None
                    } else {
                        Some(lease.expires - now)
                    };
                    match (period, remaining) {
                        (Some(period), Some(remaining)) => now + period.min(remaining),
                        (Some(period), None) if kind == Kind::Share => now + period,
                        (None, Some(remaining)) => now + remaining,
                        _ => now,
                    }
                }
                State::Breaking => {
                    let existing = lease.broken_at.unwrap_or(now);
                    period.map_or(existing, |period| existing.min(now + period))
                }
                _ => now,
            };
            let broken = Lease {
                broken_at: Some(broken_at),
                ..lease.clone()
            };
            let remaining = ((broken_at - now).max(0) + 999) / 1000;
            Ok((Some(broken), Outcome::Broken(remaining)))
        }
    }
}

fn fresh(id: String, duration: i64, now: i64) -> Lease {
    Lease {
        id,
        duration,
        expires: if duration == INFINITE {
            i64::MAX
        } else {
            now + duration * 1000
        },
        broken_at: None,
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum Use {
    Read,
    Write,
    Delete,
}

/// Checks a request's `x-ms-lease-id` (if any) against the stored lease for an ordinary
/// operation on the protected object.
pub(crate) fn check_use(
    kind: Kind,
    lease: Option<&Lease>,
    now: i64,
    supplied: Option<&str>,
    usage: Use,
) -> Result<()> {
    let (not_present, missing, mismatch, lost) = match kind {
        Kind::File => (
            Error::LeaseNotPresentWithFileOperation,
            Error::LeaseIdMissingWithFileOperation,
            Error::LeaseIdMismatchWithFileOperation,
            Error::LeaseLostWithFileOperation,
        ),
        Kind::Share => (
            Error::LeaseNotPresentWithFileShareOperation,
            Error::LeaseIdMissingWithFileShareOperation,
            Error::LeaseIdMismatchWithFileShareOperation,
            Error::LeaseLostWithFileShareOperation,
        ),
    };
    let held = lease.map(|lease| lease.id.as_str());
    match (state(lease, now), supplied) {
        (State::Available, None) => Ok(()),
        (State::Available, Some(_)) => Err(not_present),
        (State::Leased, None) => match usage {
            Use::Read => Ok(()),
            _ => Err(missing),
        },
        (State::Breaking, None) => match usage {
            Use::Delete => Err(missing),
            _ => Ok(()),
        },
        (State::Leased | State::Breaking, Some(id)) => {
            if held == Some(id) {
                Ok(())
            } else {
                Err(mismatch)
            }
        }
        (State::Expired | State::Broken, None) => Ok(()),
        (State::Expired | State::Broken, Some(id)) => {
            Err(if held == Some(id) { lost } else { mismatch })
        }
    }
}

/// A broken file lease reverts to available once a write goes through without it.
pub(crate) fn after_write(kind: Kind, lease: &mut Option<Lease>, now: i64) {
    if kind == Kind::File && state(lease.as_ref(), now) == State::Broken {
        *lease = None;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const A: &str = "aaaaaaaa-0000-0000-0000-000000000001";
    const B: &str = "bbbbbbbb-0000-0000-0000-000000000002";
    const C: &str = "cccccccc-0000-0000-0000-000000000003";
    const X: &str = "99999999-0000-0000-0000-000000000009";
    const NOW: i64 = 1_000_000;

    fn leased(id: &str, duration: i64) -> Lease {
        fresh(id.to_owned(), duration, NOW)
    }

    fn breaking(id: &str) -> Lease {
        Lease {
            broken_at: Some(NOW + 10_000),
            ..leased(id, 60)
        }
    }

    fn broken(id: &str) -> Lease {
        Lease {
            broken_at: Some(NOW - 1),
            ..leased(id, 60)
        }
    }

    fn expired(id: &str) -> Lease {
        fresh(id.to_owned(), 15, NOW - 20_000)
    }

    fn run(
        kind: Kind,
        lease: Option<&Lease>,
        action: Action<'_>,
    ) -> Result<(Option<Lease>, Outcome)> {
        apply(kind, lease, NOW, action, || X.to_owned())
    }

    fn acquire<'a>(proposed: Option<&'a str>, duration: i64) -> Action<'a> {
        Action::Acquire { duration, proposed }
    }

    fn state_of(result: &Result<(Option<Lease>, Outcome)>) -> State {
        state(result.as_ref().unwrap().0.as_ref(), NOW)
    }

    fn id_of(result: &Result<(Option<Lease>, Outcome)>) -> String {
        result.as_ref().unwrap().0.as_ref().unwrap().id.clone()
    }

    #[test]
    fn state_is_computed_from_the_clock() {
        let lease = leased(A, 15);
        assert_eq!(state(None, NOW), State::Available);
        assert_eq!(state(Some(&lease), NOW + 14_999), State::Leased);
        assert_eq!(state(Some(&lease), NOW + 15_000), State::Expired);
        assert_eq!(
            state(Some(&leased(A, INFINITE)), i64::MAX - 1),
            State::Leased
        );
        assert_eq!(state(Some(&breaking(A)), NOW), State::Breaking);
        assert_eq!(state(Some(&breaking(A)), NOW + 10_000), State::Broken);
        assert_eq!(State::Breaking.status(), "locked");
        assert_eq!(State::Expired.status(), "unlocked");
        assert_eq!(summary(Some(&lease), NOW).duration, Some("fixed"));
        assert_eq!(summary(Some(&expired(A)), NOW).duration, None);
    }

    #[test]
    fn share_acquire_follows_the_outcome_table() {
        use State::Leased;
        let ok = |lease: Option<&Lease>, proposed, expect_state, expect_id: &str| {
            let result = run(Kind::Share, lease, acquire(proposed, 30));
            assert_eq!(state_of(&result), expect_state);
            assert_eq!(id_of(&result), expect_id);
        };
        ok(None, None, Leased, X);
        ok(None, Some(A), Leased, A);
        ok(Some(&leased(A, 30)), Some(A), Leased, A);
        ok(Some(&broken(A)), None, Leased, X);
        ok(Some(&broken(A)), Some(B), Leased, B);
        ok(Some(&expired(A)), None, Leased, X);
        ok(Some(&expired(A)), Some(A), Leased, A);
        let fails = |lease: &Lease, proposed, error| {
            assert_eq!(
                run(Kind::Share, Some(lease), acquire(proposed, 30)).unwrap_err(),
                error
            );
        };
        fails(&leased(A, 30), None, Error::LeaseAlreadyPresent);
        fails(&leased(A, 30), Some(B), Error::LeaseAlreadyPresent);
        fails(
            &breaking(A),
            Some(A),
            Error::LeaseIsBreakingAndCannotBeAcquired,
        );
        fails(&breaking(A), Some(B), Error::LeaseAlreadyPresent);
        fails(&breaking(A), None, Error::LeaseAlreadyPresent);
    }

    #[test]
    fn acquire_again_with_the_same_id_resets_the_duration() {
        let lease = leased(A, 15);
        let result = apply(
            Kind::Share,
            Some(&lease),
            NOW + 5_000,
            acquire(Some(A), INFINITE),
            || X.to_owned(),
        )
        .unwrap();
        assert_eq!(result.0.unwrap().duration, INFINITE);
    }

    #[test]
    fn durations_are_validated_per_kind() {
        for duration in [0, 14, 61, -2] {
            assert_eq!(
                run(Kind::Share, None, acquire(None, duration)).unwrap_err(),
                Error::InvalidHeaderValue
            );
        }
        for duration in [15, 60, INFINITE] {
            assert!(run(Kind::Share, None, acquire(None, duration)).is_ok());
        }
        assert_eq!(
            run(Kind::File, None, acquire(None, 30)).unwrap_err(),
            Error::InvalidHeaderValue
        );
        assert!(run(Kind::File, None, acquire(None, INFINITE)).is_ok());
    }

    #[test]
    fn share_renew_follows_the_outcome_table() {
        let renew = |lease: Option<&Lease>, id| run(Kind::Share, lease, Action::Renew { id });
        assert_eq!(state_of(&renew(Some(&leased(A, 30)), A)), State::Leased);
        assert_eq!(state_of(&renew(Some(&expired(A)), A)), State::Leased);
        let share_mismatch = Error::LeaseIdMismatchWithFileShareLeaseOperation;
        assert_eq!(renew(Some(&leased(A, 30)), B).unwrap_err(), share_mismatch);
        assert_eq!(renew(Some(&expired(A)), B).unwrap_err(), share_mismatch);
        assert_eq!(
            renew(None, A).unwrap_err(),
            Error::LeaseNotPresentWithFileShareLeaseOperation
        );
        for lease in [breaking(A), broken(A)] {
            assert_eq!(
                renew(Some(&lease), A).unwrap_err(),
                Error::LeaseIsBrokenAndCannotBeRenewed
            );
        }
        assert_eq!(
            run(
                Kind::File,
                Some(&leased(A, INFINITE)),
                Action::Renew { id: A }
            )
            .unwrap_err(),
            Error::InvalidHeaderValue
        );
    }

    #[test]
    fn renew_restarts_the_fixed_clock() {
        let lease = leased(A, 15);
        let (renewed, _) = apply(
            Kind::Share,
            Some(&lease),
            NOW + 10_000,
            Action::Renew { id: A },
            || X.to_owned(),
        )
        .unwrap();
        assert_eq!(renewed.unwrap().expires, NOW + 25_000);
    }

    #[test]
    fn change_follows_the_outcome_table() {
        for kind in [Kind::Share, Kind::File] {
            let change = |lease: Option<&Lease>, id, proposed| {
                run(kind, lease, Action::Change { id, proposed })
            };
            let held = leased(A, INFINITE);
            assert_eq!(id_of(&change(Some(&held), A, B)), B);
            assert_eq!(id_of(&change(Some(&held), B, A)), A, "retry of a change");
            let wrong = match kind {
                Kind::Share => Error::LeaseIdMismatchWithFileShareLeaseOperation,
                Kind::File => Error::LeaseIdMismatchWithFileLeaseOperation,
            };
            assert_eq!(change(Some(&held), B, C).unwrap_err(), wrong);
            let absent = match kind {
                Kind::Share => Error::LeaseNotPresentWithFileShareLeaseOperation,
                Kind::File => Error::LeaseNotPresentWithFileLeaseOperation,
            };
            assert_eq!(change(None, A, B).unwrap_err(), absent);
            assert_eq!(change(Some(&broken(A)), A, B).unwrap_err(), absent);
        }
        let result = run(
            Kind::Share,
            Some(&breaking(A)),
            Action::Change { id: A, proposed: B },
        );
        assert_eq!(
            result.unwrap_err(),
            Error::LeaseIsBreakingAndCannotBeChanged
        );
        assert_eq!(
            run(
                Kind::Share,
                Some(&expired(A)),
                Action::Change { id: A, proposed: B }
            )
            .unwrap_err(),
            Error::LeaseNotPresentWithFileShareLeaseOperation
        );
    }

    #[test]
    fn release_follows_the_outcome_table() {
        for lease in [leased(A, 30), breaking(A), broken(A), expired(A)] {
            let released = run(Kind::Share, Some(&lease), Action::Release { id: A }).unwrap();
            assert_eq!((released.0, released.1), (None, Outcome::Released));
            assert_eq!(
                run(Kind::Share, Some(&lease), Action::Release { id: B }).unwrap_err(),
                Error::LeaseIdMismatchWithFileShareLeaseOperation
            );
        }
        assert_eq!(
            run(Kind::File, None, Action::Release { id: A }).unwrap_err(),
            Error::LeaseNotPresentWithFileLeaseOperation
        );
    }

    #[test]
    fn share_break_follows_the_outcome_table() {
        let brk = |lease: Option<&Lease>, period| run(Kind::Share, lease, Action::Break { period });
        assert_eq!(
            brk(None, None).unwrap_err(),
            Error::LeaseNotPresentWithFileShareLeaseOperation
        );
        let immediate = brk(Some(&leased(A, 60)), Some(0)).unwrap();
        assert_eq!(immediate.1, Outcome::Broken(0));
        assert_eq!(state(immediate.0.as_ref(), NOW), State::Broken);
        let timed = brk(Some(&leased(A, INFINITE)), Some(30)).unwrap();
        assert_eq!(timed.1, Outcome::Broken(30));
        assert_eq!(state(timed.0.as_ref(), NOW), State::Breaking);
        let short = brk(Some(&leased(A, 15)), Some(60)).unwrap();
        assert_eq!(
            short.1,
            Outcome::Broken(15),
            "never longer than the remaining lease"
        );
        let fixed_default = brk(Some(&leased(A, 20)), None).unwrap();
        assert_eq!(fixed_default.1, Outcome::Broken(20));
        let infinite_default = brk(Some(&leased(A, INFINITE)), None).unwrap();
        assert_eq!(infinite_default.1, Outcome::Broken(0));
        let shortened = brk(Some(&breaking(A)), Some(3)).unwrap();
        assert_eq!(shortened.1, Outcome::Broken(3));
        let kept = brk(Some(&breaking(A)), None).unwrap();
        assert_eq!(kept.1, Outcome::Broken(10));
        assert_eq!(state_of(&brk(Some(&broken(A)), Some(5))), State::Broken);
        assert_eq!(brk(Some(&expired(A)), None).unwrap().1, Outcome::Broken(0));
        assert_eq!(state_of(&brk(Some(&expired(A)), None)), State::Broken);
    }

    #[test]
    fn file_break_is_immediate() {
        let result = run(
            Kind::File,
            Some(&leased(A, INFINITE)),
            Action::Break { period: Some(30) },
        );
        let (lease, outcome) = result.unwrap();
        assert_eq!(outcome, Outcome::Broken(0));
        assert_eq!(state(lease.as_ref(), NOW), State::Broken);
        assert_eq!(
            run(Kind::File, None, Action::Break { period: None }).unwrap_err(),
            Error::LeaseNotPresentWithFileLeaseOperation
        );
    }

    #[test]
    fn share_use_follows_the_outcome_table() {
        let check =
            |lease: Option<&Lease>, id, usage| check_use(Kind::Share, lease, NOW, id, usage);
        use Use::{Delete, Read, Write};
        let share_missing = Error::LeaseIdMissingWithFileShareOperation;
        let share_mismatch = Error::LeaseIdMismatchWithFileShareOperation;
        let share_lost = Error::LeaseLostWithFileShareOperation;
        for usage in [Read, Write, Delete] {
            assert_eq!(check(None, None, usage), Ok(()));
            assert_eq!(
                check(None, Some(A), usage),
                Err(Error::LeaseNotPresentWithFileShareOperation)
            );
            assert_eq!(check(Some(&leased(A, 30)), Some(A), usage), Ok(()));
            assert_eq!(
                check(Some(&leased(A, 30)), Some(B), usage),
                Err(share_mismatch)
            );
            assert_eq!(check(Some(&breaking(A)), Some(A), usage), Ok(()));
            assert_eq!(
                check(Some(&breaking(A)), Some(B), usage),
                Err(share_mismatch)
            );
            for lease in [broken(A), expired(A)] {
                assert_eq!(check(Some(&lease), None, usage), Ok(()));
                assert_eq!(check(Some(&lease), Some(A), usage), Err(share_lost));
                assert_eq!(check(Some(&lease), Some(B), usage), Err(share_mismatch));
            }
        }
        assert_eq!(check(Some(&leased(A, 30)), None, Read), Ok(()));
        assert_eq!(check(Some(&leased(A, 30)), None, Write), Err(share_missing));
        assert_eq!(
            check(Some(&leased(A, 30)), None, Delete),
            Err(share_missing)
        );
        assert_eq!(check(Some(&breaking(A)), None, Write), Ok(()));
        assert_eq!(check(Some(&breaking(A)), None, Delete), Err(share_missing));
    }

    #[test]
    fn file_use_follows_the_outcome_table() {
        let check = |lease: Option<&Lease>, id, usage| check_use(Kind::File, lease, NOW, id, usage);
        let held = leased(A, INFINITE);
        assert_eq!(check(Some(&held), Some(A), Use::Write), Ok(()));
        assert_eq!(
            check(Some(&held), None, Use::Write),
            Err(Error::LeaseIdMissingWithFileOperation)
        );
        assert_eq!(
            check(Some(&held), Some(B), Use::Write),
            Err(Error::LeaseIdMismatchWithFileOperation)
        );
        assert_eq!(check(Some(&held), None, Use::Read), Ok(()));
        assert_eq!(
            check(Some(&broken(A)), Some(A), Use::Write),
            Err(Error::LeaseLostWithFileOperation)
        );
        assert_eq!(check(Some(&broken(A)), None, Use::Write), Ok(()));
        assert_eq!(
            check(None, Some(A), Use::Read),
            Err(Error::LeaseNotPresentWithFileOperation)
        );
    }

    #[test]
    fn a_broken_file_lease_clears_after_an_unleased_write() {
        let mut lease = Some(broken(A));
        after_write(Kind::File, &mut lease, NOW);
        assert_eq!(lease, None);
        let mut kept = Some(leased(A, INFINITE));
        after_write(Kind::File, &mut kept, NOW);
        assert!(kept.is_some());
        let mut share = Some(broken(A));
        after_write(Kind::Share, &mut share, NOW);
        assert!(share.is_some());
    }

    #[test]
    fn lease_ids_are_normalised() {
        assert_eq!(
            parse_id("1F812371-A41D-49E6-B123-F4B542E851C5").unwrap(),
            "1f812371-a41d-49e6-b123-f4b542e851c5"
        );
        assert_eq!(parse_id("not-a-guid"), Err(Error::InvalidHeaderValue));
    }
}
