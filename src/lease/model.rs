//! Randomized comparison of the lease state machine with an independent model.
//!
//! The model is written from Azure's lease state table, not from `StoredLease`: it moves
//! a lease from Leased to Expired and from Breaking to Broken as the clock passes, where
//! the implementation derives those states from stored deadlines only when asked.

use super::*;
use crate::prng::Rng;

const POOL: [u128; 3] = [11, 22, 33];

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum Model {
    Available,
    /// `until` is `None` for an infinite lease; `length` is in milliseconds.
    Leased {
        id: LeaseId,
        until: Option<i64>,
        length: Option<i64>,
    },
    Expired {
        id: LeaseId,
        length: Option<i64>,
    },
    Breaking {
        id: LeaseId,
        until: i64,
        length: Option<i64>,
    },
    Broken {
        id: LeaseId,
    },
}

/// What a successful operation reports.
#[derive(Debug, Eq, PartialEq)]
struct Done {
    id: Option<LeaseId>,
    break_seconds: Option<u32>,
}

impl Model {
    /// Applies the passing of time: a fixed lease expires and a break completes.
    fn tick(&mut self, now: i64) {
        *self = match *self {
            Self::Leased {
                id,
                until: Some(until),
                length,
            } if now >= until => Self::Expired { id, length },
            Self::Breaking { id, until, .. } if now >= until => Self::Broken { id },
            other => other,
        };
    }

    fn name(&self) -> &'static str {
        match self {
            Self::Available => "available",
            Self::Leased { .. } => "leased",
            Self::Expired { .. } => "expired",
            Self::Breaking { .. } => "breaking",
            Self::Broken { .. } => "broken",
        }
    }

    fn id(&self) -> Option<LeaseId> {
        match *self {
            Self::Available => None,
            Self::Leased { id, .. }
            | Self::Expired { id, .. }
            | Self::Breaking { id, .. }
            | Self::Broken { id } => Some(id),
        }
    }

    fn held(id: LeaseId, duration: LeaseDuration, now: i64) -> Self {
        match duration {
            LeaseDuration::Infinite => Self::Leased {
                id,
                until: None,
                length: None,
            },
            LeaseDuration::Seconds(seconds) => Self::Leased {
                id,
                until: Some(now + i64::from(seconds) * 1000),
                length: Some(i64::from(seconds) * 1000),
            },
        }
    }

    /// The Azure outcome of `action`; `fresh` is the id the implementation generated.
    fn apply(&mut self, action: LeaseAction, now: i64, fresh: Option<LeaseId>) -> Result<Done> {
        self.tick(now);
        let current = self.id();
        let done = |id| Done {
            id,
            break_seconds: None,
        };
        match action {
            LeaseAction::Acquire { duration, proposed } => {
                let granted = |id: Option<LeaseId>| id.or(fresh).ok_or(Error::Internal);
                match *self {
                    Self::Available | Self::Expired { .. } | Self::Broken { .. } => {
                        let id = granted(proposed)?;
                        *self = Self::held(id, duration, now);
                        Ok(done(Some(id)))
                    }
                    Self::Leased { id, .. } if proposed == Some(id) => {
                        *self = Self::held(id, duration, now);
                        Ok(done(Some(id)))
                    }
                    Self::Breaking { id, .. } if proposed == Some(id) => {
                        Err(Error::LeaseBreakingNoAcquire)
                    }
                    Self::Leased { .. } | Self::Breaking { .. } => Err(Error::LeaseAlreadyPresent),
                }
            }
            LeaseAction::Renew(id) => match *self {
                Self::Available => Err(Error::LeaseNotPresentLease),
                _ if current != Some(id) => Err(Error::LeaseMismatchLease),
                Self::Leased { length, .. } | Self::Expired { length, .. } => {
                    *self = Self::Leased {
                        id,
                        until: length.map(|length| now + length),
                        length,
                    };
                    Ok(done(Some(id)))
                }
                _ => Err(Error::LeaseBrokenNoRenew),
            },
            LeaseAction::Change {
                current: asked,
                proposed,
            } => match *self {
                Self::Available | Self::Expired { .. } | Self::Broken { .. } => {
                    Err(Error::LeaseNotPresentLease)
                }
                _ if current != Some(asked) => Err(Error::LeaseMismatchLease),
                Self::Breaking { .. } => Err(Error::LeaseBreakingNoChange),
                Self::Leased { until, length, .. } => {
                    *self = Self::Leased {
                        id: proposed,
                        until,
                        length,
                    };
                    Ok(done(Some(proposed)))
                }
            },
            LeaseAction::Release(id) => match *self {
                Self::Available => Err(Error::LeaseNotPresentLease),
                _ if current != Some(id) => Err(Error::LeaseMismatchLease),
                _ => {
                    *self = Self::Available;
                    Ok(done(None))
                }
            },
            LeaseAction::Break { period } => {
                let asked = period.map(|seconds| i64::from(seconds) * 1000);
                let (id, length, until) = match *self {
                    Self::Available => return Err(Error::LeaseNotPresentLease),
                    Self::Expired { id, length } => (id, length, now),
                    Self::Broken { id } => (id, None, now),
                    Self::Leased {
                        id,
                        until: None,
                        length,
                    } => (id, length, now + asked.unwrap_or(0)),
                    Self::Leased {
                        id,
                        until: Some(until),
                        length,
                    } => (
                        id,
                        length,
                        asked.map_or(until, |asked| until.min(now + asked)),
                    ),
                    Self::Breaking { id, until, length } => (
                        id,
                        length,
                        asked.map_or(until, |asked| until.min(now + asked)),
                    ),
                };
                *self = Self::Breaking { id, until, length };
                let remaining = until - now;
                let after = *self;
                self.tick(now);
                Ok(Done {
                    id: Some(id),
                    break_seconds: Some(u32::try_from((remaining + 999) / 1000).unwrap_or(0)),
                })
                .inspect(|_| assert_eq!(after.id(), Some(id)))
            }
        }
    }

    /// The Azure rule for a data operation presenting `supplied` against this lease.
    fn check(&self, supplied: Option<LeaseId>, need: LeaseNeed, owner: LeaseOwner) -> Result<()> {
        let (mismatch, absent, missing) = match owner {
            LeaseOwner::Blob => (
                Error::LeaseMismatchBlob,
                Error::LeaseNotPresentBlob,
                Error::LeaseIdMissingBlob,
            ),
            LeaseOwner::Container => (
                Error::LeaseMismatchContainer,
                Error::LeaseNotPresentContainer,
                Error::LeaseIdMissing,
            ),
        };
        let active = matches!(self, Self::Leased { .. } | Self::Breaking { .. });
        match (supplied, active) {
            (None, true) if need == LeaseNeed::Required => Err(missing),
            (None, _) => Ok(()),
            (Some(id), true) => (self.id() == Some(id)).then_some(()).ok_or(mismatch),
            (Some(_), false) if matches!(self, Self::Available) => Err(absent),
            (Some(id), false) => {
                if self.id() == Some(id) {
                    Err(Error::LeaseLost)
                } else {
                    Err(absent)
                }
            }
        }
    }
}

fn id(rng: &mut Rng) -> LeaseId {
    LeaseId(Uuid::from_u128(*rng.pick(&POOL)))
}

fn action(rng: &mut Rng) -> LeaseAction {
    match rng.below(8) {
        0..=1 => LeaseAction::Acquire {
            duration: *rng.pick(&[
                LeaseDuration::Infinite,
                LeaseDuration::Seconds(15),
                LeaseDuration::Seconds(30),
                LeaseDuration::Seconds(60),
            ]),
            proposed: if rng.below(3) == 0 {
                None
            } else {
                Some(id(rng))
            },
        },
        2 => LeaseAction::Renew(id(rng)),
        3 => LeaseAction::Change {
            current: id(rng),
            proposed: id(rng),
        },
        4 => LeaseAction::Release(id(rng)),
        _ => LeaseAction::Break {
            period: if rng.below(3) == 0 {
                None
            } else {
                Some(*rng.pick(&[0, 1, 5, 15, 30, 60]))
            },
        },
    }
}

#[test]
fn random_sequences_follow_the_azure_state_table() {
    let mut transitions = std::collections::BTreeSet::new();
    for seed in 1..=400u64 {
        let mut rng = Rng::seeded(seed);
        let mut stored = StoredLease::default();
        let mut model = Model::Available;
        let mut now = 1_700_000_000_000i64;
        for step in 0..150 {
            let at = format!("seed {seed} step {step}");
            // Long gaps let leases expire and breaks finish; short ones sit on the boundaries.
            now += *rng.pick(&[
                0, 0, 1, 999, 1000, 4000, 14_999, 15_000, 16_000, 30_000, 61_000,
            ]);
            model.tick(now);
            assert_eq!(stored.state(now).name(), model.name(), "{at}");

            let action = action(&mut rng);
            let before = model.name();
            let real = stored.apply(action, now);
            let fresh = real.as_ref().ok().and_then(|outcome| outcome.id);
            let expected = model.apply(action, now, fresh);
            match (&real, &expected) {
                (Ok(outcome), Ok(done)) => {
                    assert_eq!(outcome.id, done.id, "{at}: {action:?} on {before}");
                    assert_eq!(
                        outcome.break_seconds, done.break_seconds,
                        "{at}: {action:?}"
                    );
                    stored = outcome.lease;
                }
                (Err(real), Err(expected)) => {
                    assert_eq!(real, expected, "{at}: {action:?} on {before}");
                }
                _ => {
                    panic!(
                        "{at}: {action:?} on {before}: {:?} but the model says {expected:?}",
                        real.as_ref().map(|outcome| outcome.id)
                    )
                }
            }
            transitions.insert((before, model.name()));

            assert_eq!(stored.state(now).name(), model.name(), "{at}: {action:?}");
            assert_eq!(stored.id, model.id(), "{at}");
            let view = stored.view(now);
            let locked = matches!(model.name(), "leased" | "breaking");
            assert_eq!(view.status() == "locked", locked, "{at}");
            assert_eq!(view.duration().is_some(), locked, "{at}");
            if let Model::Leased { length, until, .. } = model {
                assert_eq!(view.infinite, length.is_none(), "{at}");
                if let Some(until) = until {
                    assert_eq!(stored.deadline, until, "{at}");
                }
            }

            for need in [LeaseNeed::Required, LeaseNeed::Optional] {
                for owner in [LeaseOwner::Blob, LeaseOwner::Container] {
                    for supplied in [None, Some(id(&mut rng)), Some(LeaseId(Uuid::from_u128(99)))] {
                        assert_eq!(
                            stored.check(supplied, need, owner, now),
                            model.check(supplied, need, owner),
                            "{at}: check {supplied:?} {need:?} {owner:?} on {}",
                            model.name()
                        );
                    }
                }
            }
        }
    }
    // The walk reached every state and left each by more than one route.
    for state in ["available", "leased", "expired", "breaking", "broken"] {
        assert!(
            transitions.iter().any(|(from, _)| *from == state)
                && transitions.iter().any(|(_, to)| *to == state),
            "{state} was never entered and left: {transitions:?}"
        );
    }
}

#[test]
fn a_fixed_lease_expires_exactly_at_its_deadline_and_a_break_completes_exactly_at_its_own() {
    let now = 5_000;
    let held = StoredLease::default()
        .apply(
            LeaseAction::Acquire {
                duration: LeaseDuration::Seconds(15),
                proposed: Some(LeaseId(Uuid::from_u128(1))),
            },
            now,
        )
        .unwrap()
        .lease;
    assert_eq!(held.state(now + 14_999), LeaseState::Leased);
    assert_eq!(held.state(now + 15_000), LeaseState::Expired);
    let breaking = held
        .apply(LeaseAction::Break { period: Some(5) }, now)
        .unwrap()
        .lease;
    assert_eq!(breaking.state(now + 4_999), LeaseState::Breaking);
    assert_eq!(breaking.state(now + 5_000), LeaseState::Broken);
}
