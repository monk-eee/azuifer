use super::{
    Details, ErrorCode, Header, INITIAL, Probe, Response, Step, header,
    lifecycle::{LEASE_ID, WRONG_LEASE_ID},
    usable_etag,
};
use anyhow::{Context as _, Result, ensure};
use reqwest::{Method, blocking::RequestBuilder, header::HeaderMap};
use std::{
    thread,
    time::{Duration, Instant},
};

const BREAK_SECONDS: u32 = 8;
const FINITE: &str = "60";
const CHANGE_ID: &str = WRONG_LEASE_ID;

pub(super) fn details(step: Step, headers: &HeaderMap) -> Option<Details> {
    let is = |name, expected: &str| header(headers, name, |value| value == expected);
    Some(match step {
        Step::RenewBlobLease | Step::ChangeBlobLease | Step::ReacquireBlobLease => {
            Details::LeaseId {
                id: is(
                    "x-ms-lease-id",
                    if step == Step::ChangeBlobLease {
                        CHANGE_ID
                    } else {
                        LEASE_ID
                    },
                ),
            }
        }
        Step::BreakBlobLease => Details::LeaseTime {
            remaining: header(headers, "x-ms-lease-time", |value| {
                value
                    .parse::<u32>()
                    .is_ok_and(|seconds| (1..=BREAK_SECONDS).contains(&seconds))
            }),
            id: is("x-ms-lease-id", CHANGE_ID),
        },
        Step::ReadBrokenBlob => Details::LeaseState {
            status: is("x-ms-lease-status", "unlocked"),
            state: is("x-ms-lease-state", "broken"),
            duration: is("x-ms-lease-duration", "fixed"),
        },
        Step::HeadCoolBlob | Step::ReadCoolBlob => Details::Tier {
            cool: is("x-ms-access-tier", "Cool"),
            inferred: is("x-ms-access-tier-inferred", "true"),
            change_time: header(headers, "x-ms-access-tier-change-time", |value| {
                httpdate::parse_http_date(value).is_ok()
            }),
        },
        _ => return None,
    })
}

pub(super) fn matches_fixture(response: &Response) -> bool {
    use Step::*;
    match response.step {
        RejectOldBlobLease => {
            response.status == 409 && response.error_header == ErrorCode::LeaseMismatchLease
        }
        RejectAcquireWhileBreaking => {
            response.status == 409
                && matches!(
                    response.error_header,
                    ErrorCode::LeaseBreakingNoAcquire | ErrorCode::LeaseAlreadyPresent
                )
        }
        RejectPremiumTier => {
            response.status == 400 && response.error_header == ErrorCode::InvalidHeaderValue
        }
        RenewBlobLease | ChangeBlobLease | ReacquireBlobLease => {
            matches!(
                &response.details,
                Some(Details::LeaseId {
                    id: Header::Matches
                })
            )
        }
        BreakBlobLease => matches!(
            &response.details,
            Some(Details::LeaseTime {
                remaining: Header::Matches,
                ..
            })
        ),
        ReadBrokenBlob => matches!(
            &response.details,
            Some(Details::LeaseState {
                state: Header::Matches,
                status: Header::Matches,
                ..
            })
        ),
        HeadCoolBlob | ReadCoolBlob => matches!(
            &response.details,
            Some(Details::Tier {
                cool: Header::Matches,
                change_time: Header::Matches,
                inferred: Header::Missing,
            })
        ),
        _ => true,
    }
}

impl Probe<'_> {
    fn lease_request(&self, action: &'static str) -> RequestBuilder {
        self.request(Method::PUT)
            .query(&[("comp", "lease")])
            .header("content-length", "0")
            .header("x-ms-lease-action", action)
    }

    pub(super) fn finite_lease(&mut self) -> Result<()> {
        let seed = self.setup(
            self.put_blob(INITIAL, "initial"),
            201,
            "seed finite lease blob",
        )?;
        let etag = usable_etag(seed.headers()).context("finite lease seed lacks ETag")?;
        let acquire = |probe: &Self, id: &str| {
            probe
                .lease_request("acquire")
                .header("x-ms-lease-duration", FINITE)
                .header("x-ms-proposed-lease-id", id)
        };
        let renew =
            |probe: &Self, id: &str| probe.lease_request("renew").header("x-ms-lease-id", id);
        self.record(Step::AcquireLease, acquire(self, LEASE_ID), Some(etag))?;
        self.record(Step::RenewBlobLease, renew(self, LEASE_ID), Some(etag))?;
        self.record(
            Step::ChangeBlobLease,
            self.lease_request("change")
                .header("x-ms-lease-id", LEASE_ID)
                .header("x-ms-proposed-lease-id", CHANGE_ID),
            Some(etag),
        )?;
        self.record(Step::RejectOldBlobLease, renew(self, LEASE_ID), Some(etag))?;
        let breaking = self.record(
            Step::BreakBlobLease,
            self.lease_request("break")
                .header("x-ms-lease-break-period", BREAK_SECONDS.to_string()),
            Some(etag),
        )?;
        let seconds = breaking
            .lease_time
            .filter(|seconds| (1..=BREAK_SECONDS).contains(seconds))
            .context("break did not report a bounded positive lease-time")?;
        let check_at = Instant::now() + Duration::from_secs(u64::from(seconds) + 1);
        self.record(
            Step::RejectAcquireWhileBreaking,
            acquire(self, CHANGE_ID),
            Some(etag),
        )?;
        thread::sleep(check_at.saturating_duration_since(Instant::now()));
        self.record(Step::ReadBrokenBlob, self.request(Method::HEAD), Some(etag))?;
        self.record(
            Step::ReacquireBlobLease,
            acquire(self, LEASE_ID),
            Some(etag),
        )?;
        self.record(
            Step::ReleaseLease,
            self.lease_request("release")
                .header("x-ms-lease-id", LEASE_ID),
            Some(etag),
        )?;
        Ok(())
    }

    pub(super) fn set_tier(&mut self) -> Result<()> {
        let seed = self.setup(
            self.put_blob(INITIAL, "initial"),
            201,
            "seed block blob for tiering",
        )?;
        let etag = usable_etag(seed.headers()).context("tiering seed lacks ETag")?;
        let tier = |probe: &Self, tier: &str| {
            probe
                .request(Method::PUT)
                .query(&[("comp", "tier")])
                .header("content-length", "0")
                .header("x-ms-access-tier", tier)
        };
        self.record(Step::SetCoolTier, tier(self, "Cool"), Some(etag))?;
        self.record(Step::HeadCoolBlob, self.request(Method::HEAD), Some(etag))?;
        self.record(Step::RejectPremiumTier, tier(self, "P10"), Some(etag))?;
        let after = self.record(Step::ReadCoolBlob, self.request(Method::GET), Some(etag))?;
        ensure!(
            after.bytes == INITIAL,
            "tier change did not retain the synthetic data"
        );
        Ok(())
    }
}
