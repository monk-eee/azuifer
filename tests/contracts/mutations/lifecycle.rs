use super::{
    FIRST_BLOCK, INITIAL, Probe, REJECTED, REPLACEMENT, SECOND_BLOCK, Step, header, header_text,
};
use crate::contracts::cassette::{Header, is_utc_timestamp};
use anyhow::{Context as _, Result, ensure};
use reqwest::{Method, blocking::RequestBuilder, header::HeaderMap};
use serde::{Deserialize, Serialize};

pub(super) const LEASE_ID: &str = "00000000-0000-4000-8000-000000000001";
pub(super) const WRONG_LEASE_ID: &str = "00000000-0000-4000-8000-000000000002";
pub(super) const APPENDED: &[u8] = b"first\nsecond ";
pub(super) const PAGE_SIZE: usize = 512;
pub(super) const PAGE_BLOCK: [u8; PAGE_SIZE] = [b'p'; PAGE_SIZE];
pub(super) const SPARSE_PAGES: [u8; 2 * PAGE_SIZE] = {
    let mut pages = [0; 2 * PAGE_SIZE];
    let (_, second) = pages.split_at_mut(PAGE_SIZE);
    second.copy_from_slice(&PAGE_BLOCK);
    pages
};
const SEQUENCE: u64 = 3;

#[derive(Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub(super) enum Details {
    LeaseId {
        id: Header,
    },
    LeaseState {
        status: Header,
        state: Header,
        duration: Header,
    },
    Snapshot {
        timestamp: Header,
    },
    Append {
        offset: Option<u64>,
        blocks: Option<u64>,
    },
    Sequence {
        number: Option<u64>,
    },
}

pub(super) fn details(step: Step, headers: &HeaderMap) -> Option<Details> {
    use Step::*;
    let number = |name| header_text(headers, name).and_then(|value| value.parse().ok());
    Some(match step {
        AcquireLease | ReleaseLease => Details::LeaseId {
            id: header(headers, "x-ms-lease-id", |id| id == LEASE_ID),
        },
        ReadLeasedOriginal | ReadLeasedReplacement | ReadReleased => {
            let (status, state) = if step == ReadReleased {
                ("unlocked", "available")
            } else {
                ("locked", "leased")
            };
            Details::LeaseState {
                status: header(headers, "x-ms-lease-status", |value| value == status),
                state: header(headers, "x-ms-lease-state", |value| value == state),
                duration: header(headers, "x-ms-lease-duration", |value| value == "infinite"),
            }
        }
        CreateSnapshot => Details::Snapshot {
            timestamp: header(headers, "x-ms-snapshot", is_utc_timestamp),
        },
        AppendFirst | AppendSecond | ReadFirstAppend | ReadBothAppends => Details::Append {
            offset: number("x-ms-blob-append-offset"),
            blocks: number("x-ms-blob-committed-block-count"),
        },
        WritePage | ReadSparsePages | ReadPagesAfterRejection | ClearPage | ReadClearedPages => {
            Details::Sequence {
                number: number("x-ms-blob-sequence-number"),
            }
        }
        _ => return None,
    })
}

impl Probe<'_> {
    pub(super) fn lease_guard(&mut self) -> Result<()> {
        let initial = self
            .record(Step::Seed, self.put_blob(INITIAL, "initial"), None)?
            .etag
            .context("seed response lacks a usable ETag")?;
        self.record(
            Step::AcquireLease,
            self.request(Method::PUT)
                .query(&[("comp", "lease")])
                .header("content-length", "0")
                .header("x-ms-lease-action", "acquire")
                .header("x-ms-lease-duration", "-1")
                .header("x-ms-proposed-lease-id", LEASE_ID),
            Some(&initial),
        )?;
        self.record(
            Step::RejectMissingLease,
            self.put_blob(REJECTED, "rejected"),
            Some(&initial),
        )?;
        self.record(
            Step::RejectWrongLease,
            self.put_blob(REJECTED, "rejected")
                .header("x-ms-lease-id", WRONG_LEASE_ID),
            Some(&initial),
        )?;
        self.record(
            Step::ReadLeasedOriginal,
            self.request(Method::GET),
            Some(&initial),
        )?;
        let replacement = self
            .record(
                Step::Overwrite,
                self.put_blob(REPLACEMENT, "replacement")
                    .header("x-ms-lease-id", LEASE_ID),
                Some(&initial),
            )?
            .etag
            .context("overwrite response lacks a usable ETag")?;
        self.record(
            Step::ReadLeasedReplacement,
            self.request(Method::GET),
            Some(&replacement),
        )?;
        self.record(
            Step::ReleaseLease,
            self.request(Method::PUT)
                .query(&[("comp", "lease")])
                .header("content-length", "0")
                .header("x-ms-lease-action", "release")
                .header("x-ms-lease-id", LEASE_ID),
            Some(&replacement),
        )?;
        self.record(
            Step::ReadReleased,
            self.request(Method::GET),
            Some(&replacement),
        )?;
        Ok(())
    }

    pub(super) fn snapshot_recovery(&mut self) -> Result<()> {
        let initial = self
            .record(Step::Seed, self.put_blob(INITIAL, "initial"), None)?
            .etag
            .context("seed response lacks a usable ETag")?;
        let snapshot = self
            .record(
                Step::CreateSnapshot,
                self.request(Method::PUT)
                    .query(&[("comp", "snapshot")])
                    .header("content-length", "0"),
                Some(&initial),
            )?
            .snapshot
            .context("snapshot response lacks a usable selector")?;
        let replacement = self
            .record(
                Step::Overwrite,
                self.put_blob(REPLACEMENT, "replacement")
                    .header("if-match", &initial),
                Some(&initial),
            )?
            .etag
            .context("overwrite response lacks a usable ETag")?;
        self.record(
            Step::RejectDeleteWithSnapshots,
            self.request(Method::DELETE),
            Some(&replacement),
        )?;
        let observed = self.record(
            Step::ReadSnapshot,
            self.request(Method::GET).query(&[("snapshot", snapshot)]),
            Some(&initial),
        )?;
        ensure!(
            observed.bytes == INITIAL,
            "snapshot did not return synthetic seed bytes"
        );
        self.record(
            Step::ReadReplacement,
            self.request(Method::GET),
            Some(&replacement),
        )?;
        let restored = self
            .record(
                Step::RestoreSnapshot,
                self.put_blob(observed.bytes, "initial")
                    .header("if-match", &replacement),
                Some(&replacement),
            )?
            .etag
            .context("restore response lacks a usable ETag")?;
        self.record(
            Step::ReadRestored,
            self.request(Method::GET),
            Some(&restored),
        )?;
        Ok(())
    }

    pub(super) fn append_position(&mut self) -> Result<()> {
        let create = self
            .record(
                Step::CreateAppend,
                self.create_blob("AppendBlob", "appended")
                    .header("content-length", "0"),
                None,
            )?
            .etag
            .context("append creation lacks a usable ETag")?;
        let first = self
            .record(
                Step::AppendFirst,
                self.append_block(0, FIRST_BLOCK),
                Some(&create),
            )?
            .etag
            .context("first append lacks a usable ETag")?;
        self.record(
            Step::RejectAppendPosition,
            self.append_block(0, REJECTED),
            Some(&first),
        )?;
        self.record(
            Step::ReadFirstAppend,
            self.request(Method::GET),
            Some(&first),
        )?;
        let final_tag = self
            .record(
                Step::AppendSecond,
                self.append_block(FIRST_BLOCK.len(), SECOND_BLOCK),
                Some(&first),
            )?
            .etag
            .context("second append lacks a usable ETag")?;
        self.record(
            Step::ReadBothAppends,
            self.request(Method::GET),
            Some(&final_tag),
        )?;
        Ok(())
    }

    fn append_block(&self, position: usize, bytes: &'static [u8]) -> RequestBuilder {
        self.request(Method::PUT)
            .query(&[("comp", "appendblock")])
            .header("x-ms-blob-condition-appendpos", position.to_string())
            .body(bytes)
    }

    pub(super) fn sparse_page_writes(&mut self) -> Result<()> {
        let create = self
            .record(
                Step::CreatePage,
                self.create_blob("PageBlob", "pages")
                    .header("content-length", "0")
                    .header("x-ms-blob-content-length", (2 * PAGE_SIZE).to_string())
                    .header("x-ms-blob-sequence-number", SEQUENCE.to_string()),
                None,
            )?
            .etag
            .context("page creation lacks a usable ETag")?;
        let written = self
            .record(
                Step::WritePage,
                self.write_page(SEQUENCE, &PAGE_BLOCK),
                Some(&create),
            )?
            .etag
            .context("page write lacks a usable ETag")?;
        self.record(
            Step::ReadSparsePages,
            self.request(Method::GET),
            Some(&written),
        )?;
        self.record(
            Step::RejectPageSequence,
            self.write_page(SEQUENCE + 1, &[b'x'; PAGE_SIZE]),
            Some(&written),
        )?;
        self.record(
            Step::ReadPagesAfterRejection,
            self.request(Method::GET),
            Some(&written),
        )?;
        let cleared = self
            .record(
                Step::ClearPage,
                self.page("clear").header("content-length", "0"),
                Some(&written),
            )?
            .etag
            .context("page clear lacks a usable ETag")?;
        self.record(
            Step::ReadClearedPages,
            self.request(Method::GET),
            Some(&cleared),
        )?;
        Ok(())
    }

    fn write_page(&self, sequence: u64, bytes: &'static [u8]) -> RequestBuilder {
        self.page("update")
            .header("x-ms-if-sequence-number-eq", sequence.to_string())
            .body(bytes)
    }

    fn page(&self, action: &'static str) -> RequestBuilder {
        self.request(Method::PUT)
            .query(&[("comp", "page")])
            .header("x-ms-page-write", action)
            .header(
                "x-ms-range",
                format!("bytes={PAGE_SIZE}-{}", 2 * PAGE_SIZE - 1),
            )
    }
}
