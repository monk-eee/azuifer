use super::{
    Details, ErrorCode, FIRST_BLOCK, Header, INITIAL, Probe, REJECTED, REPLACEMENT, Response,
    SECOND_BLOCK, Step, header, header_text, usable_etag,
};
use crate::contracts::cassette::is_utc_timestamp;
use anyhow::{Context as _, Result, ensure};
use reqwest::{Method, blocking::RequestBuilder, header::HeaderMap};

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
pub(super) const GROWN_PAGES: [u8; 4 * PAGE_SIZE] = {
    let mut pages = [0; 4 * PAGE_SIZE];
    let (preserved, _) = pages.split_at_mut(2 * PAGE_SIZE);
    preserved.copy_from_slice(&SPARSE_PAGES);
    pages
};
const SEQUENCE: u64 = 3;
pub(super) const UNALIGNED_PAGE_RANGE: &str = "bytes=513-1024";

pub(super) fn details(step: Step, headers: &HeaderMap) -> Option<Details> {
    use Step::*;
    let number = |name| header_text(headers, name).and_then(|value| value.parse().ok());
    Some(match step {
        AcquireLease | RenewContainerLease | ReleaseLease => Details::LeaseId {
            id: header(headers, "x-ms-lease-id", |id| id == LEASE_ID),
        },
        ReadLeasedOriginal | ReadLeasedReplacement | ReadReleased | ReadLeasedContainer => {
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
        AppendFirst | AppendSecond | ReadFirstAppend | ReadBothAppends | AppendAtMaxSize => {
            Details::Append {
                offset: number("x-ms-blob-append-offset"),
                blocks: number("x-ms-blob-committed-block-count"),
            }
        }
        WritePage
        | ReadSparsePages
        | ReadPagesAfterRejection
        | ClearPage
        | ReadClearedPages
        | ShrinkPageBlob
        | ReadShrunkPages
        | GrowAndMaxSequence
        | ReadGrownPages
        | UpdateSequence
        | IncrementSequence => Details::Sequence {
            number: number("x-ms-blob-sequence-number"),
        },
        SealAppend | ReadSealedAppend => Details::AppendSeal {
            sealed: header(headers, "x-ms-blob-sealed", |value| value == "true"),
            blocks: number("x-ms-blob-committed-block-count"),
        },
        _ => return None,
    })
}

pub(super) fn matches_new_fixture(response: &Response) -> bool {
    use Step::*;
    let status_and_code = |status, code| response.status == status && response.error_header == code;
    let sequence = |expected| matches!(&response.details, Some(Details::Sequence { number: Some(number) }) if *number == expected);
    match response.step {
        RejectBlockWidth => status_and_code(400, ErrorCode::InvalidBlobOrBlock),
        RejectUnalignedPage => status_and_code(400, ErrorCode::InvalidHeaderValue),
        RejectAppendOverMax => status_and_code(412, ErrorCode::MaxBlobSizeConditionNotMet),
        RejectSealedAppend => status_and_code(409, ErrorCode::BlobIsSealed),
        ShrinkPageBlob | ReadShrunkPages | IncrementSequence => sequence(3),
        GrowAndMaxSequence | ReadGrownPages => sequence(7),
        UpdateSequence => sequence(2),
        AppendAtMaxSize => matches!(
            response.details,
            Some(Details::Append {
                offset: Some(0),
                blocks: Some(1)
            })
        ),
        ReadSealedAppend => matches!(
            response.details,
            Some(Details::AppendSeal {
                sealed: Header::Matches,
                blocks: Some(1)
            })
        ),
        _ => true,
    }
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

    pub(super) fn append_sealing(&mut self) -> Result<()> {
        let created = self.setup(
            self.create_blob("AppendBlob", "appended")
                .header("content-length", "0"),
            201,
            "create append blob for seal probe",
        )?;
        let initial = usable_etag(created.headers()).context("append creation lacks ETag")?;
        let size = FIRST_BLOCK.len();
        let appended = self
            .record(
                Step::AppendAtMaxSize,
                self.append_block(0, FIRST_BLOCK)
                    .header("x-ms-blob-condition-maxsize", size.to_string()),
                Some(initial),
            )?
            .etag
            .context("append lacks ETag")?;
        self.record(
            Step::RejectAppendOverMax,
            self.append_block(size, b"x")
                .header("x-ms-blob-condition-maxsize", size.to_string()),
            Some(&appended),
        )?;
        let sealed = self
            .record(
                Step::SealAppend,
                self.request(Method::PUT)
                    .query(&[("comp", "seal")])
                    .header("content-length", "0")
                    .header("if-match", &appended),
                Some(&appended),
            )?
            .etag
            .context("seal lacks ETag")?;
        self.record(
            Step::RejectSealedAppend,
            self.append_block(size, b"x"),
            Some(&sealed),
        )?;
        self.record(
            Step::ReadSealedAppend,
            self.request(Method::GET),
            Some(&sealed),
        )?;
        Ok(())
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

    pub(super) fn page_resize_sequence(&mut self) -> Result<()> {
        self.setup(
            self.create_blob("PageBlob", "pages")
                .header("content-length", "0")
                .header("x-ms-blob-content-length", "2048")
                .header("x-ms-blob-sequence-number", SEQUENCE.to_string()),
            201,
            "create page blob for range and resize probe",
        )?;
        let written = self.setup(
            self.request(Method::PUT)
                .query(&[("comp", "page")])
                .header("x-ms-page-write", "update")
                .header("x-ms-range", "bytes=512-1535")
                .body(&[b'p'; 2 * PAGE_SIZE][..]),
            201,
            "allocate two adjacent pages",
        )?;
        let initial = usable_etag(written.headers()).context("page write lacks ETag")?;
        let list = |probe: &Self| probe.request(Method::GET).query(&[("comp", "pagelist")]);
        self.record(Step::ListPageRanges, list(self), Some(initial))?;
        self.record(
            Step::ListBoundedPageRanges,
            list(self).header("x-ms-range", "bytes=1024-1535"),
            Some(initial),
        )?;
        self.record(
            Step::RejectUnalignedPage,
            self.request(Method::PUT)
                .query(&[("comp", "page")])
                .header("x-ms-page-write", "update")
                .header("x-ms-range", UNALIGNED_PAGE_RANGE)
                .body(&[b'x'; PAGE_SIZE][..]),
            Some(initial),
        )?;
        let properties = |probe: &Self| {
            probe
                .request(Method::PUT)
                .query(&[("comp", "properties")])
                .header("content-length", "0")
        };
        let shrunk = self
            .record(
                Step::ShrinkPageBlob,
                properties(self).header("x-ms-blob-content-length", "1024"),
                Some(initial),
            )?
            .etag
            .context("shrink lacks ETag")?;
        self.record(
            Step::ReadShrunkPages,
            self.request(Method::GET),
            Some(&shrunk),
        )?;
        let grown = self
            .record(
                Step::GrowAndMaxSequence,
                properties(self)
                    .header("x-ms-blob-content-length", "2048")
                    .header("x-ms-sequence-number-action", "max")
                    .header("x-ms-blob-sequence-number", "7"),
                Some(&shrunk),
            )?
            .etag
            .context("grow lacks ETag")?;
        self.record(
            Step::ReadGrownPages,
            self.request(Method::GET),
            Some(&grown),
        )?;
        let updated = self
            .record(
                Step::UpdateSequence,
                properties(self)
                    .header("x-ms-sequence-number-action", "update")
                    .header("x-ms-blob-sequence-number", "2"),
                Some(&grown),
            )?
            .etag
            .context("sequence update lacks ETag")?;
        self.record(
            Step::IncrementSequence,
            properties(self).header("x-ms-sequence-number-action", "increment"),
            Some(&updated),
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
