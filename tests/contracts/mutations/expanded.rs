use super::{
    Details, ErrorCode, Header, INITIAL, Probe, REPLACEMENT, Response, Step, header, header_text,
};
use crate::contracts::{require_status, send};
use anyhow::{Context as _, Result};
use base64::{Engine as _, engine::general_purpose::STANDARD};
use crc::{CRC_64_NVME, Crc};
use md5::{Digest as _, Md5};
use reqwest::{Method, header::HeaderMap};
use std::time::{Duration, SystemTime};

const MD5_FLAG: &str = "x-ms-range-get-content-md5";
const CRC64_FLAG: &str = "x-ms-range-get-content-crc64";
const FIRST_RANGE: &str = "bytes=0-4";
const SECOND_RANGE: &str = "bytes=5-11";
const TAIL_RANGE: &str = "bytes=12-";
const STALE: &str = "\"synthetic-stale-etag\"";
pub(super) const UPDATED: &str = "updated";
const CONTENT_TYPE: &str = "application/octet-stream";
const CACHE_CONTROL: &str = "max-age=300";

pub(super) fn range_bounds(step: Step) -> Option<(usize, usize)> {
    Some(match step {
        Step::RangeMd5 | Step::ReadMatchingRange => (0, 4),
        Step::RangeCrc64Precedence => (5, 11),
        Step::RangeTail => (12, INITIAL.len() - 1),
        _ => return None,
    })
}

pub(super) fn details(step: Step, headers: &HeaderMap) -> Option<Details> {
    use Step::*;
    let matches = |name, expected: &str| header(headers, name, |value| value == expected);
    let range = |bounds| {
        let length = INITIAL.len();
        let (expected, bytes) = match bounds {
            Some((start, end)) => (
                format!("bytes {start}-{end}/{length}"),
                &INITIAL[start..=end],
            ),
            None if step == RejectPastEnd => (format!("bytes */{length}"), INITIAL),
            None => (String::new(), INITIAL),
        };
        let digest = STANDARD.encode(Md5::digest(bytes));
        let crc = Crc::<u64>::new(&CRC_64_NVME).checksum(bytes);
        Details::Range {
            content_range: matches("content-range", &expected),
            md5: matches("content-md5", &digest),
            crc64: matches("x-ms-content-crc64", &STANDARD.encode(crc.to_le_bytes())),
        }
    };
    Some(match step {
        RangeMd5
        | RangeCrc64Precedence
        | RangeTail
        | RejectBothChecksums
        | RejectPastEnd
        | ReadOriginalWithChecksum
        | ReadMatchingRange => range(range_bounds(step)),
        ReadMetadata | ReadMetadataAfterRejection => Details::Metadata {
            purpose: matches("x-ms-meta-purpose", UPDATED),
            removed: matches("x-ms-meta-remove", "present"),
        },
        HeadProperties | ReadUpdatedProperties => Details::Properties {
            purpose: matches("x-ms-meta-purpose", UPDATED),
            removed: matches("x-ms-meta-remove", "present"),
            content_type: matches("content-type", CONTENT_TYPE),
            cache_control: matches("cache-control", CACHE_CONTROL),
            language: matches("content-language", "en"),
            length: header_text(headers, "content-length").and_then(|value| value.parse().ok()),
        },
        DeleteCurrent => Details::Deletion {
            permanent: matches("x-ms-delete-type-permanent", "true"),
        },
        _ => return None,
    })
}

pub(super) fn matches_fixture(response: &Response) -> bool {
    use Step::*;
    let status_and_code = |status, code| response.status == status && response.error_header == code;
    match response.step {
        RangeMd5 => matches!(
            &response.details,
            Some(Details::Range {
                content_range: Header::Matches,
                md5: Header::Matches,
                ..
            })
        ),
        RangeCrc64Precedence => matches!(
            &response.details,
            Some(Details::Range {
                content_range: Header::Matches,
                crc64: Header::Matches,
                ..
            })
        ),
        RangeTail | ReadMatchingRange => matches!(
            &response.details,
            Some(Details::Range {
                content_range: Header::Matches,
                ..
            })
        ),
        ReadOriginalWithChecksum => matches!(
            &response.details,
            Some(Details::Range {
                content_range: Header::Missing,
                md5: Header::Matches,
                ..
            })
        ),
        ReadMetadata | ReadMetadataAfterRejection => matches!(
            &response.details,
            Some(Details::Metadata {
                purpose: Header::Matches,
                removed: Header::Missing,
            })
        ),
        HeadProperties | ReadUpdatedProperties => {
            matches!(&response.details, Some(Details::Properties {
            purpose: Header::Matches, removed: Header::Missing,
            content_type: Header::Matches, cache_control: Header::Matches,
            language: Header::Missing, length: Some(length),
        }) if *length == INITIAL.len() as u64)
        }
        RejectBothChecksums => status_and_code(400, ErrorCode::BothCrc64AndMd5RangeHeaderPresent),
        RejectPastEnd => status_and_code(416, ErrorCode::InvalidRange),
        RejectStaleMetadata | RejectStaleRead | RejectOldUnmodifiedSince | RejectStaleDelete => {
            status_and_code(412, ErrorCode::ConditionNotMet)
        }
        ReadDeleted | DeleteMissing => status_and_code(404, ErrorCode::BlobNotFound),
        _ => true,
    }
}

impl Probe<'_> {
    pub(super) fn range_checksums(&mut self) -> Result<()> {
        let etag = self
            .record(Step::Seed, self.put_blob(INITIAL, "initial"), None)?
            .etag
            .context("seed response lacks a usable ETag")?;
        for (step, request) in [
            (
                Step::RangeMd5,
                self.request(Method::GET)
                    .header("range", FIRST_RANGE)
                    .header(MD5_FLAG, "true"),
            ),
            (
                Step::RangeCrc64Precedence,
                self.request(Method::GET)
                    .header("range", FIRST_RANGE)
                    .header("x-ms-range", SECOND_RANGE)
                    .header(CRC64_FLAG, "true"),
            ),
            (
                Step::RangeTail,
                self.request(Method::GET).header("range", TAIL_RANGE),
            ),
            (
                Step::RejectBothChecksums,
                self.request(Method::GET)
                    .header("range", FIRST_RANGE)
                    .header(MD5_FLAG, "true")
                    .header(CRC64_FLAG, "true"),
            ),
            (
                Step::RejectPastEnd,
                self.request(Method::GET)
                    .header("range", format!("bytes={}-", INITIAL.len() + 1)),
            ),
            (Step::ReadOriginalWithChecksum, self.request(Method::GET)),
        ] {
            self.record(step, request, Some(&etag))?;
        }
        Ok(())
    }

    pub(super) fn metadata_properties(&mut self) -> Result<()> {
        let seed = self
            .put_blob(INITIAL, "initial")
            .header("x-ms-meta-remove", "present")
            .header("x-ms-blob-content-language", "en");
        let original = self
            .record(Step::Seed, seed, None)?
            .etag
            .context("seed response lacks a usable ETag")?;
        let set_metadata = |probe: &Self, etag: &str, value: &str| {
            probe
                .request(Method::PUT)
                .query(&[("comp", "metadata")])
                .header("content-length", "0")
                .header("if-match", etag)
                .header("x-ms-meta-purpose", value)
        };
        let get_metadata = |probe: &Self| probe.request(Method::GET).query(&[("comp", "metadata")]);
        let updated = self
            .record(
                Step::SetMetadata,
                set_metadata(self, &original, UPDATED),
                Some(&original),
            )?
            .etag
            .context("updated metadata lacks a usable ETag")?;
        self.record(Step::ReadMetadata, get_metadata(self), Some(&updated))?;
        self.record(
            Step::RejectStaleMetadata,
            set_metadata(self, &original, "rejected"),
            Some(&updated),
        )?;
        self.record(
            Step::ReadMetadataAfterRejection,
            get_metadata(self),
            Some(&updated),
        )?;
        let properties = self
            .record(
                Step::SetProperties,
                self.request(Method::PUT)
                    .query(&[("comp", "properties")])
                    .header("content-length", "0")
                    .header("if-match", &updated)
                    .header("x-ms-blob-content-type", CONTENT_TYPE)
                    .header("x-ms-blob-cache-control", CACHE_CONTROL),
                Some(&updated),
            )?
            .etag
            .context("updated properties lack a usable ETag")?;
        self.record(
            Step::HeadProperties,
            self.request(Method::HEAD),
            Some(&properties),
        )?;
        self.record(
            Step::ReadUpdatedProperties,
            self.request(Method::GET),
            Some(&properties),
        )?;
        Ok(())
    }

    fn seed_for_conditions(&self) -> Result<(String, SystemTime)> {
        let response = send(self.put_blob(INITIAL, "initial"), "seed conditional probe")?;
        require_status(&response, 201, "seed conditional probe")?;
        let etag = super::usable_etag(response.headers()).context("seed lacks a usable ETag")?;
        let modified = header_text(response.headers(), "last-modified")
            .and_then(|date| httpdate::parse_http_date(date).ok())
            .context("seed lacks a usable Last-Modified date")?;
        Ok((etag.to_owned(), modified))
    }

    pub(super) fn conditional_reads(&mut self) -> Result<()> {
        let (etag, modified) = self.seed_for_conditions()?;
        let same = httpdate::fmt_http_date(modified);
        let before = httpdate::fmt_http_date(
            modified
                .checked_sub(Duration::from_secs(60))
                .context("seed date cannot be offset")?,
        );
        for (step, request) in [
            (
                Step::HeadNotModified,
                self.request(Method::HEAD).header("if-none-match", &etag),
            ),
            (
                Step::RejectStaleRead,
                self.request(Method::GET).header("if-match", STALE),
            ),
            (
                Step::GetNotModified,
                self.request(Method::GET).header("if-modified-since", &same),
            ),
            (
                Step::RejectOldUnmodifiedSince,
                self.request(Method::GET)
                    .header("if-unmodified-since", before),
            ),
            (
                Step::ReadMatchingRange,
                self.request(Method::GET)
                    .header("if-match", &etag)
                    .header("range", FIRST_RANGE),
            ),
            (
                Step::MixedNotModified,
                self.request(Method::GET)
                    .header("if-match", &etag)
                    .header("if-unmodified-since", &same)
                    .header("if-none-match", STALE)
                    .header("if-modified-since", &same),
            ),
        ] {
            self.record_conditional(step, request, Some(&etag), Some(modified))?;
        }
        Ok(())
    }

    pub(super) fn conditional_delete(&mut self) -> Result<()> {
        let (etag, _) = self.seed_for_conditions()?;
        self.record(
            Step::DeleteCurrent,
            self.request(Method::DELETE).header("if-match", &etag),
            Some(&etag),
        )?;
        self.record(Step::ReadDeleted, self.request(Method::GET), None)?;
        self.record(Step::DeleteMissing, self.request(Method::DELETE), None)?;
        let recreated = self
            .record(
                Step::Recreate,
                self.put_blob(REPLACEMENT, "replacement")
                    .header("if-none-match", "*"),
                Some(&etag),
            )?
            .etag
            .context("recreated blob lacks a usable ETag")?;
        self.record(
            Step::RejectStaleDelete,
            self.request(Method::DELETE).header("if-match", &etag),
            Some(&recreated),
        )?;
        self.record(
            Step::ReadReplacement,
            self.request(Method::GET),
            Some(&recreated),
        )?;
        Ok(())
    }
}
