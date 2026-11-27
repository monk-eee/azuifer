use super::{
    VERSION,
    cassette::{
        ApiVersion, ErrorCode, Header, Media, Source, error_message, flat_xml, header, header_text,
        is_utc_timestamp, media,
    },
    read_bounded, request, sent, with_fresh_container, with_local,
};
use anyhow::{Context as _, Result, ensure};
use reqwest::{
    Method, Url,
    blocking::{Client, RequestBuilder},
};
use serde::{Deserialize, Serialize};
use std::{fs::File, path::Path};

mod input;
mod lifecycle;

const SCHEMA_VERSION: u8 = 2;
const INITIAL: &[u8] = b"original synthetic bytes\n";
const REPLACEMENT: &[u8] = b"replacement synthetic bytes\n";
const REJECTED: &[u8] = b"these bytes must not be stored\n";
const FIRST_BLOCK: &[u8] = b"first\n";
const SECOND_BLOCK: &[u8] = b"second ";
const ASSEMBLED: &[u8] = b"second first\n";

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub(super) enum Case {
    #[serde(rename = "blob-conditional-overwrite")]
    ConditionalOverwrite,
    #[serde(rename = "blob-staged-block-commit")]
    StagedBlockCommit,
    #[serde(rename = "blob-lease-guard")]
    LeaseGuard,
    #[serde(rename = "blob-snapshot-recovery")]
    SnapshotRecovery,
    #[serde(rename = "blob-append-position")]
    AppendPosition,
    #[serde(rename = "blob-sparse-page-writes")]
    SparsePageWrites,
}

impl Case {
    pub(super) fn file_stem(self) -> &'static str {
        match self {
            Self::ConditionalOverwrite => "blob-conditional-overwrite",
            Self::StagedBlockCommit => "blob-staged-block-commit",
            Self::LeaseGuard => "blob-lease-guard",
            Self::SnapshotRecovery => "blob-snapshot-recovery",
            Self::AppendPosition => "blob-append-position",
            Self::SparsePageWrites => "blob-sparse-page-writes",
        }
    }

    fn steps(self) -> &'static [Step] {
        use Step::*;
        match self {
            Self::ConditionalOverwrite => &[
                Seed,
                RejectExisting,
                ReadOriginal,
                Overwrite,
                RejectStale,
                ReadReplacement,
            ],
            Self::StagedBlockCommit => &[
                StageFirst,
                StageSecond,
                ReadUncommitted,
                Commit,
                ReadCommitted,
                RejectUnknownBlock,
                ReadAfterRejectedCommit,
            ],
            Self::LeaseGuard => &[
                Seed,
                AcquireLease,
                RejectMissingLease,
                RejectWrongLease,
                ReadLeasedOriginal,
                Overwrite,
                ReadLeasedReplacement,
                ReleaseLease,
                ReadReleased,
            ],
            Self::SnapshotRecovery => &[
                Seed,
                CreateSnapshot,
                Overwrite,
                RejectDeleteWithSnapshots,
                ReadSnapshot,
                ReadReplacement,
                RestoreSnapshot,
                ReadRestored,
            ],
            Self::AppendPosition => &[
                CreateAppend,
                AppendFirst,
                RejectAppendPosition,
                ReadFirstAppend,
                AppendSecond,
                ReadBothAppends,
            ],
            Self::SparsePageWrites => &[
                CreatePage,
                WritePage,
                ReadSparsePages,
                RejectPageSequence,
                ReadPagesAfterRejection,
                ClearPage,
                ReadClearedPages,
            ],
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
enum Step {
    Seed,
    RejectExisting,
    ReadOriginal,
    Overwrite,
    RejectStale,
    ReadReplacement,
    StageFirst,
    StageSecond,
    ReadUncommitted,
    Commit,
    ReadCommitted,
    RejectUnknownBlock,
    ReadAfterRejectedCommit,
    AcquireLease,
    RejectMissingLease,
    RejectWrongLease,
    ReadLeasedOriginal,
    ReadLeasedReplacement,
    ReleaseLease,
    ReadReleased,
    CreateSnapshot,
    RejectDeleteWithSnapshots,
    ReadSnapshot,
    RestoreSnapshot,
    ReadRestored,
    CreateAppend,
    AppendFirst,
    RejectAppendPosition,
    ReadFirstAppend,
    AppendSecond,
    ReadBothAppends,
    CreatePage,
    WritePage,
    ReadSparsePages,
    RejectPageSequence,
    ReadPagesAfterRejection,
    ClearPage,
    ReadClearedPages,
}

impl Step {
    fn expected_blob(self) -> Option<(&'static [u8], &'static str, &'static str)> {
        match self {
            Self::ReadOriginal
            | Self::ReadLeasedOriginal
            | Self::ReadSnapshot
            | Self::ReadRestored => Some((INITIAL, "initial", "BlockBlob")),
            Self::ReadReplacement | Self::ReadLeasedReplacement | Self::ReadReleased => {
                Some((REPLACEMENT, "replacement", "BlockBlob"))
            }
            Self::ReadCommitted | Self::ReadAfterRejectedCommit => {
                Some((ASSEMBLED, "assembled", "BlockBlob"))
            }
            Self::ReadFirstAppend => Some((FIRST_BLOCK, "appended", "AppendBlob")),
            Self::ReadBothAppends => Some((lifecycle::APPENDED, "appended", "AppendBlob")),
            Self::ReadSparsePages | Self::ReadPagesAfterRejection => {
                Some((&lifecycle::SPARSE_PAGES, "pages", "PageBlob"))
            }
            Self::ReadClearedPages => Some((&[0; 2 * lifecycle::PAGE_SIZE], "pages", "PageBlob")),
            _ => None,
        }
    }

    fn is_rejection(self) -> bool {
        matches!(
            self,
            Self::RejectExisting
                | Self::RejectStale
                | Self::ReadUncommitted
                | Self::RejectUnknownBlock
                | Self::RejectMissingLease
                | Self::RejectWrongLease
                | Self::RejectDeleteWithSnapshots
                | Self::RejectAppendPosition
                | Self::RejectPageSequence
        )
    }

    fn expected_write(self) -> Option<(u16, Tag)> {
        Some(match self {
            Self::Seed | Self::Commit | Self::CreateAppend | Self::CreatePage => (201, Tag::Valid),
            Self::StageFirst | Self::StageSecond => (201, Tag::Missing),
            Self::Overwrite
            | Self::RestoreSnapshot
            | Self::AppendFirst
            | Self::AppendSecond
            | Self::WritePage
            | Self::ClearPage => (201, Tag::Changed),
            Self::AcquireLease | Self::CreateSnapshot => (201, Tag::Matches),
            Self::ReleaseLease => (200, Tag::Matches),
            _ => return None,
        })
    }
}

#[derive(Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
enum Tag {
    Missing,
    Valid,
    Matches,
    Changed,
    Malformed,
}

#[derive(Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
enum Body {
    Empty {},
    Blob {
        bytes_match: bool,
        length: Option<u64>,
        media: Media,
        blob_type: Header,
        metadata: Header,
    },
    XmlError {
        media: Media,
        code: ErrorCode,
        correlation: Header,
        message_matches: bool,
        extra_elements: usize,
    },
    Other {},
}

#[derive(Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
struct Response {
    step: Step,
    request: input::Input,
    status: u16,
    api_version: Header,
    request_id: Header,
    etag: Tag,
    error_header: ErrorCode,
    body: Body,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    details: Option<lifecycle::Details>,
}

#[derive(Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub(super) struct MutationCassette {
    schema_version: u8,
    source: Source,
    pub(super) case: Case,
    api_version: ApiVersion,
    responses: Vec<Response>,
}

impl MutationCassette {
    pub(super) fn validate(&self) -> Result<()> {
        ensure!(
            self.schema_version == SCHEMA_VERSION,
            "unsupported mutation cassette version"
        );
        ensure!(
            self.responses.iter().map(|response| response.step).eq(self
                .case
                .steps()
                .iter()
                .copied()),
            "unexpected mutation cassette steps"
        );
        for r in &self.responses {
            ensure!(
                r.api_version == Header::Matches && r.request_id == Header::Matches,
                "{:?}: missing protocol version or request ID",
                r.step
            );
            let valid = if r.step.is_rejection() {
                (400..500).contains(&r.status)
                    && matches!(&r.body, Body::XmlError { code, media: Media::Xml, .. }
                        if *code == r.error_header && !matches!(code, ErrorCode::Missing | ErrorCode::Other))
            } else if let Some((status, tag)) = r.step.expected_write() {
                r.status == status && r.etag == tag && r.body == (Body::Empty {})
            } else {
                r.step.expected_blob().is_some_and(|(bytes, _, _)| {
                    r.status == 200
                        && r.etag == Tag::Matches
                        && matches!(&r.body, Body::Blob {
                            bytes_match: true, length: Some(length), media: Media::TextPlain,
                            blob_type: Header::Matches, metadata: Header::Matches
                        } if *length == bytes.len() as u64)
                })
            };
            ensure!(
                valid,
                "{:?}: did not produce the expected Blob state: {r:#?}",
                r.step
            );
        }
        Ok(())
    }

    pub(super) fn compare(&self, actual: &Self) -> Result<()> {
        self.validate()?;
        ensure!(
            self.case == actual.case && self.responses.len() == actual.responses.len(),
            "different mutation scenario"
        );
        let differences: Vec<_> = self
            .responses
            .iter()
            .zip(&actual.responses)
            .filter(|(reference, observed)| reference != observed)
            .collect();
        ensure!(
            differences.is_empty(),
            "{}: differing exchanges (reviewed, observed):\n{differences:#?}",
            self.case.file_stem()
        );
        Ok(())
    }
}

struct Probe<'a> {
    client: &'a Client,
    url: Url,
    bearer: &'a str,
    responses: Vec<Response>,
}

struct Observed {
    etag: Option<String>,
    snapshot: Option<String>,
    bytes: Vec<u8>,
}

impl Probe<'_> {
    fn request(&self, method: Method) -> RequestBuilder {
        request(self.client, method, self.url.clone()).bearer_auth(self.bearer)
    }

    fn create_blob(&self, kind: &'static str, metadata: &'static str) -> RequestBuilder {
        self.request(Method::PUT)
            .header("x-ms-blob-type", kind)
            .header("content-type", "text/plain")
            .header("x-ms-meta-purpose", metadata)
    }

    fn put_blob(
        &self,
        bytes: impl Into<reqwest::blocking::Body>,
        metadata: &'static str,
    ) -> RequestBuilder {
        self.create_blob("BlockBlob", metadata).body(bytes)
    }

    fn put_block(&self, id: &str, bytes: &'static [u8]) -> RequestBuilder {
        self.request(Method::PUT)
            .query(&[("comp", "block"), ("blockid", id)])
            .body(bytes)
    }

    fn commit(&self, block_list: &'static str, metadata: &'static str) -> RequestBuilder {
        self.request(Method::PUT)
            .query(&[("comp", "blocklist")])
            .header("content-type", "application/xml")
            .header("x-ms-blob-content-type", "text/plain")
            .header("x-ms-meta-purpose", metadata)
            .body(block_list)
    }

    fn record(
        &mut self,
        step: Step,
        wire: RequestBuilder,
        reference: Option<&str>,
    ) -> Result<Observed> {
        let wire = wire
            .build()
            .map_err(|_| anyhow::anyhow!("{step:?}: could not build Blob probe request"))?;
        let request =
            input::Input::observe(&wire, reference).with_context(|| format!("{step:?}"))?;
        let response = sent(self.client.execute(wire), "send Blob mutation probe")
            .with_context(|| format!("{step:?}"))?;
        let status = response.status().as_u16();
        let headers = response.headers().clone();
        let bytes = read_bounded(response).with_context(|| format!("{step:?}"))?;
        let text = |name| header_text(&headers, name);
        let tag = text("etag").filter(|value| {
            value
                .strip_prefix('"')
                .and_then(|rest| rest.strip_suffix('"'))
                .is_some_and(|inner| {
                    !inner.is_empty() && inner.bytes().all(|b| b.is_ascii_graphic() && b != b'"')
                })
        });
        let etag = match (tag, reference) {
            (None, _) if headers.contains_key("etag") => Tag::Malformed,
            (None, _) => Tag::Missing,
            (Some(_), None) => Tag::Valid,
            (Some(actual), Some(expected)) if actual == expected => Tag::Matches,
            (Some(_), Some(_)) => Tag::Changed,
        };
        let error_header = ErrorCode::from_value(text("x-ms-error-code"));
        let body = if let (200, Some((expected, metadata, kind))) = (status, step.expected_blob()) {
            Body::Blob {
                bytes_match: bytes == expected,
                length: text("content-length").and_then(|value| value.parse().ok()),
                media: media(&headers),
                blob_type: header(&headers, "x-ms-blob-type", |value| value == kind),
                metadata: header(&headers, "x-ms-meta-purpose", |value| value == metadata),
            }
        } else if bytes.is_empty() {
            Body::Empty {}
        } else {
            std::str::from_utf8(&bytes)
                .ok()
                .and_then(|xml| flat_xml(xml, "Error"))
                .and_then(|fields| {
                    let code = ErrorCode::from_value(fields.get("Code").map(String::as_str));
                    let (message, correlation) =
                        error_message(fields.get("Message")?, text("x-ms-request-id"));
                    let expected = match code {
                        ErrorCode::BlobNotFound => "The specified blob does not exist.",
                        ErrorCode::BlobAlreadyExists => "The specified blob already exists.",
                        ErrorCode::ConditionNotMet => {
                            "The condition specified using HTTP conditional header(s) is not met."
                        }
                        ErrorCode::InvalidBlockList => "The specified block list is invalid.",
                        ErrorCode::LeaseIdMissing => "There is currently a lease on the blob and no lease ID was specified in the request.",
                        ErrorCode::LeaseMismatchBlob => "The lease ID specified did not match the lease ID for the blob.",
                        ErrorCode::SnapshotsPresent => "This operation is not permitted because the blob has snapshots.",
                        ErrorCode::AppendPositionConditionNotMet => "The append position condition specified was not met.",
                        ErrorCode::SequenceNumberConditionNotMet => "The sequence number condition specified was not met.",
                        _ => return None,
                    };
                    Some(Body::XmlError {
                        media: media(&headers),
                        code,
                        correlation,
                        message_matches: message == expected,
                        extra_elements: fields
                            .keys()
                            .filter(|name| !matches!(name.as_str(), "Code" | "Message"))
                            .count(),
                    })
                })
                .unwrap_or(Body::Other {})
        };
        self.responses.push(Response {
            step,
            request,
            status,
            etag,
            body,
            error_header,
            details: lifecycle::details(step, &headers),
            api_version: header(&headers, "x-ms-version", |value| value == VERSION),
            request_id: header(&headers, "x-ms-request-id", |id| {
                uuid::Uuid::parse_str(id).is_ok()
            }),
        });
        Ok(Observed {
            etag: tag.map(str::to_owned),
            snapshot: text("x-ms-snapshot")
                .filter(|value| is_utc_timestamp(value))
                .map(str::to_owned),
            bytes,
        })
    }

    fn conditional_overwrite(&mut self) -> Result<()> {
        let initial = self
            .record(Step::Seed, self.put_blob(INITIAL, "initial"), None)?
            .etag
            .context("seed response lacks a usable ETag")?;
        self.record(
            Step::RejectExisting,
            self.put_blob(REJECTED, "rejected")
                .header("if-none-match", "*"),
            Some(&initial),
        )?;
        self.record(
            Step::ReadOriginal,
            self.request(Method::GET),
            Some(&initial),
        )?;
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
            Step::RejectStale,
            self.put_blob(REJECTED, "rejected")
                .header("if-match", &initial),
            Some(&replacement),
        )?;
        self.record(
            Step::ReadReplacement,
            self.request(Method::GET),
            Some(&replacement),
        )?;
        Ok(())
    }

    fn staged_block_commit(&mut self) -> Result<()> {
        self.record(Step::StageFirst, self.put_block("YQ==", FIRST_BLOCK), None)?;
        self.record(
            Step::StageSecond,
            self.put_block("Yg==", SECOND_BLOCK),
            None,
        )?;
        self.record(Step::ReadUncommitted, self.request(Method::GET), None)?;
        let commit = self.commit(
            "<BlockList><Latest>Yg==</Latest><Latest>YQ==</Latest></BlockList>",
            "assembled",
        );
        let etag = self
            .record(Step::Commit, commit, None)?
            .etag
            .context("block commit response lacks a usable ETag")?;
        self.record(Step::ReadCommitted, self.request(Method::GET), Some(&etag))?;
        self.record(
            Step::RejectUnknownBlock,
            self.commit("<BlockList><Latest>Yw==</Latest></BlockList>", "rejected"),
            Some(&etag),
        )?;
        self.record(
            Step::ReadAfterRejectedCommit,
            self.request(Method::GET),
            Some(&etag),
        )?;
        Ok(())
    }
}

pub(super) fn observe(
    client: &Client,
    endpoint: &Url,
    bearer: &str,
    source: Source,
    case: Case,
) -> Result<MutationCassette> {
    with_fresh_container(client, endpoint, bearer, |_, url| {
        let mut probe = Probe {
            client,
            url,
            bearer,
            responses: Vec::with_capacity(case.steps().len()),
        };
        match case {
            Case::ConditionalOverwrite => probe.conditional_overwrite()?,
            Case::StagedBlockCommit => probe.staged_block_commit()?,
            Case::LeaseGuard => probe.lease_guard()?,
            Case::SnapshotRecovery => probe.snapshot_recovery()?,
            Case::AppendPosition => probe.append_position()?,
            Case::SparsePageWrites => probe.sparse_page_writes()?,
        }
        Ok(MutationCassette {
            schema_version: SCHEMA_VERSION,
            source,
            case,
            api_version: ApiVersion::Baseline,
            responses: probe.responses,
        })
    })
}

pub(super) fn reviewed(case: Case) -> Result<MutationCassette> {
    let path = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("tests")
        .join("contracts")
        .join("cassettes")
        .join(format!("{}.json", case.file_stem()));
    let fixture = read_bounded(
        File::open(path)
            .with_context(|| format!("could not open reviewed {} cassette", case.file_stem()))?,
    )?;
    let expected: MutationCassette = serde_json::from_slice(&fixture)
        .map_err(|error| anyhow::anyhow!("invalid mutation cassette at line {}", error.line()))?;
    ensure!(
        expected.source == Source::Azure && expected.case == case,
        "expected the recorded Azure case"
    );
    expected.validate()?;
    Ok(expected)
}

pub(super) fn observe_local(case: Case) -> Result<MutationCassette> {
    with_local(|client, endpoint, bearer| {
        observe(client, endpoint, bearer, Source::Synthetic, case)
    })
}

fn replay(case: Case) -> Result<()> {
    reviewed(case)?.compare(&observe_local(case)?)
}

#[test]
fn replay_blob_mutation_conditional_overwrite() -> Result<()> {
    replay(Case::ConditionalOverwrite)
}

#[test]
fn replay_blob_mutation_staged_block_commit() -> Result<()> {
    replay(Case::StagedBlockCommit)
}

#[test]
fn replay_blob_mutation_lease_guard() -> Result<()> {
    replay(Case::LeaseGuard)
}

#[test]
fn replay_blob_mutation_snapshot_recovery() -> Result<()> {
    replay(Case::SnapshotRecovery)
}

#[test]
fn replay_blob_mutation_append_position() -> Result<()> {
    replay(Case::AppendPosition)
}

#[test]
fn replay_blob_mutation_sparse_page_writes() -> Result<()> {
    replay(Case::SparsePageWrites)
}

#[test]
fn changed_request_is_detected_even_when_responses_match() -> Result<()> {
    let expected = reviewed(Case::AppendPosition)?;
    let mut changed = serde_json::to_value(&expected)?;
    changed["responses"][1]["request"]["append_position"] = serde_json::json!(1);
    let changed = serde_json::from_value(changed)?;
    let error = expected
        .compare(&changed)
        .expect_err("a changed append guard must fail even with identical responses");
    assert!(error.to_string().contains("AppendFirst"));
    Ok(())
}
