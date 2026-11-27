use super::{header, header_text, lifecycle::LEASE_ID};
use crate::contracts::cassette::Header;
use anyhow::{Context as _, Result, bail};
use reqwest::{Method, blocking::Request};
use serde::{Deserialize, Serialize};
use std::time::SystemTime;

#[derive(Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
enum Verb {
    Get,
    Head,
    Put,
    Delete,
}

#[derive(Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
enum Operation {
    Blob,
    PutBlockBlob,
    PutAppendBlob,
    PutPageBlob,
    StageBlock,
    CommitBlockList,
    AcquireLease,
    ReleaseLease,
    CreateSnapshot,
    ReadSnapshot,
    AppendBlock,
    UpdatePage,
    ClearPage,
    BlobMetadata,
    SetBlobProperties,
}

#[derive(Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
struct Range {
    start: u64,
    end: Option<u64>,
}

#[derive(Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
enum DateRelation {
    Earlier,
    Same,
    Later,
    Other,
}

#[derive(Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub(super) struct Input {
    method: Verb,
    operation: Operation,
    body_bytes: usize,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    if_match: Option<Header>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    if_none_match_star: Option<Header>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    lease_id: Option<Header>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    lease_seconds: Option<i64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    append_position: Option<i64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    page_size: Option<i64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    page_range: Option<[u64; 2]>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    sequence: Option<i64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    sequence_equal: Option<i64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    range: Option<Range>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    storage_range: Option<Range>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    range_md5: Option<Header>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    range_crc64: Option<Header>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    if_none_match_etag: Option<Header>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    if_modified_since: Option<DateRelation>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    if_unmodified_since: Option<DateRelation>,
}

impl Input {
    pub(super) fn observe(
        wire: &Request,
        reference: Option<&str>,
        modified: Option<SystemTime>,
    ) -> Result<Self> {
        let query = |name| {
            wire.url()
                .query_pairs()
                .find(|(key, _)| key == name)
                .map(|(_, value)| value)
        };
        let headers = wire.headers();
        let text = |name| header_text(headers, name);
        let method = match *wire.method() {
            Method::GET => Verb::Get,
            Method::HEAD => Verb::Head,
            Method::PUT => Verb::Put,
            Method::DELETE => Verb::Delete,
            _ => bail!("unexpected Blob probe method"),
        };
        let operation = match query("comp").as_deref() {
            None if query("snapshot").is_some() => Operation::ReadSnapshot,
            None => match text("x-ms-blob-type") {
                Some("BlockBlob") => Operation::PutBlockBlob,
                Some("AppendBlob") => Operation::PutAppendBlob,
                Some("PageBlob") => Operation::PutPageBlob,
                None => Operation::Blob,
                _ => bail!("unexpected Blob probe type"),
            },
            Some("block") => Operation::StageBlock,
            Some("blocklist") => Operation::CommitBlockList,
            Some("snapshot") => Operation::CreateSnapshot,
            Some("appendblock") => Operation::AppendBlock,
            Some("metadata") => Operation::BlobMetadata,
            Some("properties") => Operation::SetBlobProperties,
            Some("lease") => match text("x-ms-lease-action") {
                Some("acquire") => Operation::AcquireLease,
                Some("release") => Operation::ReleaseLease,
                _ => bail!("unexpected Blob probe lease action"),
            },
            Some("page") => match text("x-ms-page-write") {
                Some("update") => Operation::UpdatePage,
                Some("clear") => Operation::ClearPage,
                _ => bail!("unexpected Blob probe page action"),
            },
            _ => bail!("unexpected Blob probe operation"),
        };
        let body_bytes = match wire.body() {
            Some(body) => body.as_bytes().context("probe body is not buffered")?.len(),
            None => 0,
        };
        let number = |name| -> Result<_> {
            text(name)
                .map(str::parse)
                .transpose()
                .with_context(|| format!("invalid {name} in Blob probe"))
        };
        let observe_header = |seen| match seen {
            Header::Missing => None,
            _ => Some(seen),
        };
        let parse_range = |name| -> Result<Option<Range>> {
            text(name)
                .map(|range| -> Result<_> {
                    let (start, end) = range
                        .strip_prefix("bytes=")
                        .and_then(|value| value.split_once('-'))
                        .context("invalid range in Blob probe")?;
                    Ok(Range {
                        start: start.parse().context("invalid range start in Blob probe")?,
                        end: (!end.is_empty())
                            .then(|| end.parse())
                            .transpose()
                            .context("invalid range end in Blob probe")?,
                    })
                })
                .transpose()
        };
        let mut storage_range = parse_range("x-ms-range")?;
        let page_range = if matches!(operation, Operation::UpdatePage | Operation::ClearPage) {
            let range = storage_range
                .take()
                .context("missing page range in probe")?;
            Some([range.start, range.end.context("missing page end in probe")?])
        } else {
            None
        };
        let date_relation = |name| {
            text(name).map(|value| match (httpdate::parse_http_date(value), modified) {
                (Ok(date), Some(expected)) if date < expected => DateRelation::Earlier,
                (Ok(date), Some(expected)) if date == expected => DateRelation::Same,
                (Ok(_), Some(_)) => DateRelation::Later,
                _ => DateRelation::Other,
            })
        };
        let requested_flag = |name| observe_header(header(headers, name, |value| value == "true"));
        Ok(Self {
            method,
            body_bytes,
            if_match: observe_header(header(headers, "if-match", |value| {
                Some(value) == reference
            })),
            if_none_match_star: (text("if-none-match") == Some("*")).then_some(Header::Matches),
            if_none_match_etag: text("if-none-match")
                .filter(|value| *value != "*")
                .map(|value| {
                    if Some(value) == reference {
                        Header::Matches
                    } else {
                        Header::Different
                    }
                }),
            lease_id: observe_header(header(
                headers,
                if operation == Operation::AcquireLease {
                    "x-ms-proposed-lease-id"
                } else {
                    "x-ms-lease-id"
                },
                |value| value == LEASE_ID,
            )),
            lease_seconds: number("x-ms-lease-duration")?,
            append_position: number("x-ms-blob-condition-appendpos")?,
            page_size: number("x-ms-blob-content-length")?,
            page_range,
            sequence: number("x-ms-blob-sequence-number")?,
            sequence_equal: number("x-ms-if-sequence-number-eq")?,
            range: parse_range("range")?,
            storage_range,
            range_md5: requested_flag("x-ms-range-get-content-md5"),
            range_crc64: requested_flag("x-ms-range-get-content-crc64"),
            if_modified_since: date_relation("if-modified-since"),
            if_unmodified_since: date_relation("if-unmodified-since"),
            operation,
        })
    }
}

#[test]
fn projection_omits_request_credentials_selectors_and_body() -> Result<()> {
    let wire = reqwest::blocking::Client::new()
        .put("https://private-account.invalid/container/blob?comp=block&blockid=PRIVATE-ID")
        .bearer_auth("SECRET-TOKEN")
        .body("PRIVATE-BODY")
        .build()?;
    let input = Input::observe(&wire, None, None)?;
    let json = serde_json::to_value(&input)?;
    assert_eq!(
        json,
        serde_json::json!({"method": "put", "operation": "stage_block", "body_bytes": 12})
    );
    Ok(())
}
