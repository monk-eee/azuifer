use super::{header, header_text, lifecycle::LEASE_ID};
use crate::contracts::cassette::Header;
use anyhow::{Context as _, Result, bail};
use reqwest::{Method, blocking::Request};
use serde::{Deserialize, Serialize};

#[derive(Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
enum Verb {
    Get,
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
}

impl Input {
    pub(super) fn observe(wire: &Request, reference: Option<&str>) -> Result<Self> {
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
        let page_range = text("x-ms-range")
            .map(|range| -> Result<_> {
                let (start, end) = range
                    .strip_prefix("bytes=")
                    .and_then(|value| value.split_once('-'))
                    .context("invalid range in page probe")?;
                Ok([start.parse()?, end.parse()?])
            })
            .transpose()?;
        Ok(Self {
            method,
            body_bytes,
            if_match: observe_header(header(headers, "if-match", |value| {
                Some(value) == reference
            })),
            if_none_match_star: observe_header(header(headers, "if-none-match", |value| {
                value == "*"
            })),
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
    let input = Input::observe(&wire, None)?;
    let json = serde_json::to_value(&input)?;
    assert_eq!(
        json,
        serde_json::json!({"method": "put", "operation": "stage_block", "body_bytes": 12})
    );
    Ok(())
}
