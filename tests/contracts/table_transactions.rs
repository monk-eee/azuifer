use super::{
    cassette::{ErrorCode, Header, OdataError, header_text},
    table_entities::{Step, valid_etag},
};
use anyhow::{Context as _, Result, ensure};
use reqwest::{Url, blocking::RequestBuilder, header::HeaderMap};
use serde::{Deserialize, Serialize};
use serde_json::json;
use std::fmt::Write as _;

const BATCH: &str = "batch_azuifer_wave2";
const CHANGE: &str = "changeset_azuifer_wave2";

pub(super) struct Op<'a> {
    pub(super) method: &'a str,
    pub(super) partition: &'a str,
    pub(super) row: &'a str,
    pub(super) count: u32,
    pub(super) etag: Option<&'a str>,
}

pub(super) fn wire(
    request: RequestBuilder,
    endpoint: &Url,
    table: &str,
    operations: &[Op<'_>],
) -> Result<RequestBuilder> {
    let mut body = format!("--{BATCH}\r\nContent-Type: multipart/mixed; boundary={CHANGE}\r\n\r\n");
    for (index, op) in operations.iter().enumerate() {
        let path = if op.method == "POST" {
            table.to_owned()
        } else {
            format!(
                "{table}(PartitionKey='{}',RowKey='{}')",
                op.partition, op.row
            )
        };
        let url = endpoint.join(&path)?;
        let payload =
            json!({"PartitionKey":op.partition,"RowKey":op.row,"Count":op.count}).to_string();
        write!(
            &mut body,
            "--{CHANGE}\r\nContent-Type: application/http\r\nContent-Transfer-Encoding: binary\r\nContent-ID: {}\r\n\r\n{} {url} HTTP/1.1\r\nContent-Type: application/json\r\nAccept: application/json;odata=nometadata\r\nPrefer: return-no-content\r\nContent-Length: {}\r\n",
            index + 1,
            op.method,
            payload.len(),
        )?;
        if let Some(tag) = op.etag {
            write!(&mut body, "If-Match: {tag}\r\n")?;
        }
        write!(&mut body, "\r\n{payload}\r\n")?;
    }
    write!(&mut body, "--{CHANGE}--\r\n--{BATCH}--\r\n")?;
    Ok(request
        .header("content-type", format!("multipart/mixed; boundary={BATCH}"))
        .body(body))
}

#[derive(Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub(super) struct Part {
    status: u16,
    mime_content_id: Option<u16>,
    http_content_id: Option<u16>,
    etag: Header,
    dataserviceversion: Header,
    request_id_present: bool,
    header_code: ErrorCode,
    preference: Header,
    error: Option<OdataError>,
    empty: bool,
}

fn field<'a>(head: &'a str, name: &str) -> Option<&'a str> {
    head.lines()
        .filter_map(|line| line.split_once(':'))
        .find_map(|(key, value)| {
            key.trim()
                .eq_ignore_ascii_case(name)
                .then_some(value.trim())
        })
}

fn multipart<'a>(content_type: &str, body: &'a str) -> Result<Vec<&'a str>> {
    let (media, params) = content_type
        .split_once(';')
        .context("missing multipart parameters")?;
    ensure!(
        media.trim() == "multipart/mixed",
        "unexpected Table batch media"
    );
    let boundary = params
        .split(';')
        .filter_map(|part| part.trim().split_once('='))
        .find_map(|(key, value)| (key == "boundary").then_some(value.trim().trim_matches('"')))
        .filter(|value| {
            !value.is_empty()
                && value
                    .bytes()
                    .all(|c| c.is_ascii_alphanumeric() || b"-_".contains(&c))
        })
        .context("invalid Table batch response boundary")?;
    let boundary = format!("--{boundary}");
    let mut sections = body.split(&boundary);
    ensure!(
        sections.next().is_some_and(|start| start.trim().is_empty()),
        "unexpected Table batch preamble"
    );
    let mut parts = vec![];
    while let Some(section) = sections.next() {
        if section.trim() == "--" {
            ensure!(sections.next().is_none(), "unexpected Table batch epilogue");
            return Ok(parts);
        }
        parts.push(
            section
                .strip_prefix("\r\n")
                .context("invalid Table batch part line endings")?,
        );
    }
    anyhow::bail!("missing closing Table batch boundary")
}

fn project_part(wire: &str, outer_id: Option<&str>, expected: &str) -> Result<Part> {
    let (mime, http) = wire
        .split_once("\r\n\r\n")
        .context("missing Table subresponse MIME headers")?;
    ensure!(
        field(mime, "content-type") == Some("application/http"),
        "unexpected Table subresponse type"
    );
    let (head, body) = http.split_once("\r\n\r\n").unwrap_or((http, ""));
    let body = body.trim();
    let status: u16 = head
        .lines()
        .next()
        .and_then(|line| line.strip_prefix("HTTP/1.1 "))
        .and_then(|line| line.split_whitespace().next())
        .context("missing Table subresponse status")?
        .parse()
        .context("invalid Table subresponse status")?;
    let id = field(head, "x-ms-request-id");
    let error = if status >= 400 {
        Some(OdataError::project(
            body.as_bytes(),
            id.or(outer_id),
            expected,
        )?)
    } else {
        None
    };
    let marker = |name, expected: fn(&str) -> bool| match field(head, name) {
        Some(value) if expected(value) => Header::Matches,
        Some(_) => Header::Different,
        None => Header::Missing,
    };
    Ok(Part {
        status,
        mime_content_id: field(mime, "content-id")
            .map(str::parse)
            .transpose()
            .context("invalid MIME content ID")?,
        http_content_id: field(head, "content-id")
            .map(str::parse)
            .transpose()
            .context("invalid HTTP content ID")?,
        etag: marker("etag", valid_etag),
        dataserviceversion: marker("dataserviceversion", |v| v == "3.0;"),
        request_id_present: id.is_some(),
        header_code: ErrorCode::from_value(field(head, "x-ms-error-code")),
        preference: marker("preference-applied", |v| v == "return-no-content"),
        error,
        empty: body.is_empty(),
    })
}

pub(super) fn project(headers: &HeaderMap, bytes: &[u8], expected: &str) -> Result<Vec<Part>> {
    let media = header_text(headers, "content-type").context("missing Table batch Content-Type")?;
    let text = std::str::from_utf8(bytes)
        .context("invalid Table batch encoding")?
        .trim_start_matches('\u{feff}');
    let outer = multipart(media, text)?;
    let [changeset] = outer.as_slice() else {
        anyhow::bail!("expected exactly one Table changeset");
    };
    let (head, body) = changeset
        .split_once("\r\n\r\n")
        .context("missing Table changeset headers")?;
    let changeset_type = field(head, "content-type").context("missing Table changeset type")?;
    multipart(changeset_type, body)?
        .iter()
        .map(|wire| project_part(wire, header_text(headers, "x-ms-request-id"), expected))
        .collect()
}

pub(super) fn matches(step: Step, parts: &[Part]) -> bool {
    match (step, parts) {
        (Step::Commit, [a, b]) => [a, b]
            .into_iter()
            .all(|p| p.status == 204 && p.etag == Header::Matches && p.empty),
        (Step::Rollback, [p]) => {
            p.status == 412
                && p.error
                    .as_ref()
                    .is_some_and(|error| error.code == ErrorCode::UpdateConditionNotSatisfied)
        }
        (Step::Mixed, [p]) => {
            p.status == 400
                && p.error.as_ref().is_some_and(|error| {
                    error.code == ErrorCode::CommandsInBatchActOnDifferentPartitions
                })
        }
        _ => false,
    }
}
