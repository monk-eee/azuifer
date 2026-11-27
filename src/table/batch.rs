//! Entity group transactions: `multipart/mixed` batch parsing and response assembly.

use super::{
    NoDataServiceVersion,
    error::{Kind, TableError},
    protocol::{self, Format, Operation, Request, Target},
    store::WriteKind,
};
use axum::{
    body::{Body, to_bytes},
    http::{HeaderMap, HeaderName, HeaderValue, Method, StatusCode},
    response::Response,
};
use std::collections::HashSet;
use uuid::Uuid;

pub(super) const MAX_OPERATIONS: usize = 100;
const MAX_PART_BYTES: usize = 8 * 1024 * 1024;

pub(super) struct SubRequest {
    pub(super) request: Request,
    pub(super) content_id: Option<String>,
}

pub(super) struct Batch {
    pub(super) requests: Vec<SubRequest>,
    /// True for a change set (atomic writes); false for a single query.
    pub(super) transaction: bool,
}

/// A batch failure. `index` identifies the failed operation in a change set; without
/// one the whole HTTP request fails.
pub(super) struct BatchError {
    pub(super) index: Option<usize>,
    pub(super) error: TableError,
    pub(super) format: Option<Format>,
    pub(super) content_id: Option<String>,
}

impl From<TableError> for BatchError {
    fn from(error: TableError) -> Self {
        Self {
            index: None,
            error,
            format: None,
            content_id: None,
        }
    }
}

fn invalid(detail: &str) -> TableError {
    TableError::with(Kind::InvalidInput, detail)
}

struct Part<'a> {
    headers: Vec<(String, &'a str)>,
    body: &'a str,
}

impl Part<'_> {
    fn header(&self, name: &str) -> Option<&str> {
        self.headers
            .iter()
            .find(|(candidate, _)| candidate == name)
            .map(|(_, value)| *value)
    }
}

fn boundary_of(content_type: &str) -> Option<&str> {
    let mut parts = content_type.split(';').map(str::trim);
    if !parts.next()?.eq_ignore_ascii_case("multipart/mixed") {
        return None;
    }
    parts
        .filter_map(|part| part.split_once('='))
        .find(|(name, _)| name.trim().eq_ignore_ascii_case("boundary"))
        .map(|(_, value)| value.trim().trim_matches('"'))
        .filter(|value| !value.is_empty())
}

/// Splits `head\r\n\r\nbody` (or bare `\n`) into its two halves.
fn split_head(text: &str) -> (&str, &str) {
    let mut at = 0;
    for line in text.split_inclusive('\n') {
        if line.trim_end_matches(['\r', '\n']).is_empty() {
            return (
                text.get(..at).unwrap_or_default(),
                text.get(at + line.len()..).unwrap_or_default(),
            );
        }
        at += line.len();
    }
    (text, "")
}

fn header_lines(head: &str) -> Vec<(String, &str)> {
    head.lines()
        .filter_map(|line| line.split_once(':'))
        .map(|(name, value)| (name.trim().to_ascii_lowercase(), value.trim()))
        .collect()
}

/// Finds `delimiter` at the start of a line at or after `from`.
fn find_delimiter(text: &str, delimiter: &str, from: usize) -> Option<usize> {
    let mut at = from;
    while let Some(found) = text.get(at..)?.find(delimiter) {
        let position = at + found;
        let line_start = position == 0 || text.as_bytes().get(position - 1) == Some(&b'\n');
        let after = text.as_bytes().get(position + delimiter.len());
        if line_start && after.is_none_or(|b| matches!(b, b'\r' | b'\n' | b'-' | b' ' | b'\t')) {
            return Some(position);
        }
        at = position + delimiter.len();
    }
    None
}

fn split_parts<'a>(text: &'a str, boundary: &str) -> Result<Vec<Part<'a>>, TableError> {
    let malformed = || invalid("The batch request body is not a valid multipart/mixed message.");
    let delimiter = format!("--{boundary}");
    let mut at = find_delimiter(text, &delimiter, 0).ok_or_else(malformed)?;
    let mut parts = Vec::new();
    loop {
        let after = at + delimiter.len();
        if text.get(after..).ok_or_else(malformed)?.starts_with("--") {
            return Ok(parts);
        }
        let line_end = text
            .get(after..)
            .and_then(|rest| rest.find('\n'))
            .ok_or_else(malformed)?;
        let start = after + line_end + 1;
        let next = find_delimiter(text, &delimiter, start).ok_or_else(malformed)?;
        let content = text.get(start..next).ok_or_else(malformed)?;
        let content = content
            .strip_suffix("\r\n")
            .or_else(|| content.strip_suffix('\n'))
            .unwrap_or(content);
        let (head, body) = split_head(content);
        parts.push(Part {
            headers: header_lines(head),
            body,
        });
        at = next;
    }
}

/// One inner HTTP request: method, target, headers, and body.
struct Http<'a> {
    method: Method,
    remainder: String,
    query: Option<&'a str>,
    headers: HeaderMap,
    body: &'a str,
}

fn parse_http<'a>(part: &Part<'a>, account: &str) -> Result<Http<'a>, TableError> {
    let (head, body) = split_head(part.body);
    let mut lines = head.lines();
    let request_line = lines
        .next()
        .ok_or_else(|| invalid("A batch operation has no request line."))?;
    let mut words = request_line.split_whitespace();
    let (Some(method), Some(uri), Some(_)) = (words.next(), words.next(), words.next()) else {
        return Err(invalid("A batch operation has a malformed request line."));
    };
    let method =
        Method::from_bytes(method.as_bytes()).map_err(|_| invalid("Unknown HTTP method."))?;
    let path_and_query = match uri.split_once("://") {
        Some((_, rest)) => rest.find('/').and_then(|at| rest.get(at..)).unwrap_or("/"),
        None => uri,
    };
    let (path, query) = match path_and_query.split_once('?') {
        Some((path, query)) => (path, Some(query)),
        None => (path_and_query, None),
    };
    let trimmed = path.strip_prefix('/').unwrap_or(path);
    let remainder = match trimmed.split_once('/') {
        Some((first, rest)) if first == account => rest,
        None if trimmed == account => "",
        _ => trimmed,
    };
    let mut headers = HeaderMap::new();
    for line in lines {
        let (name, value) = line
            .split_once(':')
            .ok_or_else(|| invalid("A batch operation has a malformed header."))?;
        let name = HeaderName::from_bytes(name.trim().as_bytes())
            .map_err(|_| invalid("A batch operation has a malformed header."))?;
        let value = HeaderValue::from_str(value.trim())
            .map_err(|_| invalid("A batch operation has a malformed header."))?;
        headers.append(name, value);
    }
    Ok(Http {
        method,
        remainder: remainder.to_owned(),
        query,
        headers,
        body,
    })
}

fn sub_request(part: &Part<'_>, account: &str) -> Result<SubRequest, TableError> {
    let http = parse_http(part, account)?;
    let method = protocol::effective_method(&http.method, &http.headers)?;
    let query = protocol::parse_query(http.query)?;
    let target = protocol::parse_target(&http.remainder)?;
    if matches!(
        target,
        Target::Batch | Target::Service | Target::Tables | Target::TableItem(_)
    ) {
        return Err(invalid(
            "A batch operation must address a table or an entity.",
        ));
    }
    let content_id = http
        .headers
        .get("content-id")
        .and_then(|value| value.to_str().ok())
        .map(str::to_owned);
    let request = protocol::build(
        &method,
        target,
        &query,
        &http.headers,
        http.body.trim().as_bytes(),
    )?;
    Ok(SubRequest {
        request,
        content_id,
    })
}

/// Parses a batch request. Failures inside a change set carry the failed operation's index.
pub(super) fn parse(content_type: &str, body: &[u8], account: &str) -> Result<Batch, BatchError> {
    let boundary = boundary_of(content_type)
        .ok_or_else(|| invalid("The batch request must be multipart/mixed with a boundary."))?;
    let text =
        std::str::from_utf8(body).map_err(|_| invalid("The batch request body must be UTF-8."))?;
    let outer = split_parts(text, boundary)?;
    let mut change_sets = Vec::new();
    let mut loose = Vec::new();
    for part in &outer {
        let content_type = part.header("content-type").unwrap_or_default();
        if let Some(inner) = boundary_of(content_type) {
            change_sets.push(split_parts(part.body, inner)?);
        } else if content_type
            .to_ascii_lowercase()
            .starts_with("application/http")
        {
            loose.push(part);
        } else {
            return Err(invalid("Unsupported batch part content type.").into());
        }
    }
    match (change_sets.as_slice(), loose.len()) {
        ([], 1) => query_batch(loose[0], account),
        ([set], 0) => change_set(set, account),
        ([], 0) => Err(invalid("The batch request contains no operations.").into()),
        _ => {
            Err(invalid("A batch must contain exactly one change set or exactly one query.").into())
        }
    }
}

fn query_batch(part: &Part<'_>, account: &str) -> Result<Batch, BatchError> {
    let mut sub = sub_request(part, account)?;
    if sub.content_id.is_none() {
        sub.content_id = Some(part.header("content-id").unwrap_or("1").to_owned());
    }
    if !matches!(
        sub.request.operation,
        Operation::GetEntity(..) | Operation::QueryEntities(..)
    ) {
        return Err(invalid("Only a query may appear outside a change set.").into());
    }
    Ok(Batch {
        requests: vec![sub],
        transaction: false,
    })
}

fn change_set(parts: &[Part<'_>], account: &str) -> Result<Batch, BatchError> {
    if parts.len() > MAX_OPERATIONS {
        return Err(invalid(
            "The batch request operation exceeds the maximum 100 changes per change set.",
        )
        .into());
    }
    if parts.is_empty() {
        return Err(invalid("The batch request contains no operations.").into());
    }
    let at = |index, sub: Option<&SubRequest>| {
        let format = sub.map(|sub| sub.request.format);
        let content_id = sub.and_then(|sub| sub.content_id.clone());
        move |error: TableError| BatchError {
            index: Some(index),
            error,
            format,
            content_id,
        }
    };
    let mut requests = Vec::with_capacity(parts.len());
    for (index, part) in parts.iter().enumerate() {
        let content_type = part.header("content-type").unwrap_or_default();
        if !content_type
            .to_ascii_lowercase()
            .starts_with("application/http")
        {
            return Err(at(index, None)(invalid(
                "A change set operation must be application/http.",
            )));
        }
        requests.push(sub_request(part, account).map_err(at(index, None))?);
    }
    let mut seen = HashSet::new();
    let mut first = None;
    for (index, sub) in requests.iter().enumerate() {
        let Operation::Write(table, op) = &sub.request.operation else {
            return Err(at(index, Some(sub))(invalid(
                "Only inserts, updates, and deletes may appear in a change set.",
            )));
        };
        let scope = (table.key(), op.key.partition.as_str());
        if *first.get_or_insert(scope.clone()) != scope {
            return Err(at(index, Some(sub))(TableError::new(
                Kind::CommandsInBatchActOnDifferentPartitions,
            )));
        }
        if !seen.insert(op.key.row.as_str()) {
            return Err(at(index, Some(sub))(TableError::with(
                Kind::InvalidDuplicateRow,
                format!(
                    "A command with RowKey '{}' is already present in the batch. An entity can appear only once in a batch.",
                    op.key.row.as_str()
                ),
            )));
        }
        // An insert may not be conditional; the other kinds read their own headers.
        if matches!(op.kind, WriteKind::Insert) && op.condition != super::model::Precondition::None
        {
            return Err(at(index, Some(sub))(invalid(
                "An insert cannot carry an If-Match header.",
            )));
        }
    }
    Ok(Batch {
        requests,
        transaction: true,
    })
}

fn canonical(name: &str) -> String {
    if name == "etag" {
        return "ETag".to_owned();
    }
    name.split('-')
        .map(|word| {
            let mut chars = word.chars();
            chars
                .next()
                .map(|first| first.to_ascii_uppercase().to_string() + chars.as_str())
                .unwrap_or_default()
        })
        .collect::<Vec<_>>()
        .join("-")
}

/// Renders one `application/http` response part.
async fn render_part(content_id: Option<&str>, response: Response) -> Result<String, TableError> {
    let (parts, body) = response.into_parts();
    let bytes = to_bytes(body, MAX_PART_BYTES)
        .await
        .map_err(|_| TableError::new(Kind::Internal))?;
    let mut text =
        String::from("Content-Type: application/http\r\nContent-Transfer-Encoding: binary\r\n\r\n");
    text.push_str(&format!(
        "HTTP/1.1 {} {}\r\n",
        parts.status.as_u16(),
        parts.status.canonical_reason().unwrap_or("Unknown"),
    ));
    if let Some(content_id) = content_id {
        text.push_str(&format!("Content-ID: {content_id}\r\n"));
    }
    text.push_str("DataServiceVersion: 3.0;\r\nX-Content-Type-Options: nosniff\r\nCache-Control: no-cache\r\n");
    for (name, value) in &parts.headers {
        if let Ok(value) = value.to_str() {
            text.push_str(&format!("{}: {value}\r\n", canonical(name.as_str())));
        }
    }
    text.push_str("\r\n");
    text.push_str(&String::from_utf8_lossy(&bytes));
    Ok(text)
}

/// Assembles the `202 Accepted` multipart response from per-operation responses.
pub(super) async fn assemble(
    responses: Vec<(Option<String>, Response)>,
    transaction: bool,
) -> Result<Response, TableError> {
    let batch_id = format!("batchresponse_{}", Uuid::new_v4());
    let change_id = format!("changesetresponse_{}", Uuid::new_v4());
    let mut text = format!("--{batch_id}\r\n");
    if transaction {
        text.push_str(&format!(
            "Content-Type: multipart/mixed; boundary={change_id}\r\n\r\n"
        ));
    }
    for (content_id, response) in responses {
        let part = render_part(content_id.as_deref(), response).await?;
        if transaction {
            text.push_str(&format!("--{change_id}\r\n"));
        }
        text.push_str(&part);
        text.push_str("\r\n");
    }
    if transaction {
        text.push_str(&format!("--{change_id}--\r\n"));
    }
    text.push_str(&format!("--{batch_id}--\r\n"));
    let mut response = Response::new(Body::from(text));
    *response.status_mut() = StatusCode::ACCEPTED;
    if transaction {
        response.extensions_mut().insert(NoDataServiceVersion);
    }
    response.headers_mut().insert(
        "content-type",
        HeaderValue::from_str(&format!("multipart/mixed; boundary={batch_id}"))
            .map_err(|_| TableError::new(Kind::Internal))?,
    );
    Ok(response)
}

#[cfg(test)]
mod tests {
    use super::*;

    const ACCOUNT: &str = "acct";
    const CONTENT_TYPE: &str = "multipart/mixed; boundary=batch_1";

    fn op(method: &str, path: &str, extra: &str, body: &str) -> String {
        format!(
            "--changeset_1\r\nContent-Type: application/http\r\nContent-Transfer-Encoding: binary\r\n\r\n{method} http://127.0.0.1:1/acct/{path} HTTP/1.1\r\nContent-Type: application/json\r\nAccept: application/json;odata=minimalmetadata\r\n{extra}\r\n{body}\r\n"
        )
    }

    fn wrap(ops: &[String]) -> Vec<u8> {
        format!(
            "--batch_1\r\nContent-Type: multipart/mixed; boundary=changeset_1\r\n\r\n{}--changeset_1--\r\n--batch_1--\r\n",
            ops.concat()
        )
        .into_bytes()
    }

    fn insert(row: &str) -> String {
        op(
            "POST",
            "People",
            "Prefer: return-no-content\r\n",
            &format!(r#"{{"PartitionKey":"p","RowKey":"{row}","N":1}}"#),
        )
    }

    #[test]
    fn change_sets_parse_in_order_with_content_ids() {
        let body = wrap(&[
            insert("1"),
            op(
                "MERGE",
                "People(PartitionKey='p',RowKey='2')",
                "If-Match: *\r\nContent-ID: 7\r\n",
                r#"{"N":2}"#,
            ),
            op(
                "DELETE",
                "People(PartitionKey='p',RowKey='3')",
                "If-Match: *\r\n",
                "",
            ),
        ]);
        let batch = parse(CONTENT_TYPE, &body, ACCOUNT).ok().unwrap();
        assert!(batch.transaction);
        let ids: Vec<_> = batch
            .requests
            .iter()
            .map(|r| r.content_id.as_deref())
            .collect();
        assert_eq!(ids, [None, Some("7"), None]);
        assert!(!batch.requests[0].request.format.return_content);
        assert!(
            matches!(&batch.requests[1].request.operation, Operation::Write(_, w) if matches!(w.kind, WriteKind::Merge))
        );
    }

    #[test]
    fn lf_only_bodies_and_quoted_boundaries_parse() {
        let body = wrap(&[insert("1")]);
        let text = String::from_utf8(body).unwrap().replace("\r\n", "\n");
        assert!(
            parse(
                "multipart/mixed; boundary=\"batch_1\"",
                text.as_bytes(),
                ACCOUNT
            )
            .is_ok()
        );
    }

    #[test]
    fn a_single_query_is_allowed_outside_a_change_set() {
        let body = "--batch_1\r\nContent-Type: application/http\r\nContent-Transfer-Encoding: binary\r\n\r\nGET http://h/acct/People(PartitionKey='p',RowKey='1') HTTP/1.1\r\nAccept: application/json\r\n\r\n\r\n--batch_1--\r\n";
        let batch = parse(CONTENT_TYPE, body.as_bytes(), ACCOUNT).ok().unwrap();
        assert!(!batch.transaction);
        assert!(matches!(
            batch.requests[0].request.operation,
            Operation::GetEntity(..)
        ));
    }

    #[test]
    fn structural_violations_name_the_failing_operation() {
        let failing = |ops: &[String]| parse(CONTENT_TYPE, &wrap(ops), ACCOUNT).err().unwrap();
        let different = op(
            "POST",
            "People",
            "",
            r#"{"PartitionKey":"other","RowKey":"2"}"#,
        );
        let error = failing(&[insert("1"), different]);
        assert_eq!(error.index, Some(1));
        assert_eq!(
            error.error.kind(),
            Kind::CommandsInBatchActOnDifferentPartitions
        );
        let error = failing(&[insert("1"), insert("1")]);
        assert_eq!(
            (error.index, error.error.kind()),
            (Some(1), Kind::InvalidDuplicateRow)
        );
        let bad_body = op("POST", "People", "", "{not json");
        assert_eq!(failing(&[insert("1"), bad_body]).index, Some(1));
        let query = op("GET", "People(PartitionKey='p',RowKey='2')", "", "");
        assert_eq!(failing(&[insert("1"), query]).index, Some(1));
        let many: Vec<String> = (0..101).map(|i| insert(&i.to_string())).collect();
        let error = failing(&many);
        assert_eq!(
            (error.index, error.error.kind()),
            (None, Kind::InvalidInput)
        );
        assert_eq!(failing(&[]).index, None);
        assert!(parse("text/plain", b"x", ACCOUNT).is_err());
        assert!(parse(CONTENT_TYPE, b"no boundaries here", ACCOUNT).is_err());
    }

    #[test]
    fn two_change_sets_are_refused() {
        let one = String::from_utf8(wrap(&[insert("1")])).unwrap();
        let both = one.replace("--batch_1--\r\n", "") + &one;
        assert!(parse(CONTENT_TYPE, both.as_bytes(), ACCOUNT).is_err());
    }

    #[tokio::test]
    async fn responses_assemble_into_nested_multipart() {
        let mut ok = Response::new(Body::empty());
        *ok.status_mut() = StatusCode::NO_CONTENT;
        ok.headers_mut()
            .insert("etag", HeaderValue::from_static("W/\"x\""));
        let response = assemble(vec![(Some("1".into()), ok)], true)
            .await
            .ok()
            .unwrap();
        assert_eq!(response.status(), StatusCode::ACCEPTED);
        let content_type = response.headers()["content-type"]
            .to_str()
            .unwrap()
            .to_owned();
        assert!(content_type.starts_with("multipart/mixed; boundary=batchresponse_"));
        let text = String::from_utf8(to_bytes(response.into_body(), 4096).await.unwrap().to_vec())
            .unwrap();
        assert!(text.contains("HTTP/1.1 204 No Content\r\nContent-ID: 1\r\n"));
        assert!(text.contains("ETag: W/\"x\"\r\n"));
        assert!(text.contains("boundary=changesetresponse_"));
        assert!(text.trim_end().ends_with("--"));
    }

    #[test]
    fn hostile_batches_are_answered_without_panic() {
        let seed = "--batch_1\r\nContent-Type: multipart/mixed; boundary=changeset_1\r\n\r\n\
                    --changeset_1\r\nContent-Type: application/http\r\nContent-Transfer-Encoding: binary\r\nContent-ID: 1\r\n\r\n\
                    POST /acct/tbl HTTP/1.1\r\nContent-Type: application/json\r\nAccept: application/json;odata=nometadata\r\n\r\n\
                    {\"PartitionKey\":\"p\",\"RowKey\":\"r\",\"V\":1}\r\n--changeset_1--\r\n--batch_1--\r\n";
        assert!(parse("multipart/mixed; boundary=batch_1", seed.as_bytes(), "acct").is_ok());
        crate::hostile::sweep(
            &[seed],
            (
                "--batch_1\r\nContent-Type: multipart/mixed; boundary=batch_1\r\n\r\n",
                "--batch_1--",
            ),
            |text| {
                let _ = parse("multipart/mixed; boundary=batch_1", text.as_bytes(), "acct");
            },
        );
        crate::hostile::sweep(
            &["multipart/mixed; boundary=\"batch_1\""],
            (";", "="),
            |text| {
                let _ = boundary_of(text);
            },
        );
        let part =
            "--c\r\nContent-Type: application/http\r\n\r\nPOST /acct/tbl HTTP/1.1\r\n\r\n{}\r\n";
        let nested = format!(
            "--b\r\nContent-Type: multipart/mixed; boundary=c\r\n\r\n{}--c--\r\n--b--\r\n",
            part.repeat(5000)
        );
        assert!(parse("multipart/mixed; boundary=b", nested.as_bytes(), "acct").is_err());
    }
}
