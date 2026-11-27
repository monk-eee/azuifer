use super::{
    VERSION,
    cassette::{ApiVersion, ErrorCode, Header, Source, header, header_text},
    read_bounded, request,
    request_errors::{XmlError, project_error},
    require_status, send, with_fresh_container, with_local,
};
use anyhow::{Context as _, Result, ensure};
use reqwest::{Method, Url, blocking::Client, header::HeaderMap};
use serde::{Deserialize, Serialize};
use std::{fs::File, path::Path, time::SystemTime};
use uuid::Uuid;

pub(super) const CASE: &str = "blob-batch-mixed-results";
const BOUNDARY: &str = "azuifer-contract-batch";
const BYTES: &[u8] = b"synthetic batch blob\n";
const MISSING_MESSAGE: &str = "The specified blob does not exist.";
const MIXED_MESSAGE: &str = "All batch subrequests should be the same api.";

pub(super) struct WirePart<'a> {
    mime: &'a str,
    http: &'a str,
    pub(super) status: u16,
    pub(super) body: &'a str,
}

impl<'a> WirePart<'a> {
    pub(super) fn content_id(&self) -> Option<&'a str> {
        part_header(self.mime, "Content-ID")
    }

    pub(super) fn header(&self, name: &str) -> Option<&'a str> {
        part_header(self.http, name)
    }
}

fn part_header<'a>(lines: &'a str, name: &str) -> Option<&'a str> {
    lines
        .lines()
        .filter_map(|line| line.split_once(':'))
        .find_map(|(key, value)| key.eq_ignore_ascii_case(name).then_some(value.trim()))
}

pub(super) fn parse_parts<'a>(headers: &HeaderMap, wire: &'a str) -> Option<Vec<WirePart<'a>>> {
    let (kind, parameters) = header_text(headers, "content-type")?.split_once(';')?;
    let (name, boundary) = parameters.trim().split_once('=')?;
    let boundary = boundary.trim().trim_matches('"');
    if kind.trim() != "multipart/mixed"
        || name.trim() != "boundary"
        || boundary.is_empty()
        || !boundary
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || b"-_".contains(&byte))
    {
        return None;
    }
    let boundary = format!("--{boundary}");
    let mut sections = wire.split(&boundary);
    if !sections.next()?.is_empty() {
        return None;
    }
    let mut parts = Vec::new();
    while let Some(section) = sections.next() {
        if section.trim_end() == "--" && sections.next().is_none() {
            return Some(parts);
        }
        let (mime, http) = section.strip_prefix("\r\n")?.split_once("\r\n\r\n")?;
        if part_header(mime, "Content-Type") != Some("application/http") {
            return None;
        }
        let (http, body) = http.split_once("\r\n\r\n").unwrap_or((http, ""));
        let status = http
            .lines()
            .next()?
            .strip_prefix("HTTP/1.1 ")?
            .split_whitespace()
            .next()?
            .parse()
            .ok()?;
        parts.push(WirePart {
            mime,
            http,
            status,
            body: body.trim(),
        });
    }
    None
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
enum Step {
    DeleteBatch,
    ReadDeletedA,
    ReadDeletedB,
    TierBatch,
    ReadTiered,
    MixedBatch,
    ReadUnaffected,
}

#[derive(Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
struct Part {
    content_id: Option<u16>,
    status: u16,
    request_id: bool,
    api_version: Header,
    error_header: ErrorCode,
    permanent_delete: Header,
    empty_body: bool,
    error: Option<XmlError>,
}

impl Part {
    fn project(wire: WirePart<'_>) -> Result<Self> {
        use super::cassette::echoed;
        let id = wire.header("x-ms-request-id");
        let error = match wire.status {
            404 => project_error(wire.body, id, MISSING_MESSAGE),
            400 => project_error(wire.body, id, MIXED_MESSAGE),
            _ => None,
        };
        Ok(Self {
            content_id: wire
                .content_id()
                .map(str::parse)
                .transpose()
                .context("unexpected batch content ID")?,
            status: wire.status,
            request_id: id.is_some_and(|id| Uuid::parse_str(id).is_ok()),
            api_version: echoed(wire.header("x-ms-version"), Some(VERSION)),
            error_header: ErrorCode::from_value(wire.header("x-ms-error-code")),
            permanent_delete: echoed(wire.header("x-ms-delete-type-permanent"), Some("true")),
            empty_body: wire.body.is_empty(),
            error,
        })
    }
}

#[derive(Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
enum Body {
    Multipart {
        parts: Vec<Part>,
    },
    Blob {
        bytes_match: bool,
        tier_cool: Header,
        original_etag: Header,
    },
    Xml(XmlError),
    Other {},
}

#[derive(Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
struct Exchange {
    step: Step,
    status: u16,
    request_id: bool,
    api_version: Header,
    error_header: ErrorCode,
    body: Body,
}

impl Exchange {
    fn valid(&self) -> bool {
        use Step::*;
        if !self.request_id || self.api_version != Header::Matches {
            return false;
        }
        match (&self.body, self.step) {
            (Body::Multipart { parts }, step @ (DeleteBatch | TierBatch | MixedBatch)) => {
                let expected: &[(Option<u16>, u16)] = match step {
                    DeleteBatch => &[(Some(0), 202), (Some(1), 202), (Some(2), 404)],
                    TierBatch => &[(Some(0), 200), (Some(1), 404)],
                    _ => &[(None, 400)],
                };
                self.status == 202
                    && parts
                        .iter()
                        .map(|part| (part.content_id, part.status))
                        .eq(expected.iter().copied())
                    && parts.iter().all(|part| {
                        part.request_id
                            && part.api_version == Header::Matches
                            && match part.status {
                                202 => part.empty_body && part.permanent_delete == Header::Matches,
                                200 => part.empty_body,
                                404 => {
                                    part.error_header == ErrorCode::BlobNotFound
                                        && part.error.as_ref().is_some_and(|error| {
                                            error.code == ErrorCode::BlobNotFound
                                        })
                                }
                                400 => {
                                    part.error_header == ErrorCode::MixedBatchOperations
                                        && part.error.as_ref().is_some_and(|error| {
                                            error.code == ErrorCode::MixedBatchOperations
                                        })
                                }
                                _ => false,
                            }
                    })
            }
            (Body::Xml(error), ReadDeletedA | ReadDeletedB) => {
                self.status == 404
                    && self.error_header == ErrorCode::BlobNotFound
                    && error.code == ErrorCode::BlobNotFound
            }
            (
                Body::Blob {
                    bytes_match: true,
                    tier_cool: Header::Matches,
                    original_etag: Header::Matches,
                },
                ReadTiered | ReadUnaffected,
            ) => self.status == 200,
            _ => false,
        }
    }
}

#[derive(Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub(super) struct BatchCassette {
    schema_version: u8,
    source: Source,
    api_version: ApiVersion,
    responses: [Exchange; 7],
}

impl BatchCassette {
    pub(super) fn validate(&self) -> Result<()> {
        use Step::*;
        ensure!(
            self.schema_version == 1,
            "unsupported Batch cassette version"
        );
        ensure!(
            self.responses.each_ref().map(|response| response.step)
                == [
                    DeleteBatch,
                    ReadDeletedA,
                    ReadDeletedB,
                    TierBatch,
                    ReadTiered,
                    MixedBatch,
                    ReadUnaffected
                ],
            "unexpected Batch steps"
        );
        for response in &self.responses {
            ensure!(
                response.valid(),
                "Batch probe did not reach the expected synthetic outcome: {response:#?}"
            );
        }
        Ok(())
    }

    pub(super) fn compare(&self, actual: &Self) -> Result<()> {
        self.validate()?;
        for (reviewed, observed) in self.responses.iter().zip(&actual.responses) {
            ensure!(
                reviewed == observed,
                "{:?}: expected {reviewed:#?}, observed {observed:#?}",
                reviewed.step
            );
        }
        Ok(())
    }
}

struct Probe<'a> {
    client: &'a Client,
    bearer: &'a str,
    batch_url: Url,
}

impl Probe<'_> {
    fn seed(&self, url: &Url) -> Result<String> {
        let response = send(
            request(self.client, Method::PUT, url.clone())
                .bearer_auth(self.bearer)
                .header("x-ms-blob-type", "BlockBlob")
                .header("content-type", "text/plain")
                .body(BYTES),
            "seed synthetic Batch blob",
        )?;
        require_status(&response, 201, "seed synthetic Batch blob")?;
        header_text(response.headers(), "etag")
            .map(str::to_owned)
            .context("Batch seed lacks an ETag")
    }

    fn submit(&self, step: Step, parts: &[(Method, &Url)]) -> Result<Exchange> {
        use std::fmt::Write as _;
        let mut wire = String::new();
        let date = httpdate::fmt_http_date(SystemTime::now());
        for (id, (method, url)) in parts.iter().enumerate() {
            let path = url.path();
            let (query, tier) = if *method == Method::PUT {
                ("?comp=tier", "x-ms-access-tier: Cool\r\n")
            } else {
                ("", "")
            };
            write!(
                wire,
                "--{BOUNDARY}\r\nContent-Type: application/http\r\nContent-Transfer-Encoding: binary\r\nContent-ID: {id}\r\n\r\n{method} {path}{query} HTTP/1.1\r\nx-ms-date: {date}\r\nAuthorization: Bearer {}\r\nContent-Length: 0\r\n{tier}\r\n",
                self.bearer
            )?;
        }
        write!(wire, "--{BOUNDARY}--\r\n")?;
        let response = self.observe(
            step,
            request(self.client, Method::POST, self.batch_url.clone())
                .header(
                    "content-type",
                    format!("multipart/mixed; boundary={BOUNDARY}"),
                )
                .body(wire),
            None,
        )?;
        Ok(response)
    }

    fn read(&self, step: Step, url: &Url, reference: Option<&str>) -> Result<Exchange> {
        self.observe(
            step,
            request(self.client, Method::GET, url.clone()),
            reference,
        )
    }

    fn observe(
        &self,
        step: Step,
        wire: reqwest::blocking::RequestBuilder,
        reference: Option<&str>,
    ) -> Result<Exchange> {
        let response = send(wire.bearer_auth(self.bearer), "observe Batch workflow")
            .with_context(|| format!("{step:?}"))?;
        let status = response.status().as_u16();
        let headers = response.headers().clone();
        let bytes = read_bounded(response)?;
        let text = std::str::from_utf8(&bytes).context("invalid Batch response encoding")?;
        let id = header_text(&headers, "x-ms-request-id");
        let body = if let Some(raw) = parse_parts(&headers, text) {
            let mut parts: Vec<_> = raw.into_iter().map(Part::project).collect::<Result<_>>()?;
            parts.sort_by_key(|part| part.content_id);
            Body::Multipart { parts }
        } else if status == 200 {
            Body::Blob {
                bytes_match: bytes == BYTES,
                tier_cool: header(&headers, "x-ms-access-tier", |value| value == "Cool"),
                original_etag: header(&headers, "etag", |value| Some(value) == reference),
            }
        } else if let Some(error) = project_error(text, id, MISSING_MESSAGE) {
            Body::Xml(error)
        } else {
            Body::Other {}
        };
        Ok(Exchange {
            step,
            status,
            body,
            api_version: header(&headers, "x-ms-version", |value| value == VERSION),
            error_header: ErrorCode::from_value(header_text(&headers, "x-ms-error-code")),
            request_id: id.is_some_and(|id| Uuid::parse_str(id).is_ok()),
        })
    }
}

pub(super) fn observe(
    client: &Client,
    endpoint: &Url,
    bearer: &str,
    source: Source,
) -> Result<BatchCassette> {
    with_fresh_container(client, endpoint, bearer, |container, first| {
        use Step::*;
        let probe = Probe {
            client,
            bearer,
            batch_url: endpoint.join(&format!("{container}?restype=container&comp=batch"))?,
        };
        let second = first.join("second.txt")?;
        let keep = first.join("keep.txt")?;
        let missing = first.join("missing.txt")?;
        probe.seed(&first)?;
        probe.seed(&second)?;
        let etag = probe.seed(&keep)?;
        let responses = [
            probe.submit(
                DeleteBatch,
                &[
                    (Method::DELETE, &first),
                    (Method::DELETE, &second),
                    (Method::DELETE, &missing),
                ],
            )?,
            probe.read(ReadDeletedA, &first, None)?,
            probe.read(ReadDeletedB, &second, None)?,
            probe.submit(TierBatch, &[(Method::PUT, &keep), (Method::PUT, &missing)])?,
            probe.read(ReadTiered, &keep, Some(&etag))?,
            probe.submit(MixedBatch, &[(Method::DELETE, &keep), (Method::PUT, &keep)])?,
            probe.read(ReadUnaffected, &keep, Some(&etag))?,
        ];
        Ok(BatchCassette {
            schema_version: 1,
            source,
            api_version: ApiVersion::Baseline,
            responses,
        })
    })
}

pub(super) fn reviewed() -> Result<BatchCassette> {
    let path = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("tests/contracts/cassettes")
        .join(format!("{CASE}.json"));
    let bytes = read_bounded(File::open(path).context("open the reviewed Batch cassette")?)?;
    let value: BatchCassette = serde_json::from_slice(&bytes)
        .map_err(|error| anyhow::anyhow!("invalid Batch cassette at line {}", error.line()))?;
    ensure!(
        value.source == Source::Azure,
        "expected the reviewed Azure Batch recording"
    );
    value.validate()?;
    Ok(value)
}

pub(super) fn observe_local() -> Result<BatchCassette> {
    with_local(|client, endpoint, bearer| observe(client, endpoint, bearer, Source::Synthetic))
}

#[test]
fn replay_blob_batch_mixed_results() -> Result<()> {
    reviewed()?.compare(&observe_local()?)
}
