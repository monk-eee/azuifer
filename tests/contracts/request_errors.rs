use super::{
    VERSION,
    cassette::{
        ApiVersion, ErrorCode, Header, Media, Source, error_message, flat_xml, header, header_text,
        media,
    },
    read_bounded, request, send, with_fresh_container, with_local,
};
use anyhow::{Context as _, Result, ensure};
use reqwest::{Method, Url, blocking::Client, header::HeaderMap};
use serde::{Deserialize, Serialize};
use std::{fs::File, path::Path};
use uuid::Uuid;

const BOUNDARY: &str = "azuifer-contract-batch";
const INVALID_INPUT: &str = "One of the request inputs is not valid.";
const INVALID_XML: &str = "XML specified is not syntactically valid.";

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub(super) enum Case {
    EmptyBatch,
    TruncatedBatch,
    MalformedQueryXml,
}

impl Case {
    pub(super) fn file_stem(self) -> &'static str {
        match self {
            Self::EmptyBatch => "blob-batch-empty-envelope",
            Self::TruncatedBatch => "blob-batch-truncated-part",
            Self::MalformedQueryXml => "blob-query-malformed-xml",
        }
    }
}

#[derive(Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub(super) struct XmlError {
    pub(super) code: ErrorCode,
    correlation: Header,
    message_matches: bool,
    extra_elements: usize,
}

pub(super) fn project_error(
    xml: &str,
    request_id: Option<&str>,
    expected: &str,
) -> Option<XmlError> {
    let fields = flat_xml(xml, "Error")?;
    let (message, correlation) = error_message(fields.get("Message")?, request_id);
    Some(XmlError {
        code: ErrorCode::from_value(fields.get("Code").map(String::as_str)),
        correlation,
        message_matches: message == expected,
        extra_elements: fields
            .keys()
            .filter(|name| !matches!(name.as_str(), "Code" | "Message"))
            .count(),
    })
}

#[derive(Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
struct Part {
    status: u16,
    content_id_present: bool,
    header_code: ErrorCode,
    request_id: bool,
    api_version: Header,
    error: Option<XmlError>,
}

#[derive(Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
enum Body {
    Multipart(Part),
    Xml(XmlError),
    Other {},
}

fn part(headers: &HeaderMap, wire: &str) -> Option<Part> {
    let parts = super::batch::parse_parts(headers, wire)?;
    let [wire] = parts.as_slice() else {
        return None;
    };
    let id = wire.header("x-ms-request-id");
    Some(Part {
        status: wire.status,
        content_id_present: wire.content_id().is_some(),
        header_code: ErrorCode::from_value(wire.header("x-ms-error-code")),
        request_id: id.is_some_and(|id| Uuid::parse_str(id).is_ok()),
        api_version: super::cassette::echoed(wire.header("x-ms-version"), Some(VERSION)),
        error: project_error(wire.body, id, INVALID_INPUT),
    })
}

#[derive(Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub(super) struct Rejection {
    schema_version: u8,
    source: Source,
    pub(super) case: Case,
    api_version: ApiVersion,
    response: Exchange,
}

#[derive(Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
struct Exchange {
    status: u16,
    request_id: Header,
    api_version: Header,
    header_code: ErrorCode,
    body: Body,
}

impl Rejection {
    pub(super) fn validate(&self) -> Result<()> {
        ensure!(
            self.schema_version == 1,
            "unsupported request rejection cassette version"
        );
        let response = &self.response;
        let valid = match (&response.body, self.case) {
            (Body::Multipart(part), Case::EmptyBatch | Case::TruncatedBatch) => {
                response.status == 202
                    && response.header_code == ErrorCode::Missing
                    && part.status == 400
                    && !part.content_id_present
                    && part
                        .error
                        .as_ref()
                        .is_some_and(|error| error.code == ErrorCode::InvalidInput)
            }
            (Body::Xml(error), Case::MalformedQueryXml) => {
                response.status == 400
                    && response.header_code == ErrorCode::InvalidXmlDocument
                    && error.code == ErrorCode::InvalidXmlDocument
            }
            _ => false,
        };
        ensure!(
            response.api_version == Header::Matches
                && response.request_id == Header::Matches
                && valid,
            "{:?} did not reach the expected rejection: {response:#?}",
            self.case
        );
        Ok(())
    }

    pub(super) fn compare(&self, observed: &Self) -> Result<()> {
        self.validate()?;
        ensure!(
            self.case == observed.case && self.response == observed.response,
            "{:?}: expected {:#?}, observed {:#?}",
            self.case,
            self.response,
            observed.response
        );
        Ok(())
    }
}

pub(super) fn observe(
    client: &Client,
    endpoint: &Url,
    bearer: &str,
    source: Source,
    case: Case,
) -> Result<Rejection> {
    with_fresh_container(client, endpoint, bearer, |container, blob| {
        let wire = match case {
            Case::EmptyBatch | Case::TruncatedBatch => request(
                client,
                Method::POST,
                endpoint.join(&format!("{container}?restype=container&comp=batch"))?,
            )
            .header(
                "content-type",
                format!("multipart/mixed; boundary={BOUNDARY}"),
            )
            .body(if case == Case::EmptyBatch {
                format!("--{BOUNDARY}--\r\n")
            } else {
                format!("--{BOUNDARY}\r\nContent-Type: application/http\r\n")
            }),
            Case::MalformedQueryXml => request(client, Method::POST, blob.join("?comp=query")?)
                .header("content-type", "application/xml; charset=UTF-8")
                .body("<QueryRequest>"),
        };
        let response = send(wire.bearer_auth(bearer), "observe Blob request rejection")?;
        let status = response.status().as_u16();
        let headers = response.headers().clone();
        let bytes = read_bounded(response)?;
        let text = std::str::from_utf8(&bytes).context("invalid Blob rejection encoding")?;
        let expected = match case {
            Case::EmptyBatch | Case::TruncatedBatch => INVALID_INPUT,
            Case::MalformedQueryXml => INVALID_XML,
        };
        let body = if media(&headers) == Media::Xml {
            project_error(text, header_text(&headers, "x-ms-request-id"), expected).map(Body::Xml)
        } else {
            part(&headers, text).map(Body::Multipart)
        }
        .unwrap_or(Body::Other {});
        Ok(Rejection {
            schema_version: 1,
            case,
            source,
            api_version: ApiVersion::Baseline,
            response: Exchange {
                status,
                api_version: header(&headers, "x-ms-version", |value| value == VERSION),
                request_id: header(&headers, "x-ms-request-id", |id| {
                    Uuid::parse_str(id).is_ok()
                }),
                header_code: ErrorCode::from_value(header_text(&headers, "x-ms-error-code")),
                body,
            },
        })
    })
}

pub(super) fn reviewed(case: Case) -> Result<Rejection> {
    let path = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("tests")
        .join("contracts")
        .join("cassettes")
        .join(format!("{}.json", case.file_stem()));
    let raw = read_bounded(
        File::open(path)
            .with_context(|| format!("could not open reviewed {} cassette", case.file_stem()))?,
    )?;
    let value: Rejection = serde_json::from_slice(&raw)
        .map_err(|error| anyhow::anyhow!("invalid rejection cassette at line {}", error.line()))?;
    ensure!(
        value.source == Source::Azure && value.case == case,
        "expected the reviewed Azure rejection"
    );
    value.validate()?;
    Ok(value)
}

pub(super) fn observe_local(case: Case) -> Result<Rejection> {
    with_local(|client, endpoint, bearer| {
        observe(client, endpoint, bearer, Source::Synthetic, case)
    })
}

#[test]
fn replay_blob_batch_empty_envelope() -> Result<()> {
    let case = Case::EmptyBatch;
    reviewed(case)?.compare(&observe_local(case)?)
}

#[test]
fn replay_blob_batch_truncated_part() -> Result<()> {
    let case = Case::TruncatedBatch;
    reviewed(case)?.compare(&observe_local(case)?)
}

#[test]
fn replay_blob_query_malformed_xml() -> Result<()> {
    let case = Case::MalformedQueryXml;
    reviewed(case)?.compare(&observe_local(case)?)
}
