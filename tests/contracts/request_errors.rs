use super::{
    Service, VERSION,
    cassette::{
        ApiVersion, ErrorCode, Header, Media, OdataError, Source, error_message, flat_xml, header,
        header_text, media, project_xml,
    },
    catalog, read_bounded, request, send, with_fresh_container, with_local_service,
};
use anyhow::{Context as _, Result, ensure};
use reqwest::{
    Method, Url,
    blocking::{Client, RequestBuilder},
    header::HeaderMap,
};
use serde::{Deserialize, Serialize};
use std::{collections::BTreeMap, fs::File, path::Path};
use uuid::Uuid;

const BOUNDARY: &str = "azuifer-contract-batch";
const INVALID_INPUT: &str = "One of the request inputs is not valid.";
const INVALID_XML: &str = "XML specified is not syntactically valid.";
const QUEUE_LIMIT: usize = 64 * 1024;
const INVALID_VISIBILITY: &str = "604801";
const ATOM: &str = "application/atom+xml";
const NO_METADATA: &str = "application/json;odata=nometadata";
const ODATA_XML_NS: &str = "http://schemas.microsoft.com/ado/2007/08/dataservices/metadata";
const INCOMPLETE_FILTER: &str = "PartitionKey eq";
const ATOM_MESSAGE: &str = "Atom format is not supported.";

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub(super) enum Case {
    EmptyBatch,
    TruncatedBatch,
    MalformedQueryXml,
    QueueVisibility,
    QueueMessageTooLarge,
    TableAtomAccept,
    TableAtomFormat,
    TableAtomContent,
    TableIncompleteFilter,
}

impl Case {
    pub(super) fn service(self) -> Service {
        match self {
            Self::EmptyBatch | Self::TruncatedBatch | Self::MalformedQueryXml => Service::Blob,
            Self::QueueVisibility | Self::QueueMessageTooLarge => Service::Queue,
            _ => Service::Table,
        }
    }

    pub(super) fn file_stem(self) -> &'static str {
        match self {
            Self::EmptyBatch => "blob-batch-empty-envelope",
            Self::TruncatedBatch => "blob-batch-truncated-part",
            Self::MalformedQueryXml => "blob-query-malformed-xml",
            Self::QueueVisibility => "queue-put-visibility-limit",
            Self::QueueMessageTooLarge => "queue-put-message-size-limit",
            Self::TableAtomAccept => "table-atom-accept",
            Self::TableAtomFormat => "table-atom-format",
            Self::TableAtomContent => "table-atom-content",
            Self::TableIncompleteFilter => "table-incomplete-filter",
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
    project_xml_error(&fields, request_id, expected)
}

fn project_xml_error(
    fields: &BTreeMap<String, String>,
    request_id: Option<&str>,
    expected: &str,
) -> Option<XmlError> {
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
    QueueXml {
        error: XmlError,
        limit_details_match: bool,
    },
    TableXml {
        code: ErrorCode,
        namespace_matches: bool,
        english: bool,
        message_matches: bool,
        correlation: Header,
    },
    TableJson {
        media: Media,
        error: OdataError,
    },
    Other {},
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RawOdataError {
    #[serde(rename = "@xmlns")]
    namespace: String,
    code: String,
    message: RawOdataMessage,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RawOdataMessage {
    #[serde(rename = "@xml:lang")]
    lang: String,
    #[serde(rename = "$text")]
    value: String,
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
    #[serde(default, skip_serializing_if = "Option::is_none")]
    dataserviceversion: Option<Header>,
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
            (
                Body::QueueXml {
                    error,
                    limit_details_match,
                },
                Case::QueueVisibility | Case::QueueMessageTooLarge,
            ) => {
                let (status, code, fields) = if self.case == Case::QueueVisibility {
                    (400, ErrorCode::OutOfRangeQueryParameterValue, 4)
                } else {
                    (413, ErrorCode::RequestBodyTooLarge, 1)
                };
                response.status == status
                    && error.code == code
                    && response.header_code == code
                    && error.correlation == Header::Matches
                    && error.message_matches
                    && error.extra_elements == fields
                    && *limit_details_match
            }
            (
                Body::TableXml {
                    code: ErrorCode::AtomFormatNotSupported,
                    namespace_matches: true,
                    english: true,
                    message_matches: true,
                    correlation: Header::Matches,
                },
                Case::TableAtomAccept | Case::TableAtomFormat,
            ) => response.is_table_rejection(415),
            (
                Body::TableJson {
                    media: Media::JsonNoMetadata,
                    error,
                },
                Case::TableAtomContent,
            ) => {
                response.is_table_rejection(415) && error.matches(ErrorCode::AtomFormatNotSupported)
            }
            (
                Body::TableJson {
                    media: Media::JsonNoMetadata,
                    error,
                },
                Case::TableIncompleteFilter,
            ) => response.is_table_rejection(400) && error.matches(ErrorCode::InvalidInput),
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

impl Exchange {
    fn is_table_rejection(&self, status: u16) -> bool {
        self.status == status
            && self.header_code == ErrorCode::Missing
            && self.dataserviceversion == Some(Header::Missing)
    }
}

pub(super) fn observe(
    client: &Client,
    endpoint: &Url,
    bearer: &str,
    source: Source,
    case: Case,
) -> Result<Rejection> {
    let response = match case.service() {
        Service::Blob => with_fresh_container(client, endpoint, bearer, |container, blob| {
            let wire = if case == Case::MalformedQueryXml {
                request(client, Method::POST, blob.join("?comp=query")?)
                    .header("content-type", "application/xml; charset=UTF-8")
                    .body("<QueryRequest>")
            } else {
                request(
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
                })
            };
            exchange(case, wire.bearer_auth(bearer))
        }),
        Service::Queue => catalog::with_fresh_resource(
            client,
            endpoint,
            bearer,
            catalog::Case::QueueLifecycle,
            |name| {
                let text = if case == Case::QueueMessageTooLarge {
                    "x".repeat(QUEUE_LIMIT + 1)
                } else {
                    "x".to_owned()
                };
                let wire = request(
                    client,
                    Method::POST,
                    endpoint.join(&format!("{name}/messages"))?,
                )
                .bearer_auth(bearer)
                .header("content-type", "application/xml")
                .body(format!(
                    "<QueueMessage><MessageText>{text}</MessageText></QueueMessage>"
                ));
                let wire = if case == Case::QueueVisibility {
                    wire.query(&[("visibilitytimeout", INVALID_VISIBILITY)])
                } else {
                    wire
                };
                exchange(case, wire)
            },
        ),
        Service::Table => catalog::with_fresh_resource(
            client,
            endpoint,
            bearer,
            catalog::Case::TableLifecycle,
            |name| {
                let wire = if case == Case::TableAtomContent {
                    request(client, Method::POST, endpoint.join(name)?)
                        .header("content-type", ATOM)
                        .body("<entry xmlns=\"http://www.w3.org/2005/Atom\"/>")
                } else {
                    let wire = request(client, Method::GET, endpoint.join(&format!("{name}()"))?)
                        .query(&[("$top", "1")]);
                    match case {
                        Case::TableIncompleteFilter => {
                            wire.query(&[("$filter", INCOMPLETE_FILTER)])
                        }
                        Case::TableAtomFormat => wire.query(&[("$format", "atom")]),
                        _ => wire,
                    }
                };
                let accept = if case == Case::TableAtomAccept {
                    ATOM
                } else {
                    NO_METADATA
                };
                exchange(
                    case,
                    wire.bearer_auth(bearer)
                        .header("accept", accept)
                        .header("dataserviceversion", "3.0"),
                )
            },
        ),
    }?;
    Ok(Rejection {
        schema_version: 1,
        case,
        source,
        api_version: ApiVersion::Baseline,
        response,
    })
}

fn exchange(case: Case, wire: RequestBuilder) -> Result<Exchange> {
    let response = send(wire, "observe request rejection")?;
    let status = response.status().as_u16();
    let headers = response.headers().clone();
    let bytes = read_bounded(response)?;
    let id = header_text(&headers, "x-ms-request-id");
    let text = std::str::from_utf8(&bytes).context("invalid rejection response encoding")?;
    let body = match case.service() {
        Service::Blob => {
            if media(&headers) == Media::Xml {
                let expected = if case == Case::MalformedQueryXml {
                    INVALID_XML
                } else {
                    INVALID_INPUT
                };
                project_error(text, id, expected).map(Body::Xml)
            } else {
                part(&headers, text).map(Body::Multipart)
            }
        }
        Service::Queue => queue_error(case, text, id, media(&headers)),
        Service::Table => Some(table_error(case, &headers, &bytes, id)?),
    };
    Ok(Exchange {
        status,
        api_version: header(&headers, "x-ms-version", |value| value == VERSION),
        request_id: header(&headers, "x-ms-request-id", |value| {
            Uuid::parse_str(value).is_ok()
        }),
        header_code: ErrorCode::from_value(header_text(&headers, "x-ms-error-code")),
        dataserviceversion: matches!(case.service(), Service::Table)
            .then(|| header(&headers, "dataserviceversion", |value| value == "3.0;")),
        body: body.unwrap_or(Body::Other {}),
    })
}

fn queue_error(case: Case, xml: &str, id: Option<&str>, media: Media) -> Option<Body> {
    if media != Media::Xml {
        return None;
    }
    let fields = flat_xml(xml, "Error")?;
    let field = |key| fields.get(key).map(String::as_str);
    let (message, limit_details_match) = if case == Case::QueueVisibility {
        (
            "One of the query parameters specified in the request URI is outside the permissible range.",
            field("QueryParameterName") == Some("visibilitytimeout")
                && field("QueryParameterValue") == Some(INVALID_VISIBILITY)
                && field("MinimumAllowed") == Some("0")
                && field("MaximumAllowed") == Some("604800"),
        )
    } else {
        (
            "The request body is too large and exceeds the maximum permissible limit.",
            field("MaxLimit").and_then(|value| value.parse::<usize>().ok()) == Some(QUEUE_LIMIT),
        )
    };
    Some(Body::QueueXml {
        error: project_xml_error(&fields, id, message)?,
        limit_details_match,
    })
}

fn table_error(case: Case, headers: &HeaderMap, bytes: &[u8], id: Option<&str>) -> Result<Body> {
    let media = media(headers);
    if media == Media::OdataXml {
        let error: RawOdataError = project_xml(bytes, "error")?;
        let (message, correlation) = error_message(&error.message.value, id);
        return Ok(Body::TableXml {
            code: ErrorCode::from_value(Some(&error.code)),
            namespace_matches: error.namespace == ODATA_XML_NS,
            english: error.message.lang == "en-US",
            message_matches: message == ATOM_MESSAGE,
            correlation,
        });
    }
    let message = if case == Case::TableIncompleteFilter {
        "Expression expected at position 15 in 'PartitionKey eq'."
    } else {
        ATOM_MESSAGE
    };
    Ok(Body::TableJson {
        media,
        error: OdataError::project(bytes, id, message)?,
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
    with_local_service(case.service(), |client, endpoint, bearer| {
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

fn replay(case: Case) -> Result<()> {
    reviewed(case)?.compare(&observe_local(case)?)
}

#[test]
fn replay_wave_2_queue_visibility() -> Result<()> {
    replay(Case::QueueVisibility)
}

#[test]
fn replay_wave_2_queue_message_size() -> Result<()> {
    replay(Case::QueueMessageTooLarge)
}

#[test]
fn replay_wave_2_table_atom_accept() -> Result<()> {
    replay(Case::TableAtomAccept)
}

#[test]
fn replay_wave_2_table_atom_format() -> Result<()> {
    replay(Case::TableAtomFormat)
}

#[test]
fn replay_wave_2_table_atom_content() -> Result<()> {
    replay(Case::TableAtomContent)
}

#[test]
fn replay_wave_2_table_incomplete_filter() -> Result<()> {
    replay(Case::TableIncompleteFilter)
}
