use super::{
    Service, VERSION,
    account::WireProperties,
    cassette::{
        ApiVersion, ErrorCode, Header, Media, Source, flat_xml, header, header_text, media,
        project_xml,
    },
    catalog, read_bounded, request,
    request_errors::{OdataXmlError, XmlError, project_xml_error},
    require_status, send, with_local_service,
};
use anyhow::{Context as _, Result, anyhow, ensure};
use reqwest::{
    Method, Url,
    blocking::{Client, RequestBuilder},
    header::HeaderMap,
};
use serde::{Deserialize, Serialize};
use std::{fs::File, path::Path};
use uuid::Uuid;

const ORIGIN: &str = "https://azuifer-contract.invalid";
const NO_RULE: &str = "CORS not enabled or no matching rule found for this request.";
const MISSING_HEADER: &str = "A required CORS header is not present.";
const PROPERTIES: &str = "?restype=service&comp=properties";
const LOCAL_PROFILE: &str = concat!(
    "<StorageServiceProperties>",
    "<Logging><Version>1.0</Version><Delete>false</Delete><Read>false</Read><Write>false</Write>",
    "<RetentionPolicy><Enabled>false</Enabled></RetentionPolicy></Logging>",
    "<HourMetrics><Version>1.0</Version><Enabled>false</Enabled>",
    "<RetentionPolicy><Enabled>false</Enabled></RetentionPolicy></HourMetrics>",
    "<MinuteMetrics><Version>1.0</Version><Enabled>false</Enabled>",
    "<RetentionPolicy><Enabled>false</Enabled></RetentionPolicy></MinuteMetrics>",
    "<Cors/></StorageServiceProperties>",
);

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub(super) enum Case {
    Queue,
    Table,
}

impl Case {
    pub(super) fn service(self) -> Service {
        match self {
            Self::Queue => Service::Queue,
            Self::Table => Service::Table,
        }
    }

    pub(super) fn file_stem(self) -> &'static str {
        match self {
            Self::Queue => "queue-read-only-settings",
            Self::Table => "table-read-only-settings",
        }
    }

    fn catalog(self) -> catalog::Case {
        match self {
            Self::Queue => catalog::Case::QueueLifecycle,
            Self::Table => catalog::Case::TableLifecycle,
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
enum Step {
    Properties,
    EmptyAcl,
    RuleMiss,
    MissingMethod,
    MissingOrigin,
}

const STEPS: [Step; 5] = [
    Step::Properties,
    Step::EmptyAcl,
    Step::RuleMiss,
    Step::MissingMethod,
    Step::MissingOrigin,
];

impl Step {
    fn preflight(self) -> Option<(u16, ErrorCode, &'static str, &'static str)> {
        match self {
            Self::RuleMiss => Some((
                403,
                ErrorCode::CorsPreflightFailure,
                NO_RULE,
                "No CORS rules matches this request",
            )),
            Self::MissingMethod => Some((
                400,
                ErrorCode::InvalidHeaderValue,
                MISSING_HEADER,
                "Missing required CORS header Access-Control-Request-Method",
            )),
            Self::MissingOrigin => Some((
                400,
                ErrorCode::InvalidHeaderValue,
                MISSING_HEADER,
                "Missing required CORS header Origin",
            )),
            _ => None,
        }
    }
}

#[derive(Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
enum Body {
    Properties {
        analytics_disabled: bool,
        cors_count: Option<usize>,
    },
    Acl {
        policies: usize,
    },
    QueueCors {
        error: XmlError,
        details_match: bool,
    },
    TableCors(OdataXmlError),
    Unexpected {},
}

#[derive(Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
struct Exchange {
    step: Step,
    status: u16,
    media: Media,
    api_version: Header,
    request_id: Header,
    date: Header,
    dataserviceversion: Header,
    error_header: ErrorCode,
    cors_headers_present: bool,
    body: Body,
}

#[derive(Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub(super) struct ServiceReadCassette {
    schema_version: u8,
    source: Source,
    pub(super) case: Case,
    api_version: ApiVersion,
    responses: [Exchange; 5],
}

impl ServiceReadCassette {
    pub(super) fn validate(&self) -> Result<()> {
        ensure!(
            self.schema_version == 1,
            "unsupported service-read cassette version"
        );
        ensure!(
            self.responses.each_ref().map(|r| r.step) == STEPS,
            "unexpected service-read steps"
        );
        for r in &self.responses {
            let valid = match (r.step, &r.body) {
                (
                    Step::Properties,
                    Body::Properties {
                        analytics_disabled: true,
                        cors_count: Some(0),
                    },
                )
                | (Step::EmptyAcl, Body::Acl { policies: 0 }) => {
                    r.status == 200 && r.error_header == ErrorCode::Missing
                }
                (step, body) => step.preflight().is_some_and(|(status, code, _, _)| {
                    if status != r.status || code != r.error_header {
                        return false;
                    }
                    match (self.case, body) {
                        (
                            Case::Queue,
                            Body::QueueCors {
                                error,
                                details_match,
                            },
                        ) => *details_match && error.matches(code, 1),
                        (Case::Table, Body::TableCors(error)) => error.matches(code),
                        _ => false,
                    }
                }),
            };
            ensure!(
                valid
                    && r.media == Media::Xml
                    && r.api_version == Header::Matches
                    && r.request_id == Header::Matches
                    && r.date == Header::Matches
                    && r.dataserviceversion == Header::Missing
                    && !r.cors_headers_present,
                "{:?} did not reach the expected read-only contract: {r:#?}",
                r.step
            );
        }
        Ok(())
    }

    pub(super) fn compare(&self, actual: &Self) -> Result<()> {
        self.validate()?;
        ensure!(self.case == actual.case, "unexpected service-read case");
        let diffs: Vec<_> = self
            .responses
            .iter()
            .zip(&actual.responses)
            .filter(|(a, b)| a != b)
            .collect();
        ensure!(
            diffs.is_empty(),
            "{}: differing exchanges (reviewed, observed):\n{diffs:#?}",
            self.case.file_stem()
        );
        Ok(())
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct WireAcl {
    #[serde(rename = "SignedIdentifier", default)]
    policies: Vec<serde::de::IgnoredAny>,
}

fn exchange(
    step: Step,
    wire: RequestBuilder,
    project: impl FnOnce(&HeaderMap, &[u8]) -> Result<Body>,
) -> Result<Exchange> {
    let response = send(wire, "record read-only Queue or Table response")?;
    let status = response.status().as_u16();
    let headers = response.headers().clone();
    let bytes = read_bounded(response)?;
    let body = project(&headers, &bytes)
        .with_context(|| format!("{step:?}: Azure-shaped body expected, got HTTP {status}"))?;
    Ok(Exchange {
        step,
        status,
        media: media(&headers),
        api_version: header(&headers, "x-ms-version", |value| value == VERSION),
        request_id: header(&headers, "x-ms-request-id", |id| {
            Uuid::parse_str(id).is_ok()
        }),
        date: header(&headers, "date", |value| {
            httpdate::parse_http_date(value).is_ok()
        }),
        dataserviceversion: header(&headers, "dataserviceversion", |value| value == "3.0;"),
        error_header: ErrorCode::from_value(header_text(&headers, "x-ms-error-code")),
        cors_headers_present: headers.keys().any(|name| {
            name.as_str().starts_with("access-control-allow-") || name == "access-control-max-age"
        }),
        body,
    })
}

fn preflight(case: Case, client: &Client, endpoint: &Url, step: Step) -> Result<Exchange> {
    let (_, _, message, detail) = step.preflight().context("unexpected preflight step")?;
    let mut wire = request(client, Method::OPTIONS, endpoint.clone());
    if case == Case::Table {
        wire = wire.header("accept", "application/xml");
    }
    if step != Step::MissingOrigin {
        wire = wire.header("origin", ORIGIN);
    }
    if step != Step::MissingMethod {
        wire = wire.header("access-control-request-method", "GET");
    }
    exchange(step, wire, |headers, bytes| {
        if media(headers) != Media::Xml {
            return Ok(Body::Unexpected {});
        }
        let id = header_text(headers, "x-ms-request-id");
        Ok(match case {
            Case::Queue => {
                let xml = std::str::from_utf8(bytes).context("invalid Queue XML encoding")?;
                let fields = flat_xml(xml, "Error").context("invalid Queue XML error")?;
                Body::QueueCors {
                    error: project_xml_error(&fields, id, message)
                        .context("missing Queue error message")?,
                    details_match: fields.get("MessageDetails").map(String::as_str) == Some(detail),
                }
            }
            Case::Table => Body::TableCors(OdataXmlError::project(bytes, id, message)?),
        })
    })
}

pub(super) fn observe(
    client: &Client,
    endpoint: &Url,
    bearer: &str,
    source: Source,
    case: Case,
) -> Result<ServiceReadCassette> {
    let properties = exchange(
        Step::Properties,
        request(client, Method::GET, endpoint.join(PROPERTIES)?).bearer_auth(bearer),
        |_, bytes| {
            let wire: WireProperties = project_xml(bytes, "StorageServiceProperties")?;
            Ok(Body::Properties {
                analytics_disabled: wire.analytics_disabled(),
                cors_count: wire.cors_count(),
            })
        },
    )?;
    ensure!(
        matches!(
            properties.body,
            Body::Properties {
                cors_count: Some(0),
                ..
            }
        ),
        "read-only probe requires a profile without CORS rules"
    );
    let acl = catalog::with_fresh_resource(client, endpoint, bearer, case.catalog(), |name| {
        let wire = request(
            client,
            Method::GET,
            endpoint.join(&format!("{name}?comp=acl"))?,
        )
        .bearer_auth(bearer);
        let wire = if case == Case::Table {
            wire.header("accept", "application/xml")
        } else {
            wire
        };
        exchange(Step::EmptyAcl, wire, |_, bytes| {
            let wire: WireAcl = project_xml(bytes, "SignedIdentifiers")?;
            Ok(Body::Acl {
                policies: wire.policies.len(),
            })
        })
    })?;
    Ok(ServiceReadCassette {
        schema_version: 1,
        source,
        api_version: ApiVersion::Baseline,
        case,
        responses: [
            properties,
            acl,
            preflight(case, client, endpoint, Step::RuleMiss)?,
            preflight(case, client, endpoint, Step::MissingMethod)?,
            preflight(case, client, endpoint, Step::MissingOrigin)?,
        ],
    })
}

pub(super) fn reviewed(case: Case) -> Result<ServiceReadCassette> {
    let path = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("tests/contracts/cassettes")
        .join(format!("{}.json", case.file_stem()));
    let raw = read_bounded(
        File::open(path).with_context(|| format!("could not open {}", case.file_stem()))?,
    )?;
    let cassette: ServiceReadCassette = serde_json::from_slice(&raw)
        .map_err(|error| anyhow!("invalid service-read cassette at line {}", error.line()))?;
    ensure!(
        cassette.source == Source::Azure && cassette.case == case,
        "expected the reviewed Azure service read"
    );
    cassette.validate()?;
    Ok(cassette)
}

pub(super) fn observe_local(case: Case) -> Result<ServiceReadCassette> {
    with_local_service(case.service(), |client, endpoint, bearer| {
        let setup = request(client, Method::PUT, endpoint.join(PROPERTIES)?)
            .bearer_auth(bearer)
            .header("content-type", "application/xml")
            .body(LOCAL_PROFILE);
        require_status(
            &send(setup, "seed local-only service profile")?,
            202,
            "seed local-only service profile",
        )?;
        observe(client, endpoint, bearer, Source::Synthetic, case)
    })
}

#[test]
fn replay_queue_read_only_settings() -> Result<()> {
    let case = Case::Queue;
    reviewed(case)?.compare(&observe_local(case)?)
}

#[test]
fn replay_table_read_only_settings() -> Result<()> {
    let case = Case::Table;
    reviewed(case)?.compare(&observe_local(case)?)
}
