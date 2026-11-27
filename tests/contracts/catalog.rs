use super::{
    Service, VERSION,
    cassette::{
        ApiVersion, ErrorCode, Header, Media, OdataError, Source, echoed, header, header_text,
        media, project_xml,
    },
    finish_cleanup, read_bounded, request,
    request_errors::{XmlError, project_error},
    require_status, send, with_local_service,
};
use anyhow::{Context as _, Result, anyhow, ensure};
use reqwest::{
    Method, Url,
    blocking::{Client, RequestBuilder, Response},
    header::HeaderMap,
};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use std::{collections::BTreeMap, fs::File, path::Path};
use uuid::Uuid;

const PURPOSE: &str = "x-ms-meta-purpose";
const REMOVED: &str = "x-ms-meta-remove";
const PREFERENCE: &str = "return-no-content";
const TABLE_MARKER: &str = "x-ms-continuation-nexttablename";

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "kebab-case")]
pub(super) enum Case {
    QueueLifecycle,
    TableLifecycle,
}

impl Case {
    pub(super) fn service(self) -> Service {
        match self {
            Self::QueueLifecycle => Service::Queue,
            Self::TableLifecycle => Service::Table,
        }
    }

    pub(super) fn file_stem(self) -> &'static str {
        match self {
            Self::QueueLifecycle => "queue-lifecycle",
            Self::TableLifecycle => "table-lifecycle",
        }
    }

    fn fresh_prefix(self) -> String {
        let id = Uuid::new_v4().simple();
        match self {
            Self::QueueLifecycle => format!("azuifer-contract-{id}-"),
            Self::TableLifecycle => format!("AzuiferContract{id}"),
        }
    }

    fn steps(self) -> &'static [(Step, u16)] {
        use Step::*;
        match self {
            Self::QueueLifecycle => &[
                (Create, 201),
                (RepeatCreate, 204),
                (ReplaceMetadata, 204),
                (ReadMetadata, 200),
                (FirstPage, 200),
                (NextPage, 200),
                (Delete, 204),
                (ReadMissing, 404),
            ],
            Self::TableLifecycle => &[
                (Create, 204),
                (RepeatCreate, 409),
                (FirstPage, 200),
                (NextPage, 200),
                (Delete, 204),
                (ReadMissing, 404),
                (RepeatDelete, 404),
            ],
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
enum Step {
    Create,
    RepeatCreate,
    ReplaceMetadata,
    ReadMetadata,
    FirstPage,
    NextPage,
    Delete,
    ReadMissing,
    RepeatDelete,
}

#[derive(Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
enum QueueMetadata {
    Absent,
    Empty,
    Updated,
    Different,
}

#[derive(Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
enum Body {
    Empty {
        empty: bool,
    },
    QueueProperties {
        empty: bool,
        purpose: Header,
        removed: Header,
        count_zero: Header,
    },
    QueuePage {
        endpoint: Header,
        limit: Header,
        prefix: Header,
        marker_echo: Header,
        has_next: Option<bool>,
        expected_queue: bool,
        metadata: QueueMetadata,
    },
    TableCreated {
        empty: bool,
        preference: Header,
        location: Header,
        resource_id: Header,
    },
    TablePage {
        continuation: Header,
        expected_table: bool,
        no_odata_metadata: bool,
    },
    XmlError(XmlError),
    TableError(OdataError),
}

#[derive(Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
struct Exchange {
    step: Step,
    status: u16,
    api_version: Header,
    request_id: Header,
    odata_version: Header,
    media: Media,
    error_header: ErrorCode,
    body: Body,
}

#[derive(Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub(super) struct CatalogCassette {
    schema_version: u8,
    source: Source,
    pub(super) case: Case,
    api_version: ApiVersion,
    exchanges: Vec<Exchange>,
}

impl CatalogCassette {
    pub(super) fn validate(&self) -> Result<()> {
        ensure!(
            self.schema_version == 1,
            "unsupported catalog cassette version"
        );
        ensure!(
            self.exchanges
                .iter()
                .map(|exchange| (exchange.step, exchange.status))
                .eq(self.case.steps().iter().copied()),
            "unexpected catalog lifecycle statuses or step order: {:#?}",
            self.exchanges
        );
        for exchange in &self.exchanges {
            ensure!(
                exchange.api_version == Header::Matches
                    && exchange.request_id == Header::Matches
                    && match (&exchange.body, exchange.step) {
                        (
                            Body::QueueProperties {
                                empty,
                                purpose,
                                removed,
                                count_zero,
                            },
                            Step::ReadMetadata,
                        ) =>
                            *empty
                                && *purpose == Header::Matches
                                && *removed == Header::Missing
                                && *count_zero == Header::Matches,
                        (
                            Body::QueuePage {
                                expected_queue,
                                metadata,
                                has_next,
                                ..
                            },
                            step,
                        ) =>
                            *expected_queue
                                && match step {
                                    Step::FirstPage =>
                                        *metadata == QueueMetadata::Updated
                                            && *has_next == Some(true),
                                    Step::NextPage => *has_next == Some(false),
                                    _ => false,
                                },
                        (
                            Body::TablePage {
                                expected_table,
                                no_odata_metadata,
                                continuation,
                            },
                            step,
                        ) =>
                            *expected_table
                                && *no_odata_metadata
                                && match step {
                                    Step::FirstPage => *continuation == Header::Matches,
                                    Step::NextPage => *continuation == Header::Missing,
                                    _ => false,
                                },
                        (Body::XmlError(error), Step::ReadMissing) =>
                            error.code == ErrorCode::QueueNotFound,
                        (Body::TableError(error), Step::RepeatCreate) =>
                            error.code == ErrorCode::TableAlreadyExists,
                        (Body::TableError(error), Step::ReadMissing | Step::RepeatDelete) =>
                            error.code == ErrorCode::ResourceNotFound,
                        (
                            Body::TableCreated {
                                empty, preference, ..
                            },
                            Step::Create,
                        ) => *empty && *preference == Header::Matches,
                        (
                            Body::Empty { empty },
                            Step::Create
                            | Step::RepeatCreate
                            | Step::ReplaceMetadata
                            | Step::Delete,
                        ) => *empty,
                        _ => false,
                    },
                "catalog exchange did not exercise the expected behavior: {exchange:#?}"
            );
        }
        Ok(())
    }

    pub(super) fn compare(&self, observed: &Self) -> Result<()> {
        self.validate()?;
        ensure!(
            self.case == observed.case && self.exchanges.len() == observed.exchanges.len(),
            "unexpected catalog lifecycle or exchange count"
        );
        let differences: Vec<_> = self
            .exchanges
            .iter()
            .zip(&observed.exchanges)
            .filter(|(expected, actual)| expected != actual)
            .map(|(expected, actual)| {
                format!(
                    "{:?}: expected {expected:#?}, observed {actual:#?}",
                    expected.step
                )
            })
            .collect();
        ensure!(differences.is_empty(), "{}", differences.join("\n"));
        Ok(())
    }
}

struct Reply {
    status: u16,
    headers: HeaderMap,
    bytes: Vec<u8>,
}

impl Reply {
    fn receive(response: Response) -> Result<Self> {
        Ok(Self {
            status: response.status().as_u16(),
            headers: response.headers().clone(),
            bytes: read_bounded(response)?,
        })
    }

    fn exchange(&self, step: Step, body: Body) -> Exchange {
        Exchange {
            step,
            status: self.status,
            api_version: echoed(header_text(&self.headers, "x-ms-version"), Some(VERSION)),
            request_id: header(&self.headers, "x-ms-request-id", |id| {
                Uuid::parse_str(id).is_ok()
            }),
            odata_version: echoed(
                header_text(&self.headers, "dataserviceversion"),
                Some("3.0;"),
            ),
            media: media(&self.headers),
            error_header: ErrorCode::from_value(header_text(&self.headers, "x-ms-error-code")),
            body,
        }
    }

    fn empty(&self, step: Step) -> Exchange {
        self.exchange(
            step,
            Body::Empty {
                empty: self.bytes.is_empty(),
            },
        )
    }

    fn table_error(&self, step: Step, expected: &str) -> Result<Exchange> {
        let error = OdataError::project(
            &self.bytes,
            header_text(&self.headers, "x-ms-request-id"),
            expected,
        )?;
        Ok(self.exchange(step, Body::TableError(error)))
    }

    fn json(&self) -> Result<Value> {
        serde_json::from_slice(&self.bytes).map_err(|_| anyhow!("invalid Table JSON response"))
    }
}

#[derive(Deserialize)]
#[serde(rename_all = "PascalCase")]
struct QueuePage {
    #[serde(rename = "@ServiceEndpoint")]
    endpoint: Option<String>,
    prefix: Option<String>,
    max_results: Option<String>,
    marker: Option<String>,
    next_marker: Option<String>,
    queues: Queues,
}

#[derive(Deserialize)]
struct Queues {
    #[serde(rename = "Queue", default)]
    entries: Vec<QueueItem>,
}

#[derive(Deserialize)]
#[serde(rename_all = "PascalCase")]
struct QueueItem {
    name: String,
    metadata: Option<BTreeMap<String, String>>,
}

struct Probe<'a> {
    client: &'a Client,
    endpoint: &'a Url,
    bearer: &'a str,
    case: Case,
}

impl Probe<'_> {
    fn request(&self, method: Method, url: Url) -> RequestBuilder {
        let request = request(self.client, method, url).bearer_auth(self.bearer);
        match self.case {
            Case::QueueLifecycle => request,
            Case::TableLifecycle => request
                .header("accept", "application/json;odata=nometadata")
                .header("dataserviceversion", "3.0"),
        }
    }

    fn resource(&self, name: &str) -> Result<Url> {
        Ok(match self.case {
            Case::QueueLifecycle => self.endpoint.join(name)?,
            Case::TableLifecycle => self.endpoint.join(&format!("Tables('{name}')"))?,
        })
    }

    fn create(&self, name: &str, with_metadata: bool) -> Result<Response> {
        let wire = match self.case {
            Case::QueueLifecycle => {
                let wire = self
                    .request(Method::PUT, self.resource(name)?)
                    .header("content-length", "0");
                if with_metadata {
                    wire.header(PURPOSE, "initial").header(REMOVED, "present")
                } else {
                    wire
                }
            }
            Case::TableLifecycle => self
                .request(Method::POST, self.endpoint.join("Tables")?)
                .header("prefer", PREFERENCE)
                .header("content-type", "application/json")
                .body(json!({"TableName": name}).to_string()),
        };
        send(wire, "create catalog resource")
    }

    fn queue_metadata(&self, name: &str, exchanges: &mut Vec<Exchange>) -> Result<()> {
        let url = self.resource(name)?.join("?comp=metadata")?;
        let response = send(
            self.request(Method::PUT, url.clone())
                .header("content-length", "0")
                .header(PURPOSE, "updated"),
            "replace queue metadata",
        )?;
        exchanges.push(Reply::receive(response)?.empty(Step::ReplaceMetadata));
        let response = Reply::receive(send(self.request(Method::GET, url), "get queue metadata")?)?;
        exchanges.push(response.exchange(
            Step::ReadMetadata,
            Body::QueueProperties {
                empty: response.bytes.is_empty(),
                purpose: echoed(header_text(&response.headers, PURPOSE), Some("updated")),
                removed: header(&response.headers, REMOVED, |_| false),
                count_zero: echoed(
                    header_text(&response.headers, "x-ms-approximate-messages-count"),
                    Some("0"),
                ),
            },
        ));
        Ok(())
    }

    fn page(
        &self,
        prefix: &str,
        names: [&str; 2],
        marker: Option<&str>,
    ) -> Result<(Exchange, Option<String>)> {
        let step = if marker.is_some() {
            Step::NextPage
        } else {
            Step::FirstPage
        };
        let expected = names[usize::from(marker.is_some())];
        let mut url = match self.case {
            Case::QueueLifecycle => self.endpoint.clone(),
            Case::TableLifecycle => self.endpoint.join("Tables")?,
        };
        match self.case {
            Case::QueueLifecycle => {
                let mut query = url.query_pairs_mut();
                query.extend_pairs([
                    ("comp", "list"),
                    ("prefix", prefix),
                    ("maxresults", "1"),
                    ("include", "metadata"),
                ]);
                if let Some(marker) = marker {
                    query.append_pair("marker", marker);
                }
            }
            Case::TableLifecycle => {
                let mut query = url.query_pairs_mut();
                query.append_pair("$top", "1").append_pair(
                    "$filter",
                    &format!(
                        "TableName ge '{}' and TableName le '{}'",
                        names[0], names[1]
                    ),
                );
                if let Some(marker) = marker {
                    query.append_pair("NextTableName", marker);
                }
            }
        }
        let response = send(self.request(Method::GET, url), "list isolated catalog page")?;
        require_status(&response, 200, "list isolated catalog page")?;
        let reply = Reply::receive(response)?;
        let (body, next) = match self.case {
            Case::QueueLifecycle => {
                let page: QueuePage = project_xml(&reply.bytes, "EnumerationResults")?;
                let queue = match page.queues.entries.as_slice() {
                    [queue] => Some(queue),
                    _ => None,
                };
                let metadata = match queue.and_then(|queue| queue.metadata.as_ref()) {
                    None => QueueMetadata::Absent,
                    Some(map) if map.is_empty() => QueueMetadata::Empty,
                    Some(map)
                        if map.len() == 1
                            && map.get("purpose").is_some_and(|value| value == "updated") =>
                    {
                        QueueMetadata::Updated
                    }
                    Some(_) => QueueMetadata::Different,
                };
                let body = Body::QueuePage {
                    endpoint: echoed(page.endpoint.as_deref(), Some(self.endpoint.as_str())),
                    limit: echoed(page.max_results.as_deref(), Some("1")),
                    prefix: echoed(page.prefix.as_deref(), Some(prefix)),
                    marker_echo: echoed(page.marker.as_deref(), marker),
                    has_next: page.next_marker.as_ref().map(|next| !next.is_empty()),
                    expected_queue: queue.is_some_and(|queue| queue.name == expected),
                    metadata,
                };
                (body, page.next_marker)
            }
            Case::TableLifecycle => {
                let json = reply.json()?;
                let table = match json["value"].as_array().map(Vec::as_slice) {
                    Some([table]) => Some(table),
                    _ => None,
                };
                let body = Body::TablePage {
                    continuation: header(&reply.headers, TABLE_MARKER, |value| !value.is_empty()),
                    expected_table: table.is_some_and(|table| table["TableName"] == expected),
                    no_odata_metadata: json.as_object().is_some_and(|map| map.len() == 1)
                        && table
                            .and_then(Value::as_object)
                            .is_some_and(|map| map.len() == 1),
                };
                (
                    body,
                    header_text(&reply.headers, TABLE_MARKER).map(str::to_owned),
                )
            }
        };
        Ok((
            reply.exchange(step, body),
            next.filter(|token| !token.is_empty()),
        ))
    }

    fn delete(&self, name: &str) -> Result<Response> {
        send(
            self.request(Method::DELETE, self.resource(name)?),
            "delete catalog resource",
        )
    }

    fn missing(&self, name: &str) -> Result<Exchange> {
        let step = Step::ReadMissing;
        let mut url = self.resource(name)?;
        if self.case == Case::QueueLifecycle {
            url.set_query(Some("comp=metadata"));
        }
        let reply = Reply::receive(send(
            self.request(Method::GET, url),
            "read deleted catalog resource",
        )?)?;
        match self.case {
            Case::QueueLifecycle => {
                let xml =
                    std::str::from_utf8(&reply.bytes).context("invalid Queue error encoding")?;
                let error = project_error(
                    xml,
                    header_text(&reply.headers, "x-ms-request-id"),
                    "The specified queue does not exist.",
                )
                .with_context(|| {
                    format!(
                        "expected Queue error XML after delete, got HTTP {}",
                        reply.status
                    )
                })?;
                Ok(reply.exchange(step, Body::XmlError(error)))
            }
            Case::TableLifecycle => {
                reply.table_error(step, "The specified resource does not exist.")
            }
        }
    }
}

pub(super) fn with_fresh_resource<T>(
    client: &Client,
    endpoint: &Url,
    bearer: &str,
    case: Case,
    observe: impl FnOnce(&str) -> Result<T>,
) -> Result<T> {
    let probe = Probe {
        client,
        endpoint,
        bearer,
        case,
    };
    let name = format!("{}a", case.fresh_prefix());
    require_status(
        &probe.create(&name, false)?,
        case.steps()[0].1,
        "create validation probe resource",
    )?;
    let outcome = observe(&name);
    let cleanup = probe
        .delete(&name)
        .and_then(|response| require_status(&response, 204, "clean up validation probe resource"));
    finish_cleanup(outcome, cleanup)
}

pub(super) fn observe(
    client: &Client,
    endpoint: &Url,
    bearer: &str,
    source: Source,
    case: Case,
) -> Result<CatalogCassette> {
    let probe = Probe {
        client,
        endpoint,
        bearer,
        case,
    };
    let prefix = case.fresh_prefix();
    let suffixes = match case {
        Case::QueueLifecycle => ["a", "b"],
        Case::TableLifecycle => ["A", "B"],
    };
    let (first, second) = (
        format!("{prefix}{}", suffixes[0]),
        format!("{prefix}{}", suffixes[1]),
    );
    let mut created = [false; 2];
    let outcome = (|| {
        let status = case.steps()[0].1;
        let response = probe.create(&first, true)?;
        require_status(&response, status, "create first catalog resource")?;
        created[0] = true;
        let reply = Reply::receive(response)?;
        let mut exchanges = Vec::with_capacity(case.steps().len());
        match case {
            Case::QueueLifecycle => exchanges.push(reply.empty(Step::Create)),
            Case::TableLifecycle => {
                let target = probe.resource(&first)?;
                exchanges.push(reply.exchange(
                    Step::Create,
                    Body::TableCreated {
                        empty: reply.bytes.is_empty(),
                        preference: echoed(
                            header_text(&reply.headers, "preference-applied"),
                            Some(PREFERENCE),
                        ),
                        location: echoed(
                            header_text(&reply.headers, "location"),
                            Some(target.as_str()),
                        ),
                        resource_id: echoed(
                            header_text(&reply.headers, "dataserviceid"),
                            Some(target.as_str()),
                        ),
                    },
                ));
            }
        }

        let repeat = Reply::receive(probe.create(&first, true)?)?;
        match case {
            Case::QueueLifecycle => {
                exchanges.push(repeat.empty(Step::RepeatCreate));
                probe.queue_metadata(&first, &mut exchanges)?;
            }
            Case::TableLifecycle => exchanges.push(
                repeat.table_error(Step::RepeatCreate, "The table specified already exists.")?,
            ),
        }
        require_status(
            &probe.create(&second, false)?,
            status,
            "seed second catalog resource",
        )?;
        created[1] = true;

        let names = [first.as_str(), second.as_str()];
        let (page, marker) = probe.page(&prefix, names, None)?;
        exchanges.push(page);
        let marker = marker.context("first catalog page did not return a continuation")?;
        exchanges.push(probe.page(&prefix, names, Some(&marker))?.0);
        let response = probe.delete(&first)?;
        if response.status().as_u16() == 204 {
            created[0] = false;
        }
        exchanges.push(Reply::receive(response)?.empty(Step::Delete));
        exchanges.push(probe.missing(&first)?);
        if case == Case::TableLifecycle {
            let reply = Reply::receive(probe.delete(&first)?)?;
            exchanges.push(
                reply.table_error(Step::RepeatDelete, "The specified resource does not exist.")?,
            );
        }
        Ok(CatalogCassette {
            schema_version: 1,
            source,
            case,
            api_version: ApiVersion::Baseline,
            exchanges,
        })
    })();
    let clean = |name, owned| {
        if owned {
            require_status(&probe.delete(name)?, 204, "clean up catalog resource")?;
        }
        Ok(())
    };
    finish_cleanup(
        outcome,
        finish_cleanup(clean(&first, created[0]), clean(&second, created[1])),
    )
}

pub(super) fn observe_local(case: Case) -> Result<CatalogCassette> {
    with_local_service(case.service(), |client, endpoint, bearer| {
        observe(client, endpoint, bearer, Source::Synthetic, case)
    })
}

pub(super) fn reviewed(case: Case) -> Result<CatalogCassette> {
    let path = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("tests")
        .join("contracts")
        .join("cassettes")
        .join(format!("{}.json", case.file_stem()));
    let bytes = read_bounded(
        File::open(path)
            .with_context(|| format!("could not open reviewed {} cassette", case.file_stem()))?,
    )?;
    let cassette: CatalogCassette = serde_json::from_slice(&bytes)
        .map_err(|error| anyhow!("invalid catalog cassette at line {}", error.line()))?;
    ensure!(
        cassette.source == Source::Azure && cassette.case == case,
        "expected the reviewed Azure catalog cassette"
    );
    cassette.validate()?;
    Ok(cassette)
}

#[test]
fn replay_catalog_queue_lifecycle() -> Result<()> {
    let case = Case::QueueLifecycle;
    reviewed(case)?.compare(&observe_local(case)?)
}

#[test]
fn replay_catalog_table_lifecycle() -> Result<()> {
    let case = Case::TableLifecycle;
    reviewed(case)?.compare(&observe_local(case)?)
}
