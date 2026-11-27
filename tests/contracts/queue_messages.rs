use super::{
    Service, VERSION,
    cassette::{
        ApiVersion, ErrorCode, Header, Media, Source, header, header_text, media, project_xml,
    },
    catalog, read_bounded, request,
    request_errors::{XmlError, project_error},
    require_status, send, with_local_service,
};
use anyhow::{Context as _, Result, anyhow, ensure};
use reqwest::{
    Method, Url,
    blocking::{Client, RequestBuilder},
    header::HeaderMap,
};
use serde::{Deserialize, Serialize};
use std::{fs::File, path::Path, thread, time::Duration};
use uuid::Uuid;

const INITIAL: &str = "initial";
const UPDATED: &str = "updated";
const STANDARD_TTL: u64 = 7 * 86_400;

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub(super) enum Case {
    Receipts,
    Visibility,
    Expiration,
}

impl Case {
    pub(super) fn file_stem(self) -> &'static str {
        match self {
            Self::Receipts => "queue-message-receipts",
            Self::Visibility => "queue-message-visibility",
            Self::Expiration => "queue-message-expiration",
        }
    }

    fn steps(self) -> &'static [(Step, u16)] {
        use Step::*;
        match self {
            Self::Receipts => &[
                (Put, 201),
                (Peek, 200),
                (Receive, 200),
                (Hidden, 200),
                (Update, 204),
                (PeekUpdated, 200),
                (Stale, 404),
                (Delete, 204),
                (Empty, 200),
            ],
            Self::Visibility => &[
                (Put, 201),
                (Hidden, 200),
                (Receive, 200),
                (Redeliver, 200),
                (PeekRedelivered, 200),
                (Stale, 404),
            ],
            Self::Expiration => &[
                (Put, 201),
                (Peek, 200),
                (Expired, 200),
                (Clear, 204),
                (Empty, 200),
            ],
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
enum Step {
    Put,
    Peek,
    Receive,
    Hidden,
    Update,
    PeekUpdated,
    Stale,
    Delete,
    Empty,
    Redeliver,
    PeekRedelivered,
    Expired,
    Clear,
}

#[derive(Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
enum Body {
    Messages {
        count: usize,
        identity: Header,
        receipt: Header,
        ttl_seconds: Option<u64>,
        visibility: Header,
        dequeue_count: Option<u32>,
        text: Header,
    },
    Update {
        empty: bool,
        receipt_rotated: Header,
        visibility: Header,
    },
    Error(XmlError),
    Empty {},
    Unexpected {},
}

#[derive(Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
struct Exchange {
    step: Step,
    status: u16,
    api_version: Header,
    request_id: Header,
    error_header: ErrorCode,
    media: Media,
    body: Body,
}

#[derive(Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub(super) struct MessageCassette {
    schema_version: u8,
    source: Source,
    pub(super) case: Case,
    api_version: ApiVersion,
    responses: Vec<Exchange>,
}

impl MessageCassette {
    pub(super) fn validate(&self) -> Result<()> {
        ensure!(
            self.schema_version == 1,
            "unsupported Queue message cassette version"
        );
        ensure!(
            self.responses
                .iter()
                .map(|r| (r.step, r.status))
                .eq(self.case.steps().iter().copied()),
            "unexpected Queue message step or status: {:#?}",
            self.responses
        );
        for r in &self.responses {
            let valid = match (&r.body, r.step) {
                (Body::Messages { count: 0, .. }, Step::Hidden | Step::Expired | Step::Empty) => {
                    true
                }
                (
                    Body::Messages {
                        count: 1,
                        identity: Header::Matches,
                        receipt,
                        ttl_seconds,
                        visibility,
                        dequeue_count,
                        text,
                    },
                    step,
                ) => {
                    use Step::*;
                    let expected_dequeues = match step {
                        Put => None,
                        Peek => Some(0),
                        Receive | PeekUpdated => Some(1),
                        Redeliver | PeekRedelivered => Some(2),
                        _ => return Err(anyhow!("unexpected nonempty response: {step:?}")),
                    };
                    let issued = matches!(step, Put | Receive | Redeliver);
                    let ttl = match self.case {
                        Case::Visibility => 60,
                        Case::Expiration => 8,
                        Case::Receipts => STANDARD_TTL,
                    };
                    *ttl_seconds == Some(ttl)
                        && *dequeue_count == expected_dequeues
                        && *receipt
                            == if issued {
                                Header::Matches
                            } else {
                                Header::Missing
                            }
                        && *visibility
                            == if issued {
                                Header::Matches
                            } else {
                                Header::Missing
                            }
                        && *text
                            == if step == Put {
                                Header::Missing
                            } else {
                                Header::Matches
                            }
                }
                (
                    Body::Update {
                        empty: true,
                        receipt_rotated: Header::Matches,
                        visibility: Header::Matches,
                    },
                    Step::Update,
                ) => true,
                (Body::Empty {}, Step::Clear | Step::Delete) => true,
                (Body::Error(error), Step::Stale) => {
                    error.matches(ErrorCode::MessageNotFound, 0)
                        && r.error_header == ErrorCode::MessageNotFound
                        && r.media == Media::Xml
                }
                _ => false,
            };
            ensure!(
                valid && r.api_version == Header::Matches && r.request_id == Header::Matches,
                "Queue exchange did not prove the expected state: {r:#?}"
            );
        }
        Ok(())
    }

    pub(super) fn compare(&self, actual: &Self) -> Result<()> {
        self.validate()?;
        ensure!(
            self.case == actual.case && self.responses.len() == actual.responses.len(),
            "wrong Queue journey"
        );
        let diff: Vec<_> = self
            .responses
            .iter()
            .zip(&actual.responses)
            .filter(|(a, b)| a != b)
            .collect();
        ensure!(
            diff.is_empty(),
            "{}: differing exchanges (reviewed, observed):\n{diff:#?}",
            self.case.file_stem()
        );
        Ok(())
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct WireList {
    #[serde(rename = "QueueMessage", default)]
    items: Vec<WireMessage>,
}

#[derive(Deserialize)]
#[serde(rename_all = "PascalCase", deny_unknown_fields)]
struct WireMessage {
    message_id: String,
    insertion_time: String,
    expiration_time: String,
    time_next_visible: Option<String>,
    pop_receipt: Option<String>,
    dequeue_count: Option<u32>,
    message_text: Option<String>,
}

struct Probe<'a> {
    client: &'a Client,
    bearer: &'a str,
    messages: Url,
    id: Option<String>,
    receipt: Option<String>,
    responses: Vec<Exchange>,
}

fn relation(actual: Option<&str>, expected: impl FnOnce(&str) -> bool) -> Header {
    match actual {
        Some(value) if expected(value) => Header::Matches,
        Some(_) => Header::Different,
        None => Header::Missing,
    }
}

fn visible_at(value: &str, headers: &HeaderMap, delay: u64) -> bool {
    let Some(date) =
        header_text(headers, "date").and_then(|date| httpdate::parse_http_date(date).ok())
    else {
        return false;
    };
    httpdate::parse_http_date(value).is_ok_and(|at| {
        let expected = date + Duration::from_secs(delay);
        at.duration_since(expected)
            .or_else(|_| expected.duration_since(at))
            .is_ok_and(|difference| difference <= Duration::from_secs(2))
    })
}

impl Probe<'_> {
    fn wire(&self, method: Method) -> RequestBuilder {
        request(self.client, method, self.messages.clone()).bearer_auth(self.bearer)
    }

    fn record(
        &mut self,
        step: Step,
        wire: RequestBuilder,
        list: bool,
        delay: u64,
        text: Option<&str>,
    ) -> Result<()> {
        let response = send(wire, "record Queue message operation")?;
        let status = response.status().as_u16();
        let headers = response.headers().clone();
        let bytes = read_bounded(response)?;
        let body = if list && matches!(status, 200 | 201) {
            let payload: WireList = project_xml(&bytes, "QueueMessagesList")?;
            let mut identity = Header::Missing;
            let mut receipt = Header::Missing;
            let mut ttl_seconds = None;
            let mut visibility = Header::Missing;
            let mut dequeue_count = None;
            let mut message_text = Header::Missing;
            if let [msg] = payload.items.as_slice() {
                identity = relation(Some(&msg.message_id), |id| {
                    Uuid::parse_str(id).is_ok()
                        && self.id.as_deref().is_none_or(|first| first == id)
                });
                if self.id.is_none() && identity == Header::Matches {
                    self.id = Some(msg.message_id.clone());
                }
                receipt = relation(msg.pop_receipt.as_deref(), |receipt| {
                    !receipt.is_empty() && self.receipt.as_deref() != Some(receipt)
                });
                if let Some(value) = &msg.pop_receipt {
                    self.receipt = Some(value.clone());
                }
                ttl_seconds = httpdate::parse_http_date(&msg.expiration_time)
                    .ok()
                    .zip(httpdate::parse_http_date(&msg.insertion_time).ok())
                    .and_then(|(until, from)| until.duration_since(from).ok())
                    .map(|duration| duration.as_secs());
                visibility = relation(msg.time_next_visible.as_deref(), |value| {
                    visible_at(value, &headers, delay)
                });
                dequeue_count = msg.dequeue_count;
                message_text = relation(msg.message_text.as_deref(), |value| Some(value) == text);
            }
            Body::Messages {
                count: payload.items.len(),
                identity,
                receipt,
                ttl_seconds,
                visibility,
                dequeue_count,
                text: message_text,
            }
        } else if step == Step::Update && status == 204 {
            let fresh = header_text(&headers, "x-ms-popreceipt");
            let receipt_rotated = relation(fresh, |receipt| {
                !receipt.is_empty() && self.receipt.as_deref() != Some(receipt)
            });
            self.receipt = fresh.map(str::to_owned);
            Body::Update {
                empty: bytes.is_empty(),
                receipt_rotated,
                visibility: header(&headers, "x-ms-time-next-visible", |value| {
                    visible_at(value, &headers, delay)
                }),
            }
        } else if bytes.is_empty() {
            Body::Empty {}
        } else {
            let expected = "The specified message does not exist.";
            let xml = std::str::from_utf8(&bytes).context("invalid Queue error encoding")?;
            project_error(xml, header_text(&headers, "x-ms-request-id"), expected)
                .map_or(Body::Unexpected {}, Body::Error)
        };
        let r = Exchange {
            step,
            status,
            media: media(&headers),
            api_version: header(&headers, "x-ms-version", |v| v == VERSION),
            request_id: header(&headers, "x-ms-request-id", |id| {
                Uuid::parse_str(id).is_ok()
            }),
            error_header: ErrorCode::from_value(header_text(&headers, "x-ms-error-code")),
            body,
        };
        self.responses.push(r);
        Ok(())
    }

    fn put(&mut self, delay: u64, ttl: u64) -> Result<()> {
        self.record(
            Step::Put,
            self.wire(Method::POST)
                .query(&[("visibilitytimeout", delay), ("messagettl", ttl)])
                .header("content-type", "application/xml")
                .body("<QueueMessage><MessageText>initial</MessageText></QueueMessage>"),
            true,
            delay,
            None,
        )
    }

    fn get(&mut self, step: Step, peek: bool, delay: u64, text: &str) -> Result<()> {
        let wire = self.wire(Method::GET).query(&[("numofmessages", "1")]);
        let wire = if peek {
            wire.query(&[("peekonly", "true")])
        } else {
            wire.query(&[("visibilitytimeout", delay)])
        };
        self.record(step, wire, true, delay, Some(text))
    }

    fn current_receipt(&self) -> Result<&str> {
        self.receipt
            .as_deref()
            .filter(|value| !value.is_empty())
            .context("Queue response lacks pop receipt")
    }

    fn target(&self, method: Method, receipt: &str) -> Result<RequestBuilder> {
        let id = self
            .id
            .as_deref()
            .context("Queue response lacks message ID")?;
        Ok(request(
            self.client,
            method,
            self.messages.join(&format!("messages/{id}"))?,
        )
        .bearer_auth(self.bearer)
        .query(&[("popreceipt", receipt)]))
    }

    fn run(&mut self, case: Case) -> Result<()> {
        use Step::*;
        match case {
            Case::Receipts => {
                self.put(0, STANDARD_TTL)?;
                self.get(Peek, true, 0, INITIAL)?;
                self.get(Receive, false, 30, INITIAL)?;
                self.get(Hidden, true, 0, INITIAL)?;
                let old = self.current_receipt()?.to_owned();
                self.record(
                    Update,
                    self.target(Method::PUT, &old)?
                        .query(&[("visibilitytimeout", "0")])
                        .header("content-type", "application/xml")
                        .body("<QueueMessage><MessageText>updated</MessageText></QueueMessage>"),
                    false,
                    0,
                    None,
                )?;
                self.get(PeekUpdated, true, 0, UPDATED)?;
                self.record(Stale, self.target(Method::DELETE, &old)?, false, 0, None)?;
                self.record(
                    Delete,
                    self.target(Method::DELETE, self.current_receipt()?)?,
                    false,
                    0,
                    None,
                )?;
                self.get(Empty, false, 30, UPDATED)?;
            }
            Case::Visibility => {
                self.put(8, 60)?;
                self.get(Hidden, true, 0, INITIAL)?;
                thread::sleep(Duration::from_secs(9));
                self.get(Receive, false, 2, INITIAL)?;
                let old = self.current_receipt()?.to_owned();
                thread::sleep(Duration::from_secs(3));
                self.get(Redeliver, false, 2, INITIAL)?;
                thread::sleep(Duration::from_secs(3));
                self.get(PeekRedelivered, true, 0, INITIAL)?;
                self.record(Stale, self.target(Method::DELETE, &old)?, false, 0, None)?;
            }
            Case::Expiration => {
                self.put(0, 8)?;
                self.get(Peek, true, 0, INITIAL)?;
                thread::sleep(Duration::from_secs(9));
                self.get(Expired, true, 0, INITIAL)?;
                let seed = self
                    .wire(Method::POST)
                    .header("content-type", "application/xml")
                    .body("<QueueMessage><MessageText>clear</MessageText></QueueMessage>");
                require_status(
                    &send(seed, "seed a message to clear")?,
                    201,
                    "seed a message to clear",
                )?;
                self.record(Clear, self.wire(Method::DELETE), false, 0, None)?;
                self.get(Empty, false, 30, INITIAL)?;
            }
        }
        Ok(())
    }
}

pub(super) fn observe(
    client: &Client,
    endpoint: &Url,
    bearer: &str,
    source: Source,
    case: Case,
) -> Result<MessageCassette> {
    catalog::with_fresh_resource(
        client,
        endpoint,
        bearer,
        catalog::Case::QueueLifecycle,
        |name| {
            let mut probe = Probe {
                client,
                bearer,
                messages: endpoint.join(&format!("{name}/messages"))?,
                id: None,
                receipt: None,
                responses: vec![],
            };
            probe.run(case)?;
            Ok(MessageCassette {
                schema_version: 1,
                source,
                case,
                api_version: ApiVersion::Baseline,
                responses: probe.responses,
            })
        },
    )
}

pub(super) fn local(case: Case) -> Result<MessageCassette> {
    with_local_service(Service::Queue, |client, endpoint, bearer| {
        observe(client, endpoint, bearer, Source::Synthetic, case)
    })
}

pub(super) fn reviewed(case: Case) -> Result<MessageCassette> {
    let path = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("tests/contracts/cassettes")
        .join(format!("{}.json", case.file_stem()));
    let raw = read_bounded(
        File::open(path).with_context(|| format!("could not open {}", case.file_stem()))?,
    )?;
    let c: MessageCassette = serde_json::from_slice(&raw)
        .map_err(|error| anyhow!("invalid Queue cassette at line {}", error.line()))?;
    ensure!(
        c.source == Source::Azure && c.case == case,
        "expected reviewed Queue message cassette"
    );
    c.validate()?;
    Ok(c)
}

#[test]
fn replay_queue_message_receipts() -> Result<()> {
    reviewed(Case::Receipts)?.compare(&local(Case::Receipts)?)
}
#[test]
fn replay_queue_message_visibility() -> Result<()> {
    reviewed(Case::Visibility)?.compare(&local(Case::Visibility)?)
}
#[test]
fn replay_queue_message_expiration() -> Result<()> {
    reviewed(Case::Expiration)?.compare(&local(Case::Expiration)?)
}
