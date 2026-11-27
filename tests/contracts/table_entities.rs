use super::{
    Service, VERSION,
    cassette::{
        ApiVersion, ErrorCode, Header, Media, OdataError, Source, header, header_text,
        is_utc_timestamp, media,
    },
    catalog, read_bounded, request, require_status, send, table_transactions, with_local_service,
};
use anyhow::{Context as _, Result, anyhow, ensure};
use reqwest::{
    Method, Url,
    blocking::{Client, RequestBuilder},
    header::HeaderMap,
};
use serde::{Deserialize, Serialize};
use serde_json::{Value as Json, json};
use std::{fs::File, path::Path};
use uuid::Uuid;

const FORMAT: &str = "application/json;odata=nometadata";
const NO_CONTENT: &str = "return-no-content";
const NEXT_PARTITION: &str = "x-ms-continuation-nextpartitionkey";
const NEXT_ROW: &str = "x-ms-continuation-nextrowkey";
const STALE: &str = "The update condition specified in the request was not satisfied.";

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub(super) enum Case {
    Lifecycle,
    Upsert,
    Query,
    Transactions,
}

impl Case {
    pub(super) fn file_stem(self) -> &'static str {
        match self {
            Self::Lifecycle => "table-entity-lifecycle",
            Self::Upsert => "table-entity-upsert",
            Self::Query => "table-entity-query",
            Self::Transactions => "table-entity-transactions",
        }
    }

    fn steps(self) -> &'static [(Step, u16)] {
        use Step::*;
        match self {
            Self::Lifecycle => &[
                (Insert, 204),
                (Duplicate, 409),
                (ReadInitial, 200),
                (Merge, 204),
                (ReadMerged, 200),
                (StaleReplace, 412),
                (Replace, 204),
                (ReadReplaced, 200),
                (Delete, 204),
                (ReadMissing, 404),
            ],
            Self::Upsert => &[
                (InsertOrMerge, 204),
                (MergeExisting, 204),
                (ReadMerged, 200),
                (InsertOrReplace, 204),
                (ReplaceExisting, 204),
                (ReadReplaced, 200),
                (StaleDelete, 412),
            ],
            Self::Query => &[
                (Typed, 200),
                (Selected, 200),
                (KeyFilter, 200),
                (Escaped, 200),
                (FirstPage, 200),
                (NextPage, 200),
                (EmptyPage, 200),
                (Unsupported, 501),
            ],
            Self::Transactions => &[
                (Commit, 202),
                (ReadFirst, 200),
                (ReadSecond, 200),
                (Rollback, 202),
                (Unchanged, 200),
                (Mixed, 202),
                (ReadFinal, 200),
            ],
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub(super) enum Step {
    Insert,
    Duplicate,
    ReadInitial,
    Merge,
    ReadMerged,
    StaleReplace,
    Replace,
    ReadReplaced,
    Delete,
    ReadMissing,
    InsertOrMerge,
    MergeExisting,
    InsertOrReplace,
    ReplaceExisting,
    StaleDelete,
    Typed,
    Selected,
    KeyFilter,
    Escaped,
    FirstPage,
    NextPage,
    EmptyPage,
    Unsupported,
    Commit,
    ReadFirst,
    ReadSecond,
    Rollback,
    Unchanged,
    Mixed,
    ReadFinal,
}

#[derive(Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
enum Tag {
    Missing,
    Valid,
    Matches,
    Changed,
    Malformed,
}

#[derive(Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
enum Body {
    Empty {
        empty: bool,
    },
    Rows {
        matches: bool,
        rows: usize,
    },
    Error(OdataError),
    Transaction {
        parts: Vec<table_transactions::Part>,
    },
    Unexpected {},
}

enum Expected<'a> {
    Empty,
    Entity(&'a Json),
    Page(&'a [Json]),
    Error(&'static str),
    Batch(&'static str),
}

#[derive(Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
struct Exchange {
    step: Step,
    status: u16,
    api_version: Header,
    request_id: Header,
    dataserviceversion: Header,
    error_header: ErrorCode,
    media: Media,
    etag: Tag,
    preference: Header,
    location: Header,
    dataserviceid: Header,
    next_partition: Header,
    next_row: Header,
    body: Body,
}

#[derive(Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub(super) struct EntityCassette {
    schema_version: u8,
    source: Source,
    pub(super) case: Case,
    api_version: ApiVersion,
    responses: Vec<Exchange>,
}

impl EntityCassette {
    pub(super) fn validate(&self) -> Result<()> {
        ensure!(
            self.schema_version == 1,
            "unsupported Table cassette version"
        );
        ensure!(
            self.responses
                .iter()
                .map(|r| (r.step, r.status))
                .eq(self.case.steps().iter().copied()),
            "unexpected Table journey step or status: {:#?}",
            self.responses
        );
        for r in &self.responses {
            let valid = match &r.body {
                Body::Empty { empty } => {
                    *empty
                        && match r.step {
                            Step::Delete => r.etag == Tag::Missing,
                            Step::Merge
                            | Step::Replace
                            | Step::MergeExisting
                            | Step::ReplaceExisting => r.etag == Tag::Changed,
                            _ => r.etag == Tag::Valid,
                        }
                }
                Body::Rows { matches, .. } => {
                    *matches
                        && match r.step {
                            Step::FirstPage => {
                                r.next_partition == Header::Matches && r.next_row == Header::Matches
                            }
                            Step::NextPage | Step::EmptyPage => {
                                r.next_partition == Header::Missing && r.next_row == Header::Missing
                            }
                            Step::ReadInitial
                            | Step::ReadMerged
                            | Step::ReadReplaced
                            | Step::Unchanged => r.etag == Tag::Matches,
                            _ => true,
                        }
                }
                Body::Error(error) => match r.step {
                    Step::Duplicate => error.matches(ErrorCode::EntityAlreadyExists),
                    Step::StaleReplace | Step::StaleDelete => {
                        error.matches(ErrorCode::UpdateConditionNotSatisfied)
                    }
                    Step::ReadMissing => error.matches(ErrorCode::ResourceNotFound),
                    Step::Unsupported => error.matches(ErrorCode::NotImplemented),
                    _ => false,
                },
                Body::Transaction { parts } => table_transactions::matches(r.step, parts),
                _ => false,
            };
            ensure!(
                valid && r.api_version == Header::Matches && r.request_id == Header::Matches,
                "Table exchange did not prove the expected state: {r:#?}"
            );
        }
        Ok(())
    }

    pub(super) fn compare(&self, actual: &Self) -> Result<()> {
        self.validate()?;
        ensure!(
            self.case == actual.case && self.responses.len() == actual.responses.len(),
            "wrong Table journey"
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

struct Reply {
    headers: HeaderMap,
}

impl Reply {
    fn etag(&self) -> Result<&str> {
        header_text(&self.headers, "etag")
            .filter(|v| valid_etag(v))
            .context("Table response lacks a usable ETag")
    }
}

pub(super) fn valid_etag(value: &str) -> bool {
    value
        .strip_prefix("W/\"")
        .and_then(|v| v.strip_suffix('"'))
        .is_some_and(|inner| {
            !inner.is_empty() && inner.bytes().all(|c| c.is_ascii_graphic() && c != b'"')
        })
}

fn row(row: &str, v: Json) -> Json {
    let mut entry = json!({"PartitionKey":"p","RowKey":row});
    if let (Some(entry), Json::Object(props)) = (entry.as_object_mut(), v) {
        entry.extend(props);
    }
    entry
}

fn match_row(actual: &Json, expected: &Json) -> bool {
    let mut actual = actual.clone();
    let Some(fields) = actual.as_object_mut() else {
        return false;
    };
    if expected.get("PartitionKey").is_some()
        && !fields
            .remove("Timestamp")
            .and_then(|value| value.as_str().map(is_utc_timestamp))
            .unwrap_or(false)
    {
        return false;
    }
    &actual == expected
}

fn rows(bytes: &[u8], expected: &[Json], page: bool) -> Result<Body> {
    let mut json: Json =
        serde_json::from_slice(bytes).map_err(|_| anyhow!("invalid Table entity JSON"))?;
    let mut rows = vec![];
    let shape = if page {
        match json.as_object_mut() {
            Some(body) if body.len() == 1 => match body.remove("value") {
                Some(Json::Array(values)) => {
                    rows = values;
                    true
                }
                _ => false,
            },
            _ => false,
        }
    } else {
        rows.push(json);
        true
    };
    Ok(Body::Rows {
        matches: shape
            && rows.len() == expected.len()
            && rows.iter().zip(expected).all(|(a, b)| match_row(a, b)),
        rows: rows.len(),
    })
}

struct Probe<'a> {
    client: &'a Client,
    endpoint: &'a Url,
    bearer: &'a str,
    table: &'a str,
    responses: Vec<Exchange>,
}

impl Probe<'_> {
    fn request(&self, method: Method, path: &str) -> Result<RequestBuilder> {
        Ok(request(self.client, method, self.endpoint.join(path)?)
            .bearer_auth(self.bearer)
            .header("accept", FORMAT)
            .header("dataserviceversion", "3.0"))
    }

    fn key(&self, r: &str) -> String {
        format!("{}(PartitionKey='p',RowKey='{r}')", self.table)
    }

    fn write(
        &self,
        method: Method,
        r: &str,
        props: Json,
        tag: Option<&str>,
    ) -> Result<RequestBuilder> {
        let path = if method == Method::POST {
            self.table.to_owned()
        } else {
            self.key(r)
        };
        let mut wire = self
            .request(method.clone(), &path)?
            .header("prefer", NO_CONTENT);
        if let Some(tag) = tag {
            wire = wire.header("if-match", tag);
        }
        if method != Method::DELETE {
            wire = wire
                .header("content-type", "application/json")
                .body(row(r, props).to_string());
        }
        Ok(wire)
    }

    fn record(
        &mut self,
        step: Step,
        wire: RequestBuilder,
        expected: Expected<'_>,
        previous: Option<&str>,
    ) -> Result<Reply> {
        let response = send(wire, "record Table entity operation")?;
        let status = response.status().as_u16();
        let h = response.headers().clone();
        let bytes = read_bounded(response)?;
        let id = header_text(&h, "x-ms-request-id");
        let body = match expected {
            Expected::Empty => Body::Empty {
                empty: bytes.is_empty(),
            },
            Expected::Entity(entity) if status == 200 => {
                rows(&bytes, std::slice::from_ref(entity), false)?
            }
            Expected::Page(entities) if status == 200 => rows(&bytes, entities, true)?,
            Expected::Error(message) if (400..600).contains(&status) => {
                Body::Error(OdataError::project(&bytes, id, message)?)
            }
            Expected::Batch(message) if status == 202 => Body::Transaction {
                parts: table_transactions::project(&h, &bytes, message)?,
            },
            _ => Body::Unexpected {},
        };
        let etag = match header_text(&h, "etag") {
            Some(tag) if !valid_etag(tag) => Tag::Malformed,
            Some(tag) => match previous {
                None => Tag::Valid,
                Some(prev) if prev == tag => Tag::Matches,
                _ => Tag::Changed,
            },
            None => Tag::Missing,
        };
        let location = self.endpoint.join(&self.key("a"))?;
        self.responses.push(Exchange {
            step,
            status,
            etag,
            media: media(&h),
            body,
            api_version: header(&h, "x-ms-version", |v| v == VERSION),
            request_id: header(&h, "x-ms-request-id", |v| Uuid::parse_str(v).is_ok()),
            dataserviceversion: header(&h, "dataserviceversion", |v| v == "3.0;"),
            error_header: ErrorCode::from_value(header_text(&h, "x-ms-error-code")),
            preference: header(&h, "preference-applied", |v| v == NO_CONTENT),
            location: header(&h, "location", |v| v == location.as_str()),
            dataserviceid: header(&h, "dataserviceid", |v| v == location.as_str()),
            next_partition: header(&h, NEXT_PARTITION, |v| !v.is_empty()),
            next_row: header(&h, NEXT_ROW, |v| !v.is_empty()),
        });
        Ok(Reply { headers: h })
    }

    fn get(&mut self, step: Step, key: &str, expected: Json, tag: Option<&str>) -> Result<Reply> {
        self.record(
            step,
            self.request(Method::GET, &self.key(key))?,
            Expected::Entity(&expected),
            tag,
        )
    }

    fn query(&mut self, step: Step, params: &[(&str, &str)], expected: &[Json]) -> Result<Reply> {
        self.record(
            step,
            self.request(Method::GET, &format!("{}()", self.table))?
                .query(params),
            Expected::Page(expected),
            None,
        )
    }

    fn seed(&self, method: Method, r: &str, props: Json, tag: Option<&str>) -> Result<Reply> {
        let response = send(
            self.write(method, r, props, tag)?,
            "seed synthetic Table entity",
        )?;
        require_status(&response, 204, "seed synthetic Table entity")?;
        Ok(Reply {
            headers: response.headers().clone(),
        })
    }

    fn lifecycle(&mut self, merge: Method) -> Result<()> {
        use Step::*;
        let first = json!({"Name":"initial","Count":3});
        let a = self.record(
            Insert,
            self.write(Method::POST, "a", first.clone(), None)?,
            Expected::Empty,
            None,
        )?;
        self.record(
            Duplicate,
            self.write(Method::POST, "a", json!({"Count":0}), None)?,
            Expected::Error("The specified entity already exists."),
            None,
        )?;
        self.get(ReadInitial, "a", row("a", first), Some(a.etag()?))?;
        let b = self.record(
            Merge,
            self.write(merge, "a", json!({"City":"merged"}), Some(a.etag()?))?,
            Expected::Empty,
            Some(a.etag()?),
        )?;
        self.get(
            ReadMerged,
            "a",
            row("a", json!({"Name":"initial","Count":3,"City":"merged"})),
            Some(b.etag()?),
        )?;
        self.record(
            StaleReplace,
            self.write(Method::PUT, "a", json!({"Name":"stale"}), Some(a.etag()?))?,
            Expected::Error(STALE),
            None,
        )?;
        let replace = json!({"Name":"replaced"});
        let c = self.record(
            Replace,
            self.write(Method::PUT, "a", replace.clone(), Some(b.etag()?))?,
            Expected::Empty,
            Some(b.etag()?),
        )?;
        self.get(ReadReplaced, "a", row("a", replace), Some(c.etag()?))?;
        self.record(
            Delete,
            self.write(Method::DELETE, "a", json!({}), Some(c.etag()?))?,
            Expected::Empty,
            None,
        )?;
        self.record(
            ReadMissing,
            self.request(Method::GET, &self.key("a"))?,
            Expected::Error("The specified resource does not exist."),
            None,
        )?;
        Ok(())
    }

    fn upsert(&mut self, merge: Method) -> Result<()> {
        use Step::*;
        let a = self.record(
            InsertOrMerge,
            self.write(merge.clone(), "a", json!({"Count":3}), None)?,
            Expected::Empty,
            None,
        )?;
        let b = self.record(
            MergeExisting,
            self.write(merge, "a", json!({"City":"merged"}), None)?,
            Expected::Empty,
            Some(a.etag()?),
        )?;
        self.get(
            ReadMerged,
            "a",
            row("a", json!({"Count":3,"City":"merged"})),
            Some(b.etag()?),
        )?;
        let c = self.record(
            InsertOrReplace,
            self.write(Method::PUT, "b", json!({"Count":7}), None)?,
            Expected::Empty,
            None,
        )?;
        let replace = json!({"Name":"replaced"});
        let d = self.record(
            ReplaceExisting,
            self.write(Method::PUT, "b", replace.clone(), None)?,
            Expected::Empty,
            Some(c.etag()?),
        )?;
        self.get(ReadReplaced, "b", row("b", replace), Some(d.etag()?))?;
        self.record(
            StaleDelete,
            self.write(Method::DELETE, "b", json!({}), Some(c.etag()?))?,
            Expected::Error(STALE),
            None,
        )?;
        Ok(())
    }

    fn queries(&mut self) -> Result<()> {
        use Step::*;
        let typed = json!({"Count":3,"Flag":true,"Big":"9007199254740993","Name":"o'clock"});
        let mut seed = typed.clone();
        seed["Big@odata.type"] = json!("Edm.Int64");
        seed["Nullable"] = Json::Null;
        self.seed(Method::POST, "a", seed, None)?;
        self.seed(Method::POST, "b", json!({"Count":7}), None)?;
        let typed = row("a", typed);
        let other = row("b", json!({"Count":7}));
        self.query(
            Typed,
            &[("$filter", "RowKey eq 'a'")],
            std::slice::from_ref(&typed),
        )?;
        self.query(
            Selected,
            &[
                ("$filter", "RowKey eq 'a'"),
                ("$select", "RowKey,Count,Omitted"),
            ],
            &[json!({"RowKey":"a","Count":3,"Omitted":null})],
        )?;
        self.query(
            KeyFilter,
            &[("$filter", "PartitionKey eq 'p' and RowKey eq 'b'")],
            std::slice::from_ref(&other),
        )?;
        self.query(
            Escaped,
            &[("$filter", "Name eq 'o''clock'")],
            std::slice::from_ref(&typed),
        )?;
        let p = self.query(
            FirstPage,
            &[("$filter", "PartitionKey eq 'p'"), ("$top", "1")],
            &[typed],
        )?;
        let partition = header_text(&p.headers, NEXT_PARTITION)
            .context("missing Table partition continuation")?;
        let row = header_text(&p.headers, NEXT_ROW).context("missing Table row continuation")?;
        self.query(
            NextPage,
            &[
                ("$filter", "PartitionKey eq 'p'"),
                ("$top", "1"),
                ("NextPartitionKey", partition),
                ("NextRowKey", row),
            ],
            &[other],
        )?;
        self.query(
            EmptyPage,
            &[("$filter", "PartitionKey eq 'p' and RowKey eq 'missing'")],
            &[],
        )?;
        self.record(
            Unsupported,
            self.request(Method::GET, &format!("{}()", self.table))?
                .query(&[("$filter", "startswith(RowKey, 'a')")]),
            Expected::Error(
                "The requested operation is not implemented on the specified resource.",
            ),
            None,
        )?;
        Ok(())
    }

    fn transactions(&mut self, merge: Method) -> Result<()> {
        use Step::*;
        use table_transactions::{Op, wire};
        let count = |n| json!({"Count":n});
        let shared = |method, r, value, etag| Op {
            method,
            partition: "p",
            row: r,
            count: value,
            etag,
        };
        let batch = self.request(Method::POST, "$batch")?;
        let commit = wire(
            batch,
            self.endpoint,
            self.table,
            &[shared("POST", "a", 3, None), shared("POST", "b", 7, None)],
        )?;
        self.record(Commit, commit, Expected::Batch(""), None)?;
        let a = self.get(ReadFirst, "a", row("a", count(3)), None)?;
        let b = self.get(ReadSecond, "b", row("b", count(7)), None)?;
        let changed = self.seed(merge, "b", count(7), Some(b.etag()?))?;
        ensure!(
            changed.etag()? != b.etag()?,
            "setup could not establish a stale batch ETag"
        );
        let rollback = wire(
            self.request(Method::POST, "$batch")?,
            self.endpoint,
            self.table,
            &[
                shared("MERGE", "a", 9, Some(a.etag()?)),
                shared("MERGE", "b", 11, Some(b.etag()?)),
            ],
        )?;
        self.record(
            Rollback,
            rollback,
            Expected::Batch("1:The update condition specified in the request was not satisfied."),
            None,
        )?;
        self.get(Unchanged, "a", row("a", count(3)), Some(a.etag()?))?;
        let mixed = wire(
            self.request(Method::POST, "$batch")?,
            self.endpoint,
            self.table,
            &[
                shared("MERGE", "a", 9, Some(a.etag()?)),
                Op {
                    method: "POST",
                    partition: "other",
                    row: "b",
                    count: 11,
                    etag: None,
                },
            ],
        )?;
        self.record(
            Mixed,
            mixed,
            Expected::Batch("1:All commands in a batch must operate on same entity group."),
            None,
        )?;
        self.query(
            ReadFinal,
            &[("$top", "5")],
            &[row("a", count(3)), row("b", count(7))],
        )?;
        Ok(())
    }
}

pub(super) fn observe(
    client: &Client,
    endpoint: &Url,
    bearer: &str,
    source: Source,
    case: Case,
) -> Result<EntityCassette> {
    catalog::with_fresh_resource(
        client,
        endpoint,
        bearer,
        catalog::Case::TableLifecycle,
        |name| {
            let mut probe = Probe {
                client,
                endpoint,
                bearer,
                table: name,
                responses: vec![],
            };
            let merge = Method::from_bytes(b"MERGE")?;
            match case {
                Case::Lifecycle => probe.lifecycle(merge)?,
                Case::Upsert => probe.upsert(merge)?,
                Case::Query => probe.queries()?,
                Case::Transactions => probe.transactions(merge)?,
            }
            Ok(EntityCassette {
                schema_version: 1,
                source,
                case,
                api_version: ApiVersion::Baseline,
                responses: probe.responses,
            })
        },
    )
}

pub(super) fn local(case: Case) -> Result<EntityCassette> {
    with_local_service(Service::Table, |client, endpoint, bearer| {
        observe(client, endpoint, bearer, Source::Synthetic, case)
    })
}

pub(super) fn reviewed(case: Case) -> Result<EntityCassette> {
    let path = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("tests/contracts/cassettes")
        .join(format!("{}.json", case.file_stem()));
    let raw = read_bounded(
        File::open(path).with_context(|| format!("could not open {}", case.file_stem()))?,
    )?;
    let c: EntityCassette = serde_json::from_slice(&raw)
        .map_err(|error| anyhow!("invalid Table cassette at line {}", error.line()))?;
    ensure!(
        c.source == Source::Azure && c.case == case,
        "expected reviewed Table entity cassette"
    );
    c.validate()?;
    Ok(c)
}

#[test]
fn replay_table_entity_lifecycle() -> Result<()> {
    reviewed(Case::Lifecycle)?.compare(&local(Case::Lifecycle)?)
}
#[test]
fn replay_table_entity_upsert() -> Result<()> {
    reviewed(Case::Upsert)?.compare(&local(Case::Upsert)?)
}
#[test]
fn replay_table_entity_query() -> Result<()> {
    reviewed(Case::Query)?.compare(&local(Case::Query)?)
}
#[test]
fn replay_table_entity_transactions() -> Result<()> {
    reviewed(Case::Transactions)?.compare(&local(Case::Transactions)?)
}
