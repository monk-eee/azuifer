use super::{
    VERSION,
    cassette::{ApiVersion, ErrorCode, Header, Media, Source, header, header_text, media},
    read_bounded, request,
    request_errors::{XmlError, project_error},
    require_status, send, with_fresh_container, with_local,
};
use anyhow::{Context as _, Result, ensure};
use reqwest::{Method, Url, blocking::Client};
use serde::{Deserialize, Serialize};
use std::{fs::File, path::Path};
use uuid::Uuid;

#[path = "../support/query_avro.rs"]
mod avro;

pub(super) const CASE: &str = "blob-query-avro";
const CSV: &[u8] = b"ann,31\nbob,25\ncy,40\n";
const JSON: &[u8] = b"{\"name\":\"ann\",\"age\":31}\n{\"name\":\"cy\",\"age\":40}\n";
const JSON_FORMAT: &str = "<Format><Type>json</Type><JsonTextConfiguration><RecordSeparator>&#10;</RecordSeparator></JsonTextConfiguration></Format>";
const BAD_SQL: &str = "SELEC _1 FROM BlobStorage";
const STEPS: [Step; 7] = [
    Step::CsvFilter,
    Step::JsonProjection,
    Step::AllRows,
    Step::EmptyResult,
    Step::ConversionErrors,
    Step::InvalidSql,
    Step::ReadOriginal,
];

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
enum Step {
    CsvFilter,
    JsonProjection,
    AllRows,
    EmptyResult,
    ConversionErrors,
    InvalidSql,
    ReadOriginal,
}

impl Step {
    fn sql(self) -> &'static str {
        match self {
            Self::CsvFilter => "SELECT _1 FROM BlobStorage WHERE CAST(_2 AS INT) &gt; 30",
            Self::JsonProjection => "SELECT name FROM BlobStorage",
            Self::AllRows => "SELECT _1 FROM BlobStorage",
            Self::EmptyResult => "SELECT _1 FROM BlobStorage WHERE CAST(_2 AS INT) &gt; 99",
            Self::ConversionErrors => "SELECT CAST(_1 AS INT) FROM BlobStorage",
            Self::InvalidSql => BAD_SQL,
            Self::ReadOriginal => "",
        }
    }

    fn expected(self) -> &'static [u8] {
        match self {
            Self::CsvFilter => b"ann\ncy\n",
            Self::JsonProjection => b"{\"name\":\"ann\"}\n{\"name\":\"cy\"}\n",
            Self::AllRows => b"ann\nbob\ncy\n",
            Self::ReadOriginal => CSV,
            Self::EmptyResult | Self::ConversionErrors | Self::InvalidSql => b"",
        }
    }
}

#[derive(Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
enum Name {
    InvalidTypeConversion,
    Other,
}

#[derive(Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
enum Record {
    Data {
        bytes: usize,
    },
    Progress {
        scanned: u64,
        total: u64,
    },
    End {
        total: u64,
    },
    Error {
        fatal: bool,
        name: Name,
        description_matches: bool,
        position: u64,
    },
}

#[derive(Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
struct Avro {
    schema: Vec<avro::Kind>,
    qualified_names: bool,
    explicit_null_codec: bool,
    block_sizes: Vec<usize>,
    records: Vec<Record>,
    bytes_match: bool,
}

impl Avro {
    fn project(bytes: &[u8], reference: &[u8]) -> Result<Self> {
        let stream = avro::decode(bytes)?;
        let mut output = Vec::new();
        let records = stream
            .records
            .into_iter()
            .map(|record| match record {
                avro::Record::Data(bytes) => {
                    output.extend_from_slice(bytes);
                    Record::Data { bytes: bytes.len() }
                }
                avro::Record::Progress { scanned, total } => Record::Progress { scanned, total },
                avro::Record::End(total) => Record::End { total },
                avro::Record::Error {
                    fatal,
                    name,
                    description,
                    position,
                } => Record::Error {
                    fatal,
                    name: if name == "InvalidTypeConversion" {
                        Name::InvalidTypeConversion
                    } else {
                        Name::Other
                    },
                    description_matches: description == "Invalid type conversion.",
                    position,
                },
            })
            .collect();
        Ok(Self {
            schema: stream.schema,
            qualified_names: stream.qualified_names,
            explicit_null_codec: stream.explicit_null_codec,
            block_sizes: stream.block_sizes,
            records,
            bytes_match: output == reference,
        })
    }
}

#[derive(Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
enum Body {
    Avro(Avro),
    Readback { bytes_match: bool },
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
    media: Media,
    length_present: bool,
    etag: Header,
    modified: Header,
    body: Body,
}

#[derive(Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub(super) struct QueryCassette {
    schema_version: u8,
    source: Source,
    api_version: ApiVersion,
    responses: [Exchange; 7],
}

impl QueryCassette {
    pub(super) fn validate(&self) -> Result<()> {
        ensure!(
            self.schema_version == 1,
            "unsupported Query cassette version"
        );
        ensure!(
            self.responses.each_ref().map(|response| response.step) == STEPS,
            "unexpected Query steps"
        );
        for r in &self.responses {
            let valid = match (&r.body, r.step) {
                (Body::Avro(avro), step)
                    if !matches!(step, Step::ReadOriginal | Step::InvalidSql) =>
                {
                    let total = if step == Step::JsonProjection {
                        JSON.len()
                    } else {
                        CSV.len()
                    } as u64;
                    let errors: Vec<_> = avro
                        .records
                        .iter()
                        .filter_map(|record| match record {
                            Record::Error {
                                fatal: false,
                                name: Name::InvalidTypeConversion,
                                position,
                                ..
                            } => Some(*position),
                            Record::Error { .. } => Some(u64::MAX),
                            _ => None,
                        })
                        .collect();
                    r.status == 200
                        && r.media == Media::AvroBinary
                        && r.etag == Header::Matches
                        && r.modified == Header::Matches
                        && avro.bytes_match
                        && matches!(avro.records.last(), Some(Record::End { total: observed }) if *observed == total)
                        && if step == Step::ConversionErrors {
                            errors == [0, 7, 14]
                        } else {
                            errors.is_empty()
                        }
                }
                (Body::Xml(error), Step::InvalidSql) => {
                    r.status == 400
                        && r.error_header == ErrorCode::QueryExpression
                        && error.code == ErrorCode::QueryExpression
                }
                (Body::Readback { bytes_match: true }, Step::ReadOriginal) => {
                    r.status == 200 && r.etag == Header::Matches && r.modified == Header::Matches
                }
                _ => false,
            };
            ensure!(
                r.request_id && r.api_version == Header::Matches && valid,
                "Query probe did not reach the expected synthetic outcome: {r:#?}"
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

struct Original {
    etag: String,
    modified: String,
}

struct Probe<'a> {
    client: &'a Client,
    bearer: &'a str,
}

impl Probe<'_> {
    fn seed(&self, url: &Url, bytes: &'static [u8]) -> Result<Original> {
        let response = send(
            request(self.client, Method::PUT, url.clone())
                .bearer_auth(self.bearer)
                .header("x-ms-blob-type", "BlockBlob")
                .header("content-type", "text/plain")
                .body(bytes),
            "seed synthetic Query blob",
        )?;
        require_status(&response, 201, "seed synthetic Query blob")?;
        let read = |name| {
            header_text(response.headers(), name)
                .map(str::to_owned)
                .with_context(|| format!("Query seed lacks {name}"))
        };
        Ok(Original {
            etag: read("etag")?,
            modified: read("last-modified")?,
        })
    }

    fn record(&self, step: Step, url: &Url, original: &Original) -> Result<Exchange> {
        let wire = if step == Step::ReadOriginal {
            request(self.client, Method::GET, url.clone())
        } else {
            let format = if step == Step::JsonProjection {
                format!(
                    "<InputSerialization>{JSON_FORMAT}</InputSerialization><OutputSerialization>{JSON_FORMAT}</OutputSerialization>"
                )
            } else {
                String::new()
            };
            let sql = step.sql();
            request(self.client, Method::POST, url.clone())
                .query(&[("comp", "query")])
                .header("content-type", "application/xml; charset=UTF-8")
                .body(format!("<QueryRequest><QueryType>SQL</QueryType><Expression>{sql}</Expression>{format}</QueryRequest>"))
        };
        let response = send(wire.bearer_auth(self.bearer), "observe Query Blob Contents")
            .with_context(|| format!("{step:?}"))?;
        let status = response.status().as_u16();
        let headers = response.headers().clone();
        let bytes = read_bounded(response)?;
        let id = header_text(&headers, "x-ms-request-id");
        let body = if (200..300).contains(&status) {
            if step == Step::ReadOriginal {
                Body::Readback {
                    bytes_match: bytes == step.expected(),
                }
            } else {
                Body::Avro(
                    Avro::project(&bytes, step.expected()).with_context(|| format!("{step:?}"))?,
                )
            }
        } else {
            let expected = format!("Syntax error in query: {BAD_SQL}");
            std::str::from_utf8(&bytes)
                .ok()
                .and_then(|text| project_error(text, id, &expected))
                .map_or(Body::Other {}, Body::Xml)
        };
        Ok(Exchange {
            step,
            status,
            body,
            request_id: id.is_some_and(|id| Uuid::parse_str(id).is_ok()),
            api_version: header(&headers, "x-ms-version", |value| value == VERSION),
            error_header: ErrorCode::from_value(header_text(&headers, "x-ms-error-code")),
            media: media(&headers),
            length_present: headers.contains_key("content-length"),
            etag: header(&headers, "etag", |value| value == original.etag),
            modified: header(&headers, "last-modified", |value| {
                value == original.modified
            }),
        })
    }
}

pub(super) fn observe(
    client: &Client,
    endpoint: &Url,
    bearer: &str,
    source: Source,
) -> Result<QueryCassette> {
    with_fresh_container(client, endpoint, bearer, |_, csv| {
        let json = csv.join("rows.json")?;
        let probe = Probe { client, bearer };
        let csv_original = probe.seed(&csv, CSV)?;
        let json_original = probe.seed(&json, JSON)?;
        let responses = STEPS
            .into_iter()
            .map(|step| {
                if step == Step::JsonProjection {
                    probe.record(step, &json, &json_original)
                } else {
                    probe.record(step, &csv, &csv_original)
                }
            })
            .collect::<Result<Vec<_>>>()?
            .try_into()
            .map_err(|_| anyhow::anyhow!("wrong Query response count"))?;
        Ok(QueryCassette {
            schema_version: 1,
            source,
            api_version: ApiVersion::Baseline,
            responses,
        })
    })
}

pub(super) fn reviewed() -> Result<QueryCassette> {
    let path = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("tests/contracts/cassettes")
        .join(format!("{CASE}.json"));
    let bytes = read_bounded(File::open(path).context("open the reviewed Query cassette")?)?;
    let value: QueryCassette = serde_json::from_slice(&bytes)
        .map_err(|error| anyhow::anyhow!("invalid Query cassette at line {}", error.line()))?;
    ensure!(
        value.source == Source::Azure,
        "expected the reviewed Azure Query recording"
    );
    value.validate()?;
    Ok(value)
}

pub(super) fn observe_local() -> Result<QueryCassette> {
    with_local(|client, endpoint, bearer| observe(client, endpoint, bearer, Source::Synthetic))
}

#[test]
fn replay_blob_query_avro() -> Result<()> {
    reviewed()?.compare(&observe_local()?)
}
