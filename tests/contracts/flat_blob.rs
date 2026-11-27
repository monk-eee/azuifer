use super::{
    ACCOUNT, BLOB, BLOB_BYTES, VERSION,
    cassette::{
        ApiVersion, ErrorCode, Header, Media, Source, error_message, flat_xml, header, header_text,
        is_utc_timestamp, media,
    },
    delegation_key_document, iso,
    mutations::lists::{PageRanges, page_ranges},
    read_bounded, request, require_status, send, sign_sas, sign_sas_with_options,
    with_fresh_container, with_local,
};
use anyhow::{Context as _, Result, ensure};
use reqwest::{
    Method, Url,
    blocking::{Client, RequestBuilder},
    header::HeaderMap,
};
use serde::{Deserialize, Serialize};
use std::{fs::File, path::Path, thread, time::Duration};
use uuid::Uuid;

mod copy;

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub(super) enum Case {
    FromUrl,
    IncrementalCopy,
    SasWindows,
    RenameBoundary,
}

impl Case {
    pub(super) fn file_stem(self) -> &'static str {
        match self {
            Self::FromUrl => "blob-write-from-url",
            Self::IncrementalCopy => "blob-incremental-copy",
            Self::SasWindows => "blob-user-delegation-sas-windows",
            Self::RenameBoundary => "blob-container-rename-boundary",
        }
    }

    fn steps(self) -> &'static [Step] {
        use Step::*;
        match self {
            Self::FromUrl => &[
                PutBlob,
                ReadWhole,
                StageBlock,
                CommitBlock,
                ReadBlock,
                AppendBlock,
                ReadAppend,
                PutPage,
                ReadPage,
                RejectSourceRange,
            ],
            Self::IncrementalCopy => &[
                StartCopy,
                CopyComplete,
                RejectBaseRead,
                UpdateSource,
                SnapshotSource,
                CopyAgain,
                ChangedRanges,
                ReadSnapshot,
            ],
            Self::SasWindows => &[InWindow, Expired, FutureStart, SignedStart, ExpiredKey],
            Self::RenameBoundary => &[RejectRename],
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
enum Step {
    PutBlob,
    ReadWhole,
    StageBlock,
    CommitBlock,
    ReadBlock,
    AppendBlock,
    ReadAppend,
    PutPage,
    ReadPage,
    RejectSourceRange,
    StartCopy,
    CopyComplete,
    RejectBaseRead,
    UpdateSource,
    SnapshotSource,
    CopyAgain,
    ChangedRanges,
    ReadSnapshot,
    InWindow,
    Expired,
    FutureStart,
    SignedStart,
    ExpiredKey,
    RejectRename,
}

impl Step {
    fn success_status(self) -> u16 {
        use Step::*;
        match self {
            PutBlob | StageBlock | CommitBlock | AppendBlock | PutPage | UpdateSource
            | SnapshotSource => 201,
            StartCopy | CopyAgain => 202,
            _ => 200,
        }
    }

    fn error(self) -> Option<(u16, ErrorCode, ErrorDetail)> {
        use Step::*;
        Some(match self {
            RejectSourceRange => (416, ErrorCode::CannotVerifyCopySource, ErrorDetail::None),
            RejectBaseRead => (
                409,
                ErrorCode::OperationNotAllowedOnIncrementalCopyBlob,
                ErrorDetail::None,
            ),
            Expired | FutureStart => (403, ErrorCode::AuthenticationFailed, ErrorDetail::SasTime),
            ExpiredKey => (
                403,
                ErrorCode::AuthenticationFailed,
                ErrorDetail::KeyExpired,
            ),
            RejectRename => (
                400,
                ErrorCode::InvalidQueryParameterValue,
                ErrorDetail::Rename,
            ),
            _ => return None,
        })
    }
}

#[derive(Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
enum ErrorDetail {
    None,
    SasTime,
    KeyExpired,
    Rename,
    Other,
}

#[derive(Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
enum Body {
    Empty {
        matches: bool,
    },
    Bytes {
        matches: bool,
        length: Header,
        blob_type: Header,
    },
    Ranges(PageRanges),
    Error {
        code: ErrorCode,
        correlation: Header,
        detail: ErrorDetail,
    },
    Other,
}

#[derive(Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
enum Detail {
    Copy {
        id: Header,
        status: Header,
        incremental: Header,
        snapshot: Header,
    },
    Snapshot {
        timestamp: Header,
    },
    Append {
        offset: Header,
        committed_blocks: Header,
    },
    Page {
        sequence: Header,
    },
}

#[derive(Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
struct Exchange {
    step: Step,
    status: u16,
    api_version: Header,
    request_id: Header,
    media: Media,
    etag: Header,
    error_header: ErrorCode,
    body: Body,
    details: Option<Detail>,
}

impl Exchange {
    fn matches_contract(&self) -> bool {
        if self.request_id != Header::Matches {
            return false;
        }
        if let Some((status, code, detail)) = self.step.error() {
            return self.status == status
                && self.error_header == code
                && matches!(
                    &self.body, Body::Error { code: body_code, correlation: Header::Matches, detail: actual }
                    if body_code == &code && actual == &detail
                );
        }
        self.status == self.step.success_status()
            && self.api_version == Header::Matches
            && self.error_header == ErrorCode::Missing
            && match &self.details {
                Some(Detail::Copy {
                    id,
                    status,
                    incremental,
                    snapshot,
                }) => {
                    let completed = self.step == Step::CopyComplete;
                    let expected = if completed {
                        Header::Matches
                    } else {
                        Header::Missing
                    };
                    *id == Header::Matches
                        && *status == Header::Matches
                        && *incremental == expected
                        && *snapshot == expected
                }
                Some(Detail::Snapshot { timestamp }) => *timestamp == Header::Matches,
                Some(Detail::Append {
                    offset,
                    committed_blocks,
                }) => *offset == Header::Matches && *committed_blocks == Header::Matches,
                Some(Detail::Page { sequence }) => *sequence == Header::Matches,
                None => true,
            }
            && match &self.body {
                Body::Empty { matches } => *matches,
                Body::Bytes {
                    matches,
                    length,
                    blob_type,
                } => *matches && *length == Header::Matches && *blob_type == Header::Matches,
                Body::Ranges(ranges) => ranges.has_layout(2048, &[[1024, 1535]], &[]),
                _ => false,
            }
    }
}

#[derive(Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub(super) struct Cassette {
    schema_version: u8,
    source: Source,
    pub(super) case: Case,
    api_version: ApiVersion,
    exchanges: Vec<Exchange>,
}

impl Cassette {
    pub(super) fn validate(&self) -> Result<()> {
        ensure!(
            self.schema_version == 1,
            "unsupported flat Blob cassette schema"
        );
        ensure!(
            self.exchanges.iter().map(|exchange| exchange.step).eq(self
                .case
                .steps()
                .iter()
                .copied()),
            "unexpected {:?} exchange sequence",
            self.case
        );
        for exchange in &self.exchanges {
            ensure!(
                exchange.matches_contract(),
                "invalid {:?} observation: {exchange:#?}",
                self.case
            );
        }
        Ok(())
    }

    pub(super) fn compare(&self, actual: &Self) -> Result<()> {
        self.validate()?;
        ensure!(
            self.case == actual.case
                && self.schema_version == actual.schema_version
                && self.api_version == actual.api_version
                && self.exchanges.len() == actual.exchanges.len(),
            "flat Blob cassette identity differs"
        );
        for (expected, observed) in self.exchanges.iter().zip(&actual.exchanges) {
            ensure!(
                expected == observed,
                "{:?}/{:?}: expected {expected:#?}, observed {observed:#?}",
                self.case,
                expected.step
            );
        }
        Ok(())
    }
}

struct Reply {
    status: u16,
    headers: HeaderMap,
    bytes: Vec<u8>,
}

fn auth_times(detail: &str, prefix: &str, labels: [&str; 3]) -> bool {
    let Some(fields) = detail.strip_prefix(prefix) else {
        return false;
    };
    let mut fields = fields.split(" - ");
    labels.into_iter().all(|label| {
        fields
            .next()
            .and_then(|field| field.strip_prefix(label))
            .and_then(|field| field.strip_suffix(']'))
            .is_some_and(|date| httpdate::parse_http_date(date).is_ok())
    }) && fields.next().is_none()
}

impl Reply {
    fn receive(request: RequestBuilder) -> Result<Self> {
        let response = send(request, "send flat Blob contract request")?;
        Ok(Self {
            status: response.status().as_u16(),
            headers: response.headers().clone(),
            bytes: read_bounded(response)?,
        })
    }

    fn field(&self, name: &'static str) -> Option<&str> {
        header_text(&self.headers, name)
    }

    fn value(&self, name: &'static str, expected: &str) -> Header {
        header(&self.headers, name, |actual| actual == expected)
    }

    fn contents(&self, expected: &[u8], blob_type: &str) -> Body {
        Body::Bytes {
            matches: self.bytes == expected,
            length: header(&self.headers, "content-length", |value| {
                value.parse::<usize>() == Ok(expected.len())
            }),
            blob_type: self.value("x-ms-blob-type", blob_type),
        }
    }

    fn empty(&self) -> Body {
        Body::Empty {
            matches: self.bytes.is_empty(),
        }
    }

    fn error(&self) -> Body {
        let Some(fields) = std::str::from_utf8(&self.bytes)
            .ok()
            .and_then(|text| flat_xml(text, "Error"))
        else {
            return Body::Other;
        };
        let get = |name| fields.get(name).map(String::as_str);
        let (_, correlation) = error_message(
            get("Message").unwrap_or_default(),
            self.field("x-ms-request-id"),
        );
        let detail = match get("AuthenticationErrorDetail") {
            Some(value)
                if auth_times(
                    value,
                    "Signature not valid in the specified time frame: ",
                    ["Start [", "Expiry [", "Current ["],
                ) =>
            {
                ErrorDetail::SasTime
            }
            Some(value)
                if auth_times(
                    value,
                    "Signature not valid in the specified key time frame: ",
                    ["Key start [", "Key expiry [", "Current ["],
                ) =>
            {
                ErrorDetail::KeyExpired
            }
            _ if get("QueryParameterName") == Some("comp")
                && get("QueryParameterValue") == Some("rename") =>
            {
                ErrorDetail::Rename
            }
            None if fields.len() == 2 => ErrorDetail::None,
            _ => ErrorDetail::Other,
        };
        Body::Error {
            code: ErrorCode::from_value(get("Code")),
            correlation,
            detail,
        }
    }
}

struct Probe<'a> {
    client: &'a Client,
    bearer: &'a str,
    endpoint: &'a Url,
    account: &'a str,
    container: &'a str,
    exchanges: Vec<Exchange>,
}

impl Probe<'_> {
    fn url(&self, target: &str) -> Result<Url> {
        Ok(self
            .endpoint
            .join(&format!("{}/{target}", self.container))?)
    }

    fn wire(&self, method: Method, target: &str) -> Result<RequestBuilder> {
        Ok(request(self.client, method, self.url(target)?).bearer_auth(self.bearer))
    }

    fn put(&self, target: &str) -> Result<RequestBuilder> {
        Ok(self
            .wire(Method::PUT, target)?
            .header("content-length", "0"))
    }

    fn setup(request: RequestBuilder, status: u16, phase: &'static str) -> Result<()> {
        require_status(&send(request, phase)?, status, phase)
    }

    fn record(&mut self, step: Step, reply: &Reply, body: Body, details: Option<Detail>) {
        self.exchanges.push(Exchange {
            step,
            status: reply.status,
            api_version: reply.value("x-ms-version", VERSION),
            request_id: header(&reply.headers, "x-ms-request-id", |id| {
                Uuid::parse_str(id).is_ok()
            }),
            media: media(&reply.headers),
            etag: header(&reply.headers, "etag", |tag| {
                tag.len() > 2 && tag.starts_with('"') && tag.ends_with('"')
            }),
            error_header: ErrorCode::from_value(reply.field("x-ms-error-code")),
            body: if reply.status >= 400 {
                reply.error()
            } else {
                body
            },
            details,
        });
    }

    fn write_empty(&mut self, step: Step, builder: RequestBuilder) -> Result<()> {
        let reply = Reply::receive(builder)?;
        self.record(step, &reply, reply.empty(), None);
        Ok(())
    }

    fn read_blob(
        &mut self,
        step: Step,
        builder: RequestBuilder,
        expected: &[u8],
        kind: &str,
    ) -> Result<()> {
        let reply = Reply::receive(builder)?;
        self.record(step, &reply, reply.contents(expected, kind), None);
        Ok(())
    }

    fn seed_block(&self, name: &str, bytes: &[u8]) -> Result<()> {
        Self::setup(
            self.wire(Method::PUT, name)?
                .header("x-ms-blob-type", "BlockBlob")
                .header("content-type", "text/plain")
                .body(bytes.to_vec()),
            201,
            "seed flat Blob source",
        )
    }

    fn sas_read(&self, key: &str, start: &str, expiry: &str) -> Result<RequestBuilder> {
        let mut url = self.url(BLOB)?;
        url.set_query(Some(&sign_sas_with_options(
            key,
            (self.account, self.container, Some(BLOB)),
            "r",
            (start, expiry),
            [""; 5],
        )?));
        Ok(request(self.client, Method::GET, url))
    }

    fn sas_windows(&mut self) -> Result<()> {
        self.seed_block(BLOB, BLOB_BYTES)?;
        let sas_end = iso(300);
        let key = delegation_key_document(self.client, self.endpoint, self.bearer, &iso(600))?;
        for (step, start, end) in [
            (Step::InWindow, String::new(), sas_end.clone()),
            (Step::Expired, iso(-90), iso(-45)),
            (Step::FutureStart, iso(120), sas_end.clone()),
            (Step::SignedStart, iso(-45), sas_end.clone()),
        ] {
            self.read_blob(
                step,
                self.sas_read(&key, &start, &end)?,
                BLOB_BYTES,
                "BlockBlob",
            )?;
        }

        let short_end = iso(15);
        let short_key =
            delegation_key_document(self.client, self.endpoint, self.bearer, &short_end)?;
        let still_valid = self.sas_read(&short_key, "", &sas_end)?;
        let before = Reply::receive(still_valid)?;
        ensure!(
            before.status == 200 && before.bytes == BLOB_BYTES,
            "SAS must work while the short key is valid (HTTP {})",
            before.status
        );
        thread::sleep(Duration::from_secs(17));
        self.read_blob(
            Step::ExpiredKey,
            self.sas_read(&short_key, "", &sas_end)?,
            BLOB_BYTES,
            "BlockBlob",
        )
    }

    fn rename_boundary(&mut self) -> Result<()> {
        let url = self
            .endpoint
            .join(&format!("{}?restype=container&comp=rename", self.container))?;
        self.write_empty(
            Step::RejectRename,
            request(self.client, Method::PUT, url)
                .bearer_auth(self.bearer)
                .header("content-length", "0")
                .header("x-ms-source-container", self.container),
        )
    }
}

pub(super) fn observe(
    client: &Client,
    account: &str,
    endpoint: &Url,
    bearer: &str,
    source: Source,
    case: Case,
) -> Result<Cassette> {
    with_fresh_container(client, endpoint, bearer, |container, _| {
        let mut probe = Probe {
            client,
            bearer,
            endpoint,
            account,
            container,
            exchanges: Vec::new(),
        };
        match case {
            Case::FromUrl => probe.write_from_url()?,
            Case::IncrementalCopy => probe.incremental_copy()?,
            Case::SasWindows => probe.sas_windows()?,
            Case::RenameBoundary => probe.rename_boundary()?,
        }
        Ok(Cassette {
            schema_version: 1,
            api_version: ApiVersion::Baseline,
            source,
            case,
            exchanges: probe.exchanges,
        })
    })
}

pub(super) fn local(case: Case) -> Result<Cassette> {
    with_local(|client, endpoint, bearer| {
        observe(client, ACCOUNT, endpoint, bearer, Source::Synthetic, case)
    })
}

pub(super) fn reviewed(case: Case) -> Result<Cassette> {
    let path = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("tests/contracts/cassettes")
        .join(format!("{}.json", case.file_stem()));
    let bytes = read_bounded(
        File::open(path).with_context(|| format!("missing {:?} Azure fixture", case))?,
    )?;
    let expected: Cassette = serde_json::from_slice(&bytes)
        .map_err(|_| anyhow::anyhow!("invalid flat Blob cassette"))?;
    ensure!(
        expected.source == Source::Azure && expected.case == case,
        "expected reviewed Azure observation"
    );
    expected.validate()?;
    Ok(expected)
}

#[test]
fn replay_flat_blob_from_url() -> Result<()> {
    reviewed(Case::FromUrl)?.compare(&local(Case::FromUrl)?)
}

#[test]
fn replay_flat_blob_incremental_copy() -> Result<()> {
    reviewed(Case::IncrementalCopy)?.compare(&local(Case::IncrementalCopy)?)
}

#[test]
fn replay_flat_blob_sas_windows() -> Result<()> {
    reviewed(Case::SasWindows)?.compare(&local(Case::SasWindows)?)
}

#[test]
fn replay_flat_blob_rename_boundary() -> Result<()> {
    reviewed(Case::RenameBoundary)?.compare(&local(Case::RenameBoundary)?)
}
