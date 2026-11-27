use super::{
    ACCOUNT, BLOB, BLOB_BYTES, RANGE_END, RANGE_START, VERSION,
    cassette::{
        ApiVersion, ErrorCode, Header, Media, Source, XmlError, header, header_text, media,
        xml_error,
    },
    delegation_key_document, iso, read_bounded, request, require_status, send, sign_sas,
    sign_sas_with_options, with_fresh_container, with_local,
};
use anyhow::{Context as _, Result, ensure};
use reqwest::{
    Method, Url,
    blocking::{Client, RequestBuilder},
    header::HeaderMap,
};
use serde::{Deserialize, Serialize};
use std::{fs::File, path::Path};
use uuid::Uuid;

mod list;

// Keep the values in the same order as the five signed response fields.
const CONTENT_FIELDS: [(&str, &str); 5] = [
    ("cache-control", "x-ms-blob-cache-control"),
    ("content-disposition", "x-ms-blob-content-disposition"),
    ("content-encoding", "x-ms-blob-content-encoding"),
    ("content-language", "x-ms-blob-content-language"),
    ("content-type", "x-ms-blob-content-type"),
];
const STORED: [&str; 5] = ["max-age=120", "inline", "", "en", "text/plain"];
const OVERRIDES: [&str; 5] = [
    "no-store",
    "attachment; filename=download.txt",
    "identity",
    "fr",
    "application/octet-stream",
];
const PURPOSE: &str = "azuifer-contract";

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub(super) enum Case {
    #[serde(rename = "blob-user-delegation-sas-list")]
    ContainerList,
    #[serde(rename = "blob-user-delegation-sas-overrides")]
    ResponseOverrides,
}

impl Case {
    pub(super) fn file_stem(self) -> &'static str {
        match self {
            Self::ContainerList => "blob-user-delegation-sas-list",
            Self::ResponseOverrides => "blob-user-delegation-sas-overrides",
        }
    }

    fn steps(self) -> &'static [Step] {
        use Step::*;
        match self {
            Self::ContainerList => &[
                ListFirst, ListNext, ListNested, ReadDenied, ListDenied, ReadNested,
            ],
            Self::ResponseOverrides => &[OverriddenHead, OverriddenRange, PlainRead],
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
enum Step {
    ListFirst,
    ListNext,
    ListNested,
    ReadDenied,
    ListDenied,
    ReadNested,
    OverriddenHead,
    OverriddenRange,
    PlainRead,
}

#[derive(Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
enum ContentValue {
    Missing,
    Stored,
    Override,
    Other,
}

#[derive(Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
struct Readback {
    bytes_match: bool,
    length: Option<u64>,
    etag: Header,
    range: Header,
    metadata: Header,
    blob_type: Header,
    cache_control: ContentValue,
    disposition: ContentValue,
    encoding: ContentValue,
    language: ContentValue,
    content_type: ContentValue,
}

impl Readback {
    fn observe(step: Step, headers: &HeaderMap, bytes: &[u8], etag: &str) -> Self {
        let content_range = format!("bytes {RANGE_START}-{RANGE_END}/{}", BLOB_BYTES.len());
        let is = |name, expected: &str| header(headers, name, |value| value == expected);
        let [cache_control, disposition, encoding, language, content_type] =
            std::array::from_fn(|i| {
                let name = CONTENT_FIELDS[i].0;
                match header_text(headers, name) {
                    Some(value) if value == STORED[i] => ContentValue::Stored,
                    Some(value) if value == OVERRIDES[i] => ContentValue::Override,
                    None if !headers.contains_key(name) => ContentValue::Missing,
                    _ => ContentValue::Other,
                }
            });
        let expected = match step {
            Step::OverriddenHead => &[][..],
            Step::OverriddenRange => &BLOB_BYTES[RANGE_START..=RANGE_END],
            _ => BLOB_BYTES,
        };
        Self {
            bytes_match: bytes == expected,
            length: header_text(headers, "content-length").and_then(|value| value.parse().ok()),
            etag: is("etag", etag),
            range: is("content-range", &content_range),
            metadata: is("x-ms-meta-purpose", PURPOSE),
            blob_type: is("x-ms-blob-type", "BlockBlob"),
            cache_control,
            disposition,
            encoding,
            language,
            content_type,
        }
    }

    fn matches_fixture(&self, step: Step) -> bool {
        let (length, range) = if step == Step::OverriddenRange {
            (RANGE_END - RANGE_START + 1, Header::Matches)
        } else {
            (BLOB_BYTES.len(), Header::Missing)
        };
        self.bytes_match
            && self.length == Some(length as u64)
            && self.range == range
            && self.etag == Header::Matches
            && self.metadata == Header::Matches
            && self.blob_type == Header::Matches
    }
}

#[derive(Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
enum Body {
    List(list::Page),
    Read(Readback),
    XmlError(XmlError),
    Other {},
}

#[derive(Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
struct Exchange {
    step: Step,
    status: u16,
    api_version: Header,
    request_id: Header,
    error_header: ErrorCode,
    body: Body,
}

impl Exchange {
    fn observe(
        step: Step,
        wire: RequestBuilder,
        success: impl FnOnce(&HeaderMap, &[u8]) -> Result<Body>,
    ) -> Result<Self> {
        let response = send(wire, "send Blob SAS probe").with_context(|| format!("{step:?}"))?;
        let status = response.status();
        let headers = response.headers().clone();
        let bytes = read_bounded(response).with_context(|| format!("{step:?}"))?;
        let request_id = |id: &str| Uuid::parse_str(id).is_ok();
        let body = if status.is_success() {
            success(&headers, &bytes).with_context(|| format!("{step:?}"))?
        } else if media(&headers) == Media::Xml {
            xml_error(&bytes, header_text(&headers, "x-ms-request-id"))
                .map_or(Body::Other {}, Body::XmlError)
        } else {
            Body::Other {}
        };
        Ok(Self {
            step,
            status: status.as_u16(),
            api_version: header(&headers, "x-ms-version", |value| value == VERSION),
            request_id: header(&headers, "x-ms-request-id", request_id),
            error_header: ErrorCode::from_value(header_text(&headers, "x-ms-error-code")),
            body,
        })
    }

    fn matches_fixture(&self) -> bool {
        if self.api_version != Header::Matches || self.request_id != Header::Matches {
            return false;
        }
        match (&self.body, self.step) {
            (Body::List(page), Step::ListFirst | Step::ListNext | Step::ListNested) => {
                self.status == 200
                    && self.error_header == ErrorCode::Missing
                    && page.matches_fixture(self.step)
            }
            (
                Body::Read(read),
                Step::ReadNested | Step::OverriddenHead | Step::OverriddenRange | Step::PlainRead,
            ) => {
                self.status
                    == if self.step == Step::OverriddenRange {
                        206
                    } else {
                        200
                    }
                    && self.error_header == ErrorCode::Missing
                    && read.matches_fixture(self.step)
            }
            (Body::XmlError(error), Step::ReadDenied | Step::ListDenied) => {
                self.status == 403
                    && self.error_header == ErrorCode::PermissionMismatch
                    && error.permission_denial()
            }
            _ => false,
        }
    }
}

#[derive(Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub(super) struct SasReadCassette {
    schema_version: u8,
    source: Source,
    pub(super) case: Case,
    api_version: ApiVersion,
    exchanges: Vec<Exchange>,
}

impl SasReadCassette {
    pub(super) fn validate(&self) -> Result<()> {
        ensure!(
            self.schema_version == 1,
            "unsupported SAS read cassette schema"
        );
        ensure!(
            self.exchanges.iter().map(|exchange| exchange.step).eq(self
                .case
                .steps()
                .iter()
                .copied()),
            "unexpected SAS read cassette steps"
        );
        for exchange in &self.exchanges {
            ensure!(
                exchange.matches_fixture(),
                "{:?}: did not produce the expected synthetic SAS result: {exchange:?}",
                exchange.step
            );
        }
        Ok(())
    }

    pub(super) fn compare(&self, actual: &Self) -> Result<()> {
        self.validate()?;
        ensure!(
            self.case == actual.case && self.exchanges.len() == actual.exchanges.len(),
            "different SAS read scenario"
        );
        let differences: Vec<_> = self
            .exchanges
            .iter()
            .zip(&actual.exchanges)
            .filter(|(expected, observed)| expected != observed)
            .collect();
        ensure!(
            differences.is_empty(),
            "{}: differing exchanges (reviewed, observed):\n{differences:#?}",
            self.case.file_stem()
        );
        Ok(())
    }
}

fn seed(client: &Client, url: &Url, bearer: &str) -> Result<String> {
    let mut put = request(client, Method::PUT, url.clone())
        .bearer_auth(bearer)
        .header("x-ms-blob-type", "BlockBlob")
        .header("x-ms-meta-purpose", PURPOSE);
    for ((_, name), value) in CONTENT_FIELDS.into_iter().zip(STORED) {
        if !value.is_empty() {
            put = put.header(name, value);
        }
    }
    let response = send(put.body(BLOB_BYTES), "seed SAS test blob")?;
    require_status(&response, 201, "seed SAS test blob")?;
    let etag = header_text(response.headers(), "etag")
        .filter(|tag| tag.starts_with('"') && tag.ends_with('"') && tag.len() > 2)
        .context("seed test blob: missing or malformed ETag")?;
    Ok(etag.to_owned())
}

fn signed_url(mut url: Url, sas: &str) -> Url {
    url.set_query(Some(sas));
    url
}

fn observe_overrides(
    client: &Client,
    url: Url,
    key: &str,
    scope: (&str, &str),
    expiry: &str,
    etag: &str,
) -> Result<Vec<Exchange>> {
    let (account, container) = scope;
    let resource = (account, container, Some(BLOB));
    let signed = sign_sas_with_options(key, resource, "r", ("", expiry), OVERRIDES)?;
    let overridden = signed_url(url.clone(), &signed);
    let plain = signed_url(url, &sign_sas(key, resource, "r", expiry)?);
    [
        (
            Step::OverriddenHead,
            request(client, Method::HEAD, overridden.clone()),
        ),
        (
            Step::OverriddenRange,
            request(client, Method::GET, overridden)
                .header("range", format!("bytes={RANGE_START}-{RANGE_END}")),
        ),
        (Step::PlainRead, request(client, Method::GET, plain)),
    ]
    .into_iter()
    .map(|(step, wire)| {
        Exchange::observe(step, wire, |headers, bytes| {
            Ok(Body::Read(Readback::observe(step, headers, bytes, etag)))
        })
    })
    .collect()
}

pub(super) fn observe(
    client: &Client,
    account: &str,
    endpoint: &Url,
    bearer: &str,
    source: Source,
    case: Case,
) -> Result<SasReadCassette> {
    with_fresh_container(client, endpoint, bearer, |container, blob_url| {
        let expiry = iso(900);
        let key = delegation_key_document(client, endpoint, bearer, &expiry)?;
        let exchanges = match case {
            Case::ContainerList => {
                list::observe(client, &key, &expiry, account, endpoint, container, bearer)?
            }
            Case::ResponseOverrides => {
                let etag = seed(client, &blob_url, bearer)?;
                observe_overrides(client, blob_url, &key, (account, container), &expiry, &etag)?
            }
        };
        Ok(SasReadCassette {
            schema_version: 1,
            source,
            case,
            api_version: ApiVersion::Baseline,
            exchanges,
        })
    })
}

pub(super) fn reviewed(case: Case) -> Result<SasReadCassette> {
    let path = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("tests")
        .join("contracts")
        .join("cassettes")
        .join(format!("{}.json", case.file_stem()));
    let file = File::open(path)
        .with_context(|| format!("could not open reviewed {} cassette", case.file_stem()))?;
    let value: SasReadCassette = serde_json::from_slice(&read_bounded(file)?)
        .map_err(|error| anyhow::anyhow!("invalid SAS read cassette at line {}", error.line()))?;
    ensure!(
        value.source == Source::Azure && value.case == case,
        "expected the recorded Azure SAS read case"
    );
    value.validate()?;
    Ok(value)
}

pub(super) fn observe_local(case: Case) -> Result<SasReadCassette> {
    with_local(|client, endpoint, bearer| {
        observe(client, ACCOUNT, endpoint, bearer, Source::Synthetic, case)
    })
}

#[test]
fn replay_blob_sas_container_listing() -> Result<()> {
    let case = Case::ContainerList;
    reviewed(case)?.compare(&observe_local(case)?)
}

#[test]
fn replay_blob_sas_response_overrides() -> Result<()> {
    let case = Case::ResponseOverrides;
    reviewed(case)?.compare(&observe_local(case)?)
}
