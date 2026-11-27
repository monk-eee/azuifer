use anyhow::{Result, ensure};
use quick_xml::{Reader, events::Event};
use reqwest::header::HeaderMap;
use serde::{Deserialize, Serialize, de::DeserializeOwned};
use std::collections::BTreeMap;

use super::{BLOB_BYTES, RANGE_END, RANGE_START, VERSION};

pub(super) const MAX_CASSETTE_BYTES: u64 = 16 * 1024;
const PERMISSION_MESSAGE: &str =
    "This request is not authorized to perform this operation using this permission.";

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub(super) enum Source {
    Synthetic,
    Azure,
}

#[derive(Debug, Deserialize, Eq, PartialEq, Serialize)]
pub(super) enum Scenario {
    #[serde(rename = "blob-user-delegation-sas-read-only")]
    SasReadOnly,
    #[serde(rename = "blob-get-user-delegation-key")]
    DelegationKeyIssued,
    #[serde(rename = "blob-delegation-key-invalid-windows")]
    DelegationKeyInvalidWindows,
}

#[derive(Debug, Deserialize, Eq, PartialEq, Serialize)]
pub(super) enum ApiVersion {
    #[serde(rename = "2023-11-03")]
    Baseline,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub(super) enum Step {
    Head,
    Range,
    DeniedDelete,
    ReadBack,
}

pub(super) const STEPS: [Step; 4] = [Step::Head, Step::Range, Step::DeniedDelete, Step::ReadBack];

#[derive(Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub(super) enum Header {
    Missing,
    Matches,
    Different,
}

pub(super) fn echoed(actual: Option<&str>, expected: Option<&str>) -> Header {
    match actual {
        Some(value) if Some(value) == expected => Header::Matches,
        Some(_) => Header::Different,
        None => Header::Missing,
    }
}

#[derive(Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub(super) enum XmlEtag {
    Matches,
    UnquotedMatch,
    Missing,
    Different,
}

impl XmlEtag {
    pub(super) fn observe(value: Option<&str>, expected: Option<&str>) -> Self {
        match (value, expected) {
            (Some(actual), Some(expected)) if actual == expected => Self::Matches,
            (Some(actual), Some(expected)) if actual == expected.trim_matches('"') => {
                Self::UnquotedMatch
            }
            (None, _) => Self::Missing,
            _ => Self::Different,
        }
    }
}

#[derive(Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub(super) enum Media {
    Missing,
    TextPlain,
    OctetStream,
    AvroBinary,
    Xml,
    JsonNoMetadata,
    JsonMinimalMetadata,
    Json,
    Other,
}

#[derive(Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub(super) enum ErrorCode {
    Missing,
    PermissionMismatch,
    AuthenticationFailed,
    AuthorizationFailure,
    BlobNotFound,
    BlobAlreadyExists,
    ConditionNotMet,
    InvalidBlockList,
    LeaseIdMissing,
    LeaseMismatchBlob,
    LeaseMismatchLease,
    LeaseBreakingNoAcquire,
    LeaseAlreadyPresent,
    SnapshotsPresent,
    AppendPositionConditionNotMet,
    SequenceNumberConditionNotMet,
    ContainerNotFound,
    ContainerAlreadyExists,
    InvalidBlockId,
    InvalidBlobOrBlock,
    InvalidPageRange,
    MaxBlobSizeConditionNotMet,
    BlobIsSealed,
    InvalidInput,
    InvalidHeaderValue,
    InvalidRange,
    BothCrc64AndMd5RangeHeaderPresent,
    MixedBatchOperations,
    QueryExpression,
    InvalidXmlDocument,
    InvalidXmlNodeValue,
    QueueNotFound,
    TableAlreadyExists,
    ResourceNotFound,
    SourceConditionNotMet,
    NoPendingCopyOperation,
    Other,
}

impl ErrorCode {
    pub(super) fn from_value(value: Option<&str>) -> Self {
        match value {
            None => Self::Missing,
            Some("AuthorizationPermissionMismatch") => Self::PermissionMismatch,
            Some("AuthenticationFailed") => Self::AuthenticationFailed,
            Some("AuthorizationFailure") => Self::AuthorizationFailure,
            Some("BlobNotFound") => Self::BlobNotFound,
            Some("BlobAlreadyExists") => Self::BlobAlreadyExists,
            Some("ConditionNotMet") => Self::ConditionNotMet,
            Some("InvalidBlockList") => Self::InvalidBlockList,
            Some("LeaseIdMissing") => Self::LeaseIdMissing,
            Some("LeaseIdMismatchWithBlobOperation") => Self::LeaseMismatchBlob,
            Some("LeaseIdMismatchWithLeaseOperation") => Self::LeaseMismatchLease,
            Some("LeaseIsBreakingAndCannotBeAcquired") => Self::LeaseBreakingNoAcquire,
            Some("LeaseAlreadyPresent") => Self::LeaseAlreadyPresent,
            Some("SnapshotsPresent") => Self::SnapshotsPresent,
            Some("AppendPositionConditionNotMet") => Self::AppendPositionConditionNotMet,
            Some("SequenceNumberConditionNotMet") => Self::SequenceNumberConditionNotMet,
            Some("ContainerNotFound") => Self::ContainerNotFound,
            Some("ContainerAlreadyExists") => Self::ContainerAlreadyExists,
            Some("InvalidBlockId") => Self::InvalidBlockId,
            Some("InvalidBlobOrBlock") => Self::InvalidBlobOrBlock,
            Some("InvalidPageRange") => Self::InvalidPageRange,
            Some("MaxBlobSizeConditionNotMet") => Self::MaxBlobSizeConditionNotMet,
            Some("BlobIsSealed") => Self::BlobIsSealed,
            Some("InvalidInput") => Self::InvalidInput,
            Some("InvalidHeaderValue") => Self::InvalidHeaderValue,
            Some("InvalidRange") => Self::InvalidRange,
            Some("BothCrc64AndMd5RangeHeaderPresent") => Self::BothCrc64AndMd5RangeHeaderPresent,
            Some("AllBatchSubRequestsShouldBeSameApi") => Self::MixedBatchOperations,
            Some("ErrorProcessingQueryExpression") => Self::QueryExpression,
            Some("InvalidXmlDocument") => Self::InvalidXmlDocument,
            Some("InvalidXmlNodeValue") => Self::InvalidXmlNodeValue,
            Some("QueueNotFound") => Self::QueueNotFound,
            Some("TableAlreadyExists") => Self::TableAlreadyExists,
            Some("ResourceNotFound") => Self::ResourceNotFound,
            Some("SourceConditionNotMet") => Self::SourceConditionNotMet,
            Some("NoPendingCopyOperation") => Self::NoPendingCopyOperation,
            Some(_) => Self::Other,
        }
    }
}

pub(super) fn project_xml<T: DeserializeOwned>(bytes: &[u8], root: &str) -> Result<T> {
    let text = std::str::from_utf8(bytes)
        .map_err(|_| anyhow::anyhow!("invalid {root} response encoding"))?
        .trim_start_matches('\u{feff}');
    let mut reader = Reader::from_str(text);
    reader.config_mut().trim_text(true);
    let start = match reader.read_event() {
        Ok(Event::Decl(_)) => reader.read_event(),
        event => event,
    };
    ensure!(
        matches!(start, Ok(Event::Start(tag) | Event::Empty(tag)) if tag.name().as_ref() == root),
        "unexpected {root} XML envelope"
    );
    quick_xml::de::from_str(text).map_err(|_| anyhow::anyhow!("invalid {root} XML fields"))
}

#[derive(Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
enum Body {
    Empty {},
    FixtureRange {},
    FixtureFull {},
    XmlError(XmlError),
    Other {},
}

#[derive(Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub(super) struct XmlError {
    code: ErrorCode,
    permission_message: bool,
    correlation: Header,
    extra_elements: bool,
}

impl XmlError {
    pub(super) fn permission_denial(&self) -> bool {
        self.code == ErrorCode::PermissionMismatch
            && self.permission_message
            && self.correlation == Header::Matches
            && !self.extra_elements
    }
}

#[derive(Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub(super) struct Exchange {
    step: Step,
    status: u16,
    media: Media,
    content_length: Option<u64>,
    content_range: Header,
    blob_type: Header,
    accept_ranges: Header,
    fixture_metadata: Header,
    etag: Header,
    api_version: Header,
    request_id: Header,
    last_modified: Header,
    error_header: ErrorCode,
    body: Body,
}

#[derive(Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub(super) struct Cassette {
    schema_version: u8,
    source: Source,
    scenario: Scenario,
    api_version: ApiVersion,
    exchanges: [Exchange; 4],
}

impl Cassette {
    pub(super) fn new(source: Source, exchanges: [Exchange; 4]) -> Self {
        Self {
            schema_version: 1,
            source,
            scenario: Scenario::SasReadOnly,
            api_version: ApiVersion::Baseline,
            exchanges,
        }
    }

    pub(super) fn load(bytes: &[u8]) -> Result<Self> {
        ensure!(
            bytes.len() as u64 <= MAX_CASSETTE_BYTES,
            "cassette is too large"
        );
        let value: Self = serde_json::from_slice(bytes)
            .map_err(|error| anyhow::anyhow!("invalid cassette schema at line {}", error.line()))?;
        ensure!(
            value.schema_version == 1,
            "unsupported cassette schema version"
        );
        ensure!(
            value.scenario == Scenario::SasReadOnly,
            "unexpected cassette scenario"
        );
        ensure!(
            value.exchanges.each_ref().map(|exchange| exchange.step) == STEPS,
            "unexpected cassette step order"
        );
        Ok(value)
    }

    pub(super) fn load_azure(bytes: &[u8]) -> Result<Self> {
        let value = Self::load(bytes)?;
        ensure!(
            value.source == Source::Azure,
            "expected a recorded Azure SAS cassette"
        );
        Ok(value)
    }

    pub(super) fn compare(&self, actual: &Self) -> Result<()> {
        for (expected, observed) in self.exchanges.iter().zip(&actual.exchanges) {
            ensure!(
                expected == observed,
                "{:?}: expected {expected:#?}, observed {observed:#?}",
                expected.step
            );
            ensure!(
                observed.is_contract_result(),
                "{:?}: matching responses do not meet the SAS scenario's invariants",
                observed.step
            );
        }
        Ok(())
    }

    pub(super) fn seeded_blob_was_read(&self) -> bool {
        self.exchanges[0].status == 200
            && self.exchanges[0].etag == Header::Matches
            && self.exchanges[1].status == 206
            && self.exchanges[1].body == (Body::FixtureRange {})
    }
}

pub(super) fn header_text<'a>(headers: &'a HeaderMap, name: &'static str) -> Option<&'a str> {
    let mut values = headers.get_all(name).iter();
    let value = values.next()?;
    if values.next().is_some() {
        return None;
    }
    value.to_str().ok()
}

pub(super) fn header(
    headers: &HeaderMap,
    name: &'static str,
    verify: impl FnOnce(&str) -> bool,
) -> Header {
    match header_text(headers, name) {
        Some(value) if verify(value) => Header::Matches,
        _ if headers.contains_key(name) => Header::Different,
        _ => Header::Missing,
    }
}

pub(super) fn media(headers: &HeaderMap) -> Media {
    match header_text(headers, "content-type") {
        Some("text/plain") => Media::TextPlain,
        Some("application/octet-stream") => Media::OctetStream,
        Some("avro/binary") => Media::AvroBinary,
        Some("application/xml" | "application/xml; charset=utf-8") => Media::Xml,
        Some("application/json;odata=nometadata;streaming=true;charset=utf-8") => {
            Media::JsonNoMetadata
        }
        Some("application/json;odata=minimalmetadata;streaming=true;charset=utf-8") => {
            Media::JsonMinimalMetadata
        }
        Some("application/json") => Media::Json,
        None if !headers.contains_key("content-type") => Media::Missing,
        _ => Media::Other,
    }
}

impl Exchange {
    fn is_contract_result(&self) -> bool {
        if self.api_version != Header::Matches || self.request_id != Header::Matches {
            return false;
        }
        if self.step == Step::DeniedDelete {
            return self.status == 403
                && self.media == Media::Xml
                && self.error_header == ErrorCode::PermissionMismatch
                && matches!(&self.body, Body::XmlError(error) if error.permission_denial());
        }
        if self.etag != Header::Matches
            || self.media != Media::TextPlain
            || self.blob_type != Header::Matches
            || self.accept_ranges != Header::Matches
            || self.fixture_metadata != Header::Matches
            || self.last_modified != Header::Matches
            || self.error_header != ErrorCode::Missing
        {
            return false;
        }
        let (status, body, len, range) = match self.step {
            Step::Head => (200, Body::Empty {}, BLOB_BYTES.len(), Header::Missing),
            Step::Range => (
                206,
                Body::FixtureRange {},
                RANGE_END - RANGE_START + 1,
                Header::Matches,
            ),
            Step::ReadBack => (200, Body::FixtureFull {}, BLOB_BYTES.len(), Header::Missing),
            Step::DeniedDelete => return false,
        };
        self.status == status
            && self.body == body
            && self.content_length == Some(len as u64)
            && self.content_range == range
    }

    pub(super) fn observe(
        step: Step,
        status: u16,
        headers: &HeaderMap,
        bytes: &[u8],
        original_etag: &str,
    ) -> Self {
        let get = |name| header_text(headers, name);
        let is = |name, expected: &str| header(headers, name, |value| value == expected);
        let content_range = format!("bytes {RANGE_START}-{RANGE_END}/{}", BLOB_BYTES.len());
        let body = if bytes.is_empty() {
            Body::Empty {}
        } else if step == Step::Range && bytes == &BLOB_BYTES[RANGE_START..=RANGE_END] {
            Body::FixtureRange {}
        } else if step == Step::ReadBack && bytes == BLOB_BYTES {
            Body::FixtureFull {}
        } else {
            xml_error(bytes, get("x-ms-request-id")).map_or(Body::Other {}, Body::XmlError)
        };
        Self {
            step,
            status,
            media: media(headers),
            // Dynamic error messages change the XML byte count; the XML shape is recorded below.
            content_length: (status < 400)
                .then(|| get("content-length").and_then(|value| value.parse().ok()))
                .flatten(),
            content_range: is("content-range", &content_range),
            blob_type: is("x-ms-blob-type", "BlockBlob"),
            accept_ranges: is("accept-ranges", "bytes"),
            fixture_metadata: is("x-ms-meta-purpose", "azuifer-contract"),
            etag: is("etag", original_etag),
            api_version: is("x-ms-version", VERSION),
            request_id: header(headers, "x-ms-request-id", |id| {
                uuid::Uuid::parse_str(id).is_ok()
            }),
            last_modified: header(headers, "last-modified", |value| {
                httpdate::parse_http_date(value).is_ok()
            }),
            error_header: match get("x-ms-error-code") {
                None if headers.contains_key("x-ms-error-code") => ErrorCode::Other,
                value => ErrorCode::from_value(value),
            },
            body,
        }
    }
}

pub(super) fn xml_error(bytes: &[u8], request_id: Option<&str>) -> Option<XmlError> {
    let fields = flat_xml(std::str::from_utf8(bytes).ok()?, "Error")?;
    let code = ErrorCode::from_value(fields.get("Code").map(String::as_str));
    let (message, correlation) = error_message(fields.get("Message")?, request_id);
    Some(XmlError {
        code,
        permission_message: message == PERMISSION_MESSAGE,
        correlation,
        extra_elements: fields.len() != 2,
    })
}

pub(super) fn error_message<'a>(message: &'a str, request_id: Option<&str>) -> (&'a str, Header) {
    let mut lines = message.lines();
    let prefix = lines.next().unwrap_or_default().trim();
    let correlation = match (lines.next(), lines.next(), lines.next()) {
        (None, None, None) => Header::Missing,
        (Some(id), Some(time), None)
            if request_id
                .is_some_and(|expected| id.trim().strip_prefix("RequestId:") == Some(expected))
                && time
                    .trim()
                    .strip_prefix("Time:")
                    .is_some_and(is_utc_timestamp) =>
        {
            Header::Matches
        }
        _ => Header::Different,
    };
    (prefix, correlation)
}

pub(super) fn is_utc_timestamp(value: &str) -> bool {
    value.ends_with('Z')
        && value.contains('T')
        && value
            .bytes()
            .all(|b| b.is_ascii_digit() || b"-:.TZ".contains(&b))
}

// These two Azure envelopes contain only text leaves. Never include a parse error's input.
pub(super) fn flat_xml(document: &str, root: &str) -> Option<BTreeMap<String, String>> {
    let mut reader = Reader::from_str(document.trim_start_matches('\u{feff}'));
    reader.config_mut().trim_text(true);
    let first = match reader.read_event().ok()? {
        Event::Decl(_) => reader.read_event().ok()?,
        event => event,
    };
    if !matches!(first, Event::Start(tag) if tag.name().as_ref() == root) {
        return None;
    }
    let mut fields = BTreeMap::new();
    loop {
        match reader.read_event().ok()? {
            Event::Start(tag) => {
                let name = tag.name().into_inner();
                let text = reader.read_text(tag.name()).ok()?;
                if text.contains('<')
                    || fields
                        .insert(name.to_owned(), text.trim().to_owned())
                        .is_some()
                {
                    return None;
                }
            }
            Event::Empty(tag) => {
                if fields
                    .insert(tag.name().as_ref().to_owned(), String::new())
                    .is_some()
                {
                    return None;
                }
            }
            Event::End(tag) if tag.name().as_ref() == root => {
                return matches!(reader.read_event().ok()?, Event::Eof).then_some(fields);
            }
            _ => return None,
        }
    }
}

#[test]
fn serialization_never_contains_headers_credentials_or_arbitrary_bodies() {
    use reqwest::header::HeaderValue;
    let mut headers = HeaderMap::new();
    let secret = "PRIVATE-CREDENTIAL-FIXTURE";
    for (name, value) in [
        ("authorization", secret),
        ("set-cookie", secret),
        ("x-ms-request-id", secret),
        ("x-ms-error-code", secret),
        ("content-type", secret),
        ("etag", secret),
    ] {
        headers.insert(name, HeaderValue::from_str(value).unwrap());
    }

    let exchanges = STEPS.map(|step| {
        Exchange::observe(
            step,
            403,
            &headers,
            format!("<Error><Code>{secret}</Code><Message>{secret}</Message><AuthenticationErrorDetail>{secret}</AuthenticationErrorDetail></Error>").as_bytes(),
            secret,
        )
    });
    let cassette = Cassette::new(Source::Azure, exchanges);
    let directory = tempfile::tempdir().unwrap();
    let path = super::live::save(super::live::Record::Sas(&cassette), directory.path()).unwrap();
    let json = std::fs::read_to_string(path).unwrap();
    assert!(!json.contains(secret));
    assert_eq!(Cassette::load(json.as_bytes()).unwrap(), cassette);

    let unsafe_json = json.replacen('{', &format!("{{\"raw_url\":\"?sig={secret}\","), 1);
    let rejected = Cassette::load(unsafe_json.as_bytes())
        .unwrap_err()
        .to_string();
    assert!(!rejected.contains(secret));

    let mut unsafe_body: serde_json::Value = serde_json::from_slice(super::SAS_CASSETTE).unwrap();
    unsafe_body["exchanges"][0]["body"]["raw_body"] = serde_json::json!(secret);
    let rejected = Cassette::load(&serde_json::to_vec(&unsafe_body).unwrap())
        .unwrap_err()
        .to_string();
    assert!(!rejected.contains(secret));
}

#[test]
fn matching_failures_cannot_count_as_parity() {
    let response = HeaderMap::new();
    let failed = Cassette::new(
        Source::Azure,
        STEPS.map(|step| Exchange::observe(step, 403, &response, b"", "\"seed\"")),
    );
    assert!(failed.compare(&failed).is_err());
}

#[test]
fn azure_error_correlation_normalizes_values_but_detects_a_missing_request_id() {
    let observe = |id: &str, time: &str| {
        let body = format!(
            "<Error><Code>AuthorizationPermissionMismatch</Code><Message>{PERMISSION_MESSAGE}\r\nRequestId:{id}\r\nTime:{time}</Message></Error>"
        );
        xml_error(body.as_bytes(), Some(id)).unwrap()
    };
    let original = observe(
        "00000000-0000-0000-0000-000000000001",
        "2026-01-02T03:04:05.001Z",
    );
    let later = observe(
        "00000000-0000-0000-0000-000000000002",
        "2026-01-02T03:04:07.002Z",
    );
    assert_eq!(original, later);
    assert_eq!(original.correlation, Header::Matches);
    let without_correlation = format!(
        "<Error><Code>AuthorizationPermissionMismatch</Code><Message>{PERMISSION_MESSAGE}</Message></Error>"
    );
    assert_ne!(
        original,
        xml_error(without_correlation.as_bytes(), None).unwrap()
    );
}
