use super::{
    VERSION,
    cassette::{ApiVersion, Header, Media, Scenario, Source, flat_xml, header, media},
    get_delegation_key, iso, read_bounded, require_status, with_local,
};
use anyhow::{Context as _, Result, anyhow, ensure};
use base64::{Engine as _, engine::general_purpose::STANDARD};
use reqwest::{Url, blocking::Client, header::HeaderMap};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

const KEY_FIELDS: [&str; 7] = [
    "SignedOid",
    "SignedTid",
    "SignedStart",
    "SignedExpiry",
    "SignedService",
    "SignedVersion",
    "Value",
];
const AZURE_FIXTURE: &[u8] = include_bytes!("cassettes/blob-get-user-delegation-key.json");

#[derive(Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub(super) struct KeyCassette {
    schema_version: u8,
    source: Source,
    scenario: Scenario,
    api_version: ApiVersion,
    response: KeyResponse,
}

#[derive(Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
struct KeyResponse {
    status: u16,
    media: Media,
    api_version_header: Header,
    request_id: Header,
    date: Header,
    object_id_is_uuid: bool,
    tenant_id_is_uuid: bool,
    start_matches: bool,
    expiry_matches: bool,
    service_is_blob: bool,
    signed_version_matches: bool,
    decoded_key_bytes: usize,
    extra_elements: usize,
}

impl KeyCassette {
    pub(super) fn compare(&self, local: &Self) -> Result<()> {
        ensure!(
            self.scenario == Scenario::BlobGetUserDelegationKey
                && self.schema_version == 1
                && self.response == local.response,
            "Get User Delegation Key: expected {:#?}, observed {:#?}",
            self.response,
            local.response
        );
        ensure!(
            self.response.status == 200
                && self.response.media == Media::Xml
                && self.response.api_version_header == Header::Matches
                && self.response.request_id == Header::Matches
                && self.response.date == Header::Matches
                && self.response.object_id_is_uuid
                && self.response.tenant_id_is_uuid
                && self.response.start_matches
                && self.response.expiry_matches
                && self.response.service_is_blob
                && self.response.signed_version_matches,
            "matching responses did not issue a usable Blob delegation key"
        );
        Ok(())
    }
}

pub(super) fn observe(
    client: &Client,
    endpoint: &Url,
    bearer: &str,
    source: Source,
) -> Result<KeyCassette> {
    let (start, expiry) = (iso(-120), iso(300));
    let response = get_delegation_key(client, endpoint, bearer, &start, &expiry)?;
    require_status(&response, 200, "get user delegation key")?;
    let status = response.status().as_u16();
    let headers = response.headers().clone();
    let body = read_bounded(response)?;
    let result = project(status, &headers, &body, &start, &expiry)?;
    Ok(KeyCassette {
        schema_version: 1,
        source,
        scenario: Scenario::BlobGetUserDelegationKey,
        api_version: ApiVersion::Baseline,
        response: result,
    })
}

fn project(
    status: u16,
    headers: &HeaderMap,
    body: &[u8],
    start: &str,
    expiry: &str,
) -> Result<KeyResponse> {
    let text = std::str::from_utf8(body)
        .map_err(|_| anyhow!("invalid delegation key response encoding"))?;
    let fields =
        flat_xml(text, "UserDelegationKey").context("invalid delegation key response envelope")?;
    let field = |name| fields.get(name).map(String::as_str);
    let is_uuid = |name| field(name).is_some_and(|value| Uuid::parse_str(value).is_ok());
    let decoded_key_bytes = STANDARD
        .decode(field("Value").context("delegation key response has no Value element")?)
        .map_err(|_| anyhow!("invalid delegation key encoding"))?
        .len();
    ensure!(
        decoded_key_bytes != 0,
        "delegation key response contained no key bytes"
    );
    let matches_time = |name, expected: &str| {
        field(name).is_some_and(|value| {
            if value == expected {
                return true;
            }
            let Some((whole, fraction)) = value
                .strip_suffix('Z')
                .and_then(|value| value.split_once('.'))
            else {
                return false;
            };
            expected.strip_suffix('Z') == Some(whole)
                && !fraction.is_empty()
                && fraction.bytes().all(|byte| byte == b'0')
        })
    };
    Ok(KeyResponse {
        status,
        media: media(headers),
        api_version_header: header(headers, "x-ms-version", |value| value == VERSION),
        request_id: header(headers, "x-ms-request-id", |id| Uuid::parse_str(id).is_ok()),
        date: header(headers, "date", |date| {
            httpdate::parse_http_date(date).is_ok()
        }),
        object_id_is_uuid: is_uuid("SignedOid"),
        tenant_id_is_uuid: is_uuid("SignedTid"),
        start_matches: matches_time("SignedStart", start),
        expiry_matches: matches_time("SignedExpiry", expiry),
        service_is_blob: field("SignedService") == Some("b"),
        signed_version_matches: field("SignedVersion") == Some(VERSION),
        decoded_key_bytes,
        extra_elements: fields
            .keys()
            .filter(|name| !KEY_FIELDS.contains(&name.as_str()))
            .count(),
    })
}

#[test]
fn replay_get_user_delegation_key_against_azure_cassette() -> Result<()> {
    let expected: KeyCassette =
        serde_json::from_slice(AZURE_FIXTURE).map_err(|_| anyhow!("invalid Azure key cassette"))?;
    ensure!(
        expected.source == Source::Azure,
        "replay requires the observed Azure fixture"
    );
    let local = with_local(|client, endpoint, bearer| {
        observe(client, endpoint, bearer, Source::Synthetic)
    })?;
    expected.compare(&local)
}

#[test]
fn delegation_value_and_identifiers_are_not_serialized() {
    let oid = "00000000-0000-0000-0000-000000000001";
    let tid = "00000000-0000-0000-0000-000000000002";
    let start = "2024-01-02T03:04:05Z";
    let expiry = "2024-01-02T03:09:05Z";
    let key = STANDARD.encode([41u8; 32]);
    let body = format!(
        "<UserDelegationKey><SignedOid>{oid}</SignedOid><SignedTid>{tid}</SignedTid>\
         <SignedStart>{start}</SignedStart><SignedExpiry>{expiry}</SignedExpiry>\
         <SignedService>b</SignedService><SignedVersion>{VERSION}</SignedVersion>\
         <Value>{key}</Value></UserDelegationKey>"
    );
    let projected = project(200, &HeaderMap::new(), body.as_bytes(), start, expiry).unwrap();
    assert_eq!(projected.decoded_key_bytes, 32);
    let serialized = serde_json::to_string(&projected).unwrap();
    for raw in [key.as_str(), oid, tid, start, expiry] {
        assert!(!serialized.contains(raw));
    }
}
