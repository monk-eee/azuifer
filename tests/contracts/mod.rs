mod account;
mod batch;
mod cassette;
mod catalog;
mod delegation;
mod flat_blob;
mod live;
mod mutations;
mod query;
mod queue_messages;
mod request_errors;
mod sas_reads;
mod service_reads;
mod table_entities;
mod table_transactions;

use super::{ACCOUNT, Server, VERSION, basic_token, client, iso, sas_query};
use anyhow::{Context as _, Result, anyhow, ensure};
use base64::{Engine as _, engine::general_purpose::STANDARD};
use cassette::{
    Cassette, ErrorCode, Exchange, MAX_CASSETTE_BYTES, STEPS, Source, Step, flat_xml, header_text,
};
use hmac::{Hmac, Mac as _};
use reqwest::{
    Method, Url,
    blocking::{Client, RequestBuilder, Response},
};
use sha2::Sha256;
use std::{fs::File, io::Read, time::SystemTime};
use uuid::Uuid;

const BLOB: &str = "object.txt";
const BLOB_BYTES: &[u8] = b"azuifer synthetic contract fixture\n";
const RANGE_START: usize = 2;
const RANGE_END: usize = 8;
const SAS_CASSETTE: &[u8] = include_bytes!("cassettes/blob-user-delegation-sas-read-only.json");
const SAS_RESPONSE_FIELDS: [&str; 5] = ["rscc", "rscd", "rsce", "rscl", "rsct"];

#[derive(Clone, Copy)]
enum Service {
    Blob,
    Queue,
    Table,
}

impl Service {
    fn name(self) -> &'static str {
        match self {
            Self::Blob => "blob",
            Self::Queue => "queue",
            Self::Table => "table",
        }
    }
}

pub(super) fn sign_sas(
    key_document: &str,
    (account, container, blob): (&str, &str, Option<&str>),
    permissions: &str,
    expiry: &str,
) -> Result<String> {
    sign_sas_with_options(
        key_document,
        (account, container, blob),
        permissions,
        ("", expiry),
        [""; 5],
    )
}

fn sign_sas_with_options(
    key_document: &str,
    (account, container, blob): (&str, &str, Option<&str>),
    permissions: &str,
    (signed_start, expiry): (&str, &str),
    overrides: [&str; 5],
) -> Result<String> {
    let fields = flat_xml(key_document, "UserDelegationKey")
        .context("invalid user delegation key envelope")?;
    let get = |name| {
        fields
            .get(name)
            .map(String::as_str)
            .filter(|value| !value.is_empty() && value.bytes().all(|b| b.is_ascii_graphic()))
            .context("missing or malformed user delegation key field")
    };
    let (oid, tid) = (get("SignedOid")?, get("SignedTid")?);
    let (start, end) = (get("SignedStart")?, get("SignedExpiry")?);
    let (service, version) = (get("SignedService")?, get("SignedVersion")?);
    ensure!(service == "b", "the delegation key is not for Blob");
    let (path, resource) = match blob {
        Some(blob) => (format!("/blob/{account}/{container}/{blob}"), "b"),
        None => (format!("/blob/{account}/{container}"), "c"),
    };
    let string_to_sign = format!(
        "{permissions}\n{signed_start}\n{expiry}\n{path}\n{oid}\n{tid}\n{start}\n{end}\n{service}\n{version}\n\n\n\n\nhttps\n{VERSION}\n{resource}\n\n\n{}",
        overrides.join("\n"),
    );
    let value = STANDARD
        .decode(get("Value")?)
        .map_err(|_| anyhow!("invalid user delegation key encoding"))?;
    ensure!(
        (32..=64).contains(&value.len()),
        "invalid user delegation key size"
    );
    let mut mac =
        Hmac::<Sha256>::new_from_slice(&value).map_err(|_| anyhow!("invalid HMAC key"))?;
    mac.update(string_to_sign.as_bytes());
    let signature = STANDARD.encode(mac.finalize().into_bytes());
    let mut fields = vec![
        ("sv", VERSION),
        ("sr", resource),
        ("sp", permissions),
        ("spr", "https"),
        ("se", expiry),
        ("skoid", oid),
        ("sktid", tid),
        ("skt", start),
        ("ske", end),
        ("sks", service),
        ("skv", version),
        ("sig", &signature),
    ];
    if !signed_start.is_empty() {
        fields.push(("st", signed_start));
    }
    fields.extend(
        SAS_RESPONSE_FIELDS
            .into_iter()
            .zip(overrides)
            .filter(|(_, value)| !value.is_empty()),
    );
    Ok(sas_query(&fields))
}

fn request(client: &Client, method: Method, url: Url) -> RequestBuilder {
    client
        .request(method, url)
        .header("x-ms-version", VERSION)
        .header("x-ms-date", httpdate::fmt_http_date(SystemTime::now()))
}

fn send(request: RequestBuilder, phase: &'static str) -> Result<Response> {
    sent(request.send(), phase)
}

fn sent(response: reqwest::Result<Response>, phase: &'static str) -> Result<Response> {
    response.map_err(|error| {
        let kind = if error.is_timeout() {
            "timeout"
        } else if error.is_connect() {
            "connection or TLS failure"
        } else {
            "HTTP transport failure"
        };
        anyhow!("{phase}: {kind}")
    })
}

fn require_status(response: &Response, expected: u16, phase: &'static str) -> Result<()> {
    let status = response.status().as_u16();
    ensure!(
        status == expected,
        "{phase}: HTTP {status}, expected {expected} ({:?})",
        ErrorCode::from_value(header_text(response.headers(), "x-ms-error-code"))
    );
    Ok(())
}

fn read_bounded(reader: impl Read) -> Result<Vec<u8>> {
    let mut bytes = Vec::new();
    reader
        .take(MAX_CASSETTE_BYTES + 1)
        .read_to_end(&mut bytes)
        .map_err(|_| anyhow!("could not read bounded contract input"))?;
    ensure!(
        bytes.len() as u64 <= MAX_CASSETTE_BYTES,
        "contract input is too large"
    );
    Ok(bytes)
}

fn get_delegation_key(
    client: &Client,
    endpoint: &Url,
    bearer: &str,
    start: Option<&str>,
    expiry: Option<&str>,
) -> Result<Response> {
    let url = endpoint.join("?restype=service&comp=userdelegationkey")?;
    let mut body = "<KeyInfo>".to_owned();
    for (name, value) in [("Start", start), ("Expiry", expiry)] {
        if let Some(value) = value {
            std::fmt::Write::write_fmt(&mut body, format_args!("<{name}>{value}</{name}>"))?;
        }
    }
    body.push_str("</KeyInfo>");
    send(
        request(client, Method::POST, url)
            .bearer_auth(bearer)
            .header("content-type", "application/xml")
            .body(body),
        "get user delegation key",
    )
}

fn delegation_key_document(
    client: &Client,
    endpoint: &Url,
    bearer: &str,
    expiry: &str,
) -> Result<String> {
    let key = get_delegation_key(client, endpoint, bearer, Some(&iso(-120)), Some(expiry))?;
    require_status(&key, 200, "get user delegation key")?;
    String::from_utf8(read_bounded(key)?)
        .map_err(|_| anyhow!("invalid user delegation key encoding"))
}

fn with_fresh_container<T>(
    client: &Client,
    endpoint: &Url,
    bearer: &str,
    observe: impl FnOnce(&str, Url) -> Result<T>,
) -> Result<T> {
    let container = format!("azuifer-contract-{}", Uuid::new_v4().simple());
    let container_url = endpoint.join(&format!("{container}?restype=container"))?;
    let blob_url = endpoint.join(&format!("{container}/{BLOB}"))?;

    let created = send(
        request(client, Method::PUT, container_url.clone())
            .bearer_auth(bearer)
            .header("content-length", "0"),
        "create test container",
    )?;
    require_status(&created, 201, "create test container")?;

    let outcome = observe(&container, blob_url);
    let cleanup = remove_test_container(client, container_url, bearer);
    finish_cleanup(outcome, cleanup)
}

fn remove_test_container(client: &Client, container_url: Url, bearer: &str) -> Result<()> {
    let response = send(
        request(client, Method::DELETE, container_url).bearer_auth(bearer),
        "delete test container",
    )?;
    // Some journeys delete their own container before cleanup.
    if response.status().as_u16() == 404
        && header_text(response.headers(), "x-ms-error-code") == Some("ContainerNotFound")
    {
        return Ok(());
    }
    require_status(&response, 202, "delete test container")
}

fn finish_cleanup<T>(outcome: Result<T>, cleanup: Result<()>) -> Result<T> {
    match (outcome, cleanup) {
        (Ok(cassette), Ok(())) => Ok(cassette),
        (Ok(_), Err(error)) | (Err(error), Ok(())) => Err(error),
        (Err(scenario), Err(cleanup)) => {
            Err(anyhow!("{scenario:#}; cleanup also failed: {cleanup:#}"))
        }
    }
}

fn observe_blob(
    client: &Client,
    account: &str,
    endpoint: &Url,
    bearer: &str,
    source: Source,
) -> Result<Cassette> {
    with_fresh_container(client, endpoint, bearer, |container, blob_url| {
        let put = send(
            request(client, Method::PUT, blob_url.clone())
                .bearer_auth(bearer)
                .header("x-ms-blob-type", "BlockBlob")
                .header("content-type", "text/plain")
                .header("x-ms-meta-purpose", "azuifer-contract")
                .body(BLOB_BYTES),
            "seed test blob",
        )?;
        require_status(&put, 201, "seed test blob")?;
        let etag = header_text(put.headers(), "etag")
            .filter(|tag| tag.starts_with('"') && tag.ends_with('"') && tag.len() > 2)
            .context("seed test blob: missing or malformed ETag")?;

        let expiry = iso(900);
        let key = delegation_key_document(client, endpoint, bearer, &expiry)?;
        let mut signed_url = blob_url;
        signed_url.set_query(Some(&sign_sas(
            &key,
            (account, container, Some(BLOB)),
            "r",
            &expiry,
        )?));

        let mut exchanges = Vec::with_capacity(STEPS.len());
        for step in STEPS {
            let method = match step {
                Step::Head => Method::HEAD,
                Step::Range | Step::ReadBack => Method::GET,
                Step::DeniedDelete => Method::DELETE,
            };
            let mut probe = request(client, method, signed_url.clone());
            if step == Step::Range {
                probe = probe.header("range", format!("bytes={RANGE_START}-{RANGE_END}"));
            }
            let response = send(probe, "send SAS probe").with_context(|| format!("{step:?}"))?;
            let status = response.status().as_u16();
            let headers = response.headers().clone();
            let body = read_bounded(response).with_context(|| format!("{step:?}"))?;
            exchanges.push(Exchange::observe(step, status, &headers, &body, etag));
        }
        let exchanges = exchanges
            .try_into()
            .map_err(|_| anyhow!("missing SAS probe results"))?;
        Ok(Cassette::new(source, exchanges))
    })
}

fn observe_local() -> Result<Cassette> {
    with_local(|client, endpoint, bearer| {
        observe_blob(client, ACCOUNT, endpoint, bearer, Source::Synthetic)
    })
}

fn reviewed_sas() -> Result<Cassette> {
    Cassette::load_azure(SAS_CASSETTE)
}

fn with_local<T>(observe: impl FnOnce(&Client, &Url, &str) -> Result<T>) -> Result<T> {
    with_local_service(Service::Blob, observe)
}

fn with_local_service<T>(
    service: Service,
    observe: impl FnOnce(&Client, &Url, &str) -> Result<T>,
) -> Result<T> {
    let service = service.name();
    let server = Server::start(
        &[
            "--in-memory",
            "--services",
            service,
            "--tls-generate",
            "--oauth",
            "basic",
        ],
        &[],
    );
    let trusting = client(Some(&server.generated_certificate()));
    let endpoint = Url::parse(&format!("{}/{ACCOUNT}/", server.url(service)))?;
    observe(&trusting, &endpoint, &basic_token())
}

#[test]
fn replay_blob_sas_contract() -> Result<()> {
    reviewed_sas()?.compare(&observe_local()?)
}

#[test]
#[ignore = "optional saved SAS cassette: set AZUIFER_CONTRACT_REPLAY_FILE"]
fn replay_saved_blob_sas_contract() -> Result<()> {
    let path = std::env::var_os("AZUIFER_CONTRACT_REPLAY_FILE")
        .context("AZUIFER_CONTRACT_REPLAY_FILE must select a saved SAS cassette")?;
    let file = File::open(path)
        .map_err(|error| anyhow!("could not open replay cassette ({:?})", error.kind()))?;
    Cassette::load(&read_bounded(file)?)?.compare(&observe_local()?)
}

#[test]
fn replay_detects_a_changed_range_contract() -> Result<()> {
    let mut changed: serde_json::Value = serde_json::from_slice(SAS_CASSETTE)?;
    changed["exchanges"][1]["content_length"] = serde_json::json!(99);
    let changed = Cassette::load(&serde_json::to_vec(&changed)?)?;
    let error = changed
        .compare(&observe_local()?)
        .expect_err("different response lengths must fail replay");
    assert!(error.to_string().starts_with("Range:"));
    Ok(())
}
