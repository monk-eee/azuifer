use super::{
    VERSION,
    cassette::{
        ApiVersion, ErrorCode, Header, Media, Source, header, header_text, media, project_xml,
    },
    read_bounded, request, require_status, send, with_local,
};
use anyhow::{Context as _, Result, ensure};
use reqwest::{Method, Url, blocking::Client, header::HeaderMap};
use serde::{Deserialize, Serialize};
use std::{fs::File, path::Path};
use uuid::Uuid;

pub(super) const CASE: &str = "blob-account-read-only";

#[derive(Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub(super) struct AccountCassette {
    schema_version: u8,
    source: Source,
    api_version: ApiVersion,
    responses: [Exchange; 2],
}

#[derive(Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
struct Exchange {
    status: u16,
    api_version: Header,
    request_id: Header,
    error_header: ErrorCode,
    body: Body,
}

#[derive(Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
enum Body {
    AccountInformation {
        empty: bool,
        sku_lrs: Header,
        storage_v2: Header,
        hns_disabled: Header,
    },
    ServiceProperties {
        media: Media,
        logging_version_1: bool,
        hour_metrics_version_1: bool,
        minute_metrics_version_1: bool,
        cors_rules: Option<usize>,
        blob_soft_delete: Option<bool>,
        static_website: Option<bool>,
    },
}

// Deserialize only the selected fields; rule contents and arbitrary XML are never retained.
#[derive(Deserialize)]
#[serde(rename_all = "PascalCase")]
pub(super) struct WireProperties {
    logging: Option<WireVersion>,
    hour_metrics: Option<WireVersion>,
    minute_metrics: Option<WireVersion>,
    cors: Option<WireCors>,
    delete_retention_policy: Option<WireEnabled>,
    static_website: Option<WireEnabled>,
}

#[derive(Deserialize)]
struct WireVersion {
    #[serde(rename = "Version")]
    version: String,
    #[serde(rename = "Read")]
    read: Option<bool>,
    #[serde(rename = "Write")]
    write: Option<bool>,
    #[serde(rename = "Delete")]
    delete: Option<bool>,
    #[serde(rename = "Enabled")]
    enabled: Option<bool>,
    #[serde(rename = "RetentionPolicy")]
    retention: Option<WireEnabled>,
}

#[derive(Deserialize)]
struct WireCors {
    #[serde(rename = "CorsRule", default)]
    rules: Vec<serde::de::IgnoredAny>,
}

#[derive(Deserialize)]
struct WireEnabled {
    #[serde(rename = "Enabled")]
    enabled: bool,
}

impl WireProperties {
    pub(super) fn cors_count(&self) -> Option<usize> {
        self.cors.as_ref().map(|cors| cors.rules.len())
    }

    pub(super) fn analytics_disabled(&self) -> bool {
        let version_and_retention = |part: &WireVersion| {
            part.version == "1.0" && part.retention.as_ref().is_some_and(|r| !r.enabled)
        };
        self.logging.as_ref().is_some_and(|part| {
            version_and_retention(part) && [part.read, part.write, part.delete] == [Some(false); 3]
        }) && [&self.hour_metrics, &self.minute_metrics]
            .into_iter()
            .all(|metrics| {
                metrics
                    .as_ref()
                    .is_some_and(|part| version_and_retention(part) && part.enabled == Some(false))
            })
    }
}

impl AccountCassette {
    pub(super) fn validate(&self) -> Result<()> {
        ensure!(
            self.schema_version == 1,
            "unsupported account read cassette version"
        );
        ensure!(
            self.responses.iter().all(|response| response.status == 200
                && response.api_version == Header::Matches
                && response.request_id == Header::Matches
                && response.error_header == ErrorCode::Missing),
            "account reads did not use the expected wire contract"
        );
        ensure!(
            matches!(
                &self.responses[0].body,
                Body::AccountInformation {
                    empty: true,
                    sku_lrs: Header::Matches,
                    storage_v2: Header::Matches,
                    hns_disabled: Header::Matches,
                }
            ) && matches!(
                &self.responses[1].body,
                Body::ServiceProperties {
                    media: Media::Xml,
                    blob_soft_delete: Some(false),
                    static_website: Some(false),
                    cors_rules: Some(0),
                    ..
                }
            ),
            "observations did not describe the dedicated flat LRS profile: {:#?}",
            self.responses
        );
        Ok(())
    }

    pub(super) fn compare(&self, actual: &Self) -> Result<()> {
        self.validate()?;
        ensure!(
            self.responses == actual.responses,
            "{CASE}: expected {:#?}, observed {:#?}",
            self.responses,
            actual.responses
        );
        Ok(())
    }
}

pub(super) fn observe(
    client: &Client,
    endpoint: &Url,
    bearer: &str,
    source: Source,
) -> Result<AccountCassette> {
    let get = |kind, project: fn(&HeaderMap, &[u8]) -> Result<Body>| -> Result<Exchange> {
        let url = endpoint.join(&format!("?restype={kind}&comp=properties"))?;
        let wire = request(client, Method::GET, url).bearer_auth(bearer);
        let response = send(wire, "read Blob account or service properties")?;
        require_status(&response, 200, "read Blob account or service properties")?;
        let status = response.status().as_u16();
        let headers = response.headers().clone();
        let bytes = read_bounded(response)?;
        Ok(Exchange {
            status,
            api_version: header(&headers, "x-ms-version", |value| value == VERSION),
            request_id: header(&headers, "x-ms-request-id", |id| {
                Uuid::parse_str(id).is_ok()
            }),
            error_header: ErrorCode::from_value(header_text(&headers, "x-ms-error-code")),
            body: project(&headers, &bytes)?,
        })
    };
    let account = get("account", |headers, bytes| {
        Ok(Body::AccountInformation {
            empty: bytes.is_empty(),
            sku_lrs: header(headers, "x-ms-sku-name", |value| value == "Standard_LRS"),
            storage_v2: header(headers, "x-ms-account-kind", |value| value == "StorageV2"),
            hns_disabled: header(headers, "x-ms-is-hns-enabled", |value| value == "false"),
        })
    })?;
    let service = get("service", |headers, bytes| {
        let xml: WireProperties = project_xml(bytes, "StorageServiceProperties")?;
        let cors_rules = xml.cors_count();
        let version_1 =
            |wire: Option<WireVersion>| wire.is_some_and(|field| field.version == "1.0");
        Ok(Body::ServiceProperties {
            media: media(headers),
            logging_version_1: version_1(xml.logging),
            hour_metrics_version_1: version_1(xml.hour_metrics),
            minute_metrics_version_1: version_1(xml.minute_metrics),
            cors_rules,
            blob_soft_delete: xml.delete_retention_policy.map(|value| value.enabled),
            static_website: xml.static_website.map(|value| value.enabled),
        })
    })?;
    Ok(AccountCassette {
        schema_version: 1,
        source,
        api_version: ApiVersion::Baseline,
        responses: [account, service],
    })
}

pub(super) fn reviewed() -> Result<AccountCassette> {
    let path = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("tests")
        .join("contracts")
        .join("cassettes")
        .join(format!("{CASE}.json"));
    let file = File::open(path).context("could not open reviewed account read cassette")?;
    let cassette: AccountCassette =
        serde_json::from_slice(&read_bounded(file)?).map_err(|error| {
            anyhow::anyhow!("invalid account read cassette at line {}", error.line())
        })?;
    ensure!(
        cassette.source == Source::Azure,
        "expected recorded Azure account reads"
    );
    cassette.validate()?;
    Ok(cassette)
}

pub(super) fn observe_local() -> Result<AccountCassette> {
    with_local(|client, endpoint, bearer| observe(client, endpoint, bearer, Source::Synthetic))
}

#[test]
fn replay_blob_account_reads() -> Result<()> {
    reviewed()?.compare(&observe_local()?)
}
