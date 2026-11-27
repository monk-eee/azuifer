use super::{
    BLOB_BYTES, Body, Exchange, PURPOSE, Readback, Step, request, seed, sign_sas, signed_url,
};
use crate::contracts::cassette::{Header, Media, XmlEtag, echoed, media, project_xml};
use anyhow::{Context as _, Result};
use reqwest::{Method, Url, blocking::Client};
use serde::{Deserialize, Serialize};

const PREFIX: &str = "docs/";
const GROUP: &str = "docs/group/";
const DIRECT: &str = "docs/a.txt";
const NESTED: &str = "docs/group/b.txt";
const DELIMITER: &str = "/";
const LIMIT: &str = "1";

#[derive(Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
enum Name {
    Direct,
    Group,
    Nested,
    Other,
}

impl Name {
    fn observed(name: &str) -> Self {
        match name {
            DIRECT => Self::Direct,
            GROUP => Self::Group,
            NESTED => Self::Nested,
            _ => Self::Other,
        }
    }
}

#[derive(Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
enum Marker {
    Missing,
    End,
    More,
}

#[derive(Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
enum Entry {
    Blob {
        name: Name,
        length: Option<u64>,
        etag: XmlEtag,
        block_blob: bool,
        purpose_matches: bool,
    },
    Prefix {
        name: Name,
    },
    Other {},
}

#[derive(Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub(super) struct Page {
    media: Media,
    service_endpoint: Header,
    container_name: Header,
    prefix: Header,
    delimiter: Header,
    max_results: Option<u32>,
    echoed_marker: Header,
    next_marker: Marker,
    entries: Vec<Entry>,
}

impl Page {
    pub(super) fn matches_fixture(&self, step: Step) -> bool {
        if self.media != Media::Xml
            || self.service_endpoint != Header::Matches
            || self.container_name != Header::Matches
            || self.prefix != Header::Matches
            || self.delimiter != Header::Matches
            || self.max_results != Some(1)
        {
            return false;
        }
        match (step, self.entries.as_slice(), &self.next_marker) {
            (Step::ListNext, [Entry::Prefix { name: Name::Group }], Marker::End) => true,
            (
                Step::ListFirst | Step::ListNested,
                [
                    Entry::Blob {
                        name,
                        length: Some(length),
                        etag: XmlEtag::Matches | XmlEtag::UnquotedMatch,
                        block_blob: true,
                        purpose_matches: true,
                    },
                ],
                next,
            ) => {
                *length == BLOB_BYTES.len() as u64
                    && matches!(
                        (step, name, next),
                        (Step::ListFirst, Name::Direct, Marker::More)
                            | (Step::ListNested, Name::Nested, Marker::End)
                    )
            }
            _ => false,
        }
    }
}

#[derive(Deserialize)]
#[serde(rename_all = "PascalCase")]
struct WirePage {
    #[serde(rename = "@ServiceEndpoint")]
    service_endpoint: Option<String>,
    #[serde(rename = "@ContainerName")]
    container_name: Option<String>,
    prefix: Option<String>,
    delimiter: Option<String>,
    max_results: Option<u32>,
    marker: Option<String>,
    next_marker: Option<String>,
    blobs: WireBlobs,
}

#[derive(Deserialize)]
struct WireBlobs {
    #[serde(rename = "$value", default)]
    entries: Vec<WireEntry>,
}

#[derive(Deserialize)]
enum WireEntry {
    Blob {
        #[serde(rename = "Name")]
        name: String,
        #[serde(rename = "Properties")]
        properties: WireProperties,
        #[serde(rename = "Metadata")]
        metadata: Option<WireMetadata>,
    },
    BlobPrefix {
        #[serde(rename = "Name")]
        name: String,
    },
    #[serde(other)]
    Other,
}

#[derive(Deserialize)]
#[serde(rename_all = "PascalCase")]
struct WireProperties {
    #[serde(rename = "Content-Length")]
    length: Option<u64>,
    etag: Option<String>,
    blob_type: Option<String>,
}

#[derive(Deserialize)]
struct WireMetadata {
    purpose: Option<String>,
}

struct Listing<'a> {
    client: &'a Client,
    endpoint: &'a Url,
    container: &'a str,
    url: Url,
    direct_etag: String,
    nested_etag: String,
}

impl Listing<'_> {
    fn wire(
        &self,
        sas: &str,
        prefix: &str,
        marker: Option<&str>,
    ) -> reqwest::blocking::RequestBuilder {
        let mut url = signed_url(self.url.clone(), sas);
        url.query_pairs_mut()
            .extend_pairs([
                ("restype", "container"),
                ("comp", "list"),
                ("prefix", prefix),
                ("delimiter", DELIMITER),
                ("maxresults", LIMIT),
                ("include", "metadata"),
            ])
            .extend_pairs(marker.map(|value| ("marker", value)));
        request(self.client, Method::GET, url)
    }

    fn page(&self, raw: &WirePage, media: Media, prefix: &str, marker: Option<&str>) -> Page {
        let entries = raw
            .blobs
            .entries
            .iter()
            .map(|entry| match entry {
                WireEntry::Blob {
                    name,
                    properties,
                    metadata,
                } => {
                    let name = Name::observed(name);
                    let expected = match name {
                        Name::Direct => Some(self.direct_etag.as_str()),
                        Name::Nested => Some(self.nested_etag.as_str()),
                        _ => None,
                    };
                    let etag = XmlEtag::observe(properties.etag.as_deref(), expected);
                    Entry::Blob {
                        name,
                        length: properties.length,
                        etag,
                        block_blob: properties.blob_type.as_deref() == Some("BlockBlob"),
                        purpose_matches: metadata
                            .as_ref()
                            .and_then(|value| value.purpose.as_deref())
                            == Some(PURPOSE),
                    }
                }
                WireEntry::BlobPrefix { name } => Entry::Prefix {
                    name: Name::observed(name),
                },
                WireEntry::Other => Entry::Other {},
            })
            .collect();
        Page {
            media,
            service_endpoint: echoed(
                raw.service_endpoint.as_deref(),
                Some(self.endpoint.as_str()),
            ),
            container_name: echoed(raw.container_name.as_deref(), Some(self.container)),
            prefix: echoed(raw.prefix.as_deref(), Some(prefix)),
            delimiter: echoed(raw.delimiter.as_deref(), Some(DELIMITER)),
            max_results: raw.max_results,
            echoed_marker: echoed(raw.marker.as_deref(), marker),
            next_marker: match raw.next_marker.as_deref() {
                Some("") => Marker::End,
                Some(_) => Marker::More,
                None => Marker::Missing,
            },
            entries,
        }
    }

    fn list(
        &self,
        step: Step,
        sas: &str,
        prefix: &str,
        marker: Option<&str>,
    ) -> Result<(Exchange, Option<String>)> {
        let mut next = None;
        let exchange =
            Exchange::observe(step, self.wire(sas, prefix, marker), |headers, bytes| {
                let raw: WirePage = project_xml(bytes, "EnumerationResults")?;
                let page = self.page(&raw, media(headers), prefix, marker);
                next = raw.next_marker.filter(|value| !value.is_empty());
                Ok(Body::List(page))
            })?;
        Ok((exchange, next))
    }
}

pub(super) fn observe(
    client: &Client,
    key: &str,
    expiry: &str,
    account: &str,
    endpoint: &Url,
    container: &str,
    bearer: &str,
) -> Result<Vec<Exchange>> {
    let blob = |name| endpoint.join(&format!("{container}/{name}"));
    let nested_url = blob(NESTED)?;
    let listing = Listing {
        client,
        endpoint,
        container,
        url: endpoint.join(container)?,
        direct_etag: seed(client, &blob(DIRECT)?, bearer)?,
        nested_etag: seed(client, &nested_url, bearer)?,
    };
    seed(client, &blob("outside.txt")?, bearer)?;
    let scope = (account, container, None);
    let list_sas = sign_sas(key, scope, "l", expiry)?;
    let read_sas = sign_sas(key, scope, "r", expiry)?;
    let (first, next) = listing.list(Step::ListFirst, &list_sas, PREFIX, None)?;
    let next = next.with_context(|| format!("list first page lacks a continuation: {first:?}"))?;
    let (second, _) = listing.list(Step::ListNext, &list_sas, PREFIX, Some(&next))?;
    let (nested, _) = listing.list(Step::ListNested, &list_sas, GROUP, None)?;
    let wrong_read = Exchange::observe(
        Step::ReadDenied,
        request(
            client,
            Method::GET,
            signed_url(nested_url.clone(), &list_sas),
        ),
        |_, _| Ok(Body::Other {}),
    )?;
    let wrong_list = Exchange::observe(
        Step::ListDenied,
        listing.wire(&read_sas, PREFIX, None),
        |_, _| Ok(Body::Other {}),
    )?;
    let read = Exchange::observe(
        Step::ReadNested,
        request(client, Method::GET, signed_url(nested_url, &read_sas)),
        |headers, bytes| {
            Ok(Body::Read(Readback::observe(
                Step::ReadNested,
                headers,
                bytes,
                &listing.nested_etag,
            )))
        },
    )?;
    Ok(vec![first, second, nested, wrong_read, wrong_list, read])
}
