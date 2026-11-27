use super::{
    Body, Details, ErrorCode, Header, Probe, Response, Step, header, header_text, lists::Marker,
};
use crate::contracts::{
    cassette::{Media, XmlEtag, echoed, media, project_xml},
    delete_test_container, finish_cleanup, request, require_status,
};
use anyhow::{Context as _, Result};
use reqwest::{Method, Url, header::HeaderMap};
use serde::{Deserialize, Serialize};

const PURPOSE: &str = "updated";

fn tracked_name(companion: &str) -> String {
    format!("{companion}-tracked")
}

#[derive(Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
enum Container {
    Companion,
    Tracked,
    Other,
}

#[derive(Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
struct Entry {
    name: Container,
    purpose: Header,
    tracked_etag: Option<XmlEtag>,
}

#[derive(Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub(super) struct ContainerPage {
    media: Media,
    service_endpoint: Header,
    prefix: Header,
    max_results: Option<u32>,
    echoed_marker: Header,
    next_marker: Marker,
    entries: Vec<Entry>,
}

#[derive(Deserialize)]
#[serde(rename_all = "PascalCase")]
struct WirePage {
    #[serde(rename = "@ServiceEndpoint")]
    service_endpoint: Option<String>,
    prefix: Option<String>,
    max_results: Option<u32>,
    marker: Option<String>,
    next_marker: Option<String>,
    containers: WireContainers,
}

#[derive(Deserialize)]
struct WireContainers {
    #[serde(rename = "Container", default)]
    entries: Vec<WireContainer>,
}

#[derive(Deserialize)]
#[serde(rename_all = "PascalCase")]
struct WireContainer {
    name: String,
    metadata: Option<WireMetadata>,
    properties: WireProperties,
}

#[derive(Deserialize)]
struct WireMetadata {
    purpose: Option<String>,
}

#[derive(Deserialize)]
struct WireProperties {
    #[serde(rename = "Etag")]
    etag: Option<String>,
}

pub(super) fn project(
    url: &Url,
    reference: Option<&str>,
    headers: &HeaderMap,
    bytes: &[u8],
) -> Result<(ContainerPage, Option<String>)> {
    let response: WirePage = project_xml(bytes, "EnumerationResults")?;
    let query = |name| {
        url.query_pairs()
            .find(|(key, _)| key == name)
            .map(|(_, value)| value)
    };
    let prefix = query("prefix").context("container list probe needs its unique prefix")?;
    let sent_marker = query("marker");
    let mut endpoint = url.clone();
    endpoint.set_query(None);
    let tracked = tracked_name(&prefix);
    let entries = response
        .containers
        .entries
        .into_iter()
        .map(|wire| {
            let (name, tracked_etag) = if wire.name == tracked {
                (
                    Container::Tracked,
                    Some(XmlEtag::observe(wire.properties.etag.as_deref(), reference)),
                )
            } else if wire.name == prefix {
                (Container::Companion, None)
            } else {
                (Container::Other, None)
            };
            Entry {
                name,
                purpose: echoed(
                    wire.metadata.and_then(|m| m.purpose).as_deref(),
                    Some(PURPOSE),
                ),
                tracked_etag,
            }
        })
        .collect();
    let page = ContainerPage {
        media: media(headers),
        service_endpoint: echoed(
            response.service_endpoint.as_deref(),
            Some(endpoint.as_str()),
        ),
        prefix: echoed(response.prefix.as_deref(), Some(&prefix)),
        max_results: response.max_results,
        echoed_marker: echoed(response.marker.as_deref(), sent_marker.as_deref()),
        next_marker: Marker::observe(response.next_marker.as_deref()),
        entries,
    };
    Ok((page, response.next_marker.filter(|value| !value.is_empty())))
}

pub(super) fn matches_listing(response: &Response) -> bool {
    let Body::ContainerList(page) = &response.body else {
        return false;
    };
    page.media == Media::Xml
        && page.service_endpoint == Header::Matches
        && page.prefix == Header::Matches
        && page.max_results == Some(1)
        && matches!(
            (response.step, &page.next_marker, page.entries.as_slice()),
            (
                Step::ListContainersFirst,
                Marker::Present,
                [Entry {
                    name: Container::Companion,
                    purpose: Header::Missing,
                    ..
                }]
            ) | (
                Step::ListContainersNext,
                Marker::Empty,
                [Entry {
                    name: Container::Tracked,
                    purpose: Header::Matches,
                    ..
                }]
            )
        )
}

pub(super) fn details(step: Step, headers: &HeaderMap) -> Option<Details> {
    matches!(step, Step::ReadContainerMetadata | Step::HeadContainer).then(|| {
        let is = |name, expected: &str| header(headers, name, |value| value == expected);
        Details::Container {
            purpose: is("x-ms-meta-purpose", PURPOSE),
            removed: is("x-ms-meta-remove", "present"),
            lease_state: is("x-ms-lease-state", "available"),
            lease_status: is("x-ms-lease-status", "unlocked"),
            public_access: is("x-ms-blob-public-access", "private"),
        }
    })
}

pub(super) fn matches_fixture(response: &Response) -> bool {
    match response.step {
        Step::RejectDuplicateContainer => {
            response.status == 409 && response.error_header == ErrorCode::ContainerAlreadyExists
        }
        Step::ReadMissingContainer => {
            response.status == 404 && response.error_header == ErrorCode::ContainerNotFound
        }
        Step::ReadContainerMetadata | Step::HeadContainer => matches!(
            &response.details,
            Some(Details::Container {
                purpose: Header::Matches,
                removed: Header::Missing,
                ..
            })
        ),
        _ => true,
    }
}

impl Probe<'_> {
    pub(super) fn container_lifecycle(&mut self, endpoint: &Url, companion: &str) -> Result<()> {
        let url = endpoint.join(&format!("{}?restype=container", tracked_name(companion)))?;
        self.url = url.clone();
        let outcome = self.observe_container(endpoint, companion);
        let cleanup = delete_test_container(self.client, url, self.bearer).and_then(|response| {
            if response.status().as_u16() == 404
                && header_text(response.headers(), "x-ms-error-code") == Some("ContainerNotFound")
            {
                // The tracked container is deleted by the recorded journey.
                Ok(())
            } else {
                require_status(&response, 202, "delete tracked test container")
            }
        });
        finish_cleanup(outcome, cleanup)
    }

    fn observe_container(&mut self, endpoint: &Url, companion: &str) -> Result<()> {
        let empty_put = |probe: &Self| probe.request(Method::PUT).header("content-length", "0");
        let created = self
            .record(
                Step::CreateContainer,
                empty_put(self)
                    .header("x-ms-meta-purpose", "initial")
                    .header("x-ms-meta-remove", "present"),
                None,
            )?
            .etag
            .context("create container lacks ETag")?;
        self.record(
            Step::RejectDuplicateContainer,
            empty_put(self),
            Some(&created),
        )?;
        let updated = self
            .record(
                Step::SetContainerMetadata,
                empty_put(self)
                    .query(&[("comp", "metadata")])
                    .header("x-ms-meta-purpose", PURPOSE),
                Some(&created),
            )?
            .etag
            .context("set container metadata lacks ETag")?;
        self.record(
            Step::ReadContainerMetadata,
            self.request(Method::GET).query(&[("comp", "metadata")]),
            Some(&updated),
        )?;
        self.record(
            Step::HeadContainer,
            self.request(Method::HEAD),
            Some(&updated),
        )?;
        let listing = |probe: &Self| {
            request(probe.client, Method::GET, endpoint.clone())
                .bearer_auth(probe.bearer)
                .query(&[
                    ("comp", "list"),
                    ("maxresults", "1"),
                    ("prefix", companion),
                    ("include", "metadata"),
                ])
        };
        let marker = self
            .record(Step::ListContainersFirst, listing(self), Some(&updated))?
            .next_marker
            .context("first container page lacks a continuation")?;
        self.record(
            Step::ListContainersNext,
            listing(self).query(&[("marker", marker)]),
            Some(&updated),
        )?;
        self.record(
            Step::DeleteContainer,
            self.request(Method::DELETE),
            Some(&updated),
        )?;
        self.record(Step::ReadMissingContainer, self.request(Method::GET), None)?;
        Ok(())
    }
}
