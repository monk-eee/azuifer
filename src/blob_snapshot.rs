//! Snapshots, versions, soft delete, and listings of them at the HTTP edge
//! (ADR-0018): which retained state a request addresses, how a delete is
//! scoped, and the responses of the operations that read or change them.

use crate::{
    auth::{Query, header},
    blob_exec::{self, Context},
    blob_tags,
    domain::{ContainerKey, Error, Include, ListRequest, Result},
    lease::LeaseId,
    protocol::Operation,
    respond::{self, blob_properties, empty, entity_response, http_date, set},
    server::App,
    stamp::Ticks,
    store::{Deletion, ExtendedListing, Listed, Selected},
    wire::Xml,
};
use axum::{body::Body, http::HeaderMap, http::StatusCode, response::Response};

/// The retained state of a blob a request names with `snapshot` or `versionid`.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum Selector {
    Snapshot(Ticks),
    Version(Ticks),
}

/// `x-ms-delete-snapshots`: refuse to delete a blob that has snapshots, delete
/// them with the blob, or delete only the snapshots.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub(crate) enum DeleteSnapshots {
    #[default]
    Refuse,
    Include,
    Only,
}

/// What Delete Blob removes: the blob (and per `snapshots` its snapshots), one
/// snapshot, or one version.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub(crate) struct Removal {
    pub(crate) selector: Option<Selector>,
    pub(crate) snapshots: DeleteSnapshots,
}

pub(crate) fn selector(query: &Query) -> Result<Option<Selector>> {
    let snapshot = query.get("snapshot").map(|time| Ticks::parse(time));
    let version = query.get("versionid").map(|id| Ticks::parse(id));
    match (snapshot, version) {
        (None, None) => Ok(None),
        (Some(time), None) => Ok(Some(Selector::Snapshot(time?))),
        (None, Some(id)) => Ok(Some(Selector::Version(id?))),
        (Some(_), Some(_)) => Err(Error::InvalidQuery),
    }
}

pub(crate) fn removal(headers: &HeaderMap, query: &Query) -> Result<Removal> {
    let selector = selector(query)?;
    let snapshots = match header(headers, "x-ms-delete-snapshots")? {
        None => DeleteSnapshots::Refuse,
        Some("include") => DeleteSnapshots::Include,
        Some("only") => DeleteSnapshots::Only,
        Some(_) => return Err(Error::InvalidHeader),
    };
    // Azure rejects the option when the request already names one retained state.
    if selector.is_some() && snapshots != DeleteSnapshots::Refuse {
        return Err(Error::InvalidHeader);
    }
    Ok(Removal {
        selector,
        snapshots,
    })
}

/// Whether a listing needs the history tables instead of the plain listing.
pub(crate) fn is_extended(include: &[Include]) -> bool {
    include.iter().any(|item| {
        matches!(
            item,
            Include::Snapshots | Include::Versions | Include::Deleted | Include::Tags
        )
    })
}

pub(crate) fn delete_response(outcome: Deletion) -> Result<Response> {
    let mut response = empty(StatusCode::ACCEPTED);
    set(
        response.headers_mut(),
        "x-ms-delete-type-permanent",
        if outcome == Deletion::Permanent {
            "true"
        } else {
            "false"
        },
    )?;
    Ok(response)
}

pub(crate) async fn list(
    app: &App,
    key: ContainerKey,
    request: ListRequest,
    lease: Option<LeaseId>,
) -> Result<Response> {
    if request.include.contains(&Include::Uncommitted) {
        return Err(Error::Unsupported);
    }
    let endpoint = blob_exec::storage_endpoint(app, key.account.as_str());
    let name = key.name.as_str().to_owned();
    let (prefix, delimiter, limit) = (
        request.page.prefix.clone(),
        request.delimiter.clone(),
        request.page.limit,
    );
    let include = request.include.clone();
    let listing = app.store.list_extended(key, request, lease).await?;
    list_response(
        &endpoint,
        &name,
        (&prefix, delimiter.as_deref(), limit),
        listing,
        &include,
    )
}

fn list_response(
    endpoint: &str,
    container: &str,
    (prefix, delimiter, limit): (&str, Option<&str>, u32),
    listing: ExtendedListing,
    include: &[Include],
) -> Result<Response> {
    let mut xml = Xml::root(
        "EnumerationResults",
        &[("ServiceEndpoint", endpoint), ("ContainerName", container)],
    );
    if !prefix.is_empty() {
        xml.element("Prefix", prefix);
    }
    xml.element("MaxResults", &limit.to_string());
    if let Some(delimiter) = delimiter {
        xml.element("Delimiter", delimiter);
    }
    xml.open("Blobs");
    for entry in listing.entries {
        match entry {
            Listed::Prefix(name) => {
                xml.open("BlobPrefix");
                xml.element("Name", &name);
                xml.close("BlobPrefix");
            }
            Listed::Blob(blob) => {
                xml.open("Blob");
                xml.element("Name", &blob.name);
                if blob.deleted.is_some() {
                    xml.element("Deleted", "true");
                }
                if let Some(snapshot) = blob.snapshot {
                    xml.element("Snapshot", &snapshot.text());
                }
                if let Some(version) = blob.version {
                    xml.element("VersionId", &version.text());
                }
                if blob.current_version {
                    xml.element("IsCurrentVersion", "true");
                }
                let mut extra = Vec::new();
                if let Some(deleted) = &blob.deleted {
                    extra.push(("DeletedTime", http_date(deleted.at)?));
                    extra.push(("RemainingRetentionDays", deleted.remaining_days.to_string()));
                }
                if !blob.tags.is_empty() {
                    extra.push(("TagCount", blob.tags.len().to_string()));
                }
                blob_properties(
                    &mut xml,
                    &blob.info,
                    include.contains(&Include::Copy),
                    false,
                    &extra,
                )?;
                if include.contains(&Include::Metadata) {
                    xml.metadata(blob.info.metadata);
                }
                if include.contains(&Include::Tags) && !blob.tags.is_empty() {
                    xml.open("Tags");
                    blob_tags::write_tag_set(&mut xml, &blob.tags);
                    xml.close("Tags");
                }
                xml.close("Blob");
            }
        }
    }
    xml.close("Blobs");
    xml.element("NextMarker", &listing.next);
    Ok(xml.finish("EnumerationResults", StatusCode::OK))
}

fn read_selected_response(
    selected: Selected,
    selector: Selector,
    metadata_only: bool,
    ctx: &Context<'_>,
) -> Result<Response> {
    let Selected { download, current } = selected;
    let mut response = if metadata_only {
        respond::blob_metadata_response(download)?
    } else {
        respond::download_response(download, ctx.credentials.overrides())?
    };
    if matches!(selector, Selector::Version(_)) {
        set(
            response.headers_mut(),
            "x-ms-is-current-version",
            if current { "true" } else { "false" },
        )?;
    }
    Ok(response)
}

/// Runs the operations of this module and forwards tag and batch operations.
pub(crate) async fn execute(
    app: &App,
    op: Operation,
    body: Body,
    ctx: &Context<'_>,
) -> Result<Response> {
    let store = &app.store;
    match op {
        Operation::SnapshotBlob(key, metadata, guard) => {
            let snapshot = store.snapshot_blob(key, metadata, guard).await?;
            let mut response = entity_response(StatusCode::CREATED, snapshot.entity)?;
            set(
                response.headers_mut(),
                "x-ms-snapshot",
                &snapshot.time.text(),
            )?;
            Ok(response)
        }
        Operation::UndeleteBlob(key) => {
            store.undelete_blob(key).await?;
            Ok(empty(StatusCode::OK))
        }
        Operation::ReadSelected(key, selector, options, metadata_only) => {
            let selected = store.read_selected(key, selector, options).await?;
            read_selected_response(selected, selector, metadata_only, ctx)
        }
        Operation::BlocksSelected(key, selector, kind, guard) => {
            blob_exec::block_list_response(store.blocks_selected(key, selector, kind, guard).await?)
        }
        other => blob_tags::execute(app, other, body, ctx).await,
    }
}
