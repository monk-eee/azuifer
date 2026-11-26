//! Runs a parsed, authorized Blob operation against the store and maps the
//! outcome to its Azure response.

use crate::{
    acl,
    blob_auth::Credentials,
    blob_copy, blob_external,
    blob_sas::Connection,
    blob_snapshot,
    checksum::{Checksums, Hasher},
    conditions::Conditions,
    delegation,
    domain::{AccountName, BlobInfo, BlobWrite, BlockList, ByteRange, CopyRecord, Error, Result},
    lease::LeaseAction,
    protocol::{self, ContainerView, Operation, SourceRequest, UploadOptions},
    respond::{self, empty, entity_response, set, write_response},
    server::App,
    service_props::ServiceProperties,
    store::{LeaseResult, PathRead, SourceBytes, Upload, Uploaded},
    wire::{self, Xml},
};
use axum::{
    body::{Body, to_bytes},
    http::{HeaderValue, StatusCode},
    response::Response,
};
use base64::{Engine as _, engine::general_purpose::STANDARD};
use futures_util::StreamExt as _;
use uuid::Uuid;

mod lifecycle;
mod page;

/// Facts about the request that operations need beyond their typed arguments.
pub(crate) struct Context<'a> {
    pub(crate) host: Option<&'a str>,
    pub(crate) account: &'a AccountName,
    pub(crate) credentials: &'a Credentials,
    pub(crate) connection: &'a Connection,
    pub(crate) request_id: &'a str,
}

pub(crate) async fn execute(
    app: &App,
    op: Operation,
    body: Body,
    ctx: &Context<'_>,
) -> Result<Response> {
    let store = &app.store;
    match op {
        Operation::ListContainers(account, page, metadata, deleted) => {
            let endpoint = storage_endpoint(app, account.as_str());
            let (limit, prefix) = (page.limit, page.prefix.clone());
            if deleted {
                let page = store.list_containers_with_deleted(account, page).await?;
                return lifecycle::list_containers(&endpoint, limit, &prefix, page, metadata);
            }
            let page = store.list_containers(account, page).await?;
            respond::list_containers(&endpoint, limit, &prefix, page, metadata)
        }
        Operation::GetServiceProperties(account) => {
            let properties = store.service_properties(account).await?;
            Ok(properties
                .to_xml()
                .finish("StorageServiceProperties", StatusCode::OK))
        }
        Operation::SetServiceProperties(account, options) => {
            let (bytes, _) = read_bounded(app, body, &options).await?;
            let update = ServiceProperties::parse(&bytes)?;
            store.set_service_properties(account, update).await?;
            Ok(empty(StatusCode::ACCEPTED))
        }
        Operation::UserDelegationKey(account, options) => {
            let Credentials::Bearer(principal) = ctx.credentials else {
                return Err(Error::AuthenticationFailed);
            };
            let (bytes, _) = read_bounded(app, body, &options).await?;
            delegation::respond(
                &app.config.delegation,
                &account,
                principal,
                &bytes,
                app.clock.now(),
                app.config.api_version.as_str(),
                ctx.request_id,
            )
        }
        Operation::ServiceStats => {
            // Azure serves replication statistics only from the read-only secondary endpoint.
            let secondary = crate::address::host_label("blob", ctx.host)
                .is_some_and(|label| label.ends_with(crate::address::SECONDARY));
            if !secondary {
                return Err(Error::Ext(
                    crate::blob_lifecycle::LifecycleError::InsufficientAccountPermissions,
                ));
            }
            let mut xml = Xml::root("StorageServiceStats", &[]);
            xml.open("GeoReplication");
            xml.element("Status", "live");
            xml.element("LastSyncTime", &httpdate::fmt_http_date(app.clock.now()));
            xml.close("GeoReplication");
            Ok(xml.finish("StorageServiceStats", StatusCode::OK))
        }
        Operation::AccountInfo => {
            let mut response = empty(StatusCode::OK);
            let headers = response.headers_mut();
            set(headers, "x-ms-sku-name", "Standard_LRS")?;
            set(headers, "x-ms-account-kind", "StorageV2")?;
            set(
                headers,
                "x-ms-is-hns-enabled",
                if app.config.hns_accounts.contains(ctx.account) {
                    "true"
                } else {
                    "false"
                },
            )?;
            Ok(response)
        }
        Operation::CreateContainer(key, options) => entity_response(
            StatusCode::CREATED,
            store.create_container(key, options).await?,
        ),
        Operation::ContainerProperties(key, lease, view) => {
            let info = store.container(key, lease).await?;
            respond::container_response(info, matches!(view, ContainerView::Metadata))
        }
        Operation::SetContainerMetadata(key, metadata, guard) => entity_response(
            StatusCode::OK,
            store.set_container_metadata(key, metadata, guard).await?,
        ),
        Operation::GetContainerAcl(key, lease) => {
            let info = store.container(key, lease).await?;
            respond::acl_response(info.entity, info.public_access, &info.identifiers)
        }
        Operation::SetContainerAcl(key, options, public_access, guard) => {
            let (bytes, _) = read_bounded(app, body, &options).await?;
            let identifiers = acl::parse(&bytes)?;
            entity_response(
                StatusCode::OK,
                store
                    .set_container_acl(key, public_access, identifiers, guard)
                    .await?,
            )
        }
        Operation::LeaseContainer(key, action, guard) => {
            lease_response(action, store.lease_container(key, action, guard).await?)
        }
        Operation::DeleteContainer(key, guard) => {
            store.delete_container(key, guard).await?;
            Ok(empty(StatusCode::ACCEPTED))
        }
        Operation::ListBlobs(key, request, lease) => {
            if blob_snapshot::is_extended(&request.include) {
                return blob_snapshot::list(app, key, request, lease).await;
            }
            let endpoint = storage_endpoint(app, key.account.as_str());
            let name = key.name.as_str().to_owned();
            let prefix = request.page.prefix.clone();
            let delimiter = request.delimiter.clone();
            let limit = request.page.limit;
            let include = request.include.clone();
            let hierarchical = app.config.hns_accounts.contains(&key.account);
            let listing = store.list_blobs(key, request, lease).await?;
            respond::list_blobs(
                &endpoint,
                &name,
                (&prefix, delimiter.as_deref(), limit),
                listing,
                &include,
                hierarchical,
            )
        }
        Operation::PutBlob(key, body_options, options) => {
            let upload = receive_upload(app, body, &body_options).await?;
            let checksum = upload.checksums.response(body_options.checksum);
            let entity = store.put_blob(key, options, upload).await?;
            write_response(entity_response(StatusCode::CREATED, entity)?, checksum)
        }
        Operation::PutBlobFromUrl(key, mut options, request) => {
            let (copy_properties, copy_tags) = (request.copy_properties, request.copy_tags);
            let (source, _) = read_source(app, ctx, request).await?;
            if copy_properties {
                options.headers = source.info.headers.clone();
            }
            if copy_tags {
                options.tags = source.info.tags.clone();
            }
            let checksum = ("content-md5", source.upload.checksums.md5_text());
            let entity = store.put_blob(key, options, source.upload).await?;
            write_response(entity_response(StatusCode::CREATED, entity)?, checksum)
        }
        Operation::PutBlock(key, id, options, lease) => {
            let upload = receive_upload(app, body, &options).await?;
            let checksum = upload.checksums.response(options.checksum);
            store.put_block(key, id, upload, lease).await?;
            write_response(empty(StatusCode::CREATED), checksum)
        }
        Operation::PutBlockFromUrl(key, id, lease, request) => {
            let (source, _) = read_source(app, ctx, request).await?;
            let checksum = ("content-md5", source.upload.checksums.md5_text());
            store.put_block(key, id, source.upload, lease).await?;
            write_response(empty(StatusCode::CREATED), checksum)
        }
        Operation::PutBlockList(key, body_options, options) => {
            let (bytes, checksums) = read_bounded(app, body, &body_options).await?;
            let blocks = protocol::parse_block_list(&bytes)?;
            let entity = store
                .commit_blocks(key, options, blocks, app.config.max_assembled_blob_bytes)
                .await?;
            write_response(
                entity_response(StatusCode::CREATED, entity)?,
                checksums.response(body_options.checksum),
            )
        }
        Operation::GetBlockList(key, kind, guard) => {
            block_list_response(store.blocks(key, kind, guard).await?)
        }
        Operation::ReadBlob(key, options) => match store.read_path(key, options).await? {
            PathRead::File(download) => {
                respond::download_response(*download, ctx.credentials.overrides())
            }
            PathRead::Directory(entity, metadata) => {
                wire::blob_directory_response(StatusCode::OK, entity, metadata)
            }
        },
        Operation::BlobMetadata(key, guard) => {
            let download = store
                .read_path(
                    key,
                    crate::domain::BlobRead {
                        guard,
                        range: None,
                        with_body: false,
                        range_checksum: None,
                    },
                )
                .await?;
            match download {
                PathRead::File(download) => respond::blob_metadata_response(*download),
                PathRead::Directory(entity, metadata) => {
                    wire::blob_directory_response(StatusCode::OK, entity, metadata)
                }
            }
        }
        Operation::SetBlobProperties(key, headers, md5, replace, guard, change) => {
            let (entity, sequence) = store
                .set_blob_properties(key, headers, md5, replace, guard, change)
                .await?;
            let mut response = entity_response(StatusCode::OK, entity)?;
            if let Some(sequence) = sequence {
                set(
                    response.headers_mut(),
                    "x-ms-blob-sequence-number",
                    &sequence.to_string(),
                )?;
            }
            Ok(response)
        }
        Operation::SetBlobMetadata(key, metadata, guard) => {
            let entity = store.set_blob_metadata(key, metadata, guard).await?;
            let mut response = entity_response(StatusCode::OK, entity)?;
            response.headers_mut().insert(
                "x-ms-request-server-encrypted",
                HeaderValue::from_static("false"),
            );
            Ok(response)
        }
        Operation::SetBlobTier(key, tier, lease) => {
            let rehydrating = store.set_blob_tier(key, tier, lease).await?;
            Ok(empty(if rehydrating {
                StatusCode::ACCEPTED
            } else {
                StatusCode::OK
            }))
        }
        Operation::LeaseBlob(key, action, conditions) => {
            lease_response(action, store.lease_blob(key, action, conditions).await?)
        }
        Operation::CopyBlob(key, options, request) => {
            let choices = (request.replace_metadata, request.copy_tags);
            let (source, display) = if is_external(app, ctx, &request) {
                read_source(app, ctx, request).await?
            } else {
                let resolved = resolve_source(app, ctx, &request).await?;
                if let Some(response) =
                    page::copy_ranges(app, &key, &options, &resolved, &request).await?
                {
                    return Ok(response);
                }
                read_resolved(app, resolved, request).await?
            };
            let write = copy_write(options, &source.info, choices, display);
            let id = write
                .copy
                .as_ref()
                .map(|copy| copy.id.clone())
                .unwrap_or_default();
            let entity = store.put_blob(key, write, source.upload).await?;
            let mut response = entity_response(StatusCode::ACCEPTED, entity)?;
            set(response.headers_mut(), "x-ms-copy-id", &id)?;
            set(response.headers_mut(), "x-ms-copy-status", "success")?;
            Ok(response)
        }
        Operation::AbortCopy(key, copy_id, lease) => {
            store.abort_copy(key, copy_id, lease).await?;
            Ok(empty(StatusCode::NO_CONTENT))
        }
        Operation::DeleteBlob(key, guard, removal) => {
            blob_snapshot::delete_response(store.delete_path(key, guard, removal).await?)
        }
        Operation::Page(operation) => page::execute(app, operation, body, ctx).await,
        Operation::Lifecycle(operation) => lifecycle::execute(app, operation, ctx).await,
        other => blob_snapshot::execute(app, other, body, ctx).await,
    }
}

pub(crate) fn storage_endpoint(app: &App, account: &str) -> String {
    format!("{}://{}/{account}/", app.config.scheme(), app.address)
}

/// Authorizes and reads a copy source: on this listener, or when the operator
/// allowed its host, on another one.
async fn read_source(
    app: &App,
    ctx: &Context<'_>,
    request: SourceRequest,
) -> Result<(SourceBytes, String)> {
    if is_external(app, ctx, &request) {
        return read_external(app, request).await;
    }
    let resolved = resolve_source(app, ctx, &request).await?;
    read_resolved(app, resolved, request).await
}

fn is_external(app: &App, ctx: &Context<'_>, request: &SourceRequest) -> bool {
    !request.url.is_local(app.address.port(), ctx.host)
}

/// Reads a source on an allowed host (`--allow-external-copy-sources`). Source
/// conditions and leases belong to Azure sources, so they are refused here.
async fn read_external(app: &App, request: SourceRequest) -> Result<(SourceBytes, String)> {
    if request.guard.lease.is_some() || request.guard.conditions != Conditions::default() {
        return Err(Error::Unsupported);
    }
    let target = blob_external::Target::new(&request.url);
    let range = request.range.as_ref().map(ByteRange::header_value);
    let remote = blob_external::open(
        &app.config.external_copy_sources,
        &target,
        range.as_deref(),
        app.config.max_assembled_blob_bytes,
        app.config.upload_timeout,
    )
    .await?;
    let now = u64::try_from(app.clock.now_millis() / 1000).unwrap_or_default();
    let source = blob_external::read(&app.store, remote, now).await?;
    Ok((source, target.display().to_owned()))
}

/// Resolves a copy source on this listener and checks the caller may read it.
async fn resolve_source(
    app: &App,
    ctx: &Context<'_>,
    request: &SourceRequest,
) -> Result<blob_copy::Resolved> {
    let resolved = request.url.resolve(app.address.port(), ctx.host)?;
    blob_copy::authorize_source(
        &app.store,
        &app.config,
        ctx.credentials,
        ctx.account,
        &resolved,
        ctx.connection,
    )
    .await?;
    Ok(resolved)
}

async fn read_resolved(
    app: &App,
    resolved: blob_copy::Resolved,
    request: SourceRequest,
) -> Result<(SourceBytes, String)> {
    let source = app
        .store
        .read_source(
            resolved.key.clone(),
            resolved.selector,
            request.guard,
            request.range,
        )
        .await
        .map_err(|error| match error {
            Error::BlobMissing | Error::ContainerMissing => Error::CopySourceMissing,
            other => other,
        })?;
    Ok((source, resolved.display))
}

/// The destination write of a Copy Blob: source properties, and source
/// metadata unless the request supplied its own.
fn copy_write(
    mut options: BlobWrite,
    source: &BlobInfo,
    (replace_metadata, copy_tags): (bool, bool),
    display: String,
) -> BlobWrite {
    options.headers = source.headers.clone();
    if !replace_metadata {
        options.metadata = source.metadata.clone();
    }
    if copy_tags {
        options.tags = source.tags.clone();
    }
    options.md5 = source
        .md5
        .as_deref()
        .and_then(|md5| STANDARD.decode(md5).ok())
        .and_then(|md5| md5.try_into().ok());
    options.copy = Some(CopyRecord {
        id: Uuid::new_v4().to_string(),
        source: display,
    });
    options
}

fn lease_response(action: LeaseAction, result: LeaseResult) -> Result<Response> {
    let status = match action {
        LeaseAction::Acquire { .. } => StatusCode::CREATED,
        LeaseAction::Break { .. } => StatusCode::ACCEPTED,
        _ => StatusCode::OK,
    };
    let mut response = entity_response(status, result.entity)?;
    match (action, result.id, result.break_seconds) {
        (LeaseAction::Break { .. }, _, Some(seconds)) => {
            set(
                response.headers_mut(),
                "x-ms-lease-time",
                &seconds.to_string(),
            )?;
        }
        (LeaseAction::Release(_), _, _) => (),
        (_, Some(id), _) => set(response.headers_mut(), "x-ms-lease-id", &id.text())?,
        _ => (),
    }
    Ok(response)
}

pub(crate) fn block_list_response(list: BlockList) -> Result<Response> {
    let mut xml = Xml::root("BlockList", &[]);
    for (tag, blocks) in [
        ("CommittedBlocks", list.committed),
        ("UncommittedBlocks", list.uncommitted),
    ] {
        if let Some(blocks) = blocks {
            xml.open(tag);
            for (id, length) in blocks {
                xml.open("Block");
                xml.element("Name", &id);
                xml.element("Size", &length.0.to_string());
                xml.close("Block");
            }
            xml.close(tag);
        }
    }
    let mut response = xml.finish("BlockList", StatusCode::OK);
    set(
        response.headers_mut(),
        "x-ms-blob-content-length",
        &list.length.0.to_string(),
    )?;
    if let Some(entity) = list.entity {
        respond::entity_headers(response.headers_mut(), entity)?;
    }
    Ok(response)
}

async fn receive_upload(app: &App, body: Body, options: &UploadOptions) -> Result<Uploaded> {
    let mut upload = app.store.begin_upload(options.length).await?;
    tokio::time::timeout(app.config.upload_timeout, receive(body, &mut upload))
        .await
        .map_err(|_| Error::Timeout)??;
    upload.finish(options.checksum).await
}

/// Reads a small body (XML) completely and verifies its checksum.
pub(crate) async fn read_bounded(
    app: &App,
    body: Body,
    options: &UploadOptions,
) -> Result<(axum::body::Bytes, Checksums)> {
    let bytes = tokio::time::timeout(
        app.config.upload_timeout,
        to_bytes(body, options.length.0 as usize),
    )
    .await
    .map_err(|_| Error::Timeout)?
    .map_err(|_| Error::InvalidLength)?;
    if bytes.len() as u64 != options.length.0 {
        return Err(Error::InvalidLength);
    }
    let mut hash = Hasher::new();
    hash.update(&bytes);
    let checksums = hash.finish(options.checksum)?;
    Ok((bytes, checksums))
}

async fn receive(body: Body, upload: &mut Upload) -> Result<()> {
    let mut data = body.into_data_stream();
    while let Some(chunk) = data.next().await {
        let chunk = chunk.map_err(|_| Error::InvalidLength)?;
        upload.append(&chunk).await?;
    }
    Ok(())
}
