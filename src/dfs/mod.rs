//! Azure Data Lake Storage Gen2 (DFS) on the shared Blob/DFS namespace (ADR-0003, ADR-0020).
//!
//! Authentication reuses the Blob credential checks, the shared clock and the Blob
//! request-slot limit. Requests parse into typed operations (`request`), run against the
//! store, and map to DFS JSON responses (`respond`, `error`).

mod auth;
mod error;
mod headers;
mod request;
mod respond;
mod token;

use crate::{
    blob_auth::{self, Authorization, Credentials},
    blob_sas::Connection,
    clock::Clock,
    config::{Config, PERMIT_WAIT},
    domain::{ContainerCreate, Error, Metadata, PublicAccess, Result},
    store::{Append, Caller, Store},
    wire::{self, empty, entity_response, set},
};
use anyhow::Context as _;
use axum::{
    Router,
    body::Body,
    extract::{ConnectInfo, Request, State},
    http::{HeaderValue, Method, StatusCode, request::Parts},
    response::Response,
};
use error::{DfsError, error_response};
use futures_util::StreamExt as _;
use request::{DELETE_BATCH, Operation, View};
use std::{net::SocketAddr, sync::Arc};
use token::Continuation;
use tokio::sync::Semaphore;
use uuid::Uuid;

struct App {
    config: Arc<Config>,
    store: Store,
    permits: Arc<Semaphore>,
    clock: Clock,
    version: HeaderValue,
    /// Serves requests addressed to the account's `blob` host on this listener.
    blob: Arc<crate::server::App>,
}

pub(crate) fn router(
    config: Arc<Config>,
    store: Store,
    permits: Arc<Semaphore>,
    clock: Clock,
    blob: Arc<crate::server::App>,
) -> anyhow::Result<Router> {
    let version = HeaderValue::from_str(config.api_version.as_str())
        .context("invalid HTTP version in the protocol manifest")?;
    let app = App {
        config,
        store,
        permits,
        clock,
        version,
        blob,
    };
    Ok(Router::new().fallback(dispatch).with_state(Arc::new(app)))
}

/// Whether the request addresses `{account}.blob.{domain}`, which the Data Lake SDKs use
/// for their Blob calls (properties, metadata, downloads) against a DFS URL.
fn is_blob_host(request: &Request) -> bool {
    let host = request
        .uri()
        .authority()
        .map(axum::http::uri::Authority::as_str)
        .or_else(|| {
            request
                .headers()
                .get("host")
                .and_then(|value| value.to_str().ok())
        });
    crate::address::host_account("blob", host).is_some()
}

/// Whether a path-style request uses a Blob-only query parameter. The Data Lake clients
/// cannot derive a `blob` host from an IP endpoint, so AzCopy lists a filesystem through
/// the Blob API on the DFS URL itself; DFS operations never use `restype` or `comp`.
fn is_blob_query(request: &Request) -> bool {
    request.uri().query().is_some_and(|query| {
        query.split('&').any(|pair| {
            let name = pair.split('=').next().unwrap_or_default();
            name == "restype" || name == "comp"
        })
    })
}

/// Rewrites a host-style `{account}.dfs.{domain}` Host header to the `blob` host.
fn rewrite_dfs_host(request: &mut Request) {
    let Some(host) = request
        .headers()
        .get("host")
        .and_then(|value| value.to_str().ok())
    else {
        return;
    };
    if crate::address::host_account("dfs", Some(host)).is_none() {
        return;
    }
    let mut labels = host.splitn(3, '.');
    let (Some(account), Some(_), Some(rest)) = (labels.next(), labels.next(), labels.next()) else {
        return;
    };
    if let Ok(value) = HeaderValue::from_str(&format!("{account}.blob.{rest}")) {
        request.headers_mut().insert("host", value);
    }
}

async fn dispatch(State(app): State<Arc<App>>, mut request: Request) -> Response {
    if is_blob_host(&request) {
        return crate::server::dispatch(State(app.blob.clone()), request).await;
    }
    if is_blob_query(&request) {
        // The JS Data Lake SDK sends Blob calls to the `dfs` host; the Blob service
        // resolves the account from a `blob` host.
        rewrite_dfs_host(&mut request);
        return crate::server::dispatch(State(app.blob.clone()), request).await;
    }
    let request_id = Uuid::new_v4().simple().to_string();
    let (parts, body) = request.into_parts();
    let head = parts.method == Method::HEAD;
    let client_request_id = parts.headers.get("x-ms-client-request-id").cloned();
    let mut response =
        match tokio::time::timeout(PERMIT_WAIT, app.permits.clone().acquire_owned()).await {
            Ok(Ok(permit)) => match handle(&app, &parts, body, &request_id).await {
                Ok(mut response) => {
                    if parts.method == Method::GET {
                        wire::retain_download_permit(&mut response, permit);
                    }
                    response
                }
                Err(error) => error_response(error),
            },
            _ => error_response(Error::Busy.into()),
        };
    let headers = response.headers_mut();
    headers.insert("x-ms-version", app.version.clone());
    if let Some(id) = client_request_id {
        headers.insert("x-ms-client-request-id", id);
    }
    if set(headers, "x-ms-request-id", &request_id)
        .and_then(|()| set(headers, "date", &httpdate::fmt_http_date(app.clock.now())))
        .is_err()
    {
        return error_response(Error::Internal.into());
    }
    if head {
        *response.body_mut() = Body::empty();
    }
    tracing::info!(%request_id, status = response.status().as_u16(), "dfs request");
    response
}

/// Authenticates, authorizes and runs one request.
async fn handle(
    app: &App,
    parts: &Parts,
    body: Body,
    request_id: &str,
) -> std::result::Result<Response, DfsError> {
    let now = app.clock.now();
    let authenticated = auth::authenticate(parts, &app.config, now)?;
    if matches!(authenticated.credentials, Credentials::Anonymous) {
        return Err(Error::AuthenticationFailed.into());
    }
    if authenticated.requested_version != app.config.api_version {
        tracing::info!(
            %request_id,
            requested_api_version = authenticated.requested_version.as_str(),
            effective_api_version = app.config.api_version.as_str(),
            "using the configured DFS protocol baseline"
        );
    }
    let caller = auth::caller(&authenticated.credentials);
    let parsed = request::parse(parts, &authenticated, &app.config, &caller)?;
    let connection = Connection {
        now,
        client_ip: parts
            .extensions
            .get::<ConnectInfo<SocketAddr>>()
            .map(|info| info.0.ip()),
        https: app.config.tls.is_some(),
    };
    blob_auth::authorize(
        &app.store,
        Authorization {
            credentials: &authenticated.credentials,
            target: &authenticated.target,
            need: &parsed.sas,
            connection: &connection,
        },
    )
    .await?;
    for check in parsed.access {
        app.store
            .authorize_path(caller.clone(), check.key, check.path, check.need)
            .await?;
    }
    execute(app, parsed.operation, body, caller).await
}

async fn receive(app: &App, body: Body, upload: &mut crate::store::Upload) -> Result<()> {
    let receive = async {
        let mut data = body.into_data_stream();
        while let Some(chunk) = data.next().await {
            let chunk = chunk.map_err(|_| Error::InvalidLength)?;
            upload.append(&chunk).await?;
        }
        Ok(())
    };
    tokio::time::timeout(app.config.upload_timeout, receive)
        .await
        .map_err(|_| Error::Timeout)?
}

async fn execute(
    app: &App,
    operation: Operation,
    body: Body,
    caller: Caller,
) -> std::result::Result<Response, DfsError> {
    let store = &app.store;
    Ok(match operation {
        Operation::ListFilesystems(account, page) => {
            let page = store.list_containers(account, page).await?;
            respond::list_filesystems(crate::domain::Page {
                items: page
                    .items
                    .into_iter()
                    .map(|(name, info)| (name, info.entity))
                    .collect(),
                next: page.next,
            })?
        }
        Operation::CreateFilesystem(key, metadata) => {
            let created = ContainerCreate {
                metadata,
                public_access: PublicAccess::default(),
            };
            let entity = store.create_container(key, created).await?;
            respond::filesystem(StatusCode::CREATED, entity, None)?
        }
        Operation::SetFilesystemProperties(key, metadata, guard) => {
            let entity = store.set_container_metadata(key, metadata, guard).await?;
            respond::filesystem(StatusCode::OK, entity, None)?
        }
        Operation::FilesystemProperties(key) => {
            respond::filesystem_properties(store.container(key, None).await?)?
        }
        Operation::DeleteFilesystem(key, guard) => {
            store.delete_container(key, guard).await?;
            empty(StatusCode::ACCEPTED)
        }
        Operation::ListPaths(list) => {
            let (entity, page) = store
                .list_paths(list.key, list.directory, list.recursive, list.page)
                .await?;
            respond::list_paths(entity, page)?
        }
        Operation::CreatePath(request) => {
            let created = store.create_path(*request).await?;
            let mut response = entity_response(StatusCode::CREATED, created.entity)?;
            let headers = response.headers_mut();
            headers.insert("content-length", HeaderValue::from_static("0"));
            if let Some(lease) = created.lease {
                set(headers, "x-ms-lease-id", &lease.text())?;
            }
            response
        }
        Operation::RenamePath(request) => {
            let entity = store.rename_path(*request).await?;
            entity_response(StatusCode::CREATED, entity)?
        }
        Operation::Append(request) => {
            let request::AppendRequest {
                key,
                position,
                upload: options,
                guard,
                lease,
            } = *request;
            let mut upload = store.begin_upload(options.length).await?;
            receive(app, body, &mut upload).await?;
            let upload = upload.finish(options.checksum).await?;
            let (name, value) = upload.checksums.response(options.checksum);
            let reported = store
                .append_path(Append {
                    key,
                    position,
                    upload,
                    guard,
                    lease,
                    limit: app.config.max_assembled_blob_bytes,
                    owner: caller.oid().map(str::to_owned),
                })
                .await?;
            let mut response = empty(StatusCode::ACCEPTED);
            let headers = response.headers_mut();
            set(headers, name, &value)?;
            headers.insert(
                "x-ms-request-server-encrypted",
                HeaderValue::from_static("true"),
            );
            if let Some(lease) = reported {
                set(headers, "x-ms-lease-id", &lease.text())?;
            }
            response
        }
        Operation::Flush(request) => {
            let (entity, length) = store.flush_path(*request).await?;
            let mut response = entity_response(StatusCode::OK, entity)?;
            let headers = response.headers_mut();
            set(headers, "content-length", "0")?;
            set(headers, "x-ms-content-length", &length.to_string())?;
            headers.insert(
                "x-ms-request-server-encrypted",
                HeaderValue::from_static("true"),
            );
            response
        }
        Operation::SetProperties(key, guard, update) => {
            let entity = store.set_path_properties(key, guard, update).await?;
            entity_response(StatusCode::OK, entity)?
        }
        Operation::SetAccess(key, path, update, guard) => {
            let entity = store.set_access(key, path, update, guard, caller).await?;
            entity_response(StatusCode::OK, entity)?
        }
        Operation::SetAccessRecursive(request) => {
            let outcome = store.change_access_recursive(*request).await?;
            recursive_response(outcome)?
        }
        Operation::ReadPath(key, options) => {
            let view = store.read_path_view(key, options).await?;
            if matches!(view.read, crate::store::PathRead::Directory(..)) {
                return Err(Error::PathConflict.into());
            }
            respond::path_view(view, true, View::Properties)?
        }
        Operation::PathProperties(key, Some(path), guard, view) => {
            let options = crate::domain::BlobRead {
                guard,
                range: None,
                with_body: false,
                range_checksum: None,
            };
            let found = store
                .read_path_view(
                    crate::domain::BlobKey {
                        container: key,
                        path,
                    },
                    options,
                )
                .await?;
            respond::path_view(found, false, view)?
        }
        Operation::PathProperties(key, None, _, _) => {
            let (entity, attributes) = store.access_of(key).await?;
            let view = crate::store::PathView {
                read: crate::store::PathRead::Directory(entity, Metadata::new()),
                attributes,
                directory_properties: Metadata::new(),
            };
            respond::path_view(view, false, View::AccessControl)?
        }
        Operation::DeletePath {
            key,
            guard,
            recursive,
            continuation,
        } => {
            if continuation
                .as_ref()
                .is_some_and(|token| token.path() != key.path.as_str())
            {
                return Err(Error::InvalidQuery.into());
            }
            let next = store
                .delete_tree(key, guard, DELETE_BATCH, recursive)
                .await?;
            let mut response = empty(StatusCode::OK);
            if let Some(path) = next {
                set(
                    response.headers_mut(),
                    "x-ms-continuation",
                    &Continuation::after(&path).render(),
                )?;
            }
            response
        }
        Operation::LeasePath(key, action, conditions) => {
            let result = store.lease_path(key, action, conditions).await?;
            lease_response(action, result)?
        }
    })
}

fn lease_response(
    action: crate::lease::LeaseAction,
    result: crate::store::LeaseResult,
) -> Result<Response> {
    use crate::lease::LeaseAction;
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

fn recursive_response(outcome: crate::store::RecursiveOutcome) -> Result<Response> {
    let failed: Vec<_> = outcome
        .failures
        .iter()
        .map(|failure| {
            serde_json::json!({
                "name": failure.name,
                "type": if failure.kind == crate::posix::PathKind::Directory { "DIRECTORY" } else { "FILE" },
                "errorMessage": "This request is not authorized to perform this operation using this permission.",
            })
        })
        .collect();
    let body = serde_json::json!({
        "directoriesSuccessful": outcome.directories,
        "filesSuccessful": outcome.files,
        "failureCount": failed.len(),
        "failedEntries": failed,
    });
    let next = outcome
        .next
        .map(|path| Continuation::after(&path).render())
        .unwrap_or_default();
    respond::list_response(body, &next)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn request(host: &str, target: &str) -> Request {
        axum::http::Request::builder()
            .uri(target)
            .header("host", host)
            .body(Body::empty())
            .unwrap()
    }

    #[test]
    fn blob_calls_on_the_dfs_host_are_moved_to_the_blob_host() {
        let mut blob = request("acct1.dfs.localhost:10003", "/fs?restype=container");
        assert!(is_blob_query(&blob));
        rewrite_dfs_host(&mut blob);
        assert_eq!(blob.headers()["host"], "acct1.blob.localhost:10003");
        assert!(is_blob_host(&blob));

        let mut path_style = request("127.0.0.1:10003", "/acct1/fs?restype=container");
        rewrite_dfs_host(&mut path_style);
        assert_eq!(path_style.headers()["host"], "127.0.0.1:10003");
    }

    #[test]
    fn dfs_requests_are_not_mistaken_for_blob_calls() {
        assert!(!is_blob_query(&request(
            "h",
            "/fs/p?action=append&position=0"
        )));
        assert!(!is_blob_query(&request(
            "h",
            "/fs?resource=filesystem&recursive=true"
        )));
        assert!(is_blob_query(&request(
            "h",
            "/fs?comp=list&restype=container"
        )));
    }
}
