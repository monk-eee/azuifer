use crate::{
    auth::header,
    conditions::{Conditions, Guard, STANDARD as CONDITION_HEADERS},
    config::Config,
    domain::{
        AccountName, BlobKey, BlobPath, BlobRead, ByteRange, ContainerCreate, ContainerKey, Entity,
        Error, Metadata, Page, PageRequest, PathEntry, PublicAccess, Result,
    },
    protocol::{self, AuthenticatedRequest, Resource},
    store::{PathRead, Store},
    wire::{self, empty, entity_response, json_response, modified, set},
};
use anyhow::Context as _;
use axum::{
    Router,
    extract::{Request, State},
    http::{HeaderValue, Method, StatusCode, request::Parts},
    response::Response,
};
use base64::{Engine as _, engine::general_purpose::STANDARD};
use std::sync::Arc;
use tokio::sync::Semaphore;
use uuid::Uuid;

const JSON: &str = "application/json; charset=utf-8";

struct App {
    config: Arc<Config>,
    store: Store,
    permits: Arc<Semaphore>,
    version: HeaderValue,
}

enum Operation {
    CreateFilesystem(ContainerKey),
    FilesystemProperties(ContainerKey),
    DeleteFilesystem(ContainerKey, Guard),
    ListFilesystems(AccountName, PageRequest),
    CreateDirectory(BlobKey, Conditions),
    ListPaths(ContainerKey, Option<BlobPath>, bool, PageRequest),
    ReadPath(BlobKey, BlobRead),
    DeletePath(BlobKey, Guard),
}

enum DfsError {
    NamespaceDisabled,
    MissingRecursive,
    Request(Error),
}

impl From<Error> for DfsError {
    fn from(error: Error) -> Self {
        Self::Request(error)
    }
}

pub(crate) fn router(
    config: Arc<Config>,
    store: Store,
    permits: Arc<Semaphore>,
) -> anyhow::Result<Router> {
    let version = HeaderValue::from_str(config.api_version.as_str())
        .context("invalid HTTP version in the protocol manifest")?;
    let app = App {
        config,
        store,
        permits,
        version,
    };
    Ok(Router::new().fallback(dispatch).with_state(Arc::new(app)))
}

async fn dispatch(State(app): State<Arc<App>>, request: Request) -> Response {
    let request_id = Uuid::new_v4().simple().to_string();
    let (parts, _) = request.into_parts();
    let head = parts.method == Method::HEAD;
    let mut response = match app.permits.clone().try_acquire_owned() {
        Ok(permit) => match parse(&parts, &app.config, &request_id) {
            Ok(op) => {
                let download = matches!(&op, Operation::ReadPath(_, options) if options.with_body);
                match execute(&app.store, op).await {
                    Ok(mut response) => {
                        if download {
                            wire::retain_download_permit(&mut response, permit);
                        }
                        response
                    }
                    Err(error) => error_response(error.into()),
                }
            }
            Err(error) => error_response(error),
        },
        Err(_) => error_response(Error::Busy.into()),
    };
    if wire::stamp_response(&mut response, &app.version, &request_id, head).is_err() {
        return error_response(Error::Internal.into());
    }
    tracing::info!(%request_id, status = response.status().as_u16(), "dfs request");
    response
}

fn parse(
    parts: &Parts,
    config: &Config,
    request_id: &str,
) -> std::result::Result<Operation, DfsError> {
    let AuthenticatedRequest {
        requested_version,
        resource,
        query,
    } = protocol::authenticate(parts, config)?;
    if !config.hns_accounts.contains(resource.account()) {
        return Err(DfsError::NamespaceDisabled);
    }
    if requested_version != config.api_version {
        tracing::info!(
            %request_id,
            requested_api_version = requested_version.as_str(),
            effective_api_version = config.api_version.as_str(),
            "using the configured DFS protocol baseline"
        );
    }
    let headers = &parts.headers;
    if header(headers, "content-length")?.is_some_and(|length| length.parse::<u64>() != Ok(0))
        || headers.contains_key("transfer-encoding")
    {
        return Err(Error::InvalidLength.into());
    }
    let param = |name| query.get(name).map(String::as_str);
    let check = |params: &[&str], fields: &[&str]| {
        protocol::check(&query, headers, params, &[fields], false)
    };
    let conditions = ["if-match", "if-none-match"];
    let file_conditions = ["if-match", "if-none-match", "x-ms-lease-id"];
    let op = match (resource, &parts.method, param("resource")) {
        (Resource::Account(account), &Method::GET, Some("account")) => {
            check(&["resource", "prefix", "continuation", "maxresults"], &[])?;
            let page =
                PageRequest::parse(param("prefix"), param("continuation"), param("maxresults"))?;
            Operation::ListFilesystems(account, page)
        }
        (Resource::Container(key), &Method::GET, Some("filesystem")) => {
            check(
                &[
                    "resource",
                    "directory",
                    "recursive",
                    "continuation",
                    "maxresults",
                    "upn",
                ],
                &[],
            )?;
            let recursive =
                boolean_parameter(param("recursive"))?.ok_or(DfsError::MissingRecursive)?;
            if boolean_parameter(param("upn"))? == Some(true) {
                return Err(Error::Unsupported.into());
            }
            let directory = param("directory")
                .filter(|value| !matches!(*value, "" | "/"))
                .map(|value| -> Result<_> {
                    let path =
                        BlobPath::parse(value.to_owned()).map_err(|_| Error::InvalidQuery)?;
                    path.check_hns().map_err(|_| Error::InvalidQuery)?;
                    Ok(path)
                })
                .transpose()?;
            let page = PageRequest::parse(None, param("continuation"), param("maxresults"))?;
            Operation::ListPaths(key, directory, recursive, page)
        }
        (Resource::Container(key), method, Some("filesystem")) => {
            check(&["resource"], &[])?;
            match *method {
                Method::PUT => Operation::CreateFilesystem(key),
                Method::HEAD => Operation::FilesystemProperties(key),
                Method::DELETE => Operation::DeleteFilesystem(key, Guard::parse(headers)?),
                _ => return Err(Error::Unsupported.into()),
            }
        }
        (Resource::Blob(key), &Method::PUT, Some("directory")) => {
            check(&["resource"], &conditions)?;
            Operation::CreateDirectory(key, Conditions::parse(headers, &CONDITION_HEADERS)?)
        }
        (Resource::Blob(key), method @ (&Method::GET | &Method::HEAD), None) => {
            let with_body = method == Method::GET;
            let fields: &[&str] = if with_body {
                &["if-match", "if-none-match", "range", "x-ms-lease-id"]
            } else {
                &file_conditions
            };
            check(&[], fields)?;
            let range = header(headers, "x-ms-range")?
                .or(header(headers, "range")?)
                .map(ByteRange::parse)
                .transpose()?;
            Operation::ReadPath(
                key,
                BlobRead {
                    guard: Guard::parse(headers)?,
                    range,
                    with_body,
                    range_checksum: None,
                },
            )
        }
        (Resource::Blob(key), &Method::DELETE, None) => {
            check(&["recursive"], &file_conditions)?;
            if boolean_parameter(param("recursive"))? == Some(true) {
                return Err(Error::Unsupported.into());
            }
            Operation::DeletePath(key, Guard::parse(headers)?)
        }
        _ => return Err(Error::Unsupported.into()),
    };
    Ok(op)
}

fn boolean_parameter(value: Option<&str>) -> Result<Option<bool>> {
    value
        .map(|value| value.parse().map_err(|_| Error::InvalidQuery))
        .transpose()
}

async fn execute(store: &Store, op: Operation) -> Result<Response> {
    match op {
        Operation::CreateFilesystem(key) => filesystem(
            StatusCode::CREATED,
            store
                .create_container(
                    key,
                    ContainerCreate {
                        metadata: Metadata::new(),
                        public_access: PublicAccess::default(),
                    },
                )
                .await?,
        ),
        Operation::FilesystemProperties(key) => {
            filesystem(StatusCode::OK, store.container(key, None).await?.entity)
        }
        Operation::DeleteFilesystem(key, guard) => {
            store.delete_container(key, guard).await?;
            Ok(empty(StatusCode::ACCEPTED))
        }
        Operation::ListFilesystems(account, page) => {
            let page = store.list_containers(account, page).await?;
            list_filesystems(Page {
                items: page
                    .items
                    .into_iter()
                    .map(|(name, info)| (name, info.entity))
                    .collect(),
                next: page.next,
            })
        }
        Operation::CreateDirectory(key, conditions) => wire::directory_response(
            StatusCode::CREATED,
            store.create_directory(key, conditions).await?,
        ),
        Operation::ListPaths(key, directory, recursive, page) => {
            let (entity, page) = store.list_paths(key, directory, recursive, page).await?;
            list_paths(entity, page)
        }
        Operation::DeletePath(key, guard) => {
            store.delete_path(key, guard).await?;
            Ok(empty(StatusCode::ACCEPTED))
        }
        Operation::ReadPath(key, options) => {
            let with_body = options.with_body;
            let download = match store.read_path(key, options).await? {
                PathRead::File(download) => download,
                PathRead::Directory(_) if with_body => return Err(Error::PathConflict),
                PathRead::Directory(entity) => {
                    return wire::directory_response(StatusCode::OK, entity);
                }
            };
            let (mut response, metadata) = wire::download_response(*download)?;
            let headers = response.headers_mut();
            headers.insert("x-ms-resource-type", HeaderValue::from_static("file"));
            if !metadata.is_empty() {
                let properties = metadata
                    .into_iter()
                    .map(|(name, value)| format!("{name}={}", STANDARD.encode(value)))
                    .collect::<Vec<_>>()
                    .join(",");
                set(headers, "x-ms-properties", &properties)?;
            }
            Ok(response)
        }
    }
}

fn list_paths(entity: Entity, page: Page<PathEntry>) -> Result<Response> {
    let paths = page
        .items
        .into_iter()
        .map(|(name, entry)| {
            let (entity, directory, length) = match entry {
                PathEntry::File(entity, length) => (entity, false, length.0),
                PathEntry::Directory(entity) => (entity, true, 0),
            };
            Ok(serde_json::json!({
                "name": name,
                "etag": entity.etag().as_str(),
                "lastModified": modified(entity)?,
                "isDirectory": directory,
                "contentLength": length,
            }))
        })
        .collect::<Result<Vec<_>>>()?;
    let mut response = list_response(serde_json::json!({ "paths": paths }), &page.next)?;
    wire::entity_headers(response.headers_mut(), entity)?;
    Ok(response)
}

fn filesystem(status: StatusCode, entity: Entity) -> Result<Response> {
    let mut response = entity_response(status, entity)?;
    response
        .headers_mut()
        .insert("x-ms-namespace-enabled", HeaderValue::from_static("true"));
    Ok(response)
}

fn list_filesystems(page: Page<Entity>) -> Result<Response> {
    let filesystems = page
        .items
        .into_iter()
        .map(|(name, entity)| {
            Ok(serde_json::json!({
                "name": name,
                "eTag": entity.etag().as_str(),
                "lastModified": modified(entity)?,
            }))
        })
        .collect::<Result<Vec<_>>>()?;
    list_response(
        serde_json::json!({ "filesystems": filesystems }),
        &page.next,
    )
}

fn list_response(body: serde_json::Value, next: &str) -> Result<Response> {
    let mut response = json_response(StatusCode::OK, body, JSON);
    if !next.is_empty() {
        set(response.headers_mut(), "x-ms-continuation", next)?;
    }
    Ok(response)
}

fn error_response(error: DfsError) -> Response {
    use StatusCode as S;
    let internal = (
        S::INTERNAL_SERVER_ERROR,
        "InternalError",
        "The local storage operation failed.",
    );
    let (status, code, message) = match error {
        DfsError::NamespaceDisabled => (
            S::CONFLICT,
            "HierarchicalNamespaceNotEnabled",
            "The account does not have a hierarchical namespace enabled.",
        ),
        DfsError::MissingRecursive => (
            S::BAD_REQUEST,
            "MissingRequiredQueryParameter",
            "The recursive query parameter is required for listing paths.",
        ),
        DfsError::Request(error) => match error {
            Error::AuthenticationFailed => (
                S::FORBIDDEN,
                "AuthorizationFailure",
                "This request is not authorized to perform this operation.",
            ),
            Error::InvalidName => (
                S::BAD_REQUEST,
                "InvalidResourceName",
                "The specified resource name contains invalid characters.",
            ),
            Error::InvalidHeader => (
                S::BAD_REQUEST,
                "InvalidHeaderValue",
                "The value for one of the HTTP headers is not in the correct format.",
            ),
            Error::InvalidQuery => (
                S::BAD_REQUEST,
                "InvalidQueryParameterValue",
                "A query parameter is invalid.",
            ),
            Error::InvalidVersion => (
                S::BAD_REQUEST,
                "UnsupportedRestVersion",
                "The specified Rest Version is Unsupported.",
            ),
            Error::InvalidLength => (
                S::BAD_REQUEST,
                "ContentLengthMustBeZero",
                "The Content-Length request header must be zero.",
            ),
            Error::Unsupported => (
                S::NOT_IMPLEMENTED,
                "NotImplemented",
                "This operation or option is not implemented.",
            ),
            Error::ContainerExists => (
                S::CONFLICT,
                "FilesystemAlreadyExists",
                "The specified filesystem already exists.",
            ),
            Error::ContainerMissing => (
                S::NOT_FOUND,
                "FilesystemNotFound",
                "The specified filesystem does not exist.",
            ),
            Error::BlobMissing => (
                S::NOT_FOUND,
                "PathNotFound",
                "The specified path does not exist.",
            ),
            Error::PathConflict => (
                S::CONFLICT,
                "PathConflict",
                "The path conflicts with a file or directory.",
            ),
            Error::DirectoryNotEmpty => (
                S::CONFLICT,
                "DirectoryNotEmpty",
                "The recursive query parameter value must be true to delete a non-empty directory.",
            ),
            Error::LeaseIdMissing => (
                S::PRECONDITION_FAILED,
                "LeaseIdMissing",
                "There is currently a lease on the resource and no lease ID was specified.",
            ),
            Error::LeaseMismatchBlob | Error::LeaseMismatchContainer => (
                S::PRECONDITION_FAILED,
                "LeaseIdMismatch",
                "The lease ID does not match the lease on the resource.",
            ),
            Error::LeaseNotPresentBlob | Error::LeaseNotPresentContainer => (
                S::PRECONDITION_FAILED,
                "LeaseNotPresent",
                "There is no active lease on the resource.",
            ),
            Error::LeaseLost => (
                S::PRECONDITION_FAILED,
                "LeaseLost",
                "The lease has expired.",
            ),
            Error::ConditionNotMet => (
                S::PRECONDITION_FAILED,
                "ConditionNotMet",
                "The condition specified using HTTP conditional header(s) is not met.",
            ),
            Error::NotModified => return empty(S::NOT_MODIFIED),
            Error::InvalidRange(_) => (
                S::RANGE_NOT_SATISFIABLE,
                "InvalidRange",
                "The range specified is invalid for the current size of the resource.",
            ),
            Error::Busy => (
                S::SERVICE_UNAVAILABLE,
                "ServerBusy",
                "Too many active requests.",
            ),
            Error::Internal => internal,
            _ => {
                tracing::error!(?error, "unexpected DFS storage error");
                internal
            }
        },
    };
    let mut response = json_response(
        status,
        serde_json::json!({ "error": { "code": code, "message": message } }),
        JSON,
    );
    let headers = response.headers_mut();
    headers.insert("x-ms-error-code", HeaderValue::from_static(code));
    if let DfsError::Request(Error::InvalidRange(length)) = error
        && wire::unsatisfied_range(headers, length).is_err()
    {
        return error_response(Error::Internal.into());
    }
    response
}
