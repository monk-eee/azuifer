use crate::{
    auth::header,
    config::Config,
    domain::{AccountName, BlobKey, ContainerKey, Entity, Error, Page, PageRequest, Result},
    protocol::{self, AuthenticatedRequest, ReadOptions, Resource},
    store::Store,
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
    DeleteFilesystem(ContainerKey),
    ListFilesystems(AccountName, PageRequest),
    ReadFile(BlobKey, ReadOptions),
}

enum DfsError {
    NamespaceDisabled,
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
                let download = matches!(&op, Operation::ReadFile(_, options) if options.with_body);
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
    let check =
        |params: &[&str], fields: &[&str]| protocol::check(&query, headers, params, fields, false);
    let op = match (resource, &parts.method, param("resource")) {
        (Resource::Account(account), &Method::GET, Some("account")) => {
            check(&["resource", "prefix", "continuation", "maxresults"], &[])?;
            let page =
                PageRequest::parse(param("prefix"), param("continuation"), param("maxresults"))?;
            Operation::ListFilesystems(account, page)
        }
        (Resource::Container(key), method, Some("filesystem")) => {
            check(&["resource"], &[])?;
            match *method {
                Method::PUT => Operation::CreateFilesystem(key),
                Method::HEAD => Operation::FilesystemProperties(key),
                Method::DELETE => Operation::DeleteFilesystem(key),
                _ => return Err(Error::Unsupported.into()),
            }
        }
        (Resource::Blob(key), method @ (&Method::GET | &Method::HEAD), None) => {
            let with_body = method == Method::GET;
            let fields: &[&str] = if with_body {
                &["if-match", "if-none-match", "range"]
            } else {
                &["if-match", "if-none-match"]
            };
            check(&[], fields)?;
            Operation::ReadFile(key, protocol::read_options(headers, with_body)?)
        }
        _ => return Err(Error::Unsupported.into()),
    };
    Ok(op)
}

async fn execute(store: &Store, op: Operation) -> Result<Response> {
    match op {
        Operation::CreateFilesystem(key) => {
            filesystem(StatusCode::CREATED, store.create_container(key).await?)
        }
        Operation::FilesystemProperties(key) => {
            filesystem(StatusCode::OK, store.container(key).await?)
        }
        Operation::DeleteFilesystem(key) => {
            store.delete_container(key).await?;
            Ok(empty(StatusCode::ACCEPTED))
        }
        Operation::ListFilesystems(account, page) => {
            list_filesystems(store.list_containers(account, page).await?)
        }
        Operation::ReadFile(key, options) => {
            let download = store
                .read_blob(key, options.condition, options.range, options.with_body)
                .await?;
            let (mut response, metadata) = wire::download_response(download)?;
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
    let mut response = json_response(
        StatusCode::OK,
        serde_json::json!({ "filesystems": filesystems }),
        JSON,
    );
    if !page.next.is_empty() {
        set(response.headers_mut(), "x-ms-continuation", &page.next)?;
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
