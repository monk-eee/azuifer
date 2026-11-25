use crate::{
    checksum::{Checksums, Hasher},
    config::Config,
    domain::{BlobInfo, BlockList, Entity, Error, Metadata, Page, Result},
    protocol::{self, Operation, UploadOptions},
    store::{Download, Payload, Store, Upload, Uploaded},
};
use anyhow::Context as _;
use axum::{
    Router,
    body::{Body, to_bytes},
    extract::{Request, State},
    http::{HeaderMap, HeaderValue, Method, StatusCode},
    response::Response,
    routing::get,
};
use futures_util::{StreamExt as _, TryStreamExt as _};
use std::{
    net::SocketAddr,
    sync::Arc,
    time::{Duration, SystemTime, UNIX_EPOCH},
};
use tokio::{io::AsyncReadExt as _, net::TcpListener, sync::Semaphore};
use tokio_util::{io::ReaderStream, sync::CancellationToken};
use uuid::Uuid;

struct App {
    config: Config,
    version: HeaderValue,
    store: Store,
    address: SocketAddr,
    permits: Arc<Semaphore>,
}

pub(crate) async fn serve(config: Config, shutdown_on_stdin_eof: bool) -> anyhow::Result<()> {
    let version = HeaderValue::from_str(config.api_version.as_str())
        .context("invalid HTTP version in the protocol manifest")?;
    let blob = TcpListener::bind(config.blob)
        .await
        .context("could not bind the Blob listener")?;
    let admin = TcpListener::bind(config.admin)
        .await
        .context("could not bind the admin listener")?;
    let location = config.location.clone();
    let memory_limit = config.memory_limit;
    let store = tokio::task::spawn_blocking(move || Store::open(location.as_deref(), memory_limit))
        .await
        .context("storage initialization did not complete")??;
    let address = blob.local_addr()?;
    let admin_address = admin.local_addr()?;
    let app = Arc::new(App {
        config,
        version,
        store,
        address,
        permits: Arc::new(Semaphore::new(16)),
    });
    let blob_router = Router::new().fallback(dispatch).with_state(app);
    let admin_router = Router::new()
        .route("/healthz", get(|| async { "ok\n" }))
        .route("/readyz", get(|| async { "ready\n" }));
    let stop = CancellationToken::new();
    tracing::info!(blob = %address, admin = %admin_address, "listening");
    println!("blob_url=http://{address}");
    println!("admin_url=http://{admin_address}");
    let blob_task = async {
        axum::serve(blob, blob_router)
            .with_graceful_shutdown(stop.clone().cancelled_owned())
            .await
    };
    let admin_task = async {
        axum::serve(admin, admin_router)
            .with_graceful_shutdown(stop.clone().cancelled_owned())
            .await
    };
    let signal = async {
        wait_for_shutdown(shutdown_on_stdin_eof).await?;
        stop.cancel();
        Ok(())
    };
    tokio::try_join!(blob_task, admin_task, signal).context("HTTP server exited unexpectedly")?;
    Ok(())
}

async fn wait_for_shutdown(shutdown_on_stdin_eof: bool) -> std::io::Result<()> {
    if !shutdown_on_stdin_eof {
        return wait_for_signal().await;
    }
    let (sender, eof) = tokio::sync::oneshot::channel();
    std::thread::Builder::new()
        .name("stdin-shutdown".into())
        .spawn(move || {
            let result =
                std::io::copy(&mut std::io::stdin().lock(), &mut std::io::sink()).map(|_| ());
            let _ = sender.send(result);
        })?;
    tokio::select! {
        result = wait_for_signal() => result,
        result = eof => result.map_err(std::io::Error::other)?,
    }
}

async fn wait_for_signal() -> std::io::Result<()> {
    #[cfg(unix)]
    {
        use tokio::signal::unix::{SignalKind, signal};
        let mut terminate = signal(SignalKind::terminate())?;
        tokio::select! {
            result = tokio::signal::ctrl_c() => result,
            _ = terminate.recv() => Ok(()),
        }
    }
    #[cfg(not(unix))]
    tokio::signal::ctrl_c().await
}

async fn dispatch(State(app): State<Arc<App>>, request: Request) -> Response {
    let request_id = Uuid::new_v4().simple().to_string();
    let (parts, body) = request.into_parts();
    let head = parts.method == Method::HEAD;
    let mut response = match app.permits.clone().try_acquire_owned() {
        Ok(permit) => match protocol::parse(&parts, &app.config) {
            Ok(parsed) => {
                if parsed.requested_version != app.config.api_version {
                    tracing::info!(
                        %request_id,
                        requested_api_version = parsed.requested_version.as_str(),
                        effective_api_version = app.config.api_version.as_str(),
                        "using the configured Blob protocol baseline"
                    );
                }
                match execute(&app, parsed.operation, body).await {
                    Ok(mut response) => {
                        if parts.method == Method::GET
                            && response.headers().contains_key("x-ms-blob-type")
                        {
                            let body = std::mem::replace(response.body_mut(), Body::empty());
                            *response.body_mut() =
                                Body::from_stream(body.into_data_stream().map(move |item| {
                                    let _permit = &permit;
                                    item
                                }));
                        }
                        response
                    }
                    Err(error) => error_response(error),
                }
            }
            Err(error) => error_response(error),
        },
        Err(_) => error_response(Error::Busy),
    };
    response
        .headers_mut()
        .insert("x-ms-version", app.version.clone());
    if set(response.headers_mut(), "x-ms-request-id", &request_id)
        .and_then(|_| {
            set(
                response.headers_mut(),
                "date",
                &httpdate::fmt_http_date(SystemTime::now()),
            )
        })
        .is_err()
    {
        return error_response(Error::Internal);
    }
    if head {
        *response.body_mut() = Body::empty();
    }
    tracing::info!(%request_id, status = response.status().as_u16(), "blob request");
    response
}

async fn execute(app: &App, op: Operation, body: Body) -> Result<Response> {
    let store = &app.store;
    match op {
        Operation::CreateContainer(key) => {
            entity_response(StatusCode::CREATED, store.create_container(key).await?)
        }
        Operation::ContainerProperties(key) => {
            entity_response(StatusCode::OK, store.container(key).await?)
        }
        Operation::DeleteContainer(key) => {
            store.delete_container(key).await?;
            Ok(empty(StatusCode::ACCEPTED))
        }
        Operation::ListContainers(account, page) => {
            let endpoint = storage_endpoint(app.address, account.as_str());
            let limit = page.limit;
            let page = store.list_containers(account, page).await?;
            list_containers(&endpoint, limit, page)
        }
        Operation::ListBlobs(key, page, metadata) => {
            let endpoint = storage_endpoint(app.address, key.account.as_str());
            let name = key.name.as_str().to_owned();
            let limit = page.limit;
            let page = store.list_blobs(key, page).await?;
            list_blobs(&endpoint, &name, limit, page, metadata)
        }
        Operation::PutBlob(key, body_options, options) => {
            let upload = receive_upload(app, body, &body_options).await?;
            let checksum = upload.checksums.response(body_options.checksum);
            let entity = store.put_blob(key, options, upload).await?;
            write_response(entity_response(StatusCode::CREATED, entity)?, checksum)
        }
        Operation::PutBlock(key, id, options) => {
            let upload = receive_upload(app, body, &options).await?;
            let checksum = upload.checksums.response(options.checksum);
            store.put_block(key, id, upload).await?;
            write_response(empty(StatusCode::CREATED), checksum)
        }
        Operation::PutBlockList(key, body_options, options, md5) => {
            let (blocks, checksums) = read_block_list(app, body, &body_options).await?;
            let entity = store
                .commit_blocks(
                    key,
                    options,
                    blocks,
                    md5,
                    app.config.max_assembled_blob_bytes,
                )
                .await?;
            write_response(
                entity_response(StatusCode::CREATED, entity)?,
                checksums.response(body_options.checksum),
            )
        }
        Operation::GetBlockList(key, kind, condition) => {
            block_list_response(store.blocks(key, kind, condition).await?)
        }
        Operation::ReadBlob(key, options) => {
            let download = store
                .read_blob(key, options.condition, options.range, options.with_body)
                .await?;
            download_response(download)
        }
        Operation::DeleteBlob(key, condition) => {
            store.delete_blob(key, condition).await?;
            Ok(empty(StatusCode::ACCEPTED))
        }
    }
}

async fn receive_upload(app: &App, body: Body, options: &UploadOptions) -> Result<Uploaded> {
    let mut upload = app.store.begin_upload(options.length).await?;
    tokio::time::timeout(app.config.upload_timeout, receive(body, &mut upload))
        .await
        .map_err(|_| Error::Timeout)??;
    upload.finish(options.checksum).await
}

async fn read_block_list(
    app: &App,
    body: Body,
    options: &UploadOptions,
) -> Result<(Vec<crate::domain::BlockSelection>, Checksums)> {
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
    Ok((protocol::parse_block_list(&bytes)?, checksums))
}

async fn receive(body: Body, upload: &mut Upload) -> Result<()> {
    let mut data = body.into_data_stream();
    while let Some(chunk) = data.next().await {
        let chunk = chunk.map_err(|_| Error::InvalidLength)?;
        upload.append(&chunk).await?;
    }
    Ok(())
}

fn storage_endpoint(address: SocketAddr, account: &str) -> String {
    format!("http://{address}/{account}/")
}

fn empty(status: StatusCode) -> Response {
    let mut response = Response::new(Body::empty());
    *response.status_mut() = status;
    response
}

fn modified(entity: Entity) -> Result<String> {
    if entity.modified >= 253_402_300_800 {
        tracing::error!("metadata timestamp is outside the HTTP date range");
        return Err(Error::Internal);
    }
    Ok(httpdate::fmt_http_date(
        UNIX_EPOCH + Duration::from_secs(entity.modified),
    ))
}

fn entity_response(status: StatusCode, entity: Entity) -> Result<Response> {
    let mut response = empty(status);
    entity_headers(response.headers_mut(), entity)?;
    Ok(response)
}

fn entity_headers(headers: &mut HeaderMap, entity: Entity) -> Result<()> {
    set(headers, "etag", entity.etag().as_str())?;
    set(headers, "last-modified", &modified(entity)?)
}

fn write_response(
    mut response: Response,
    (name, value): (&'static str, String),
) -> Result<Response> {
    set(response.headers_mut(), name, &value)?;
    response.headers_mut().insert(
        "x-ms-request-server-encrypted",
        HeaderValue::from_static("false"),
    );
    Ok(response)
}

fn set(headers: &mut HeaderMap, name: &'static str, value: &str) -> Result<()> {
    let value = HeaderValue::from_str(value).map_err(|_| {
        tracing::error!(header = name, "could not encode response header");
        Error::Internal
    })?;
    headers.insert(name, value);
    Ok(())
}

fn download_response(download: Download) -> Result<Response> {
    let Download {
        info,
        range,
        payload,
    } = download;
    let status = if range.is_some() {
        StatusCode::PARTIAL_CONTENT
    } else {
        StatusCode::OK
    };
    let mut response = entity_response(status, info.entity)?;
    let headers = response.headers_mut();
    let size = if let Some(range) = range {
        set(
            headers,
            "content-range",
            &format!("bytes {}-{}/{}", range.start, range.end - 1, info.length.0),
        )?;
        range.end - range.start
    } else {
        if let Some(md5) = &info.md5 {
            set(headers, "content-md5", md5)?;
        }
        info.length.0
    };
    set(headers, "content-length", &size.to_string())?;
    set(headers, "content-type", &info.content_type)?;
    headers.insert("accept-ranges", HeaderValue::from_static("bytes"));
    headers.insert("x-ms-blob-type", HeaderValue::from_static("BlockBlob"));
    for (name, value) in info.metadata {
        let name = axum::http::HeaderName::from_bytes(format!("x-ms-meta-{name}").as_bytes())
            .map_err(|_| {
                tracing::error!("invalid stored metadata header");
                Error::Internal
            })?;
        let value = HeaderValue::from_str(&value).map_err(|_| {
            tracing::error!("invalid stored metadata value");
            Error::Internal
        })?;
        headers.insert(name, value);
    }
    *response.body_mut() = match payload {
        Some(Payload::Disk(file)) => {
            let reader = tokio::fs::File::from_std(file).take(size);
            Body::from_stream(ReaderStream::new(reader).inspect_err(|error| {
                tracing::error!(kind = ?error.kind(), "content read failed");
            }))
        }
        Some(Payload::Memory(bytes)) => Body::from(bytes),
        None => Body::empty(),
    };
    Ok(response)
}

fn list_containers(endpoint: &str, limit: u32, page: Page<Entity>) -> Result<Response> {
    let mut xml = Xml::root("EnumerationResults", &[("ServiceEndpoint", endpoint)]);
    xml.element("MaxResults", &limit.to_string());
    xml.open("Containers");
    for (name, entity) in page.items {
        xml.open("Container");
        xml.element("Name", &name);
        xml.open("Properties");
        xml.entity(entity)?;
        xml.close("Properties");
        xml.close("Container");
    }
    xml.close("Containers");
    xml.element("NextMarker", &page.next);
    Ok(xml.finish("EnumerationResults", StatusCode::OK))
}

fn list_blobs(
    endpoint: &str,
    name: &str,
    limit: u32,
    page: Page<BlobInfo>,
    metadata: bool,
) -> Result<Response> {
    let mut xml = Xml::root(
        "EnumerationResults",
        &[("ServiceEndpoint", endpoint), ("ContainerName", name)],
    );
    xml.element("MaxResults", &limit.to_string());
    xml.open("Blobs");
    for (name, properties) in page.items {
        xml.open("Blob");
        xml.element("Name", &name);
        xml.open("Properties");
        xml.entity(properties.entity)?;
        xml.element("Content-Length", &properties.length.0.to_string());
        xml.element("Content-Type", &properties.content_type);
        if let Some(md5) = &properties.md5 {
            xml.element("Content-MD5", md5);
        }
        xml.element("BlobType", "BlockBlob");
        xml.close("Properties");
        if metadata {
            xml.metadata(properties.metadata);
        }
        xml.close("Blob");
    }
    xml.close("Blobs");
    xml.element("NextMarker", &page.next);
    Ok(xml.finish("EnumerationResults", StatusCode::OK))
}

fn block_list_response(list: BlockList) -> Result<Response> {
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
        entity_headers(response.headers_mut(), entity)?;
    }
    Ok(response)
}

fn error_response(error: Error) -> Response {
    use StatusCode as S;
    let (status, code, message) = match error {
        Error::AuthenticationFailed => (
            S::FORBIDDEN,
            "AuthenticationFailed",
            "The request could not be authenticated.",
        ),
        Error::InvalidName => (
            S::BAD_REQUEST,
            "InvalidResourceName",
            "The resource name is invalid.",
        ),
        Error::InvalidHeader => (
            S::BAD_REQUEST,
            "InvalidHeaderValue",
            "A request header is invalid or missing.",
        ),
        Error::InvalidVersion => (
            S::BAD_REQUEST,
            "InvalidHeaderValue",
            "The requested API version is not supported.",
        ),
        Error::InvalidQuery => (
            S::BAD_REQUEST,
            "InvalidQueryParameterValue",
            "A query parameter is invalid.",
        ),
        Error::Unsupported => (
            S::NOT_IMPLEMENTED,
            "NotImplemented",
            "This operation or option is not implemented.",
        ),
        Error::MissingLength => (
            S::LENGTH_REQUIRED,
            "MissingContentLengthHeader",
            "A Content-Length header is required.",
        ),
        Error::InvalidLength => (
            S::BAD_REQUEST,
            "InvalidInput",
            "The body does not match Content-Length.",
        ),
        Error::TooLarge => (
            S::PAYLOAD_TOO_LARGE,
            "RequestBodyTooLarge",
            "The upload exceeds the configured limit.",
        ),
        Error::Md5Mismatch => (
            S::BAD_REQUEST,
            "Md5Mismatch",
            "The body checksum does not match Content-MD5.",
        ),
        Error::Crc64Mismatch => (
            S::BAD_REQUEST,
            "Crc64Mismatch",
            "The body checksum does not match x-ms-content-crc64.",
        ),
        Error::InvalidBlockId => (
            S::BAD_REQUEST,
            "InvalidBlockId",
            "The block ID is malformed or has inconsistent length.",
        ),
        Error::InvalidBlockList => (
            S::BAD_REQUEST,
            "InvalidBlockList",
            "The specified block list is invalid.",
        ),
        Error::InvalidXml => (
            S::BAD_REQUEST,
            "InvalidXmlDocument",
            "The block list XML is invalid.",
        ),
        Error::BlockCountExceeded => (
            S::CONFLICT,
            "BlockCountExceedsLimit",
            "The block count exceeds the limit.",
        ),
        Error::BlockListTooLong => (
            S::BAD_REQUEST,
            "BlockListTooLong",
            "The block list exceeds 50,000 entries.",
        ),
        Error::ContainerExists => (
            S::CONFLICT,
            "ContainerAlreadyExists",
            "The container already exists.",
        ),
        Error::ContainerMissing => (
            S::NOT_FOUND,
            "ContainerNotFound",
            "The specified container does not exist.",
        ),
        Error::BlobMissing => (
            S::NOT_FOUND,
            "BlobNotFound",
            "The specified blob does not exist.",
        ),
        Error::ConditionNotMet => (
            S::PRECONDITION_FAILED,
            "ConditionNotMet",
            "The specified condition was not met.",
        ),
        Error::NotModified => return empty(S::NOT_MODIFIED),
        Error::InvalidRange(_) => (
            S::RANGE_NOT_SATISFIABLE,
            "InvalidRange",
            "The range is outside the blob.",
        ),
        Error::QuotaExceeded => (
            S::INSUFFICIENT_STORAGE,
            "InsufficientStorage",
            "The in-memory content quota was exceeded.",
        ),
        Error::Busy => (
            S::SERVICE_UNAVAILABLE,
            "ServerBusy",
            "Too many active requests.",
        ),
        Error::Timeout => (
            S::REQUEST_TIMEOUT,
            "OperationTimedOut",
            "The upload did not finish in time.",
        ),
        Error::Internal => (
            S::INTERNAL_SERVER_ERROR,
            "InternalError",
            "The local storage operation failed.",
        ),
    };
    let mut xml = Xml::root("Error", &[]);
    xml.element("Code", code);
    xml.element("Message", message);
    let mut response = xml.finish("Error", status);
    response
        .headers_mut()
        .insert("x-ms-error-code", HeaderValue::from_static(code));
    if let Error::InvalidRange(length) = error
        && set(
            response.headers_mut(),
            "content-range",
            &format!("bytes */{length}"),
        )
        .is_err()
    {
        return error_response(Error::Internal);
    }
    response
}

struct Xml(String);

impl Xml {
    fn root(name: &str, attributes: &[(&str, &str)]) -> Self {
        let mut xml = Self("<?xml version=\"1.0\" encoding=\"utf-8\"?>".to_owned());
        xml.0.push('<');
        xml.0.push_str(name);
        for (key, value) in attributes {
            xml.0.push(' ');
            xml.0.push_str(key);
            xml.0.push_str("=\"");
            xml.text(value);
            xml.0.push('"');
        }
        xml.0.push('>');
        xml
    }

    fn open(&mut self, tag: &str) {
        self.0.push('<');
        self.0.push_str(tag);
        self.0.push('>');
    }

    fn close(&mut self, tag: &str) {
        self.0.push_str("</");
        self.0.push_str(tag);
        self.0.push('>');
    }

    fn text(&mut self, value: &str) {
        for ch in value.chars() {
            match ch {
                '&' => self.0.push_str("&amp;"),
                '<' => self.0.push_str("&lt;"),
                '>' => self.0.push_str("&gt;"),
                '"' => self.0.push_str("&quot;"),
                '\'' => self.0.push_str("&apos;"),
                _ => self.0.push(ch),
            }
        }
    }

    fn element(&mut self, tag: &str, value: &str) {
        self.open(tag);
        self.text(value);
        self.close(tag);
    }

    fn entity(&mut self, entity: Entity) -> Result<()> {
        self.element("Last-Modified", &modified(entity)?);
        self.element("Etag", entity.etag().as_str());
        Ok(())
    }

    fn metadata(&mut self, metadata: Metadata) {
        self.open("Metadata");
        for (name, value) in metadata {
            self.element(&name, &value);
        }
        self.close("Metadata");
    }

    fn finish(mut self, root: &str, status: StatusCode) -> Response {
        self.close(root);
        let mut response = Response::new(Body::from(self.0));
        *response.status_mut() = status;
        response.headers_mut().insert(
            "content-type",
            HeaderValue::from_static("application/xml; charset=utf-8"),
        );
        response
    }
}
