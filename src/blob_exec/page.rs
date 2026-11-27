//! Executes page and append blob operations and maps their outcomes to responses.

use super::{Context, copy_write, read_source, receive_upload};
use crate::{
    blob_copy::Resolved,
    blob_page::{MAX_APPEND_BLOCK_BYTES, MAX_WRITE_BYTES, PageOperation},
    domain::{BlobInfo, BlobKey, BlobWrite, Error, Result},
    protocol::SourceRequest,
    respond::{entity_headers, entity_response, set, write_response},
    server::App,
    store::{Appended, PageRanges, PageWritten},
    wire::Xml,
};
use axum::{
    body::Body,
    http::{HeaderValue, StatusCode},
    response::Response,
};

pub(super) async fn execute(
    app: &App,
    operation: PageOperation,
    body: Body,
    ctx: &Context<'_>,
) -> Result<Response> {
    let store = &app.store;
    match operation {
        PageOperation::Create(key, options, creation) => {
            let entity = store.create_paged(key, options, creation).await?;
            encrypted(entity_response(StatusCode::CREATED, entity)?)
        }
        PageOperation::PutPage(key, write, Some(options)) => {
            let upload = receive_upload(app, body, &options).await?;
            let checksum = upload.checksums.response(options.checksum);
            let written = store.put_page(key, write, Some(upload)).await?;
            page_written(written, Some(checksum))
        }
        PageOperation::PutPage(key, write, None) => {
            page_written(store.put_page(key, write, None).await?, None)
        }
        PageOperation::PutPageFromUrl(key, write, request) => {
            if write.range.end - write.range.start > MAX_WRITE_BYTES {
                return Err(Error::TooLarge);
            }
            let (source, _) = read_source(app, ctx, request).await?;
            let checksum = ("content-md5", source.upload.checksums.md5_text());
            let written = store.put_page(key, write, Some(source.upload)).await?;
            page_written(written, Some(checksum))
        }
        PageOperation::PageRanges(key, query) => {
            let paged = query.limit.is_some() || query.marker.is_some();
            page_list(store.page_ranges(key, query).await?, paged)
        }
        PageOperation::AppendBlock(key, write, options) => {
            let upload = receive_upload(app, body, &options).await?;
            let checksum = upload.checksums.response(options.checksum);
            appended(store.append_block(key, write, upload).await?, checksum)
        }
        PageOperation::AppendBlockFromUrl(key, write, request) => {
            let (source, _) = read_source(app, ctx, request).await?;
            if source.upload.len() == 0 || source.upload.len() > MAX_APPEND_BLOCK_BYTES {
                return Err(Error::InvalidHeader);
            }
            let checksum = ("content-md5", source.upload.checksums.md5_text());
            appended(
                store.append_block(key, write, source.upload).await?,
                checksum,
            )
        }
        PageOperation::Seal(key, write) => {
            let entity = store.seal_blob(key, write).await?;
            let mut response = entity_response(StatusCode::OK, entity)?;
            set(response.headers_mut(), "x-ms-blob-sealed", "true")?;
            Ok(response)
        }
    }
}

/// Copy Blob of a page or append blob shares the source's extents. Returns `None`
/// when the source is a block blob, which the caller copies by content.
pub(super) async fn copy_ranges(
    app: &App,
    key: &BlobKey,
    options: &BlobWrite,
    source: &Resolved,
    request: &SourceRequest,
) -> Result<Option<Response>> {
    let choices = (request.replace_metadata, request.copy_tags);
    let display = source.display.clone();
    let options = options.clone();
    let copied = app
        .store
        .copy_ranges(
            source.key.clone(),
            source.selector,
            request.guard.clone(),
            key.clone(),
            move |info: &BlobInfo| copy_write(options, info, choices, display),
        )
        .await?;
    let Some(copied) = copied else {
        return Ok(None);
    };
    let mut response = entity_response(StatusCode::ACCEPTED, copied.entity)?;
    set(response.headers_mut(), "x-ms-copy-id", &copied.copy_id)?;
    set(response.headers_mut(), "x-ms-copy-status", "success")?;
    Ok(Some(response))
}

fn encrypted(mut response: Response) -> Result<Response> {
    response.headers_mut().insert(
        "x-ms-request-server-encrypted",
        HeaderValue::from_static("false"),
    );
    Ok(response)
}

fn page_written(
    written: PageWritten,
    checksum: Option<(&'static str, String)>,
) -> Result<Response> {
    let mut response = entity_response(StatusCode::CREATED, written.entity)?;
    set(
        response.headers_mut(),
        "x-ms-blob-sequence-number",
        &written.sequence.to_string(),
    )?;
    match checksum {
        Some(checksum) => write_response(response, checksum),
        None => encrypted(response),
    }
}

fn appended(appended: Appended, checksum: (&'static str, String)) -> Result<Response> {
    let Appended {
        entity,
        offset,
        committed,
    } = appended;
    let mut response = entity_response(StatusCode::CREATED, entity)?;
    set(
        response.headers_mut(),
        "x-ms-blob-append-offset",
        &offset.to_string(),
    )?;
    set(
        response.headers_mut(),
        "x-ms-blob-committed-block-count",
        &committed.to_string(),
    )?;
    write_response(response, checksum)
}

fn page_list(list: PageRanges, paged: bool) -> Result<Response> {
    let mut xml = Xml::root("PageList", &[]);
    // A diff lists changed and cleared ranges together, in offset order.
    let mut entries: Vec<(&std::ops::Range<u64>, &str)> = list
        .ranges
        .iter()
        .map(|range| (range, "PageRange"))
        .chain(list.cleared.iter().map(|range| (range, "ClearRange")))
        .collect();
    entries.sort_by_key(|(range, _)| range.start);
    for (range, tag) in entries {
        xml.open(tag);
        xml.element("Start", &range.start.to_string());
        xml.element("End", &(range.end - 1).to_string());
        xml.close(tag);
    }
    if paged {
        xml.element(
            "NextMarker",
            &list.next.map(|next| next.to_string()).unwrap_or_default(),
        );
    }
    let mut response = xml.finish("PageList", StatusCode::OK);
    entity_headers(response.headers_mut(), list.entity)?;
    set(
        response.headers_mut(),
        "x-ms-blob-content-length",
        &list.length.to_string(),
    )?;
    Ok(response)
}
