//! File content operations: Put Range, Put Range From URL, List Ranges, and Copy File.

use super::{Context, local_source, with_etag};
use crate::{
    checksum::Checksum,
    files::{
        auth::{Signed, verify_sas},
        error::{Error, Result},
        model::{Metadata, NodeInfo, TimeSpec},
        name::ShareName,
        request::{ByteRange, Operation, Query, Target},
        response::{self, empty, etag_headers, set},
        store::{CopyRequest, CopySource, ReadOptions, ReadRange, ShareRef},
        stored_policy, time,
    },
};
use axum::{
    body::Body,
    http::{HeaderMap, Method, StatusCode},
    response::Response,
};
use base64::{Engine as _, engine::general_purpose::STANDARD as STANDARD_MD5};
use futures_util::StreamExt as _;

const MAX_RANGE_BYTES: u64 = 4 * 1024 * 1024;

/// `x-ms-file-last-write-time` of a range write: `now` (default) or `preserve`, in any case.
fn last_write_spec(ctx: &Context<'_>) -> Result<TimeSpec> {
    match ctx.headers.get("x-ms-file-last-write-time")? {
        None => Ok(TimeSpec::Now),
        Some(value) if value.eq_ignore_ascii_case("now") => Ok(TimeSpec::Now),
        Some(value) if value.eq_ignore_ascii_case("preserve") => Ok(TimeSpec::Preserve),
        Some(_) => Err(Error::InvalidHeaderValue),
    }
}

pub(super) async fn put_range(ctx: &Context<'_>, body: Body) -> Result<Response> {
    let (offset, length) = ctx
        .headers
        .range()?
        .ok_or(Error::MissingRequiredHeader)?
        .exact()?;
    let last_write = last_write_spec(ctx)?;
    let request_length = ctx.headers.content_length()?;
    match ctx.headers.required("x-ms-write")? {
        "clear" => {
            if request_length != 0 {
                return Err(Error::InvalidHeaderValue);
            }
            let node = ctx
                .app
                .store
                .clear_range(
                    ctx.live()?,
                    ctx.target.path.clone(),
                    ctx.lease_id()?,
                    offset,
                    length,
                    last_write,
                )
                .await?;
            range_response(&node, None)
        }
        "update" => {
            if length > MAX_RANGE_BYTES || request_length != length {
                return Err(Error::InvalidHeaderValue);
            }
            let checksum = match (
                ctx.headers.md5("content-md5")?,
                ctx.headers.crc64("x-ms-content-crc64")?,
            ) {
                (Some(md5), None) => Some(Checksum::Md5(md5)),
                (None, Some(crc)) => Some(Checksum::Crc64(crc)),
                (None, None) => None,
                (Some(_), Some(_)) => return Err(Error::InvalidHeaderValue),
            };
            write_range(ctx, (offset, length), checksum, last_write, body).await
        }
        _ => Err(Error::InvalidHeaderValue),
    }
}

/// Stages `body` and publishes it at `range` (`offset`, `length`), as Put Range
/// and Put Range From URL both do.
async fn write_range(
    ctx: &Context<'_>,
    (offset, length): (u64, u64),
    checksum: Option<Checksum>,
    last_write: TimeSpec,
    body: Body,
) -> Result<Response> {
    let mut upload = ctx.app.store.begin_upload(length).await?;
    let receive = async {
        let mut data = body.into_data_stream();
        while let Some(chunk) = data.next().await {
            upload
                .append(&chunk.map_err(|_| Error::InvalidInput)?)
                .await?;
        }
        Ok::<_, Error>(())
    };
    tokio::time::timeout(ctx.app.config.upload_timeout, receive)
        .await
        .map_err(|_| Error::OperationTimedOut)??;
    let staged = upload.finish(checksum).await?;
    let checksums = (
        STANDARD_MD5.encode(staged.checksums.md5),
        staged.checksums.response(Some(Checksum::Crc64(0))).1,
    );
    let node = ctx
        .app
        .store
        .put_range(
            ctx.live()?,
            ctx.target.path.clone(),
            ctx.lease_id()?,
            offset,
            staged,
            last_write,
        )
        .await?;
    range_response(
        &node,
        Some((checksums, matches!(checksum, Some(Checksum::Crc64(_))))),
    )
}

/// A SAS on a same-account source URL must itself allow reading that file, whatever the
/// request is signed with; a source URL without one is read with the request's own
/// credentials, as Learn describes for a source in the same account (ADR-0032).
async fn verify_source_sas(ctx: &Context<'_>, source: &Target, query: &Query) -> Result<()> {
    if query.get("sig").is_none() {
        return Ok(());
    }
    let refused = |_| Error::CopySourceNotAuthorized;
    let keys = ctx
        .app
        .config
        .accounts
        .get(&source.account)
        .ok_or(Error::CopySourceNotAuthorized)?;
    let policy = stored_policy(ctx.app, source, query)
        .await
        .map_err(refused)?;
    let signed = Signed {
        account: &source.account,
        keys,
        method: &Method::GET,
        raw_path: "",
        query,
        headers: &HeaderMap::new(),
        now: ctx.app.clock.now(),
        share: source.share.as_ref().map(ShareName::as_str),
        path: &source.decoded,
    };
    verify_sas(&signed, policy.as_ref())
        .and_then(|grant| grant.authorize(&Operation::GetFile.needs()))
        .map_err(refused)
}

/// Put Range From URL: writes a range read from a file on this instance and account.
pub(super) async fn put_range_from_url(ctx: &Context<'_>) -> Result<Response> {
    let (offset, length) = ctx
        .headers
        .range()?
        .ok_or(Error::MissingRequiredHeader)?
        .exact()?;
    let source_range = ByteRange::parse(ctx.headers.required("x-ms-source-range")?)?;
    if ctx.headers.required("x-ms-write")? != "update"
        || length > MAX_RANGE_BYTES
        || source_range.exact()?.1 != length
        || ctx.headers.content_length()? != 0
    {
        return Err(Error::InvalidHeaderValue);
    }
    let last_write = last_write_spec(ctx)?;
    let (source, query) = local_source(ctx, ctx.headers.required("x-ms-copy-source")?)?;
    if source.account != ctx.target.account {
        return Err(Error::CannotVerifyCopySource);
    }
    verify_source_sas(ctx, &source, &query).await?;
    let from = ShareRef {
        account: source.account.clone(),
        share: source.share.clone().ok_or(Error::InvalidHeaderValue)?,
        snapshot: query.snapshot("sharesnapshot")?,
    };
    let read = ctx
        .app
        .store
        .read_file(
            from,
            source.path,
            ReadOptions {
                lease_id: None,
                conditions: Default::default(),
                range: Some(ReadRange {
                    start: source_range.start,
                    end: source_range.end,
                }),
                want_md5: false,
                with_body: true,
            },
        )
        .await?;
    if read
        .range
        .is_none_or(|range| range.end - range.start != length)
    {
        return Err(Error::InvalidRange);
    }
    write_range(
        ctx,
        (offset, length),
        None,
        last_write,
        Body::from_stream(read.body.into_stream()),
    )
    .await
}

type Checksums = ((String, String), bool);

fn range_response(node: &NodeInfo, checksums: Option<Checksums>) -> Result<Response> {
    let mut reply = empty(StatusCode::CREATED);
    let headers = reply.headers_mut();
    etag_headers(headers, &node.etag, node.modified)?;
    set(headers, "x-ms-request-server-encrypted", "true")?;
    set(
        headers,
        "x-ms-file-last-write-time",
        &time::iso_ticks(node.last_write),
    )?;
    if let Some(((md5, crc64), wants_crc64)) = checksums {
        set(headers, "content-md5", &md5)?;
        if wants_crc64 {
            set(headers, "x-ms-content-crc64", &crc64)?;
        }
    }
    Ok(reply)
}

pub(super) async fn list_ranges(ctx: &Context<'_>) -> Result<Response> {
    let window = ctx.headers.range()?.map(|range: ByteRange| {
        range.start..range.end.map_or(u64::MAX, |end| end.saturating_add(1))
    });
    let previous = ctx.query.snapshot("prevsharesnapshot")?;
    let listing = ctx
        .app
        .store
        .list_ranges(
            ctx.share()?,
            ctx.target.path.clone(),
            ctx.lease_id()?,
            window,
            previous,
        )
        .await?;
    let mut reply = response::ranges(&listing.ranges, &listing.cleared);
    etag_headers(
        reply.headers_mut(),
        &listing.info.etag,
        listing.info.modified,
    )?;
    set(
        reply.headers_mut(),
        "x-ms-content-length",
        &listing.info.length.to_string(),
    )?;
    Ok(reply)
}

pub(super) async fn copy_file(ctx: &Context<'_>) -> Result<Response> {
    let url = ctx.headers.required("x-ms-copy-source")?;
    let (source, query) = local_source(ctx, url)?;
    if source.account != ctx.target.account {
        return Err(Error::CannotVerifyCopySource);
    }
    verify_source_sas(ctx, &source, &query).await?;
    let from = ShareRef {
        account: source.account.clone(),
        share: source.share.clone().ok_or(Error::InvalidHeaderValue)?,
        snapshot: query.snapshot("sharesnapshot")?,
    };
    let copy_mode_override = match ctx.headers.get("x-ms-file-copy-mode")? {
        None | Some("source") => false,
        Some("override") => true,
        Some(_) => return Err(Error::InvalidHeaderValue),
    };
    let metadata: Option<Metadata> = ctx
        .headers
        .has_metadata()
        .then(|| ctx.headers.metadata())
        .transpose()?;
    let ignore_readonly = ctx.headers.flag("x-ms-file-copy-ignore-read-only")?
        || ctx.headers.flag("x-ms-file-copy-ignore-readonly")?;
    let request = CopyRequest {
        dest_lease: ctx.lease_id()?,
        ignore_readonly,
        metadata,
        smb: copy_mode_override
            .then(|| ctx.headers.smb(true, &ctx.version))
            .transpose()?,
        nfs: ctx.headers.nfs_copy()?,
    };
    let clean_url = url.split('?').next().unwrap_or(url).to_owned();
    let (node, copy_id) = ctx
        .app
        .store
        .copy_file(
            CopySource {
                target: from,
                path: source.path,
                url: clean_url,
            },
            ctx.live()?,
            ctx.target.path.clone(),
            request,
        )
        .await?;
    let mut reply = with_etag(StatusCode::ACCEPTED, &node.etag, node.modified)?;
    set(reply.headers_mut(), "x-ms-copy-id", &copy_id)?;
    set(reply.headers_mut(), "x-ms-copy-status", "success")?;
    Ok(reply)
}
