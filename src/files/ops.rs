//! Operation handlers: parse typed values from the request, call the store, build the response.

use super::{
    App,
    auth::Overrides,
    error::{Error, Result},
    lease::{self, Kind, Outcome},
    model::{AccessPolicy, Metadata, TimeSpec},
    request::{ByteRange, Headers, Operation, Query, Target, file_length},
    response::{
        self, EntryDetail, ListEntriesView, ListSharesView, decode_marker, empty, etag_headers,
        http_property_headers, node_headers, property_headers, set, share_headers,
    },
    store::{
        CopyRequest, CopySource, LeaseRequest, ListSharesRequest, NewFile, ReadOptions, ReadRange,
        RenameFlags, ShareRef, SnapshotPolicy, Want,
    },
    time, xml,
};
use crate::checksum::Checksum;
use axum::{
    body::{Body, Bytes, to_bytes},
    http::StatusCode,
    response::Response,
};
use futures_util::StreamExt as _;
use std::{ops::Range, sync::Arc, time::Duration};

const MAX_XML_BYTES: u64 = 1024 * 1024;
const MAX_RANGE_BYTES: u64 = 4 * 1024 * 1024;
const MAX_QUOTA_GIB: u64 = 102_400;
const TIERS: [&str; 3] = ["TransactionOptimized", "Hot", "Cool"];

pub(super) struct Context<'a> {
    pub(super) app: &'a Arc<App>,
    pub(super) operation: Operation,
    pub(super) target: Target,
    /// The `Host` the client addressed, when it used host-style addressing.
    pub(super) host: Option<String>,
    pub(super) query: Query,
    pub(super) headers: Headers<'a>,
    pub(super) overrides: Overrides,
}

impl Context<'_> {
    fn share(&self) -> Result<ShareRef> {
        Ok(ShareRef {
            account: self.target.account.clone(),
            share: self.target.share.clone().ok_or(Error::InvalidUri)?,
            snapshot: self.query.snapshot("sharesnapshot")?,
        })
    }

    /// The live share, for operations that snapshots do not support.
    fn live(&self) -> Result<ShareRef> {
        let target = self.share()?;
        if target.snapshot.is_some() {
            return Err(Error::ShareSnapshotOperationNotSupported);
        }
        Ok(target)
    }

    fn lease_id(&self) -> Result<Option<String>> {
        self.headers.lease_id("x-ms-lease-id")
    }

    fn now(&self) -> i64 {
        self.app.clock.now_millis()
    }

    fn endpoint(&self) -> String {
        let scheme = self.app.config.scheme();
        match &self.host {
            Some(host) => format!("{scheme}://{host}/"),
            None => format!(
                "{scheme}://{}/{}/",
                self.app.address,
                self.target.account.as_str()
            ),
        }
    }
}

fn with_node(status: StatusCode, node: &super::model::NodeInfo) -> Result<Response> {
    let mut response = empty(status);
    node_headers(response.headers_mut(), node)?;
    Ok(response)
}

fn with_etag(status: StatusCode, etag: &str, modified: i64) -> Result<Response> {
    let mut response = empty(status);
    etag_headers(response.headers_mut(), etag, modified)?;
    Ok(response)
}

pub(super) async fn execute(ctx: Context<'_>, body: Body) -> Result<Response> {
    use Operation as O;
    match ctx.operation {
        O::ListShares => list_shares(&ctx).await,
        O::CreateShare => create_share(&ctx).await,
        O::GetShareProperties | O::GetShareMetadata => {
            let share = ctx.app.store.share(ctx.share()?).await?;
            let mut response = empty(StatusCode::OK);
            share_headers(response.headers_mut(), &share, ctx.now())?;
            Ok(response)
        }
        O::SetShareProperties => set_share_properties(&ctx).await,
        O::SetShareMetadata => {
            let metadata = ctx.headers.metadata()?;
            let share = ctx
                .app
                .store
                .set_share_metadata(ctx.live()?, ctx.lease_id()?, metadata)
                .await?;
            with_etag(StatusCode::OK, &share.etag, share.modified)
        }
        O::DeleteShare => {
            let policy = match ctx.headers.get("x-ms-delete-snapshots")? {
                None => SnapshotPolicy::Refuse,
                Some("include") => SnapshotPolicy::Include,
                Some("include-leased") => SnapshotPolicy::IncludeLeased,
                Some(_) => return Err(Error::InvalidHeaderValue),
            };
            ctx.app
                .store
                .delete_share(ctx.share()?, ctx.lease_id()?, policy)
                .await?;
            Ok(empty(StatusCode::ACCEPTED))
        }
        O::GetShareAcl => {
            let (share, policies) = ctx.app.store.share_acl(ctx.live()?).await?;
            let mut reply = response::access_policies(&policies);
            etag_headers(reply.headers_mut(), &share.etag, share.modified)?;
            Ok(reply)
        }
        O::SetShareAcl => {
            let bytes = read_small(&ctx, body).await?;
            let policies = xml::parse_access_policies(&bytes)?;
            let share = ctx
                .app
                .store
                .set_share_acl(ctx.live()?, ctx.lease_id()?, policies)
                .await?;
            with_etag(StatusCode::OK, &share.etag, share.modified)
        }
        O::GetShareStats => {
            let target = ctx.live()?;
            let share = ctx.app.store.share(target.clone()).await?;
            let usage = ctx.app.store.share_usage(target).await?;
            let mut reply = response::share_stats(usage);
            etag_headers(reply.headers_mut(), &share.etag, share.modified)?;
            Ok(reply)
        }
        O::LeaseShare => {
            let request = lease_request(&ctx.headers)?;
            let (share, outcome) = ctx.app.store.lease_share(ctx.share()?, request).await?;
            lease_response(outcome, &share.etag, share.modified)
        }
        O::SnapshotShare => {
            let metadata = ctx
                .headers
                .has_metadata()
                .then(|| ctx.headers.metadata())
                .transpose()?;
            let share = ctx.app.store.snapshot_share(ctx.live()?, metadata).await?;
            let mut reply = with_etag(StatusCode::CREATED, &share.etag, share.modified)?;
            if let Some(snapshot) = share.snapshot {
                set(reply.headers_mut(), "x-ms-snapshot", &time::iso(snapshot))?;
            }
            Ok(reply)
        }
        O::CreatePermission => {
            let bytes = read_small(&ctx, body).await?;
            let key = ctx
                .app
                .store
                .create_permission(ctx.live()?, xml::parse_permission(&bytes)?)
                .await?;
            let mut reply = empty(StatusCode::CREATED);
            set(reply.headers_mut(), "x-ms-file-permission-key", &key)?;
            Ok(reply)
        }
        O::GetPermission => {
            let key = ctx.headers.required("x-ms-file-permission-key")?.to_owned();
            let sddl = ctx.app.store.permission(ctx.live()?, key).await?;
            Ok(response::json(
                StatusCode::OK,
                &serde_json::json!({ "permission": sddl }),
            ))
        }
        O::CreateDirectory => {
            let node = ctx
                .app
                .store
                .create_directory(
                    ctx.live()?,
                    ctx.target.path.clone(),
                    ctx.headers.smb(true)?,
                    ctx.headers.metadata()?,
                )
                .await?;
            with_node(StatusCode::CREATED, &node)
        }
        O::GetDirectoryProperties => {
            let node = ctx
                .app
                .store
                .node(
                    ctx.share()?,
                    ctx.target.path.clone(),
                    Want::Directory,
                    None,
                    ctx.headers.conditions()?,
                )
                .await?;
            let mut reply = empty(StatusCode::OK);
            property_headers(reply.headers_mut(), &node, ctx.now())?;
            Ok(reply)
        }
        O::SetDirectoryProperties => {
            let node = ctx
                .app
                .store
                .set_directory_properties(
                    ctx.live()?,
                    ctx.target.path.clone(),
                    ctx.headers.smb(false)?,
                )
                .await?;
            with_node(StatusCode::OK, &node)
        }
        O::GetDirectoryMetadata | O::GetFileMetadata => {
            let want = if ctx.operation == O::GetFileMetadata {
                Want::File
            } else {
                Want::Directory
            };
            let node = ctx
                .app
                .store
                .node(
                    ctx.share()?,
                    ctx.target.path.clone(),
                    want,
                    ctx.lease_id()?,
                    ctx.headers.conditions()?,
                )
                .await?;
            let mut reply = empty(StatusCode::OK);
            property_headers(reply.headers_mut(), &node, ctx.now())?;
            Ok(reply)
        }
        O::SetDirectoryMetadata | O::SetFileMetadata => {
            let want = if ctx.operation == O::SetFileMetadata {
                Want::File
            } else {
                Want::Directory
            };
            let node = ctx
                .app
                .store
                .set_metadata(
                    ctx.live()?,
                    ctx.target.path.clone(),
                    want,
                    ctx.lease_id()?,
                    ctx.headers.metadata()?,
                )
                .await?;
            with_etag(StatusCode::OK, &node.etag, node.modified)
        }
        O::DeleteDirectory => {
            ctx.app
                .store
                .delete_directory(ctx.live()?, ctx.target.path.clone())
                .await?;
            Ok(empty(StatusCode::ACCEPTED))
        }
        O::ListFilesAndDirectories => list_entries(&ctx).await,
        O::RenameDirectory | O::RenameFile => rename(&ctx).await,
        O::ListDirectoryHandles
        | O::ListFileHandles
        | O::ForceCloseDirectoryHandles
        | O::ForceCloseFileHandles => handles(&ctx).await,
        O::CreateFile => create_file(&ctx).await,
        O::GetFile | O::GetFileProperties => get_file(&ctx).await,
        O::SetFileProperties => {
            let length = file_length(&ctx.headers, "x-ms-content-length")?;
            let node = ctx
                .app
                .store
                .set_file_properties(
                    ctx.live()?,
                    ctx.target.path.clone(),
                    ctx.lease_id()?,
                    length,
                    ctx.headers.http_properties()?,
                    ctx.headers.smb(false)?,
                )
                .await?;
            with_node(StatusCode::OK, &node)
        }
        O::DeleteFile => {
            ctx.app
                .store
                .delete_file(ctx.live()?, ctx.target.path.clone(), ctx.lease_id()?)
                .await?;
            Ok(empty(StatusCode::ACCEPTED))
        }
        O::PutRange => put_range(&ctx, body).await,
        O::PutRangeFromUrl => put_range_from_url(&ctx).await,
        O::ListRanges => list_ranges(&ctx).await,
        O::CopyFile => copy_file(&ctx).await,
        O::AbortCopyFile => {
            if ctx.headers.get("x-ms-copy-action")? != Some("abort") {
                return Err(Error::InvalidHeaderValue);
            }
            let copy_id = ctx
                .query
                .get("copyid")
                .ok_or(Error::InvalidQueryParameterValue)?
                .to_owned();
            ctx.app
                .store
                .abort_copy(
                    ctx.live()?,
                    ctx.target.path.clone(),
                    copy_id,
                    ctx.lease_id()?,
                )
                .await?;
            Ok(empty(StatusCode::NO_CONTENT))
        }
        O::LeaseFile => {
            let request = lease_request(&ctx.headers)?;
            let (node, outcome) = ctx
                .app
                .store
                .lease_file(ctx.share()?, ctx.target.path.clone(), request)
                .await?;
            lease_response(outcome, &node.etag, node.modified)
        }
        O::GetFileServiceProperties
        | O::SetFileServiceProperties
        | O::RestoreShare
        | O::CreateHardLink
        | O::CreateSymbolicLink
        | O::GetSymbolicLink => Err(Error::NotImplemented),
    }
}

async fn read_small(ctx: &Context<'_>, body: Body) -> Result<Bytes> {
    let length = ctx.headers.content_length()?;
    if length > MAX_XML_BYTES {
        return Err(Error::RequestBodyTooLarge);
    }
    let bytes = tokio::time::timeout(
        ctx.app.config.upload_timeout,
        to_bytes(body, MAX_XML_BYTES as usize),
    )
    .await
    .map_err(|_| Error::OperationTimedOut)?
    .map_err(|_| Error::InvalidInput)?;
    if bytes.len() as u64 != length {
        return Err(Error::InvalidInput);
    }
    Ok(bytes)
}

fn quota(headers: &Headers<'_>) -> Result<Option<u64>> {
    headers
        .number("x-ms-share-quota")?
        .map(|quota| {
            if (1..=MAX_QUOTA_GIB).contains(&quota) {
                Ok(quota)
            } else {
                Err(Error::InvalidHeaderValue)
            }
        })
        .transpose()
}

fn tier(headers: &Headers<'_>) -> Result<Option<String>> {
    headers
        .get("x-ms-access-tier")?
        .map(|tier| {
            TIERS
                .iter()
                .find(|known| known.eq_ignore_ascii_case(tier))
                .map(|known| (*known).to_owned())
                .ok_or(Error::InvalidHeaderValue)
        })
        .transpose()
}

async fn list_shares(ctx: &Context<'_>) -> Result<Response> {
    let includes = ctx.query.includes();
    let marker = ctx.query.get("marker").filter(|marker| !marker.is_empty());
    let after = marker
        .map(|marker| {
            let text = decode_marker(marker)?;
            let (name, snapshot) = text
                .split_once('\0')
                .ok_or(Error::InvalidContinuationToken)?;
            let snapshot = snapshot
                .parse()
                .map_err(|_| Error::InvalidContinuationToken)?;
            Ok::<_, Error>((name.to_owned(), snapshot))
        })
        .transpose()?;
    let limit = ctx.query.limit()?;
    let prefix = ctx.query.get("prefix").unwrap_or_default();
    let (shares, next) = ctx
        .app
        .store
        .list_shares(
            ctx.target.account.clone(),
            ListSharesRequest {
                prefix: prefix.to_owned(),
                after,
                limit,
                snapshots: includes.iter().any(|include| include == "snapshots"),
            },
        )
        .await?;
    let view = ListSharesView {
        prefix,
        marker,
        limit,
        metadata: includes.iter().any(|include| include == "metadata"),
    };
    response::list_shares(&ctx.endpoint(), &view, &shares, next, ctx.now())
}

async fn create_share(ctx: &Context<'_>) -> Result<Response> {
    if ctx
        .headers
        .get("x-ms-enabled-protocols")?
        .is_some_and(|protocols| !protocols.eq_ignore_ascii_case("SMB"))
    {
        return Err(Error::NotImplemented);
    }
    let share = ctx
        .app
        .store
        .create_share(
            ctx.live()?,
            quota(&ctx.headers)?,
            tier(&ctx.headers)?,
            ctx.headers.metadata()?,
        )
        .await?;
    with_etag(StatusCode::CREATED, &share.etag, share.modified)
}

async fn set_share_properties(ctx: &Context<'_>) -> Result<Response> {
    let share = ctx
        .app
        .store
        .set_share_properties(
            ctx.live()?,
            ctx.lease_id()?,
            quota(&ctx.headers)?,
            tier(&ctx.headers)?,
        )
        .await?;
    with_etag(StatusCode::OK, &share.etag, share.modified)
}

fn lease_request(headers: &Headers<'_>) -> Result<LeaseRequest> {
    let id =
        |name| -> Result<String> { headers.lease_id(name)?.ok_or(Error::MissingRequiredHeader) };
    match headers.required("x-ms-lease-action")? {
        "acquire" => {
            let duration = headers
                .required("x-ms-lease-duration")?
                .parse()
                .map_err(|_| Error::InvalidHeaderValue)?;
            Ok(LeaseRequest::Acquire {
                duration,
                proposed: headers.lease_id("x-ms-proposed-lease-id")?,
            })
        }
        "renew" => Ok(LeaseRequest::Renew(id("x-ms-lease-id")?)),
        "change" => Ok(LeaseRequest::Change {
            id: id("x-ms-lease-id")?,
            proposed: id("x-ms-proposed-lease-id")?,
        }),
        "release" => Ok(LeaseRequest::Release(id("x-ms-lease-id")?)),
        "break" => {
            let period = headers
                .number("x-ms-lease-break-period")?
                .map(|period| {
                    i64::try_from(period)
                        .ok()
                        .filter(|period| *period <= lease::MAX_BREAK_PERIOD)
                        .ok_or(Error::InvalidHeaderValue)
                })
                .transpose()?;
            Ok(LeaseRequest::Break(period))
        }
        _ => Err(Error::InvalidHeaderValue),
    }
}

fn lease_response(outcome: Outcome, etag: &str, modified: i64) -> Result<Response> {
    let (status, id, remaining) = match outcome {
        Outcome::Acquired(id) => (StatusCode::CREATED, Some(id), None),
        Outcome::Renewed(id) | Outcome::Changed(id) => (StatusCode::OK, Some(id), None),
        Outcome::Released => (StatusCode::OK, None, None),
        Outcome::Broken(seconds) => (StatusCode::ACCEPTED, None, Some(seconds)),
    };
    let mut reply = with_etag(status, etag, modified)?;
    if let Some(id) = id {
        set(reply.headers_mut(), "x-ms-lease-id", &id)?;
    }
    if let Some(seconds) = remaining {
        set(reply.headers_mut(), "x-ms-lease-time", &seconds.to_string())?;
    }
    Ok(reply)
}

async fn list_entries(ctx: &Context<'_>) -> Result<Response> {
    let includes = ctx.query.includes();
    let target = ctx.share()?;
    let marker = ctx.query.get("marker").filter(|marker| !marker.is_empty());
    let after = marker.map(decode_marker).transpose()?;
    let limit = ctx.query.limit()?;
    let prefix = ctx.query.get("prefix").filter(|prefix| !prefix.is_empty());
    let listing = ctx
        .app
        .store
        .list_directory(
            target.clone(),
            ctx.target.path.clone(),
            prefix.unwrap_or_default().to_owned(),
            after,
            limit,
        )
        .await?;
    let has = |name: &str| includes.iter().any(|include| include == name);
    let view = ListEntriesView {
        endpoint: &ctx.endpoint(),
        target: &target,
        directory: &ctx.target.path.joined(),
        prefix,
        marker,
        limit: ctx.query.get("maxresults").map(|_| limit),
        detail: EntryDetail {
            timestamps: has("timestamps"),
            etag: has("etag"),
            attributes: has("attributes"),
            permission_key: has("permissionkey"),
        },
    };
    Ok(response::list_entries(&view, &listing))
}

/// Splits a same-instance URL (or absolute path) into its path and query.
fn local_source(ctx: &Context<'_>, url: &str) -> Result<(Target, Query)> {
    let path_and_query = if let Some(rest) = url
        .strip_prefix("http://")
        .or_else(|| url.strip_prefix("https://"))
    {
        let (authority, path) = rest.split_once('/').ok_or(Error::InvalidHeaderValue)?;
        let host = authority.split(':').next().unwrap_or_default();
        let port = authority
            .rsplit_once(':')
            .and_then(|(_, port)| port.parse::<u16>().ok());
        // Azure CLI builds source URLs as `{account}.file.core.windows.net` regardless of the
        // configured endpoint, so a host-style name of a configured account is local too.
        let host_account = host
            .split_once(".file.")
            .and_then(|(account, _)| crate::domain::AccountName::parse(account).ok())
            .filter(|account| ctx.app.config.accounts.contains_key(account));
        if let Some(account) = host_account {
            format!("/{}/{path}", account.as_str())
        } else if port == Some(ctx.app.address.port()) {
            format!("/{path}")
        } else {
            return Err(Error::NotImplemented);
        }
    } else if url.starts_with('/') {
        url.to_owned()
    } else {
        return Err(Error::InvalidHeaderValue);
    };
    let (path, query) = path_and_query
        .split_once('?')
        .unwrap_or((path_and_query.as_str(), ""));
    let keep = ctx.headers.flag("x-ms-source-allow-trailing-dot")?
        || ctx.headers.flag("x-ms-allow-trailing-dot")?;
    let source = Target::parse(path, keep).map_err(|_| Error::InvalidHeaderValue)?;
    Ok((source, Query::parse(Some(query))?))
}

async fn rename(ctx: &Context<'_>) -> Result<Response> {
    let url = ctx.headers.required("x-ms-file-rename-source")?;
    let (source, query) = local_source(ctx, url)?;
    if query.get("sharesnapshot").is_some() {
        return Err(Error::InvalidQueryParameterValue);
    }
    if source.account != ctx.target.account || source.share != ctx.target.share {
        return Err(Error::RenameAcrossAccountsAndSharesNotSupported);
    }
    if ctx.query.get("sharesnapshot").is_some() {
        return Err(Error::InvalidQueryParameterValue);
    }
    let replace = ctx.headers.flag("x-ms-file-rename-replace-if-exists")?;
    let ignore_readonly = ctx.headers.flag("x-ms-file-rename-ignore-readonly")?;
    if ignore_readonly && !replace {
        return Err(Error::InvalidHeaderValue);
    }
    let flags = RenameFlags {
        replace,
        ignore_readonly,
        source_lease: ctx.headers.lease_id("x-ms-source-lease-id")?,
        dest_lease: ctx.headers.lease_id("x-ms-destination-lease-id")?,
        content_type: ctx.headers.get("x-ms-content-type")?.map(str::to_owned),
        metadata: ctx
            .headers
            .has_metadata()
            .then(|| ctx.headers.metadata())
            .transpose()?,
        smb: ctx.headers.smb(false)?,
    };
    let node = ctx
        .app
        .store
        .rename(ctx.live()?, source.path, ctx.target.path.clone(), flags)
        .await?;
    with_node(StatusCode::OK, &node)
}

/// Handles are recorded metadata only: there is no SMB session, so none are ever open.
async fn handles(ctx: &Context<'_>) -> Result<Response> {
    let (want, close) = match ctx.operation {
        Operation::ListDirectoryHandles => (Want::Directory, false),
        Operation::ForceCloseDirectoryHandles => (Want::Directory, true),
        Operation::ListFileHandles => (Want::File, false),
        _ => (Want::File, true),
    };
    ctx.app
        .store
        .node(
            ctx.share()?,
            ctx.target.path.clone(),
            want,
            None,
            Default::default(),
        )
        .await?;
    if !close {
        return Ok(response::no_handles());
    }
    ctx.headers.required("x-ms-handle-id")?;
    let mut reply = empty(StatusCode::OK);
    set(reply.headers_mut(), "x-ms-number-of-handles-closed", "0")?;
    set(reply.headers_mut(), "x-ms-number-of-handles-failed", "0")?;
    Ok(reply)
}

async fn create_file(ctx: &Context<'_>) -> Result<Response> {
    match ctx.headers.required("x-ms-type")? {
        value if value.eq_ignore_ascii_case("file") => {}
        _ => return Err(Error::InvalidHeaderValue),
    }
    let length =
        file_length(&ctx.headers, "x-ms-content-length")?.ok_or(Error::MissingRequiredHeader)?;
    let node = ctx
        .app
        .store
        .create_file(
            ctx.live()?,
            ctx.target.path.clone(),
            NewFile {
                length,
                http: ctx.headers.http_properties()?.unwrap_or_default(),
                smb: ctx.headers.smb(true)?,
                metadata: ctx.headers.metadata()?,
            },
            ctx.lease_id()?,
        )
        .await?;
    with_node(StatusCode::CREATED, &node)
}

async fn get_file(ctx: &Context<'_>) -> Result<Response> {
    let head = ctx.operation == Operation::GetFileProperties;
    let range = if head { None } else { ctx.headers.range()? };
    let want_md5 = !head && ctx.headers.flag("x-ms-range-get-content-md5")?;
    if want_md5 && range.is_none() {
        return Err(Error::InvalidHeaderValue);
    }
    let read = ctx
        .app
        .store
        .read_file(
            ctx.share()?,
            ctx.target.path.clone(),
            ReadOptions {
                lease_id: ctx.lease_id()?,
                conditions: ctx.headers.conditions()?,
                range: range.map(|range| ReadRange {
                    start: range.start,
                    end: range.end,
                }),
                want_md5,
                with_body: !head,
            },
        )
        .await?;
    let node = &read.info;
    let status = if read.range.is_some() {
        StatusCode::PARTIAL_CONTENT
    } else {
        StatusCode::OK
    };
    let mut reply = empty(status);
    let headers = reply.headers_mut();
    property_headers(headers, node, ctx.now())?;
    http_property_headers(headers, node)?;
    for (name, value) in &ctx.overrides.0 {
        set(headers, name, value)?;
    }
    set(headers, "accept-ranges", "bytes")?;
    match &read.range {
        Some(range) => {
            set(
                headers,
                "content-length",
                &(range.end - range.start).to_string(),
            )?;
            set(
                headers,
                "content-range",
                &format!("bytes {}-{}/{}", range.start, range.end - 1, node.length),
            )?;
        }
        None => set(headers, "content-length", &node.length.to_string())?,
    }
    if let Some(md5) = read.md5.as_ref().or(if read.range.is_none() {
        node.http.md5.as_ref()
    } else {
        None
    }) {
        set(headers, "content-md5", md5)?;
    }
    if !head {
        *reply.body_mut() = Body::from_stream(read.body.into_stream());
    }
    Ok(reply)
}

/// `x-ms-file-last-write-time` of a range write: `now` (default) or `preserve`, in any case.
fn last_write_spec(ctx: &Context<'_>) -> Result<TimeSpec> {
    match ctx.headers.get("x-ms-file-last-write-time")? {
        None => Ok(TimeSpec::Now),
        Some(value) if value.eq_ignore_ascii_case("now") => Ok(TimeSpec::Now),
        Some(value) if value.eq_ignore_ascii_case("preserve") => Ok(TimeSpec::Preserve),
        Some(_) => Err(Error::InvalidHeaderValue),
    }
}

async fn put_range(ctx: &Context<'_>, body: Body) -> Result<Response> {
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

/// Put Range From URL: writes a range read from a file on this instance and account.
async fn put_range_from_url(ctx: &Context<'_>) -> Result<Response> {
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

use base64::{Engine as _, engine::general_purpose::STANDARD as STANDARD_MD5};

type Checksums = ((String, String), bool);

fn range_response(node: &super::model::NodeInfo, checksums: Option<Checksums>) -> Result<Response> {
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

async fn list_ranges(ctx: &Context<'_>) -> Result<Response> {
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

async fn copy_file(ctx: &Context<'_>) -> Result<Response> {
    let url = ctx.headers.required("x-ms-copy-source")?;
    let (source, query) = local_source(ctx, url)?;
    if source.account != ctx.target.account {
        return Err(Error::CannotVerifyCopySource);
    }
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
            .then(|| ctx.headers.smb(true))
            .transpose()?,
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

#[allow(dead_code)]
fn _types(_: Range<u64>, _: Duration, _: Kind, _: AccessPolicy) {}
