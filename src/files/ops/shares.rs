//! Share operations: list, create, set properties, and the share's permissions.

use super::{Context, read_small, with_etag};
use crate::files::{
    error::{Error, Result},
    model::{Protocol, RootSquash},
    request::Headers,
    response::{self, ListSharesView, decode_marker, empty, set},
    sd,
    store::{ListSharesRequest, NfsShareSettings, ShareOptions},
    xml,
};
use axum::{body::Body, http::StatusCode, response::Response};

const MAX_QUOTA_GIB: u64 = 102_400;
const TIERS: [&str; 3] = ["TransactionOptimized", "Hot", "Cool"];

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

pub(super) async fn list_shares(ctx: &Context<'_>) -> Result<Response> {
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
                deleted: includes.iter().any(|include| include == "deleted"),
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

pub(super) async fn create_share(ctx: &Context<'_>) -> Result<Response> {
    let protocol = ctx
        .headers
        .get("x-ms-enabled-protocols")?
        .map(Protocol::parse)
        .transpose()?
        .unwrap_or_default();
    let squash = ctx
        .headers
        .get("x-ms-root-squash")?
        .map(RootSquash::parse)
        .transpose()?;
    let access = ctx
        .headers
        .optional_flag("x-ms-enable-snapshot-virtual-directory-access")?;
    // Root squash and snapshot directory access are NFS settings.
    if protocol != Protocol::Nfs && (squash.is_some() || access.is_some()) {
        return Err(Error::InvalidHeaderValue);
    }
    let options = ShareOptions {
        protocol,
        root_squash: (protocol == Protocol::Nfs).then(|| squash.unwrap_or_default()),
        snapshot_virtual_directory_access: access.unwrap_or(true),
    };
    let share = ctx
        .app
        .store
        .create_share(
            ctx.live()?,
            quota(&ctx.headers)?,
            tier(&ctx.headers)?,
            ctx.headers.metadata()?,
            options,
        )
        .await?;
    with_etag(StatusCode::CREATED, &share.etag, share.modified)
}

pub(super) async fn set_share_properties(ctx: &Context<'_>) -> Result<Response> {
    let nfs = NfsShareSettings {
        root_squash: ctx
            .headers
            .get("x-ms-root-squash")?
            .map(RootSquash::parse)
            .transpose()?,
        snapshot_virtual_directory_access: ctx
            .headers
            .optional_flag("x-ms-enable-snapshot-virtual-directory-access")?,
    };
    let share = ctx
        .app
        .store
        .set_share_properties(
            ctx.live()?,
            ctx.lease_id()?,
            quota(&ctx.headers)?,
            tier(&ctx.headers)?,
            nfs,
        )
        .await?;
    with_etag(StatusCode::OK, &share.etag, share.modified)
}

/// Create Permission. From 2024-11-04 the body may name `format` `sddl` or `binary`; an
/// older version ignores it, as it ignores any field it does not know (ADR-0032).
pub(super) async fn create_permission(ctx: &Context<'_>, body: Body) -> Result<Response> {
    ctx.deny_on_nfs().await?;
    let bytes = read_small(ctx, body).await?;
    let (permission, format) = xml::parse_permission(&bytes)?;
    let sddl = match format.as_deref().filter(|_| ctx.at_least("2024-11-04")) {
        None | Some("sddl") => permission,
        Some("binary") => sd::sddl_from_binary(&permission)?,
        Some(_) => return Err(Error::InvalidInput),
    };
    let key = ctx.app.store.create_permission(ctx.live()?, sddl).await?;
    let mut reply = empty(StatusCode::CREATED);
    set(reply.headers_mut(), "x-ms-file-permission-key", &key)?;
    Ok(reply)
}

/// Get Permission. From 2024-11-04 the answer names its `format`, and
/// `x-ms-file-permission-format: binary` asks for the base64 binary descriptor.
pub(super) async fn get_permission(ctx: &Context<'_>) -> Result<Response> {
    ctx.deny_on_nfs().await?;
    let key = ctx.headers.required("x-ms-file-permission-key")?.to_owned();
    let versioned = ctx.at_least("2024-11-04");
    let format = if versioned {
        ctx.headers.get("x-ms-file-permission-format")?
    } else {
        None
    };
    let sddl = ctx.app.store.permission(ctx.live()?, key).await?;
    let body = match format {
        None | Some("sddl") if versioned => {
            serde_json::json!({ "format": "sddl", "permission": sddl })
        }
        None | Some("sddl") => serde_json::json!({ "permission": sddl }),
        Some("binary") => {
            serde_json::json!({ "format": "binary", "permission": sd::binary_from_sddl(&sddl)? })
        }
        Some(_) => return Err(Error::InvalidHeaderValue),
    };
    Ok(response::json(StatusCode::OK, &body))
}
