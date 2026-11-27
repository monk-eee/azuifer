//! Share operations: list, create, and set properties.

use super::{Context, with_etag};
use crate::files::{
    error::{Error, Result},
    model::{Protocol, RootSquash},
    request::Headers,
    response::{self, ListSharesView, decode_marker},
    store::{ListSharesRequest, NfsShareSettings, ShareOptions},
};
use axum::{http::StatusCode, response::Response};

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
