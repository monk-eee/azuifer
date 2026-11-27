//! NFS hard links and symbolic links (ADR-0029).

use super::{Context, with_etag, with_node};
use crate::files::{
    error::{Error, Result},
    model::Posix,
    response::{self, set},
};
use axum::{http::StatusCode, response::Response};

/// First versions of the NFS link operations: hard links with NFS over REST, symbolic links
/// two versions later.
const HARD_LINK_VERSION: &str = "2025-05-05";
const SYMBOLIC_LINK_VERSION: &str = "2025-07-05";

/// A share snapshot is read-only; the link operations that write refuse one.
fn refuse_snapshot(ctx: &Context<'_>) -> Result<()> {
    if ctx.query.get("sharesnapshot").is_some() {
        return Err(Error::InvalidQueryParameterValue);
    }
    Ok(())
}

pub(super) async fn create_hard_link(ctx: &Context<'_>) -> Result<Response> {
    ctx.require_version(HARD_LINK_VERSION)?;
    refuse_snapshot(ctx)?;
    match ctx.headers.required("x-ms-type")? {
        value if value.eq_ignore_ascii_case("file") => {}
        _ => return Err(Error::InvalidHeaderValue),
    }
    let source = ctx.share_path(ctx.headers.required("x-ms-file-target-file")?)?;
    let node = ctx
        .app
        .store
        .create_hard_link(ctx.live()?, ctx.target.path.clone(), source)
        .await?;
    let mut reply = with_node(StatusCode::CREATED, &node)?;
    response::link_count_header(reply.headers_mut(), node.links)?;
    Ok(reply)
}

pub(super) async fn create_symbolic_link(ctx: &Context<'_>) -> Result<Response> {
    ctx.require_version(SYMBOLIC_LINK_VERSION)?;
    refuse_snapshot(ctx)?;
    let text = ctx.headers.required("x-ms-link-text")?.to_owned();
    let mut smb = ctx.headers.smb(true)?;
    // Only the two times a symbolic link can set; the rest is the share's business.
    smb.attributes = None;
    let node = ctx
        .app
        .store
        .create_symlink(
            ctx.live()?,
            ctx.target.path.clone(),
            text,
            Posix {
                mode: None,
                ..ctx.headers.posix()?
            },
            ctx.headers.metadata()?,
            smb,
        )
        .await?;
    with_node(StatusCode::CREATED, &node)
}

pub(super) async fn read_symbolic_link(ctx: &Context<'_>) -> Result<Response> {
    ctx.require_version(SYMBOLIC_LINK_VERSION)?;
    let node = ctx
        .app
        .store
        .read_symlink(ctx.share()?, ctx.target.path.clone())
        .await?;
    let mut reply = with_etag(StatusCode::OK, &node.etag, node.modified)?;
    let text = node
        .nfs
        .as_ref()
        .and_then(|nfs| nfs.link_text.as_deref())
        .unwrap_or_default();
    set(reply.headers_mut(), "x-ms-link-text", text)?;
    Ok(reply)
}
