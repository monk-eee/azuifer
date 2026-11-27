//! Executes the lifecycle operations and maps their outcomes to responses.

use super::{Context, resolve_source};
use crate::{
    blob_immutability::Protection,
    blob_lifecycle::{IncrementalCopy, LifecycleError, LifecycleOperation},
    blob_snapshot::Selector,
    domain::{CopyRecord, Error, Page, Result},
    respond::{empty, entity_response, http_date, lease_elements, set},
    server::App,
    store::ListedContainer,
    wire::Xml,
};
use axum::{http::StatusCode, response::Response};
use uuid::Uuid;

pub(super) async fn execute(
    app: &App,
    operation: LifecycleOperation,
    ctx: &Context<'_>,
) -> Result<Response> {
    let store = &app.store;
    match operation {
        LifecycleOperation::SetExpiry(key, option, guard) => {
            entity_response(StatusCode::OK, store.set_expiry(key, option, guard).await?)
        }
        LifecycleOperation::SetImmutabilityPolicy(key, selector, request, guard) => {
            let protection = store
                .set_immutability_policy(key, selector, request, guard)
                .await?;
            policy_response(&protection)
        }
        LifecycleOperation::DeleteImmutabilityPolicy(key, selector, guard) => {
            store
                .delete_immutability_policy(key, selector, guard)
                .await?;
            Ok(empty(StatusCode::OK))
        }
        LifecycleOperation::SetLegalHold(key, selector, hold, guard) => {
            let protection = store.set_legal_hold(key, selector, hold, guard).await?;
            let mut response = empty(StatusCode::OK);
            set(
                response.headers_mut(),
                "x-ms-legal-hold",
                if protection.legal_hold {
                    "true"
                } else {
                    "false"
                },
            )?;
            Ok(response)
        }
        LifecycleOperation::RestoreContainer(dest, name, version) => entity_response(
            StatusCode::CREATED,
            store.restore_container(name, version, dest).await?,
        ),
        LifecycleOperation::IncrementalCopy(copy) => {
            let IncrementalCopy {
                key,
                mut options,
                source: request,
            } = *copy;
            let resolved = resolve_source(app, ctx, &request).await?;
            let Some(Selector::Snapshot(snapshot)) = resolved.selector else {
                return Err(Error::Ext(
                    LifecycleError::IncrementalCopySourceMustBeSnapshot,
                ));
            };
            options.copy = Some(CopyRecord {
                id: Uuid::new_v4().to_string(),
                source: resolved.display.clone(),
            });
            let copied = store
                .incremental_copy(resolved.key.clone(), snapshot, key, options)
                .await?;
            let mut response = entity_response(StatusCode::ACCEPTED, copied.entity)?;
            set(response.headers_mut(), "x-ms-copy-id", &copied.copy_id)?;
            set(response.headers_mut(), "x-ms-copy-status", "success")?;
            Ok(response)
        }
    }
}

fn policy_response(protection: &Protection) -> Result<Response> {
    let mut response = empty(StatusCode::OK);
    if let (Some(until), Some(mode)) = (protection.until, protection.mode) {
        set(
            response.headers_mut(),
            "x-ms-immutability-policy-until-date",
            &crate::blob_expiry::http_time(until)?,
        )?;
        set(
            response.headers_mut(),
            "x-ms-immutability-policy-mode",
            mode.name(),
        )?;
    }
    Ok(response)
}

/// List Containers with `include=deleted`: soft-deleted containers appear with
/// `Deleted`, `Version`, `DeletedTime`, and `RemainingRetentionDays`.
pub(super) fn list_containers(
    mut xml: Xml,
    page: Page<ListedContainer>,
    metadata: bool,
) -> Result<Response> {
    for (_, listed) in page.items {
        let ListedContainer {
            name,
            info,
            deleted,
        } = listed;
        xml.open("Container");
        xml.element("Name", &name);
        if let Some(deleted) = &deleted {
            xml.element("Deleted", "true");
            xml.element("Version", &deleted.version);
        }
        xml.open("Properties");
        xml.entity(info.entity)?;
        lease_elements(&mut xml, info.lease);
        if let Some(access) = info.public_access.name() {
            xml.element("PublicAccess", access);
        }
        xml.element("DefaultEncryptionScope", "$account-encryption-key");
        xml.element("DenyEncryptionScopeOverride", "false");
        xml.element("HasImmutabilityPolicy", "false");
        xml.element("HasLegalHold", "false");
        if let Some(deleted) = &deleted {
            xml.element("DeletedTime", &http_date(deleted.deleted_at)?);
            xml.element(
                "RemainingRetentionDays",
                &deleted.remaining_days.to_string(),
            );
        }
        xml.close("Properties");
        if metadata && deleted.is_none() {
            xml.metadata(info.metadata);
        }
        xml.close("Container");
    }
    xml.close("Containers");
    xml.element("NextMarker", &page.next);
    Ok(xml.finish("EnumerationResults", StatusCode::OK))
}
