//! Parses the lifecycle operations: Set Blob Expiry, immutability policies, legal
//! holds, Incremental Copy Blob, and Restore Container. Each returns `None` for
//! requests it does not own.

use super::{CONDITIONS, LEASE, Request, blob_write};
use crate::{
    auth::header,
    blob_expiry::ExpiryOption,
    blob_immutability::{PolicyRequest, parse_legal_hold},
    blob_lifecycle::{IncrementalCopy, LifecycleOperation},
    blob_snapshot,
    conditions::Guard,
    domain::{BlobKey, ContainerKey, Error, Result},
};
use axum::http::Method;

const POLICY_HEADERS: &[&str] = &[
    "x-ms-immutability-policy-until-date",
    "x-ms-immutability-policy-mode",
];

impl Request<'_> {
    pub(super) fn lifecycle_operation(&self, key: &BlobKey) -> Result<Option<LifecycleOperation>> {
        let key = key.clone();
        let guard = || Guard::parse(self.headers);
        Ok(Some(match (self.method, self.param("comp")) {
            (&Method::PUT, Some("expiry")) => {
                self.check(
                    &["comp"],
                    &[LEASE, &["x-ms-expiry-option", "x-ms-expiry-time"]],
                    false,
                )?;
                LifecycleOperation::SetExpiry(key, ExpiryOption::parse(self.headers)?, guard()?)
            }
            (&Method::PUT, Some("immutabilityPolicies")) => {
                self.check(
                    &["comp", "snapshot", "versionid"],
                    &[CONDITIONS, POLICY_HEADERS],
                    false,
                )?;
                LifecycleOperation::SetImmutabilityPolicy(
                    key,
                    blob_snapshot::selector(self.query)?,
                    PolicyRequest::parse(self.headers)?,
                    guard()?,
                )
            }
            (&Method::DELETE, Some("immutabilityPolicies")) => {
                self.check(&["comp", "snapshot", "versionid"], &[CONDITIONS], false)?;
                LifecycleOperation::DeleteImmutabilityPolicy(
                    key,
                    blob_snapshot::selector(self.query)?,
                    guard()?,
                )
            }
            (&Method::PUT, Some("legalhold")) => {
                self.check(
                    &["comp", "snapshot", "versionid"],
                    &[CONDITIONS, &["x-ms-legal-hold"]],
                    false,
                )?;
                LifecycleOperation::SetLegalHold(
                    key,
                    blob_snapshot::selector(self.query)?,
                    parse_legal_hold(self.headers)?,
                    guard()?,
                )
            }
            (&Method::PUT, Some("incrementalcopy")) => {
                self.check(&["comp"], &[&["x-ms-copy-source"], CONDITIONS, LEASE], true)?;
                self.require_empty_body()?;
                LifecycleOperation::IncrementalCopy(Box::new(IncrementalCopy {
                    key,
                    options: blob_write(self.headers, false)?,
                    source: self.source(None, true)?,
                }))
            }
            _ => return Ok(None),
        }))
    }

    /// Restore Container: `PUT ?restype=container&comp=undelete`, which names the
    /// deleted container and its version in headers and the new name in the path.
    pub(super) fn restore_container(
        &self,
        key: &ContainerKey,
    ) -> Result<Option<LifecycleOperation>> {
        if *self.method != Method::PUT
            || self.param("restype") != Some("container")
            || self.param("comp") != Some("undelete")
        {
            return Ok(None);
        }
        self.check(
            &["restype", "comp"],
            &[&[
                "x-ms-deleted-container-name",
                "x-ms-deleted-container-version",
            ]],
            false,
        )?;
        let name = header(self.headers, "x-ms-deleted-container-name")?;
        let version = header(self.headers, "x-ms-deleted-container-version")?;
        match (name, version) {
            (Some(name), Some(version)) if !name.is_empty() && !version.is_empty() => {
                Ok(Some(LifecycleOperation::RestoreContainer(
                    key.clone(),
                    name.to_owned(),
                    version.to_owned(),
                )))
            }
            _ => Err(Error::MissingHeader),
        }
    }
}
