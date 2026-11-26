//! Lifecycle state of a blob (expiry, immutability, legal hold, incremental copy),
//! the typed operations that change it, and its Azure errors and response fields.

use crate::{
    blob_expiry::{self, ExpiryOption},
    blob_immutability::{PolicyRequest, Protection},
    blob_sas::{Need, Public},
    blob_snapshot::Selector,
    conditions::Guard,
    domain::{BlobKey, BlobWrite, ContainerKey, Result},
    protocol::SourceRequest,
    respond::set,
    stamp::Ticks,
    wire::Xml,
};
use axum::http::{HeaderMap, StatusCode};

/// The snapshots an incremental copy blob remembers.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct Incremental {
    /// The last source snapshot copied into the blob.
    pub(crate) source: Ticks,
    /// The snapshot taken of the blob when that copy finished.
    pub(crate) destination: Ticks,
}

/// What a blob carries beyond its content and properties. Times are Unix milliseconds.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub(crate) struct Lifecycle {
    pub(crate) expires: Option<i64>,
    pub(crate) protection: Protection,
    /// Whether the account keeps versions, which lets a protected blob be overwritten.
    pub(crate) versioned: bool,
    pub(crate) incremental: Option<Incremental>,
}

impl Lifecycle {
    /// Writes that replace or change a protected blob are refused, except in a
    /// versioned account where the protected state stays behind as a version.
    pub(crate) fn check_write(&self, now: i64) -> Result<()> {
        if self.versioned {
            Ok(())
        } else {
            self.protection.check_delete(now)
        }
    }
}

/// Failures specific to the lifecycle operations.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum LifecycleError {
    ImmutableDueToPolicy,
    ImmutableDueToLegalHold,
    InsufficientAccountPermissions,
    IncrementalCopyBlobMismatch,
    IncrementalCopyOfEarlierSnapshot,
    IncrementalCopySourceMustBeSnapshot,
    InvalidSourceBlobType,
    OperationNotAllowedOnIncrementalCopyBlob,
    PreviousSnapshotCannotBeNewer,
    PreviousSnapshotNotFound,
    ConflictingTagOptions,
}

impl LifecycleError {
    pub(crate) fn describe(self) -> (StatusCode, &'static str, &'static str) {
        use StatusCode as S;
        match self {
            Self::ImmutableDueToPolicy => (
                S::CONFLICT,
                "BlobImmutableDueToPolicy",
                "This operation is not permitted as the blob is immutable due to a policy.",
            ),
            Self::ImmutableDueToLegalHold => (
                S::CONFLICT,
                "BlobImmutableDueToLegalHold",
                "This operation is not permitted as the blob is immutable due to one or more legal holds.",
            ),
            Self::InsufficientAccountPermissions => (
                S::FORBIDDEN,
                "InsufficientAccountPermissions",
                "The account being accessed does not have sufficient permissions to execute this operation.",
            ),
            Self::IncrementalCopyBlobMismatch => (
                S::CONFLICT,
                "IncrementalCopyBlobMismatch",
                "The specified source blob is different than the copy source of the existing incremental copy blob.",
            ),
            Self::IncrementalCopyOfEarlierSnapshot => (
                S::CONFLICT,
                "IncrementalCopyOfEarlierVersionSnapshotNotAllowed",
                "The specified snapshot is earlier than the last snapshot copied into the incremental copy blob.",
            ),
            Self::IncrementalCopySourceMustBeSnapshot => (
                S::CONFLICT,
                "IncrementalCopySourceMustBeSnapshot",
                "The source for incremental copy request must be a snapshot.",
            ),
            Self::InvalidSourceBlobType => (
                S::CONFLICT,
                "InvalidSourceBlobType",
                "The copy source blob type is invalid for this operation.",
            ),
            Self::OperationNotAllowedOnIncrementalCopyBlob => (
                S::CONFLICT,
                "OperationNotAllowedOnIncrementalCopyBlob",
                "The specified operation is not allowed on an incremental copy blob.",
            ),
            Self::PreviousSnapshotCannotBeNewer => (
                S::BAD_REQUEST,
                "PreviousSnapshotCannotBeNewer",
                "The prevsnapshot query parameter value cannot be newer than snapshot query parameter value.",
            ),
            Self::PreviousSnapshotNotFound => (
                S::CONFLICT,
                "PreviousSnapshotNotFound",
                "The previous snapshot is not found.",
            ),
            Self::ConflictingTagOptions => (
                S::CONFLICT,
                "InvalidHeaderValue",
                "x-ms-copy-source-tag-option COPY cannot be combined with x-ms-tags.",
            ),
        }
    }
}

pub(crate) enum LifecycleOperation {
    SetExpiry(BlobKey, ExpiryOption, Guard),
    SetImmutabilityPolicy(BlobKey, Option<Selector>, PolicyRequest, Guard),
    DeleteImmutabilityPolicy(BlobKey, Option<Selector>, Guard),
    SetLegalHold(BlobKey, Option<Selector>, bool, Guard),
    /// Restore Container: the destination, then the deleted container's name and version.
    RestoreContainer(ContainerKey, String, String),
    /// Incremental Copy Blob from a same-instance page blob snapshot.
    IncrementalCopy(Box<IncrementalCopy>),
}

/// The destination, its writing options, and the source of an Incremental Copy Blob.
pub(crate) struct IncrementalCopy {
    pub(crate) key: BlobKey,
    pub(crate) options: BlobWrite,
    pub(crate) source: SourceRequest,
}

const fn need(service: &'static str) -> Need {
    Need {
        service: Some(service),
        account: Some(('o', service)),
        public: Public::Never,
    }
}

impl LifecycleOperation {
    pub(crate) fn need(&self) -> Need {
        match self {
            Self::SetExpiry(..) => need("w"),
            Self::SetImmutabilityPolicy(..) | Self::DeleteImmutabilityPolicy(..) => need("i"),
            Self::SetLegalHold(..) => need("il"),
            Self::IncrementalCopy(..) => need("wc"),
            Self::RestoreContainer(..) => Need {
                service: None,
                account: Some(('c', "w")),
                public: Public::Never,
            },
        }
    }
}

/// The lifecycle response headers of Get Blob and Get Blob Properties.
pub(crate) fn lifecycle_headers(headers: &mut HeaderMap, lifecycle: &Lifecycle) -> Result<()> {
    if let Some(expires) = lifecycle.expires {
        set(
            headers,
            "x-ms-expiry-time",
            &blob_expiry::http_time(expires)?,
        )?;
    }
    let protection = &lifecycle.protection;
    if let (Some(until), Some(mode)) = (protection.until, protection.mode) {
        set(
            headers,
            "x-ms-immutability-policy-until-date",
            &blob_expiry::http_time(until)?,
        )?;
        set(headers, "x-ms-immutability-policy-mode", mode.name())?;
    }
    if protection.has_policy() || protection.legal_hold {
        set(
            headers,
            "x-ms-legal-hold",
            if protection.legal_hold {
                "true"
            } else {
                "false"
            },
        )?;
    }
    if let Some(incremental) = lifecycle.incremental {
        set(headers, "x-ms-incremental-copy", "true")?;
        set(
            headers,
            "x-ms-copy-destination-snapshot",
            &incremental.destination.text(),
        )?;
    }
    Ok(())
}

/// The lifecycle elements of a List Blobs `Properties`.
pub(crate) fn lifecycle_elements(xml: &mut Xml, lifecycle: &Lifecycle) -> Result<()> {
    if let Some(expires) = lifecycle.expires {
        xml.element("Expiry-Time", &blob_expiry::http_time(expires)?);
    }
    let protection = &lifecycle.protection;
    if let (Some(until), Some(mode)) = (protection.until, protection.mode) {
        xml.element(
            "ImmutabilityPolicyUntilDate",
            &blob_expiry::http_time(until)?,
        );
        xml.element("ImmutabilityPolicyMode", mode.name());
    }
    if protection.has_policy() || protection.legal_hold {
        xml.element(
            "LegalHold",
            if protection.legal_hold {
                "true"
            } else {
                "false"
            },
        );
    }
    if let Some(incremental) = lifecycle.incremental {
        xml.element("IncrementalCopy", "true");
        xml.element("DestinationSnapshot", &incremental.destination.text());
    }
    Ok(())
}
