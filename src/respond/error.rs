//! Maps Blob errors to Azure status codes, headers, and XML diagnostics.

use super::{empty, http_date, set};
use crate::{
    blob_lifecycle::LifecycleError,
    blob_page::PageError,
    domain::{Error, Result},
    wire::{correlated_error_message, xml_error, xml_error_with_details},
};
use axum::{
    http::{HeaderMap, HeaderValue, StatusCode},
    response::Response,
};
use std::time::{SystemTime, UNIX_EPOCH};

/// The Azure status, error code, and message for a domain error.
fn describe(error: Error) -> (StatusCode, &'static str, &'static str) {
    use StatusCode as S;
    match error {
        Error::AuthenticationFailed
        | Error::DelegationSasWindow { .. }
        | Error::DelegationKeyExpired { .. } => (
            S::FORBIDDEN,
            "AuthenticationFailed",
            "Server failed to authenticate the request. Make sure the value of the Authorization header is formed correctly including the signature.",
        ),
        Error::InvalidAuthenticationInfo => (
            S::UNAUTHORIZED,
            "InvalidAuthenticationInfo",
            "Server failed to authenticate the request. Please refer to the information in the www-authenticate header.",
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
        Error::IncompatibleBlobTier => (
            S::BAD_REQUEST,
            "InvalidHeaderValue",
            "The value for one of the HTTP headers is not in the correct format.",
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
        Error::ContainerRenameUnsupported => (
            S::BAD_REQUEST,
            "InvalidQueryParameterValue",
            "Value for one of the query parameters specified in the request URI is invalid.",
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
        Error::BlockIdWidthMismatch => (
            S::BAD_REQUEST,
            "InvalidBlobOrBlock",
            "The specified blob or block content is invalid.",
        ),
        Error::InvalidBlockList => (
            S::BAD_REQUEST,
            "InvalidBlockList",
            "The specified block list is invalid.",
        ),
        Error::InvalidXml => (
            S::BAD_REQUEST,
            "InvalidXmlDocument",
            "The request XML document is invalid.",
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
            "The specified container already exists.",
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
        Error::PathConflict => (
            S::CONFLICT,
            "BlobOperationNotSupported",
            "The path conflicts with a file or directory.",
        ),
        Error::DirectoryNotEmpty => (
            S::CONFLICT,
            "DirectoryIsNotEmpty",
            "This operation is not permitted on a non-empty directory.",
        ),
        Error::ResourceNotFound => (
            S::NOT_FOUND,
            "ResourceNotFound",
            "The specified resource does not exist.",
        ),
        Error::ConditionNotMet | Error::NotModified => (
            if error == Error::NotModified {
                S::NOT_MODIFIED
            } else {
                S::PRECONDITION_FAILED
            },
            "ConditionNotMet",
            "The condition specified using HTTP conditional header(s) is not met.",
        ),
        Error::SourceConditionNotMet => (
            S::PRECONDITION_FAILED,
            "SourceConditionNotMet",
            "The source condition specified using HTTP conditional header(s) is not met.",
        ),
        Error::InvalidRange(_) => (
            S::RANGE_NOT_SATISFIABLE,
            "InvalidRange",
            "The range specified is invalid for the current size of the resource.",
        ),
        Error::ConflictingRangeChecksums => (
            S::BAD_REQUEST,
            "BothCrc64AndMd5RangeHeaderPresent",
            "Both x-ms-range-get-content-crc64 header and x-ms-range-get-content-md5 header are present.",
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
        Error::PermissionMismatch => (
            S::FORBIDDEN,
            "AuthorizationPermissionMismatch",
            "This request is not authorized to perform this operation using this permission.",
        ),
        Error::ResourceTypeMismatch => (
            S::FORBIDDEN,
            "AuthorizationResourceTypeMismatch",
            "This request is not authorized to perform this operation using this resource type.",
        ),
        Error::ServiceMismatch => (
            S::FORBIDDEN,
            "AuthorizationServiceMismatch",
            "This request is not authorized to perform this operation using this service.",
        ),
        Error::SourceIpMismatch => (
            S::FORBIDDEN,
            "AuthorizationSourceIPMismatch",
            "This request is not authorized to perform this operation using this source IP address.",
        ),
        Error::ProtocolMismatch => (
            S::FORBIDDEN,
            "AuthorizationProtocolMismatch",
            "This request is not authorized to perform this operation using this protocol.",
        ),
        Error::BlobAlreadyExists => (
            S::CONFLICT,
            "BlobAlreadyExists",
            "The specified blob already exists.",
        ),
        Error::BlobArchived => (
            S::CONFLICT,
            "BlobArchived",
            "This operation is not permitted on an archived blob.",
        ),
        Error::MissingHeader => (
            S::BAD_REQUEST,
            "MissingRequiredHeader",
            "An HTTP header that is mandatory for this request is not specified.",
        ),
        Error::LeaseIdMissing => (
            S::PRECONDITION_FAILED,
            "LeaseIdMissing",
            "There is currently a lease on the container and no lease ID was specified in the request.",
        ),
        Error::LeaseIdMissingBlob => (
            S::PRECONDITION_FAILED,
            "LeaseIdMissing",
            "There is currently a lease on the blob and no lease ID was specified in the request.",
        ),
        Error::LeaseLost => (
            S::PRECONDITION_FAILED,
            "LeaseLost",
            "A lease ID was specified, but the lease for the resource has expired.",
        ),
        Error::LeaseAlreadyPresent => (
            S::CONFLICT,
            "LeaseAlreadyPresent",
            "There is already a lease present.",
        ),
        Error::LeaseMismatchBlob => (
            S::PRECONDITION_FAILED,
            "LeaseIdMismatchWithBlobOperation",
            "The lease ID specified did not match the lease ID for the blob.",
        ),
        Error::LeaseMismatchContainer => (
            S::PRECONDITION_FAILED,
            "LeaseIdMismatchWithContainerOperation",
            "The lease ID specified did not match the lease ID for the container.",
        ),
        Error::LeaseMismatchLease => (
            S::CONFLICT,
            "LeaseIdMismatchWithLeaseOperation",
            "The lease ID specified did not match the lease ID for the blob.",
        ),
        Error::LeaseMismatchContainerLease => (
            S::CONFLICT,
            "LeaseIdMismatchWithLeaseOperation",
            "The lease ID specified did not match the lease ID for the container.",
        ),
        Error::LeaseNotPresentBlob => (
            S::PRECONDITION_FAILED,
            "LeaseNotPresentWithBlobOperation",
            "There is currently no lease on the blob.",
        ),
        Error::LeaseNotPresentContainer => (
            S::PRECONDITION_FAILED,
            "LeaseNotPresentWithContainerOperation",
            "There is currently no lease on the container.",
        ),
        Error::LeaseNotPresentLease => (
            S::CONFLICT,
            "LeaseNotPresentWithLeaseOperation",
            "There is currently no lease on the resource.",
        ),
        Error::LeaseBreakingNoAcquire => (
            S::CONFLICT,
            "LeaseIsBreakingAndCannotBeAcquired",
            "The lease ID matched, but the lease is currently in breaking state and cannot be acquired until it is broken.",
        ),
        Error::LeaseBreakingNoChange => (
            S::CONFLICT,
            "LeaseIsBreakingAndCannotBeChanged",
            "The lease ID matched, but the lease is currently in breaking state and cannot be changed.",
        ),
        Error::LeaseBrokenNoRenew => (
            S::CONFLICT,
            "LeaseIsBrokenAndCannotBeRenewed",
            "The lease ID matched, but the lease has been broken explicitly and cannot be renewed.",
        ),
        Error::NoPendingCopy => (
            S::CONFLICT,
            "NoPendingCopyOperation",
            "There is currently no pending copy operation.",
        ),
        Error::CopyIdMismatch => (
            S::CONFLICT,
            "CopyIdMismatch",
            "The specified copy ID did not match the copy ID for the destination blob.",
        ),
        Error::CopySourceDenied => (
            S::FORBIDDEN,
            "CannotVerifyCopySource",
            "Could not verify the copy source within the specified time.",
        ),
        Error::CopySourceMissing => (
            S::NOT_FOUND,
            "CannotVerifyCopySource",
            "Could not verify the copy source: the source does not exist.",
        ),
        Error::CopySourceRange => (
            S::RANGE_NOT_SATISFIABLE,
            "CannotVerifyCopySource",
            "Could not verify the copy source within the specified time.",
        ),
        Error::SnapshotsPresent => (
            S::CONFLICT,
            "SnapshotsPresent",
            "This operation is not permitted because the blob has snapshots.",
        ),
        Error::InvalidTag => (
            S::BAD_REQUEST,
            "InvalidTag",
            "The tags specified are invalid. They contain characters that are not permitted.",
        ),
        Error::TagsTooLarge => (
            S::BAD_REQUEST,
            "TagsTooLarge",
            "The tags specified exceed the permitted number or length.",
        ),
        Error::InvalidInput | Error::InvalidBatchEnvelope => (
            S::BAD_REQUEST,
            "InvalidInput",
            "One of the request inputs is not valid.",
        ),
        Error::MixedBatchOperations => (
            S::BAD_REQUEST,
            "AllBatchSubRequestsShouldBeSameApi",
            "All batch subrequests should be the same api.",
        ),
        Error::CorsPreflight => (
            S::FORBIDDEN,
            "CorsPreflightFailure",
            "CORS is not enabled or no matching rule was found for this request.",
        ),
        Error::Page(error) => error.describe(),
        Error::Ext(error) => error.describe(),
    }
}

pub(crate) fn error_response(error: Error) -> Response {
    render_error(error, None)
}

pub(crate) fn correlated_error_response(
    error: Error,
    request_id: &str,
    now: SystemTime,
) -> Response {
    render_error(error, Some((request_id, now)))
}

pub(crate) fn request_error_response(
    error: Error,
    request_headers: &HeaderMap,
    request_id: &str,
    now: SystemTime,
) -> Response {
    match error {
        Error::DelegationSasWindow { .. } | Error::DelegationKeyExpired { .. } => {
            return delegation_sas_error(error, request_id, now).unwrap_or_else(error_response);
        }
        Error::ContainerRenameUnsupported => {
            let (status, code, message) = describe(error);
            return xml_error_with_details(
                status,
                code,
                &correlated_error_message(message, request_id, now),
                &[
                    ("QueryParameterName", "comp"),
                    ("QueryParameterValue", "rename"),
                ],
            );
        }
        _ => {}
    }
    let rejected_header = match error {
        Error::Page(PageError::UnalignedPageRange) => Some((
            "Range",
            request_headers
                .get("x-ms-range")
                .or_else(|| request_headers.get("range")),
        )),
        Error::IncompatibleBlobTier => {
            Some(("x-ms-access-tier", request_headers.get("x-ms-access-tier")))
        }
        _ => None,
    };
    if let Some((name, value)) = rejected_header {
        let Some(value) = value.and_then(|value| value.to_str().ok()) else {
            tracing::error!(header = name, "missing rejected Blob request header");
            return error_response(Error::Internal);
        };
        let (status, code, message) = describe(error);
        return xml_error_with_details(
            status,
            code,
            &correlated_error_message(message, request_id, now),
            &[("HeaderName", name), ("HeaderValue", value)],
        );
    }
    let correlation = matches!(
        error,
        Error::PermissionMismatch
            | Error::BlobAlreadyExists
            | Error::ConditionNotMet
            | Error::SourceConditionNotMet
            | Error::CopySourceRange
            | Error::NoPendingCopy
            | Error::BlobMissing
            | Error::ContainerExists
            | Error::ContainerMissing
            | Error::InvalidBlockList
            | Error::BlockIdWidthMismatch
            | Error::InvalidRange(_)
            | Error::ConflictingRangeChecksums
            | Error::LeaseIdMissing
            | Error::LeaseIdMissingBlob
            | Error::LeaseMismatchBlob
            | Error::LeaseMismatchLease
            | Error::LeaseMismatchContainerLease
            | Error::LeaseBreakingNoAcquire
            | Error::SnapshotsPresent
            | Error::Ext(LifecycleError::OperationNotAllowedOnIncrementalCopyBlob)
            | Error::Page(
                PageError::AppendPositionConditionNotMet
                    | PageError::SequenceNumberConditionNotMet
                    | PageError::MaxBlobSizeConditionNotMet
                    | PageError::BlobIsSealed
            )
    )
    .then_some((request_id, now));
    render_error(error, correlation)
}

#[derive(Clone, Copy)]
pub(crate) struct OmitApiVersion;

fn delegation_sas_error(error: Error, request_id: &str, now: SystemTime) -> Result<Response> {
    let date = |time: SystemTime| {
        http_date(
            time.duration_since(UNIX_EPOCH)
                .map_err(|_| {
                    tracing::error!("SAS timestamp predates the HTTP date range");
                    Error::Internal
                })?
                .as_secs(),
        )
    };
    let detail = match error {
        Error::DelegationSasWindow { start, expiry } => format!(
            "Signature not valid in the specified time frame: Start [{}] - Expiry [{}] - Current [{}]",
            date(start)?,
            date(expiry)?,
            date(now)?,
        ),
        Error::DelegationKeyExpired { start, expiry } => format!(
            "Signature not valid in the specified key time frame: Key start [{}] - Key expiry [{}] - Current [{}]",
            date(start)?,
            date(expiry)?,
            date(now)?,
        ),
        _ => return Ok(error_response(error)),
    };
    let (status, code, message) = describe(error);
    let mut response = xml_error_with_details(
        status,
        code,
        &correlated_error_message(message, request_id, now),
        &[("AuthenticationErrorDetail", &detail)],
    );
    response.extensions_mut().insert(OmitApiVersion);
    Ok(response)
}

fn render_error(error: Error, correlation: Option<(&str, SystemTime)>) -> Response {
    let (status, code, message) = describe(error);
    if status == StatusCode::NOT_MODIFIED {
        let mut response = empty(status);
        response
            .headers_mut()
            .insert("x-ms-error-code", HeaderValue::from_static(code));
        return response;
    }
    let mut response = match correlation {
        Some((request_id, now)) => xml_error(
            status,
            code,
            &correlated_error_message(message, request_id, now),
        ),
        None => xml_error(status, code, message),
    };
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
