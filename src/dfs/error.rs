//! Maps DFS failures to the Azure status, error code and JSON error body.

use crate::{
    domain::Error,
    store::PathError,
    wire::{self, empty, json_response},
};
use axum::{
    http::{HeaderValue, StatusCode},
    response::Response,
};

pub(super) const JSON: &str = "application/json; charset=utf-8";

pub(super) enum DfsError {
    NamespaceDisabled,
    MissingRecursive,
    MissingParameter(&'static str),
    Request(Error),
    Path(PathError),
}

impl From<Error> for DfsError {
    fn from(error: Error) -> Self {
        Self::Request(error)
    }
}

impl From<PathError> for DfsError {
    fn from(error: PathError) -> Self {
        match error {
            PathError::Shared(error) => Self::Request(error),
            other => Self::Path(other),
        }
    }
}

type Described = (StatusCode, &'static str, &'static str);

fn path_error(error: PathError) -> Described {
    use StatusCode as S;
    match error {
        PathError::Shared(_) => (
            S::INTERNAL_SERVER_ERROR,
            "InternalError",
            "The local storage operation failed.",
        ),
        PathError::InvalidFlushPosition => (
            S::BAD_REQUEST,
            "InvalidFlushPosition",
            "The uploaded data is not contiguous or the position query parameter value is not equal to the length of the file after appending the uploaded data.",
        ),
        PathError::ResourceTypeMismatch => (
            S::CONFLICT,
            "ResourceTypeMismatch",
            "The resource type specified in the request does not match the type of the resource.",
        ),
        PathError::SourceNotFound => (
            S::NOT_FOUND,
            "SourcePathNotFound",
            "The source path for a rename operation does not exist.",
        ),
        PathError::DestinationParentNotFound => (
            S::NOT_FOUND,
            "RenameDestinationParentPathNotFound",
            "The parent directory of the destination path does not exist.",
        ),
        PathError::InvalidRenameSource => (
            S::CONFLICT,
            "InvalidRenameSourcePath",
            "The source directory cannot be the same as the destination directory, nor can the destination be a subdirectory of the source directory.",
        ),
        PathError::RenameTypeMismatch => (
            S::CONFLICT,
            "InvalidSourceOrDestinationResourceType",
            "The source and destination resource type must be identical.",
        ),
    }
}

fn request_error(error: Error) -> Described {
    use StatusCode as S;
    match error {
        Error::AuthenticationFailed => (
            S::FORBIDDEN,
            "AuthorizationFailure",
            "This request is not authorized to perform this operation.",
        ),
        Error::InvalidAuthenticationInfo => (
            S::UNAUTHORIZED,
            "InvalidAuthenticationInfo",
            "Server failed to authenticate the request. Please refer to the information in the www-authenticate header.",
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
        Error::InvalidName => (
            S::BAD_REQUEST,
            "InvalidResourceName",
            "The specified resource name contains invalid characters.",
        ),
        Error::InvalidHeader | Error::InvalidTag => (
            S::BAD_REQUEST,
            "InvalidHeaderValue",
            "The value for one of the HTTP headers is not in the correct format.",
        ),
        Error::InvalidQuery => (
            S::BAD_REQUEST,
            "InvalidQueryParameterValue",
            "A query parameter is invalid.",
        ),
        Error::InvalidVersion => (
            S::BAD_REQUEST,
            "UnsupportedRestVersion",
            "The specified Rest Version is Unsupported.",
        ),
        Error::InvalidLength => (
            S::BAD_REQUEST,
            "ContentLengthMustBeZero",
            "The Content-Length request header must be zero.",
        ),
        Error::InvalidInput => (
            S::BAD_REQUEST,
            "InvalidInput",
            "One of the request inputs is not valid.",
        ),
        Error::MissingHeader => (
            S::BAD_REQUEST,
            "MissingRequiredHeader",
            "An HTTP header that's mandatory for this request is not specified.",
        ),
        Error::MissingLength => (
            S::LENGTH_REQUIRED,
            "MissingContentLengthHeader",
            "The Content-Length header is required for this request.",
        ),
        Error::Md5Mismatch => (
            S::BAD_REQUEST,
            "Md5Mismatch",
            "The MD5 value specified in the request did not match the MD5 value calculated by the server.",
        ),
        Error::Crc64Mismatch => (
            S::BAD_REQUEST,
            "Crc64Mismatch",
            "The CRC64 value specified in the request did not match the CRC64 value calculated by the server.",
        ),
        Error::TooLarge => (
            S::PAYLOAD_TOO_LARGE,
            "RequestBodyTooLarge",
            "The request body is too large and exceeds the maximum permissible limit.",
        ),
        Error::Unsupported => (
            S::NOT_IMPLEMENTED,
            "NotImplemented",
            "This operation or option is not implemented.",
        ),
        Error::ContainerExists => (
            S::CONFLICT,
            "FilesystemAlreadyExists",
            "The specified filesystem already exists.",
        ),
        Error::ContainerMissing => (
            S::NOT_FOUND,
            "FilesystemNotFound",
            "The specified filesystem does not exist.",
        ),
        Error::BlobMissing | Error::ResourceNotFound => (
            S::NOT_FOUND,
            "PathNotFound",
            "The specified path does not exist.",
        ),
        Error::BlobAlreadyExists => (
            S::CONFLICT,
            "PathAlreadyExists",
            "The specified path already exists.",
        ),
        Error::PathConflict => (
            S::CONFLICT,
            "PathConflict",
            "The path conflicts with a file or directory.",
        ),
        Error::DirectoryNotEmpty => (
            S::CONFLICT,
            "DirectoryNotEmpty",
            "The recursive query parameter value must be true to delete a non-empty directory.",
        ),
        Error::LeaseIdMissing | Error::LeaseIdMissingBlob => (
            S::PRECONDITION_FAILED,
            "LeaseIdMissing",
            "There is currently a lease on the resource and no lease ID was specified.",
        ),
        Error::LeaseMismatchBlob | Error::LeaseMismatchContainer => (
            S::PRECONDITION_FAILED,
            "LeaseIdMismatch",
            "The lease ID does not match the lease on the resource.",
        ),
        Error::LeaseNotPresentBlob | Error::LeaseNotPresentContainer => (
            S::PRECONDITION_FAILED,
            "LeaseNotPresent",
            "There is no active lease on the resource.",
        ),
        Error::LeaseLost => (
            S::PRECONDITION_FAILED,
            "LeaseLost",
            "The lease has expired.",
        ),
        Error::LeaseAlreadyPresent => (
            S::CONFLICT,
            "LeaseAlreadyPresent",
            "There is already a lease present.",
        ),
        Error::LeaseMismatchLease => (
            S::CONFLICT,
            "LeaseIdMismatchWithLeaseOperation",
            "The lease ID specified did not match the lease ID for the resource with the specified lease operation.",
        ),
        Error::LeaseNotPresentLease => (
            S::CONFLICT,
            "LeaseNotPresentWithLeaseOperation",
            "The lease ID is not present with the specified lease operation.",
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
        Error::ConditionNotMet => (
            S::PRECONDITION_FAILED,
            "ConditionNotMet",
            "The condition specified using HTTP conditional header(s) is not met.",
        ),
        Error::SourceConditionNotMet => (
            S::PRECONDITION_FAILED,
            "SourceConditionNotMet",
            "The source condition specified using HTTP conditional header(s) is not met.",
        ),
        Error::QuotaExceeded => (
            S::INSUFFICIENT_STORAGE,
            "InsufficientStorage",
            "The in-memory content quota was exceeded.",
        ),
        Error::Timeout => (
            S::INTERNAL_SERVER_ERROR,
            "OperationTimedOut",
            "The operation could not be completed within the permitted time.",
        ),
        Error::Busy => (
            S::SERVICE_UNAVAILABLE,
            "ServerBusy",
            "Too many active requests.",
        ),
        other => {
            if other != Error::Internal {
                tracing::error!(error = ?other, "unexpected DFS storage error");
            }
            (
                S::INTERNAL_SERVER_ERROR,
                "InternalError",
                "The local storage operation failed.",
            )
        }
    }
}

pub(super) fn error_response(error: DfsError) -> Response {
    use StatusCode as S;
    let (status, code, message) = match &error {
        DfsError::NamespaceDisabled => (
            S::CONFLICT,
            "HierarchicalNamespaceNotEnabled",
            "The account does not have a hierarchical namespace enabled.",
        ),
        DfsError::MissingRecursive => (
            S::BAD_REQUEST,
            "MissingRequiredQueryParameter",
            "The recursive query parameter is required for listing paths.",
        ),
        DfsError::MissingParameter(name) => {
            return coded(
                S::BAD_REQUEST,
                "MissingRequiredQueryParameter",
                &format!("The {name} query parameter is required for this operation."),
            );
        }
        DfsError::Request(Error::NotModified) => return empty(S::NOT_MODIFIED),
        DfsError::Request(Error::InvalidRange(length)) => return range_error(*length),
        DfsError::Request(error) => request_error(*error),
        DfsError::Path(error) => path_error(*error),
    };
    coded(status, code, message)
}

fn coded(status: StatusCode, code: &'static str, message: &str) -> Response {
    let mut response = json_response(
        status,
        serde_json::json!({ "error": { "code": code, "message": message } }),
        JSON,
    );
    response
        .headers_mut()
        .insert("x-ms-error-code", HeaderValue::from_static(code));
    response
}

fn range_error(length: u64) -> Response {
    let mut response = json_response(
        StatusCode::RANGE_NOT_SATISFIABLE,
        serde_json::json!({ "error": {
            "code": "InvalidRange",
            "message": "The range specified is invalid for the current size of the resource.",
        } }),
        JSON,
    );
    let headers = response.headers_mut();
    headers.insert("x-ms-error-code", HeaderValue::from_static("InvalidRange"));
    if wire::unsatisfied_range(headers, length).is_err() {
        return error_response(DfsError::Request(Error::Internal));
    }
    response
}
