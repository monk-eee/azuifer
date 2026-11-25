use axum::http::StatusCode;

/// Declares every FileREST failure once, with its HTTP status, Azure error code, and message.
macro_rules! errors {
    ($($variant:ident($status:expr, $code:literal, $message:literal)),* $(,)?) => {
        #[derive(Clone, Copy, Debug, Eq, PartialEq)]
        pub(crate) enum Error {
            $($variant,)*
        }

        impl Error {
            pub(crate) fn info(self) -> (StatusCode, &'static str, &'static str) {
                match self {
                    $(Self::$variant => ($status, $code, $message),)*
                }
            }
        }
    };
}

pub(crate) type Result<T> = std::result::Result<T, Error>;

errors! {
    AuthenticationFailed(StatusCode::FORBIDDEN, "AuthenticationFailed", "Server failed to authenticate the request. Make sure the value of the Authorization header is formed correctly including the signature."),
    InvalidAuthenticationInfo(StatusCode::UNAUTHORIZED, "InvalidAuthenticationInfo", "Server failed to authenticate the request. Please refer to the information in the www-authenticate header."),
    NoAuthenticationInformation(StatusCode::FORBIDDEN, "NoAuthenticationInformation", "Server failed to authenticate the request. The request carries no authentication information."),
    AuthorizationPermissionMismatch(StatusCode::FORBIDDEN, "AuthorizationPermissionMismatch", "This request is not authorized to perform this operation using this permission."),
    MissingRequiredHeader(StatusCode::BAD_REQUEST, "MissingRequiredHeader", "An HTTP header that's mandatory for this request is not specified."),
    InvalidHeaderValue(StatusCode::BAD_REQUEST, "InvalidHeaderValue", "The value for one of the HTTP headers is not in the correct format."),
    InvalidQueryParameterValue(StatusCode::BAD_REQUEST, "InvalidQueryParameterValue", "Value for one of the query parameters specified in the request URI is invalid."),
    InvalidUri(StatusCode::BAD_REQUEST, "InvalidUri", "The requested URI does not represent any resource on the server."),
    InvalidInput(StatusCode::BAD_REQUEST, "InvalidInput", "One of the request inputs is not valid."),
    InvalidXmlDocument(StatusCode::BAD_REQUEST, "InvalidXmlDocument", "XML specified is not syntactically valid."),
    InvalidMd5(StatusCode::BAD_REQUEST, "InvalidMd5", "The MD5 value specified in the request is invalid. The MD5 value must be 128 bits and Base64-encoded."),
    Md5Mismatch(StatusCode::BAD_REQUEST, "Md5Mismatch", "The MD5 value specified in the request did not match with the MD5 value calculated by the server."),
    Crc64Mismatch(StatusCode::BAD_REQUEST, "Crc64Mismatch", "The CRC64 value specified in the request did not match with the CRC64 value calculated by the server."),
    InvalidResourceName(StatusCode::BAD_REQUEST, "InvalidResourceName", "The specified resource name contains invalid characters."),
    InvalidFileOrDirectoryPathName(StatusCode::BAD_REQUEST, "InvalidFileOrDirectoryPathName", "The file or directory path is too long or has too many subdirectories."),
    MetadataTooLarge(StatusCode::BAD_REQUEST, "MetadataTooLarge", "The metadata size exceeds the maximum allowed."),
    InvalidMetadata(StatusCode::BAD_REQUEST, "InvalidMetadata", "The metadata specified is invalid. It has characters that are not permitted."),
    EmptyMetadataKey(StatusCode::BAD_REQUEST, "EmptyMetadataKey", "The key for one of the metadata key-value pairs is empty."),
    MissingContentLengthHeader(StatusCode::LENGTH_REQUIRED, "MissingContentLengthHeader", "The Content-Length header was not specified."),
    RequestBodyTooLarge(StatusCode::PAYLOAD_TOO_LARGE, "RequestBodyTooLarge", "The size of the request body exceeds the maximum size permitted."),
    UnsupportedHttpVerb(StatusCode::METHOD_NOT_ALLOWED, "UnsupportedHttpVerb", "The resource doesn't support the specified HTTP verb."),
    InvalidRange(StatusCode::RANGE_NOT_SATISFIABLE, "InvalidRange", "The range specified is invalid for the current size of the resource."),
    ConditionNotMet(StatusCode::PRECONDITION_FAILED, "ConditionNotMet", "The condition specified using HTTP conditional header(s) is not met."),
    NotModified(StatusCode::NOT_MODIFIED, "NotModified", "The resource has not been modified."),
    ShareNotFound(StatusCode::NOT_FOUND, "ShareNotFound", "The specified share does not exist."),
    ShareAlreadyExists(StatusCode::CONFLICT, "ShareAlreadyExists", "The specified share already exists."),
    ShareHasSnapshots(StatusCode::CONFLICT, "ShareHasSnapshots", "The share has snapshots and the operation requires no snapshots."),
    ShareSnapshotNotFound(StatusCode::NOT_FOUND, "ShareSnapshotNotFound", "The specified share snapshot does not exist."),
    ShareSnapshotOperationNotSupported(StatusCode::BAD_REQUEST, "ShareSnapshotOperationNotSupported", "The operation is not supported on a share snapshot."),
    DeleteShareWhenSnapshotLeased(StatusCode::CONFLICT, "DeleteShareWhenSnapshotLeased", "Unable to delete the share because one or more share snapshots have active leases."),
    ShareSizeLimitReached(StatusCode::FORBIDDEN, "ShareSizeLimitReached", "The specified share is full."),
    ResourceNotFound(StatusCode::NOT_FOUND, "ResourceNotFound", "The specified resource does not exist."),
    ResourceAlreadyExists(StatusCode::CONFLICT, "ResourceAlreadyExists", "The specified resource already exists."),
    ResourceTypeMismatch(StatusCode::CONFLICT, "ResourceTypeMismatch", "The specified resource type does not match the type of the existing resource."),
    ParentNotFound(StatusCode::NOT_FOUND, "ParentNotFound", "The specified parent path does not exist."),
    DirectoryNotEmpty(StatusCode::CONFLICT, "DirectoryNotEmpty", "The specified directory is not empty."),
    ReadOnlyAttribute(StatusCode::CONFLICT, "ReadOnlyAttribute", "The specified resource is read-only and cannot be modified at this time."),
    CannotDeleteFileOrDirectory(StatusCode::CONFLICT, "CannotDeleteFileOrDirectory", "An attempt has been made to remove a file or directory that cannot be deleted."),
    FileInvalidPermission(StatusCode::BAD_REQUEST, "FileInvalidPermission", "The specified file permission is not valid."),
    FileInvalidPermissionKey(StatusCode::BAD_REQUEST, "FileInvalidPermissionKey", "The specified file permission key does not exist in the share."),
    InvalidContinuationToken(StatusCode::BAD_REQUEST, "InvalidContinuationToken", "The specified continuation token is not valid."),
    PreviousSnapshotNotFound(StatusCode::CONFLICT, "PreviousSnapshotNotFound", "The previous snapshot was not found."),
    PreviousSnapshotCannotBeNewer(StatusCode::BAD_REQUEST, "PreviousSnapshotCannotBeNewer", "The previous snapshot cannot be equal or newer than the target snapshot."),
    FileGenerationMismatch(StatusCode::CONFLICT, "FileGenerationMismatch", "The file has been recreated since the previous snapshot was taken."),
    RenameAcrossAccountsAndSharesNotSupported(StatusCode::BAD_REQUEST, "RenameAcrossAccountsAndSharesNotSupported", "REST Rename does not support renaming a file between different accounts or shares."),
    RenameDirectoryOperationNotSupported(StatusCode::BAD_REQUEST, "RenameDirectoryOperationNotSupported", "REST Rename does not support overwriting a directory."),
    RenameCycle(StatusCode::CONFLICT, "RenameCycle", "Attempt to move a directory to its own subdirectory is not supported."),
    NoPendingCopyOperation(StatusCode::CONFLICT, "NoPendingCopyOperation", "There is currently no pending copy operation."),
    CannotVerifyCopySource(StatusCode::NOT_FOUND, "CannotVerifyCopySource", "Could not verify the copy source within the specified time."),
    LeaseAlreadyPresent(StatusCode::CONFLICT, "LeaseAlreadyPresent", "There is already a lease present."),
    LeaseIsBreakingAndCannotBeAcquired(StatusCode::CONFLICT, "LeaseIsBreakingAndCannotBeAcquired", "The lease ID matched, but the lease is currently in breaking state and cannot be acquired until it is broken."),
    LeaseIsBreakingAndCannotBeChanged(StatusCode::CONFLICT, "LeaseIsBreakingAndCannotBeChanged", "The lease ID matched, but the lease is currently in breaking state and cannot be changed."),
    LeaseIsBrokenAndCannotBeRenewed(StatusCode::CONFLICT, "LeaseIsBrokenAndCannotBeRenewed", "The lease ID matched, but the lease has been broken explicitly and cannot be renewed."),
    LeaseIdMismatchWithFileLeaseOperation(StatusCode::CONFLICT, "LeaseIdMismatchWithFileLeaseOperation", "The lease ID specified did not match the lease ID for the file."),
    LeaseIdMismatchWithFileShareLeaseOperation(StatusCode::CONFLICT, "LeaseIdMismatchWithFileShareLeaseOperation", "The lease ID specified did not match the lease ID for the file share."),
    LeaseIdMismatchWithFileOperation(StatusCode::PRECONDITION_FAILED, "LeaseIdMismatchWithFileOperation", "The lease ID specified did not match the lease ID for the file."),
    LeaseIdMismatchWithFileShareOperation(StatusCode::PRECONDITION_FAILED, "LeaseIdMismatchWithFileShareOperation", "The lease ID specified did not match the lease ID for the file share."),
    LeaseIdMissingWithFileOperation(StatusCode::PRECONDITION_FAILED, "LeaseIdMissingWithFileOperation", "There is currently a lease on the file and no lease ID was specified in the request."),
    LeaseIdMissingWithFileShareOperation(StatusCode::PRECONDITION_FAILED, "LeaseIdMissingWithFileShareOperation", "There is currently a lease on the file share and no lease ID was specified in the request."),
    LeaseLostWithFileOperation(StatusCode::PRECONDITION_FAILED, "LeaseLostWithFileOperation", "A lease ID was specified, but the lease for the file has expired or been released."),
    LeaseLostWithFileShareOperation(StatusCode::PRECONDITION_FAILED, "LeaseLostWithFileShareOperation", "A lease ID was specified, but the lease for the file share has expired."),
    LeaseNotPresentWithFileOperation(StatusCode::PRECONDITION_FAILED, "LeaseNotPresentWithFileOperation", "There is currently no lease on the file."),
    LeaseNotPresentWithFileShareOperation(StatusCode::PRECONDITION_FAILED, "LeaseNotPresentWithFileShareOperation", "There is currently no lease on the file share."),
    LeaseNotPresentWithFileLeaseOperation(StatusCode::CONFLICT, "LeaseNotPresentWithFileLeaseOperation", "There is currently no lease on the file."),
    LeaseNotPresentWithFileShareLeaseOperation(StatusCode::CONFLICT, "LeaseNotPresentWithFileShareLeaseOperation", "There is currently no lease on the file share."),
    NotImplemented(StatusCode::NOT_IMPLEMENTED, "NotImplemented", "This operation or option is not implemented."),
    InsufficientStorage(StatusCode::INSUFFICIENT_STORAGE, "InsufficientStorage", "The in-memory content quota was exceeded."),
    ServerBusy(StatusCode::SERVICE_UNAVAILABLE, "ServerBusy", "Too many active requests."),
    OperationTimedOut(StatusCode::REQUEST_TIMEOUT, "OperationTimedOut", "The request body did not arrive in time."),
    Internal(StatusCode::INTERNAL_SERVER_ERROR, "InternalError", "The local storage operation failed."),
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn errors_carry_their_documented_status_and_code() {
        assert_eq!(Error::ShareNotFound.info().0, StatusCode::NOT_FOUND);
        assert_eq!(Error::ParentNotFound.info().1, "ParentNotFound");
        assert_eq!(Error::Internal.info().1, "InternalError");
        assert_eq!(
            Error::LeaseIdMissingWithFileOperation.info().0,
            StatusCode::PRECONDITION_FAILED
        );
        assert_eq!(
            Error::LeaseIdMismatchWithFileLeaseOperation.info().0,
            StatusCode::CONFLICT
        );
    }
}
