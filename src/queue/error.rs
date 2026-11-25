use super::time;
use crate::{domain, wire::Xml};
use axum::{http::HeaderValue, http::StatusCode, response::Response};

pub(super) type Result<T> = std::result::Result<T, QueueError>;

/// Structured Queue service failures; the wire status, code, message, and
/// extra XML elements are derived in one place.
#[derive(Debug, Eq, PartialEq)]
pub(super) enum QueueError {
    AuthenticationFailed,
    InvalidAuthenticationInfo,
    PermissionMismatch,
    ServiceMismatch,
    ResourceTypeMismatch,
    ProtocolMismatch,
    InvalidUri,
    UnsupportedVerb,
    InvalidResourceName,
    OutOfRangeName,
    MissingHeader(&'static str),
    InvalidVersion(String),
    MalformedHeaders,
    InvalidQuery(&'static str, String, &'static str),
    OutOfRangeQuery(&'static str, String, i64, i64),
    MissingQuery(&'static str),
    InvalidXml,
    InvalidMetadata,
    MetadataTooLarge,
    BodyTooLarge(u64),
    QueueNotFound,
    QueueAlreadyExists,
    MessageNotFound,
    PopReceiptMismatch,
    CorsPreflightFailure,
    Busy,
    Internal,
}

impl QueueError {
    fn parts(&self) -> (StatusCode, &'static str, &'static str) {
        use StatusCode as S;
        match self {
            Self::AuthenticationFailed => (
                S::FORBIDDEN,
                "AuthenticationFailed",
                "Server failed to authenticate the request. Make sure the value of the Authorization header is formed correctly including the signature.",
            ),
            Self::InvalidAuthenticationInfo => (
                S::BAD_REQUEST,
                "InvalidAuthenticationInfo",
                "Authentication information is not given in the correct format. Check the value of Authorization header.",
            ),
            Self::PermissionMismatch => (
                S::FORBIDDEN,
                "AuthorizationPermissionMismatch",
                "This request is not authorized to perform this operation using this permission.",
            ),
            Self::ServiceMismatch => (
                S::FORBIDDEN,
                "AuthorizationServiceMismatch",
                "This request is not authorized to perform this operation using this service.",
            ),
            Self::ResourceTypeMismatch => (
                S::FORBIDDEN,
                "AuthorizationResourceTypeMismatch",
                "This request is not authorized to perform this operation using this resource type.",
            ),
            Self::ProtocolMismatch => (
                S::FORBIDDEN,
                "AuthorizationProtocolMismatch",
                "This request is not authorized to perform this operation using this protocol.",
            ),
            Self::InvalidUri => (
                S::BAD_REQUEST,
                "InvalidUri",
                "The requested URI does not represent any resource on the server.",
            ),
            Self::UnsupportedVerb => (
                S::METHOD_NOT_ALLOWED,
                "UnsupportedHttpVerb",
                "The resource doesn't support specified Http Verb.",
            ),
            Self::InvalidResourceName => (
                S::BAD_REQUEST,
                "InvalidResourceName",
                "The specifed resource name contains invalid characters.",
            ),
            Self::OutOfRangeName => (
                S::BAD_REQUEST,
                "OutOfRangeInput",
                "The specified resource name length is not within the permissible limits.",
            ),
            Self::InvalidVersion(_) | Self::MalformedHeaders => (
                S::BAD_REQUEST,
                "InvalidHeaderValue",
                "The value for one of the HTTP headers is not in the correct format.",
            ),
            Self::MissingHeader(_) => (
                S::BAD_REQUEST,
                "MissingRequiredHeader",
                "An HTTP header that's mandatory for this request is not specified.",
            ),
            Self::InvalidQuery(..) => (
                S::BAD_REQUEST,
                "InvalidQueryParameterValue",
                "Value for one of the query parameters specified in the request URI is invalid.",
            ),
            Self::OutOfRangeQuery(..) => (
                S::BAD_REQUEST,
                "OutOfRangeQueryParameterValue",
                "One of the query parameters specified in the request URI is outside the permissible range.",
            ),
            Self::MissingQuery(_) => (
                S::BAD_REQUEST,
                "MissingRequiredQueryParameter",
                "A required query parameter was not specified for this request.",
            ),
            Self::InvalidXml => (
                S::BAD_REQUEST,
                "InvalidXmlDocument",
                "XML specified is not syntactically valid.",
            ),
            Self::InvalidMetadata => (
                S::BAD_REQUEST,
                "InvalidMetadata",
                "The metadata specified is invalid. It has characters that are not permitted.",
            ),
            Self::MetadataTooLarge => (
                S::BAD_REQUEST,
                "MetadataTooLarge",
                "The metadata specified exceeds the maximum permissible limit.",
            ),
            Self::BodyTooLarge(_) => (
                S::PAYLOAD_TOO_LARGE,
                "RequestBodyTooLarge",
                "The request body is too large and exceeds the maximum permissible limit.",
            ),
            Self::QueueNotFound => (
                S::NOT_FOUND,
                "QueueNotFound",
                "The specified queue does not exist.",
            ),
            Self::QueueAlreadyExists => (
                S::CONFLICT,
                "QueueAlreadyExists",
                "The specified queue already exists.",
            ),
            Self::MessageNotFound => (
                S::NOT_FOUND,
                "MessageNotFound",
                "The specified message does not exist.",
            ),
            Self::PopReceiptMismatch => (
                S::BAD_REQUEST,
                "PopReceiptMismatch",
                "The specified pop receipt did not match the pop receipt for a dequeued message.",
            ),
            Self::CorsPreflightFailure => (
                S::FORBIDDEN,
                "CorsPreflightFailure",
                "CORS not enabled or no matching rule found for this request.",
            ),
            Self::Busy => (S::SERVICE_UNAVAILABLE, "ServerBusy", "The server is busy."),
            Self::Internal => (
                S::INTERNAL_SERVER_ERROR,
                "InternalError",
                "The server encountered an internal error. Please retry the request.",
            ),
        }
    }

    fn details(&self) -> Vec<(&'static str, String)> {
        match self {
            Self::InvalidVersion(value) => vec![
                ("HeaderName", "x-ms-version".into()),
                ("HeaderValue", value.clone()),
            ],
            Self::MissingHeader(name) => vec![("HeaderName", (*name).into())],
            Self::InvalidQuery(name, value, reason) => vec![
                ("QueryParameterName", (*name).into()),
                ("QueryParameterValue", value.clone()),
                ("Reason", (*reason).into()),
            ],
            Self::OutOfRangeQuery(name, value, min, max) => vec![
                ("QueryParameterName", (*name).into()),
                ("QueryParameterValue", value.clone()),
                ("MinimumAllowed", min.to_string()),
                ("MaximumAllowed", max.to_string()),
            ],
            Self::MissingQuery(name) => vec![("QueryParameterName", (*name).into())],
            Self::BodyTooLarge(max) => vec![("MaxLimit", max.to_string())],
            _ => Vec::new(),
        }
    }

    pub(super) fn code(&self) -> &'static str {
        self.parts().1
    }

    pub(super) fn into_response(self, request_id: &str, now_millis: i64) -> Response {
        let (status, code, message) = self.parts();
        let mut xml = Xml::root("Error", &[]);
        xml.element("Code", code);
        xml.element(
            "Message",
            &format!(
                "{message}\nRequestId:{request_id}\nTime:{}",
                time::iso8601(now_millis)
            ),
        );
        for (name, value) in self.details() {
            xml.element(name, &value);
        }
        let mut response = xml.finish("Error", status);
        response
            .headers_mut()
            .insert("x-ms-error-code", HeaderValue::from_static(code));
        response
    }
}

impl From<domain::Error> for QueueError {
    fn from(error: domain::Error) -> Self {
        match error {
            domain::Error::AuthenticationFailed => Self::AuthenticationFailed,
            domain::Error::InvalidHeader => Self::MalformedHeaders,
            domain::Error::InvalidVersion => Self::InvalidVersion(String::new()),
            domain::Error::Busy => Self::Busy,
            _ => Self::Internal,
        }
    }
}

impl From<rusqlite::Error> for QueueError {
    fn from(error: rusqlite::Error) -> Self {
        tracing::error!(%error, "queue metadata operation failed");
        Self::Internal
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn errors_carry_azure_status_code_and_detail_elements() {
        let error = QueueError::OutOfRangeQuery("numofmessages", "33".into(), 1, 32);
        assert_eq!(error.code(), "OutOfRangeQueryParameterValue");
        let response = error.into_response("abc", 0);
        assert_eq!(response.status(), 400);
        assert_eq!(
            response.headers()["x-ms-error-code"],
            "OutOfRangeQueryParameterValue"
        );
        let missing = QueueError::MessageNotFound;
        assert_eq!(missing.into_response("abc", 0).status(), 404);
        assert_eq!(
            QueueError::BodyTooLarge(1).into_response("a", 0).status(),
            413
        );
    }
}
