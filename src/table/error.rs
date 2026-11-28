//! Table service errors and their Azure wire shape.

use super::edm::Metadata;
use crate::{domain::Error, runtime_metrics, wire};
use axum::http::StatusCode;

pub(super) type Result<T> = std::result::Result<T, TableError>;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum Kind {
    AuthenticationFailed,
    /// A bearer token that is disabled, malformed, expired, or otherwise not accepted.
    InvalidBearer,
    AuthorizationFailure,
    InvalidHeaderValue,
    InvalidQueryParameterValue,
    InvalidInput,
    InvalidResourceName,
    InvalidXmlDocument,
    InvalidValueType,
    OutOfRangeInput,
    PropertiesNeedValue,
    PropertyNameInvalid,
    PropertyNameTooLong,
    PropertyValueTooLarge,
    TooManyProperties,
    EntityTooLarge,
    DuplicatePropertiesSpecified,
    InvalidDuplicateRow,
    CommandsInBatchActOnDifferentPartitions,
    TableNotFound,
    TableAlreadyExists,
    ResourceNotFound,
    EntityAlreadyExists,
    UpdateConditionNotSatisfied,
    JsonFormatNotSupported,
    AtomFormatNotSupported,
    MethodNotAllowed,
    NotImplemented,
    RequestBodyTooLarge,
    CorsPreflightFailure,
    Internal,
}

impl Kind {
    fn status(self) -> StatusCode {
        use StatusCode as S;
        match self {
            Self::AuthenticationFailed
            | Self::AuthorizationFailure
            | Self::CorsPreflightFailure => S::FORBIDDEN,
            Self::InvalidBearer => S::UNAUTHORIZED,
            Self::TableNotFound | Self::ResourceNotFound => S::NOT_FOUND,
            Self::TableAlreadyExists | Self::EntityAlreadyExists => S::CONFLICT,
            Self::UpdateConditionNotSatisfied => S::PRECONDITION_FAILED,
            Self::JsonFormatNotSupported | Self::AtomFormatNotSupported => {
                S::UNSUPPORTED_MEDIA_TYPE
            }
            Self::MethodNotAllowed => S::METHOD_NOT_ALLOWED,
            Self::NotImplemented => S::NOT_IMPLEMENTED,
            Self::RequestBodyTooLarge => S::PAYLOAD_TOO_LARGE,
            Self::Internal => S::INTERNAL_SERVER_ERROR,
            _ => S::BAD_REQUEST,
        }
    }

    fn code(self) -> &'static str {
        match self {
            Self::AuthenticationFailed => "AuthenticationFailed",
            Self::InvalidBearer => "InvalidAuthenticationInfo",
            Self::AuthorizationFailure => "AuthorizationFailure",
            Self::InvalidHeaderValue => "InvalidHeaderValue",
            Self::InvalidQueryParameterValue => "InvalidQueryParameterValue",
            Self::InvalidInput => "InvalidInput",
            Self::InvalidResourceName => "InvalidResourceName",
            Self::InvalidXmlDocument => "InvalidXmlDocument",
            Self::InvalidValueType => "InvalidValueType",
            Self::OutOfRangeInput => "OutOfRangeInput",
            Self::PropertiesNeedValue => "PropertiesNeedValue",
            Self::PropertyNameInvalid => "PropertyNameInvalid",
            Self::PropertyNameTooLong => "PropertyNameTooLong",
            Self::PropertyValueTooLarge => "PropertyValueTooLarge",
            Self::TooManyProperties => "TooManyProperties",
            Self::EntityTooLarge => "EntityTooLarge",
            Self::DuplicatePropertiesSpecified => "DuplicatePropertiesSpecified",
            Self::InvalidDuplicateRow => "InvalidDuplicateRow",
            Self::CommandsInBatchActOnDifferentPartitions => {
                "CommandsInBatchActOnDifferentPartitions"
            }
            Self::TableNotFound => "TableNotFound",
            Self::TableAlreadyExists => "TableAlreadyExists",
            Self::ResourceNotFound => "ResourceNotFound",
            Self::EntityAlreadyExists => "EntityAlreadyExists",
            Self::UpdateConditionNotSatisfied => "UpdateConditionNotSatisfied",
            Self::JsonFormatNotSupported => "JsonFormatNotSupported",
            Self::AtomFormatNotSupported => "AtomFormatNotSupported",
            Self::MethodNotAllowed => "MethodNotAllowed",
            Self::NotImplemented => "NotImplemented",
            Self::RequestBodyTooLarge => "RequestBodyTooLarge",
            Self::CorsPreflightFailure => "CorsPreflightFailure",
            Self::Internal => "InternalError",
        }
    }

    fn message(self) -> &'static str {
        match self {
            Self::AuthenticationFailed => {
                "Server failed to authenticate the request. Make sure the value of Authorization header is formed correctly including the signature."
            }
            Self::InvalidBearer => {
                "Server failed to authenticate the request. Please refer to the information in the www-authenticate header."
            }
            Self::AuthorizationFailure => {
                "This request is not authorized to perform this operation."
            }
            Self::InvalidHeaderValue => {
                "The value for one of the HTTP headers is not in the correct format."
            }
            Self::InvalidQueryParameterValue => {
                "Value for one of the query parameters specified in the request URI is invalid."
            }
            Self::InvalidInput => "One of the request inputs is not valid.",
            Self::InvalidResourceName => "The specifed resource name contains invalid characters.",
            Self::InvalidXmlDocument => "XML specified is not syntactically valid.",
            Self::InvalidValueType => "The value specified is invalid.",
            Self::OutOfRangeInput => "One of the request inputs is out of range.",
            Self::PropertiesNeedValue => {
                "Values have not been specified for all properties in the entity."
            }
            Self::PropertyNameInvalid => "The property name is invalid.",
            Self::PropertyNameTooLong => "The property name exceeds the maximum allowed length.",
            Self::PropertyValueTooLarge => {
                "The property value exceeds the maximum allowed size (64KB). If the property value is a string, it is UTF-16 encoded and the maximum number of characters should be 32K or less."
            }
            Self::TooManyProperties => "The entity contains more properties than allowed.",
            Self::EntityTooLarge => "The entity is larger than the maximum size permitted.",
            Self::DuplicatePropertiesSpecified => "A property is specified more than one time.",
            Self::InvalidDuplicateRow => "An entity can appear only once in a batch request.",
            Self::CommandsInBatchActOnDifferentPartitions => {
                "All commands in a batch must operate on same entity group."
            }
            Self::TableNotFound => "The table specified does not exist.",
            Self::TableAlreadyExists => "The table specified already exists.",
            Self::ResourceNotFound => "The specified resource does not exist.",
            Self::EntityAlreadyExists => "The specified entity already exists.",
            Self::UpdateConditionNotSatisfied => {
                "The update condition specified in the request was not satisfied."
            }
            Self::JsonFormatNotSupported => "JSON format is not supported.",
            Self::AtomFormatNotSupported => "Atom format is not supported.",
            Self::MethodNotAllowed => {
                "The requested method is not allowed on the specified resource."
            }
            Self::NotImplemented => {
                "The requested operation is not implemented on the specified resource."
            }
            Self::RequestBodyTooLarge => {
                "The request body is too large and exceeds the maximum permissible limit."
            }
            Self::CorsPreflightFailure => {
                "CORS not enabled or no matching rule found for this request."
            }
            Self::Internal => "The server encountered an internal error. Please retry the request.",
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(super) struct TableError {
    kind: Kind,
    detail: Option<String>,
    odata_format: Option<OdataErrorFormat>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum OdataErrorFormat {
    Json(Metadata),
    Xml,
}

impl TableError {
    pub(super) fn new(kind: Kind) -> Self {
        Self {
            kind,
            detail: None,
            odata_format: None,
        }
    }

    /// An error whose message carries request-specific detail in place of the generic text.
    pub(super) fn with(kind: Kind, detail: impl Into<String>) -> Self {
        Self {
            detail: Some(detail.into()),
            ..Self::new(kind)
        }
    }

    pub(super) fn with_odata_format(mut self, format: OdataErrorFormat) -> Self {
        self.odata_format = Some(format);
        self
    }

    pub(super) fn odata_format(&self) -> Option<OdataErrorFormat> {
        self.odata_format
    }

    pub(super) fn kind(&self) -> Kind {
        self.kind
    }

    pub(super) fn status(&self) -> StatusCode {
        self.kind.status()
    }

    pub(super) fn code(&self) -> &'static str {
        self.kind.code()
    }

    /// The Azure error document. `index` prefixes the message with the failed batch
    /// operation, and the request id and time trail the text as Azure sends them.
    pub(super) fn body(&self, index: Option<usize>, request_id: &str, time: &str) -> String {
        wire::json_error_body(
            self.code(),
            &self.correlated_message(index, request_id, time),
        )
    }

    pub(super) fn correlated_message(
        &self,
        index: Option<usize>,
        request_id: &str,
        time: &str,
    ) -> String {
        let text = self.detail.as_deref().unwrap_or(self.kind.message());
        let prefix = index.map_or_else(String::new, |index| format!("{index}:"));
        format!("{prefix}{text}\nRequestId:{request_id}\nTime:{time}")
    }
}

impl From<Error> for TableError {
    fn from(error: Error) -> Self {
        Self::new(match error {
            Error::AuthenticationFailed => Kind::AuthenticationFailed,
            Error::InvalidHeader | Error::InvalidVersion => Kind::InvalidHeaderValue,
            Error::InvalidQuery => Kind::InvalidQueryParameterValue,
            Error::InvalidName => Kind::InvalidResourceName,
            Error::Unsupported => Kind::NotImplemented,
            Error::TooLarge => Kind::RequestBodyTooLarge,
            Error::Internal | Error::Busy | Error::Timeout => Kind::Internal,
            _ => Kind::InvalidInput,
        })
    }
}

/// Logs the cause and reports the generic internal error.
pub(super) fn internal(reason: &'static str) -> TableError {
    tracing::error!(reason, "table operation failed");
    runtime_metrics::failure(
        runtime_metrics::Store::Table,
        runtime_metrics::Failure::Internal,
    );
    TableError::new(Kind::Internal)
}

pub(super) fn db_error(error: rusqlite::Error) -> TableError {
    tracing::error!(code = ?error.sqlite_error_code(), "table metadata operation failed");
    runtime_metrics::database_failure(runtime_metrics::Store::Table, &error);
    TableError::new(Kind::Internal)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn batch_errors_are_prefixed_with_the_failed_index() {
        let body = TableError::new(Kind::EntityAlreadyExists).body(Some(2), "rid", "now");
        let json: serde_json::Value = serde_json::from_str(&body).unwrap();
        assert_eq!(json["odata.error"]["code"], "EntityAlreadyExists");
        assert_eq!(
            json["odata.error"]["message"]["value"],
            "2:The specified entity already exists.\nRequestId:rid\nTime:now"
        );
        assert_eq!(
            TableError::new(Kind::EntityAlreadyExists).status(),
            StatusCode::CONFLICT
        );
    }
}
