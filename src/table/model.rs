//! Validated Table domain types: names, keys, typed values, and entities.

use super::{
    datetime::Ticks,
    error::{Kind, Result, TableError},
};
use std::collections::BTreeMap;
use uuid::Uuid;

pub(super) const MAX_KEY_UNITS: usize = 1024;
pub(super) const MAX_USER_PROPERTIES: usize = 252;
pub(super) const MAX_ENTITY_BYTES: usize = 1024 * 1024;
pub(super) const MAX_STRING_UNITS: usize = 32 * 1024;
pub(super) const MAX_BINARY_BYTES: usize = 64 * 1024;
const MAX_PROPERTY_NAME: usize = 255;

/// A table name: 3-63 ASCII alphanumerics starting with a letter. Names keep their case
/// but are unique and looked up case-insensitively.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(super) struct TableName(String);

impl TableName {
    pub(super) fn parse(value: &str) -> Result<Self> {
        let mut chars = value.chars();
        let valid = (3..=63).contains(&value.len())
            && chars.next().is_some_and(|c| c.is_ascii_alphabetic())
            && chars.all(|c| c.is_ascii_alphanumeric())
            && !value.eq_ignore_ascii_case("tables");
        if !valid {
            return Err(TableError::new(Kind::InvalidResourceName));
        }
        Ok(Self(value.to_owned()))
    }

    pub(super) fn as_str(&self) -> &str {
        &self.0
    }

    /// The case-folded identity used for storage and SAS canonicalization.
    pub(super) fn key(&self) -> String {
        self.0.to_ascii_lowercase()
    }
}

/// A `PartitionKey` or `RowKey` value (empty is valid).
#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub(super) struct KeyValue(String);

impl KeyValue {
    pub(super) fn parse(value: &str) -> Result<Self> {
        if value.encode_utf16().count() > MAX_KEY_UNITS {
            return Err(TableError::with(
                Kind::InvalidInput,
                "The key value exceeds the maximum allowed size (1024 characters).",
            ));
        }
        let forbidden = |c: char| matches!(c, '/' | '\\' | '#' | '?') || c.is_control();
        if value.chars().any(forbidden) {
            return Err(TableError::with(
                Kind::InvalidInput,
                "The key value contains characters that are not allowed in PartitionKey or RowKey.",
            ));
        }
        Ok(Self(value.to_owned()))
    }

    pub(super) fn as_str(&self) -> &str {
        &self.0
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(super) struct EntityKey {
    pub(super) partition: KeyValue,
    pub(super) row: KeyValue,
}

#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub(super) struct PropertyName(String);

impl PropertyName {
    pub(super) fn parse(value: &str) -> Result<Self> {
        if value.is_empty() {
            return Err(TableError::new(Kind::PropertyNameInvalid));
        }
        if value.chars().count() > MAX_PROPERTY_NAME {
            return Err(TableError::new(Kind::PropertyNameTooLong));
        }
        let mut chars = value.chars();
        let valid = chars.next().is_some_and(|c| c.is_alphabetic() || c == '_')
            && chars.all(|c| c.is_alphanumeric() || c == '_');
        if !valid || matches!(value, "PartitionKey" | "RowKey" | "Timestamp") {
            return Err(TableError::new(Kind::PropertyNameInvalid));
        }
        Ok(Self(value.to_owned()))
    }

    pub(super) fn as_str(&self) -> &str {
        &self.0
    }
}

impl std::borrow::Borrow<str> for PropertyName {
    fn borrow(&self) -> &str {
        &self.0
    }
}

/// The inclusive entity range a service SAS grants (`spk`/`srk` through `epk`/`erk`).
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub(super) struct KeyRange {
    pub(super) lower: Option<(String, Option<String>)>,
    pub(super) upper: Option<(String, Option<String>)>,
}

impl KeyRange {
    pub(super) fn contains(&self, key: &EntityKey) -> bool {
        let (partition, row) = (key.partition.as_str(), key.row.as_str());
        let above = match &self.lower {
            None => true,
            Some((start, None)) => partition >= start.as_str(),
            Some((start, Some(start_row))) => {
                (partition, row) >= (start.as_str(), start_row.as_str())
            }
        };
        let below = match &self.upper {
            None => true,
            Some((end, None)) => partition <= end.as_str(),
            Some((end, Some(end_row))) => (partition, row) <= (end.as_str(), end_row.as_str()),
        };
        above && below
    }

    pub(super) fn partition_min(&self) -> Option<&str> {
        self.lower.as_ref().map(|(partition, _)| partition.as_str())
    }

    pub(super) fn partition_max(&self) -> Option<&str> {
        self.upper.as_ref().map(|(partition, _)| partition.as_str())
    }
}

/// A typed `Edm` property value.
#[derive(Clone, Debug, PartialEq)]
pub(super) enum Value {
    String(String),
    Boolean(bool),
    Int32(i32),
    Int64(i64),
    Double(f64),
    DateTime(Ticks),
    Guid(Uuid),
    Binary(Vec<u8>),
}

impl Value {
    /// Approximate stored size used for the 1 MiB entity limit.
    pub(super) fn size(&self) -> usize {
        match self {
            Self::String(value) => value.encode_utf16().count() * 2,
            Self::Boolean(_) => 1,
            Self::Int32(_) => 4,
            Self::Int64(_) | Self::Double(_) | Self::DateTime(_) => 8,
            Self::Guid(_) => 16,
            Self::Binary(value) => value.len(),
        }
    }

    /// Checks the per-value limits for strings and binary data.
    pub(super) fn check_limits(&self) -> Result<()> {
        let too_large = match self {
            Self::String(value) => value.encode_utf16().count() > MAX_STRING_UNITS,
            Self::Binary(value) => value.len() > MAX_BINARY_BYTES,
            _ => false,
        };
        if too_large {
            return Err(TableError::new(Kind::PropertyValueTooLarge));
        }
        Ok(())
    }
}

pub(super) type Properties = BTreeMap<PropertyName, Value>;

#[derive(Clone, Debug, PartialEq)]
pub(super) struct Entity {
    pub(super) key: EntityKey,
    pub(super) timestamp: Ticks,
    pub(super) properties: Properties,
}

/// Validates the property count and the total entity size for stored properties.
pub(super) fn check_entity_limits(key: &EntityKey, properties: &Properties) -> Result<()> {
    if properties.len() > MAX_USER_PROPERTIES {
        return Err(TableError::new(Kind::TooManyProperties));
    }
    let mut size = (key.partition.as_str().encode_utf16().count()
        + key.row.as_str().encode_utf16().count())
        * 2
        + 8;
    for (name, value) in properties {
        value.check_limits()?;
        size += name.as_str().encode_utf16().count() * 2 + value.size();
    }
    if size > MAX_ENTITY_BYTES {
        return Err(TableError::new(Kind::EntityTooLarge));
    }
    Ok(())
}

/// The weak ETag derived from an entity's `Timestamp`.
pub(super) fn etag(timestamp: Ticks) -> String {
    format!("W/\"datetime'{}'\"", timestamp.format().replace(':', "%3A"))
}

/// A parsed `If-Match` header.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(super) enum Precondition {
    None,
    Any,
    Tag(String),
}

impl Precondition {
    pub(super) fn parse(if_match: Option<&str>, if_none_match: Option<&str>) -> Result<Self> {
        if if_none_match.is_some() {
            return Err(TableError::with(
                Kind::InvalidInput,
                if if_match.is_some() {
                    "Both If-Match and If-None-Match HTTP headers cannot be specified at the same time. Please specify either one of the headers or none of them."
                } else {
                    "If-None-Match HTTP header cannot be specified for this operation."
                },
            ));
        }
        match if_match.map(str::trim) {
            None => Ok(Self::None),
            Some("*") => Ok(Self::Any),
            Some(tag) => {
                let body = tag.strip_prefix("W/").unwrap_or(tag);
                let valid = body.len() >= 2
                    && body.starts_with('"')
                    && body.ends_with('"')
                    && !body[1..body.len() - 1].contains('"');
                if !valid {
                    return Err(TableError::with(
                        Kind::InvalidInput,
                        format!(
                            "The etag value '{tag}' specified in one of the request headers is not valid. Please make sure only one etag value is specified and is valid."
                        ),
                    ));
                }
                Ok(Self::Tag(normalize_etag(tag)))
            }
        }
    }

    /// True when the stored entity satisfies the condition (`None` always does).
    pub(super) fn holds(&self, current: Ticks) -> bool {
        match self {
            Self::None | Self::Any => true,
            Self::Tag(tag) => *tag == normalize_etag(&etag(current)),
        }
    }
}

// Weak/strong forms and percent-encoded colons all denote the same Timestamp.
fn normalize_etag(tag: &str) -> String {
    tag.strip_prefix("W/")
        .unwrap_or(tag)
        .replace("%3A", ":")
        .replace("%3a", ":")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn table_names_follow_azure_rules() {
        for ok in ["abc", "MyTable1", &"a".repeat(63)] {
            assert!(TableName::parse(ok).is_ok(), "{ok}");
        }
        for bad in [
            "ab",
            "1abc",
            "my-table",
            "tables",
            "Tables",
            &"a".repeat(64),
            "",
        ] {
            assert!(TableName::parse(bad).is_err(), "{bad}");
        }
        assert_eq!(TableName::parse("MyTable").unwrap().key(), "mytable");
    }

    #[test]
    fn keys_reject_forbidden_characters_and_length() {
        assert!(KeyValue::parse("").is_ok());
        assert!(KeyValue::parse("a b'c é").is_ok());
        for bad in [
            "a/b", "a\\b", "a#b", "a?b", "a\tb", "a\nb", "a\u{7f}b", "a\u{85}b",
        ] {
            assert!(KeyValue::parse(bad).is_err(), "{bad:?}");
        }
        assert!(KeyValue::parse(&"k".repeat(1024)).is_ok());
        assert!(KeyValue::parse(&"k".repeat(1025)).is_err());
    }

    #[test]
    fn property_names_reject_system_and_malformed_names() {
        assert!(PropertyName::parse("Name_1").is_ok());
        for bad in ["", "1a", "a-b", "a b", "PartitionKey", "Timestamp"] {
            assert!(PropertyName::parse(bad).is_err(), "{bad}");
        }
        assert_eq!(
            PropertyName::parse(&"n".repeat(256)).unwrap_err().kind(),
            Kind::PropertyNameTooLong
        );
    }

    #[test]
    fn etags_match_weak_strong_and_encoded_forms() {
        let ticks = Ticks::parse("2013-08-22T01:12:06.2608595Z").unwrap();
        assert_eq!(
            etag(ticks),
            "W/\"datetime'2013-08-22T01%3A12%3A06.2608595Z'\""
        );
        for header in [
            etag(ticks),
            "\"datetime'2013-08-22T01%3A12%3A06.2608595Z'\"".to_owned(),
            "W/\"datetime'2013-08-22T01:12:06.2608595Z'\"".to_owned(),
        ] {
            assert!(
                Precondition::parse(Some(&header), None)
                    .unwrap()
                    .holds(ticks)
            );
        }
        let other = ticks.after();
        assert!(
            !Precondition::parse(Some(&etag(ticks)), None)
                .unwrap()
                .holds(other)
        );
        assert!(Precondition::parse(Some("*"), None).unwrap().holds(other));
        assert!(Precondition::parse(Some("garbage"), None).is_err());
        assert!(Precondition::parse(None, Some("*")).is_err());
    }
}
