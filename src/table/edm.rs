//! JSON wire form of entities: request parsing and response serialization (OData v3 JSON).

use super::{
    datetime::Ticks,
    error::{Kind, Result, TableError},
    model::{
        Entity, EntityKey, KeyValue, MAX_USER_PROPERTIES, Properties, PropertyName, TableName,
        Value, etag,
    },
};
use base64::{Engine as _, engine::general_purpose::STANDARD};
use percent_encoding::{AsciiSet, NON_ALPHANUMERIC, utf8_percent_encode};
use serde::{
    Deserialize, Deserializer,
    de::{MapAccess, Visitor},
};
use serde_json::{Map, Number, Value as Json};
use std::collections::{BTreeMap, BTreeSet};
use uuid::Uuid;

const PATH: &AsciiSet = &NON_ALPHANUMERIC
    .remove(b'-')
    .remove(b'_')
    .remove(b'.')
    .remove(b'~')
    .remove(b'\'');

/// The JSON control level negotiated through `Accept` or `$format`.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum Metadata {
    None,
    Minimal,
    Full,
}

impl Metadata {
    pub(super) fn content_type(self) -> &'static str {
        match self {
            Self::None => "application/json;odata=nometadata;streaming=true;charset=utf-8",
            Self::Minimal => "application/json;odata=minimalmetadata;streaming=true;charset=utf-8",
            Self::Full => "application/json;odata=fullmetadata;streaming=true;charset=utf-8",
        }
    }
}

/// Where this account's resources live, for `odata.*` links.
#[derive(Clone, Debug)]
pub(super) struct Urls {
    pub(super) account: String,
    pub(super) base: String,
}

/// `Table(PartitionKey='p',RowKey='r')` with quotes doubled and other characters escaped.
pub(super) fn entity_path(table: &TableName, key: &EntityKey) -> String {
    let quote = |value: &str| utf8_percent_encode(&value.replace('\'', "''"), PATH).to_string();
    format!(
        "{}(PartitionKey='{}',RowKey='{}')",
        table.as_str(),
        quote(key.partition.as_str()),
        quote(key.row.as_str())
    )
}

struct RawObject(Vec<(String, Json)>);

impl<'de> Deserialize<'de> for RawObject {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> std::result::Result<Self, D::Error> {
        struct Pairs;
        impl<'de> Visitor<'de> for Pairs {
            type Value = RawObject;

            fn expecting(&self, formatter: &mut std::fmt::Formatter) -> std::fmt::Result {
                formatter.write_str("a JSON object")
            }

            fn visit_map<A: MapAccess<'de>>(
                self,
                mut map: A,
            ) -> std::result::Result<RawObject, A::Error> {
                let mut pairs = Vec::new();
                while let Some(pair) = map.next_entry::<String, Json>()? {
                    pairs.push(pair);
                }
                Ok(RawObject(pairs))
            }
        }
        deserializer.deserialize_map(Pairs)
    }
}

/// Parses a request body into its JSON members in order, keeping duplicates visible.
fn members(body: &[u8]) -> Result<Vec<(String, Json)>> {
    serde_json::from_slice::<RawObject>(body)
        .map(|object| object.0)
        .map_err(|_| TableError::new(Kind::InvalidInput))
}

/// Reads the `TableName` member of a Create Table body.
pub(super) fn parse_table_name(body: &[u8]) -> Result<TableName> {
    let name = members(body)?
        .into_iter()
        .find(|(name, _)| name == "TableName")
        .and_then(|(_, value)| value.as_str().map(str::to_owned))
        .ok_or_else(|| TableError::new(Kind::PropertiesNeedValue))?;
    TableName::parse(&name)
}

pub(super) struct EntityBody {
    pub(super) partition: Option<KeyValue>,
    pub(super) row: Option<KeyValue>,
    pub(super) properties: Properties,
}

pub(super) fn parse_entity(body: &[u8]) -> Result<EntityBody> {
    let members = members(body)?;
    let mut types = BTreeMap::new();
    let mut values = BTreeMap::new();
    for (name, value) in members {
        if let Some(property) = name.strip_suffix("@odata.type") {
            let Some(type_name) = value.as_str() else {
                return Err(TableError::new(Kind::InvalidValueType));
            };
            if types
                .insert(property.to_owned(), type_name.to_owned())
                .is_some()
            {
                return Err(TableError::new(Kind::DuplicatePropertiesSpecified));
            }
        } else if name.starts_with("odata.") {
            continue;
        } else if name.contains('@') {
            return Err(TableError::new(Kind::InvalidInput));
        } else if values.insert(name, value).is_some() {
            return Err(TableError::new(Kind::DuplicatePropertiesSpecified));
        }
    }
    if types.keys().any(|name| !values.contains_key(name)) {
        return Err(TableError::new(Kind::PropertiesNeedValue));
    }
    let mut body = EntityBody {
        partition: None,
        row: None,
        properties: Properties::new(),
    };
    for (name, value) in values {
        let declared = types.get(&name).map(String::as_str);
        match name.as_str() {
            "PartitionKey" | "RowKey" => {
                let Json::String(text) = &value else {
                    return Err(TableError::new(Kind::InvalidInput));
                };
                if declared.is_some_and(|declared| declared != "Edm.String") {
                    return Err(TableError::new(Kind::InvalidInput));
                }
                let key = KeyValue::parse(text)?;
                if name == "PartitionKey" {
                    body.partition = Some(key);
                } else {
                    body.row = Some(key);
                }
            }
            // The server owns Timestamp; a client-supplied value is ignored.
            "Timestamp" => {}
            _ => {
                let property = PropertyName::parse(&name)?;
                if let Some(value) = convert(declared, &value)? {
                    value.check_limits()?;
                    body.properties.insert(property, value);
                }
            }
        }
    }
    if body.properties.len() > MAX_USER_PROPERTIES {
        return Err(TableError::new(Kind::TooManyProperties));
    }
    Ok(body)
}

fn invalid_value() -> TableError {
    TableError::new(Kind::InvalidValueType)
}

/// Converts one JSON value to its Edm type; `None` is a null, which is never stored.
fn convert(declared: Option<&str>, json: &Json) -> Result<Option<Value>> {
    if json.is_null() {
        return Ok(None);
    }
    let value = match (declared, json) {
        (None | Some("Edm.String"), Json::String(text)) => Value::String(text.clone()),
        (None | Some("Edm.Boolean"), Json::Bool(flag)) => Value::Boolean(*flag),
        (Some("Edm.Boolean"), Json::String(text)) => match text.as_str() {
            "true" => Value::Boolean(true),
            "false" => Value::Boolean(false),
            _ => return Err(invalid_value()),
        },
        (None, Json::Number(number)) => infer_number(number),
        (Some("Edm.Int32"), Json::Number(number)) => number
            .as_i64()
            .and_then(|value| i32::try_from(value).ok())
            .map(Value::Int32)
            .ok_or_else(invalid_value)?,
        (Some("Edm.Int32"), Json::String(text)) => {
            Value::Int32(text.parse().map_err(|_| invalid_value())?)
        }
        (Some("Edm.Int64"), Json::Number(number)) => {
            Value::Int64(number.as_i64().ok_or_else(invalid_value)?)
        }
        (Some("Edm.Int64"), Json::String(text)) => {
            Value::Int64(text.parse().map_err(|_| invalid_value())?)
        }
        (Some("Edm.Double"), Json::Number(number)) => {
            Value::Double(normalize_zero(number.as_f64().ok_or_else(invalid_value)?))
        }
        (Some("Edm.Double"), Json::String(text)) => Value::Double(parse_double(text)?),
        (Some("Edm.DateTime"), Json::String(text)) => {
            Value::DateTime(Ticks::parse(text).ok_or_else(invalid_value)?)
        }
        (Some("Edm.Guid"), Json::String(text)) => {
            if text.len() != 36 {
                return Err(invalid_value());
            }
            Value::Guid(Uuid::parse_str(text).map_err(|_| invalid_value())?)
        }
        (Some("Edm.Binary"), Json::String(text)) => {
            Value::Binary(STANDARD.decode(text).map_err(|_| invalid_value())?)
        }
        _ => return Err(invalid_value()),
    };
    Ok(Some(value))
}

fn infer_number(number: &Number) -> Value {
    match number.as_i64().map(i32::try_from) {
        Some(Ok(value)) => Value::Int32(value),
        _ => Value::Double(normalize_zero(number.as_f64().unwrap_or(f64::NAN))),
    }
}

fn normalize_zero(value: f64) -> f64 {
    if value == 0.0 { 0.0 } else { value }
}

/// Parses the string forms of `Edm.Double`: the non-finite names and plain decimals.
pub(super) fn parse_double(text: &str) -> Result<f64> {
    match text {
        "NaN" => Ok(f64::NAN),
        "Infinity" | "INF" => Ok(f64::INFINITY),
        "-Infinity" | "-INF" => Ok(f64::NEG_INFINITY),
        _ if text
            .bytes()
            .all(|b| b.is_ascii_digit() || matches!(b, b'+' | b'-' | b'.' | b'e' | b'E')) =>
        {
            text.parse()
                .map(normalize_zero)
                .map_err(|_| invalid_value())
        }
        _ => Err(invalid_value()),
    }
}

/// The Edm type annotation a value needs because JSON cannot convey it.
fn annotation(value: &Value) -> Option<&'static str> {
    match value {
        Value::Binary(_) => Some("Edm.Binary"),
        Value::DateTime(_) => Some("Edm.DateTime"),
        Value::Guid(_) => Some("Edm.Guid"),
        Value::Int64(_) => Some("Edm.Int64"),
        Value::Double(value) if !value.is_finite() => Some("Edm.Double"),
        _ => None,
    }
}

fn to_json(value: &Value) -> Json {
    match value {
        Value::String(text) => Json::String(text.clone()),
        Value::Boolean(flag) => Json::Bool(*flag),
        Value::Int32(value) => Json::from(*value),
        Value::Int64(value) => Json::String(value.to_string()),
        Value::Double(value) => match Number::from_f64(*value) {
            Some(number) => Json::Number(number),
            None if value.is_nan() => Json::String("NaN".into()),
            None if *value > 0.0 => Json::String("Infinity".into()),
            None => Json::String("-Infinity".into()),
        },
        Value::DateTime(ticks) => Json::String(ticks.format_trimmed()),
        Value::Guid(value) => Json::String(value.hyphenated().to_string()),
        Value::Binary(bytes) => Json::String(STANDARD.encode(bytes)),
    }
}

/// A validated `$select` list.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub(super) struct Select(BTreeSet<String>);

impl Select {
    /// `None` means every property (`$select=*` or no `$select`).
    pub(super) fn parse(text: &str) -> Result<Option<Self>> {
        let mut names = BTreeSet::new();
        for name in text.split(',').map(str::trim) {
            if name == "*" {
                return Ok(None);
            }
            if !matches!(name, "PartitionKey" | "RowKey" | "Timestamp") {
                PropertyName::parse(name)?;
            }
            names.insert(name.to_owned());
        }
        Ok(Some(Self(names)))
    }
}

/// Serializes one entity at the requested metadata level.
pub(super) fn entity_json(
    entity: &Entity,
    table: &TableName,
    level: Metadata,
    urls: &Urls,
    select: Option<&Select>,
) -> Map<String, Json> {
    let mut map = Map::new();
    if level != Metadata::None {
        map.insert("odata.etag".into(), Json::String(etag(entity.timestamp)));
    }
    if level == Metadata::Full {
        let path = entity_path(table, &entity.key);
        map.insert(
            "odata.type".into(),
            Json::String(format!("{}.{}", urls.account, table.as_str())),
        );
        map.insert(
            "odata.id".into(),
            Json::String(format!("{}/{path}", urls.base)),
        );
        map.insert("odata.editLink".into(), Json::String(path));
    }
    let wanted = |name: &str| select.is_none_or(|select| select.0.contains(name));
    if wanted("PartitionKey") {
        map.insert(
            "PartitionKey".into(),
            Json::String(entity.key.partition.as_str().to_owned()),
        );
    }
    if wanted("RowKey") {
        map.insert(
            "RowKey".into(),
            Json::String(entity.key.row.as_str().to_owned()),
        );
    }
    if wanted("Timestamp") {
        if level == Metadata::Full {
            map.insert(
                "Timestamp@odata.type".into(),
                Json::String("Edm.DateTime".into()),
            );
        }
        map.insert("Timestamp".into(), Json::String(entity.timestamp.format()));
    }
    for (name, value) in &entity.properties {
        if !wanted(name.as_str()) {
            continue;
        }
        if level != Metadata::None
            && let Some(type_name) = annotation(value)
        {
            map.insert(
                format!("{}@odata.type", name.as_str()),
                Json::String(type_name.into()),
            );
        }
        map.insert(name.as_str().to_owned(), to_json(value));
    }
    if let Some(select) = select {
        for name in &select.0 {
            if !map.contains_key(name)
                && !matches!(name.as_str(), "PartitionKey" | "RowKey" | "Timestamp")
            {
                map.insert(name.clone(), Json::Null);
            }
        }
    }
    map
}

/// The `odata.metadata` link for a collection or a single resource.
pub(super) fn metadata_link(urls: &Urls, table: Option<&TableName>, single: bool) -> String {
    let name = table.map_or("Tables", TableName::as_str);
    match (table, single) {
        (Some(_), true) => format!("{}/{name}/$metadata#{name}/@Element", urls.base),
        (None, true) => format!("{}/$metadata#{name}/@Element", urls.base),
        _ => format!("{}/$metadata#{name}", urls.base),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn urls() -> Urls {
        Urls {
            account: "acct".into(),
            base: "http://h/acct".into(),
        }
    }

    fn table() -> TableName {
        TableName::parse("tab").unwrap()
    }

    const BODY: &str = r#"{
        "PartitionKey":"p","RowKey":"r",
        "S":"text","B":true,"I":7,"D":1.0,
        "L@odata.type":"Edm.Int64","L":"9223372036854775807",
        "T@odata.type":"Edm.DateTime","T":"2013-08-02T17:37:43.9004348Z",
        "G@odata.type":"Edm.Guid","G":"4185404a-5818-48c3-b9be-f217df0dba6f",
        "Bin@odata.type":"Edm.Binary","Bin":"AQIDBA==",
        "Nan@odata.type":"Edm.Double","Nan":"NaN",
        "Neg@odata.type":"Edm.Double","Neg":"-Infinity",
        "Gone":null
    }"#;

    fn entity() -> Entity {
        let body = parse_entity(BODY.as_bytes()).unwrap();
        Entity {
            key: EntityKey {
                partition: body.partition.unwrap(),
                row: body.row.unwrap(),
            },
            timestamp: Ticks::parse("2013-08-22T01:12:06.2608595Z").unwrap(),
            properties: body.properties,
        }
    }

    #[test]
    fn request_body_types_are_inferred_and_annotated() {
        let entity = entity();
        let get = |name: &str| entity.properties.get(&PropertyName::parse(name).unwrap());
        assert_eq!(get("S"), Some(&Value::String("text".into())));
        assert_eq!(get("B"), Some(&Value::Boolean(true)));
        assert_eq!(get("I"), Some(&Value::Int32(7)));
        assert_eq!(get("D"), Some(&Value::Double(1.0)));
        assert_eq!(get("L"), Some(&Value::Int64(i64::MAX)));
        assert_eq!(get("Bin"), Some(&Value::Binary(vec![1, 2, 3, 4])));
        assert!(matches!(get("Nan"), Some(Value::Double(v)) if v.is_nan()));
        assert_eq!(get("Neg"), Some(&Value::Double(f64::NEG_INFINITY)));
        assert_eq!(get("Gone"), None);
    }

    #[test]
    fn serialization_follows_the_metadata_level() {
        let entity = entity();
        let table = table();
        let minimal = entity_json(&entity, &table, Metadata::Minimal, &urls(), None);
        assert_eq!(minimal["L"], "9223372036854775807");
        assert_eq!(minimal["L@odata.type"], "Edm.Int64");
        assert_eq!(minimal["D"].to_string(), "1.0");
        assert_eq!(minimal["Nan"], "NaN");
        assert_eq!(minimal["Nan@odata.type"], "Edm.Double");
        assert_eq!(minimal["Timestamp"], "2013-08-22T01:12:06.2608595Z");
        assert!(
            minimal["odata.etag"]
                .as_str()
                .unwrap()
                .starts_with("W/\"datetime'")
        );
        assert!(!minimal.contains_key("Timestamp@odata.type"));
        assert!(!minimal.contains_key("odata.id"));

        let none = entity_json(&entity, &table, Metadata::None, &urls(), None);
        assert!(none.keys().all(|key| !key.contains("odata")));
        assert_eq!(none["L"], "9223372036854775807");

        let full = entity_json(&entity, &table, Metadata::Full, &urls(), None);
        assert_eq!(full["Timestamp@odata.type"], "Edm.DateTime");
        assert_eq!(full["odata.editLink"], "tab(PartitionKey='p',RowKey='r')");
        assert_eq!(
            full["odata.id"],
            "http://h/acct/tab(PartitionKey='p',RowKey='r')"
        );
    }

    #[test]
    fn serialized_entities_parse_back_to_the_same_values() {
        let entity = entity();
        let table = table();
        let json = entity_json(&entity, &table, Metadata::Full, &urls(), None);
        let again = parse_entity(Json::Object(json).to_string().as_bytes()).unwrap();
        // NaN != NaN, so compare the stored encodings.
        assert_eq!(
            super::super::codec::encode(&again.properties),
            super::super::codec::encode(&entity.properties)
        );
        assert_eq!(again.partition, Some(entity.key.partition));
    }

    #[test]
    fn select_projects_and_reports_missing_properties_as_null() {
        let entity = entity();
        let select = Select::parse("S,Missing").unwrap();
        let json = entity_json(
            &entity,
            &table(),
            Metadata::Minimal,
            &urls(),
            select.as_ref(),
        );
        assert_eq!(json["S"], "text");
        assert_eq!(json["Missing"], Json::Null);
        assert!(!json.contains_key("RowKey") && !json.contains_key("I"));
        assert_eq!(Select::parse("*").unwrap(), None);
        assert!(Select::parse("bad-name").is_err());
    }

    #[test]
    fn invalid_bodies_map_to_azure_error_codes() {
        let kind = |body: &str| parse_entity(body.as_bytes()).err().map(|e| e.kind());
        assert_eq!(kind("[]"), Some(Kind::InvalidInput));
        assert_eq!(kind("{"), Some(Kind::InvalidInput));
        assert_eq!(
            kind(r#"{"A":1,"A":2}"#),
            Some(Kind::DuplicatePropertiesSpecified)
        );
        assert_eq!(
            kind(r#"{"A@odata.type":"Edm.Int64"}"#),
            Some(Kind::PropertiesNeedValue)
        );
        assert_eq!(
            kind(r#"{"A@odata.type":"Edm.Int32","A":"x"}"#),
            Some(Kind::InvalidValueType)
        );
        assert_eq!(
            kind(r#"{"A@odata.type":"Edm.Foo","A":"x"}"#),
            Some(Kind::InvalidValueType)
        );
        assert_eq!(kind(r#"{"A":[1]}"#), Some(Kind::InvalidValueType));
        assert_eq!(kind(r#"{"bad-name":1}"#), Some(Kind::PropertyNameInvalid));
        assert_eq!(kind(r#"{"PartitionKey":"a/b"}"#), Some(Kind::InvalidInput));
        let big = format!(r#"{{"A":"{}"}}"#, "x".repeat(32 * 1024 + 1));
        assert_eq!(kind(&big), Some(Kind::PropertyValueTooLarge));
        assert!(parse_entity(br#"{"A":"x"}"#).is_ok());
    }

    #[test]
    fn create_table_body_requires_a_valid_name() {
        assert_eq!(
            parse_table_name(br#"{"TableName":"MyTable"}"#)
                .unwrap()
                .as_str(),
            "MyTable"
        );
        assert!(parse_table_name(br#"{"TableName":"1bad"}"#).is_err());
        assert!(parse_table_name(b"{}").is_err());
    }
}
