//! Maps a Table HTTP request to a typed operation (parse and validate once at the edge).

use super::{
    auth::Access,
    batch::{self, Batch},
    edm::{self, Metadata, Select},
    error::{Kind, OdataErrorFormat, Result, TableError},
    filter::{self, Expr},
    model::{EntityKey, KeyValue, Precondition, Properties, TableName},
    service::{self, AccessPolicy},
    store::{WriteKind, WriteOp},
};
use crate::{
    address,
    auth::{Query, header},
    domain::AccountName,
};
use axum::http::{HeaderMap, Method, request::Parts};
use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use percent_encoding::percent_decode_str;
use std::collections::BTreeMap;

const MAX_QUERY_BYTES: usize = 32 * 1024;
const MAX_PAGE: usize = 1000;

/// The resource a request path addresses, after the account segment.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(super) enum Target {
    Service,
    Tables,
    TableItem(String),
    Batch,
    Table(TableName),
    Entities(TableName),
    Entity(TableName, EntityKey),
}

impl Target {
    /// The table a request addresses, which service SAS tokens are scoped to.
    pub(super) fn table(&self) -> Option<&TableName> {
        match self {
            Self::Table(table) | Self::Entities(table) | Self::Entity(table, _) => Some(table),
            _ => None,
        }
    }
}

/// Response shape negotiated from the request.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) struct Format {
    pub(super) level: Metadata,
    pub(super) return_content: bool,
}

pub(super) struct TableQuery {
    pub(super) filter: Option<Expr>,
    pub(super) top: usize,
    pub(super) after: Option<String>,
}

pub(super) struct EntityQuery {
    pub(super) filter: Option<Expr>,
    pub(super) select: Option<Select>,
    pub(super) top: usize,
    pub(super) start: Option<(String, String)>,
}

pub(super) enum Operation {
    GetServiceProperties,
    SetServiceProperties(BTreeMap<String, String>),
    GetServiceStats,
    QueryTables(TableQuery),
    GetTable(TableName),
    CreateTable(TableName),
    DeleteTable(TableName),
    GetAcl(TableName),
    SetAcl(TableName, Vec<AccessPolicy>),
    QueryEntities(TableName, EntityQuery),
    GetEntity(TableName, EntityKey, Option<Select>),
    Write(TableName, WriteOp),
    Batch(Batch),
}

pub(super) struct Request {
    pub(super) operation: Operation,
    pub(super) format: Format,
}

impl Operation {
    /// Calls `check` with each access the operation needs, stopping at the first refusal.
    pub(super) fn check_access(
        &self,
        check: &mut impl FnMut(Access, Option<&TableName>, Option<&EntityKey>) -> Result<()>,
    ) -> Result<()> {
        match self {
            Self::GetServiceProperties | Self::GetServiceStats => {
                check(Access::ServiceRead, None, None)
            }
            Self::SetServiceProperties(_) => check(Access::ServiceWrite, None, None),
            Self::QueryTables(_) | Self::GetTable(_) => check(Access::ListTables, None, None),
            Self::CreateTable(_) => check(Access::CreateTable, None, None),
            Self::DeleteTable(_) => check(Access::DeleteTable, None, None),
            Self::GetAcl(table) | Self::SetAcl(table, _) => {
                check(Access::TableAcl, Some(table), None)
            }
            Self::QueryEntities(table, _) => check(Access::EntityRead, Some(table), None),
            Self::GetEntity(table, key, _) => check(Access::EntityRead, Some(table), Some(key)),
            Self::Write(table, op) => {
                let access = match (&op.kind, &op.condition) {
                    (WriteKind::Insert, _) => Access::EntityAdd,
                    (WriteKind::Delete, _) => Access::EntityDelete,
                    (_, Precondition::None) => Access::EntityUpsert,
                    _ => Access::EntityUpdate,
                };
                check(access, Some(table), Some(&op.key))
            }
            Self::Batch(batch) => {
                for sub in &batch.requests {
                    sub.request.operation.check_access(check)?;
                }
                Ok(())
            }
        }
    }
}

fn decode(value: &str) -> Option<String> {
    let bytes = value.as_bytes();
    let malformed = bytes.iter().enumerate().any(|(at, byte)| {
        *byte == b'%'
            && !bytes
                .get(at + 1..at + 3)
                .is_some_and(|pair| pair.iter().all(u8::is_ascii_hexdigit))
    });
    if malformed {
        return None;
    }
    percent_decode_str(value)
        .decode_utf8()
        .ok()
        .map(|text| text.into_owned())
}

/// Parses the query string; names are case-folded, duplicates are refused.
pub(super) fn parse_query(query: Option<&str>) -> Result<Query> {
    let mut result = Query::new();
    let invalid = || TableError::new(Kind::InvalidQueryParameterValue);
    for pair in query
        .unwrap_or_default()
        .split('&')
        .filter(|pair| !pair.is_empty())
    {
        if query.is_some_and(|query| query.len() > MAX_QUERY_BYTES) {
            return Err(invalid());
        }
        let (name, value) = pair.split_once('=').unwrap_or((pair, ""));
        let name = decode(&name.replace('+', " "))
            .ok_or_else(invalid)?
            .to_ascii_lowercase();
        let value = decode(&value.replace('+', " ")).ok_or_else(invalid)?;
        if result.insert(name, value).is_some() {
            return Err(invalid());
        }
    }
    Ok(result)
}

/// The request path in path-style form, and whether the request used host-style
/// addressing. `{account}[-secondary].table.{domain}` supplies the account segment.
pub(super) fn logical_path(parts: &Parts) -> (String, bool) {
    let label = address::host_label("table", address::request_host(parts)).filter(|label| {
        AccountName::parse(label.strip_suffix("-secondary").unwrap_or(label)).is_ok()
    });
    match label {
        Some(label) => (format!("/{label}{}", parts.uri.path()), true),
        None => (parts.uri.path().to_owned(), false),
    }
}

/// Splits a `/account/...` path into the account and the addressed resource. A
/// `-secondary` account suffix selects the read-only secondary location.
pub(super) fn parse_path(path: &str) -> Result<(AccountName, bool, Target)> {
    let rest = path
        .strip_prefix('/')
        .ok_or_else(|| TableError::new(Kind::InvalidInput))?;
    let (account, remainder) = rest.split_once('/').unwrap_or((rest, ""));
    let (account, secondary) = account
        .strip_suffix("-secondary")
        .map_or((account, false), |primary| (primary, true));
    let account = AccountName::parse(account)?;
    // Some SDKs build the secondary URL as `/<account>-secondary/<account>/...`.
    let remainder = match remainder.strip_prefix(account.as_str()) {
        Some(tail) if secondary && (tail.is_empty() || tail.starts_with('/')) => {
            tail.trim_start_matches('/')
        }
        _ => remainder,
    };
    Ok((account, secondary, parse_target(remainder)?))
}

/// Parses the resource part of a path, such as `Tables`, `t()`, or `t(PartitionKey='a',RowKey='b')`.
pub(super) fn parse_target(remainder: &str) -> Result<Target> {
    let segment = remainder.strip_suffix('/').unwrap_or(remainder);
    if segment.is_empty() {
        return Ok(Target::Service);
    }
    if segment.contains('/') {
        return Err(TableError::new(Kind::InvalidInput));
    }
    let segment = decode(segment).ok_or_else(|| TableError::new(Kind::InvalidInput))?;
    if segment == "$batch" {
        return Ok(Target::Batch);
    }
    if segment.eq_ignore_ascii_case("Tables") {
        return Ok(Target::Tables);
    }
    let Some((name, tail)) = segment.split_once('(') else {
        return Ok(Target::Table(TableName::parse(&segment)?));
    };
    let inner = tail
        .strip_suffix(')')
        .ok_or_else(|| TableError::new(Kind::InvalidInput))?;
    if name.eq_ignore_ascii_case("Tables") {
        let table = inner
            .strip_prefix('\'')
            .and_then(|text| text.strip_suffix('\''))
            .ok_or_else(|| TableError::new(Kind::InvalidInput))?;
        return Ok(Target::TableItem(table.replace("''", "'")));
    }
    let table = TableName::parse(name)?;
    if inner.is_empty() {
        return Ok(Target::Entities(table));
    }
    Ok(Target::Entity(table, parse_key_spec(inner)?))
}

fn quoted(text: &str) -> Option<(String, &str)> {
    let mut chars = text.strip_prefix('\'')?.char_indices().peekable();
    let mut value = String::new();
    while let Some((at, c)) = chars.next() {
        if c != '\'' {
            value.push(c);
        } else if chars.peek().is_some_and(|(_, next)| *next == '\'') {
            value.push('\'');
            chars.next();
        } else {
            return Some((value, text.get(at + 2..)?));
        }
    }
    None
}

fn parse_key_spec(inner: &str) -> Result<EntityKey> {
    let invalid = || TableError::new(Kind::InvalidInput);
    let rest = inner.strip_prefix("PartitionKey=").ok_or_else(invalid)?;
    let (partition, rest) = quoted(rest).ok_or_else(invalid)?;
    let rest = rest.trim_start().strip_prefix(',').ok_or_else(invalid)?;
    let rest = rest
        .trim_start()
        .strip_prefix("RowKey=")
        .ok_or_else(invalid)?;
    let (row, rest) = quoted(rest).ok_or_else(invalid)?;
    if !rest.trim().is_empty() {
        return Err(invalid());
    }
    Ok(EntityKey {
        partition: KeyValue::parse(&partition)?,
        row: KeyValue::parse(&row)?,
    })
}

/// The effective method, honouring `X-HTTP-Method` on POST.
pub(super) fn effective_method(method: &Method, headers: &HeaderMap) -> Result<Method> {
    let mut values = headers.get_all("x-http-method").iter();
    let Some(first) = values.next() else {
        return Ok(method.clone());
    };
    if values.next().is_some() || *method != Method::POST {
        return Err(TableError::new(Kind::InvalidInput));
    }
    match first
        .to_str()
        .map_err(|_| TableError::new(Kind::InvalidInput))?
        .to_ascii_uppercase()
        .as_str()
    {
        "MERGE" => {
            Ok(Method::from_bytes(b"MERGE").map_err(|_| TableError::new(Kind::InvalidInput))?)
        }
        "PATCH" => Ok(Method::PATCH),
        "PUT" => Ok(Method::PUT),
        "DELETE" => Ok(Method::DELETE),
        _ => Err(TableError::new(Kind::InvalidInput)),
    }
}

fn level_from_media(value: &str) -> Option<Metadata> {
    let mut parts = value.split(';').map(str::trim);
    let media = parts.next()?.to_ascii_lowercase();
    if !matches!(media.as_str(), "application/json" | "application/*" | "*/*") {
        return None;
    }
    let level = parts
        .filter_map(|part| part.split_once('='))
        .find(|(name, _)| name.trim().eq_ignore_ascii_case("odata"))
        .map(|(_, level)| level.trim().to_ascii_lowercase());
    Some(match level.as_deref() {
        Some("nometadata") => Metadata::None,
        Some("fullmetadata") => Metadata::Full,
        _ => Metadata::Minimal,
    })
}

pub(super) fn explicit_json_level(accept: &str) -> Option<Metadata> {
    accept
        .split(',')
        .filter(|item| {
            item.split(';')
                .next()
                .is_some_and(|media| media.trim().eq_ignore_ascii_case("application/json"))
        })
        .find_map(level_from_media)
}

fn atom_not_supported(format: OdataErrorFormat) -> TableError {
    TableError::new(Kind::AtomFormatNotSupported).with_odata_format(format)
}

fn negotiate(accept: Option<&str>, format: Option<&str>) -> Result<Metadata> {
    if let Some(format) = format {
        return match format.trim().to_ascii_lowercase().as_str() {
            "json" => Ok(Metadata::Minimal),
            "atom" | "xml" => Err(atom_not_supported(OdataErrorFormat::Xml)),
            _ => level_from_media(format)
                .ok_or_else(|| TableError::new(Kind::JsonFormatNotSupported)),
        };
    }
    let Some(accept) = accept.filter(|accept| !accept.trim().is_empty()) else {
        return Ok(Metadata::Minimal);
    };
    if let Some(level) = accept.split(',').find_map(level_from_media) {
        return Ok(level);
    }
    let atom = accept.split(',').any(|item| {
        let media = item
            .split(';')
            .next()
            .unwrap_or_default()
            .trim()
            .to_ascii_lowercase();
        matches!(media.as_str(), "application/atom+xml" | "application/xml")
    });
    Err(if atom {
        atom_not_supported(OdataErrorFormat::Xml)
    } else {
        TableError::new(Kind::JsonFormatNotSupported)
    })
}

fn format(headers: &HeaderMap, query: &Query) -> Result<Format> {
    let level = negotiate(
        header(headers, "accept")?,
        query.get("$format").map(String::as_str),
    )?;
    let return_content = !header(headers, "prefer")?
        .is_some_and(|prefer| prefer.to_ascii_lowercase().contains("return-no-content"));
    Ok(Format {
        level,
        return_content,
    })
}

fn require_json(headers: &HeaderMap, level: Metadata) -> Result<()> {
    let content_type = header(headers, "content-type")?.unwrap_or_default();
    let media = content_type
        .split(';')
        .next()
        .unwrap_or_default()
        .trim()
        .to_ascii_lowercase();
    match media.as_str() {
        "" | "application/json" => Ok(()),
        "application/atom+xml" | "application/xml" => {
            Err(atom_not_supported(OdataErrorFormat::Json(level)))
        }
        _ => Err(TableError::new(Kind::JsonFormatNotSupported)),
    }
}

/// Continuation tokens look like Azure's `1!<length>!<base64>` and are opaque to clients.
pub(super) fn encode_token(value: &str) -> String {
    let encoded = URL_SAFE_NO_PAD.encode(value);
    format!("1!{}!{encoded}", encoded.len())
}

fn decode_token(token: &str) -> Result<String> {
    let invalid = || TableError::new(Kind::InvalidQueryParameterValue);
    let mut parts = token.splitn(3, '!');
    let (version, length, encoded) = (parts.next(), parts.next(), parts.next());
    let (Some("1"), Some(length), Some(encoded)) = (version, length, encoded) else {
        return Err(invalid());
    };
    if length.parse::<usize>() != Ok(encoded.len()) {
        return Err(invalid());
    }
    let bytes = URL_SAFE_NO_PAD.decode(encoded).map_err(|_| invalid())?;
    String::from_utf8(bytes).map_err(|_| invalid())
}

fn top(query: &Query) -> Result<usize> {
    let Some(value) = query.get("$top") else {
        return Ok(MAX_PAGE);
    };
    match value.parse::<i64>() {
        Ok(top) if top >= 1 => Ok(usize::try_from(top).map_or(MAX_PAGE, |top| top.min(MAX_PAGE))),
        _ => Err(TableError::with(
            Kind::OutOfRangeInput,
            format!("The '$top' parameter of value '{value}' is out of range."),
        )),
    }
}

fn reject_unsupported_options(query: &Query) -> Result<()> {
    if [
        "$orderby",
        "$skip",
        "$expand",
        "$inlinecount",
        "$skiptoken",
        "$count",
        "$search",
    ]
    .iter()
    .any(|name| query.contains_key(*name))
    {
        return Err(TableError::new(Kind::NotImplemented));
    }
    Ok(())
}

fn parse_filter(query: &Query, level: Metadata) -> Result<Option<Expr>> {
    query
        .get("$filter")
        .map(|text| {
            filter::parse(text)
                .map_err(|error| error.with_odata_format(OdataErrorFormat::Json(level)))
        })
        .transpose()
}

fn precondition(headers: &HeaderMap) -> Result<Precondition> {
    Precondition::parse(
        header(headers, "if-match")?,
        header(headers, "if-none-match")?,
    )
}

/// Builds the typed request from an already routed method and target.
pub(super) fn build(
    method: &Method,
    target: Target,
    query: &Query,
    headers: &HeaderMap,
    body: &[u8],
) -> Result<Request> {
    let comp = query.get("comp").map(String::as_str);
    // Service properties and ACLs are XML documents; JSON negotiation does not apply.
    let format = if matches!(target, Target::Service) || comp == Some("acl") {
        Format {
            level: Metadata::Minimal,
            return_content: true,
        }
    } else {
        format(headers, query)?
    };
    let not_allowed = || TableError::new(Kind::MethodNotAllowed);
    let merge = method.as_str() == "MERGE" || *method == Method::PATCH;
    let operation = match target {
        Target::Service => match (method, query.get("restype").map(String::as_str), comp) {
            (&Method::GET, Some("service"), Some("properties")) => Operation::GetServiceProperties,
            (&Method::GET, Some("service"), Some("stats")) => Operation::GetServiceStats,
            (&Method::PUT, Some("service"), Some("properties")) => {
                Operation::SetServiceProperties(service::parse_properties(body)?)
            }
            (&Method::GET | &Method::PUT, _, _) => {
                return Err(TableError::new(Kind::InvalidQueryParameterValue));
            }
            _ => return Err(not_allowed()),
        },
        Target::Tables => match *method {
            Method::GET => {
                reject_unsupported_options(query)?;
                Operation::QueryTables(TableQuery {
                    filter: parse_filter(query, format.level)?,
                    top: top(query)?,
                    after: query.get("nexttablename").cloned(),
                })
            }
            Method::POST => {
                require_json(headers, format.level)?;
                Operation::CreateTable(edm::parse_table_name(body)?)
            }
            _ => return Err(not_allowed()),
        },
        Target::TableItem(name) => {
            let table = TableName::parse(&name)?;
            match *method {
                Method::GET => Operation::GetTable(table),
                Method::DELETE => Operation::DeleteTable(table),
                _ => return Err(not_allowed()),
            }
        }
        Target::Batch => return Err(not_allowed()),
        Target::Table(table) => match (method, comp) {
            (&Method::GET, Some("acl")) => Operation::GetAcl(table),
            (&Method::PUT, Some("acl")) => Operation::SetAcl(table, service::parse_acl(body)?),
            (&Method::POST, None) => {
                require_json(headers, format.level)?;
                let entity = edm::parse_entity(body)?;
                let (Some(partition), Some(row)) = (entity.partition, entity.row) else {
                    return Err(TableError::new(Kind::PropertiesNeedValue));
                };
                Operation::Write(
                    table,
                    WriteOp {
                        kind: WriteKind::Insert,
                        key: EntityKey { partition, row },
                        properties: entity.properties,
                        condition: Precondition::None,
                    },
                )
            }
            _ => return Err(not_allowed()),
        },
        Target::Entities(table) => match *method {
            Method::GET => {
                reject_unsupported_options(query)?;
                let start = query.get("nextpartitionkey").map(|partition| {
                    let row = query
                        .get("nextrowkey")
                        .map_or(Ok(String::new()), |row| decode_token(row));
                    Ok::<_, TableError>((decode_token(partition)?, row?))
                });
                Operation::QueryEntities(
                    table,
                    EntityQuery {
                        filter: parse_filter(query, format.level)?,
                        select: query
                            .get("$select")
                            .map(|s| Select::parse(s))
                            .transpose()?
                            .flatten(),
                        top: top(query)?,
                        start: start.transpose()?,
                    },
                )
            }
            _ => return Err(not_allowed()),
        },
        Target::Entity(table, key) => match method.as_str() {
            "GET" => Operation::GetEntity(
                table,
                key,
                query
                    .get("$select")
                    .map(|s| Select::parse(s))
                    .transpose()?
                    .flatten(),
            ),
            "DELETE" => {
                let condition = precondition(headers)?;
                if condition == Precondition::None {
                    return Err(TableError::with(
                        Kind::InvalidInput,
                        "The If-Match header is required for delete operations.",
                    ));
                }
                write(table, WriteKind::Delete, key, Properties::new(), condition)
            }
            "PUT" | "MERGE" | "PATCH" => {
                require_json(headers, format.level)?;
                let condition = precondition(headers)?;
                let entity = edm::parse_entity(body)?;
                let mismatch = entity
                    .partition
                    .as_ref()
                    .is_some_and(|p| *p != key.partition)
                    || entity.row.as_ref().is_some_and(|r| *r != key.row);
                if mismatch {
                    return Err(TableError::with(
                        Kind::InvalidInput,
                        "The values provided for PartitionKey and RowKey do not match the request URI.",
                    ));
                }
                let kind = if merge {
                    WriteKind::Merge
                } else {
                    WriteKind::Replace
                };
                write(table, kind, key, entity.properties, condition)
            }
            _ => return Err(not_allowed()),
        },
    };
    Ok(Request { operation, format })
}

fn write(
    table: TableName,
    kind: WriteKind,
    key: EntityKey,
    properties: Properties,
    condition: Precondition,
) -> Operation {
    Operation::Write(
        table,
        WriteOp {
            kind,
            key,
            properties,
            condition,
        },
    )
}

/// The batch operation, whose members are parsed by the `batch` module.
pub(super) fn build_batch(
    headers: &HeaderMap,
    body: &[u8],
    account: &str,
) -> std::result::Result<Request, batch::BatchError> {
    let format = format(headers, &Query::new())?;
    let content_type = header(headers, "content-type")
        .map_err(TableError::from)?
        .unwrap_or_default();
    Ok(Request {
        operation: Operation::Batch(batch::parse(content_type, body, account)?),
        format,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn target(path: &str) -> Result<Target> {
        parse_path(path).map(|(_, _, target)| target)
    }

    #[test]
    fn a_secondary_suffix_selects_the_primary_account_read_only() {
        let (account, secondary, target) = parse_path("/acct-secondary/").unwrap();
        assert_eq!(
            (account.as_str(), secondary, target),
            ("acct", true, Target::Service)
        );
        assert!(!parse_path("/acct/Tables").unwrap().1);
        let (_, secondary, target) = parse_path("/acct-secondary/acct/").unwrap();
        assert!(secondary && target == Target::Service);
    }

    #[test]
    fn paths_route_to_service_tables_entities_and_batches() {
        assert_eq!(target("/acct").unwrap(), Target::Service);
        assert_eq!(target("/acct/").unwrap(), Target::Service);
        assert_eq!(target("/acct/Tables").unwrap(), Target::Tables);
        assert_eq!(target("/acct/$batch").unwrap(), Target::Batch);
        assert_eq!(target("/acct/%24batch").unwrap(), Target::Batch);
        assert_eq!(
            target("/acct/Tables('My')").unwrap(),
            Target::TableItem("My".into())
        );
        let table = TableName::parse("People").unwrap();
        assert_eq!(
            target("/acct/People").unwrap(),
            Target::Table(table.clone())
        );
        assert_eq!(
            target("/acct/People()").unwrap(),
            Target::Entities(table.clone())
        );
        let key = |p: &str, r: &str| EntityKey {
            partition: KeyValue::parse(p).unwrap(),
            row: KeyValue::parse(r).unwrap(),
        };
        assert_eq!(
            target("/acct/People(PartitionKey='a',RowKey='b')").unwrap(),
            Target::Entity(table.clone(), key("a", "b"))
        );
        assert_eq!(
            target("/acct/People(PartitionKey='o''k',RowKey='%C3%A9,)(')").unwrap(),
            Target::Entity(table.clone(), key("o'k", "é,)("))
        );
        assert_eq!(
            target("/acct/People(PartitionKey='a', RowKey='')").unwrap(),
            Target::Entity(table, key("a", ""))
        );
        for bad in [
            "/acct/a/b",
            "/acct/People(PartitionKey='a')",
            "/acct/People(RowKey='a',PartitionKey='b')",
            "/acct/People(PartitionKey='a',RowKey='b'",
            "/acct/People(PartitionKey='a/b',RowKey='c')",
            "/acct/ab",
            "/ac/Tables",
        ] {
            assert!(target(bad).is_err(), "{bad}");
        }
    }

    #[test]
    fn query_strings_decode_and_reject_duplicates() {
        let query = parse_query(Some("%24filter=A%20eq%20%27x+y%27&$TOP=5&comp=acl&flag")).unwrap();
        assert_eq!(query["$filter"], "A eq 'x y'");
        assert_eq!(query["$top"], "5");
        assert_eq!(query["flag"], "");
        assert!(parse_query(Some("a=1&A=2")).is_err());
        assert!(parse_query(Some("a=%zz")).is_err());
        assert!(parse_query(None).unwrap().is_empty());
    }

    #[test]
    fn accept_and_format_select_the_json_metadata_level() {
        for (accept, expected) in [
            (None, Metadata::Minimal),
            (Some("application/json"), Metadata::Minimal),
            (Some("application/json;odata=nometadata"), Metadata::None),
            (
                Some("application/json; odata=fullmetadata; streaming=true"),
                Metadata::Full,
            ),
            (Some("*/*"), Metadata::Minimal),
            (
                Some("application/atom+xml, application/json;odata=nometadata"),
                Metadata::None,
            ),
        ] {
            assert_eq!(negotiate(accept, None).unwrap(), expected, "{accept:?}");
        }
        assert_eq!(
            negotiate(
                Some("application/json"),
                Some("application/json;odata=fullmetadata")
            )
            .unwrap(),
            Metadata::Full
        );
        assert_eq!(
            negotiate(Some("application/atom+xml"), None)
                .unwrap_err()
                .kind(),
            Kind::AtomFormatNotSupported
        );
        assert_eq!(
            negotiate(Some("text/html"), None).unwrap_err().kind(),
            Kind::JsonFormatNotSupported
        );
    }

    #[test]
    fn continuation_tokens_round_trip_and_reject_tampering() {
        let token = encode_token("pé/k");
        assert_eq!(decode_token(&token).unwrap(), "pé/k");
        assert!(decode_token("garbage").is_err());
        assert!(decode_token("1!3!AAAA").is_err());
        assert!(decode_token("2!4!AAAA").is_err());
    }

    #[test]
    fn x_http_method_overrides_only_post() {
        let mut headers = HeaderMap::new();
        headers.insert("x-http-method", "merge".parse().unwrap());
        assert_eq!(
            effective_method(&Method::POST, &headers).unwrap().as_str(),
            "MERGE"
        );
        assert!(effective_method(&Method::GET, &headers).is_err());
        headers.insert("x-http-method", "bogus".parse().unwrap());
        assert!(effective_method(&Method::POST, &headers).is_err());
        assert_eq!(
            effective_method(&Method::PUT, &HeaderMap::new()).unwrap(),
            Method::PUT
        );
    }

    #[test]
    fn writes_derive_conditions_and_reject_bad_requests() {
        let key = target("/acct/People(PartitionKey='a',RowKey='b')").unwrap();
        let headers = |if_match: Option<&str>| {
            let mut headers = HeaderMap::new();
            if let Some(tag) = if_match {
                headers.insert("if-match", tag.parse().unwrap());
            }
            headers
        };
        let q = Query::new();
        let delete =
            |tag| build(&Method::DELETE, key.clone(), &q, &headers(tag), b"").map(|r| r.operation);
        assert!(delete(None).is_err());
        assert!(
            matches!(delete(Some("*")), Ok(Operation::Write(_, op)) if op.condition == Precondition::Any)
        );
        let put = |tag, body: &[u8]| {
            build(&Method::PUT, key.clone(), &q, &headers(tag), body).map(|r| r.operation)
        };
        assert!(
            matches!(put(None, b"{}"), Ok(Operation::Write(_, op)) if op.condition == Precondition::None)
        );
        assert!(put(Some("*"), br#"{"PartitionKey":"other"}"#).is_err());
        let mut access = Vec::new();
        let op = put(None, b"{}").unwrap();
        op.check_access(&mut |a, _, _| {
            access.push(a);
            Ok(())
        })
        .unwrap();
        assert_eq!(access, [Access::EntityUpsert]);
    }
}
