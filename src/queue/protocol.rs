use super::{
    error::{QueueError, Result},
    model::{
        MAX_METADATA_BYTES, MAX_VISIBILITY_SECONDS, MessageId, Metadata, PopReceipt, QueueName,
    },
};
use crate::{
    address,
    auth::{Query, header},
    domain::{AccountName, PageRequest, xml_safe},
};
use axum::http::{HeaderMap, Method, request::Parts};
use percent_encoding::percent_decode_str;

pub(super) struct Request {
    pub(super) account: AccountName,
    /// The `Host` the client addressed, when it used host-style addressing.
    pub(super) host: Option<String>,
    pub(super) query: Query,
    pub(super) operation: Operation,
}

pub(super) struct ListOptions {
    pub(super) page: PageRequest,
    pub(super) marker: String,
    pub(super) metadata: bool,
}

pub(super) struct PutOptions {
    pub(super) visibility_seconds: i64,
    /// `None` is a message that never expires (`messagettl=-1`).
    pub(super) ttl_seconds: Option<i64>,
}

pub(super) struct Preflight {
    pub(super) origin: String,
    pub(super) method: String,
    pub(super) headers: Vec<String>,
}

pub(super) enum Operation {
    GetServiceProperties,
    SetServiceProperties,
    GetServiceStats,
    ListQueues(ListOptions),
    CreateQueue(QueueName, Metadata),
    DeleteQueue(QueueName),
    GetQueueMetadata(QueueName),
    SetQueueMetadata(QueueName, Metadata),
    GetQueueAcl(QueueName),
    SetQueueAcl(QueueName),
    PutMessage(QueueName, PutOptions),
    GetMessages(QueueName, u32, i64),
    PeekMessages(QueueName, u32),
    UpdateMessage(QueueName, MessageId, PopReceipt, i64),
    DeleteMessage(QueueName, MessageId, PopReceipt),
    ClearMessages(QueueName),
    Preflight(Preflight),
}

/// The account SAS resource type an operation addresses.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum Scope {
    Service,
    Container,
    Object,
}

impl Scope {
    pub(super) fn letter(self) -> char {
        match self {
            Self::Service => 's',
            Self::Container => 'c',
            Self::Object => 'o',
        }
    }
}

/// What a SAS must grant: any letter of `account` on an account SAS, or the
/// `service` letter on a service SAS (`None` when a service SAS cannot grant it).
pub(super) struct Grant {
    pub(super) scope: Scope,
    pub(super) account: &'static str,
    pub(super) service: Option<char>,
}

impl Operation {
    pub(super) fn queue(&self) -> Option<&QueueName> {
        match self {
            Self::CreateQueue(queue, _)
            | Self::DeleteQueue(queue)
            | Self::GetQueueMetadata(queue)
            | Self::SetQueueMetadata(queue, _)
            | Self::GetQueueAcl(queue)
            | Self::SetQueueAcl(queue)
            | Self::PutMessage(queue, _)
            | Self::GetMessages(queue, ..)
            | Self::PeekMessages(queue, _)
            | Self::UpdateMessage(queue, ..)
            | Self::DeleteMessage(queue, ..)
            | Self::ClearMessages(queue) => Some(queue),
            _ => None,
        }
    }

    /// The permission table from the account and service SAS references; `None`
    /// means the operation is not authorized by any SAS (the CORS preflight is anonymous).
    pub(super) fn grant(&self) -> Option<Grant> {
        let grant = |scope, account, service| {
            Some(Grant {
                scope,
                account,
                service,
            })
        };
        match self {
            Self::GetServiceProperties | Self::GetServiceStats => grant(Scope::Service, "r", None),
            Self::SetServiceProperties => grant(Scope::Service, "w", None),
            Self::ListQueues(_) => grant(Scope::Service, "l", None),
            Self::CreateQueue(..) => grant(Scope::Container, "cw", None),
            Self::DeleteQueue(_) => grant(Scope::Container, "d", None),
            Self::GetQueueMetadata(_) => grant(Scope::Container, "r", Some('r')),
            Self::GetQueueAcl(_) => grant(Scope::Container, "r", None),
            Self::SetQueueMetadata(..) | Self::SetQueueAcl(_) => grant(Scope::Container, "w", None),
            Self::PutMessage(..) => grant(Scope::Object, "a", Some('a')),
            Self::GetMessages(..) | Self::DeleteMessage(..) => grant(Scope::Object, "p", Some('p')),
            Self::PeekMessages(..) => grant(Scope::Object, "r", Some('r')),
            Self::UpdateMessage(..) => grant(Scope::Object, "u", Some('u')),
            Self::ClearMessages(_) => grant(Scope::Object, "d", None),
            Self::Preflight(_) => None,
        }
    }
}

enum Target {
    Service,
    Queue(QueueName),
    Messages(QueueName),
    Message(QueueName, MessageId),
}

pub(super) fn parse(parts: &Parts) -> Result<Request> {
    let headers = &parts.headers;
    if headers.len() > 100
        || headers
            .iter()
            .map(|(name, value)| name.as_str().len() + value.len())
            .sum::<usize>()
            > 32768
    {
        return Err(QueueError::MalformedHeaders);
    }
    let query = parse_query(parts.uri.query())?;
    let (path, host) = address::resolve("queue", parts);
    let (account, target) = parse_path(&path)?;
    let operation = route(&parts.method, target, &query, headers)?;
    Ok(Request {
        account,
        host: host.map(str::to_owned),
        query,
        operation,
    })
}

/// The account a request addresses, used to evaluate CORS when routing failed.
pub(super) fn account_of(parts: &Parts) -> Option<AccountName> {
    parse_path(&address::resolve("queue", parts).0)
        .ok()
        .map(|(account, _)| account)
}

fn decode(value: &str, plus_is_space: bool) -> Result<String> {
    let prepared = if plus_is_space {
        value.replace('+', " ")
    } else {
        value.to_owned()
    };
    let decoded = percent_decode_str(&prepared)
        .decode_utf8()
        .map_err(|_| QueueError::InvalidUri)?;
    if !xml_safe(&decoded) {
        return Err(QueueError::InvalidUri);
    }
    Ok(decoded.into_owned())
}

fn parse_path(path: &str) -> Result<(AccountName, Target)> {
    let rest = path.strip_prefix('/').ok_or(QueueError::InvalidUri)?;
    let mut segments = rest.split('/');
    let account = AccountName::parse(segments.next().unwrap_or_default())
        .map_err(|_| QueueError::InvalidUri)?;
    let rest: Vec<&str> = segments.collect();
    let target = match rest.as_slice() {
        [] | [""] => Target::Service,
        [queue] | [queue, ""] => Target::Queue(QueueName::parse(&decode(queue, false)?)?),
        [queue, "messages"] | [queue, "messages", ""] => {
            Target::Messages(QueueName::parse(&decode(queue, false)?)?)
        }
        [queue, "messages", id] => Target::Message(
            QueueName::parse(&decode(queue, false)?)?,
            MessageId::parse(decode(id, false)?)?,
        ),
        _ => return Err(QueueError::InvalidUri),
    };
    Ok((account, target))
}

fn parse_query(query: Option<&str>) -> Result<Query> {
    let mut result = Query::new();
    let Some(query) = query.filter(|query| !query.is_empty()) else {
        return Ok(result);
    };
    if query.len() > 16 * 1024 {
        return Err(QueueError::InvalidUri);
    }
    for pair in query.split('&').filter(|pair| !pair.is_empty()) {
        let (name, value) = pair.split_once('=').unwrap_or((pair, ""));
        let name = decode(name, true)?.to_ascii_lowercase();
        if name.is_empty() || result.insert(name, decode(value, true)?).is_some() {
            return Err(QueueError::InvalidUri);
        }
    }
    Ok(result)
}

fn integer(query: &Query, name: &'static str) -> Result<Option<i64>> {
    query
        .get(name)
        .map(|value| {
            value.parse::<i64>().map_err(|_| {
                QueueError::InvalidQuery(name, value.clone(), "Value must be an integer.")
            })
        })
        .transpose()
}

fn bounded(name: &'static str, value: i64, min: i64, max: i64) -> Result<i64> {
    if (min..=max).contains(&value) {
        Ok(value)
    } else {
        Err(QueueError::OutOfRangeQuery(
            name,
            value.to_string(),
            min,
            max,
        ))
    }
}

fn seconds(query: &Query, name: &'static str, default: i64, min: i64) -> Result<i64> {
    let value = integer(query, name)?.unwrap_or(default);
    bounded(name, value, min, MAX_VISIBILITY_SECONDS)
}

fn message_count(query: &Query) -> Result<u32> {
    let count = bounded(
        "numofmessages",
        integer(query, "numofmessages")?.unwrap_or(1),
        1,
        32,
    )?;
    u32::try_from(count).map_err(|_| QueueError::Internal)
}

fn put_options(query: &Query) -> Result<PutOptions> {
    let visibility = seconds(query, "visibilitytimeout", 0, 0)?;
    let ttl = match integer(query, "messagettl")? {
        None => Some(7 * 24 * 3600),
        Some(-1) => None,
        Some(ttl) if ttl < 1 => {
            return Err(QueueError::InvalidQuery(
                "messagettl",
                ttl.to_string(),
                "Value must be greater than or equal to 1, or -1 to indicate an infinite TTL.",
            ));
        }
        Some(ttl) => Some(ttl),
    };
    if ttl.is_some_and(|ttl| visibility >= ttl) {
        return Err(QueueError::InvalidQuery(
            "visibilitytimeout",
            visibility.to_string(),
            "messagettl must be greater than visibilitytimeout.",
        ));
    }
    Ok(PutOptions {
        visibility_seconds: visibility,
        ttl_seconds: ttl,
    })
}

fn receipt(query: &Query) -> Result<PopReceipt> {
    query
        .get("popreceipt")
        .ok_or(QueueError::MissingQuery("popreceipt"))
        .and_then(|value| PopReceipt::parse(value))
}

fn metadata(headers: &HeaderMap) -> Result<Metadata> {
    let mut metadata = Metadata::new();
    let mut size = 0;
    for (name, value) in headers {
        let Some(name) = name.as_str().strip_prefix("x-ms-meta-") else {
            continue;
        };
        let mut letters = name.bytes();
        let valid_name = letters
            .next()
            .is_some_and(|b| b.is_ascii_alphabetic() || b == b'_')
            && letters.all(|b| b.is_ascii_alphanumeric() || b == b'_');
        let value = value.to_str().map_err(|_| QueueError::InvalidMetadata)?;
        if !valid_name || !xml_safe(value) {
            return Err(QueueError::InvalidMetadata);
        }
        size += name.len() + value.len();
        if metadata.insert(name.to_owned(), value.to_owned()).is_some() {
            return Err(QueueError::InvalidMetadata);
        }
    }
    if size > MAX_METADATA_BYTES {
        return Err(QueueError::MetadataTooLarge);
    }
    Ok(metadata)
}

fn list_options(query: &Query) -> Result<ListOptions> {
    let limit = match query.get("maxresults") {
        None => None,
        Some(value) => {
            let number = value.parse::<i64>().map_err(|_| {
                QueueError::InvalidQuery("maxresults", value.clone(), "Value must be an integer.")
            })?;
            bounded("maxresults", number, 1, 5000)?;
            Some(value.as_str())
        }
    };
    let marker = query.get("marker").map_or("", String::as_str);
    let page = PageRequest::parse(query.get("prefix").map(String::as_str), Some(marker), limit)
        .map_err(|_| {
            QueueError::InvalidQuery(
                "marker",
                marker.to_owned(),
                "The marker or prefix is invalid.",
            )
        })?;
    let metadata = match query.get("include").map(String::as_str) {
        None | Some("") => false,
        Some(include) => {
            if include
                .split(',')
                .any(|item| !item.trim().eq_ignore_ascii_case("metadata"))
            {
                return Err(QueueError::InvalidQuery(
                    "include",
                    include.to_owned(),
                    "Only metadata can be included.",
                ));
            }
            true
        }
    };
    Ok(ListOptions {
        page,
        marker: marker.to_owned(),
        metadata,
    })
}

fn preflight(headers: &HeaderMap) -> Result<Preflight> {
    let text = |name: &'static str| {
        header(headers, name)?
            .map(str::to_owned)
            .ok_or(QueueError::MissingCorsHeader(name))
    };
    Ok(Preflight {
        origin: text("Origin")?,
        method: text("Access-Control-Request-Method")?,
        headers: header(headers, "access-control-request-headers")?
            .map(|value| {
                value
                    .split(',')
                    .map(|item| item.trim().to_owned())
                    .filter(|item| !item.is_empty())
                    .collect()
            })
            .unwrap_or_default(),
    })
}

fn route(method: &Method, target: Target, query: &Query, headers: &HeaderMap) -> Result<Operation> {
    let comp = query.get("comp").map(String::as_str);
    let restype = query.get("restype").map(String::as_str);
    let unknown_comp = |comp: Option<&str>| match comp {
        Some(value) => QueueError::InvalidQuery("comp", value.to_owned(), "Unknown component."),
        None => QueueError::InvalidUri,
    };
    if method == Method::OPTIONS {
        return Ok(Operation::Preflight(preflight(headers)?));
    }
    match target {
        Target::Service => match (restype, comp) {
            (Some("service"), Some("properties")) => match *method {
                Method::GET => Ok(Operation::GetServiceProperties),
                Method::PUT => Ok(Operation::SetServiceProperties),
                _ => Err(QueueError::UnsupportedVerb),
            },
            (Some("service"), Some("stats")) if method == Method::GET => {
                Ok(Operation::GetServiceStats)
            }
            (_, Some("list")) if method == Method::GET => {
                Ok(Operation::ListQueues(list_options(query)?))
            }
            (Some("service"), Some("stats")) | (_, Some("list")) => {
                Err(QueueError::UnsupportedVerb)
            }
            _ => Err(unknown_comp(comp)),
        },
        Target::Queue(queue) => match (comp, method.clone()) {
            (None, Method::PUT) => Ok(Operation::CreateQueue(queue, metadata(headers)?)),
            (None, Method::DELETE) => Ok(Operation::DeleteQueue(queue)),
            (Some("metadata"), Method::GET | Method::HEAD) => {
                Ok(Operation::GetQueueMetadata(queue))
            }
            (Some("metadata"), Method::PUT) => {
                Ok(Operation::SetQueueMetadata(queue, metadata(headers)?))
            }
            (Some("acl"), Method::GET) => Ok(Operation::GetQueueAcl(queue)),
            (Some("acl"), Method::PUT) => Ok(Operation::SetQueueAcl(queue)),
            (None | Some("metadata" | "acl"), _) => Err(QueueError::UnsupportedVerb),
            (other, _) => Err(unknown_comp(other)),
        },
        Target::Messages(queue) => match *method {
            Method::POST => Ok(Operation::PutMessage(queue, put_options(query)?)),
            Method::GET => match query.get("peekonly").map(String::as_str) {
                None => Ok(Operation::GetMessages(
                    queue,
                    message_count(query)?,
                    seconds(query, "visibilitytimeout", 30, 1)?,
                )),
                Some(value) if value.eq_ignore_ascii_case("true") => {
                    Ok(Operation::PeekMessages(queue, message_count(query)?))
                }
                Some(value) => Err(QueueError::InvalidQuery(
                    "peekonly",
                    value.to_owned(),
                    "Value must be true.",
                )),
            },
            Method::DELETE => Ok(Operation::ClearMessages(queue)),
            _ => Err(QueueError::UnsupportedVerb),
        },
        Target::Message(queue, id) => match *method {
            Method::PUT => {
                let receipt = receipt(query)?;
                let visibility = integer(query, "visibilitytimeout")?
                    .ok_or(QueueError::MissingQuery("visibilitytimeout"))?;
                let visibility =
                    bounded("visibilitytimeout", visibility, 0, MAX_VISIBILITY_SECONDS)?;
                Ok(Operation::UpdateMessage(queue, id, receipt, visibility))
            }
            Method::DELETE => Ok(Operation::DeleteMessage(queue, id, receipt(query)?)),
            _ => Err(QueueError::UnsupportedVerb),
        },
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::http::Request as HttpRequest;

    fn parse_request(method: &str, uri: &str, headers: &[(&str, &str)]) -> Result<Request> {
        let mut builder = HttpRequest::builder().method(method).uri(uri);
        for (name, value) in headers {
            builder = builder.header(*name, *value);
        }
        parse(&builder.body(()).unwrap().into_parts().0)
    }

    fn operation(method: &str, uri: &str) -> Result<Operation> {
        parse_request(method, uri, &[]).map(|request| request.operation)
    }

    #[test]
    fn routes_every_queue_operation() {
        let base = "/devstoreaccount1";
        let cases = [
            (
                "GET",
                "/?restype=service&comp=properties",
                "GetServiceProperties",
            ),
            (
                "PUT",
                "/?restype=service&comp=properties",
                "SetServiceProperties",
            ),
            ("GET", "?restype=service&comp=stats", "GetServiceStats"),
            ("GET", "/?comp=list&maxresults=3", "ListQueues"),
            ("PUT", "/myq", "CreateQueue"),
            ("DELETE", "/myq", "DeleteQueue"),
            ("HEAD", "/myq?comp=metadata", "GetQueueMetadata"),
            ("PUT", "/myq?comp=metadata", "SetQueueMetadata"),
            ("GET", "/myq?comp=acl", "GetQueueAcl"),
            ("PUT", "/myq?comp=acl", "SetQueueAcl"),
            ("POST", "/myq/messages", "PutMessage"),
            ("GET", "/myq/messages?numofmessages=2", "GetMessages"),
            ("GET", "/myq/messages?peekonly=true", "PeekMessages"),
            ("DELETE", "/myq/messages", "ClearMessages"),
            (
                "PUT",
                "/myq/messages/id1?popreceipt=AAAA&visibilitytimeout=5",
                "UpdateMessage",
            ),
            (
                "DELETE",
                "/myq/messages/id1?popreceipt=AAAA",
                "DeleteMessage",
            ),
        ];
        for (method, rest, expected) in cases {
            let uri = format!("{base}{rest}");
            let op = operation(method, &uri).unwrap_or_else(|e| panic!("{method} {uri}: {e:?}"));
            let name = match op {
                Operation::GetServiceProperties => "GetServiceProperties",
                Operation::SetServiceProperties => "SetServiceProperties",
                Operation::GetServiceStats => "GetServiceStats",
                Operation::ListQueues(_) => "ListQueues",
                Operation::CreateQueue(..) => "CreateQueue",
                Operation::DeleteQueue(_) => "DeleteQueue",
                Operation::GetQueueMetadata(_) => "GetQueueMetadata",
                Operation::SetQueueMetadata(..) => "SetQueueMetadata",
                Operation::GetQueueAcl(_) => "GetQueueAcl",
                Operation::SetQueueAcl(_) => "SetQueueAcl",
                Operation::PutMessage(..) => "PutMessage",
                Operation::GetMessages(..) => "GetMessages",
                Operation::PeekMessages(..) => "PeekMessages",
                Operation::UpdateMessage(..) => "UpdateMessage",
                Operation::DeleteMessage(..) => "DeleteMessage",
                Operation::ClearMessages(_) => "ClearMessages",
                Operation::Preflight(_) => "Preflight",
            };
            assert_eq!(name, expected, "{method} {uri}");
        }
    }

    #[test]
    fn rejects_bad_paths_verbs_and_names() {
        let err = |m, u: &str| operation(m, u).err().unwrap();
        assert_eq!(err("GET", "/acct"), QueueError::InvalidUri);
        assert_eq!(
            err("GET", "/devstoreaccount1/q/other/x"),
            QueueError::InvalidUri
        );
        assert_eq!(
            err("GET", "/devstoreaccount1/Q/messages"),
            QueueError::OutOfRangeName
        );
        assert_eq!(
            err("GET", "/devstoreaccount1/up_per1"),
            QueueError::InvalidResourceName
        );
        assert_eq!(
            err("POST", "/devstoreaccount1/myq"),
            QueueError::UnsupportedVerb
        );
        assert_eq!(
            err("PATCH", "/devstoreaccount1/myq/messages"),
            QueueError::UnsupportedVerb
        );
        assert!(matches!(
            err("GET", "/devstoreaccount1/myq?comp=bogus"),
            QueueError::InvalidQuery("comp", ..)
        ));
        assert_eq!(
            err("DELETE", "/devstoreaccount1/myq/messages/id"),
            QueueError::MissingQuery("popreceipt")
        );
        assert_eq!(
            err("PUT", "/devstoreaccount1/myq/messages/id?popreceipt=AAAA"),
            QueueError::MissingQuery("visibilitytimeout")
        );
    }

    #[test]
    fn message_parameters_are_bounded() {
        let err = |u: &str| operation("GET", u).err().unwrap();
        let base = "/devstoreaccount1/myq/messages";
        assert!(matches!(
            err(&format!("{base}?numofmessages=33")),
            QueueError::OutOfRangeQuery("numofmessages", ..)
        ));
        assert!(matches!(
            err(&format!("{base}?numofmessages=0")),
            QueueError::OutOfRangeQuery(..)
        ));
        assert!(matches!(
            err(&format!("{base}?visibilitytimeout=0")),
            QueueError::OutOfRangeQuery("visibilitytimeout", ..)
        ));
        assert!(matches!(
            err(&format!("{base}?visibilitytimeout=abc")),
            QueueError::InvalidQuery("visibilitytimeout", ..)
        ));
        assert!(
            operation(
                "GET",
                &format!("{base}?numofmessages=32&visibilitytimeout=604800")
            )
            .is_ok()
        );
        let put = |q: &str| operation("POST", &format!("{base}{q}")).err();
        assert_eq!(put(""), None);
        assert_eq!(put("?messagettl=-1&visibilitytimeout=100"), None);
        assert!(matches!(
            put("?messagettl=0"),
            Some(QueueError::InvalidQuery("messagettl", ..))
        ));
        assert!(matches!(
            put("?messagettl=5&visibilitytimeout=5"),
            Some(QueueError::InvalidQuery("visibilitytimeout", ..))
        ));
        assert!(matches!(
            put("?visibilitytimeout=604801"),
            Some(QueueError::OutOfRangeQuery("visibilitytimeout", ..))
        ));
    }

    #[test]
    fn metadata_headers_are_validated() {
        let create = |headers: &[(&str, &str)]| {
            parse_request("PUT", "/devstoreaccount1/myq", headers).map(|r| r.operation)
        };
        let Ok(Operation::CreateQueue(_, metadata)) = create(&[("x-ms-meta-Foo_1", "bar")]) else {
            panic!("valid metadata");
        };
        assert_eq!(metadata["foo_1"], "bar");
        assert!(matches!(
            create(&[("x-ms-meta-1abc", "v")]),
            Err(QueueError::InvalidMetadata)
        ));
        assert!(matches!(
            create(&[("x-ms-meta-a-b", "v")]),
            Err(QueueError::InvalidMetadata)
        ));
        let big = "x".repeat(MAX_METADATA_BYTES);
        assert!(matches!(
            create(&[("x-ms-meta-big", &big)]),
            Err(QueueError::MetadataTooLarge)
        ));
    }

    #[test]
    fn listing_options_validate_limit_marker_and_include() {
        let list = |q: &str| operation("GET", &format!("/devstoreaccount1/?comp=list&{q}")).err();
        assert_eq!(list("include=metadata&maxresults=5000"), None);
        assert!(matches!(
            list("maxresults=5001"),
            Some(QueueError::OutOfRangeQuery(..))
        ));
        assert!(matches!(
            list("maxresults=0"),
            Some(QueueError::OutOfRangeQuery(..))
        ));
        assert!(matches!(
            list("include=snapshots"),
            Some(QueueError::InvalidQuery("include", ..))
        ));
        assert!(matches!(
            list("marker=***"),
            Some(QueueError::InvalidQuery("marker", ..))
        ));
    }

    #[test]
    fn preflight_requires_origin_and_method() {
        let ok = parse_request(
            "OPTIONS",
            "/devstoreaccount1/myq/messages",
            &[
                ("origin", "http://a.example"),
                ("access-control-request-method", "PUT"),
                (
                    "access-control-request-headers",
                    "x-ms-version, content-type",
                ),
            ],
        );
        let Ok(Request {
            operation: Operation::Preflight(p),
            ..
        }) = ok
        else {
            panic!("preflight");
        };
        assert_eq!(p.headers, ["x-ms-version", "content-type"]);
        assert!(matches!(
            parse_request("OPTIONS", "/devstoreaccount1/myq", &[]),
            Err(QueueError::MissingCorsHeader("Origin"))
        ));
    }
}
