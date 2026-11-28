//! Table authentication: Shared Key, Shared Key Lite, account SAS, and service SAS (ADR-0011).

use super::{
    error::{Kind, Result, TableError},
    model::{EntityKey, KeyRange, TableName},
    store::Store,
};
use crate::{
    auth::{Query, check_skew, header, verify_signature},
    config::Service,
    domain::AccountName,
    oauth::{self, OAuth, Principal},
    sas::Sas,
};
use axum::http::{HeaderMap, Method};
use std::time::SystemTime;

/// What a request is allowed to do, established once the signature is verified.
#[derive(Debug)]
pub(super) enum Credential {
    SharedKey,
    /// A validated OAuth bearer token.
    Bearer(Principal),
    AccountSas {
        services: String,
        resource_types: String,
        permissions: String,
    },
    ServiceSas {
        table: String,
        permissions: String,
        range: KeyRange,
    },
}

/// An operation's required access, independent of how the caller authenticated.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum Access {
    ServiceRead,
    ServiceWrite,
    ListTables,
    CreateTable,
    DeleteTable,
    TableAcl,
    EntityRead,
    EntityAdd,
    EntityUpdate,
    EntityUpsert,
    EntityDelete,
}

impl Access {
    fn reads(self) -> bool {
        matches!(
            self,
            Self::ServiceRead | Self::ListTables | Self::EntityRead
        )
    }

    /// The account SAS resource type letters (any one) and permission letters (all of
    /// one alternative) that grant this access.
    fn account_sas(self) -> Option<(&'static str, &'static [&'static str])> {
        Some(match self {
            Self::ServiceRead => ("s", &["r"]),
            Self::ServiceWrite => ("s", &["w"]),
            Self::ListTables => ("sc", &["l"]),
            Self::CreateTable => ("c", &["c", "w"]),
            Self::DeleteTable => ("c", &["d"]),
            Self::EntityRead => ("o", &["r"]),
            Self::EntityAdd => ("o", &["a"]),
            Self::EntityUpdate => ("o", &["u"]),
            Self::EntityUpsert => ("o", &["au"]),
            Self::EntityDelete => ("o", &["d"]),
            Self::TableAcl => return None,
        })
    }

    /// The service SAS permission letters that grant this access, when it can be granted.
    fn service_sas(self) -> Option<&'static str> {
        match self {
            Self::EntityRead => Some("r"),
            Self::EntityAdd => Some("a"),
            Self::EntityUpdate => Some("u"),
            Self::EntityUpsert => Some("au"),
            Self::EntityDelete => Some("d"),
            _ => None,
        }
    }
}

fn denied() -> TableError {
    TableError::new(Kind::AuthorizationFailure)
}

fn has_all(granted: &str, wanted: &str) -> bool {
    wanted.chars().all(|letter| granted.contains(letter))
}

impl Credential {
    pub(super) fn authorize(
        &self,
        access: Access,
        table: Option<&TableName>,
        key: Option<&EntityKey>,
    ) -> Result<()> {
        match self {
            Self::SharedKey => Ok(()),
            Self::Bearer(principal) => principal
                .permits(Service::Table, !access.reads())
                .then_some(())
                .ok_or_else(denied),
            Self::AccountSas {
                services,
                resource_types,
                permissions,
            } => {
                let (types, alternatives) = access.account_sas().ok_or_else(denied)?;
                let allowed = services.contains('t')
                    && types.chars().any(|t| resource_types.contains(t))
                    && alternatives
                        .iter()
                        .any(|letters| has_all(permissions, letters));
                allowed.then_some(()).ok_or_else(denied)
            }
            Self::ServiceSas {
                table: signed,
                permissions,
                range,
            } => {
                let letters = access.service_sas().ok_or_else(denied)?;
                let same_table = table.is_some_and(|table| table.key() == *signed);
                let in_range = key.is_none_or(|key| range.contains(key));
                (same_table && has_all(permissions, letters) && in_range)
                    .then_some(())
                    .ok_or_else(denied)
            }
        }
    }

    /// The entity range a service SAS restricts queries to.
    pub(super) fn range(&self) -> Option<&KeyRange> {
        match self {
            Self::ServiceSas { range, .. } => Some(range),
            _ => None,
        }
    }
}

/// Everything signature verification reads from the request.
pub(super) struct Presented<'a> {
    pub(super) account: &'a AccountName,
    pub(super) keys: &'a [Vec<u8>],
    pub(super) method: &'a Method,
    pub(super) raw_path: &'a str,
    pub(super) query: &'a Query,
    pub(super) headers: &'a HeaderMap,
    pub(super) table: Option<&'a TableName>,
    pub(super) now: SystemTime,
    /// Whether the listener terminates TLS, so an HTTPS-only SAS can match.
    pub(super) https: bool,
}

/// Validates an Authorization: Bearer header, or returns None when the request
/// carries no bearer token for uthenticate to handle.
pub(super) fn bearer(oauth: &OAuth, request: &Presented<'_>) -> Result<Option<Credential>> {
    let Some(token) = header(request.headers, "authorization")?.and_then(oauth::bearer) else {
        return Ok(None);
    };
    if request.query.contains_key("sig") {
        return Ok(None);
    }
    let principal = oauth
        .authenticate(
            token,
            &oauth::Request {
                account: request.account.as_str(),
                host: header(request.headers, "host")?,
                now: request.now,
            },
        )
        .map_err(|_| TableError::new(Kind::InvalidBearer))?;
    Ok(Some(Credential::Bearer(principal)))
}

pub(super) async fn authenticate(store: &Store, request: &Presented<'_>) -> Result<Credential> {
    let authorization = header(request.headers, "authorization")?;
    if request.query.contains_key("sig") {
        if authorization.is_some() {
            return Err(TableError::new(Kind::AuthenticationFailed));
        }
        return sas(store, request).await;
    }
    let authorization = authorization.ok_or_else(|| TableError::new(Kind::AuthenticationFailed))?;
    let (scheme, credentials) = authorization
        .split_once(' ')
        .ok_or_else(|| TableError::new(Kind::AuthenticationFailed))?;
    match scheme {
        "SharedKey" | "SharedKeyLite" => {
            shared_key(request, scheme == "SharedKeyLite", credentials)
        }
        "Bearer" => Err(TableError::new(Kind::InvalidBearer)),
        _ => Err(TableError::new(Kind::AuthenticationFailed)),
    }
}

fn shared_key(request: &Presented<'_>, lite: bool, credentials: &str) -> Result<Credential> {
    let failed = || TableError::new(Kind::AuthenticationFailed);
    let (name, signature) = credentials.split_once(':').ok_or_else(failed)?;
    if name != request.account.as_str() {
        return Err(failed());
    }
    let date = header(request.headers, "x-ms-date")?
        .or(header(request.headers, "date")?)
        .ok_or_else(failed)?;
    check_skew(date, request.now)?;
    let comp = request.query.get("comp").map(String::as_str);
    let md5 = header(request.headers, "content-md5")?.unwrap_or_default();
    let content_type = header(request.headers, "content-type")?.unwrap_or_default();
    // Secondary-location requests are signed with the primary path (the account name
    // never carries `-secondary` in a signature), so accept either form.
    let primary = request.raw_path.replacen("-secondary", "", 1);
    let nested =
        request
            .raw_path
            .replacen(&format!("{}-secondary/", request.account.as_str()), "", 1);
    let mut result = Err(failed());
    for path in [request.raw_path, primary.as_str(), nested.as_str()] {
        let message = if lite {
            shared_key_lite_string_to_sign(date, request.account.as_str(), path, comp)
        } else {
            shared_key_string_to_sign(
                request.method.as_str(),
                md5,
                content_type,
                date,
                request.account.as_str(),
                path,
                comp,
            )
        };
        result = verify_signature(request.keys, &message, signature).map_err(TableError::from);
        if result.is_ok() {
            break;
        }
    }
    result?;
    Ok(Credential::SharedKey)
}

fn resource(account: &str, raw_path: &str, comp: Option<&str>) -> String {
    let mut text = format!("/{account}{raw_path}");
    if let Some(comp) = comp {
        text.push_str("?comp=");
        text.push_str(comp);
    }
    text
}

/// Shared Key for the Table service: only `comp` is signed from the query, and `Date`
/// carries the `x-ms-date` value when that header is used.
pub(super) fn shared_key_string_to_sign(
    method: &str,
    content_md5: &str,
    content_type: &str,
    date: &str,
    account: &str,
    raw_path: &str,
    comp: Option<&str>,
) -> String {
    format!(
        "{method}\n{content_md5}\n{content_type}\n{date}\n{}",
        resource(account, raw_path, comp)
    )
}

pub(super) fn shared_key_lite_string_to_sign(
    date: &str,
    account: &str,
    raw_path: &str,
    comp: Option<&str>,
) -> String {
    format!("{date}\n{}", resource(account, raw_path, comp))
}

fn field<'a>(query: &'a Query, name: &str) -> &'a str {
    query.get(name).map_or("", String::as_str)
}

/// Account SAS string-to-sign for service versions 2015-04-05 and later.
pub(super) fn account_sas_string_to_sign(account: &str, query: &Query) -> String {
    let mut text = format!(
        "{account}\n{}\n{}\n{}\n{}\n{}\n{}\n{}\n{}\n",
        field(query, "sp"),
        field(query, "ss"),
        field(query, "srt"),
        field(query, "st"),
        field(query, "se"),
        field(query, "sip"),
        field(query, "spr"),
        field(query, "sv"),
    );
    if field(query, "sv") >= "2020-12-06" {
        text.push_str(field(query, "ses"));
        text.push('\n');
    }
    text
}

/// Service SAS string-to-sign for a table. The resource names the lower-cased table.
pub(super) fn service_sas_string_to_sign(account: &str, table_key: &str, query: &Query) -> String {
    let version = field(query, "sv");
    let canonical = if version >= "2015-02-21" {
        format!("/table/{account}/{table_key}")
    } else {
        format!("/{account}/{table_key}")
    };
    let mut parts = vec![
        field(query, "sp"),
        field(query, "st"),
        field(query, "se"),
        &canonical,
        field(query, "si"),
    ];
    if version >= "2015-04-05" {
        parts.extend([field(query, "sip"), field(query, "spr")]);
    }
    parts.extend([
        version,
        field(query, "spk"),
        field(query, "srk"),
        field(query, "epk"),
        field(query, "erk"),
    ]);
    parts.join("\n")
}

async fn sas(store: &Store, request: &Presented<'_>) -> Result<Credential> {
    let failed = || TableError::new(Kind::AuthenticationFailed);
    let query = request.query;
    if field(query, "sv").is_empty() || (field(query, "spr") == "https" && !request.https) {
        return Err(failed());
    }
    if query.contains_key("ss") {
        return account_sas(request);
    }
    let table = request.table.ok_or_else(denied)?;
    if !field(query, "tn").eq_ignore_ascii_case(table.as_str()) {
        return Err(denied());
    }
    let mut effective = query.clone();
    if let Some(identifier) = query.get("si") {
        let policies = store
            .table_acl(request.account.clone(), table.clone())
            .await
            .map_err(|_| failed())?;
        let policy = policies
            .iter()
            .find(|policy| policy.id == *identifier)
            .ok_or_else(failed)?;
        for (name, value) in [
            ("sp", &policy.permission),
            ("st", &policy.start),
            ("se", &policy.expiry),
        ] {
            match (query.get(name), value) {
                (None, Some(value)) => {
                    effective.insert(name.to_owned(), value.clone());
                }
                (Some(_), _) => return Err(failed()),
                (None, None) => {}
            }
        }
    }
    let token = Sas::from_query(&effective)?.ok_or_else(failed)?;
    token.check_window(request.now)?;
    let message = service_sas_string_to_sign(request.account.as_str(), &table.key(), query);
    token.verify(request.keys, &message)?;
    let boundary = |partition: &str, row: &str| -> Result<Option<(String, Option<String>)>> {
        match (field(query, partition), field(query, row)) {
            ("", "") => Ok(None),
            ("", _) => Err(failed()),
            (partition, "") => Ok(Some((partition.to_owned(), None))),
            (partition, row) => Ok(Some((partition.to_owned(), Some(row.to_owned())))),
        }
    };
    Ok(Credential::ServiceSas {
        table: table.key(),
        permissions: effective.get("sp").cloned().unwrap_or_default(),
        range: KeyRange {
            lower: boundary("spk", "srk")?,
            upper: boundary("epk", "erk")?,
        },
    })
}

fn account_sas(request: &Presented<'_>) -> Result<Credential> {
    let token = Sas::from_query(request.query)?
        .ok_or_else(|| TableError::new(Kind::AuthenticationFailed))?;
    token.check_window(request.now)?;
    let message = account_sas_string_to_sign(request.account.as_str(), request.query);
    token.verify(request.keys, &message)?;
    Ok(Credential::AccountSas {
        services: token.field("ss").to_owned(),
        resource_types: token.field("srt").to_owned(),
        permissions: token.field("sp").to_owned(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use base64::{Engine as _, engine::general_purpose::STANDARD};
    use hmac::{Hmac, KeyInit as _, Mac as _};
    use sha2::Sha256;

    const KEY: [u8; 32] = [7; 32];

    fn sign(message: &str) -> String {
        let mut mac = Hmac::<Sha256>::new_from_slice(&KEY).unwrap();
        mac.update(message.as_bytes());
        STANDARD.encode(mac.finalize().into_bytes())
    }

    fn query(pairs: &[(&str, &str)]) -> Query {
        pairs
            .iter()
            .map(|(k, v)| ((*k).to_owned(), (*v).to_owned()))
            .collect()
    }

    #[test]
    fn shared_key_string_to_sign_uses_date_and_only_comp() {
        assert_eq!(
            shared_key_string_to_sign(
                "PUT",
                "",
                "application/xml",
                "Fri, 26 Jun 2015 23:39:12 GMT",
                "myaccount",
                "/myaccount/mytable",
                Some("acl"),
            ),
            "PUT\n\napplication/xml\nFri, 26 Jun 2015 23:39:12 GMT\n/myaccount/myaccount/mytable?comp=acl"
        );
        assert_eq!(
            shared_key_string_to_sign("GET", "", "", "d", "a", "/a/Tables", None),
            "GET\n\n\nd\n/a/a/Tables"
        );
    }

    #[test]
    fn shared_key_lite_matches_the_published_create_table_example() {
        // From "Authorize with Shared Key": the Table Shared Key Lite example.
        assert_eq!(
            shared_key_lite_string_to_sign(
                "Sun, 11 Oct 2009 19:52:39 GMT",
                "testaccount1",
                "/Tables",
                None
            ),
            "Sun, 11 Oct 2009 19:52:39 GMT\n/testaccount1/Tables"
        );
    }

    #[test]
    fn account_sas_string_to_sign_adds_the_encryption_scope_from_2020_12_06() {
        let mut q = query(&[
            ("sv", "2019-02-02"),
            ("ss", "t"),
            ("srt", "sco"),
            ("sp", "rwdlacu"),
            ("st", "2024-01-01T00:00:00Z"),
            ("se", "2030-01-01T00:00:00Z"),
            ("spr", "https,http"),
        ]);
        assert_eq!(
            account_sas_string_to_sign("acct", &q),
            "acct\nrwdlacu\nt\nsco\n2024-01-01T00:00:00Z\n2030-01-01T00:00:00Z\n\nhttps,http\n2019-02-02\n"
        );
        q.insert("sv".into(), "2023-11-03".into());
        assert!(account_sas_string_to_sign("acct", &q).ends_with("2023-11-03\n\n"));
    }

    #[test]
    fn service_sas_string_to_sign_matches_the_documented_table_format() {
        let q = query(&[
            ("sv", "2019-02-02"),
            ("tn", "Employees"),
            ("sp", "raud"),
            ("se", "2030-01-01T00:00:00Z"),
            ("spk", "a"),
            ("srk", "b"),
        ]);
        assert_eq!(
            service_sas_string_to_sign("myaccount", "employees", &q),
            "raud\n\n2030-01-01T00:00:00Z\n/table/myaccount/employees\n\n\n\n2019-02-02\na\nb\n\n"
        );
        let old = query(&[("sv", "2014-02-14"), ("sp", "r"), ("se", "x")]);
        assert_eq!(
            service_sas_string_to_sign("a", "t", &old),
            "r\n\nx\n/a/t\n\n2014-02-14\n\n\n\n"
        );
    }

    fn request<'a>(
        account: &'a AccountName,
        keys: &'a [Vec<u8>],
        query: &'a Query,
        headers: &'a HeaderMap,
        table: Option<&'a TableName>,
    ) -> Presented<'a> {
        Presented {
            account,
            keys,
            method: &Method::GET,
            raw_path: "/acct/Tables",
            query,
            headers,
            table,
            now: crate::sas::parse_time("2025-06-01").unwrap(),
            https: false,
        }
    }

    #[tokio::test]
    async fn account_sas_verifies_signature_window_and_permissions() {
        let store = Store::open(None).unwrap();
        let account = AccountName::parse("acct").unwrap();
        let keys = vec![KEY.to_vec()];
        let mut q = query(&[
            ("sv", "2023-11-03"),
            ("ss", "t"),
            ("srt", "co"),
            ("sp", "rac"),
            ("se", "2030-01-01T00:00:00Z"),
        ]);
        q.insert("sig".into(), sign(&account_sas_string_to_sign("acct", &q)));
        let headers = HeaderMap::new();
        let credential = authenticate(&store, &request(&account, &keys, &q, &headers, None))
            .await
            .unwrap();
        assert!(credential.authorize(Access::EntityRead, None, None).is_ok());
        assert!(
            credential
                .authorize(Access::CreateTable, None, None)
                .is_ok()
        );
        assert!(
            credential
                .authorize(Access::EntityUpsert, None, None)
                .is_err()
        );
        assert!(
            credential
                .authorize(Access::DeleteTable, None, None)
                .is_err()
        );
        assert!(
            credential
                .authorize(Access::ListTables, None, None)
                .is_err()
        );
        assert!(
            credential
                .authorize(Access::ServiceRead, None, None)
                .is_err()
        );
        assert!(credential.authorize(Access::TableAcl, None, None).is_err());

        let mut tampered = q.clone();
        tampered.insert("sp".into(), "rwdlacu".into());
        assert!(
            authenticate(&store, &request(&account, &keys, &tampered, &headers, None))
                .await
                .is_err()
        );
        let mut expired = q.clone();
        expired.insert("se".into(), "2025-01-01T00:00:00Z".into());
        expired.insert(
            "sig".into(),
            sign(&account_sas_string_to_sign("acct", &expired)),
        );
        assert!(
            authenticate(&store, &request(&account, &keys, &expired, &headers, None))
                .await
                .is_err()
        );
        let rotated = vec![vec![9; 32], KEY.to_vec()];
        assert!(
            authenticate(&store, &request(&account, &rotated, &q, &headers, None))
                .await
                .is_ok()
        );
    }

    #[tokio::test]
    async fn service_sas_is_scoped_to_one_table_and_key_range() {
        let store = Store::open(None).unwrap();
        let account = AccountName::parse("acct").unwrap();
        let keys = vec![KEY.to_vec()];
        let table = TableName::parse("Employees").unwrap();
        let mut q = query(&[
            ("sv", "2023-11-03"),
            ("tn", "Employees"),
            ("sp", "ru"),
            ("se", "2030-01-01T00:00:00Z"),
            ("spk", "b"),
            ("epk", "d"),
        ]);
        q.insert(
            "sig".into(),
            sign(&service_sas_string_to_sign("acct", "employees", &q)),
        );
        let headers = HeaderMap::new();
        let credential = authenticate(
            &store,
            &request(&account, &keys, &q, &headers, Some(&table)),
        )
        .await
        .unwrap();
        let key = |p: &str| EntityKey {
            partition: super::super::model::KeyValue::parse(p).unwrap(),
            row: super::super::model::KeyValue::parse("r").unwrap(),
        };
        assert!(
            credential
                .authorize(Access::EntityRead, Some(&table), Some(&key("c")))
                .is_ok()
        );
        assert!(
            credential
                .authorize(Access::EntityRead, Some(&table), Some(&key("a")))
                .is_err()
        );
        assert!(
            credential
                .authorize(Access::EntityRead, Some(&table), Some(&key("e")))
                .is_err()
        );
        assert!(
            credential
                .authorize(Access::EntityAdd, Some(&table), Some(&key("c")))
                .is_err()
        );
        assert!(
            credential
                .authorize(Access::ListTables, None, None)
                .is_err()
        );
        let other = TableName::parse("Other").unwrap();
        assert!(
            credential
                .authorize(Access::EntityRead, Some(&other), Some(&key("c")))
                .is_err()
        );
        assert!(
            authenticate(
                &store,
                &request(&account, &keys, &q, &headers, Some(&other))
            )
            .await
            .is_err()
        );
        assert!(
            authenticate(&store, &request(&account, &keys, &q, &headers, None))
                .await
                .is_err()
        );
    }

    #[tokio::test]
    async fn shared_key_requires_a_matching_signature_and_fresh_date() {
        let store = Store::open(None).unwrap();
        let account = AccountName::parse("acct").unwrap();
        let keys = vec![KEY.to_vec()];
        let date = "Sun, 01 Jun 2025 00:00:05 GMT";
        let good = sign(&shared_key_string_to_sign(
            "GET",
            "",
            "",
            date,
            "acct",
            "/acct/Tables",
            None,
        ));
        let q = Query::new();
        let mut headers = HeaderMap::new();
        headers.insert("x-ms-date", date.parse().unwrap());
        headers.insert(
            "authorization",
            format!("SharedKey acct:{good}").parse().unwrap(),
        );
        let req = request(&account, &keys, &q, &headers, None);
        assert!(matches!(
            authenticate(&store, &req).await,
            Ok(Credential::SharedKey)
        ));

        let lite = sign(&shared_key_lite_string_to_sign(
            date,
            "acct",
            "/acct/Tables",
            None,
        ));
        headers.insert(
            "authorization",
            format!("SharedKeyLite acct:{lite}").parse().unwrap(),
        );
        assert!(matches!(
            authenticate(&store, &request(&account, &keys, &q, &headers, None)).await,
            Ok(Credential::SharedKey)
        ));
        headers.insert(
            "authorization",
            format!("SharedKey acct:{lite}").parse().unwrap(),
        );
        assert!(
            authenticate(&store, &request(&account, &keys, &q, &headers, None))
                .await
                .is_err()
        );
        headers.insert(
            "authorization",
            format!("SharedKey acct:{good}").parse().unwrap(),
        );
        headers.insert(
            "x-ms-date",
            "Sun, 01 Jun 2025 01:00:00 GMT".parse().unwrap(),
        );
        assert!(
            authenticate(&store, &request(&account, &keys, &q, &headers, None))
                .await
                .is_err()
        );
        headers.remove("authorization");
        assert!(
            authenticate(&store, &request(&account, &keys, &q, &headers, None))
                .await
                .is_err()
        );
    }
}
