//! FileREST authentication: Shared Key, Shared Key Lite, account SAS, and service SAS.
//!
//! The signature primitives, window checks, and constant-time comparison live in
//! [`crate::auth`] and [`crate::sas`]; this module owns only what differs for the File
//! service (string-to-sign layouts, resource canonicalisation, and permission scopes).

use super::{
    error::{Error, Result},
    model::AccessPolicy,
    request::Query,
};
use crate::{
    auth::{self, canonical, fold_whitespace},
    config::Service,
    domain::AccountName,
    oauth::{self, OAuth},
    sas::Sas,
};
use axum::http::{HeaderMap, Method};
use std::{collections::BTreeMap, time::SystemTime};

/// How a request is credentialed, before any signature is checked.
pub(super) enum Credentials {
    SharedKey {
        account: String,
        signature: String,
    },
    SharedKeyLite {
        account: String,
        signature: String,
    },
    Sas,
    /// An OAuth bearer token, validated by [`verify_bearer`].
    Bearer(String),
}

/// Where in the namespace an operation acts, for SAS scope checks.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum Level {
    Account,
    Share,
    Directory,
    File,
}

/// What an operation demands of a SAS. Permission strings list alternatives: holding any
/// one letter suffices. An empty service-SAS list means a service SAS cannot do this.
#[derive(Clone, Copy, Debug)]
pub(super) struct Needs {
    pub(super) level: Level,
    /// Account SAS resource types (`s` service, `c` container/share, `o` object).
    pub(super) resource_types: &'static str,
    pub(super) account_permissions: &'static str,
    pub(super) service_permissions: &'static str,
}

/// Response header overrides a service SAS may request (`rscc`, `rscd`, `rsce`, `rscl`, `rsct`).
#[derive(Clone, Debug, Default)]
pub(super) struct Overrides(pub(super) Vec<(&'static str, String)>);

pub(super) fn credentials(headers: &HeaderMap, query: &Query) -> Result<Credentials> {
    if query.get("sig").is_some() {
        return Ok(Credentials::Sas);
    }
    let authorization = auth::header(headers, "authorization")
        .map_err(|_| Error::AuthenticationFailed)?
        .ok_or(Error::NoAuthenticationInformation)?;
    let (scheme, rest) = authorization
        .split_once(' ')
        .ok_or(Error::AuthenticationFailed)?;
    if scheme.eq_ignore_ascii_case("bearer") {
        return oauth::bearer(authorization)
            .map(|token| Credentials::Bearer(token.to_owned()))
            .ok_or(Error::InvalidAuthenticationInfo);
    }
    let (account, signature) = rest.split_once(':').ok_or(Error::AuthenticationFailed)?;
    let (account, signature) = (account.to_owned(), signature.to_owned());
    match scheme {
        "SharedKey" => Ok(Credentials::SharedKey { account, signature }),
        "SharedKeyLite" => Ok(Credentials::SharedKeyLite { account, signature }),
        _ => Err(Error::AuthenticationFailed),
    }
}

/// Everything signature verification needs to know about the request.
pub(super) struct Signed<'a> {
    pub(super) account: &'a AccountName,
    pub(super) keys: &'a [Vec<u8>],
    pub(super) method: &'a Method,
    pub(super) raw_path: &'a str,
    pub(super) query: &'a Query,
    pub(super) headers: &'a HeaderMap,
    pub(super) now: SystemTime,
    /// The share named in the path and the decoded entry path, for SAS resource strings.
    pub(super) share: Option<&'a str>,
    pub(super) path: &'a str,
}

/// Verifies a Shared Key or Shared Key Lite header.
pub(super) fn verify_header(credentials: &Credentials, request: &Signed<'_>) -> Result<()> {
    let (name, signature, lite) = match credentials {
        Credentials::SharedKey { account, signature } => (account, signature, false),
        Credentials::SharedKeyLite { account, signature } => (account, signature, true),
        Credentials::Sas | Credentials::Bearer(_) => return Err(Error::AuthenticationFailed),
    };
    if name != request.account.as_str() {
        return Err(Error::AuthenticationFailed);
    }
    let date = auth::header(request.headers, "x-ms-date")
        .and_then(|date| match date {
            Some(date) => Ok(Some(date)),
            None => auth::header(request.headers, "date"),
        })
        .map_err(|_| Error::AuthenticationFailed)?
        .ok_or(Error::AuthenticationFailed)?;
    auth::check_skew(date, request.now).map_err(|_| Error::AuthenticationFailed)?;
    let message = if lite {
        lite_string(request)?
    } else {
        canonical(
            request.account,
            request.method,
            request.raw_path,
            &request.query.joined(),
            request.headers,
        )
        .map_err(|_| Error::AuthenticationFailed)?
    };
    auth::verify_signature(request.keys, &message, signature)
        .map_err(|_| Error::AuthenticationFailed)
}

/// Validates an OAuth bearer token; Reader roles may only read.
pub(super) fn verify_bearer(oauth: &OAuth, token: &str, request: &Signed<'_>) -> Result<()> {
    let host = auth::header(request.headers, "host").map_err(|_| Error::InvalidHeaderValue)?;
    let principal = oauth
        .authenticate(
            token,
            &oauth::Request {
                account: request.account.as_str(),
                host,
                now: request.now,
            },
        )
        .map_err(|_| Error::InvalidAuthenticationInfo)?;
    if principal.permits(Service::File, oauth::is_write(request.method)) {
        Ok(())
    } else {
        Err(Error::AuthorizationPermissionMismatch)
    }
}

/// Shared Key Lite: verb, MD5, type, date, `x-ms-` headers, and the path plus `comp` only.
fn lite_string(request: &Signed<'_>) -> Result<String> {
    let header = |name: &str| -> Result<&str> {
        auth::header(request.headers, name)
            .map(Option::unwrap_or_default)
            .map_err(|_| Error::AuthenticationFailed)
    };
    let date = if request.headers.contains_key("x-ms-date") {
        ""
    } else {
        header("date")?
    };
    let mut text = format!(
        "{}\n{}\n{}\n{}\n",
        request.method.as_str(),
        header("content-md5")?,
        header("content-type")?,
        date
    );
    let mut extensions = BTreeMap::new();
    for (name, value) in request.headers {
        if name.as_str().starts_with("x-ms-") {
            let value = value.to_str().map_err(|_| Error::AuthenticationFailed)?;
            if extensions.insert(name.as_str(), value).is_some() {
                return Err(Error::AuthenticationFailed);
            }
        }
    }
    for (name, value) in extensions {
        text.push_str(&format!("{name}:{}\n", fold_whitespace(value)));
    }
    text.push('/');
    text.push_str(request.account.as_str());
    text.push_str(request.raw_path);
    if let Some(comp) = request.query.get("comp") {
        text.push_str("?comp=");
        text.push_str(comp);
    }
    Ok(text)
}

/// A verified SAS and what it may touch.
pub(super) struct SasGrant {
    kind: Kind,
    permissions: String,
    pub(super) overrides: Overrides,
}

enum Kind {
    Account { services: String, types: String },
    Service { resource: String },
}

/// Verifies a SAS query and returns its grant. `policy` is the share's stored access
/// policy named by `si`, if the caller found one.
pub(super) fn verify_sas(request: &Signed<'_>, policy: Option<&AccessPolicy>) -> Result<SasGrant> {
    let original = request.query.joined();
    let mut effective = original.clone();
    if original.contains_key("si") {
        let policy = policy.ok_or(Error::AuthenticationFailed)?;
        for (name, value) in [
            ("st", &policy.start),
            ("se", &policy.expiry),
            ("sp", &policy.permission),
        ] {
            if !effective.contains_key(name)
                && let Some(value) = value
            {
                effective.insert(name.to_owned(), value.clone());
            }
        }
    }
    let sas = Sas::from_query(&effective)
        .map_err(|_| Error::AuthenticationFailed)?
        .ok_or(Error::AuthenticationFailed)?;
    let field = |name: &str| original.get(name).map_or("", String::as_str);
    let version = field("sv");
    if version.is_empty() {
        return Err(Error::AuthenticationFailed);
    }
    let (to_sign, kind) = if original.contains_key("ss") && original.contains_key("srt") {
        let mut text = format!(
            "{}\n{}\n{}\n{}\n{}\n{}\n{}\n{}\n{}\n",
            request.account.as_str(),
            field("sp"),
            field("ss"),
            field("srt"),
            field("st"),
            field("se"),
            field("sip"),
            field("spr"),
            version
        );
        if version >= "2020-12-06" {
            text.push_str(field("ses"));
            text.push('\n');
        }
        (
            text,
            Kind::Account {
                services: field("ss").to_owned(),
                types: field("srt").to_owned(),
            },
        )
    } else {
        let resource = field("sr");
        let share = request.share.ok_or(Error::AuthenticationFailed)?;
        let canonical_resource = match resource {
            "s" => format!("/file/{}/{share}", request.account.as_str()),
            "f" => format!(
                "/file/{}/{share}/{}",
                request.account.as_str(),
                request.path
            ),
            _ => return Err(Error::AuthenticationFailed),
        };
        let mut text = format!(
            "{}\n{}\n{}\n{}\n{}\n",
            field("sp"),
            field("st"),
            field("se"),
            canonical_resource,
            field("si")
        );
        if version >= "2015-04-05" {
            text.push_str(&format!("{}\n{}\n", field("sip"), field("spr")));
        }
        text.push_str(&format!(
            "{version}\n{}\n{}\n{}\n{}\n{}",
            field("rscc"),
            field("rscd"),
            field("rsce"),
            field("rscl"),
            field("rsct")
        ));
        (
            text,
            Kind::Service {
                resource: resource.to_owned(),
            },
        )
    };
    sas.verify(request.keys, &to_sign)
        .map_err(|_| Error::AuthenticationFailed)?;
    sas.check_window(request.now)
        .map_err(|_| Error::AuthenticationFailed)?;
    let overrides = [
        ("rscc", "cache-control"),
        ("rscd", "content-disposition"),
        ("rsce", "content-encoding"),
        ("rscl", "content-language"),
        ("rsct", "content-type"),
    ]
    .into_iter()
    .filter(|(name, _)| !field(name).is_empty())
    .map(|(name, header)| (header, field(name).to_owned()))
    .collect();
    Ok(SasGrant {
        kind,
        permissions: sas.field("sp").to_owned(),
        overrides: Overrides(overrides),
    })
}

impl SasGrant {
    /// Checks the SAS covers an operation, returning `AuthorizationPermissionMismatch` if not.
    pub(super) fn authorize(&self, needs: &Needs) -> Result<()> {
        let holds = |letters: &str| {
            letters
                .chars()
                .any(|letter| self.permissions.contains(letter))
        };
        let allowed = match &self.kind {
            Kind::Account { services, types } => {
                services.contains('f')
                    && needs
                        .resource_types
                        .chars()
                        .any(|kind| types.contains(kind))
                    && holds(needs.account_permissions)
            }
            Kind::Service { resource } => {
                let in_scope = match needs.level {
                    Level::Account | Level::Share => false,
                    Level::Directory => resource == "s",
                    Level::File => resource == "s" || resource == "f",
                };
                in_scope && holds(needs.service_permissions)
            }
        };
        if allowed {
            Ok(())
        } else {
            Err(Error::AuthorizationPermissionMismatch)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::http::HeaderValue;
    use base64::{Engine as _, engine::general_purpose::STANDARD};
    use hmac::{Hmac, Mac as _};
    use sha2::Sha256;

    const KEY: [u8; 32] = [7; 32];

    fn headers(pairs: &[(&str, &str)]) -> HeaderMap {
        let mut map = HeaderMap::new();
        for (name, value) in pairs {
            map.insert(
                axum::http::HeaderName::from_bytes(name.as_bytes()).unwrap(),
                HeaderValue::from_str(value).unwrap(),
            );
        }
        map
    }

    fn sign(message: &str) -> String {
        let mut mac = Hmac::<Sha256>::new_from_slice(&KEY).unwrap();
        mac.update(message.as_bytes());
        STANDARD.encode(mac.finalize().into_bytes())
    }

    fn request<'a>(
        account: &'a AccountName,
        keys: &'a [Vec<u8>],
        method: &'a Method,
        path: &'a str,
        query: &'a Query,
        headers: &'a HeaderMap,
    ) -> Signed<'a> {
        Signed {
            account,
            keys,
            method,
            raw_path: path,
            query,
            headers,
            now: crate::sas::parse_time("2015-06-26T23:40:00Z").unwrap(),
            share: Some("music"),
            path: "intro.mp3",
        }
    }

    #[test]
    fn shared_key_uses_the_documented_string_to_sign() {
        let account = AccountName::parse("myaccount").unwrap();
        let headers = headers(&[
            ("x-ms-date", "Fri, 26 Jun 2015 23:39:12 GMT"),
            ("x-ms-version", "2015-02-21"),
        ]);
        let query = Query::parse(Some("restype=container&comp=metadata&timeout=20")).unwrap();
        let expected = "GET\n\n\n\n\n\n\n\n\n\n\n\nx-ms-date:Fri, 26 Jun 2015 23:39:12 GMT\n\
            x-ms-version:2015-02-21\n/myaccount/mycontainer\ncomp:metadata\nrestype:container\ntimeout:20";
        let actual = canonical(
            &account,
            &Method::GET,
            "/mycontainer",
            &query.joined(),
            &headers,
        )
        .unwrap();
        assert_eq!(actual, expected);
        let keys = vec![KEY.to_vec()];
        let mut signed = headers.clone();
        signed.insert(
            "authorization",
            HeaderValue::from_str(&format!("SharedKey myaccount:{}", sign(expected))).unwrap(),
        );
        let credentials = credentials(&signed, &query).unwrap();
        let method = Method::GET;
        let request = request(&account, &keys, &method, "/mycontainer", &query, &signed);
        assert!(verify_header(&credentials, &request).is_ok());
        let tampered = Query::parse(Some("restype=container&comp=acl&timeout=20")).unwrap();
        let request = request_with_query(request, &tampered);
        assert_eq!(
            verify_header(&credentials, &request),
            Err(Error::AuthenticationFailed)
        );
    }

    fn request_with_query<'a>(request: Signed<'a>, query: &'a Query) -> Signed<'a> {
        Signed { query, ..request }
    }

    #[test]
    fn multi_valued_query_parameters_are_sorted_and_comma_joined() {
        let query = Query::parse(Some("comp=list&include=snapshots&include=metadata")).unwrap();
        let account = AccountName::parse("myaccount").unwrap();
        let text = canonical(
            &account,
            &Method::GET,
            "/",
            &query.joined(),
            &HeaderMap::new(),
        )
        .unwrap();
        assert!(text.ends_with("/myaccount/\ncomp:list\ninclude:metadata,snapshots"));
    }

    #[test]
    fn shared_key_lite_signs_only_comp_from_the_query() {
        let account = AccountName::parse("testaccount1").unwrap();
        let headers = headers(&[
            ("content-type", "text/plain; charset=UTF-8"),
            ("x-ms-date", "Sun, 20 Sep 2009 20:36:40 GMT"),
            ("x-ms-meta-m1", "v1"),
            ("x-ms-meta-m2", "v2"),
        ]);
        let query = Query::parse(Some("comp=metadata&timeout=30")).unwrap();
        let keys = vec![KEY.to_vec()];
        let method = Method::PUT;
        let request = Signed {
            now: crate::sas::parse_time("2009-09-20T20:40:00Z").unwrap(),
            ..request(
                &account,
                &keys,
                &method,
                "/mycontainer/hello.txt",
                &query,
                &headers,
            )
        };
        let expected = "PUT\n\ntext/plain; charset=UTF-8\n\nx-ms-date:Sun, 20 Sep 2009 20:36:40 GMT\n\
            x-ms-meta-m1:v1\nx-ms-meta-m2:v2\n/testaccount1/mycontainer/hello.txt?comp=metadata";
        assert_eq!(lite_string(&request).unwrap(), expected);
        let mut signed = headers.clone();
        signed.insert(
            "authorization",
            HeaderValue::from_str(&format!("SharedKeyLite testaccount1:{}", sign(expected)))
                .unwrap(),
        );
        let credentials = credentials(&signed, &query).unwrap();
        let request = Signed {
            headers: &signed,
            ..request
        };
        assert!(verify_header(&credentials, &request).is_ok());
    }

    #[test]
    fn clock_skew_beyond_fifteen_minutes_is_rejected() {
        let account = AccountName::parse("myaccount").unwrap();
        let headers = headers(&[("x-ms-date", "Fri, 26 Jun 2015 23:00:00 GMT")]);
        let query = Query::parse(None).unwrap();
        let keys = vec![KEY.to_vec()];
        let method = Method::GET;
        let request = request(&account, &keys, &method, "/", &query, &headers);
        let credentials = Credentials::SharedKey {
            account: "myaccount".into(),
            signature: String::new(),
        };
        assert_eq!(
            verify_header(&credentials, &request),
            Err(Error::AuthenticationFailed)
        );
    }

    #[test]
    fn missing_and_unknown_authorization_are_distinguished() {
        let query = Query::parse(None).unwrap();
        assert_eq!(
            credentials(&HeaderMap::new(), &query).err(),
            Some(Error::NoAuthenticationInformation)
        );
        let bearer = headers(&[("authorization", "Bearer token")]);
        assert!(matches!(
            credentials(&bearer, &query),
            Ok(Credentials::Bearer(token)) if token == "token"
        ));
        let empty = headers(&[("authorization", "Bearer ")]);
        assert_eq!(
            credentials(&empty, &query).err(),
            Some(Error::InvalidAuthenticationInfo)
        );
        let unknown = headers(&[("authorization", "Digest x")]);
        assert_eq!(
            credentials(&unknown, &query).err(),
            Some(Error::AuthenticationFailed)
        );
    }

    fn service_sas_query(signature: &str) -> String {
        format!(
            "sv=2023-11-03&sr=f&sp=r&se=2030-01-01T00:00:00Z&sig={}",
            percent_encoding::utf8_percent_encode(signature, percent_encoding::NON_ALPHANUMERIC)
        )
    }

    #[test]
    fn service_sas_for_a_file_signs_the_documented_string() {
        let account = AccountName::parse("myaccount").unwrap();
        let expected = "r\n\n2030-01-01T00:00:00Z\n/file/myaccount/music/intro.mp3\n\n\n\n2023-11-03\n\n\n\n\n";
        let query = Query::parse(Some(&service_sas_query(&sign(expected)))).unwrap();
        let keys = vec![KEY.to_vec()];
        let headers = HeaderMap::new();
        let method = Method::GET;
        let request = request(
            &account,
            &keys,
            &method,
            "/music/intro.mp3",
            &query,
            &headers,
        );
        let grant = verify_sas(&request, None).unwrap();
        let read_file = Needs {
            level: Level::File,
            resource_types: "o",
            account_permissions: "r",
            service_permissions: "r",
        };
        assert!(grant.authorize(&read_file).is_ok());
        let write_file = Needs {
            account_permissions: "w",
            service_permissions: "w",
            ..read_file
        };
        assert_eq!(
            grant.authorize(&write_file),
            Err(Error::AuthorizationPermissionMismatch)
        );
        let directory = Needs {
            level: Level::Directory,
            ..read_file
        };
        assert_eq!(
            grant.authorize(&directory),
            Err(Error::AuthorizationPermissionMismatch)
        );
    }

    #[test]
    fn sas_for_another_resource_or_after_expiry_fails() {
        let account = AccountName::parse("myaccount").unwrap();
        let expected = "r\n\n2030-01-01T00:00:00Z\n/file/myaccount/music/other.mp3\n\n\n\n2023-11-03\n\n\n\n\n";
        let query = Query::parse(Some(&service_sas_query(&sign(expected)))).unwrap();
        let keys = vec![KEY.to_vec()];
        let headers = HeaderMap::new();
        let method = Method::GET;
        let request = request(
            &account,
            &keys,
            &method,
            "/music/intro.mp3",
            &query,
            &headers,
        );
        assert_eq!(
            verify_sas(&request, None).err(),
            Some(Error::AuthenticationFailed)
        );

        let expected = "r\n\n2015-01-01T00:00:00Z\n/file/myaccount/music/intro.mp3\n\n\n\n2023-11-03\n\n\n\n\n";
        let query = Query::parse(Some(&format!(
            "sv=2023-11-03&sr=f&sp=r&se=2015-01-01T00:00:00Z&sig={}",
            percent_encoding::utf8_percent_encode(
                &sign(expected),
                percent_encoding::NON_ALPHANUMERIC
            )
        )))
        .unwrap();
        let request = request_with_query(request, &query);
        assert_eq!(
            verify_sas(&request, None).err(),
            Some(Error::AuthenticationFailed)
        );
    }

    #[test]
    fn account_sas_includes_the_encryption_scope_line_from_2020_12_06() {
        let account = AccountName::parse("myaccount").unwrap();
        let expected = "myaccount\nrwdlc\nf\nsco\n\n2030-01-01T00:00:00Z\n\n\n2023-11-03\n\n";
        let query = Query::parse(Some(&format!(
            "sv=2023-11-03&ss=f&srt=sco&sp=rwdlc&se=2030-01-01T00:00:00Z&sig={}",
            percent_encoding::utf8_percent_encode(
                &sign(expected),
                percent_encoding::NON_ALPHANUMERIC
            )
        )))
        .unwrap();
        let keys = vec![KEY.to_vec()];
        let headers = HeaderMap::new();
        let method = Method::GET;
        let request = request(&account, &keys, &method, "/", &query, &headers);
        let grant = verify_sas(&request, None).unwrap();
        let list_shares = Needs {
            level: Level::Account,
            resource_types: "s",
            account_permissions: "l",
            service_permissions: "",
        };
        assert!(grant.authorize(&list_shares).is_ok());
    }

    #[test]
    fn account_sas_needs_the_file_service_and_resource_type() {
        let grant = SasGrant {
            kind: Kind::Account {
                services: "b".into(),
                types: "o".into(),
            },
            permissions: "rwdlc".into(),
            overrides: Overrides::default(),
        };
        let needs = Needs {
            level: Level::File,
            resource_types: "o",
            account_permissions: "r",
            service_permissions: "r",
        };
        assert_eq!(
            grant.authorize(&needs),
            Err(Error::AuthorizationPermissionMismatch)
        );
        let files = SasGrant {
            kind: Kind::Account {
                services: "f".into(),
                types: "s".into(),
            },
            ..grant
        };
        assert_eq!(
            files.authorize(&needs),
            Err(Error::AuthorizationPermissionMismatch)
        );
    }

    #[test]
    fn stored_access_policy_supplies_missing_fields() {
        let account = AccountName::parse("myaccount").unwrap();
        let expected = "\n\n\n/file/myaccount/music\npolicy1\n\n\n2023-11-03\n\n\n\n\n";
        let query = Query::parse(Some(&format!(
            "sv=2023-11-03&sr=s&si=policy1&sig={}",
            percent_encoding::utf8_percent_encode(
                &sign(expected),
                percent_encoding::NON_ALPHANUMERIC
            )
        )))
        .unwrap();
        let keys = vec![KEY.to_vec()];
        let headers = HeaderMap::new();
        let method = Method::GET;
        let request = request(&account, &keys, &method, "/music", &query, &headers);
        assert_eq!(
            verify_sas(&request, None).err(),
            Some(Error::AuthenticationFailed)
        );
        let policy = AccessPolicy {
            id: "policy1".into(),
            start: None,
            expiry: Some("2030-01-01T00:00:00Z".into()),
            permission: Some("r".into()),
        };
        let grant = verify_sas(&request, Some(&policy)).unwrap();
        let list = Needs {
            level: Level::Directory,
            resource_types: "o",
            account_permissions: "l",
            service_permissions: "l",
        };
        assert_eq!(
            grant.authorize(&list),
            Err(Error::AuthorizationPermissionMismatch)
        );
    }

    #[test]
    fn response_overrides_are_collected() {
        let account = AccountName::parse("myaccount").unwrap();
        let expected = "r\n\n2030-01-01T00:00:00Z\n/file/myaccount/music/intro.mp3\n\n\n\n2023-11-03\n\ninline\n\n\ntext/plain";
        let query = Query::parse(Some(&format!(
            "sv=2023-11-03&sr=f&sp=r&se=2030-01-01T00:00:00Z&rscd=inline&rsct=text%2Fplain&sig={}",
            percent_encoding::utf8_percent_encode(
                &sign(expected),
                percent_encoding::NON_ALPHANUMERIC
            )
        )))
        .unwrap();
        let keys = vec![KEY.to_vec()];
        let headers = HeaderMap::new();
        let method = Method::GET;
        let request = request(
            &account,
            &keys,
            &method,
            "/music/intro.mp3",
            &query,
            &headers,
        );
        let grant = verify_sas(&request, None).unwrap();
        assert_eq!(
            grant.overrides.0,
            [
                ("content-disposition", "inline".to_owned()),
                ("content-type", "text/plain".to_owned())
            ]
        );
    }
}
