//! Blob request authentication: Shared Key, Shared Key Lite, SAS, and
//! anonymous access (ADR-0011, ADR-0019).
//!
//! Credentials are verified before the operation is parsed, so a bad signature
//! never reveals whether an operation is supported. Authorization (SAS
//! permissions, stored access policies, public access) runs after parsing,
//! because it depends on the operation and on stored container state.

use crate::{
    auth::{self, Query, header},
    blob_sas::{Connection, Need, Overrides, Public, Resource, Token},
    config::Service,
    delegation::Keys,
    domain::{AccountName, BlobKey, ContainerKey, Error, PublicAccess, Result},
    oauth::{self, OAuth, Principal},
    store::Store,
};
use axum::http::{HeaderMap, Method};
use std::time::SystemTime;

/// The resource a request addresses.
#[derive(Clone)]
pub(crate) enum Target {
    Account(AccountName),
    Container(ContainerKey),
    Blob(BlobKey),
}

impl Target {
    pub(crate) fn account(&self) -> &AccountName {
        match self {
            Self::Account(account) => account,
            Self::Container(key) => &key.account,
            Self::Blob(key) => &key.container.account,
        }
    }

    pub(crate) fn container(&self) -> Option<&ContainerKey> {
        match self {
            Self::Account(_) => None,
            Self::Container(key) => Some(key),
            Self::Blob(key) => Some(&key.container),
        }
    }

    fn resource(&self) -> Resource<'_> {
        Resource {
            account: self.account(),
            container: self.container().map(|key| key.name.as_str()),
            blob: match self {
                Self::Blob(key) => Some(key.path.as_str()),
                _ => None,
            },
        }
    }
}

pub(crate) enum Credentials {
    /// A verified Shared Key or Shared Key Lite signature.
    Key,
    Sas(Box<Token>),
    /// A validated OAuth bearer token.
    Bearer(Principal),
    Anonymous,
}

impl Credentials {
    pub(crate) fn overrides(&self) -> Option<&Overrides> {
        match self {
            Self::Sas(token) => Some(&token.overrides),
            _ => None,
        }
    }

    /// How HNS POSIX access checks treat the caller: Shared Key and key-backed SAS
    /// bypass ACLs (a user-delegation SAS carries the delegating user), and so do
    /// bearer tokens with a data role; a bearer token without one is checked against
    /// the ACLs by its object id.
    pub(crate) fn dfs_caller(&self) -> crate::store::Caller {
        match self {
            Self::Key => crate::store::Caller::Superuser,
            Self::Sas(token) => token
                .delegated_oid()
                .map_or(crate::store::Caller::Superuser, |oid| {
                    crate::store::Caller::Principal(Some(oid.to_owned()))
                }),
            Self::Bearer(principal) if principal.has_roles() => crate::store::Caller::Superuser,
            Self::Bearer(principal) => crate::store::Caller::Principal(principal.oid.clone()),
            Self::Anonymous => crate::store::Caller::Principal(None),
        }
    }
}

pub(crate) struct Presented<'a> {
    pub(crate) keys: &'a [Vec<u8>],
    pub(crate) oauth: &'a OAuth,
    pub(crate) delegation: &'a Keys,
    pub(crate) method: &'a Method,
    /// The path as the client sent it, which Shared Key signs.
    pub(crate) signing_path: &'a str,
    pub(crate) query: &'a Query,
    pub(crate) headers: &'a HeaderMap,
    pub(crate) target: &'a Target,
    pub(crate) now: SystemTime,
}

/// Verifies whichever credential the request carries.
pub(crate) fn credentials(request: &Presented<'_>) -> Result<Credentials> {
    let account = request.target.account();
    let authorization = header(request.headers, "authorization")?;
    let signed = request.query.contains_key("sig");
    match (authorization, signed) {
        (Some(_), true) => Err(Error::AuthenticationFailed),
        (Some(value), false) => match value.split_once(' ').map(|(scheme, _)| scheme) {
            Some("SharedKey") => {
                auth::verify(
                    account,
                    request.keys,
                    request.method,
                    request.signing_path,
                    request.query,
                    request.headers,
                    request.now,
                )?;
                Ok(Credentials::Key)
            }
            Some("SharedKeyLite") => {
                verify_lite(request, value)?;
                Ok(Credentials::Key)
            }
            Some(scheme) if scheme.eq_ignore_ascii_case("bearer") => verify_bearer(request, value),
            Some(_) => Err(Error::Unsupported),
            None => Err(Error::AuthenticationFailed),
        },
        (None, true) => {
            let token = Token::verify(
                request.query,
                &request.target.resource(),
                request.keys,
                request.delegation,
            )?
            .ok_or(Error::AuthenticationFailed)?;
            Ok(Credentials::Sas(Box::new(token)))
        }
        (None, false) => Ok(Credentials::Anonymous),
    }
}

/// Validates an OAuth bearer token. Reader roles may not change data; Get User
/// Delegation Key is a read-class operation for them, as it is in Azure.
fn verify_bearer(request: &Presented<'_>, authorization: &str) -> Result<Credentials> {
    let token = oauth::bearer(authorization).ok_or(Error::InvalidAuthenticationInfo)?;
    let delegation_key = request.query.get("comp").map(String::as_str) == Some("userdelegationkey");
    authenticate_bearer(
        request.oauth,
        token,
        &oauth::Request {
            account: request.target.account().as_str(),
            host: header(request.headers, "host")?,
            now: request.now,
        },
        oauth::is_write(request.method) && !delegation_key,
    )
}

pub(crate) fn authenticate_bearer(
    oauth: &OAuth,
    token: &str,
    request: &oauth::Request<'_>,
    write: bool,
) -> Result<Credentials> {
    let principal = oauth
        .authenticate(token, request)
        .map_err(|_| Error::InvalidAuthenticationInfo)?;
    if !principal.permits(Service::Blob, write) {
        return Err(Error::PermissionMismatch);
    }
    Ok(Credentials::Bearer(principal))
}

/// Shared Key Lite signs the verb, `Content-MD5`, `Content-Type`, the date, the
/// `x-ms-*` headers, and the resource with only its `comp` parameter.
fn verify_lite(request: &Presented<'_>, authorization: &str) -> Result<()> {
    let account = request.target.account();
    let (_, credentials) = authorization
        .split_once(' ')
        .ok_or(Error::AuthenticationFailed)?;
    let (name, signature) = credentials
        .split_once(':')
        .ok_or(Error::AuthenticationFailed)?;
    if name != account.as_str() {
        return Err(Error::AuthenticationFailed);
    }
    let date = header(request.headers, "x-ms-date")?
        .or(header(request.headers, "date")?)
        .ok_or(Error::AuthenticationFailed)?;
    auth::check_skew(date, request.now)?;
    let own_date = if request.headers.contains_key("x-ms-date") {
        ""
    } else {
        date
    };
    let mut text = format!(
        "{}\n{}\n{}\n{own_date}\n{}/{}{}",
        request.method.as_str(),
        header(request.headers, "content-md5")?.unwrap_or_default(),
        header(request.headers, "content-type")?.unwrap_or_default(),
        auth::canonical_headers(request.headers)?,
        account.as_str(),
        request.signing_path,
    );
    if let Some(comp) = request.query.get("comp") {
        text.push_str("?comp=");
        text.push_str(comp);
    }
    auth::verify_signature(request.keys, &text, signature)
}

pub(crate) struct Authorization<'a> {
    pub(crate) credentials: &'a Credentials,
    pub(crate) target: &'a Target,
    pub(crate) need: &'a Need,
    pub(crate) connection: &'a Connection,
}

/// Decides whether the verified credentials may perform the operation.
pub(crate) async fn authorize(store: &Store, request: Authorization<'_>) -> Result<()> {
    match request.credentials {
        Credentials::Key | Credentials::Bearer(_) => Ok(()),
        Credentials::Sas(token) => {
            let policy = match (token.identifier(), request.target.container()) {
                (Some(id), Some(container)) => {
                    let (_, identifiers) = store
                        .container_access(container.clone())
                        .await
                        .map_err(|error| match error {
                            Error::ContainerMissing => Error::AuthenticationFailed,
                            other => other,
                        })?;
                    identifiers.into_iter().find(|policy| policy.id == id)
                }
                _ => None,
            };
            token.authorize(request.need, policy.as_ref(), request.connection)
        }
        Credentials::Anonymous => anonymous(store, request.target, request.need).await,
    }
}

async fn anonymous(store: &Store, target: &Target, need: &Need) -> Result<()> {
    let denied = match need.public {
        Public::Never => return Err(Error::AuthenticationFailed),
        Public::Blob => Error::ResourceNotFound,
        Public::Container => Error::AuthenticationFailed,
    };
    let Some(container) = target.container() else {
        return Err(denied);
    };
    let (access, _) =
        store
            .container_access(container.clone())
            .await
            .map_err(|error| match error {
                Error::ContainerMissing => denied,
                other => other,
            })?;
    let allowed = matches!(
        (need.public, access),
        (Public::Blob, PublicAccess::Blob | PublicAccess::Container)
            | (Public::Container, PublicAccess::Container)
    );
    if allowed { Ok(()) } else { Err(denied) }
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::http::HeaderValue;
    use base64::{Engine as _, engine::general_purpose::STANDARD};
    use hmac::{Hmac, Mac as _};
    use sha2::Sha256;

    const KEY: [u8; 32] = [3; 32];

    fn lite(date: &str, path: &str, signed: &str) -> Result<Credentials> {
        let mut mac = Hmac::<Sha256>::new_from_slice(&KEY).unwrap();
        mac.update(signed.as_bytes());
        let signature = STANDARD.encode(mac.finalize().into_bytes());
        let mut headers = HeaderMap::new();
        for (name, value) in [
            (
                "authorization",
                format!("SharedKeyLite testaccount:{signature}"),
            ),
            ("x-ms-date", date.to_owned()),
            ("x-ms-version", "2023-11-03".to_owned()),
        ] {
            headers.insert(name, HeaderValue::from_str(&value).unwrap());
        }
        let target = Target::Account(AccountName::parse("testaccount").unwrap());
        let query = Query::from([
            ("comp".into(), "list".into()),
            ("prefix".into(), "unsigned".into()),
        ]);
        credentials(&Presented {
            keys: &[KEY.to_vec()],
            oauth: &OAuth::default(),
            delegation: &Keys::default(),
            method: &Method::GET,
            signing_path: path,
            query: &query,
            headers: &headers,
            target: &target,
            now: SystemTime::now(),
        })
    }

    #[test]
    fn shared_key_lite_signs_only_the_comp_parameter() {
        let date = httpdate::fmt_http_date(SystemTime::now());
        let signed = format!(
            "GET\n\n\n\nx-ms-date:{date}\nx-ms-version:2023-11-03\n/testaccount/testaccount/?comp=list"
        );
        assert!(matches!(
            lite(&date, "/testaccount/", &signed),
            Ok(Credentials::Key)
        ));
        let other = signed.replace("?comp=list", "?comp=list&prefix=unsigned");
        assert!(lite(&date, "/testaccount/", &other).is_err());
        assert!(lite(&date, "/testaccount/other", &signed).is_err());
        let stale = "Fri, 26 Jun 2015 23:39:12 GMT";
        let stale_signed = signed.replace(&date, stale);
        assert!(lite(stale, "/testaccount/", &stale_signed).is_err());
    }
}
