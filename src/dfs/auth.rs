//! DFS request authentication: the shared Blob credential checks (Shared Key, Shared Key
//! Lite, account, service and user-delegation SAS, bearer tokens) with DFS addressing
//! and the shared clock (ADR-0011, ADR-0012).

use crate::{
    address,
    auth::{Query, header},
    blob_auth::{self, Credentials, Presented, Target},
    blob_sas,
    config::Config,
    domain::{ApiVersion, BlobKey, BlobPath, Error, Result},
    protocol,
    store::Caller,
};
use axum::http::request::Parts;
use std::time::SystemTime;

pub(super) struct Authenticated {
    pub(super) requested_version: ApiVersion,
    pub(super) target: Target,
    /// The request's query parameters, without SAS fields.
    pub(super) query: Query,
    pub(super) credentials: Credentials,
}

pub(super) fn authenticate(
    parts: &Parts,
    config: &Config,
    now: SystemTime,
) -> Result<Authenticated> {
    let headers = &parts.headers;
    if headers.len() > 100
        || headers
            .iter()
            .map(|(name, value)| name.as_str().len() + value.len())
            .sum::<usize>()
            > 32768
    {
        return Err(Error::InvalidHeader);
    }
    let requested_version = match header(headers, "x-ms-version")? {
        Some(version) => ApiVersion::parse(version)?,
        // SAS and anonymous requests may omit the version; signed requests may not.
        None if !headers.contains_key("authorization") => {
            ApiVersion::parse(config.api_version.as_str())?
        }
        None => return Err(Error::InvalidVersion),
    };
    if !requested_version.is_served(&config.api_version, config.skip_api_version_check) {
        return Err(Error::InvalidVersion);
    }
    let mut query = protocol::parse_query(parts.uri.query())?;
    // DFS accepts `{account}.dfs.{domain}`; the signature covers the path as sent.
    let (logical, _) = address::resolve("dfs", parts);
    let target = protocol::parse_target(&logical)?;
    let keys = config
        .accounts
        .get(target.account())
        .ok_or(Error::AuthenticationFailed)?;
    let signed_target = sas_target(&target, &query);
    let credentials = blob_auth::credentials(&Presented {
        keys,
        oauth: &config.oauth,
        delegation: &config.delegation,
        method: &parts.method,
        signing_path: parts.uri.path(),
        query: &query,
        headers,
        target: signed_target.as_ref().unwrap_or(&target),
        now,
    })?;
    if matches!(credentials, Credentials::Sas(_)) {
        query.retain(|name, _| !blob_sas::is_sas_param(name));
    }
    protocol::check_hns_path(&target, config)?;
    Ok(Authenticated {
        requested_version,
        target,
        query,
        credentials,
    })
}

/// A directory SAS authorizes listing the directory it names, so a listing is signed
/// against its `directory` parameter as if that path had been addressed.
fn sas_target(target: &Target, query: &Query) -> Option<Target> {
    let Target::Container(key) = target else {
        return None;
    };
    let directory = query
        .get("directory")
        .filter(|value| !matches!(value.as_str(), "" | "/"))?;
    let path = BlobPath::parse(directory.trim_matches('/').to_owned()).ok()?;
    Some(Target::Blob(BlobKey {
        container: key.clone(),
        path,
    }))
}

/// How the POSIX access check treats the caller: Shared Key and SAS bypass the ACLs
/// (a user-delegation SAS carries the delegating user), and so do bearer tokens with a
/// data role; a bearer token without one is checked against the ACLs by its object id.
pub(super) fn caller(credentials: &Credentials) -> Caller {
    match credentials {
        Credentials::Key => Caller::Superuser,
        Credentials::Sas(token) => token.delegated_oid().map_or(Caller::Superuser, |oid| {
            Caller::Principal(Some(oid.to_owned()))
        }),
        Credentials::Bearer(principal) if principal.has_roles() => Caller::Superuser,
        Credentials::Bearer(principal) => Caller::Principal(principal.oid.clone()),
        Credentials::Anonymous => Caller::Principal(None),
    }
}
