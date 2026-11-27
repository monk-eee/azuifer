//! Same-instance copy sources (ADR-0018). A source URL is accepted only when it
//! addresses this listener; fetching from other hosts is a documented gap.

use crate::{
    address,
    auth::Query,
    blob_auth::{self, Authorization, Credentials, Target},
    blob_sas::{Connection, Need, Public, Resource, Token},
    blob_snapshot::{self, Selector},
    config::Config,
    domain::{AccountName, BlobKey, BlobPath, ContainerKey, ContainerName, Error, Result},
    oauth,
    protocol::parse_query,
    store::Store,
};
use axum::http::Uri;
use percent_encoding::percent_decode_str;

const READ: Need = Need {
    service: Some("r"),
    account: Some(('o', "r")),
    public: Public::Blob,
};

/// A parsed `x-ms-copy-source`. Its query may carry a SAS, so `Debug` omits it.
#[derive(Clone)]
pub(crate) struct CopySource {
    scheme: String,
    host: String,
    port: Option<u16>,
    path: String,
    query: Option<String>,
}

impl std::fmt::Debug for CopySource {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("CopySource")
            .field("host", &self.host)
            .field("port", &self.port)
            .field("path", &self.path)
            .finish_non_exhaustive()
    }
}

pub(crate) struct Resolved {
    pub(crate) key: BlobKey,
    /// The source URL without its query, recorded as the destination's copy source.
    pub(crate) display: String,
    /// The snapshot or version the source URL names, if any.
    pub(crate) selector: Option<Selector>,
    sas: Option<Query>,
    authority: String,
    https: bool,
}

pub(crate) struct SourceBearer(String);

impl SourceBearer {
    pub(crate) fn parse(authorization: &str) -> Result<Self> {
        oauth::bearer(authorization)
            .map(|token| Self(token.to_owned()))
            .ok_or(Error::InvalidHeader)
    }
}

impl CopySource {
    pub(crate) fn parse(url: &str) -> Result<Self> {
        let uri: Uri = url.parse().map_err(|_| Error::InvalidHeader)?;
        if uri.scheme_str() != Some("http") && uri.scheme_str() != Some("https") {
            return Err(Error::InvalidHeader);
        }
        let authority = uri.authority().ok_or(Error::InvalidHeader)?;
        if authority.as_str().contains('@') {
            return Err(Error::InvalidHeader);
        }
        Ok(Self {
            scheme: uri.scheme_str().unwrap_or_default().to_owned(),
            host: authority.host().to_ascii_lowercase(),
            port: authority.port_u16(),
            path: uri.path().to_owned(),
            query: uri.query().map(str::to_owned),
        })
    }

    fn authority(&self) -> String {
        match self.port {
            Some(port) => format!("{}:{port}", self.host),
            None => self.host.clone(),
        }
    }

    /// Whether the URL names this listener: the host of the copy request itself,
    /// or a loopback name on the listener's port.
    pub(crate) fn is_local(&self, own_port: u16, request_host: Option<&str>) -> bool {
        let local_name = matches!(
            self.host.as_str(),
            "localhost" | "127.0.0.1" | "::1" | "[::1]"
        ) || self.host.ends_with(".localhost");
        let same_host =
            request_host.is_some_and(|host| host.eq_ignore_ascii_case(&self.authority()));
        same_host || local_name && self.port == Some(own_port)
    }

    /// The scheme, host, port, path, and query, for a fetch from another host.
    pub(crate) fn parts(&self) -> (&str, &str, Option<u16>, &str, Option<&str>) {
        (
            &self.scheme,
            &self.host,
            self.port,
            &self.path,
            self.query.as_deref(),
        )
    }

    /// Resolves a source on this listener. `own_port` is the listener port and
    /// `request_host` the `Host` header of the copy request.
    pub(crate) fn resolve(&self, own_port: u16, request_host: Option<&str>) -> Result<Resolved> {
        let authority = self.authority();
        if !self.is_local(own_port, request_host) {
            return Err(Error::Unsupported);
        }
        let account = address::host_account("blob", Some(&authority));
        let path = address::logical_path(account.as_ref(), &self.path);
        let decoded = percent_decode_str(&path)
            .decode_utf8()
            .map_err(|_| Error::InvalidHeader)?;
        let mut segments = decoded
            .strip_prefix('/')
            .ok_or(Error::InvalidHeader)?
            .splitn(3, '/');
        let account = AccountName::parse(segments.next().ok_or(Error::InvalidHeader)?)
            .map_err(|_| Error::InvalidHeader)?;
        let container = ContainerName::parse(segments.next().ok_or(Error::InvalidHeader)?)
            .map_err(|_| Error::InvalidHeader)?;
        let blob = BlobPath::parse(segments.next().ok_or(Error::InvalidHeader)?.to_owned())
            .map_err(|_| Error::InvalidHeader)?;
        let query = self
            .query
            .as_deref()
            .map(|query| parse_query(Some(query)))
            .transpose()?;
        let selector = query
            .as_ref()
            .map(blob_snapshot::selector)
            .transpose()?
            .flatten();
        let sas = query.filter(|query| query.contains_key("sig"));
        let display = format!("{}://{authority}{}", self.scheme, self.path);
        Ok(Resolved {
            key: BlobKey {
                container: ContainerKey {
                    account,
                    name: container,
                },
                path: blob,
            },
            display,
            selector,
            sas,
            authority,
            https: self.scheme == "https",
        })
    }
}

/// Decides whether the copy request may read the source: a valid read SAS on the
/// source, same-account Shared Key or bearer credentials, or public access.
pub(crate) async fn authorize_source(
    store: &Store,
    config: &Config,
    caller: &Credentials,
    destination: &AccountName,
    source: &Resolved,
    connection: &Connection,
    bearer: Option<&SourceBearer>,
) -> Result<()> {
    let denied = |_| Error::CopySourceDenied;
    let account = &source.key.container.account;
    let keys = config
        .accounts
        .get(account)
        .ok_or(Error::CopySourceDenied)?;
    let target = Target::Blob(source.key.clone());
    let credentials = match (bearer, &source.sas) {
        (Some(bearer), None) if source.https && connection.https && account == destination => {
            blob_auth::authenticate_bearer(
                &config.oauth,
                &bearer.0,
                &oauth::Request {
                    account: account.as_str(),
                    host: Some(&source.authority),
                    now: connection.now,
                },
                false,
            )
            .map_err(denied)?
        }
        (Some(_), _) => return Err(Error::CopySourceDenied),
        (None, Some(query)) => {
            let resource = Resource {
                account,
                container: Some(source.key.container.name.as_str()),
                blob: Some(source.key.path.as_str()),
            };
            let token = Token::verify(query, &resource, keys, &config.delegation)
                .map_err(denied)?
                .ok_or(Error::CopySourceDenied)?;
            Credentials::Sas(Box::new(token))
        }
        (None, None)
            if matches!(caller, Credentials::Key | Credentials::Bearer(_))
                && account == destination =>
        {
            Credentials::Key
        }
        (None, None) => Credentials::Anonymous,
    };
    blob_auth::authorize(
        store,
        Authorization {
            credentials: &credentials,
            target: &target,
            need: &READ,
            connection,
        },
    )
    .await
    .map_err(|error| match error {
        Error::Internal => Error::Internal,
        _ => Error::CopySourceDenied,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn resolve(url: &str, host: Option<&str>) -> Result<Resolved> {
        CopySource::parse(url)?.resolve(10000, host)
    }

    #[test]
    fn same_instance_sources_resolve_in_either_addressing_style() {
        let path_style =
            resolve("http://127.0.0.1:10000/acct1/box/dir/a%20b.txt?x=1", None).unwrap();
        assert_eq!(path_style.key.path.as_str(), "dir/a b.txt");
        assert_eq!(path_style.key.container.account.as_str(), "acct1");
        assert_eq!(
            path_style.display,
            "http://127.0.0.1:10000/acct1/box/dir/a%20b.txt"
        );
        let host_style = resolve(
            "http://acct1.blob.localhost:10000/box/a.txt",
            Some("127.0.0.1:10000"),
        )
        .unwrap();
        assert_eq!(host_style.key.container.name.as_str(), "box");
        assert_eq!(host_style.key.container.account.as_str(), "acct1");
        let by_host = resolve(
            "http://emulator.test:8080/acct1/box/a",
            Some("emulator.test:8080"),
        )
        .unwrap();
        assert_eq!(by_host.key.path.as_str(), "a");
    }

    #[test]
    fn other_hosts_and_malformed_urls_are_not_followed() {
        assert_eq!(
            resolve(
                "https://acct1.blob.core.windows.net/box/a",
                Some("127.0.0.1:10000")
            )
            .err(),
            Some(Error::Unsupported)
        );
        assert_eq!(
            resolve("http://127.0.0.1:9999/acct1/box/a", None).err(),
            Some(Error::Unsupported)
        );
        assert!(CopySource::parse("ftp://127.0.0.1/a").is_err());
        assert!(CopySource::parse("not a url").is_err());
        assert!(resolve("http://127.0.0.1:10000/acct1/box", None).is_err());
    }

    #[test]
    fn only_signed_queries_are_treated_as_sas() {
        assert!(
            resolve("http://127.0.0.1:10000/acct1/box/a?comp=x", None)
                .unwrap()
                .sas
                .is_none()
        );
        assert!(
            resolve(
                "http://127.0.0.1:10000/acct1/box/a?sv=2023-11-03&sig=abc",
                None
            )
            .unwrap()
            .sas
            .is_some()
        );
    }
}
