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

#[derive(Clone, Debug)]
pub(crate) struct CopySource {
    host: String,
    port: Option<u16>,
    path: String,
    query: Option<String>,
}

pub(crate) struct Resolved {
    pub(crate) key: BlobKey,
    /// The source URL without its query, recorded as the destination's copy source.
    pub(crate) display: String,
    /// The snapshot or version the source URL names, if any.
    pub(crate) selector: Option<Selector>,
    sas: Option<Query>,
}

impl CopySource {
    pub(crate) fn parse(url: &str) -> Result<Self> {
        let uri: Uri = url.parse().map_err(|_| Error::InvalidHeader)?;
        if uri.scheme_str() != Some("http") && uri.scheme_str() != Some("https") {
            return Err(Error::InvalidHeader);
        }
        let authority = uri.authority().ok_or(Error::InvalidHeader)?;
        Ok(Self {
            host: authority.host().to_ascii_lowercase(),
            port: authority.port_u16(),
            path: uri.path().to_owned(),
            query: uri.query().map(str::to_owned),
        })
    }

    /// Resolves a source on this listener. `own_port` is the listener port and
    /// `request_host` the `Host` header of the copy request.
    pub(crate) fn resolve(&self, own_port: u16, request_host: Option<&str>) -> Result<Resolved> {
        let local_name = matches!(
            self.host.as_str(),
            "localhost" | "127.0.0.1" | "::1" | "[::1]"
        ) || self.host.ends_with(".localhost");
        let authority = match self.port {
            Some(port) => format!("{}:{port}", self.host),
            None => self.host.clone(),
        };
        let same_host = request_host.is_some_and(|host| host.eq_ignore_ascii_case(&authority));
        if !(same_host || local_name && self.port == Some(own_port)) {
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
        let scheme_free = format!("http://{authority}{}", self.path);
        Ok(Resolved {
            key: BlobKey {
                container: ContainerKey {
                    account,
                    name: container,
                },
                path: blob,
            },
            display: scheme_free,
            selector,
            sas,
        })
    }
}

/// Decides whether the copy request may read the source: a valid read SAS on the
/// source, the caller's own Shared Key within the same account, or public access.
pub(crate) async fn authorize_source(
    store: &Store,
    config: &Config,
    caller: &Credentials,
    destination: &AccountName,
    source: &Resolved,
    connection: &Connection,
) -> Result<()> {
    let denied = |_| Error::CopySourceDenied;
    let account = &source.key.container.account;
    let keys = config
        .accounts
        .get(account)
        .ok_or(Error::CopySourceDenied)?;
    let target = Target::Blob(source.key.clone());
    let credentials = match &source.sas {
        Some(query) => {
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
        None if matches!(caller, Credentials::Key | Credentials::Bearer(_))
            && account == destination =>
        {
            Credentials::Key
        }
        None => Credentials::Anonymous,
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
