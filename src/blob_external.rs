//! Copy sources outside this instance (opt-in).
//!
//! `--allow-external-copy-sources` names the hosts that Copy Blob, Put Blob From
//! URL, Put Block From URL, Append Block From URL, and Put Page From URL may read
//! over HTTP(S). It is off by default, so a request for any other host answers
//! `NotImplemented`, as before. The fetch is guarded against server-side request
//! forgery: only listed hosts are contacted, loopback, link-local, private, and
//! other non-public addresses are refused unless the operator listed that exact host
//! or address, the resolved address is the one connected to (no second lookup),
//! redirects are never followed, and the body must announce its length and stay
//! under the size limit. A SAS in the source URL is passed through to the source and
//! never logged or recorded. Copies complete synchronously, unlike Azure's
//! asynchronous copy from an external URL.

use crate::{
    blob_copy::CopySource,
    domain::{BlobInfo, ContentHeaders, ContentLength, Entity, Error, Result},
    lease::StoredLease,
    store::{SourceBytes, Store},
};
use anyhow::{Context as _, ensure};
use std::{
    net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr},
    time::Duration,
};
use tokio::time::Instant;
use uuid::Uuid;

const CONNECT_TIMEOUT: Duration = Duration::from_secs(10);

/// One entry of the allowlist.
#[derive(Clone, Debug, Eq, PartialEq)]
enum Rule {
    /// A named host or address, optionally with a port. The operator chose it by
    /// name, so it may resolve to a private or loopback address.
    Exact { host: String, port: Option<u16> },
    /// `*.suffix`: any subdomain. It must resolve to public addresses only.
    Suffix(String),
}

impl Rule {
    fn parse(entry: &str) -> anyhow::Result<Self> {
        let entry = entry.to_ascii_lowercase();
        ensure!(
            !entry.contains("://") && !entry.contains(['/', '@', ' ']),
            "an allowed copy source is a host, host:port, or *.domain, not a URL"
        );
        if let Some(suffix) = entry.strip_prefix("*.") {
            ensure!(
                suffix.contains('.') && !suffix.contains([':', '*']),
                "a wildcard copy source needs a domain such as *.example.com"
            );
            return Ok(Self::Suffix(format!(".{suffix}")));
        }
        ensure!(!entry.contains('*'), "wildcards are written as *.domain");
        let (host, port) = split_host_port(&entry)?;
        ensure!(!host.is_empty(), "an allowed copy source cannot be empty");
        Ok(Self::Exact {
            host: normalize_literal(&host),
            port,
        })
    }

    fn matches(&self, host: &str, port: u16) -> bool {
        match self {
            Self::Exact {
                host: allowed,
                port: allowed_port,
            } => allowed == host && allowed_port.is_none_or(|allowed| allowed == port),
            Self::Suffix(suffix) => host.ends_with(suffix.as_str()),
        }
    }

    /// The addresses this rule may connect to: every one for an exact rule, only
    /// public ones for a wildcard (which names a family of hosts, not one).
    fn admit(&self, addresses: &[IpAddr]) -> Option<IpAddr> {
        match self {
            Self::Exact { .. } => addresses.first().copied(),
            Self::Suffix(_) => addresses
                .iter()
                .all(|address| is_public(*address))
                .then(|| addresses.first().copied())
                .flatten(),
        }
    }
}

fn normalize_literal(host: &str) -> String {
    host.parse::<Ipv6Addr>()
        .map_or_else(|_| host.to_owned(), |address| address.to_string())
}

/// `host`, `host:port`, `[v6]`, or `[v6]:port`, lowercased and without brackets.
fn split_host_port(entry: &str) -> anyhow::Result<(String, Option<u16>)> {
    if let Some(rest) = entry.strip_prefix('[') {
        let (host, after) = rest
            .split_once(']')
            .context("an IPv6 copy source needs a closing bracket")?;
        let port = after
            .strip_prefix(':')
            .map(str::parse)
            .transpose()
            .context("invalid port in an allowed copy source")?;
        ensure!(
            after.is_empty() || port.is_some(),
            "invalid allowed copy source"
        );
        return Ok((host.to_owned(), port));
    }
    match entry.rsplit_once(':') {
        Some((host, port)) if !host.contains(':') => Ok((
            host.to_owned(),
            Some(
                port.parse()
                    .context("invalid port in an allowed copy source")?,
            ),
        )),
        _ => Ok((entry.to_owned(), None)),
    }
}

/// The hosts external copies may read; empty (the default) means none.
#[derive(Clone, Debug, Default)]
pub(crate) struct Allowlist(Vec<Rule>);

impl Allowlist {
    pub(crate) fn parse(list: &str) -> anyhow::Result<Self> {
        let mut rules = Vec::new();
        for entry in list
            .split(',')
            .map(str::trim)
            .filter(|entry| !entry.is_empty())
        {
            let rule = Rule::parse(entry)?;
            ensure!(
                !rules.contains(&rule),
                "duplicate allowed copy source `{entry}`"
            );
            rules.push(rule);
        }
        Ok(Self(rules))
    }

    pub(crate) fn is_enabled(&self) -> bool {
        !self.0.is_empty()
    }

    fn rule(&self, host: &str, port: u16) -> Option<&Rule> {
        self.0.iter().find(|rule| rule.matches(host, port))
    }
}

/// Whether an address is a routable public one. Loopback, private, link-local
/// (including cloud metadata addresses), shared, documentation, multicast, and
/// reserved ranges are not, and neither are IPv4-mapped forms of them.
pub(crate) fn is_public(address: IpAddr) -> bool {
    match address {
        IpAddr::V4(address) => is_public_v4(address),
        IpAddr::V6(address) => is_public_v6(address),
    }
}

fn is_public_v4(address: Ipv4Addr) -> bool {
    let [a, b, c, _] = address.octets();
    !(address.is_unspecified()
        || address.is_loopback()
        || address.is_private()
        || address.is_link_local()
        || address.is_broadcast()
        || address.is_multicast()
        || a == 0
        || (a == 100 && (64..128).contains(&b))
        || (a == 192 && b == 0 && c == 0)
        || (a == 192 && b == 0 && c == 2)
        || (a == 198 && (b == 18 || b == 19))
        || (a == 198 && b == 51 && c == 100)
        || (a == 203 && b == 0 && c == 113)
        || a >= 240)
}

fn is_public_v6(address: Ipv6Addr) -> bool {
    if let Some(mapped) = address.to_ipv4_mapped() {
        return is_public_v4(mapped);
    }
    let segments = address.segments();
    // 64:ff9b::/96 (NAT64) embeds an IPv4 address in its last 32 bits.
    if segments[..6] == [0x64, 0xff9b, 0, 0, 0, 0] {
        let [high, low] = [segments[6], segments[7]];
        return is_public_v4(Ipv4Addr::new(
            (high >> 8) as u8,
            high as u8,
            (low >> 8) as u8,
            low as u8,
        ));
    }
    !(address.is_unspecified()
        || address.is_loopback()
        || address.is_multicast()
        || segments[0] & 0xfe00 == 0xfc00
        || segments[0] & 0xffc0 == 0xfe80
        || (segments[0] == 0x2001 && segments[1] == 0x0db8))
}

/// A source URL outside this instance, split for the fetch. Its query may carry a
/// SAS, so it is never formatted into a log line or an error.
pub(crate) struct Target {
    pub(crate) host: String,
    pub(crate) port: u16,
    url: String,
    display: String,
}

impl Target {
    pub(crate) fn new(source: &CopySource) -> Self {
        let (scheme, host, port, path, query) = source.parts();
        let port = port.unwrap_or(if scheme == "https" { 443 } else { 80 });
        let host = host.trim_matches(['[', ']']);
        let bracketed = if host.contains(':') {
            format!("[{host}]")
        } else {
            host.to_owned()
        };
        let display = format!("{scheme}://{bracketed}:{port}{path}");
        let url = match query {
            Some(query) => format!("{display}?{query}"),
            None => display.clone(),
        };
        Self {
            host: normalize_literal(host),
            port,
            url,
            display,
        }
    }

    /// The source without its query, as recorded for the destination blob.
    pub(crate) fn display(&self) -> &str {
        &self.display
    }
}

/// An open response to stream into an upload.
pub(crate) struct Remote {
    response: reqwest::Response,
    length: u64,
}

async fn resolve(host: &str, port: u16) -> Result<Vec<IpAddr>> {
    if let Ok(address) = host.parse::<IpAddr>() {
        return Ok(vec![address]);
    }
    let addresses = tokio::net::lookup_host((host, port))
        .await
        .map_err(|_| Error::CopySourceDenied)?;
    Ok(addresses.map(|address| address.ip()).collect())
}

/// Checks the guard and opens the source. `range` is a `Range` header value for a
/// ranged copy. A body larger than `limit` or without a length is refused.
pub(crate) async fn open(
    allowlist: &Allowlist,
    target: &Target,
    range: Option<&str>,
    limit: u64,
    timeout: Duration,
) -> Result<Remote> {
    open_with_resolution(
        allowlist,
        target,
        range,
        limit,
        timeout,
        resolve(&target.host, target.port),
    )
    .await
}

async fn open_with_resolution(
    allowlist: &Allowlist,
    target: &Target,
    range: Option<&str>,
    limit: u64,
    timeout: Duration,
    resolution: impl Future<Output = Result<Vec<IpAddr>>>,
) -> Result<Remote> {
    let rule = allowlist
        .rule(&target.host, target.port)
        .ok_or(Error::Unsupported)?;
    let started = Instant::now();
    let deadline = started + timeout;
    let addresses = tokio::time::timeout_at(started + timeout.min(CONNECT_TIMEOUT), resolution)
        .await
        .map_err(|_| Error::CopySourceDenied)??;
    let address = rule.admit(&addresses).ok_or(Error::CopySourceDenied)?;
    let mut builder = reqwest::Client::builder()
        .no_proxy()
        .redirect(reqwest::redirect::Policy::none())
        .connect_timeout(CONNECT_TIMEOUT)
        .user_agent("azuifer-copy");
    if target.host.parse::<IpAddr>().is_err() {
        // Connect to the address that passed the guard, not to a second lookup.
        builder = builder.resolve(&target.host, SocketAddr::new(address, target.port));
    }
    let client = builder.build().map_err(|_| Error::Internal)?;
    let mut request = client.get(&target.url);
    if let Some(range) = range {
        request = request.header("range", range);
    }
    // Reqwest applies the remaining budget through the last response body byte.
    let remaining = deadline
        .checked_duration_since(Instant::now())
        .filter(|duration| !duration.is_zero())
        .ok_or(Error::CopySourceDenied)?;
    let response = request.timeout(remaining).send().await.map_err(|error| {
        tracing::warn!(
            timeout = error.is_timeout(),
            "external copy source unreachable"
        );
        Error::CopySourceDenied
    })?;
    let status = response.status().as_u16();
    match status {
        200 | 206 => (),
        404 => return Err(Error::CopySourceMissing),
        _ => return Err(Error::CopySourceDenied),
    }
    let length = response.content_length().ok_or(Error::CopySourceDenied)?;
    if length > limit {
        return Err(Error::TooLarge);
    }
    Ok(Remote { response, length })
}

/// Streams the source into a staged upload and presents it as a copy source.
pub(crate) async fn read(store: &Store, mut remote: Remote, now: u64) -> Result<SourceBytes> {
    let headers = ContentHeaders {
        content_type: header(&remote.response, "content-type")
            .unwrap_or_else(|| "application/octet-stream".to_owned()),
        encoding: header(&remote.response, "content-encoding").unwrap_or_default(),
        language: header(&remote.response, "content-language").unwrap_or_default(),
        disposition: header(&remote.response, "content-disposition").unwrap_or_default(),
        cache_control: header(&remote.response, "cache-control").unwrap_or_default(),
    };
    let mut upload = store.begin_upload(ContentLength(remote.length)).await?;
    while let Some(chunk) = remote
        .response
        .chunk()
        .await
        .map_err(|_| Error::CopySourceDenied)?
    {
        upload.append(&chunk).await?;
    }
    // A source `Content-MD5` covers the whole resource, not a requested range, so it is not checked.
    let upload = upload.finish(None).await?;
    let id = Uuid::new_v4();
    Ok(SourceBytes {
        info: BlobInfo {
            entity: Entity {
                id,
                tag: id,
                modified: now,
                version: None,
            },
            created: now,
            length: ContentLength(remote.length),
            headers,
            md5: None,
            metadata: Default::default(),
            tier: None,
            lease: StoredLease::default().view(0),
            copy: None,
            uncommitted: false,
            kind: crate::blob_page::BlobKind::Block,
            tags: Default::default(),
            lifecycle: Default::default(),
        },
        upload,
    })
}

fn header(response: &reqwest::Response, name: &str) -> Option<String> {
    response
        .headers()
        .get(name)
        .and_then(|value| value.to_str().ok())
        .map(str::to_owned)
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};

    fn allow(list: &str) -> Allowlist {
        Allowlist::parse(list).unwrap()
    }

    #[test]
    fn the_allowlist_takes_hosts_ports_and_wildcards() {
        assert!(!Allowlist::default().is_enabled());
        assert!(!allow("").is_enabled());
        let list = allow("Files.Example.com, 10.1.2.3:8080, [::1], *.cdn.example.net");
        assert!(list.rule("files.example.com", 443).is_some());
        assert!(list.rule("10.1.2.3", 8080).is_some());
        assert!(
            list.rule("10.1.2.3", 80).is_none(),
            "a listed port must match"
        );
        assert!(list.rule("::1", 80).is_some());
        assert!(list.rule("a.cdn.example.net", 443).is_some());
        assert!(list.rule("cdn.example.net", 443).is_none());
        assert!(list.rule("evilcdn.example.net", 443).is_none());
        assert!(list.rule("example.com", 443).is_none());
        for bad in [
            "http://example.com",
            "example.com/path",
            "user@example.com",
            "*.com",
            "*example.com",
            "example.com:port",
            "a.com,a.com",
        ] {
            assert!(Allowlist::parse(bad).is_err(), "{bad}");
        }
    }

    #[test]
    fn exact_ipv6_rules_accept_equivalent_notation_only_on_the_configured_port() {
        let compressed = "[2001:db8::42]";
        let expanded = "[2001:0DB8:0000:0000:0000:0000:0000:0042]";
        for (configured, requested) in [(expanded, compressed), (compressed, expanded)] {
            let list = allow(&format!("{configured}:8443"));
            let target = |host, port| {
                Target::new(
                    &CopySource::parse(&format!("https://{host}:{port}/archive/example")).unwrap(),
                )
            };
            let intended = target(requested, 8443);
            assert!(list.rule(&intended.host, intended.port).is_some());
            let wrong_port = target(requested, 443);
            assert!(list.rule(&wrong_port.host, wrong_port.port).is_none());
            let different = target("[2001:db8::43]", 8443);
            assert!(list.rule(&different.host, different.port).is_none());
        }
    }

    #[test]
    fn only_public_addresses_pass_the_guard() {
        for private in [
            "127.0.0.1",
            "10.0.0.1",
            "172.16.5.5",
            "192.168.1.1",
            "169.254.169.254",
            "100.64.0.1",
            "0.0.0.0",
            "224.0.0.1",
            "255.255.255.255",
            "198.18.0.1",
            "::1",
            "::",
            "fe80::1",
            "fd00::1",
            "ff02::1",
            "::ffff:127.0.0.1",
            "::ffff:10.0.0.1",
            "64:ff9b::7f00:1",
            "2001:db8::1",
        ] {
            assert!(!is_public(private.parse().unwrap()), "{private}");
        }
        for public in [
            "8.8.8.8",
            "1.1.1.1",
            "93.184.216.34",
            "2606:4700::1111",
            "::ffff:8.8.8.8",
        ] {
            assert!(is_public(public.parse().unwrap()), "{public}");
        }
    }

    #[test]
    fn an_exact_rule_admits_private_addresses_but_a_wildcard_does_not() {
        let loopback: IpAddr = "127.0.0.1".parse().unwrap();
        let public: IpAddr = "8.8.8.8".parse().unwrap();
        let exact = Rule::parse("files.internal").unwrap();
        let wildcard = Rule::parse("*.example.com").unwrap();
        assert_eq!(exact.admit(&[loopback]), Some(loopback));
        assert_eq!(wildcard.admit(&[loopback]), None);
        assert_eq!(wildcard.admit(&[public]), Some(public));
        assert_eq!(
            wildcard.admit(&[public, loopback]),
            None,
            "one private answer refuses the host (DNS rebinding)"
        );
        assert_eq!(wildcard.admit(&[]), None);
    }

    /// Serves one canned response per connection and returns the request head.
    async fn serve(response: &'static [u8]) -> (u16, tokio::task::JoinHandle<String>) {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        let task = tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.unwrap();
            let mut head = Vec::new();
            let mut byte = [0u8; 1];
            while !head.ends_with(b"\r\n\r\n") {
                if stream.read(&mut byte).await.unwrap() == 0 {
                    break;
                }
                head.push(byte[0]);
            }
            stream.write_all(response).await.unwrap();
            stream.shutdown().await.ok();
            String::from_utf8(head).unwrap()
        });
        (port, task)
    }

    fn target(port: u16, path: &str) -> Target {
        Target::new(
            &CopySource::parse(&format!("http://127.0.0.1:{port}{path}?sig=secret")).unwrap(),
        )
    }

    const TIMEOUT: Duration = Duration::from_secs(5);

    #[tokio::test]
    async fn resolving_a_source_consumes_the_fetch_time_budget() {
        let target =
            Target::new(&CopySource::parse("https://source.example.test/archive/example").unwrap());
        let list = allow("source.example.test");
        let result = tokio::time::timeout(
            Duration::from_secs(1),
            open_with_resolution(
                &list,
                &target,
                None,
                100,
                Duration::from_millis(25),
                std::future::pending(),
            ),
        )
        .await
        .expect("copy must time out without waiting for the resolver");
        assert_eq!(result.err(), Some(Error::CopySourceDenied));
    }

    #[tokio::test]
    async fn an_allowlisted_host_is_read_with_its_range_and_sas_passed_through() {
        let (port, server) = serve(
            b"HTTP/1.1 206 Partial Content\r\ncontent-length: 5\r\nconnection: close\r\n\r\nhello",
        )
        .await;
        let target = target(port, "/box/blob");
        assert_eq!(
            target.display(),
            format!("http://127.0.0.1:{port}/box/blob")
        );
        let remote = open(
            &allow("127.0.0.1"),
            &target,
            Some("bytes=0-4"),
            100,
            TIMEOUT,
        )
        .await
        .unwrap();
        assert_eq!(remote.length, 5);
        let head = server.await.unwrap();
        assert!(
            head.starts_with("GET /box/blob?sig=secret HTTP/1.1"),
            "{head}"
        );
        assert!(
            head.to_ascii_lowercase().contains("range: bytes=0-4"),
            "{head}"
        );
    }

    #[tokio::test]
    async fn a_host_that_is_not_listed_is_not_contacted() {
        let (port, server) = serve(b"HTTP/1.1 200 OK\r\ncontent-length: 0\r\n\r\n").await;
        for list in ["", "localhost", "*.example.com", "127.0.0.1:1"] {
            let result = open(&allow(list), &target(port, "/a"), None, 100, TIMEOUT).await;
            assert_eq!(result.err(), Some(Error::Unsupported), "{list}");
        }
        server.abort();
    }

    #[tokio::test]
    async fn redirects_missing_lengths_and_large_bodies_are_refused() {
        let cases: [(&'static [u8], Error); 5] = [
            (
                b"HTTP/1.1 302 Found\r\nlocation: http://169.254.169.254/\r\ncontent-length: 0\r\n\r\n",
                Error::CopySourceDenied,
            ),
            (
                b"HTTP/1.1 404 Not Found\r\ncontent-length: 0\r\n\r\n",
                Error::CopySourceMissing,
            ),
            (
                b"HTTP/1.1 403 Forbidden\r\ncontent-length: 0\r\n\r\n",
                Error::CopySourceDenied,
            ),
            (
                b"HTTP/1.1 200 OK\r\ntransfer-encoding: chunked\r\n\r\n0\r\n\r\n",
                Error::CopySourceDenied,
            ),
            (
                b"HTTP/1.1 200 OK\r\ncontent-length: 101\r\n\r\n",
                Error::TooLarge,
            ),
        ];
        for (response, expected) in cases {
            let (port, server) = serve(response).await;
            let result = open(&allow("127.0.0.1"), &target(port, "/a"), None, 100, TIMEOUT).await;
            assert_eq!(result.err(), Some(expected));
            server.abort();
        }
    }

    #[tokio::test]
    async fn an_unreachable_source_is_denied_without_leaking_the_url() {
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let port = listener.local_addr().unwrap().port();
        drop(listener);
        let result = open(&allow("127.0.0.1"), &target(port, "/a"), None, 100, TIMEOUT).await;
        assert_eq!(result.err(), Some(Error::CopySourceDenied));
    }
}
