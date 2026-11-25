//! Bearer-token (OAuth) authentication shared by every service (ADR-0011, ADR-0006).
//!
//! Three modes. `off` (the default) rejects every bearer token with Azure's
//! `InvalidAuthenticationInfo`. `basic` is the reduced-validation mode of Azurite:
//! the token must be a well-formed JWT with an Entra-shaped issuer, a storage
//! audience, and a valid time window, but its signature is not verified, so it is
//! refused on a non-loopback bind. `jwks` verifies RS256 signatures against a local
//! JWKS file or an HTTPS URL and requires the configured issuer and audience.
//!
//! Authorization is deliberately coarse. In `basic` mode every operation is
//! allowed, as in Azurite. In `jwks` mode a token with a `roles` claim is limited by
//! the Azure data roles it names (see [`Principal::permits`]); a token without one
//! is allowed everything.

use crate::{
    config::Service,
    jwt::{Jwt, KeySet},
};
use anyhow::{Context as _, Result, anyhow, ensure};
use axum::{http::Method, response::Response};
use clap::{Args, ValueEnum};
use serde::Deserialize;
use std::{
    path::PathBuf,
    sync::{Arc, PoisonError, RwLock},
    time::{Duration, SystemTime, UNIX_EPOCH},
};
use tokio_util::sync::CancellationToken;

/// Sent with every 401 so SDKs learn which resource to request a token for.
const CHALLENGE: &str = "Bearer authorization_uri=https://login.microsoftonline.com/common/oauth2/authorize resource_id=https://storage.azure.com";
const STORAGE_AUDIENCE: &str = "https://storage.azure.com";
const SERVICE_HOSTS: [&str; 5] = ["blob", "queue", "table", "dfs", "file"];
/// Entra's own clock-skew tolerance for `exp` and `nbf`.
const TOLERANCE_SECONDS: f64 = 300.0;
const REFRESH_INTERVAL: Duration = Duration::from_secs(3600);
const MAX_JWKS_BYTES: usize = 1024 * 1024;

#[derive(Clone, Copy, Debug, Default, Deserialize, Eq, PartialEq, ValueEnum)]
#[serde(rename_all = "lowercase")]
pub(crate) enum Mode {
    /// Reject bearer tokens.
    #[default]
    Off,
    /// Validate claims only, like Azurite. Loopback only.
    Basic,
    /// Validate RS256 signatures against a JWKS and the configured issuer and audience.
    Jwks,
}

#[derive(Args, Default)]
pub(crate) struct OAuthOptions {
    /// Bearer token validation: off, basic (claims only, loopback only), or jwks.
    #[arg(long = "oauth", env = "AZUIFER_OAUTH", global = true, value_enum)]
    mode: Option<Mode>,
    /// JWKS file or HTTPS URL holding the RS256 verification keys (`--oauth jwks`).
    #[arg(long = "oauth-jwks", env = "AZUIFER_OAUTH_JWKS", global = true)]
    jwks: Option<String>,
    /// Comma-separated accepted `iss` values (`--oauth jwks`).
    #[arg(long = "oauth-issuer", env = "AZUIFER_OAUTH_ISSUER", global = true)]
    issuer: Option<String>,
    /// Comma-separated accepted `aud` values; defaults to the Azure Storage audiences.
    #[arg(long = "oauth-audience", env = "AZUIFER_OAUTH_AUDIENCE", global = true)]
    audience: Option<String>,
}

/// The `[oauth]` table of the TOML configuration.
#[derive(Default, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub(crate) struct FileSettings {
    mode: Option<Mode>,
    jwks: Option<String>,
    issuer: Option<String>,
    audience: Option<String>,
}

enum Source {
    File(PathBuf),
    Url(reqwest::Url),
}

#[derive(Default)]
pub(crate) struct OAuth {
    mode: Mode,
    source: Option<Source>,
    issuers: Vec<String>,
    audiences: Vec<String>,
    keys: RwLock<Arc<KeySet>>,
}

/// The facts of a request that decide which audiences are acceptable.
pub(crate) struct Request<'a> {
    pub(crate) account: &'a str,
    /// The `Host` the client addressed.
    pub(crate) host: Option<&'a str>,
    pub(crate) now: SystemTime,
}

/// A bearer token that failed validation. The reason is for diagnostics only; the
/// client always receives the same Azure error.
#[derive(Debug, Eq, PartialEq)]
pub(crate) struct Rejected(pub(crate) &'static str);

/// The caller a validated token identifies.
#[derive(Clone, Debug, Default)]
pub(crate) struct Principal {
    pub(crate) oid: Option<String>,
    pub(crate) tid: Option<String>,
    /// Set only in `jwks` mode, from the token's `roles` claim.
    roles: Option<Vec<String>>,
}

impl OAuth {
    pub(crate) fn resolve(
        options: OAuthOptions,
        file: FileSettings,
        loopback: bool,
    ) -> Result<Self> {
        let mode = options.mode.or(file.mode).unwrap_or_default();
        let jwks = options.jwks.or(file.jwks);
        let issuer = options.issuer.or(file.issuer);
        let audience = options.audience.or(file.audience);
        if mode != Mode::Jwks {
            ensure!(
                jwks.is_none() && issuer.is_none() && audience.is_none(),
                "--oauth-jwks, --oauth-issuer, and --oauth-audience require --oauth jwks"
            );
        }
        ensure!(
            mode != Mode::Basic || loopback,
            "--oauth basic does not verify signatures and requires loopback binding"
        );
        let list = |value: Option<String>| -> Vec<String> {
            value
                .iter()
                .flat_map(|value| value.split(','))
                .map(|item| item.trim().to_owned())
                .filter(|item| !item.is_empty())
                .collect()
        };
        let (issuers, audiences) = (list(issuer), list(audience));
        let source = if mode == Mode::Jwks {
            ensure!(!issuers.is_empty(), "--oauth jwks requires --oauth-issuer");
            Some(source(&jwks.ok_or_else(|| {
                anyhow!("--oauth jwks requires --oauth-jwks")
            })?)?)
        } else {
            None
        };
        Ok(Self {
            mode,
            source,
            issuers,
            audiences,
            keys: RwLock::default(),
        })
    }

    /// Loads the JWKS. Startup fails when it cannot be read, so validated mode
    /// never runs without keys.
    pub(crate) async fn load_keys(&self) -> Result<()> {
        let Some(source) = &self.source else {
            return Ok(());
        };
        let document = match source {
            Source::File(path) => tokio::fs::read(path)
                .await
                .context("could not read the JWKS file")?,
            Source::Url(url) => fetch(url).await?,
        };
        let keys = KeySet::parse(&document).map_err(|reason| anyhow!(reason))?;
        *self.keys.write().unwrap_or_else(PoisonError::into_inner) = Arc::new(keys);
        Ok(())
    }

    fn refreshes(&self) -> bool {
        matches!(self.source, Some(Source::Url(_)))
    }

    pub(crate) fn authenticate(
        &self,
        token: &str,
        request: &Request<'_>,
    ) -> Result<Principal, Rejected> {
        let outcome = self.check(token, request);
        if let Err(Rejected(reason)) = &outcome {
            tracing::info!(reason, "bearer token rejected");
        }
        outcome
    }

    fn check(&self, token: &str, request: &Request<'_>) -> Result<Principal, Rejected> {
        if self.mode == Mode::Off {
            return Err(Rejected("bearer tokens are disabled (--oauth off)"));
        }
        let jwt = Jwt::parse(token).map_err(|error| Rejected(error.reason()))?;
        if self.mode == Mode::Jwks {
            let keys = self
                .keys
                .read()
                .unwrap_or_else(PoisonError::into_inner)
                .clone();
            jwt.verify(&keys)
                .map_err(|error| Rejected(error.reason()))?;
        }
        let claims = jwt.claims;
        let issuer = claims.iss.as_deref().unwrap_or_default();
        let issuer_ok = match self.mode {
            Mode::Jwks => self
                .issuers
                .iter()
                .any(|accepted| accepted.trim_end_matches('/') == issuer.trim_end_matches('/')),
            _ => entra_issuer(issuer),
        };
        if !issuer_ok {
            return Err(Rejected("the token issuer is not accepted"));
        }
        if !claims
            .aud
            .values()
            .iter()
            .any(|value| self.audience_accepted(value, request))
        {
            return Err(Rejected("the token audience is not accepted"));
        }
        let now = request
            .now
            .duration_since(UNIX_EPOCH)
            .map_err(|_| Rejected("the clock is before 1970"))?
            .as_secs_f64();
        let expiry = claims.exp.ok_or(Rejected("the token has no exp claim"))?;
        if now > expiry + TOLERANCE_SECONDS {
            return Err(Rejected("the token has expired"));
        }
        if claims
            .nbf
            .is_some_and(|start| now + TOLERANCE_SECONDS < start)
        {
            return Err(Rejected("the token is not valid yet"));
        }
        Ok(Principal {
            oid: claims.oid,
            tid: claims.tid,
            roles: if self.mode == Mode::Jwks {
                claims.roles
            } else {
                None
            },
        })
    }

    fn audience_accepted(&self, audience: &str, request: &Request<'_>) -> bool {
        let audience = normalize(audience);
        if !self.audiences.is_empty() {
            return self
                .audiences
                .iter()
                .any(|accepted| normalize(accepted) == audience);
        }
        let account = request.account;
        audience == STORAGE_AUDIENCE
            || SERVICE_HOSTS
                .iter()
                .any(|service| audience == format!("https://{account}.{service}.core.windows.net"))
            || request.host.is_some_and(|host| {
                let host = host.to_ascii_lowercase();
                ["https", "http"].iter().any(|scheme| {
                    audience == format!("{scheme}://{host}")
                        || audience == format!("{scheme}://{host}/{account}")
                })
            })
    }
}

/// Reloads a remote JWKS periodically until `stop`; a failed refresh keeps the
/// keys already loaded.
pub(crate) async fn refresh_keys(config: Arc<crate::config::Config>, stop: CancellationToken) {
    if !config.oauth.refreshes() {
        return;
    }
    loop {
        tokio::select! {
            () = stop.cancelled() => return,
            () = tokio::time::sleep(REFRESH_INTERVAL) => {}
        }
        if let Err(error) = config.oauth.load_keys().await {
            tracing::warn!(%error, "could not refresh the JWKS; keeping the previous keys");
        }
    }
}

fn normalize(value: &str) -> String {
    value.trim_end_matches('/').to_ascii_lowercase()
}

/// `https://sts.windows.net/{tenant}/` or `https://login.microsoftonline.com/{tenant}/v2.0`.
fn entra_issuer(issuer: &str) -> bool {
    let tenant = issuer
        .strip_prefix("https://sts.windows.net/")
        .and_then(|rest| rest.strip_suffix('/'))
        .or_else(|| {
            issuer
                .strip_prefix("https://login.microsoftonline.com/")
                .and_then(|rest| rest.strip_suffix("/v2.0"))
        });
    tenant.is_some_and(|tenant| {
        !tenant.is_empty()
            && tenant
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'.'))
    })
}

fn source(value: &str) -> Result<Source> {
    if !value.starts_with("http://") && !value.starts_with("https://") {
        return Ok(Source::File(value.into()));
    }
    let url = reqwest::Url::parse(value).context("--oauth-jwks is not a valid URL")?;
    let host = url.host_str().unwrap_or_default();
    let local = host.eq_ignore_ascii_case("localhost")
        || host
            .trim_matches(['[', ']'])
            .parse::<std::net::IpAddr>()
            .is_ok_and(|address| address.is_loopback());
    ensure!(
        url.scheme() == "https" || local,
        "--oauth-jwks must use https unless it points at the local machine"
    );
    Ok(Source::Url(url))
}

async fn fetch(url: &reqwest::Url) -> Result<Vec<u8>> {
    let client = reqwest::Client::builder()
        .timeout(Duration::from_secs(10))
        .build()
        .context("could not create the JWKS client")?;
    let bytes = client
        .get(url.clone())
        .send()
        .await
        .and_then(reqwest::Response::error_for_status)
        .context("could not fetch the JWKS")?
        .bytes()
        .await
        .context("could not read the JWKS")?;
    ensure!(bytes.len() <= MAX_JWKS_BYTES, "the JWKS is too large");
    Ok(bytes.to_vec())
}

impl Principal {
    /// Whether the token's roles allow `service` and, if `write`, changes. Tokens
    /// without a `roles` claim (and every `basic` token) are allowed everything.
    ///
    /// Recognised: `Storage Blob Data Owner|Contributor|Reader` (Blob and DFS),
    /// `Storage Queue Data Contributor|Reader`, `Storage Table Data Contributor|Reader`,
    /// and `Storage File Data Privileged Contributor|Reader` plus the
    /// `SMB Share Contributor|Elevated Contributor|Reader` roles (Files).
    pub(crate) fn permits(&self, service: Service, write: bool) -> bool {
        let Some(roles) = &self.roles else {
            return true;
        };
        let prefix = match service {
            Service::Blob | Service::Dfs => "storage blob data ",
            Service::Queue => "storage queue data ",
            Service::Table => "storage table data ",
            Service::File => "storage file data ",
        };
        roles.iter().any(|role| {
            let role = role.to_ascii_lowercase();
            let Some(name) = role.strip_prefix(prefix) else {
                return false;
            };
            match name {
                "owner" | "contributor" => true,
                "reader" => !write,
                "privileged contributor"
                | "smb share contributor"
                | "smb share elevated contributor" => service == Service::File,
                "privileged reader" | "smb share reader" => service == Service::File && !write,
                _ => false,
            }
        })
    }
}

/// The token of an `Authorization: Bearer <token>` header.
pub(crate) fn bearer(authorization: &str) -> Option<&str> {
    let (scheme, token) = authorization.split_once(' ')?;
    let token = token.trim();
    (scheme.eq_ignore_ascii_case("bearer") && !token.is_empty()).then_some(token)
}

/// Whether the method only reads. Everything else needs a writer role.
pub(crate) fn is_write(method: &Method) -> bool {
    !matches!(*method, Method::GET | Method::HEAD | Method::OPTIONS)
}

/// Adds the `WWW-Authenticate` challenge Azure sends with a 401, once for all services.
pub(crate) async fn add_challenge(mut response: Response) -> Response {
    if response.status() == axum::http::StatusCode::UNAUTHORIZED {
        response.headers_mut().insert(
            "www-authenticate",
            axum::http::HeaderValue::from_static(CHALLENGE),
        );
    }
    response
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::jwt::tests::{jwks, sign};
    use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};

    const NOW: u64 = 1_900_000_000;

    fn at(offset: i64) -> SystemTime {
        UNIX_EPOCH + Duration::from_secs(NOW.saturating_add_signed(offset))
    }

    fn request(now: SystemTime) -> Request<'static> {
        Request {
            account: "devstoreaccount1",
            host: Some("127.0.0.1:10000"),
            now,
        }
    }

    fn claims(iss: &str, aud: &str, exp_offset: i64, extra: &str) -> String {
        format!(
            r#"{{"iss":"{iss}","aud":{aud},"exp":{},"oid":"oid-1","tid":"tid-1"{extra}}}"#,
            NOW.saturating_add_signed(exp_offset)
        )
    }

    fn unsigned(claims: &str) -> String {
        format!(
            "{}.{}.",
            URL_SAFE_NO_PAD.encode(r#"{"alg":"none"}"#),
            URL_SAFE_NO_PAD.encode(claims)
        )
    }

    fn basic() -> OAuth {
        OAuth {
            mode: Mode::Basic,
            source: None,
            issuers: Vec::new(),
            audiences: Vec::new(),
            keys: RwLock::default(),
        }
    }

    const V1: &str = "https://sts.windows.net/72f988bf-86f1-41af-91ab-2d7cd011db47/";
    const V2: &str = "https://login.microsoftonline.com/72f988bf-86f1-41af-91ab-2d7cd011db47/v2.0";

    #[test]
    fn basic_mode_accepts_entra_issuers_and_storage_audiences() {
        let oauth = basic();
        for (iss, aud) in [
            (V1, r#""https://storage.azure.com""#),
            (V2, r#""https://storage.azure.com/""#),
            (V1, r#""https://devstoreaccount1.blob.core.windows.net""#),
            (V1, r#""https://devstoreaccount1.queue.core.windows.net/""#),
            (V1, r#""https://127.0.0.1:10000/devstoreaccount1""#),
            (V1, r#"["other","https://storage.azure.com"]"#),
        ] {
            let token = unsigned(&claims(iss, aud, 3600, ""));
            let principal = oauth.authenticate(&token, &request(at(0))).unwrap();
            assert_eq!(principal.oid.as_deref(), Some("oid-1"), "{iss} {aud}");
            assert!(principal.permits(Service::Queue, true));
        }
    }

    #[test]
    fn basic_mode_rejects_bad_issuers_audiences_and_windows() {
        let oauth = basic();
        let rejected = |claims: String, now| {
            oauth
                .authenticate(&unsigned(&claims), &request(now))
                .unwrap_err()
                .0
        };
        let good = r#""https://storage.azure.com""#;
        assert!(rejected(claims("https://evil.test/t/", good, 60, ""), at(0)).contains("issuer"));
        assert!(
            rejected(claims("https://sts.windows.net//", good, 60, ""), at(0)).contains("issuer")
        );
        assert!(
            rejected(claims(V1, r#""https://other.test""#, 60, ""), at(0)).contains("audience")
        );
        assert!(
            rejected(
                claims(V1, r#""https://other.blob.core.windows.net""#, 60, ""),
                at(0)
            )
            .contains("audience")
        );
        assert!(rejected(claims(V1, good, -600, ""), at(0)).contains("expired"));
        assert!(
            rejected(claims(V1, good, 60, r#","nbf":2000000000"#), at(0)).contains("valid yet")
        );
        assert!(rejected(r#"{"iss":"x"}"#.into(), at(0)).contains("issuer"));
        let no_exp = format!(r#"{{"iss":"{V1}","aud":{good}}}"#);
        assert!(rejected(no_exp, at(0)).contains("exp"));
        assert!(basic().authenticate("garbage", &request(at(0))).is_err());
    }

    #[test]
    fn expiry_and_not_before_use_a_five_minute_tolerance_on_the_given_clock() {
        let oauth = basic();
        let token = unsigned(&claims(
            V1,
            r#""https://storage.azure.com""#,
            0,
            r#","nbf":1900000000"#,
        ));
        assert!(oauth.authenticate(&token, &request(at(299))).is_ok());
        assert!(oauth.authenticate(&token, &request(at(301))).is_err());
        assert!(oauth.authenticate(&token, &request(at(-299))).is_ok());
        assert!(oauth.authenticate(&token, &request(at(-301))).is_err());
    }

    #[test]
    fn off_mode_rejects_every_token() {
        let oauth = OAuth {
            mode: Mode::Off,
            ..basic()
        };
        let token = unsigned(&claims(V1, r#""https://storage.azure.com""#, 60, ""));
        assert!(oauth.authenticate(&token, &request(at(0))).is_err());
    }

    fn jwks_mode(audiences: &[&str]) -> OAuth {
        OAuth {
            mode: Mode::Jwks,
            source: None,
            issuers: vec!["https://issuer.test/".into()],
            audiences: audiences.iter().map(|value| (*value).to_owned()).collect(),
            keys: RwLock::new(Arc::new(KeySet::parse(jwks("k1").as_bytes()).unwrap())),
        }
    }

    const HEADER: &str = r#"{"alg":"RS256","kid":"k1"}"#;

    #[test]
    fn jwks_mode_verifies_signature_issuer_and_configured_audience() {
        let oauth = jwks_mode(&["api://azuifer"]);
        let token = sign(
            HEADER,
            &claims("https://issuer.test", r#""api://azuifer/""#, 60, ""),
        );
        assert!(oauth.authenticate(&token, &request(at(0))).is_ok());
        let wrong_issuer = sign(HEADER, &claims(V1, r#""api://azuifer""#, 60, ""));
        assert!(oauth.authenticate(&wrong_issuer, &request(at(0))).is_err());
        let default_audience = sign(
            HEADER,
            &claims(
                "https://issuer.test",
                r#""https://storage.azure.com""#,
                60,
                "",
            ),
        );
        assert!(
            oauth
                .authenticate(&default_audience, &request(at(0)))
                .is_err()
        );
        let unsigned = unsigned(&claims("https://issuer.test", r#""api://azuifer""#, 60, ""));
        assert!(oauth.authenticate(&unsigned, &request(at(0))).is_err());
        let (head, rest) = token.split_once('.').unwrap();
        let (_, signature) = rest.split_once('.').unwrap();
        let forged_claims = claims("https://issuer.test", r#""api://azuifer""#, 99_999, "");
        let forged = format!(
            "{head}.{}.{signature}",
            URL_SAFE_NO_PAD.encode(forged_claims)
        );
        assert!(oauth.authenticate(&forged, &request(at(0))).is_err());
    }

    #[test]
    fn jwks_mode_without_configured_audience_uses_the_storage_defaults() {
        let oauth = jwks_mode(&[]);
        let token = sign(
            HEADER,
            &claims(
                "https://issuer.test/",
                r#""https://storage.azure.com""#,
                60,
                "",
            ),
        );
        assert!(oauth.authenticate(&token, &request(at(0))).is_ok());
    }

    #[test]
    fn roles_limit_jwks_tokens_by_service_and_access() {
        let oauth = jwks_mode(&[]);
        let token = |roles: &str| {
            sign(
                HEADER,
                &claims(
                    "https://issuer.test/",
                    r#""https://storage.azure.com""#,
                    60,
                    &format!(r#","roles":{roles}"#),
                ),
            )
        };
        let principal = |roles: &str| oauth.authenticate(&token(roles), &request(at(0))).unwrap();
        let reader = principal(r#"["Storage Blob Data Reader"]"#);
        assert!(reader.permits(Service::Blob, false));
        assert!(reader.permits(Service::Dfs, false));
        assert!(!reader.permits(Service::Blob, true));
        assert!(!reader.permits(Service::Queue, false));
        let owner = principal(r#"["storage blob data owner","Storage Queue Data Reader"]"#);
        assert!(owner.permits(Service::Blob, true));
        assert!(owner.permits(Service::Queue, false));
        assert!(!owner.permits(Service::Queue, true));
        let unrelated = principal(r#"["Reader"]"#);
        assert!(!unrelated.permits(Service::Blob, false));
        let file = principal(r#"["Storage File Data SMB Share Contributor"]"#);
        assert!(file.permits(Service::File, true));
        assert!(!file.permits(Service::Table, false));
        let unrestricted = oauth
            .authenticate(
                &sign(
                    HEADER,
                    &claims(
                        "https://issuer.test/",
                        r#""https://storage.azure.com""#,
                        60,
                        "",
                    ),
                ),
                &request(at(0)),
            )
            .unwrap();
        assert!(unrestricted.permits(Service::Table, true));
    }

    fn resolve(
        mode: Option<Mode>,
        jwks: Option<&str>,
        issuer: Option<&str>,
        loopback: bool,
    ) -> Result<OAuth> {
        OAuth::resolve(
            OAuthOptions {
                mode,
                jwks: jwks.map(str::to_owned),
                issuer: issuer.map(str::to_owned),
                audience: None,
            },
            FileSettings::default(),
            loopback,
        )
    }

    #[test]
    fn configuration_is_validated() {
        assert_eq!(resolve(None, None, None, false).unwrap().mode, Mode::Off);
        assert_eq!(
            resolve(Some(Mode::Basic), None, None, true).unwrap().mode,
            Mode::Basic
        );
        assert!(resolve(Some(Mode::Basic), None, None, false).is_err());
        assert!(resolve(Some(Mode::Off), Some("keys.json"), None, true).is_err());
        assert!(resolve(Some(Mode::Jwks), None, Some("i"), true).is_err());
        assert!(resolve(Some(Mode::Jwks), Some("keys.json"), None, true).is_err());
        assert!(resolve(Some(Mode::Jwks), Some("keys.json"), Some("i"), false).is_ok());
        assert!(
            resolve(
                Some(Mode::Jwks),
                Some("http://example.test/k"),
                Some("i"),
                true
            )
            .is_err()
        );
        assert!(
            resolve(
                Some(Mode::Jwks),
                Some("https://example.test/k"),
                Some("i"),
                true
            )
            .is_ok()
        );
        assert!(
            resolve(
                Some(Mode::Jwks),
                Some("http://127.0.0.1:9/k"),
                Some("i"),
                true
            )
            .is_ok()
        );
    }

    #[test]
    fn bearer_header_parsing() {
        assert_eq!(bearer("Bearer abc"), Some("abc"));
        assert_eq!(bearer("bearer abc"), Some("abc"));
        assert_eq!(bearer("Bearer "), None);
        assert_eq!(bearer("SharedKey a:b"), None);
        assert_eq!(bearer("Bearer"), None);
    }
}
