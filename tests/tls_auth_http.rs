use base64::{
    Engine as _,
    engine::general_purpose::{STANDARD, URL_SAFE_NO_PAD},
};
use reqwest::{
    Method,
    blocking::{Client, Response},
};
use ring::signature::{RSA_PKCS1_SHA256, RsaKeyPair, RsaPublicKeyComponents};
use rustls::pki_types::{CertificateDer, PrivateKeyDer, pem::PemObject as _};
use serde_json::{Value, json};
use std::{
    collections::HashMap,
    io::{BufRead as _, BufReader, Read as _, Write as _},
    net::TcpListener,
    path::{Path, PathBuf},
    process::{Child, Command, Stdio},
    thread,
    time::{Duration, SystemTime, UNIX_EPOCH},
};

mod contracts;

const ACCOUNT: &str = "devstoreaccount1";
const VERSION: &str = "2023-11-03";
const ISSUER_V1: &str = "https://sts.windows.net/72f988bf-86f1-41af-91ab-2d7cd011db47/";
const STORAGE: &str = "https://storage.azure.com";
const SIGNING_KEY: &str = include_str!("data/rs256-test-key.pk8.b64");

struct Server {
    child: Child,
    urls: HashMap<String, String>,
    other: HashMap<String, String>,
}

fn command(args: &[&str], env: &[(&str, &str)]) -> Command {
    let mut command = Command::new(env!("CARGO_BIN_EXE_azuifer"));
    for (name, _) in std::env::vars_os() {
        if name
            .to_string_lossy()
            .to_ascii_uppercase()
            .starts_with("AZUIFER_")
        {
            command.env_remove(name);
        }
    }
    command.envs(env.iter().copied()).args(args);
    command
}

impl Server {
    /// Starts `serve` on ephemeral ports with extra arguments and environment.
    fn start(args: &[&str], env: &[(&str, &str)]) -> Self {
        let mut command = command(&["serve", "--port", "0", "--admin-port", "0"], env);
        command
            .args(args)
            .arg("--shutdown-on-stdin-eof")
            .stdin(Stdio::piped())
            .stdout(Stdio::piped());
        let mut child = command.spawn().expect("start Azuifer");
        let mut lines = BufReader::new(child.stdout.take().expect("piped stdout")).lines();
        let (mut urls, mut other) = (HashMap::new(), HashMap::new());
        for line in lines.by_ref() {
            let line = line.expect("startup line");
            let (name, value) = line.split_once('=').expect("a `name=value` startup line");
            match name.strip_suffix("_url") {
                Some(service) => urls.insert(service.to_owned(), value.to_owned()),
                None => other.insert(name.to_owned(), value.to_owned()),
            };
            if name == "admin_url" {
                break;
            }
        }
        // Keep draining so the server never fails writing to a closed pipe.
        thread::spawn(move || lines.for_each(drop));
        Self { child, urls, other }
    }

    fn url(&self, service: &str) -> &str {
        &self.urls[service]
    }

    fn generated_certificate(&self) -> Vec<u8> {
        std::fs::read(&self.other["tls_cert"]).expect("the generated certificate")
    }
}

impl Drop for Server {
    fn drop(&mut self) {
        drop(self.child.stdin.take());
        let _ = self.child.wait();
    }
}

fn client(trusted: Option<&[u8]>) -> Client {
    let mut builder = Client::builder()
        .no_proxy()
        .timeout(Duration::from_secs(10));
    if let Some(pem) = trusted {
        builder = builder.add_root_certificate(reqwest::Certificate::from_pem(pem).unwrap());
    }
    builder.build().unwrap()
}

fn now() -> i64 {
    i64::try_from(
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs(),
    )
    .unwrap()
}

fn signing_key() -> RsaKeyPair {
    RsaKeyPair::from_pkcs8(&STANDARD.decode(SIGNING_KEY.trim()).unwrap()).unwrap()
}

fn jwks(kid: &str) -> String {
    let public = RsaPublicKeyComponents::<Vec<u8>>::from(signing_key().public());
    json!({"keys": [{
        "kty": "RSA", "use": "sig", "kid": kid,
        "n": URL_SAFE_NO_PAD.encode(public.n),
        "e": URL_SAFE_NO_PAD.encode(public.e),
    }]})
    .to_string()
}

/// A hand-built, unsigned JWT: what a test credential for reduced validation returns.
fn unsigned(claims: &Value) -> String {
    format!(
        "{}.{}.",
        URL_SAFE_NO_PAD.encode(r#"{"alg":"none","typ":"JWT"}"#),
        URL_SAFE_NO_PAD.encode(claims.to_string())
    )
}

fn signed(claims: &Value) -> String {
    let input = format!(
        "{}.{}",
        URL_SAFE_NO_PAD.encode(r#"{"alg":"RS256","typ":"JWT","kid":"test-key"}"#),
        URL_SAFE_NO_PAD.encode(claims.to_string())
    );
    let key = signing_key();
    let mut signature = vec![0; key.public().modulus_len()];
    key.sign(
        &RSA_PKCS1_SHA256,
        &ring::rand::SystemRandom::new(),
        input.as_bytes(),
        &mut signature,
    )
    .unwrap();
    format!("{input}.{}", URL_SAFE_NO_PAD.encode(signature))
}

fn claims(issuer: &str, audience: &str, lifetime: i64) -> Value {
    json!({
        "iss": issuer,
        "aud": audience,
        "iat": now(),
        "nbf": now() - 60,
        "exp": now() + lifetime,
        "oid": "11111111-2222-3333-4444-555555555555",
        "tid": "72f988bf-86f1-41af-91ab-2d7cd011db47",
    })
}

fn with_roles(mut claims: Value, roles: &[&str]) -> Value {
    claims["roles"] = json!(roles);
    claims
}

fn basic_token() -> String {
    unsigned(&claims(ISSUER_V1, STORAGE, 3600))
}

fn call(client: &Client, method: Method, url: &str, token: Option<&str>) -> Response {
    let mut request = client.request(method, url).header("x-ms-version", VERSION);
    if let Some(token) = token {
        request = request.header("authorization", format!("Bearer {token}"));
    }
    request.send().expect("a response")
}

fn error_code(response: &Response) -> String {
    response
        .headers()
        .get("x-ms-error-code")
        .map(|value| value.to_str().unwrap().to_owned())
        .unwrap_or_default()
}

/// A service name, a list URL, and the extra headers that service needs.
type ListRequest = (&'static str, String, Vec<(&'static str, &'static str)>);

/// One list request per service; each returns 200 for an authorized caller.
fn list_requests(server: &Server) -> Vec<ListRequest> {
    let account = |service: &str| format!("{}/{ACCOUNT}", server.url(service));
    vec![
        ("blob", format!("{}?comp=list", account("blob")), vec![]),
        ("queue", format!("{}?comp=list", account("queue")), vec![]),
        (
            "table",
            format!("{}/Tables", account("table")),
            vec![("accept", "application/json;odata=nometadata")],
        ),
        ("file", format!("{}?comp=list", account("file")), vec![]),
        (
            "dfs",
            format!("{}?resource=account", account("dfs")),
            vec![],
        ),
    ]
}

fn send_list(
    client: &Client,
    url: &str,
    headers: &[(&str, &str)],
    token: Option<&str>,
) -> Response {
    let mut request = client.get(url).header("x-ms-version", VERSION);
    for (name, value) in headers {
        request = request.header(*name, *value);
    }
    if let Some(token) = token {
        request = request.header("authorization", format!("Bearer {token}"));
    }
    request.send().expect("a response")
}

const ALL_SERVICES: [&str; 6] = ["admin", "blob", "queue", "table", "dfs", "file"];

#[test]
fn generated_certificate_serves_every_service_over_https_and_is_reused() {
    let directory = tempfile::tempdir().unwrap();
    let location = directory.path().to_str().unwrap();
    let server = Server::start(&["--location", location, "--tls-generate"], &[]);
    let certificate_path = Path::new(&server.other["tls_cert"]).to_owned();
    assert_eq!(
        certificate_path,
        directory.path().join("tls").join("azuifer-dev.crt")
    );
    let mut names: Vec<_> = server.urls.keys().map(String::as_str).collect();
    names.sort_unstable();
    assert_eq!(names, ["admin", "blob", "dfs", "file", "queue", "table"]);
    for service in ALL_SERVICES {
        let scheme = if service == "admin" {
            "http://"
        } else {
            "https://"
        };
        assert!(
            server.url(service).starts_with(scheme),
            "{service}: {}",
            server.url(service)
        );
    }
    let pem = server.generated_certificate();
    let trusting = client(Some(&pem));
    for service in ["blob", "queue", "table", "dfs", "file"] {
        let response = trusting
            .get(format!("{}/{ACCOUNT}", server.url(service)))
            .header("x-ms-version", VERSION)
            .send()
            .unwrap_or_else(|error| panic!("{service}: {error}"));
        assert!(response.status().is_client_error(), "{service}");
    }
    let admin = trusting
        .get(format!("{}/readyz", server.url("admin")))
        .send()
        .unwrap();
    assert_eq!(admin.text().unwrap(), "ready\n");

    // Without the certificate as a trust anchor the handshake fails, as does plain HTTP.
    assert!(
        client(None)
            .get(format!("{}/{ACCOUNT}?comp=list", server.url("blob")))
            .send()
            .is_err()
    );
    let plain = server.url("blob").replacen("https://", "http://", 1);
    assert!(
        trusting
            .get(format!("{plain}/{ACCOUNT}?comp=list"))
            .send()
            .is_err()
    );

    drop(server);
    let restarted = Server::start(&["--location", location, "--tls-generate"], &[]);
    assert_eq!(
        restarted.generated_certificate(),
        pem,
        "the certificate is reused"
    );
}

#[test]
fn in_memory_runs_generate_into_a_temporary_directory_that_is_removed() {
    let server = Server::start(&["--in-memory", "--tls-generate"], &[]);
    let path = PathBuf::from(&server.other["tls_cert"]);
    assert!(path.is_file());
    let pem = server.generated_certificate();
    let response = call(
        &client(Some(&pem)),
        Method::GET,
        &format!("{}/{ACCOUNT}?comp=list", server.url("blob")),
        None,
    );
    assert_eq!(response.status(), 403);
    drop(server);
    assert!(!path.exists());
}

fn self_signed() -> (String, String) {
    let certified =
        rcgen::generate_simple_self_signed(vec!["localhost".to_owned(), "127.0.0.1".to_owned()])
            .unwrap();
    (certified.cert.pem(), certified.signing_key.serialize_pem())
}

fn pfx(cert_pem: &str, key_pem: &str, password: &str) -> Vec<u8> {
    let certificate = CertificateDer::from_pem_slice(cert_pem.as_bytes()).unwrap();
    let key = PrivateKeyDer::from_pem_slice(key_pem.as_bytes()).unwrap();
    let mut store = p12_keystore::KeyStore::new();
    store.add_entry(
        "azuifer",
        p12_keystore::KeyStoreEntry::PrivateKeyChain(p12_keystore::PrivateKeyChain::new(
            b"1".to_vec(),
            p12_keystore::PrivateKey::from_der(key.secret_der()).unwrap(),
            [p12_keystore::Certificate::from_der(certificate.as_ref()).unwrap()],
        )),
    );
    store.writer(password).write().unwrap()
}
fn serves_https_with(server: &Server, trusted_pem: &str) {
    let trusting = client(Some(trusted_pem.as_bytes()));
    let response = call(
        &trusting,
        Method::GET,
        &format!("{}/{ACCOUNT}?comp=list", server.url("queue")),
        None,
    );
    assert_eq!(response.status(), 403, "TLS worked and auth then refused");
    assert_eq!(error_code(&response), "AuthenticationFailed");
}

#[test]
fn certificates_load_from_pem_flags_pfx_environment_and_toml() {
    let directory = tempfile::tempdir().unwrap();
    let (cert_pem, key_pem) = self_signed();
    let (cert, key) = (
        directory.path().join("c.pem"),
        directory.path().join("k.pem"),
    );
    std::fs::write(&cert, &cert_pem).unwrap();
    std::fs::write(&key, &key_pem).unwrap();
    let (cert_arg, key_arg) = (cert.to_str().unwrap(), key.to_str().unwrap());

    let by_flags = Server::start(
        &["--in-memory", "--tls-cert", cert_arg, "--tls-key", key_arg],
        &[],
    );
    assert!(by_flags.url("blob").starts_with("https://"));
    assert!(
        !by_flags.other.contains_key("tls_cert"),
        "only generated certificates are announced"
    );
    serves_https_with(&by_flags, &cert_pem);
    drop(by_flags);

    let by_env = Server::start(
        &["--in-memory"],
        &[("AZUIFER_TLS_CERT", cert_arg), ("AZUIFER_TLS_KEY", key_arg)],
    );
    serves_https_with(&by_env, &cert_pem);
    drop(by_env);

    let file = directory.path().join("id.pfx");
    std::fs::write(&file, pfx(&cert_pem, &key_pem, "s3cret")).unwrap();
    let file_arg = file.to_str().unwrap();
    let by_pfx_env = Server::start(
        &["--in-memory", "--tls-pfx", file_arg],
        &[("AZUIFER_TLS_PFX_PASSWORD", "s3cret")],
    );
    serves_https_with(&by_pfx_env, &cert_pem);
    drop(by_pfx_env);

    let toml = directory.path().join("azuifer.toml");
    std::fs::write(
        &toml,
        format!("[tls]\ncert = {cert_arg:?}\nkey = {key_arg:?}\n\n[oauth]\nmode = \"basic\"\n"),
    )
    .unwrap();
    let by_toml = Server::start(&["--in-memory", "--config", toml.to_str().unwrap()], &[]);
    serves_https_with(&by_toml, &cert_pem);
    let response = call(
        &client(Some(cert_pem.as_bytes())),
        Method::GET,
        &format!("{}/{ACCOUNT}?comp=list", by_toml.url("queue")),
        Some(&basic_token()),
    );
    assert_eq!(response.status(), 200, "the TOML [oauth] table is honoured");
}

#[test]
fn invalid_tls_and_oauth_configuration_is_refused() {
    let directory = tempfile::tempdir().unwrap();
    let file = directory.path().join("x");
    std::fs::write(&file, "x").unwrap();
    let file_arg = file.to_str().unwrap();
    let custom_key = STANDARD.encode([5u8; 32]);
    let cases: &[(&[&str], &str)] = &[
        (&["--tls-cert", file_arg], "together"),
        (&["--tls-key", file_arg], "together"),
        (&["--tls-generate", "--tls-pfx", file_arg], "choose one"),
        (
            &[
                "--tls-generate",
                "--tls-cert",
                file_arg,
                "--tls-key",
                file_arg,
            ],
            "choose one",
        ),
        (&["--tls-pfx-password", "x"], "requires --tls-pfx"),
        (&["--tls-pfx", "missing.pfx"], "does not exist"),
        (
            &["--oauth", "basic", "--bind", "0.0.0.0"],
            "does not verify signatures",
        ),
        (&["--oauth", "jwks"], "--oauth-issuer"),
        (&["--oauth", "jwks", "--oauth-issuer", "i"], "--oauth-jwks"),
        (
            &["--oauth", "off", "--oauth-issuer", "i"],
            "require --oauth jwks",
        ),
        (&["--oauth", "weird"], "invalid value"),
    ];
    for (args, expected) in cases {
        let output = command(
            &["config", "validate"],
            &[("AZUIFER_ACCOUNT_KEY", &custom_key)],
        )
        .args(*args)
        .output()
        .unwrap();
        assert!(!output.status.success(), "{args:?} should be refused");
        let stderr = String::from_utf8_lossy(&output.stderr);
        assert!(stderr.contains(expected), "{args:?}: {stderr}");
    }
    let valid = command(
        &["config", "validate", "--tls-generate", "--oauth", "basic"],
        &[],
    )
    .output()
    .unwrap();
    assert!(valid.status.success());
    let jwks_file = directory.path().join("keys.json");
    std::fs::write(&jwks_file, jwks("k")).unwrap();
    let remote = command(
        &[
            "config",
            "validate",
            "--bind",
            "0.0.0.0",
            "--oauth",
            "jwks",
            "--oauth-issuer",
            "i",
            "--oauth-jwks",
        ],
        &[("AZUIFER_ACCOUNT_KEY", &custom_key)],
    )
    .arg(jwks_file)
    .output()
    .unwrap();
    assert!(
        remote.status.success(),
        "jwks mode is allowed beyond loopback"
    );

    // A JWKS that cannot be read stops startup rather than serving without keys.
    let mut missing = command(
        &[
            "serve",
            "--port",
            "0",
            "--admin-port",
            "0",
            "--in-memory",
            "--oauth",
            "jwks",
            "--oauth-issuer",
            "i",
            "--oauth-jwks",
        ],
        &[],
    );
    let output = missing
        .arg(directory.path().join("absent.json"))
        .output()
        .unwrap();
    assert!(!output.status.success());
    assert!(String::from_utf8_lossy(&output.stderr).contains("JWKS"));
}

#[test]
fn bearer_is_rejected_with_the_azure_error_unless_oauth_is_enabled() {
    let server = Server::start(
        &["--in-memory", "--tls-generate", "--hns-accounts", ACCOUNT],
        &[],
    );
    let trusting = client(Some(&server.generated_certificate()));
    let token = basic_token();
    for (service, url, headers) in list_requests(&server) {
        let response = send_list(&trusting, &url, &headers, Some(&token));
        assert_eq!(response.status(), 401, "{service}");
        assert_eq!(
            error_code(&response),
            "InvalidAuthenticationInfo",
            "{service}"
        );
        let challenge = response.headers()["www-authenticate"].to_str().unwrap();
        assert!(
            challenge.starts_with("Bearer authorization_uri=")
                && challenge.contains("resource_id=https://storage.azure.com"),
            "{service}: {challenge}"
        );
    }
}

#[test]
fn reduced_validation_accepts_unsigned_tokens_on_every_service() {
    let server = Server::start(
        &[
            "--in-memory",
            "--tls-generate",
            "--oauth",
            "basic",
            "--hns-accounts",
            ACCOUNT,
        ],
        &[],
    );
    let trusting = client(Some(&server.generated_certificate()));
    for audience in [
        STORAGE.to_owned(),
        format!("{STORAGE}/"),
        format!("https://{ACCOUNT}.blob.core.windows.net"),
    ] {
        let token = unsigned(&claims(ISSUER_V1, &audience, 3600));
        for (service, url, headers) in list_requests(&server) {
            let response = send_list(&trusting, &url, &headers, Some(&token));
            assert_eq!(response.status(), 200, "{service} with audience {audience}");
        }
    }
    // The address a client used is an accepted audience for that service.
    for (service, url, headers) in list_requests(&server) {
        let audience = format!("{}/{ACCOUNT}", server.url(service));
        let token = unsigned(&claims(ISSUER_V1, &audience, 3600));
        let response = send_list(&trusting, &url, &headers, Some(&token));
        assert_eq!(response.status(), 200, "{service} with audience {audience}");
    }
    let v2 = unsigned(&claims(
        "https://login.microsoftonline.com/72f988bf-86f1-41af-91ab-2d7cd011db47/v2.0",
        STORAGE,
        3600,
    ));
    for (service, url, headers) in list_requests(&server) {
        let response = send_list(&trusting, &url, &headers, Some(&v2));
        assert_eq!(response.status(), 200, "{service} v2.0 issuer");
    }

    // A bearer caller can use the data plane: create a container, put and get a blob.
    let token = basic_token();
    let container = format!("{}/{ACCOUNT}/bearer?restype=container", server.url("blob"));
    assert_eq!(
        call(&trusting, Method::PUT, &container, Some(&token)).status(),
        201
    );
    let blob = format!("{}/{ACCOUNT}/bearer/a.txt", server.url("blob"));
    let put = trusting
        .put(&blob)
        .header("x-ms-version", VERSION)
        .header("x-ms-blob-type", "BlockBlob")
        .header("authorization", format!("Bearer {token}"))
        .body("hello bearer")
        .send()
        .unwrap();
    assert_eq!(put.status(), 201);
    let got = call(&trusting, Method::GET, &blob, Some(&token));
    assert_eq!(got.text().unwrap(), "hello bearer");

    // Queue, Table, and File writes work as well.
    let queue = call(
        &trusting,
        Method::PUT,
        &format!("{}/{ACCOUNT}/jobs", server.url("queue")),
        Some(&token),
    );
    assert_eq!(queue.status(), 201);
    let table = trusting
        .post(format!("{}/{ACCOUNT}/Tables", server.url("table")))
        .header("x-ms-version", VERSION)
        .header("accept", "application/json;odata=nometadata")
        .header("prefer", "return-no-content")
        .header("content-type", "application/json")
        .header("authorization", format!("Bearer {token}"))
        .body(r#"{"TableName":"people"}"#)
        .send()
        .unwrap();
    assert_eq!(table.status(), 204);
    let share = call(
        &trusting,
        Method::PUT,
        &format!("{}/{ACCOUNT}/docs?restype=share", server.url("file")),
        Some(&token),
    );
    assert_eq!(share.status(), 201);
    let filesystem = trusting
        .put(format!(
            "{}/{ACCOUNT}/lake?resource=filesystem",
            server.url("dfs")
        ))
        .header("x-ms-version", VERSION)
        .header("authorization", format!("Bearer {token}"))
        .send()
        .unwrap();
    assert_eq!(filesystem.status(), 201);
}

#[test]
fn reduced_validation_rejects_malformed_expired_and_foreign_tokens() {
    let server = Server::start(&["--in-memory", "--tls-generate", "--oauth", "basic"], &[]);
    let trusting = client(Some(&server.generated_certificate()));
    let bad = [
        ("garbage", "not-a-jwt".to_owned()),
        ("expired", unsigned(&claims(ISSUER_V1, STORAGE, -3600))),
        (
            "not yet valid",
            unsigned(&{
                let mut claims = claims(ISSUER_V1, STORAGE, 7200);
                claims["nbf"] = json!(now() + 3600);
                claims
            }),
        ),
        (
            "foreign issuer",
            unsigned(&claims("https://issuer.example/t/", STORAGE, 3600)),
        ),
        (
            "wrong audience",
            unsigned(&claims(ISSUER_V1, "https://other.example", 3600)),
        ),
        (
            "other account",
            unsigned(&claims(
                ISSUER_V1,
                "https://other.blob.core.windows.net",
                3600,
            )),
        ),
        (
            "no expiry",
            unsigned(&json!({"iss": ISSUER_V1, "aud": STORAGE})),
        ),
    ];
    for (service, url, headers) in list_requests(&server) {
        for (name, token) in &bad {
            let response = send_list(&trusting, &url, &headers, Some(token));
            assert_eq!(response.status(), 401, "{service}: {name}");
            assert_eq!(
                error_code(&response),
                "InvalidAuthenticationInfo",
                "{service}: {name}"
            );
            assert!(
                response.headers().contains_key("www-authenticate"),
                "{service}"
            );
        }
    }
}

fn jwks_server(directory: &Path, extra: &[&str]) -> Server {
    let file = directory.join("keys.json");
    std::fs::write(&file, jwks("test-key")).unwrap();
    let mut args = vec![
        "--in-memory",
        "--tls-generate",
        "--oauth",
        "jwks",
        "--oauth-jwks",
        file.to_str().unwrap(),
        "--oauth-issuer",
        "https://issuer.example/,https://other-issuer.example",
    ];
    args.extend_from_slice(extra);
    Server::start(&args, &[])
}

#[test]
fn validated_mode_checks_signature_issuer_audience_and_roles() {
    let directory = tempfile::tempdir().unwrap();
    let server = jwks_server(
        directory.path(),
        &[
            "--oauth-audience",
            "api://azuifer,https://storage.azure.com",
        ],
    );
    let trusting = client(Some(&server.generated_certificate()));
    let issuer = "https://issuer.example/";
    let list = format!("{}/{ACCOUNT}?comp=list", server.url("blob"));
    let status = |token: &str| {
        call(&trusting, Method::GET, &list, Some(token))
            .status()
            .as_u16()
    };

    assert_eq!(status(&signed(&claims(issuer, STORAGE, 3600))), 200);
    assert_eq!(
        status(&signed(&claims(
            "https://other-issuer.example",
            "api://azuifer",
            3600
        ))),
        200
    );
    // Rejected: unsigned, tampered, wrong issuer or audience, expired.
    assert_eq!(status(&unsigned(&claims(issuer, STORAGE, 3600))), 401);
    assert_eq!(status(&signed(&claims(ISSUER_V1, STORAGE, 3600))), 401);
    assert_eq!(
        status(&signed(&claims(issuer, "https://other.example", 3600))),
        401
    );
    assert_eq!(status(&signed(&claims(issuer, STORAGE, -3600))), 401);
    let good = signed(&claims(issuer, STORAGE, 3600));
    let (head, rest) = good.split_once('.').unwrap();
    let (_, signature) = rest.split_once('.').unwrap();
    let forged = URL_SAFE_NO_PAD.encode(claims(issuer, STORAGE, 90_000).to_string());
    assert_eq!(status(&format!("{head}.{forged}.{signature}")), 401);
    let hs256 = format!(
        "{}.{}.{signature}",
        URL_SAFE_NO_PAD.encode(r#"{"alg":"HS256","kid":"test-key"}"#),
        URL_SAFE_NO_PAD.encode(claims(issuer, STORAGE, 3600).to_string())
    );
    assert_eq!(status(&hs256), 401);

    // Roles: Reader reads, Contributor writes, unrelated roles do neither.
    let with = |roles: &[&str]| signed(&with_roles(claims(issuer, STORAGE, 3600), roles));
    let container = format!("{}/{ACCOUNT}/roles?restype=container", server.url("blob"));
    let reader = with(&["Storage Blob Data Reader"]);
    let put = call(&trusting, Method::PUT, &container, Some(&reader));
    assert_eq!(put.status(), 403);
    assert_eq!(error_code(&put), "AuthorizationPermissionMismatch");
    assert_eq!(status(&reader), 200);
    let contributor = with(&["Storage Blob Data Contributor"]);
    assert_eq!(
        call(&trusting, Method::PUT, &container, Some(&contributor)).status(),
        201
    );
    let unrelated = with(&["Storage Queue Data Contributor"]);
    assert_eq!(status(&unrelated), 403);
    let queue_list = format!("{}/{ACCOUNT}?comp=list", server.url("queue"));
    assert_eq!(
        call(&trusting, Method::GET, &queue_list, Some(&unrelated)).status(),
        200
    );
    let queue_put = format!("{}/{ACCOUNT}/queue1", server.url("queue"));
    assert_eq!(
        call(&trusting, Method::PUT, &queue_put, Some(&reader)).status(),
        403
    );
    let table_list = send_list(
        &trusting,
        &format!("{}/{ACCOUNT}/Tables", server.url("table")),
        &[("accept", "application/json;odata=nometadata")],
        Some(&with(&["Storage Table Data Reader"])),
    );
    assert_eq!(table_list.status(), 200);
    let share = format!("{}/{ACCOUNT}/share1?restype=share", server.url("file"));
    let file_reader = with(&["Storage File Data SMB Share Reader"]);
    let denied = call(&trusting, Method::PUT, &share, Some(&file_reader));
    assert_eq!(denied.status(), 403);
}

/// Serves `body` as the response to every request on an ephemeral loopback port.
fn serve_json(body: String) -> String {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let port = listener.local_addr().unwrap().port();
    thread::spawn(move || {
        for stream in listener.incoming() {
            let Ok(mut stream) = stream else { continue };
            let mut seen = Vec::new();
            let mut byte = [0u8; 1];
            while !seen.ends_with(b"\r\n\r\n") && stream.read(&mut byte).is_ok_and(|n| n == 1) {
                seen.push(byte[0]);
            }
            let _ = write!(
                stream,
                "HTTP/1.1 200 OK\r\ncontent-type: application/json\r\ncontent-length: {}\r\nconnection: close\r\n\r\n{body}",
                body.len()
            );
        }
    });
    format!("http://127.0.0.1:{port}/keys")
}

#[test]
fn keys_load_from_a_jwks_url() {
    let url = serve_json(jwks("test-key"));
    let server = Server::start(
        &[
            "--in-memory",
            "--tls-generate",
            "--oauth",
            "jwks",
            "--oauth-jwks",
            &url,
            "--oauth-issuer",
            "https://issuer.example/",
        ],
        &[],
    );
    let trusting = client(Some(&server.generated_certificate()));
    let list = format!("{}/{ACCOUNT}?comp=list", server.url("blob"));
    let token = signed(&claims("https://issuer.example/", STORAGE, 3600));
    assert_eq!(
        call(&trusting, Method::GET, &list, Some(&token)).status(),
        200
    );
    let foreign = serve_json(jwks("another-key"));
    let other = Server::start(
        &[
            "--in-memory",
            "--tls-generate",
            "--oauth",
            "jwks",
            "--oauth-jwks",
            &foreign,
            "--oauth-issuer",
            "https://issuer.example/",
        ],
        &[],
    );
    let list = format!("{}/{ACCOUNT}?comp=list", other.url("blob"));
    let other_client = client(Some(&other.generated_certificate()));
    assert_eq!(
        call(&other_client, Method::GET, &list, Some(&token)).status(),
        401,
        "a token whose kid is not in the JWKS fails"
    );
}

fn xml_text<'a>(xml: &'a str, tag: &str) -> &'a str {
    let open = format!("<{tag}>");
    let start = xml
        .find(&open)
        .unwrap_or_else(|| panic!("missing XML element {tag}"))
        + open.len();
    let end = xml[start..].find(&format!("</{tag}>")).unwrap() + start;
    &xml[start..end]
}

fn sas_query(fields: &[(&str, &str)]) -> String {
    fields
        .iter()
        .map(|(name, value)| {
            format!(
                "{name}={}",
                percent_encoding::utf8_percent_encode(value, percent_encoding::NON_ALPHANUMERIC)
            )
        })
        .collect::<Vec<_>>()
        .join("&")
}

fn delegation_sas(
    key: &str,
    container: &str,
    blob: Option<&str>,
    permissions: &str,
    expiry: &str,
) -> String {
    contracts::sign_sas(key, (ACCOUNT, container, blob), permissions, expiry).unwrap()
}

fn iso(seconds_from_now: i64) -> String {
    let seconds = now() + seconds_from_now;
    let days = seconds.div_euclid(86_400);
    let rest = seconds.rem_euclid(86_400);
    // Howard Hinnant's civil-from-days algorithm.
    let shifted = days + 719_468;
    let era = shifted.div_euclid(146_097);
    let day_of_era = shifted.rem_euclid(146_097);
    let year_of_era =
        (day_of_era - day_of_era / 1460 + day_of_era / 36_524 - day_of_era / 146_096) / 365;
    let day_of_year = day_of_era - (365 * year_of_era + year_of_era / 4 - year_of_era / 100);
    let month_prime = (5 * day_of_year + 2) / 153;
    let day = day_of_year - (153 * month_prime + 2) / 5 + 1;
    let month = if month_prime < 10 {
        month_prime + 3
    } else {
        month_prime - 9
    };
    let year = year_of_era + era * 400 + i64::from(month <= 2);
    format!(
        "{year:04}-{month:02}-{day:02}T{:02}:{:02}:{:02}Z",
        rest / 3600,
        rest % 3600 / 60,
        rest % 60
    )
}

fn key_request(client: &Client, server: &Server, token: Option<&str>, body: &str) -> Response {
    let mut request = client
        .post(format!(
            "{}/{ACCOUNT}?restype=service&comp=userdelegationkey",
            server.url("blob")
        ))
        .header("x-ms-version", VERSION)
        .header("content-type", "application/xml")
        .body(body.to_owned());
    if let Some(token) = token {
        request = request.header("authorization", format!("Bearer {token}"));
    }
    request.send().unwrap()
}

#[test]
fn user_delegation_sas_is_issued_to_a_bearer_caller_and_honoured_by_blob() {
    let server = Server::start(
        &[
            "--in-memory",
            "--tls-generate",
            "--oauth",
            "basic",
            "--test-clock",
        ],
        &[],
    );
    let trusting = client(Some(&server.generated_certificate()));
    let token = unsigned(&claims(ISSUER_V1, STORAGE, 30 * 86_400));
    let container = format!(
        "{}/{ACCOUNT}/delegated?restype=container",
        server.url("blob")
    );
    assert_eq!(
        call(&trusting, Method::PUT, &container, Some(&token)).status(),
        201
    );
    let blob_url = format!("{}/{ACCOUNT}/delegated/a.txt", server.url("blob"));
    let put = trusting
        .put(&blob_url)
        .header("x-ms-version", VERSION)
        .header("x-ms-blob-type", "BlockBlob")
        .header("authorization", format!("Bearer {token}"))
        .body("delegated bytes")
        .send()
        .unwrap();
    assert_eq!(put.status(), 201);

    // Only a bearer token may ask for a key.
    let body = format!(
        "<KeyInfo><Start>{}</Start><Expiry>{}</Expiry></KeyInfo>",
        iso(-60),
        iso(86_400)
    );
    let anonymous = key_request(&trusting, &server, None, &body);
    assert_eq!(anonymous.status(), 403);
    let too_long = key_request(
        &trusting,
        &server,
        Some(&token),
        &format!(
            "<KeyInfo><Start>{}</Start><Expiry>{}</Expiry></KeyInfo>",
            iso(-60),
            iso(8 * 86_400)
        ),
    );
    assert_eq!(too_long.status(), 400);
    assert_eq!(error_code(&too_long), "InvalidInput");
    let malformed = key_request(&trusting, &server, Some(&token), "<KeyInfo>");
    assert_eq!(malformed.status(), 400);

    let response = key_request(&trusting, &server, Some(&token), &body);
    assert_eq!(response.status(), 200);
    let key = response.text().unwrap();
    assert_eq!(
        xml_text(&key, "SignedOid"),
        "11111111-2222-3333-4444-555555555555"
    );
    assert_eq!(
        xml_text(&key, "SignedTid"),
        "72f988bf-86f1-41af-91ab-2d7cd011db47"
    );
    assert_eq!(xml_text(&key, "SignedService"), "b");

    let expiry = iso(3600);
    let sas = delegation_sas(&key, "delegated", Some("a.txt"), "r", &expiry);
    let read = trusting.get(format!("{blob_url}?{sas}")).send().unwrap();
    assert_eq!(read.status(), 200);
    assert_eq!(read.text().unwrap(), "delegated bytes");

    // A container SAS lists; a read-only blob SAS does not write; tampering fails.
    let list_sas = delegation_sas(&key, "delegated", None, "rl", &expiry);
    let listing = trusting
        .get(format!(
            "{}/{ACCOUNT}/delegated?restype=container&comp=list&{list_sas}",
            server.url("blob")
        ))
        .send()
        .unwrap();
    assert_eq!(listing.status(), 200);
    assert!(listing.text().unwrap().contains("<Name>a.txt</Name>"));
    let write = trusting
        .put(format!("{blob_url}?{sas}"))
        .header("x-ms-blob-type", "BlockBlob")
        .body("nope")
        .send()
        .unwrap();
    assert_eq!(write.status(), 403);
    assert_eq!(error_code(&write), "AuthorizationPermissionMismatch");
    let tampered = sas.replace("sp=r", "sp=rw");
    let forged = trusting
        .get(format!("{blob_url}?{tampered}"))
        .send()
        .unwrap();
    assert_eq!(forged.status(), 403);
    assert_eq!(error_code(&forged), "AuthenticationFailed");
    let other_blob = trusting
        .get(format!(
            "{}/{ACCOUNT}/delegated/b.txt?{sas}",
            server.url("blob")
        ))
        .send()
        .unwrap();
    assert_eq!(other_blob.status(), 403);

    // A key the server never issued, even with a valid-looking signature, fails.
    let foreign = key.replace(xml_text(&key, "Value"), &STANDARD.encode([9u8; 32]));
    let unissued = delegation_sas(&foreign, "delegated", Some("a.txt"), "r", &expiry);
    assert_eq!(
        trusting
            .get(format!("{blob_url}?{unissued}"))
            .send()
            .unwrap()
            .status(),
        403
    );

    // The SAS lapses with its own window, and always with the key's.
    let advance = |seconds: u64| {
        trusting
            .post(format!(
                "{}/_azuifer/clock/advance?seconds={seconds}",
                server.url("blob")
            ))
            .send()
            .unwrap()
    };
    assert_eq!(advance(7200).status(), 200);
    let expired = trusting.get(format!("{blob_url}?{sas}")).send().unwrap();
    assert_eq!(expired.status(), 403, "the SAS expired two hours ago");
    let long_sas = delegation_sas(&key, "delegated", Some("a.txt"), "r", &iso(10 * 86_400));
    assert_eq!(
        trusting
            .get(format!("{blob_url}?{long_sas}"))
            .send()
            .unwrap()
            .status(),
        200,
        "the key is still valid a few hours in"
    );
    assert_eq!(advance(2 * 86_400).status(), 200);
    let lapsed = trusting
        .get(format!("{blob_url}?{long_sas}"))
        .send()
        .unwrap();
    assert_eq!(lapsed.status(), 403, "the key itself has expired");
}

#[test]
fn delegation_keys_follow_the_token_roles() {
    let directory = tempfile::tempdir().unwrap();
    let server = jwks_server(directory.path(), &[]);
    let trusting = client(Some(&server.generated_certificate()));
    let issuer = "https://issuer.example/";
    let body = format!("<KeyInfo><Expiry>{}</Expiry></KeyInfo>", iso(3600));
    let reader = signed(&with_roles(
        claims(issuer, STORAGE, 3600),
        &["Storage Blob Data Reader"],
    ));
    assert_eq!(
        key_request(&trusting, &server, Some(&reader), &body).status(),
        200
    );
    let unrelated = signed(&with_roles(
        claims(issuer, STORAGE, 3600),
        &["Storage Table Data Reader"],
    ));
    assert_eq!(
        key_request(&trusting, &server, Some(&unrelated), &body).status(),
        403
    );
}
