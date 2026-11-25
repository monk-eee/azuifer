//! Host-style addressing (`{account}.{service}.{domain}`) for Queue, Table, Files and DFS,
//! against the real binary. Requests connect to the loopback listener and name the account in
//! the `Host` header, so the tests do not depend on the platform resolving `*.localhost`.

use base64::{Engine as _, engine::general_purpose::STANDARD};
use hmac::{Hmac, Mac as _};
use reqwest::{Method, Url, blocking::Client};
use sha2::Sha256;
use std::{
    collections::BTreeMap,
    io::{BufRead as _, BufReader},
    process::{Child, Command, Stdio},
    time::{Duration, SystemTime},
};

const ACCOUNT: &str = "testaccount";
const VERSION: &str = "2023-11-03";
const KEY: [u8; 32] = [41; 32];
const FAR_FUTURE: &str = "2100-01-01T00:00:00Z";

struct Emulator {
    child: Child,
    urls: BTreeMap<String, String>,
    client: Client,
}

impl Emulator {
    fn start() -> Self {
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
        let mut child = command
            .env("AZUIFER_ACCOUNT_NAME", ACCOUNT)
            .env("AZUIFER_ACCOUNT_KEY", STANDARD.encode(KEY))
            .args([
                "serve",
                "--port",
                "0",
                "--admin-port",
                "0",
                "--in-memory",
                "--hns-accounts",
                ACCOUNT,
                "--shutdown-on-stdin-eof",
            ])
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .spawn()
            .expect("start Azuifer");
        let mut lines = BufReader::new(child.stdout.take().expect("piped stdout")).lines();
        let mut urls = BTreeMap::new();
        for line in lines.by_ref() {
            let line = line.expect("startup line");
            let (name, url) = line.split_once("_url=").expect("a listener URL line");
            urls.insert(name.to_owned(), url.to_owned());
            if name == "admin" {
                break;
            }
        }
        std::thread::spawn(move || lines.for_each(drop));
        Self {
            child,
            urls,
            client: Client::builder()
                .no_proxy()
                .timeout(Duration::from_secs(10))
                .build()
                .unwrap(),
        }
    }

    fn port(&self, service: &str) -> &str {
        self.urls[service].rsplit(':').next().unwrap()
    }

    /// The URL to connect to and the `Host` to present for one addressing style.
    fn target(&self, service: &str, style: Style, target: &str) -> (Url, Option<String>) {
        let base = &self.urls[service];
        match style {
            Style::Path => (
                Url::parse(&format!("{base}/{ACCOUNT}{target}")).unwrap(),
                None,
            ),
            Style::PathVia(other) => (
                Url::parse(&format!("{base}/{ACCOUNT}{target}")).unwrap(),
                Some(format!(
                    "{ACCOUNT}.{other}.localhost:{}",
                    self.port(service)
                )),
            ),
            Style::Host(label) => (
                Url::parse(&format!("{base}{target}")).unwrap(),
                Some(format!(
                    "{label}.{service}.localhost:{}",
                    self.port(service)
                )),
            ),
        }
    }

    fn send(
        &self,
        service: &str,
        style: Style,
        method: &str,
        target: &str,
        headers: &[(&str, &str)],
        body: &str,
    ) -> Reply {
        let method = Method::from_bytes(method.as_bytes()).unwrap();
        let (url, host) = self.target(service, style, target);
        let mut all = BTreeMap::from([
            (
                "x-ms-date".to_owned(),
                httpdate::fmt_http_date(SystemTime::now()),
            ),
            ("x-ms-version".to_owned(), VERSION.to_owned()),
        ]);
        if !body.is_empty() {
            all.insert("content-length".into(), body.len().to_string());
        }
        for (name, value) in headers {
            all.insert((*name).into(), (*value).into());
        }
        let authorization = if service == "table" {
            sign_table(&method, &url, &all)
        } else {
            sign(&method, &url, &all)
        };
        all.insert("authorization".into(), authorization);
        self.dispatch(method, url, host, &all, body)
    }

    /// A request that carries a SAS in its query and no Authorization header.
    fn send_sas(
        &self,
        service: &str,
        style: Style,
        target: &str,
        token: &[(String, String)],
    ) -> Reply {
        let (mut url, host) = self.target(service, style, target);
        url.query_pairs_mut().extend_pairs(token);
        let headers = BTreeMap::from([("x-ms-version".to_owned(), VERSION.to_owned())]);
        self.dispatch(Method::GET, url, host, &headers, "")
    }

    fn dispatch(
        &self,
        method: Method,
        url: Url,
        host: Option<String>,
        headers: &BTreeMap<String, String>,
        body: &str,
    ) -> Reply {
        let mut request = self.client.request(method.clone(), url);
        if let Some(host) = host {
            request = request.header("host", host);
        }
        for (name, value) in headers {
            request = request.header(name, value);
        }
        if matches!(method, Method::PUT | Method::POST) {
            request = request.body(body.to_owned());
        }
        let response = request.send().expect("HTTP request completed");
        Reply {
            status: response.status().as_u16(),
            error_code: response
                .headers()
                .get("x-ms-error-code")
                .map(|value| value.to_str().unwrap().to_owned()),
            body: response.text().unwrap(),
        }
    }
}

impl Drop for Emulator {
    fn drop(&mut self) {
        drop(self.child.stdin.take());
        let _ = self.child.wait();
    }
}

#[derive(Clone, Copy)]
enum Style {
    Path,
    /// The first host label: the account, or `{account}-secondary` for Table.
    Host(&'static str),
    /// A path-style URL presented with another service's host-style `Host`.
    PathVia(&'static str),
}

const HOSTED: Style = Style::Host(ACCOUNT);

struct Reply {
    status: u16,
    error_code: Option<String>,
    body: String,
}

fn expect(reply: Reply, status: u16) -> Reply {
    assert_eq!(
        reply.status, status,
        "{:?}: {}",
        reply.error_code, reply.body
    );
    reply
}

fn expect_auth_failure(reply: Reply) {
    assert!(
        matches!(reply.status, 403),
        "expected 403, got {} {:?}: {}",
        reply.status,
        reply.error_code,
        reply.body
    );
}

fn hmac(message: &str) -> String {
    let mut mac = Hmac::<Sha256>::new_from_slice(&KEY).unwrap();
    mac.update(message.as_bytes());
    STANDARD.encode(mac.finalize().into_bytes())
}

/// Shared Key for Queue, Files and DFS (the Blob scheme): the account name followed by the
/// path exactly as sent.
fn sign(method: &Method, url: &Url, headers: &BTreeMap<String, String>) -> String {
    let value = |name| headers.get(name).map_or("", String::as_str);
    let extensions: String = headers
        .iter()
        .filter(|(name, _)| name.starts_with("x-ms-"))
        .map(|(name, value)| format!("{name}:{value}\n"))
        .collect();
    let query: BTreeMap<_, _> = url.query_pairs().collect();
    let query: String = query
        .iter()
        .map(|(name, value)| format!("\n{name}:{value}"))
        .collect();
    let message = format!(
        "{}\n\n\n{}\n\n{}\n\n\n\n\n\n\n{extensions}/{ACCOUNT}{}{query}",
        method.as_str(),
        value("content-length"),
        value("content-type"),
        url.path()
    );
    format!("SharedKey {ACCOUNT}:{}", hmac(&message))
}

/// Shared Key for Table: `Date` is the `x-ms-date` value and only `comp` is signed.
fn sign_table(method: &Method, url: &Url, headers: &BTreeMap<String, String>) -> String {
    let value = |name| headers.get(name).map_or("", String::as_str);
    let comp = url
        .query_pairs()
        .find(|(name, _)| name == "comp")
        .map_or_else(String::new, |(_, value)| format!("?comp={value}"));
    let message = format!(
        "{}\n\n{}\n{}\n/{ACCOUNT}{}{comp}",
        method.as_str(),
        value("content-type"),
        value("x-ms-date"),
        url.path()
    );
    format!("SharedKey {ACCOUNT}:{}", hmac(&message))
}

/// A SAS for a whole account that covers the service, container and object levels.
fn account_sas(services: &str) -> Vec<(String, String)> {
    let message =
        format!("{ACCOUNT}\nrwdlacup\n{services}\nsco\n\n{FAR_FUTURE}\n\n\n{VERSION}\n\n");
    [
        ("sv", VERSION),
        ("ss", services),
        ("srt", "sco"),
        ("sp", "rwdlacup"),
        ("se", FAR_FUTURE),
    ]
    .into_iter()
    .map(|(name, value)| (name.to_owned(), value.to_owned()))
    .chain([("sig".to_owned(), hmac(&message))])
    .collect()
}

const MESSAGE: &str = "<QueueMessage><MessageText>hello</MessageText></QueueMessage>";

#[test]
fn queue_accepts_host_style_urls_and_signs_the_path_as_sent() {
    let server = Emulator::start();
    let host = server.port("queue");
    expect(server.send("queue", HOSTED, "PUT", "/hosted", &[], ""), 201);
    expect(
        server.send("queue", HOSTED, "POST", "/hosted/messages", &[], MESSAGE),
        201,
    );
    // Path-style addressing reaches the same queue.
    let peek = expect(
        server.send(
            "queue",
            Style::Path,
            "GET",
            "/hosted/messages?peekonly=true",
            &[],
            "",
        ),
        200,
    );
    assert!(peek.body.contains("<MessageText>hello</MessageText>"));
    let got = expect(
        server.send("queue", HOSTED, "GET", "/hosted/messages", &[], ""),
        200,
    );
    assert!(got.body.contains("<MessageText>hello</MessageText>"));

    let listing = expect(
        server.send("queue", HOSTED, "GET", "/?comp=list", &[], ""),
        200,
    );
    assert!(
        listing.body.contains(&format!(
            "ServiceEndpoint=\"http://{ACCOUNT}.queue.localhost:{host}/\""
        )),
        "{}",
        listing.body
    );
    assert!(listing.body.contains("<Name>hosted</Name>"));
}

#[test]
fn queue_host_style_rejects_a_signature_over_the_wrong_path() {
    let server = Emulator::start();
    // The path-style signature covers `/{account}/{account}/hosted`; a host-style request is
    // signed over `/{account}/hosted`, so each style fails against the other's signature.
    let (url, _) = server.target("queue", Style::Path, "/hosted?comp=metadata");
    let headers = BTreeMap::from([
        (
            "x-ms-date".to_owned(),
            httpdate::fmt_http_date(SystemTime::now()),
        ),
        ("x-ms-version".to_owned(), VERSION.to_owned()),
    ]);
    let path_style_signature = sign(&Method::GET, &url, &headers);
    let mut request = server
        .client
        .get(format!("{}/hosted?comp=metadata", server.urls["queue"]))
        .header(
            "host",
            format!("{ACCOUNT}.queue.localhost:{}", server.port("queue")),
        )
        .header("authorization", path_style_signature);
    for (name, value) in &headers {
        request = request.header(name, value);
    }
    let reply = request.send().unwrap();
    assert_eq!(reply.status(), 403);
    assert_eq!(reply.headers()["x-ms-error-code"], "AuthenticationFailed");
}

#[test]
fn queue_sas_validates_on_a_host_style_url() {
    let server = Emulator::start();
    expect(server.send("queue", HOSTED, "PUT", "/sassy", &[], ""), 201);
    expect(
        server.send("queue", HOSTED, "POST", "/sassy/messages", &[], MESSAGE),
        201,
    );
    let account = account_sas("q");
    let listing = expect(
        server.send_sas("queue", HOSTED, "/?comp=list", &account),
        200,
    );
    assert!(listing.body.contains("<Name>sassy</Name>"));

    let message = format!("r\n\n{FAR_FUTURE}\n/queue/{ACCOUNT}/sassy\n\n\n\n{VERSION}");
    let service = [
        ("sv", VERSION.to_owned()),
        ("sp", "r".to_owned()),
        ("se", FAR_FUTURE.to_owned()),
        ("sig", hmac(&message)),
    ]
    .map(|(name, value)| (name.to_owned(), value))
    .to_vec();
    let peek = expect(
        server.send_sas("queue", HOSTED, "/sassy/messages?peekonly=true", &service),
        200,
    );
    assert!(peek.body.contains("<MessageText>hello</MessageText>"));
    let mut forged = service;
    forged.last_mut().unwrap().1 = hmac("forged");
    expect_auth_failure(server.send_sas("queue", HOSTED, "/sassy/messages?peekonly=true", &forged));
}

#[test]
fn table_accepts_host_style_urls_including_the_secondary_location() {
    let server = Emulator::start();
    let host = server.port("table");
    let json = [
        ("content-type", "application/json"),
        ("accept", "application/json;odata=minimalmetadata"),
    ];
    let created = expect(
        server.send(
            "table",
            HOSTED,
            "POST",
            "/Tables",
            &json,
            r#"{"TableName":"hosted"}"#,
        ),
        201,
    );
    assert!(
        created.body.contains(&format!(
            "http://{ACCOUNT}.table.localhost:{host}/$metadata#Tables/@Element"
        )),
        "{}",
        created.body
    );
    expect(
        server.send(
            "table",
            HOSTED,
            "POST",
            "/hosted",
            &json,
            r#"{"PartitionKey":"p","RowKey":"r","Value":"v"}"#,
        ),
        201,
    );
    let entity = expect(
        server.send(
            "table",
            HOSTED,
            "GET",
            "/hosted(PartitionKey='p',RowKey='r')",
            &json,
            "",
        ),
        200,
    );
    assert!(entity.body.contains("\"Value\":\"v\""));
    let same = expect(
        server.send(
            "table",
            Style::Path,
            "GET",
            "/hosted(PartitionKey='p',RowKey='r')",
            &json,
            "",
        ),
        200,
    );
    assert!(same.body.contains("\"Value\":\"v\""));

    let secondary = Style::Host("testaccount-secondary");
    expect(
        server.send("table", secondary, "GET", "/Tables", &json, ""),
        200,
    );
    let write = server.send(
        "table",
        secondary,
        "POST",
        "/hosted",
        &json,
        r#"{"PartitionKey":"p","RowKey":"r2"}"#,
    );
    assert_eq!(write.status, 405, "{}", write.body);

    let account = account_sas("t");
    let tables = expect(server.send_sas("table", HOSTED, "/Tables", &account), 200);
    assert!(tables.body.contains("hosted"));
}

#[test]
fn files_accepts_host_style_urls() {
    let server = Emulator::start();
    let host = server.port("file");
    expect(
        server.send("file", HOSTED, "PUT", "/hosted?restype=share", &[], ""),
        201,
    );
    expect(
        server.send(
            "file",
            HOSTED,
            "PUT",
            "/hosted/doc.txt",
            &[("x-ms-type", "file"), ("x-ms-content-length", "5")],
            "",
        ),
        201,
    );
    expect(
        server.send(
            "file",
            HOSTED,
            "PUT",
            "/hosted/doc.txt?comp=range",
            &[("x-ms-range", "bytes=0-4"), ("x-ms-write", "update")],
            "hello",
        ),
        201,
    );
    let read = expect(
        server.send("file", HOSTED, "GET", "/hosted/doc.txt", &[], ""),
        200,
    );
    assert_eq!(read.body, "hello");
    let path_style = expect(
        server.send("file", Style::Path, "GET", "/hosted/doc.txt", &[], ""),
        200,
    );
    assert_eq!(path_style.body, "hello");

    let listing = expect(
        server.send("file", HOSTED, "GET", "/?comp=list", &[], ""),
        200,
    );
    assert!(
        listing.body.contains(&format!(
            "ServiceEndpoint=\"http://{ACCOUNT}.file.localhost:{host}/\""
        )),
        "{}",
        listing.body
    );
    let account = account_sas("f");
    let shares = expect(
        server.send_sas("file", HOSTED, "/?comp=list", &account),
        200,
    );
    assert!(shares.body.contains("<Name>hosted</Name>"));
    expect_auth_failure(server.send_sas(
        "file",
        HOSTED,
        "/?comp=list",
        &[("sv".into(), VERSION.into()), ("sig".into(), "AAAA".into())],
    ));
}

#[test]
fn dfs_accepts_host_style_urls() {
    let server = Emulator::start();
    expect(
        server.send("dfs", HOSTED, "PUT", "/hosted?resource=filesystem", &[], ""),
        201,
    );
    expect(
        server.send(
            "dfs",
            HOSTED,
            "PUT",
            "/hosted/dir?resource=directory",
            &[],
            "",
        ),
        201,
    );
    let paths = expect(
        server.send(
            "dfs",
            HOSTED,
            "GET",
            "/hosted?resource=filesystem&recursive=false",
            &[],
            "",
        ),
        200,
    );
    assert!(paths.body.contains("\"name\":\"dir\""), "{}", paths.body);
    let filesystems = expect(
        server.send("dfs", HOSTED, "GET", "/?resource=account", &[], ""),
        200,
    );
    assert!(filesystems.body.contains("\"name\":\"hosted\""));
    expect(
        server.send("dfs", Style::Path, "HEAD", "/hosted/dir", &[], ""),
        200,
    );
}

#[test]
fn a_host_for_another_service_is_not_host_style() {
    let server = Emulator::start();
    // `{account}.table.localhost` on the Queue listener names no account for Queue, so the
    // request keeps its path-style meaning.
    let listing = expect(
        server.send(
            "queue",
            Style::PathVia("table"),
            "GET",
            "/?comp=list",
            &[],
            "",
        ),
        200,
    );
    assert!(listing.body.contains("<EnumerationResults"));
}
