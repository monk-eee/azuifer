use base64::{Engine as _, engine::general_purpose::STANDARD};
use hmac::{Hmac, Mac as _};
use reqwest::{
    Method, Url,
    blocking::{Client, Response},
};
use sha2::Sha256;
use std::{
    cell::Cell,
    collections::BTreeMap,
    fs,
    io::{BufRead as _, BufReader, Read as _, Write as _},
    net::TcpStream,
    path::{Path, PathBuf},
    process::{Child, Command, ExitStatus, Stdio},
    sync::{Barrier, mpsc},
    thread,
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};

const ACCOUNT: &str = "testaccount";
const VERSION: &str = "2023-11-03";
const CONTAINER: &str = "/testaccount/container?restype=container";
const BLOB: &str = "/testaccount/container/docs/a%26b.txt";
const KEY: [u8; 32] = [41; 32];

thread_local! {
    // Seconds the test clock has been advanced on this test's server. Every test
    // runs on its own thread, so signed dates follow that test's server clock.
    static CLOCK_OFFSET: Cell<u64> = const { Cell::new(0) };
}

struct TestProcess(Child);

impl TestProcess {
    fn shutdown(&mut self) -> std::io::Result<Option<ExitStatus>> {
        drop(self.0.stdin.take());
        let deadline = Instant::now() + Duration::from_secs(5);
        loop {
            if let Some(status) = self.0.try_wait()? {
                return Ok(Some(status));
            }
            if Instant::now() >= deadline {
                return Ok(None);
            }
            thread::sleep(Duration::from_millis(10));
        }
    }

    fn crash(&mut self) {
        self.0.kill().expect("terminate the running emulator");
        self.0.wait().expect("reap the crashed emulator");
    }
}

impl Drop for TestProcess {
    fn drop(&mut self) {
        if !matches!(self.shutdown(), Ok(Some(_))) {
            let _ = self.0.kill();
            let _ = self.0.wait();
        }
    }
}

struct Emulator {
    process: TestProcess,
    blob: Option<String>,
    dfs: Option<String>,
    admin: String,
    client: Client,
}

fn emulator_command() -> Command {
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
    command
        .env("AZUIFER_ACCOUNT_NAME", ACCOUNT)
        .env("AZUIFER_ACCOUNT_KEY", STANDARD.encode(KEY));
    command
}

impl Emulator {
    fn start(location: Option<&Path>, extra: &[&str]) -> Self {
        Self::start_services(location, "blob", extra)
    }

    fn start_services(location: Option<&Path>, services: &str, extra: &[&str]) -> Self {
        let mut command = emulator_command();
        command.args([
            "serve",
            "--port",
            "0",
            "--admin-port",
            "0",
            "--services",
            services,
        ]);
        if let Some(location) = location {
            command.arg("--location").arg(location);
        } else {
            command.arg("--in-memory");
        }
        command.args(extra);
        Self::spawn(command)
    }

    fn spawn(mut command: Command) -> Self {
        command
            .arg("--shutdown-on-stdin-eof")
            .stdin(Stdio::piped())
            .stdout(Stdio::piped());
        let mut process = TestProcess(command.spawn().expect("start Azuifer"));
        let stdout = process.0.stdout.take().expect("piped startup addresses");
        let (sender, receiver) = mpsc::channel();
        thread::spawn(move || {
            let addresses = || {
                let mut lines = BTreeMap::new();
                for line in BufReader::new(stdout).lines().take(6) {
                    let line = line?;
                    let (name, url) = line
                        .split_once("_url=")
                        .ok_or_else(|| std::io::Error::other("expected a listener URL"))?;
                    lines.insert(name.to_owned(), url.to_owned());
                    if name == "admin" {
                        break;
                    }
                }
                Ok::<_, std::io::Error>(lines)
            };
            sender.send(addresses()).ok();
        });
        let mut lines = receiver
            .recv_timeout(Duration::from_secs(10))
            .expect("server bound its ports")
            .expect("read startup addresses");
        let client = Client::builder()
            .no_proxy()
            .timeout(Duration::from_secs(10))
            .build()
            .unwrap();
        let started = Self {
            process,
            blob: lines.remove("blob"),
            dfs: lines.remove("dfs"),
            admin: lines.remove("admin").expect("admin listener URL"),
            client,
        };
        assert_eq!(
            started
                .client
                .get(format!("{}/readyz", started.admin))
                .send()
                .unwrap()
                .text()
                .unwrap(),
            "ready\n"
        );
        started
    }

    fn request(&self, method: Method, path: &str, extra: &[(&str, &str)], body: &[u8]) -> Response {
        self.request_with_key(method, path, extra, body, &KEY)
    }

    fn request_with_key(
        &self,
        method: Method,
        path: &str,
        extra: &[(&str, &str)],
        body: &[u8],
        key: &[u8],
    ) -> Response {
        self.request_at(self.blob_url(), method, path, extra, body, key)
    }

    fn blob_url(&self) -> &str {
        self.blob.as_deref().expect("Blob listener URL")
    }

    fn dfs(&self, method: Method, path: &str, extra: &[(&str, &str)], body: &[u8]) -> Response {
        self.request_at(
            self.dfs.as_deref().expect("DFS listener URL"),
            method,
            path,
            extra,
            body,
            &KEY,
        )
    }

    fn request_at(
        &self,
        endpoint: &str,
        method: Method,
        path: &str,
        extra: &[(&str, &str)],
        body: &[u8],
        key: &[u8],
    ) -> Response {
        let url = Url::parse(&format!("{endpoint}{path}")).unwrap();
        let length = (method == Method::PUT).then_some(body.len());
        let headers = signed(&method, &url, extra, length, key);
        let mut request = self.client.request(method, url);
        for (name, value) in headers {
            request = request.header(name, value);
        }
        if length.is_some() {
            request = request.body(body.to_vec());
        }
        request.send().expect("HTTP request completed")
    }

    fn create_container(&self) {
        let response = self.request(Method::PUT, CONTAINER, &[], b"");
        assert_eq!(response.status(), 201);
        assert_eq!(response.headers()["x-ms-version"], VERSION);
        assert_eq!(response.headers()["x-ms-request-id"].len(), 32);
        assert!(response.headers().contains_key("last-modified"));
    }

    /// A request without Authorization, optionally with extra headers (such as `host` or `origin`).
    fn raw(&self, method: Method, path: &str, headers: &[(&str, &str)], body: &[u8]) -> Response {
        let url = Url::parse(&format!("{}{path}", self.blob_url())).unwrap();
        let mut request = self.client.request(method.clone(), url);
        for (name, value) in headers {
            request = request.header(*name, *value);
        }
        if method == Method::PUT {
            request = request.body(body.to_vec());
        }
        request.send().expect("HTTP request completed")
    }

    /// Moves the server's `--test-clock` forward and keeps signed dates in step.
    fn advance(&self, seconds: u64) {
        let response = self
            .client
            .post(format!(
                "{}/_azuifer/clock/advance?seconds={seconds}",
                self.blob_url()
            ))
            .send()
            .unwrap();
        assert_eq!(response.status(), 200);
        CLOCK_OFFSET.set(CLOCK_OFFSET.get() + seconds);
    }

    fn clocked() -> Self {
        CLOCK_OFFSET.set(0);
        Self::start(None, &["--test-clock"])
    }

    fn lease(&self, path: &str, extra: &[(&str, &str)]) -> Response {
        self.request(Method::PUT, path, extra, b"")
    }

    fn put(&self, path: &str, extra: &[(&str, &str)], bytes: &[u8]) -> Response {
        let mut headers = vec![("x-ms-blob-type", "BlockBlob")];
        headers.extend_from_slice(extra);
        self.request(Method::PUT, path, &headers, bytes)
    }

    fn start_partial_upload(&self, path: &str, length: usize, bytes: &[u8]) -> TcpStream {
        let url = Url::parse(&format!("{}{path}", self.blob_url())).unwrap();
        let address = url.socket_addrs(|| None).unwrap()[0];
        let mut socket = TcpStream::connect(address).unwrap();
        let headers = signed(
            &Method::PUT,
            &url,
            &[("x-ms-blob-type", "BlockBlob")],
            Some(length),
            &KEY,
        );
        write!(
            socket,
            "PUT {path} HTTP/1.1\r\nHost: {address}\r\nConnection: close\r\n"
        )
        .unwrap();
        for (name, value) in headers {
            write!(socket, "{name}: {value}\r\n").unwrap();
        }
        socket.write_all(b"\r\n").unwrap();
        socket.write_all(bytes).unwrap();
        socket
    }
}

fn signed(
    method: &Method,
    url: &Url,
    extra: &[(&str, &str)],
    length: Option<usize>,
    key: &[u8],
) -> BTreeMap<String, String> {
    let mut headers: BTreeMap<String, String> = BTreeMap::from([
        ("x-ms-date".into(), httpdate::fmt_http_date(server_now())),
        ("x-ms-version".into(), VERSION.into()),
    ]);
    if let Some(length) = length {
        headers.insert("content-length".into(), length.to_string());
    }
    for (name, value) in extra {
        headers.insert((*name).into(), (*value).into());
    }
    let value = |name| headers.get(name).map_or("", String::as_str);
    let lines = [
        method.as_str(),
        value("content-encoding"),
        value("content-language"),
        if length.is_none_or(|length| length == 0) {
            ""
        } else {
            value("content-length")
        },
        value("content-md5"),
        value("content-type"),
        "",
        value("if-modified-since"),
        value("if-match"),
        value("if-none-match"),
        value("if-unmodified-since"),
        value("range"),
    ];
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
        "{}\n{extensions}/{ACCOUNT}{}{query}",
        lines.join("\n"),
        url.path()
    );
    let mut mac = Hmac::<Sha256>::new_from_slice(key).unwrap();
    mac.update(message.as_bytes());
    let signature = STANDARD.encode(mac.finalize().into_bytes());
    headers.insert(
        "authorization".into(),
        format!("SharedKey {ACCOUNT}:{signature}"),
    );
    headers
}

/// The test server's current time: the real clock plus how far this test advanced it.
fn server_now() -> SystemTime {
    SystemTime::now() + Duration::from_secs(CLOCK_OFFSET.get())
}

fn unix_seconds(time: SystemTime) -> u64 {
    time.duration_since(UNIX_EPOCH).unwrap().as_secs()
}

/// `YYYY-MM-DDThh:mm:ssZ` for a Unix time (Howard Hinnant's civil-from-days).
fn iso8601(seconds: u64) -> String {
    let days = (seconds / 86_400) as i64;
    let rest = seconds % 86_400;
    let z = days + 719_468;
    let era = z.div_euclid(146_097);
    let day_of_era = z - era * 146_097;
    let year_of_era =
        (day_of_era - day_of_era / 1460 + day_of_era / 36_524 - day_of_era / 146_096) / 365;
    let day_of_year = day_of_era - (365 * year_of_era + year_of_era / 4 - year_of_era / 100);
    let shifted_month = (5 * day_of_year + 2) / 153;
    let day = day_of_year - (153 * shifted_month + 2) / 5 + 1;
    let month = if shifted_month < 10 {
        shifted_month + 3
    } else {
        shifted_month - 9
    };
    let year = year_of_era + era * 400 + i64::from(month <= 2);
    format!(
        "{year:04}-{month:02}-{day:02}T{:02}:{:02}:{:02}Z",
        rest / 3600,
        rest % 3600 / 60,
        rest % 60
    )
}

fn in_seconds(offset: i64) -> String {
    let now = unix_seconds(server_now()) as i64;
    iso8601((now + offset) as u64)
}

fn sign_text(text: &str) -> String {
    let mut mac = Hmac::<Sha256>::new_from_slice(&KEY).unwrap();
    mac.update(text.as_bytes());
    STANDARD.encode(mac.finalize().into_bytes())
}

fn encode(value: &str) -> String {
    value
        .bytes()
        .map(|byte| match byte {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' => {
                (byte as char).to_string()
            }
            _ => format!("%{byte:02X}"),
        })
        .collect()
}

/// A service SAS for `container` (and `blob` for `sr=b`) per the documented
/// string-to-sign of version 2023-11-03, signed with the test key.
fn service_sas(container: &str, blob: Option<&str>, permissions: &str, expiry: &str) -> SasBuilder {
    SasBuilder {
        container: container.into(),
        blob: blob.map(Into::into),
        permissions: permissions.into(),
        expiry: expiry.into(),
        start: String::new(),
        identifier: String::new(),
        response_type: String::new(),
        protocol: String::new(),
        ip: String::new(),
        version: VERSION.into(),
    }
}

struct SasBuilder {
    container: String,
    blob: Option<String>,
    permissions: String,
    expiry: String,
    start: String,
    identifier: String,
    response_type: String,
    protocol: String,
    ip: String,
    version: String,
}

impl SasBuilder {
    fn build(&self) -> String {
        let (resource, canonical) = match &self.blob {
            Some(blob) => ("b", format!("/blob/{ACCOUNT}/{}/{blob}", self.container)),
            None => ("c", format!("/blob/{ACCOUNT}/{}", self.container)),
        };
        let signed = [
            self.permissions.as_str(),
            self.start.as_str(),
            self.expiry.as_str(),
            canonical.as_str(),
            self.identifier.as_str(),
            self.ip.as_str(),
            self.protocol.as_str(),
            self.version.as_str(),
            resource,
            "",
            "",
            "",
            "",
            "",
            "",
            self.response_type.as_str(),
        ]
        .join("\n");
        let mut query = format!("sv={}&sr={resource}", self.version);
        for (name, value) in [
            ("sp", &self.permissions),
            ("st", &self.start),
            ("se", &self.expiry),
            ("si", &self.identifier),
            ("sip", &self.ip),
            ("spr", &self.protocol),
            ("rsct", &self.response_type),
        ] {
            if !value.is_empty() {
                query.push_str(&format!("&{name}={}", encode(value)));
            }
        }
        format!("{query}&sig={}", encode(&sign_text(&signed)))
    }
}

fn account_sas(permissions: &str, services: &str, types: &str, expiry: &str) -> String {
    let signed =
        format!("{ACCOUNT}\n{permissions}\n{services}\n{types}\n\n{expiry}\n\n\n{VERSION}\n\n");
    format!(
        "sv={VERSION}&ss={services}&srt={types}&sp={permissions}&se={}&sig={}",
        encode(expiry),
        encode(&sign_text(&signed))
    )
}

fn header_text(response: &Response, name: &str) -> String {
    response
        .headers()
        .get(name)
        .unwrap_or_else(|| panic!("missing {name}"))
        .to_str()
        .unwrap()
        .to_owned()
}

fn etag(response: &Response) -> String {
    response.headers()["etag"].to_str().unwrap().to_owned()
}

fn error(response: Response, status: u16, code: &str) {
    assert_eq!(response.status().as_u16(), status);
    assert_eq!(response.headers()["x-ms-error-code"], code);
    assert!(
        response
            .text()
            .unwrap()
            .contains(&format!("<Code>{code}</Code>"))
    );
}

#[test]
fn blob_lifecycle_conditions_ranges_and_properties() {
    let server = Emulator::start(None, &[]);
    let health = server
        .client
        .get(format!("{}/healthz", server.admin))
        .send()
        .unwrap();
    assert_eq!(health.text().unwrap(), "ok\n");
    server.create_container();
    assert_eq!(
        server.request(Method::GET, CONTAINER, &[], b"").status(),
        200
    );
    error(
        server.request(Method::PUT, CONTAINER, &[], b""),
        409,
        "ContainerAlreadyExists",
    );

    let put = server.put(
        BLOB,
        &[
            ("if-none-match", "*"),
            ("content-type", "text/plain"),
            ("content-md5", "XrY7u+Ae7tCTyyK7j1rNww=="),
            ("x-ms-meta-note", "a & b"),
        ],
        b"hello world",
    );
    assert_eq!(put.status(), 201);
    let original = etag(&put);
    let head = server.request(Method::HEAD, BLOB, &[], b"");
    assert_eq!(head.status(), 200);
    assert_eq!(head.headers()["content-length"], "11");
    assert_eq!(head.headers()["content-md5"], "XrY7u+Ae7tCTyyK7j1rNww==");
    assert_eq!(head.headers()["content-type"], "text/plain");
    assert_eq!(head.headers()["x-ms-meta-note"], "a & b");
    assert_eq!(etag(&head), original);
    assert!(head.bytes().unwrap().is_empty());

    let range = server.request(Method::GET, BLOB, &[("range", "bytes=6-100")], b"");
    assert_eq!(range.status(), 206);
    assert_eq!(range.headers()["content-range"], "bytes 6-10/11");
    assert_eq!(range.bytes().unwrap().as_ref(), b"world");
    let invalid_range = server.request(Method::GET, BLOB, &[("x-ms-range", "bytes=11-")], b"");
    assert_eq!(invalid_range.headers()["content-range"], "bytes */11");
    error(invalid_range, 416, "InvalidRange");
    let cached = server.request(Method::GET, BLOB, &[("if-none-match", &original)], b"");
    assert_eq!(cached.status(), 304);
    assert!(cached.bytes().unwrap().is_empty());
    error(
        server.put(BLOB, &[("if-none-match", "*")], b"bad"),
        409,
        "BlobAlreadyExists",
    );
    error(
        server.put(BLOB, &[("content-md5", "1B2M2Y8AsgTpgAmY7PhCfg==")], b"bad"),
        400,
        "Md5Mismatch",
    );
    let unchanged = server.request(Method::GET, BLOB, &[], b"");
    assert_eq!(etag(&unchanged), original);
    assert_eq!(unchanged.bytes().unwrap().as_ref(), b"hello world");

    let replacement = server.put(BLOB, &[("if-match", &original)], b"next");
    assert_eq!(replacement.status(), 201);
    let new_etag = etag(&replacement);
    assert_ne!(original, new_etag);
    error(
        server.request(Method::DELETE, BLOB, &[("if-match", &original)], b""),
        412,
        "ConditionNotMet",
    );
    assert_eq!(
        server
            .request(Method::DELETE, BLOB, &[("if-match", &new_etag)], b"")
            .status(),
        202
    );
    error(
        server.request(Method::GET, BLOB, &[], b""),
        404,
        "BlobNotFound",
    );
    assert_eq!(
        server.request(Method::DELETE, CONTAINER, &[], b"").status(),
        202
    );
    error(
        server.request(Method::GET, CONTAINER, &[], b""),
        404,
        "ContainerNotFound",
    );
}

#[test]
fn listing_uses_opaque_markers_and_rejects_unimplemented_options() {
    let location = tempfile::tempdir().unwrap();
    let server = Emulator::start(Some(location.path()), &[]);
    server.create_container();
    let containers = server.request(
        Method::GET,
        "/testaccount/?comp=list&include=&prefix=con",
        &[],
        b"",
    );
    assert_eq!(containers.status(), 200);
    assert!(
        containers
            .text()
            .unwrap()
            .contains("<Name>container</Name>")
    );
    assert_eq!(
        server
            .request(
                Method::GET,
                "/testaccount/?comp=list&include=deleted",
                &[],
                b"",
            )
            .status(),
        200
    );
    error(
        server.request(
            Method::GET,
            "/testaccount/?comp=list&include=system",
            &[],
            b"",
        ),
        501,
        "NotImplemented",
    );
    assert_eq!(
        server
            .put(BLOB, &[("x-ms-meta-comment", "a < b & c")], b"")
            .status(),
        201
    );
    let later = "/testaccount/container/docs/z.txt";
    assert_eq!(server.put(later, &[], b"other").status(), 201);

    let query = "/testaccount/container?restype=container&maxresults=1&comp=list&include=metadata&prefix=docs%2F";
    let first = server.request(Method::GET, query, &[], b"");
    assert_eq!(first.status(), 200);
    let first = first.text().unwrap();
    assert!(first.contains("<Name>docs/a&amp;b.txt</Name>"));
    assert!(first.contains("<comment>a &lt; b &amp; c</comment>"));
    assert!(!first.contains("z.txt"));
    let marker = first
        .split_once("<NextMarker>")
        .unwrap()
        .1
        .split_once("</NextMarker>")
        .unwrap()
        .0;
    assert!(!marker.is_empty());
    let next = server.request(Method::GET, &format!("{query}&marker={marker}"), &[], b"");
    assert_eq!(next.status(), 200);
    let next = next.text().unwrap();
    assert!(next.contains("<Name>docs/z.txt</Name>"));
    assert!(!next.contains("a&amp;b.txt"));
    assert!(next.contains("<NextMarker></NextMarker>"));
    error(
        server.request(
            Method::GET,
            "/testaccount/container?restype=container&comp=list&include=immutabilitypolicy",
            &[],
            b"",
        ),
        501,
        "NotImplemented",
    );
    error(
        server.request(Method::GET, &format!("{query}&marker=bad%25"), &[], b""),
        400,
        "InvalidQueryParameterValue",
    );
    error(
        server.request(Method::GET, BLOB, &[("x-ms-version", "2099-01-01")], b""),
        400,
        "InvalidHeaderValue",
    );
    error(
        server.request(Method::PUT, &format!("{BLOB}?comp=query"), &[], b""),
        501,
        "NotImplemented",
    );
    assert_eq!(
        server.request(Method::DELETE, CONTAINER, &[], b"").status(),
        202
    );
    error(
        server.request(Method::GET, BLOB, &[], b""),
        404,
        "ContainerNotFound",
    );
    server.create_container();
    error(
        server.request(Method::GET, BLOB, &[], b""),
        404,
        "BlobNotFound",
    );
}

#[test]
fn rejects_unsigned_stale_and_tampered_requests_and_enforces_content_limits() {
    let server = Emulator::start(None, &["--memory-limit", "5", "--max-blob-bytes", "10"]);
    server.create_container();
    let unsigned = server
        .client
        .get(format!("{}{CONTAINER}", server.blob_url()))
        .header("x-ms-version", VERSION)
        .send()
        .unwrap();
    error(unsigned, 403, "AuthenticationFailed");
    error(
        server.request_with_key(Method::GET, CONTAINER, &[], b"", &[24; 32]),
        403,
        "AuthenticationFailed",
    );
    error(
        server.request(
            Method::GET,
            CONTAINER,
            &[("x-ms-date", "Fri, 26 Jun 2015 23:39:12 GMT")],
            b"",
        ),
        403,
        "AuthenticationFailed",
    );
    error(
        server.request(
            Method::GET,
            &format!("{BLOB}?sig=not-implemented"),
            &[],
            b"",
        ),
        403,
        "AuthenticationFailed",
    );
    assert_eq!(server.put(BLOB, &[], b"four").status(), 201);
    let other = "/testaccount/container/other";
    error(server.put(other, &[], b"12"), 507, "InsufficientStorage");
    error(
        server.put(other, &[], b"01234567890"),
        413,
        "RequestBodyTooLarge",
    );
    error(
        server.request(Method::GET, other, &[], b""),
        404,
        "BlobNotFound",
    );
    assert_eq!(server.put(BLOB, &[], b"five!").status(), 201);
    assert_eq!(server.request(Method::DELETE, BLOB, &[], b"").status(), 202);
    assert_eq!(server.put(other, &[], b"12").status(), 201);
}

#[test]
fn newer_version_fallback_is_opt_in_and_does_not_change_auth_or_operations() {
    let newer = [("x-ms-version", "2026-04-06")];
    let strict = Emulator::start(None, &[]);
    error(
        strict.request(Method::PUT, CONTAINER, &newer, b""),
        400,
        "InvalidHeaderValue",
    );
    error(
        strict.request(Method::GET, CONTAINER, &[], b""),
        404,
        "ContainerNotFound",
    );

    let compatible = Emulator::start(None, &["--skip-api-version-check"]);
    let created = compatible.request(Method::PUT, CONTAINER, &newer, b"");
    assert_eq!(created.status(), 201);
    let export = emulator_command()
        .args(["conformance", "export"])
        .output()
        .unwrap();
    assert!(export.status.success());
    let manifest: serde_json::Value = serde_json::from_slice(&export.stdout).unwrap();
    assert_eq!(
        created.headers()["x-ms-version"],
        manifest["api_version"].as_str().unwrap()
    );
    let read = compatible.request(Method::GET, CONTAINER, &[], b"");
    assert_eq!(read.status(), 200);
    assert_eq!(etag(&read), etag(&created));
    error(
        compatible.request_with_key(Method::GET, CONTAINER, &newer, b"", &[24; 32]),
        403,
        "AuthenticationFailed",
    );
    error(
        compatible.request(Method::PUT, &format!("{BLOB}?comp=query"), &newer, b""),
        501,
        "NotImplemented",
    );
    for version in ["2009-09-18", "2026-02-29", "2026-4-06", "nonsense"] {
        error(
            compatible.request(Method::GET, CONTAINER, &[("x-ms-version", version)], b""),
            400,
            "InvalidHeaderValue",
        );
    }
    // Older versions are served with baseline behavior, in strict mode too.
    let older = compatible.request(
        Method::GET,
        CONTAINER,
        &[("x-ms-version", "2014-12-01")],
        b"",
    );
    assert_eq!(older.status(), 200);
    assert_eq!(older.headers()["x-ms-version"], VERSION);
    error(
        strict.request(
            Method::GET,
            CONTAINER,
            &[("x-ms-version", "2014-12-01")],
            b"",
        ),
        404,
        "ContainerNotFound",
    );
}

#[test]
fn cli_overrides_environment_and_toml_for_upload_limits_and_storage_mode() {
    let root = tempfile::tempdir().unwrap();
    let file = root.path().join("settings.toml");
    fs::write(&file, "in_memory = true\nmax_blob_bytes = 2\n").unwrap();
    for (env_limit, limit) in [(None, 2), (Some("4"), 4)] {
        let mut command = emulator_command();
        command.env("AZUIFER_CONFIG", &file).args([
            "serve",
            "--port",
            "0",
            "--admin-port",
            "0",
            "--services",
            "blob",
        ]);
        if let Some(value) = env_limit {
            command.env("AZUIFER_MAX_BLOB_BYTES", value);
        }
        let server = Emulator::spawn(command);
        server.create_container();
        assert_eq!(server.put(BLOB, &[], &b"1234"[..limit]).status(), 201);
        error(
            server.put(BLOB, &[], &b"12345"[..=limit]),
            413,
            "RequestBodyTooLarge",
        );
    }
    let location = root.path().join("selected from CLI");
    let mut command = emulator_command();
    command
        .env("AZUIFER_MAX_BLOB_BYTES", "4")
        .env("AZUIFER_IN_MEMORY", "true")
        .arg("--config")
        .arg(&file)
        .args([
            "serve",
            "--port",
            "0",
            "--admin-port",
            "0",
            "--services",
            "blob",
            "--in-memory=false",
            "--max-blob-bytes",
            "6",
            "--location",
        ])
        .arg(&location);
    let mut server = Emulator::spawn(command);
    server.create_container();
    assert_eq!(server.put(BLOB, &[], b"abcdef").status(), 201);
    error(
        server.put(BLOB, &[], b"too big"),
        413,
        "RequestBodyTooLarge",
    );
    assert!(
        server
            .process
            .shutdown()
            .unwrap()
            .expect("stdin EOF should stop the server")
            .success()
    );
    let restarted = Emulator::start(Some(&location), &[]);
    let saved = restarted.request(Method::GET, BLOB, &[], b"");
    assert_eq!(saved.status(), 200);
    assert_eq!(saved.bytes().unwrap().as_ref(), b"abcdef");
}

#[test]
fn upload_timeout_flag_aborts_an_overwrite_without_changing_the_blob() {
    let location = tempfile::tempdir().unwrap();
    let server = Emulator::start(Some(location.path()), &["--upload-timeout-seconds", "1"]);
    server.create_container();
    let saved = server.put(BLOB, &[], b"committed");
    assert_eq!(saved.status(), 201);
    let saved_tag = etag(&saved);

    let mut stalled = server.start_partial_upload(BLOB, 32, b"incomplete");
    stalled
        .set_read_timeout(Some(Duration::from_secs(8)))
        .unwrap();
    let mut reply = String::new();
    stalled.read_to_string(&mut reply).unwrap();
    assert!(reply.starts_with("HTTP/1.1 408 "), "{reply}");
    assert!(reply.contains("<Code>OperationTimedOut</Code>"), "{reply}");
    let current = server.request(Method::GET, BLOB, &[], b"");
    assert_eq!(current.status(), 200);
    assert_eq!(etag(&current), saved_tag);
    assert_eq!(current.bytes().unwrap().as_ref(), b"committed");
    assert_eq!(
        server
            .put(BLOB, &[("if-match", &saved_tag)], b"replacement")
            .status(),
        201
    );
}

#[test]
fn cli_validation_rejects_misconfiguration_without_leaking_keys() {
    let key = "synthetic invalid credential; do not print";
    let invalid_key = emulator_command()
        .env("AZUIFER_ACCOUNT_KEY", key)
        .args(["config", "validate"])
        .output()
        .unwrap();
    assert!(!invalid_key.status.success());
    assert!(invalid_key.stdout.is_empty());
    let errors = String::from_utf8(invalid_key.stderr).unwrap();
    assert!(errors.contains("Shared Key must be valid Base64"));
    assert!(!errors.contains(key));

    let public_bind = emulator_command()
        .env_remove("AZUIFER_ACCOUNT_NAME")
        .env_remove("AZUIFER_ACCOUNT_KEY")
        .args(["config", "validate", "--bind", "0.0.0.0"])
        .output()
        .unwrap();
    assert!(!public_bind.status.success());
    assert!(
        String::from_utf8(public_bind.stderr)
            .unwrap()
            .contains("requires loopback")
    );

    for (flags, diagnostic) in [
        (
            &["--port", "6000", "--admin-port", "6000"][..],
            "ports must differ",
        ),
        (&["--services", "blob,bogus"][..], "unknown service"),
        (&["--services", "blob,blob"][..], "duplicate service"),
        (
            &[
                "--services",
                "blob,queue",
                "--queue-port",
                "6001",
                "--port",
                "6001",
            ][..],
            "ports must differ",
        ),
        (
            &["--upload-timeout-seconds", "0"][..],
            "upload-timeout-seconds must be between",
        ),
    ] {
        let output = emulator_command()
            .args(["config", "validate"])
            .args(flags)
            .output()
            .unwrap();
        assert!(!output.status.success());
        assert!(output.stdout.is_empty());
        assert!(
            String::from_utf8(output.stderr)
                .unwrap()
                .contains(diagnostic)
        );
    }

    let valid = emulator_command()
        .args(["config", "validate"])
        .output()
        .unwrap();
    assert!(valid.status.success());
    assert_eq!(
        String::from_utf8(valid.stdout).unwrap().trim(),
        "Configuration is valid."
    );
}

#[test]
fn only_one_concurrent_overwrite_can_use_the_same_etag() {
    let location = tempfile::tempdir().unwrap();
    let server = Emulator::start(Some(location.path()), &[]);
    server.create_container();
    let first = server.put(BLOB, &[], b"one");
    assert_eq!(first.status(), 201);
    let prior = etag(&first);
    let start = Barrier::new(2);
    let candidates: [&[u8]; 2] = [b"two distinct", b"three distinct"];

    let results = thread::scope(|scope| {
        let (start, server, prior) = (&start, &server, prior.as_str());
        candidates
            .map(|bytes| {
                scope.spawn(move || {
                    start.wait();
                    (server.put(BLOB, &[("if-match", prior)], bytes), bytes)
                })
            })
            .map(|thread| thread.join().unwrap())
    });
    let mut winning = None;
    for (response, bytes) in results {
        if response.status() == 201 {
            assert!(winning.replace((etag(&response), bytes)).is_none());
        } else {
            error(response, 412, "ConditionNotMet");
        }
    }
    let (tag, bytes) = winning.expect("exactly one update must commit");
    let saved = server.request(Method::GET, BLOB, &[], b"");
    assert_eq!(saved.status(), 200);
    assert_eq!(etag(&saved), tag);
    assert_eq!(saved.bytes().unwrap().as_ref(), bytes);
}

#[test]
fn a_busy_data_directory_and_a_truncated_extent_fail_explicitly() {
    let location = tempfile::tempdir().unwrap();
    let server = Emulator::start(Some(location.path()), &[]);
    server.create_container();
    assert_eq!(server.put(BLOB, &[], b"complete").status(), 201);
    let second = emulator_command()
        .args(["serve", "--port", "0", "--admin-port", "0", "--location"])
        .arg(location.path())
        .output()
        .unwrap();
    assert!(!second.status.success());
    assert!(
        second.stdout.is_empty(),
        "a second process must not announce readiness"
    );
    assert!(
        String::from_utf8(second.stderr)
            .unwrap()
            .contains("storage directory is already in use")
    );
    let saved = server.request(Method::GET, BLOB, &[], b"");
    assert_eq!(saved.status(), 200);
    assert_eq!(saved.bytes().unwrap().as_ref(), b"complete");

    let content = fs::read_dir(location.path().join("content"))
        .unwrap()
        .map(|entry| entry.unwrap().path())
        .collect::<Vec<_>>();
    let [extent] = content.as_slice() else {
        panic!("expected exactly one committed extent")
    };
    fs::write(extent, b"short").unwrap();
    error(
        server.request(Method::GET, BLOB, &[], b""),
        500,
        "InternalError",
    );
    let dest = "/testaccount/container/rejected-copy.txt";
    let source = blob_url(&server, BLOB);
    error(
        server.request(
            Method::PUT,
            dest,
            &[
                ("x-ms-blob-type", "BlockBlob"),
                ("x-ms-copy-source", &source),
            ],
            b"",
        ),
        500,
        "InternalError",
    );
    error(
        server.request(Method::GET, dest, &[], b""),
        404,
        "BlobNotFound",
    );
}

#[test]
fn rejected_requests_never_change_the_stored_blob() {
    let server = Emulator::start(None, &[]);
    server.create_container();
    let put = server.put(BLOB, &[], b"original");
    assert_eq!(put.status(), 201);
    let original = etag(&put);
    for (header, expected_status, expected_code) in [
        (("x-ms-meta-bad-name", "no"), 400, "InvalidHeaderValue"),
        (("content-type", ""), 400, "InvalidHeaderValue"),
        (("x-ms-lease-id", "missing"), 400, "InvalidHeaderValue"),
    ] {
        error(
            server.put(BLOB, &[header], b"replacement"),
            expected_status,
            expected_code,
        );
    }
    error(
        server.request(Method::PUT, BLOB, &[("x-ms-blob-type", "PageBlob")], b""),
        400,
        "MissingRequiredHeader",
    );
    error(
        server.request(Method::PUT, BLOB, &[], b"not a typed upload"),
        400,
        "InvalidHeaderValue",
    );
    let current = server.request(Method::GET, BLOB, &[], b"");
    assert_eq!(current.status(), 200);
    assert_eq!(etag(&current), original);
    assert_eq!(current.bytes().unwrap().as_ref(), b"original");
}

fn wait_for_staged_uploads(directory: &Path, count: usize) {
    let deadline = Instant::now() + Duration::from_secs(5);
    loop {
        let staged = fs::read_dir(directory)
            .unwrap()
            .filter(|entry| {
                entry
                    .as_ref()
                    .unwrap()
                    .file_name()
                    .to_string_lossy()
                    .starts_with("incoming-")
            })
            .count();
        if staged == count {
            return;
        }
        assert!(
            Instant::now() < deadline,
            "expected {count} staged uploads, got {staged}"
        );
        thread::sleep(Duration::from_millis(10));
    }
}

#[test]
fn upload_saturation_returns_backpressure_and_recovers_after_disconnects() {
    let location = tempfile::tempdir().unwrap();
    let server = Emulator::start(Some(location.path()), &[]);
    server.create_container();
    assert_eq!(server.put(BLOB, &[], b"keep me").status(), 201);
    let stalled: Vec<_> = (0..16)
        .map(|_| server.start_partial_upload(BLOB, 32, b"incomplete"))
        .collect();
    wait_for_staged_uploads(&location.path().join("content"), stalled.len());
    error(
        server.request(Method::GET, BLOB, &[], b""),
        503,
        "ServerBusy",
    );
    drop(stalled);
    wait_for_staged_uploads(&location.path().join("content"), 0);
    let deadline = Instant::now() + Duration::from_secs(5);
    let response = loop {
        let response = server.request(Method::GET, BLOB, &[], b"");
        if response.status() != 503 {
            break response;
        }
        assert!(
            Instant::now() < deadline,
            "disconnected uploads should release permits"
        );
        thread::sleep(Duration::from_millis(10));
    };
    assert_eq!(response.status(), 200);
    assert_eq!(response.bytes().unwrap().as_ref(), b"keep me");
}

#[test]
fn persistent_blob_names_do_not_inherit_host_filesystem_rules() {
    let root = tempfile::tempdir().unwrap();
    let cases: [(&str, &[u8]); 4] = [
        ("/testaccount/container/docs/CON", b"upper"),
        ("/testaccount/container/docs/con", b"lower"),
        ("/testaccount/container/caf%C3%A9", b"composed"),
        ("/testaccount/container/cafe%CC%81", b"decomposed"),
    ];
    let server = Emulator::start(Some(root.path()), &[]);
    server.create_container();
    for (path, data) in cases {
        assert_eq!(server.put(path, &[], data).status(), 201);
    }

    drop(server);
    let restarted = Emulator::start(Some(root.path()), &[]);
    for (path, data) in cases {
        let response = restarted.request(Method::GET, path, &[], b"");
        assert_eq!(response.status(), 200);
        assert_eq!(response.bytes().unwrap().as_ref(), data);
    }
}

#[test]
fn staged_blocks_survive_restart_and_commit_in_selection_order() {
    let location = tempfile::tempdir().unwrap();
    let server = Emulator::start(Some(location.path()), &[]);
    server.create_container();
    let put = server.put(BLOB, &[], b"preceding");
    assert_eq!(put.status(), 201);
    let preceding = etag(&put);
    let block_list = format!("{BLOB}?comp=blocklist");
    let all = format!("{block_list}&blocklisttype=all");

    for (id, bytes) in [
        ("Qg==", &b"first"[..]),
        ("QQ==", &b"one"[..]),
        ("Qg==", &b"last"[..]),
    ] {
        let response = server.request(
            Method::PUT,
            &format!("{BLOB}?comp=block&blockid={id}"),
            &[],
            bytes,
        );
        assert_eq!(response.status(), 201);
    }
    let unchanged = server.request(Method::GET, BLOB, &[], b"");
    assert_eq!(etag(&unchanged), preceding);
    assert_eq!(unchanged.bytes().unwrap().as_ref(), b"preceding");

    drop(server);
    let server = Emulator::start(Some(location.path()), &[]);
    let staged = server.request(Method::GET, &all, &[], b"");
    assert_eq!(staged.status(), 200);
    let staged = staged.text().unwrap();
    assert!(staged.contains("<UncommittedBlocks><Block><Name>QQ==</Name><Size>3</Size></Block><Block><Name>Qg==</Name><Size>4</Size></Block></UncommittedBlocks>"));

    error(
        server.request(
            Method::PUT,
            &block_list,
            &[],
            b"<BlockList><Latest>Wg==</Latest></BlockList>",
        ),
        400,
        "InvalidBlockList",
    );
    let after_rejection = server.request(Method::GET, &all, &[], b"");
    assert_eq!(after_rejection.text().unwrap(), staged);
    let xml = b"<?xml version=\"1.0\" encoding=\"utf-8\"?><BlockList><Latest>Qg==</Latest><Uncommitted>QQ==</Uncommitted><Latest>Qg==</Latest></BlockList>";
    let commit = server.request(
        Method::PUT,
        &block_list,
        &[
            ("if-match", &preceding),
            ("x-ms-blob-content-type", "text/plain"),
        ],
        xml,
    );
    assert_eq!(commit.status(), 201);
    let committed_tag = etag(&commit);
    assert_ne!(committed_tag, preceding);
    let updated = server.request(Method::GET, BLOB, &[], b"");
    assert_eq!(etag(&updated), committed_tag);
    assert_eq!(updated.headers()["content-type"], "text/plain");
    assert!(!updated.headers().contains_key("content-md5"));
    assert_eq!(updated.bytes().unwrap().as_ref(), b"lastonelast");
    let listing = server.request(Method::GET, &all, &[], b"");
    assert_eq!(listing.headers()["x-ms-blob-content-length"], "11");
    let listing = listing.text().unwrap();
    assert!(listing.contains("<CommittedBlocks><Block><Name>Qg==</Name><Size>4</Size></Block><Block><Name>QQ==</Name><Size>3</Size></Block><Block><Name>Qg==</Name><Size>4</Size></Block></CommittedBlocks>"));
    assert!(listing.contains("<UncommittedBlocks></UncommittedBlocks>"));

    assert_eq!(
        server
            .request(
                Method::PUT,
                &format!("{BLOB}?comp=block&blockid=Qg=="),
                &[],
                b"new"
            )
            .status(),
        201
    );
    let xml = b"<BlockList><Committed>Qg==</Committed><Latest>QQ==</Latest></BlockList>";
    error(
        server.request(Method::PUT, &block_list, &[("if-match", &preceding)], xml),
        412,
        "ConditionNotMet",
    );
    assert_eq!(
        server
            .request(
                Method::PUT,
                &block_list,
                &[("if-match", &committed_tag)],
                xml
            )
            .status(),
        201
    );
    assert_eq!(
        server
            .request(Method::GET, BLOB, &[], b"")
            .bytes()
            .unwrap()
            .as_ref(),
        b"lastone"
    );
}

#[test]
fn rejected_block_requests_leave_staged_bytes_and_quota_intact() {
    let server = Emulator::start(
        None,
        &[
            "--memory-limit",
            "6",
            "--max-blob-bytes",
            "8",
            "--max-block-bytes",
            "8",
            "--max-assembled-blob-bytes",
            "8",
        ],
    );
    server.create_container();
    let block = |id| format!("{BLOB}?comp=block&blockid={id}");
    let list = format!("{BLOB}?comp=blocklist");
    let all = format!("{list}&blocklisttype=all");
    let crc = [("x-ms-content-crc64", "0GFnV7RfVNI=")];
    let first = server.request(Method::PUT, &block("QQ=="), &crc, b"\x11");
    assert_eq!(first.status(), 201);
    assert_eq!(first.headers()["x-ms-content-crc64"], crc[0].1);
    error(
        server.request(Method::PUT, &block("QQ=="), &crc, b"wrong"),
        400,
        "Crc64Mismatch",
    );
    error(
        server.request(Method::PUT, &block("QUM="), &[], b"wrong width"),
        413,
        "RequestBodyTooLarge",
    );
    error(
        server.request(Method::PUT, &block("QUM="), &[], b"wide"),
        400,
        "InvalidBlobOrBlock",
    );
    assert_eq!(
        server
            .request(Method::PUT, &block("Qg=="), &[], b"bcdef")
            .status(),
        201
    );
    error(
        server.request(Method::PUT, &block("Qw=="), &[], b"extra"),
        507,
        "InsufficientStorage",
    );
    error(
        server.request(Method::GET, BLOB, &[], b""),
        404,
        "BlobNotFound",
    );

    let staged = server.request(Method::GET, &all, &[], b"");
    assert_eq!(staged.status(), 200);
    assert_eq!(staged.headers()["x-ms-blob-content-length"], "0");
    let staged = staged.text().unwrap();
    assert!(staged.contains("<CommittedBlocks></CommittedBlocks>"));
    error(
        server.request(
            Method::PUT,
            &list,
            &[],
            b"<BlockList><Latest>QQ==</Latest></Wrong>",
        ),
        400,
        "InvalidXmlDocument",
    );
    error(
        server.request(
            Method::PUT,
            &list,
            &[],
            b"<BlockList><Committed>QQ==</Committed><Latest>QQ==</Latest></BlockList>",
        ),
        400,
        "InvalidBlockList",
    );
    error(
        server.request(
            Method::PUT,
            &list,
            &[],
            b"<BlockList><Latest>Qg==</Latest><Latest>Qg==</Latest></BlockList>",
        ),
        413,
        "RequestBodyTooLarge",
    );
    error(server.request(Method::PUT, &list, &[], b"<BlockList><Latest>Qg==</Latest><Latest>QQ==</Latest><Latest>QQ==</Latest></BlockList>"), 507, "InsufficientStorage");
    let oversized_list = format!(
        "<BlockList>{}</BlockList>",
        "<Latest>QQ==</Latest>".repeat(50_001)
    );
    error(
        server.request(Method::PUT, &list, &[], oversized_list.as_bytes()),
        400,
        "BlockListTooLong",
    );
    assert_eq!(
        server.request(Method::GET, &all, &[], b"").text().unwrap(),
        staged
    );
    let ordered = b"<BlockList><Uncommitted>QQ==</Uncommitted><Latest>Qg==</Latest></BlockList>";
    assert_eq!(
        server.request(Method::PUT, &list, &[], ordered).status(),
        201
    );
    assert_eq!(
        server
            .request(Method::GET, BLOB, &[], b"")
            .bytes()
            .unwrap()
            .as_ref(),
        b"\x11bcdef"
    );
}

#[test]
fn zero_length_blocks_commit_and_read_in_memory() {
    let server = Emulator::start(None, &[]);
    server.create_container();
    let block = format!("{BLOB}?comp=block&blockid=QQ==");
    let list = format!("{BLOB}?comp=blocklist");
    assert_eq!(server.request(Method::PUT, &block, &[], b"").status(), 201);
    let response = server.request(
        Method::PUT,
        &list,
        &[],
        b"<BlockList><Latest>QQ==</Latest></BlockList>",
    );
    assert_eq!(response.status(), 201);
    let tag = etag(&response);
    let read = server.request(Method::GET, BLOB, &[], b"");
    assert_eq!(read.status(), 200);
    assert_eq!(etag(&read), tag);
    assert_eq!(read.headers()["content-length"], "0");
    assert!(read.bytes().unwrap().is_empty());

    let committed = server.request(Method::GET, &list, &[], b"");
    assert_eq!(committed.status(), 200);
    assert!(
        committed
            .text()
            .unwrap()
            .contains("<Name>QQ==</Name><Size>0</Size>")
    );
}

#[test]
fn dfs_requires_hns_and_authentication() {
    let server = Emulator::start_services(None, "blob,dfs", &[]);
    let response = server.dfs(Method::GET, "/testaccount?resource=account", &[], b"");
    dfs_error(response, 409, "HierarchicalNamespaceNotEnabled");

    let hns = Emulator::start_services(None, "blob,dfs", &["--hns-accounts", ACCOUNT]);
    let unsigned = hns
        .client
        .get(format!(
            "{}/testaccount?resource=account",
            hns.dfs.as_deref().unwrap()
        ))
        .header("x-ms-version", VERSION)
        .send()
        .unwrap();
    dfs_error(unsigned, 403, "AuthorizationFailure");
}

#[test]
fn hns_configuration_rejects_an_account_that_does_not_exist() {
    let result = emulator_command()
        .args(["serve", "--hns-accounts", "unconfigured"])
        .output()
        .unwrap();
    assert!(!result.status.success());
    assert!(
        String::from_utf8_lossy(&result.stderr)
            .contains("HNS account `unconfigured` is not configured")
    );
}

#[test]
fn dfs_filesystems_and_blob_bytes_share_the_same_persistent_store() {
    const FILESYSTEM: &str = "/testaccount/container?resource=filesystem";
    let location = tempfile::tempdir().unwrap();
    let start = |services| {
        Emulator::start_services(
            Some(location.path()),
            services,
            &["--hns-accounts", ACCOUNT, "--skip-api-version-check"],
        )
    };
    let server = start("blob,dfs");
    dfs_error(
        server.dfs(Method::PUT, FILESYSTEM, &[], b"not allowed"),
        400,
        "ContentLengthMustBeZero",
    );
    let created = server.dfs(Method::PUT, FILESYSTEM, &[], b"");
    assert_eq!(created.status(), 201);
    assert_eq!(created.headers()["x-ms-namespace-enabled"], "true");
    let container_tag = etag(&created);
    let blob_container = server.request(Method::HEAD, CONTAINER, &[], b"");
    assert_eq!(blob_container.status(), 200);
    assert_eq!(etag(&blob_container), container_tag);
    let properties = server.dfs(Method::HEAD, FILESYSTEM, &[], b"");
    assert_eq!(properties.status(), 200);
    assert_eq!(etag(&properties), container_tag);
    dfs_error(
        server.dfs(Method::PUT, FILESYSTEM, &[], b""),
        409,
        "FilesystemAlreadyExists",
    );

    assert_eq!(
        server
            .request(
                Method::PUT,
                "/testaccount/second?restype=container",
                &[],
                b"",
            )
            .status(),
        201,
    );
    let page = server.dfs(
        Method::GET,
        "/testaccount?resource=account&maxresults=1",
        &[],
        b"",
    );
    assert_eq!(page.status(), 200);
    let marker = page.headers()["x-ms-continuation"]
        .to_str()
        .unwrap()
        .to_owned();
    let listed: serde_json::Value = serde_json::from_slice(&page.bytes().unwrap()).unwrap();
    assert_eq!(listed["filesystems"].as_array().unwrap().len(), 1);
    assert_eq!(listed["filesystems"][0]["name"], "container");
    assert_eq!(listed["filesystems"][0]["eTag"], container_tag);
    let next = server.dfs(
        Method::GET,
        &format!("/testaccount?resource=account&maxresults=1&continuation={marker}"),
        &[],
        b"",
    );
    assert_eq!(next.status(), 200);
    assert!(!next.headers().contains_key("x-ms-continuation"));
    let listed: serde_json::Value = serde_json::from_slice(&next.bytes().unwrap()).unwrap();
    assert_eq!(listed["filesystems"][0]["name"], "second");
    dfs_error(
        server.dfs(
            Method::GET,
            "/testaccount?resource=account&continuation=*invalid*",
            &[],
            b"",
        ),
        400,
        "InvalidQueryParameterValue",
    );

    let written = server.put(BLOB, &[("x-ms-meta-origin", "blob")], b"shared bytes");
    assert_eq!(written.status(), 201);
    let tag = etag(&written);
    drop(server);
    let server = start("dfs");
    let metadata = server.dfs(Method::HEAD, BLOB, &[], b"");
    assert_eq!(metadata.status(), 200);
    assert_eq!(metadata.headers()["x-ms-resource-type"], "file");
    assert_eq!(metadata.headers()["x-ms-properties"], "origin=YmxvYg==");
    assert_eq!(metadata.headers()["content-length"], "12");
    assert_eq!(etag(&metadata), tag);
    assert!(metadata.bytes().unwrap().is_empty());

    let full = server.dfs(Method::GET, BLOB, &[], b"");
    assert_eq!(full.status(), 200);
    assert_eq!(etag(&full), tag);
    assert_eq!(full.bytes().unwrap().as_ref(), b"shared bytes");
    let unchanged = server.dfs(Method::GET, BLOB, &[("if-none-match", &tag)], b"");
    assert_eq!(unchanged.status(), 304);
    assert!(unchanged.bytes().unwrap().is_empty());

    let ranged = server.dfs(
        Method::GET,
        BLOB,
        &[
            ("range", "bytes=7-11"),
            ("if-match", &tag),
            ("x-ms-version", "2026-04-06"),
        ],
        b"",
    );
    assert_eq!(ranged.status(), 206);
    assert_eq!(ranged.headers()["x-ms-version"], VERSION);
    assert_eq!(ranged.headers()["content-range"], "bytes 7-11/12");
    assert_eq!(ranged.bytes().unwrap().as_ref(), b"bytes");
    let bad_range = server.dfs(Method::GET, BLOB, &[("range", "bytes=12-")], b"");
    assert_eq!(bad_range.headers()["content-range"], "bytes */12");
    dfs_error(bad_range, 416, "InvalidRange");
    dfs_error(
        server.dfs(Method::GET, BLOB, &[("if-match", "\"not-current\"")], b""),
        412,
        "ConditionNotMet",
    );
    dfs_error(
        server.dfs(Method::GET, "/testaccount/container/missing", &[], b""),
        404,
        "PathNotFound",
    );
    let access = server.dfs(
        Method::HEAD,
        &format!("{BLOB}?action=getAccessControl"),
        &[],
        b"",
    );
    assert_eq!(access.status(), 200);
    assert_eq!(access.headers()["x-ms-owner"], "$superuser");
    assert_eq!(access.headers()["x-ms-permissions"], "rw-r-----");
    assert_eq!(
        access.headers()["x-ms-acl"],
        "user::rw-,group::r--,other::---"
    );
    drop(server);
    let server = start("blob,dfs");
    assert_eq!(
        server.dfs(Method::DELETE, FILESYSTEM, &[], b"").status(),
        202
    );
    error(
        server.request(Method::GET, BLOB, &[], b""),
        404,
        "ContainerNotFound",
    );
    dfs_error(
        server.dfs(Method::GET, BLOB, &[], b""),
        404,
        "FilesystemNotFound",
    );
}

fn dfs_error(response: Response, status: u16, code: &str) {
    assert_eq!(response.status().as_u16(), status);
    assert_eq!(response.headers()["x-ms-error-code"], code);
    let body: serde_json::Value = serde_json::from_slice(&response.bytes().unwrap()).unwrap();
    assert_eq!(body["error"]["code"], code);
}

#[test]
fn dfs_directory_lifecycle_shares_identity_and_pages_the_tree() {
    const ROOT: &str = "/testaccount/container?recursive=false&resource=filesystem";
    const EMPTY: &str = "/testaccount/container/empty/sub";
    const DOCS: &str = "/testaccount/container/docs";
    let location = tempfile::tempdir().unwrap();
    let start = || {
        Emulator::start_services(
            Some(location.path()),
            "blob,dfs",
            &["--hns-accounts", ACCOUNT],
        )
    };
    let emulator = start();
    emulator.create_container();
    let account = emulator.request(
        Method::HEAD,
        "/testaccount?comp=properties&restype=account",
        &[],
        b"",
    );
    assert_eq!(account.status(), 200);
    assert_eq!(account.headers()["x-ms-is-hns-enabled"], "true");

    let created = emulator.dfs(
        Method::PUT,
        &format!("{EMPTY}?resource=directory"),
        &[("if-none-match", "*")],
        b"",
    );
    assert_eq!(created.status(), 201);
    let dir_tag = etag(&created);
    dfs_error(
        emulator.dfs(
            Method::PUT,
            &format!("{EMPTY}?resource=directory"),
            &[("if-none-match", "*")],
            b"",
        ),
        409,
        "PathAlreadyExists",
    );
    let body = b"visible on both endpoints";
    let file = emulator.put(BLOB, &[], body);
    assert_eq!(file.status(), 201);
    let file_tag = etag(&file);
    assert_eq!(
        emulator
            .put("/testaccount/container/docs2/other", &[], b"not under docs")
            .status(),
        201,
    );
    let root_page = emulator.dfs(Method::GET, &format!("{ROOT}&maxresults=2"), &[], b"");
    assert_eq!(root_page.status(), 200);
    let token = root_page.headers()["x-ms-continuation"]
        .to_str()
        .unwrap()
        .to_owned();
    let page: serde_json::Value = serde_json::from_slice(&root_page.bytes().unwrap()).unwrap();
    assert_eq!(page["paths"].as_array().unwrap().len(), 2);
    assert_eq!(page["paths"][0]["name"], "docs");
    assert_eq!(page["paths"][0]["isDirectory"], "true");
    assert_eq!(page["paths"][1]["name"], "docs2");
    let next = emulator.dfs(
        Method::GET,
        &format!("{ROOT}&maxresults=2&continuation={token}"),
        &[],
        b"",
    );
    assert_eq!(next.status(), 200);
    assert!(!next.headers().contains_key("x-ms-continuation"));
    let page: serde_json::Value = serde_json::from_slice(&next.bytes().unwrap()).unwrap();
    assert_eq!(page["paths"].as_array().unwrap().len(), 1);
    assert_eq!(page["paths"][0]["name"], "empty");

    drop(emulator);
    let emulator = start();
    let head = emulator.dfs(Method::HEAD, EMPTY, &[], b"");
    assert_eq!(head.status(), 200);
    assert_eq!(etag(&head), dir_tag);
    assert_eq!(head.headers()["x-ms-resource-type"], "directory");
    let blob_head = emulator.request(Method::HEAD, EMPTY, &[], b"");
    assert_eq!(blob_head.status(), 200);
    assert_eq!(etag(&blob_head), dir_tag);
    let listed = emulator.dfs(
        Method::GET,
        "/testaccount/container?directory=docs&recursive=true&resource=filesystem",
        &[],
        b"",
    );
    assert_eq!(listed.status(), 200);
    let page: serde_json::Value = serde_json::from_slice(&listed.bytes().unwrap()).unwrap();
    assert_eq!(page["paths"].as_array().unwrap().len(), 1);
    assert_eq!(page["paths"][0]["name"], "docs/a&b.txt");
    assert_eq!(page["paths"][0]["etag"], file_tag);
    assert_eq!(page["paths"][0]["contentLength"], body.len().to_string());
    assert!(page["paths"][0].get("isDirectory").is_none());
    dfs_error(
        emulator.dfs(
            Method::GET,
            "/testaccount/container?directory=absent&recursive=false&resource=filesystem",
            &[],
            b"",
        ),
        404,
        "PathNotFound",
    );
    let blob_list = emulator.request(
        Method::GET,
        &format!("{CONTAINER}&comp=list&prefix=empty"),
        &[],
        b"",
    );
    let xml = blob_list.text().unwrap();
    assert!(
        xml.contains("<Name>empty/sub</Name>")
            && xml.contains("<ResourceType>directory</ResourceType>"),
        "{xml}"
    );

    dfs_error(
        emulator.dfs(Method::DELETE, &format!("{DOCS}?recursive=false"), &[], b""),
        409,
        "DirectoryNotEmpty",
    );
    dfs_error(
        emulator.dfs(
            Method::DELETE,
            &format!("{EMPTY}?recursive=false"),
            &[("if-match", "\"not-current\"")],
            b"",
        ),
        412,
        "ConditionNotMet",
    );
    assert_eq!(
        emulator
            .dfs(
                Method::DELETE,
                &format!("{EMPTY}?recursive=false"),
                &[("if-match", &dir_tag)],
                b""
            )
            .status(),
        200,
    );
    assert_eq!(
        emulator.request(Method::HEAD, EMPTY, &[], b"").status(),
        404
    );
    assert_eq!(
        emulator
            .request(Method::GET, BLOB, &[], b"")
            .bytes()
            .unwrap()
            .as_ref(),
        body
    );
}

#[test]
fn hns_blob_commits_do_not_replace_directories_or_publish_staged_paths() {
    const PATH: &str = "/testaccount/container/automatic/nested/block";
    const PARENT: &str = "/testaccount/container/automatic";
    let emulator = Emulator::start_services(None, "blob,dfs", &["--hns-accounts", ACCOUNT]);
    emulator.create_container();
    assert_eq!(
        emulator
            .request(
                Method::PUT,
                &format!("{PATH}?comp=block&blockid=YQ%3D%3D"),
                &[],
                b"block"
            )
            .status(),
        201,
    );
    assert_eq!(emulator.dfs(Method::HEAD, PARENT, &[], b"").status(), 404);
    let commit = |id| {
        emulator.request(
            Method::PUT,
            &format!("{PATH}?comp=blocklist"),
            &[],
            format!("<BlockList><Latest>{id}</Latest></BlockList>").as_bytes(),
        )
    };
    error(commit("Yg=="), 400, "InvalidBlockList");
    assert_eq!(emulator.dfs(Method::HEAD, PARENT, &[], b"").status(), 404);
    let committed = commit("YQ==");
    assert_eq!(committed.status(), 201);
    let parent = emulator.dfs(Method::HEAD, PARENT, &[], b"");
    assert_eq!(parent.status(), 200);
    assert_eq!(parent.headers()["x-ms-resource-type"], "directory");
    error(
        emulator.put(PARENT, &[], b"overwrite"),
        409,
        "BlobOperationNotSupported",
    );
    error(
        emulator.put(&format!("{PATH}/child"), &[], b"child"),
        409,
        "BlobOperationNotSupported",
    );
    dfs_error(
        emulator.dfs(Method::PUT, &format!("{PATH}?resource=directory"), &[], b""),
        409,
        "PathConflict",
    );
    let read = emulator.dfs(Method::GET, PATH, &[], b"");
    assert_eq!(etag(&read), etag(&committed));
    assert_eq!(read.bytes().unwrap().as_ref(), b"block");
}

#[test]
fn enabling_hns_keeps_existing_blob_identity_and_creates_missing_parents() {
    let location = tempfile::tempdir().unwrap();
    let flat = Emulator::start(Some(location.path()), &[]);
    flat.create_container();
    let written = flat.put(BLOB, &[], b"prior data");
    assert_eq!(written.status(), 201);
    let tag = etag(&written);
    drop(flat);

    let hns = Emulator::start_services(
        Some(location.path()),
        "blob,dfs",
        &["--hns-accounts", ACCOUNT],
    );
    let directory = hns.dfs(Method::HEAD, "/testaccount/container/docs", &[], b"");
    assert_eq!(directory.status(), 200);
    assert_eq!(directory.headers()["x-ms-resource-type"], "directory");
    let file = hns.dfs(Method::GET, BLOB, &[], b"");
    assert_eq!(etag(&file), tag);
    assert_eq!(file.bytes().unwrap().as_ref(), b"prior data");
}

#[test]
fn dfs_cannot_delete_a_file_protected_by_a_blob_lease() {
    let emulator = Emulator::start_services(None, "blob,dfs", &["--hns-accounts", ACCOUNT]);
    emulator.create_container();
    let blob = emulator.put(BLOB, &[], b"protected by a lease");
    assert_eq!(blob.status(), 201);

    let leased = emulator.request(
        Method::PUT,
        &format!("{BLOB}?comp=lease"),
        &[
            ("x-ms-lease-action", "acquire"),
            ("x-ms-lease-duration", "-1"),
        ],
        b"",
    );
    assert_eq!(leased.status(), 201);
    let lease = leased.headers()["x-ms-lease-id"].to_str().unwrap();
    dfs_error(
        emulator.dfs(Method::DELETE, BLOB, &[], b""),
        412,
        "LeaseIdMissing",
    );
    let still_exists = emulator.request(Method::HEAD, BLOB, &[], b"");
    assert_eq!(etag(&still_exists), etag(&blob));
    assert_eq!(
        emulator
            .dfs(Method::DELETE, BLOB, &[("x-ms-lease-id", lease)], b"")
            .status(),
        200,
    );
    assert_eq!(emulator.request(Method::HEAD, BLOB, &[], b"").status(), 404);
}

#[test]
fn enabling_hns_rejects_existing_file_parent_conflicts_without_changing_flat_data() {
    const FILE: &str = "/testaccount/container/docs";
    let location = tempfile::tempdir().unwrap();
    let flat = Emulator::start(Some(location.path()), &[]);
    flat.create_container();
    assert_eq!(flat.put(FILE, &[], b"parent file").status(), 201);
    assert_eq!(flat.put(BLOB, &[], b"nested file").status(), 201);
    drop(flat);

    let result = emulator_command()
        .args([
            "serve",
            "--port",
            "0",
            "--admin-port",
            "0",
            "--services",
            "blob,dfs",
            "--hns-accounts",
            ACCOUNT,
            "--shutdown-on-stdin-eof",
            "--location",
        ])
        .arg(location.path())
        .stdin(Stdio::null())
        .output()
        .unwrap();
    assert!(!result.status.success());
    assert!(String::from_utf8_lossy(&result.stderr).contains("cannot be opened with HNS"));

    let flat = Emulator::start(Some(location.path()), &[]);
    for (name, bytes) in [(FILE, b"parent file"), (BLOB, b"nested file")] {
        let response = flat.request(Method::GET, name, &[], b"");
        assert_eq!(response.status(), 200);
        assert_eq!(response.bytes().unwrap().as_ref(), bytes);
    }
}

#[test]
fn restart_preserves_acknowledged_data_and_recovers_an_interrupted_upload() {
    let root = tempfile::tempdir().unwrap();
    let location = root.path().join("store with spaces");
    let mut server = Emulator::start(Some(&location), &[]);
    server.create_container();
    let put = server.put(BLOB, &[], b"committed");
    assert_eq!(put.status(), 201);
    let saved_tag = etag(&put);
    let content = location.join("content");

    let partially_sent = "/testaccount/container/incomplete";
    let socket = server.start_partial_upload(partially_sent, 50, b"incomplete bytes");
    wait_for_staged_uploads(&content, 1);
    server.process.crash();
    drop(socket);
    let orphan = content.join("extent-00000000000000000000000000000001");
    fs::write(&orphan, b"durable but never referenced").unwrap();

    let restarted = Emulator::start(Some(&location), &[]);
    let committed = restarted.request(Method::GET, BLOB, &[], b"");
    assert_eq!(committed.status(), 200);
    assert_eq!(etag(&committed), saved_tag);
    assert_eq!(committed.bytes().unwrap().as_ref(), b"committed");
    error(
        restarted.request(Method::GET, partially_sent, &[], b""),
        404,
        "BlobNotFound",
    );
    let entries: Vec<PathBuf> = fs::read_dir(&content)
        .unwrap()
        .map(|item| item.unwrap().path())
        .collect();
    assert_eq!(entries.len(), 1);
    assert!(!orphan.exists());
}

const LEASE_A: &str = "aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa";
const LEASE_B: &str = "bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb";
const LEASED: &str = "/testaccount/container/leased.txt";
const LEASED_LEASE: &str = "/testaccount/container/leased.txt?comp=lease";
const CONTAINER_LEASE: &str = "/testaccount/container?restype=container&comp=lease";

fn lease_view(server: &Emulator, path: &str) -> (String, String, Option<String>) {
    let head = server.request(Method::HEAD, path, &[], b"");
    assert_eq!(head.status(), 200, "{path}");
    (
        header_text(&head, "x-ms-lease-state"),
        header_text(&head, "x-ms-lease-status"),
        head.headers()
            .get("x-ms-lease-duration")
            .map(|value| value.to_str().unwrap().to_owned()),
    )
}

fn acquire(seconds: &str, id: &str) -> [(&'static str, String); 3] {
    [
        ("x-ms-lease-action", "acquire".into()),
        ("x-ms-lease-duration", seconds.into()),
        ("x-ms-proposed-lease-id", id.into()),
    ]
}

fn lease_call(server: &Emulator, path: &str, headers: &[(&str, &str)]) -> Response {
    server.lease(path, headers)
}

/// One request per mutating blob operation, each carrying `lease` when given.
fn guarded_writes(server: &Emulator, lease: Option<&str>) -> Vec<(&'static str, Response)> {
    type WriteCase<'a> = (&'a str, Method, String, Vec<(&'a str, &'a str)>, &'a [u8]);
    let cases: [WriteCase<'_>; 6] = [
        (
            "put",
            Method::PUT,
            LEASED.into(),
            vec![("x-ms-blob-type", "BlockBlob")],
            b"v2",
        ),
        (
            "block",
            Method::PUT,
            format!("{LEASED}?comp=block&blockid=QQ=="),
            vec![],
            b"x",
        ),
        (
            "blocklist",
            Method::PUT,
            format!("{LEASED}?comp=blocklist"),
            vec![],
            b"<BlockList></BlockList>",
        ),
        (
            "metadata",
            Method::PUT,
            format!("{LEASED}?comp=metadata"),
            vec![("x-ms-meta-a", "b")],
            b"",
        ),
        (
            "properties",
            Method::PUT,
            format!("{LEASED}?comp=properties"),
            vec![("x-ms-blob-content-type", "text/x")],
            b"",
        ),
        ("delete", Method::DELETE, LEASED.into(), vec![], b""),
    ];
    cases
        .into_iter()
        .map(|(name, method, path, mut headers, body)| {
            if let Some(id) = lease {
                headers.push(("x-ms-lease-id", id));
            }
            (name, server.request(method, &path, &headers, body))
        })
        .collect()
}

#[test]
fn blob_leases_follow_the_state_machine_and_guard_every_write() {
    let server = Emulator::clocked();
    server.create_container();
    assert_eq!(server.put(LEASED, &[], b"v1").status(), 201);
    error(
        lease_call(&server, LEASED_LEASE, &[("x-ms-lease-duration", "15")]),
        400,
        "MissingRequiredHeader",
    );
    error(
        lease_call(
            &server,
            "/testaccount/container/absent?comp=lease",
            &[
                ("x-ms-lease-action", "acquire"),
                ("x-ms-lease-duration", "15"),
            ],
        ),
        404,
        "BlobNotFound",
    );
    for bad in ["14", "61", "0", "abc"] {
        error(
            lease_call(
                &server,
                LEASED_LEASE,
                &[
                    ("x-ms-lease-action", "acquire"),
                    ("x-ms-lease-duration", bad),
                ],
            ),
            400,
            "InvalidHeaderValue",
        );
    }
    assert_eq!(lease_view(&server, LEASED).0, "available");

    let original = server.request(Method::HEAD, LEASED, &[], b"");
    let stale_tag = "\"00000000000000000000000000000000\"";
    error(
        lease_call(
            &server,
            LEASED_LEASE,
            &[
                ("x-ms-lease-action", "acquire"),
                ("x-ms-lease-duration", "15"),
                ("if-match", stale_tag),
            ],
        ),
        412,
        "ConditionNotMet",
    );
    let pairs = acquire("15", LEASE_A);
    let refs: Vec<(&str, &str)> = pairs
        .iter()
        .map(|(name, value)| (*name, value.as_str()))
        .collect();
    let acquired = lease_call(&server, LEASED_LEASE, &refs);
    assert_eq!(acquired.status(), 201);
    assert_eq!(header_text(&acquired, "x-ms-lease-id"), LEASE_A);
    assert_eq!(
        etag(&acquired),
        etag(&original),
        "leasing does not change the ETag"
    );
    assert_eq!(
        lease_view(&server, LEASED),
        ("leased".into(), "locked".into(), Some("fixed".into()))
    );

    // Every mutating operation needs the id while the lease is active.
    for (name, response) in guarded_writes(&server, None) {
        assert_eq!(response.status(), 412, "{name}");
        assert_eq!(
            header_text(&response, "x-ms-error-code"),
            "LeaseIdMissing",
            "{name}"
        );
    }
    for (name, response) in guarded_writes(&server, Some(LEASE_B)) {
        assert_eq!(response.status(), 412, "{name}");
        assert_eq!(
            header_text(&response, "x-ms-error-code"),
            "LeaseIdMismatchWithBlobOperation",
            "{name}"
        );
    }
    assert_eq!(
        server
            .put(LEASED, &[("x-ms-lease-id", LEASE_A)], b"v2")
            .status(),
        201
    );
    assert_eq!(
        lease_view(&server, LEASED).0,
        "leased",
        "a write keeps the lease"
    );
    // Reads need no id, but a supplied id must match.
    assert_eq!(server.request(Method::GET, LEASED, &[], b"").status(), 200);
    assert_eq!(
        server
            .request(Method::GET, LEASED, &[("x-ms-lease-id", LEASE_A)], b"")
            .status(),
        200
    );
    error(
        server.request(Method::GET, LEASED, &[("x-ms-lease-id", LEASE_B)], b""),
        412,
        "LeaseIdMismatchWithBlobOperation",
    );
    // Set tier tolerates a missing id but rejects a wrong one.
    let tier = format!("{LEASED}?comp=tier");
    assert_eq!(
        server
            .request(Method::PUT, &tier, &[("x-ms-access-tier", "Cool")], b"")
            .status(),
        200
    );
    error(
        server.request(
            Method::PUT,
            &tier,
            &[("x-ms-access-tier", "Hot"), ("x-ms-lease-id", LEASE_B)],
            b"",
        ),
        412,
        "LeaseIdMismatchWithBlobOperation",
    );

    // Conflicting lease operations.
    let other = acquire("15", LEASE_B);
    let other: Vec<(&str, &str)> = other.iter().map(|(n, v)| (*n, v.as_str())).collect();
    error(
        lease_call(&server, LEASED_LEASE, &other),
        409,
        "LeaseAlreadyPresent",
    );
    error(
        lease_call(
            &server,
            LEASED_LEASE,
            &[("x-ms-lease-action", "renew"), ("x-ms-lease-id", LEASE_B)],
        ),
        409,
        "LeaseIdMismatchWithLeaseOperation",
    );
    error(
        lease_call(
            &server,
            LEASED_LEASE,
            &[("x-ms-lease-action", "release"), ("x-ms-lease-id", LEASE_B)],
        ),
        409,
        "LeaseIdMismatchWithLeaseOperation",
    );
    error(
        lease_call(
            &server,
            LEASED_LEASE,
            &[
                ("x-ms-lease-action", "change"),
                ("x-ms-lease-id", LEASE_B),
                ("x-ms-proposed-lease-id", LEASE_A),
            ],
        ),
        409,
        "LeaseIdMismatchWithLeaseOperation",
    );
    assert_eq!(
        lease_call(
            &server,
            LEASED_LEASE,
            &[("x-ms-lease-action", "renew"), ("x-ms-lease-id", LEASE_A)]
        )
        .status(),
        200
    );
    let changed = lease_call(
        &server,
        LEASED_LEASE,
        &[
            ("x-ms-lease-action", "change"),
            ("x-ms-lease-id", LEASE_A),
            ("x-ms-proposed-lease-id", LEASE_B),
        ],
    );
    assert_eq!(changed.status(), 200);
    assert_eq!(header_text(&changed, "x-ms-lease-id"), LEASE_B);
    error(
        server.put(LEASED, &[("x-ms-lease-id", LEASE_A)], b"v3"),
        412,
        "LeaseIdMismatchWithBlobOperation",
    );

    // Breaking: the old id still writes until the period ends.
    let broken = lease_call(
        &server,
        LEASED_LEASE,
        &[
            ("x-ms-lease-action", "break"),
            ("x-ms-lease-break-period", "5"),
        ],
    );
    assert_eq!(broken.status(), 202);
    assert_eq!(header_text(&broken, "x-ms-lease-time"), "5");
    assert_eq!(lease_view(&server, LEASED).0, "breaking");
    assert_eq!(
        server
            .put(LEASED, &[("x-ms-lease-id", LEASE_B)], b"v3")
            .status(),
        201
    );
    error(server.put(LEASED, &[], b"v4"), 412, "LeaseIdMissing");
    let again: Vec<(&str, &str)> = vec![
        ("x-ms-lease-action", "acquire"),
        ("x-ms-lease-duration", "15"),
        ("x-ms-proposed-lease-id", LEASE_B),
    ];
    error(
        lease_call(&server, LEASED_LEASE, &again),
        409,
        "LeaseIsBreakingAndCannotBeAcquired",
    );
    let foreign: Vec<(&str, &str)> = vec![
        ("x-ms-lease-action", "acquire"),
        ("x-ms-lease-duration", "15"),
        ("x-ms-proposed-lease-id", LEASE_A),
    ];
    error(
        lease_call(&server, LEASED_LEASE, &foreign),
        409,
        "LeaseAlreadyPresent",
    );
    error(
        lease_call(
            &server,
            LEASED_LEASE,
            &[("x-ms-lease-action", "renew"), ("x-ms-lease-id", LEASE_B)],
        ),
        409,
        "LeaseIsBrokenAndCannotBeRenewed",
    );
    error(
        lease_call(
            &server,
            LEASED_LEASE,
            &[
                ("x-ms-lease-action", "change"),
                ("x-ms-lease-id", LEASE_B),
                ("x-ms-proposed-lease-id", LEASE_A),
            ],
        ),
        409,
        "LeaseIsBreakingAndCannotBeChanged",
    );
    server.advance(6);
    assert_eq!(
        lease_view(&server, LEASED),
        ("broken".into(), "unlocked".into(), None)
    );
    error(
        server.put(LEASED, &[("x-ms-lease-id", LEASE_B)], b"v4"),
        412,
        "LeaseLost",
    );
    assert_eq!(server.put(LEASED, &[], b"v4").status(), 201);
    error(
        lease_call(
            &server,
            LEASED_LEASE,
            &[("x-ms-lease-action", "renew"), ("x-ms-lease-id", LEASE_B)],
        ),
        409,
        "LeaseIsBrokenAndCannotBeRenewed",
    );
    let released = lease_call(
        &server,
        LEASED_LEASE,
        &[("x-ms-lease-action", "release"), ("x-ms-lease-id", LEASE_B)],
    );
    assert_eq!(released.status(), 200);
    assert_eq!(lease_view(&server, LEASED).0, "available");
    error(
        lease_call(
            &server,
            LEASED_LEASE,
            &[("x-ms-lease-action", "release"), ("x-ms-lease-id", LEASE_B)],
        ),
        409,
        "LeaseNotPresentWithLeaseOperation",
    );
    for action in ["renew", "break"] {
        error(
            lease_call(
                &server,
                LEASED_LEASE,
                &[("x-ms-lease-action", action), ("x-ms-lease-id", LEASE_B)],
            ),
            409,
            "LeaseNotPresentWithLeaseOperation",
        );
    }
    error(
        server.put(LEASED, &[("x-ms-lease-id", LEASE_B)], b"v5"),
        412,
        "LeaseNotPresentWithBlobOperation",
    );

    // A fixed lease expires with the clock and can be renewed until another is taken.
    let fixed = lease_call(&server, LEASED_LEASE, &refs);
    assert_eq!(fixed.status(), 201);
    server.advance(14);
    assert_eq!(lease_view(&server, LEASED).0, "leased");
    error(server.put(LEASED, &[], b"v5"), 412, "LeaseIdMissing");
    server.advance(1);
    assert_eq!(
        lease_view(&server, LEASED),
        ("expired".into(), "unlocked".into(), None)
    );
    assert_eq!(server.put(LEASED, &[], b"v5").status(), 201);
    assert_eq!(
        lease_call(
            &server,
            LEASED_LEASE,
            &[("x-ms-lease-action", "renew"), ("x-ms-lease-id", LEASE_A)]
        )
        .status(),
        200
    );
    assert_eq!(lease_view(&server, LEASED).0, "leased");
    assert_eq!(
        lease_call(
            &server,
            LEASED_LEASE,
            &[("x-ms-lease-action", "release"), ("x-ms-lease-id", LEASE_A)]
        )
        .status(),
        200
    );

    // An infinite lease never expires and breaks immediately without a period.
    let infinite = acquire("-1", LEASE_A);
    let infinite: Vec<(&str, &str)> = infinite.iter().map(|(n, v)| (*n, v.as_str())).collect();
    assert_eq!(lease_call(&server, LEASED_LEASE, &infinite).status(), 201);
    server.advance(7200);
    assert_eq!(
        lease_view(&server, LEASED),
        ("leased".into(), "locked".into(), Some("infinite".into()))
    );
    let immediate = lease_call(&server, LEASED_LEASE, &[("x-ms-lease-action", "break")]);
    assert_eq!(immediate.status(), 202);
    assert_eq!(header_text(&immediate, "x-ms-lease-time"), "0");
    assert_eq!(lease_view(&server, LEASED).0, "broken");
    // Breaking a fixed lease without a period waits out the remainder.
    assert_eq!(lease_call(&server, LEASED_LEASE, &refs).status(), 201);
    let remainder = lease_call(&server, LEASED_LEASE, &[("x-ms-lease-action", "break")]);
    assert_eq!(header_text(&remainder, "x-ms-lease-time"), "15");
    assert_eq!(lease_view(&server, LEASED).0, "breaking");
    let shortened = lease_call(
        &server,
        LEASED_LEASE,
        &[
            ("x-ms-lease-action", "break"),
            ("x-ms-lease-break-period", "2"),
        ],
    );
    assert_eq!(header_text(&shortened, "x-ms-lease-time"), "2");

    // Listings report the lease.
    let listing = server
        .request(
            Method::GET,
            "/testaccount/container?restype=container&comp=list",
            &[],
            b"",
        )
        .text()
        .unwrap();
    assert!(listing.contains("<LeaseStatus>locked</LeaseStatus><LeaseState>breaking</LeaseState><LeaseDuration>fixed</LeaseDuration>"), "{listing}");
}

#[test]
fn container_leases_guard_delete_and_report_state_in_properties_and_listings() {
    let server = Emulator::clocked();
    server.create_container();
    assert_eq!(server.put(BLOB, &[], b"inside").status(), 201);
    let view = |server: &Emulator| {
        let properties = server.request(Method::GET, CONTAINER, &[], b"");
        assert_eq!(properties.status(), 200);
        (
            header_text(&properties, "x-ms-lease-state"),
            header_text(&properties, "x-ms-lease-status"),
            properties
                .headers()
                .get("x-ms-lease-duration")
                .map(|v| v.to_str().unwrap().to_owned()),
        )
    };
    assert_eq!(view(&server).0, "available");
    let pairs = acquire("-1", LEASE_A);
    let refs: Vec<(&str, &str)> = pairs.iter().map(|(n, v)| (*n, v.as_str())).collect();
    let acquired = server.lease(CONTAINER_LEASE, &refs);
    assert_eq!(acquired.status(), 201);
    assert_eq!(header_text(&acquired, "x-ms-lease-id"), LEASE_A);
    assert_eq!(
        view(&server),
        ("leased".into(), "locked".into(), Some("infinite".into()))
    );
    let containers = server
        .request(Method::GET, "/testaccount/?comp=list", &[], b"")
        .text()
        .unwrap();
    assert!(containers.contains("<LeaseStatus>locked</LeaseStatus><LeaseState>leased</LeaseState><LeaseDuration>infinite</LeaseDuration>"), "{containers}");

    error(
        server.request(Method::DELETE, CONTAINER, &[], b""),
        412,
        "LeaseIdMissing",
    );
    error(
        server.request(
            Method::DELETE,
            CONTAINER,
            &[("x-ms-lease-id", LEASE_B)],
            b"",
        ),
        412,
        "LeaseIdMismatchWithContainerOperation",
    );
    error(
        server.request(Method::GET, CONTAINER, &[("x-ms-lease-id", LEASE_B)], b""),
        412,
        "LeaseIdMismatchWithContainerOperation",
    );
    // Metadata and listing tolerate a missing id.
    let metadata = "/testaccount/container?restype=container&comp=metadata";
    assert_eq!(
        server
            .request(Method::PUT, metadata, &[("x-ms-meta-owner", "ops")], b"")
            .status(),
        200
    );
    error(
        server.request(
            Method::PUT,
            metadata,
            &[("x-ms-meta-owner", "ops"), ("x-ms-lease-id", LEASE_B)],
            b"",
        ),
        412,
        "LeaseIdMismatchWithContainerOperation",
    );
    assert_eq!(
        server
            .request(
                Method::GET,
                "/testaccount/container?restype=container&comp=list",
                &[("x-ms-lease-id", LEASE_A)],
                b""
            )
            .status(),
        200
    );
    error(
        server.lease(
            CONTAINER_LEASE,
            &[
                ("x-ms-lease-action", "acquire"),
                ("x-ms-lease-duration", "15"),
                ("x-ms-proposed-lease-id", LEASE_B),
            ],
        ),
        409,
        "LeaseAlreadyPresent",
    );
    let changed = server.lease(
        CONTAINER_LEASE,
        &[
            ("x-ms-lease-action", "change"),
            ("x-ms-lease-id", LEASE_A),
            ("x-ms-proposed-lease-id", LEASE_B),
        ],
    );
    assert_eq!(header_text(&changed, "x-ms-lease-id"), LEASE_B);
    let released = server.lease(
        CONTAINER_LEASE,
        &[("x-ms-lease-action", "release"), ("x-ms-lease-id", LEASE_B)],
    );
    assert_eq!(released.status(), 200);
    error(
        server.request(
            Method::DELETE,
            CONTAINER,
            &[("x-ms-lease-id", LEASE_B)],
            b"",
        ),
        412,
        "LeaseNotPresentWithContainerOperation",
    );
    error(
        server.lease(
            CONTAINER_LEASE,
            &[("x-ms-lease-action", "release"), ("x-ms-lease-id", LEASE_B)],
        ),
        409,
        "LeaseNotPresentWithLeaseOperation",
    );

    let fixed = acquire("15", LEASE_A);
    let fixed: Vec<(&str, &str)> = fixed.iter().map(|(n, v)| (*n, v.as_str())).collect();
    assert_eq!(server.lease(CONTAINER_LEASE, &fixed).status(), 201);
    let broke = server.lease(
        CONTAINER_LEASE,
        &[
            ("x-ms-lease-action", "break"),
            ("x-ms-lease-break-period", "10"),
        ],
    );
    assert_eq!(header_text(&broke, "x-ms-lease-time"), "10");
    assert_eq!(view(&server).0, "breaking");
    error(
        server.lease(
            CONTAINER_LEASE,
            &[("x-ms-lease-action", "renew"), ("x-ms-lease-id", LEASE_A)],
        ),
        409,
        "LeaseIsBrokenAndCannotBeRenewed",
    );
    server.advance(10);
    assert_eq!(view(&server).0, "broken");
    assert_eq!(
        server.request(Method::DELETE, CONTAINER, &[], b"").status(),
        202
    );
}

#[test]
fn leases_and_their_deadlines_survive_a_restart() {
    let location = tempfile::tempdir().unwrap();
    let server = Emulator::start(Some(location.path()), &["--test-clock"]);
    server.create_container();
    assert_eq!(server.put(LEASED, &[], b"held").status(), 201);
    let infinite = acquire("-1", LEASE_A);
    let infinite: Vec<(&str, &str)> = infinite.iter().map(|(n, v)| (*n, v.as_str())).collect();
    assert_eq!(server.lease(LEASED_LEASE, &infinite).status(), 201);
    assert_eq!(
        server
            .lease(
                CONTAINER_LEASE,
                &acquire("15", LEASE_B)
                    .iter()
                    .map(|(n, v)| (*n, v.as_str()))
                    .collect::<Vec<_>>()
            )
            .status(),
        201
    );
    drop(server);

    let restarted = Emulator::start(Some(location.path()), &["--test-clock"]);
    assert_eq!(
        lease_view(&restarted, LEASED),
        ("leased".into(), "locked".into(), Some("infinite".into()))
    );
    error(restarted.put(LEASED, &[], b"x"), 412, "LeaseIdMissing");
    assert_eq!(
        restarted
            .put(LEASED, &[("x-ms-lease-id", LEASE_A)], b"x")
            .status(),
        201
    );
    let properties = restarted.request(Method::GET, CONTAINER, &[], b"");
    assert_eq!(header_text(&properties, "x-ms-lease-state"), "leased");
    // The container lease was 15 seconds long; a clock moved on after the restart expires it.
    restarted.advance(16);
    let expired = restarted.request(Method::GET, CONTAINER, &[], b"");
    assert_eq!(header_text(&expired, "x-ms-lease-state"), "expired");
}

const PAST: &str = "Fri, 03 Nov 2023 12:00:00 GMT";
const FUTURE: &str = "Tue, 03 Nov 2099 12:00:00 GMT";

#[test]
fn blob_properties_metadata_and_content_headers_round_trip() {
    let server = Emulator::start(None, &[]);
    server.create_container();
    let put = server.put(
        BLOB,
        &[
            ("x-ms-blob-content-type", "text/x-test"),
            ("x-ms-blob-content-encoding", "gzip"),
            ("x-ms-blob-content-language", "en-AU"),
            (
                "x-ms-blob-content-disposition",
                "attachment; filename=a.txt",
            ),
            ("x-ms-blob-cache-control", "no-cache"),
            ("x-ms-meta-owner", "ops"),
            ("x-ms-meta-team", "core"),
        ],
        b"hello world",
    );
    assert_eq!(put.status(), 201);
    let first_tag = etag(&put);
    for method in [Method::GET, Method::HEAD] {
        let read = server.request(method, BLOB, &[], b"");
        assert_eq!(read.status(), 200);
        let headers = read.headers().clone();
        assert_eq!(headers["content-type"], "text/x-test");
        assert_eq!(headers["content-encoding"], "gzip");
        assert_eq!(headers["content-language"], "en-AU");
        assert_eq!(headers["content-disposition"], "attachment; filename=a.txt");
        assert_eq!(headers["cache-control"], "no-cache");
        assert_eq!(headers["x-ms-meta-owner"], "ops");
        assert_eq!(headers["x-ms-meta-team"], "core");
        assert_eq!(headers["x-ms-blob-type"], "BlockBlob");
        assert_eq!(headers["x-ms-lease-state"], "available");
        assert_eq!(headers["x-ms-lease-status"], "unlocked");
        assert_eq!(headers["x-ms-access-tier"], "Hot");
        assert_eq!(headers["x-ms-access-tier-inferred"], "true");
        assert_eq!(headers["x-ms-server-encrypted"], "true");
        assert_eq!(headers["accept-ranges"], "bytes");
        assert!(headers.contains_key("x-ms-creation-time"));
        assert!(!headers.contains_key("x-ms-copy-id"));
    }
    // Plain content headers also set properties on Put Blob.
    let plain = "/testaccount/container/plain.json";
    assert_eq!(
        server
            .put(
                plain,
                &[
                    ("content-type", "application/json"),
                    ("content-language", "fr"),
                    ("cache-control", "max-age=1"),
                    ("content-encoding", "br")
                ],
                b"{}"
            )
            .status(),
        201
    );
    let plain_read = server.request(Method::HEAD, plain, &[], b"");
    assert_eq!(plain_read.headers()["content-type"], "application/json");
    assert_eq!(plain_read.headers()["content-language"], "fr");
    assert_eq!(plain_read.headers()["content-encoding"], "br");
    assert_eq!(plain_read.headers()["cache-control"], "max-age=1");

    // Set Blob Properties replaces every content property; metadata and bytes stay.
    let properties = format!("{BLOB}?comp=properties");
    let set = server.request(
        Method::PUT,
        &properties,
        &[
            ("x-ms-blob-cache-control", "max-age=5"),
            ("x-ms-blob-content-md5", "1B2M2Y8AsgTpgAmY7PhCfg=="),
        ],
        b"",
    );
    assert_eq!(set.status(), 200);
    assert_ne!(etag(&set), first_tag);
    assert!(set.headers().contains_key("last-modified"));
    let after = server.request(Method::GET, BLOB, &[], b"");
    assert_eq!(after.headers()["cache-control"], "max-age=5");
    assert_eq!(after.headers()["content-type"], "application/octet-stream");
    assert_eq!(after.headers()["content-md5"], "1B2M2Y8AsgTpgAmY7PhCfg==");
    for cleared in [
        "content-encoding",
        "content-language",
        "content-disposition",
    ] {
        assert!(!after.headers().contains_key(cleared), "{cleared}");
    }
    assert_eq!(after.headers()["x-ms-meta-owner"], "ops");
    assert_eq!(etag(&after), etag(&set));
    assert_eq!(after.bytes().unwrap().as_ref(), b"hello world");
    // With no property headers the properties stay, but the ETag still moves.
    let untouched = server.request(Method::PUT, &properties, &[], b"");
    assert_ne!(etag(&untouched), etag(&set));
    assert_eq!(
        server.request(Method::HEAD, BLOB, &[], b"").headers()["cache-control"],
        "max-age=5"
    );

    // Set Blob Metadata replaces all user metadata; Get Blob Metadata returns it.
    let metadata = format!("{BLOB}?comp=metadata");
    let replaced = server.request(Method::PUT, &metadata, &[("x-ms-meta-only", "this")], b"");
    assert_eq!(replaced.status(), 200);
    assert_ne!(etag(&replaced), etag(&untouched));
    for method in [Method::GET, Method::HEAD] {
        let read = server.request(method, &metadata, &[], b"");
        assert_eq!(read.status(), 200);
        assert_eq!(read.headers()["x-ms-meta-only"], "this");
        assert!(!read.headers().contains_key("x-ms-meta-owner"));
        assert_eq!(etag(&read), etag(&replaced));
        assert!(read.bytes().unwrap().is_empty());
    }
    error(
        server.request(Method::PUT, &metadata, &[("x-ms-meta-bad-name", "1")], b""),
        400,
        "InvalidHeaderValue",
    );
    error(
        server.request(
            Method::PUT,
            "/testaccount/container/absent?comp=metadata",
            &[],
            b"",
        ),
        404,
        "BlobNotFound",
    );

    // Put Block List carries the same headers, metadata, and tier.
    let committed = "/testaccount/container/committed.bin";
    assert_eq!(
        server
            .request(
                Method::PUT,
                &format!("{committed}?comp=block&blockid=QQ=="),
                &[],
                b"abc"
            )
            .status(),
        201
    );
    let list = server.request(
        Method::PUT,
        &format!("{committed}?comp=blocklist"),
        &[
            ("x-ms-blob-content-type", "image/png"),
            ("x-ms-blob-content-md5", "XUFAKrxLKna5cZ2REBfFkg=="),
            ("x-ms-meta-kind", "list"),
            ("x-ms-access-tier", "Cool"),
        ],
        b"<BlockList><Latest>QQ==</Latest></BlockList>",
    );
    assert_eq!(list.status(), 201);
    let read = server.request(Method::HEAD, committed, &[], b"");
    assert_eq!(read.headers()["content-type"], "image/png");
    assert_eq!(read.headers()["content-md5"], "XUFAKrxLKna5cZ2REBfFkg==");
    assert_eq!(read.headers()["x-ms-meta-kind"], "list");
    assert_eq!(read.headers()["x-ms-access-tier"], "Cool");
    assert!(!read.headers().contains_key("x-ms-access-tier-inferred"));
}

#[test]
fn container_metadata_and_properties_round_trip_with_listings() {
    let server = Emulator::start(None, &[]);
    let created = server.request(
        Method::PUT,
        CONTAINER,
        &[
            ("x-ms-meta-purpose", "tests"),
            ("x-ms-blob-public-access", "blob"),
        ],
        b"",
    );
    assert_eq!(created.status(), 201);
    let properties = server.request(Method::GET, CONTAINER, &[], b"");
    assert_eq!(properties.headers()["x-ms-meta-purpose"], "tests");
    assert_eq!(properties.headers()["x-ms-blob-public-access"], "blob");
    assert_eq!(properties.headers()["x-ms-lease-state"], "available");
    assert_eq!(
        properties.headers()["x-ms-has-immutability-policy"],
        "false"
    );
    assert_eq!(properties.headers()["x-ms-has-legal-hold"], "false");
    assert!(
        properties
            .headers()
            .contains_key("x-ms-default-encryption-scope")
    );
    let metadata = "/testaccount/container?restype=container&comp=metadata";
    let set = server.request(Method::PUT, metadata, &[("x-ms-meta-owner", "ops")], b"");
    assert_eq!(set.status(), 200);
    assert_ne!(etag(&set), etag(&properties));
    for method in [Method::GET, Method::HEAD] {
        let read = server.request(method, metadata, &[], b"");
        assert_eq!(read.headers()["x-ms-meta-owner"], "ops");
        assert!(!read.headers().contains_key("x-ms-meta-purpose"));
        assert_eq!(etag(&read), etag(&set));
    }
    error(
        server.request(Method::PUT, metadata, &[("if-unmodified-since", PAST)], b""),
        412,
        "ConditionNotMet",
    );
    error(
        server.request(Method::PUT, metadata, &[("if-match", "*")], b""),
        501,
        "NotImplemented",
    );
    let listing = server
        .request(
            Method::GET,
            "/testaccount/?comp=list&include=metadata",
            &[],
            b"",
        )
        .text()
        .unwrap();
    assert!(
        listing.contains("<Metadata><owner>ops</owner></Metadata>"),
        "{listing}"
    );
    assert!(
        listing.contains("<PublicAccess>blob</PublicAccess>"),
        "{listing}"
    );
    let plain = server
        .request(Method::GET, "/testaccount/?comp=list", &[], b"")
        .text()
        .unwrap();
    assert!(!plain.contains("<Metadata>"));
    error(
        server.request(
            Method::PUT,
            CONTAINER,
            &[("x-ms-blob-public-access", "everyone")],
            b"",
        ),
        400,
        "InvalidHeaderValue",
    );
}

#[test]
fn conditional_headers_apply_to_reads_and_writes() {
    let server = Emulator::start(None, &[]);
    server.create_container();
    let put = server.put(BLOB, &[], b"conditions");
    let tag = etag(&put);
    let modified = header_text(&put, "last-modified");
    let other = "\"00000000000000000000000000000001\"";
    let get = |headers: &[(&str, &str)]| server.request(Method::GET, BLOB, headers, b"");

    // Date conditions on reads: 304 when unmodified since, 412 when modified since.
    assert_eq!(get(&[("if-modified-since", &modified)]).status(), 304);
    assert_eq!(get(&[("if-modified-since", PAST)]).status(), 200);
    assert_eq!(get(&[("if-modified-since", FUTURE)]).status(), 304);
    assert_eq!(get(&[("if-unmodified-since", &modified)]).status(), 200);
    error(
        get(&[("if-unmodified-since", PAST)]),
        412,
        "ConditionNotMet",
    );
    assert_eq!(
        server
            .request(Method::HEAD, BLOB, &[("if-modified-since", FUTURE)], b"")
            .status(),
        304
    );
    // Both ETag conditions together.
    assert_eq!(
        get(&[("if-match", &tag), ("if-none-match", other)]).status(),
        200
    );
    assert_eq!(
        get(&[("if-match", &tag), ("if-none-match", &tag)]).status(),
        304
    );
    error(
        get(&[("if-match", other), ("if-none-match", other)]),
        412,
        "ConditionNotMet",
    );
    assert_eq!(get(&[("if-match", "*")]).status(), 200);
    // A combination of ETag and date conditions.
    assert_eq!(
        get(&[("if-match", &tag), ("if-unmodified-since", FUTURE)]).status(),
        200
    );
    error(
        get(&[("if-match", &tag), ("if-unmodified-since", PAST)]),
        412,
        "ConditionNotMet",
    );

    // The same conditions guard writes with 412 (never 304).
    for headers in [
        vec![("if-modified-since", FUTURE)],
        vec![("if-unmodified-since", PAST)],
        vec![("if-match", other)],
        vec![("if-none-match", tag.as_str())],
    ] {
        error(server.put(BLOB, &headers, b"nope"), 412, "ConditionNotMet");
        error(
            server.request(Method::DELETE, BLOB, &headers, b""),
            412,
            "ConditionNotMet",
        );
        error(
            server.request(Method::PUT, &format!("{BLOB}?comp=metadata"), &headers, b""),
            412,
            "ConditionNotMet",
        );
        error(
            server.request(
                Method::PUT,
                &format!("{BLOB}?comp=properties"),
                &headers,
                b"",
            ),
            412,
            "ConditionNotMet",
        );
    }
    assert_eq!(get(&[]).bytes().unwrap().as_ref(), b"conditions");
    assert_eq!(
        server
            .put(
                BLOB,
                &[
                    ("if-match", &tag),
                    ("if-unmodified-since", FUTURE),
                    ("if-none-match", other)
                ],
                b"two"
            )
            .status(),
        201
    );
    error(
        get(&[("if-modified-since", "not a date")]),
        400,
        "InvalidHeaderValue",
    );
    error(
        server.request(
            Method::GET,
            &format!("{BLOB}?comp=blocklist"),
            &[("if-match", other)],
            b"",
        ),
        412,
        "ConditionNotMet",
    );
}

#[test]
fn range_reads_can_return_a_checksum_of_the_range() {
    let server = Emulator::start(None, &[]);
    server.create_container();
    assert_eq!(server.put(BLOB, &[], b"hello world").status(), 201);
    let block = server.request(
        Method::PUT,
        "/testaccount/container/crc?comp=block&blockid=QQ==",
        &[],
        b"hello",
    );
    let hello_crc = header_text(&block, "x-ms-content-crc64");
    let ranged = server.request(
        Method::GET,
        BLOB,
        &[
            ("x-ms-range", "bytes=0-4"),
            ("x-ms-range-get-content-md5", "true"),
        ],
        b"",
    );
    assert_eq!(ranged.status(), 206);
    assert_eq!(ranged.headers()["content-md5"], "XUFAKrxLKna5cZ2REBfFkg==");
    assert_eq!(ranged.bytes().unwrap().as_ref(), b"hello");
    let crc = server.request(
        Method::GET,
        BLOB,
        &[
            ("range", "bytes=0-4"),
            ("x-ms-range-get-content-crc64", "true"),
        ],
        b"",
    );
    assert_eq!(crc.headers()["x-ms-content-crc64"], hello_crc.as_str());
    assert!(!crc.headers().contains_key("content-md5"));
    // Without a range the stored digest is returned and the flag is ignored.
    let whole = server.request(
        Method::GET,
        BLOB,
        &[("x-ms-range-get-content-md5", "true")],
        b"",
    );
    assert_eq!(whole.status(), 200);
    assert_eq!(whole.headers()["content-md5"], "XrY7u+Ae7tCTyyK7j1rNww==");
    error(
        server.request(
            Method::GET,
            BLOB,
            &[
                ("range", "bytes=0-4"),
                ("x-ms-range-get-content-md5", "true"),
                ("x-ms-range-get-content-crc64", "true"),
            ],
            b"",
        ),
        400,
        "BothCrc64AndMd5RangeHeaderPresent",
    );
}

#[test]
fn listings_collapse_delimited_prefixes_and_page_through_them() {
    let server = Emulator::start(None, &[]);
    server.create_container();
    for name in ["a/1", "a/2", "b", "c/d/e", "c/f"] {
        assert_eq!(
            server
                .put(
                    &format!("/testaccount/container/{name}"),
                    &[("x-ms-meta-n", "v")],
                    b"x"
                )
                .status(),
            201
        );
    }
    let base = "/testaccount/container?restype=container&comp=list";
    let names = |body: &str, tag: &str| -> Vec<String> {
        body.split(&format!("<{tag}><Name>"))
            .skip(1)
            .map(|part| part.split_once("</Name>").unwrap().0.to_owned())
            .collect()
    };
    let flat = server
        .request(Method::GET, &format!("{base}&delimiter=%2F"), &[], b"")
        .text()
        .unwrap();
    assert!(flat.contains("<Delimiter>/</Delimiter>"));
    assert_eq!(names(&flat, "BlobPrefix"), ["a/", "c/"]);
    assert_eq!(names(&flat, "Blob"), ["b"]);
    let (first_prefix, blob_at, second_prefix) = (
        flat.find("<Name>a/</Name>").unwrap(),
        flat.find("<Name>b</Name>").unwrap(),
        flat.find("<Name>c/</Name>").unwrap(),
    );
    assert!(
        first_prefix < blob_at && blob_at < second_prefix,
        "entries stay in name order"
    );

    let nested = server
        .request(
            Method::GET,
            &format!("{base}&delimiter=%2F&prefix=c%2F"),
            &[],
            b"",
        )
        .text()
        .unwrap();
    assert_eq!(names(&nested, "BlobPrefix"), ["c/d/"]);
    assert_eq!(names(&nested, "Blob"), ["c/f"]);
    assert!(nested.contains("<Prefix>c/</Prefix>"));

    // Pages count blobs and prefixes together, and the marker skips a collapsed prefix.
    let mut seen = Vec::new();
    let mut marker = String::new();
    loop {
        let page = server
            .request(
                Method::GET,
                &format!("{base}&delimiter=%2F&maxresults=1&marker={marker}"),
                &[],
                b"",
            )
            .text()
            .unwrap();
        let on_page: Vec<String> = page
            .split("<Name>")
            .skip(1)
            .map(|part| part.split_once("</Name>").unwrap().0.to_owned())
            .collect();
        assert_eq!(on_page.len(), 1, "{page}");
        seen.extend(on_page);
        marker = page
            .split_once("<NextMarker>")
            .unwrap()
            .1
            .split_once("</NextMarker>")
            .unwrap()
            .0
            .to_owned();
        if marker.is_empty() {
            break;
        }
    }
    assert_eq!(seen, ["a/", "b", "c/"]);
    // Without a delimiter the listing stays flat.
    let all = server.request(Method::GET, base, &[], b"").text().unwrap();
    assert_eq!(names(&all, "Blob"), ["a/1", "a/2", "b", "c/d/e", "c/f"]);
    assert!(!all.contains("BlobPrefix"));
    let long = server
        .request(
            Method::GET,
            &format!("{base}&delimiter=d%2F&prefix=c%2F"),
            &[],
            b"",
        )
        .text()
        .unwrap();
    assert_eq!(names(&long, "BlobPrefix"), ["c/d/"]);

    // Uncommitted blobs and copy/metadata sections appear only when asked for.
    assert_eq!(
        server
            .request(
                Method::PUT,
                "/testaccount/container/pending?comp=block&blockid=QQ==",
                &[],
                b"abc"
            )
            .status(),
        201
    );
    let hidden = server.request(Method::GET, base, &[], b"").text().unwrap();
    assert!(!hidden.contains("pending"));
    let shown = server
        .request(
            Method::GET,
            &format!("{base}&include=uncommittedblobs%2Cmetadata%2Ccopy&prefix=pending"),
            &[],
            b"",
        )
        .text()
        .unwrap();
    assert!(
        shown.contains("<Name>pending</Name><Properties><Content-Length>0</Content-Length>"),
        "{shown}"
    );
    let with_metadata = server
        .request(
            Method::GET,
            &format!("{base}&include=metadata&prefix=b"),
            &[],
            b"",
        )
        .text()
        .unwrap();
    assert!(
        with_metadata.contains("<Metadata><n>v</n></Metadata>"),
        "{with_metadata}"
    );
    let properties = &with_metadata;
    for field in [
        "<Creation-Time>",
        "<Content-Encoding></Content-Encoding>",
        "<BlobType>BlockBlob</BlobType>",
        "<AccessTier>Hot</AccessTier>",
        "<AccessTierInferred>true</AccessTierInferred>",
        "<LeaseStatus>unlocked</LeaseStatus>",
        "<LeaseState>available</LeaseState>",
        "<ServerEncrypted>true</ServerEncrypted>",
    ] {
        assert!(properties.contains(field), "{field} in {properties}");
    }
}

#[test]
fn access_tiers_are_stored_and_archived_blobs_cannot_be_read() {
    let server = Emulator::start(None, &[]);
    server.create_container();
    assert_eq!(
        server
            .put(BLOB, &[("x-ms-access-tier", "Cold")], b"tiered")
            .status(),
        201
    );
    assert_eq!(
        server.request(Method::HEAD, BLOB, &[], b"").headers()["x-ms-access-tier"],
        "Cold"
    );
    let tier = format!("{BLOB}?comp=tier");
    let set = |value: &str| server.request(Method::PUT, &tier, &[("x-ms-access-tier", value)], b"");
    assert_eq!(set("Cool").status(), 200);
    let head = server.request(Method::HEAD, BLOB, &[], b"");
    assert_eq!(head.headers()["x-ms-access-tier"], "Cool");
    assert!(head.headers().contains_key("x-ms-access-tier-change-time"));
    assert!(!head.headers().contains_key("x-ms-access-tier-inferred"));
    let listing = server
        .request(
            Method::GET,
            "/testaccount/container?restype=container&comp=list",
            &[],
            b"",
        )
        .text()
        .unwrap();
    assert!(listing.contains("<AccessTier>Cool</AccessTier>"));
    assert_eq!(set("Archive").status(), 200);
    error(
        server.request(Method::GET, BLOB, &[], b""),
        409,
        "BlobArchived",
    );
    let source = blob_url(&server, BLOB);
    let dest = "/testaccount/container/tier-copy.bin";
    assert_eq!(server.put(dest, &[], b"keep").status(), 201);
    let before = etag(&server.request(Method::HEAD, dest, &[], b""));
    error(
        server.request(
            Method::PUT,
            dest,
            &[
                ("x-ms-blob-type", "BlockBlob"),
                ("x-ms-copy-source", &source),
            ],
            b"",
        ),
        409,
        "BlobArchived",
    );
    let unchanged = server.request(Method::GET, dest, &[], b"");
    assert_eq!(etag(&unchanged), before);
    assert_eq!(unchanged.bytes().unwrap().as_ref(), b"keep");
    assert_eq!(
        server.request(Method::HEAD, BLOB, &[], b"").headers()["x-ms-access-tier"],
        "Archive"
    );
    assert_eq!(set("Hot").status(), 202, "leaving Archive is a rehydration");
    assert_eq!(
        server
            .request(Method::GET, BLOB, &[], b"")
            .bytes()
            .unwrap()
            .as_ref(),
        b"tiered"
    );
    error(set("Lukewarm"), 400, "InvalidHeaderValue");
    error(
        server.request(Method::PUT, &tier, &[], b""),
        400,
        "MissingRequiredHeader",
    );
    error(
        server.request(
            Method::PUT,
            "/testaccount/container/absent?comp=tier",
            &[("x-ms-access-tier", "Hot")],
            b"",
        ),
        404,
        "BlobNotFound",
    );
    // Overwriting a blob drops its explicit tier.
    assert_eq!(server.put(BLOB, &[], b"again").status(), 201);
    assert_eq!(
        server.request(Method::HEAD, BLOB, &[], b"").headers()["x-ms-access-tier-inferred"],
        "true"
    );
}

const BLOB_NAME: &str = "docs/a&b.txt";

fn sas_request(server: &Emulator, method: Method, path: &str, sas: &str, body: &[u8]) -> Response {
    let separator = if path.contains('?') { '&' } else { '?' };
    let creates_blob = !path.contains("restype=") && !path.contains("comp=");
    let headers: &[(&str, &str)] = if method == Method::PUT && creates_blob {
        &[("x-ms-blob-type", "BlockBlob")]
    } else {
        &[]
    };
    server.raw(method, &format!("{path}{separator}{sas}"), headers, body)
}

#[test]
fn service_sas_tokens_authorize_by_resource_permission_and_time() {
    let server = Emulator::clocked();
    server.create_container();
    assert_eq!(
        server
            .put(BLOB, &[("x-ms-meta-k", "v")], b"sas body")
            .status(),
        201
    );
    let far = "2099-01-01T00:00:00Z";
    let blob_sas =
        |permissions: &str| service_sas("container", Some(BLOB_NAME), permissions, far).build();
    let container_sas =
        |permissions: &str| service_sas("container", None, permissions, far).build();
    let listing = "/testaccount/container?restype=container&comp=list";
    let denied = |response: Response, status: u16, code: &str| error(response, status, code);

    // A blob SAS is bound to its blob and its permissions.
    let read = sas_request(&server, Method::GET, BLOB, &blob_sas("r"), b"");
    assert_eq!(
        read.status(),
        200,
        "no x-ms-version or Authorization needed"
    );
    assert_eq!(read.bytes().unwrap().as_ref(), b"sas body");
    assert_eq!(
        sas_request(&server, Method::HEAD, BLOB, &blob_sas("r"), b"").status(),
        200
    );
    denied(
        sas_request(&server, Method::PUT, BLOB, &blob_sas("r"), b"x"),
        403,
        "AuthorizationPermissionMismatch",
    );
    denied(
        sas_request(&server, Method::DELETE, BLOB, &blob_sas("rw"), b""),
        403,
        "AuthorizationPermissionMismatch",
    );
    denied(
        sas_request(&server, Method::GET, BLOB, &blob_sas("w"), b""),
        403,
        "AuthorizationPermissionMismatch",
    );
    assert_eq!(
        sas_request(&server, Method::PUT, BLOB, &blob_sas("w"), b"written").status(),
        201
    );
    assert_eq!(
        sas_request(&server, Method::PUT, BLOB, &blob_sas("c"), b"created").status(),
        201
    );
    let props = format!("{BLOB}?comp=properties");
    assert_eq!(
        sas_request(&server, Method::PUT, &props, &blob_sas("w"), b"").status(),
        200
    );
    denied(
        sas_request(&server, Method::PUT, &props, &blob_sas("r"), b""),
        403,
        "AuthorizationPermissionMismatch",
    );
    let meta = format!("{BLOB}?comp=metadata");
    assert_eq!(
        sas_request(&server, Method::PUT, &meta, &blob_sas("racwdl"), b"").status(),
        200
    );
    assert_eq!(
        sas_request(&server, Method::DELETE, BLOB, &blob_sas("d"), b"").status(),
        202
    );
    assert_eq!(server.put(BLOB, &[], b"back").status(), 201);

    // A blob SAS cannot reach other blobs or the container; a container SAS reaches both.
    denied(
        sas_request(
            &server,
            Method::GET,
            "/testaccount/container/other.txt",
            &blob_sas("r"),
            b"",
        ),
        403,
        "AuthenticationFailed",
    );
    denied(
        sas_request(&server, Method::GET, listing, &blob_sas("rl"), b""),
        403,
        "AuthorizationResourceTypeMismatch",
    );
    assert_eq!(
        sas_request(&server, Method::GET, BLOB, &container_sas("r"), b"").status(),
        200
    );
    assert_eq!(
        sas_request(&server, Method::GET, listing, &container_sas("l"), b"").status(),
        200
    );
    denied(
        sas_request(&server, Method::GET, listing, &container_sas("r"), b""),
        403,
        "AuthorizationPermissionMismatch",
    );
    assert_eq!(
        sas_request(&server, Method::GET, CONTAINER, &container_sas("r"), b"").status(),
        200
    );
    let elsewhere = service_sas("elsewhere", None, "rl", far).build();
    denied(
        sas_request(&server, Method::GET, BLOB, &elsewhere, b""),
        403,
        "AuthenticationFailed",
    );
    // Service SAS tokens cannot do account-level work.
    denied(
        sas_request(
            &server,
            Method::GET,
            "/testaccount/?comp=list",
            &container_sas("rl"),
            b"",
        ),
        403,
        "AuthorizationResourceTypeMismatch",
    );
    denied(
        sas_request(&server, Method::PUT, CONTAINER, &container_sas("rwdl"), b""),
        403,
        "AuthorizationResourceTypeMismatch",
    );
    // Tampering with any signed field invalidates the signature.
    let tampered = blob_sas("r").replace("sp=r", "sp=rw");
    denied(
        sas_request(&server, Method::GET, BLOB, &tampered, b""),
        403,
        "AuthenticationFailed",
    );
    let forged = blob_sas("r").replace("&sig=", "&sig=A");
    denied(
        sas_request(&server, Method::GET, BLOB, &forged, b""),
        403,
        "AuthenticationFailed",
    );
    denied(
        sas_request(
            &server,
            Method::GET,
            BLOB,
            &blob_sas("r").replace(far.get(..4).unwrap(), "2098"),
            b"",
        ),
        403,
        "AuthenticationFailed",
    );
    // A SAS together with an Authorization header is ambiguous.
    denied(
        server.request(Method::GET, &format!("{BLOB}?{}", blob_sas("r")), &[], b""),
        403,
        "AuthenticationFailed",
    );

    // Validity window, evaluated on the server's clock.
    let mut windowed = service_sas("container", Some(BLOB_NAME), "r", &in_seconds(120));
    windowed.start = in_seconds(60);
    let windowed = windowed.build();
    denied(
        sas_request(&server, Method::GET, BLOB, &windowed, b""),
        403,
        "AuthenticationFailed",
    );
    server.advance(61);
    assert_eq!(
        sas_request(&server, Method::GET, BLOB, &windowed, b"").status(),
        200
    );
    server.advance(60);
    denied(
        sas_request(&server, Method::GET, BLOB, &windowed, b""),
        403,
        "AuthenticationFailed",
    );
    let past = service_sas("container", Some(BLOB_NAME), "r", "2020-01-01T00:00:00Z").build();
    denied(
        sas_request(&server, Method::GET, BLOB, &past, b""),
        403,
        "AuthenticationFailed",
    );

    // Response header overrides, protocol, and user-delegation tokens.
    let mut overriding = service_sas("container", Some(BLOB_NAME), "r", far);
    overriding.response_type = "text/csv".into();
    let overridden = sas_request(&server, Method::GET, BLOB, &overriding.build(), b"");
    assert_eq!(overridden.headers()["content-type"], "text/csv");
    let mut secure = service_sas("container", Some(BLOB_NAME), "r", far);
    secure.protocol = "https".into();
    denied(
        sas_request(&server, Method::GET, BLOB, &secure.build(), b""),
        403,
        "AuthorizationProtocolMismatch",
    );
    let mut both = service_sas("container", Some(BLOB_NAME), "r", far);
    both.protocol = "https,http".into();
    assert_eq!(
        sas_request(&server, Method::GET, BLOB, &both.build(), b"").status(),
        200
    );
    let mut local = service_sas("container", Some(BLOB_NAME), "r", far);
    local.ip = "10.9.8.7".into();
    assert_eq!(
        sas_request(&server, Method::GET, BLOB, &local.build(), b"").status(),
        200,
        "the peer address is unknown to the router, so sip is not enforced"
    );
    denied(
        sas_request(
            &server,
            Method::GET,
            BLOB,
            "sv=2023-11-03&sr=b&sp=r&se=2099-01-01T00%3A00%3A00Z&skoid=oid&sktid=tid&sig=x",
            b"",
        ),
        403,
        "AuthenticationFailed",
    );
    denied(
        sas_request(
            &server,
            Method::GET,
            BLOB,
            "sv=2023-11-03&sr=b&sp=r&sig=x",
            b"",
        ),
        403,
        "AuthenticationFailed",
    );
    denied(
        sas_request(
            &server,
            Method::GET,
            BLOB,
            "sr=b&sp=r&se=2099-01-01T00%3A00%3A00Z&sig=x",
            b"",
        ),
        403,
        "AuthenticationFailed",
    );
}

#[test]
fn stored_access_policies_drive_service_sas_permissions_and_expiry() {
    let server = Emulator::clocked();
    server.create_container();
    assert_eq!(server.put(BLOB, &[], b"policy").status(), 201);
    let acl_path = "/testaccount/container?restype=container&comp=acl";
    let policies = format!(
        "<?xml version=\"1.0\" encoding=\"utf-8\"?><SignedIdentifiers>\
         <SignedIdentifier><Id>reader</Id><AccessPolicy><Start>2020-01-01T00:00:00Z</Start><Expiry>2099-01-01T00:00:00Z</Expiry><Permission>rl</Permission></AccessPolicy></SignedIdentifier>\
         <SignedIdentifier><Id>old</Id><AccessPolicy><Expiry>2021-01-01T00:00:00Z</Expiry><Permission>r</Permission></AccessPolicy></SignedIdentifier>\
         <SignedIdentifier><Id>short</Id><AccessPolicy><Expiry>{}</Expiry><Permission>r</Permission></AccessPolicy></SignedIdentifier>\
         </SignedIdentifiers>",
        in_seconds(30)
    );
    let before = server.request(Method::GET, CONTAINER, &[], b"");
    let set = server.request(
        Method::PUT,
        acl_path,
        &[("x-ms-blob-public-access", "container")],
        policies.as_bytes(),
    );
    assert_eq!(set.status(), 200);
    assert_ne!(etag(&set), etag(&before));
    let read = server.request(Method::GET, acl_path, &[], b"");
    assert_eq!(read.status(), 200);
    assert_eq!(read.headers()["x-ms-blob-public-access"], "container");
    assert_eq!(etag(&read), etag(&set));
    let body = read.text().unwrap();
    for expected in [
        "<Id>reader</Id>",
        "<Permission>rl</Permission>",
        "<Expiry>2099-01-01T00:00:00Z</Expiry>",
        "<Id>old</Id>",
        "<Id>short</Id>",
    ] {
        assert!(body.contains(expected), "{expected} in {body}");
    }

    let by_policy = |id: &str, blob: Option<&str>| {
        let mut sas = service_sas("container", blob, "", "");
        sas.identifier = id.into();
        sas.build()
    };
    let listing = "/testaccount/container?restype=container&comp=list";
    assert_eq!(
        sas_request(
            &server,
            Method::GET,
            BLOB,
            &by_policy("reader", Some(BLOB_NAME)),
            b""
        )
        .status(),
        200
    );
    assert_eq!(
        sas_request(&server, Method::GET, BLOB, &by_policy("reader", None), b"").status(),
        200
    );
    assert_eq!(
        sas_request(
            &server,
            Method::GET,
            listing,
            &by_policy("reader", None),
            b""
        )
        .status(),
        200
    );
    error(
        sas_request(
            &server,
            Method::PUT,
            BLOB,
            &by_policy("reader", Some(BLOB_NAME)),
            b"x",
        ),
        403,
        "AuthorizationPermissionMismatch",
    );
    error(
        sas_request(
            &server,
            Method::GET,
            BLOB,
            &by_policy("old", Some(BLOB_NAME)),
            b"",
        ),
        403,
        "AuthenticationFailed",
    );
    error(
        sas_request(
            &server,
            Method::GET,
            BLOB,
            &by_policy("missing", Some(BLOB_NAME)),
            b"",
        ),
        403,
        "AuthenticationFailed",
    );
    assert_eq!(
        sas_request(
            &server,
            Method::GET,
            BLOB,
            &by_policy("short", Some(BLOB_NAME)),
            b""
        )
        .status(),
        200
    );
    server.advance(31);
    error(
        sas_request(
            &server,
            Method::GET,
            BLOB,
            &by_policy("short", Some(BLOB_NAME)),
            b"",
        ),
        403,
        "AuthenticationFailed",
    );

    // Replacing the ACL revokes the policy and, with no header, makes the container private.
    assert_eq!(
        server
            .request(Method::PUT, acl_path, &[], b"<SignedIdentifiers />")
            .status(),
        200
    );
    error(
        sas_request(
            &server,
            Method::GET,
            BLOB,
            &by_policy("reader", Some(BLOB_NAME)),
            b"",
        ),
        403,
        "AuthenticationFailed",
    );
    let cleared = server.request(Method::GET, acl_path, &[], b"");
    assert!(!cleared.headers().contains_key("x-ms-blob-public-access"));
    assert!(cleared.text().unwrap().contains("<SignedIdentifiers>"));
    for bad in [
        "<SignedIdentifiers><SignedIdentifier><Id>a</Id></SignedIdentifier><SignedIdentifier><Id>a</Id></SignedIdentifier></SignedIdentifiers>",
        "<SignedIdentifiers><SignedIdentifier><Id>a</Id><AccessPolicy><Permission>zz</Permission></AccessPolicy></SignedIdentifier></SignedIdentifiers>",
        "<SignedIdentifiers><SignedIdentifier><Id>a</Id><AccessPolicy><Expiry>someday</Expiry></AccessPolicy></SignedIdentifier></SignedIdentifiers>",
        "<Wrong/>",
    ] {
        error(
            server.request(Method::PUT, acl_path, &[], bad.as_bytes()),
            400,
            "InvalidXmlDocument",
        );
    }
    let many = format!(
        "<SignedIdentifiers>{}</SignedIdentifiers>",
        (0..6)
            .map(|n| format!("<SignedIdentifier><Id>p{n}</Id></SignedIdentifier>"))
            .collect::<String>()
    );
    error(
        server.request(Method::PUT, acl_path, &[], many.as_bytes()),
        400,
        "InvalidXmlDocument",
    );
    error(
        server.request(
            Method::PUT,
            "/testaccount/absent?restype=container&comp=acl",
            &[],
            b"",
        ),
        404,
        "ContainerNotFound",
    );
}

#[test]
fn account_sas_tokens_check_services_resource_types_and_permissions() {
    let server = Emulator::start(None, &[]);
    let far = "2099-01-01T00:00:00Z";
    let all = account_sas("rwdlac", "b", "sco", far);
    assert_eq!(
        sas_request(&server, Method::GET, "/testaccount/?comp=list", &all, b"").status(),
        200
    );
    let create = sas_request(&server, Method::PUT, CONTAINER, &all, b"");
    assert_eq!(create.status(), 201);
    assert_eq!(
        sas_request(&server, Method::PUT, BLOB, &all, b"account").status(),
        201
    );
    assert_eq!(
        sas_request(&server, Method::GET, BLOB, &all, b"")
            .bytes()
            .unwrap()
            .as_ref(),
        b"account"
    );
    let listing = "/testaccount/container?restype=container&comp=list";
    assert_eq!(
        sas_request(&server, Method::GET, listing, &all, b"").status(),
        200
    );
    assert_eq!(
        sas_request(
            &server,
            Method::GET,
            "/testaccount/?restype=service&comp=properties",
            &all,
            b""
        )
        .status(),
        200,
        "service reads need `r`"
    );
    assert_eq!(
        sas_request(&server, Method::DELETE, BLOB, &all, b"").status(),
        202
    );
    assert_eq!(
        sas_request(&server, Method::DELETE, CONTAINER, &all, b"").status(),
        202
    );

    server.create_container();
    assert_eq!(server.put(BLOB, &[], b"x").status(), 201);
    let object_read = account_sas("r", "b", "o", far);
    assert_eq!(
        sas_request(&server, Method::GET, BLOB, &object_read, b"").status(),
        200
    );
    error(
        sas_request(
            &server,
            Method::GET,
            "/testaccount/?comp=list",
            &object_read,
            b"",
        ),
        403,
        "AuthorizationResourceTypeMismatch",
    );
    error(
        sas_request(&server, Method::GET, listing, &object_read, b""),
        403,
        "AuthorizationResourceTypeMismatch",
    );
    error(
        sas_request(&server, Method::PUT, BLOB, &object_read, b"x"),
        403,
        "AuthorizationPermissionMismatch",
    );
    error(
        sas_request(
            &server,
            Method::GET,
            BLOB,
            &account_sas("r", "f", "o", far),
            b"",
        ),
        403,
        "AuthorizationServiceMismatch",
    );
    error(
        sas_request(
            &server,
            Method::GET,
            BLOB,
            &account_sas("r", "b", "o", "2020-01-01T00:00:00Z"),
            b"",
        ),
        403,
        "AuthenticationFailed",
    );
    let tampered = object_read.replace("sp=r", "sp=rd");
    error(
        sas_request(&server, Method::DELETE, BLOB, &tampered, b""),
        403,
        "AuthenticationFailed",
    );
    // Account information needs only a valid token.
    let info = sas_request(
        &server,
        Method::GET,
        "/testaccount/?restype=account&comp=properties",
        &object_read,
        b"",
    );
    assert_eq!(info.status(), 200);
    assert_eq!(info.headers()["x-ms-account-kind"], "StorageV2");
    assert_eq!(info.headers()["x-ms-sku-name"], "Standard_LRS");
    assert_eq!(info.headers()["x-ms-is-hns-enabled"], "false");
}

/// Shared Key Lite signs the verb, MD5, content type, date, `x-ms-*` headers and `comp` only.
fn lite_request(
    server: &Emulator,
    method: Method,
    path: &str,
    extra: &[(&str, &str)],
    body: &[u8],
    key: &[u8],
) -> Response {
    let url = Url::parse(&format!("{}{path}", server.blob_url())).unwrap();
    let mut headers: BTreeMap<String, String> = BTreeMap::from([
        ("x-ms-date".into(), httpdate::fmt_http_date(server_now())),
        ("x-ms-version".into(), VERSION.into()),
    ]);
    for (name, value) in extra {
        headers.insert((*name).into(), (*value).into());
    }
    let extensions: String = headers
        .iter()
        .filter(|(name, _)| name.starts_with("x-ms-"))
        .map(|(name, value)| format!("{name}:{value}\n"))
        .collect();
    let comp = url
        .query_pairs()
        .find(|(name, _)| name == "comp")
        .map(|(_, value)| format!("?comp={value}"))
        .unwrap_or_default();
    let text = format!(
        "{}\n{}\n{}\n\n{extensions}/{ACCOUNT}{}{comp}",
        method.as_str(),
        headers.get("content-md5").map_or("", String::as_str),
        headers.get("content-type").map_or("", String::as_str),
        url.path()
    );
    let mut mac = Hmac::<Sha256>::new_from_slice(key).unwrap();
    mac.update(text.as_bytes());
    headers.insert(
        "authorization".into(),
        format!(
            "SharedKeyLite {ACCOUNT}:{}",
            STANDARD.encode(mac.finalize().into_bytes())
        ),
    );
    let mut request = server.client.request(method.clone(), url);
    for (name, value) in headers {
        request = request.header(name, value);
    }
    if method == Method::PUT {
        request = request.body(body.to_vec());
    }
    request.send().unwrap()
}

#[test]
fn shared_key_lite_authenticates_the_same_operations() {
    let server = Emulator::start(None, &[]);
    let lite = |method, path: &str, extra: &[(&str, &str)], body: &[u8]| {
        lite_request(&server, method, path, extra, body, &KEY)
    };
    assert_eq!(lite(Method::PUT, CONTAINER, &[], b"").status(), 201);
    assert_eq!(
        lite(
            Method::PUT,
            BLOB,
            &[
                ("x-ms-blob-type", "BlockBlob"),
                ("content-type", "text/plain"),
                ("x-ms-meta-a", "b")
            ],
            b"lite"
        )
        .status(),
        201
    );
    let read = lite(Method::GET, BLOB, &[], b"");
    assert_eq!(read.status(), 200);
    assert_eq!(read.bytes().unwrap().as_ref(), b"lite");
    let listing = lite(
        Method::GET,
        "/testaccount/container?restype=container&comp=list&prefix=docs",
        &[],
        b"",
    );
    assert_eq!(listing.status(), 200);
    assert!(listing.text().unwrap().contains("a&amp;b.txt"));
    assert_eq!(
        lite(
            Method::PUT,
            &format!("{BLOB}?comp=metadata"),
            &[("x-ms-meta-c", "d")],
            b""
        )
        .status(),
        200
    );
    error(
        lite_request(&server, Method::GET, BLOB, &[], b"", &[24; 32]),
        403,
        "AuthenticationFailed",
    );
    // Shared Key and Shared Key Lite signatures are not interchangeable.
    let shared = server.request(Method::GET, BLOB, &[], b"");
    assert_eq!(shared.status(), 200);
}

#[test]
fn anonymous_access_follows_the_container_public_access_level() {
    let server = Emulator::start(None, &[]);
    server.create_container();
    assert_eq!(server.put(BLOB, &[], b"public?").status(), 201);
    let listing = "/testaccount/container?restype=container&comp=list";
    let acl = "/testaccount/container?restype=container&comp=acl";
    let anon = |method, path: &str| server.raw(method, path, &[], b"");

    // Private: nothing is readable anonymously, and blobs look absent.
    error(anon(Method::GET, BLOB), 404, "ResourceNotFound");
    let head = anon(Method::HEAD, BLOB);
    assert_eq!(
        (
            head.status().as_u16(),
            header_text(&head, "x-ms-error-code")
        ),
        (404, "ResourceNotFound".into())
    );
    error(anon(Method::GET, listing), 403, "AuthenticationFailed");
    error(anon(Method::GET, CONTAINER), 403, "AuthenticationFailed");
    error(
        anon(Method::GET, "/testaccount/?comp=list"),
        403,
        "AuthenticationFailed",
    );
    error(
        server.raw(Method::PUT, BLOB, &[("x-ms-blob-type", "BlockBlob")], b""),
        403,
        "AuthenticationFailed",
    );
    error(
        anon(Method::GET, "/testaccount/absent/blob"),
        404,
        "ResourceNotFound",
    );

    // Blob level: blobs are readable, the container is not.
    assert_eq!(
        server
            .request(
                Method::PUT,
                acl,
                &[("x-ms-blob-public-access", "blob")],
                b""
            )
            .status(),
        200
    );
    let public = anon(Method::GET, BLOB);
    assert_eq!(public.status(), 200);
    assert_eq!(public.bytes().unwrap().as_ref(), b"public?");
    assert_eq!(anon(Method::HEAD, BLOB).status(), 200);
    assert_eq!(
        anon(Method::GET, &format!("{BLOB}?comp=metadata")).status(),
        200
    );
    assert_eq!(
        anon(Method::GET, &format!("{BLOB}?comp=blocklist")).status(),
        200
    );
    error(anon(Method::GET, listing), 403, "AuthenticationFailed");
    error(anon(Method::GET, CONTAINER), 403, "AuthenticationFailed");
    error(anon(Method::GET, acl), 403, "AuthenticationFailed");
    error(
        server.raw(Method::PUT, BLOB, &[("x-ms-blob-type", "BlockBlob")], b""),
        403,
        "AuthenticationFailed",
    );
    error(anon(Method::DELETE, BLOB), 403, "AuthenticationFailed");
    let ranged = server.raw(Method::GET, BLOB, &[("range", "bytes=0-5")], b"");
    assert_eq!(ranged.bytes().unwrap().as_ref(), b"public");
    assert_eq!(
        server.request(Method::GET, CONTAINER, &[], b"").headers()["x-ms-blob-public-access"],
        "blob"
    );

    // Container level: listing and properties too, but never the ACL or writes.
    assert_eq!(
        server
            .request(
                Method::PUT,
                acl,
                &[("x-ms-blob-public-access", "container")],
                b""
            )
            .status(),
        200
    );
    assert_eq!(anon(Method::GET, listing).status(), 200);
    assert_eq!(anon(Method::GET, CONTAINER).status(), 200);
    assert_eq!(anon(Method::GET, BLOB).status(), 200);
    assert_eq!(
        anon(
            Method::GET,
            "/testaccount/container?restype=container&comp=metadata"
        )
        .status(),
        200
    );
    error(anon(Method::GET, acl), 403, "AuthenticationFailed");
    error(anon(Method::PUT, CONTAINER), 403, "AuthenticationFailed");
    error(
        anon(Method::GET, "/testaccount/?comp=list"),
        403,
        "AuthenticationFailed",
    );
    let created = server.request(
        Method::PUT,
        "/testaccount/second?restype=container",
        &[("x-ms-blob-public-access", "container")],
        b"",
    );
    assert_eq!(created.status(), 201);
    // Setting the ACL without the header makes the container private again.
    assert_eq!(server.request(Method::PUT, acl, &[], b"").status(), 200);
    error(anon(Method::GET, BLOB), 404, "ResourceNotFound");
}

#[test]
fn service_properties_cors_stats_and_account_information() {
    let server = Emulator::start(None, &[]);
    server.create_container();
    assert_eq!(server.put(BLOB, &[], b"cors").status(), 201);
    let path = "/testaccount/?restype=service&comp=properties";
    let defaults = server.request(Method::GET, path, &[], b"");
    assert_eq!(defaults.status(), 200);
    let text = defaults.text().unwrap();
    for expected in [
        "<Logging><Version>1.0</Version>",
        "<HourMetrics>",
        "<MinuteMetrics>",
        "<Cors></Cors>",
        "<DeleteRetentionPolicy>",
        "<StaticWebsite><Enabled>false</Enabled>",
    ] {
        assert!(text.contains(expected), "{expected} in {text}");
    }
    // Without rules there is nothing to match.
    let preflight = |origin: &str, method: &str, headers: &str| {
        server.raw(
            Method::OPTIONS,
            BLOB,
            &[
                ("origin", origin),
                ("access-control-request-method", method),
                ("access-control-request-headers", headers),
            ],
            b"",
        )
    };
    error(
        preflight("https://app.test", "GET", ""),
        403,
        "CorsPreflightFailure",
    );

    let rules = "<?xml version=\"1.0\" encoding=\"utf-8\"?><StorageServiceProperties>\
        <Cors><CorsRule><AllowedOrigins>https://app.test</AllowedOrigins><AllowedMethods>GET,PUT</AllowedMethods>\
        <MaxAgeInSeconds>120</MaxAgeInSeconds><ExposedHeaders>x-ms-meta-*,etag</ExposedHeaders><AllowedHeaders>x-ms-*,content-type</AllowedHeaders></CorsRule>\
        <CorsRule><AllowedOrigins>*</AllowedOrigins><AllowedMethods>HEAD</AllowedMethods><MaxAgeInSeconds>5</MaxAgeInSeconds><ExposedHeaders></ExposedHeaders><AllowedHeaders>*</AllowedHeaders></CorsRule></Cors>\
        <DefaultServiceVersion>2023-11-03</DefaultServiceVersion>\
        <DeleteRetentionPolicy><Enabled>true</Enabled><Days>7</Days></DeleteRetentionPolicy></StorageServiceProperties>";
    let set = server.request(Method::PUT, path, &[], rules.as_bytes());
    assert_eq!(set.status(), 202);
    let stored = server.request(Method::GET, path, &[], b"").text().unwrap();
    assert!(stored.contains("<AllowedOrigins>https://app.test</AllowedOrigins><AllowedMethods>GET,PUT</AllowedMethods><MaxAgeInSeconds>120</MaxAgeInSeconds>"), "{stored}");
    assert!(stored.contains("<DefaultServiceVersion>2023-11-03</DefaultServiceVersion>"));
    assert!(stored.contains("<DeleteRetentionPolicy><Enabled>true</Enabled><Days>7</Days>"));
    assert!(
        stored.contains("<HourMetrics><Version>1.0</Version><Enabled>true</Enabled>"),
        "an update leaves unspecified groups alone"
    );

    let allowed = preflight("https://app.test", "PUT", "X-Ms-Meta-Owner, Content-Type");
    assert_eq!(allowed.status(), 200);
    assert_eq!(
        allowed.headers()["access-control-allow-origin"],
        "https://app.test"
    );
    assert_eq!(allowed.headers()["access-control-allow-methods"], "PUT");
    assert_eq!(
        allowed.headers()["access-control-allow-headers"],
        "X-Ms-Meta-Owner, Content-Type"
    );
    assert_eq!(allowed.headers()["access-control-max-age"], "120");
    assert_eq!(
        allowed.headers()["access-control-allow-credentials"],
        "true"
    );
    assert_eq!(allowed.headers()["vary"], "Origin");
    error(
        preflight("https://other.test", "GET", ""),
        403,
        "CorsPreflightFailure",
    );
    error(
        preflight("https://app.test", "DELETE", ""),
        403,
        "CorsPreflightFailure",
    );
    error(
        preflight("https://app.test", "GET", "authorization"),
        403,
        "CorsPreflightFailure",
    );
    let wildcard = preflight("https://anywhere.test", "HEAD", "x-custom");
    assert_eq!(wildcard.status(), 200);
    assert_eq!(wildcard.headers()["access-control-allow-origin"], "*");
    assert!(
        !wildcard
            .headers()
            .contains_key("access-control-allow-credentials")
    );
    error(
        server.raw(
            Method::OPTIONS,
            BLOB,
            &[("origin", "https://app.test")],
            b"",
        ),
        403,
        "CorsPreflightFailure",
    );

    // Real requests get headers only for a matching origin and method.
    assert_eq!(
        server
            .put(
                "/testaccount/container/c.txt",
                &[("x-ms-meta-owner", "ops")],
                b"x"
            )
            .status(),
        201
    );
    let with_origin = server.request(
        Method::GET,
        "/testaccount/container/c.txt",
        &[("origin", "https://app.test")],
        b"",
    );
    assert_eq!(with_origin.status(), 200);
    assert_eq!(
        with_origin.headers()["access-control-allow-origin"],
        "https://app.test"
    );
    let exposed = with_origin.headers()["access-control-expose-headers"]
        .to_str()
        .unwrap()
        .to_owned();
    assert!(
        exposed.contains("x-ms-meta-owner") && exposed.contains("etag"),
        "{exposed}"
    );
    let foreign = server.request(Method::GET, BLOB, &[("origin", "https://other.test")], b"");
    assert_eq!(foreign.status(), 200);
    assert!(
        !foreign
            .headers()
            .contains_key("access-control-allow-origin")
    );
    let method_mismatch = server.request(
        Method::DELETE,
        "/testaccount/container/c.txt",
        &[("origin", "https://app.test")],
        b"",
    );
    assert!(
        !method_mismatch
            .headers()
            .contains_key("access-control-allow-origin")
    );
    let none = server.request(Method::GET, BLOB, &[], b"");
    assert!(!none.headers().contains_key("access-control-allow-origin"));

    // Invalid documents are rejected and leave the stored rules alone.
    for bad in [
        "<StorageServiceProperties><Cors><CorsRule><AllowedOrigins>*</AllowedOrigins><AllowedMethods>TRACE</AllowedMethods><MaxAgeInSeconds>1</MaxAgeInSeconds></CorsRule></Cors></StorageServiceProperties>",
        "<StorageServiceProperties><DefaultServiceVersion>soon</DefaultServiceVersion></StorageServiceProperties>",
        "<Other/>",
        "<StorageServiceProperties>",
    ] {
        error(
            server.request(Method::PUT, path, &[], bad.as_bytes()),
            400,
            "InvalidXmlDocument",
        );
    }
    let six = format!(
        "<StorageServiceProperties><Cors>{}</Cors></StorageServiceProperties>",
        "<CorsRule><AllowedOrigins>*</AllowedOrigins><AllowedMethods>GET</AllowedMethods><MaxAgeInSeconds>1</MaxAgeInSeconds></CorsRule>".repeat(6)
    );
    error(
        server.request(Method::PUT, path, &[], six.as_bytes()),
        400,
        "InvalidXmlDocument",
    );
    assert!(
        server
            .request(Method::GET, path, &[], b"")
            .text()
            .unwrap()
            .contains("https://app.test")
    );
    // An empty Cors element clears the rules.
    assert_eq!(
        server
            .request(
                Method::PUT,
                path,
                &[],
                b"<StorageServiceProperties><Cors /></StorageServiceProperties>"
            )
            .status(),
        202
    );
    assert!(
        server
            .request(Method::GET, path, &[], b"")
            .text()
            .unwrap()
            .contains("<Cors></Cors>")
    );

    // Replication statistics exist only on the secondary endpoint (see blob3_http).
    error(
        server.request(
            Method::GET,
            "/testaccount/?restype=service&comp=stats",
            &[],
            b"",
        ),
        403,
        "InsufficientAccountPermissions",
    );
    for target in [
        "/testaccount/?restype=account&comp=properties",
        "/testaccount/container?restype=account&comp=properties",
        "/testaccount/container/docs/a%26b.txt?restype=account&comp=properties",
    ] {
        for method in [Method::GET, Method::HEAD] {
            let info = server.request(method, target, &[], b"");
            assert_eq!(info.status(), 200, "{target}");
            assert_eq!(info.headers()["x-ms-sku-name"], "Standard_LRS");
            assert_eq!(info.headers()["x-ms-account-kind"], "StorageV2");
        }
    }
}

fn blob_url(server: &Emulator, path: &str) -> String {
    format!("{}{path}", server.blob_url())
}

#[test]
fn copy_blob_completes_synchronously_for_same_instance_sources() {
    let server = Emulator::start(None, &[]);
    server.create_container();
    let source = "/testaccount/container/source.txt";
    let dest = "/testaccount/container/dest.txt";
    let put = server.put(
        source,
        &[
            ("x-ms-blob-content-type", "text/x-source"),
            ("x-ms-blob-cache-control", "no-store"),
            ("x-ms-meta-origin", "source"),
        ],
        b"copy me",
    );
    assert_eq!(put.status(), 201);
    let source_url = blob_url(&server, source);
    let copy = |dest: &str, extra: &[(&str, &str)]| {
        let mut headers = vec![("x-ms-copy-source", source_url.as_str())];
        headers.extend_from_slice(extra);
        server.request(Method::PUT, dest, &headers, b"")
    };
    let copied = copy(dest, &[]);
    assert_eq!(copied.status(), 202);
    assert_eq!(copied.headers()["x-ms-copy-status"], "success");
    let copy_id = header_text(&copied, "x-ms-copy-id");
    assert_eq!(copy_id.len(), 36);
    assert!(copied.headers().contains_key("etag"));
    let read = server.request(Method::GET, dest, &[], b"");
    assert_eq!(read.headers()["content-type"], "text/x-source");
    assert_eq!(read.headers()["cache-control"], "no-store");
    assert_eq!(read.headers()["x-ms-meta-origin"], "source");
    assert_eq!(read.headers()["x-ms-copy-id"], copy_id.as_str());
    assert_eq!(read.headers()["x-ms-copy-status"], "success");
    assert_eq!(read.headers()["x-ms-copy-source"], source_url.as_str());
    assert_eq!(read.headers()["x-ms-copy-progress"], "7/7");
    assert!(read.headers().contains_key("x-ms-copy-completion-time"));
    assert_eq!(
        read.headers()["content-md5"],
        server.request(Method::HEAD, source, &[], b"").headers()["content-md5"]
    );
    assert_eq!(read.bytes().unwrap().as_ref(), b"copy me");
    assert!(
        !server
            .request(Method::HEAD, source, &[], b"")
            .headers()
            .contains_key("x-ms-copy-id")
    );
    let listing = server
        .request(
            Method::GET,
            "/testaccount/container?restype=container&comp=list&prefix=dest&include=copy",
            &[],
            b"",
        )
        .text()
        .unwrap();
    assert!(listing.contains(&format!("<CopyId>{copy_id}</CopyId><CopyStatus>success</CopyStatus><CopySource>{source_url}</CopySource><CopyProgress>7/7</CopyProgress>")), "{listing}");

    // Source and destination are independent afterwards; supplied metadata replaces the source's.
    assert_eq!(server.put(source, &[], b"changed").status(), 201);
    assert_eq!(
        server
            .request(Method::GET, dest, &[], b"")
            .bytes()
            .unwrap()
            .as_ref(),
        b"copy me"
    );
    let replaced = copy(
        "/testaccount/container/replaced.txt",
        &[("x-ms-meta-own", "yes"), ("x-ms-access-tier", "Cool")],
    );
    assert_eq!(replaced.status(), 202);
    let head = server.request(
        Method::HEAD,
        "/testaccount/container/replaced.txt",
        &[],
        b"",
    );
    assert_eq!(head.headers()["x-ms-meta-own"], "yes");
    assert!(!head.headers().contains_key("x-ms-meta-origin"));
    assert_eq!(head.headers()["x-ms-access-tier"], "Cool");

    // Overwrite rules: conditions on the destination, its lease, and source conditions.
    error(
        copy(dest, &[("if-none-match", "*")]),
        409,
        "BlobAlreadyExists",
    );
    error(
        copy(
            dest,
            &[("if-match", "\"00000000000000000000000000000002\"")],
        ),
        412,
        "ConditionNotMet",
    );
    error(
        copy(
            dest,
            &[(
                "x-ms-source-if-match",
                "\"00000000000000000000000000000002\"",
            )],
        ),
        412,
        "SourceConditionNotMet",
    );
    let tag = etag(&server.request(Method::HEAD, source, &[], b""));
    assert_eq!(copy(dest, &[("x-ms-source-if-match", &tag)]).status(), 202);
    assert_eq!(
        server
            .request(Method::GET, dest, &[], b"")
            .bytes()
            .unwrap()
            .as_ref(),
        b"changed"
    );
    assert_eq!(
        server
            .lease(
                &format!("{dest}?comp=lease"),
                &[
                    ("x-ms-lease-action", "acquire"),
                    ("x-ms-lease-duration", "-1"),
                    ("x-ms-proposed-lease-id", LEASE_A)
                ]
            )
            .status(),
        201
    );
    error(copy(dest, &[]), 412, "LeaseIdMissing");
    assert_eq!(copy(dest, &[("x-ms-lease-id", LEASE_A)]).status(), 202);
    assert_eq!(
        server
            .lease(
                &format!("{source}?comp=lease"),
                &[
                    ("x-ms-lease-action", "acquire"),
                    ("x-ms-lease-duration", "-1"),
                    ("x-ms-proposed-lease-id", LEASE_B)
                ]
            )
            .status(),
        201
    );
    error(
        copy(
            dest,
            &[
                ("x-ms-lease-id", LEASE_A),
                ("x-ms-source-lease-id", LEASE_A),
            ],
        ),
        412,
        "LeaseIdMismatchWithBlobOperation",
    );
    assert_eq!(
        copy(
            dest,
            &[
                ("x-ms-lease-id", LEASE_A),
                ("x-ms-source-lease-id", LEASE_B)
            ]
        )
        .status(),
        202
    );

    // Missing sources, other hosts, and malformed URLs.
    let missing = server.request(
        Method::PUT,
        "/testaccount/container/x",
        &[(
            "x-ms-copy-source",
            &blob_url(&server, "/testaccount/container/absent"),
        )],
        b"",
    );
    error(missing, 404, "CannotVerifyCopySource");
    let remote = server.request(
        Method::PUT,
        "/testaccount/container/x",
        &[(
            "x-ms-copy-source",
            "https://other.blob.core.windows.net/c/b",
        )],
        b"",
    );
    error(remote, 501, "NotImplemented");
    let malformed = server.request(
        Method::PUT,
        "/testaccount/container/x",
        &[("x-ms-copy-source", "not a url")],
        b"",
    );
    error(malformed, 400, "InvalidHeaderValue");

    // Abort Copy: every copy has already completed.
    let abort = |id: &str| {
        server.request(
            Method::PUT,
            &format!("{dest}?comp=copy&copyid={id}"),
            &[("x-ms-copy-action", "abort"), ("x-ms-lease-id", LEASE_A)],
            b"",
        )
    };
    let last = header_text(
        &server.request(Method::HEAD, dest, &[], b""),
        "x-ms-copy-id",
    );
    error(abort(&last), 409, "NoPendingCopyOperation");
    error(
        abort("00000000-0000-0000-0000-000000000000"),
        409,
        "CopyIdMismatch",
    );
    error(
        server.request(
            Method::PUT,
            &format!("{source}?comp=copy&copyid=x"),
            &[("x-ms-copy-action", "abort"), ("x-ms-lease-id", LEASE_B)],
            b"",
        ),
        409,
        "NoPendingCopyOperation",
    );
    error(
        server.request(
            Method::PUT,
            &format!("{dest}?comp=copy&copyid={last}"),
            &[("x-ms-lease-id", LEASE_A)],
            b"",
        ),
        400,
        "InvalidHeaderValue",
    );
    error(
        server.request(
            Method::PUT,
            "/testaccount/container/absent?comp=copy&copyid=x",
            &[("x-ms-copy-action", "abort")],
            b"",
        ),
        404,
        "BlobNotFound",
    );
}

#[test]
fn copy_sources_are_authorized_by_sas_account_key_or_public_access() {
    let server = Emulator::clocked();
    server.create_container();
    assert_eq!(server.put(BLOB, &[], b"guarded").status(), 201);
    let dest = "/testaccount/container/copy.txt";
    let far = "2099-01-01T00:00:00Z";
    let with = |sas: &str| format!("{}?{sas}", blob_url(&server, BLOB));
    let copy_from =
        |url: &str| server.request(Method::PUT, dest, &[("x-ms-copy-source", url)], b"");

    // The account key reads same-account sources; a read SAS on the source is honoured too.
    assert_eq!(copy_from(&blob_url(&server, BLOB)).status(), 202);
    let read = service_sas("container", Some(BLOB_NAME), "r", far).build();
    assert_eq!(copy_from(&with(&read)).status(), 202);
    let write_only = service_sas("container", Some(BLOB_NAME), "w", far).build();
    error(copy_from(&with(&write_only)), 403, "CannotVerifyCopySource");
    error(
        copy_from(&with(&read.replace("sp=r", "sp=rd"))),
        403,
        "CannotVerifyCopySource",
    );
    error(
        copy_from(&with(
            &service_sas("container", Some(BLOB_NAME), "r", "2020-01-01T00:00:00Z").build(),
        )),
        403,
        "CannotVerifyCopySource",
    );
    assert_eq!(
        copy_from(&with(&account_sas("r", "b", "o", far))).status(),
        202
    );

    // A destination authorized only by a write SAS has no right to read a private source.
    let dest_sas = service_sas("container", Some("copy.txt"), "wc", far).build();
    let by_sas = |url: &str| {
        server.raw(
            Method::PUT,
            &format!("{dest}?{dest_sas}"),
            &[("x-ms-copy-source", url)],
            b"",
        )
    };
    error(
        by_sas(&blob_url(&server, BLOB)),
        403,
        "CannotVerifyCopySource",
    );
    assert_eq!(by_sas(&with(&read)).status(), 202);
    // Public sources can be copied anonymously-style.
    let acl = "/testaccount/container?restype=container&comp=acl";
    assert_eq!(
        server
            .request(
                Method::PUT,
                acl,
                &[("x-ms-blob-public-access", "blob")],
                b""
            )
            .status(),
        200
    );
    assert_eq!(by_sas(&blob_url(&server, BLOB)).status(), 202);
}

#[test]
fn put_blob_and_put_block_from_url_read_same_instance_sources() {
    let server = Emulator::start(None, &[]);
    server.create_container();
    let source = "/testaccount/container/source.bin";
    assert_eq!(
        server
            .put(
                source,
                &[
                    ("x-ms-blob-content-type", "application/x-src"),
                    ("x-ms-meta-from", "source")
                ],
                b"0123456789"
            )
            .status(),
        201
    );
    let url = blob_url(&server, source);
    let dest = "/testaccount/container/from-url.bin";
    let put = |extra: &[(&str, &str)]| {
        let mut headers = vec![
            ("x-ms-blob-type", "BlockBlob"),
            ("x-ms-copy-source", url.as_str()),
        ];
        headers.extend_from_slice(extra);
        server.request(Method::PUT, dest, &headers, b"")
    };
    let created = put(&[("x-ms-meta-mine", "dest")]);
    assert_eq!(created.status(), 201);
    assert!(created.headers().contains_key("content-md5"));
    let read = server.request(Method::GET, dest, &[], b"");
    assert_eq!(
        read.headers()["content-type"],
        "application/x-src",
        "source properties are copied by default"
    );
    assert_eq!(read.headers()["x-ms-meta-mine"], "dest");
    assert!(!read.headers().contains_key("x-ms-meta-from"));
    assert!(!read.headers().contains_key("x-ms-copy-id"));
    assert_eq!(read.bytes().unwrap().as_ref(), b"0123456789");
    let own = put(&[
        ("x-ms-copy-source-blob-properties", "false"),
        ("x-ms-blob-content-type", "text/own"),
    ]);
    assert_eq!(own.status(), 201);
    assert_eq!(
        server.request(Method::HEAD, dest, &[], b"").headers()["content-type"],
        "text/own"
    );
    error(put(&[("if-none-match", "*")]), 409, "BlobAlreadyExists");
    let absent = server.request(
        Method::PUT,
        dest,
        &[
            ("x-ms-blob-type", "BlockBlob"),
            (
                "x-ms-copy-source",
                &blob_url(&server, "/testaccount/container/absent"),
            ),
        ],
        b"",
    );
    error(absent, 404, "CannotVerifyCopySource");

    // Put Block From URL stages a source range, which a block list then commits in order.
    let target = "/testaccount/container/assembled.bin";
    let stage = |id: &str, range: Option<&str>| {
        let mut headers = vec![("x-ms-copy-source", url.as_str())];
        if let Some(range) = range {
            headers.push(("x-ms-source-range", range));
        }
        server.request(
            Method::PUT,
            &format!("{target}?comp=block&blockid={id}"),
            &headers,
            b"",
        )
    };
    assert_eq!(stage("QQ==", Some("bytes=2-4")).status(), 201);
    assert_eq!(stage("Qg==", None).status(), 201);
    error(stage("Qw==", Some("bytes=20-30")), 416, "InvalidRange");
    let committed = server.request(
        Method::PUT,
        &format!("{target}?comp=blocklist"),
        &[],
        b"<BlockList><Latest>Qg==</Latest><Latest>QQ==</Latest></BlockList>",
    );
    assert_eq!(committed.status(), 201);
    assert_eq!(
        server
            .request(Method::GET, target, &[], b"")
            .bytes()
            .unwrap()
            .as_ref(),
        b"0123456789234"
    );
    let sizes = server
        .request(Method::GET, &format!("{target}?comp=blocklist"), &[], b"")
        .text()
        .unwrap();
    assert!(
        sizes.contains("<Name>Qg==</Name><Size>10</Size>")
            && sizes.contains("<Name>QQ==</Name><Size>3</Size>"),
        "{sizes}"
    );
}

#[test]
fn host_style_addressing_names_the_account_in_the_host() {
    let server = Emulator::start(None, &[]);
    let port = server.blob_url().rsplit(':').next().unwrap().to_owned();
    let host = format!("testaccount.blob.localhost:{port}");
    let styled = |method: Method, path: &str, extra: &[(&str, &str)], body: &[u8]| {
        let mut headers = vec![("host", host.as_str())];
        headers.extend_from_slice(extra);
        server.request(method, path, &headers, body)
    };
    assert_eq!(
        styled(Method::PUT, "/container?restype=container", &[], b"").status(),
        201
    );
    assert_eq!(
        styled(
            Method::PUT,
            "/container/docs/a%26b.txt",
            &[("x-ms-blob-type", "BlockBlob")],
            b"host style"
        )
        .status(),
        201
    );
    let read = styled(Method::GET, "/container/docs/a%26b.txt", &[], b"");
    assert_eq!(read.status(), 200);
    assert_eq!(read.bytes().unwrap().as_ref(), b"host style");
    // The same data is reachable path-style.
    assert_eq!(
        server
            .request(Method::GET, BLOB, &[], b"")
            .bytes()
            .unwrap()
            .as_ref(),
        b"host style"
    );
    let containers = styled(Method::GET, "/?comp=list", &[], b"");
    assert_eq!(containers.status(), 200);
    assert!(
        containers
            .text()
            .unwrap()
            .contains("<Name>container</Name>")
    );
    let listing = styled(
        Method::GET,
        "/container?restype=container&comp=list&delimiter=%2F",
        &[],
        b"",
    );
    assert!(
        listing
            .text()
            .unwrap()
            .contains("<BlobPrefix><Name>docs/</Name></BlobPrefix>")
    );
    // SAS and anonymous requests also resolve the account from the host.
    let sas = service_sas("container", Some(BLOB_NAME), "r", "2099-01-01T00:00:00Z").build();
    let by_sas = server.raw(
        Method::GET,
        &format!("/container/docs/a%26b.txt?{sas}"),
        &[("host", &host)],
        b"",
    );
    assert_eq!(by_sas.status(), 200);
    error(
        server.raw(
            Method::GET,
            "/container/docs/a%26b.txt",
            &[("host", &host)],
            b"",
        ),
        404,
        "ResourceNotFound",
    );
    // An unknown account, or a signature made for a different account, fails.
    let unknown = format!("nobodyhere.blob.localhost:{port}");
    error(
        server.request(
            Method::GET,
            "/container?restype=container",
            &[("host", &unknown)],
            b"",
        ),
        403,
        "AuthenticationFailed",
    );
    // A host naming another service is path-style, so the first path segment is taken as the account.
    error(
        server.request(
            Method::GET,
            "/container?restype=container",
            &[("host", &format!("testaccount.queue.localhost:{port}"))],
            b"",
        ),
        403,
        "AuthenticationFailed",
    );
}

#[test]
fn version_header_and_client_request_id_follow_the_wire_contract() {
    let server = Emulator::start(None, &[]);
    server.create_container();
    let echoed = server.request(
        Method::GET,
        CONTAINER,
        &[("x-ms-client-request-id", "trace-123")],
        b"",
    );
    assert_eq!(echoed.headers()["x-ms-client-request-id"], "trace-123");
    assert_eq!(echoed.headers()["x-ms-version"], VERSION);
    // A signed request must name its version; SAS and anonymous ones may omit it.
    let url = format!("{}{CONTAINER}", server.blob_url());
    let mut headers = signed(&Method::GET, &Url::parse(&url).unwrap(), &[], None, &KEY);
    headers.remove("x-ms-version");
    let mut request = server.client.get(&url);
    for (name, value) in headers {
        request = request.header(name, value);
    }
    error(request.send().unwrap(), 400, "InvalidHeaderValue");
    assert_eq!(server.put(BLOB, &[], b"v").status(), 201);
    let sas = service_sas("container", Some(BLOB_NAME), "r", "2099-01-01T00:00:00Z").build();
    let unversioned = server.raw(Method::GET, &format!("{BLOB}?{sas}"), &[], b"");
    assert_eq!(unversioned.status(), 200);
    assert_eq!(unversioned.headers()["x-ms-version"], VERSION);
    let older = server.raw(
        Method::GET,
        &format!("{BLOB}?{sas}"),
        &[("x-ms-version", "2014-02-14")],
        b"",
    );
    assert_eq!(older.status(), 200, "older versions get baseline behavior");
    assert_eq!(older.headers()["x-ms-version"], VERSION);
    let too_old = server.raw(
        Method::GET,
        &format!("{BLOB}?{sas}"),
        &[("x-ms-version", "2009-09-18")],
        b"",
    );
    error(too_old, 400, "InvalidHeaderValue");
}

#[test]
fn the_test_clock_is_opt_in_and_loopback_only() {
    let server = Emulator::start(None, &[]);
    error(
        server.raw(Method::GET, "/_azuifer/clock", &[], b""),
        400,
        "InvalidResourceName",
    );
    let enabled = Emulator::clocked();
    let now = enabled
        .client
        .get(format!("{}/_azuifer/clock", enabled.blob_url()))
        .send()
        .unwrap()
        .text()
        .unwrap();
    assert!(now.starts_with("{\"unix_ms\":"), "{now}");
    let output = emulator_command()
        .args(["config", "validate", "--test-clock", "--bind", "0.0.0.0"])
        .output()
        .unwrap();
    assert!(!output.status.success());
    assert!(
        String::from_utf8(output.stderr)
            .unwrap()
            .contains("--test-clock requires loopback")
    );
    let local = emulator_command()
        .args(["config", "validate", "--test-clock"])
        .output()
        .unwrap();
    assert!(local.status.success());
}

#[test]
fn per_request_limits_are_configurable_and_default_to_azure_scale() {
    let server = Emulator::start(
        None,
        &[
            "--max-block-bytes",
            "3",
            "--max-blob-bytes",
            "20000000",
            "--memory-limit",
            "60000000",
        ],
    );
    server.create_container();
    error(
        server.request(
            Method::PUT,
            &format!("{BLOB}?comp=block&blockid=QQ=="),
            &[],
            b"four",
        ),
        413,
        "RequestBodyTooLarge",
    );
    assert_eq!(
        server
            .request(
                Method::PUT,
                &format!("{BLOB}?comp=block&blockid=QQ=="),
                &[],
                b"abc"
            )
            .status(),
        201
    );
    // Beyond the former 16 MiB ceiling, a single Put Blob works.
    let big = vec![7u8; 17 * 1024 * 1024];
    let uploaded = server.put("/testaccount/container/big.bin", &[], &big);
    assert_eq!(uploaded.status(), 201);
    assert_eq!(
        server
            .request(Method::HEAD, "/testaccount/container/big.bin", &[], b"")
            .headers()["content-length"],
        big.len().to_string().as_str()
    );
    for flag in [
        ["--max-block-bytes", "0"],
        ["--max-blob-bytes", "5242880001"],
    ] {
        let output = emulator_command()
            .args(["config", "validate"])
            .args(flag)
            .output()
            .unwrap();
        assert!(!output.status.success(), "{flag:?}");
    }
    let defaults = emulator_command()
        .args([
            "config",
            "validate",
            "--max-block-bytes",
            "5242880000",
            "--max-blob-bytes",
            "268435456",
        ])
        .output()
        .unwrap();
    assert!(defaults.status.success());
}

#[test]
fn a_data_directory_from_the_previous_schema_opens_and_gains_the_new_features() {
    let location = tempfile::tempdir().unwrap();
    let content = location.path().join("content");
    fs::create_dir_all(&content).unwrap();
    {
        let db = rusqlite::Connection::open(location.path().join("metadata.sqlite3")).unwrap();
        db.execute_batch(
            "CREATE TABLE containers (account TEXT NOT NULL, name TEXT NOT NULL, id BLOB NOT NULL, modified INTEGER NOT NULL, PRIMARY KEY (account, name)) STRICT;
             CREATE TABLE blobs (account TEXT NOT NULL, container TEXT NOT NULL, name TEXT NOT NULL, id BLOB NOT NULL UNIQUE, modified INTEGER NOT NULL, length INTEGER NOT NULL, content_type TEXT NOT NULL, md5 TEXT NOT NULL, metadata TEXT NOT NULL, bytes BLOB, PRIMARY KEY (account, container, name), FOREIGN KEY (account, container) REFERENCES containers (account, name) ON DELETE CASCADE) STRICT;
             CREATE TABLE staged_blocks (account TEXT NOT NULL, container TEXT NOT NULL, name TEXT NOT NULL, block_id TEXT NOT NULL, width INTEGER NOT NULL, id BLOB NOT NULL UNIQUE, length INTEGER NOT NULL, bytes BLOB, PRIMARY KEY (account, container, name, block_id), FOREIGN KEY (account, container) REFERENCES containers (account, name) ON DELETE CASCADE) STRICT;
             CREATE TABLE committed_blocks (account TEXT NOT NULL, container TEXT NOT NULL, name TEXT NOT NULL, position INTEGER NOT NULL, block_id TEXT NOT NULL, offset INTEGER NOT NULL, length INTEGER NOT NULL, PRIMARY KEY (account, container, name, position), FOREIGN KEY (account, container, name) REFERENCES blobs (account, container, name) ON DELETE CASCADE) STRICT;
             INSERT INTO containers VALUES ('testaccount', 'container', x'11111111111111111111111111111111', 1700000000);
             INSERT INTO blobs VALUES ('testaccount', 'container', 'docs/a&b.txt', x'22222222222222222222222222222222', 1700000001, 5, 'text/old', '', '{\"legacy\":\"yes\"}', NULL);",
        )
        .unwrap();
        db.pragma_update(None, "journal_mode", "WAL").unwrap();
    }
    fs::write(
        content.join("extent-22222222222222222222222222222222"),
        b"hello",
    )
    .unwrap();

    let server = Emulator::start(Some(location.path()), &["--test-clock"]);
    let read = server.request(Method::GET, BLOB, &[], b"");
    assert_eq!(read.status(), 200);
    assert_eq!(
        read.headers()["etag"],
        "\"22222222222222222222222222222222\""
    );
    assert_eq!(read.headers()["content-type"], "text/old");
    assert_eq!(read.headers()["x-ms-meta-legacy"], "yes");
    assert_eq!(read.headers()["x-ms-lease-state"], "available");
    assert_eq!(read.headers()["x-ms-access-tier"], "Hot");
    assert_eq!(
        read.headers()["x-ms-creation-time"],
        "Tue, 14 Nov 2023 22:13:21 GMT"
    );
    assert_eq!(read.bytes().unwrap().as_ref(), b"hello");
    let container = server.request(Method::GET, CONTAINER, &[], b"");
    assert_eq!(
        container.headers()["etag"],
        "\"11111111111111111111111111111111\""
    );
    assert_eq!(container.headers()["x-ms-lease-state"], "available");
    assert!(!container.headers().contains_key("x-ms-blob-public-access"));
    // The upgraded rows take the new features: leases, metadata, properties.
    assert_eq!(
        server
            .lease(
                LEASED_LEASE
                    .replace("leased.txt", "docs/a%26b.txt")
                    .as_str(),
                &[
                    ("x-ms-lease-action", "acquire"),
                    ("x-ms-lease-duration", "-1"),
                    ("x-ms-proposed-lease-id", LEASE_A)
                ]
            )
            .status(),
        201
    );
    assert_eq!(
        server
            .request(
                Method::PUT,
                &format!("{BLOB}?comp=metadata"),
                &[("x-ms-lease-id", LEASE_A), ("x-ms-meta-new", "1")],
                b""
            )
            .status(),
        200
    );
    drop(server);
    let again = Emulator::start(Some(location.path()), &[]);
    let head = again.request(Method::HEAD, BLOB, &[], b"");
    assert_eq!(head.headers()["x-ms-meta-new"], "1");
    assert_eq!(head.headers()["x-ms-lease-state"], "leased");
    assert_eq!(
        again
            .request(Method::GET, BLOB, &[], b"")
            .bytes()
            .unwrap()
            .as_ref(),
        b"hello"
    );
}

#[test]
fn the_conformance_manifest_inventory_is_well_formed_and_never_claims_exact() {
    let export = emulator_command()
        .args(["conformance", "export"])
        .output()
        .unwrap();
    assert!(export.status.success());
    let manifest: serde_json::Value = serde_json::from_slice(&export.stdout).unwrap();
    for field in [
        "schema_version",
        "service",
        "api_version",
        "authorization",
        "azure_differential_verified",
        "implemented_locally",
        "unsupported_by_default",
        "other_services",
    ] {
        assert!(manifest.get(field).is_some(), "root field {field}");
    }
    assert_eq!(manifest["azure_differential_verified"], false);
    assert_eq!(manifest["api_version"], VERSION);
    let modes = [
        "SharedKey",
        "SharedKeyLite",
        "AccountSAS",
        "ServiceSAS",
        "UserDelegationSAS",
        "Bearer",
        "Anonymous",
    ];
    let inventory = manifest["services"]["blob"]["operations"]
        .as_array()
        .unwrap();
    let local: Vec<&str> = manifest["implemented_locally"]
        .as_array()
        .unwrap()
        .iter()
        .map(|item| item.as_str().unwrap())
        .collect();
    let mut names = Vec::new();
    for entry in inventory {
        let object = entry.as_object().unwrap();
        let name = object["name"].as_str().unwrap();
        let state = object["state"].as_str().unwrap();
        assert!(
            ["compatible", "known-difference", "unsupported"].contains(&state),
            "{name}: {state}"
        );
        let supported = state != "unsupported";
        let mut keys: Vec<_> = object.keys().map(String::as_str).collect();
        keys.sort_unstable();
        let has_notes = object
            .get("notes")
            .and_then(|notes| notes.as_str())
            .is_some_and(|notes| !notes.trim().is_empty());
        assert!(!supported || has_notes, "{name} needs notes");
        assert_eq!(
            keys,
            if object.contains_key("notes") {
                vec!["authorization", "name", "notes", "state"]
            } else {
                vec!["authorization", "name", "state"]
            },
            "{entry}"
        );
        let authorization = object["authorization"].as_array().unwrap();
        assert!(!supported || !authorization.is_empty(), "{name}");
        for mode in authorization {
            assert!(modes.contains(&mode.as_str().unwrap()), "{name}: {mode}");
        }
        assert_eq!(
            supported,
            local.iter().any(|item| item.starts_with(name)),
            "{name} must agree with implemented_locally"
        );
        names.push(name);
    }
    let mut unique = names.clone();
    unique.sort_unstable();
    unique.dedup();
    assert_eq!(unique.len(), names.len(), "operation names are unique");
    for name in [
        "Lease Blob",
        "Lease Container",
        "Set Blob Properties",
        "Copy Blob",
        "Get Blob Service Properties",
        "Snapshot Blob",
        "Put Page",
        "Append Block",
        "Submit Batch",
        "Find Blobs by Tags",
    ] {
        assert!(names.contains(&name), "{name} is inventoried");
    }
}

#[test]
fn the_web_host_serves_the_web_container_as_a_static_website() {
    let server = Emulator::start(None, &[]);
    let port = server.blob_url().rsplit(':').next().unwrap().to_owned();
    let host = format!("testaccount.web.localhost:{port}");
    let site = |enabled: bool| {
        format!(
            "<StorageServiceProperties><StaticWebsite><Enabled>{enabled}</Enabled>\
             <IndexDocument>index.html</IndexDocument>\
             <ErrorDocument404Path>404.html</ErrorDocument404Path></StaticWebsite>\
             </StorageServiceProperties>"
        )
    };
    let settings = "/testaccount?restype=service&comp=properties";
    assert_eq!(
        server
            .request(Method::PUT, settings, &[], site(true).as_bytes())
            .status(),
        202
    );
    assert_eq!(
        server
            .request(Method::PUT, "/testaccount/$web?restype=container", &[], b"")
            .status(),
        201
    );
    for (name, body) in [
        ("index.html", "home"),
        ("docs/index.html", "docs home"),
        ("docs/page.html", "a page"),
        ("404.html", "custom missing"),
    ] {
        let put = server.request(
            Method::PUT,
            &format!("/testaccount/$web/{name}"),
            &[
                ("x-ms-blob-type", "BlockBlob"),
                ("x-ms-blob-content-type", "text/html"),
            ],
            body.as_bytes(),
        );
        assert_eq!(put.status(), 201, "{name}");
    }
    // SDKs may percent-encode the `$` of the container name.
    let encoded = server.request(Method::GET, "/testaccount/%24web/index.html", &[], b"");
    assert_eq!(encoded.status(), 200);
    assert_eq!(encoded.text().unwrap(), "home");
    let client = Client::builder()
        .no_proxy()
        .redirect(reqwest::redirect::Policy::none())
        .build()
        .unwrap();
    let get = |method: Method, path: &str| {
        client
            .request(method, format!("{}{path}", server.blob_url()))
            .header("host", &host)
            .send()
            .unwrap()
    };

    let home = get(Method::GET, "/");
    assert_eq!(home.status(), 200);
    assert_eq!(home.headers()["content-type"], "text/html");
    assert_eq!(home.text().unwrap(), "home");
    assert_eq!(get(Method::GET, "/docs/").text().unwrap(), "docs home");
    assert_eq!(
        get(Method::GET, "/docs/page.html").text().unwrap(),
        "a page"
    );
    let redirect = get(Method::GET, "/docs?x=1");
    assert_eq!(redirect.status(), 302);
    assert_eq!(redirect.headers()["location"], "/docs/?x=1");

    let missing = get(Method::GET, "/nothing.html");
    assert_eq!(missing.status(), 404);
    assert_eq!(missing.text().unwrap(), "custom missing");
    let missing_range = client
        .get(format!("{}/nothing.html", server.blob_url()))
        .header("host", &host)
        .header("range", "bytes=0-1")
        .send()
        .unwrap();
    assert_eq!(missing_range.status(), 404);
    assert!(!missing_range.headers().contains_key("content-range"));
    assert_eq!(missing_range.text().unwrap(), "custom missing");
    let head = get(Method::HEAD, "/docs/page.html");
    assert_eq!(head.status(), 200);
    assert_eq!(head.headers()["content-length"], "6");
    assert_eq!(get(Method::PUT, "/index.html").status(), 405);

    // Path-style access still needs authorization; the website setting does not open it.
    assert_eq!(
        server
            .raw(Method::GET, "/testaccount/$web/index.html", &[], b"")
            .status(),
        404
    );

    // Turning the website off answers 404 with the web error code.
    server.request(Method::PUT, settings, &[], site(false).as_bytes());
    let off = get(Method::GET, "/");
    assert_eq!(off.status(), 404);
    assert_eq!(off.headers()["x-ms-error-code"], "WebContentNotFound");

    let without_index = site(true).replace("<IndexDocument>index.html</IndexDocument>", "");
    assert_eq!(
        server
            .request(Method::PUT, settings, &[], without_index.as_bytes())
            .status(),
        202
    );
    let asset = get(Method::GET, "/docs/%70age.html");
    assert_eq!(asset.status(), 200);
    assert_eq!(asset.text().unwrap(), "a page");
    let no_index = get(Method::GET, "/");
    assert_eq!(no_index.status(), 404);
    assert_eq!(no_index.text().unwrap(), "custom missing");
}

#[test]
fn a_static_website_does_not_hide_a_damaged_error_document() {
    let location = tempfile::tempdir().unwrap();
    let server = Emulator::start(Some(location.path()), &[]);
    let settings = "/testaccount?restype=service&comp=properties";
    assert_eq!(
        server.request(
            Method::PUT, settings, &[],
            b"<StorageServiceProperties><StaticWebsite><Enabled>true</Enabled>\
              <IndexDocument>index.html</IndexDocument><ErrorDocument404Path>404.html</ErrorDocument404Path>\
              </StaticWebsite></StorageServiceProperties>"
        ).status(),
        202
    );
    assert_eq!(
        server
            .request(Method::PUT, "/testaccount/$web?restype=container", &[], b"")
            .status(),
        201
    );
    let host = format!(
        "testaccount.web.localhost:{}",
        server.blob_url().rsplit(':').next().unwrap()
    );
    let get_missing = || server.raw(Method::GET, "/absent", &[("host", &host)], b"");
    let missing = get_missing();
    assert_eq!(missing.status(), 404);
    assert_eq!(missing.headers()["x-ms-error-code"], "WebContentNotFound");
    assert_eq!(
        server
            .put("/testaccount/$web/404.html", &[], b"custom")
            .status(),
        201
    );
    assert_eq!(get_missing().text().unwrap(), "custom");
    let extent = fs::read_dir(location.path().join("content"))
        .unwrap()
        .next()
        .expect("committed 404 extent")
        .unwrap()
        .path();
    fs::write(extent, b"short").unwrap();
    error(get_missing(), 500, "InternalError");
}

#[test]
fn root_and_logs_containers_are_ordinary_and_the_root_has_an_implicit_path() {
    let server = Emulator::start(None, &[]);
    for name in ["$root", "$logs"] {
        let path = format!("/testaccount/{name}?restype=container");
        assert_eq!(server.request(Method::PUT, &path, &[], b"").status(), 201);
        assert_eq!(server.request(Method::HEAD, &path, &[], b"").status(), 200);
    }
    // A blob written under the explicit name is readable at the short path, and the reverse.
    assert_eq!(
        server.put("/testaccount/$root/a.txt", &[], b"one").status(),
        201
    );
    assert_eq!(
        server
            .request(Method::GET, "/testaccount/a.txt", &[], b"")
            .bytes()
            .unwrap()
            .as_ref(),
        b"one"
    );
    assert_eq!(server.put("/testaccount/B.txt", &[], b"two").status(), 201);
    assert_eq!(
        server
            .request(Method::GET, "/testaccount/$root/B.txt", &[], b"")
            .bytes()
            .unwrap()
            .as_ref(),
        b"two"
    );
    let listing = server
        .request(
            Method::GET,
            "/testaccount/$root?restype=container&comp=list",
            &[],
            b"",
        )
        .text()
        .unwrap();
    assert!(listing.contains("<Name>a.txt</Name>") && listing.contains("<Name>B.txt</Name>"));
    assert_eq!(
        server
            .request(Method::DELETE, "/testaccount/B.txt", &[], b"")
            .status(),
        202
    );
    error(
        server.request(Method::GET, "/testaccount/$root/B.txt", &[], b""),
        404,
        "BlobNotFound",
    );
    // Containers named with restype=container are never mistaken for root blobs.
    error(
        server.request(
            Method::GET,
            "/testaccount/absent?restype=container",
            &[],
            b"",
        ),
        404,
        "ContainerNotFound",
    );
    let account = server
        .request(Method::GET, "/testaccount?comp=list", &[], b"")
        .text()
        .unwrap();
    assert!(account.contains("<Name>$root</Name>") && account.contains("<Name>$logs</Name>"));
    assert_eq!(
        server
            .request(
                Method::DELETE,
                "/testaccount/$logs?restype=container",
                &[],
                b""
            )
            .status(),
        202
    );
}
