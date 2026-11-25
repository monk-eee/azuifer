use base64::{Engine as _, engine::general_purpose::STANDARD};
use hmac::{Hmac, Mac as _};
use reqwest::{
    Method, Url,
    blocking::{Client, Response},
};
use sha2::Sha256;
use std::{
    collections::BTreeMap,
    fs,
    io::{BufRead as _, BufReader, Read as _, Write as _},
    net::TcpStream,
    path::{Path, PathBuf},
    process::{Child, Command, ExitStatus, Stdio},
    sync::{Barrier, mpsc},
    thread,
    time::{Duration, Instant, SystemTime},
};

const ACCOUNT: &str = "testaccount";
const VERSION: &str = "2023-11-03";
const CONTAINER: &str = "/testaccount/container?restype=container";
const BLOB: &str = "/testaccount/container/docs/a%26b.txt";
const KEY: [u8; 32] = [41; 32];

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
    blob: String,
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
        let mut command = emulator_command();
        command.args(["serve", "--port", "0", "--admin-port", "0"]);
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
            let lines = BufReader::new(stdout)
                .lines()
                .take(2)
                .collect::<std::io::Result<Vec<_>>>();
            sender.send(lines).ok();
        });
        let lines = receiver
            .recv_timeout(Duration::from_secs(10))
            .expect("server bound its ports")
            .expect("read startup addresses");
        let [blob, admin]: [String; 2] = lines.try_into().expect("two listener addresses");
        let client = Client::builder()
            .no_proxy()
            .timeout(Duration::from_secs(10))
            .build()
            .unwrap();
        let started = Self {
            process,
            blob: blob.strip_prefix("blob_url=").unwrap().to_owned(),
            admin: admin.strip_prefix("admin_url=").unwrap().to_owned(),
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
        let url = Url::parse(&format!("{}{path}", self.blob)).unwrap();
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

    fn put(&self, path: &str, extra: &[(&str, &str)], bytes: &[u8]) -> Response {
        let mut headers = vec![("x-ms-blob-type", "BlockBlob")];
        headers.extend_from_slice(extra);
        self.request(Method::PUT, path, &headers, bytes)
    }

    fn start_partial_upload(&self, path: &str, length: usize, bytes: &[u8]) -> TcpStream {
        let url = Url::parse(&format!("{}{path}", self.blob)).unwrap();
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
        (
            "x-ms-date".into(),
            httpdate::fmt_http_date(SystemTime::now()),
        ),
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
        412,
        "ConditionNotMet",
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
    error(
        server.request(
            Method::GET,
            "/testaccount/?comp=list&include=deleted",
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
        server.request(Method::GET, &format!("{query}&delimiter=%2F"), &[], b""),
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
        server.request(Method::PUT, &format!("{BLOB}?comp=lease"), &[], b""),
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
        .get(format!("{}{CONTAINER}", server.blob))
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
        501,
        "NotImplemented",
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
        compatible.request(Method::PUT, &format!("{BLOB}?comp=lease"), &newer, b""),
        501,
        "NotImplemented",
    );
    for version in ["2014-12-01", "2026-02-29", "2026-4-06", "nonsense"] {
        error(
            compatible.request(Method::GET, CONTAINER, &[("x-ms-version", version)], b""),
            400,
            "InvalidHeaderValue",
        );
    }
}

#[test]
fn cli_overrides_environment_and_toml_for_upload_limits_and_storage_mode() {
    let root = tempfile::tempdir().unwrap();
    let file = root.path().join("settings.toml");
    fs::write(&file, "in_memory = true\nmax_blob_bytes = 2\n").unwrap();
    for (env_limit, limit) in [(None, 2), (Some("4"), 4)] {
        let mut command = emulator_command();
        command
            .env("AZUIFER_CONFIG", &file)
            .args(["serve", "--port", "0", "--admin-port", "0"]);
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
        (&["--services", "blob,dfs"][..], "only the Blob service"),
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
        (("x-ms-lease-id", "missing"), 501, "NotImplemented"),
    ] {
        error(
            server.put(BLOB, &[header], b"replacement"),
            expected_status,
            expected_code,
        );
    }
    error(
        server.request(Method::PUT, BLOB, &[("x-ms-blob-type", "PageBlob")], b""),
        501,
        "NotImplemented",
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
        "InvalidBlockId",
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
