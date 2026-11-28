//! HTTP protocol tests for the third Blob wave against the built binary: page and
//! append blob snapshots, versions and diffs, incremental copy, expiry, immutability
//! and legal holds, soft-deleted containers, external copy sources, and the
//! hierarchical-namespace invariants of every new writer.

use base64::{Engine as _, engine::general_purpose::STANDARD};
use hmac::{Hmac, KeyInit as _, Mac as _};
use reqwest::{
    Method, Url,
    blocking::{Client, Response},
};
use sha2::Sha256;
use std::{
    collections::BTreeMap,
    fs,
    io::{BufRead as _, BufReader, Write as _},
    path::Path,
    process::{Child, Command, ExitStatus, Stdio},
    sync::{Arc, Mutex, mpsc},
    thread,
    time::{Duration, Instant, SystemTime},
};

const ACCOUNT: &str = "testaccount";
const VERSION: &str = "2023-11-03";
const CONTAINER: &str = "/testaccount/container?restype=container";
const KEY: [u8; 32] = [41; 32];
const PAGE: &str = "/testaccount/container/disk.vhd";
const APPEND: &str = "/testaccount/container/log.txt";
const BLOCK: &str = "/testaccount/container/plain.txt";

thread_local! {
    // Seconds the test clock has been advanced on this test's server.
    static CLOCK_OFFSET: std::cell::Cell<u64> = const { std::cell::Cell::new(0) };
}

fn server_now() -> SystemTime {
    SystemTime::now() + Duration::from_secs(CLOCK_OFFSET.get())
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

impl Emulator {
    fn start(location: Option<&Path>, extra: &[&str]) -> Self {
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
            .env("AZUIFER_ACCOUNT_KEY", STANDARD.encode(KEY))
            .args([
                "serve",
                "--port",
                "0",
                "--admin-port",
                "0",
                "--services",
                "blob",
            ]);
        if let Some(location) = location {
            command.arg("--location").arg(location);
        } else {
            command.arg("--in-memory");
        }
        command
            .args(extra)
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
            .timeout(Duration::from_secs(20))
            .build()
            .unwrap();
        let started = Self {
            process,
            blob: lines.remove("blob").expect("Blob listener URL"),
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

    /// Moves the test clock (start with `--test-clock`) and the dates requests are signed with.
    fn advance(&self, seconds: u64) {
        let response = self
            .client
            .post(format!(
                "{}/_azuifer/clock/advance?seconds={seconds}",
                self.admin
            ))
            .send()
            .unwrap();
        assert_eq!(response.status(), 200);
        CLOCK_OFFSET.set(CLOCK_OFFSET.get() + seconds);
    }

    fn request(&self, method: Method, path: &str, extra: &[(&str, &str)], body: &[u8]) -> Response {
        let url = Url::parse(&format!("{}{path}", self.blob)).unwrap();
        let length = (method == Method::PUT).then_some(body.len());
        let headers = signed(&method, &url, extra, length);
        let mut request = self.client.request(method, url);
        for (name, value) in headers {
            request = request.header(name, value);
        }
        if length.is_some() {
            request = request.body(body.to_vec());
        }
        // A server that rejects an oversize body before reading it can reset the
        // connection while the client is still writing; the rejection is the answer
        // under test, so retry until the response is read.
        let mut failure = None;
        for _ in 0..5 {
            match request.try_clone().expect("buffered body").send() {
                Ok(response) => return response,
                Err(error) => failure = Some(error),
            }
        }
        panic!("HTTP request completed: {failure:?}");
    }

    /// A request authenticated only by what the path carries (a SAS).
    fn anonymous(
        &self,
        method: Method,
        path: &str,
        extra: &[(&str, &str)],
        body: &[u8],
    ) -> Response {
        let url = Url::parse(&format!("{}{path}", self.blob)).unwrap();
        let mut request = self.client.request(method.clone(), url);
        for (name, value) in extra {
            request = request.header(*name, *value);
        }
        if method == Method::PUT {
            request = request.body(body.to_vec());
        }
        request.send().expect("HTTP request completed")
    }

    fn create_container(&self) {
        assert_eq!(self.request(Method::PUT, CONTAINER, &[], b"").status(), 201);
    }

    fn source_url(&self, path: &str) -> String {
        format!("{}{path}", self.blob)
    }

    fn create_page(&self, path: &str, size: u64, extra: &[(&str, &str)]) -> Response {
        let size = size.to_string();
        let mut headers = vec![
            ("x-ms-blob-type", "PageBlob"),
            ("x-ms-blob-content-length", size.as_str()),
        ];
        headers.extend_from_slice(extra);
        self.request(Method::PUT, path, &headers, b"")
    }

    fn create_append(&self, path: &str, extra: &[(&str, &str)]) -> Response {
        let mut headers = vec![("x-ms-blob-type", "AppendBlob")];
        headers.extend_from_slice(extra);
        self.request(Method::PUT, path, &headers, b"")
    }

    fn put_block_blob(&self, path: &str, body: &[u8]) -> Response {
        self.request(Method::PUT, path, &[("x-ms-blob-type", "BlockBlob")], body)
    }

    /// Put Page update of `start..start + body.len()`.
    fn write_pages(&self, path: &str, start: u64, body: &[u8], extra: &[(&str, &str)]) -> Response {
        let range = format!("bytes={start}-{}", start + body.len() as u64 - 1);
        let mut headers = vec![
            ("x-ms-page-write", "update"),
            ("x-ms-range", range.as_str()),
        ];
        headers.extend_from_slice(extra);
        self.request(Method::PUT, &format!("{path}?comp=page"), &headers, body)
    }

    fn clear_pages(&self, path: &str, start: u64, length: u64, extra: &[(&str, &str)]) -> Response {
        let range = format!("bytes={start}-{}", start + length - 1);
        let mut headers = vec![("x-ms-page-write", "clear"), ("x-ms-range", range.as_str())];
        headers.extend_from_slice(extra);
        self.request(Method::PUT, &format!("{path}?comp=page"), &headers, b"")
    }

    fn append(&self, path: &str, body: &[u8], extra: &[(&str, &str)]) -> Response {
        self.request(
            Method::PUT,
            &format!("{path}?comp=appendblock"),
            extra,
            body,
        )
    }

    fn page_ranges(&self, path: &str, query: &str, extra: &[(&str, &str)]) -> Response {
        self.request(
            Method::GET,
            &format!("{path}?comp=pagelist{query}"),
            extra,
            b"",
        )
    }

    fn read(&self, path: &str, range: Option<&str>) -> Response {
        let extra: Vec<(&str, &str)> = range
            .map(|range| ("x-ms-range", range))
            .into_iter()
            .collect();
        self.request(Method::GET, path, &extra, b"")
    }

    fn head(&self, path: &str) -> Response {
        self.request(Method::HEAD, path, &[], b"")
    }

    fn set_properties(&self, path: &str, extra: &[(&str, &str)]) -> Response {
        self.request(Method::PUT, &format!("{path}?comp=properties"), extra, b"")
    }
}

fn signed(
    method: &Method,
    url: &Url,
    extra: &[(&str, &str)],
    length: Option<usize>,
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
    let mut mac = Hmac::<Sha256>::new_from_slice(&KEY).unwrap();
    mac.update(message.as_bytes());
    headers.insert(
        "authorization".into(),
        format!(
            "SharedKey {ACCOUNT}:{}",
            STANDARD.encode(mac.finalize().into_bytes())
        ),
    );
    headers
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

fn account_sas(permissions: &str, types: &str) -> String {
    let expiry = "2099-01-01T00:00:00Z";
    let signed = format!("{ACCOUNT}\n{permissions}\nb\n{types}\n\n{expiry}\n\n\n{VERSION}\n\n");
    let mut mac = Hmac::<Sha256>::new_from_slice(&KEY).unwrap();
    mac.update(signed.as_bytes());
    format!(
        "sv={VERSION}&ss=b&srt={types}&sp={permissions}&se={}&sig={}",
        encode(expiry),
        encode(&STANDARD.encode(mac.finalize().into_bytes()))
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

fn has_header(response: &Response, name: &str) -> bool {
    response.headers().contains_key(name)
}

fn etag(response: &Response) -> String {
    header_text(response, "etag")
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

fn body(response: Response) -> Vec<u8> {
    response.bytes().unwrap().to_vec()
}

fn extent_files(location: &Path) -> Vec<String> {
    let mut names: Vec<String> = fs::read_dir(location.join("content"))
        .unwrap()
        .map(|entry| entry.unwrap().file_name().to_string_lossy().into_owned())
        .collect();
    names.sort();
    names
}

/// Runs `check` against an in-memory server and against a disk-backed one.
fn in_both_modes(check: impl Fn(&Emulator)) {
    check(&Emulator::start(None, &[]));
    let root = tempfile::tempdir().unwrap();
    check(&Emulator::start(Some(root.path()), &[]));
}

const DEST: &str = "/testaccount/container/backup.vhd";

#[test]
fn sas_permissions_gate_the_lifecycle_operations() {
    let server = Emulator::start(None, &[]);
    server.create_container();
    let blob = "/testaccount/container/a.txt";
    server.put_block_blob(blob, b"x");
    let sas = |permissions: &str| account_sas(permissions, "o");
    let call = |comp: &str, sas: String, extra: &[(&str, &str)]| {
        server.anonymous(
            Method::PUT,
            &format!("{blob}?comp={comp}&{sas}"),
            extra,
            b"",
        )
    };
    let never = [("x-ms-expiry-option", "NeverExpire")];
    error(
        call("expiry", sas("r"), &never),
        403,
        "AuthorizationPermissionMismatch",
    );
    assert_eq!(call("expiry", sas("w"), &never).status(), 200);
    let hold = [("x-ms-legal-hold", "true")];
    error(
        call("legalhold", sas("w"), &hold),
        403,
        "AuthorizationPermissionMismatch",
    );
    assert_eq!(call("legalhold", sas("l"), &hold).status(), 200);
    assert_eq!(
        call("legalhold", sas("i"), &[("x-ms-legal-hold", "false")]).status(),
        200
    );
    let until = http_date_in(3600);
    let policy = [("x-ms-immutability-policy-until-date", until.as_str())];
    error(
        call("immutabilityPolicies", sas("l"), &policy),
        403,
        "AuthorizationPermissionMismatch",
    );
    assert_eq!(
        call("immutabilityPolicies", sas("i"), &policy).status(),
        200
    );
    let restore = server.anonymous(
        Method::PUT,
        &format!(
            "/testaccount/other?restype=container&comp=undelete&{}",
            account_sas("w", "c")
        ),
        &[
            ("x-ms-deleted-container-name", "gone"),
            ("x-ms-deleted-container-version", "01D"),
        ],
        b"",
    );
    error(restore, 404, "ContainerNotFound");
}

fn extents_on_disk(location: &Path) -> usize {
    extent_files(location)
        .iter()
        .filter(|name| name.starts_with("extent-"))
        .count()
}

/// `(element, start, end)` of every range of a Get Page Ranges answer, in document order.
fn page_list(response: Response) -> Vec<(&'static str, u64, u64)> {
    assert_eq!(response.status(), 200);
    let text = response.text().unwrap();
    let number = |tag: &str, from: usize| -> (u64, usize) {
        let open = format!("<{tag}>");
        let start = text[from..].find(&open).unwrap() + from + open.len();
        let end = text[start..].find('<').unwrap() + start;
        (text[start..end].parse().unwrap(), end)
    };
    let mut found = Vec::new();
    let mut at = 0;
    while let Some(next) = text[at..].find("<Start>") {
        let position = at + next;
        let tag = if text[..position].ends_with("<ClearRange>") {
            "ClearRange"
        } else {
            "PageRange"
        };
        let (start, after) = number("Start", position);
        let (end, after) = number("End", after);
        found.push((tag, start, end));
        at = after;
    }
    found
}

/// A buffer of `total` zero bytes with `(offset, value, length)` runs filled in.
fn laid_out(total: usize, parts: &[(usize, u8, usize)]) -> Vec<u8> {
    let mut bytes = vec![0u8; total];
    for (offset, value, length) in parts {
        bytes[*offset..offset + length].fill(*value);
    }
    bytes
}

impl Emulator {
    fn put(&self, path: &str, extra: &[(&str, &str)], body: &[u8]) -> Response {
        self.request(Method::PUT, path, extra, body)
    }

    /// Snapshot Blob; returns the snapshot time.
    fn snapshot(&self, path: &str) -> String {
        let response = self.request(Method::PUT, &format!("{path}?comp=snapshot"), &[], b"");
        assert_eq!(response.status(), 201);
        header_text(&response, "x-ms-snapshot")
    }

    fn list(&self, query: &str) -> String {
        let extra = if query.is_empty() {
            String::new()
        } else {
            format!("&{query}")
        };
        let response = self.request(
            Method::GET,
            &format!("/testaccount/container?restype=container&comp=list{extra}"),
            &[],
            b"",
        );
        assert_eq!(response.status(), 200);
        response.text().unwrap()
    }

    fn set_retention(&self, days: u32) {
        let body = format!(
            "<StorageServiceProperties><DeleteRetentionPolicy><Enabled>true</Enabled>\
             <Days>{days}</Days></DeleteRetentionPolicy></StorageServiceProperties>"
        );
        assert_eq!(
            self.request(
                Method::PUT,
                "/testaccount/?restype=service&comp=properties",
                &[],
                body.as_bytes()
            )
            .status(),
            202
        );
    }

    fn restart(&mut self, location: &Path, extra: &[&str]) {
        self.process.shutdown().unwrap();
        *self = Self::start(Some(location), extra);
    }
}

#[test]
fn page_blob_snapshots_report_ranges_and_diffs() {
    in_both_modes(|server| {
        server.create_container();
        assert_eq!(
            server
                .create_page(PAGE, 4096, &[("x-ms-blob-sequence-number", "3")])
                .status(),
            201
        );
        for (start, value) in [(0u64, b'a'), (1024, b'b'), (2048, b'c')] {
            assert_eq!(
                server.write_pages(PAGE, start, &[value; 512], &[]).status(),
                201
            );
        }
        let first = server.snapshot(PAGE);
        assert_eq!(server.write_pages(PAGE, 0, &[b'd'; 512], &[]).status(), 201);
        assert_eq!(server.clear_pages(PAGE, 1024, 512, &[]).status(), 201);
        assert_eq!(
            server.write_pages(PAGE, 3072, &[b'e'; 512], &[]).status(),
            201
        );
        let second = server.snapshot(PAGE);
        assert!(first < second);

        let snapshot_one = laid_out(
            4096,
            &[(0, b'a', 512), (1024, b'b', 512), (2048, b'c', 512)],
        );
        let at_first = server.read(&format!("{PAGE}?snapshot={first}"), None);
        assert_eq!(at_first.status(), 200);
        assert_eq!(header_text(&at_first, "x-ms-blob-type"), "PageBlob");
        assert_eq!(header_text(&at_first, "x-ms-blob-sequence-number"), "3");
        assert_eq!(body(at_first), snapshot_one);
        let head = server.request(Method::HEAD, &format!("{PAGE}?snapshot={second}"), &[], b"");
        assert_eq!(head.status(), 200);
        assert_eq!(header_text(&head, "content-length"), "4096");

        // Plain listing of a snapshot.
        assert_eq!(
            page_list(server.page_ranges(PAGE, &format!("&snapshot={first}"), &[])),
            [
                ("PageRange", 0, 511),
                ("PageRange", 1024, 1535),
                ("PageRange", 2048, 2559)
            ]
        );
        // The diff of the live blob and of the second snapshot against the first.
        let changes = [
            ("PageRange", 0, 511),
            ("ClearRange", 1024, 1535),
            ("PageRange", 3072, 3583),
        ];
        assert_eq!(
            page_list(server.page_ranges(PAGE, &format!("&prevsnapshot={first}"), &[])),
            changes
        );
        assert_eq!(
            page_list(server.page_ranges(
                PAGE,
                &format!("&snapshot={second}&prevsnapshot={first}"),
                &[]
            )),
            changes
        );
        assert!(
            page_list(server.page_ranges(PAGE, &format!("&prevsnapshot={second}"), &[])).is_empty()
        );
        // A window clips the diff; maxresults pages through it.
        assert_eq!(
            page_list(server.page_ranges(
                PAGE,
                &format!("&prevsnapshot={first}"),
                &[("x-ms-range", "bytes=1000-3100")]
            )),
            [("ClearRange", 1024, 1535), ("PageRange", 3072, 3100)]
        );
        let paged = server.page_ranges(PAGE, &format!("&prevsnapshot={first}&maxresults=1"), &[]);
        let text = paged.text().unwrap();
        assert!(text.contains("<NextMarker>1024</NextMarker>"), "{text}");
        assert_eq!(
            page_list(server.page_ranges(
                PAGE,
                &format!("&prevsnapshot={first}&maxresults=1&marker=1024"),
                &[]
            )),
            [("ClearRange", 1024, 1535)]
        );
        // Errors.
        error(
            server.page_ranges(
                PAGE,
                &format!("&snapshot={first}&prevsnapshot={second}"),
                &[],
            ),
            400,
            "PreviousSnapshotCannotBeNewer",
        );
        error(
            server.page_ranges(PAGE, "&prevsnapshot=2020-01-01T00:00:00.0000000Z", &[]),
            409,
            "PreviousSnapshotNotFound",
        );
        error(
            server.page_ranges(PAGE, "&snapshot=2020-01-01T00:00:00.0000000Z", &[]),
            404,
            "BlobNotFound",
        );
        error(
            server.page_ranges(PAGE, "&snapshot=not-a-time", &[]),
            400,
            "InvalidQueryParameterValue",
        );
        let tag =
            etag(&server.request(Method::HEAD, &format!("{PAGE}?snapshot={first}"), &[], b""));
        assert_eq!(
            server
                .page_ranges(
                    PAGE,
                    &format!("&snapshot={first}"),
                    &[("if-match", tag.as_str())]
                )
                .status(),
            200,
            "a snapshot is conditioned on its own ETag"
        );
        // The listing shows both snapshots as page blobs.
        let listing = server.list("include=snapshots");
        assert_eq!(
            listing.matches("<BlobType>PageBlob</BlobType>").count(),
            3,
            "{listing}"
        );
        assert!(listing.contains(&format!("<Snapshot>{first}</Snapshot>")));
    });
}

#[test]
fn a_page_blob_snapshot_shares_extents_and_outlives_overwrites_and_deletes() {
    let root = tempfile::tempdir().unwrap();
    let location = root.path().join("store");
    let mut server = Emulator::start(Some(&location), &[]);
    server.create_container();
    server.create_page(PAGE, 1024, &[]);
    server.write_pages(PAGE, 0, &[b'a'; 512], &[]);
    let first = server.snapshot(PAGE);
    assert_eq!(
        extents_on_disk(&location),
        1,
        "the snapshot shares the extent"
    );
    server.write_pages(PAGE, 0, &[b'b'; 512], &[]);
    assert_eq!(
        extents_on_disk(&location),
        2,
        "the overwritten extent is kept"
    );
    let expected = laid_out(1024, &[(0, b'a', 512)]);
    assert_eq!(
        body(server.read(&format!("{PAGE}?snapshot={first}"), None)),
        expected
    );

    server.restart(&location, &[]);
    assert_eq!(
        extents_on_disk(&location),
        2,
        "recovery keeps referenced extents"
    );
    assert_eq!(
        body(server.read(&format!("{PAGE}?snapshot={first}"), None)),
        expected
    );
    error(
        server.request(Method::DELETE, PAGE, &[], b""),
        409,
        "SnapshotsPresent",
    );
    let deleted = server.request(
        Method::DELETE,
        &format!("{PAGE}?snapshot={first}"),
        &[],
        b"",
    );
    assert_eq!(deleted.status(), 202);
    assert_eq!(header_text(&deleted, "x-ms-delete-type-permanent"), "true");
    assert_eq!(extents_on_disk(&location), 1);

    let second = server.snapshot(PAGE);
    assert_eq!(
        server
            .request(
                Method::DELETE,
                PAGE,
                &[("x-ms-delete-snapshots", "include")],
                b""
            )
            .status(),
        202
    );
    assert_eq!(extents_on_disk(&location), 0, "the last reference is gone");
    error(
        server.read(&format!("{PAGE}?snapshot={second}"), None),
        404,
        "BlobNotFound",
    );

    // Deleting a container releases the extents its snapshots held.
    server.create_page(PAGE, 512, &[]);
    server.write_pages(PAGE, 0, &[b'z'; 512], &[]);
    server.snapshot(PAGE);
    server.write_pages(PAGE, 0, &[b'y'; 512], &[]);
    assert_eq!(extents_on_disk(&location), 2);
    assert_eq!(
        server
            .request(
                Method::DELETE,
                "/testaccount/container?restype=container",
                &[],
                b""
            )
            .status(),
        202
    );
    assert_eq!(extents_on_disk(&location), 0);
}

#[test]
fn append_blob_snapshots_and_versions_keep_their_blocks() {
    let server = Emulator::start(None, &["--versioning-accounts", ACCOUNT]);
    server.create_container();
    let created = server.create_append(APPEND, &[]);
    assert_eq!(created.status(), 201);
    let empty_version = header_text(&created, "x-ms-version-id");
    let first = server.append(APPEND, b"abc", &[]);
    assert_eq!(first.status(), 201);
    let one_block = header_text(&first, "x-ms-version-id");
    assert_ne!(empty_version, one_block, "an append is a new version");
    assert_eq!(server.append(APPEND, b"def", &[]).status(), 201);

    let version = server.read(&format!("{APPEND}?versionid={one_block}"), None);
    assert_eq!(version.status(), 200);
    assert_eq!(header_text(&version, "x-ms-blob-type"), "AppendBlob");
    assert_eq!(
        header_text(&version, "x-ms-blob-committed-block-count"),
        "1"
    );
    assert_eq!(header_text(&version, "x-ms-is-current-version"), "false");
    assert_eq!(body(version), b"abc");
    assert_eq!(
        body(server.read(&format!("{APPEND}?versionid={empty_version}"), None)),
        b""
    );
    let listing = server.list("include=versions");
    assert_eq!(listing.matches("<VersionId>").count(), 3, "{listing}");

    let snapshot = server.snapshot(APPEND);
    assert_eq!(server.append(APPEND, b"ghi", &[]).status(), 201);
    let at_snapshot = server.read(&format!("{APPEND}?snapshot={snapshot}"), None);
    assert_eq!(
        header_text(&at_snapshot, "x-ms-blob-committed-block-count"),
        "2"
    );
    assert_eq!(body(at_snapshot), b"abcdef");
    assert_eq!(body(server.read(APPEND, None)), b"abcdefghi");
    let range = server.read(&format!("{APPEND}?snapshot={snapshot}"), Some("bytes=2-3"));
    assert_eq!(range.status(), 206);
    assert_eq!(body(range), b"cd");

    // A sealed blob snapshots as sealed, and the snapshot stays readable after deletion.
    let seal = server.request(Method::PUT, &format!("{APPEND}?comp=seal"), &[], b"");
    assert_eq!(seal.status(), 200);
    let sealed = server.snapshot(APPEND);
    let at_sealed = server.read(&format!("{APPEND}?snapshot={sealed}"), None);
    assert_eq!(header_text(&at_sealed, "x-ms-blob-sealed"), "true");
    let deleted = server.request(
        Method::DELETE,
        APPEND,
        &[("x-ms-delete-snapshots", "include")],
        b"",
    );
    assert_eq!(header_text(&deleted, "x-ms-delete-type-permanent"), "false");
    assert_eq!(
        body(server.read(&format!("{APPEND}?versionid={one_block}"), None)),
        b"abc",
        "a delete keeps the versions"
    );
}

#[test]
fn page_blob_versions_survive_overwrites_and_deletes_and_promote_by_copy() {
    let server = Emulator::start(None, &["--versioning-accounts", ACCOUNT]);
    server.create_container();
    let created = server.create_page(PAGE, 1024, &[]);
    assert_eq!(created.status(), 201);
    let written = server.write_pages(PAGE, 0, &[b'a'; 512], &[]);
    let old = header_text(&written, "x-ms-version-id");
    let newer = header_text(
        &server.write_pages(PAGE, 0, &[b'b'; 512], &[]),
        "x-ms-version-id",
    );
    assert_ne!(old, newer);
    let at_old = server.read(&format!("{PAGE}?versionid={old}"), None);
    assert_eq!(header_text(&at_old, "x-ms-is-current-version"), "false");
    assert_eq!(body(at_old), laid_out(1024, &[(0, b'a', 512)]));
    assert_eq!(
        page_list(server.page_ranges(PAGE, "", &[])),
        [("PageRange", 0, 511)]
    );

    let deleted = server.request(Method::DELETE, PAGE, &[], b"");
    assert_eq!(deleted.status(), 202);
    assert_eq!(header_text(&deleted, "x-ms-delete-type-permanent"), "false");
    error(server.read(PAGE, None), 404, "BlobNotFound");
    assert_eq!(
        body(server.read(&format!("{PAGE}?versionid={old}"), None)),
        laid_out(1024, &[(0, b'a', 512)])
    );

    // Copying a version onto the name promotes it, keeping its type and ranges.
    let promote = server.put(
        PAGE,
        &[(
            "x-ms-copy-source",
            &format!("{}?versionid={old}", server.source_url(PAGE)),
        )],
        b"",
    );
    assert_eq!(promote.status(), 202);
    let current = server.read(PAGE, None);
    assert_eq!(header_text(&current, "x-ms-blob-type"), "PageBlob");
    assert_eq!(body(current), laid_out(1024, &[(0, b'a', 512)]));
}

#[test]
fn soft_deleted_page_blobs_restore_and_are_purged_on_the_clock() {
    let root = tempfile::tempdir().unwrap();
    let location = root.path().join("store");
    let server = Emulator::start(Some(&location), &["--test-clock"]);
    server.create_container();
    server.set_retention(1);
    server.create_page(PAGE, 1024, &[("x-ms-blob-sequence-number", "7")]);
    server.write_pages(PAGE, 512, &[b'q'; 512], &[]);
    let deleted = server.request(Method::DELETE, PAGE, &[], b"");
    assert_eq!(header_text(&deleted, "x-ms-delete-type-permanent"), "false");
    error(server.read(PAGE, None), 404, "BlobNotFound");
    let listing = server.list("include=deleted");
    assert!(listing.contains("<Deleted>true</Deleted>"), "{listing}");
    assert!(listing.contains("<BlobType>PageBlob</BlobType>"));
    assert_eq!(
        extents_on_disk(&location),
        1,
        "soft-deleted content stays on disk"
    );

    let restored = server.request(Method::PUT, &format!("{PAGE}?comp=undelete"), &[], b"");
    assert_eq!(restored.status(), 200);
    let back = server.read(PAGE, None);
    assert_eq!(header_text(&back, "x-ms-blob-type"), "PageBlob");
    assert_eq!(header_text(&back, "x-ms-blob-sequence-number"), "7");
    assert_eq!(body(back), laid_out(1024, &[(512, b'q', 512)]));
    assert_eq!(
        page_list(server.page_ranges(PAGE, "", &[])),
        [("PageRange", 512, 1023)],
        "the restored blob keeps its ranges"
    );
    assert_eq!(extents_on_disk(&location), 1);

    // An overwrite keeps the old content as a soft-deleted snapshot until retention ends.
    assert_eq!(
        server.put_block_blob(PAGE, b"now a block blob").status(),
        201
    );
    assert_eq!(
        extents_on_disk(&location),
        2,
        "the old ranges and the new block"
    );
    assert!(
        server
            .list("include=deleted,snapshots")
            .contains("<Snapshot>")
    );
    server.advance(2 * 86_400);
    let after = server.list("include=deleted,snapshots");
    assert!(
        !after.contains("<Snapshot>"),
        "expired entries vanish at once: {after}"
    );
    // The next change that commits reclaims the expired entry's storage.
    server.snapshot(PAGE);
    assert_eq!(extents_on_disk(&location), 1, "only the block blob remains");
}

#[test]
fn incremental_copy_blob_copies_snapshots_and_takes_its_own() {
    in_both_modes(|server| {
        server.create_container();
        server.create_page(PAGE, 4096, &[("x-ms-blob-sequence-number", "5")]);
        server.write_pages(PAGE, 0, &[b'a'; 512], &[]);
        server.write_pages(PAGE, 1024, &[b'b'; 512], &[]);
        let one = server.snapshot(PAGE);
        server.write_pages(PAGE, 0, &[b'c'; 512], &[]);
        server.write_pages(PAGE, 2048, &[b'd'; 512], &[]);
        let two = server.snapshot(PAGE);
        let source = |time: &str| format!("{}?snapshot={time}", server.source_url(PAGE));
        let copy = |from: &str| {
            server.put(
                &format!("{DEST}?comp=incrementalcopy"),
                &[("x-ms-copy-source", from)],
                b"",
            )
        };

        let first = copy(&source(&one));
        assert_eq!(first.status(), 202);
        assert_eq!(header_text(&first, "x-ms-copy-status"), "pending");
        assert!(has_header(&first, "x-ms-copy-id") && has_header(&first, "etag"));
        let expected_one = laid_out(4096, &[(0, b'a', 512), (1024, b'b', 512)]);
        error(
            server.read(DEST, None),
            409,
            "OperationNotAllowedOnIncrementalCopyBlob",
        );
        let head = server.head(DEST);
        assert_eq!(header_text(&head, "x-ms-blob-type"), "PageBlob");
        assert_eq!(header_text(&head, "x-ms-blob-sequence-number"), "5");
        assert_eq!(header_text(&head, "x-ms-incremental-copy"), "true");
        assert_eq!(header_text(&head, "x-ms-copy-status"), "success");
        let first_snapshot = header_text(&head, "x-ms-copy-destination-snapshot");
        assert_eq!(
            body(server.read(&format!("{DEST}?snapshot={first_snapshot}"), None)),
            expected_one
        );
        assert!(
            server
                .list("include=snapshots&prefix=backup")
                .contains(&format!("<Snapshot>{first_snapshot}</Snapshot>"))
        );

        let second = copy(&source(&two));
        assert_eq!(second.status(), 202);
        let expected_two = laid_out(
            4096,
            &[(0, b'c', 512), (1024, b'b', 512), (2048, b'd', 512)],
        );
        let second_snapshot = header_text(&server.head(DEST), "x-ms-copy-destination-snapshot");
        assert_ne!(first_snapshot, second_snapshot);
        assert_eq!(
            body(server.read(&format!("{DEST}?snapshot={second_snapshot}"), None)),
            expected_two
        );
        assert_eq!(
            body(server.read(&format!("{DEST}?snapshot={first_snapshot}"), None)),
            expected_one,
            "the destination snapshot keeps the first copy"
        );
        assert_eq!(
            page_list(server.page_ranges(
                DEST,
                &format!("&snapshot={second_snapshot}&prevsnapshot={first_snapshot}"),
                &[]
            )),
            [("PageRange", 0, 511), ("PageRange", 2048, 2559)],
            "later copies diff against the snapshots the destination took"
        );
        let listing = server.list("include=snapshots&prefix=backup");
        assert!(
            listing.contains("<IncrementalCopy>true</IncrementalCopy>"),
            "{listing}"
        );

        error(
            copy(&source(&one)),
            409,
            "IncrementalCopyOfEarlierVersionSnapshotNotAllowed",
        );
        error(
            copy(&server.source_url(PAGE)),
            409,
            "IncrementalCopySourceMustBeSnapshot",
        );
        let other = "/testaccount/container/other.vhd";
        server.create_page(other, 512, &[]);
        let other_snapshot = server.snapshot(other);
        error(
            copy(&format!(
                "{}?snapshot={other_snapshot}",
                server.source_url(other)
            )),
            409,
            "IncrementalCopyBlobMismatch",
        );
        error(
            server.write_pages(DEST, 0, &[1u8; 512], &[]),
            409,
            "OperationNotAllowedOnIncrementalCopyBlob",
        );
        // Sources and destinations that cannot take part.
        assert_eq!(server.put_block_blob(BLOCK, b"block").status(), 201);
        let block_snapshot = server.snapshot(BLOCK);
        let fresh = "/testaccount/container/fresh.vhd";
        error(
            server.put(
                &format!("{fresh}?comp=incrementalcopy"),
                &[(
                    "x-ms-copy-source",
                    &format!("{}?snapshot={block_snapshot}", server.source_url(BLOCK)),
                )],
                b"",
            ),
            409,
            "InvalidSourceBlobType",
        );
        let existing = "/testaccount/container/existing.vhd";
        server.create_page(existing, 512, &[]);
        error(
            server.put(
                &format!("{existing}?comp=incrementalcopy"),
                &[("x-ms-copy-source", &source(&one))],
                b"",
            ),
            409,
            "BlobAlreadyExists",
        );
        error(
            server.put(
                &format!("{fresh}?comp=incrementalcopy"),
                &[(
                    "x-ms-copy-source",
                    &format!(
                        "{}?snapshot=2020-01-01T00:00:00.0000000Z",
                        server.source_url(PAGE)
                    ),
                )],
                b"",
            ),
            404,
            "CannotVerifyCopySource",
        );
    });
}

#[test]
fn copy_blob_of_a_page_snapshot_shares_its_extents() {
    let root = tempfile::tempdir().unwrap();
    let location = root.path().join("store");
    let server = Emulator::start(Some(&location), &[]);
    server.create_container();
    server.create_page(PAGE, 1024, &[]);
    server.write_pages(PAGE, 0, &[b'a'; 512], &[]);
    let snapshot = server.snapshot(PAGE);
    server.write_pages(PAGE, 0, &[b'b'; 512], &[]);
    let copy = server.put(
        DEST,
        &[(
            "x-ms-copy-source",
            &format!("{}?snapshot={snapshot}", server.source_url(PAGE)),
        )],
        b"",
    );
    assert_eq!(copy.status(), 202);
    let copied = server.read(DEST, None);
    assert_eq!(header_text(&copied, "x-ms-blob-type"), "PageBlob");
    assert_eq!(body(copied), laid_out(1024, &[(0, b'a', 512)]));
    assert_eq!(extents_on_disk(&location), 2, "the copy added no extent");
    // A Put Blob From URL of a page snapshot reads it densely into a block blob.
    let dense = "/testaccount/container/dense.bin";
    let from_url = server.put(
        dense,
        &[
            ("x-ms-blob-type", "BlockBlob"),
            (
                "x-ms-copy-source",
                &format!("{}?snapshot={snapshot}", server.source_url(PAGE)),
            ),
        ],
        b"",
    );
    assert_eq!(from_url.status(), 201);
    assert_eq!(
        body(server.read(dense, None)),
        laid_out(1024, &[(0, b'a', 512)])
    );
}

fn http_date_in(seconds: u64) -> String {
    httpdate::fmt_http_date(server_now() + Duration::from_secs(seconds))
}

fn expiry(
    server: &Emulator,
    path: &str,
    option: &str,
    time: Option<&str>,
    extra: &[(&str, &str)],
) -> Response {
    let mut headers = vec![("x-ms-expiry-option", option)];
    if let Some(time) = time {
        headers.push(("x-ms-expiry-time", time));
    }
    headers.extend_from_slice(extra);
    server.put(&format!("{path}?comp=expiry"), &headers, b"")
}

#[test]
fn an_expiry_too_far_ahead_to_report_is_refused_and_leaves_the_blob_usable() {
    let server = Emulator::start(None, &[]);
    server.create_container();
    let blob = "/testaccount/container/a.txt";
    assert_eq!(server.put_block_blob(blob, b"x").status(), 201);
    for option in ["RelativeToNow", "RelativeToCreation"] {
        for millis in ["9000000000000000", "9223372036854775807", "253402300800000"] {
            error(
                expiry(&server, blob, option, Some(millis), &[]),
                400,
                "InvalidHeaderValue",
            );
            let head = server.head(blob);
            assert_eq!(
                head.status(),
                200,
                "{option} {millis} must not break the blob"
            );
            assert!(!has_header(&head, "x-ms-expiry-time"));
        }
    }
    let year = "31536000000";
    assert_eq!(
        expiry(&server, blob, "RelativeToNow", Some(year), &[]).status(),
        200
    );
    assert!(has_header(&server.head(blob), "x-ms-expiry-time"));
}

#[test]
fn service_statistics_exist_only_on_the_secondary_endpoint() {
    let server = Emulator::start(None, &[]);
    let port = server.blob.rsplit(':').next().unwrap().to_owned();
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
    let host = format!("testaccount-secondary.blob.localhost:{port}");
    let stats = server.request(
        Method::GET,
        "/?restype=service&comp=stats",
        &[("host", host.as_str())],
        b"",
    );
    assert_eq!(stats.status(), 200);
    let text = stats.text().unwrap();
    assert!(
        text.contains("<GeoReplication><Status>live</Status><LastSyncTime>"),
        "{text}"
    );
}

#[test]
fn set_blob_expiry_removes_blobs_lazily_on_the_clock() {
    let server = Emulator::start(None, &["--test-clock"]);
    server.create_container();
    let blob = "/testaccount/container/a.txt";
    assert_eq!(server.put_block_blob(blob, b"short lived").status(), 201);

    let set = expiry(&server, blob, "RelativeToNow", Some("30000"), &[]);
    assert_eq!(set.status(), 200);
    assert!(has_header(&set, "etag") && has_header(&set, "last-modified"));
    let head = server.head(blob);
    let deadline = httpdate::parse_http_date(&header_text(&head, "x-ms-expiry-time")).unwrap();
    let remaining = deadline.duration_since(server_now()).unwrap();
    assert!(remaining > Duration::from_secs(25) && remaining <= Duration::from_secs(30));
    assert!(has_header(&server.read(blob, None), "x-ms-expiry-time"));
    assert!(server.list("").contains("<Expiry-Time>"));

    server.advance(29);
    assert_eq!(server.head(blob).status(), 200);
    server.advance(2);
    error(server.read(blob, None), 404, "BlobNotFound");
    assert!(!server.list("").contains("a.txt"));

    // Absolute and relative-to-creation deadlines.
    assert_eq!(server.put_block_blob(blob, b"again").status(), 201);
    assert_eq!(
        expiry(&server, blob, "Absolute", Some(&http_date_in(60)), &[]).status(),
        200
    );
    server.advance(61);
    assert_eq!(server.head(blob).status(), 404);
    assert_eq!(server.put_block_blob(blob, b"third").status(), 201);
    assert_eq!(
        expiry(&server, blob, "RelativeToCreation", Some("120000"), &[]).status(),
        200
    );
    server.advance(100);
    assert_eq!(server.head(blob).status(), 200);
    server.advance(30);
    assert_eq!(server.head(blob).status(), 404);

    // NeverExpire removes a deadline, and an overwrite starts a new blob without one.
    assert_eq!(server.put_block_blob(blob, b"x").status(), 201);
    assert_eq!(
        expiry(&server, blob, "RelativeToNow", Some("10000"), &[]).status(),
        200
    );
    assert_eq!(
        expiry(&server, blob, "NeverExpire", None, &[]).status(),
        200
    );
    assert!(!has_header(&server.head(blob), "x-ms-expiry-time"));
    assert_eq!(
        expiry(&server, blob, "RelativeToNow", Some("10000"), &[]).status(),
        200
    );
    assert_eq!(server.put_block_blob(blob, b"y").status(), 201);
    assert!(!has_header(&server.head(blob), "x-ms-expiry-time"));
    server.advance(60);
    assert_eq!(server.head(blob).status(), 200);

    // Errors.
    error(
        server.put(&format!("{blob}?comp=expiry"), &[], b""),
        400,
        "MissingRequiredHeader",
    );
    error(
        expiry(&server, blob, "Absolute", Some(&http_date_in(0)), &[]),
        400,
        "InvalidHeaderValue",
    );
    error(
        expiry(&server, blob, "NeverExpire", Some("5"), &[]),
        400,
        "InvalidHeaderValue",
    );
    error(
        expiry(&server, blob, "RelativeToNow", None, &[]),
        400,
        "MissingRequiredHeader",
    );
    error(
        expiry(
            &server,
            "/testaccount/container/missing",
            "RelativeToNow",
            Some("1"),
            &[],
        ),
        404,
        "BlobNotFound",
    );
    error(
        expiry(
            &server,
            blob,
            "RelativeToNow",
            Some("1000"),
            &[("if-match", "*")],
        ),
        501,
        "NotImplemented",
    );
}

#[test]
fn an_expiring_blob_needs_its_lease_and_an_expired_page_blob_frees_its_extents() {
    let root = tempfile::tempdir().unwrap();
    let location = root.path().join("store");
    let server = Emulator::start(Some(&location), &["--test-clock"]);
    server.create_container();
    server.create_page(PAGE, 1024, &[]);
    server.write_pages(PAGE, 0, &[b'a'; 512], &[]);
    server.snapshot(PAGE);
    server.write_pages(PAGE, 0, &[b'b'; 512], &[]);
    assert_eq!(extents_on_disk(&location), 2);
    let lease = server.put(
        &format!("{PAGE}?comp=lease"),
        &[
            ("x-ms-lease-action", "acquire"),
            ("x-ms-lease-duration", "-1"),
        ],
        b"",
    );
    let lease_id = header_text(&lease, "x-ms-lease-id");
    error(
        expiry(&server, PAGE, "RelativeToNow", Some("5000"), &[]),
        412,
        "LeaseIdMissing",
    );
    assert_eq!(
        expiry(
            &server,
            PAGE,
            "RelativeToNow",
            Some("5000"),
            &[("x-ms-lease-id", lease_id.as_str())]
        )
        .status(),
        200
    );
    server.advance(6);
    assert_eq!(server.head(PAGE).status(), 404);
    assert_eq!(
        extents_on_disk(&location),
        0,
        "the blob and its snapshot are gone"
    );
    assert!(
        !server
            .list("include=snapshots,deleted")
            .contains("disk.vhd")
    );
}

#[test]
fn an_expired_blob_is_not_soft_deleted() {
    let server = Emulator::start(None, &["--test-clock"]);
    server.create_container();
    server.set_retention(1);
    let blob = "/testaccount/container/a.txt";
    server.put_block_blob(blob, b"x");
    expiry(&server, blob, "RelativeToNow", Some("1000"), &[]);
    server.advance(2);
    assert_eq!(server.head(blob).status(), 404);
    assert!(!server.list("include=deleted").contains("a.txt"));
    error(
        server.put(&format!("{blob}?comp=undelete"), &[], b""),
        404,
        "BlobNotFound",
    );
}

fn policy(server: &Emulator, path: &str, until: &str, mode: Option<&str>) -> Response {
    let mut headers = vec![("x-ms-immutability-policy-until-date", until)];
    if let Some(mode) = mode {
        headers.push(("x-ms-immutability-policy-mode", mode));
    }
    server.put(&format!("{path}?comp=immutabilityPolicies"), &headers, b"")
}

#[test]
fn an_unlocked_immutability_policy_blocks_changes_until_it_is_removed_or_ends() {
    let server = Emulator::start(None, &["--test-clock"]);
    server.create_container();
    let blob = "/testaccount/container/ledger.txt";
    assert_eq!(server.put_block_blob(blob, b"entry").status(), 201);
    let tag = etag(&server.head(blob));
    let until = http_date_in(3600);
    let set = policy(&server, blob, &until, None);
    assert_eq!(set.status(), 200);
    assert_eq!(
        header_text(&set, "x-ms-immutability-policy-until-date"),
        until
    );
    assert_eq!(
        header_text(&set, "x-ms-immutability-policy-mode"),
        "unlocked"
    );
    assert_eq!(
        etag(&server.head(blob)),
        tag,
        "a policy does not change the ETag"
    );

    for response in [server.head(blob), server.read(blob, None)] {
        assert_eq!(
            header_text(&response, "x-ms-immutability-policy-until-date"),
            until
        );
        assert_eq!(
            header_text(&response, "x-ms-immutability-policy-mode"),
            "unlocked"
        );
        assert_eq!(header_text(&response, "x-ms-legal-hold"), "false");
    }
    let listing = server.list("");
    assert!(
        listing.contains("<ImmutabilityPolicyMode>unlocked</ImmutabilityPolicyMode>"),
        "{listing}"
    );

    let blocked = |response: Response| error(response, 409, "BlobImmutableDueToPolicy");
    blocked(server.put_block_blob(blob, b"rewrite"));
    blocked(server.request(Method::DELETE, blob, &[], b""));
    blocked(server.put(
        &format!("{blob}?comp=metadata"),
        &[("x-ms-meta-a", "b")],
        b"",
    ));
    blocked(server.set_properties(blob, &[("x-ms-blob-content-type", "text/x-new")]));
    server.put_block_blob(BLOCK, b"source");
    blocked(server.put(
        blob,
        &[("x-ms-copy-source", &server.source_url(BLOCK))],
        b"",
    ));
    blocked(server.request(
        Method::DELETE,
        "/testaccount/container?restype=container",
        &[],
        b"",
    ));
    // Reads, snapshots, tiers, and tags are not changes to the protected data.
    assert!(!server.snapshot(blob).is_empty());
    assert_eq!(
        server
            .put(
                &format!("{blob}?comp=tier"),
                &[("x-ms-access-tier", "Cool")],
                b""
            )
            .status(),
        200
    );
    assert_eq!(
        server
            .put(
                &format!("{blob}?comp=tags"),
                &[],
                b"<Tags><TagSet><Tag><Key>k</Key><Value>v</Value></Tag></TagSet></Tags>"
            )
            .status(),
        204
    );

    // A bad time or mode is a client error.
    error(
        policy(&server, blob, &http_date_in(0), None),
        400,
        "InvalidHeaderValue",
    );
    error(
        policy(&server, blob, &until, Some("Mutable")),
        400,
        "InvalidHeaderValue",
    );
    error(
        server.put(&format!("{blob}?comp=immutabilityPolicies"), &[], b""),
        400,
        "MissingRequiredHeader",
    );
    error(
        policy(&server, "/testaccount/container/none", &until, None),
        404,
        "BlobNotFound",
    );

    // An unlocked policy can be shortened and then removed.
    let shorter = http_date_in(120);
    assert_eq!(
        policy(&server, blob, &shorter, Some("Unlocked")).status(),
        200
    );
    let removed = server.request(
        Method::DELETE,
        &format!("{blob}?comp=immutabilityPolicies"),
        &[],
        b"",
    );
    assert_eq!(removed.status(), 200);
    assert!(!has_header(
        &server.head(blob),
        "x-ms-immutability-policy-mode"
    ));
    assert_eq!(server.put_block_blob(blob, b"rewritten").status(), 201);

    // A policy that has ended no longer protects the blob.
    assert_eq!(policy(&server, blob, &http_date_in(30), None).status(), 200);
    blocked(server.request(Method::DELETE, blob, &[], b""));
    server.advance(31);
    error(
        server.request(Method::DELETE, blob, &[], b""),
        409,
        "SnapshotsPresent",
    );
    let include = [("x-ms-delete-snapshots", "include")];
    assert_eq!(
        server.request(Method::DELETE, blob, &include, b"").status(),
        202
    );
}

#[test]
fn a_locked_policy_can_only_be_extended_and_blocks_container_deletion() {
    let server = Emulator::start(None, &["--test-clock"]);
    server.create_container();
    let blob = "/testaccount/container/worm.txt";
    server.put_block_blob(blob, b"once");
    let first = http_date_in(3600);
    let set = policy(&server, blob, &first, Some("Locked"));
    assert_eq!(header_text(&set, "x-ms-immutability-policy-mode"), "locked");
    let blocked = |response: Response| error(response, 409, "BlobImmutableDueToPolicy");
    blocked(policy(&server, blob, &http_date_in(60), Some("Locked")));
    blocked(policy(&server, blob, &http_date_in(7200), Some("Unlocked")));
    blocked(server.request(
        Method::DELETE,
        &format!("{blob}?comp=immutabilityPolicies"),
        &[],
        b"",
    ));
    let longer = http_date_in(7200);
    assert_eq!(policy(&server, blob, &longer, Some("Locked")).status(), 200);
    assert_eq!(
        header_text(&server.head(blob), "x-ms-immutability-policy-until-date"),
        longer
    );
    blocked(server.request(
        Method::DELETE,
        "/testaccount/container?restype=container",
        &[],
        b"",
    ));
    server.advance(7300);
    assert_eq!(server.request(Method::DELETE, blob, &[], b"").status(), 202);
    assert_eq!(
        server
            .request(
                Method::DELETE,
                "/testaccount/container?restype=container",
                &[],
                b""
            )
            .status(),
        202
    );
}

#[test]
fn legal_holds_block_changes_until_cleared_and_persist_across_restart() {
    let root = tempfile::tempdir().unwrap();
    let location = root.path().join("store");
    let mut server = Emulator::start(Some(&location), &[]);
    server.create_container();
    let blob = "/testaccount/container/held.txt";
    server.put_block_blob(blob, b"evidence");
    let hold = |server: &Emulator, value: &str| {
        server.put(
            &format!("{blob}?comp=legalhold"),
            &[("x-ms-legal-hold", value)],
            b"",
        )
    };
    let set = hold(&server, "true");
    assert_eq!(set.status(), 200);
    assert_eq!(header_text(&set, "x-ms-legal-hold"), "true");
    assert_eq!(header_text(&server.head(blob), "x-ms-legal-hold"), "true");
    let held = |response: Response| error(response, 409, "BlobImmutableDueToLegalHold");
    held(server.request(Method::DELETE, blob, &[], b""));
    held(server.put_block_blob(blob, b"tamper"));
    held(server.request(
        Method::DELETE,
        "/testaccount/container?restype=container",
        &[],
        b"",
    ));
    server.restart(&location, &[]);
    assert_eq!(header_text(&server.head(blob), "x-ms-legal-hold"), "true");
    held(server.request(Method::DELETE, blob, &[], b""));
    error(hold(&server, "maybe"), 400, "InvalidHeaderValue");
    error(
        server.put(&format!("{blob}?comp=legalhold"), &[], b""),
        400,
        "MissingRequiredHeader",
    );
    let cleared = hold(&server, "false");
    assert_eq!(header_text(&cleared, "x-ms-legal-hold"), "false");
    assert!(!has_header(&server.head(blob), "x-ms-legal-hold"));
    assert_eq!(server.request(Method::DELETE, blob, &[], b"").status(), 202);
}

#[test]
fn a_versioned_account_overwrites_protected_blobs_into_a_new_version_but_never_deletes_them() {
    let server = Emulator::start(None, &["--versioning-accounts", ACCOUNT]);
    server.create_container();
    let blob = "/testaccount/container/a.txt";
    server.put_block_blob(blob, b"first");
    assert_eq!(
        policy(&server, blob, &http_date_in(3600), Some("Locked")).status(),
        200
    );
    assert_eq!(server.put_block_blob(blob, b"second").status(), 201);
    assert!(
        !has_header(&server.head(blob), "x-ms-immutability-policy-mode"),
        "the new current version starts unprotected"
    );
    let held = server.put(
        &format!("{blob}?comp=legalhold"),
        &[("x-ms-legal-hold", "true")],
        b"",
    );
    assert_eq!(held.status(), 200);
    assert_eq!(server.put_block_blob(blob, b"third").status(), 201);
    server.put(
        &format!("{blob}?comp=legalhold"),
        &[("x-ms-legal-hold", "true")],
        b"",
    );
    error(
        server.request(Method::DELETE, blob, &[], b""),
        409,
        "BlobImmutableDueToLegalHold",
    );
}

const CONTAINER_PATH: &str = "/testaccount/container?restype=container";

fn restore(server: &Emulator, into: &str, name: &str, version: &str) -> Response {
    server.put(
        &format!("/testaccount/{into}?restype=container&comp=undelete"),
        &[
            ("x-ms-deleted-container-name", name),
            ("x-ms-deleted-container-version", version),
        ],
        b"",
    )
}

fn containers(server: &Emulator, include: &str) -> String {
    let response = server.request(
        Method::GET,
        &format!("/testaccount/?comp=list&include={include}"),
        &[],
        b"",
    );
    assert_eq!(response.status(), 200);
    response.text().unwrap()
}

fn deleted_version(listing: &str) -> String {
    let after = listing
        .split_once("<Version>")
        .unwrap_or_else(|| panic!("no deleted container in {listing}"))
        .1;
    after.split_once("</Version>").unwrap().0.to_owned()
}

#[test]
fn soft_deleted_containers_are_listed_restored_under_any_name_and_expire() {
    let root = tempfile::tempdir().unwrap();
    let location = root.path().join("store");
    let mut server = Emulator::start(Some(&location), &["--test-clock"]);
    server.create_container();
    server.set_retention(1);
    assert_eq!(
        server
            .put(
                "/testaccount/container?restype=container&comp=metadata",
                &[("x-ms-meta-team", "blue")],
                b""
            )
            .status(),
        200
    );
    let blob = "/testaccount/container/a.txt";
    server.put_block_blob(blob, b"inside");
    server.put(
        &format!("{blob}?comp=tags"),
        &[],
        b"<Tags><TagSet><Tag><Key>k</Key><Value>v</Value></Tag></TagSet></Tags>",
    );
    server.create_page(PAGE, 1024, &[]);
    server.write_pages(PAGE, 0, &[b'p'; 512], &[]);
    server.snapshot(PAGE);
    assert_eq!(extents_on_disk(&location), 2);
    let find = "/testaccount/?comp=blobs&where=%22k%22%3D%27v%27";
    assert!(
        server
            .request(Method::GET, find, &[], b"")
            .text()
            .unwrap()
            .contains("a.txt")
    );

    assert_eq!(
        server
            .request(Method::DELETE, CONTAINER_PATH, &[], b"")
            .status(),
        202
    );
    error(
        server.request(Method::GET, CONTAINER_PATH, &[], b""),
        404,
        "ContainerNotFound",
    );
    error(server.read(blob, None), 404, "ContainerNotFound");
    assert!(!containers(&server, "metadata").contains("<Name>container</Name>"));
    assert!(
        !server
            .request(Method::GET, find, &[], b"")
            .text()
            .unwrap()
            .contains("a.txt"),
        "a hidden container's blobs are not found by tags"
    );
    assert_eq!(
        extents_on_disk(&location),
        2,
        "the data stays while retained"
    );
    let listing = containers(&server, "deleted");
    assert!(listing.contains("<Name>container</Name>"), "{listing}");
    assert!(listing.contains("<Deleted>true</Deleted>"));
    assert!(listing.contains("<RemainingRetentionDays>1</RemainingRetentionDays>"));
    assert!(listing.contains("<DeletedTime>"));
    let version = deleted_version(&listing);

    // The name is free again; the deleted container waits for a restore.
    server.create_container();
    assert!(
        !server.list("").contains("a.txt"),
        "the new container is empty"
    );
    error(
        restore(&server, "container", "container", &version),
        409,
        "ContainerAlreadyExists",
    );
    error(
        restore(&server, "restored", "container", "0000000000000000"),
        404,
        "ContainerNotFound",
    );
    error(
        server.put(
            "/testaccount/restored?restype=container&comp=undelete",
            &[],
            b"",
        ),
        400,
        "MissingRequiredHeader",
    );
    assert_eq!(
        restore(&server, "restored", "container", &version).status(),
        201
    );
    let restored = "/testaccount/restored/a.txt";
    assert_eq!(body(server.read(restored, None)), b"inside");
    let properties = server.request(
        Method::GET,
        "/testaccount/restored?restype=container",
        &[],
        b"",
    );
    assert_eq!(header_text(&properties, "x-ms-meta-team"), "blue");
    let paged = "/testaccount/restored/disk.vhd";
    assert_eq!(
        header_text(&server.head(paged), "x-ms-blob-type"),
        "PageBlob"
    );
    assert!(
        server
            .request(
                Method::GET,
                "/testaccount/restored?restype=container&comp=list&include=snapshots",
                &[],
                b""
            )
            .text()
            .unwrap()
            .contains("<Snapshot>")
    );
    assert!(
        server
            .request(Method::GET, find, &[], b"")
            .text()
            .unwrap()
            .contains("restored")
    );
    assert!(
        !containers(&server, "deleted").contains("<Deleted>"),
        "a restored container is no longer deleted"
    );
    error(
        restore(&server, "again", "container", &version),
        404,
        "ContainerNotFound",
    );

    // A deleted container survives a restart and expires on the clock.
    assert_eq!(
        server
            .request(
                Method::DELETE,
                "/testaccount/restored?restype=container",
                &[],
                b""
            )
            .status(),
        202
    );
    server.restart(&location, &["--test-clock"]);
    let after_restart = containers(&server, "deleted");
    assert!(
        after_restart.contains("<Name>restored</Name>"),
        "{after_restart}"
    );
    let version = deleted_version(&after_restart);
    server.advance(2 * 86_400);
    assert!(!containers(&server, "deleted").contains("<Deleted>"));
    error(
        restore(&server, "restored", "restored", &version),
        404,
        "ContainerNotFound",
    );
    assert_eq!(
        extents_on_disk(&location),
        0,
        "expired containers free their extents"
    );
}

#[test]
fn deleting_a_container_without_a_retention_policy_is_permanent() {
    let server = Emulator::start(None, &[]);
    server.create_container();
    assert_eq!(
        server
            .request(Method::DELETE, CONTAINER_PATH, &[], b"")
            .status(),
        202
    );
    assert!(!containers(&server, "deleted").contains("<Deleted>"));
    error(
        restore(&server, "container", "container", "0000000000000000"),
        404,
        "ContainerNotFound",
    );
    error(
        server.request(
            Method::GET,
            "/testaccount/?comp=list&include=bogus",
            &[],
            b"",
        ),
        501,
        "NotImplemented",
    );
}

fn tags_of(server: &Emulator, path: &str) -> String {
    server
        .request(Method::GET, &format!("{path}?comp=tags"), &[], b"")
        .text()
        .unwrap()
}

#[test]
fn copy_source_tag_option_copies_or_replaces_tags() {
    in_both_modes(|server| {
        server.create_container();
        let source = "/testaccount/container/source.txt";
        assert_eq!(
            server
                .put(
                    source,
                    &[
                        ("x-ms-blob-type", "BlockBlob"),
                        ("x-ms-tags", "env=prod&team=blue")
                    ],
                    b"data"
                )
                .status(),
            201
        );
        let from = server.source_url(source);
        let dest = "/testaccount/container/dest.txt";
        // Copy Blob: the default REPLACE sets only the tags the request carries.
        assert_eq!(
            server
                .put(dest, &[("x-ms-copy-source", &from)], b"")
                .status(),
            202
        );
        assert!(!tags_of(server, dest).contains("<Key>env</Key>"));
        assert_eq!(
            server
                .put(
                    dest,
                    &[("x-ms-copy-source", &from), ("x-ms-tags", "own=1")],
                    b""
                )
                .status(),
            202
        );
        let own = tags_of(server, dest);
        assert!(
            own.contains("<Key>own</Key>") && !own.contains("<Key>env</Key>"),
            "{own}"
        );
        assert_eq!(
            server
                .put(
                    dest,
                    &[
                        ("x-ms-copy-source", &from),
                        ("x-ms-copy-source-tag-option", "COPY")
                    ],
                    b""
                )
                .status(),
            202
        );
        let copied = tags_of(server, dest);
        assert!(
            copied.contains("<Key>env</Key>") && copied.contains("<Key>team</Key>"),
            "{copied}"
        );
        assert!(!copied.contains("<Key>own</Key>"));
        error(
            server.put(
                dest,
                &[
                    ("x-ms-copy-source", &from),
                    ("x-ms-copy-source-tag-option", "COPY"),
                    ("x-ms-tags", "a=b"),
                ],
                b"",
            ),
            409,
            "InvalidHeaderValue",
        );
        error(
            server.put(
                dest,
                &[
                    ("x-ms-copy-source", &from),
                    ("x-ms-copy-source-tag-option", "copy"),
                ],
                b"",
            ),
            400,
            "InvalidHeaderValue",
        );
        // Put Blob From URL.
        let from_url = "/testaccount/container/from-url.txt";
        assert_eq!(
            server
                .put(
                    from_url,
                    &[
                        ("x-ms-blob-type", "BlockBlob"),
                        ("x-ms-copy-source", &from),
                        ("x-ms-copy-source-tag-option", "COPY"),
                    ],
                    b""
                )
                .status(),
            201
        );
        assert!(tags_of(server, from_url).contains("<Key>env</Key>"));
        // A page blob copy carries its tags too.
        let page = "/testaccount/container/tagged.vhd";
        server.create_page(page, 512, &[("x-ms-tags", "disk=yes")]);
        let page_copy = "/testaccount/container/tagged-copy.vhd";
        assert_eq!(
            server
                .put(
                    page_copy,
                    &[
                        ("x-ms-copy-source", &server.source_url(page)),
                        ("x-ms-copy-source-tag-option", "COPY"),
                    ],
                    b""
                )
                .status(),
            202
        );
        assert!(tags_of(server, page_copy).contains("<Key>disk</Key>"));
        assert!(
            tags_of(server, page).contains("<Key>disk</Key>"),
            "Put Blob keeps x-ms-tags on page blobs"
        );
    });
}

/// A small HTTP server standing in for a source outside Azuifer. `/data` serves the
/// body (honoring one `Range`), and `/redirect`, `/missing`, and `/chunked` misbehave.
struct Source {
    port: u16,
    requests: Arc<Mutex<Vec<String>>>,
}

impl Source {
    fn start(body: Vec<u8>) -> Self {
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let port = listener.local_addr().unwrap().port();
        let requests = Arc::new(Mutex::new(Vec::new()));
        let log = requests.clone();
        thread::spawn(move || {
            for stream in listener.incoming() {
                let Ok(mut stream) = stream else { break };
                let mut head = Vec::new();
                let mut byte = [0u8; 1];
                while !head.ends_with(b"\r\n\r\n") {
                    if std::io::Read::read(&mut stream, &mut byte).unwrap_or(0) == 0 {
                        break;
                    }
                    head.push(byte[0]);
                }
                let head = String::from_utf8_lossy(&head).into_owned();
                log.lock().unwrap().push(head.clone());
                let target = head.split_whitespace().nth(1).unwrap_or("/").to_owned();
                let range = head.lines().find_map(|line| {
                    let (name, value) = line.split_once(':')?;
                    name.eq_ignore_ascii_case("range")
                        .then(|| value.trim().to_owned())
                });
                let (status, extra, payload): (&str, String, Vec<u8>) =
                    if target.starts_with("/redirect") {
                        (
                            "302 Found",
                            "location: http://169.254.169.254/\r\n".into(),
                            Vec::new(),
                        )
                    } else if target.starts_with("/missing") {
                        ("404 Not Found", String::new(), Vec::new())
                    } else if let Some(range) = range.and_then(|range| {
                        let (start, end) = range.strip_prefix("bytes=")?.split_once('-')?;
                        Some((start.parse::<usize>().ok()?, end.parse::<usize>().ok()?))
                    }) {
                        let end = (range.1 + 1).min(body.len());
                        (
                            "206 Partial Content",
                            String::new(),
                            body[range.0..end].to_vec(),
                        )
                    } else {
                        ("200 OK", String::new(), body.clone())
                    };
                let response = format!(
                    "HTTP/1.1 {status}\r\ncontent-type: application/x-test\r\ncontent-length: {}\r\n{extra}connection: close\r\n\r\n",
                    payload.len()
                );
                let _ = stream.write_all(response.as_bytes());
                let _ = stream.write_all(&payload);
            }
        });
        Self { port, requests }
    }

    fn url(&self, path: &str) -> String {
        format!("http://127.0.0.1:{}{path}", self.port)
    }

    fn requests(&self) -> Vec<String> {
        self.requests.lock().unwrap().clone()
    }
}

const EXTERNAL: &[&str] = &["--allow-external-copy-sources", "127.0.0.1"];

#[test]
fn external_copy_sources_are_off_unless_the_operator_allows_the_host() {
    let source = Source::start(b"remote bytes".to_vec());
    let from = source.url("/data");
    let off = Emulator::start(None, &[]);
    off.create_container();
    error(
        off.put(BLOCK, &[("x-ms-copy-source", &from)], b""),
        501,
        "NotImplemented",
    );
    let other_host = Emulator::start(
        None,
        &["--allow-external-copy-sources", "localhost,127.0.0.1:1"],
    );
    other_host.create_container();
    error(
        other_host.put(BLOCK, &[("x-ms-copy-source", &from)], b""),
        501,
        "NotImplemented",
    );
    assert!(
        source.requests().is_empty(),
        "no request reached a host that is not allowed"
    );
    let bad = Command::new(env!("CARGO_BIN_EXE_azuifer"))
        .args([
            "config",
            "validate",
            "--allow-external-copy-sources",
            "http://127.0.0.1",
        ])
        .env_remove("AZUIFER_ACCOUNT_KEY")
        .output()
        .unwrap();
    assert!(!bad.status.success(), "a URL is not a host");
}

#[test]
fn copy_blob_reads_an_allowed_external_source_synchronously() {
    let root = tempfile::tempdir().unwrap();
    let log = root.path().join("azuifer.log");
    let mut server = Emulator::start(
        None,
        &[
            "--allow-external-copy-sources",
            "127.0.0.1",
            "--log-file",
            log.to_str().unwrap(),
        ],
    );
    let source = Source::start(b"remote bytes".to_vec());
    server.create_container();
    let secret = "supersecretsignature";
    let from = format!("{}?sv=2023-11-03&sig={secret}", source.url("/data"));
    let copy = server.put(BLOCK, &[("x-ms-copy-source", &from)], b"");
    assert_eq!(copy.status(), 202);
    assert_eq!(header_text(&copy, "x-ms-copy-status"), "success");
    let copied = server.read(BLOCK, None);
    assert_eq!(header_text(&copied, "content-type"), "application/x-test");
    assert_eq!(
        header_text(&copied, "x-ms-copy-source"),
        source.url("/data"),
        "the SAS is not recorded"
    );
    assert_eq!(header_text(&copied, "x-ms-copy-status"), "success");
    assert_eq!(body(copied), b"remote bytes");
    let requests = source.requests();
    assert!(
        requests[0].starts_with(&format!("GET /data?sv=2023-11-03&sig={secret} HTTP/1.1")),
        "the SAS is passed through to the source: {}",
        requests[0]
    );
    // Put Blob From URL, with and without a range, and a ranged copy.
    let from_url = "/testaccount/container/from-url.txt";
    assert_eq!(
        server
            .put(
                from_url,
                &[
                    ("x-ms-blob-type", "BlockBlob"),
                    ("x-ms-copy-source", &source.url("/data"))
                ],
                b""
            )
            .status(),
        201
    );
    assert_eq!(body(server.read(from_url, None)), b"remote bytes");
    // Put Block From URL with a source range, then commit it.
    let id = STANDARD.encode("0001");
    let block = server.put(
        &format!("{BLOCK}?comp=block&blockid={}", encode(&id)),
        &[
            ("x-ms-copy-source", &source.url("/data")),
            ("x-ms-source-range", "bytes=7-11"),
        ],
        b"",
    );
    assert_eq!(block.status(), 201);
    assert!(
        source
            .requests()
            .last()
            .unwrap()
            .to_ascii_lowercase()
            .contains("range: bytes=7-11"),
        "the range is forwarded"
    );
    let list = format!("<BlockList><Latest>{id}</Latest></BlockList>");
    assert_eq!(
        server
            .put(&format!("{BLOCK}?comp=blocklist"), &[], list.as_bytes())
            .status(),
        201
    );
    assert_eq!(body(server.read(BLOCK, None)), b"bytes");
    // Append Block From URL and Put Page From URL.
    assert_eq!(server.create_append(APPEND, &[]).status(), 201);
    let appended = server.put(
        &format!("{APPEND}?comp=appendblock"),
        &[
            ("x-ms-copy-source", &source.url("/data")),
            ("x-ms-source-range", "bytes=0-5"),
        ],
        b"",
    );
    assert_eq!(appended.status(), 201);
    assert_eq!(body(server.read(APPEND, None)), b"remote");
    let pages = Source::start(vec![b'P'; 512]);
    server.create_page(PAGE, 1024, &[]);
    let page = server.put(
        &format!("{PAGE}?comp=page"),
        &[
            ("x-ms-copy-source", &pages.url("/data")),
            ("x-ms-source-range", "bytes=0-511"),
            ("x-ms-range", "bytes=512-1023"),
            ("x-ms-page-write", "update"),
        ],
        b"",
    );
    assert_eq!(page.status(), 201);
    assert_eq!(
        body(server.read(PAGE, None)),
        laid_out(1024, &[(512, b'P', 512)])
    );

    server.process.shutdown().unwrap();
    let logged = fs::read_to_string(&log).unwrap_or_default();
    assert!(!logged.is_empty(), "the server wrote a log");
    assert!(!logged.contains(secret), "a source SAS is never logged");
}

#[test]
fn external_copy_refuses_redirects_missing_sources_conditions_and_large_bodies() {
    let source = Source::start(vec![b'z'; 20]);
    let mut args = EXTERNAL.to_vec();
    args.extend(["--max-assembled-blob-bytes", "10"]);
    let server = Emulator::start(None, &args);
    server.create_container();
    let copy = |path: &str, extra: &[(&str, &str)]| {
        let from = source.url(path);
        let mut headers = vec![("x-ms-copy-source", from.as_str())];
        headers.extend_from_slice(extra);
        server.put(BLOCK, &headers, b"")
    };
    error(copy("/data", &[]), 413, "RequestBodyTooLarge");
    error(
        copy("/data", &[("x-ms-source-range", "bytes=0-4")]),
        501,
        "NotImplemented",
    );
    error(copy("/redirect", &[]), 403, "CannotVerifyCopySource");
    error(copy("/missing", &[]), 404, "CannotVerifyCopySource");
    error(
        copy("/data", &[("x-ms-source-if-match", "\"abc\"")]),
        501,
        "NotImplemented",
    );
    error(
        server.put(
            BLOCK,
            &[(
                "x-ms-copy-source",
                &format!("http://user:pass@127.0.0.1:{}/data", source.port),
            )],
            b"",
        ),
        400,
        "InvalidHeaderValue",
    );
    // The redirect target is never contacted.
    assert!(
        source
            .requests()
            .iter()
            .all(|request| !request.contains("169.254"))
    );
    error(server.read(BLOCK, None), 404, "BlobNotFound");
}

#[test]
fn every_new_writer_creates_missing_parents_on_hns_accounts_and_rejects_collisions() {
    let server = Emulator::start(
        None,
        &[
            "--hns-accounts",
            ACCOUNT,
            "--allow-external-copy-sources",
            "127.0.0.1",
        ],
    );
    server.create_container();
    server.create_page(PAGE, 1024, &[]);
    server.write_pages(PAGE, 0, &[b'a'; 512], &[]);
    let snapshot = server.snapshot(PAGE);
    let source = format!("{}?snapshot={snapshot}", server.source_url(PAGE));
    let entries = |server: &Emulator| server.list("");

    // Incremental Copy Blob into a nested path creates the directories with the blob.
    let nested = "/testaccount/container/backups/2026/disk.vhd";
    assert_eq!(
        server
            .put(
                &format!("{nested}?comp=incrementalcopy"),
                &[("x-ms-copy-source", &source)],
                b""
            )
            .status(),
        202
    );
    let listing = entries(&server);
    for name in ["backups", "backups/2026", "backups/2026/disk.vhd"] {
        assert!(
            listing.contains(&format!("<Name>{name}</Name>")),
            "{name} in {listing}"
        );
    }
    // Copy Blob of a page blob and a snapshot, and an external copy, create parents too.
    assert_eq!(
        server
            .put(
                "/testaccount/container/copies/one/disk.vhd",
                &[("x-ms-copy-source", &source)],
                b""
            )
            .status(),
        202
    );
    let remote = Source::start(b"remote".to_vec());
    assert_eq!(
        server
            .put(
                "/testaccount/container/remote/deep/blob.txt",
                &[("x-ms-copy-source", &remote.url("/data"))],
                b""
            )
            .status(),
        202
    );
    let listing = entries(&server);
    for name in ["copies/one", "remote/deep"] {
        assert!(
            listing.contains(&format!("<Name>{name}</Name>")),
            "{name} in {listing}"
        );
    }

    // A parent that is a file, or a name that is a directory, is a path conflict.
    let conflict = |response: Response| error(response, 409, "BlobOperationNotSupported");
    assert_eq!(
        server
            .put_block_blob("/testaccount/container/file", b"x")
            .status(),
        201
    );
    conflict(server.put(
        "/testaccount/container/file/under.vhd?comp=incrementalcopy",
        &[("x-ms-copy-source", &source)],
        b"",
    ));
    conflict(server.put(
        "/testaccount/container/file/under.vhd",
        &[("x-ms-copy-source", &source)],
        b"",
    ));
    conflict(server.put(
        "/testaccount/container/file/under.txt",
        &[("x-ms-copy-source", &remote.url("/data"))],
        b"",
    ));
    conflict(server.create_page("/testaccount/container/file/disk.vhd", 512, &[]));
    conflict(server.create_append("/testaccount/container/file/log.txt", &[]));
    conflict(server.put(
        "/testaccount/container/backups?comp=incrementalcopy",
        &[("x-ms-copy-source", &source)],
        b"",
    ));
    conflict(server.put(
        "/testaccount/container/copies",
        &[("x-ms-copy-source", &source)],
        b"",
    ));
    conflict(server.create_page("/testaccount/container/backups", 512, &[]));
    assert!(!entries(&server).contains("<Name>file/under"));

    // Restoring a soft-deleted page blob whose name became a directory conflicts.
    server.set_retention(1);
    let page = "/testaccount/container/gone/disk.vhd";
    server.create_page(page, 512, &[]);
    assert_eq!(server.request(Method::DELETE, page, &[], b"").status(), 202);
    assert_eq!(
        server
            .put_block_blob(&format!("{page}/child"), b"x")
            .status(),
        201
    );
    conflict(server.put(&format!("{page}?comp=undelete"), &[], b""));
    assert_eq!(
        server
            .request(Method::DELETE, &format!("{page}/child"), &[], b"")
            .status(),
        202
    );
}
