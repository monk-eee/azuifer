//! HTTP protocol tests for page blobs and append blobs against the built binary.

use base64::{Engine as _, engine::general_purpose::STANDARD};
use crc::{CRC_64_NVME, Crc};
use hmac::{Hmac, Mac as _};
use md5::{Digest as _, Md5};
use reqwest::{
    Method, Url,
    blocking::{Client, Response},
};
use sha2::Sha256;
use std::{
    collections::BTreeMap,
    fs,
    io::{BufRead as _, BufReader, Write as _},
    net::TcpStream,
    path::Path,
    process::{Child, Command, ExitStatus, Stdio},
    sync::mpsc,
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
const TIB: u64 = 1024 * 1024 * 1024 * 1024;

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

    fn start_partial_request(
        &self,
        path: &str,
        extra: &[(&str, &str)],
        length: usize,
        bytes: &[u8],
    ) -> TcpStream {
        let url = Url::parse(&format!("{}{path}", self.blob)).unwrap();
        let address = url.socket_addrs(|| None).unwrap()[0];
        let mut socket = TcpStream::connect(address).unwrap();
        let headers = signed(&Method::PUT, &url, extra, Some(length));
        let target = format!(
            "{}{}",
            url.path(),
            url.query()
                .map_or_else(String::new, |query| format!("?{query}"))
        );
        write!(
            socket,
            "PUT {target} HTTP/1.1\r\nHost: {address}\r\nConnection: close\r\n"
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

fn md5_text(bytes: &[u8]) -> String {
    STANDARD.encode(Md5::digest(bytes))
}

fn crc64_text(bytes: &[u8]) -> String {
    STANDARD.encode(Crc::<u64>::new(&CRC_64_NVME).checksum(bytes).to_le_bytes())
}

/// The `(start, end)` pairs of a Get Page Ranges response.
fn ranges(response: Response) -> Vec<(u64, u64)> {
    assert_eq!(response.status(), 200);
    let text = response.text().unwrap();
    let numbers = |tag: &str| -> Vec<u64> {
        text.split(&format!("<{tag}>"))
            .skip(1)
            .map(|part| part.split('<').next().unwrap().parse().unwrap())
            .collect()
    };
    numbers("Start").into_iter().zip(numbers("End")).collect()
}

fn extent_files(location: &Path) -> Vec<String> {
    let mut names: Vec<String> = fs::read_dir(location.join("content"))
        .unwrap()
        .map(|entry| entry.unwrap().file_name().to_string_lossy().into_owned())
        .collect();
    names.sort();
    names
}

fn wait_for_staged_uploads(location: &Path, count: usize) {
    let deadline = Instant::now() + Duration::from_secs(5);
    loop {
        let staged = extent_files(location)
            .iter()
            .filter(|name| name.starts_with("incoming-"))
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

/// Runs `check` against an in-memory server and against a disk-backed one.
fn in_both_modes(check: impl Fn(&Emulator)) {
    check(&Emulator::start(None, &[]));
    let root = tempfile::tempdir().unwrap();
    check(&Emulator::start(Some(root.path()), &[]));
}

#[test]
fn page_blob_reads_writes_and_clears_sparse_content() {
    in_both_modes(|server| {
        server.create_container();
        let created = server.create_page(
            PAGE,
            4096,
            &[
                ("x-ms-blob-sequence-number", "3"),
                ("x-ms-access-tier", "P10"),
                ("x-ms-blob-content-type", "application/x-vhd"),
                ("x-ms-meta-owner", "disk"),
            ],
        );
        assert_eq!(created.status(), 201);
        assert_eq!(
            header_text(&created, "x-ms-request-server-encrypted"),
            "false"
        );
        let created_tag = etag(&created);

        let head = server.head(PAGE);
        assert_eq!(head.status(), 200);
        assert_eq!(header_text(&head, "x-ms-blob-type"), "PageBlob");
        assert_eq!(header_text(&head, "content-length"), "4096");
        assert_eq!(header_text(&head, "x-ms-blob-sequence-number"), "3");
        assert_eq!(header_text(&head, "x-ms-access-tier"), "P10");
        assert_eq!(header_text(&head, "content-type"), "application/x-vhd");
        assert_eq!(header_text(&head, "x-ms-meta-owner"), "disk");
        assert!(!has_header(&head, "x-ms-access-tier-inferred"));
        assert_eq!(body(server.read(PAGE, None)), vec![0u8; 4096]);
        assert!(ranges(server.page_ranges(PAGE, "", &[])).is_empty());

        let first = server.write_pages(PAGE, 512, &[b'a'; 512], &[]);
        assert_eq!(first.status(), 201);
        assert_eq!(header_text(&first, "x-ms-blob-sequence-number"), "3");
        assert_eq!(
            header_text(&first, "x-ms-content-crc64"),
            crc64_text(&[b'a'; 512])
        );
        assert_ne!(etag(&first), created_tag);
        assert_eq!(
            server.write_pages(PAGE, 1024, &[b'b'; 1024], &[]).status(),
            201
        );
        assert_eq!(ranges(server.page_ranges(PAGE, "", &[])), [(512, 2047)]);

        let partial = server.read(PAGE, Some("bytes=0-1535"));
        assert_eq!(partial.status(), 206);
        assert_eq!(header_text(&partial, "content-range"), "bytes 0-1535/4096");
        let mut expected = vec![0u8; 512];
        expected.extend([b'a'; 512]);
        expected.extend([b'b'; 512]);
        assert_eq!(body(partial), expected);

        assert_eq!(
            server.write_pages(PAGE, 1024, &[b'c'; 512], &[]).status(),
            201
        );
        assert_eq!(server.clear_pages(PAGE, 512, 512, &[]).status(), 201);
        assert_eq!(ranges(server.page_ranges(PAGE, "", &[])), [(1024, 2047)]);
        let whole = body(server.read(PAGE, None));
        assert_eq!(&whole[..1024], vec![0u8; 1024].as_slice());
        assert_eq!(&whole[1024..1536], [b'c'; 512].as_slice());
        assert_eq!(&whole[1536..2048], [b'b'; 512].as_slice());
        assert_eq!(&whole[2048..], vec![0u8; 2048].as_slice());
        assert_eq!(
            ranges(server.page_ranges(PAGE, "", &[("x-ms-range", "bytes=1536-4095")])),
            [(1536, 2047)]
        );
        let sparse = server.page_ranges(PAGE, "", &[]);
        assert_eq!(header_text(&sparse, "x-ms-blob-content-length"), "4096");
        assert!(has_header(&sparse, "etag"));
        assert!(has_header(&sparse, "last-modified"));
    });
}

#[test]
fn put_page_validates_ranges_bodies_and_checksums() {
    let server = Emulator::start(None, &[]);
    server.create_container();
    assert_eq!(server.create_page(PAGE, 8 * 1024 * 1024, &[]).status(), 201);
    for (range, status, code) in [
        ("bytes=1-512", 416, "InvalidPageRange"),
        ("bytes=0-1022", 416, "InvalidPageRange"),
        ("bytes=8388608-8389119", 416, "InvalidPageRange"),
        ("bytes=0-1023", 400, "InvalidHeaderValue"),
        ("bytes=0-", 400, "InvalidHeaderValue"),
        ("pages=0-511", 400, "InvalidHeaderValue"),
    ] {
        let response = server.request(
            Method::PUT,
            &format!("{PAGE}?comp=page"),
            &[("x-ms-page-write", "update"), ("x-ms-range", range)],
            &[1u8; 512],
        );
        error(response, status, code);
    }
    error(
        server.request(
            Method::PUT,
            &format!("{PAGE}?comp=page"),
            &[("x-ms-page-write", "update")],
            &[1u8; 512],
        ),
        400,
        "MissingRequiredHeader",
    );
    error(
        server.request(
            Method::PUT,
            &format!("{PAGE}?comp=page"),
            &[("x-ms-range", "bytes=0-511")],
            &[1u8; 512],
        ),
        400,
        "MissingRequiredHeader",
    );
    error(
        server.request(
            Method::PUT,
            &format!("{PAGE}?comp=page"),
            &[("x-ms-page-write", "append"), ("x-ms-range", "bytes=0-511")],
            &[1u8; 512],
        ),
        400,
        "InvalidHeaderValue",
    );
    error(
        server.request(
            Method::PUT,
            &format!("{PAGE}?comp=page"),
            &[("x-ms-page-write", "clear"), ("x-ms-range", "bytes=0-511")],
            &[1u8; 512],
        ),
        400,
        "InvalidHeaderValue",
    );
    let four_mib = 4 * 1024 * 1024;
    assert_eq!(
        server
            .write_pages(PAGE, 0, &vec![7u8; four_mib], &[])
            .status(),
        201
    );
    error(
        server.write_pages(PAGE, 0, &vec![7u8; four_mib + 512], &[]),
        413,
        "RequestBodyTooLarge",
    );
    assert_eq!(
        server.clear_pages(PAGE, 0, 8 * 1024 * 1024, &[]).status(),
        201,
        "a clear is not limited to 4 MiB"
    );
    assert!(ranges(server.page_ranges(PAGE, "", &[])).is_empty());

    let page = [9u8; 512];
    let good = server.write_pages(PAGE, 0, &page, &[("content-md5", &md5_text(&page))]);
    assert_eq!(good.status(), 201);
    assert_eq!(header_text(&good, "content-md5"), md5_text(&page));
    let crc = server.write_pages(
        PAGE,
        512,
        &page,
        &[("x-ms-content-crc64", &crc64_text(&page))],
    );
    assert_eq!(crc.status(), 201);
    assert_eq!(header_text(&crc, "x-ms-content-crc64"), crc64_text(&page));
    error(
        server.write_pages(PAGE, 1024, &page, &[("content-md5", &md5_text(b"other"))]),
        400,
        "Md5Mismatch",
    );
    error(
        server.write_pages(
            PAGE,
            1024,
            &page,
            &[("x-ms-content-crc64", &crc64_text(b"other"))],
        ),
        400,
        "Crc64Mismatch",
    );
    assert_eq!(ranges(server.page_ranges(PAGE, "", &[])), [(0, 1023)]);
    error(
        server.write_pages("/testaccount/container/missing", 0, &page, &[]),
        404,
        "BlobNotFound",
    );

    for (size, status, code) in [
        (513, 400, "InvalidHeaderValue"),
        (8 * TIB + 512, 400, "InvalidHeaderValue"),
    ] {
        error(server.create_page(PAGE, size, &[]), status, code);
    }
    error(
        server.request(Method::PUT, PAGE, &[("x-ms-blob-type", "PageBlob")], b""),
        400,
        "MissingRequiredHeader",
    );
    error(
        server.request(
            Method::PUT,
            PAGE,
            &[
                ("x-ms-blob-type", "PageBlob"),
                ("x-ms-blob-content-length", "512"),
            ],
            b"body",
        ),
        400,
        "InvalidHeaderValue",
    );
    assert_eq!(
        ranges(server.page_ranges(PAGE, "", &[])),
        [(0, 1023)],
        "rejected requests leave the blob alone"
    );
}

#[test]
fn sequence_numbers_gate_page_writes_and_change_through_set_properties() {
    let server = Emulator::start(None, &[]);
    server.create_container();
    assert_eq!(
        server
            .create_page(PAGE, 1024, &[("x-ms-blob-sequence-number", "5")])
            .status(),
        201
    );
    let page = [1u8; 512];
    for (condition, value, allowed) in [
        ("x-ms-if-sequence-number-lt", "5", false),
        ("x-ms-if-sequence-number-lt", "6", true),
        ("x-ms-if-sequence-number-le", "4", false),
        ("x-ms-if-sequence-number-le", "5", true),
        ("x-ms-if-sequence-number-eq", "4", false),
        ("x-ms-if-sequence-number-eq", "5", true),
    ] {
        let response = server.write_pages(PAGE, 0, &page, &[(condition, value)]);
        if allowed {
            assert_eq!(response.status(), 201, "{condition}={value}");
        } else {
            error(response, 412, "SequenceNumberConditionNotMet");
        }
    }
    error(
        server.clear_pages(PAGE, 0, 512, &[("x-ms-if-sequence-number-eq", "9")]),
        412,
        "SequenceNumberConditionNotMet",
    );
    assert_eq!(ranges(server.page_ranges(PAGE, "", &[])), [(0, 511)]);

    let action = |action: &str, number: Option<&str>| {
        let mut headers = vec![("x-ms-sequence-number-action", action)];
        if let Some(number) = number {
            headers.push(("x-ms-blob-sequence-number", number));
        }
        server.set_properties(PAGE, &headers)
    };
    let response = action("max", Some("3"));
    assert_eq!(response.status(), 200);
    assert_eq!(header_text(&response, "x-ms-blob-sequence-number"), "5");
    assert_eq!(
        header_text(&action("max", Some("9")), "x-ms-blob-sequence-number"),
        "9"
    );
    assert_eq!(
        header_text(&action("update", Some("2")), "x-ms-blob-sequence-number"),
        "2"
    );
    assert_eq!(
        header_text(&action("increment", None), "x-ms-blob-sequence-number"),
        "3"
    );
    assert_eq!(
        header_text(&server.head(PAGE), "x-ms-blob-sequence-number"),
        "3"
    );
    error(action("update", None), 400, "MissingRequiredHeader");
    error(action("increment", Some("1")), 400, "InvalidHeaderValue");
    error(action("max", Some("-1")), 400, "InvalidHeaderValue");
    error(
        action("max", Some("9223372036854775808")),
        400,
        "InvalidHeaderValue",
    );
    error(action("reset", Some("1")), 400, "InvalidHeaderValue");
    error(
        server.set_properties(PAGE, &[("x-ms-blob-sequence-number", "1")]),
        400,
        "MissingRequiredHeader",
    );
    assert_eq!(
        header_text(
            &action("update", Some("9223372036854775807")),
            "x-ms-blob-sequence-number"
        ),
        "9223372036854775807"
    );
    error(
        action("increment", None),
        409,
        "SequenceNumberIncrementTooLarge",
    );
}

#[test]
fn resizing_a_page_blob_trims_and_zero_extends() {
    in_both_modes(|server| {
        server.create_container();
        assert_eq!(server.create_page(PAGE, 2048, &[]).status(), 201);
        assert_eq!(
            server.write_pages(PAGE, 512, &[b'x'; 1024], &[]).status(),
            201
        );
        let resize =
            |size: &str| server.set_properties(PAGE, &[("x-ms-blob-content-length", size)]);
        let shrunk = resize("1024");
        assert_eq!(shrunk.status(), 200);
        assert_eq!(header_text(&shrunk, "x-ms-blob-sequence-number"), "0");
        assert_eq!(header_text(&server.head(PAGE), "content-length"), "1024");
        assert_eq!(ranges(server.page_ranges(PAGE, "", &[])), [(512, 1023)]);
        assert_eq!(resize("4096").status(), 200);
        assert_eq!(ranges(server.page_ranges(PAGE, "", &[])), [(512, 1023)]);
        let whole = body(server.read(PAGE, None));
        assert_eq!(whole.len(), 4096);
        assert_eq!(&whole[512..1024], [b'x'; 512].as_slice());
        assert!(whole[1024..].iter().all(|byte| *byte == 0));
        assert_eq!(resize("0").status(), 200);
        assert!(ranges(server.page_ranges(PAGE, "", &[])).is_empty());
        assert!(body(server.read(PAGE, None)).is_empty());
        assert_eq!(resize("2048").status(), 200);
        assert_eq!(body(server.read(PAGE, None)), vec![0u8; 2048]);
        error(resize("1000"), 400, "InvalidHeaderValue");
        error(resize("-512"), 400, "InvalidHeaderValue");

        let combined = server.set_properties(
            PAGE,
            &[
                ("x-ms-blob-content-length", "1024"),
                ("x-ms-blob-content-type", "text/plain"),
                ("x-ms-sequence-number-action", "increment"),
            ],
        );
        assert_eq!(header_text(&combined, "x-ms-blob-sequence-number"), "1");
        let head = server.head(PAGE);
        assert_eq!(header_text(&head, "content-type"), "text/plain");
        assert_eq!(header_text(&head, "content-length"), "1024");
    });
}

#[test]
fn page_ranges_support_windows_paging_and_reject_unknown_snapshots() {
    let server = Emulator::start(None, &[]);
    server.create_container();
    assert_eq!(server.create_page(PAGE, 8192, &[]).status(), 201);
    for start in [0u64, 1024, 2048, 4096] {
        assert_eq!(
            server.write_pages(PAGE, start, &[1u8; 512], &[]).status(),
            201
        );
    }
    let all = [(0, 511), (1024, 1535), (2048, 2559), (4096, 4607)];
    assert_eq!(ranges(server.page_ranges(PAGE, "", &[])), all);
    assert_eq!(
        ranges(server.page_ranges(PAGE, "", &[("x-ms-range", "bytes=1000-2100")])),
        [(1024, 1535), (2048, 2100)]
    );
    assert_eq!(
        ranges(server.page_ranges(PAGE, "", &[("range", "bytes=4096-")])),
        [(4096, 4607)]
    );
    let first = server.page_ranges(PAGE, "&maxresults=2", &[]);
    let text = first.text().unwrap();
    assert!(text.contains("<NextMarker>2048</NextMarker>"), "{text}");
    assert_eq!(
        ranges(server.page_ranges(PAGE, "&maxresults=2&marker=2048", &[])),
        [(2048, 2559), (4096, 4607)]
    );
    error(
        server.page_ranges(PAGE, "", &[("x-ms-range", "bytes=8192-")]),
        416,
        "InvalidRange",
    );
    error(
        server.page_ranges(PAGE, "&maxresults=0", &[]),
        400,
        "InvalidQueryParameterValue",
    );
    error(
        server.page_ranges(PAGE, "&prevsnapshot=2024-01-01T00:00:00.0000000Z", &[]),
        409,
        "PreviousSnapshotNotFound",
    );
    error(
        server.page_ranges(PAGE, "&snapshot=2024-01-01T00:00:00.0000000Z", &[]),
        404,
        "BlobNotFound",
    );
    error(
        server.page_ranges(PAGE, "", &[("if-match", "\"nope\"")]),
        412,
        "ConditionNotMet",
    );
    let current = etag(&server.head(PAGE));
    assert_eq!(
        server
            .page_ranges(PAGE, "", &[("if-match", &current)])
            .status(),
        200
    );
}

#[test]
fn a_page_blob_can_be_eight_tebibytes_without_allocating_it() {
    let server = Emulator::start(None, &[]);
    server.create_container();
    assert_eq!(server.create_page(PAGE, 8 * TIB, &[]).status(), 201);
    assert_eq!(
        header_text(&server.head(PAGE), "content-length"),
        (8 * TIB).to_string()
    );
    let last = 8 * TIB - 512;
    assert_eq!(
        server.write_pages(PAGE, last, &[5u8; 512], &[]).status(),
        201
    );
    assert_eq!(
        ranges(server.page_ranges(PAGE, "", &[])),
        [(last, 8 * TIB - 1)]
    );
    let tail = server.read(PAGE, Some(&format!("bytes={}-{}", last - 512, last + 511)));
    assert_eq!(tail.status(), 206);
    let mut expected = vec![0u8; 512];
    expected.extend([5u8; 512]);
    assert_eq!(body(tail), expected);
    let middle = server.read(PAGE, Some(&format!("bytes={}-{}", 4 * TIB, 4 * TIB + 99)));
    assert_eq!(body(middle), vec![0u8; 100]);
    assert_eq!(
        server
            .set_properties(PAGE, &[("x-ms-blob-content-length", "512")])
            .status(),
        200
    );
    assert!(ranges(server.page_ranges(PAGE, "", &[])).is_empty());
}

#[test]
fn page_blob_writes_honor_leases_and_conditions() {
    let server = Emulator::start(None, &[]);
    server.create_container();
    assert_eq!(server.create_page(PAGE, 1024, &[]).status(), 201);
    let lease_id = "aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa";
    let leased = server.request(
        Method::PUT,
        &format!("{PAGE}?comp=lease"),
        &[
            ("x-ms-lease-action", "acquire"),
            ("x-ms-lease-duration", "-1"),
            ("x-ms-proposed-lease-id", lease_id),
        ],
        b"",
    );
    assert_eq!(leased.status(), 201);
    let page = [1u8; 512];
    error(
        server.write_pages(PAGE, 0, &page, &[]),
        412,
        "LeaseIdMissing",
    );
    error(server.clear_pages(PAGE, 0, 512, &[]), 412, "LeaseIdMissing");
    error(
        server.set_properties(PAGE, &[("x-ms-blob-content-length", "512")]),
        412,
        "LeaseIdMissing",
    );
    assert_eq!(
        server
            .write_pages(PAGE, 0, &page, &[("x-ms-lease-id", lease_id)])
            .status(),
        201
    );
    assert_eq!(
        server
            .set_properties(
                PAGE,
                &[
                    ("x-ms-blob-content-length", "512"),
                    ("x-ms-lease-id", lease_id)
                ]
            )
            .status(),
        200
    );
    assert_eq!(server.read(PAGE, None).status(), 200, "reads need no lease");
    assert_eq!(server.page_ranges(PAGE, "", &[]).status(), 200);
    error(
        server.write_pages(
            PAGE,
            0,
            &page,
            &[("x-ms-lease-id", lease_id), ("if-match", "\"stale\"")],
        ),
        412,
        "ConditionNotMet",
    );
}

#[test]
fn page_and_append_blobs_reject_block_blob_operations_and_vice_versa() {
    let server = Emulator::start(None, &[]);
    server.create_container();
    assert_eq!(server.create_page(PAGE, 1024, &[]).status(), 201);
    assert_eq!(server.create_append(APPEND, &[]).status(), 201);
    assert_eq!(server.put_block_blob(BLOCK, b"block").status(), 201);
    for path in [PAGE, APPEND] {
        error(
            server.request(
                Method::PUT,
                &format!("{path}?comp=block&blockid=QUFB"),
                &[],
                b"data",
            ),
            409,
            "InvalidBlobType",
        );
        error(
            server.request(
                Method::PUT,
                &format!("{path}?comp=blocklist"),
                &[],
                b"<BlockList></BlockList>",
            ),
            409,
            "InvalidBlobType",
        );
        error(
            server.request(Method::GET, &format!("{path}?comp=blocklist"), &[], b""),
            409,
            "InvalidBlobType",
        );
    }
    error(server.append(PAGE, b"x", &[]), 409, "InvalidBlobType");
    error(
        server.request(Method::PUT, &format!("{PAGE}?comp=seal"), &[], b""),
        409,
        "InvalidBlobType",
    );
    error(
        server.write_pages(APPEND, 0, &[0u8; 512], &[]),
        409,
        "InvalidBlobType",
    );
    error(
        server.clear_pages(APPEND, 0, 512, &[]),
        409,
        "InvalidBlobType",
    );
    error(server.page_ranges(APPEND, "", &[]), 409, "InvalidBlobType");
    error(
        server.set_properties(APPEND, &[("x-ms-blob-content-length", "512")]),
        409,
        "InvalidBlobType",
    );
    error(
        server.set_properties(BLOCK, &[("x-ms-sequence-number-action", "increment")]),
        409,
        "InvalidBlobType",
    );
    error(
        server.write_pages(BLOCK, 0, &[0u8; 512], &[]),
        409,
        "InvalidBlobType",
    );
    error(server.page_ranges(BLOCK, "", &[]), 409, "InvalidBlobType");
    error(server.append(BLOCK, b"x", &[]), 409, "InvalidBlobType");
    assert_eq!(body(server.read(BLOCK, None)), b"block");
}

#[test]
fn put_blob_replaces_a_blob_of_another_type() {
    let root = tempfile::tempdir().unwrap();
    let server = Emulator::start(Some(root.path()), &[]);
    server.create_container();
    assert_eq!(server.create_page(PAGE, 1024, &[]).status(), 201);
    assert_eq!(server.write_pages(PAGE, 0, &[3u8; 512], &[]).status(), 201);
    assert_eq!(extent_files(root.path()).len(), 1);
    let replaced = server.put_block_blob(PAGE, b"now a block blob");
    assert_eq!(replaced.status(), 201);
    let head = server.head(PAGE);
    assert_eq!(header_text(&head, "x-ms-blob-type"), "BlockBlob");
    assert!(!has_header(&head, "x-ms-blob-sequence-number"));
    assert_eq!(body(server.read(PAGE, None)), b"now a block blob");
    assert_eq!(
        extent_files(root.path()).len(),
        1,
        "the page extent is gone"
    );
    error(server.page_ranges(PAGE, "", &[]), 409, "InvalidBlobType");

    assert_eq!(server.create_append(PAGE, &[]).status(), 201);
    assert_eq!(server.append(PAGE, b"line", &[]).status(), 201);
    assert_eq!(
        header_text(&server.head(PAGE), "x-ms-blob-type"),
        "AppendBlob"
    );
    assert_eq!(server.create_page(PAGE, 512, &[]).status(), 201);
    assert_eq!(
        header_text(&server.head(PAGE), "x-ms-blob-type"),
        "PageBlob"
    );
    assert!(extent_files(root.path()).is_empty());
    error(
        server.request(
            Method::PUT,
            PAGE,
            &[("x-ms-blob-type", "AppendBlob"), ("if-none-match", "*")],
            b"",
        ),
        409,
        "BlobAlreadyExists",
    );
}

#[test]
fn append_blob_appends_report_offsets_and_concatenate() {
    in_both_modes(|server| {
        server.create_container();
        let created = server.create_append(APPEND, &[("x-ms-blob-content-type", "text/plain")]);
        assert_eq!(created.status(), 201);
        let head = server.head(APPEND);
        assert_eq!(header_text(&head, "x-ms-blob-type"), "AppendBlob");
        assert_eq!(header_text(&head, "content-length"), "0");
        assert_eq!(header_text(&head, "x-ms-blob-committed-block-count"), "0");
        assert!(!has_header(&head, "x-ms-blob-sealed"));
        assert!(!has_header(&head, "x-ms-access-tier"));

        let first = server.append(APPEND, b"hello ", &[("content-md5", &md5_text(b"hello "))]);
        assert_eq!(first.status(), 201);
        assert_eq!(header_text(&first, "x-ms-blob-append-offset"), "0");
        assert_eq!(header_text(&first, "x-ms-blob-committed-block-count"), "1");
        assert_eq!(header_text(&first, "content-md5"), md5_text(b"hello "));
        let second = server.append(APPEND, b"world", &[]);
        assert_eq!(header_text(&second, "x-ms-blob-append-offset"), "6");
        assert_eq!(header_text(&second, "x-ms-blob-committed-block-count"), "2");
        assert_eq!(
            header_text(&second, "x-ms-content-crc64"),
            crc64_text(b"world")
        );
        assert_ne!(etag(&first), etag(&second));

        let all = server.read(APPEND, None);
        assert_eq!(header_text(&all, "x-ms-blob-type"), "AppendBlob");
        assert_eq!(header_text(&all, "x-ms-blob-committed-block-count"), "2");
        assert_eq!(header_text(&all, "content-type"), "text/plain");
        assert_eq!(etag(&all), etag(&second));
        assert_eq!(body(all), b"hello world");
        let partial = server.read(APPEND, Some("bytes=3-8"));
        assert_eq!(partial.status(), 206);
        assert_eq!(header_text(&partial, "content-range"), "bytes 3-8/11");
        assert_eq!(body(partial), b"lo wor");
        assert_eq!(header_text(&server.head(APPEND), "content-length"), "11");
    });
}

#[test]
fn append_conditions_checksums_and_limits_are_enforced() {
    let server = Emulator::start(None, &[]);
    server.create_container();
    assert_eq!(server.create_append(APPEND, &[]).status(), 201);
    assert_eq!(server.append(APPEND, b"12345", &[]).status(), 201);
    error(
        server.append(APPEND, b"x", &[("x-ms-blob-condition-appendpos", "4")]),
        412,
        "AppendPositionConditionNotMet",
    );
    error(
        server.append(APPEND, b"abcd", &[("x-ms-blob-condition-maxsize", "8")]),
        412,
        "MaxBlobSizeConditionNotMet",
    );
    let exact = server.append(
        APPEND,
        b"abc",
        &[
            ("x-ms-blob-condition-appendpos", "5"),
            ("x-ms-blob-condition-maxsize", "8"),
        ],
    );
    assert_eq!(exact.status(), 201);
    error(
        server.append(APPEND, b"x", &[("x-ms-blob-condition-maxsize", "8")]),
        412,
        "MaxBlobSizeConditionNotMet",
    );
    error(
        server.append(APPEND, b"x", &[("x-ms-blob-condition-appendpos", "nine")]),
        400,
        "InvalidHeaderValue",
    );
    error(
        server.append(APPEND, b"zz", &[("content-md5", &md5_text(b"other"))]),
        400,
        "Md5Mismatch",
    );
    error(server.append(APPEND, b"", &[]), 400, "InvalidHeaderValue");
    let four_mib = 4 * 1024 * 1024;
    // Version 2022-11-02 raised the Append Block limit to 100 MiB.
    error(
        server.append(APPEND, &vec![1u8; 100 * 1024 * 1024 + 1], &[]),
        413,
        "RequestBodyTooLarge",
    );
    assert_eq!(body(server.read(APPEND, None)), b"12345abc");
    let big = server.append(APPEND, &vec![1u8; four_mib], &[]);
    assert_eq!(big.status(), 201);
    assert_eq!(header_text(&big, "x-ms-blob-append-offset"), "8");
    assert_eq!(
        header_text(&server.head(APPEND), "content-length"),
        (four_mib + 8).to_string()
    );
    error(
        server.append("/testaccount/container/missing", b"x", &[]),
        404,
        "BlobNotFound",
    );
    let lease_id = "aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa";
    assert_eq!(
        server
            .request(
                Method::PUT,
                &format!("{APPEND}?comp=lease"),
                &[
                    ("x-ms-lease-action", "acquire"),
                    ("x-ms-lease-duration", "-1"),
                    ("x-ms-proposed-lease-id", lease_id),
                ],
                b"",
            )
            .status(),
        201
    );
    error(server.append(APPEND, b"x", &[]), 412, "LeaseIdMissing");
    assert_eq!(
        server
            .append(APPEND, b"x", &[("x-ms-lease-id", lease_id)])
            .status(),
        201
    );
}

#[test]
fn sealing_an_append_blob_makes_it_read_only() {
    in_both_modes(|server| {
        server.create_container();
        assert_eq!(server.create_append(APPEND, &[]).status(), 201);
        assert_eq!(server.append(APPEND, b"data", &[]).status(), 201);
        let seal = |extra: &[(&str, &str)]| {
            server.request(Method::PUT, &format!("{APPEND}?comp=seal"), extra, b"")
        };
        error(
            seal(&[("x-ms-blob-condition-appendpos", "1")]),
            412,
            "AppendPositionConditionNotMet",
        );
        let sealed = seal(&[("x-ms-blob-condition-appendpos", "4")]);
        assert_eq!(sealed.status(), 200);
        assert_eq!(header_text(&sealed, "x-ms-blob-sealed"), "true");
        let head = server.head(APPEND);
        assert_eq!(header_text(&head, "x-ms-blob-sealed"), "true");
        assert_eq!(header_text(&head, "x-ms-blob-committed-block-count"), "1");
        assert_eq!(
            header_text(&server.read(APPEND, None), "x-ms-blob-sealed"),
            "true"
        );
        error(server.append(APPEND, b"more", &[]), 409, "BlobIsSealed");
        assert_eq!(seal(&[]).status(), 200, "sealing twice is harmless");
        assert_eq!(etag(&seal(&[])), etag(&head));
        assert_eq!(body(server.read(APPEND, None)), b"data");
        let metadata = server.request(
            Method::PUT,
            &format!("{APPEND}?comp=metadata"),
            &[("x-ms-meta-state", "sealed")],
            b"",
        );
        assert_eq!(metadata.status(), 200);
        assert_eq!(server.create_append(APPEND, &[]).status(), 201);
        assert_eq!(server.append(APPEND, b"fresh", &[]).status(), 201);
        assert!(!has_header(&server.head(APPEND), "x-ms-blob-sealed"));
        assert_eq!(
            server.request(Method::DELETE, APPEND, &[], b"").status(),
            202
        );
    });
}

#[test]
fn listings_report_blob_types_lengths_and_sequence_numbers() {
    let server = Emulator::start(None, &[]);
    server.create_container();
    assert_eq!(
        server
            .create_page(
                PAGE,
                2048,
                &[
                    ("x-ms-blob-sequence-number", "7"),
                    ("x-ms-access-tier", "P20")
                ]
            )
            .status(),
        201
    );
    assert_eq!(server.create_append(APPEND, &[]).status(), 201);
    assert_eq!(server.append(APPEND, b"abc", &[]).status(), 201);
    assert_eq!(server.put_block_blob(BLOCK, b"four").status(), 201);
    let list = server
        .request(
            Method::GET,
            "/testaccount/container?restype=container&comp=list",
            &[],
            b"",
        )
        .text()
        .unwrap();
    let entry = |name: &str| {
        let start = list.find(&format!("<Name>{name}</Name>")).unwrap();
        let end = list[start..].find("</Blob>").unwrap();
        list[start..start + end].to_owned()
    };
    let page = entry("disk.vhd");
    assert!(
        page.contains("<Content-Length>2048</Content-Length>"),
        "{page}"
    );
    assert!(page.contains("<BlobType>PageBlob</BlobType>"));
    assert!(page.contains("<x-ms-blob-sequence-number>7</x-ms-blob-sequence-number>"));
    assert!(page.contains("<AccessTier>P20</AccessTier>"));
    assert!(!page.contains("AccessTierInferred"));
    let append = entry("log.txt");
    assert!(
        append.contains("<Content-Length>3</Content-Length>"),
        "{append}"
    );
    assert!(append.contains("<BlobType>AppendBlob</BlobType>"));
    assert!(!append.contains("<Sealed>"));
    let block = entry("plain.txt");
    assert!(block.contains("<BlobType>BlockBlob</BlobType>"));
    assert!(block.contains("<AccessTier>Hot</AccessTier>"));
    assert_eq!(
        server
            .request(Method::PUT, &format!("{APPEND}?comp=seal"), &[], b"")
            .status(),
        200
    );
    let sealed = server
        .request(
            Method::GET,
            "/testaccount/container?restype=container&comp=list&prefix=log",
            &[],
            b"",
        )
        .text()
        .unwrap();
    assert!(sealed.contains("<Sealed>true</Sealed>"), "{sealed}");
}

#[test]
fn premium_tiers_belong_to_page_blobs() {
    let server = Emulator::start(None, &[]);
    server.create_container();
    assert_eq!(server.create_page(PAGE, 512, &[]).status(), 201);
    assert!(!has_header(&server.head(PAGE), "x-ms-access-tier"));
    let tier = |path: &str, tier: &str| {
        server.request(
            Method::PUT,
            &format!("{path}?comp=tier"),
            &[("x-ms-access-tier", tier)],
            b"",
        )
    };
    assert_eq!(tier(PAGE, "P30").status(), 200);
    assert_eq!(header_text(&server.head(PAGE), "x-ms-access-tier"), "P30");
    assert!(has_header(
        &server.head(PAGE),
        "x-ms-access-tier-change-time"
    ));
    error(tier(PAGE, "Hot"), 400, "InvalidHeaderValue");
    error(tier(PAGE, "P99"), 400, "InvalidHeaderValue");
    assert_eq!(server.put_block_blob(BLOCK, b"x").status(), 201);
    error(tier(BLOCK, "P10"), 400, "InvalidHeaderValue");
    assert_eq!(tier(BLOCK, "Cool").status(), 200);
    error(
        server.request(
            Method::PUT,
            "/testaccount/container/tiered",
            &[("x-ms-blob-type", "BlockBlob"), ("x-ms-access-tier", "P10")],
            b"x",
        ),
        400,
        "InvalidHeaderValue",
    );
    error(
        server.create_page(
            "/testaccount/container/hot-page",
            512,
            &[("x-ms-access-tier", "Hot")],
        ),
        400,
        "InvalidHeaderValue",
    );
    assert_eq!(server.create_append(APPEND, &[]).status(), 201);
    error(tier(APPEND, "Hot"), 400, "InvalidHeaderValue");
}

#[test]
fn copy_blob_preserves_type_and_shares_content_without_coupling() {
    let root = tempfile::tempdir().unwrap();
    let server = Emulator::start(Some(root.path()), &[]);
    server.create_container();
    assert_eq!(
        server
            .create_page(
                PAGE,
                4096,
                &[
                    ("x-ms-blob-sequence-number", "4"),
                    ("x-ms-meta-kind", "src")
                ]
            )
            .status(),
        201
    );
    assert_eq!(
        server.write_pages(PAGE, 512, &[b'p'; 1024], &[]).status(),
        201
    );
    assert_eq!(
        server.write_pages(PAGE, 3072, &[b'q'; 512], &[]).status(),
        201
    );
    let copy = "/testaccount/container/disk-copy.vhd";
    let started = server.request(
        Method::PUT,
        copy,
        &[("x-ms-copy-source", &server.source_url(PAGE))],
        b"",
    );
    assert_eq!(started.status(), 202);
    assert_eq!(header_text(&started, "x-ms-copy-status"), "success");
    let head = server.head(copy);
    assert_eq!(header_text(&head, "x-ms-blob-type"), "PageBlob");
    assert_eq!(header_text(&head, "content-length"), "4096");
    assert_eq!(header_text(&head, "x-ms-meta-kind"), "src");
    assert_eq!(header_text(&head, "x-ms-copy-status"), "success");
    assert_eq!(
        ranges(server.page_ranges(copy, "", &[])),
        [(512, 1535), (3072, 3583)],
        "holes stay holes in the copy"
    );
    assert_eq!(body(server.read(copy, None)), body(server.read(PAGE, None)));
    assert_eq!(
        extent_files(root.path()).len(),
        2,
        "the copy shares extents"
    );

    assert_eq!(
        server.write_pages(PAGE, 512, &[b'z'; 512], &[]).status(),
        201
    );
    assert_eq!(server.clear_pages(copy, 3072, 512, &[]).status(), 201);
    let source = body(server.read(PAGE, None));
    let copied = body(server.read(copy, None));
    assert_eq!(&source[512..1024], [b'z'; 512].as_slice());
    assert_eq!(&copied[512..1024], [b'p'; 512].as_slice());
    assert_eq!(&source[3072..3584], [b'q'; 512].as_slice());
    assert!(copied[3072..3584].iter().all(|byte| *byte == 0));

    assert_eq!(server.request(Method::DELETE, PAGE, &[], b"").status(), 202);
    let survivor = body(server.read(copy, None));
    assert_eq!(&survivor[512..1536], [b'p'; 1024].as_slice());
    assert_eq!(server.request(Method::DELETE, copy, &[], b"").status(), 202);
    assert!(extent_files(root.path()).is_empty());

    assert_eq!(server.create_append(APPEND, &[]).status(), 201);
    assert_eq!(server.append(APPEND, b"one", &[]).status(), 201);
    assert_eq!(server.append(APPEND, b"two", &[]).status(), 201);
    assert_eq!(
        server
            .request(Method::PUT, &format!("{APPEND}?comp=seal"), &[], b"")
            .status(),
        200
    );
    let log_copy = "/testaccount/container/log-copy.txt";
    assert_eq!(
        server
            .request(
                Method::PUT,
                log_copy,
                &[("x-ms-copy-source", &server.source_url(APPEND))],
                b"",
            )
            .status(),
        202
    );
    let head = server.head(log_copy);
    assert_eq!(header_text(&head, "x-ms-blob-type"), "AppendBlob");
    assert_eq!(header_text(&head, "x-ms-blob-committed-block-count"), "2");
    assert!(
        !has_header(&head, "x-ms-blob-sealed"),
        "a copy is not sealed"
    );
    assert_eq!(body(server.read(log_copy, None)), b"onetwo");
    let more = server.append(log_copy, b"!", &[]);
    assert_eq!(header_text(&more, "x-ms-blob-append-offset"), "6");
    assert_eq!(body(server.read(APPEND, None)), b"onetwo");

    assert_eq!(server.put_block_blob(BLOCK, b"block").status(), 201);
    assert_eq!(
        server
            .request(
                Method::PUT,
                BLOCK,
                &[("x-ms-copy-source", &server.source_url(log_copy))],
                b"",
            )
            .status(),
        202
    );
    assert_eq!(
        header_text(&server.head(BLOCK), "x-ms-blob-type"),
        "AppendBlob"
    );
    error(
        server.request(
            Method::PUT,
            "/testaccount/container/x",
            &[(
                "x-ms-copy-source",
                &server.source_url("/testaccount/container/nothing"),
            )],
            b"",
        ),
        404,
        "CannotVerifyCopySource",
    );
}

#[test]
fn page_and_append_blocks_can_be_read_from_a_same_instance_url() {
    in_both_modes(|server| {
        server.create_container();
        let mut source = vec![b'a'; 512];
        source.extend([b'b'; 1024]);
        assert_eq!(server.put_block_blob(BLOCK, &source).status(), 201);
        assert_eq!(server.create_page(PAGE, 4096, &[]).status(), 201);
        let url = server.source_url(BLOCK);
        let from_url = server.request(
            Method::PUT,
            &format!("{PAGE}?comp=page"),
            &[
                ("x-ms-copy-source", &url),
                ("x-ms-source-range", "bytes=512-1535"),
                ("x-ms-range", "bytes=1024-2047"),
            ],
            b"",
        );
        assert_eq!(from_url.status(), 201);
        assert_eq!(ranges(server.page_ranges(PAGE, "", &[])), [(1024, 2047)]);
        assert_eq!(
            body(server.read(PAGE, Some("bytes=1024-2047"))),
            vec![b'b'; 1024]
        );
        error(
            server.request(
                Method::PUT,
                &format!("{PAGE}?comp=page"),
                &[
                    ("x-ms-copy-source", &url),
                    ("x-ms-source-range", "bytes=0-1023"),
                    ("x-ms-range", "bytes=0-511"),
                ],
                b"",
            ),
            400,
            "InvalidHeaderValue",
        );

        assert_eq!(server.create_append(APPEND, &[]).status(), 201);
        let appended = server.request(
            Method::PUT,
            &format!("{APPEND}?comp=appendblock"),
            &[
                ("x-ms-copy-source", &url),
                ("x-ms-source-range", "bytes=0-511"),
            ],
            b"",
        );
        assert_eq!(appended.status(), 201);
        assert_eq!(header_text(&appended, "x-ms-blob-append-offset"), "0");
        assert_eq!(
            header_text(&appended, "x-ms-blob-committed-block-count"),
            "1"
        );
        let from_page = server.request(
            Method::PUT,
            &format!("{APPEND}?comp=appendblock"),
            &[
                ("x-ms-copy-source", &server.source_url(PAGE)),
                ("x-ms-source-range", "bytes=1024-1535"),
                ("x-ms-blob-condition-appendpos", "512"),
            ],
            b"",
        );
        assert_eq!(from_page.status(), 201);
        let mut expected = vec![b'a'; 512];
        expected.extend([b'b'; 512]);
        assert_eq!(body(server.read(APPEND, None)), expected);
        error(
            server.request(
                Method::PUT,
                &format!("{APPEND}?comp=appendblock"),
                &[
                    ("x-ms-copy-source", &url),
                    ("x-ms-source-range", "bytes=0-99"),
                    ("x-ms-blob-condition-appendpos", "1"),
                ],
                b"",
            ),
            412,
            "AppendPositionConditionNotMet",
        );
    });
}

#[test]
fn a_sas_with_add_permission_can_append_but_not_write_pages() {
    let server = Emulator::start(None, &[]);
    server.create_container();
    assert_eq!(server.create_append(APPEND, &[]).status(), 201);
    assert_eq!(server.create_page(PAGE, 512, &[]).status(), 201);
    let add = account_sas("a", "o");
    let appended = server.anonymous(
        Method::PUT,
        &format!("{APPEND}?comp=appendblock&{add}"),
        &[],
        b"via sas",
    );
    assert_eq!(appended.status(), 201);
    error(
        server.anonymous(
            Method::PUT,
            &format!("{PAGE}?comp=page&{add}"),
            &[("x-ms-page-write", "update"), ("x-ms-range", "bytes=0-511")],
            &[0u8; 512],
        ),
        403,
        "AuthorizationPermissionMismatch",
    );
    let write = account_sas("w", "o");
    assert_eq!(
        server
            .anonymous(
                Method::PUT,
                &format!("{PAGE}?comp=page&{write}"),
                &[("x-ms-page-write", "update"), ("x-ms-range", "bytes=0-511")],
                &[0u8; 512],
            )
            .status(),
        201
    );
    let read = account_sas("r", "o");
    assert_eq!(
        server
            .anonymous(
                Method::GET,
                &format!("{PAGE}?comp=pagelist&{read}"),
                &[],
                b""
            )
            .status(),
        200
    );
    error(
        server.anonymous(
            Method::PUT,
            &format!("{APPEND}?comp=appendblock&{read}"),
            &[],
            b"x",
        ),
        403,
        "AuthorizationPermissionMismatch",
    );
}

#[test]
fn memory_quota_counts_page_and_append_extents_not_logical_length() {
    let server = Emulator::start(None, &["--memory-limit", "4096"]);
    server.create_container();
    assert_eq!(
        server.create_page(PAGE, 8 * TIB, &[]).status(),
        201,
        "a sparse blob costs nothing"
    );
    assert_eq!(server.write_pages(PAGE, 0, &[1u8; 4096], &[]).status(), 201);
    error(
        server.write_pages(PAGE, 4096, &[1u8; 512], &[]),
        507,
        "InsufficientStorage",
    );
    assert_eq!(
        server.write_pages(PAGE, 0, &[2u8; 4096], &[]).status(),
        201,
        "an overwrite frees the replaced extent"
    );
    assert_eq!(server.clear_pages(PAGE, 0, 4096, &[]).status(), 201);
    assert_eq!(server.write_pages(PAGE, 0, &[3u8; 512], &[]).status(), 201);
    assert_eq!(
        server.write_pages(PAGE, 512, &[3u8; 3584], &[]).status(),
        201
    );
    error(
        server.write_pages(PAGE, 4096, &[3u8; 512], &[]),
        507,
        "InsufficientStorage",
    );
    assert_eq!(
        server
            .set_properties(PAGE, &[("x-ms-blob-content-length", "512")])
            .status(),
        200,
        "shrinking frees the trimmed extent"
    );
    assert_eq!(server.create_append(APPEND, &[]).status(), 201);
    error(
        server.append(APPEND, &[4u8; 4096], &[]),
        507,
        "InsufficientStorage",
    );
    assert_eq!(server.request(Method::DELETE, PAGE, &[], b"").status(), 202);
    assert_eq!(server.append(APPEND, &[4u8; 4096], &[]).status(), 201);
    error(server.append(APPEND, b"x", &[]), 507, "InsufficientStorage");
    assert_eq!(server.put_block_blob(BLOCK, b"x").status(), 507);
    assert_eq!(
        server.request(Method::DELETE, APPEND, &[], b"").status(),
        202
    );
    assert_eq!(server.put_block_blob(BLOCK, &[5u8; 4096]).status(), 201);
    assert_eq!(server.create_page(PAGE, 4096, &[]).status(), 201);
    error(
        server.write_pages(PAGE, 0, &[1u8; 512], &[]),
        507,
        "InsufficientStorage",
    );
    assert_eq!(
        server.request(Method::DELETE, BLOCK, &[], b"").status(),
        202
    );
    assert_eq!(server.write_pages(PAGE, 0, &[1u8; 512], &[]).status(), 201);
    assert_eq!(
        server.put_block_blob(PAGE, &[6u8; 4096]).status(),
        201,
        "replacing a page blob frees its extents first"
    );
}

#[test]
fn page_and_append_blobs_survive_restart() {
    let root = tempfile::tempdir().unwrap();
    let location = root.path().join("store");
    let mut server = Emulator::start(Some(&location), &[]);
    server.create_container();
    assert_eq!(
        server
            .create_page(
                PAGE,
                4096,
                &[
                    ("x-ms-blob-sequence-number", "2"),
                    ("x-ms-access-tier", "P10")
                ]
            )
            .status(),
        201
    );
    assert_eq!(
        server.write_pages(PAGE, 0, &[b'a'; 1024], &[]).status(),
        201
    );
    assert_eq!(
        server.write_pages(PAGE, 2048, &[b'b'; 512], &[]).status(),
        201
    );
    assert_eq!(server.clear_pages(PAGE, 512, 512, &[]).status(), 201);
    let resized = server.set_properties(PAGE, &[("x-ms-blob-content-length", "3072")]);
    assert_eq!(resized.status(), 200);
    assert_eq!(server.create_append(APPEND, &[]).status(), 201);
    assert_eq!(server.append(APPEND, b"alpha", &[]).status(), 201);
    assert_eq!(server.append(APPEND, b"beta", &[]).status(), 201);
    assert_eq!(
        server
            .request(Method::PUT, &format!("{APPEND}?comp=seal"), &[], b"")
            .status(),
        200
    );
    let page_tag = etag(&server.head(PAGE));
    let page_body = body(server.read(PAGE, None));
    let append_tag = etag(&server.head(APPEND));
    server.process.shutdown().unwrap();
    drop(server);

    let restarted = Emulator::start(Some(&location), &[]);
    let head = restarted.head(PAGE);
    assert_eq!(etag(&head), page_tag);
    assert_eq!(header_text(&head, "x-ms-blob-type"), "PageBlob");
    assert_eq!(header_text(&head, "content-length"), "3072");
    assert_eq!(header_text(&head, "x-ms-blob-sequence-number"), "2");
    assert_eq!(header_text(&head, "x-ms-access-tier"), "P10");
    assert_eq!(body(restarted.read(PAGE, None)), page_body);
    assert_eq!(
        ranges(restarted.page_ranges(PAGE, "", &[])),
        [(0, 511), (2048, 2559)]
    );
    let head = restarted.head(APPEND);
    assert_eq!(etag(&head), append_tag);
    assert_eq!(header_text(&head, "x-ms-blob-committed-block-count"), "2");
    assert_eq!(header_text(&head, "x-ms-blob-sealed"), "true");
    assert_eq!(body(restarted.read(APPEND, None)), b"alphabeta");
    error(restarted.append(APPEND, b"x", &[]), 409, "BlobIsSealed");
    assert_eq!(
        restarted.write_pages(PAGE, 512, &[b'c'; 512], &[]).status(),
        201
    );
}

#[test]
fn an_interrupted_page_or_append_write_leaves_the_previous_content() {
    let root = tempfile::tempdir().unwrap();
    let location = root.path().join("store");
    let mut server = Emulator::start(Some(&location), &[]);
    server.create_container();
    assert_eq!(server.create_page(PAGE, 4096, &[]).status(), 201);
    assert_eq!(
        server.write_pages(PAGE, 0, &[b'a'; 1024], &[]).status(),
        201
    );
    assert_eq!(server.create_append(APPEND, &[]).status(), 201);
    assert_eq!(server.append(APPEND, b"kept", &[]).status(), 201);
    let page_tag = etag(&server.head(PAGE));
    let append_tag = etag(&server.head(APPEND));
    assert_eq!(extent_files(&location).len(), 2);

    let page_socket = server.start_partial_request(
        &format!("{PAGE}?comp=page"),
        &[
            ("x-ms-page-write", "update"),
            ("x-ms-range", "bytes=0-1023"),
        ],
        1024,
        &[b'z'; 100],
    );
    let append_socket = server.start_partial_request(
        &format!("{APPEND}?comp=appendblock"),
        &[],
        50,
        b"incomplete",
    );
    wait_for_staged_uploads(&location, 2);
    server.process.crash();
    drop((page_socket, append_socket));
    let orphan = location
        .join("content")
        .join("extent-00000000000000000000000000000001");
    fs::write(&orphan, b"durable but never referenced").unwrap();

    let restarted = Emulator::start(Some(&location), &[]);
    assert_eq!(etag(&restarted.head(PAGE)), page_tag);
    assert_eq!(etag(&restarted.head(APPEND)), append_tag);
    assert_eq!(
        body(restarted.read(PAGE, Some("bytes=0-1023"))),
        vec![b'a'; 1024]
    );
    assert_eq!(ranges(restarted.page_ranges(PAGE, "", &[])), [(0, 1023)]);
    assert_eq!(body(restarted.read(APPEND, None)), b"kept");
    assert_eq!(
        extent_files(&location).len(),
        2,
        "staging files and unreferenced extents are collected"
    );
    assert!(!orphan.exists());
    assert_eq!(restarted.append(APPEND, b"+", &[]).status(), 201);
}

#[test]
fn replaced_cleared_deleted_and_container_dropped_extents_are_reclaimed() {
    let root = tempfile::tempdir().unwrap();
    let server = Emulator::start(Some(root.path()), &[]);
    server.create_container();
    assert_eq!(server.create_page(PAGE, 4096, &[]).status(), 201);
    assert!(extent_files(root.path()).is_empty());
    assert_eq!(server.write_pages(PAGE, 0, &[1u8; 1024], &[]).status(), 201);
    assert_eq!(extent_files(root.path()).len(), 1);
    assert_eq!(server.write_pages(PAGE, 0, &[2u8; 1024], &[]).status(), 201);
    assert_eq!(
        extent_files(root.path()).len(),
        1,
        "a full overwrite frees the old extent"
    );
    assert_eq!(
        server.write_pages(PAGE, 512, &[3u8; 512], &[]).status(),
        201
    );
    assert_eq!(
        extent_files(root.path()).len(),
        2,
        "a partial overwrite keeps both"
    );
    assert_eq!(server.clear_pages(PAGE, 0, 512, &[]).status(), 201);
    assert_eq!(extent_files(root.path()).len(), 1);
    let whole = body(server.read(PAGE, Some("bytes=0-1023")));
    assert!(whole[..512].iter().all(|byte| *byte == 0));
    assert_eq!(&whole[512..], [3u8; 512].as_slice());
    assert_eq!(
        server
            .set_properties(PAGE, &[("x-ms-blob-content-length", "512")])
            .status(),
        200
    );
    assert!(
        extent_files(root.path()).is_empty(),
        "shrinking frees trimmed extents"
    );

    assert_eq!(server.write_pages(PAGE, 0, &[4u8; 512], &[]).status(), 201);
    assert_eq!(server.create_append(APPEND, &[]).status(), 201);
    assert_eq!(server.append(APPEND, b"a", &[]).status(), 201);
    assert_eq!(server.append(APPEND, b"b", &[]).status(), 201);
    assert_eq!(extent_files(root.path()).len(), 3);
    assert_eq!(
        server.request(Method::DELETE, APPEND, &[], b"").status(),
        202
    );
    assert_eq!(extent_files(root.path()).len(), 1);
    assert_eq!(server.append(APPEND, b"c", &[]).status(), 404);
    assert_eq!(server.create_append(APPEND, &[]).status(), 201);
    assert_eq!(server.append(APPEND, b"d", &[]).status(), 201);
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
    assert!(extent_files(root.path()).is_empty());
}
