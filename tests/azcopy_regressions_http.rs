//! Regression tests for incompatibilities found by running AzCopy 10.34.2 against
//! Azuifer (see the AzCopy sections of `docs/compatibility/blob.md` and `files.md`).
//!
//! The helpers are a local copy of the harness in `blob_http.rs` and `files_http.rs`.
//! Set `AZCOPY_REGRESSION_BINARY` to run the suite against another build, for example
//! one made before a fix, to see the test fail.

use base64::{Engine as _, engine::general_purpose::STANDARD};
use hmac::{Hmac, Mac as _};
use percent_encoding::{NON_ALPHANUMERIC, utf8_percent_encode};
use reqwest::{Method, Url, blocking::Client, header::HeaderMap};
use sha2::Sha256;
use std::{
    collections::BTreeMap,
    ffi::OsString,
    fs,
    io::{BufRead as _, BufReader, Write as _},
    net::TcpStream,
    path::Path,
    process::{Child, Command, Stdio},
    thread,
    time::{Duration, Instant, SystemTime},
};

const ACCOUNT: &str = "testaccount";
const VERSION: &str = "2023-11-03";
const KEY: [u8; 32] = [41; 32];
const FAR: &str = "2099-01-01T00:00:00Z";
const MIB: usize = 1024 * 1024;

struct Server {
    child: Child,
    blob: String,
    file: String,
    client: Client,
}

struct Reply {
    status: u16,
    headers: HeaderMap,
    body: Vec<u8>,
}

impl Reply {
    fn header(&self, name: &str) -> &str {
        self.headers
            .get(name)
            .unwrap_or_else(|| panic!("missing header {name}: {:?}", self.headers))
            .to_str()
            .unwrap()
    }
}

impl Server {
    fn start(location: Option<&Path>) -> Self {
        let binary = std::env::var_os("AZCOPY_REGRESSION_BINARY")
            .unwrap_or_else(|| OsString::from(env!("CARGO_BIN_EXE_azuifer")));
        let mut command = Command::new(binary);
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
                "blob,file",
                "--shutdown-on-stdin-eof",
            ]);
        match location {
            Some(location) => command.arg("--location").arg(location),
            None => command.arg("--in-memory"),
        };
        let mut child = command
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::null())
            .spawn()
            .expect("start Azuifer");
        let mut urls = BTreeMap::new();
        let mut lines = BufReader::new(child.stdout.take().expect("piped stdout")).lines();
        for line in lines.by_ref() {
            let line = line.expect("read stdout");
            let (name, url) = line.split_once("_url=").expect("listener URL");
            urls.insert(name.to_owned(), url.to_owned());
            if name == "admin" {
                break;
            }
        }
        thread::spawn(move || lines.for_each(drop));
        Self {
            child,
            blob: urls.remove("blob").expect("blob_url"),
            file: urls.remove("file").expect("file_url"),
            client: Client::builder()
                .no_proxy()
                .timeout(Duration::from_secs(20))
                .build()
                .unwrap(),
        }
    }

    /// A Shared Key request to the Blob listener.
    fn blob(&self, method: &str, path: &str, extra: &[(&str, &str)], body: &[u8]) -> Reply {
        let method = Method::from_bytes(method.as_bytes()).unwrap();
        let url = Url::parse(&format!("{}{path}", self.blob)).unwrap();
        let length = (method == Method::PUT).then_some(body.len());
        let headers = signed(&method, &url, extra, length);
        self.dispatch(method, url, headers, body, length.is_some())
    }

    /// A SAS request to the Files listener, as AzCopy sends them.
    fn file(&self, method: &str, path: &str, extra: &[(&str, &str)], body: &[u8]) -> Reply {
        let method = Method::from_bytes(method.as_bytes()).unwrap();
        let url = Url::parse(&format!("{}{path}", self.file)).unwrap();
        let mut headers: BTreeMap<String, String> =
            BTreeMap::from([("x-ms-version".into(), VERSION.into())]);
        for (name, value) in extra {
            headers.insert((*name).into(), (*value).into());
        }
        let with_body = method == Method::PUT;
        self.dispatch(method, url, headers, body, with_body)
    }

    fn dispatch(
        &self,
        method: Method,
        url: Url,
        headers: BTreeMap<String, String>,
        body: &[u8],
        with_body: bool,
    ) -> Reply {
        let mut request = self.client.request(method, url);
        for (name, value) in headers {
            request = request.header(name, value);
        }
        if with_body {
            request = request.body(body.to_vec());
        }
        let response = request.send().expect("HTTP request completed");
        Reply {
            status: response.status().as_u16(),
            headers: response.headers().clone(),
            body: response.bytes().expect("response body").to_vec(),
        }
    }

    fn start_partial_upload(&self, path: &str, length: usize) -> TcpStream {
        let url = Url::parse(&format!("{}{path}", self.blob)).unwrap();
        let address = url.socket_addrs(|| None).unwrap()[0];
        let mut socket = TcpStream::connect(address).unwrap();
        let headers = signed(
            &Method::PUT,
            &url,
            &[("x-ms-blob-type", "BlockBlob")],
            Some(length),
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
        socket.write_all(b"incomplete").unwrap();
        socket
    }
}

impl Drop for Server {
    fn drop(&mut self) {
        drop(self.child.stdin.take());
        let deadline = Instant::now() + Duration::from_secs(10);
        while Instant::now() < deadline {
            if self.child.try_wait().unwrap().is_some() {
                return;
            }
            thread::sleep(Duration::from_millis(20));
        }
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

fn sign(message: &str) -> String {
    let mut mac = Hmac::<Sha256>::new_from_slice(&KEY).unwrap();
    mac.update(message.as_bytes());
    STANDARD.encode(mac.finalize().into_bytes())
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
    let extensions: String = headers
        .iter()
        .filter(|(name, _)| name.starts_with("x-ms-"))
        .map(|(name, value)| format!("{name}:{value}\n"))
        .collect();
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
    let signature = sign(&message);
    headers.insert(
        "authorization".into(),
        format!("SharedKey {ACCOUNT}:{signature}"),
    );
    headers
}

/// An account SAS for the File service covering shares, directories, and files.
fn file_sas() -> String {
    let message = format!("{ACCOUNT}\nrwdlc\nf\nsco\n\n{FAR}\n\n\n{VERSION}\n\n");
    format!(
        "sv={VERSION}&ss=f&srt=sco&sp=rwdlc&se={FAR}&sig={}",
        utf8_percent_encode(&sign(&message), NON_ALPHANUMERIC)
    )
}

fn expect(reply: Reply, status: u16) -> Reply {
    assert_eq!(
        reply.status,
        status,
        "body: {}",
        String::from_utf8_lossy(&reply.body)
    );
    reply
}

fn expect_error(reply: Reply, status: u16, code: &str) {
    let reply = expect(reply, status);
    assert_eq!(reply.header("x-ms-error-code"), code);
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
fn append_block_accepts_the_8_mib_blocks_azcopy_sends() {
    let server = Server::start(None);
    let container = format!("/{ACCOUNT}/azcopy");
    expect(
        server.blob("PUT", &format!("{container}?restype=container"), &[], b""),
        201,
    );
    let log = format!("{container}/log.bin");
    expect(
        server.blob("PUT", &log, &[("x-ms-blob-type", "AppendBlob")], b""),
        201,
    );
    let block = vec![7u8; 8 * MIB];
    for offset in [0, 8 * MIB] {
        let reply = expect(
            server.blob(
                "PUT",
                &format!("{log}?comp=appendblock"),
                &[("x-ms-blob-condition-appendpos", &offset.to_string())],
                &block,
            ),
            201,
        );
        assert_eq!(reply.header("x-ms-blob-append-offset"), offset.to_string());
    }
    let head = expect(server.blob("HEAD", &log, &[], b""), 200);
    assert_eq!(head.header("content-length"), (16 * MIB).to_string());
}

#[test]
fn set_blob_properties_accepts_the_empty_content_md5_azcopy_sends() {
    let server = Server::start(None);
    let container = format!("/{ACCOUNT}/azcopy");
    expect(
        server.blob("PUT", &format!("{container}?restype=container"), &[], b""),
        201,
    );
    let page = format!("{container}/page.bin");
    expect(
        server.blob(
            "PUT",
            &page,
            &[
                ("x-ms-blob-type", "PageBlob"),
                ("x-ms-blob-content-length", "512"),
            ],
            b"",
        ),
        201,
    );
    // Without --put-md5, AzCopy follows every page and append upload with this call.
    expect(
        server.blob(
            "PUT",
            &format!("{page}?comp=properties"),
            &[
                ("x-ms-blob-content-md5", ""),
                ("x-ms-blob-content-type", "application/octet-stream"),
            ],
            b"",
        ),
        200,
    );
    let head = expect(server.blob("HEAD", &page, &[], b""), 200);
    assert_eq!(head.header("content-type"), "application/octet-stream");
    assert!(!head.headers.contains_key("content-md5"));
}

#[test]
fn requests_queue_for_a_permit_instead_of_failing_with_server_busy() {
    let location = tempfile::tempdir().unwrap();
    let server = Server::start(Some(location.path()));
    let container = format!("/{ACCOUNT}/azcopy");
    expect(
        server.blob("PUT", &format!("{container}?restype=container"), &[], b""),
        201,
    );
    let blob = format!("{container}/keep.txt");
    expect(
        server.blob("PUT", &blob, &[("x-ms-blob-type", "BlockBlob")], b"keep me"),
        201,
    );
    let stalled: Vec<_> = (0..16)
        .map(|_| server.start_partial_upload(&blob, 32))
        .collect();
    wait_for_staged_uploads(&location.path().join("content"), stalled.len());
    let release = thread::spawn(move || {
        thread::sleep(Duration::from_millis(500));
        drop(stalled);
    });
    // AzCopy opens hundreds of connections at once, so a burst above the 16 active
    // requests must wait for a permit rather than be answered 503.
    let reply = expect(server.blob("GET", &blob, &[], b""), 200);
    assert_eq!(reply.body, b"keep me");
    release.join().unwrap();
}

#[test]
fn put_range_accepts_the_capitalised_preserve_keyword() {
    let server = Server::start(None);
    let sas = file_sas();
    expect(
        server.file(
            "PUT",
            &format!("/{ACCOUNT}/ranges?restype=share&{sas}"),
            &[],
            b"",
        ),
        201,
    );
    let path = format!("/{ACCOUNT}/ranges/f.bin");
    let created = expect(
        server.file(
            "PUT",
            &format!("{path}?{sas}"),
            &[
                ("x-ms-type", "file"),
                ("x-ms-content-length", "4"),
                ("x-ms-file-last-write-time", "2020-01-02T03:04:05.0000000Z"),
            ],
            b"",
        ),
        201,
    );
    let last_write = created.header("x-ms-file-last-write-time").to_owned();
    for keyword in ["Preserve", "PRESERVE"] {
        let written = expect(
            server.file(
                "PUT",
                &format!("{path}?comp=range&{sas}"),
                &[
                    ("x-ms-range", "bytes=0-3"),
                    ("x-ms-write", "update"),
                    ("x-ms-file-last-write-time", keyword),
                ],
                b"data",
            ),
            201,
        );
        assert_eq!(written.header("x-ms-file-last-write-time"), last_write);
    }
    expect_error(
        server.file(
            "PUT",
            &format!("{path}?comp=range&{sas}"),
            &[
                ("x-ms-range", "bytes=0-3"),
                ("x-ms-write", "update"),
                ("x-ms-file-last-write-time", "later"),
            ],
            b"data",
        ),
        400,
        "InvalidHeaderValue",
    );
}

#[test]
fn smb_timestamps_keep_100_nanosecond_precision() {
    let server = Server::start(None);
    let sas = file_sas();
    expect(
        server.file(
            "PUT",
            &format!("/{ACCOUNT}/stamps?restype=share&{sas}"),
            &[],
            b"",
        ),
        201,
    );
    let path = format!("/{ACCOUNT}/stamps/f.txt");
    // AzCopy creates a file with the epoch as its write time, uploads, then sets the
    // source's NTFS timestamp, and `sync` re-sends any file whose source time is newer.
    expect(
        server.file(
            "PUT",
            &format!("{path}?{sas}"),
            &[
                ("x-ms-type", "file"),
                ("x-ms-content-length", "0"),
                ("x-ms-file-creation-time", "2026-11-25T09:36:06.2670280Z"),
                ("x-ms-file-last-write-time", "1970-01-01T00:00:00.0000000Z"),
            ],
            b"",
        ),
        201,
    );
    expect(
        server.file(
            "PUT",
            &format!("{path}?comp=properties&{sas}"),
            &[
                ("x-ms-file-last-write-time", "2026-11-25T09:42:48.4240173Z"),
                ("x-ms-file-change-time", "2026-11-25T09:42:49.0000001Z"),
            ],
            b"",
        ),
        200,
    );
    let head = expect(server.file("HEAD", &format!("{path}?{sas}"), &[], b""), 200);
    assert_eq!(
        head.header("x-ms-file-creation-time"),
        "2026-11-25T09:36:06.2670280Z"
    );
    assert_eq!(
        head.header("x-ms-file-last-write-time"),
        "2026-11-25T09:42:48.4240173Z"
    );
    assert_eq!(
        head.header("x-ms-file-change-time"),
        "2026-11-25T09:42:49.0000001Z"
    );
    let listing = expect(
        server.file(
            "GET",
            &format!("/{ACCOUNT}/stamps?restype=directory&comp=list&include=Timestamps&{sas}"),
            &[],
            b"",
        ),
        200,
    );
    assert!(
        String::from_utf8(listing.body)
            .unwrap()
            .contains("<LastWriteTime>2026-11-25T09:42:48.4240173Z</LastWriteTime>")
    );
}

#[test]
fn put_range_from_url_copies_a_source_range_within_the_account() {
    let server = Server::start(None);
    let sas = file_sas();
    for share in ["src", "dst"] {
        expect(
            server.file(
                "PUT",
                &format!("/{ACCOUNT}/{share}?restype=share&{sas}"),
                &[],
                b"",
            ),
            201,
        );
    }
    let create = |share: &str, length: &str| {
        expect(
            server.file(
                "PUT",
                &format!("/{ACCOUNT}/{share}/dir%2Fa.bin?{sas}"),
                &[("x-ms-type", "file"), ("x-ms-content-length", length)],
                b"",
            ),
            201,
        );
    };
    expect(
        server.file(
            "PUT",
            &format!("/{ACCOUNT}/src/dir?restype=directory&{sas}"),
            &[],
            b"",
        ),
        201,
    );
    expect(
        server.file(
            "PUT",
            &format!("/{ACCOUNT}/dst/dir?restype=directory&{sas}"),
            &[],
            b"",
        ),
        201,
    );
    create("src", "8");
    create("dst", "4");
    expect(
        server.file(
            "PUT",
            &format!("/{ACCOUNT}/src/dir/a.bin?comp=range&{sas}"),
            &[("x-ms-range", "bytes=0-7"), ("x-ms-write", "update")],
            b"abcdefgh",
        ),
        201,
    );
    let source = format!("{}/{ACCOUNT}/src/dir/a.bin?{sas}", server.file);
    let destination = format!("/{ACCOUNT}/dst/dir/a.bin?comp=range&{sas}");
    let copy = |range: &str, source: &str| {
        server.file(
            "PUT",
            &destination,
            &[
                ("x-ms-range", "bytes=0-3"),
                ("x-ms-source-range", range),
                ("x-ms-copy-source", source),
                ("x-ms-write", "update"),
                ("x-ms-file-last-write-time", "Preserve"),
            ],
            b"",
        )
    };
    expect_error(copy("bytes=2-4", &source), 400, "InvalidHeaderValue");
    expect_error(copy("bytes=6-9", &source), 416, "InvalidRange");
    let missing = source.replace("a.bin", "missing.bin");
    expect_error(copy("bytes=2-5", &missing), 404, "ResourceNotFound");
    expect(copy("bytes=2-5", &source), 201);
    let read = expect(
        server.file("GET", &format!("/{ACCOUNT}/dst/dir/a.bin?{sas}"), &[], b""),
        200,
    );
    assert_eq!(read.body, b"cdef");
}
