//! FileREST HTTP protocol tests against the real binary.

use base64::{Engine as _, engine::general_purpose::STANDARD};
use hmac::{Hmac, Mac as _};
use md5::{Digest as _, Md5};
use percent_encoding::{NON_ALPHANUMERIC, utf8_percent_encode};
use reqwest::{Method, Url, blocking::Client, header::HeaderMap};
use sha2::Sha256;
use std::{
    collections::BTreeMap,
    io::{BufRead as _, BufReader, Write as _},
    net::TcpStream,
    path::Path,
    process::{Child, Command, Stdio},
    time::{Duration, Instant, SystemTime},
};

const ACCOUNT: &str = "testaccount";
const VERSION: &str = "2023-11-03";
const KEY: [u8; 32] = [41; 32];
const SDDL: &str = "O:SYG:SYD:(A;;FA;;;SY)(A;;FA;;;BA)(A;;0x1200a9;;;S-1-5-21-1-2-3-4)";
const POLICIES: &str = "<SignedIdentifiers><SignedIdentifier><Id>read-only</Id><AccessPolicy>\
    <Start>2020-01-01T00:00:00.0000000Z</Start><Expiry>2099-01-01T00:00:00.0000000Z</Expiry>\
    <Permission>rl</Permission></AccessPolicy></SignedIdentifier></SignedIdentifiers>";

struct Emulator {
    child: Child,
    base: String,
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

    fn text(&self) -> String {
        String::from_utf8(self.body.clone()).unwrap()
    }
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
                "file",
                "--shutdown-on-stdin-eof",
            ]);
        match location {
            Some(location) => command.arg("--location").arg(location),
            None => command.arg("--in-memory"),
        };
        command.args(extra);
        let mut child = command
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::null())
            .spawn()
            .expect("start Azuifer");
        let mut lines = BufReader::new(child.stdout.take().expect("piped stdout")).lines();
        let file = lines.next().expect("file_url line").expect("read stdout");
        lines.next().expect("admin_url line").expect("read stdout");
        std::thread::spawn(move || lines.for_each(drop));
        Self {
            child,
            base: file.strip_prefix("file_url=").expect("file_url").to_owned(),
            client: Client::builder()
                .no_proxy()
                .timeout(Duration::from_secs(20))
                .build()
                .unwrap(),
        }
    }

    fn url(&self, target: &str) -> Url {
        Url::parse(&format!("{}{target}", self.base)).unwrap()
    }

    fn shutdown(&mut self) {
        drop(self.child.stdin.take());
        let deadline = Instant::now() + Duration::from_secs(10);
        while Instant::now() < deadline {
            if self.child.try_wait().unwrap().is_some() {
                return;
            }
            std::thread::sleep(Duration::from_millis(20));
        }
        self.crash();
    }

    fn crash(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }

    fn send(&self, method: &str, target: &str, headers: &[(&str, &str)], body: &[u8]) -> Reply {
        self.send_signed(method, target, headers, body, &KEY, false)
    }

    fn send_signed(
        &self,
        method: &str,
        target: &str,
        extra: &[(&str, &str)],
        body: &[u8],
        key: &[u8],
        lite: bool,
    ) -> Reply {
        let method = Method::from_bytes(method.as_bytes()).unwrap();
        let url = self.url(target);
        let length = (method == Method::PUT).then_some(body.len());
        let headers = signed(&method, &url, extra, length, key, lite);
        self.dispatch(method, url, headers, body, length.is_some())
    }

    /// Sends exactly the given headers, for requests that carry their own credentials.
    fn send_raw(&self, method: &str, target: &str, headers: &[(&str, &str)]) -> Reply {
        let method = Method::from_bytes(method.as_bytes()).unwrap();
        let headers = headers
            .iter()
            .map(|(name, value)| ((*name).to_owned(), (*value).to_owned()))
            .collect();
        self.dispatch(
            method.clone(),
            self.url(target),
            headers,
            b"",
            method == Method::PUT,
        )
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
        let reply = Reply {
            status: response.status().as_u16(),
            headers: response.headers().clone(),
            body: response.bytes().expect("response body").to_vec(),
        };
        assert_eq!(reply.header("x-ms-request-id").len(), 32);
        assert!(reply.headers.contains_key("date"));
        assert!(
            reply.header("x-ms-version") == VERSION,
            "every response reports the effective version"
        );
        reply
    }
}

impl Drop for Emulator {
    fn drop(&mut self) {
        self.shutdown();
    }
}

fn signed(
    method: &Method,
    url: &Url,
    extra: &[(&str, &str)],
    length: Option<usize>,
    key: &[u8],
    lite: bool,
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
    let message = if lite {
        let comp = url
            .query_pairs()
            .find(|(name, _)| name == "comp")
            .map(|(_, value)| format!("?comp={value}"))
            .unwrap_or_default();
        format!(
            "{}\n{}\n{}\n\n{extensions}/{ACCOUNT}{}{comp}",
            method.as_str(),
            value("content-md5"),
            value("content-type"),
            url.path()
        )
    } else {
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
        format!(
            "{}\n{extensions}/{ACCOUNT}{}{query}",
            lines.join("\n"),
            url.path()
        )
    };
    let signature = sign(&message, key);
    headers.insert(
        "authorization".into(),
        format!(
            "{} {ACCOUNT}:{signature}",
            if lite { "SharedKeyLite" } else { "SharedKey" }
        ),
    );
    headers
}

fn sign(message: &str, key: &[u8]) -> String {
    let mut mac = Hmac::<Sha256>::new_from_slice(key).unwrap();
    mac.update(message.as_bytes());
    STANDARD.encode(mac.finalize().into_bytes())
}

fn expect(reply: Reply, status: u16) -> Reply {
    assert_eq!(reply.status, status, "body: {}", reply.text());
    reply
}

fn expect_error(reply: Reply, status: u16, code: &str) {
    assert_eq!(reply.status, status, "body: {}", reply.text());
    assert_eq!(reply.header("x-ms-error-code"), code);
    assert!(
        reply.body.is_empty() || reply.text().contains(&format!("<Code>{code}</Code>")),
        "HEAD responses carry no body"
    );
}

fn share(emulator: &Emulator, name: &str) {
    expect(
        emulator.send("PUT", &format!("/{ACCOUNT}/{name}?restype=share"), &[], b""),
        201,
    );
}

fn directory(emulator: &Emulator, share: &str, path: &str) -> Reply {
    expect(
        emulator.send(
            "PUT",
            &format!("/{ACCOUNT}/{share}/{path}?restype=directory"),
            &[],
            b"",
        ),
        201,
    )
}

fn file(emulator: &Emulator, share: &str, path: &str, length: usize) -> Reply {
    expect(
        emulator.send(
            "PUT",
            &format!("/{ACCOUNT}/{share}/{path}"),
            &[
                ("x-ms-type", "file"),
                ("x-ms-content-length", &length.to_string()),
            ],
            b"",
        ),
        201,
    )
}

fn put(emulator: &Emulator, share: &str, path: &str, offset: usize, data: &[u8]) -> Reply {
    let range = format!("bytes={offset}-{}", offset + data.len() - 1);
    expect(
        emulator.send(
            "PUT",
            &format!("/{ACCOUNT}/{share}/{path}?comp=range"),
            &[("x-ms-range", &range), ("x-ms-write", "update")],
            data,
        ),
        201,
    )
}

fn get(emulator: &Emulator, share: &str, path: &str, range: Option<&str>) -> Reply {
    let headers: Vec<(&str, &str)> = range
        .map(|range| ("x-ms-range", range))
        .into_iter()
        .collect();
    emulator.send("GET", &format!("/{ACCOUNT}/{share}/{path}"), &headers, b"")
}

fn pairs(reply: &Reply, tag: &str) -> Vec<String> {
    let text = reply.text();
    let (open, close) = (format!("<{tag}>"), format!("</{tag}>"));
    text.split(&open)
        .skip(1)
        .map(|part| part.split(&close).next().unwrap().to_owned())
        .collect()
}

#[test]
fn share_lifecycle_properties_listing_acl_and_stats() {
    let emulator = Emulator::start(None, &[]);
    let create = expect(
        emulator.send(
            "PUT",
            &format!("/{ACCOUNT}/alpha?restype=share"),
            &[
                ("x-ms-share-quota", "7"),
                ("x-ms-meta-owner", "ada"),
                ("x-ms-access-tier", "Hot"),
            ],
            b"",
        ),
        201,
    );
    assert!(create.header("etag").starts_with("\"0x"));
    assert!(create.headers.contains_key("last-modified"));
    expect_error(
        emulator.send("PUT", &format!("/{ACCOUNT}/alpha?restype=share"), &[], b""),
        409,
        "ShareAlreadyExists",
    );
    expect_error(
        emulator.send(
            "PUT",
            &format!("/{ACCOUNT}/Bad_Name?restype=share"),
            &[],
            b"",
        ),
        400,
        "InvalidResourceName",
    );

    let props = expect(
        emulator.send("HEAD", &format!("/{ACCOUNT}/alpha?restype=share"), &[], b""),
        200,
    );
    assert_eq!(props.header("x-ms-share-quota"), "7");
    assert_eq!(props.header("x-ms-meta-owner"), "ada");
    assert_eq!(props.header("x-ms-access-tier"), "Hot");
    assert_eq!(props.header("x-ms-lease-state"), "available");
    assert_eq!(props.header("x-ms-lease-status"), "unlocked");

    expect(
        emulator.send(
            "PUT",
            &format!("/{ACCOUNT}/alpha?restype=share&comp=properties"),
            &[("x-ms-share-quota", "9")],
            b"",
        ),
        200,
    );
    expect_error(
        emulator.send(
            "PUT",
            &format!("/{ACCOUNT}/alpha?restype=share&comp=properties"),
            &[("x-ms-share-quota", "0")],
            b"",
        ),
        400,
        "InvalidHeaderValue",
    );
    expect(
        emulator.send(
            "PUT",
            &format!("/{ACCOUNT}/alpha?restype=share&comp=metadata"),
            &[("x-ms-meta-stage", "two")],
            b"",
        ),
        200,
    );
    let props = expect(
        emulator.send("GET", &format!("/{ACCOUNT}/alpha?restype=share"), &[], b""),
        200,
    );
    assert_eq!(props.header("x-ms-share-quota"), "9");
    assert_eq!(props.header("x-ms-meta-stage"), "two");
    assert!(!props.headers.contains_key("x-ms-meta-owner"));
    expect_error(
        emulator.send(
            "GET",
            &format!("/{ACCOUNT}/missing?restype=share"),
            &[],
            b"",
        ),
        404,
        "ShareNotFound",
    );

    share(&emulator, "beta");
    share(&emulator, "gamma");
    let first = expect(
        emulator.send(
            "GET",
            &format!("/{ACCOUNT}?comp=list&maxresults=2"),
            &[],
            b"",
        ),
        200,
    );
    assert_eq!(pairs(&first, "Name"), ["alpha", "beta"]);
    let marker = pairs(&first, "NextMarker").remove(0);
    assert!(!marker.is_empty());
    let second = expect(
        emulator.send(
            "GET",
            &format!("/{ACCOUNT}?comp=list&maxresults=2&marker={marker}"),
            &[],
            b"",
        ),
        200,
    );
    assert_eq!(pairs(&second, "Name"), ["gamma"]);
    assert!(second.text().contains("<NextMarker></NextMarker>"));
    let filtered = expect(
        emulator.send(
            "GET",
            &format!("/{ACCOUNT}?comp=list&prefix=al&include=metadata"),
            &[],
            b"",
        ),
        200,
    );
    assert_eq!(pairs(&filtered, "Name"), ["alpha"]);
    assert!(
        filtered
            .text()
            .contains("<Metadata><stage>two</stage></Metadata>")
    );
    assert!(filtered.text().contains("<Quota>9</Quota>"));
    expect_error(
        emulator.send("GET", &format!("/{ACCOUNT}?comp=list&marker=!!"), &[], b""),
        400,
        "InvalidContinuationToken",
    );

    expect(
        emulator.send(
            "PUT",
            &format!("/{ACCOUNT}/alpha?restype=share&comp=acl"),
            &[],
            POLICIES.as_bytes(),
        ),
        200,
    );
    let acl = expect(
        emulator.send(
            "GET",
            &format!("/{ACCOUNT}/alpha?restype=share&comp=acl"),
            &[],
            b"",
        ),
        200,
    );
    assert_eq!(pairs(&acl, "Id"), ["read-only"]);
    assert_eq!(pairs(&acl, "Permission"), ["rl"]);
    expect_error(
        emulator.send(
            "PUT",
            &format!("/{ACCOUNT}/alpha?restype=share&comp=acl"),
            &[],
            b"<SignedIdentifiers><Bogus/></SignedIdentifiers>",
        ),
        400,
        "InvalidXmlDocument",
    );

    let stats = |expected: &str| {
        let reply = expect(
            emulator.send(
                "GET",
                &format!("/{ACCOUNT}/alpha?restype=share&comp=stats"),
                &[],
                b"",
            ),
            200,
        );
        assert_eq!(pairs(&reply, "ShareUsageBytes"), [expected]);
    };
    stats("0");
    file(&emulator, "alpha", "f.bin", 100);
    put(&emulator, "alpha", "f.bin", 10, b"12345");
    stats("5");

    expect(
        emulator.send(
            "DELETE",
            &format!("/{ACCOUNT}/alpha?restype=share"),
            &[],
            b"",
        ),
        202,
    );
    expect_error(
        emulator.send("HEAD", &format!("/{ACCOUNT}/alpha?restype=share"), &[], b""),
        404,
        "ShareNotFound",
    );
}

#[test]
fn directories_files_properties_listing_and_errors() {
    let emulator = Emulator::start(None, &[]);
    share(&emulator, "docs");
    let created = directory(&emulator, "docs", "Reports");
    assert_eq!(created.header("x-ms-file-attributes"), "Directory");
    assert!(created.header("x-ms-file-permission-key").ends_with("*1"));
    assert!(created.headers.contains_key("x-ms-file-id"));
    assert!(created.header("x-ms-file-creation-time").ends_with("0000Z"));
    expect_error(
        emulator.send(
            "PUT",
            &format!("/{ACCOUNT}/docs/reports?restype=directory"),
            &[],
            b"",
        ),
        409,
        "ResourceAlreadyExists",
    );
    expect_error(
        emulator.send(
            "PUT",
            &format!("/{ACCOUNT}/docs/missing/child?restype=directory"),
            &[],
            b"",
        ),
        404,
        "ParentNotFound",
    );
    expect_error(
        emulator.send(
            "PUT",
            &format!("/{ACCOUNT}/docs/bad%3Aname?restype=directory"),
            &[],
            b"",
        ),
        400,
        "InvalidResourceName",
    );
    directory(&emulator, "docs", "REPORTS/2026");

    let create = expect(
        emulator.send(
            "PUT",
            &format!("/{ACCOUNT}/docs/reports/Q1.TXT"),
            &[
                ("x-ms-type", "file"),
                ("x-ms-content-length", "20"),
                ("x-ms-content-type", "text/plain"),
                ("x-ms-content-language", "en"),
                ("x-ms-cache-control", "no-cache"),
                ("x-ms-meta-source", "test"),
                ("x-ms-file-attributes", "ReadOnly|Archive"),
                ("x-ms-file-creation-time", "2020-02-03T04:05:06.0000000Z"),
                ("x-ms-file-last-write-time", "2021-02-03T04:05:06.0000000Z"),
            ],
            b"",
        ),
        201,
    );
    assert_eq!(
        create.header("x-ms-file-creation-time"),
        "2020-02-03T04:05:06.0000000Z"
    );
    assert_eq!(create.header("x-ms-file-attributes"), "ReadOnly|Archive");
    let parent = directory_id(&emulator, "docs", "reports");
    assert_eq!(create.header("x-ms-file-parent-id"), parent);
    expect_error(
        emulator.send(
            "PUT",
            &format!("/{ACCOUNT}/docs/reports"),
            &[("x-ms-type", "file"), ("x-ms-content-length", "1")],
            b"",
        ),
        409,
        "ResourceTypeMismatch",
    );
    expect_error(
        emulator.send(
            "PUT",
            &format!("/{ACCOUNT}/docs/reports/other"),
            &[("x-ms-content-length", "1")],
            b"",
        ),
        400,
        "MissingRequiredHeader",
    );

    let head = expect(
        emulator.send("HEAD", &format!("/{ACCOUNT}/docs/REPORTS/q1.txt"), &[], b""),
        200,
    );
    assert_eq!(head.header("content-length"), "20");
    assert_eq!(head.header("content-type"), "text/plain");
    assert_eq!(head.header("content-language"), "en");
    assert_eq!(head.header("cache-control"), "no-cache");
    assert_eq!(head.header("x-ms-meta-source"), "test");
    assert_eq!(head.header("x-ms-type"), "File");
    assert_eq!(head.header("x-ms-lease-state"), "available");
    assert!(head.body.is_empty());

    expect_error(
        emulator.send(
            "PUT",
            &format!("/{ACCOUNT}/docs/reports/Q1.TXT?comp=range"),
            &[("x-ms-range", "bytes=0-4"), ("x-ms-write", "update")],
            b"12345",
        ),
        409,
        "ReadOnlyAttribute",
    );
    expect(
        emulator.send(
            "PUT",
            &format!("/{ACCOUNT}/docs/reports/Q1.TXT?comp=properties"),
            &[("x-ms-file-attributes", "None")],
            b"",
        ),
        200,
    );
    let md5 = STANDARD.encode(Md5::digest(b"hello world"));
    let written = expect(
        emulator.send(
            "PUT",
            &format!("/{ACCOUNT}/docs/reports/Q1.TXT?comp=range"),
            &[
                ("x-ms-range", "bytes=4-14"),
                ("x-ms-write", "update"),
                ("content-md5", &md5),
            ],
            b"hello world",
        ),
        201,
    );
    assert_eq!(written.header("content-md5"), md5);
    expect_error(
        emulator.send(
            "PUT",
            &format!("/{ACCOUNT}/docs/reports/Q1.TXT?comp=range"),
            &[
                ("x-ms-range", "bytes=0-4"),
                ("x-ms-write", "update"),
                ("content-md5", &md5),
            ],
            b"12345",
        ),
        400,
        "Md5Mismatch",
    );
    expect_error(
        emulator.send(
            "PUT",
            &format!("/{ACCOUNT}/docs/reports/Q1.TXT?comp=range"),
            &[("x-ms-range", "bytes=18-22"), ("x-ms-write", "update")],
            b"12345",
        ),
        416,
        "InvalidRange",
    );
    expect_error(
        emulator.send(
            "PUT",
            &format!("/{ACCOUNT}/docs/reports/Q1.TXT?comp=range"),
            &[("x-ms-range", "bytes=0-4"), ("x-ms-write", "update")],
            b"1234",
        ),
        400,
        "InvalidHeaderValue",
    );

    let full = expect(get(&emulator, "docs", "reports/q1.txt", None), 200);
    let mut expected = vec![0; 4];
    expected.extend_from_slice(b"hello world");
    expected.extend_from_slice(&[0; 5]);
    assert_eq!(full.body, expected);
    let part = expect(
        get(&emulator, "docs", "reports/q1.txt", Some("bytes=4-8")),
        206,
    );
    assert_eq!(part.body, b"hello");
    assert_eq!(part.header("content-range"), "bytes 4-8/20");
    let open_ended = expect(
        get(&emulator, "docs", "reports/q1.txt", Some("bytes=15-")),
        206,
    );
    assert_eq!(open_ended.body, [0; 5]);
    expect_error(
        get(&emulator, "docs", "reports/q1.txt", Some("bytes=20-30")),
        416,
        "InvalidRange",
    );
    let hashed = expect(
        emulator.send(
            "GET",
            &format!("/{ACCOUNT}/docs/reports/q1.txt"),
            &[
                ("x-ms-range", "bytes=4-14"),
                ("x-ms-range-get-content-md5", "true"),
            ],
            b"",
        ),
        206,
    );
    assert_eq!(hashed.header("content-md5"), md5);

    expect(
        emulator.send(
            "PUT",
            &format!("/{ACCOUNT}/docs/reports/q1.txt?comp=properties"),
            &[
                ("x-ms-content-length", "8"),
                ("x-ms-content-type", "text/csv"),
            ],
            b"",
        ),
        200,
    );
    let resized = expect(get(&emulator, "docs", "reports/q1.txt", None), 200);
    assert_eq!(resized.body, [&[0u8; 4][..], b"hell"].concat());
    assert_eq!(resized.header("content-type"), "text/csv");
    expect(
        emulator.send(
            "PUT",
            &format!("/{ACCOUNT}/docs/reports/q1.txt?comp=metadata"),
            &[("x-ms-meta-reviewed", "yes")],
            b"",
        ),
        200,
    );
    let metadata = expect(
        emulator.send(
            "GET",
            &format!("/{ACCOUNT}/docs/reports/q1.txt?comp=metadata"),
            &[],
            b"",
        ),
        200,
    );
    assert_eq!(metadata.header("x-ms-meta-reviewed"), "yes");
    assert!(!metadata.headers.contains_key("x-ms-meta-source"));

    expect_error(
        emulator.send(
            "DELETE",
            &format!("/{ACCOUNT}/docs/reports?restype=directory"),
            &[],
            b"",
        ),
        409,
        "DirectoryNotEmpty",
    );
    expect_error(
        emulator.send(
            "GET",
            &format!("/{ACCOUNT}/docs/reports/none.txt"),
            &[],
            b"",
        ),
        404,
        "ResourceNotFound",
    );
    expect_error(
        emulator.send("GET", &format!("/{ACCOUNT}/docs/nodir/none.txt"), &[], b""),
        404,
        "ParentNotFound",
    );
    expect_error(
        emulator.send("GET", &format!("/{ACCOUNT}/nosuch/f"), &[], b""),
        404,
        "ShareNotFound",
    );

    for name in ["b.txt", "A.txt", "c.txt"] {
        file(&emulator, "docs", &format!("reports/{name}"), 1);
    }
    let all = expect(
        emulator.send(
            "GET",
            &format!("/{ACCOUNT}/docs/Reports?restype=directory&comp=list"),
            &[],
            b"",
        ),
        200,
    );
    assert_eq!(
        pairs(&all, "Name"),
        ["2026", "A.txt", "b.txt", "c.txt", "Q1.TXT"]
    );
    assert!(all.text().contains("DirectoryPath=\"Reports\""));
    assert!(all.text().contains("<Directory><FileId>"));
    let first = expect(
        emulator.send(
            "GET",
            &format!("/{ACCOUNT}/docs/reports?restype=directory&comp=list&maxresults=2&include=Timestamps,ETag,Attributes,PermissionKey"),
            &[],
            b"",
        ),
        200,
    );
    assert_eq!(pairs(&first, "Name"), ["2026", "A.txt"]);
    assert!(first.text().contains("<CreationTime>"));
    assert!(first.text().contains("<Attributes>Directory</Attributes>"));
    assert!(first.text().contains("<PermissionKey>"));
    let marker = pairs(&first, "NextMarker").remove(0);
    let rest = expect(
        emulator.send(
            "GET",
            &format!(
                "/{ACCOUNT}/docs/reports?restype=directory&comp=list&maxresults=2&marker={marker}"
            ),
            &[],
            b"",
        ),
        200,
    );
    assert_eq!(pairs(&rest, "Name"), ["b.txt", "c.txt"]);
    let prefixed = expect(
        emulator.send(
            "GET",
            &format!("/{ACCOUNT}/docs/reports?restype=directory&comp=list&prefix=Q"),
            &[],
            b"",
        ),
        200,
    );
    assert_eq!(pairs(&prefixed, "Name"), ["Q1.TXT"]);
    assert_eq!(pairs(&prefixed, "Content-Length"), ["8"]);

    expect(
        emulator.send(
            "DELETE",
            &format!("/{ACCOUNT}/docs/reports/q1.txt"),
            &[],
            b"",
        ),
        202,
    );
    expect_error(
        emulator.send("HEAD", &format!("/{ACCOUNT}/docs/reports/q1.txt"), &[], b""),
        404,
        "ResourceNotFound",
    );
    expect_error(
        emulator.send("GET", &format!("/{ACCOUNT}/docs/reports/%00x"), &[], b""),
        400,
        "InvalidResourceName",
    );
    let handles = expect(
        emulator.send(
            "GET",
            &format!("/{ACCOUNT}/docs/reports/a.txt?comp=listhandles"),
            &[],
            b"",
        ),
        200,
    );
    assert!(handles.text().contains("<Entries></Entries>"));
    let closed = expect(
        emulator.send(
            "PUT",
            &format!("/{ACCOUNT}/docs/reports?restype=directory&comp=forceclosehandles"),
            &[("x-ms-handle-id", "*")],
            b"",
        ),
        200,
    );
    assert_eq!(closed.header("x-ms-number-of-handles-closed"), "0");
}

fn directory_id(emulator: &Emulator, share: &str, path: &str) -> String {
    emulator
        .send(
            "HEAD",
            &format!("/{ACCOUNT}/{share}/{path}?restype=directory"),
            &[],
            b"",
        )
        .header("x-ms-file-id")
        .to_owned()
}

#[test]
fn clear_range_list_ranges_and_snapshot_diffs() {
    let emulator = Emulator::start(None, &[]);
    share(&emulator, "snap");
    file(&emulator, "snap", "data.bin", 4096);
    put(&emulator, "snap", "data.bin", 0, &[1; 512]);
    put(&emulator, "snap", "data.bin", 512, &[2; 512]);
    put(&emulator, "snap", "data.bin", 2048, &[3; 100]);
    let ranges = |target: &str| {
        let reply = expect(emulator.send("GET", target, &[], b""), 200);
        (pairs(&reply, "Start"), pairs(&reply, "End"), reply)
    };
    let (starts, ends, reply) = ranges(&format!("/{ACCOUNT}/snap/data.bin?comp=rangelist"));
    assert_eq!(
        (starts, ends),
        (
            vec!["0".into(), "2048".into()],
            vec!["1023".into(), "2147".into()]
        )
    );
    assert_eq!(reply.header("x-ms-content-length"), "4096");
    let (starts, _, _) = ranges(&format!("/{ACCOUNT}/snap/data.bin?comp=rangelist"));
    assert_eq!(starts.len(), 2);

    let windowed = expect(
        emulator.send(
            "GET",
            &format!("/{ACCOUNT}/snap/data.bin?comp=rangelist"),
            &[("x-ms-range", "bytes=512-2063")],
            b"",
        ),
        200,
    );
    assert_eq!(pairs(&windowed, "Start"), ["512", "2048"]);
    assert_eq!(pairs(&windowed, "End"), ["1023", "2063"]);

    let snapshot = expect(
        emulator.send(
            "PUT",
            &format!("/{ACCOUNT}/snap?restype=share&comp=snapshot"),
            &[],
            b"",
        ),
        201,
    );
    let id = snapshot.header("x-ms-snapshot").to_owned();
    assert!(id.ends_with("0000Z"));
    put(&emulator, "snap", "data.bin", 256, &[9; 100]);
    expect(
        emulator.send(
            "PUT",
            &format!("/{ACCOUNT}/snap/data.bin?comp=range"),
            &[("x-ms-range", "bytes=2048-2147"), ("x-ms-write", "clear")],
            b"",
        ),
        201,
    );
    let (starts, ends, _) = ranges(&format!("/{ACCOUNT}/snap/data.bin?comp=rangelist"));
    assert_eq!((starts, ends), (vec!["0".into()], vec!["1023".into()]));

    let old = expect(
        emulator.send(
            "GET",
            &format!("/{ACCOUNT}/snap/data.bin?sharesnapshot={id}"),
            &[("x-ms-range", "bytes=256-355")],
            b"",
        ),
        206,
    );
    assert_eq!(old.body, [1; 100]);
    let diff = expect(
        emulator.send(
            "GET",
            &format!("/{ACCOUNT}/snap/data.bin?comp=rangelist&prevsharesnapshot={id}"),
            &[],
            b"",
        ),
        200,
    );
    assert_eq!(pairs(&diff, "Start"), ["256", "2048"]);
    assert_eq!(pairs(&diff, "End"), ["355", "2147"]);
    assert!(
        diff.text()
            .contains("<ClearRange><Start>2048</Start><End>2147</End></ClearRange>")
    );

    expect_error(
        emulator.send(
            "GET",
            &format!("/{ACCOUNT}/snap/data.bin?comp=rangelist&prevsharesnapshot=2001-01-01T00:00:00.0000000Z"),
            &[],
            b"",
        ),
        409,
        "PreviousSnapshotNotFound",
    );
    expect_error(
        emulator.send(
            "GET",
            &format!(
                "/{ACCOUNT}/snap/data.bin?comp=rangelist&sharesnapshot={id}&prevsharesnapshot={id}"
            ),
            &[],
            b"",
        ),
        400,
        "PreviousSnapshotCannotBeNewer",
    );
    expect_error(
        emulator.send(
            "PUT",
            &format!("/{ACCOUNT}/snap/data.bin?sharesnapshot={id}&comp=range"),
            &[("x-ms-range", "bytes=0-0"), ("x-ms-write", "update")],
            b"x",
        ),
        400,
        "ShareSnapshotOperationNotSupported",
    );
    expect_error(
        emulator.send(
            "GET",
            &format!("/{ACCOUNT}/snap/data.bin?sharesnapshot=2001-01-01T00:00:00.0000000Z"),
            &[],
            b"",
        ),
        404,
        "ShareSnapshotNotFound",
    );

    let listing = expect(
        emulator.send(
            "GET",
            &format!("/{ACCOUNT}?comp=list&include=snapshots"),
            &[],
            b"",
        ),
        200,
    );
    assert_eq!(pairs(&listing, "Snapshot"), std::slice::from_ref(&id));
    expect_error(
        emulator.send(
            "DELETE",
            &format!("/{ACCOUNT}/snap?restype=share"),
            &[],
            b"",
        ),
        409,
        "ShareHasSnapshots",
    );
    expect(
        emulator.send(
            "DELETE",
            &format!("/{ACCOUNT}/snap?restype=share&sharesnapshot={id}"),
            &[],
            b"",
        ),
        202,
    );
    expect(
        emulator.send(
            "DELETE",
            &format!("/{ACCOUNT}/snap?restype=share"),
            &[],
            b"",
        ),
        202,
    );
}

#[test]
fn rename_and_copy_move_content_without_changing_it() {
    let emulator = Emulator::start(None, &[]);
    share(&emulator, "move");
    directory(&emulator, "move", "src");
    directory(&emulator, "move", "src/inner");
    file(&emulator, "move", "src/inner/a.txt", 5);
    put(&emulator, "move", "src/inner/a.txt", 0, b"hello");
    file(&emulator, "move", "keep.txt", 3);
    let source = |path: &str| format!("{}/{ACCOUNT}/move/{path}", emulator.base);

    expect_error(
        emulator.send(
            "PUT",
            &format!("/{ACCOUNT}/move/src/inner/sub?restype=directory&comp=rename"),
            &[("x-ms-file-rename-source", &source("src/inner"))],
            b"",
        ),
        409,
        "RenameCycle",
    );
    expect_error(
        emulator.send(
            "PUT",
            &format!("/{ACCOUNT}/move/keep.txt?comp=rename"),
            &[("x-ms-file-rename-source", &source("src/inner/a.txt"))],
            b"",
        ),
        409,
        "ResourceAlreadyExists",
    );
    expect_error(
        emulator.send(
            "PUT",
            &format!("/{ACCOUNT}/move/keep.txt?comp=rename"),
            &[
                (
                    "x-ms-file-rename-source",
                    &format!("{}/{ACCOUNT}/other/x", emulator.base),
                ),
                ("x-ms-file-rename-replace-if-exists", "true"),
            ],
            b"",
        ),
        400,
        "RenameAcrossAccountsAndSharesNotSupported",
    );
    let renamed = expect(
        emulator.send(
            "PUT",
            &format!("/{ACCOUNT}/move/keep.txt?comp=rename"),
            &[
                ("x-ms-file-rename-source", &source("src/inner/a.txt")),
                ("x-ms-file-rename-replace-if-exists", "true"),
            ],
            b"",
        ),
        200,
    );
    assert!(renamed.headers.contains_key("etag"));
    assert_eq!(get(&emulator, "move", "keep.txt", None).body, b"hello");
    expect_error(
        emulator.send(
            "HEAD",
            &format!("/{ACCOUNT}/move/src/inner/a.txt"),
            &[],
            b"",
        ),
        404,
        "ResourceNotFound",
    );

    file(&emulator, "move", "src/inner/b.txt", 3);
    put(&emulator, "move", "src/inner/b.txt", 0, b"abc");
    expect(
        emulator.send(
            "PUT",
            &format!("/{ACCOUNT}/move/Archive?restype=directory&comp=rename"),
            &[("x-ms-file-rename-source", &source("SRC"))],
            b"",
        ),
        200,
    );
    assert_eq!(
        get(&emulator, "move", "archive/inner/b.txt", None).body,
        b"abc"
    );
    expect_error(
        emulator.send(
            "HEAD",
            &format!("/{ACCOUNT}/move/src?restype=directory"),
            &[],
            b"",
        ),
        404,
        "ResourceNotFound",
    );

    let copy = expect(
        emulator.send(
            "PUT",
            &format!("/{ACCOUNT}/move/archive/copy.txt"),
            &[
                ("x-ms-copy-source", &source("archive/inner/b.txt")),
                ("x-ms-meta-copied", "yes"),
            ],
            b"",
        ),
        202,
    );
    assert_eq!(copy.header("x-ms-copy-status"), "success");
    let copy_id = copy.header("x-ms-copy-id").to_owned();
    let props = expect(
        emulator.send(
            "HEAD",
            &format!("/{ACCOUNT}/move/archive/copy.txt"),
            &[],
            b"",
        ),
        200,
    );
    assert_eq!(props.header("x-ms-copy-status"), "success");
    assert_eq!(props.header("x-ms-copy-id"), copy_id);
    assert_eq!(props.header("x-ms-copy-progress"), "3/3");
    assert_eq!(props.header("x-ms-meta-copied"), "yes");
    assert_eq!(
        get(&emulator, "move", "archive/copy.txt", None).body,
        b"abc"
    );
    put(&emulator, "move", "archive/inner/b.txt", 0, b"XYZ");
    assert_eq!(
        get(&emulator, "move", "archive/copy.txt", None).body,
        b"abc",
        "copies are independent afterwards"
    );
    expect_error(
        emulator.send(
            "PUT",
            &format!("/{ACCOUNT}/move/archive/copy.txt?comp=copy&copyid={copy_id}"),
            &[("x-ms-copy-action", "abort")],
            b"",
        ),
        409,
        "NoPendingCopyOperation",
    );
    expect_error(
        emulator.send(
            "PUT",
            &format!("/{ACCOUNT}/move/archive/gone.txt"),
            &[("x-ms-copy-source", &source("archive/missing.txt"))],
            b"",
        ),
        404,
        "CannotVerifyCopySource",
    );
}

#[test]
fn file_and_share_leases_follow_their_state_machines() {
    let emulator = Emulator::start(None, &[]);
    share(&emulator, "locks");
    file(&emulator, "locks", "a.txt", 10);
    let lease = |target: &str, headers: &[(&str, &str)]| {
        emulator.send("PUT", &format!("/{ACCOUNT}/{target}"), headers, b"")
    };
    let id = "1f812371-a41d-49e6-b123-f4b542e851c5";
    let other = "2f812371-a41d-49e6-b123-f4b542e851c5";

    expect_error(
        lease(
            "locks/a.txt?comp=lease",
            &[
                ("x-ms-lease-action", "acquire"),
                ("x-ms-lease-duration", "30"),
            ],
        ),
        400,
        "InvalidHeaderValue",
    );
    let acquired = expect(
        lease(
            "locks/a.txt?comp=lease",
            &[
                ("x-ms-lease-action", "acquire"),
                ("x-ms-lease-duration", "-1"),
                ("x-ms-proposed-lease-id", id),
            ],
        ),
        201,
    );
    assert_eq!(acquired.header("x-ms-lease-id"), id);
    let head = expect(
        emulator.send("HEAD", &format!("/{ACCOUNT}/locks/a.txt"), &[], b""),
        200,
    );
    assert_eq!(head.header("x-ms-lease-state"), "leased");
    assert_eq!(head.header("x-ms-lease-status"), "locked");
    assert_eq!(head.header("x-ms-lease-duration"), "infinite");
    let write = |lease: Option<&str>| {
        let mut headers = vec![("x-ms-range", "bytes=0-0"), ("x-ms-write", "update")];
        if let Some(lease) = lease {
            headers.push(("x-ms-lease-id", lease));
        }
        emulator.send(
            "PUT",
            &format!("/{ACCOUNT}/locks/a.txt?comp=range"),
            &headers,
            b"x",
        )
    };
    expect_error(write(None), 412, "LeaseIdMissingWithFileOperation");
    expect_error(write(Some(other)), 412, "LeaseIdMismatchWithFileOperation");
    expect(write(Some(id)), 201);
    expect_error(
        emulator.send("DELETE", &format!("/{ACCOUNT}/locks/a.txt"), &[], b""),
        412,
        "LeaseIdMissingWithFileOperation",
    );
    expect_error(
        lease(
            "locks/a.txt?comp=lease",
            &[
                ("x-ms-lease-action", "acquire"),
                ("x-ms-lease-duration", "-1"),
                ("x-ms-proposed-lease-id", other),
            ],
        ),
        409,
        "LeaseAlreadyPresent",
    );
    let changed = expect(
        lease(
            "locks/a.txt?comp=lease",
            &[
                ("x-ms-lease-action", "change"),
                ("x-ms-lease-id", id),
                ("x-ms-proposed-lease-id", other),
            ],
        ),
        200,
    );
    assert_eq!(changed.header("x-ms-lease-id"), other);
    let broken = expect(
        lease("locks/a.txt?comp=lease", &[("x-ms-lease-action", "break")]),
        202,
    );
    assert_eq!(broken.header("x-ms-lease-time"), "0");
    expect_error(write(Some(other)), 412, "LeaseLostWithFileOperation");
    expect(write(None), 201);
    expect_error(
        lease(
            "locks/a.txt?comp=lease",
            &[("x-ms-lease-action", "release"), ("x-ms-lease-id", other)],
        ),
        409,
        "LeaseNotPresentWithFileLeaseOperation",
    );

    let share_lease = |headers: &[(&str, &str)]| lease("locks?restype=share&comp=lease", headers);
    let held = expect(
        share_lease(&[
            ("x-ms-lease-action", "acquire"),
            ("x-ms-lease-duration", "60"),
            ("x-ms-proposed-lease-id", id),
        ]),
        201,
    );
    assert_eq!(held.header("x-ms-lease-id"), id);
    let props = expect(
        emulator.send("HEAD", &format!("/{ACCOUNT}/locks?restype=share"), &[], b""),
        200,
    );
    assert_eq!(props.header("x-ms-lease-state"), "leased");
    assert_eq!(props.header("x-ms-lease-duration"), "fixed");
    expect_error(
        emulator.send(
            "DELETE",
            &format!("/{ACCOUNT}/locks?restype=share"),
            &[],
            b"",
        ),
        412,
        "LeaseIdMissingWithFileShareOperation",
    );
    expect_error(
        emulator.send(
            "DELETE",
            &format!("/{ACCOUNT}/locks?restype=share"),
            &[("x-ms-lease-id", other)],
            b"",
        ),
        412,
        "LeaseIdMismatchWithFileShareOperation",
    );
    expect_error(
        emulator.send(
            "PUT",
            &format!("/{ACCOUNT}/locks?restype=share&comp=metadata"),
            &[("x-ms-meta-a", "b")],
            b"",
        ),
        412,
        "LeaseIdMissingWithFileShareOperation",
    );
    expect(
        emulator.send(
            "PUT",
            &format!("/{ACCOUNT}/locks?restype=share&comp=metadata"),
            &[("x-ms-meta-a", "b"), ("x-ms-lease-id", id)],
            b"",
        ),
        200,
    );
    expect(
        share_lease(&[("x-ms-lease-action", "renew"), ("x-ms-lease-id", id)]),
        200,
    );
    let broken = expect(
        share_lease(&[
            ("x-ms-lease-action", "break"),
            ("x-ms-lease-break-period", "30"),
        ]),
        202,
    );
    assert!(broken.header("x-ms-lease-time").parse::<u32>().unwrap() <= 30);
    let state = expect(
        emulator.send("HEAD", &format!("/{ACCOUNT}/locks?restype=share"), &[], b""),
        200,
    );
    assert_eq!(state.header("x-ms-lease-state"), "breaking");
    expect_error(
        share_lease(&[("x-ms-lease-action", "renew"), ("x-ms-lease-id", id)]),
        409,
        "LeaseIsBrokenAndCannotBeRenewed",
    );
    expect(
        share_lease(&[("x-ms-lease-action", "release"), ("x-ms-lease-id", id)]),
        200,
    );
    expect(
        emulator.send(
            "DELETE",
            &format!("/{ACCOUNT}/locks?restype=share"),
            &[],
            b"",
        ),
        202,
    );
}

#[test]
fn permissions_are_stored_per_share_and_referenced_by_key() {
    let emulator = Emulator::start(None, &[]);
    share(&emulator, "perm");
    let body = format!("{{\"permission\":\"{SDDL}\"}}");
    let created = expect(
        emulator.send(
            "PUT",
            &format!("/{ACCOUNT}/perm?restype=share&comp=filepermission"),
            &[],
            body.as_bytes(),
        ),
        201,
    );
    let key = created.header("x-ms-file-permission-key").to_owned();
    let again = expect(
        emulator.send(
            "PUT",
            &format!("/{ACCOUNT}/perm?restype=share&comp=filepermission"),
            &[],
            body.as_bytes(),
        ),
        201,
    );
    assert_eq!(
        again.header("x-ms-file-permission-key"),
        key,
        "the same descriptor reuses its key"
    );
    let fetched = expect(
        emulator.send(
            "GET",
            &format!("/{ACCOUNT}/perm?restype=share&comp=filepermission"),
            &[("x-ms-file-permission-key", &key)],
            b"",
        ),
        200,
    );
    assert!(fetched.text().contains("S-1-5-21-1-2-3-4"));
    expect_error(
        emulator.send(
            "GET",
            &format!("/{ACCOUNT}/perm?restype=share&comp=filepermission"),
            &[("x-ms-file-permission-key", "nope")],
            b"",
        ),
        400,
        "FileInvalidPermissionKey",
    );
    expect_error(
        emulator.send(
            "PUT",
            &format!("/{ACCOUNT}/perm?restype=share&comp=filepermission"),
            &[],
            b"{\"permission\":\"junk\"}",
        ),
        400,
        "FileInvalidPermission",
    );
    let dir = expect(
        emulator.send(
            "PUT",
            &format!("/{ACCOUNT}/perm/d?restype=directory"),
            &[("x-ms-file-permission-key", &key)],
            b"",
        ),
        201,
    );
    assert_eq!(dir.header("x-ms-file-permission-key"), key);
    let inherited = file(&emulator, "perm", "d/f.txt", 1);
    assert_eq!(
        inherited.header("x-ms-file-permission-key"),
        key,
        "new entries inherit by default"
    );
    let with_sddl = expect(
        emulator.send(
            "PUT",
            &format!("/{ACCOUNT}/perm/d/g.txt"),
            &[
                ("x-ms-type", "file"),
                ("x-ms-content-length", "1"),
                ("x-ms-file-permission", SDDL),
            ],
            b"",
        ),
        201,
    );
    assert_eq!(with_sddl.header("x-ms-file-permission-key"), key);
    expect_error(
        emulator.send(
            "PUT",
            &format!("/{ACCOUNT}/perm/d/h.txt"),
            &[
                ("x-ms-type", "file"),
                ("x-ms-content-length", "1"),
                ("x-ms-file-permission-key", "bogus"),
            ],
            b"",
        ),
        400,
        "FileInvalidPermissionKey",
    );
}

fn service_sas(permissions: &str, expiry: &str, resource: &str, path: &str) -> String {
    let (kind, canonical) = (
        if path.is_empty() { "s" } else { "f" },
        format!(
            "/file/{ACCOUNT}/{resource}{}",
            if path.is_empty() {
                String::new()
            } else {
                format!("/{path}")
            }
        ),
    );
    let message = format!("{permissions}\n\n{expiry}\n{canonical}\n\n\n\n{VERSION}\n\n\n\n\n");
    format!(
        "sv={VERSION}&sr={kind}&sp={permissions}&se={expiry}&sig={}",
        utf8_percent_encode(&sign(&message, &KEY), NON_ALPHANUMERIC)
    )
}

fn account_sas(permissions: &str, types: &str, expiry: &str) -> String {
    let message = format!("{ACCOUNT}\n{permissions}\nf\n{types}\n\n{expiry}\n\n\n{VERSION}\n\n");
    format!(
        "sv={VERSION}&ss=f&srt={types}&sp={permissions}&se={expiry}&sig={}",
        utf8_percent_encode(&sign(&message, &KEY), NON_ALPHANUMERIC)
    )
}

#[test]
fn authentication_accepts_valid_credentials_and_rejects_the_rest() {
    let emulator = Emulator::start(None, &[]);
    share(&emulator, "auth");
    file(&emulator, "auth", "f.txt", 4);
    put(&emulator, "auth", "f.txt", 0, b"data");
    let target = format!("/{ACCOUNT}/auth/f.txt");

    let lite = emulator.send_signed("GET", &target, &[], b"", &KEY, true);
    assert_eq!(expect(lite, 200).body, b"data");
    let lite_meta = emulator.send_signed(
        "GET",
        &format!("{target}?comp=metadata"),
        &[],
        b"",
        &KEY,
        true,
    );
    expect(lite_meta, 200);
    expect_error(
        emulator.send_signed("GET", &target, &[], b"", &[7; 32], false),
        403,
        "AuthenticationFailed",
    );
    expect_error(
        emulator.send_raw("GET", &target, &[("x-ms-version", VERSION)]),
        403,
        "NoAuthenticationInformation",
    );
    expect_error(
        emulator.send_raw(
            "GET",
            &target,
            &[("authorization", "Bearer abc"), ("x-ms-version", VERSION)],
        ),
        401,
        "InvalidAuthenticationInfo",
    );
    expect_error(
        emulator.send_raw(
            "GET",
            &target,
            &[
                ("authorization", &format!("SharedKey {ACCOUNT}:AAAA")),
                ("x-ms-date", "Mon, 01 Jan 2001 00:00:00 GMT"),
                ("x-ms-version", VERSION),
            ],
        ),
        403,
        "AuthenticationFailed",
    );
    expect_error(
        emulator.send_raw(
            "GET",
            &target,
            &[("authorization", &format!("SharedKey {ACCOUNT}:AAAA"))],
        ),
        400,
        "MissingRequiredHeader",
    );
    expect_error(
        emulator.send_raw(
            "GET",
            &target,
            &[
                ("authorization", &format!("SharedKey {ACCOUNT}:AAAA")),
                ("x-ms-version", "2009-09-18"),
            ],
        ),
        400,
        "InvalidHeaderValue",
    );
    expect_error(
        emulator.send_raw(
            "GET",
            &target,
            &[
                ("authorization", &format!("SharedKey {ACCOUNT}:AAAA")),
                ("x-ms-version", "2999-01-01"),
            ],
        ),
        400,
        "InvalidHeaderValue",
    );
    expect_error(
        emulator.send("GET", "/unknownacct/auth/f.txt", &[], b""),
        403,
        "AuthenticationFailed",
    );

    let far = "2099-01-01T00:00:00Z";
    let read = service_sas("r", far, "auth", "f.txt");
    let sas_get = |sas: &str, method: &str, path: &str| {
        emulator.send_raw(
            method,
            &format!(
                "/{ACCOUNT}/{path}{}{sas}",
                if path.contains('?') { '&' } else { '?' }
            ),
            &[],
        )
    };
    assert_eq!(
        expect(sas_get(&read, "GET", "auth/f.txt"), 200).body,
        b"data"
    );
    expect_error(
        sas_get(&read, "GET", "auth/other.txt"),
        403,
        "AuthenticationFailed",
    );
    expect_error(
        sas_get(&read, "DELETE", "auth/f.txt"),
        403,
        "AuthorizationPermissionMismatch",
    );
    expect_error(
        sas_get(
            &service_sas("r", "2001-01-01T00:00:00Z", "auth", "f.txt"),
            "GET",
            "auth/f.txt",
        ),
        403,
        "AuthenticationFailed",
    );
    expect_error(
        sas_get(&format!("{read}x"), "GET", "auth/f.txt"),
        403,
        "AuthenticationFailed",
    );
    expect_error(
        sas_get(
            &service_sas("r", far, "auth", "f.txt"),
            "GET",
            "auth?restype=share",
        ),
        403,
        "AuthenticationFailed",
    );
    let share_sas = service_sas("rl", far, "auth", "");
    assert_eq!(
        expect(sas_get(&share_sas, "GET", "auth/f.txt"), 200).body,
        b"data"
    );
    let listing = expect(
        sas_get(&share_sas, "GET", "auth?restype=directory&comp=list"),
        200,
    );
    assert_eq!(pairs(&listing, "Name"), ["f.txt"]);
    expect_error(
        sas_get(&share_sas, "GET", "auth?restype=share"),
        403,
        "AuthorizationPermissionMismatch",
    );
    let overridden = service_sas_with_overrides(far);
    let reply = expect(sas_get(&overridden, "GET", "auth/f.txt"), 200);
    assert_eq!(reply.header("content-disposition"), "attachment");

    let account = account_sas("rwdlc", "sco", far);
    assert_eq!(
        pairs(&expect(sas_get(&account, "GET", "?comp=list"), 200), "Name"),
        ["auth"]
    );
    expect(sas_get(&account, "GET", "auth?restype=share"), 200);
    let narrow = account_sas("rl", "o", far);
    expect_error(
        sas_get(&narrow, "GET", "?comp=list"),
        403,
        "AuthorizationPermissionMismatch",
    );
    assert_eq!(
        expect(sas_get(&narrow, "GET", "auth/f.txt"), 200).body,
        b"data"
    );
    expect_error(
        sas_get(&narrow, "DELETE", "auth/f.txt"),
        403,
        "AuthorizationPermissionMismatch",
    );

    expect(
        emulator.send(
            "PUT",
            &format!("/{ACCOUNT}/auth?restype=share&comp=acl"),
            &[],
            POLICIES.as_bytes(),
        ),
        200,
    );
    let message = format!("\n\n\n/file/{ACCOUNT}/auth\nread-only\n\n\n{VERSION}\n\n\n\n\n");
    let policy_sas = format!(
        "sv={VERSION}&sr=s&si=read-only&sig={}",
        utf8_percent_encode(&sign(&message, &KEY), NON_ALPHANUMERIC)
    );
    assert_eq!(
        expect(sas_get(&policy_sas, "GET", "auth/f.txt"), 200).body,
        b"data"
    );
    expect_error(
        sas_get(&policy_sas, "DELETE", "auth/f.txt"),
        403,
        "AuthorizationPermissionMismatch",
    );
    let unknown = format!(
        "sv={VERSION}&sr=s&si=nope&sig={}",
        utf8_percent_encode(
            &sign(&message.replace("read-only", "nope"), &KEY),
            NON_ALPHANUMERIC
        )
    );
    expect_error(
        sas_get(&unknown, "GET", "auth/f.txt"),
        403,
        "AuthenticationFailed",
    );
}

fn service_sas_with_overrides(expiry: &str) -> String {
    let message =
        format!("r\n\n{expiry}\n/file/{ACCOUNT}/auth/f.txt\n\n\n\n{VERSION}\n\nattachment\n\n\n");
    format!(
        "sv={VERSION}&sr=f&sp=r&se={expiry}&rscd=attachment&sig={}",
        utf8_percent_encode(&sign(&message, &KEY), NON_ALPHANUMERIC)
    )
}

#[test]
fn conditional_reads_use_etags_and_modification_times() {
    let emulator = Emulator::start(None, &[]);
    share(&emulator, "cond");
    let created = file(&emulator, "cond", "f.txt", 1);
    let etag = created.header("etag").to_owned();
    let modified = created.header("last-modified").to_owned();
    let target = format!("/{ACCOUNT}/cond/f.txt");
    expect(
        emulator.send("GET", &target, &[("if-match", &etag)], b""),
        200,
    );
    assert_eq!(
        emulator
            .send("GET", &target, &[("if-none-match", &etag)], b"")
            .status,
        304
    );
    expect_error(
        emulator.send("GET", &target, &[("if-match", "\"0x1\"")], b""),
        412,
        "ConditionNotMet",
    );
    assert_eq!(
        emulator
            .send("HEAD", &target, &[("if-modified-since", &modified)], b"")
            .status,
        304
    );
}

#[test]
fn unsupported_operations_return_a_stable_error() {
    let emulator = Emulator::start(None, &[]);
    share(&emulator, "later");
    file(&emulator, "later", "f.txt", 1);
    expect_error(
        emulator.send(
            "GET",
            &format!("/{ACCOUNT}?restype=service&comp=properties"),
            &[],
            b"",
        ),
        501,
        "NotImplemented",
    );
    expect_error(
        emulator.send(
            "PUT",
            &format!("/{ACCOUNT}/later/f.txt?comp=hardlink"),
            &[],
            b"",
        ),
        501,
        "NotImplemented",
    );
    expect_error(
        emulator.send("POST", &format!("/{ACCOUNT}/later/f.txt"), &[], b""),
        405,
        "UnsupportedHttpVerb",
    );
    expect_error(
        emulator.send(
            "PUT",
            &format!("/{ACCOUNT}/nfs?restype=share"),
            &[("x-ms-enabled-protocols", "NFS")],
            b"",
        ),
        501,
        "NotImplemented",
    );
}

#[test]
fn state_survives_restart_and_abrupt_termination() {
    let directory = tempfile::tempdir().unwrap();
    let location = directory.path();
    let digest_of = |emulator: &Emulator| {
        let reply = get(emulator, "keep", "Dir/data.bin", None);
        assert_eq!(reply.status, 200);
        reply.body
    };
    let mut expected = vec![0u8; 3000];
    {
        let mut emulator = Emulator::start(Some(location), &[]);
        share(&emulator, "keep");
        expect(
            emulator.send(
                "PUT",
                &format!("/{ACCOUNT}/keep?restype=share&comp=metadata"),
                &[("x-ms-meta-persisted", "yes")],
                b"",
            ),
            200,
        );
        directory_create(&emulator);
        file(&emulator, "keep", "Dir/data.bin", 3000);
        put(&emulator, "keep", "Dir/data.bin", 100, &[7; 200]);
        put(&emulator, "keep", "Dir/data.bin", 2900, &[9; 100]);
        expected[100..300].fill(7);
        expected[2900..].fill(9);
        let snapshot = expect(
            emulator.send(
                "PUT",
                &format!("/{ACCOUNT}/keep?restype=share&comp=snapshot"),
                &[],
                b"",
            ),
            201,
        );
        let id = snapshot.header("x-ms-snapshot").to_owned();
        put(&emulator, "keep", "Dir/data.bin", 100, &[8; 50]);
        expected[100..150].fill(8);
        expect(
            emulator.send(
                "PUT",
                &format!("/{ACCOUNT}/keep/Dir/data.bin?comp=lease"),
                &[
                    ("x-ms-lease-action", "acquire"),
                    ("x-ms-lease-duration", "-1"),
                    (
                        "x-ms-proposed-lease-id",
                        "1f812371-a41d-49e6-b123-f4b542e851c5",
                    ),
                ],
                b"",
            ),
            201,
        );
        std::fs::write(location.join("snapshot-id"), &id).unwrap();
        emulator.shutdown();
    }
    let id = std::fs::read_to_string(location.join("snapshot-id")).unwrap();
    {
        let mut emulator = Emulator::start(Some(location), &[]);
        let props = expect(
            emulator.send("HEAD", &format!("/{ACCOUNT}/keep?restype=share"), &[], b""),
            200,
        );
        assert_eq!(props.header("x-ms-meta-persisted"), "yes");
        assert_eq!(digest_of(&emulator).len(), 3000);
        let head = expect(
            emulator.send("HEAD", &format!("/{ACCOUNT}/keep/dir/DATA.bin"), &[], b""),
            200,
        );
        assert_eq!(
            head.header("x-ms-lease-state"),
            "leased",
            "leases survive restart"
        );
        let snap = expect(
            emulator.send(
                "GET",
                &format!("/{ACCOUNT}/keep/Dir/data.bin?sharesnapshot={id}"),
                &[("x-ms-range", "bytes=100-149")],
                b"",
            ),
            206,
        );
        assert_eq!(
            snap.body, [7; 50],
            "the snapshot keeps its bytes across restart"
        );

        // A partial upload that never completes must not change the committed content.
        let url = emulator.url(&format!("/{ACCOUNT}/keep/Dir/data.bin?comp=range"));
        let address = url.socket_addrs(|| None).unwrap()[0];
        let mut socket = TcpStream::connect(address).unwrap();
        let headers = signed(
            &Method::PUT,
            &url,
            &[
                ("x-ms-range", "bytes=0-1999"),
                ("x-ms-write", "update"),
                ("x-ms-lease-id", "1f812371-a41d-49e6-b123-f4b542e851c5"),
            ],
            Some(2000),
            &KEY,
            false,
        );
        write!(
            socket,
            "PUT {}?comp=range HTTP/1.1\r\nHost: {address}\r\nConnection: close\r\n",
            url.path()
        )
        .unwrap();
        for (name, value) in headers {
            write!(socket, "{name}: {value}\r\n").unwrap();
        }
        socket.write_all(b"\r\n").unwrap();
        socket.write_all(&[5; 500]).unwrap();
        socket.flush().unwrap();
        std::thread::sleep(Duration::from_millis(300));
        emulator.crash();
        drop(socket);
    }
    {
        let mut emulator = Emulator::start(Some(location), &[]);
        assert_eq!(
            digest_of(&emulator),
            expected,
            "the interrupted write left the prior content"
        );
        let content = location.join("file").join("content");
        let leftovers: Vec<_> = std::fs::read_dir(&content)
            .unwrap()
            .map(|entry| entry.unwrap().file_name().to_string_lossy().into_owned())
            .filter(|name| name.starts_with("incoming-"))
            .collect();
        assert!(
            leftovers.is_empty(),
            "recovery removed staging files: {leftovers:?}"
        );
        // Stray content that no range references is reclaimed on the next start.
        std::fs::write(
            content.join("extent-00000000000000000000000000000000"),
            b"orphan",
        )
        .unwrap();
        emulator.shutdown();
    }
    let emulator = Emulator::start(Some(location), &[]);
    assert_eq!(digest_of(&emulator), expected);
    assert!(
        !location
            .join("file")
            .join("content")
            .join("extent-00000000000000000000000000000000")
            .exists()
    );
    let entries: Vec<_> = std::fs::read_dir(location)
        .unwrap()
        .map(|entry| entry.unwrap().file_name().to_string_lossy().into_owned())
        .filter(|name| name != "snapshot-id")
        .collect();
    assert_eq!(
        entries,
        ["file"],
        "FileREST keeps all its state in its own directory"
    );
}

fn directory_create(emulator: &Emulator) {
    directory(emulator, "keep", "Dir");
}

#[test]
fn a_second_process_cannot_share_the_storage_directory() {
    let directory = tempfile::tempdir().unwrap();
    let first = Emulator::start(Some(directory.path()), &[]);
    let status = Command::new(env!("CARGO_BIN_EXE_azuifer"))
        .args([
            "serve",
            "--port",
            "0",
            "--admin-port",
            "0",
            "--services",
            "file",
            "--location",
        ])
        .arg(directory.path())
        .env("AZUIFER_ACCOUNT_NAME", ACCOUNT)
        .env("AZUIFER_ACCOUNT_KEY", STANDARD.encode(KEY))
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .unwrap();
    assert!(!status.success());
    drop(first);
}

#[test]
fn memory_mode_fails_predictably_at_its_limit_and_writes_nothing_to_disk() {
    let directory = tempfile::tempdir().unwrap();
    let emulator = Emulator::start(None, &["--memory-limit", "4096"]);
    share(&emulator, "tiny");
    file(&emulator, "tiny", "f.bin", 100_000);
    put(&emulator, "tiny", "f.bin", 0, &[1; 3000]);
    expect_error(
        emulator.send(
            "PUT",
            &format!("/{ACCOUNT}/tiny/f.bin?comp=range"),
            &[("x-ms-range", "bytes=3000-5999"), ("x-ms-write", "update")],
            &[2; 3000],
        ),
        507,
        "InsufficientStorage",
    );
    for _ in 0..3 {
        put(&emulator, "tiny", "f.bin", 0, &[3; 3000]);
    }
    assert_eq!(
        get(&emulator, "tiny", "f.bin", Some("bytes=0-2999")).body,
        [3; 3000]
    );
    assert!(
        std::fs::read_dir(directory.path())
            .unwrap()
            .next()
            .is_none()
    );
}

#[test]
fn every_handled_operation_is_in_the_conformance_manifest() {
    let manifest: serde_json::Value = serde_json::from_str(
        &std::fs::read_to_string(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/specs/conformance/file.json"
        ))
        .unwrap(),
    )
    .unwrap();
    assert_eq!(manifest["service"], "file");
    assert_eq!(manifest["api_version"], VERSION);
    for entry in manifest["operations"].as_array().unwrap() {
        let state = entry["state"].as_str().unwrap();
        assert!(
            ["compatible", "known-difference", "unsupported"].contains(&state),
            "{entry}"
        );
        let authorization = entry["authorization"].as_array().unwrap();
        assert_eq!(authorization.is_empty(), state == "unsupported", "{entry}");
        if state != "unsupported" {
            assert!(!entry["notes"].as_str().unwrap().is_empty(), "{entry}");
        }
    }
}
