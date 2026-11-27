//! HTTP protocol tests for snapshots, versions, soft delete, blob index tags,
//! and Submit Batch (ADR-0018, ADR-0019). The server is the built binary; the
//! helpers mirror `blob_http.rs` so the two files merge independently.

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
    io::{BufRead as _, BufReader},
    path::Path,
    process::{Child, Command, Stdio},
    sync::mpsc,
    thread,
    time::{Duration, Instant, SystemTime},
};

const ACCOUNT: &str = "testaccount";
const VERSION: &str = "2023-11-03";
const KEY: [u8; 32] = [41; 32];
const CONTAINER: &str = "/testaccount/container";

thread_local! {
    // Seconds the test clock has been advanced on this test's server.
    static CLOCK_OFFSET: Cell<u64> = const { Cell::new(0) };
}

struct Emulator {
    child: Child,
    blob: String,
    client: Client,
}

impl Drop for Emulator {
    fn drop(&mut self) {
        drop(self.child.stdin.take());
        let deadline = Instant::now() + Duration::from_secs(5);
        while Instant::now() < deadline {
            if matches!(self.child.try_wait(), Ok(Some(_))) {
                return;
            }
            thread::sleep(Duration::from_millis(10));
        }
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

fn command() -> Command {
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
        CLOCK_OFFSET.set(0);
        let mut command = command();
        command.args([
            "serve",
            "--port",
            "0",
            "--admin-port",
            "0",
            "--services",
            "blob",
        ]);
        match location {
            Some(location) => command.arg("--location").arg(location),
            None => command.arg("--in-memory"),
        };
        command
            .args(extra)
            .arg("--shutdown-on-stdin-eof")
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::null());
        let mut child = command.spawn().expect("start Azuifer");
        let stdout = child.stdout.take().expect("piped startup addresses");
        let (sender, receiver) = mpsc::channel();
        thread::spawn(move || {
            let mut urls = BTreeMap::new();
            for line in BufReader::new(stdout).lines().take(6).map_while(Result::ok) {
                if let Some((name, url)) = line.split_once("_url=") {
                    urls.insert(name.to_owned(), url.to_owned());
                    if name == "admin" {
                        break;
                    }
                }
            }
            sender.send(urls).ok();
        });
        let mut urls = receiver
            .recv_timeout(Duration::from_secs(10))
            .expect("server bound its ports");
        Self {
            child,
            blob: urls.remove("blob").expect("Blob listener URL"),
            client: Client::builder()
                .no_proxy()
                .timeout(Duration::from_secs(10))
                .build()
                .unwrap(),
        }
    }

    fn memory() -> Self {
        Self::start(None, &[])
    }

    fn clocked() -> Self {
        Self::start(None, &["--test-clock"])
    }

    fn versioned() -> Self {
        Self::start(None, &["--versioning-accounts", ACCOUNT])
    }

    fn advance(&self, seconds: u64) {
        let response = self
            .client
            .post(format!(
                "{}/_azuifer/clock/advance?seconds={seconds}",
                self.blob
            ))
            .send()
            .unwrap();
        assert_eq!(response.status(), 200);
        CLOCK_OFFSET.set(CLOCK_OFFSET.get() + seconds);
    }

    fn send(&self, method: Method, path: &str, extra: &[(&str, &str)], body: &[u8]) -> Response {
        let url = Url::parse(&format!("{}{path}", self.blob)).unwrap();
        let sends_body = matches!(method, Method::PUT | Method::POST);
        let headers = signed(&method, &url, extra, sends_body.then_some(body.len()), true);
        let mut request = self.client.request(method, url);
        for (name, value) in headers {
            request = request.header(name, value);
        }
        if sends_body {
            request = request.body(body.to_vec());
        }
        request.send().expect("HTTP request completed")
    }

    fn create_container(&self) {
        let response = self.send(
            Method::PUT,
            &format!("{CONTAINER}?restype=container"),
            &[],
            b"",
        );
        assert_eq!(response.status(), 201);
    }

    fn put(&self, name: &str, extra: &[(&str, &str)], bytes: &[u8]) -> Response {
        let mut headers = vec![("x-ms-blob-type", "BlockBlob")];
        headers.extend_from_slice(extra);
        self.send(Method::PUT, &blob(name), &headers, bytes)
    }

    fn get(&self, path: &str) -> Response {
        self.send(Method::GET, path, &[], b"")
    }

    fn snapshot(&self, name: &str) -> String {
        let response = self.send(
            Method::PUT,
            &format!("{}?comp=snapshot", blob(name)),
            &[],
            b"",
        );
        assert_eq!(response.status(), 201);
        response.headers()["x-ms-snapshot"]
            .to_str()
            .unwrap()
            .to_owned()
    }

    fn list(&self, query: &str) -> String {
        let query = if query.is_empty() {
            String::new()
        } else {
            format!("&{query}")
        };
        let response = self.get(&format!("{CONTAINER}?restype=container&comp=list{query}"));
        assert_eq!(response.status(), 200);
        response.text().unwrap()
    }

    fn set_retention(&self, days: u32) {
        let body = format!(
            "<StorageServiceProperties><DeleteRetentionPolicy><Enabled>true</Enabled><Days>{days}</Days></DeleteRetentionPolicy></StorageServiceProperties>"
        );
        let response = self.send(
            Method::PUT,
            &format!("/{ACCOUNT}?restype=service&comp=properties"),
            &[],
            body.as_bytes(),
        );
        assert_eq!(response.status(), 202);
    }
}

fn blob(name: &str) -> String {
    format!("{CONTAINER}/{name}")
}

fn status_of(response: Response) -> u16 {
    response.status().as_u16()
}

fn error_code(response: Response) -> String {
    response.headers()["x-ms-error-code"]
        .to_str()
        .unwrap()
        .to_owned()
}

fn header(response: &Response, name: &str) -> String {
    response.headers()[name].to_str().unwrap().to_owned()
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

fn server_now() -> SystemTime {
    SystemTime::now() + Duration::from_secs(CLOCK_OFFSET.get())
}

/// Shared Key headers for a request. Batch sub-requests are signed without
/// `x-ms-version` (`version: false`): they run at the batch's version.
fn signed(
    method: &Method,
    url: &Url,
    extra: &[(&str, &str)],
    length: Option<usize>,
    version: bool,
) -> BTreeMap<String, String> {
    let mut headers: BTreeMap<String, String> =
        BTreeMap::from([("x-ms-date".into(), httpdate::fmt_http_date(server_now()))]);
    if version {
        headers.insert("x-ms-version".into(), VERSION.into());
    }
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

/// The text between each `open` and the next `close`.
fn between<'a>(text: &'a str, open: &str, close: &str) -> Vec<&'a str> {
    let mut found = Vec::new();
    let mut rest = text;
    while let Some(start) = rest.find(open) {
        let after = &rest[start + open.len()..];
        let Some(end) = after.find(close) else { break };
        found.push(&after[..end]);
        rest = &after[end + close.len()..];
    }
    found
}

/// `(name, snapshot, version id)` of each `<Blob>` of a listing.
fn blobs_of(xml: &str) -> Vec<(String, Option<String>, Option<String>)> {
    between(xml, "<Blob>", "</Blob>")
        .into_iter()
        .map(|blob| {
            let one = |tag: &str| {
                between(blob, &format!("<{tag}>"), &format!("</{tag}>"))
                    .first()
                    .map(|text| (*text).to_owned())
            };
            (one("Name").unwrap(), one("Snapshot"), one("VersionId"))
        })
        .collect()
}

fn tags_body(pairs: &[(&str, &str)]) -> String {
    let tags: String = pairs
        .iter()
        .map(|(key, value)| format!("<Tag><Key>{key}</Key><Value>{value}</Value></Tag>"))
        .collect();
    format!("<?xml version=\"1.0\" encoding=\"utf-8\"?><Tags><TagSet>{tags}</TagSet></Tags>")
}

fn set_tags(server: &Emulator, name: &str, pairs: &[(&str, &str)]) -> Response {
    server.send(
        Method::PUT,
        &format!("{}?comp=tags", blob(name)),
        &[("content-type", "application/xml")],
        tags_body(pairs).as_bytes(),
    )
}

#[test]
fn a_snapshot_keeps_content_properties_and_metadata_after_the_blob_is_overwritten() {
    let server = Emulator::memory();
    server.create_container();
    let put = server.put(
        "a.txt",
        &[
            ("x-ms-meta-owner", "me"),
            ("x-ms-blob-content-type", "text/plain"),
        ],
        b"first",
    );
    assert_eq!(put.status(), 201);
    let etag = header(&put, "etag");
    let snapshot = server.snapshot("a.txt");
    assert!(
        snapshot.ends_with('Z') && snapshot.contains('.'),
        "{snapshot}"
    );
    assert_eq!(status_of(server.put("a.txt", &[], b"second!")), 201);

    let by_snapshot = format!("{}?snapshot={}", blob("a.txt"), encode(&snapshot));
    let read = server.get(&by_snapshot);
    assert_eq!(read.status(), 200);
    assert_eq!(header(&read, "etag"), etag);
    assert_eq!(header(&read, "content-type"), "text/plain");
    assert_eq!(header(&read, "x-ms-meta-owner"), "me");
    assert_eq!(read.bytes().unwrap().as_ref(), b"first");
    let head = server.send(Method::HEAD, &by_snapshot, &[], b"");
    assert_eq!(header(&head, "content-length"), "5");
    let ranged = server.send(
        Method::GET,
        &by_snapshot,
        &[("x-ms-range", "bytes=1-2")],
        b"",
    );
    assert_eq!(ranged.status(), 206);
    assert_eq!(ranged.bytes().unwrap().as_ref(), b"ir");
    let metadata = server.get(&format!(
        "{}?comp=metadata&snapshot={}",
        blob("a.txt"),
        encode(&snapshot)
    ));
    assert_eq!(header(&metadata, "x-ms-meta-owner"), "me");
    assert_eq!(
        server.get(&blob("a.txt")).bytes().unwrap().as_ref(),
        b"second!"
    );

    let missing = server.get(&format!(
        "{}?snapshot={}",
        blob("a.txt"),
        encode("2001-01-01T00:00:00.0000000Z")
    ));
    assert_eq!(missing.status(), 404);
    assert_eq!(error_code(missing), "BlobNotFound");
    let malformed = server.get(&format!("{}?snapshot=yesterday", blob("a.txt")));
    assert_eq!(error_code(malformed), "InvalidQueryParameterValue");
    let both = server.get(&format!(
        "{}?snapshot={}&versionid={}",
        blob("a.txt"),
        encode(&snapshot),
        encode(&snapshot)
    ));
    assert_eq!(both.status(), 400);
    assert_eq!(
        status_of(server.send(
            Method::PUT,
            &format!("{}?comp=snapshot", blob("none")),
            &[],
            b""
        )),
        404
    );
}

#[test]
fn snapshots_take_metadata_overrides_and_honour_conditions_and_leases() {
    let server = Emulator::memory();
    server.create_container();
    let put = server.put("a", &[("x-ms-meta-old", "1")], b"data");
    let etag = header(&put, "etag");
    let snapshot = server.send(
        Method::PUT,
        &format!("{}?comp=snapshot", blob("a")),
        &[("x-ms-meta-fresh", "2")],
        b"",
    );
    assert_eq!(snapshot.status(), 201);
    assert_eq!(header(&snapshot, "etag"), etag);
    let time = header(&snapshot, "x-ms-snapshot");
    let read = server.get(&format!("{}?snapshot={}", blob("a"), encode(&time)));
    assert_eq!(header(&read, "x-ms-meta-fresh"), "2");
    assert!(!read.headers().contains_key("x-ms-meta-old"));
    assert_eq!(header(&server.get(&blob("a")), "x-ms-meta-old"), "1");

    let failed = server.send(
        Method::PUT,
        &format!("{}?comp=snapshot", blob("a")),
        &[("if-match", "\"other\"")],
        b"",
    );
    assert_eq!(failed.status(), 412);
    assert_eq!(error_code(failed), "ConditionNotMet");

    let lease = server.send(
        Method::PUT,
        &format!("{}?comp=lease", blob("a")),
        &[
            ("x-ms-lease-action", "acquire"),
            ("x-ms-lease-duration", "-1"),
            (
                "x-ms-proposed-lease-id",
                "11111111-1111-1111-1111-111111111111",
            ),
        ],
        b"",
    );
    assert_eq!(lease.status(), 201);
    let url = format!("{}?comp=snapshot", blob("a"));
    assert_eq!(status_of(server.send(Method::PUT, &url, &[], b"")), 201);
    let ok = server.send(
        Method::PUT,
        &url,
        &[("x-ms-lease-id", "11111111-1111-1111-1111-111111111111")],
        b"",
    );
    assert_eq!(ok.status(), 201);
    let wrong = server.send(
        Method::PUT,
        &url,
        &[("x-ms-lease-id", "22222222-2222-2222-2222-222222222222")],
        b"",
    );
    assert_eq!(wrong.status(), 412);
}

#[test]
fn a_snapshot_reports_its_committed_blocks() {
    let server = Emulator::memory();
    server.create_container();
    let block = |id: &str, bytes: &[u8]| {
        let url = format!("{}?comp=block&blockid={}", blob("blocks"), encode(id));
        assert_eq!(status_of(server.send(Method::PUT, &url, &[], bytes)), 201);
    };
    let (first, second) = (STANDARD.encode("block-1"), STANDARD.encode("block-2"));
    block(&first, b"hello ");
    block(&second, b"world");
    let list = format!("<BlockList><Latest>{first}</Latest><Latest>{second}</Latest></BlockList>");
    let commit = server.send(
        Method::PUT,
        &format!("{}?comp=blocklist", blob("blocks")),
        &[],
        list.as_bytes(),
    );
    assert_eq!(commit.status(), 201);
    let snapshot = server.snapshot("blocks");
    assert_eq!(status_of(server.put("blocks", &[], b"flat")), 201);
    let listed = server
        .get(&format!(
            "{}?comp=blocklist&blocklisttype=all&snapshot={}",
            blob("blocks"),
            encode(&snapshot)
        ))
        .text()
        .unwrap();
    assert!(
        listed.contains(&format!("<Name>{first}</Name><Size>6</Size>")),
        "{listed}"
    );
    assert!(listed.contains(&format!("<Name>{second}</Name><Size>5</Size>")));
    assert!(listed.contains("<UncommittedBlocks>"));
    let current = server
        .get(&format!("{}?comp=blocklist", blob("blocks")))
        .text()
        .unwrap();
    assert!(!current.contains("block-1") && !current.contains(&first));
    let body = server.get(&format!(
        "{}?snapshot={}",
        blob("blocks"),
        encode(&snapshot)
    ));
    assert_eq!(body.bytes().unwrap().as_ref(), b"hello world");
}

#[test]
fn deleting_a_blob_with_snapshots_needs_a_delete_snapshots_option() {
    let server = Emulator::memory();
    server.create_container();
    server.put("a", &[], b"data");
    let first = server.snapshot("a");
    let second = server.snapshot("a");
    assert_ne!(first, second);

    let refused = server.send(Method::DELETE, &blob("a"), &[], b"");
    assert_eq!(refused.status(), 409);
    assert_eq!(error_code(refused), "SnapshotsPresent");
    let both = server.send(
        Method::DELETE,
        &format!("{}?snapshot={}", blob("a"), encode(&first)),
        &[("x-ms-delete-snapshots", "include")],
        b"",
    );
    assert_eq!(both.status(), 400);
    let one = server.send(
        Method::DELETE,
        &format!("{}?snapshot={}", blob("a"), encode(&first)),
        &[],
        b"",
    );
    assert_eq!(one.status(), 202);
    assert_eq!(header(&one, "x-ms-delete-type-permanent"), "true");
    assert_eq!(
        status_of(server.get(&format!("{}?snapshot={}", blob("a"), encode(&first)))),
        404
    );
    let only = server.send(
        Method::DELETE,
        &blob("a"),
        &[("x-ms-delete-snapshots", "only")],
        b"",
    );
    assert_eq!(only.status(), 202);
    assert_eq!(
        status_of(server.get(&blob("a"))),
        200,
        "the base blob stays"
    );
    assert_eq!(
        status_of(server.get(&format!("{}?snapshot={}", blob("a"), encode(&second)))),
        404
    );
    server.snapshot("a");
    let all = server.send(
        Method::DELETE,
        &blob("a"),
        &[("x-ms-delete-snapshots", "include")],
        b"",
    );
    assert_eq!(all.status(), 202);
    assert_eq!(status_of(server.get(&blob("a"))), 404);
    assert!(blobs_of(&server.list("include=snapshots")).is_empty());
    let invalid = server.send(
        Method::DELETE,
        &blob("a"),
        &[("x-ms-delete-snapshots", "everything")],
        b"",
    );
    assert_eq!(invalid.status(), 400);
}

#[test]
fn listings_include_snapshots_oldest_first_and_page_through_them() {
    let server = Emulator::memory();
    server.create_container();
    server.put("a", &[], b"1");
    server.put("b", &[], b"2");
    let first = server.snapshot("a");
    let second = server.snapshot("a");
    let third = server.snapshot("b");

    let plain = blobs_of(&server.list(""));
    assert_eq!(
        plain,
        vec![("a".into(), None, None), ("b".into(), None, None)]
    );
    let xml = server.list("include=snapshots");
    let all = blobs_of(&xml);
    assert_eq!(
        all,
        vec![
            ("a".into(), Some(first.clone()), None),
            ("a".into(), Some(second.clone()), None),
            ("a".into(), None, None),
            ("b".into(), Some(third.clone()), None),
            ("b".into(), None, None),
        ]
    );
    assert!(xml.contains("<Content-Length>1</Content-Length>"));

    let mut seen = Vec::new();
    let mut marker = String::new();
    loop {
        let page = server.list(&format!(
            "include=snapshots&maxresults=2&marker={}",
            encode(&marker)
        ));
        let entries = blobs_of(&page);
        assert!(entries.len() <= 2);
        seen.extend(entries);
        marker = between(&page, "<NextMarker>", "</NextMarker>")[0].to_owned();
        if marker.is_empty() {
            break;
        }
    }
    assert_eq!(seen, all);

    let delimited = server.list("include=snapshots&delimiter=%2F&prefix=");
    assert_eq!(blobs_of(&delimited).len(), 5);
    server.put("dir/x", &[], b"x");
    server.snapshot("dir/x");
    let grouped = server.list("include=snapshots&delimiter=%2F");
    assert!(
        grouped.contains("<BlobPrefix><Name>dir/</Name></BlobPrefix>"),
        "{grouped}"
    );
    assert_eq!(blobs_of(&grouped).len(), 5);
    let with_metadata = server.list("include=snapshots,metadata,copy");
    assert!(
        with_metadata.contains("<Metadata />") || with_metadata.contains("<Metadata></Metadata>")
    );
}

#[test]
fn a_snapshot_can_be_a_copy_source() {
    let server = Emulator::memory();
    server.create_container();
    server.put("a", &[], b"old");
    let snapshot = server.snapshot("a");
    server.put("a", &[], b"new");
    let source = format!("{}{}?snapshot={}", server.blob, blob("a"), snapshot);
    let copy = server.send(
        Method::PUT,
        &blob("copy"),
        &[("x-ms-copy-source", &source)],
        b"",
    );
    assert_eq!(copy.status(), 202, "{}", copy.text().unwrap());
    assert_eq!(server.get(&blob("copy")).bytes().unwrap().as_ref(), b"old");
    let tagged = server.send(
        Method::PUT,
        &blob("tagged"),
        &[
            ("x-ms-copy-source", &source),
            ("x-ms-tags", "from=snapshot"),
        ],
        b"",
    );
    assert_eq!(tagged.status(), 202);
    let head = server.send(Method::HEAD, &blob("tagged"), &[], b"");
    assert_eq!(header(&head, "x-ms-tag-count"), "1");
    assert!(
        !server
            .send(Method::HEAD, &blob("copy"), &[], b"")
            .headers()
            .contains_key("x-ms-tag-count")
    );
    let missing = format!(
        "{}{}?snapshot=2001-01-01T00:00:00.0000000Z",
        server.blob,
        blob("a")
    );
    let failed = server.send(
        Method::PUT,
        &blob("other"),
        &[("x-ms-copy-source", &missing)],
        b"",
    );
    assert_eq!(failed.status(), 404);
}

#[test]
fn snapshots_survive_restart_and_the_deleted_base_blob() {
    let dir = tempfile::tempdir().unwrap();
    let snapshot = {
        let server = Emulator::start(Some(dir.path()), &[]);
        server.create_container();
        server.put("a", &[], b"kept bytes");
        let snapshot = server.snapshot("a");
        server.put("a", &[], b"replacement");
        assert_eq!(
            status_of(server.send(
                Method::DELETE,
                &blob("a"),
                &[("x-ms-delete-snapshots", "only")],
                b""
            )),
            202
        );
        assert_eq!(status_of(server.snapshot_request_status("a")), 201);
        snapshot
    };
    let server = Emulator::start(Some(dir.path()), &[]);
    assert_eq!(
        server.get(&blob("a")).bytes().unwrap().as_ref(),
        b"replacement"
    );
    let all = blobs_of(&server.list("include=snapshots"));
    assert_eq!(all.len(), 2, "{all:?}");
    assert!(
        server
            .get(&format!("{}?snapshot={}", blob("a"), encode(&snapshot)))
            .status()
            == 404,
        "the deleted snapshot stays deleted"
    );
}

impl Emulator {
    fn snapshot_request_status(&self, name: &str) -> Response {
        self.send(
            Method::PUT,
            &format!("{}?comp=snapshot", blob(name)),
            &[],
            b"",
        )
    }
}

#[test]
fn versions_are_numbered_listed_read_deleted_and_promoted() {
    let server = Emulator::versioned();
    server.create_container();
    let first = server.put("a", &[("x-ms-meta-n", "1")], b"v1");
    let id1 = header(&first, "x-ms-version-id");
    let second = server.put("a", &[("x-ms-meta-n", "2")], b"v2");
    let id2 = header(&second, "x-ms-version-id");
    assert_ne!(id1, id2);

    let current = server.get(&blob("a"));
    assert_eq!(header(&current, "x-ms-version-id"), id2);
    assert_eq!(header(&current, "x-ms-is-current-version"), "true");
    let old = server.get(&format!("{}?versionid={}", blob("a"), encode(&id1)));
    assert_eq!(old.status(), 200);
    assert_eq!(header(&old, "x-ms-version-id"), id1);
    assert_eq!(header(&old, "x-ms-is-current-version"), "false");
    assert_eq!(header(&old, "x-ms-meta-n"), "1");
    assert_eq!(old.bytes().unwrap().as_ref(), b"v1");
    let same = server.get(&format!("{}?versionid={}", blob("a"), encode(&id2)));
    assert_eq!(header(&same, "x-ms-is-current-version"), "true");

    let metadata = server.send(
        Method::PUT,
        &format!("{}?comp=metadata", blob("a")),
        &[("x-ms-meta-n", "3")],
        b"",
    );
    assert_eq!(metadata.status(), 200);
    let id3 = header(&metadata, "x-ms-version-id");
    assert_ne!(id3, id2);
    let kept = server.get(&format!("{}?versionid={}", blob("a"), encode(&id2)));
    assert_eq!(
        header(&kept, "x-ms-meta-n"),
        "2",
        "the earlier version keeps its metadata"
    );
    assert_eq!(kept.bytes().unwrap().as_ref(), b"v2");

    let xml = server.list("include=versions");
    assert_eq!(
        blobs_of(&xml),
        vec![
            ("a".into(), None, Some(id1.clone())),
            ("a".into(), None, Some(id2.clone())),
            ("a".into(), None, Some(id3.clone())),
        ]
    );
    assert_eq!(
        xml.matches("<IsCurrentVersion>true</IsCurrentVersion>")
            .count(),
        1
    );
    assert!(xml.rfind("<IsCurrentVersion>").unwrap() > xml.find(&id3).unwrap());
    assert_eq!(
        blobs_of(&server.list("")).len(),
        1,
        "a plain listing shows the current blob"
    );

    let deleted = server.send(Method::DELETE, &blob("a"), &[], b"");
    assert_eq!(deleted.status(), 202);
    assert_eq!(header(&deleted, "x-ms-delete-type-permanent"), "false");
    assert_eq!(status_of(server.get(&blob("a"))), 404);
    assert_eq!(blobs_of(&server.list("")).len(), 0);
    let after = server.list("include=versions");
    assert_eq!(blobs_of(&after).len(), 3);
    assert!(!after.contains("<IsCurrentVersion>"));

    let source = format!("{}{}?versionid={}", server.blob, blob("a"), id1);
    let promote = server.send(
        Method::PUT,
        &blob("a"),
        &[("x-ms-copy-source", &source)],
        b"",
    );
    assert_eq!(promote.status(), 202);
    let promoted = header(&promote, "x-ms-version-id");
    assert!(![&id1, &id2, &id3].contains(&&promoted));
    assert_eq!(server.get(&blob("a")).bytes().unwrap().as_ref(), b"v1");

    let removed = server.send(
        Method::DELETE,
        &format!("{}?versionid={}", blob("a"), encode(&id2)),
        &[],
        b"",
    );
    assert_eq!(removed.status(), 202);
    assert_eq!(
        status_of(server.get(&format!("{}?versionid={}", blob("a"), encode(&id2)))),
        404
    );
    assert_eq!(blobs_of(&server.list("include=versions")).len(), 3);
    assert_eq!(status_of(server.get(&blob("a"))), 200);
}

#[test]
fn versions_of_a_block_blob_keep_their_block_lists() {
    let server = Emulator::versioned();
    server.create_container();
    let commit = |blocks: &[(&str, &[u8])]| {
        let mut list = String::from("<BlockList>");
        for (id, bytes) in blocks {
            let id = STANDARD.encode(id);
            let url = format!("{}?comp=block&blockid={}", blob("b"), encode(&id));
            assert_eq!(status_of(server.send(Method::PUT, &url, &[], bytes)), 201);
            list.push_str(&format!("<Latest>{id}</Latest>"));
        }
        list.push_str("</BlockList>");
        let response = server.send(
            Method::PUT,
            &format!("{}?comp=blocklist", blob("b")),
            &[],
            list.as_bytes(),
        );
        assert_eq!(response.status(), 201);
        header(&response, "x-ms-version-id")
    };
    let first = commit(&[("one", b"aaa"), ("two", b"bb")]);
    commit(&[("three", b"c")]);
    let old = server
        .get(&format!(
            "{}?comp=blocklist&versionid={}",
            blob("b"),
            encode(&first)
        ))
        .text()
        .unwrap();
    assert!(
        old.contains("<Size>3</Size>") && old.contains("<Size>2</Size>"),
        "{old}"
    );
    let body = server.get(&format!("{}?versionid={}", blob("b"), encode(&first)));
    assert_eq!(body.bytes().unwrap().as_ref(), b"aaabb");
}

#[test]
fn accounts_without_versioning_report_no_versions() {
    let server = Emulator::memory();
    server.create_container();
    let put = server.put("a", &[], b"v1");
    assert!(!put.headers().contains_key("x-ms-version-id"));
    server.put("a", &[], b"v2");
    assert!(
        !server
            .get(&blob("a"))
            .headers()
            .contains_key("x-ms-is-current-version")
    );
    let missing = server.get(&format!(
        "{}?versionid={}",
        blob("a"),
        encode("2001-01-01T00:00:00.0000000Z")
    ));
    assert_eq!(missing.status(), 404);
    assert_eq!(blobs_of(&server.list("include=versions")).len(), 1);
}

#[test]
fn versions_and_their_content_survive_restart() {
    let dir = tempfile::tempdir().unwrap();
    let args = ["--versioning-accounts", ACCOUNT];
    let id1 = {
        let server = Emulator::start(Some(dir.path()), &args);
        server.create_container();
        let id1 = header(&server.put("a", &[], b"first"), "x-ms-version-id");
        server.put("a", &[], b"second");
        id1
    };
    let server = Emulator::start(Some(dir.path()), &args);
    let old = server.get(&format!("{}?versionid={}", blob("a"), encode(&id1)));
    assert_eq!(old.bytes().unwrap().as_ref(), b"first");
    assert_eq!(server.get(&blob("a")).bytes().unwrap().as_ref(), b"second");
    let id3 = header(&server.put("a", &[], b"third"), "x-ms-version-id");
    assert_ne!(id1, id3);
    assert_eq!(blobs_of(&server.list("include=versions")).len(), 3);
}

#[test]
fn soft_deleted_blobs_are_listed_undeleted_and_expire_on_the_clock() {
    let server = Emulator::clocked();
    server.create_container();
    assert_eq!(
        status_of(server.send(
            Method::PUT,
            &format!("{}?comp=undelete", blob("a")),
            &[],
            b""
        )),
        404
    );
    server.set_retention(1);
    server.put(
        "a",
        &[("x-ms-meta-n", "1"), ("x-ms-tags", "k=v")],
        b"payload",
    );
    let snapshot = server.snapshot("a");
    let deleted = server.send(
        Method::DELETE,
        &blob("a"),
        &[("x-ms-delete-snapshots", "include")],
        b"",
    );
    assert_eq!(deleted.status(), 202);
    assert_eq!(header(&deleted, "x-ms-delete-type-permanent"), "false");
    assert_eq!(status_of(server.get(&blob("a"))), 404);
    let found = |server: &Emulator| {
        server
            .get(&format!(
                "/{ACCOUNT}?comp=blobs&where={}",
                encode("\"k\" = 'v'")
            ))
            .text()
            .unwrap()
            .contains("<Name>a</Name>")
    };
    assert!(!found(&server), "a deleted blob is not found by its tags");
    assert_eq!(
        status_of(server.get(&format!("{}?snapshot={}", blob("a"), encode(&snapshot)))),
        404,
        "a soft-deleted snapshot is not readable"
    );
    assert!(blobs_of(&server.list("include=snapshots")).is_empty());

    let xml = server.list("include=deleted,snapshots");
    assert_eq!(
        blobs_of(&xml),
        vec![
            ("a".into(), Some(snapshot.clone()), None),
            ("a".into(), None, None)
        ]
    );
    assert_eq!(xml.matches("<Deleted>true</Deleted>").count(), 2);
    assert_eq!(
        xml.matches("<RemainingRetentionDays>1</RemainingRetentionDays>")
            .count(),
        2
    );
    assert!(xml.contains("<DeletedTime>"));

    let restored = server.send(
        Method::PUT,
        &format!("{}?comp=undelete", blob("a")),
        &[],
        b"",
    );
    assert_eq!(restored.status(), 200);
    let back = server.get(&blob("a"));
    assert_eq!(header(&back, "x-ms-meta-n"), "1");
    assert_eq!(
        header(&back, "x-ms-tag-count"),
        "1",
        "tags come back with the blob"
    );
    assert!(found(&server));
    assert_eq!(back.bytes().unwrap().as_ref(), b"payload");
    let snap = server.get(&format!("{}?snapshot={}", blob("a"), encode(&snapshot)));
    assert_eq!(snap.bytes().unwrap().as_ref(), b"payload");
    assert!(
        !server
            .list("include=deleted,snapshots")
            .contains("<Deleted>")
    );
    assert_eq!(
        status_of(server.send(
            Method::PUT,
            &format!("{}?comp=undelete", blob("a")),
            &[],
            b""
        )),
        200,
        "undeleting a live blob succeeds"
    );

    server.send(
        Method::DELETE,
        &blob("a"),
        &[("x-ms-delete-snapshots", "include")],
        b"",
    );
    server.advance(86_400 + 60);
    assert!(blobs_of(&server.list("include=deleted,snapshots")).is_empty());
    assert_eq!(
        status_of(server.send(
            Method::PUT,
            &format!("{}?comp=undelete", blob("a")),
            &[],
            b""
        )),
        404
    );
}

#[test]
fn an_overwrite_keeps_a_soft_deleted_snapshot_and_a_deleted_blob_can_be_recreated() {
    let server = Emulator::clocked();
    server.create_container();
    server.set_retention(7);
    server.put("a", &[], b"one");
    server.put("a", &[], b"two");
    let xml = server.list("include=deleted,snapshots");
    let entries = blobs_of(&xml);
    assert_eq!(entries.len(), 2, "{xml}");
    assert!(entries[0].1.is_some() && entries[1].1.is_none());
    assert!(xml.contains("<Deleted>true</Deleted>"));
    server.send(Method::DELETE, &blob("a"), &[], b"");
    server.put("a", &[], b"three");
    server.send(Method::DELETE, &blob("a"), &[], b"");
    let restored = server.send(
        Method::PUT,
        &format!("{}?comp=undelete", blob("a")),
        &[],
        b"",
    );
    assert_eq!(restored.status(), 200);
    assert_eq!(server.get(&blob("a")).bytes().unwrap().as_ref(), b"three");
}

#[test]
fn tags_are_set_read_counted_conditioned_and_validated() {
    let server = Emulator::memory();
    server.create_container();
    let put = server.put(
        "a",
        &[("x-ms-tags", "Project=Azuifer&Env=Dev%20Box")],
        b"data",
    );
    assert_eq!(put.status(), 201);
    let head = server.send(Method::HEAD, &blob("a"), &[], b"");
    assert_eq!(header(&head, "x-ms-tag-count"), "2");
    assert_eq!(header(&server.get(&blob("a")), "x-ms-tag-count"), "2");
    let tags = server.get(&format!("{}?comp=tags", blob("a")));
    assert_eq!(tags.status(), 200);
    let xml = tags.text().unwrap();
    assert!(
        xml.contains("<Key>Env</Key><Value>Dev Box</Value>"),
        "{xml}"
    );
    assert!(xml.contains("<Key>Project</Key><Value>Azuifer</Value>"));

    let etag = header(&head, "etag");
    let replaced = set_tags(&server, "a", &[("Status", "Final")]);
    assert_eq!(replaced.status(), 204);
    let after = server.send(Method::HEAD, &blob("a"), &[], b"");
    assert_eq!(header(&after, "x-ms-tag-count"), "1");
    assert_eq!(header(&after, "etag"), etag, "tags do not change the ETag");

    let only = server
        .get(&format!("{}?comp=tags", blob("a")))
        .text()
        .unwrap();
    assert!(!only.contains("Project"));

    let eleven: Vec<(String, String)> = (0..11).map(|n| (format!("k{n}"), "v".into())).collect();
    let refs: Vec<(&str, &str)> = eleven
        .iter()
        .map(|(k, v)| (k.as_str(), v.as_str()))
        .collect();
    let too_many = set_tags(&server, "a", &refs);
    assert_eq!(too_many.status(), 400);
    assert_eq!(error_code(too_many), "TagsTooLarge");
    let bad = set_tags(&server, "a", &[("a", "semi;colon")]);
    assert_eq!(error_code(bad), "InvalidTag");
    let long = set_tags(&server, "a", &[(&"k".repeat(129), "v")]);
    assert_eq!(error_code(long), "TagsTooLarge");
    let dup = server.send(
        Method::PUT,
        &format!("{}?comp=tags", blob("a")),
        &[],
        b"<Tags><TagSet><Tag><Key>a</Key><Value>1</Value></Tag><Tag><Key>a</Key><Value>2</Value></Tag></TagSet></Tags>",
    );
    assert_eq!(dup.status(), 400);
    let header_limit = server.put("b", &[("x-ms-tags", "a=1&a=2")], b"x");
    assert_eq!(error_code(header_limit), "InvalidTag");
    assert_eq!(status_of(set_tags(&server, "missing", &[("a", "b")])), 404);

    let matching = server.send(
        Method::GET,
        &blob("a"),
        &[("x-ms-if-tags", "\"Status\" = 'Final'")],
        b"",
    );
    assert_eq!(matching.status(), 200);
    let failing = server.send(
        Method::GET,
        &blob("a"),
        &[("x-ms-if-tags", "\"Status\" = 'Draft'")],
        b"",
    );
    assert_eq!(failing.status(), 412);
    assert_eq!(error_code(failing), "ConditionNotMet");
    let guarded_delete = server.send(
        Method::DELETE,
        &blob("a"),
        &[("x-ms-if-tags", "\"Status\" > 'Z'")],
        b"",
    );
    assert_eq!(guarded_delete.status(), 412);
    let guarded_metadata = server.send(
        Method::PUT,
        &format!("{}?comp=metadata", blob("a")),
        &[("x-ms-if-tags", "\"Status\" = 'Final'")],
        b"",
    );
    assert_eq!(guarded_metadata.status(), 200);
    let guarded_tags = server.send(
        Method::PUT,
        &format!("{}?comp=tags", blob("a")),
        &[("x-ms-if-tags", "\"Status\" = 'Draft'")],
        tags_body(&[("x", "y")]).as_bytes(),
    );
    assert_eq!(guarded_tags.status(), 412);
    let malformed = server.send(
        Method::GET,
        &blob("a"),
        &[("x-ms-if-tags", "Status = Final")],
        b"",
    );
    assert_eq!(malformed.status(), 400);
    let unsupported = server.send(
        Method::PUT,
        &format!("{}?comp=tier", blob("a")),
        &[
            ("x-ms-access-tier", "Cool"),
            ("x-ms-if-tags", "\"Status\" = 'Final'"),
        ],
        b"",
    );
    assert_eq!(unsupported.status(), 501);

    assert_eq!(status_of(server.put("a", &[], b"overwritten")), 201);
    let cleared = server.send(Method::HEAD, &blob("a"), &[], b"");
    assert!(
        !cleared.headers().contains_key("x-ms-tag-count"),
        "an overwrite resets tags"
    );
}

#[test]
fn find_blobs_by_tags_filters_an_account_and_a_container() {
    let server = Emulator::memory();
    server.create_container();
    let other = server.send(
        Method::PUT,
        "/testaccount/second?restype=container",
        &[],
        b"",
    );
    assert_eq!(other.status(), 201);
    server.put("a", &[("x-ms-tags", "Project=alpha&Year=2019")], b"1");
    server.put("b", &[("x-ms-tags", "Project=alpha&Year=2021")], b"2");
    server.put("c", &[("x-ms-tags", "Project=beta&Year=2022")], b"3");
    server.put("plain", &[], b"4");
    let remote = server.send(
        Method::PUT,
        "/testaccount/second/z",
        &[
            ("x-ms-blob-type", "BlockBlob"),
            ("x-ms-tags", "Project=alpha"),
        ],
        b"5",
    );
    assert_eq!(remote.status(), 201);

    let find = |scope: &str, filter: &str, extra: &str| {
        let response = server.get(&format!(
            "{scope}comp=blobs&where={}{extra}",
            encode(filter)
        ));
        let status = response.status().as_u16();
        (status, response.text().unwrap())
    };
    let names = |xml: &str| {
        between(xml, "<Blob>", "</Blob>")
            .into_iter()
            .map(|blob| {
                format!(
                    "{}/{}",
                    between(blob, "<ContainerName>", "</ContainerName>")[0],
                    between(blob, "<Name>", "</Name>")[0]
                )
            })
            .collect::<Vec<_>>()
    };
    let (status, xml) = find("/testaccount?", "\"Project\" = 'alpha'", "");
    assert_eq!(status, 200, "{xml}");
    assert_eq!(names(&xml), ["container/a", "container/b", "second/z"]);
    assert!(
        xml.contains("<Where>\"Project\" = 'alpha'</Where>") || xml.contains("&quot;Project&quot;")
    );
    assert!(xml.contains("<Key>Year</Key><Value>2019</Value>"));
    let (_, ranged) = find(
        "/testaccount?",
        "\"Project\" = 'alpha' AND \"Year\" >= '2020'",
        "",
    );
    assert_eq!(names(&ranged), ["container/b"]);
    let (_, scoped) = find(
        "/testaccount?",
        "@container = 'second' AND \"Project\" = 'alpha'",
        "",
    );
    assert_eq!(names(&scoped), ["second/z"]);
    let (_, inside) = find(
        "/testaccount/container?restype=container&",
        "\"Year\" < '2022'",
        "",
    );
    assert_eq!(names(&inside), ["container/a", "container/b"]);
    let (_, none) = find("/testaccount?", "\"Project\" = 'gamma'", "");
    assert!(names(&none).is_empty());

    let (_, first) = find("/testaccount?", "\"Project\" = 'alpha'", "&maxresults=2");
    assert_eq!(names(&first), ["container/a", "container/b"]);
    let marker = between(&first, "<NextMarker>", "</NextMarker>")[0].to_owned();
    assert!(!marker.is_empty());
    let (_, second) = find(
        "/testaccount?",
        "\"Project\" = 'alpha'",
        &format!("&maxresults=2&marker={}", encode(&marker)),
    );
    assert_eq!(names(&second), ["second/z"]);
    assert!(
        between(&second, "<NextMarker>", "</NextMarker>")
            .first()
            .is_none_or(|m| m.is_empty())
    );

    assert_eq!(
        set_tags(&server, "c", &[("Project", "alpha")]).status(),
        204
    );
    let (_, updated) = find("/testaccount?", "\"Project\" = 'alpha'", "");
    assert_eq!(
        names(&updated),
        ["container/a", "container/b", "container/c", "second/z"]
    );
    assert_eq!(
        status_of(server.send(Method::DELETE, &blob("a"), &[], b"")),
        202
    );
    let (_, deleted) = find("/testaccount?", "\"Project\" = 'alpha'", "");
    assert_eq!(names(&deleted), ["container/b", "container/c", "second/z"]);

    for bad in [
        "\"Project\" = 'a' OR \"Year\" = '1'",
        "Project = 'a'",
        "\"Project\" != 'a'",
        "",
    ] {
        let (status, _) = find("/testaccount?", bad, "");
        assert_eq!(status, 400, "{bad}");
    }
    let (status, _) = find(
        "/testaccount/container?restype=container&",
        "@container = 'container'",
        "",
    );
    assert_eq!(status, 400, "@container is not valid inside a container");
    assert_eq!(status_of(server.get("/testaccount?comp=blobs")), 400);
}

#[test]
fn listings_can_include_tags() {
    let server = Emulator::memory();
    server.create_container();
    server.put("a", &[("x-ms-tags", "k=v")], b"1");
    server.put("b", &[], b"2");
    let xml = server.list("include=tags");
    assert!(xml.contains("<TagCount>1</TagCount>"));
    assert_eq!(xml.matches("<Tags>").count(), 1);
    assert!(xml.contains("<Key>k</Key><Value>v</Value>"));
}

#[test]
fn tags_follow_versions_in_a_versioned_account() {
    let server = Emulator::versioned();
    server.create_container();
    let first = server.put("a", &[("x-ms-tags", "gen=one")], b"1");
    let id1 = header(&first, "x-ms-version-id");
    server.put("a", &[("x-ms-tags", "gen=two")], b"2");
    let old = server
        .get(&format!(
            "{}?comp=tags&versionid={}",
            blob("a"),
            encode(&id1)
        ))
        .text()
        .unwrap();
    assert!(old.contains("<Value>one</Value>"), "{old}");
    assert!(
        server
            .get(&format!("{}?comp=tags", blob("a")))
            .text()
            .unwrap()
            .contains("<Value>two</Value>")
    );
    let retag = server.send(
        Method::PUT,
        &format!("{}?comp=tags&versionid={}", blob("a"), encode(&id1)),
        &[],
        tags_body(&[("gen", "uno")]).as_bytes(),
    );
    assert_eq!(retag.status(), 204);
    let found = server
        .get(&format!(
            "/testaccount?comp=blobs&where={}",
            encode("\"gen\" = 'two'")
        ))
        .text()
        .unwrap();
    assert!(found.contains("<Name>a</Name>"));
    let snapshot = server.snapshot("a");
    let tags_of_snapshot = server.get(&format!(
        "{}?comp=tags&snapshot={}",
        blob("a"),
        encode(&snapshot)
    ));
    assert_eq!(tags_of_snapshot.status(), 501);
}

fn batch_part(index: usize, request: &str) -> String {
    format!(
        "--batch_test\r\nContent-Type: application/http\r\nContent-Transfer-Encoding: binary\r\nContent-ID: {index}\r\n\r\n{request}\r\n"
    )
}

/// A sub-request line and headers; `sign` adds Shared Key credentials for it.
fn subrequest(method: Method, path: &str, extra: &[(&str, &str)], sign: bool) -> String {
    let mut text = format!("{method} {path} HTTP/1.1\r\n");
    if sign {
        let url = Url::parse(&format!("http://127.0.0.1{path}")).unwrap();
        for (name, value) in signed(&method, &url, extra, Some(0), false) {
            text.push_str(&format!("{name}: {value}\r\n"));
        }
    } else {
        for (name, value) in extra {
            text.push_str(&format!("{name}: {value}\r\n"));
        }
        text.push_str("content-length: 0\r\n");
    }
    text.push_str("\r\n");
    text
}

fn submit(server: &Emulator, path: &str, parts: &[String]) -> Response {
    let mut body: String = parts.concat();
    body.push_str("--batch_test--\r\n");
    server.send(
        Method::POST,
        path,
        &[("content-type", "multipart/mixed; boundary=batch_test")],
        body.as_bytes(),
    )
}

/// `(Content-ID, status, error code)` of each part of a batch response.
fn batch_results(text: &str) -> Vec<(String, u16, String)> {
    text.split("--batchresponse_")
        .skip(1)
        .filter(|part| part.contains("Content-ID"))
        .map(|part| {
            let id = between(part, "Content-ID: ", "\r\n")[0].to_owned();
            let status: u16 = between(part, "HTTP/1.1 ", " ")[0].parse().unwrap();
            let code = between(part, "x-ms-error-code: ", "\r\n")
                .first()
                .map(|code| (*code).to_owned())
                .unwrap_or_default();
            (id, status, code)
        })
        .collect()
}

#[test]
fn a_batch_of_deletes_reports_each_item_and_authorizes_them_separately() {
    let server = Emulator::memory();
    server.create_container();
    for name in ["a", "b", "keep", "unsigned"] {
        server.put(name, &[], b"x");
    }
    let parts = [
        batch_part(0, &subrequest(Method::DELETE, &blob("a"), &[], true)),
        batch_part(1, &subrequest(Method::DELETE, &blob("b"), &[], true)),
        batch_part(2, &subrequest(Method::DELETE, &blob("absent"), &[], true)),
        batch_part(
            3,
            &subrequest(Method::DELETE, &blob("unsigned"), &[], false),
        ),
        batch_part(
            4,
            &subrequest(
                Method::DELETE,
                &blob("keep"),
                &[("authorization", "SharedKey testaccount:AAAA")],
                false,
            ),
        ),
    ];
    let response = submit(&server, &format!("/{ACCOUNT}?comp=batch"), &parts);
    assert_eq!(response.status(), 202);
    assert!(
        header(&response, "content-type").starts_with("multipart/mixed; boundary=batchresponse_")
    );
    let text = response.text().unwrap();
    assert_eq!(
        batch_results(&text),
        vec![
            ("0".into(), 202, String::new()),
            ("1".into(), 202, String::new()),
            ("2".into(), 404, "BlobNotFound".into()),
            ("3".into(), 403, "AuthenticationFailed".into()),
            ("4".into(), 403, "AuthenticationFailed".into()),
        ],
        "{text}"
    );
    assert!(text.trim_end().ends_with("--"));
    assert_eq!(status_of(server.get(&blob("a"))), 404);
    assert_eq!(status_of(server.get(&blob("b"))), 404);
    assert_eq!(status_of(server.get(&blob("keep"))), 200);
    assert_eq!(status_of(server.get(&blob("unsigned"))), 200);
}

#[test]
fn a_batch_can_delete_snapshots_set_tiers_and_is_scoped_to_a_container() {
    let server = Emulator::memory();
    server.create_container();
    server.put("a", &[], b"x");
    let snapshot = server.snapshot("a");
    let by_snapshot = format!("{}?snapshot={}", blob("a"), encode(&snapshot));
    let deleted = submit(
        &server,
        &format!("{CONTAINER}?restype=container&comp=batch"),
        &[
            batch_part(0, &subrequest(Method::DELETE, &by_snapshot, &[], true)),
            batch_part(1, &subrequest(Method::DELETE, &blob("a"), &[], true)),
        ],
    );
    assert_eq!(deleted.status(), 202);
    let results = batch_results(&deleted.text().unwrap());
    assert_eq!(results[0].1, 202);
    assert_eq!(results[1].1, 202);
    assert_eq!(status_of(server.get(&by_snapshot)), 404);

    server.put("t", &[], b"x");
    let tier = |name: &str| {
        subrequest(
            Method::PUT,
            &format!("{}?comp=tier", blob(name)),
            &[("x-ms-access-tier", "Cool")],
            true,
        )
    };
    let tiered = submit(
        &server,
        &format!("/{ACCOUNT}?comp=batch"),
        &[batch_part(0, &tier("t")), batch_part(1, &tier("absent"))],
    );
    assert_eq!(tiered.status(), 202);
    let results = batch_results(&tiered.text().unwrap());
    assert_eq!((results[0].1, results[1].1), (200, 404));
    let head = server.send(Method::HEAD, &blob("t"), &[], b"");
    assert_eq!(header(&head, "x-ms-access-tier"), "Cool");

    let other = server.send(
        Method::PUT,
        "/testaccount/second?restype=container",
        &[],
        b"",
    );
    assert_eq!(other.status(), 201);
    server.send(
        Method::PUT,
        "/testaccount/second/z",
        &[("x-ms-blob-type", "BlockBlob")],
        b"x",
    );
    let scoped = submit(
        &server,
        &format!("{CONTAINER}?restype=container&comp=batch"),
        &[batch_part(
            0,
            &subrequest(Method::DELETE, "/testaccount/second/z", &[], true),
        )],
    );
    assert_eq!(scoped.status(), 202);
    assert_eq!(batch_results(&scoped.text().unwrap())[0].1, 400);
    assert_eq!(status_of(server.get("/testaccount/second/z")), 200);
}

#[test]
fn malformed_oversized_or_mixed_batches_are_rejected() {
    let server = Emulator::memory();
    server.create_container();
    let url = format!("/{ACCOUNT}?comp=batch");
    let item = |index: usize| batch_part(index, &subrequest(Method::DELETE, &blob("x"), &[], true));
    let many: Vec<String> = (0..257).map(item).collect();
    let too_many = submit(&server, &url, &many);
    assert_eq!(too_many.status(), 400);
    assert_eq!(error_code(too_many), "InvalidInput");
    let limit: Vec<String> = (0..256).map(item).collect();
    let at_limit = submit(&server, &url, &limit);
    assert_eq!(at_limit.status(), 202);
    assert_eq!(batch_results(&at_limit.text().unwrap()).len(), 256);

    let mixed = submit(
        &server,
        &url,
        &[
            item(0),
            batch_part(
                1,
                &subrequest(
                    Method::PUT,
                    &format!("{}?comp=tier", blob("x")),
                    &[("x-ms-access-tier", "Cool")],
                    true,
                ),
            ),
        ],
    );
    assert_eq!(mixed.status(), 400);
    let unsupported = submit(
        &server,
        &url,
        &[batch_part(
            0,
            &subrequest(Method::GET, &blob("x"), &[], true),
        )],
    );
    assert_eq!(unsupported.status(), 400);
    let empty = submit(&server, &url, &[]);
    assert_eq!(empty.status(), 400);
    let no_boundary = server.send(Method::POST, &url, &[("content-type", "text/plain")], b"x");
    assert_eq!(no_boundary.status(), 400);
    let anonymous = server
        .client
        .post(format!("{}{url}", server.blob))
        .header("content-type", "multipart/mixed; boundary=batch_test")
        .body("--batch_test--\r\n")
        .send()
        .unwrap();
    assert_eq!(
        anonymous.status(),
        403,
        "the batch itself must be authorized"
    );
}

#[test]
fn a_data_directory_from_before_snapshots_gains_versions_tags_and_snapshots() {
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
             INSERT INTO blobs VALUES ('testaccount', 'container', 'legacy', x'22222222222222222222222222222222', 1700000001, 5, 'text/old', '', '{}', NULL);",
        )
        .unwrap();
        db.pragma_update(None, "journal_mode", "WAL").unwrap();
    }
    fs::write(
        content.join("extent-22222222222222222222222222222222"),
        b"hello",
    )
    .unwrap();
    let args = ["--versioning-accounts", ACCOUNT];
    let legacy_version = {
        let server = Emulator::start(Some(location.path()), &args);
        assert_eq!(
            server.get(&blob("legacy")).bytes().unwrap().as_ref(),
            b"hello"
        );
        let snapshot = server.snapshot("legacy");
        let replaced = server.put("legacy", &[("x-ms-tags", "from=test")], b"updated");
        assert!(replaced.headers().contains_key("x-ms-version-id"));
        let by_snapshot = server.get(&format!(
            "{}?snapshot={}",
            blob("legacy"),
            encode(&snapshot)
        ));
        assert_eq!(by_snapshot.bytes().unwrap().as_ref(), b"hello");
        let versions = blobs_of(&server.list("include=versions"));
        assert_eq!(
            versions.len(),
            2,
            "the legacy state becomes a version: {versions:?}"
        );
        versions[0].2.clone().unwrap()
    };
    let server = Emulator::start(Some(location.path()), &args);
    let old = server.get(&format!(
        "{}?versionid={}",
        blob("legacy"),
        encode(&legacy_version)
    ));
    assert_eq!(old.bytes().unwrap().as_ref(), b"hello");
    assert_eq!(
        header(
            &server.send(Method::HEAD, &blob("legacy"), &[], b""),
            "x-ms-tag-count"
        ),
        "1"
    );
}

#[test]
fn the_versioning_option_validates_account_names() {
    let validate = |value: &str| {
        command()
            .args(["config", "validate", "--versioning-accounts", value])
            .output()
            .unwrap()
            .status
            .success()
    };
    assert!(validate(ACCOUNT));
    assert!(validate(""));
    assert!(!validate("unconfigured"));
    assert!(!validate("testaccount,testaccount"));
    assert!(!validate("Bad_Name"));
    let from_env = command()
        .env("AZUIFER_VERSIONING_ACCOUNTS", "unconfigured")
        .args(["config", "validate"])
        .output()
        .unwrap();
    assert!(!from_env.status.success());
}

/// The records of a Query Blob Contents Avro stream: the concatenated result data, the
/// `end` total, and any `error` record as `(fatal, name, description, position)`.
struct Queried {
    data: String,
    total: Option<i64>,
    error: Option<(bool, String, String, i64)>,
    progress: usize,
}

fn decode_query(bytes: &[u8]) -> Queried {
    fn long(bytes: &[u8], at: &mut usize) -> i64 {
        let (mut value, mut shift) = (0u64, 0);
        loop {
            let byte = bytes[*at];
            *at += 1;
            value |= u64::from(byte & 0x7f) << shift;
            if byte & 0x80 == 0 {
                return ((value >> 1) as i64) ^ -((value & 1) as i64);
            }
            shift += 7;
        }
    }
    fn blob(bytes: &[u8], at: &mut usize) -> Vec<u8> {
        let length = long(bytes, at) as usize;
        *at += length;
        bytes[*at - length..*at].to_vec()
    }
    assert_eq!(&bytes[..4], b"Obj\x01");
    let mut at = 4;
    let mut schema = String::new();
    loop {
        let count = long(bytes, &mut at);
        if count == 0 {
            break;
        }
        for _ in 0..count {
            let key = blob(bytes, &mut at);
            let value = blob(bytes, &mut at);
            if key == b"avro.schema" {
                schema = String::from_utf8(value).unwrap();
            }
        }
    }
    assert!(schema.contains("com.microsoft.azure.storage.queryBlobContents"));
    let sync = bytes[at..at + 16].to_vec();
    at += 16;
    let mut out = Queried {
        data: String::new(),
        total: None,
        error: None,
        progress: 0,
    };
    let records = long(bytes, &mut at);
    let size = long(bytes, &mut at) as usize;
    let end = at + size;
    assert_eq!(
        &bytes[end..end + 16],
        &sync[..],
        "sync marker closes the block"
    );
    for _ in 0..records {
        match long(bytes, &mut at) {
            0 => out
                .data
                .push_str(&String::from_utf8(blob(bytes, &mut at)).unwrap()),
            1 => {
                long(bytes, &mut at);
                long(bytes, &mut at);
                out.progress += 1;
            }
            2 => out.total = Some(long(bytes, &mut at)),
            3 => {
                let fatal = bytes[at] == 1;
                at += 1;
                let name = String::from_utf8(blob(bytes, &mut at)).unwrap();
                let description = String::from_utf8(blob(bytes, &mut at)).unwrap();
                out.error = Some((fatal, name, description, long(bytes, &mut at)));
            }
            other => panic!("unknown union branch {other}"),
        }
    }
    assert_eq!(at, end);
    out
}

fn query_body(expression: &str, input: &str, output: &str) -> String {
    format!(
        "<QueryRequest><QueryType>SQL</QueryType><Expression>{expression}</Expression>\
         <InputSerialization>{input}</InputSerialization>\
         <OutputSerialization>{output}</OutputSerialization></QueryRequest>"
    )
}

const CSV_WITH_HEADERS: &str = "<Format><Type>delimited</Type><DelimitedTextConfiguration>\
    <ColumnSeparator>,</ColumnSeparator><FieldQuote>\"</FieldQuote><RecordSeparator>\n</RecordSeparator>\
    <HasHeaders>true</HasHeaders></DelimitedTextConfiguration></Format>";
const CSV_PLAIN: &str = "<Format><Type>delimited</Type><DelimitedTextConfiguration>\
    <ColumnSeparator>,</ColumnSeparator><RecordSeparator>\n</RecordSeparator>\
    </DelimitedTextConfiguration></Format>";
const JSON_LINES: &str = "<Format><Type>json</Type><JsonTextConfiguration>\
    <RecordSeparator>\n</RecordSeparator></JsonTextConfiguration></Format>";

#[test]
fn query_blob_contents_runs_sql_over_csv_and_json_and_streams_avro() {
    let server = Emulator::memory();
    server.create_container();
    let csv = "name,age\nann,31\nbob,25\ncy,40\n";
    assert_eq!(server.put("people.csv", &[], csv.as_bytes()).status(), 201);
    let query = |name: &str, extra: &str, body: String| {
        server.send(
            Method::POST,
            &format!("{}?comp=query{extra}", blob(name)),
            &[],
            body.as_bytes(),
        )
    };

    let response = query(
        "people.csv",
        "",
        query_body(
            "SELECT name FROM BlobStorage WHERE age &gt; 30",
            CSV_WITH_HEADERS,
            CSV_PLAIN,
        ),
    );
    assert_eq!(response.status(), 200);
    assert_eq!(
        header(&response, "content-type"),
        "application/octet-stream"
    );
    let length = header(&response, "content-length");
    let bytes = response.bytes().unwrap();
    assert_eq!(length, bytes.len().to_string());
    let rows = decode_query(&bytes);
    assert_eq!(rows.data, "ann\ncy\n");
    assert_eq!(rows.total, Some(csv.len() as i64));
    assert!(
        rows.progress >= 1,
        "SDKs read the first record unconditionally"
    );
    assert!(rows.error.is_none());

    let positional = decode_query(
        &query(
            "people.csv",
            "",
            query_body(
                "SELECT _1, _2 FROM BlobStorage LIMIT 2",
                CSV_PLAIN,
                JSON_LINES,
            ),
        )
        .bytes()
        .unwrap(),
    );
    assert_eq!(
        positional.data,
        "{\"_1\":\"name\",\"_2\":\"age\"}\n{\"_1\":\"ann\",\"_2\":\"31\"}\n"
    );

    let count = decode_query(
        &query(
            "people.csv",
            "",
            query_body(
                "SELECT COUNT(*) AS n, MAX(CAST(age AS INT)) FROM BlobStorage WHERE age &lt; 41",
                CSV_WITH_HEADERS,
                CSV_PLAIN,
            ),
        )
        .bytes()
        .unwrap(),
    );
    assert_eq!(count.data, "3,40\n");

    assert_eq!(
        server
            .put(
                "events.json",
                &[],
                b"{\"a\":1,\"b\":{\"c\":\"x\"}}\n{\"a\":2,\"b\":{\"c\":\"y\"}}"
            )
            .status(),
        201
    );
    let json = decode_query(
        &query(
            "events.json",
            "",
            query_body(
                "SELECT s.b.c AS c, s.a + 10 AS shifted FROM BlobStorage s WHERE s.a = 2",
                JSON_LINES,
                JSON_LINES,
            ),
        )
        .bytes()
        .unwrap(),
    );
    assert_eq!(json.data, "{\"c\":\"y\",\"shifted\":12}\n");

    let failed = decode_query(
        &query(
            "people.csv",
            "",
            query_body(
                "SELECT CAST(name AS INT) FROM BlobStorage",
                CSV_WITH_HEADERS,
                CSV_PLAIN,
            ),
        )
        .bytes()
        .unwrap(),
    );
    let (fatal, name, _, position) = failed.error.expect("a runtime failure is an error record");
    assert!(fatal);
    assert_eq!(name, "CastFailed");
    assert_eq!(position, 0);
    assert_eq!(failed.total, Some(csv.len() as i64));
}

#[test]
fn query_blob_contents_reads_snapshots_and_rejects_bad_requests() {
    let server = Emulator::memory();
    server.create_container();
    assert_eq!(server.put("data.csv", &[], b"old\n").status(), 201);
    let snapshot = server.snapshot("data.csv");
    assert_eq!(server.put("data.csv", &[], b"new\n").status(), 201);
    let run = |name: &str, extra: &str, body: String| {
        server.send(
            Method::POST,
            &format!("{}?comp=query{extra}", blob(name)),
            &[],
            body.as_bytes(),
        )
    };
    let select = || query_body("SELECT _1 FROM BlobStorage", CSV_PLAIN, CSV_PLAIN);

    let old = run(
        "data.csv",
        &format!("&snapshot={}", encode(&snapshot)),
        select(),
    );
    assert_eq!(old.status(), 200);
    assert_eq!(decode_query(&old.bytes().unwrap()).data, "old\n");
    let current = run("data.csv", "", select());
    assert_eq!(decode_query(&current.bytes().unwrap()).data, "new\n");

    let syntax = run(
        "data.csv",
        "",
        query_body("SELEC _1 FROM BlobStorage", CSV_PLAIN, CSV_PLAIN),
    );
    assert_eq!(syntax.status(), 400);
    assert_eq!(error_code(syntax), "ParseError");
    let parquet = run(
        "data.csv",
        "",
        query_body(
            "SELECT * FROM BlobStorage",
            "<Format><Type>parquet</Type></Format>",
            CSV_PLAIN,
        ),
    );
    assert_eq!(status_of(parquet), 501);
    assert_eq!(
        status_of(run("data.csv", "", "<QueryRequest/>".into())),
        400
    );
    assert_eq!(status_of(run("missing.csv", "", select())), 404);
}
