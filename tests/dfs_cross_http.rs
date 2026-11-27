//! Blob/DFS interoperability on the shared namespace (ADR-0003, ADR-0020): Blob writes
//! read through DFS and DFS writes read through Blob with the same bytes and ETag, a
//! directory rename is atomic for concurrent Blob listings, and leases and restarts stay
//! coherent across both protocols. DFS operation details are in `dfs_http.rs`.

use base64::{Engine as _, engine::general_purpose::STANDARD};
use hmac::{Hmac, Mac as _};
use reqwest::{
    Method, Url,
    blocking::{Client, Response},
};
use sha2::Sha256;
use std::{
    collections::BTreeMap,
    io::{BufRead as _, BufReader},
    path::Path,
    process::{Child, Command, Stdio},
    sync::{
        atomic::{AtomicBool, AtomicU64, Ordering},
        mpsc,
    },
    thread,
    time::{Duration, Instant, SystemTime},
};

const ACCOUNT: &str = "testaccount";
const VERSION: &str = "2023-11-03";
const KEY: [u8; 32] = [41; 32];
const LAKE: &str = "/testaccount/lake";

struct Emulator {
    child: Child,
    blob: String,
    dfs: String,
    admin: String,
    client: Client,
    offset: AtomicU64,
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

impl Emulator {
    fn start(location: Option<&Path>) -> Self {
        Self::launch(location, &[])
    }

    /// An in-memory emulator whose Blob and DFS listeners share a clock the test advances.
    fn start_with_clock() -> Self {
        Self::launch(None, &["--test-clock"])
    }

    fn launch(location: Option<&Path>, extra: &[&str]) -> Self {
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
                "blob,dfs",
                "--hns-accounts",
                ACCOUNT,
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
            .spawn()
            .expect("start Azuifer");
        let stdout = child.stdout.take().expect("piped startup addresses");
        let (sender, receiver) = mpsc::channel();
        thread::spawn(move || {
            let mut urls = BTreeMap::new();
            for line in BufReader::new(stdout).lines().map_while(Result::ok) {
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
            .recv_timeout(Duration::from_secs(20))
            .expect("server bound its ports");
        Self {
            child,
            blob: urls.remove("blob").expect("blob listener"),
            dfs: urls.remove("dfs").expect("dfs listener"),
            admin: urls.remove("admin").expect("admin listener"),
            client: Client::builder()
                .no_proxy()
                .timeout(Duration::from_secs(30))
                .build()
                .unwrap(),
            offset: AtomicU64::new(0),
        }
    }

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
        self.offset.fetch_add(seconds, Ordering::Relaxed);
    }

    fn send(
        &self,
        base: &str,
        method: &str,
        path: &str,
        headers: &[(&str, &str)],
        body: &[u8],
    ) -> Response {
        let method = Method::from_bytes(method.as_bytes()).unwrap();
        let url = Url::parse(&format!("{base}{path}")).unwrap();
        let has_body = matches!(method.as_str(), "PUT" | "PATCH" | "POST");
        let mut request = self.client.request(method.clone(), url.clone());
        for (name, value) in shared_key(
            method.as_str(),
            &url,
            headers,
            has_body.then_some(body.len()),
            SystemTime::now() + Duration::from_secs(self.offset.load(Ordering::Relaxed)),
        ) {
            request = request.header(name, value);
        }
        if has_body {
            request = request.body(body.to_vec());
        }
        request.send().expect("HTTP request completed")
    }

    fn dfs(&self, method: &str, path: &str, headers: &[(&str, &str)], body: &[u8]) -> Response {
        self.send(&self.dfs, method, path, headers, body)
    }

    fn blob(&self, method: &str, path: &str, headers: &[(&str, &str)], body: &[u8]) -> Response {
        self.send(&self.blob, method, path, headers, body)
    }

    fn filesystem(&self) {
        assert_eq!(
            self.dfs("PUT", &format!("{LAKE}?resource=filesystem"), &[], b"")
                .status(),
            201
        );
    }

    fn put_blob(&self, name: &str, headers: &[(&str, &str)], body: &[u8]) -> Response {
        let mut all = vec![("x-ms-blob-type", "BlockBlob")];
        all.extend_from_slice(headers);
        let response = self.blob("PUT", &format!("{LAKE}/{name}"), &all, body);
        assert_eq!(response.status(), 201, "put {name}");
        response
    }

    fn dfs_file(&self, name: &str, content: &[u8]) -> Response {
        let url = format!("{LAKE}/{name}");
        assert_eq!(
            self.dfs("PUT", &format!("{url}?resource=file"), &[], b"")
                .status(),
            201
        );
        assert_eq!(
            self.dfs(
                "PATCH",
                &format!("{url}?action=append&position=0"),
                &[],
                content
            )
            .status(),
            202
        );
        let flushed = self.dfs(
            "PATCH",
            &format!("{url}?action=flush&position={}", content.len()),
            &[],
            b"",
        );
        assert_eq!(flushed.status(), 200);
        flushed
    }
}

fn shared_key(
    method: &str,
    url: &Url,
    extra: &[(&str, &str)],
    length: Option<usize>,
    now: SystemTime,
) -> BTreeMap<String, String> {
    let mut headers: BTreeMap<String, String> = BTreeMap::from([
        ("x-ms-date".into(), httpdate::fmt_http_date(now)),
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
        method,
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
    let query: BTreeMap<_, _> = url
        .query_pairs()
        .map(|(name, value)| (name.to_ascii_lowercase(), value))
        .collect();
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

fn etag(response: &Response) -> String {
    response.headers()["etag"].to_str().unwrap().to_owned()
}

fn header(response: &Response, name: &str) -> String {
    response
        .headers()
        .get(name)
        .unwrap_or_else(|| panic!("missing {name}"))
        .to_str()
        .unwrap()
        .to_owned()
}

fn dfs_error(response: Response, status: u16, code: &str) {
    assert_eq!(response.status().as_u16(), status, "{code}");
    assert_eq!(response.headers()["x-ms-error-code"], code);
}

#[test]
fn blob_writes_read_through_dfs_and_dfs_writes_read_through_blob() {
    let server = Emulator::start(None);
    server.filesystem();
    let written = server.put_blob(
        "a/b.txt",
        &[("content-type", "text/plain"), ("x-ms-meta-origin", "blob")],
        b"from blob",
    );
    let as_file = server.dfs("GET", &format!("{LAKE}/a/b.txt"), &[], b"");
    assert_eq!(etag(&as_file), etag(&written));
    assert_eq!(header(&as_file, "content-type"), "text/plain");
    assert_eq!(header(&as_file, "x-ms-properties"), "origin=YmxvYg==");
    assert_eq!(header(&as_file, "x-ms-resource-type"), "file");
    assert_eq!(as_file.bytes().unwrap().as_ref(), b"from blob");
    let parent = server.dfs("HEAD", &format!("{LAKE}/a"), &[], b"");
    assert_eq!(header(&parent, "x-ms-resource-type"), "directory");

    let flushed = server.dfs_file("c/d.bin", &[7u8; 5000]);
    let as_blob = server.blob("GET", &format!("{LAKE}/c/d.bin"), &[], b"");
    assert_eq!(etag(&as_blob), etag(&flushed));
    assert_eq!(header(&as_blob, "x-ms-blob-type"), "BlockBlob");
    assert_eq!(header(&as_blob, "content-length"), "5000");
    assert_eq!(as_blob.bytes().unwrap().as_ref(), &[7u8; 5000][..]);
    let listing = server
        .blob(
            "GET",
            &format!("{LAKE}?restype=container&comp=list"),
            &[],
            b"",
        )
        .text()
        .unwrap();
    for name in ["a", "a/b.txt", "c", "c/d.bin"] {
        assert!(
            listing.contains(&format!("<Name>{name}</Name>")),
            "{name}: {listing}"
        );
    }
    assert!(listing.contains("<Content-Length>5000</Content-Length>"));

    // Blob property and content changes show through DFS with the new ETag.
    let metadata = server.blob(
        "PUT",
        &format!("{LAKE}/c/d.bin?comp=metadata"),
        &[("x-ms-meta-stage", "two")],
        b"",
    );
    assert_eq!(metadata.status(), 200);
    let after = server.dfs("HEAD", &format!("{LAKE}/c/d.bin"), &[], b"");
    assert_eq!(etag(&after), etag(&metadata));
    assert_eq!(header(&after, "x-ms-properties"), "stage=dHdv");
    server.put_blob("c/d.bin", &[], b"replaced by blob");
    assert_eq!(
        server
            .dfs("GET", &format!("{LAKE}/c/d.bin"), &[], b"")
            .bytes()
            .unwrap()
            .as_ref(),
        b"replaced by blob"
    );
}

#[test]
fn dfs_reads_a_blob_with_the_same_range_checksum_and_date_conditions_as_blob() {
    let server = Emulator::start(None);
    server.filesystem();
    let written = server.put_blob("r/data.bin", &[], b"0123456789");
    let modified = header(&written, "last-modified");
    let file = format!("{LAKE}/r/data.bin");
    let range = [("range", "bytes=2-5")];
    let with_md5 = [
        ("range", "bytes=2-5"),
        ("x-ms-range-get-content-md5", "true"),
    ];

    let blob = server.blob("GET", &file, &with_md5, b"");
    let dfs = server.dfs("GET", &file, &with_md5, b"");
    assert_eq!((blob.status().as_u16(), dfs.status().as_u16()), (206, 206));
    let checksum = header(&dfs, "content-md5");
    assert_eq!(checksum, header(&blob, "content-md5"));
    assert_eq!(checksum.len(), 24, "base64 of a 16 byte MD5");
    assert_eq!(header(&dfs, "content-range"), "bytes 2-5/10");
    assert_eq!(dfs.bytes().unwrap().as_ref(), b"2345");

    let plain = server.dfs("GET", &file, &range, b"");
    assert_eq!(plain.status(), 206);
    assert!(!plain.headers().contains_key("content-md5"));

    // A whole-file read carries no range checksum unless asked, and asking needs a range.
    dfs_error(
        server.dfs("GET", &file, &[("x-ms-range-get-content-md5", "true")], b""),
        400,
        "InvalidHeaderValue",
    );
    // A range of more than 4 MiB cannot have a checksum.
    server.put_blob("r/large.bin", &[], &vec![1u8; 4 * 1024 * 1024 + 1]);
    dfs_error(
        server.dfs(
            "GET",
            &format!("{LAKE}/r/large.bin"),
            &[
                ("range", "bytes=0-4194304"),
                ("x-ms-range-get-content-md5", "true"),
            ],
            b"",
        ),
        400,
        "InvalidHeaderValue",
    );

    // Date conditions answer alike on both protocols.
    let long_ago = "Mon, 01 Jan 2001 00:00:00 GMT";
    let far_future = "Fri, 01 Jan 2100 00:00:00 GMT";
    for (condition, value, status) in [
        ("if-modified-since", modified.as_str(), 304),
        ("if-modified-since", long_ago, 200),
        ("if-unmodified-since", long_ago, 412),
        ("if-unmodified-since", far_future, 200),
    ] {
        let headers = [(condition, value)];
        let blob = server.blob("GET", &file, &headers, b"").status();
        let dfs = server.dfs("GET", &file, &headers, b"");
        assert_eq!(blob.as_u16(), status, "blob {condition} {value}");
        assert_eq!(dfs.status().as_u16(), status, "dfs {condition} {value}");
        if status == 412 {
            assert_eq!(dfs.headers()["x-ms-error-code"], "ConditionNotMet");
        }
    }
}

#[test]
fn dfs_create_path_expiry_is_seen_by_blob_and_expires_on_the_shared_clock() {
    let server = Emulator::start_with_clock();
    server.filesystem();
    let create = |name: &str, headers: &[(&str, &str)], content: &[u8]| {
        let url = format!("{LAKE}/{name}");
        let created = server.dfs("PUT", &format!("{url}?resource=file"), headers, b"");
        assert_eq!(created.status(), 201, "create {name}");
        let appended = server.dfs(
            "PATCH",
            &format!("{url}?action=append&position=0"),
            &[],
            content,
        );
        assert_eq!(appended.status(), 202);
        let flushed = server.dfs(
            "PATCH",
            &format!("{url}?action=flush&position={}", content.len()),
            &[],
            b"",
        );
        assert_eq!(flushed.status(), 200);
    };
    let absolute = httpdate::fmt_http_date(SystemTime::now() + Duration::from_secs(300));
    create(
        "ttl/relative.txt",
        &[
            ("x-ms-expiry-option", "RelativeToNow"),
            ("x-ms-expiry-time", "60000"),
        ],
        b"relative",
    );
    create(
        "ttl/absolute.txt",
        &[
            ("x-ms-expiry-option", "Absolute"),
            ("x-ms-expiry-time", &absolute),
        ],
        b"absolute",
    );
    create(
        "ttl/never.txt",
        &[("x-ms-expiry-option", "NeverExpire")],
        b"never",
    );
    create("ttl/plain.txt", &[], b"plain");

    // Blob sees the deadline DFS set, and the content flushed afterwards keeps it.
    let relative = server.blob("HEAD", &format!("{LAKE}/ttl/relative.txt"), &[], b"");
    assert_eq!(relative.status(), 200);
    assert_eq!(header(&relative, "content-length"), "8");
    let deadline = header(&relative, "x-ms-expiry-time");
    let absolute_head = server.blob("HEAD", &format!("{LAKE}/ttl/absolute.txt"), &[], b"");
    assert_eq!(header(&absolute_head, "x-ms-expiry-time"), absolute);
    for name in ["never", "plain"] {
        let head = server.blob("HEAD", &format!("{LAKE}/ttl/{name}.txt"), &[], b"");
        assert!(!head.headers().contains_key("x-ms-expiry-time"), "{name}");
    }

    // A rename keeps the deadline with the file.
    let moved = server.dfs(
        "PUT",
        &format!("{LAKE}/ttl/moved.txt"),
        &[("x-ms-rename-source", "/lake/ttl/relative.txt")],
        b"",
    );
    assert_eq!(moved.status(), 201);
    let moved_head = server.blob("HEAD", &format!("{LAKE}/ttl/moved.txt"), &[], b"");
    assert_eq!(header(&moved_head, "x-ms-expiry-time"), deadline);

    // Inside the deadline everything is still there through both protocols.
    server.advance(30);
    for name in ["moved", "absolute", "never", "plain"] {
        let path = format!("{LAKE}/ttl/{name}.txt");
        assert_eq!(server.dfs("HEAD", &path, &[], b"").status(), 200, "{name}");
        assert_eq!(server.blob("HEAD", &path, &[], b"").status(), 200, "{name}");
    }

    // Past it the relative file is gone from both, and only that one.
    server.advance(40);
    let path = format!("{LAKE}/ttl/moved.txt");
    dfs_error(server.dfs("HEAD", &path, &[], b""), 404, "PathNotFound");
    dfs_error(server.blob("HEAD", &path, &[], b""), 404, "BlobNotFound");
    dfs_error(server.blob("GET", &path, &[], b""), 404, "BlobNotFound");
    let listing = server
        .blob(
            "GET",
            &format!("{LAKE}?restype=container&comp=list&prefix=ttl/"),
            &[],
            b"",
        )
        .text()
        .unwrap();
    assert!(!listing.contains("moved.txt"), "{listing}");
    assert!(!listing.contains("relative.txt"), "{listing}");
    for name in ["absolute", "never", "plain"] {
        assert!(listing.contains(&format!("ttl/{name}.txt")), "{listing}");
    }

    // The absolute deadline passes five minutes after creation.
    server.advance(300);
    let path = format!("{LAKE}/ttl/absolute.txt");
    dfs_error(server.dfs("HEAD", &path, &[], b""), 404, "PathNotFound");
    assert_eq!(
        server
            .dfs("HEAD", &format!("{LAKE}/ttl/never.txt"), &[], b"")
            .status(),
        200
    );
}

#[test]
fn a_blob_write_discards_unflushed_dfs_data() {
    let server = Emulator::start(None);
    server.filesystem();
    let file = format!("{LAKE}/raced.txt");
    server.dfs("PUT", &format!("{file}?resource=file"), &[], b"");
    server.dfs(
        "PATCH",
        &format!("{file}?action=append&position=0"),
        &[],
        b"dfs",
    );
    server.put_blob("raced.txt", &[], b"blob");
    dfs_error(
        server.dfs(
            "PATCH",
            &format!("{file}?action=flush&position=3"),
            &[],
            b"",
        ),
        400,
        "InvalidFlushPosition",
    );
    assert_eq!(
        server.dfs("GET", &file, &[], b"").bytes().unwrap().as_ref(),
        b"blob"
    );
    // The file takes new appends from the Blob content onward.
    server.dfs(
        "PATCH",
        &format!("{file}?action=append&position=4"),
        &[],
        b"+dfs",
    );
    assert_eq!(
        server
            .dfs(
                "PATCH",
                &format!("{file}?action=flush&position=8"),
                &[],
                b""
            )
            .status(),
        200
    );
    assert_eq!(
        server.dfs("GET", &file, &[], b"").bytes().unwrap().as_ref(),
        b"blob+dfs"
    );
}

#[test]
fn a_directory_rename_is_never_partly_visible_to_blob_listings() {
    const FILES: usize = 150;
    let server = Emulator::start(None);
    server.filesystem();
    for index in 0..FILES {
        server.put_blob(&format!("tree/part/f{index:03}"), &[], b"x");
    }
    let done = AtomicBool::new(false);
    let (old_tree, new_tree) = ("tree/part/f", "moved/part/f");
    thread::scope(|scope| {
        let renamer = scope.spawn(|| {
            let mut flips = 0;
            while !done.load(Ordering::Relaxed) {
                for (from, to) in [("tree", "moved"), ("moved", "tree")] {
                    let source = format!("/lake/{from}");
                    let renamed = server.dfs(
                        "PUT",
                        &format!("{LAKE}/{to}?mode=posix"),
                        &[("x-ms-rename-source", &source)],
                        b"",
                    );
                    assert_eq!(renamed.status(), 201);
                    flips += 1;
                }
            }
            flips
        });
        for _ in 0..40 {
            let listing = server
                .blob(
                    "GET",
                    &format!("{LAKE}?restype=container&comp=list&maxresults=5000"),
                    &[],
                    b"",
                )
                .text()
                .unwrap();
            let before = listing.matches(&format!("<Name>{old_tree}")).count();
            let after = listing.matches(&format!("<Name>{new_tree}")).count();
            assert!(
                (before, after) == (FILES, 0) || (before, after) == (0, FILES),
                "partial move: {before} under the old name, {after} under the new"
            );
        }
        done.store(true, Ordering::Relaxed);
        let flips = renamer.join().unwrap();
        assert!(flips >= 2, "the listing raced {flips} renames");
    });
}

#[test]
fn blob_delete_of_a_directory_needs_it_empty_and_children_go_first() {
    let server = Emulator::start(None);
    server.filesystem();
    server.dfs_file("tree/sub/a.txt", b"a");
    server.dfs_file("tree/b.txt", b"b");
    let blob_delete = |path: &str| server.blob("DELETE", &format!("{LAKE}/{path}"), &[], b"");

    // Azure refuses to delete a directory that still has children, for each directory in turn.
    for directory in ["tree", "tree/sub"] {
        let refused = blob_delete(directory);
        assert_eq!(refused.status(), 409, "{directory}");
        assert_eq!(header(&refused, "x-ms-error-code"), "DirectoryIsNotEmpty");
        assert!(
            refused
                .text()
                .unwrap()
                .contains("This operation is not permitted on a non-empty directory.")
        );
    }
    // Deleting children first, deepest first, empties each directory so it can go.
    for path in ["tree/sub/a.txt", "tree/sub", "tree/b.txt", "tree"] {
        assert_eq!(blob_delete(path).status(), 202, "{path}");
    }
    let listing = server
        .blob(
            "GET",
            &format!("{LAKE}?restype=container&comp=list"),
            &[],
            b"",
        )
        .text()
        .unwrap();
    assert!(!listing.contains("<Name>tree"), "{listing}");
}

#[test]
fn blob_leases_protect_files_from_dfs_operations() {
    let server = Emulator::start(None);
    server.filesystem();
    server.put_blob("held.txt", &[], b"leased");
    let file = format!("{LAKE}/held.txt");
    let lease = server.blob(
        "PUT",
        &format!("{file}?comp=lease"),
        &[
            ("x-ms-lease-action", "acquire"),
            ("x-ms-lease-duration", "-1"),
        ],
        b"",
    );
    let id = header(&lease, "x-ms-lease-id");
    dfs_error(
        server.dfs(
            "PATCH",
            &format!("{file}?action=append&position=6"),
            &[],
            b"!",
        ),
        412,
        "LeaseIdMissing",
    );
    dfs_error(server.dfs("DELETE", &file, &[], b""), 412, "LeaseIdMissing");
    dfs_error(
        server.dfs(
            "PUT",
            &format!("{LAKE}/renamed.txt"),
            &[("x-ms-rename-source", "/lake/held.txt")],
            b"",
        ),
        412,
        "LeaseIdMissing",
    );
    let appended = server.dfs(
        "PATCH",
        &format!("{file}?action=append&position=6"),
        &[("x-ms-lease-id", &id)],
        b"!",
    );
    assert_eq!(appended.status(), 202);
    let flushed = server.dfs(
        "PATCH",
        &format!("{file}?action=flush&position=7"),
        &[("x-ms-lease-id", &id)],
        b"",
    );
    assert_eq!(flushed.status(), 200);
    let blob_view = server.blob("GET", &file, &[("x-ms-lease-id", &id)], b"");
    assert_eq!(etag(&blob_view), etag(&flushed));
    assert_eq!(header(&blob_view, "x-ms-lease-state"), "leased");
    assert_eq!(blob_view.bytes().unwrap().as_ref(), b"leased!");
    // A Blob write needs the lease too.
    let blocked = server.blob("PUT", &file, &[("x-ms-blob-type", "BlockBlob")], b"x");
    assert_eq!(blocked.status(), 412);
}

#[test]
fn shared_state_survives_a_restart_through_both_protocols() {
    let location = tempfile::tempdir().unwrap();
    let (blob_tag, dfs_tag);
    {
        let server = Emulator::start(Some(location.path()));
        server.filesystem();
        blob_tag = etag(&server.put_blob("dir/blob.txt", &[], b"blob data"));
        dfs_tag = etag(&server.dfs_file("dir/dfs.txt", b"dfs data"));
        server.dfs(
            "PATCH",
            &format!("{LAKE}/dir?action=setAccessControl"),
            &[("x-ms-permissions", "0700"), ("x-ms-owner", "someone")],
            b"",
        );
        let renamed = server.dfs(
            "PUT",
            &format!("{LAKE}/renamed"),
            &[("x-ms-rename-source", "/lake/dir")],
            b"",
        );
        assert_eq!(renamed.status(), 201);
    }
    let server = Emulator::start(Some(location.path()));
    for (name, tag, bytes) in [
        ("renamed/blob.txt", &blob_tag, &b"blob data"[..]),
        ("renamed/dfs.txt", &dfs_tag, &b"dfs data"[..]),
    ] {
        let as_blob = server.blob("GET", &format!("{LAKE}/{name}"), &[], b"");
        let as_file = server.dfs("GET", &format!("{LAKE}/{name}"), &[], b"");
        assert_eq!(etag(&as_blob), *tag, "{name}");
        assert_eq!(etag(&as_file), *tag, "{name}");
        assert_eq!(as_blob.bytes().unwrap().as_ref(), bytes);
        assert_eq!(as_file.bytes().unwrap().as_ref(), bytes);
    }
    let directory = server.dfs("HEAD", &format!("{LAKE}/renamed"), &[], b"");
    assert_eq!(header(&directory, "x-ms-owner"), "someone");
    assert_eq!(header(&directory, "x-ms-permissions"), "rwx------");
    assert_eq!(
        server
            .dfs("HEAD", &format!("{LAKE}/dir"), &[], b"")
            .status(),
        404
    );
}
