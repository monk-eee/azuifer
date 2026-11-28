//! NFS file shares over FileREST (ADR-0029): share protocol, POSIX properties, hard links,
//! symbolic links and the operations NFS refuses, against the real binary. The helpers mirror
//! `files_http.rs` so the two files merge independently.

use base64::{Engine as _, engine::general_purpose::STANDARD};
use hmac::{Hmac, KeyInit as _, Mac as _};
use reqwest::{Method, Url, blocking::Client, header::HeaderMap};
use sha2::Sha256;
use std::{
    collections::BTreeMap,
    io::{BufRead as _, BufReader},
    path::Path,
    process::{Child, Command, Stdio},
    time::{Duration, Instant, SystemTime},
};

const ACCOUNT: &str = "testaccount";
/// The version NFS clients speak; links need 2025-05-05 and 2025-07-05.
const NFS_VERSION: &str = "2025-07-05";
const BASELINE: &str = "2023-11-03";
const KEY: [u8; 32] = [41; 32];
const SECOND: &str = "00000000-0000-0000-0000-000000000001";

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

    fn lacks(&self, name: &str) -> bool {
        !self.headers.contains_key(name)
    }

    fn text(&self) -> String {
        String::from_utf8(self.body.clone()).unwrap()
    }
}

impl Emulator {
    fn start(location: Option<&Path>) -> Self {
        Self::start_with(location, &[])
    }

    fn start_with(location: Option<&Path>, extra: &[&str]) -> Self {
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
                "--skip-api-version-check",
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

    fn shutdown(&mut self) {
        drop(self.child.stdin.take());
        let deadline = Instant::now() + Duration::from_secs(10);
        while Instant::now() < deadline {
            if self.child.try_wait().unwrap().is_some() {
                return;
            }
            std::thread::sleep(Duration::from_millis(20));
        }
        let _ = self.child.kill();
        let _ = self.child.wait();
    }

    /// A request at the NFS API version.
    fn send(&self, method: &str, target: &str, headers: &[(&str, &str)], body: &[u8]) -> Reply {
        self.send_at(NFS_VERSION, method, target, headers, body)
    }

    fn send_at(
        &self,
        version: &str,
        method: &str,
        target: &str,
        extra: &[(&str, &str)],
        body: &[u8],
    ) -> Reply {
        let method = Method::from_bytes(method.as_bytes()).unwrap();
        let url = Url::parse(&format!("{}{target}", self.base)).unwrap();
        let sends_body = method == Method::PUT || method == Method::POST;
        let mut all = vec![("x-ms-version", version)];
        all.extend_from_slice(extra);
        let headers = signed(&method, &url, &all, sends_body.then_some(body.len()));
        let mut request = self.client.request(method, url);
        for (name, value) in headers {
            request = request.header(name, value);
        }
        if sends_body {
            request = request.body(body.to_vec());
        }
        let response = request.send().expect("HTTP request completed");
        let reply = Reply {
            status: response.status().as_u16(),
            headers: response.headers().clone(),
            body: response.bytes().expect("response body").to_vec(),
        };
        assert_eq!(reply.header("x-ms-request-id").len(), 32);
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
) -> BTreeMap<String, String> {
    let mut headers: BTreeMap<String, String> = BTreeMap::from([(
        "x-ms-date".into(),
        httpdate::fmt_http_date(SystemTime::now()),
    )]);
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

fn expect(reply: Reply, status: u16) -> Reply {
    assert_eq!(reply.status, status, "body: {}", reply.text());
    reply
}

fn expect_error(reply: Reply, status: u16, code: &str) {
    assert_eq!(reply.status, status, "body: {}", reply.text());
    assert_eq!(reply.header("x-ms-error-code"), code);
}

fn nfs_share(emulator: &Emulator, name: &str) -> Reply {
    expect(
        emulator.send(
            "PUT",
            &format!("/{ACCOUNT}/{name}?restype=share"),
            &[("x-ms-enabled-protocols", "NFS")],
            b"",
        ),
        201,
    )
}

fn smb_share(emulator: &Emulator, name: &str) {
    expect(
        emulator.send("PUT", &format!("/{ACCOUNT}/{name}?restype=share"), &[], b""),
        201,
    );
}

fn directory(emulator: &Emulator, share: &str, path: &str, extra: &[(&str, &str)]) -> Reply {
    expect(
        emulator.send(
            "PUT",
            &format!("/{ACCOUNT}/{share}/{path}?restype=directory"),
            extra,
            b"",
        ),
        201,
    )
}

fn file(
    emulator: &Emulator,
    share: &str,
    path: &str,
    length: usize,
    extra: &[(&str, &str)],
) -> Reply {
    let length = length.to_string();
    let mut headers = vec![("x-ms-type", "file"), ("x-ms-content-length", &length)];
    headers.extend_from_slice(extra);
    expect(
        emulator.send("PUT", &format!("/{ACCOUNT}/{share}/{path}"), &headers, b""),
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

fn properties(emulator: &Emulator, share: &str, path: &str) -> Reply {
    expect(
        emulator.send("HEAD", &format!("/{ACCOUNT}/{share}/{path}"), &[], b""),
        200,
    )
}

fn read(emulator: &Emulator, share: &str, path: &str) -> Vec<u8> {
    expect(
        emulator.send("GET", &format!("/{ACCOUNT}/{share}/{path}"), &[], b""),
        200,
    )
    .body
}

fn hard_link(emulator: &Emulator, share: &str, link: &str, target: &str) -> Reply {
    emulator.send(
        "PUT",
        &format!("/{ACCOUNT}/{share}/{link}?restype=hardlink"),
        &[("x-ms-type", "file"), ("x-ms-file-target-file", target)],
        b"",
    )
}

fn symbolic_link(emulator: &Emulator, share: &str, link: &str, text: &str) -> Reply {
    emulator.send(
        "PUT",
        &format!("/{ACCOUNT}/{share}/{link}?restype=symboliclink"),
        &[("x-ms-link-text", text)],
        b"",
    )
}

fn tags(reply: &Reply, tag: &str) -> Vec<String> {
    let text = reply.text();
    let (open, close) = (format!("<{tag}>"), format!("</{tag}>"));
    text.split(&open)
        .skip(1)
        .map(|part| part.split(&close).next().unwrap().to_owned())
        .collect()
}

fn usage(emulator: &Emulator, share: &str) -> String {
    let reply = expect(
        emulator.send(
            "GET",
            &format!("/{ACCOUNT}/{share}?restype=share&comp=stats"),
            &[],
            b"",
        ),
        200,
    );
    tags(&reply, "ShareUsageBytes").remove(0)
}

#[test]
fn a_share_reports_its_protocol_and_nfs_settings() {
    let emulator = Emulator::start(None);
    smb_share(&emulator, "plain");
    nfs_share(&emulator, "tuned");
    expect(
        emulator.send(
            "PUT",
            &format!("/{ACCOUNT}/custom?restype=share"),
            &[
                ("x-ms-enabled-protocols", "nfs"),
                ("x-ms-root-squash", "RootSquash"),
                ("x-ms-enable-snapshot-virtual-directory-access", "false"),
            ],
            b"",
        ),
        201,
    );

    let head = |name: &str| {
        expect(
            emulator.send(
                "HEAD",
                &format!("/{ACCOUNT}/{name}?restype=share"),
                &[],
                b"",
            ),
            200,
        )
    };
    let plain = head("plain");
    assert_eq!(plain.header("x-ms-enabled-protocols"), "SMB");
    assert!(plain.lacks("x-ms-root-squash"));
    assert!(plain.lacks("x-ms-enable-snapshot-virtual-directory-access"));
    let tuned = head("tuned");
    assert_eq!(tuned.header("x-ms-enabled-protocols"), "NFS");
    assert_eq!(tuned.header("x-ms-root-squash"), "NoRootSquash");
    assert_eq!(
        tuned.header("x-ms-enable-snapshot-virtual-directory-access"),
        "true"
    );
    let custom = head("custom");
    assert_eq!(custom.header("x-ms-root-squash"), "RootSquash");
    assert_eq!(
        custom.header("x-ms-enable-snapshot-virtual-directory-access"),
        "false"
    );

    expect(
        emulator.send(
            "PUT",
            &format!("/{ACCOUNT}/tuned?restype=share&comp=properties"),
            &[
                ("x-ms-root-squash", "AllSquash"),
                ("x-ms-enable-snapshot-virtual-directory-access", "false"),
            ],
            b"",
        ),
        200,
    );
    let changed = head("tuned");
    assert_eq!(changed.header("x-ms-root-squash"), "AllSquash");
    assert_eq!(
        changed.header("x-ms-enable-snapshot-virtual-directory-access"),
        "false"
    );
    // A change that sends only one setting keeps the other.
    expect(
        emulator.send(
            "PUT",
            &format!("/{ACCOUNT}/tuned?restype=share&comp=properties"),
            &[("x-ms-root-squash", "NoRootSquash")],
            b"",
        ),
        200,
    );
    assert_eq!(
        head("tuned").header("x-ms-enable-snapshot-virtual-directory-access"),
        "false"
    );

    let list = expect(
        emulator.send("GET", &format!("/{ACCOUNT}?comp=list"), &[], b""),
        200,
    );
    assert_eq!(
        tags(&list, "EnabledProtocols"),
        ["NFS", "SMB", "NFS"],
        "custom, plain, tuned in name order"
    );
    assert_eq!(tags(&list, "RootSquash"), ["RootSquash", "NoRootSquash"]);
    assert_eq!(
        tags(&list, "EnableSnapshotVirtualDirectoryAccess"),
        ["false", "false"]
    );

    // The NFS settings are meaningless on SMB, and values are checked.
    for headers in [
        vec![("x-ms-root-squash", "RootSquash")],
        vec![("x-ms-enable-snapshot-virtual-directory-access", "true")],
        vec![
            ("x-ms-enabled-protocols", "NFS"),
            ("x-ms-root-squash", "Some"),
        ],
        vec![("x-ms-enabled-protocols", "ext4")],
    ] {
        expect_error(
            emulator.send(
                "PUT",
                &format!("/{ACCOUNT}/refused?restype=share"),
                &headers,
                b"",
            ),
            400,
            "InvalidHeaderValue",
        );
    }
    expect_error(
        emulator.send(
            "PUT",
            &format!("/{ACCOUNT}/plain?restype=share&comp=properties"),
            &[("x-ms-root-squash", "AllSquash")],
            b"",
        ),
        400,
        "InvalidHeaderValue",
    );

    // A snapshot keeps the protocol and, like Azure, omits the share-only settings.
    let snapshot = expect(
        emulator.send(
            "PUT",
            &format!("/{ACCOUNT}/tuned?restype=share&comp=snapshot"),
            &[],
            b"",
        ),
        201,
    );
    let at = snapshot.header("x-ms-snapshot").to_owned();
    let snapped = expect(
        emulator.send(
            "HEAD",
            &format!("/{ACCOUNT}/tuned?restype=share&sharesnapshot={at}"),
            &[],
            b"",
        ),
        200,
    );
    assert_eq!(snapped.header("x-ms-enabled-protocols"), "NFS");
    assert!(snapped.lacks("x-ms-root-squash"));
}

#[test]
fn files_and_directories_carry_posix_properties_instead_of_smb_ones() {
    let emulator = Emulator::start(None);
    nfs_share(&emulator, "posix");

    let plain_dir = directory(&emulator, "posix", "plain", &[]);
    assert_eq!(plain_dir.header("x-ms-mode"), "0755");
    assert_eq!(plain_dir.header("x-ms-owner"), "0");
    assert_eq!(plain_dir.header("x-ms-group"), "0");
    assert_eq!(plain_dir.header("x-ms-file-file-type"), "Directory");
    assert!(plain_dir.lacks("x-ms-file-attributes"));
    assert!(plain_dir.lacks("x-ms-file-permission-key"));
    assert!(plain_dir.headers.contains_key("x-ms-file-creation-time"));
    assert!(plain_dir.headers.contains_key("x-ms-file-id"));

    let tuned_dir = directory(
        &emulator,
        "posix",
        "tuned",
        &[
            ("x-ms-mode", "rwxr-x---"),
            ("x-ms-owner", "1000"),
            ("x-ms-group", "100"),
        ],
    );
    assert_eq!(tuned_dir.header("x-ms-mode"), "0750");
    assert_eq!(tuned_dir.header("x-ms-owner"), "1000");
    assert_eq!(tuned_dir.header("x-ms-group"), "100");

    let created = file(&emulator, "posix", "plain/a.txt", 5, &[]);
    assert_eq!(created.header("x-ms-mode"), "0644");
    assert_eq!(created.header("x-ms-owner"), "0");
    assert_eq!(created.header("x-ms-file-file-type"), "Regular");
    assert!(created.lacks("x-ms-file-attributes"));
    assert!(
        created.lacks("x-ms-link-count"),
        "Create File does not report it"
    );
    file(
        &emulator,
        "posix",
        "plain/b.txt",
        5,
        &[
            ("x-ms-mode", "0600"),
            ("x-ms-owner", "7"),
            ("x-ms-group", "8"),
            ("x-ms-file-file-type", "Regular"),
        ],
    );

    let props = properties(&emulator, "posix", "plain/b.txt");
    assert_eq!(props.header("x-ms-mode"), "0600");
    assert_eq!(props.header("x-ms-owner"), "7");
    assert_eq!(props.header("x-ms-group"), "8");
    assert_eq!(props.header("x-ms-file-file-type"), "Regular");
    assert_eq!(props.header("x-ms-link-count"), "1");
    assert_eq!(props.header("x-ms-type"), "File");
    assert!(props.lacks("x-ms-file-attributes"));
    assert!(props.lacks("x-ms-file-permission-key"));

    // Set properties changes what it names and keeps the rest.
    let set = expect(
        emulator.send(
            "PUT",
            &format!("/{ACCOUNT}/posix/plain/b.txt?comp=properties"),
            &[("x-ms-mode", "0640")],
            b"",
        ),
        200,
    );
    assert_eq!(set.header("x-ms-mode"), "0640");
    assert_eq!(set.header("x-ms-owner"), "7");
    assert_eq!(set.header("x-ms-link-count"), "1");
    let set_dir = expect(
        emulator.send(
            "PUT",
            &format!("/{ACCOUNT}/posix/tuned?restype=directory&comp=properties"),
            &[("x-ms-group", "200")],
            b"",
        ),
        200,
    );
    assert_eq!(set_dir.header("x-ms-group"), "200");
    assert_eq!(set_dir.header("x-ms-owner"), "1000");
    assert_eq!(set_dir.header("x-ms-mode"), "0750");
    let dir_props = expect(
        emulator.send(
            "HEAD",
            &format!("/{ACCOUNT}/posix/tuned?restype=directory"),
            &[],
            b"",
        ),
        200,
    );
    assert_eq!(dir_props.header("x-ms-group"), "200");
    assert_eq!(dir_props.header("x-ms-file-file-type"), "Directory");

    // The metadata operations answer in the same terms.
    let metadata = expect(
        emulator.send(
            "GET",
            &format!("/{ACCOUNT}/posix/plain/b.txt?comp=metadata"),
            &[],
            b"",
        ),
        200,
    );
    assert_eq!(metadata.header("x-ms-mode"), "0640");

    // Bad values are refused; SMB-only headers are accepted and ignored.
    for bad in ["8", "0648", "rwxrwxrw", "zzz"] {
        expect_error(
            emulator.send(
                "PUT",
                &format!("/{ACCOUNT}/posix/bad.txt"),
                &[
                    ("x-ms-type", "file"),
                    ("x-ms-content-length", "1"),
                    ("x-ms-mode", bad),
                ],
                b"",
            ),
            400,
            "InvalidHeaderValue",
        );
    }
    for headers in [
        [("x-ms-owner", "-1")],
        [("x-ms-group", "4294967296")],
        [("x-ms-file-file-type", "Directory")],
    ] {
        let mut all = vec![("x-ms-type", "file"), ("x-ms-content-length", "1")];
        all.extend_from_slice(&headers);
        expect_error(
            emulator.send("PUT", &format!("/{ACCOUNT}/posix/bad.txt"), &all, b""),
            400,
            "InvalidHeaderValue",
        );
    }
    let ignored = file(
        &emulator,
        "posix",
        "smb.txt",
        1,
        &[
            ("x-ms-file-attributes", "Hidden"),
            ("x-ms-file-permission", "inherit"),
        ],
    );
    assert!(ignored.lacks("x-ms-file-attributes"));

    // NFS behavior does not depend on the request's version; SMB shares stay SMB.
    let old = expect(
        emulator.send_at(
            BASELINE,
            "PUT",
            &format!("/{ACCOUNT}/posix/old.txt"),
            &[("x-ms-type", "file"), ("x-ms-content-length", "1")],
            b"",
        ),
        201,
    );
    assert_eq!(old.header("x-ms-mode"), "0644");
    smb_share(&emulator, "smb");
    let smb = file(
        &emulator,
        "smb",
        "a.txt",
        1,
        &[("x-ms-mode", "0600"), ("x-ms-owner", "5")],
    );
    assert_eq!(smb.header("x-ms-file-attributes"), "Archive");
    assert!(smb.lacks("x-ms-mode"));
    assert!(smb.lacks("x-ms-owner"));
    let smb_props = properties(&emulator, "smb", "a.txt");
    assert!(smb_props.lacks("x-ms-link-count"));
    assert!(smb_props.lacks("x-ms-file-file-type"));
}

#[test]
fn an_nfs_listing_has_only_ids_names_and_lengths() {
    let emulator = Emulator::start(None);
    nfs_share(&emulator, "list");
    directory(&emulator, "list", "dir", &[]);
    file(&emulator, "list", "file.bin", 12, &[]);
    let listing = expect(
        emulator.send(
            "GET",
            &format!(
                "/{ACCOUNT}/list?restype=directory&comp=list&include=Timestamps,ETag,Attributes"
            ),
            &[],
            b"",
        ),
        200,
    );
    let text = listing.text();
    assert_eq!(tags(&listing, "Name"), ["dir", "file.bin"]);
    assert_eq!(tags(&listing, "Content-Length"), ["12"]);
    assert_eq!(tags(&listing, "FileId").len(), 2);
    for absent in [
        "Attributes",
        "PermissionKey",
        "CreationTime",
        "LastWriteTime",
        "Etag",
        "Last-Modified",
    ] {
        assert!(!text.contains(&format!("<{absent}>")), "{absent} in {text}");
    }
    let directory_entry = text
        .split("<Directory>")
        .nth(1)
        .unwrap()
        .split("</Directory>")
        .next()
        .unwrap();
    assert!(!directory_entry.contains("Properties"), "{directory_entry}");

    smb_share(&emulator, "smb");
    file(&emulator, "smb", "f.txt", 1, &[]);
    let smb = expect(
        emulator.send(
            "GET",
            &format!("/{ACCOUNT}/smb?restype=directory&comp=list&include=Timestamps,Attributes"),
            &[],
            b"",
        ),
        200,
    );
    assert!(smb.text().contains("<Attributes>Archive</Attributes>"));
}

#[test]
fn hard_links_are_names_of_one_file() {
    let emulator = Emulator::start(None);
    nfs_share(&emulator, "links");
    directory(&emulator, "links", "a", &[]);
    directory(&emulator, "links", "b", &[]);
    file(&emulator, "links", "a/one.txt", 10, &[("x-ms-owner", "3")]);
    put(&emulator, "links", "a/one.txt", 0, b"shared!");

    let link = expect(hard_link(&emulator, "links", "b/two.txt", "a/one.txt"), 201);
    assert_eq!(link.header("x-ms-link-count"), "2");
    assert_eq!(link.header("x-ms-file-file-type"), "Regular");
    assert_eq!(link.header("x-ms-owner"), "3");
    assert_eq!(link.header("x-ms-mode"), "0644");
    assert!(link.headers.contains_key("etag"));

    let first = properties(&emulator, "links", "a/one.txt");
    let second = properties(&emulator, "links", "b/two.txt");
    assert_eq!(first.header("x-ms-link-count"), "2");
    assert_eq!(second.header("x-ms-link-count"), "2");
    assert_eq!(first.header("x-ms-file-id"), second.header("x-ms-file-id"));
    assert_ne!(
        first.header("x-ms-file-parent-id"),
        second.header("x-ms-file-parent-id"),
        "each name has its own directory"
    );
    assert_eq!(link.header("x-ms-file-id"), first.header("x-ms-file-id"));
    assert_eq!(
        link.header("x-ms-file-parent-id"),
        second.header("x-ms-file-parent-id")
    );
    assert_eq!(first.header("etag"), second.header("etag"));

    // One file, two names: writes, properties and metadata show through both.
    assert_eq!(&read(&emulator, "links", "b/two.txt")[..7], b"shared!");
    put(&emulator, "links", "b/two.txt", 7, b"abc");
    assert_eq!(read(&emulator, "links", "a/one.txt"), b"shared!abc");
    expect(
        emulator.send(
            "PUT",
            &format!("/{ACCOUNT}/links/b/two.txt?comp=properties"),
            &[("x-ms-mode", "0600")],
            b"",
        ),
        200,
    );
    assert_eq!(
        properties(&emulator, "links", "a/one.txt").header("x-ms-mode"),
        "0600"
    );
    expect(
        emulator.send(
            "PUT",
            &format!("/{ACCOUNT}/links/a/one.txt?comp=metadata"),
            &[("x-ms-meta-tag", "yes")],
            b"",
        ),
        200,
    );
    assert_eq!(
        properties(&emulator, "links", "b/two.txt").header("x-ms-meta-tag"),
        "yes"
    );

    // Content counts once against the share.
    assert_eq!(usage(&emulator, "links"), "10");

    // Both names list, with the inode's id.
    let listing = |directory: &str| {
        expect(
            emulator.send(
                "GET",
                &format!("/{ACCOUNT}/links/{directory}?restype=directory&comp=list"),
                &[],
                b"",
            ),
            200,
        )
    };
    let in_b = listing("b");
    assert_eq!(tags(&in_b, "Name"), ["two.txt"]);
    assert_eq!(tags(&in_b, "FileId"), [first.header("x-ms-file-id")]);

    // A name that is taken, a missing parent or target, and the wrong kinds of target.
    expect_error(
        hard_link(&emulator, "links", "b/two.txt", "a/one.txt"),
        409,
        "ResourceAlreadyExists",
    );
    expect_error(
        hard_link(&emulator, "links", "a/one.txt", "a/one.txt"),
        409,
        "ResourceAlreadyExists",
    );
    expect_error(
        hard_link(&emulator, "links", "nowhere/x.txt", "a/one.txt"),
        404,
        "ParentNotFound",
    );
    expect_error(
        hard_link(&emulator, "links", "b/x.txt", "a/absent.txt"),
        404,
        "ResourceNotFound",
    );
    expect_error(
        hard_link(&emulator, "links", "b/x.txt", "gone/absent.txt"),
        404,
        "ParentNotFound",
    );
    expect_error(
        hard_link(&emulator, "links", "b/x.txt", "a"),
        400,
        "InvalidHeaderValue",
    );
    expect_error(
        emulator.send(
            "PUT",
            &format!("/{ACCOUNT}/links/b/x.txt?restype=hardlink"),
            &[("x-ms-type", "file")],
            b"",
        ),
        400,
        "MissingRequiredHeader",
    );
    expect_error(
        emulator.send(
            "PUT",
            &format!("/{ACCOUNT}/links/b/x.txt?restype=hardlink"),
            &[
                ("x-ms-type", "directory"),
                ("x-ms-file-target-file", "a/one.txt"),
            ],
            b"",
        ),
        400,
        "InvalidHeaderValue",
    );

    // The target may be given as a URL of this share.
    let url = format!("{}/{ACCOUNT}/links/a/one.txt", emulator.base);
    assert_eq!(
        expect(hard_link(&emulator, "links", "b/three.txt", &url), 201).header("x-ms-link-count"),
        "3"
    );
    let elsewhere = format!("{}/{ACCOUNT}/other/a/one.txt", emulator.base);
    expect_error(
        hard_link(&emulator, "links", "b/four.txt", &elsewhere),
        400,
        "InvalidHeaderValue",
    );

    // A directory holding only a link is not empty.
    let delete =
        |path: &str| emulator.send("DELETE", &format!("/{ACCOUNT}/links/{path}"), &[], b"");
    expect_error(
        emulator.send(
            "DELETE",
            &format!("/{ACCOUNT}/links/b?restype=directory"),
            &[],
            b"",
        ),
        409,
        "DirectoryNotEmpty",
    );

    // Deleting names one at a time, the first name included, keeps the file until the last.
    let gone = expect(delete("a/one.txt"), 202);
    assert_eq!(gone.header("x-ms-link-count"), "2");
    assert_eq!(read(&emulator, "links", "b/two.txt"), b"shared!abc");
    assert_eq!(
        properties(&emulator, "links", "b/two.txt").header("x-ms-link-count"),
        "2"
    );
    expect_error(
        emulator.send("HEAD", &format!("/{ACCOUNT}/links/a/one.txt"), &[], b""),
        404,
        "ResourceNotFound",
    );
    assert_eq!(usage(&emulator, "links"), "10");
    // The promoted name keeps the file id the first name had.
    assert_eq!(
        properties(&emulator, "links", "b/two.txt").header("x-ms-file-id"),
        first.header("x-ms-file-id")
    );
    assert_eq!(
        expect(delete("b/three.txt"), 202).header("x-ms-link-count"),
        "1"
    );
    assert_eq!(
        expect(delete("b/two.txt"), 202).header("x-ms-link-count"),
        "0"
    );
    assert_eq!(
        usage(&emulator, "links"),
        "0",
        "the last name frees the content"
    );
    expect(
        emulator.send(
            "DELETE",
            &format!("/{ACCOUNT}/links/b?restype=directory"),
            &[],
            b"",
        ),
        202,
    );
}

#[test]
fn a_hard_linked_name_can_be_replaced_and_listed_in_order() {
    let emulator = Emulator::start(None);
    nfs_share(&emulator, "order");
    file(&emulator, "order", "m.txt", 4, &[]);
    put(&emulator, "order", "m.txt", 0, b"mmmm");
    expect(hard_link(&emulator, "order", "a.txt", "m.txt"), 201);
    expect(hard_link(&emulator, "order", "z.txt", "m.txt"), 201);
    let listing = expect(
        emulator.send(
            "GET",
            &format!("/{ACCOUNT}/order?restype=directory&comp=list&maxresults=2"),
            &[],
            b"",
        ),
        200,
    );
    assert_eq!(tags(&listing, "Name"), ["a.txt", "m.txt"]);
    let next = tags(&listing, "NextMarker").remove(0);
    assert!(!next.is_empty());
    let rest = expect(
        emulator.send(
            "GET",
            &format!("/{ACCOUNT}/order?restype=directory&comp=list&marker={next}"),
            &[],
            b"",
        ),
        200,
    );
    assert_eq!(tags(&rest, "Name"), ["z.txt"]);

    // Create File over a linked name truncates the shared file, whatever name it goes by.
    file(&emulator, "order", "z.txt", 2, &[]);
    assert_eq!(
        properties(&emulator, "order", "m.txt").header("content-length"),
        "2"
    );
    assert_eq!(
        properties(&emulator, "order", "z.txt").header("x-ms-link-count"),
        "3"
    );
    assert_eq!(usage(&emulator, "order"), "0");
}

#[test]
fn link_operations_need_an_nfs_share_and_a_new_enough_version() {
    let emulator = Emulator::start(None);
    smb_share(&emulator, "smb");
    file(&emulator, "smb", "a.txt", 1, &[]);
    expect_error(
        hard_link(&emulator, "smb", "b.txt", "a.txt"),
        400,
        "InvalidQueryParameterValue",
    );
    expect_error(
        symbolic_link(&emulator, "smb", "c.txt", "a.txt"),
        400,
        "InvalidQueryParameterValue",
    );
    expect_error(
        emulator.send(
            "GET",
            &format!("/{ACCOUNT}/smb/a.txt?restype=symboliclink"),
            &[],
            b"",
        ),
        400,
        "InvalidQueryParameterValue",
    );

    nfs_share(&emulator, "nfs");
    file(&emulator, "nfs", "a.txt", 1, &[]);
    let hard = |version: &str| {
        emulator.send_at(
            version,
            "PUT",
            &format!("/{ACCOUNT}/nfs/b.txt?restype=hardlink"),
            &[("x-ms-type", "file"), ("x-ms-file-target-file", "a.txt")],
            b"",
        )
    };
    expect_error(hard("2025-01-05"), 400, "InvalidQueryParameterValue");
    expect(hard("2025-05-05"), 201);
    let symbolic = |version: &str, name: &str| {
        emulator.send_at(
            version,
            "PUT",
            &format!("/{ACCOUNT}/nfs/{name}?restype=symboliclink"),
            &[("x-ms-link-text", "a.txt")],
            b"",
        )
    };
    expect_error(
        symbolic("2025-05-05", "s1"),
        400,
        "InvalidQueryParameterValue",
    );
    expect(symbolic("2025-07-05", "s1"), 201);
    expect_error(
        emulator.send_at(
            "2025-05-05",
            "GET",
            &format!("/{ACCOUNT}/nfs/s1?restype=symboliclink"),
            &[],
            b"",
        ),
        400,
        "InvalidQueryParameterValue",
    );
    // The wrong verb and the share root are not link targets.
    expect_error(
        emulator.send(
            "GET",
            &format!("/{ACCOUNT}/nfs/a.txt?restype=hardlink"),
            &[],
            b"",
        ),
        405,
        "UnsupportedHttpVerb",
    );
    expect_error(
        emulator.send("PUT", &format!("/{ACCOUNT}/nfs?restype=hardlink"), &[], b""),
        400,
        "InvalidQueryParameterValue",
    );
    // A share snapshot is read-only.
    let snapshot = expect(
        emulator.send(
            "PUT",
            &format!("/{ACCOUNT}/nfs?restype=share&comp=snapshot"),
            &[],
            b"",
        ),
        201,
    );
    let at = snapshot.header("x-ms-snapshot").to_owned();
    expect_error(
        emulator.send(
            "PUT",
            &format!("/{ACCOUNT}/nfs/c.txt?restype=hardlink&sharesnapshot={at}"),
            &[("x-ms-type", "file"), ("x-ms-file-target-file", "a.txt")],
            b"",
        ),
        400,
        "InvalidQueryParameterValue",
    );
    expect_error(
        emulator.send(
            "PUT",
            &format!("/{ACCOUNT}/nfs/d?restype=symboliclink&sharesnapshot={at}"),
            &[("x-ms-link-text", "a.txt")],
            b"",
        ),
        400,
        "InvalidQueryParameterValue",
    );
}

#[test]
fn symbolic_links_keep_their_text_and_refuse_data_operations() {
    let emulator = Emulator::start(None);
    nfs_share(&emulator, "sym");
    directory(&emulator, "sym", "dir", &[]);
    file(&emulator, "sym", "dir/target.txt", 3, &[]);
    put(&emulator, "sym", "dir/target.txt", 0, b"abc");

    let text = "../dir/target%20file.txt";
    let created = emulator.send(
        "PUT",
        &format!("/{ACCOUNT}/sym/dir/link?restype=symboliclink"),
        &[
            ("x-ms-link-text", text),
            ("x-ms-owner", "12"),
            ("x-ms-group", "34"),
            ("x-ms-meta-why", "test"),
        ],
        b"",
    );
    let created = expect(created, 201);
    assert_eq!(created.header("x-ms-file-file-type"), "SymLink");
    assert_eq!(created.header("x-ms-mode"), "0777");
    assert_eq!(created.header("x-ms-owner"), "12");
    assert_eq!(created.header("x-ms-group"), "34");
    assert!(created.lacks("x-ms-link-count"));
    assert!(created.lacks("x-ms-file-attributes"));

    let read_link = expect(
        emulator.send(
            "GET",
            &format!("/{ACCOUNT}/sym/dir/link?restype=symboliclink"),
            &[],
            b"",
        ),
        200,
    );
    assert_eq!(
        read_link.header("x-ms-link-text"),
        text,
        "stored as sent, never resolved"
    );
    assert!(read_link.headers.contains_key("etag"));
    assert!(read_link.headers.contains_key("last-modified"));

    // A target that does not exist is not an error: nothing is resolved.
    let dangling = symbolic_link(&emulator, "sym", "dangling", "/nowhere/at/all");
    expect(dangling, 201);

    let props = properties(&emulator, "sym", "dir/link");
    assert_eq!(props.header("x-ms-file-file-type"), "SymLink");
    assert_eq!(props.header("content-length"), text.len().to_string());
    assert_eq!(props.header("x-ms-link-count"), "1");
    assert_eq!(props.header("x-ms-meta-why"), "test");
    let listing = expect(
        emulator.send(
            "GET",
            &format!("/{ACCOUNT}/sym/dir?restype=directory&comp=list"),
            &[],
            b"",
        ),
        200,
    );
    assert_eq!(tags(&listing, "Name"), ["link", "target.txt"]);

    // The bytes of a symbolic link are not a file's bytes.
    let refused = "XNfs4FileTypeUnsupportedException";
    expect_error(
        emulator.send("GET", &format!("/{ACCOUNT}/sym/dir/link"), &[], b""),
        400,
        refused,
    );
    expect_error(
        emulator.send(
            "PUT",
            &format!("/{ACCOUNT}/sym/dir/link?comp=range"),
            &[("x-ms-range", "bytes=0-0"), ("x-ms-write", "update")],
            b"x",
        ),
        400,
        refused,
    );
    expect_error(
        emulator.send(
            "GET",
            &format!("/{ACCOUNT}/sym/dir/link?comp=rangelist"),
            &[],
            b"",
        ),
        400,
        refused,
    );
    expect_error(
        emulator.send(
            "PUT",
            &format!("/{ACCOUNT}/sym/dir/link?comp=properties"),
            &[("x-ms-content-length", "1")],
            b"",
        ),
        400,
        refused,
    );
    expect_error(
        emulator.send(
            "PUT",
            &format!("/{ACCOUNT}/sym/dir/link"),
            &[("x-ms-type", "file"), ("x-ms-content-length", "1")],
            b"",
        ),
        400,
        refused,
    );
    expect_error(
        hard_link(&emulator, "sym", "dir/hard", "dir/link"),
        400,
        refused,
    );
    // Setting the mode or metadata is a change to the link itself.
    let chmod = expect(
        emulator.send(
            "PUT",
            &format!("/{ACCOUNT}/sym/dir/link?comp=properties"),
            &[("x-ms-mode", "0700")],
            b"",
        ),
        200,
    );
    assert_eq!(chmod.header("x-ms-mode"), "0700");
    assert_eq!(
        expect(
            emulator.send(
                "GET",
                &format!("/{ACCOUNT}/sym/dir/link?restype=symboliclink"),
                &[],
                b""
            ),
            200,
        )
        .header("x-ms-link-text"),
        text,
        "changing the mode leaves the text alone"
    );

    // Taken names, a missing parent, empty and oversized text.
    expect_error(
        symbolic_link(&emulator, "sym", "dir/link", "x"),
        409,
        "ResourceAlreadyExists",
    );
    expect_error(
        symbolic_link(&emulator, "sym", "dir/target.txt", "x"),
        409,
        "ResourceAlreadyExists",
    );
    expect_error(
        symbolic_link(&emulator, "sym", "missing/link", "x"),
        404,
        "ParentNotFound",
    );
    expect_error(
        symbolic_link(&emulator, "sym", "empty", ""),
        400,
        "InvalidHeaderValue",
    );
    expect_error(
        symbolic_link(&emulator, "sym", "long", &"a".repeat(4097)),
        400,
        "InvalidHeaderValue",
    );
    expect(
        symbolic_link(&emulator, "sym", "long", &"a".repeat(4096)),
        201,
    );
    // Reading a name that is not a link, or not there.
    expect_error(
        emulator.send(
            "GET",
            &format!("/{ACCOUNT}/sym/dir/target.txt?restype=symboliclink"),
            &[],
            b"",
        ),
        400,
        refused,
    );
    expect_error(
        emulator.send(
            "GET",
            &format!("/{ACCOUNT}/sym/dir/gone?restype=symboliclink"),
            &[],
            b"",
        ),
        404,
        "ResourceNotFound",
    );

    // A link is deleted like a file and leaves its target alone.
    let removed = expect(
        emulator.send("DELETE", &format!("/{ACCOUNT}/sym/dir/link"), &[], b""),
        202,
    );
    assert_eq!(removed.header("x-ms-link-count"), "0");
    assert_eq!(read(&emulator, "sym", "dir/target.txt"), b"abc");
}

#[test]
fn smb_only_operations_are_refused_on_nfs_shares() {
    let emulator = Emulator::start(None);
    nfs_share(&emulator, "nfs");
    directory(&emulator, "nfs", "d", &[]);
    file(&emulator, "nfs", "d/f.txt", 1, &[]);
    let denied = "XNfs4ShareDeniedException";
    let policies = b"<SignedIdentifiers/>";
    let permission = b"{\"permission\":\"O:SYG:SYD:(A;;FA;;;SY)\"}";
    for (method, target, headers, body) in [
        ("GET", "nfs?restype=share&comp=acl", vec![], &b""[..]),
        ("PUT", "nfs?restype=share&comp=acl", vec![], &policies[..]),
        (
            "PUT",
            "nfs?restype=share&comp=filepermission",
            vec![],
            &permission[..],
        ),
        (
            "GET",
            "nfs?restype=share&comp=filepermission",
            vec![("x-ms-file-permission-key", "1*1")],
            &b""[..],
        ),
        (
            "GET",
            "nfs/d?restype=directory&comp=listhandles",
            vec![],
            &b""[..],
        ),
        (
            "PUT",
            "nfs/d?restype=directory&comp=forceclosehandles",
            vec![("x-ms-handle-id", "*")],
            &b""[..],
        ),
        ("GET", "nfs/d/f.txt?comp=listhandles", vec![], &b""[..]),
        (
            "PUT",
            "nfs/d/f.txt?comp=forceclosehandles",
            vec![("x-ms-handle-id", "*")],
            &b""[..],
        ),
        (
            "PUT",
            "nfs/d/g.txt?comp=rename",
            vec![("x-ms-file-rename-source", "/testaccount/nfs/d/f.txt")],
            &b""[..],
        ),
        (
            "PUT",
            "nfs/e?restype=directory&comp=rename",
            vec![("x-ms-file-rename-source", "/testaccount/nfs/d")],
            &b""[..],
        ),
        (
            "PUT",
            "nfs/d/f.txt?comp=lease",
            vec![
                ("x-ms-lease-action", "acquire"),
                ("x-ms-lease-duration", "-1"),
            ],
            &b""[..],
        ),
    ] {
        let reply = emulator.send(method, &format!("/{ACCOUNT}/{target}"), &headers, body);
        assert_eq!(reply.status, 403, "{method} {target}: {}", reply.text());
        assert_eq!(reply.header("x-ms-error-code"), denied, "{method} {target}");
    }
    // The source survives, and share leases, which Azure documents for NFS, still work.
    assert_eq!(
        properties(&emulator, "nfs", "d/f.txt").header("x-ms-link-count"),
        "1"
    );
    let lease = expect(
        emulator.send(
            "PUT",
            &format!("/{ACCOUNT}/nfs?restype=share&comp=lease"),
            &[
                ("x-ms-lease-action", "acquire"),
                ("x-ms-lease-duration", "-1"),
            ],
            b"",
        ),
        201,
    );
    assert!(lease.headers.contains_key("x-ms-lease-id"));

    // The same operations on an SMB share are what they always were.
    smb_share(&emulator, "smb");
    expect(
        emulator.send(
            "GET",
            &format!("/{ACCOUNT}/smb?restype=share&comp=acl"),
            &[],
            b"",
        ),
        200,
    );
}

#[test]
fn file_leases_do_not_exist_on_nfs_shares() {
    let emulator = Emulator::start(None);
    nfs_share(&emulator, "nfs");
    file(&emulator, "nfs", "f.txt", 4, &[]);
    // A lease header names nothing on NFS, so no request fails over it.
    let lease = [("x-ms-lease-id", SECOND)];
    expect(
        emulator.send(
            "PUT",
            &format!("/{ACCOUNT}/nfs/f.txt?comp=range"),
            &[
                ("x-ms-range", "bytes=0-3"),
                ("x-ms-write", "update"),
                lease[0],
            ],
            b"data",
        ),
        201,
    );
    expect(
        emulator.send("HEAD", &format!("/{ACCOUNT}/nfs/f.txt"), &lease, b""),
        200,
    );
    expect(
        emulator.send("DELETE", &format!("/{ACCOUNT}/nfs/f.txt"), &lease, b""),
        202,
    );

    // SMB keeps rejecting a lease id that names no lease.
    smb_share(&emulator, "smb");
    file(&emulator, "smb", "f.txt", 4, &[]);
    let rejected = emulator.send("DELETE", &format!("/{ACCOUNT}/smb/f.txt"), &lease, b"");
    assert_eq!(rejected.status, 412, "{}", rejected.text());
}

#[test]
fn copy_file_takes_mode_and_owner_from_the_source_or_the_request() {
    let emulator = Emulator::start(None);
    nfs_share(&emulator, "copy");
    file(
        &emulator,
        "copy",
        "src.txt",
        4,
        &[
            ("x-ms-mode", "0640"),
            ("x-ms-owner", "5"),
            ("x-ms-group", "6"),
        ],
    );
    put(&emulator, "copy", "src.txt", 0, b"data");
    let source = format!("{}/{ACCOUNT}/copy/src.txt", emulator.base);
    let copy = |name: &str, extra: &[(&str, &str)]| {
        let mut headers = vec![("x-ms-copy-source", source.as_str())];
        headers.extend_from_slice(extra);
        emulator.send("PUT", &format!("/{ACCOUNT}/copy/{name}"), &headers, b"")
    };

    expect(copy("default.txt", &[]), 202);
    let by_default = properties(&emulator, "copy", "default.txt");
    assert_eq!(
        (
            by_default.header("x-ms-mode"),
            by_default.header("x-ms-owner"),
            by_default.header("x-ms-group")
        ),
        ("0640", "5", "6"),
        "source is the default"
    );
    assert_eq!(
        by_default.header("x-ms-link-count"),
        "1",
        "a copy is its own file"
    );
    assert_ne!(
        by_default.header("x-ms-file-id"),
        properties(&emulator, "copy", "src.txt").header("x-ms-file-id")
    );
    assert_eq!(read(&emulator, "copy", "default.txt"), b"data");

    expect(
        copy(
            "mode.txt",
            &[
                ("x-ms-file-mode-copy-mode", "override"),
                ("x-ms-mode", "0600"),
                ("x-ms-file-owner-copy-mode", "source"),
            ],
        ),
        202,
    );
    let mode = properties(&emulator, "copy", "mode.txt");
    assert_eq!(
        (mode.header("x-ms-mode"), mode.header("x-ms-owner")),
        ("0600", "5")
    );
    expect(
        copy(
            "owner.txt",
            &[
                ("x-ms-file-owner-copy-mode", "override"),
                ("x-ms-owner", "9"),
                ("x-ms-group", "10"),
            ],
        ),
        202,
    );
    let owner = properties(&emulator, "copy", "owner.txt");
    assert_eq!(
        (
            owner.header("x-ms-mode"),
            owner.header("x-ms-owner"),
            owner.header("x-ms-group")
        ),
        ("0640", "9", "10")
    );

    expect_error(
        copy("a.txt", &[("x-ms-file-mode-copy-mode", "override")]),
        400,
        "MissingRequiredHeader",
    );
    expect_error(
        copy(
            "b.txt",
            &[
                ("x-ms-file-owner-copy-mode", "override"),
                ("x-ms-owner", "1"),
            ],
        ),
        400,
        "MissingRequiredHeader",
    );
    expect_error(
        copy("c.txt", &[("x-ms-file-mode-copy-mode", "sideways")]),
        400,
        "InvalidHeaderValue",
    );

    // A symbolic link is neither a source nor a destination.
    symbolic_link(&emulator, "copy", "link", "src.txt");
    let refused = "XNfs4FileTypeUnsupportedException";
    expect_error(copy("link", &[]), 400, refused);
    let link_source = format!("{}/{ACCOUNT}/copy/link", emulator.base);
    expect_error(
        emulator.send(
            "PUT",
            &format!("/{ACCOUNT}/copy/from-link.txt"),
            &[("x-ms-copy-source", &link_source)],
            b"",
        ),
        400,
        refused,
    );

    // Copying over a hard-linked name rewrites the shared file.
    expect(hard_link(&emulator, "copy", "alias.txt", "mode.txt"), 201);
    file(&emulator, "copy", "small.txt", 2, &[]);
    put(&emulator, "copy", "small.txt", 0, b"hi");
    let small = format!("{}/{ACCOUNT}/copy/small.txt", emulator.base);
    expect(
        emulator.send(
            "PUT",
            &format!("/{ACCOUNT}/copy/alias.txt"),
            &[("x-ms-copy-source", &small)],
            b"",
        ),
        202,
    );
    assert_eq!(read(&emulator, "copy", "mode.txt"), b"hi");
    assert_eq!(
        properties(&emulator, "copy", "mode.txt").header("x-ms-link-count"),
        "2"
    );
}

#[test]
fn a_share_snapshot_keeps_hard_links_and_symbolic_links() {
    let emulator = Emulator::start(None);
    nfs_share(&emulator, "snap");
    file(&emulator, "snap", "a.txt", 3, &[("x-ms-mode", "0600")]);
    put(&emulator, "snap", "a.txt", 0, b"old");
    expect(hard_link(&emulator, "snap", "b.txt", "a.txt"), 201);
    expect(symbolic_link(&emulator, "snap", "s", "a.txt"), 201);
    let snapshot = expect(
        emulator.send(
            "PUT",
            &format!("/{ACCOUNT}/snap?restype=share&comp=snapshot"),
            &[],
            b"",
        ),
        201,
    );
    let at = snapshot.header("x-ms-snapshot").to_owned();

    // Change the live share: new content, one name gone, the symbolic link replaced.
    put(&emulator, "snap", "a.txt", 0, b"new");
    expect(
        emulator.send("DELETE", &format!("/{ACCOUNT}/snap/a.txt"), &[], b""),
        202,
    );
    expect(
        emulator.send("DELETE", &format!("/{ACCOUNT}/snap/s"), &[], b""),
        202,
    );
    expect(symbolic_link(&emulator, "snap", "s", "elsewhere"), 201);

    let snapped = |path: &str, method: &str, extra: &str| {
        let path = if path.is_empty() {
            String::new()
        } else {
            format!("/{path}")
        };
        emulator.send(
            method,
            &format!("/{ACCOUNT}/snap{path}?sharesnapshot={at}{extra}"),
            &[],
            b"",
        )
    };
    let old = expect(snapped("a.txt", "GET", ""), 200);
    assert_eq!(old.body, b"old");
    assert_eq!(old.header("x-ms-link-count"), "2");
    assert_eq!(old.header("x-ms-mode"), "0600");
    assert_eq!(
        expect(snapped("b.txt", "HEAD", ""), 200).header("x-ms-link-count"),
        "2"
    );
    assert_eq!(
        expect(snapped("s", "GET", "&restype=symboliclink"), 200).header("x-ms-link-text"),
        "a.txt"
    );
    let listing = expect(snapped("", "GET", "&restype=directory&comp=list"), 200);
    assert_eq!(tags(&listing, "Name"), ["a.txt", "b.txt", "s"]);

    // The live share has moved on: one name left, and the replaced link text.
    assert_eq!(
        properties(&emulator, "snap", "b.txt").header("x-ms-link-count"),
        "1"
    );
    assert_eq!(read(&emulator, "snap", "b.txt"), b"new");
    assert_eq!(
        expect(
            emulator.send(
                "GET",
                &format!("/{ACCOUNT}/snap/s?restype=symboliclink"),
                &[],
                b""
            ),
            200
        )
        .header("x-ms-link-text"),
        "elsewhere"
    );
    // A deleted share frees snapshot and live content alike.
    expect(
        emulator.send(
            "DELETE",
            &format!("/{ACCOUNT}/snap?restype=share"),
            &[("x-ms-delete-snapshots", "include")],
            b"",
        ),
        202,
    );
}

#[test]
fn ranges_and_aborted_copies_work_on_nfs_files() {
    let emulator = Emulator::start(None);
    nfs_share(&emulator, "rng");
    file(&emulator, "rng", "src.bin", 1024, &[]);
    put(&emulator, "rng", "src.bin", 0, b"aaaa");
    put(&emulator, "rng", "src.bin", 512, b"bbbb");

    let ranges = |path: &str| {
        let reply = expect(
            emulator.send(
                "GET",
                &format!("/{ACCOUNT}/rng/{path}?comp=rangelist"),
                &[],
                b"",
            ),
            200,
        );
        (tags(&reply, "Start"), tags(&reply, "End"))
    };
    assert_eq!(
        ranges("src.bin"),
        (
            vec!["0".to_owned(), "512".to_owned()],
            vec!["3".to_owned(), "515".to_owned()]
        )
    );

    // Put Range From URL copies a window of another file of the share.
    file(&emulator, "rng", "dst.bin", 4, &[]);
    let source = format!("{}/{ACCOUNT}/rng/src.bin", emulator.base);
    let from_url = |target: &str, source_url: &str| {
        emulator.send(
            "PUT",
            &format!("/{ACCOUNT}/rng/{target}?comp=range"),
            &[
                ("x-ms-copy-source", source_url),
                ("x-ms-source-range", "bytes=512-515"),
                ("x-ms-range", "bytes=0-3"),
                ("x-ms-write", "update"),
            ],
            b"",
        )
    };
    expect(from_url("dst.bin", &source), 201);
    assert_eq!(read(&emulator, "rng", "dst.bin"), b"bbbb");

    // A symbolic link is neither the source nor the target of a ranged write.
    expect(symbolic_link(&emulator, "rng", "link", "src.bin"), 201);
    let refused = "XNfs4FileTypeUnsupportedException";
    expect_error(
        from_url("dst.bin", &format!("{}/{ACCOUNT}/rng/link", emulator.base)),
        400,
        refused,
    );
    expect_error(from_url("link", &source), 400, refused);

    // Copies finish at once, so there is never one to abort.
    expect_error(
        emulator.send(
            "PUT",
            &format!(
                "/{ACCOUNT}/rng/dst.bin?comp=copy&copyid=00000000-0000-0000-0000-000000000000"
            ),
            &[("x-ms-copy-action", "abort")],
            b"",
        ),
        409,
        "NoPendingCopyOperation",
    );

    // Clearing a range deallocates it.
    expect(
        emulator.send(
            "PUT",
            &format!("/{ACCOUNT}/rng/src.bin?comp=range"),
            &[("x-ms-range", "bytes=0-3"), ("x-ms-write", "clear")],
            b"",
        ),
        201,
    );
    assert_eq!(
        ranges("src.bin"),
        (vec!["512".to_owned()], vec!["515".to_owned()])
    );
    assert_eq!(
        usage(&emulator, "rng"),
        "8",
        "4 bytes in src.bin and 4 in dst.bin"
    );
}

#[test]
fn metadata_and_soft_delete_keep_the_protocol() {
    let emulator = Emulator::start_with(None, &["--share-retention-days", "1"]);
    expect(
        emulator.send(
            "PUT",
            &format!("/{ACCOUNT}/meta?restype=share"),
            &[
                ("x-ms-enabled-protocols", "NFS"),
                ("x-ms-root-squash", "RootSquash"),
            ],
            b"",
        ),
        201,
    );
    expect(
        emulator.send(
            "PUT",
            &format!("/{ACCOUNT}/meta?restype=share&comp=metadata"),
            &[("x-ms-meta-owner", "ada")],
            b"",
        ),
        200,
    );
    let share = expect(
        emulator.send(
            "GET",
            &format!("/{ACCOUNT}/meta?restype=share&comp=metadata"),
            &[],
            b"",
        ),
        200,
    );
    assert_eq!(share.header("x-ms-meta-owner"), "ada");
    assert_eq!(share.header("x-ms-enabled-protocols"), "NFS");
    assert_eq!(share.header("x-ms-root-squash"), "RootSquash");

    directory(&emulator, "meta", "d", &[]);
    expect(
        emulator.send(
            "PUT",
            &format!("/{ACCOUNT}/meta/d?restype=directory&comp=metadata"),
            &[("x-ms-meta-k", "v")],
            b"",
        ),
        200,
    );
    let dir = expect(
        emulator.send(
            "GET",
            &format!("/{ACCOUNT}/meta/d?restype=directory&comp=metadata"),
            &[],
            b"",
        ),
        200,
    );
    assert_eq!(dir.header("x-ms-meta-k"), "v");
    assert_eq!(dir.header("x-ms-mode"), "0755");
    assert_eq!(dir.header("x-ms-file-file-type"), "Directory");

    file(&emulator, "meta", "d/f.txt", 3, &[("x-ms-mode", "0600")]);
    put(&emulator, "meta", "d/f.txt", 0, b"abc");
    expect(hard_link(&emulator, "meta", "d/g.txt", "d/f.txt"), 201);

    // A deleted share comes back under any name with its protocol, settings, modes and links.
    expect(
        emulator.send(
            "DELETE",
            &format!("/{ACCOUNT}/meta?restype=share"),
            &[],
            b"",
        ),
        202,
    );
    expect_error(
        emulator.send("HEAD", &format!("/{ACCOUNT}/meta?restype=share"), &[], b""),
        404,
        "ShareNotFound",
    );
    let deleted = expect(
        emulator.send(
            "GET",
            &format!("/{ACCOUNT}?comp=list&include=deleted"),
            &[],
            b"",
        ),
        200,
    );
    let version = tags(&deleted, "Version").remove(0);
    expect(
        emulator.send(
            "PUT",
            &format!("/{ACCOUNT}/restored?restype=share&comp=undelete"),
            &[
                ("x-ms-deleted-share-name", "meta"),
                ("x-ms-deleted-share-version", &version),
            ],
            b"",
        ),
        201,
    );
    let restored = expect(
        emulator.send(
            "HEAD",
            &format!("/{ACCOUNT}/restored?restype=share"),
            &[],
            b"",
        ),
        200,
    );
    assert_eq!(restored.header("x-ms-enabled-protocols"), "NFS");
    assert_eq!(restored.header("x-ms-root-squash"), "RootSquash");
    let back = properties(&emulator, "restored", "d/f.txt");
    assert_eq!(back.header("x-ms-mode"), "0600");
    assert_eq!(back.header("x-ms-link-count"), "2");
    assert_eq!(read(&emulator, "restored", "d/g.txt"), b"abc");
}

#[test]
fn nfs_state_survives_a_restart() {
    let data = tempfile::tempdir().unwrap();
    {
        let emulator = Emulator::start(Some(data.path()));
        expect(
            emulator.send(
                "PUT",
                &format!("/{ACCOUNT}/keep?restype=share"),
                &[
                    ("x-ms-enabled-protocols", "NFS"),
                    ("x-ms-root-squash", "AllSquash"),
                ],
                b"",
            ),
            201,
        );
        directory(&emulator, "keep", "d", &[]);
        file(
            &emulator,
            "keep",
            "d/a.txt",
            5,
            &[
                ("x-ms-mode", "0640"),
                ("x-ms-owner", "42"),
                ("x-ms-group", "43"),
            ],
        );
        put(&emulator, "keep", "d/a.txt", 0, b"state");
        expect(hard_link(&emulator, "keep", "b.txt", "d/a.txt"), 201);
        expect(symbolic_link(&emulator, "keep", "s", "d/a.txt"), 201);
    }
    let emulator = Emulator::start(Some(data.path()));
    let share = expect(
        emulator.send("HEAD", &format!("/{ACCOUNT}/keep?restype=share"), &[], b""),
        200,
    );
    assert_eq!(share.header("x-ms-enabled-protocols"), "NFS");
    assert_eq!(share.header("x-ms-root-squash"), "AllSquash");
    let first = properties(&emulator, "keep", "d/a.txt");
    assert_eq!(
        (
            first.header("x-ms-mode"),
            first.header("x-ms-owner"),
            first.header("x-ms-group")
        ),
        ("0640", "42", "43")
    );
    assert_eq!(first.header("x-ms-link-count"), "2");
    assert_eq!(
        properties(&emulator, "keep", "b.txt").header("x-ms-file-id"),
        first.header("x-ms-file-id")
    );
    assert_eq!(read(&emulator, "keep", "b.txt"), b"state");
    assert_eq!(
        expect(
            emulator.send(
                "GET",
                &format!("/{ACCOUNT}/keep/s?restype=symboliclink"),
                &[],
                b""
            ),
            200
        )
        .header("x-ms-link-text"),
        "d/a.txt"
    );
    // Deleting the first name after a restart still leaves the file under the other.
    assert_eq!(
        expect(
            emulator.send("DELETE", &format!("/{ACCOUNT}/keep/d/a.txt"), &[], b""),
            202
        )
        .header("x-ms-link-count"),
        "1"
    );
    assert_eq!(read(&emulator, "keep", "b.txt"), b"state");
}

#[test]
fn an_older_data_directory_gains_the_nfs_columns_and_stays_smb() {
    let directory = tempfile::tempdir().unwrap();
    let files = directory.path().join("file");
    std::fs::create_dir_all(files.join("content")).unwrap();
    {
        // The metadata schema as it was before ADR-0029: no protocol, POSIX or link columns.
        let db = rusqlite::Connection::open(files.join("metadata.sqlite3")).unwrap();
        db.execute_batch(
            "CREATE TABLE shares (
                id INTEGER PRIMARY KEY, account TEXT NOT NULL, name TEXT NOT NULL, snapshot INTEGER NOT NULL,
                etag TEXT NOT NULL, modified INTEGER NOT NULL, quota INTEGER NOT NULL,
                access_tier TEXT NOT NULL, access_tier_changed INTEGER NOT NULL,
                metadata TEXT NOT NULL, acl TEXT NOT NULL, lease TEXT, next_file_id INTEGER NOT NULL,
                UNIQUE (account, name, snapshot)
             ) STRICT;
             CREATE TABLE nodes (
                share_id INTEGER NOT NULL REFERENCES shares (id) ON DELETE CASCADE,
                file_id INTEGER NOT NULL, parent_id INTEGER, name TEXT NOT NULL, key TEXT NOT NULL,
                is_dir INTEGER NOT NULL, etag TEXT NOT NULL, modified INTEGER NOT NULL,
                attributes INTEGER NOT NULL, creation INTEGER NOT NULL, last_write INTEGER NOT NULL,
                change_time INTEGER NOT NULL, permission_key TEXT NOT NULL, metadata TEXT NOT NULL,
                length INTEGER NOT NULL, content_type TEXT NOT NULL, content_encoding TEXT,
                content_language TEXT, content_disposition TEXT, cache_control TEXT, md5 TEXT,
                lease TEXT, copy TEXT,
                PRIMARY KEY (share_id, file_id),
                UNIQUE (share_id, parent_id, key)
             ) STRICT;
             INSERT INTO shares VALUES (1, 'testaccount', 'old', 0, '\"0x1\"', 1700000000000, 5, 'Hot', 1700000000000, '{}', '[]', NULL, 2);
             INSERT INTO nodes (share_id, file_id, parent_id, name, key, is_dir, etag, modified, attributes,
                creation, last_write, change_time, permission_key, metadata, length, content_type)
             VALUES (1, 0, NULL, '', '', 1, '\"0x2\"', 1700000000000, 8, 0, 0, 0, 'k', '{}', 0, '');
             INSERT INTO nodes (share_id, file_id, parent_id, name, key, is_dir, etag, modified, attributes,
                creation, last_write, change_time, permission_key, metadata, length, content_type)
             VALUES (1, 1, 0, 'legacy.txt', 'LEGACY.TXT', 0, '\"0x3\"', 1700000000000, 16, 0, 0, 0, 'k', '{}', 9, 'text/old');",
        )
        .unwrap();
    }
    let emulator = Emulator::start(Some(directory.path()));
    let share = expect(
        emulator.send("HEAD", &format!("/{ACCOUNT}/old?restype=share"), &[], b""),
        200,
    );
    assert_eq!(share.header("x-ms-enabled-protocols"), "SMB");
    assert!(share.lacks("x-ms-root-squash"));
    let legacy = properties(&emulator, "old", "legacy.txt");
    assert_eq!(legacy.header("content-length"), "9");
    assert_eq!(legacy.header("x-ms-file-attributes"), "Archive");
    assert!(legacy.lacks("x-ms-mode"));
    // The old share takes new SMB files, and the same data directory takes an NFS share.
    file(&emulator, "old", "new.txt", 1, &[]);
    nfs_share(&emulator, "fresh");
    file(&emulator, "fresh", "f.txt", 1, &[]);
    expect(hard_link(&emulator, "fresh", "g.txt", "f.txt"), 201);
}
