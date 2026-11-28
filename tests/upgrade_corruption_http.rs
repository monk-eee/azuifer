//! Upgrade, downgrade and corruption behavior of the four persistent stores (Blob and DFS,
//! Files, Queue, Table), against the built binary.
//!
//! A data directory written by an older release must open and keep its data. One written by a
//! newer release, a corrupt one, and one whose directories or files are links must make startup
//! fail with a message that names the problem, and must not be modified by the refusal. A
//! content file that has gone missing must answer an error and leave the server running.

use base64::{Engine as _, engine::general_purpose::STANDARD};
use hmac::{Hmac, KeyInit as _, Mac as _};
use reqwest::{Url, blocking::Client};
use rusqlite::Connection;
use std::{
    collections::{BTreeMap, HashMap},
    fs,
    io::{BufRead as _, BufReader, Read as _},
    path::{Path, PathBuf},
    process::{Child, Command, Stdio},
    time::{Duration, Instant, SystemTime},
};

const ACCOUNT: &str = "devstoreaccount1";
const VERSION: &str = "2023-11-03";
const KEY: &[u8] = b"synthetic-account-key-for-upgrade-tests";
const FUTURE: i64 = 9999;

/// A store under test: the service that opens it, and where its files live below the data
/// directory.
struct Store {
    service: &'static str,
    /// The directory holding the database and lock, relative to the data directory.
    directory: &'static str,
    database: &'static str,
    lock: &'static str,
    /// The directory of content files, if the store has one.
    content: Option<&'static str>,
}

const STORES: [Store; 4] = [
    Store {
        service: "blob",
        directory: "",
        database: "metadata.sqlite3",
        lock: "azuifer.lock",
        content: Some("content"),
    },
    Store {
        service: "file",
        directory: "file",
        database: "metadata.sqlite3",
        lock: "azuifer.lock",
        content: Some("content"),
    },
    Store {
        service: "queue",
        directory: "queue",
        database: "queue.sqlite3",
        lock: "queue.lock",
        content: None,
    },
    Store {
        service: "table",
        directory: "table",
        database: "table.sqlite3",
        lock: "table.lock",
        content: None,
    },
];

impl Store {
    fn dir(&self, data: &Path) -> PathBuf {
        data.join(self.directory)
    }

    fn database(&self, data: &Path) -> PathBuf {
        self.dir(data).join(self.database)
    }
}

fn command(data: &Path, service: &str, extra: &[&str]) -> Command {
    let mut command = Command::new(env!("CARGO_BIN_EXE_azuifer"));
    for (name, _) in std::env::vars_os() {
        let upper = name.to_string_lossy().to_ascii_uppercase();
        if upper.starts_with("AZUIFER_") || upper.starts_with("OTEL_") {
            command.env_remove(name);
        }
    }
    command
        .env("AZUIFER_ACCOUNT_KEY", STANDARD.encode(KEY))
        .args(["serve", "--port", "0", "--admin-port", "0", "--services"])
        .arg(service)
        .arg("--location")
        .arg(data)
        .arg("--shutdown-on-stdin-eof")
        .args(extra);
    command
}

struct Server {
    child: Child,
    urls: HashMap<String, String>,
}

impl Server {
    fn start(data: &Path, service: &str, extra: &[&str]) -> Self {
        let mut child = command(data, service, extra)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::null())
            .spawn()
            .expect("start Azuifer");
        let mut lines = BufReader::new(child.stdout.take().expect("piped stdout")).lines();
        let mut urls = HashMap::new();
        for line in lines.by_ref() {
            let Ok(line) = line else { break };
            let Some((name, url)) = line.split_once("_url=") else {
                continue;
            };
            urls.insert(name.to_owned(), url.to_owned());
            if name == "admin" {
                break;
            }
        }
        assert!(urls.contains_key("admin"), "{service} did not start");
        std::thread::spawn(move || lines.for_each(drop));
        Self { child, urls }
    }

    fn url(&self, name: &str) -> &str {
        &self.urls[name]
    }

    fn alive(&mut self) -> bool {
        matches!(self.child.try_wait(), Ok(None))
    }
}

impl Drop for Server {
    fn drop(&mut self) {
        drop(self.child.stdin.take());
        let _ = self.child.wait();
    }
}

/// Starts Azuifer where it must refuse to start, and returns what it said. Standard input is
/// closed, so a server that does start shuts itself down at once and is reported as a failure
/// of the test.
fn refused(data: &Path, service: &str) -> String {
    let mut child = command(data, service, &[])
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::piped())
        .spawn()
        .expect("start Azuifer");
    let deadline = Instant::now() + Duration::from_secs(60);
    let status = loop {
        if let Some(status) = child.try_wait().unwrap() {
            break status;
        }
        assert!(
            Instant::now() < deadline,
            "{service} neither started nor failed"
        );
        std::thread::sleep(Duration::from_millis(20));
    };
    let mut stderr = String::new();
    child
        .stderr
        .take()
        .unwrap()
        .read_to_string(&mut stderr)
        .unwrap();
    assert!(
        !status.success(),
        "{service} started on a directory it should refuse:\n{stderr}"
    );
    assert!(
        !stderr.contains("panicked"),
        "{service} panicked:\n{stderr}"
    );
    assert!(
        stderr.lines().any(|line| line.starts_with("Error:")),
        "{service} gave no error message:\n{stderr}"
    );
    stderr
}

fn client() -> Client {
    Client::builder()
        .no_proxy()
        .timeout(Duration::from_secs(10))
        .build()
        .unwrap()
}

struct Reply {
    status: u16,
    body: String,
}

/// A Shared Key signed request to one of the server's listeners, not yet sent.
fn signed(
    server: &Server,
    service: &str,
    method: &str,
    path: &str,
    extra: &[(&str, &str)],
    body: &[u8],
) -> reqwest::blocking::RequestBuilder {
    let url = Url::parse(&format!("{}{path}", server.url(service))).unwrap();
    let mut headers = BTreeMap::from([
        (
            "x-ms-date".to_owned(),
            httpdate::fmt_http_date(SystemTime::now()),
        ),
        ("x-ms-version".to_owned(), VERSION.to_owned()),
    ]);
    for (name, value) in extra {
        headers.insert((*name).to_owned(), (*value).to_owned());
    }
    let length = if body.is_empty() {
        String::new()
    } else {
        body.len().to_string()
    };
    let lines = [
        method,
        "",
        "",
        length.as_str(),
        "",
        "",
        "",
        "",
        "",
        "",
        "",
        "",
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
    let query: String = query.iter().map(|(n, v)| format!("\n{n}:{v}")).collect();
    let message = format!(
        "{}\n{extensions}/{ACCOUNT}{}{query}",
        lines.join("\n"),
        url.path()
    );
    let mut mac = Hmac::<sha2::Sha256>::new_from_slice(KEY).unwrap();
    mac.update(message.as_bytes());
    let mut request = client().request(method.parse().unwrap(), url).header(
        "authorization",
        format!(
            "SharedKey {ACCOUNT}:{}",
            STANDARD.encode(mac.finalize().into_bytes())
        ),
    );
    for (name, value) in &headers {
        request = request.header(name, value);
    }
    if matches!(method, "PUT" | "POST") {
        request = request.body(body.to_vec());
    }
    request
}

fn call(
    server: &Server,
    service: &str,
    method: &str,
    path: &str,
    extra: &[(&str, &str)],
    body: &[u8],
) -> Reply {
    let response = signed(server, service, method, path, extra, body)
        .send()
        .unwrap();
    Reply {
        status: response.status().as_u16(),
        body: response.text().unwrap(),
    }
}

fn expect(reply: Reply, status: u16) -> Reply {
    assert_eq!(reply.status, status, "{}", reply.body);
    reply
}

/// Starts the store's service on a new data directory and stops it, leaving the files a
/// release would leave.
fn initialized(store: &Store) -> tempfile::TempDir {
    let data = tempfile::tempdir().unwrap();
    drop(Server::start(data.path(), store.service, &[]));
    assert!(
        store.database(data.path()).exists(),
        "{} wrote no database",
        store.service
    );
    data
}

fn user_version(path: &Path) -> i64 {
    Connection::open(path)
        .unwrap()
        .pragma_query_value(None, "user_version", |row| row.get(0))
        .unwrap()
}

fn set_user_version(path: &Path, version: i64) {
    let db = Connection::open(path).unwrap();
    db.pragma_update(None, "user_version", version).unwrap();
}

#[test]
fn a_database_from_a_newer_release_is_refused_untouched_and_opens_again_once_restored() {
    for store in &STORES {
        let data = initialized(store);
        let database = store.database(data.path());
        let supported = user_version(&database);
        set_user_version(&database, FUTURE);

        let said = refused(data.path(), store.service);
        assert!(
            said.contains("newer") && said.contains(&FUTURE.to_string()),
            "{}: the refusal should say the schema is newer:\n{said}",
            store.service
        );
        assert_eq!(
            user_version(&database),
            FUTURE,
            "{}: a refused open must not change the schema version",
            store.service
        );

        set_user_version(&database, supported);
        assert!(
            Server::start(data.path(), store.service, &[]).alive(),
            "{}",
            store.service
        );
    }
}

#[test]
fn every_store_stamps_the_schema_version_it_writes() {
    for store in &STORES {
        let data = initialized(store);
        assert!(
            user_version(&store.database(data.path())) >= 1,
            "{}",
            store.service
        );
    }
}

#[test]
fn a_corrupt_database_stops_startup_with_a_message() {
    for store in &STORES {
        let data = initialized(store);
        let database = store.database(data.path());
        for suffix in ["-wal", "-shm"] {
            let mut side = database.clone().into_os_string();
            side.push(suffix);
            let _ = fs::remove_file(side);
        }
        fs::write(&database, vec![0xA5u8; 8192]).unwrap();
        let said = refused(data.path(), store.service);
        assert!(
            said.contains(store.database) || said.to_lowercase().contains("not a database"),
            "{}: the message should point at the database:\n{said}",
            store.service
        );
    }
}

#[test]
fn a_database_cut_short_stops_startup_with_a_message() {
    for store in &STORES {
        let data = tempfile::tempdir().unwrap();
        {
            let server = Server::start(data.path(), store.service, &[]);
            // The Table Shared Key layout differs from the others, so its database is cut as
            // created; the others hold a queue, a container or a share.
            let created = match store.service {
                "queue" => ("queue", format!("/{ACCOUNT}/cut"), 201),
                "blob" => ("blob", format!("/{ACCOUNT}/cut?restype=container"), 201),
                "file" => ("file", format!("/{ACCOUNT}/cut?restype=share"), 201),
                _ => ("table", String::new(), 0),
            };
            if created.2 != 0 {
                expect(
                    call(&server, created.0, "PUT", &created.1, &[], b""),
                    created.2,
                );
            }
        }
        let database = store.database(data.path());
        let length = fs::metadata(&database).unwrap().len();
        assert!(
            length > 4096,
            "{}: the database is {length} bytes",
            store.service
        );
        let file = fs::OpenOptions::new().write(true).open(&database).unwrap();
        file.set_len(length / 2).unwrap();
        drop(file);
        refused(data.path(), store.service);
    }
}

#[cfg(unix)]
fn link(target: &Path, at: &Path) -> std::io::Result<()> {
    std::os::unix::fs::symlink(target, at)
}

/// A symbolic link where the account may create one, and for a directory otherwise a junction,
/// which is also a reparse point and needs no privilege.
#[cfg(windows)]
fn link(target: &Path, at: &Path) -> std::io::Result<()> {
    let made = if target.is_dir() {
        std::os::windows::fs::symlink_dir(target, at)
    } else {
        std::os::windows::fs::symlink_file(target, at)
    };
    if made.is_ok() || !target.is_dir() {
        return made;
    }
    let status = Command::new("cmd")
        .arg("/C")
        .arg("mklink")
        .arg("/J")
        .arg(at)
        .arg(target)
        .stdout(Stdio::null())
        .status()?;
    if status.success() { Ok(()) } else { made }
}

/// Moves `path` aside and puts a link to it in its place.
fn replace_with_link(path: &Path) -> bool {
    let mut real = path.as_os_str().to_owned();
    real.push(".real");
    let real = PathBuf::from(real);
    fs::rename(path, &real).unwrap();
    if let Err(error) = link(&real, path) {
        eprintln!(
            "skipping {}: this account cannot create links ({error})",
            path.display()
        );
        fs::rename(&real, path).unwrap();
        return false;
    }
    true
}

#[test]
fn a_store_refuses_a_directory_lock_or_database_that_is_a_link() {
    for store in &STORES {
        let mut parts = vec![
            ("lock", store.lock.to_owned()),
            ("database", store.database.to_owned()),
        ];
        if let Some(content) = store.content {
            parts.push(("content directory", content.to_owned()));
        }
        if !store.directory.is_empty() {
            parts.push(("store directory", String::new()));
        }
        for (what, name) in parts {
            let data = initialized(store);
            let target = if name.is_empty() {
                store.dir(data.path())
            } else {
                store.dir(data.path()).join(&name)
            };
            if !replace_with_link(&target) {
                continue;
            }
            let said = refused(data.path(), store.service);
            let leaf = target.file_name().unwrap().to_string_lossy().into_owned();
            assert!(
                said.contains(&leaf),
                "{} {what}: the message should name {leaf}:\n{said}",
                store.service
            );
        }
    }
}

/// The schema every release up to this one started from: no `user_version`, no blob types,
/// leases, history or hierarchical namespace.
const BLOB_V0: &str = "
CREATE TABLE containers (
    account TEXT NOT NULL, name TEXT NOT NULL, id BLOB NOT NULL, modified INTEGER NOT NULL,
    PRIMARY KEY (account, name)
) STRICT;
CREATE TABLE blobs (
    account TEXT NOT NULL, container TEXT NOT NULL, name TEXT NOT NULL,
    id BLOB NOT NULL UNIQUE, modified INTEGER NOT NULL, length INTEGER NOT NULL,
    content_type TEXT NOT NULL, md5 TEXT NOT NULL, metadata TEXT NOT NULL, bytes BLOB,
    PRIMARY KEY (account, container, name),
    FOREIGN KEY (account, container) REFERENCES containers (account, name) ON DELETE CASCADE
) STRICT;
CREATE TABLE staged_blocks (
    account TEXT NOT NULL, container TEXT NOT NULL, name TEXT NOT NULL,
    block_id TEXT NOT NULL, width INTEGER NOT NULL,
    id BLOB NOT NULL UNIQUE, length INTEGER NOT NULL, bytes BLOB,
    PRIMARY KEY (account, container, name, block_id),
    FOREIGN KEY (account, container) REFERENCES containers (account, name) ON DELETE CASCADE
) STRICT;
CREATE TABLE committed_blocks (
    account TEXT NOT NULL, container TEXT NOT NULL, name TEXT NOT NULL,
    position INTEGER NOT NULL, block_id TEXT NOT NULL, offset INTEGER NOT NULL, length INTEGER NOT NULL,
    PRIMARY KEY (account, container, name, position),
    FOREIGN KEY (account, container, name) REFERENCES blobs (account, container, name) ON DELETE CASCADE
) STRICT;";

#[test]
fn the_first_release_s_blob_database_is_upgraded_in_place_and_keeps_its_data() {
    let data = tempfile::tempdir().unwrap();
    let id = uuid::Uuid::from_u128(0x1234_5678_9abc_def0_1122_3344_5566_7788);
    let hex = id.simple().to_string();
    fs::create_dir_all(data.path().join("content")).unwrap();
    fs::write(
        data.path().join("content").join(format!("extent-{hex}")),
        b"first release",
    )
    .unwrap();
    {
        let db = Connection::open(data.path().join("metadata.sqlite3")).unwrap();
        db.execute_batch(BLOB_V0).unwrap();
        db.execute_batch(&format!(
            "INSERT INTO containers VALUES ('{ACCOUNT}', 'old', x'00000000000000000000000000000001', 1700000000);
             INSERT INTO blobs VALUES ('{ACCOUNT}', 'old', 'kept.txt', x'{hex}', 1700000000, 13,
                'text/plain', '', '{{\"origin\":\"v0\"}}', NULL);"
        ))
        .unwrap();
        assert_eq!(user_version_of(&db), 0);
    }
    let mut server = Server::start(data.path(), "blob", &[]);
    let read = expect(
        call(
            &server,
            "blob",
            "GET",
            &format!("/{ACCOUNT}/old/kept.txt"),
            &[],
            b"",
        ),
        200,
    );
    assert_eq!(read.body, "first release");
    let listing = expect(
        call(
            &server,
            "blob",
            "GET",
            &format!("/{ACCOUNT}/old?restype=container&comp=list"),
            &[],
            b"",
        ),
        200,
    );
    assert!(
        listing.body.contains("<Name>kept.txt</Name>"),
        "{}",
        listing.body
    );
    let put = [("x-ms-blob-type", "BlockBlob")];
    expect(
        call(
            &server,
            "blob",
            "PUT",
            &format!("/{ACCOUNT}/old/new.txt"),
            &put,
            b"written after",
        ),
        201,
    );
    expect(
        call(
            &server,
            "blob",
            "GET",
            &format!("/{ACCOUNT}/old/new.txt"),
            &[],
            b"",
        ),
        200,
    );
    assert!(server.alive());
    drop(server);
    assert!(
        user_version(&data.path().join("metadata.sqlite3")) > 0,
        "the upgrade is stamped"
    );

    let server = Server::start(data.path(), "blob", &[]);
    let read = expect(
        call(
            &server,
            "blob",
            "GET",
            &format!("/{ACCOUNT}/old/kept.txt"),
            &[],
            b"",
        ),
        200,
    );
    assert_eq!(read.body, "first release", "the upgraded database reopens");
}

fn user_version_of(db: &Connection) -> i64 {
    db.pragma_query_value(None, "user_version", |row| row.get(0))
        .unwrap()
}

fn failures(text: &str, store: &str, kind: &str) -> Option<f64> {
    let series = format!("azuifer_backend_failures_total{{store=\"{store}\",kind=\"{kind}\"}}");
    text.lines()
        .find_map(|line| line.strip_prefix(&series)?.trim().parse().ok())
}

fn scrape(server: &Server) -> String {
    client()
        .get(format!("{}/metrics", server.url("admin")))
        .send()
        .unwrap()
        .text()
        .unwrap()
}

fn extent_files(directory: &Path) -> Vec<PathBuf> {
    fs::read_dir(directory)
        .unwrap()
        .map(|entry| entry.unwrap().path())
        .filter(|path| {
            path.file_name()
                .unwrap()
                .to_string_lossy()
                .starts_with("extent-")
        })
        .collect()
}

#[test]
fn a_blob_whose_content_file_is_missing_answers_500_counts_the_failure_and_leaves_the_server_running()
 {
    let data = tempfile::tempdir().unwrap();
    {
        let server = Server::start(data.path(), "blob", &[]);
        expect(
            call(
                &server,
                "blob",
                "PUT",
                &format!("/{ACCOUNT}/gone?restype=container"),
                &[],
                b"",
            ),
            201,
        );
        let put = [("x-ms-blob-type", "BlockBlob")];
        for name in ["a", "b"] {
            expect(
                call(
                    &server,
                    "blob",
                    "PUT",
                    &format!("/{ACCOUNT}/gone/{name}"),
                    &put,
                    name.as_bytes(),
                ),
                201,
            );
        }
    }
    let content = data.path().join("content");
    let extents = extent_files(&content);
    assert_eq!(extents.len(), 2);
    fs::remove_file(&extents[0]).unwrap();

    let mut server = Server::start(data.path(), "blob", &["--prometheus"]);
    let statuses: Vec<u16> = ["a", "b"]
        .iter()
        .map(|name| {
            call(
                &server,
                "blob",
                "GET",
                &format!("/{ACCOUNT}/gone/{name}"),
                &[],
                b"",
            )
            .status
        })
        .collect();
    assert_eq!(
        statuses.iter().filter(|status| **status == 500).count(),
        1,
        "{statuses:?}"
    );
    assert_eq!(
        statuses.iter().filter(|status| **status == 200).count(),
        1,
        "{statuses:?}"
    );
    let text = scrape(&server);
    assert_eq!(failures(&text, "namespace", "io"), Some(1.0), "{text}");
    expect(
        call(
            &server,
            "blob",
            "GET",
            &format!("/{ACCOUNT}/gone?restype=container&comp=list"),
            &[],
            b"",
        ),
        200,
    );
    assert!(server.alive());
}

#[test]
fn a_file_whose_content_file_is_missing_does_not_stop_the_server_and_is_counted() {
    let data = tempfile::tempdir().unwrap();
    let file = format!("/{ACCOUNT}/lost/f.bin");
    {
        let server = Server::start(data.path(), "file", &[]);
        expect(
            call(
                &server,
                "file",
                "PUT",
                &format!("/{ACCOUNT}/lost?restype=share"),
                &[],
                b"",
            ),
            201,
        );
        let create = [
            ("x-ms-type", "file"),
            ("x-ms-content-length", "8"),
            ("x-ms-file-attributes", "None"),
            ("x-ms-file-creation-time", "now"),
            ("x-ms-file-last-write-time", "now"),
            ("x-ms-file-permission", "inherit"),
        ];
        expect(call(&server, "file", "PUT", &file, &create, b""), 201);
        let range = [("x-ms-write", "update"), ("x-ms-range", "bytes=0-7")];
        expect(
            call(
                &server,
                "file",
                "PUT",
                &format!("{file}?comp=range"),
                &range,
                b"12345678",
            ),
            201,
        );
    }
    let content = data.path().join("file").join("content");
    for extent in extent_files(&content) {
        fs::remove_file(extent).unwrap();
    }

    let mut server = Server::start(data.path(), "file", &["--prometheus"]);
    let download = call(&server, "file", "GET", &file, &[], b"");
    assert_eq!(download.status, 500, "{}", download.body);
    assert!(
        download.body.contains("<Code>InternalError</Code>"),
        "{}",
        download.body
    );
    expect(call(&server, "file", "HEAD", &file, &[], b""), 200);
    assert!(server.alive());
    let text = scrape(&server);
    assert_eq!(failures(&text, "files", "io"), Some(1.0), "{text}");
}
