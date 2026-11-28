//! HTTP protocol tests of the DFS operations: file lifecycle, append and flush, rename,
//! leases, POSIX permissions and ACLs, authentication, limits, and persistence.
//! Blob and DFS interoperability lives in `dfs_cross_http.rs`.

use base64::{
    Engine as _,
    engine::general_purpose::{STANDARD, URL_SAFE_NO_PAD},
};
use hmac::{Hmac, Mac as _};
use reqwest::{
    Method, Url,
    blocking::{Body, Client, Response},
};
use serde_json::{Value, json};
use sha2::Sha256;
use std::{
    collections::BTreeMap,
    io::{BufRead as _, BufReader, Read as _, Write as _},
    net::TcpStream,
    path::Path,
    process::{Child, Command, Stdio},
    sync::{
        atomic::{AtomicU64, Ordering},
        mpsc,
    },
    thread,
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};

const ACCOUNT: &str = "testaccount";
const VERSION: &str = "2023-11-03";
const KEY: [u8; 32] = [41; 32];
const LAKE: &str = "/testaccount/lake";
const OID: &str = "11111111-2222-3333-4444-555555555555";
const OTHER_OID: &str = "99999999-8888-7777-6666-555555555555";

enum Auth {
    Key,
    Lite,
    Anonymous,
    Bearer(String),
    Sas(String),
}

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
    fn start(extra: &[&str]) -> Self {
        Self::launch(None, true, extra)
    }

    fn start_on_disk(location: &Path, extra: &[&str]) -> Self {
        Self::launch(Some(location), true, extra)
    }

    fn start_flat(extra: &[&str]) -> Self {
        Self::launch(None, false, extra)
    }

    fn launch(location: Option<&Path>, hns: bool, extra: &[&str]) -> Self {
        let mut command = command();
        command.args([
            "serve",
            "--port",
            "0",
            "--admin-port",
            "0",
            "--services",
            "blob,dfs",
            "--shutdown-on-stdin-eof",
        ]);
        if hns {
            command.args(["--hns-accounts", ACCOUNT]);
        }
        match location {
            Some(location) => command.arg("--location").arg(location),
            None => command.arg("--in-memory"),
        };
        command
            .args(extra)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped());
        let mut child = command.spawn().expect("start Azuifer");
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
                .timeout(Duration::from_secs(20))
                .build()
                .unwrap(),
            offset: AtomicU64::new(0),
        }
    }

    fn crash(mut self) {
        self.child.kill().expect("terminate the emulator");
        self.child.wait().expect("reap the emulator");
    }

    fn now(&self) -> SystemTime {
        SystemTime::now() + Duration::from_secs(self.offset.load(Ordering::Relaxed))
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
        auth: &Auth,
    ) -> Response {
        let method = Method::from_bytes(method.as_bytes()).unwrap();
        let path = match auth {
            Auth::Sas(token) if path.contains('?') => format!("{path}&{token}"),
            Auth::Sas(token) => format!("{path}?{token}"),
            _ => path.to_owned(),
        };
        let url = Url::parse(&format!("{base}{path}")).unwrap();
        let has_body = matches!(method.as_str(), "PUT" | "PATCH" | "POST");
        let length = has_body.then_some(body.len());
        let signed = match auth {
            Auth::Key => self.shared_key(method.as_str(), &url, headers, length),
            Auth::Lite => self.shared_key_lite(method.as_str(), &url, headers),
            Auth::Anonymous | Auth::Sas(_) => with_version(headers),
            Auth::Bearer(token) => {
                let mut all = with_version(headers);
                all.insert("authorization".into(), format!("Bearer {token}"));
                all
            }
        };
        let mut request = self.client.request(method, url);
        for (name, value) in signed {
            request = request.header(name, value);
        }
        if has_body {
            request = request.body(body.to_vec());
        }
        request.send().expect("HTTP request completed")
    }

    fn dfs(&self, method: &str, path: &str, headers: &[(&str, &str)], body: &[u8]) -> Response {
        self.send(&self.dfs, method, path, headers, body, &Auth::Key)
    }

    fn dfs_as(&self, auth: &Auth, method: &str, path: &str, headers: &[(&str, &str)]) -> Response {
        self.send(&self.dfs, method, path, headers, b"", auth)
    }

    fn blob(&self, method: &str, path: &str, headers: &[(&str, &str)], body: &[u8]) -> Response {
        self.send(&self.blob, method, path, headers, body, &Auth::Key)
    }

    fn shared_key(
        &self,
        method: &str,
        url: &Url,
        extra: &[(&str, &str)],
        length: Option<usize>,
    ) -> BTreeMap<String, String> {
        let mut headers = with_version(extra);
        headers
            .entry("x-ms-date".into())
            .or_insert_with(|| httpdate::fmt_http_date(self.now()));
        if let Some(length) = length {
            headers.insert("content-length".into(), length.to_string());
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
        headers.insert(
            "authorization".into(),
            format!("SharedKey {ACCOUNT}:{}", sign(&message)),
        );
        headers
    }

    fn shared_key_lite(
        &self,
        method: &str,
        url: &Url,
        extra: &[(&str, &str)],
    ) -> BTreeMap<String, String> {
        let mut headers = with_version(extra);
        headers.insert("x-ms-date".into(), httpdate::fmt_http_date(self.now()));
        let extensions: String = headers
            .iter()
            .filter(|(name, _)| name.starts_with("x-ms-"))
            .map(|(name, value)| format!("{name}:{value}\n"))
            .collect();
        let message = format!("{method}\n\n\n\n{extensions}/{ACCOUNT}{}", url.path());
        headers.insert(
            "authorization".into(),
            format!("SharedKeyLite {ACCOUNT}:{}", sign(&message)),
        );
        headers
    }

    fn filesystem(&self) {
        let created = self.dfs("PUT", &format!("{LAKE}?resource=filesystem"), &[], b"");
        assert_eq!(created.status(), 201);
    }

    /// Creates a file with `content` through Create Path, Append Data and Flush Data.
    fn file(&self, path: &str, content: &[u8]) {
        let url = format!("{LAKE}/{path}");
        let created = self.dfs("PUT", &format!("{url}?resource=file"), &[], b"");
        assert_eq!(created.status(), 201, "create {path}");
        if content.is_empty() {
            return;
        }
        let appended = self.dfs(
            "PATCH",
            &format!("{url}?action=append&position=0"),
            &[],
            content,
        );
        assert_eq!(appended.status(), 202, "append {path}");
        let flushed = self.dfs(
            "PATCH",
            &format!("{url}?action=flush&position={}", content.len()),
            &[],
            b"",
        );
        assert_eq!(flushed.status(), 200, "flush {path}");
    }

    fn directory(&self, path: &str) {
        let created = self.dfs(
            "PUT",
            &format!("{LAKE}/{path}?resource=directory"),
            &[],
            b"",
        );
        assert_eq!(created.status(), 201, "create {path}");
    }

    fn token(&self, oid: &str) -> Auth {
        Auth::Bearer(token(oid))
    }
}

fn with_version(extra: &[(&str, &str)]) -> BTreeMap<String, String> {
    let mut headers = BTreeMap::from([("x-ms-version".to_owned(), VERSION.to_owned())]);
    for (name, value) in extra {
        headers.insert((*name).to_owned(), (*value).to_owned());
    }
    headers
}

fn sign_with(key: &[u8], text: &str) -> String {
    let mut mac = Hmac::<Sha256>::new_from_slice(key).unwrap();
    mac.update(text.as_bytes());
    STANDARD.encode(mac.finalize().into_bytes())
}

fn sign(text: &str) -> String {
    sign_with(&KEY, text)
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

fn unix_now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs()
}

/// An unsigned bearer token that reduced-validation mode (`--oauth basic`) accepts.
fn token(oid: &str) -> String {
    let claims = json!({
        "iss": "https://sts.windows.net/72f988bf-86f1-41af-91ab-2d7cd011db47/",
        "aud": "https://storage.azure.com",
        "exp": unix_now() + 3600,
        "oid": oid,
        "tid": "72f988bf-86f1-41af-91ab-2d7cd011db47",
    });
    format!(
        "{}.{}.",
        URL_SAFE_NO_PAD.encode(r#"{"alg":"none"}"#),
        URL_SAFE_NO_PAD.encode(claims.to_string())
    )
}

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

fn in_seconds(emulator: &Emulator, offset: i64) -> String {
    let now = emulator.now().duration_since(UNIX_EPOCH).unwrap().as_secs() as i64;
    iso8601((now + offset) as u64)
}

/// A service SAS (`sr` b, c or d) signed per the documented version 2023-11-03 layout. A
/// directory SAS signs `path` and states its depth in `sdd`.
fn service_sas(resource: &str, path: Option<&str>, permissions: &str, expiry: &str) -> String {
    let canonical = match path {
        Some(path) => format!("/blob/{ACCOUNT}/lake/{path}"),
        None => format!("/blob/{ACCOUNT}/lake"),
    };
    let signed = [
        permissions,
        "",
        expiry,
        canonical.as_str(),
        "",
        "",
        "",
        VERSION,
        resource,
        "",
        "",
        "",
        "",
        "",
        "",
        "",
    ]
    .join("\n");
    let mut query = format!(
        "sv={VERSION}&sr={resource}&sp={permissions}&se={}",
        encode(expiry)
    );
    if resource == "d" {
        let depth = path.map_or(0, |path| path.split('/').count());
        query.push_str(&format!("&sdd={depth}"));
    }
    format!("{query}&sig={}", encode(&sign(&signed)))
}

/// A read-only service SAS for one file that also states the address or the protocol it
/// accepts (`sip`, `spr`); an empty one is left out.
fn restricted_sas(path: &str, address: &str, protocol: &str, expiry: &str) -> String {
    let canonical = format!("/blob/{ACCOUNT}/lake/{path}");
    let signed = [
        "r", "", expiry, &canonical, "", address, protocol, VERSION, "b", "", "", "", "", "", "",
        "",
    ]
    .join("\n");
    let mut query = format!("sv={VERSION}&sr=b&sp=r&se={}", encode(expiry));
    for (name, value) in [("sip", address), ("spr", protocol)] {
        if !value.is_empty() {
            query.push_str(&format!("&{name}={}", encode(value)));
        }
    }
    format!("{query}&sig={}", encode(&sign(&signed)))
}

fn account_sas(permissions: &str, services: &str, types: &str, expiry: &str) -> String {
    let signed =
        format!("{ACCOUNT}\n{permissions}\n{services}\n{types}\n\n{expiry}\n\n\n{VERSION}\n\n");
    format!(
        "sv={VERSION}&ss={services}&srt={types}&sp={permissions}&se={}&sig={}",
        encode(expiry),
        encode(&sign(&signed))
    )
}

fn dfs_error(response: Response, status: u16, code: &str) {
    assert_eq!(response.status().as_u16(), status, "{code}");
    assert_eq!(response.headers()["x-ms-error-code"], code);
    let bytes = response.bytes().unwrap();
    if !bytes.is_empty() {
        let body: Value = serde_json::from_slice(&bytes).unwrap();
        assert_eq!(body["error"]["code"], code);
    }
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

fn json_body(response: Response) -> Value {
    serde_json::from_slice(&response.bytes().unwrap()).unwrap()
}

fn path_names(listing: &Value) -> Vec<String> {
    listing["paths"]
        .as_array()
        .unwrap()
        .iter()
        .map(|path| path["name"].as_str().unwrap().to_owned())
        .collect()
}

#[test]
fn create_path_stores_properties_owner_permissions_and_conflicts() {
    let server = Emulator::start(&[]);
    server.filesystem();
    let file = format!("{LAKE}/a/b.txt");
    let created = server.dfs(
        "PUT",
        &format!("{file}?resource=file"),
        &[
            ("x-ms-properties", "k=dg=="),
            ("x-ms-content-type", "text/plain"),
            ("x-ms-permissions", "rwxr-x---"),
            ("x-ms-owner", "owner1"),
            ("x-ms-group", "group1"),
        ],
        b"",
    );
    assert_eq!(created.status(), 201);
    assert!(created.headers().contains_key("last-modified"));
    let tag = etag(&created);

    let head = server.dfs("HEAD", &file, &[], b"");
    assert_eq!(head.status(), 200);
    assert_eq!(etag(&head), tag);
    assert_eq!(header(&head, "x-ms-resource-type"), "file");
    assert_eq!(header(&head, "content-length"), "0");
    assert_eq!(header(&head, "content-type"), "text/plain");
    assert_eq!(header(&head, "x-ms-properties"), "k=dg==");
    assert_eq!(header(&head, "x-ms-owner"), "owner1");
    assert_eq!(header(&head, "x-ms-group"), "group1");
    assert_eq!(header(&head, "x-ms-permissions"), "rwxr-x---");
    assert_eq!(header(&head, "x-ms-lease-state"), "available");

    let parent = server.dfs("HEAD", &format!("{LAKE}/a"), &[], b"");
    assert_eq!(header(&parent, "x-ms-resource-type"), "directory");
    assert_eq!(header(&parent, "x-ms-owner"), "$superuser");
    assert_eq!(header(&parent, "x-ms-permissions"), "rwxr-x---");
    let access = server.dfs("HEAD", &format!("{file}?action=getAccessControl"), &[], b"");
    assert_eq!(
        header(&access, "x-ms-acl"),
        "user::rwx,group::r-x,other::---"
    );

    let umask = server.dfs(
        "PUT",
        &format!("{LAKE}/private?resource=directory"),
        &[("x-ms-permissions", "0777"), ("x-ms-umask", "0077")],
        b"",
    );
    assert_eq!(umask.status(), 201);
    let private = server.dfs("HEAD", &format!("{LAKE}/private"), &[], b"");
    assert_eq!(header(&private, "x-ms-permissions"), "rwx------");

    for (headers, status, code) in [
        (vec![("x-ms-permissions", "rwq")], 400, "InvalidHeaderValue"),
        (vec![("x-ms-umask", "77")], 400, "InvalidHeaderValue"),
        (
            vec![("x-ms-properties", "bad name=dg==")],
            400,
            "InvalidHeaderValue",
        ),
        (
            vec![
                ("x-ms-permissions", "0777"),
                ("x-ms-acl", "user::rwx,group::r-x,other::---"),
            ],
            400,
            "InvalidHeaderValue",
        ),
    ] {
        dfs_error(
            server.dfs("PUT", &format!("{LAKE}/bad?resource=file"), &headers, b""),
            status,
            code,
        );
    }
    dfs_error(
        server.dfs("PUT", &format!("{LAKE}/x?resource=symlink"), &[], b""),
        400,
        "InvalidQueryParameterValue",
    );
    dfs_error(
        server.dfs("PUT", &format!("{LAKE}/x"), &[], b""),
        400,
        "MissingRequiredQueryParameter",
    );

    dfs_error(
        server.dfs("PUT", &format!("{LAKE}/a?resource=file"), &[], b""),
        409,
        "PathConflict",
    );
    dfs_error(
        server.dfs("PUT", &format!("{file}?resource=directory"), &[], b""),
        409,
        "PathConflict",
    );
    dfs_error(
        server.dfs("PUT", &format!("{file}/child?resource=file"), &[], b""),
        409,
        "PathConflict",
    );
    dfs_error(
        server.dfs(
            "PUT",
            &format!("{file}?resource=file"),
            &[("if-none-match", "*")],
            b"",
        ),
        409,
        "PathAlreadyExists",
    );
    dfs_error(
        server.dfs(
            "PUT",
            &format!("{file}?resource=file"),
            &[("if-match", "\"other\"")],
            b"",
        ),
        412,
        "ConditionNotMet",
    );
    let replaced = server.dfs(
        "PUT",
        &format!("{file}?resource=file"),
        &[("if-match", &tag)],
        b"",
    );
    assert_eq!(replaced.status(), 201);
    assert_ne!(etag(&replaced), tag);
    let after = server.dfs("HEAD", &file, &[], b"");
    assert_eq!(
        header(&after, "x-ms-owner"),
        "owner1",
        "overwrite keeps ownership"
    );
}

#[test]
fn read_path_checks_range_checksum_headers_and_date_conditions() {
    let server = Emulator::start(&[]);
    server.filesystem();
    server.file("data.bin", b"0123456789");
    let file = format!("{LAKE}/data.bin");

    let ranged = server.dfs(
        "GET",
        &file,
        &[
            ("range", "bytes=0-3"),
            ("x-ms-range-get-content-md5", "true"),
        ],
        b"",
    );
    assert_eq!(ranged.status(), 206);
    assert_eq!(
        header(&ranged, "content-md5"),
        STANDARD.encode(md5(b"0123")),
        "the MD5 covers the returned range, not the file"
    );
    // `x-ms-range` wins over `Range` and the checksum follows it.
    let both = server.dfs(
        "GET",
        &file,
        &[
            ("range", "bytes=0-3"),
            ("x-ms-range", "bytes=4-7"),
            ("x-ms-range-get-content-md5", "true"),
        ],
        b"",
    );
    assert_eq!(header(&both, "content-md5"), STANDARD.encode(md5(b"4567")));
    assert_eq!(both.bytes().unwrap().as_ref(), b"4567");

    let unasked = server.dfs(
        "GET",
        &file,
        &[
            ("range", "bytes=0-3"),
            ("x-ms-range-get-content-md5", "false"),
        ],
        b"",
    );
    assert_eq!(unasked.status(), 206);
    assert!(!unasked.headers().contains_key("content-md5"));
    let whole = server.dfs("GET", &file, &[], b"");
    assert_eq!(header(&whole, "content-length"), "10");

    dfs_error(
        server.dfs("GET", &file, &[("x-ms-range-get-content-md5", "true")], b""),
        400,
        "InvalidHeaderValue",
    );
    // Learn documents no CRC64 header for Read Path, so it stays an unsupported header.
    let crc = server.dfs(
        "GET",
        &file,
        &[
            ("range", "bytes=0-3"),
            ("x-ms-range-get-content-crc64", "true"),
        ],
        b"",
    );
    assert_eq!(crc.status(), 501);

    let modified = header(&whole, "last-modified");
    let before = "Mon, 01 Jan 2001 00:00:00 GMT";
    for (headers, status) in [
        (vec![("if-modified-since", modified.as_str())], 304),
        (vec![("if-modified-since", before)], 200),
        (vec![("if-unmodified-since", before)], 412),
        (vec![("if-unmodified-since", modified.as_str())], 200),
        (
            vec![
                ("if-unmodified-since", before),
                ("if-match", header(&whole, "etag").as_str()),
            ],
            412,
        ),
    ] {
        assert_eq!(
            server.dfs("GET", &file, &headers, b"").status().as_u16(),
            status,
            "{headers:?}"
        );
    }
}

#[test]
fn create_path_expiry_applies_to_files_with_documented_options() {
    let server = Emulator::start(&[]);
    server.filesystem();
    let create = |path: &str, kind: &str, headers: &[(&str, &str)]| {
        server.dfs(
            "PUT",
            &format!("{LAKE}/{path}?resource={kind}"),
            headers,
            b"",
        )
    };
    let expiry_of = |path: &str| {
        let head = server.blob("HEAD", &format!("{LAKE}/{path}"), &[], b"");
        assert_eq!(head.status(), 200, "{path}");
        head.headers()
            .get("x-ms-expiry-time")
            .map(|value| value.to_str().unwrap().to_owned())
    };
    let later = httpdate::fmt_http_date(SystemTime::now() + Duration::from_secs(3600));

    assert_eq!(
        create(
            "ttl.txt",
            "file",
            &[
                ("x-ms-expiry-option", "RelativeToNow"),
                ("x-ms-expiry-time", "3600000")
            ]
        )
        .status(),
        201
    );
    assert!(expiry_of("ttl.txt").is_some());
    assert_eq!(
        create(
            "at.txt",
            "file",
            &[
                ("x-ms-expiry-option", "Absolute"),
                ("x-ms-expiry-time", &later)
            ]
        )
        .status(),
        201
    );
    assert_eq!(expiry_of("at.txt"), Some(later.clone()));
    assert_eq!(
        create(
            "forever.txt",
            "file",
            &[("x-ms-expiry-option", "NeverExpire")]
        )
        .status(),
        201
    );
    assert_eq!(expiry_of("forever.txt"), None);

    // Creating the path again without an expiry replaces the file and its deadline.
    assert_eq!(create("ttl.txt", "file", &[]).status(), 201);
    assert_eq!(expiry_of("ttl.txt"), None);

    // Azure documents expiry for files only, and lists no RelativeToCreation for Create Path.
    // The error for the rest is not documented: Azuifer answers 400 InvalidHeaderValue.
    let past = httpdate::fmt_http_date(SystemTime::now() - Duration::from_secs(3600));
    for (path, kind, headers) in [
        (
            "dir",
            "directory",
            vec![
                ("x-ms-expiry-option", "RelativeToNow"),
                ("x-ms-expiry-time", "60000"),
            ],
        ),
        (
            "creation.txt",
            "file",
            vec![
                ("x-ms-expiry-option", "RelativeToCreation"),
                ("x-ms-expiry-time", "60000"),
            ],
        ),
        (
            "past.txt",
            "file",
            vec![
                ("x-ms-expiry-option", "Absolute"),
                ("x-ms-expiry-time", &past),
            ],
        ),
        (
            "nan.txt",
            "file",
            vec![
                ("x-ms-expiry-option", "RelativeToNow"),
                ("x-ms-expiry-time", "soon"),
            ],
        ),
        (
            "never-time.txt",
            "file",
            vec![
                ("x-ms-expiry-option", "NeverExpire"),
                ("x-ms-expiry-time", "60000"),
            ],
        ),
        (
            "unknown.txt",
            "file",
            vec![("x-ms-expiry-option", "Tomorrow")],
        ),
    ] {
        dfs_error(create(path, kind, &headers), 400, "InvalidHeaderValue");
        let head = server.dfs("HEAD", &format!("{LAKE}/{path}"), &[], b"");
        assert_eq!(head.status(), 404, "{path} was not created");
    }
    for headers in [
        vec![("x-ms-expiry-time", "60000")],
        vec![("x-ms-expiry-option", "RelativeToNow")],
    ] {
        dfs_error(
            create("missing.txt", "file", &headers),
            400,
            "MissingRequiredHeader",
        );
    }
}

fn append_flush_flow(server: &Emulator) {
    server.filesystem();
    let file = format!("{LAKE}/log.txt");
    let blob_file = "/testaccount/lake/log.txt";
    let created = server.dfs("PUT", &format!("{file}?resource=file"), &[], b"");
    let empty_tag = etag(&created);

    for (position, data) in [(5, "world"), (0, "hello")] {
        let appended = server.dfs(
            "PATCH",
            &format!("{file}?action=append&position={position}"),
            &[],
            data.as_bytes(),
        );
        assert_eq!(appended.status(), 202);
        assert_eq!(header(&appended, "x-ms-request-server-encrypted"), "true");
    }
    let hidden = server.dfs("GET", &file, &[], b"");
    assert_eq!(hidden.status(), 200);
    assert_eq!(etag(&hidden), empty_tag, "appends do not change the ETag");
    assert!(
        hidden.bytes().unwrap().is_empty(),
        "unflushed data is invisible to DFS"
    );
    let blob_view = server.blob("GET", blob_file, &[], b"");
    assert_eq!(etag(&blob_view), empty_tag);
    assert!(blob_view.bytes().unwrap().is_empty(), "and to Blob");

    dfs_error(
        server.dfs(
            "PATCH",
            &format!("{file}?action=flush&position=12"),
            &[],
            b"",
        ),
        400,
        "InvalidFlushPosition",
    );
    let flushed = server.dfs(
        "PATCH",
        &format!("{file}?action=flush&position=10&close=true"),
        &[],
        b"",
    );
    assert_eq!(flushed.status(), 200);
    let tag = etag(&flushed);
    assert_ne!(tag, empty_tag);
    let read = server.dfs("GET", &file, &[], b"");
    assert_eq!(etag(&read), tag);
    assert_eq!(read.bytes().unwrap().as_ref(), b"helloworld");
    let range = server.dfs("GET", &file, &[("range", "bytes=3-6")], b"");
    assert_eq!(range.status(), 206);
    assert_eq!(range.bytes().unwrap().as_ref(), b"lowo");
    let as_blob = server.blob("GET", blob_file, &[], b"");
    assert_eq!(etag(&as_blob), tag);
    assert_eq!(header(&as_blob, "x-ms-blob-type"), "BlockBlob");
    assert_eq!(as_blob.bytes().unwrap().as_ref(), b"helloworld");

    // A partial flush keeps the data after its position for the next one.
    for (position, data) in [(10, "!"), (11, "??")] {
        server.dfs(
            "PATCH",
            &format!("{file}?action=append&position={position}"),
            &[],
            data.as_bytes(),
        );
    }
    let partial = server.dfs(
        "PATCH",
        &format!("{file}?action=flush&position=11&retainUncommittedData=true"),
        &[("x-ms-content-type", "text/x-log")],
        b"",
    );
    assert_eq!(partial.status(), 200);
    let head = server.dfs("HEAD", &file, &[], b"");
    assert_eq!(header(&head, "content-length"), "11");
    assert_eq!(header(&head, "content-type"), "text/x-log");
    dfs_error(
        server.dfs(
            "PATCH",
            &format!("{file}?action=flush&position=12"),
            &[],
            b"",
        ),
        400,
        "InvalidFlushPosition",
    );
    let rest = server.dfs(
        "PATCH",
        &format!("{file}?action=flush&position=13"),
        &[],
        b"",
    );
    assert_eq!(rest.status(), 200);
    assert_eq!(
        server.dfs("GET", &file, &[], b"").bytes().unwrap().as_ref(),
        b"helloworld!??"
    );
    let same = server.dfs(
        "PATCH",
        &format!("{file}?action=flush&position=13"),
        &[],
        b"",
    );
    assert_ne!(
        etag(&same),
        etag(&rest),
        "a flush without data still touches the file"
    );

    let good = STANDARD.encode(md5(b"checked"));
    let appended = server.dfs(
        "PATCH",
        &format!("{file}?action=append&position=13"),
        &[("content-md5", &good)],
        b"checked",
    );
    assert_eq!(appended.status(), 202);
    assert_eq!(header(&appended, "content-md5"), good);
    dfs_error(
        server.dfs(
            "PATCH",
            &format!("{file}?action=append&position=20"),
            &[("content-md5", &good)],
            b"tampered",
        ),
        400,
        "Md5Mismatch",
    );

    // Uploading without overwriting appends to a missing path and flushes under If-None-Match.
    let fresh = format!("{LAKE}/fresh/new.bin");
    let created = server.dfs(
        "PATCH",
        &format!("{fresh}?action=append&position=0"),
        &[],
        b"fresh",
    );
    assert_eq!(created.status(), 202);
    let first = server.dfs(
        "PATCH",
        &format!("{fresh}?action=flush&position=5"),
        &[("if-none-match", "*")],
        b"",
    );
    assert_eq!(first.status(), 200);
    dfs_error(
        server.dfs(
            "PATCH",
            &format!("{fresh}?action=flush&position=5"),
            &[("if-none-match", "*")],
            b"",
        ),
        409,
        "PathAlreadyExists",
    );
    assert_eq!(
        server
            .dfs("GET", &fresh, &[], b"")
            .bytes()
            .unwrap()
            .as_ref(),
        b"fresh"
    );

    let oversized = raw_append(
        server,
        &format!("{LAKE}/log.txt?action=append&position=0"),
        100 * 1024 * 1024 + 1,
    );
    assert!(oversized.starts_with("HTTP/1.1 413"), "{oversized}");
}

/// Sends the headers of an append that claims `length` body bytes and returns the response.
fn raw_append(server: &Emulator, path: &str, length: usize) -> String {
    let url = Url::parse(&format!("{}{path}", server.dfs)).unwrap();
    let headers = server.shared_key("PATCH", &url, &[], Some(length));
    let address = url.socket_addrs(|| None).unwrap()[0];
    let mut socket = TcpStream::connect(address).unwrap();
    socket
        .set_read_timeout(Some(Duration::from_secs(10)))
        .unwrap();
    write!(
        socket,
        "PATCH {path} HTTP/1.1\r\nHost: {address}\r\nConnection: close\r\n"
    )
    .unwrap();
    for (name, value) in headers {
        write!(socket, "{name}: {value}\r\n").unwrap();
    }
    socket.write_all(b"\r\n").unwrap();
    let mut response = vec![0; 4096];
    let read = socket.read(&mut response).unwrap();
    String::from_utf8_lossy(&response[..read]).into_owned()
}

#[test]
fn append_and_flush_publish_in_one_step_in_memory() {
    append_flush_flow(&Emulator::start(&[]));
}

#[test]
fn append_and_flush_publish_in_one_step_on_disk() {
    let location = tempfile::tempdir().unwrap();
    append_flush_flow(&Emulator::start_on_disk(location.path(), &[]));
}

/// RFC 1321 MD5, enough to build a transactional `Content-MD5` without another dependency.
fn md5(data: &[u8]) -> [u8; 16] {
    use md5::{Digest as _, Md5};
    Md5::digest(data).into()
}

#[test]
fn update_path_sets_properties_and_access_control() {
    let server = Emulator::start(&[]);
    server.filesystem();
    server.file("doc.txt", b"data");
    let doc = format!("{LAKE}/doc.txt");

    let updated = server.dfs(
        "PATCH",
        &format!("{doc}?action=setProperties"),
        &[
            ("x-ms-properties", "a=MQ==,b=Mg=="),
            ("x-ms-content-type", "text/csv"),
        ],
        b"",
    );
    assert_eq!(updated.status(), 200);
    let head = server.dfs("HEAD", &doc, &[], b"");
    assert_eq!(header(&head, "x-ms-properties"), "a=MQ==,b=Mg==");
    assert_eq!(header(&head, "content-type"), "text/csv");
    assert_eq!(header(&head, "content-length"), "4");

    let acl = format!("user::rw-,user:{OID}:r--,group::r--,other::---");
    let set = server.dfs(
        "PATCH",
        &format!("{doc}?action=setAccessControl"),
        &[("x-ms-acl", &acl)],
        b"",
    );
    assert_eq!(set.status(), 200);
    assert_ne!(etag(&set), etag(&head), "an ACL change updates the ETag");
    let shown = server.dfs("HEAD", &format!("{doc}?action=getAccessControl"), &[], b"");
    assert_eq!(
        header(&shown, "x-ms-acl"),
        format!("user::rw-,user:{OID}:r--,group::r--,mask::r--,other::---")
    );
    assert_eq!(header(&shown, "x-ms-permissions"), "rw-r-----");

    server.dfs(
        "PATCH",
        &format!("{doc}?action=setAccessControl"),
        &[
            ("x-ms-owner", "new-owner"),
            ("x-ms-group", "new-group"),
            ("x-ms-permissions", "0600"),
        ],
        b"",
    );
    let chmod = server.dfs("HEAD", &doc, &[], b"");
    assert_eq!(header(&chmod, "x-ms-owner"), "new-owner");
    assert_eq!(header(&chmod, "x-ms-group"), "new-group");
    assert_eq!(header(&chmod, "x-ms-permissions"), "rw-------");

    dfs_error(
        server.dfs(
            "PATCH",
            &format!("{doc}?action=setAccessControl"),
            &[
                ("x-ms-permissions", "0600"),
                ("x-ms-acl", "user::rw-,group::---,other::---"),
            ],
            b"",
        ),
        400,
        "InvalidHeaderValue",
    );
    dfs_error(
        server.dfs("PATCH", &format!("{doc}?action=explode"), &[], b""),
        501,
        "NotImplemented",
    );
    dfs_error(
        server.dfs("PATCH", &format!("{doc}?action=append"), &[], b"x"),
        400,
        "MissingRequiredQueryParameter",
    );
    dfs_error(
        server.dfs(
            "PATCH",
            &format!("{LAKE}/absent?action=setAccessControl"),
            &[("x-ms-permissions", "0600")],
            b"",
        ),
        404,
        "PathNotFound",
    );

    // The filesystem root is a directory with its own ACL.
    let root = server.dfs("HEAD", &format!("{LAKE}?action=getAccessControl"), &[], b"");
    assert_eq!(root.status(), 200);
    assert_eq!(header(&root, "x-ms-acl"), "user::rwx,group::r-x,other::---");
    let root_acl = format!(
        "user::rwx,group::r-x,other::---,default:user::rwx,default:user:{OID}:r-x,default:group::r-x,default:other::---"
    );
    assert_eq!(
        server
            .dfs(
                "PATCH",
                &format!("{LAKE}?action=setAccessControl"),
                &[("x-ms-acl", &root_acl)],
                b""
            )
            .status(),
        200
    );
    server.file("inherited.txt", b"");
    let inherited = server.dfs(
        "HEAD",
        &format!("{LAKE}/inherited.txt?action=getAccessControl"),
        &[],
        b"",
    );
    assert_eq!(
        header(&inherited, "x-ms-acl"),
        format!("user::rw-,user:{OID}:r-x,group::r-x,mask::r--,other::---")
    );
}

#[test]
fn directories_inherit_default_acls_and_files_do_not_keep_them() {
    let server = Emulator::start(&[]);
    server.filesystem();
    server.directory("shared");
    let acl = format!(
        "user::rwx,group::r-x,other::---,default:user::rwx,default:user:{OID}:rwx,default:group::r-x,default:other::r-x"
    );
    server.dfs(
        "PATCH",
        &format!("{LAKE}/shared?action=setAccessControl"),
        &[("x-ms-acl", &acl)],
        b"",
    );
    server.file("shared/f.txt", b"");
    server.directory("shared/sub");
    let file = server.dfs(
        "HEAD",
        &format!("{LAKE}/shared/f.txt?action=getAccessControl"),
        &[],
        b"",
    );
    assert_eq!(
        header(&file, "x-ms-acl"),
        format!("user::rw-,user:{OID}:rwx,group::r-x,mask::rw-,other::r--")
    );
    assert_eq!(header(&file, "x-ms-permissions"), "rw-rw-r--");
    let sub = server.dfs(
        "HEAD",
        &format!("{LAKE}/shared/sub?action=getAccessControl"),
        &[],
        b"",
    );
    let sub_acl = header(&sub, "x-ms-acl");
    assert!(
        sub_acl.contains(&format!("default:user:{OID}:rwx")),
        "{sub_acl}"
    );
    assert!(
        sub_acl.starts_with(&format!(
            "user::rwx,user:{OID}:rwx,group::r-x,mask::rwx,other::r-x"
        )),
        "{sub_acl}"
    );
    // An explicit ACL on the request replaces inheritance, and the umask does not.
    let explicit = server.dfs(
        "PUT",
        &format!("{LAKE}/shared/own.txt?resource=file"),
        &[("x-ms-acl", "user::rw-,group::---,other::---")],
        b"",
    );
    assert_eq!(explicit.status(), 201);
    let own = server.dfs("HEAD", &format!("{LAKE}/shared/own.txt"), &[], b"");
    assert_eq!(header(&own, "x-ms-permissions"), "rw-------");
}

fn acl_of(server: &Emulator, path: &str) -> String {
    header(
        &server.dfs(
            "HEAD",
            &format!("{LAKE}/{path}?action=getAccessControl"),
            &[],
            b"",
        ),
        "x-ms-acl",
    )
}

#[test]
fn recursive_acl_changes_page_with_a_stable_continuation() {
    let server = Emulator::start(&[]);
    server.filesystem();
    server.directory("d/a");
    server.directory("d/b");
    for file in ["d/a/f1", "d/b/f2", "d/f3"] {
        server.file(file, b"x");
    }
    let change = |mode: &str, acl: &str, extra: &str, continuation: Option<&str>| {
        let mut path = format!("{LAKE}/d?action=setAccessControlRecursive&mode={mode}{extra}");
        if let Some(token) = continuation {
            path.push_str(&format!("&continuation={token}"));
        }
        server.dfs("PATCH", &path, &[("x-ms-acl", acl)], b"")
    };
    let entry = format!("user:{OID}:r-x");
    let (mut directories, mut files, mut calls) = (0, 0, 0);
    let mut token: Option<String> = None;
    loop {
        let response = change("modify", &entry, "&maxRecords=2", token.as_deref());
        assert_eq!(response.status(), 200);
        let next = response
            .headers()
            .get("x-ms-continuation")
            .map(|value| value.to_str().unwrap().to_owned());
        let body = json_body(response);
        directories += body["directoriesSuccessful"].as_u64().unwrap();
        files += body["filesSuccessful"].as_u64().unwrap();
        assert_eq!(body["failureCount"], 0);
        assert_eq!(body["failedEntries"], json!([]));
        calls += 1;
        match next {
            Some(next) => token = Some(next),
            None => break,
        }
    }
    assert_eq!((directories, files, calls), (3, 3, 3));
    for path in ["d", "d/a", "d/a/f1", "d/b/f2", "d/f3"] {
        assert!(
            acl_of(&server, path).contains(&format!("user:{OID}:r-x")),
            "{path}"
        );
    }
    assert_eq!(
        acl_of(&server, "d/f3"),
        format!("user::rw-,user:{OID}:r-x,group::r--,mask::r-x,other::---")
    );

    let removed = change("remove", &format!("user:{OID}"), "", None);
    let removed = json_body(removed);
    assert_eq!(removed["directoriesSuccessful"], 3);
    assert_eq!(removed["filesSuccessful"], 3);
    assert_eq!(acl_of(&server, "d/a/f1"), "user::rw-,group::r--,other::---");

    let replaced = change(
        "set",
        "user::rwx,group::r-x,other::r--,default:user::rwx,default:group::r-x,default:other::r--",
        "",
        None,
    );
    assert_eq!(json_body(replaced)["failureCount"], 0);
    assert_eq!(acl_of(&server, "d/f3"), "user::rwx,group::r-x,other::r--");
    assert!(acl_of(&server, "d/a").ends_with("default:other::r--"));

    dfs_error(
        change("explode", &entry, "", None),
        400,
        "InvalidQueryParameterValue",
    );
    dfs_error(
        change("modify", &entry, "", Some("bm90LW1pbmU")),
        400,
        "InvalidQueryParameterValue",
    );
    dfs_error(
        change("modify", &entry, "&maxRecords=0", None),
        400,
        "InvalidQueryParameterValue",
    );
    dfs_error(
        server.dfs(
            "PATCH",
            &format!("{LAKE}/d?action=setAccessControlRecursive&mode=set"),
            &[],
            b"",
        ),
        400,
        "MissingRequiredHeader",
    );
    dfs_error(
        server.dfs(
            "PATCH",
            &format!("{LAKE}/d?action=setAccessControlRecursive"),
            &[("x-ms-acl", &entry)],
            b"",
        ),
        400,
        "MissingRequiredQueryParameter",
    );
}

#[test]
fn recursive_delete_removes_a_tree_in_batches() {
    let server = Emulator::start(&[]);
    server.filesystem();
    for index in 0..1005 {
        server.file(&format!("big/dir{}/f{index}", index % 7), b"");
    }
    server.file("keep.txt", b"kept");
    let big = format!("{LAKE}/big");
    dfs_error(
        server.dfs("DELETE", &format!("{big}?recursive=false"), &[], b""),
        409,
        "DirectoryNotEmpty",
    );
    dfs_error(
        server.dfs(
            "DELETE",
            &format!("{big}?recursive=true"),
            &[("if-match", "\"other\"")],
            b"",
        ),
        412,
        "ConditionNotMet",
    );
    let first = server.dfs("DELETE", &format!("{big}?recursive=true"), &[], b"");
    assert_eq!(first.status(), 200);
    let token = header(&first, "x-ms-continuation");
    assert_eq!(
        server.dfs("HEAD", &big, &[], b"").status(),
        200,
        "the tree is only partly gone"
    );
    dfs_error(
        server.dfs(
            "DELETE",
            &format!("{LAKE}/keep.txt?recursive=true&continuation={token}"),
            &[],
            b"",
        ),
        400,
        "InvalidQueryParameterValue",
    );
    let last = server.dfs(
        "DELETE",
        &format!("{big}?recursive=true&continuation={token}"),
        &[],
        b"",
    );
    assert_eq!(last.status(), 200);
    assert!(!last.headers().contains_key("x-ms-continuation"));
    dfs_error(server.dfs("HEAD", &big, &[], b""), 404, "PathNotFound");
    let listing = json_body(server.dfs(
        "GET",
        &format!("{LAKE}?resource=filesystem&recursive=true"),
        &[],
        b"",
    ));
    assert_eq!(path_names(&listing), ["keep.txt"]);
    dfs_error(
        server.dfs("DELETE", &format!("{big}?recursive=true"), &[], b""),
        404,
        "PathNotFound",
    );
}

fn rename(
    server: &Emulator,
    from: &str,
    to: &str,
    extra: &[(&str, &str)],
    query: &str,
) -> Response {
    let source = format!("/lake/{}", encode(from).replace("%2F", "/"));
    let mut headers = vec![("x-ms-rename-source", source.as_str())];
    headers.extend_from_slice(extra);
    server.dfs("PUT", &format!("{LAKE}/{to}{query}"), &headers, b"")
}

#[test]
fn rename_moves_files_and_directories_and_rejects_conflicts() {
    let server = Emulator::start(&[]);
    server.filesystem();
    server.file("src/a.txt", b"alpha");
    server.file("src/sub/b.txt", b"beta");
    server.directory("src/empty");
    let before = etag(&server.dfs("HEAD", &format!("{LAKE}/src/a.txt"), &[], b""));

    let moved = rename(&server, "src", "dst", &[], "?mode=legacy");
    assert_eq!(moved.status(), 201);
    dfs_error(
        server.dfs("HEAD", &format!("{LAKE}/src"), &[], b""),
        404,
        "PathNotFound",
    );
    let read = server.dfs("GET", &format!("{LAKE}/dst/a.txt"), &[], b"");
    assert_eq!(etag(&read), before, "a moved file keeps its identity");
    assert_eq!(read.bytes().unwrap().as_ref(), b"alpha");
    assert_eq!(
        server
            .dfs("GET", &format!("{LAKE}/dst/sub/b.txt"), &[], b"")
            .bytes()
            .unwrap()
            .as_ref(),
        b"beta"
    );
    let listing = json_body(server.dfs(
        "GET",
        &format!("{LAKE}?resource=filesystem&recursive=true"),
        &[],
        b"",
    ));
    assert_eq!(
        path_names(&listing),
        ["dst", "dst/a.txt", "dst/empty", "dst/sub", "dst/sub/b.txt"]
    );

    let source_missing = rename(&server, "nope", "x", &[], "");
    dfs_error(source_missing, 404, "SourcePathNotFound");
    dfs_error(
        rename(&server, "dst/a.txt", "missing/parent/a.txt", &[], ""),
        404,
        "RenameDestinationParentPathNotFound",
    );
    dfs_error(
        rename(&server, "dst", "dst/inner", &[], ""),
        409,
        "InvalidRenameSourcePath",
    );
    dfs_error(
        rename(&server, "dst", "dst", &[], ""),
        409,
        "InvalidRenameSourcePath",
    );
    dfs_error(
        rename(&server, "dst/a.txt", "dst/sub", &[], ""),
        409,
        "InvalidSourceOrDestinationResourceType",
    );
    dfs_error(
        rename(&server, "dst/sub", "dst/a.txt", &[], ""),
        409,
        "InvalidSourceOrDestinationResourceType",
    );
    dfs_error(
        rename(
            &server,
            "dst/a.txt",
            "dst/sub/b.txt",
            &[("if-none-match", "*")],
            "",
        ),
        409,
        "PathAlreadyExists",
    );
    dfs_error(
        rename(&server, "dst/a.txt", "x", &[], "?mode=bogus"),
        400,
        "InvalidQueryParameterValue",
    );
    dfs_error(
        rename(
            &server,
            "dst/a.txt",
            "x",
            &[("x-ms-source-if-match", "\"other\"")],
            "",
        ),
        412,
        "SourceConditionNotMet",
    );
    // A directory cannot replace a non-empty one, but replaces an empty one.
    server.directory("full");
    server.file("full/x", b"");
    dfs_error(
        rename(&server, "dst/empty", "full", &[], ""),
        409,
        "DirectoryNotEmpty",
    );
    server.directory("hollow");
    assert_eq!(
        rename(&server, "dst/empty", "hollow", &[], "?mode=posix").status(),
        201
    );
    // A file replaces another file and takes the new properties when the request names them.
    let replaced = rename(
        &server,
        "dst/a.txt",
        "dst/sub/b.txt",
        &[("x-ms-properties", "p=cQ==")],
        "",
    );
    assert_eq!(replaced.status(), 201);
    let head = server.dfs("HEAD", &format!("{LAKE}/dst/sub/b.txt"), &[], b"");
    assert_eq!(header(&head, "x-ms-properties"), "p=cQ==");
    assert_eq!(
        server
            .dfs("GET", &format!("{LAKE}/dst/sub/b.txt"), &[], b"")
            .bytes()
            .unwrap()
            .as_ref(),
        b"alpha"
    );

    server.file("odd name/é.txt", b"unicode");
    assert_eq!(
        rename(&server, "odd name/é.txt", "odd name/plain.txt", &[], "").status(),
        201
    );
    assert_eq!(
        server
            .dfs("GET", &format!("{LAKE}/odd%20name/plain.txt"), &[], b"")
            .bytes()
            .unwrap()
            .as_ref(),
        b"unicode"
    );
}

#[test]
fn rename_accepts_a_source_that_names_the_account_too() {
    // The Go Data Lake client sends `/{account}/{filesystem}/{path}` against path-style URLs.
    let server = Emulator::start(&[]);
    server.filesystem();
    server.file("src/a.txt", b"alpha");
    server.directory("dst");
    let source = format!("/{ACCOUNT}/lake/src/a.txt");
    let moved = server.dfs(
        "PUT",
        &format!("{LAKE}/dst/a.txt?mode=legacy"),
        &[("x-ms-rename-source", source.as_str())],
        b"",
    );
    assert_eq!(moved.status(), 201);
    let read = server.dfs("GET", &format!("{LAKE}/dst/a.txt"), &[], b"");
    assert_eq!(read.bytes().unwrap().as_ref(), b"alpha");
    let elsewhere = server.dfs(
        "PUT",
        &format!("{LAKE}/dst/b.txt?mode=legacy"),
        &[("x-ms-rename-source", "/otheraccount/lake/dst/a.txt")],
        b"",
    );
    assert_eq!(elsewhere.status(), 400);
}
#[test]
fn rename_honors_leases_on_the_source_the_destination_and_descendants() {
    let server = Emulator::start(&[]);
    server.filesystem();
    server.file("dir/leased.txt", b"one");
    server.file("target.txt", b"two");
    let lease = |path: &str, headers: &[(&str, &str)]| {
        server.dfs("POST", &format!("{LAKE}/{path}"), headers, b"")
    };
    let acquired = lease(
        "dir/leased.txt",
        &[
            ("x-ms-lease-action", "acquire"),
            ("x-ms-lease-duration", "-1"),
        ],
    );
    assert_eq!(acquired.status(), 201);
    let id = header(&acquired, "x-ms-lease-id");

    dfs_error(
        rename(&server, "dir/leased.txt", "moved.txt", &[], ""),
        412,
        "LeaseIdMissing",
    );
    dfs_error(
        rename(&server, "dir", "moved-dir", &[], ""),
        412,
        "LeaseIdMissing",
    );
    dfs_error(
        rename(
            &server,
            "dir/leased.txt",
            "moved.txt",
            &[(
                "x-ms-source-lease-id",
                "00000000-0000-0000-0000-000000000000",
            )],
            "",
        ),
        412,
        "LeaseIdMismatch",
    );
    assert_eq!(
        rename(
            &server,
            "dir/leased.txt",
            "moved.txt",
            &[("x-ms-source-lease-id", &id)],
            ""
        )
        .status(),
        201
    );
    let still = server.dfs("HEAD", &format!("{LAKE}/moved.txt"), &[], b"");
    assert_eq!(
        header(&still, "x-ms-lease-state"),
        "leased",
        "the lease moves with the file"
    );

    // A leased destination can only be replaced by presenting its lease.
    let target = lease(
        "target.txt",
        &[
            ("x-ms-lease-action", "acquire"),
            ("x-ms-lease-duration", "-1"),
        ],
    );
    let target_id = header(&target, "x-ms-lease-id");
    server.file("plain.txt", b"three");
    dfs_error(
        rename(&server, "plain.txt", "target.txt", &[], ""),
        412,
        "LeaseIdMissing",
    );
    assert_eq!(
        rename(
            &server,
            "plain.txt",
            "target.txt",
            &[("x-ms-lease-id", &target_id)],
            ""
        )
        .status(),
        201
    );
}

#[test]
fn lease_path_follows_the_shared_lease_state_machine() {
    let server = Emulator::start(&[]);
    server.filesystem();
    server.file("f.txt", b"data");
    let file = format!("{LAKE}/f.txt");
    let lease = |headers: &[(&str, &str)]| server.dfs("POST", &file, headers, b"");

    let acquired = lease(&[
        ("x-ms-lease-action", "acquire"),
        ("x-ms-lease-duration", "-1"),
    ]);
    assert_eq!(acquired.status(), 201);
    let id = header(&acquired, "x-ms-lease-id");
    let head = server.dfs("HEAD", &file, &[], b"");
    assert_eq!(header(&head, "x-ms-lease-state"), "leased");
    assert_eq!(header(&head, "x-ms-lease-duration"), "infinite");
    let as_blob = server.blob("HEAD", "/testaccount/lake/f.txt", &[], b"");
    assert_eq!(
        header(&as_blob, "x-ms-lease-state"),
        "leased",
        "Blob sees the DFS lease"
    );

    dfs_error(
        server.dfs(
            "PATCH",
            &format!("{file}?action=append&position=4"),
            &[],
            b"x",
        ),
        412,
        "LeaseIdMissing",
    );
    assert_eq!(
        server
            .dfs(
                "PATCH",
                &format!("{file}?action=append&position=4"),
                &[("x-ms-lease-id", &id)],
                b"x"
            )
            .status(),
        202
    );
    dfs_error(server.dfs("DELETE", &file, &[], b""), 412, "LeaseIdMissing");
    assert_eq!(
        lease(&[("x-ms-lease-action", "renew"), ("x-ms-lease-id", &id)]).status(),
        200
    );
    dfs_error(
        lease(&[
            ("x-ms-lease-action", "renew"),
            ("x-ms-lease-id", "00000000-0000-0000-0000-000000000000"),
        ]),
        409,
        "LeaseIdMismatchWithLeaseOperation",
    );
    let proposed = "33333333-3333-3333-3333-333333333333";
    let changed = lease(&[
        ("x-ms-lease-action", "change"),
        ("x-ms-lease-id", &id),
        ("x-ms-proposed-lease-id", proposed),
    ]);
    assert_eq!(changed.status(), 200);
    assert_eq!(header(&changed, "x-ms-lease-id"), proposed);
    let broken = lease(&[
        ("x-ms-lease-action", "break"),
        ("x-ms-lease-break-period", "0"),
    ]);
    assert_eq!(broken.status(), 202);
    assert_eq!(header(&broken, "x-ms-lease-time"), "0");
    assert_eq!(
        lease(&[
            ("x-ms-lease-action", "release"),
            ("x-ms-lease-id", proposed)
        ])
        .status(),
        200
    );
    dfs_error(
        lease(&[("x-ms-lease-action", "break")]),
        409,
        "LeaseNotPresentWithLeaseOperation",
    );
    dfs_error(lease(&[]), 400, "MissingRequiredHeader");
    dfs_error(
        server.dfs(
            "POST",
            LAKE,
            &[
                ("x-ms-lease-action", "acquire"),
                ("x-ms-lease-duration", "-1"),
            ],
            b"",
        ),
        501,
        "NotImplemented",
    );

    // A lease can be taken while creating a file, and released with the flush.
    let created = server.dfs(
        "PUT",
        &format!("{LAKE}/held.txt?resource=file"),
        &[
            ("x-ms-proposed-lease-id", proposed),
            ("x-ms-lease-duration", "-1"),
        ],
        b"",
    );
    assert_eq!(header(&created, "x-ms-lease-id"), proposed);
    let held = format!("{LAKE}/held.txt");
    let append = server.dfs(
        "PATCH",
        &format!("{held}?action=append&position=0"),
        &[("x-ms-lease-id", proposed)],
        b"abc",
    );
    assert_eq!(append.status(), 202);
    let flush = server.dfs(
        "PATCH",
        &format!("{held}?action=flush&position=3&close=true"),
        &[
            ("x-ms-lease-id", proposed),
            ("x-ms-lease-action", "release"),
        ],
        b"",
    );
    assert_eq!(flush.status(), 200);
    assert_eq!(
        header(&server.dfs("HEAD", &held, &[], b""), "x-ms-lease-state"),
        "available"
    );
    // An append can take the lease itself, a later one renews it, and acquire-release
    // leaves nothing behind.
    let acquire = server.dfs(
        "PATCH",
        &format!("{held}?action=append&position=3"),
        &[
            ("x-ms-lease-action", "acquire"),
            ("x-ms-lease-duration", "-1"),
            ("x-ms-proposed-lease-id", proposed),
        ],
        b"def",
    );
    assert_eq!(header(&acquire, "x-ms-lease-id"), proposed);
    assert_eq!(
        header(&server.dfs("HEAD", &held, &[], b""), "x-ms-lease-state"),
        "leased"
    );
    let renew = server.dfs(
        "PATCH",
        &format!("{held}?action=append&position=6"),
        &[
            ("x-ms-lease-action", "auto-renew"),
            ("x-ms-lease-id", proposed),
        ],
        b"g",
    );
    assert_eq!(renew.status(), 202);
    let release = server.dfs(
        "PATCH",
        &format!("{held}?action=flush&position=7"),
        &[
            ("x-ms-lease-action", "release"),
            ("x-ms-lease-id", proposed),
        ],
        b"",
    );
    assert_eq!(release.status(), 200);
    let transient = server.dfs(
        "PATCH",
        &format!("{held}?action=append&position=7"),
        &[
            ("x-ms-lease-action", "acquire-release"),
            ("x-ms-lease-duration", "-1"),
        ],
        b"h",
    );
    assert_eq!(transient.status(), 202);
    assert_eq!(
        header(&server.dfs("HEAD", &held, &[], b""), "x-ms-lease-state"),
        "available"
    );
    server.directory("dir");
    dfs_error(
        server.dfs(
            "POST",
            &format!("{LAKE}/dir"),
            &[
                ("x-ms-lease-action", "acquire"),
                ("x-ms-lease-duration", "-1"),
            ],
            b"",
        ),
        409,
        "ResourceTypeMismatch",
    );
}

#[test]
fn path_listing_reports_ownership_and_pages_with_continuation() {
    let server = Emulator::start(&[]);
    server.filesystem();
    server.file("a.txt", b"12345");
    server.directory("dir");
    server.file("dir/b.txt", b"");
    server.file("dir/c.txt", b"x");
    let list = |query: &str| {
        server.dfs(
            "GET",
            &format!("{LAKE}?resource=filesystem&{query}"),
            &[],
            b"",
        )
    };

    let top = json_body(list("recursive=false&upn=true"));
    assert_eq!(path_names(&top), ["a.txt", "dir"]);
    let file = &top["paths"][0];
    assert_eq!(file["contentLength"], "5");
    assert!(file.get("isDirectory").is_none());
    assert_eq!(file["owner"], "$superuser");
    assert_eq!(file["group"], "$superuser");
    assert_eq!(file["permissions"], "rw-r-----");
    assert!(file["etag"].as_str().unwrap().starts_with('"'));
    assert!(file["lastModified"].as_str().unwrap().ends_with("GMT"));
    assert_eq!(top["paths"][1]["isDirectory"], "true");
    assert_eq!(top["paths"][1]["permissions"], "rwxr-x---");

    let mut seen = Vec::new();
    let mut token: Option<String> = None;
    let mut pages = 0;
    loop {
        let query = match &token {
            Some(token) => format!("recursive=true&maxResults=2&continuation={token}"),
            None => "recursive=true&maxResults=2".to_owned(),
        };
        let response = list(&query);
        let next = response
            .headers()
            .get("x-ms-continuation")
            .map(|value| value.to_str().unwrap().to_owned());
        seen.extend(path_names(&json_body(response)));
        pages += 1;
        match next {
            Some(next) => token = Some(next),
            None => break,
        }
    }
    assert_eq!(seen, ["a.txt", "dir", "dir/b.txt", "dir/c.txt"]);
    assert_eq!(pages, 2);
    assert_eq!(
        path_names(&json_body(list("recursive=true&directory=dir"))),
        ["dir/b.txt", "dir/c.txt"]
    );
    dfs_error(list("directory=dir"), 400, "MissingRequiredQueryParameter");
    dfs_error(list("recursive=true&directory=absent"), 404, "PathNotFound");
    dfs_error(list("recursive=maybe"), 400, "InvalidQueryParameterValue");
}

#[test]
fn filesystem_properties_round_trip_through_dfs_and_blob() {
    let server = Emulator::start(&[]);
    let created = server.dfs(
        "PUT",
        &format!("{LAKE}?resource=filesystem"),
        &[("x-ms-properties", "a=MQ==")],
        b"",
    );
    assert_eq!(created.status(), 201);
    let head = server.dfs("HEAD", &format!("{LAKE}?resource=filesystem"), &[], b"");
    assert_eq!(header(&head, "x-ms-properties"), "a=MQ==");
    assert_eq!(header(&head, "x-ms-namespace-enabled"), "true");
    let set = server.dfs(
        "PATCH",
        &format!("{LAKE}?resource=filesystem"),
        &[("x-ms-properties", "b=Mg==")],
        b"",
    );
    assert_eq!(set.status(), 200);
    assert_ne!(etag(&set), etag(&head));
    let after = server.dfs("HEAD", &format!("{LAKE}?resource=filesystem"), &[], b"");
    assert_eq!(header(&after, "x-ms-properties"), "b=Mg==");
    let as_container = server.blob("HEAD", &format!("{LAKE}?restype=container"), &[], b"");
    assert_eq!(header(&as_container, "x-ms-meta-b"), "2");
    assert!(!as_container.headers().contains_key("x-ms-meta-a"));
    dfs_error(
        server.dfs(
            "PATCH",
            &format!("{LAKE}?resource=filesystem"),
            &[("if-unmodified-since", "Mon, 01 Jan 2001 00:00:00 GMT")],
            b"",
        ),
        412,
        "ConditionNotMet",
    );
    let listed = json_body(server.dfs("GET", &format!("/{ACCOUNT}?resource=account"), &[], b""));
    assert_eq!(listed["filesystems"][0]["name"], "lake");
    assert_eq!(
        server
            .dfs("DELETE", &format!("{LAKE}?resource=filesystem"), &[], b"")
            .status(),
        202
    );
}

#[test]
fn shared_key_lite_and_sas_authenticate_dfs_requests() {
    let server = Emulator::start(&[]);
    server.filesystem();
    server.file("dir/f.txt", b"payload");
    server.file("other/g.txt", b"private");
    let expiry = in_seconds(&server, 600);
    let list = format!("{LAKE}?resource=filesystem&recursive=true");

    let lite = server.send(
        &server.dfs,
        "GET",
        &format!("/{ACCOUNT}?resource=account"),
        &[],
        b"",
        &Auth::Lite,
    );
    assert_eq!(lite.status(), 200);
    dfs_error(
        server.dfs_as(
            &Auth::Anonymous,
            "GET",
            &format!("/{ACCOUNT}?resource=account"),
            &[],
        ),
        403,
        "AuthorizationFailure",
    );

    let sas_read = |sas: &str, path: &str| {
        server.dfs_as(
            &Auth::Sas(sas.to_owned()),
            "GET",
            &format!("{LAKE}/{path}"),
            &[],
        )
    };
    let file_sas = service_sas("b", Some("dir/f.txt"), "r", &expiry);
    let read = sas_read(&file_sas, "dir/f.txt");
    assert_eq!(read.status(), 200);
    assert_eq!(read.bytes().unwrap().as_ref(), b"payload");
    dfs_error(
        sas_read(&file_sas, "other/g.txt"),
        403,
        "AuthorizationFailure",
    );
    dfs_error(
        server.dfs_as(
            &Auth::Sas(file_sas.clone()),
            "PUT",
            &format!("{LAKE}/dir/f.txt?resource=file"),
            &[],
        ),
        403,
        "AuthorizationPermissionMismatch",
    );
    let tampered = file_sas.replace("sp=r", "sp=rw");
    dfs_error(
        sas_read(&tampered, "dir/f.txt"),
        403,
        "AuthorizationFailure",
    );
    let expired = service_sas("b", Some("dir/f.txt"), "r", &in_seconds(&server, -60));
    dfs_error(sas_read(&expired, "dir/f.txt"), 403, "AuthorizationFailure");

    let container_sas = Auth::Sas(service_sas("c", None, "rl", &expiry));
    let listed = server.dfs_as(&container_sas, "GET", &list, &[]);
    assert_eq!(listed.status(), 200);
    assert_eq!(
        server
            .dfs_as(&container_sas, "GET", &format!("{LAKE}/other/g.txt"), &[])
            .status(),
        200
    );
    dfs_error(
        server.dfs_as(
            &container_sas,
            "DELETE",
            &format!("{LAKE}/other/g.txt"),
            &[],
        ),
        403,
        "AuthorizationPermissionMismatch",
    );

    // A directory SAS covers the directory it names, at the depth it states.
    let directory = service_sas("d", Some("dir"), "rl", &expiry);
    assert_eq!(sas_read(&directory, "dir/f.txt").status(), 200);
    dfs_error(
        sas_read(&directory, "other/g.txt"),
        403,
        "AuthorizationFailure",
    );
    let scoped = server.dfs_as(
        &Auth::Sas(directory.clone()),
        "GET",
        &format!("{LAKE}?resource=filesystem&recursive=true&directory=dir"),
        &[],
    );
    assert_eq!(path_names(&json_body(scoped)), ["dir/f.txt"]);
    dfs_error(
        server.dfs_as(
            &Auth::Sas(directory),
            "GET",
            &format!("{LAKE}?resource=filesystem&recursive=true&directory=other"),
            &[],
        ),
        403,
        "AuthorizationFailure",
    );

    // Account SAS: service, resource type and permission are all checked.
    let account = Auth::Sas(account_sas("rwlc", "b", "sco", &expiry));
    assert_eq!(
        server
            .dfs_as(
                &account,
                "GET",
                &format!("/{ACCOUNT}?resource=account"),
                &[]
            )
            .status(),
        200
    );
    assert_eq!(
        server
            .dfs_as(
                &account,
                "PUT",
                &format!("{LAKE}/viasas.txt?resource=file"),
                &[]
            )
            .status(),
        201
    );
    let read_only = Auth::Sas(account_sas("r", "b", "sco", &expiry));
    dfs_error(
        server.dfs_as(
            &read_only,
            "GET",
            &format!("/{ACCOUNT}?resource=account"),
            &[],
        ),
        403,
        "AuthorizationPermissionMismatch",
    );
    let wrong_service = Auth::Sas(account_sas("rwlc", "q", "sco", &expiry));
    dfs_error(
        server.dfs_as(
            &wrong_service,
            "GET",
            &format!("/{ACCOUNT}?resource=account"),
            &[],
        ),
        403,
        "AuthorizationServiceMismatch",
    );
    let objects_only = Auth::Sas(account_sas("rwlc", "b", "o", &expiry));
    dfs_error(
        server.dfs_as(
            &objects_only,
            "GET",
            &format!("/{ACCOUNT}?resource=account"),
            &[],
        ),
        403,
        "AuthorizationResourceTypeMismatch",
    );
    // SAS callers bypass POSIX checks, as Shared Key does.
    server.dfs(
        "PATCH",
        &format!("{LAKE}/other/g.txt?action=setAccessControl"),
        &[("x-ms-permissions", "0000")],
        b"",
    );
    assert_eq!(
        sas_read(
            &service_sas("b", Some("other/g.txt"), "r", &expiry),
            "other/g.txt"
        )
        .status(),
        200
    );
}

fn grant(server: &Emulator, path: &str, acl: &str) {
    let target = if path.is_empty() {
        LAKE.to_owned()
    } else {
        format!("{LAKE}/{path}")
    };
    let response = server.dfs(
        "PATCH",
        &format!("{target}?action=setAccessControl"),
        &[("x-ms-acl", acl)],
        b"",
    );
    assert_eq!(response.status(), 200, "grant {path}");
}

#[test]
fn recursive_acl_changes_reach_only_the_directories_a_bearer_caller_can_search() {
    let server = Emulator::start(&["--oauth", "basic"]);
    server.filesystem();
    grant(&server, "", "user::rwx,group::r-x,other::rwx");
    let user = server.token(OID);
    let call = |method: &str, path: &str, headers: &[(&str, &str)]| {
        server.dfs_as(&user, method, path, headers)
    };
    for (path, kind) in [
        ("u", "directory"),
        ("u/open", "directory"),
        ("u/open/a.txt", "file"),
        ("u/sealed", "directory"),
        ("u/sealed/inner", "directory"),
        ("u/sealed/inner/b.txt", "file"),
        ("u/sealed/c.txt", "file"),
        ("v", "directory"),
        ("v/w.txt", "file"),
    ] {
        let created = call("PUT", &format!("{LAKE}/{path}?resource={kind}"), &[]);
        assert_eq!(created.status(), 201, "create {path}");
    }
    // The caller owns all of it; removing execute from `u/sealed` hides what is below it.
    let sealed = call(
        "PATCH",
        &format!("{LAKE}/u/sealed?action=setAccessControl"),
        &[("x-ms-permissions", "0600")],
    );
    assert_eq!(sealed.status(), 200);
    let recursive = |path: &str, mode: &str, acl: &str, extra: &str| {
        json_body(call(
            "PATCH",
            &format!("{LAKE}/{path}?action=setAccessControlRecursive&mode={mode}{extra}"),
            &[("x-ms-acl", acl)],
        ))
    };
    let failed = |body: &Value| -> Vec<String> {
        body["failedEntries"]
            .as_array()
            .unwrap()
            .iter()
            .map(|entry| entry["name"].as_str().unwrap().to_owned())
            .collect()
    };
    let named = "user:44444444-4444-4444-4444-444444444444:r--";

    let forced = recursive("u", "modify", named, "&forceFlag=true");
    assert_eq!(forced["directoriesSuccessful"], 3, "u, u/open, u/sealed");
    assert_eq!(forced["filesSuccessful"], 1, "u/open/a.txt");
    assert_eq!(forced["failureCount"], 3);
    assert_eq!(
        failed(&forced),
        ["u/sealed/c.txt", "u/sealed/inner", "u/sealed/inner/b.txt"],
        "everything below the directory the caller cannot search"
    );
    assert!(acl_of(&server, "u/sealed").contains("44444444-4444-4444-4444-444444444444"));
    assert!(!acl_of(&server, "u/sealed/inner").contains("44444444-4444-4444-4444-444444444444"));

    // Without forceFlag the call stops at the first path it cannot reach.
    let stopped = recursive("u", "modify", named, "");
    assert_eq!(failed(&stopped), ["u/sealed/c.txt"]);
    assert_eq!(stopped["directoriesSuccessful"], 3);
    assert_eq!(stopped["filesSuccessful"], 1);

    // Removing a search right in this very call does not hide the entries below it.
    let locked = recursive("v", "set", "user::rw-,group::---,other::---", "");
    assert_eq!(locked["failureCount"], 0, "{locked}");
    assert_eq!(locked["directoriesSuccessful"], 1);
    assert_eq!(locked["filesSuccessful"], 1);
    // A later call does see the lost right, and so cannot reach the file.
    let later = recursive("v", "modify", named, "&forceFlag=true");
    assert_eq!(failed(&later), ["v/w.txt"]);

    // Shared Key has no ACL check, so it reaches everything.
    let all = json_body(server.dfs(
        "PATCH",
        &format!("{LAKE}/u?action=setAccessControlRecursive&mode=modify"),
        &[("x-ms-acl", named)],
        b"",
    ));
    assert_eq!(all["failureCount"], 0);
    assert_eq!(all["directoriesSuccessful"], 4);
    assert_eq!(all["filesSuccessful"], 3);
}

#[test]
fn bearer_tokens_are_checked_against_owner_and_acls() {
    let server = Emulator::start(&["--oauth", "basic"]);
    server.filesystem();
    server.directory("d");
    server.file("d/f.txt", b"secret");
    let user = server.token(OID);
    let call = |method: &str, path: &str, headers: &[(&str, &str)]| {
        server.dfs_as(&user, method, path, headers)
    };
    let list_root = format!("{LAKE}?resource=filesystem&recursive=false");

    dfs_error(
        call("GET", &list_root, &[]),
        403,
        "AuthorizationPermissionMismatch",
    );
    grant(&server, "", "user::rwx,group::r-x,other::r-x");
    assert_eq!(call("GET", &list_root, &[]).status(), 200);
    dfs_error(
        call(
            "GET",
            &format!("{LAKE}?resource=filesystem&recursive=false&directory=d"),
            &[],
        ),
        403,
        "AuthorizationPermissionMismatch",
    );
    dfs_error(
        call("HEAD", &format!("{LAKE}/d/f.txt"), &[]),
        403,
        "AuthorizationPermissionMismatch",
    );

    grant(
        &server,
        "d",
        &format!("user::rwx,user:{OID}:r-x,group::r-x,other::---"),
    );
    assert_eq!(
        call("HEAD", &format!("{LAKE}/d/f.txt"), &[]).status(),
        200,
        "execute on the directory"
    );
    dfs_error(
        call("GET", &format!("{LAKE}/d/f.txt"), &[]),
        403,
        "AuthorizationPermissionMismatch",
    );
    grant(
        &server,
        "d/f.txt",
        &format!("user::rw-,user:{OID}:r--,group::r--,other::---"),
    );
    assert_eq!(
        call("GET", &format!("{LAKE}/d/f.txt"), &[])
            .bytes()
            .unwrap()
            .as_ref(),
        b"secret"
    );
    dfs_error(
        call("PUT", &format!("{LAKE}/d/new.txt?resource=file"), &[]),
        403,
        "AuthorizationPermissionMismatch",
    );
    dfs_error(
        call(
            "PATCH",
            &format!("{LAKE}/d/f.txt?action=append&position=6"),
            &[],
        ),
        403,
        "AuthorizationPermissionMismatch",
    );

    grant(
        &server,
        "d",
        &format!("user::rwx,user:{OID}:rwx,group::r-x,other::---"),
    );
    let created = call("PUT", &format!("{LAKE}/d/new.txt?resource=file"), &[]);
    assert_eq!(created.status(), 201);
    let new_file = server.dfs("HEAD", &format!("{LAKE}/d/new.txt"), &[], b"");
    assert_eq!(
        header(&new_file, "x-ms-owner"),
        OID,
        "a bearer caller owns what it creates"
    );
    let own = call(
        "PATCH",
        &format!("{LAKE}/d/new.txt?action=setAccessControl"),
        &[("x-ms-permissions", "0600")],
    );
    assert_eq!(own.status(), 200);
    dfs_error(
        call(
            "PATCH",
            &format!("{LAKE}/d/f.txt?action=setAccessControl"),
            &[("x-ms-permissions", "0777")],
        ),
        403,
        "AuthorizationPermissionMismatch",
    );
    dfs_error(
        call(
            "PATCH",
            &format!("{LAKE}/d/new.txt?action=setAccessControl"),
            &[("x-ms-owner", OTHER_OID)],
        ),
        403,
        "AuthorizationPermissionMismatch",
    );

    // A recursive change reports the paths this caller does not own.
    let recursive = |extra: &str| {
        call(
            "PATCH",
            &format!("{LAKE}/d?action=setAccessControlRecursive&mode=modify{extra}"),
            &[("x-ms-acl", "user:44444444-4444-4444-4444-444444444444:r--")],
        )
    };
    let forced = json_body(recursive("&forceFlag=true"));
    assert_eq!(forced["failureCount"], 2);
    assert_eq!(
        forced["filesSuccessful"], 1,
        "the file the caller owns changed"
    );
    let names: Vec<_> = forced["failedEntries"]
        .as_array()
        .unwrap()
        .iter()
        .map(|entry| {
            (
                entry["name"].as_str().unwrap().to_owned(),
                entry["type"].as_str().unwrap().to_owned(),
            )
        })
        .collect();
    assert_eq!(
        names,
        [
            ("d".to_owned(), "DIRECTORY".to_owned()),
            ("d/f.txt".to_owned(), "FILE".to_owned())
        ]
    );
    let stopped = json_body(recursive(""));
    assert_eq!(stopped["failureCount"], 1);
    assert_eq!(stopped["directoriesSuccessful"], 0);

    assert_eq!(
        call("DELETE", &format!("{LAKE}/d/new.txt"), &[]).status(),
        200
    );
    dfs_error(
        server.dfs_as(&Auth::Bearer("not-a-jwt".into()), "GET", &list_root, &[]),
        401,
        "InvalidAuthenticationInfo",
    );
}

#[test]
fn user_delegation_sas_is_limited_by_the_delegating_users_acl() {
    let server = Emulator::start(&["--oauth", "basic"]);
    server.filesystem();
    server.file("f.txt", b"delegated");
    let user = server.token(OID);
    let body = format!(
        "<?xml version=\"1.0\" encoding=\"utf-8\"?><KeyInfo><Start>{}</Start><Expiry>{}</Expiry></KeyInfo>",
        in_seconds(&server, -60),
        in_seconds(&server, 3600)
    );
    let key = server.send(
        &server.blob,
        "POST",
        &format!("/{ACCOUNT}?restype=service&comp=userdelegationkey"),
        &[],
        body.as_bytes(),
        &user,
    );
    assert_eq!(key.status(), 200);
    let xml = key.text().unwrap();
    let field = |name: &str| {
        let open = format!("<{name}>");
        let start = xml.find(&open).unwrap() + open.len();
        xml[start..start + xml[start..].find('<').unwrap()].to_owned()
    };
    let (oid, tid, start, expiry) = (
        field("SignedOid"),
        field("SignedTid"),
        field("SignedStart"),
        field("SignedExpiry"),
    );
    let secret = STANDARD.decode(field("Value")).unwrap();
    let canonical = format!("/blob/{ACCOUNT}/lake/f.txt");
    let se = in_seconds(&server, 600);
    let signed = [
        "r", "", &se, &canonical, &oid, &tid, &start, &expiry, "b", VERSION, "", "", "", "", "",
        VERSION, "b", "", "", "", "", "", "", "",
    ]
    .join("\n");
    let sas = format!(
        "sv={VERSION}&sr=b&sp=r&se={}&skoid={oid}&sktid={tid}&skt={}&ske={}&sks=b&skv={VERSION}&sig={}",
        encode(&se),
        encode(&start),
        encode(&expiry),
        encode(&sign_with(&secret, &signed))
    );
    let sas = Auth::Sas(sas);
    let read = |sas: &Auth| server.dfs_as(sas, "GET", &format!("{LAKE}/f.txt"), &[]);
    dfs_error(read(&sas), 403, "AuthorizationPermissionMismatch");
    grant(&server, "", "user::rwx,group::r-x,other::--x");
    dfs_error(read(&sas), 403, "AuthorizationPermissionMismatch");
    grant(
        &server,
        "f.txt",
        &format!("user::rw-,user:{OID}:r--,group::r--,other::---"),
    );
    let allowed = read(&sas);
    assert_eq!(allowed.status(), 200);
    assert_eq!(allowed.bytes().unwrap().as_ref(), b"delegated");
}

#[test]
fn dfs_follows_the_shared_clock() {
    let server = Emulator::start(&["--test-clock"]);
    server.filesystem();
    server.file("f.txt", b"clocked");
    let file = format!("{LAKE}/f.txt");
    let sas = Auth::Sas(service_sas(
        "b",
        Some("f.txt"),
        "r",
        &in_seconds(&server, 600),
    ));
    assert_eq!(server.dfs_as(&sas, "GET", &file, &[]).status(), 200);
    let lease = server.dfs(
        "POST",
        &file,
        &[
            ("x-ms-lease-action", "acquire"),
            ("x-ms-lease-duration", "15"),
        ],
        b"",
    );
    assert_eq!(lease.status(), 201);
    dfs_error(server.dfs("DELETE", &file, &[], b""), 412, "LeaseIdMissing");

    server.advance(1200);
    dfs_error(
        server.dfs_as(&sas, "GET", &file, &[]),
        403,
        "AuthorizationFailure",
    );
    let real_date = httpdate::fmt_http_date(SystemTime::now());
    dfs_error(
        server.dfs("HEAD", &file, &[("x-ms-date", &real_date)], b""),
        403,
        "AuthorizationFailure",
    );
    let head = server.dfs("HEAD", &file, &[], b"");
    assert_eq!(head.status(), 200);
    assert_eq!(header(&head, "x-ms-lease-state"), "expired");
    assert_eq!(server.dfs("DELETE", &file, &[], b"").status(), 200);
}

#[test]
fn older_api_versions_are_served_and_newer_ones_are_not() {
    let server = Emulator::start(&[]);
    server.filesystem();
    let head = server.dfs(
        "HEAD",
        &format!("{LAKE}?resource=filesystem"),
        &[("x-ms-version", "2019-12-12")],
        b"",
    );
    assert_eq!(head.status(), 200);
    assert_eq!(header(&head, "x-ms-version"), VERSION);
    let old = server.dfs(
        "HEAD",
        &format!("{LAKE}?resource=filesystem"),
        &[("x-ms-version", "2009-09-19")],
        b"",
    );
    assert_eq!(old.status(), 200);
    dfs_error(
        server.dfs(
            "HEAD",
            &format!("{LAKE}?resource=filesystem"),
            &[("x-ms-version", "2099-01-01")],
            b"",
        ),
        400,
        "UnsupportedRestVersion",
    );
    dfs_error(
        server.dfs(
            "HEAD",
            &format!("{LAKE}?resource=filesystem"),
            &[("x-ms-version", "yesterday")],
            b"",
        ),
        400,
        "UnsupportedRestVersion",
    );
}

type Probe<'a> = (&'a str, String, &'a [(&'a str, &'a str)]);

#[test]
fn accounts_without_a_hierarchical_namespace_reject_every_dfs_operation() {
    let server = Emulator::start_flat(&[]);
    let rename = [("x-ms-rename-source", "/lake/f")];
    let chmod = [("x-ms-permissions", "0777")];
    let requests: [Probe; 7] = [
        ("GET", format!("/{ACCOUNT}?resource=account"), &[]),
        ("PUT", format!("{LAKE}?resource=filesystem"), &[]),
        ("PUT", format!("{LAKE}/f?resource=file"), &[]),
        ("PATCH", format!("{LAKE}/f?action=append&position=0"), &[]),
        ("PUT", format!("{LAKE}/g"), &rename),
        ("PATCH", format!("{LAKE}/f?action=setAccessControl"), &chmod),
        ("DELETE", format!("{LAKE}/f?recursive=true"), &[]),
    ];
    for (method, path, headers) in requests {
        dfs_error(
            server.dfs(method, &path, headers, b""),
            409,
            "HierarchicalNamespaceNotEnabled",
        );
    }
}

#[test]
fn azcopy_style_clients_reach_blob_listing_and_folder_markers_on_the_dfs_port() {
    let server = Emulator::start(&[]);
    server.filesystem();
    server.directory("tree");
    server.file("tree/one.txt", b"one");

    let head = server.dfs("HEAD", &format!("{LAKE}/tree"), &[], b"");
    assert_eq!(head.status(), 200);
    assert_eq!(header(&head, "x-ms-resource-type"), "directory");
    assert_eq!(header(&head, "x-ms-meta-hdi_isfolder"), "true");
    let file = server.dfs("HEAD", &format!("{LAKE}/tree/one.txt"), &[], b"");
    assert!(file.headers().get("x-ms-meta-hdi_isfolder").is_none());

    // A path-style URL has no blob host, so the Blob list arrives on the DFS URL.
    let listing = server.dfs(
        "GET",
        &format!("{LAKE}?restype=container&comp=list&prefix=tree/"),
        &[],
        b"",
    );
    assert_eq!(listing.status(), 200);
    assert!(
        listing
            .text()
            .unwrap()
            .contains("<Name>tree/one.txt</Name>")
    );

    // AzCopy sends an empty x-ms-content-md5 when it has no hash.
    let created = server.dfs(
        "PUT",
        &format!("{LAKE}/tree/two.txt?resource=file"),
        &[],
        b"",
    );
    assert_eq!(created.status(), 201);
    let appended = server.dfs(
        "PATCH",
        &format!("{LAKE}/tree/two.txt?action=append&position=0"),
        &[],
        b"two",
    );
    assert_eq!(appended.status(), 202);
    let flushed = server.dfs(
        "PATCH",
        &format!(
            "{LAKE}/tree/two.txt?action=flush&position=3&close=true&retainUncommittedData=false"
        ),
        &[("x-ms-content-md5", "")],
        b"",
    );
    assert_eq!(flushed.status(), 200);
}

/// Sixteen appends that never finish their bodies, which hold every request slot.
fn stall_every_request_slot(server: &Emulator) -> Vec<TcpStream> {
    let mut stalled = Vec::new();
    for index in 0..16 {
        let path = format!("{LAKE}/slot{index}?action=append&position=0");
        let url = Url::parse(&format!("{}{path}", server.dfs)).unwrap();
        let headers = server.shared_key("PATCH", &url, &[], Some(100));
        let mut socket = TcpStream::connect(url.socket_addrs(|| None).unwrap()[0]).unwrap();
        write!(
            socket,
            "PATCH {path} HTTP/1.1\r\nHost: {}\r\n",
            url.host_str().unwrap()
        )
        .unwrap();
        for (name, value) in headers {
            write!(socket, "{name}: {value}\r\n").unwrap();
        }
        socket.write_all(b"\r\nfirst").unwrap();
        stalled.push(socket);
    }
    thread::sleep(Duration::from_millis(500));
    stalled
}

#[test]
fn dfs_answers_server_busy_when_no_request_slot_frees_within_the_wait() {
    let server = Emulator::start(&[]);
    server.filesystem();
    let _stalled = stall_every_request_slot(&server);
    let started = Instant::now();
    dfs_error(
        server.dfs("HEAD", &format!("{LAKE}?resource=filesystem"), &[], b""),
        503,
        "ServerBusy",
    );
    assert!(
        started.elapsed() >= Duration::from_secs(5),
        "it waited the full five seconds first: {:?}",
        started.elapsed()
    );
}

#[test]
fn dfs_waits_for_a_request_slot_instead_of_failing_when_all_are_busy() {
    let server = Emulator::start(&[]);
    server.filesystem();
    let mut stalled = stall_every_request_slot(&server);
    let started = Instant::now();
    let waiter = thread::scope(|scope| {
        let handle =
            scope.spawn(|| server.dfs("HEAD", &format!("{LAKE}?resource=filesystem"), &[], b""));
        thread::sleep(Duration::from_millis(700));
        stalled.pop();
        handle.join().unwrap()
    });
    assert_eq!(waiter.status(), 200, "the request waited for a slot");
    assert!(
        started.elapsed() >= Duration::from_millis(600),
        "{:?}",
        started.elapsed()
    );
}

#[test]
fn unflushed_data_and_attributes_survive_a_crash_but_a_torn_append_does_not() {
    let location = tempfile::tempdir().unwrap();
    let server = Emulator::start_on_disk(location.path(), &[]);
    server.filesystem();
    server.file("p/doc.txt", b"");
    grant(
        &server,
        "p",
        "user::rwx,group::r-x,other::---,default:user::rwx,default:group::r-x,default:other::r-x",
    );
    let doc = format!("{LAKE}/p/doc.txt");
    assert_eq!(
        server
            .dfs(
                "PATCH",
                &format!("{doc}?action=append&position=0"),
                &[],
                b"staged-"
            )
            .status(),
        202
    );
    let torn = format!("{doc}?action=append&position=7");
    let url = Url::parse(&format!("{}{torn}", server.dfs)).unwrap();
    let headers = server.shared_key("PATCH", &url, &[], Some(64));
    let mut socket = TcpStream::connect(url.socket_addrs(|| None).unwrap()[0]).unwrap();
    write!(
        socket,
        "PATCH {torn} HTTP/1.1\r\nHost: {}\r\n",
        url.host_str().unwrap()
    )
    .unwrap();
    for (name, value) in headers {
        write!(socket, "{name}: {value}\r\n").unwrap();
    }
    socket.write_all(b"\r\ntorn bytes").unwrap();
    thread::sleep(Duration::from_millis(300));
    server.crash();
    drop(socket);

    let server = Emulator::start_on_disk(location.path(), &[]);
    let head = server.dfs("HEAD", &doc, &[], b"");
    assert_eq!(
        header(&head, "content-length"),
        "0",
        "staged data is not visible after restart"
    );
    let parent = server.dfs(
        "HEAD",
        &format!("{LAKE}/p?action=getAccessControl"),
        &[],
        b"",
    );
    assert!(header(&parent, "x-ms-acl").contains("default:other::r-x"));
    dfs_error(
        server.dfs(
            "PATCH",
            &format!("{doc}?action=flush&position=64"),
            &[],
            b"",
        ),
        400,
        "InvalidFlushPosition",
    );
    let flushed = server.dfs("PATCH", &format!("{doc}?action=flush&position=7"), &[], b"");
    assert_eq!(flushed.status(), 200);
    assert_eq!(
        server.dfs("GET", &doc, &[], b"").bytes().unwrap().as_ref(),
        b"staged-"
    );
    drop(server);

    let server = Emulator::start_on_disk(location.path(), &[]);
    assert_eq!(
        server.dfs("GET", &doc, &[], b"").bytes().unwrap().as_ref(),
        b"staged-"
    );
    let leftovers: Vec<_> = std::fs::read_dir(location.path().join("content"))
        .unwrap()
        .map(|entry| entry.unwrap().file_name().to_string_lossy().into_owned())
        .filter(|name| name.starts_with("incoming-"))
        .collect();
    assert!(leftovers.is_empty(), "{leftovers:?}");
}

#[test]
fn a_sas_limited_to_https_is_refused_over_plain_http() {
    let server = Emulator::start(&[]);
    server.filesystem();
    server.file("f.txt", b"data");
    let file = format!("{LAKE}/f.txt");
    let expiry = in_seconds(&server, 600);
    let read = |protocol: &str| {
        // `sip` is signed but not enforced on any listener (docs/compatibility/blob.md), so
        // only the protocol restriction is exercised here.
        let sas = Auth::Sas(restricted_sas("f.txt", "", protocol, &expiry));
        server.dfs_as(&sas, "GET", &file, &[])
    };
    assert_eq!(read("").status(), 200);
    assert_eq!(read("https,http").status(), 200);
    dfs_error(read("https"), 403, "AuthorizationProtocolMismatch");
}
#[test]
fn lease_conflicts_report_the_documented_codes_and_an_expired_lease_is_lost() {
    let server = Emulator::start(&["--test-clock"]);
    server.filesystem();
    server.file("f.txt", b"data");
    let file = format!("{LAKE}/f.txt");
    let (first, second) = (
        "11111111-1111-1111-1111-111111111111",
        "22222222-2222-2222-2222-222222222222",
    );
    let lease = |headers: &[(&str, &str)]| server.dfs("POST", &file, headers, b"");
    let acquire = |id: &str| {
        lease(&[
            ("x-ms-lease-action", "acquire"),
            ("x-ms-lease-duration", "15"),
            ("x-ms-proposed-lease-id", id),
        ])
    };
    let append = |id: &str| {
        server.dfs(
            "PATCH",
            &format!("{file}?action=append&position=4"),
            &[("x-ms-lease-id", id)],
            b"x",
        )
    };

    dfs_error(append(first), 412, "LeaseNotPresent");
    assert_eq!(acquire(first).status(), 201);
    dfs_error(acquire(second), 409, "LeaseAlreadyPresent");
    dfs_error(append(second), 412, "LeaseIdMismatch");

    let breaking = lease(&[
        ("x-ms-lease-action", "break"),
        ("x-ms-lease-break-period", "10"),
    ]);
    assert_eq!(breaking.status(), 202);
    dfs_error(acquire(first), 409, "LeaseIsBreakingAndCannotBeAcquired");
    dfs_error(
        lease(&[
            ("x-ms-lease-action", "change"),
            ("x-ms-lease-id", first),
            ("x-ms-proposed-lease-id", second),
        ]),
        409,
        "LeaseIsBreakingAndCannotBeChanged",
    );
    server.advance(11);
    dfs_error(
        lease(&[("x-ms-lease-action", "renew"), ("x-ms-lease-id", first)]),
        409,
        "LeaseIsBrokenAndCannotBeRenewed",
    );
    assert_eq!(
        lease(&[("x-ms-lease-action", "release"), ("x-ms-lease-id", first)]).status(),
        200
    );

    assert_eq!(acquire(first).status(), 201);
    server.advance(16);
    dfs_error(append(first), 412, "LeaseLost");
    dfs_error(append(second), 412, "LeaseNotPresent");
}

#[test]
fn append_data_rejects_bad_checksums_bodies_without_a_length_and_invalid_names() {
    let server = Emulator::start(&[]);
    server.filesystem();
    let file = format!("{LAKE}/f.bin");
    assert_eq!(
        server
            .dfs("PUT", &format!("{file}?resource=file"), &[], b"")
            .status(),
        201
    );
    let append = |position: u32, headers: &[(&str, &str)], body: &[u8]| {
        server.dfs(
            "PATCH",
            &format!("{file}?action=append&position={position}"),
            headers,
            body,
        )
    };

    // CRC-64 of the single byte 0x11, the vector tests/blob_http.rs uses for Put Block.
    let crc = [("x-ms-content-crc64", "0GFnV7RfVNI=")];
    assert_eq!(append(0, &crc, b"\x11").status(), 202);
    dfs_error(append(1, &crc, b"wrong"), 400, "Crc64Mismatch");
    dfs_error(
        append(1, &[("content-md5", "AAAAAAAAAAAAAAAAAAAAAA==")], b"wrong"),
        400,
        "Md5Mismatch",
    );
    let flushed = server.dfs(
        "PATCH",
        &format!("{file}?action=flush&position=1"),
        &[],
        b"",
    );
    assert_eq!(
        flushed.status(),
        200,
        "the rejected bodies stored nothing, so one byte is all there is to flush"
    );
    assert_eq!(
        server.dfs("GET", &file, &[], b"").bytes().unwrap().as_ref(),
        b"\x11"
    );
    // A chunked body has no Content-Length to hold the upload to.
    let url = Url::parse(&format!("{}{file}?action=append&position=1", server.dfs)).unwrap();
    let headers = server.shared_key("PATCH", &url, &[], None);
    let mut request = server.client.request(Method::PATCH, url);
    for (name, value) in headers {
        request = request.header(name, value);
    }
    let reply = request
        .body(Body::new(std::io::Cursor::new(b"chunked".to_vec())))
        .send()
        .unwrap();
    dfs_error(reply, 411, "MissingContentLengthHeader");

    dfs_error(
        server.dfs(
            "PUT",
            "/testaccount/Not_Valid?resource=filesystem",
            &[],
            b"",
        ),
        400,
        "InvalidResourceName",
    );
}

#[test]
fn append_data_is_limited_by_the_memory_quota_and_the_upload_timeout() {
    let server = Emulator::start(&["--memory-limit", "1024", "--upload-timeout-seconds", "1"]);
    server.filesystem();
    let file = format!("{LAKE}/big.bin");
    assert_eq!(
        server
            .dfs("PUT", &format!("{file}?resource=file"), &[], b"")
            .status(),
        201
    );
    dfs_error(
        server.dfs(
            "PATCH",
            &format!("{file}?action=append&position=0"),
            &[],
            &[7; 2048],
        ),
        507,
        "InsufficientStorage",
    );
    assert_eq!(
        server
            .dfs(
                "PATCH",
                &format!("{file}?action=append&position=0"),
                &[],
                &[7; 512],
            )
            .status(),
        202,
        "a rejected upload leaves the quota intact"
    );

    // A body that stops short of its Content-Length is cut off when the timeout passes.
    let path = format!("{LAKE}/slow.bin");
    assert_eq!(
        server
            .dfs("PUT", &format!("{path}?resource=file"), &[], b"")
            .status(),
        201
    );
    let url = Url::parse(&format!("{}{path}?action=append&position=0", server.dfs)).unwrap();
    let headers = server.shared_key("PATCH", &url, &[], Some(100));
    let mut socket = TcpStream::connect(url.socket_addrs(|| None).unwrap()[0]).unwrap();
    socket
        .set_read_timeout(Some(Duration::from_secs(10)))
        .unwrap();
    write!(
        socket,
        "PATCH {}?action=append&position=0 HTTP/1.1\r\nHost: {}\r\n",
        path,
        url.host_str().unwrap()
    )
    .unwrap();
    for (name, value) in headers {
        write!(socket, "{name}: {value}\r\n").unwrap();
    }
    socket.write_all(b"\r\nfirst").unwrap();
    let mut reply = Vec::new();
    let mut chunk = [0; 1024];
    while !reply.windows(4).any(|window| window == b"\r\n\r\n") {
        let read = socket
            .read(&mut chunk)
            .expect("a response before the read timeout");
        assert_ne!(read, 0, "the server closed without answering");
        reply.extend_from_slice(&chunk[..read]);
    }
    let reply = String::from_utf8_lossy(&reply).to_ascii_lowercase();
    assert!(reply.starts_with("http/1.1 500"), "{reply}");
    assert!(
        reply.contains("x-ms-error-code: operationtimedout"),
        "{reply}"
    );
}

#[test]
fn create_path_refuses_an_expiry_too_far_ahead_to_report() {
    let server = Emulator::start(&[]);
    server.filesystem();
    let file = format!("{LAKE}/far.txt");
    dfs_error(
        server.dfs(
            "PUT",
            &format!("{file}?resource=file"),
            &[
                ("x-ms-expiry-option", "RelativeToNow"),
                ("x-ms-expiry-time", "9000000000000000"),
            ],
            b"",
        ),
        400,
        "InvalidHeaderValue",
    );
    assert_eq!(server.dfs("HEAD", &file, &[], b"").status(), 404);
}

fn blob_error(response: Response, status: u16, code: &str) {
    assert_eq!(response.status().as_u16(), status);
    assert_eq!(response.headers()["x-ms-error-code"], code);
    let body = response.text().unwrap();
    assert!(
        body.contains(&format!("<Code>{code}</Code>")),
        "expected XML error code {code}, got {body}"
    );
}

fn filetime_to_unix_secs(ticks: &str) -> u64 {
    const EPOCH_AS_FILETIME: u64 = 116_444_736_000_000_000;
    const TICKS_PER_SECOND: u64 = 10_000_000;
    let raw: u64 = ticks.parse().expect("decimal FILETIME ticks");
    assert!(raw >= EPOCH_AS_FILETIME, "ticks before Unix epoch: {raw}");
    (raw - EPOCH_AS_FILETIME) / TICKS_PER_SECOND
}

fn http_date_unix_secs(value: &str) -> u64 {
    httpdate::parse_http_date(value)
        .expect("RFC 1123 HTTP date")
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs()
}

#[test]
fn set_path_expiry_rejects_directories_and_surfaces_expiry_on_dfs_head_and_list() {
    let server = Emulator::start(&["--test-clock"]);
    server.filesystem();
    server.directory("dir");
    server.file("dir/a.txt", b"expiring");
    server.file("dir/plain.txt", b"keep");

    // PATCH ?action=setExpiry does not exist in Azure ADLS Gen2; real Set Path Expiry is PUT ?comp=expiry.
    dfs_error(
        server.dfs(
            "PATCH",
            &format!("{LAKE}/dir/plain.txt?action=setExpiry"),
            &[
                ("x-ms-expiry-option", "RelativeToNow"),
                ("x-ms-expiry-time", "60000"),
            ],
            b"",
        ),
        501,
        "NotImplemented",
    );

    // PUT ?comp=expiry against an existing HNS directory must be rejected (not 404 BlobNotFound).
    for headers in [
        vec![
            ("x-ms-expiry-option", "RelativeToNow"),
            ("x-ms-expiry-time", "60000"),
        ],
        vec![("x-ms-expiry-option", "NeverExpire")],
    ] {
        blob_error(
            server.dfs("PUT", &format!("{LAKE}/dir?comp=expiry"), &headers, b""),
            409,
            "BlobOperationNotSupported",
        );
        blob_error(
            server.blob("PUT", &format!("{LAKE}/dir?comp=expiry"), &headers, b""),
            409,
            "BlobOperationNotSupported",
        );
    }

    // Set Absolute expiry via PUT ?comp=expiry on the DFS listener and verify DFS HEAD & List Paths.
    let absolute = httpdate::fmt_http_date(server.now() + Duration::from_secs(120));
    let absolute_secs = http_date_unix_secs(&absolute);
    let set = server.dfs(
        "PUT",
        &format!("{LAKE}/dir/a.txt?comp=expiry"),
        &[
            ("x-ms-expiry-option", "Absolute"),
            ("x-ms-expiry-time", &absolute),
        ],
        b"",
    );
    assert_eq!(set.status(), 200);

    for suffix in ["", "?action=getStatus", "?action=getAccessControl"] {
        let head = server.dfs("HEAD", &format!("{LAKE}/dir/a.txt{suffix}"), &[], b"");
        assert_eq!(head.status(), 200, "{suffix}");
        assert_eq!(header(&head, "x-ms-expiry-time"), absolute, "{suffix}");
        assert!(
            head.headers().contains_key("x-ms-creation-time"),
            "missing x-ms-creation-time on {suffix}"
        );
    }
    let plain_head = server.dfs("HEAD", &format!("{LAKE}/dir/plain.txt"), &[], b"");
    assert_eq!(plain_head.status(), 200);
    assert!(!plain_head.headers().contains_key("x-ms-expiry-time"));
    assert!(plain_head.headers().contains_key("x-ms-creation-time"));

    let dir_head = server.dfs("HEAD", &format!("{LAKE}/dir"), &[], b"");
    assert_eq!(dir_head.status(), 200);
    assert!(!dir_head.headers().contains_key("x-ms-expiry-time"));
    assert!(dir_head.headers().contains_key("x-ms-creation-time"));

    let a_created = http_date_unix_secs(&header(
        &server.dfs("HEAD", &format!("{LAKE}/dir/a.txt"), &[], b""),
        "x-ms-creation-time",
    ));
    let listing = json_body(server.dfs(
        "GET",
        &format!("{LAKE}?resource=filesystem&recursive=true"),
        &[],
        b"",
    ));
    let entry = |name: &str| {
        listing["paths"]
            .as_array()
            .unwrap()
            .iter()
            .find(|item| item["name"] == name)
            .unwrap_or_else(|| panic!("missing {name} in {listing}"))
            .clone()
    };
    let dir_entry = entry("dir");
    assert!(dir_entry["creationTime"].as_str().is_some());
    assert!(dir_entry.get("expiryTime").is_none());

    let a_entry = entry("dir/a.txt");
    assert_eq!(
        filetime_to_unix_secs(a_entry["creationTime"].as_str().unwrap()),
        a_created
    );
    assert_eq!(
        filetime_to_unix_secs(a_entry["expiryTime"].as_str().unwrap()),
        absolute_secs
    );

    let plain_entry = entry("dir/plain.txt");
    assert!(plain_entry["creationTime"].as_str().is_some());
    assert!(plain_entry.get("expiryTime").is_none());

    // RelativeToCreation and NeverExpire round-trip on DFS HEAD and List Paths.
    assert_eq!(
        server
            .dfs(
                "PUT",
                &format!("{LAKE}/dir/plain.txt?comp=expiry"),
                &[
                    ("x-ms-expiry-option", "RelativeToCreation"),
                    ("x-ms-expiry-time", "600000"),
                ],
                b"",
            )
            .status(),
        200
    );
    assert!(
        server
            .dfs("HEAD", &format!("{LAKE}/dir/plain.txt"), &[], b"")
            .headers()
            .contains_key("x-ms-expiry-time")
    );
    assert_eq!(
        server
            .dfs(
                "PUT",
                &format!("{LAKE}/dir/plain.txt?comp=expiry"),
                &[("x-ms-expiry-option", "NeverExpire")],
                b"",
            )
            .status(),
        200
    );
    assert!(
        !server
            .dfs("HEAD", &format!("{LAKE}/dir/plain.txt"), &[], b"")
            .headers()
            .contains_key("x-ms-expiry-time")
    );

    // Advance past dir/a.txt's deadline: file is removed, while directory and plain file remain.
    server.advance(130);
    dfs_error(
        server.dfs("HEAD", &format!("{LAKE}/dir/a.txt"), &[], b""),
        404,
        "PathNotFound",
    );
    let after = json_body(server.dfs(
        "GET",
        &format!("{LAKE}?resource=filesystem&recursive=true"),
        &[],
        b"",
    ));
    assert_eq!(path_names(&after), ["dir", "dir/plain.txt"]);
}

#[test]
fn set_path_expiry_enforces_posix_acls_for_bearer_and_user_delegation_sas() {
    let server = Emulator::start(&["--oauth", "basic", "--test-clock"]);
    server.filesystem();
    server.directory("d");
    server.directory("d/sub");
    server.file("d/f.txt", b"acl-protected");
    let user = server.token(OID);
    let expiry_headers = [
        ("x-ms-expiry-option", "RelativeToNow"),
        ("x-ms-expiry-time", "600000"),
    ];

    // No root/parent execute or file write -> denied on both DFS and Blob endpoints.
    blob_error(
        server.dfs_as(
            &user,
            "PUT",
            &format!("{LAKE}/d/f.txt?comp=expiry"),
            &expiry_headers,
        ),
        403,
        "AuthorizationPermissionMismatch",
    );
    blob_error(
        server.send(
            &server.blob,
            "PUT",
            &format!("{LAKE}/d/f.txt?comp=expiry"),
            &expiry_headers,
            b"",
            &user,
        ),
        403,
        "AuthorizationPermissionMismatch",
    );

    // Ancestor execute + read-only on the file is still insufficient: write right is required.
    grant(&server, "", "user::rwx,group::r-x,other::--x");
    grant(
        &server,
        "d",
        &format!("user::rwx,user:{OID}:r-x,group::r-x,other::---"),
    );
    grant(
        &server,
        "d/f.txt",
        &format!("user::rw-,user:{OID}:r--,group::r--,other::---"),
    );
    blob_error(
        server.dfs_as(
            &user,
            "PUT",
            &format!("{LAKE}/d/f.txt?comp=expiry"),
            &expiry_headers,
        ),
        403,
        "AuthorizationPermissionMismatch",
    );

    // Granting write on the file allows PUT ?comp=expiry.
    grant(
        &server,
        "d/f.txt",
        &format!("user::rw-,user:{OID}:rw-,group::r--,other::---"),
    );
    assert_eq!(
        server
            .dfs_as(
                &user,
                "PUT",
                &format!("{LAKE}/d/f.txt?comp=expiry"),
                &expiry_headers
            )
            .status(),
        200
    );
    assert!(
        server
            .dfs("HEAD", &format!("{LAKE}/d/f.txt"), &[], b"")
            .headers()
            .contains_key("x-ms-expiry-time")
    );

    // Removing execute on the parent directory blocks the caller again despite file write.
    grant(
        &server,
        "d",
        &format!("user::rwx,user:{OID}:rw-,group::r-x,other::---"),
    );
    blob_error(
        server.dfs_as(
            &user,
            "PUT",
            &format!("{LAKE}/d/f.txt?comp=expiry"),
            &[("x-ms-expiry-option", "NeverExpire")],
        ),
        403,
        "AuthorizationPermissionMismatch",
    );
    grant(
        &server,
        "d",
        &format!("user::rwx,user:{OID}:r-x,group::r-x,other::---"),
    );

    // Directory target: denied by ACL when lacking write on directory, rejected as conflict once granted.
    blob_error(
        server.dfs_as(
            &user,
            "PUT",
            &format!("{LAKE}/d/sub?comp=expiry"),
            &expiry_headers,
        ),
        403,
        "AuthorizationPermissionMismatch",
    );
    grant(
        &server,
        "d/sub",
        &format!("user::rwx,user:{OID}:rwx,group::r-x,other::---"),
    );
    blob_error(
        server.dfs_as(
            &user,
            "PUT",
            &format!("{LAKE}/d/sub?comp=expiry"),
            &expiry_headers,
        ),
        409,
        "BlobOperationNotSupported",
    );

    // User-delegation SAS with sp=w is still gated by the delegating user's POSIX ACL.
    let body = format!(
        "<?xml version=\"1.0\" encoding=\"utf-8\"?><KeyInfo><Start>{}</Start><Expiry>{}</Expiry></KeyInfo>",
        in_seconds(&server, -60),
        in_seconds(&server, 3600)
    );
    let key = server.send(
        &server.blob,
        "POST",
        &format!("/{ACCOUNT}?restype=service&comp=userdelegationkey"),
        &[],
        body.as_bytes(),
        &user,
    );
    assert_eq!(key.status(), 200);
    let xml = key.text().unwrap();
    let field = |name: &str| {
        let open = format!("<{name}>");
        let start = xml.find(&open).unwrap() + open.len();
        xml[start..start + xml[start..].find('<').unwrap()].to_owned()
    };
    let (oid, tid, start, expiry) = (
        field("SignedOid"),
        field("SignedTid"),
        field("SignedStart"),
        field("SignedExpiry"),
    );
    let secret = STANDARD.decode(field("Value")).unwrap();
    let canonical = format!("/blob/{ACCOUNT}/lake/d/f.txt");
    let se = in_seconds(&server, 600);
    let signed = [
        "w", "", &se, &canonical, &oid, &tid, &start, &expiry, "b", VERSION, "", "", "", "", "",
        VERSION, "b", "", "", "", "", "", "", "",
    ]
    .join("\n");
    let udsas = Auth::Sas(format!(
        "sv={VERSION}&sr=b&sp=w&se={}&skoid={oid}&sktid={tid}&skt={}&ske={}&sks=b&skv={VERSION}&sig={}",
        encode(&se),
        encode(&start),
        encode(&expiry),
        encode(&sign_with(&secret, &signed))
    ));

    grant(
        &server,
        "d/f.txt",
        &format!("user::rw-,user:{OID}:r--,group::r--,other::---"),
    );
    blob_error(
        server.dfs_as(
            &udsas,
            "PUT",
            &format!("{LAKE}/d/f.txt?comp=expiry"),
            &[("x-ms-expiry-option", "NeverExpire")],
        ),
        403,
        "AuthorizationPermissionMismatch",
    );
    grant(
        &server,
        "d/f.txt",
        &format!("user::rw-,user:{OID}:rw-,group::r--,other::---"),
    );
    assert_eq!(
        server
            .dfs_as(
                &udsas,
                "PUT",
                &format!("{LAKE}/d/f.txt?comp=expiry"),
                &[("x-ms-expiry-option", "NeverExpire")],
            )
            .status(),
        200
    );
    assert!(
        !server
            .dfs("HEAD", &format!("{LAKE}/d/f.txt"), &[], b"")
            .headers()
            .contains_key("x-ms-expiry-time")
    );
}
