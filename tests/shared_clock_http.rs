//! One `--test-clock` shared by every service: the admin listener moves time for Queue, Blob
//! and Files together, so visibility, TTLs and lease expiry are observed without sleeping.

use base64::{Engine as _, engine::general_purpose::STANDARD};
use hmac::{Hmac, KeyInit as _, Mac as _};
use reqwest::{Method, Url, blocking::Client, header::HeaderMap};
use sha2::Sha256;
use std::{
    collections::BTreeMap,
    io::{BufRead as _, BufReader},
    process::{Child, Command, Stdio},
    time::{Duration, SystemTime, UNIX_EPOCH},
};

const ACCOUNT: &str = "testaccount";
const VERSION: &str = "2023-11-03";
const KEY: [u8; 32] = [41; 32];
const LEASE_ID: &str = "7a1f6d0e-3c1b-4d6f-9d0e-0a5e1c2b3d4f";

struct Emulator {
    child: Child,
    urls: BTreeMap<String, String>,
    client: Client,
}

struct Reply {
    status: u16,
    headers: HeaderMap,
    body: String,
}

impl Reply {
    fn header(&self, name: &str) -> &str {
        self.headers[name].to_str().unwrap()
    }
}

impl Emulator {
    fn start(extra: &[&str]) -> Self {
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
        let mut child = command
            .env("AZUIFER_ACCOUNT_NAME", ACCOUNT)
            .env("AZUIFER_ACCOUNT_KEY", STANDARD.encode(KEY))
            .args([
                "serve",
                "--port",
                "0",
                "--admin-port",
                "0",
                "--in-memory",
                "--shutdown-on-stdin-eof",
            ])
            .args(extra)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .spawn()
            .expect("start Azuifer");
        let mut lines = BufReader::new(child.stdout.take().expect("piped stdout")).lines();
        let mut urls = BTreeMap::new();
        for line in lines.by_ref() {
            let line = line.expect("startup line");
            let (name, url) = line.split_once("_url=").expect("a listener URL line");
            urls.insert(name.to_owned(), url.to_owned());
            if name == "admin" {
                break;
            }
        }
        std::thread::spawn(move || lines.for_each(drop));
        Self {
            child,
            urls,
            client: Client::builder()
                .no_proxy()
                .timeout(Duration::from_secs(10))
                .build()
                .unwrap(),
        }
    }

    fn clocked() -> Self {
        Self::start(&["--test-clock"])
    }

    /// The clock on `listener`, which both the admin and Blob listeners serve.
    fn clock_at(&self, listener: &str) -> i64 {
        let reply = self
            .client
            .get(format!("{}/_azuifer/clock", self.urls[listener]))
            .send()
            .unwrap();
        assert_eq!(reply.status(), 200);
        let body = reply.text().unwrap();
        body.strip_prefix("{\"unix_ms\":")
            .and_then(|rest| rest.strip_suffix('}'))
            .unwrap_or_else(|| panic!("clock body {body}"))
            .parse()
            .unwrap()
    }

    fn advance_at(&self, listener: &str, query: &str) {
        let reply = self
            .client
            .post(format!(
                "{}/_azuifer/clock/advance?{query}",
                self.urls[listener]
            ))
            .send()
            .unwrap();
        assert_eq!(reply.status(), 200);
    }

    fn advance(&self, seconds: u64) {
        self.advance_at("admin", &format!("seconds={seconds}"));
    }

    fn send(
        &self,
        service: &str,
        method: &str,
        target: &str,
        extra: &[(&str, &str)],
        body: &str,
    ) -> Reply {
        let method = Method::from_bytes(method.as_bytes()).unwrap();
        let url = Url::parse(&format!("{}/{ACCOUNT}{target}", self.urls[service])).unwrap();
        // Signed dates follow the server's clock so advancing it never trips the skew check.
        let now = UNIX_EPOCH + Duration::from_millis(self.clock_at("admin").unsigned_abs());
        let mut headers = BTreeMap::from([
            ("x-ms-date".to_owned(), httpdate::fmt_http_date(now)),
            ("x-ms-version".to_owned(), VERSION.to_owned()),
        ]);
        if !body.is_empty() {
            headers.insert("content-length".into(), body.len().to_string());
        }
        for (name, value) in extra {
            headers.insert((*name).into(), (*value).into());
        }
        let authorization = sign(&method, &url, &headers);
        headers.insert("authorization".into(), authorization);
        let mut request = self.client.request(method.clone(), url);
        for (name, value) in &headers {
            request = request.header(name, value);
        }
        if matches!(method, Method::PUT | Method::POST) {
            request = request.body(body.to_owned());
        }
        let response = request.send().expect("HTTP request completed");
        Reply {
            status: response.status().as_u16(),
            headers: response.headers().clone(),
            body: response.text().unwrap(),
        }
    }
}

impl Drop for Emulator {
    fn drop(&mut self) {
        drop(self.child.stdin.take());
        let _ = self.child.wait();
    }
}

fn sign(method: &Method, url: &Url, headers: &BTreeMap<String, String>) -> String {
    let value = |name| headers.get(name).map_or("", String::as_str);
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
        "{}\n\n\n{}\n\n{}\n\n\n\n\n\n\n{extensions}/{ACCOUNT}{}{query}",
        method.as_str(),
        value("content-length"),
        value("content-type"),
        url.path()
    );
    let mut mac = Hmac::<Sha256>::new_from_slice(&KEY).unwrap();
    mac.update(message.as_bytes());
    format!(
        "SharedKey {ACCOUNT}:{}",
        STANDARD.encode(mac.finalize().into_bytes())
    )
}

fn expect(reply: Reply, status: u16) -> Reply {
    assert_eq!(reply.status, status, "{}", reply.body);
    reply
}

fn expect_error(reply: Reply, status: u16, code: &str) {
    assert_eq!(reply.status, status, "{}", reply.body);
    assert_eq!(reply.header("x-ms-error-code"), code);
}

const MESSAGE: &str = "<QueueMessage><MessageText>hello</MessageText></QueueMessage>";
const LEASE_15: [(&str, &str); 3] = [
    ("x-ms-lease-action", "acquire"),
    ("x-ms-lease-duration", "15"),
    ("x-ms-proposed-lease-id", LEASE_ID),
];

#[test]
fn the_clock_endpoints_live_on_the_admin_listener_and_share_one_clock() {
    let server = Emulator::clocked();
    let before = server.clock_at("admin");
    server.advance_at("admin", "seconds=100");
    let on_blob = server.clock_at("blob");
    assert!(on_blob >= before + 100_000, "{on_blob} vs {before}");
    server.advance_at("blob", "ms=500");
    let after = server.clock_at("admin");
    assert!(after >= on_blob + 500, "{after} vs {on_blob}");
    assert!(
        after
            < SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_millis() as i64
                + 150_000
    );

    let bad = server
        .client
        .post(format!(
            "{}/_azuifer/clock/advance?seconds=soon",
            server.urls["admin"]
        ))
        .send()
        .unwrap();
    assert_eq!(bad.status(), 400);
    let wrong_method = server
        .client
        .get(format!(
            "{}/_azuifer/clock/advance?seconds=1",
            server.urls["admin"]
        ))
        .send()
        .unwrap();
    assert_eq!(wrong_method.status(), 501);
    assert_eq!(
        server
            .client
            .get(format!("{}/readyz", server.urls["admin"]))
            .send()
            .unwrap()
            .status(),
        200
    );
}

#[test]
fn the_admin_listener_has_no_clock_endpoints_without_test_clock() {
    let server = Emulator::start(&[]);
    for (method, path) in [
        (Method::GET, "/_azuifer/clock"),
        (Method::POST, "/_azuifer/clock/advance?seconds=1"),
    ] {
        let reply = server
            .client
            .request(method, format!("{}{path}", server.urls["admin"]))
            .send()
            .unwrap();
        assert_eq!(reply.status(), 404, "{path}");
    }
}

#[test]
fn one_admin_advance_moves_queue_blob_and_file_time_without_sleeping() {
    let server = Emulator::clocked();

    // Queue: a message hidden for 30 seconds that expires after 100.
    expect(server.send("queue", "PUT", "/clocked", &[], ""), 201);
    expect(
        server.send(
            "queue",
            "POST",
            "/clocked/messages?messagettl=100",
            &[],
            MESSAGE,
        ),
        201,
    );
    let got = expect(
        server.send(
            "queue",
            "GET",
            "/clocked/messages?visibilitytimeout=30",
            &[],
            "",
        ),
        200,
    );
    assert!(got.body.contains("<MessageText>hello</MessageText>"));
    let hidden = server.send("queue", "GET", "/clocked/messages?peekonly=true", &[], "");
    assert!(!expect(hidden, 200).body.contains("<QueueMessage>"));

    // Blob: a 15 second lease guards writes until it expires.
    expect(
        server.send("blob", "PUT", "/clocked?restype=container", &[], ""),
        201,
    );
    expect(
        server.send(
            "blob",
            "PUT",
            "/clocked/b",
            &[("x-ms-blob-type", "BlockBlob")],
            "one",
        ),
        201,
    );
    expect(
        server.send("blob", "PUT", "/clocked/b?comp=lease", &LEASE_15, ""),
        201,
    );
    expect_error(
        server.send(
            "blob",
            "PUT",
            "/clocked/b",
            &[("x-ms-blob-type", "BlockBlob")],
            "two",
        ),
        412,
        "LeaseIdMissing",
    );
    assert_eq!(
        expect(server.send("blob", "HEAD", "/clocked/b", &[], ""), 200).header("x-ms-lease-state"),
        "leased"
    );

    // Files: a 15 second share lease guards the share until it expires.
    expect(
        server.send("file", "PUT", "/clocked?restype=share", &[], ""),
        201,
    );
    expect(
        server.send(
            "file",
            "PUT",
            "/clocked?restype=share&comp=lease",
            &LEASE_15,
            "",
        ),
        201,
    );
    expect_error(
        server.send("file", "DELETE", "/clocked?restype=share", &[], ""),
        412,
        "LeaseIdMissingWithFileShareOperation",
    );

    server.advance(31);

    let visible = expect(
        server.send("queue", "GET", "/clocked/messages?peekonly=true", &[], ""),
        200,
    );
    assert!(visible.body.contains("<DequeueCount>1</DequeueCount>"));
    let blob = expect(server.send("blob", "HEAD", "/clocked/b", &[], ""), 200);
    assert_eq!(blob.header("x-ms-lease-state"), "expired");
    expect(
        server.send(
            "blob",
            "PUT",
            "/clocked/b",
            &[("x-ms-blob-type", "BlockBlob")],
            "two",
        ),
        201,
    );
    let share = expect(
        server.send("file", "HEAD", "/clocked?restype=share", &[], ""),
        200,
    );
    assert_eq!(share.header("x-ms-lease-state"), "expired");
    expect(
        server.send("file", "DELETE", "/clocked?restype=share", &[], ""),
        202,
    );

    server.advance(100);

    let expired = expect(
        server.send("queue", "GET", "/clocked/messages?peekonly=true", &[], ""),
        200,
    );
    assert!(!expired.body.contains("<QueueMessage>"));
    let metadata = expect(
        server.send("queue", "HEAD", "/clocked?comp=metadata", &[], ""),
        200,
    );
    assert_eq!(metadata.header("x-ms-approximate-messages-count"), "0");
}

#[test]
fn a_file_lease_never_expires_but_a_share_lease_does() {
    let server = Emulator::clocked();
    expect(
        server.send("file", "PUT", "/clocked?restype=share", &[], ""),
        201,
    );
    expect(
        server.send(
            "file",
            "PUT",
            "/clocked/f.txt",
            &[("x-ms-type", "file"), ("x-ms-content-length", "3")],
            "",
        ),
        201,
    );
    expect(
        server.send(
            "file",
            "PUT",
            "/clocked/f.txt?comp=lease",
            &[
                ("x-ms-lease-action", "acquire"),
                ("x-ms-lease-duration", "-1"),
                ("x-ms-proposed-lease-id", LEASE_ID),
            ],
            "",
        ),
        201,
    );
    server.advance(3600);
    let head = expect(server.send("file", "HEAD", "/clocked/f.txt", &[], ""), 200);
    assert_eq!(head.header("x-ms-lease-state"), "leased");
    assert_eq!(head.header("x-ms-lease-duration"), "infinite");
    expect_error(
        server.send("file", "DELETE", "/clocked/f.txt", &[], ""),
        412,
        "LeaseIdMissingWithFileOperation",
    );
}
