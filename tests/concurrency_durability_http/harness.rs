//! A running server, signed requests and the helpers the tests share.

use base64::{Engine as _, engine::general_purpose::STANDARD};
use hmac::{Hmac, Mac as _};
use reqwest::{Method, Url, blocking::Client};
use sha2::Sha256;
use std::{
    collections::{BTreeMap, BTreeSet},
    fs,
    io::{BufRead as _, BufReader},
    path::Path,
    process::{Child, Command, Stdio},
    sync::{
        Barrier,
        atomic::{AtomicU64, Ordering},
        mpsc,
    },
    thread,
    time::{Duration, SystemTime},
};

pub const ACCOUNT: &str = "testaccount";
pub const VERSION: &str = "2023-11-03";
pub const KEY: [u8; 32] = [41; 32];
pub const THREADS: usize = 16;
pub const C: &str = "/testaccount/race";

pub struct Reply {
    pub status: u16,
    pub code: String,
    pub headers: BTreeMap<String, String>,
    pub body: Vec<u8>,
}

impl Reply {
    pub fn text(&self) -> String {
        String::from_utf8_lossy(&self.body).into_owned()
    }

    pub fn header(&self, name: &str) -> &str {
        self.headers.get(name).map_or("", String::as_str)
    }
}

pub struct Server {
    pub child: Child,
    pub blob: String,
    pub dfs: String,
    pub admin: String,
    pub client: Client,
    pub offset: AtomicU64,
}

impl Drop for Server {
    fn drop(&mut self) {
        drop(self.child.stdin.take());
        for _ in 0..500 {
            if matches!(self.child.try_wait(), Ok(Some(_))) {
                return;
            }
            thread::sleep(Duration::from_millis(10));
        }
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

impl Server {
    pub fn start(location: Option<&Path>, extra: &[&str]) -> Self {
        Self::launch(location, true, extra)
    }

    /// A server whose account has no hierarchical namespace.
    pub fn flat(location: Option<&Path>, extra: &[&str]) -> Self {
        Self::launch(location, false, extra)
    }

    pub fn launch(location: Option<&Path>, hns: bool, extra: &[&str]) -> Self {
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
            .arg("--shutdown-on-stdin-eof")
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::null());
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
            .recv_timeout(Duration::from_secs(30))
            .expect("server bound its ports");
        Self {
            child,
            blob: urls.remove("blob").expect("Blob listener"),
            dfs: urls.remove("dfs").expect("DFS listener"),
            admin: urls.remove("admin").expect("admin listener"),
            client: Client::builder()
                .no_proxy()
                .timeout(Duration::from_secs(60))
                .build()
                .unwrap(),
            offset: AtomicU64::new(0),
        }
    }

    pub fn now(&self) -> SystemTime {
        SystemTime::now() + Duration::from_secs(self.offset.load(Ordering::SeqCst))
    }

    /// Moves a server started with --test-clock, and the dates requests are signed with.
    pub fn advance(&self, seconds: u64) {
        let response = self
            .client
            .post(format!(
                "{}/_azuifer/clock/advance?seconds={seconds}",
                self.admin
            ))
            .send()
            .unwrap();
        assert_eq!(response.status(), 200);
        self.offset.fetch_add(seconds, Ordering::SeqCst);
    }

    /// Kills the process without letting it shut down, as a crash or power loss would.
    pub fn crash(mut self) {
        self.child.kill().expect("terminate the server");
        self.child.wait().expect("reap the server");
    }

    pub fn alive(&mut self) -> bool {
        matches!(self.child.try_wait(), Ok(None))
    }

    pub fn send(
        &self,
        base: &str,
        method: &str,
        path: &str,
        extra: &[(&str, &str)],
        body: &[u8],
    ) -> Reply {
        let url = Url::parse(&format!("{base}{path}")).unwrap();
        let method = Method::from_bytes(method.as_bytes()).unwrap();
        let has_body = matches!(method.as_str(), "PUT" | "PATCH" | "POST");
        let headers = signed(
            method.as_str(),
            &url,
            extra,
            has_body.then_some(body.len()),
            self.now(),
        );
        let mut request = self.client.request(method, url);
        for (name, value) in headers {
            request = request.header(name, value);
        }
        if has_body {
            request = request.body(body.to_vec());
        }
        let response = request.send().expect("HTTP request completed");
        let status = response.status().as_u16();
        let headers: BTreeMap<String, String> = response
            .headers()
            .iter()
            .map(|(name, value)| {
                (
                    name.as_str().to_owned(),
                    value.to_str().unwrap_or("").to_owned(),
                )
            })
            .collect();
        Reply {
            status,
            code: headers.get("x-ms-error-code").cloned().unwrap_or_default(),
            headers,
            body: response.bytes().expect("response body").to_vec(),
        }
    }

    pub fn blob(&self, method: &str, path: &str, extra: &[(&str, &str)], body: &[u8]) -> Reply {
        self.send(&self.blob, method, path, extra, body)
    }

    pub fn dfs(&self, method: &str, path: &str, extra: &[(&str, &str)], body: &[u8]) -> Reply {
        self.send(&self.dfs, method, path, extra, body)
    }

    pub fn container(&self, name: &str) {
        let made = self.blob(
            "PUT",
            &format!("/{ACCOUNT}/{name}?restype=container"),
            &[],
            b"",
        );
        assert_eq!(made.status, 201, "{}", made.text());
    }

    pub fn put(&self, name: &str, body: &[u8]) -> Reply {
        self.blob("PUT", name, &[("x-ms-blob-type", "BlockBlob")], body)
    }

    pub fn names(&self, container: &str, query: &str) -> Vec<String> {
        let listing = self.blob(
            "GET",
            &format!("/{ACCOUNT}/{container}?restype=container&comp=list{query}"),
            &[],
            b"",
        );
        assert_eq!(listing.status, 200, "{}", listing.text());
        let text = listing.text();
        text.split("<Name>")
            .skip(1)
            .map(|part| part.split("</Name>").next().unwrap().to_owned())
            .collect()
    }
}

/// The headers of a Shared Key request; `length` is the declared body length, if it has a body.
pub fn signed(
    method: &str,
    url: &Url,
    extra: &[(&str, &str)],
    length: Option<usize>,
    now: SystemTime,
) -> BTreeMap<String, String> {
    let mut headers = BTreeMap::from([
        ("x-ms-date".to_owned(), httpdate::fmt_http_date(now)),
        ("x-ms-version".to_owned(), VERSION.to_owned()),
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
    let query: String = query.iter().map(|(n, v)| format!("\n{n}:{v}")).collect();
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
/// Runs `work(i)` for `i` in `0..count` on as many threads, released together.
pub fn race<T: Send>(count: usize, work: impl Fn(usize) -> T + Sync) -> Vec<T> {
    let barrier = Barrier::new(count);
    thread::scope(|scope| {
        let handles: Vec<_> = (0..count)
            .map(|index| {
                let (barrier, work) = (&barrier, &work);
                scope.spawn(move || {
                    barrier.wait();
                    work(index)
                })
            })
            .collect();
        handles
            .into_iter()
            .map(|handle| handle.join().unwrap())
            .collect()
    })
}

pub fn count(replies: &[Reply], status: u16) -> usize {
    replies
        .iter()
        .filter(|reply| reply.status == status)
        .count()
}

/// No reply is a server error, and every failure carries an Azure error code.
pub fn assert_clean(replies: &[Reply]) {
    for reply in replies {
        assert!(
            reply.status < 500,
            "{} {}: {}",
            reply.status,
            reply.code,
            reply.text()
        );
        if reply.status >= 400 {
            assert!(!reply.code.is_empty(), "{} has no error code", reply.status);
        }
    }
}

pub fn in_both_modes(check: impl Fn(&Server)) {
    check(&Server::start(None, &[]));
    let root = tempfile::tempdir().unwrap();
    check(&Server::start(Some(root.path()), &[]));
}

pub fn block_id(index: usize) -> String {
    STANDARD
        .encode(format!("block-{index:04}"))
        .replace('=', "%3D")
}

pub fn encode(value: &str) -> String {
    value
        .bytes()
        .map(|b| match b {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' => {
                (b as char).to_string()
            }
            _ => format!("%{b:02X}"),
        })
        .collect()
}

pub fn extents(location: &Path) -> Vec<String> {
    let mut names: Vec<String> = fs::read_dir(location.join("content"))
        .unwrap()
        .map(|entry| entry.unwrap().file_name().to_string_lossy().into_owned())
        .collect();
    names.sort();
    names
}

pub fn borrowed<'a>(headers: &'a [(&'static str, String)]) -> Vec<(&'static str, &'a str)> {
    headers
        .iter()
        .map(|(name, value)| (*name, value.as_str()))
        .collect()
}

pub fn must(reply: Reply, status: u16) -> Reply {
    assert_eq!(reply.status, status, "{} {}", reply.code, reply.text());
    reply
}

pub fn tree(server: &Server, root: &str) -> Vec<(String, String)> {
    let mut files = Vec::new();
    for dir in 0..3 {
        for file in 0..8 {
            let name = format!("{C}/{root}/d{dir}/f{file}");
            let content = format!("{root}-{dir}-{file}");
            must(server.put(&name, content.as_bytes()), 201);
            files.push((name, content));
        }
    }
    files
}

pub fn set(names: Vec<String>) -> BTreeSet<String> {
    names.into_iter().collect()
}

pub fn rename(server: &Server, from: &str, to: &str) -> Reply {
    server.dfs(
        "PUT",
        &format!("{C}/{to}"),
        &[("x-ms-rename-source", &format!("/race/{from}"))],
        b"",
    )
}
