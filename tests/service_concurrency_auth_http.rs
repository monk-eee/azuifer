use base64::{Engine as _, engine::general_purpose::STANDARD};
use hmac::{Hmac, Mac as _};
use reqwest::{Method, Url, blocking::Client, header::HeaderMap};
use serde::Deserialize;
use serde_json::{Value, json};
use sha2::Sha256;
use std::{
    collections::{BTreeMap, BTreeSet},
    io::{BufRead as _, BufReader},
    path::Path,
    process::{Child, Command, Stdio},
    sync::{Barrier, mpsc},
    thread,
    time::{Duration, Instant, SystemTime},
};

#[path = "service_concurrency_auth_http/files.rs"]
mod files;

const ACCOUNT: &str = "testaccount";
const KEY: [u8; 32] = [41; 32];
const CLIENTS: usize = 8;

struct Reply {
    status: u16,
    headers: HeaderMap,
    body: Vec<u8>,
}

impl Reply {
    fn text(&self) -> &str {
        std::str::from_utf8(&self.body).expect("text response")
    }

    fn json(&self) -> Value {
        serde_json::from_slice(&self.body).expect("JSON response")
    }

    fn header(&self, name: &str) -> &str {
        self.headers[name].to_str().unwrap()
    }

    fn status(self, expected: u16) -> Self {
        assert_eq!(
            self.status,
            expected,
            "response: {}",
            String::from_utf8_lossy(&self.body)
        );
        self
    }

    fn error(self, status: u16, code: &str) {
        assert_eq!(self.status(status).error_code(), code);
    }

    fn error_code(&self) -> String {
        self.headers.get("x-ms-error-code").map_or_else(
            || {
                self.json()["odata.error"]["code"]
                    .as_str()
                    .unwrap()
                    .to_owned()
            },
            |code| code.to_str().unwrap().to_owned(),
        )
    }
}

impl From<reqwest::blocking::Response> for Reply {
    fn from(response: reqwest::blocking::Response) -> Self {
        Self {
            status: response.status().as_u16(),
            headers: response.headers().clone(),
            body: response.bytes().expect("complete response").to_vec(),
        }
    }
}

struct Server {
    child: Child,
    service: &'static str,
    base: String,
    admin: String,
    client: Client,
}

impl Server {
    fn start(service: &'static str, location: Option<&Path>, flags: &[&str]) -> Self {
        let client = || {
            Client::builder()
                .no_proxy()
                .timeout(Duration::from_secs(20))
        };
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
        if let Some(path) = location {
            command.arg("--location").arg(path);
        } else {
            command.arg("--in-memory");
        }
        if service == "file" {
            command.arg("--skip-api-version-check");
        }
        let child = command
            .env("AZUIFER_ACCOUNT_NAME", ACCOUNT)
            .env("AZUIFER_ACCOUNT_KEY", STANDARD.encode(KEY))
            .env("TOKIO_WORKER_THREADS", "2")
            .args([
                "serve",
                "--port",
                "0",
                "--admin-port",
                "0",
                "--services",
                service,
            ])
            .args(flags)
            .arg("--shutdown-on-stdin-eof")
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .spawn()
            .expect("start Azuifer");
        let mut server = Self {
            child,
            service,
            base: String::new(),
            admin: String::new(),
            client: client().build().unwrap(),
        };
        let (send, receive) = mpsc::channel();
        let stdout = server.child.stdout.take().expect("piped startup addresses");
        let tls = flags.contains(&"--tls-generate");
        thread::spawn(move || {
            let mut lines = BufReader::new(stdout).lines();
            let _ = send.send(
                lines
                    .by_ref()
                    .take(if tls { 3 } else { 2 })
                    .collect::<std::io::Result<Vec<_>>>(),
            );
            lines.for_each(drop);
        });
        let lines = receive
            .recv_timeout(Duration::from_secs(20))
            .expect("running emulator")
            .expect("read listener URLs");
        let at = |key: &str| lines.iter().find_map(|line| line.strip_prefix(key));
        server.base = at(format!("{service}_url=").as_str()).unwrap().into();
        server.admin = at("admin_url=").unwrap().into();
        if tls {
            let pem = std::fs::read(at("tls_cert=").expect("generated certificate path")).unwrap();
            server.client = client()
                .add_root_certificate(reqwest::Certificate::from_pem(&pem).unwrap())
                .build()
                .unwrap();
        }
        server.admin(Method::GET, "/readyz").status(200);
        server
    }

    fn crash(&mut self) {
        self.child.kill().expect("kill this test's server");
        self.child.wait().expect("reap this test's server");
    }

    fn admin(&self, method: Method, path: &str) -> Reply {
        self.client
            .request(method, format!("{}{path}", self.admin))
            .send()
            .expect("admin request")
            .into()
    }

    fn advance(&self, seconds: u64) {
        self.admin(
            Method::POST,
            &format!("/_azuifer/clock/advance?seconds={seconds}"),
        )
        .status(200);
    }

    fn url(&self, path: &str) -> String {
        format!("{}/{ACCOUNT}{path}", self.base)
    }

    fn send(&self, method: Method, path: &str, extra: &[(&str, &str)], body: &[u8]) -> Reply {
        let url = Url::parse(&self.url(path)).unwrap();
        let version = if self.service == "file" {
            "2025-07-05"
        } else {
            "2023-11-03"
        };
        let date = httpdate::fmt_http_date(SystemTime::now());
        let len = body.len().to_string();
        let mut headers = BTreeMap::from([("x-ms-date", date.as_str()), ("x-ms-version", version)]);
        if !body.is_empty() {
            headers.insert("content-length", len.as_str());
        }
        headers.extend(extra.iter().copied());
        let value = |name| headers.get(name).copied().unwrap_or("");
        let message = if self.service == "table" {
            format!(
                "{method}\n\n{}\n{date}\n/{ACCOUNT}{}",
                value("content-type"),
                url.path()
            )
        } else {
            let extensions: String = headers
                .iter()
                .filter(|(name, _)| name.starts_with("x-ms-"))
                .map(|(name, value)| format!("{name}:{value}\n"))
                .collect();
            let query: String = url
                .query_pairs()
                .collect::<BTreeMap<_, _>>()
                .into_iter()
                .map(|(name, value)| format!("\n{name}:{value}"))
                .collect();
            format!(
                "{method}\n\n\n{}\n\n{}\n\n\n\n\n\n\n{extensions}/{ACCOUNT}{}{query}",
                value("content-length"),
                value("content-type"),
                url.path(),
            )
        };
        let mut mac = Hmac::<Sha256>::new_from_slice(&KEY).unwrap();
        mac.update(message.as_bytes());
        let signature = STANDARD.encode(mac.finalize().into_bytes());
        let mut request = self
            .client
            .request(method, url)
            .header("authorization", format!("SharedKey {ACCOUNT}:{signature}"));
        for (name, value) in headers {
            request = request.header(name, value);
        }
        if !body.is_empty() {
            request = request.body(body.to_vec());
        }
        request.send().expect("data request completed").into()
    }
}

impl Drop for Server {
    fn drop(&mut self) {
        drop(self.child.stdin.take());
        let deadline = Instant::now() + Duration::from_secs(10);
        while let Ok(None) = self.child.try_wait() {
            if Instant::now() >= deadline {
                let _ = self.child.kill();
                break;
            }
            thread::sleep(Duration::from_millis(10));
        }
        let _ = self.child.wait();
    }
}

fn race<T: Send>(count: usize, request: impl Fn(usize) -> T + Sync) -> Vec<T> {
    let start = Barrier::new(count);
    thread::scope(|scope| {
        let pending: Vec<_> = (0..count)
            .map(|i| {
                let start = &start;
                let request = &request;
                scope.spawn(move || {
                    start.wait();
                    request(i)
                })
            })
            .collect();
        pending
            .into_iter()
            .map(|worker| worker.join().unwrap())
            .collect()
    })
}

#[derive(Deserialize)]
struct DeliveryList {
    #[serde(rename = "QueueMessage", default)]
    messages: Vec<Delivery>,
}

#[derive(Deserialize)]
#[serde(rename_all = "PascalCase")]
struct Delivery {
    message_id: String,
    message_text: String,
    dequeue_count: u32,
    pop_receipt: String,
}

const MESSAGES: &str = "/work/messages";

fn message(text: &str) -> String {
    format!("<QueueMessage><MessageText>{text}</MessageText></QueueMessage>")
}

fn dequeue(server: &Server) -> Option<Delivery> {
    let reply = server
        .send(
            Method::GET,
            "/work/messages?numofmessages=1&visibilitytimeout=300",
            &[],
            b"",
        )
        .status(200);
    let mut list: DeliveryList = quick_xml::de::from_str(reply.text()).unwrap();
    assert!(list.messages.len() <= 1);
    list.messages.pop()
}

fn dequeue_all(server: &Server, count: u32) -> BTreeMap<String, Delivery> {
    let mut messages = BTreeMap::new();
    for delivery in race(2 * CLIENTS, |_| dequeue(server)).into_iter().flatten() {
        assert_eq!(delivery.dequeue_count, count);
        assert!(!delivery.pop_receipt.is_empty());
        assert!(
            messages
                .insert(delivery.message_id.clone(), delivery)
                .is_none(),
            "a hidden message was delivered twice"
        );
    }
    assert_eq!(messages.len(), CLIENTS);
    messages
}

fn message_target(id: &str, receipt: &str, update: bool) -> String {
    let mut params = vec![("popreceipt", receipt)];
    if update {
        params.push(("visibilitytimeout", "300"));
    }
    let url = Url::parse_with_params("http://localhost/", params).unwrap();
    format!("{MESSAGES}/{id}?{}", url.query().unwrap())
}

fn update(server: &Server, id: &str, receipt: &str, text: &str) -> Reply {
    server.send(
        Method::PUT,
        &message_target(id, receipt, true),
        &[("content-type", "application/xml")],
        message(text).as_bytes(),
    )
}

#[test]
fn queue_delivers_each_message_once_per_visibility_window_and_persists_receipts() {
    let root = tempfile::tempdir().unwrap();
    let clocked = || Server::start("queue", Some(root.path()), &["--test-clock"]);
    let mut server = clocked();
    server.send(Method::PUT, "/work", &[], b"").status(201);
    let texts: BTreeSet<_> = (0..CLIENTS).map(|i| format!("message-{i}")).collect();
    for text in &texts {
        server
            .send(
                Method::POST,
                MESSAGES,
                &[("content-type", "application/xml")],
                message(text).as_bytes(),
            )
            .status(201);
    }
    let mut first = dequeue_all(&server, 1);
    assert_eq!(
        first
            .values()
            .map(|d| d.message_text.clone())
            .collect::<BTreeSet<_>>(),
        texts
    );
    let id = first.keys().next().unwrap().clone();
    let lease = first.get_mut(&id).unwrap();
    let stale = lease.pop_receipt.clone();
    let mut winner = None;
    for (i, reply) in race(CLIENTS, |i| {
        update(&server, &id, &stale, &format!("update-{i}"))
    })
    .into_iter()
    .enumerate()
    {
        if reply.status == 204 {
            assert!(
                winner
                    .replace((i, reply.header("x-ms-popreceipt").to_owned()))
                    .is_none()
            );
        } else {
            reply.error(404, "MessageNotFound");
        }
    }
    let (writer, rotated) = winner.expect("one update won the receipt");
    assert_ne!(rotated, stale);
    server.crash();
    drop(server);

    let server = clocked();
    assert!(
        dequeue(&server).is_none(),
        "committed visibility was lost on restart"
    );
    server
        .send(
            Method::DELETE,
            &message_target(&id, &stale, false),
            &[],
            b"",
        )
        .error(404, "MessageNotFound");
    lease.message_text = format!("update-{writer}");
    lease.pop_receipt = server
        .send(Method::PUT, &message_target(&id, &rotated, true), &[], b"")
        .status(204)
        .header("x-ms-popreceipt")
        .to_owned();
    server.advance(301);
    let second = dequeue_all(&server, 2);
    for (id, current) in &second {
        let previous = &first[id];
        assert_eq!(current.message_text, previous.message_text);
        assert_ne!(current.pop_receipt, previous.pop_receipt);
    }
    server
        .send(
            Method::DELETE,
            &message_target(&id, &first[&id].pop_receipt, false),
            &[],
            b"",
        )
        .error(404, "MessageNotFound");

    let receipt = &second[&id].pop_receipt;
    let mut successes = 0;
    for reply in race(CLIENTS, |i| {
        if i % 2 == 0 {
            update(&server, &id, receipt, "raced")
        } else {
            server.send(
                Method::DELETE,
                &message_target(&id, receipt, false),
                &[],
                b"",
            )
        }
    }) {
        if reply.status == 204 {
            successes += 1;
        } else {
            reply.error(404, "MessageNotFound");
        }
    }
    assert_eq!(
        successes, 1,
        "the current receipt can be consumed only once"
    );

    let others: Vec<_> = second.values().filter(|d| d.message_id != id).collect();
    for (i, reply) in race(others.len() + 1, |i| {
        if let Some(delivery) = others.get(i) {
            update(
                &server,
                &delivery.message_id,
                &delivery.pop_receipt,
                "raced-clear",
            )
        } else {
            server.send(Method::DELETE, MESSAGES, &[], b"")
        }
    })
    .into_iter()
    .enumerate()
    {
        if i == others.len() || reply.status == 204 {
            reply.status(204);
        } else {
            reply.error(404, "MessageNotFound");
        }
    }
    drop(server);
    let server = clocked();
    server.advance(602);
    assert!(
        dequeue(&server).is_none(),
        "clear left a message after restart"
    );
}

const ROWS: &str = "/Races";

fn row(name: &str) -> String {
    format!("{ROWS}(PartitionKey='p',RowKey='{name}')")
}

fn insert(server: &Server, row: &str, value: usize) -> Reply {
    server.send(
        Method::POST,
        ROWS,
        &[
            ("content-type", "application/json"),
            ("prefer", "return-no-content"),
        ],
        json!({"PartitionKey": "p", "RowKey": row, "V": value, "Original": true})
            .to_string()
            .as_bytes(),
    )
}

fn batch(server: &Server, marker: &str, etag: &str, value: usize) -> Reply {
    let new = json!({"PartitionKey": "p", "RowKey": marker, "V": value});
    let changed = json!({"V": value});
    let guard = row("guard");
    let body = format!(
        concat!(
            "--batch\r\nContent-Type: multipart/mixed; boundary=changes\r\n\r\n",
            "--changes\r\nContent-Type: application/http\r\nContent-Transfer-Encoding: binary\r\n\r\n",
            "POST http://localhost/{account}{rows} HTTP/1.1\r\nContent-Type: application/json\r\n",
            "Prefer: return-no-content\r\n\r\n{new}\r\n",
            "--changes\r\nContent-Type: application/http\r\nContent-Transfer-Encoding: binary\r\n\r\n",
            "PUT http://localhost/{account}{guard} HTTP/1.1\r\nContent-Type: application/json\r\n",
            "If-Match: {etag}\r\n\r\n{changed}\r\n--changes--\r\n--batch--\r\n"
        ),
        account = ACCOUNT,
        rows = ROWS,
        guard = guard,
        new = new,
        etag = etag,
        changed = changed
    );
    server
        .send(
            Method::POST,
            "/$batch",
            &[("content-type", "multipart/mixed; boundary=batch")],
            body.as_bytes(),
        )
        .status(202)
}

#[test]
fn table_batches_and_conditional_writes_serialize_and_survive_a_crash() {
    let root = tempfile::tempdir().unwrap();
    let start = || Server::start("table", Some(root.path()), &[]);
    let mut server = start();
    server
        .send(
            Method::POST,
            "/Tables",
            &[
                ("content-type", "application/json"),
                ("prefer", "return-no-content"),
            ],
            br#"{"TableName":"Races"}"#,
        )
        .status(204);
    let guard = insert(&server, "guard", 0)
        .status(204)
        .header("etag")
        .to_owned();
    let direct = insert(&server, "direct", 0)
        .status(204)
        .header("etag")
        .to_owned();
    let method = |i| match i % 3 {
        0 => Method::from_bytes(b"MERGE").unwrap(),
        1 => Method::PUT,
        _ => Method::DELETE,
    };
    let replies = race(3 * CLIENTS, |i| match i / CLIENTS {
        0 => batch(&server, &format!("marker-{i}"), &guard, i),
        1 => {
            let verb = method(i);
            let body = json!({"V": i}).to_string();
            server.send(
                verb.clone(),
                &row("direct"),
                &[("if-match", &direct), ("content-type", "application/json")],
                if verb == Method::DELETE {
                    b""
                } else {
                    body.as_bytes()
                },
            )
        }
        _ => insert(&server, "inserted", i),
    });

    let mut batch_winner = None;
    for (i, reply) in replies[..CLIENTS].iter().enumerate() {
        assert!(reply.header("content-type").starts_with("multipart/mixed"));
        let statuses: Vec<_> = reply
            .text()
            .lines()
            .filter(|line| line.starts_with("HTTP/1.1 "))
            .collect();
        if statuses == ["HTTP/1.1 204 No Content"; 2] {
            assert!(batch_winner.replace(i).is_none());
        } else {
            assert_eq!(
                statuses,
                ["HTTP/1.1 412 Precondition Failed"],
                "{}",
                reply.text()
            );
            let error: Value = serde_json::from_str(
                reply
                    .text()
                    .lines()
                    .find(|line| line.starts_with("{\"odata.error\""))
                    .unwrap(),
            )
            .unwrap();
            assert_eq!(error["odata.error"]["code"], "UpdateConditionNotSatisfied");
            assert!(
                error["odata.error"]["message"]["value"]
                    .as_str()
                    .unwrap()
                    .starts_with("1:")
            );
        }
    }
    let batch_winner = batch_winner.expect("one changeset committed");
    let sole_winner = |start: usize| {
        let winners: Vec<_> = (start..start + CLIENTS)
            .filter(|&i| replies[i].status == 204)
            .collect();
        assert_eq!(winners.len(), 1);
        winners[0]
    };
    let direct_winner = sole_winner(CLIENTS);
    let insert_winner = sole_winner(2 * CLIENTS);
    let was_deleted = method(direct_winner) == Method::DELETE;
    for (i, reply) in replies.iter().enumerate().skip(CLIENTS) {
        if i == direct_winner || i == insert_winner {
            continue;
        }
        let (status, code) = if i >= 2 * CLIENTS {
            (409, "EntityAlreadyExists")
        } else if was_deleted {
            (404, "ResourceNotFound")
        } else {
            (412, "UpdateConditionNotSatisfied")
        };
        assert_eq!(reply.status, status, "{}", reply.text());
        assert_eq!(reply.error_code(), code);
    }
    server.crash();
    drop(server);

    let server = start();
    let entities = server
        .send(Method::GET, "/Races()", &[], b"")
        .status(200)
        .json();
    let rows: BTreeMap<_, _> = entities["value"]
        .as_array()
        .unwrap()
        .iter()
        .map(|entity| (entity["RowKey"].as_str().unwrap(), entity))
        .collect();
    assert_eq!(rows.len(), if was_deleted { 3 } else { 4 });
    assert_eq!(rows["guard"]["V"], batch_winner);
    assert_eq!(
        rows[format!("marker-{batch_winner}").as_str()]["V"],
        batch_winner
    );
    assert_eq!(rows["inserted"]["V"], insert_winner);
    if was_deleted {
        assert!(!rows.contains_key("direct"));
    } else {
        assert_eq!(rows["direct"]["V"], direct_winner);
        assert_eq!(
            rows["direct"]["Original"].as_bool(),
            (method(direct_winner).as_str() == "MERGE").then_some(true)
        );
        assert_eq!(
            server
                .send(Method::GET, &row("direct"), &[], b"")
                .status(200)
                .header("etag"),
            replies[direct_winner].header("etag")
        );
    }
    server
        .send(
            Method::PUT,
            &row("guard"),
            &[("if-match", &guard), ("content-type", "application/json")],
            br#"{"V":-1}"#,
        )
        .error(412, "UpdateConditionNotSatisfied");
}

#[test]
fn admin_clock_health_and_metrics_are_consistent_during_concurrent_requests() {
    let clients = CLIENTS / 2;
    let server = Server::start(
        "queue",
        None,
        &["--test-clock", "--prometheus", "--tls-generate"],
    );
    assert!(server.base.starts_with("https://"));
    assert!(server.admin.starts_with("http://"));
    let clock = || {
        server
            .admin(Method::GET, "/_azuifer/clock")
            .status(200)
            .json()["unix_ms"]
            .as_i64()
            .unwrap()
    };
    let started = Instant::now();
    let before = clock();
    let replies = race(7 * clients, |i| match i % 7 {
        0 => server.admin(Method::POST, "/_azuifer/clock/advance?ms=250"),
        1 => server.admin(Method::GET, "/healthz"),
        2 => server.admin(Method::GET, "/readyz"),
        3 => server.admin(Method::GET, "/status"),
        4 => server.admin(Method::GET, "/metrics"),
        5 => server.send(Method::GET, "?comp=list", &[], b""),
        _ => server
            .client
            .get(server.url("?comp=list"))
            .header("authorization", "Unsupported synthetic-client-marker")
            .send()
            .unwrap()
            .into(),
    });
    let after = clock();
    let advanced = 250 * clients as i64;
    assert!(
        (advanced..=advanced + started.elapsed().as_millis() as i64 + 100)
            .contains(&(after - before))
    );
    for (i, reply) in replies.into_iter().enumerate() {
        match i % 7 {
            0 => {
                let observed = reply.status(200).json()["unix_ms"].as_i64().unwrap();
                assert!((before + 250..=after).contains(&observed));
            }
            3 => {
                let text = reply.status(200).json();
                assert_eq!(text["prometheus"], true);
                assert_eq!(
                    text["services"],
                    json!([{"name": "queue", "url": server.base}])
                );
            }
            4 => {
                let reply = reply.status(200);
                assert!(reply.header("content-type").starts_with("text/plain"));
                assert!(!reply.text().contains("synthetic-client-marker"));
            }
            6 => assert!(matches!(reply.status, 400 | 403)),
            _ => {
                reply.status(200);
            }
        }
    }
    let reply = server.admin(Method::GET, "/metrics").status(200);
    let series = |name: &str| {
        reply
            .text()
            .lines()
            .find_map(|line| line.strip_prefix(name)?.trim().parse::<usize>().ok())
            .unwrap()
    };
    assert_eq!(
        series("azuifer_http_request_duration_seconds_count{service=\"queue\"}"),
        2 * clients
    );
    assert_eq!(
        series("azuifer_http_requests_total{service=\"queue\",status=\"200\"}"),
        clients
    );
    assert_eq!(series("azuifer_http_active_requests{service=\"queue\"}"), 0);
    assert!(!reply.text().contains(&STANDARD.encode(KEY)));
    assert!(!reply.text().contains("synthetic-client-marker"));
}
