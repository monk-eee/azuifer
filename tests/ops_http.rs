use base64::{Engine as _, engine::general_purpose::STANDARD};
use reqwest::blocking::Client;
use std::{
    collections::HashMap,
    io::{BufRead as _, BufReader, Read as _, Write as _},
    net::{SocketAddr, TcpListener},
    process::{Child, Command, Stdio},
    sync::{
        Arc, Mutex,
        atomic::{AtomicUsize, Ordering},
    },
    time::{Duration, Instant},
};

#[path = "ops_http/compat.rs"]
mod compat;
#[path = "ops_http/runtime.rs"]
mod runtime;
#[path = "ops_http/traces.rs"]
mod traces;

struct Server {
    child: Child,
    urls: HashMap<String, String>,
}

impl Server {
    fn start(args: &[&str], env: &[(&str, &str)]) -> Self {
        let mut command = Command::new(env!("CARGO_BIN_EXE_azuifer"));
        for (name, _) in std::env::vars_os() {
            let upper = name.to_string_lossy().to_ascii_uppercase();
            if upper.starts_with("AZUIFER_") || upper.starts_with("OTEL_") {
                command.env_remove(name);
            }
        }
        command.envs(env.iter().copied());
        command.args([
            "serve",
            "--port",
            "0",
            "--admin-port",
            "0",
            "--shutdown-on-stdin-eof",
        ]);
        if !args.contains(&"--location") {
            command.arg("--in-memory");
        }
        command.args(args);
        let mut child = command
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::null())
            .spawn()
            .expect("start Azuifer");
        let mut lines = BufReader::new(child.stdout.take().expect("piped stdout")).lines();
        let mut urls = HashMap::new();
        for line in lines.by_ref() {
            let line = line.expect("startup line");
            let (name, url) = line.split_once("_url=").expect("a listener URL line");
            urls.insert(name.to_owned(), url.to_owned());
            if name == "admin" {
                break;
            }
        }
        std::thread::spawn(move || lines.for_each(drop));
        Self { child, urls }
    }

    fn url(&self, name: &str) -> &str {
        &self.urls[name]
    }
}

impl Drop for Server {
    fn drop(&mut self) {
        drop(self.child.stdin.take());
        let _ = self.child.wait();
    }
}

fn client() -> Client {
    Client::builder()
        .no_proxy()
        .timeout(Duration::from_secs(10))
        .build()
        .unwrap()
}

fn status_json(client: &Client, server: &Server) -> serde_json::Value {
    let body = client
        .get(format!("{}/status", server.url("admin")))
        .send()
        .unwrap()
        .text()
        .unwrap();
    serde_json::from_str(&body).unwrap()
}

/// Shared Key authorization for a body-less GET at a path-style Blob endpoint.
fn shared_key_get(key: &str, path: &str, canonical_query: &str) -> (String, String) {
    use hmac::{Hmac, Mac as _};
    let date = httpdate::fmt_http_date(std::time::SystemTime::now());
    let string_to_sign = format!(
        "GET\n\n\n\n\n\n\n\n\n\n\n\nx-ms-date:{date}\nx-ms-version:2023-11-03\n/devstoreaccount1{path}\n{canonical_query}"
    );
    let mut mac = Hmac::<sha2::Sha256>::new_from_slice(&STANDARD.decode(key).unwrap()).unwrap();
    mac.update(string_to_sign.as_bytes());
    let signature = STANDARD.encode(mac.finalize().into_bytes());
    (date, format!("SharedKey devstoreaccount1:{signature}"))
}

fn account_key() -> String {
    STANDARD.encode(b"synthetic-account-key-for-redaction-tests")
}

fn metric(text: &str, series: &str) -> Option<u64> {
    text.lines()
        .find_map(|line| line.strip_prefix(series)?.trim().parse().ok())
}

fn contains(haystack: &[u8], needle: &str) -> bool {
    haystack
        .windows(needle.len())
        .any(|window| window == needle.as_bytes())
}

#[test]
fn metrics_count_requests_per_service_and_never_expose_secrets() {
    let key = account_key();
    let server = Server::start(&["--prometheus"], &[("AZUIFER_ACCOUNT_KEY", &key)]);
    let client = client();
    for _ in 0..2 {
        client
            .get(format!(
                "{}/devstoreaccount1?comp=list",
                server.url("queue")
            ))
            .header(
                "authorization",
                "SharedKey devstoreaccount1:SEEDEDSHAREDKEYSIGNATURE",
            )
            .send()
            .unwrap();
    }
    client
        .get(format!(
            "{}/devstoreaccount1/Tables?sig=SEEDEDSASSIGNATURE",
            server.url("table")
        ))
        .send()
        .unwrap();
    for _ in 0..3 {
        client
            .get(format!(
                "{}/devstoreaccount1/{key}?restype=container&sig=SEEDEDSASSIGNATURE&token={key}",
                server.url("blob")
            ))
            .header("x-ms-version", "2023-11-03")
            .send()
            .unwrap();
    }

    let response = client
        .get(format!("{}/metrics", server.url("admin")))
        .send()
        .unwrap();
    assert_eq!(response.status(), 200);
    assert_eq!(
        response.headers()["content-type"],
        "text/plain; version=0.0.4; charset=utf-8"
    );
    let text = response.text().unwrap();
    assert_eq!(
        metric(
            &text,
            "azuifer_http_requests_total{service=\"queue\",status=\"400\"}"
        ),
        Some(2),
        "{text}"
    );
    assert_eq!(
        metric(
            &text,
            "azuifer_http_requests_total{service=\"table\",status=\"403\"}"
        ),
        Some(1),
        "{text}"
    );
    assert_eq!(
        metric(
            &text,
            "azuifer_http_request_duration_seconds_count{service=\"blob\"}"
        ),
        Some(3),
        "{text}"
    );
    assert_eq!(
        metric(
            &text,
            "azuifer_http_request_duration_seconds_count{service=\"file\"}"
        ),
        Some(0),
        "{text}"
    );
    assert_eq!(
        metric(&text, "azuifer_http_active_requests{service=\"blob\"}"),
        Some(0)
    );
    assert!(
        metric(
            &text,
            "azuifer_http_response_bytes_total{service=\"queue\"}"
        )
        .unwrap()
            > 0,
        "{text}"
    );
    for secret in [
        key.as_str(),
        "SEEDEDSASSIGNATURE",
        "SEEDEDSHAREDKEYSIGNATURE",
        "SharedKey",
    ] {
        assert!(!text.contains(secret), "metrics leaked `{secret}`:\n{text}");
    }
}

#[test]
fn metrics_are_not_served_unless_enabled() {
    let server = Server::start(&[], &[]);
    let response = client()
        .get(format!("{}/metrics", server.url("admin")))
        .send()
        .unwrap();
    assert_eq!(response.status(), 404);
}

#[test]
fn status_endpoint_lists_services_and_storage_mode() {
    let server = Server::start(&["--services", "queue,table"], &[]);
    let body = status_json(&client(), &server);
    assert_eq!(body["version"], env!("CARGO_PKG_VERSION"));
    assert_eq!(body["storage"], "in-memory");
    assert_eq!(body["location"], serde_json::Value::Null);
    assert_eq!(body["admin_url"], server.url("admin"));
    assert_eq!(body["prometheus"], false);
    assert_eq!(body["otlp"], false);
    let services: Vec<_> = body["services"]
        .as_array()
        .unwrap()
        .iter()
        .map(|service| {
            (
                service["name"].as_str().unwrap(),
                service["url"].as_str().unwrap(),
            )
        })
        .collect();
    assert_eq!(
        services,
        [
            ("queue", server.url("queue")),
            ("table", server.url("table"))
        ]
    );
    assert!(body["uptime_seconds"].is_u64());
}

#[test]
fn logs_follow_the_selected_format_and_file() {
    let dir = tempfile::tempdir().unwrap();
    let json_log = dir.path().join("json.log");
    let text_log = dir.path().join("text.log");
    for (path, format) in [(&json_log, "json"), (&text_log, "text")] {
        let server = Server::start(
            &[
                "--log-format",
                format,
                "--log-file",
                path.to_str().unwrap(),
                "--services",
                "queue",
            ],
            &[],
        );
        client()
            .get(format!(
                "{}/devstoreaccount1?comp=list",
                server.url("queue")
            ))
            .send()
            .unwrap();
        drop(server);
    }
    let json = std::fs::read_to_string(&json_log).unwrap();
    let first: serde_json::Value = serde_json::from_str(json.lines().next().unwrap()).unwrap();
    assert_eq!(first["fields"]["message"], "listening");
    let text = std::fs::read_to_string(&text_log).unwrap();
    assert!(
        text.contains("listening")
            && serde_json::from_str::<serde_json::Value>(text.lines().next().unwrap()).is_err()
    );
}

/// (path, body) of every request a fake collector received.
type Recorded = Arc<Mutex<Vec<(String, Vec<u8>)>>>;

struct Collector {
    address: SocketAddr,
    requests: Recorded,
    connections: Arc<AtomicUsize>,
}

/// A fake OTLP/HTTP collector that records every request it receives.
fn collector() -> Collector {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let address = listener.local_addr().unwrap();
    let requests = Arc::new(Mutex::new(Vec::new()));
    let connections = Arc::new(AtomicUsize::new(0));
    let (recorded, counted) = (requests.clone(), connections.clone());
    std::thread::spawn(move || {
        for stream in listener.incoming().flatten() {
            counted.fetch_add(1, Ordering::SeqCst);
            let recorded = recorded.clone();
            std::thread::spawn(move || serve_collector(stream, &recorded));
        }
    });
    Collector {
        address,
        requests,
        connections,
    }
}

fn serve_collector(mut stream: std::net::TcpStream, recorded: &Mutex<Vec<(String, Vec<u8>)>>) {
    let mut buffer = Vec::new();
    let mut chunk = [0_u8; 8192];
    loop {
        let head_end = loop {
            if let Some(position) = buffer.windows(4).position(|window| window == b"\r\n\r\n") {
                break position + 4;
            }
            match stream.read(&mut chunk) {
                Ok(0) | Err(_) => return,
                Ok(read) => buffer.extend_from_slice(&chunk[..read]),
            }
        };
        let head = String::from_utf8_lossy(&buffer[..head_end]).into_owned();
        let path = head
            .split_whitespace()
            .nth(1)
            .unwrap_or_default()
            .to_owned();
        let length: usize = head
            .lines()
            .find_map(|line| {
                let (name, value) = line.split_once(':')?;
                name.eq_ignore_ascii_case("content-length")
                    .then(|| value.trim().parse().ok())?
            })
            .expect("the exporter declares a Content-Length");
        while buffer.len() < head_end + length {
            match stream.read(&mut chunk) {
                Ok(0) | Err(_) => return,
                Ok(read) => buffer.extend_from_slice(&chunk[..read]),
            }
        }
        recorded
            .lock()
            .unwrap()
            .push((path, buffer[head_end..head_end + length].to_vec()));
        buffer.drain(..head_end + length);
        let reply =
            "HTTP/1.1 200 OK\r\nContent-Type: application/x-protobuf\r\nContent-Length: 0\r\n\r\n";
        if stream.write_all(reply.as_bytes()).is_err() {
            return;
        }
    }
}

fn payloads(collector: &Collector, path: &str) -> Vec<Vec<u8>> {
    let deadline = Instant::now() + Duration::from_secs(10);
    loop {
        let found: Vec<_> = collector
            .requests
            .lock()
            .unwrap()
            .iter()
            .filter(|(candidate, _)| candidate == path)
            .map(|(_, body)| body.clone())
            .collect();
        if !found.is_empty() || Instant::now() > deadline {
            return found;
        }
        std::thread::sleep(Duration::from_millis(50));
    }
}

#[test]
fn spans_and_metrics_reach_a_configured_otlp_http_collector_without_secrets() {
    let collector = collector();
    let key = account_key();
    let endpoint = format!("http://{}", collector.address);
    let server = Server::start(
        &[
            "--otlp-endpoint",
            &endpoint,
            "--otlp-protocol",
            "http",
            "--services",
            "blob,queue",
        ],
        &[("AZUIFER_ACCOUNT_KEY", &key)],
    );
    let client = client();
    let response = client
        .get(format!(
            "{}/devstoreaccount1?comp=list&%73ig=SEEDEDENCODEDKEYSAS",
            server.url("queue")
        ))
        .header(
            "authorization",
            "SharedKey devstoreaccount1:SEEDEDSHAREDKEYSIGNATURE",
        )
        .header("x-ms-client-request-id", "trace-me-123")
        .send()
        .unwrap();
    let request_id = response.headers()["x-ms-request-id"]
        .to_str()
        .unwrap()
        .to_owned();
    client
        .get(format!(
            "{}/devstoreaccount1/{key}?restype=container&sig=SEEDEDSASSIGNATURE",
            server.url("blob")
        ))
        .header("x-ms-version", "2023-11-03")
        .send()
        .unwrap();
    let (date, authorization) =
        shared_key_get(&key, "/devstoreaccount1/cont1", "restype:container");
    let signed = client
        .get(format!(
            "{}/devstoreaccount1/cont1?restype=container",
            server.url("blob")
        ))
        .header("x-ms-version", "2023-11-03")
        .header("x-ms-date", date)
        .header("authorization", authorization)
        .send()
        .unwrap();
    assert_eq!(
        signed.status(),
        404,
        "an authenticated request reaches storage"
    );
    let status = status_json(&client, &server);
    assert_eq!(status["otlp"], true);
    drop(server);

    let spans = payloads(&collector, "/v1/traces").concat();
    for expected in [
        "azuifer.service",
        "queue",
        "azuifer.operation",
        "GET comp=list",
        "http.response.status_code",
        "url.path",
        &request_id,
        "trace-me-123",
        "authenticate",
        "storage",
    ] {
        assert!(
            contains(&spans, expected),
            "no `{expected}` in the exported spans"
        );
    }
    let metrics = payloads(&collector, "/v1/metrics").concat();
    assert!(contains(&metrics, "azuifer.http.server.requests"));
    assert!(contains(&metrics, "azuifer.http.server.request.duration"));
    for (name, payload) in [("traces", &spans), ("metrics", &metrics)] {
        for secret in [
            key.as_str(),
            "SEEDEDSASSIGNATURE",
            "SEEDEDENCODEDKEYSAS",
            "SEEDEDSHAREDKEYSIGNATURE",
        ] {
            assert!(
                !contains(payload, secret),
                "exported {name} leaked `{secret}`"
            );
        }
    }
    assert!(contains(&spans, "REDACTED"));
}

#[test]
fn nothing_is_sent_unless_an_endpoint_is_configured() {
    let collector = collector();
    let endpoint = format!("http://{}", collector.address);
    let server = Server::start(
        &["--services", "queue", "--prometheus"],
        &[
            ("OTEL_EXPORTER_OTLP_ENDPOINT", &endpoint),
            ("OTEL_TRACES_EXPORTER", "otlp"),
        ],
    );
    client()
        .get(format!(
            "{}/devstoreaccount1?comp=list",
            server.url("queue")
        ))
        .send()
        .unwrap();
    drop(server);
    std::thread::sleep(Duration::from_millis(500));
    assert_eq!(collector.connections.load(Ordering::SeqCst), 0);
    assert!(collector.requests.lock().unwrap().is_empty());
}

#[test]
fn spans_reach_a_configured_otlp_grpc_collector() {
    let runtime = tokio::runtime::Runtime::new().unwrap();
    let received: Recorded = Arc::new(Mutex::new(Vec::new()));
    let address = runtime.block_on(async {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let received = received.clone();
        tokio::spawn(async move {
            loop {
                let Ok((stream, _)) = listener.accept().await else {
                    return;
                };
                let received = received.clone();
                let service = hyper::service::service_fn(
                    move |request: hyper::Request<hyper::body::Incoming>| {
                        let received = received.clone();
                        async move {
                            let path = request.uri().path().to_owned();
                            let body = axum::body::to_bytes(
                                axum::body::Body::new(request.into_body()),
                                usize::MAX,
                            )
                            .await
                            .unwrap_or_default();
                            received.lock().unwrap().push((path, body.to_vec()));
                            Ok::<_, std::convert::Infallible>(
                                hyper::Response::builder()
                                    .header("content-type", "application/grpc")
                                    .header("grpc-status", "0")
                                    .body(axum::body::Body::from(vec![0_u8; 5]))
                                    .unwrap(),
                            )
                        }
                    },
                );
                tokio::spawn(
                    hyper::server::conn::http2::Builder::new(hyper_util::rt::TokioExecutor::new())
                        .serve_connection(hyper_util::rt::TokioIo::new(stream), service),
                );
            }
        });
        address
    });
    let endpoint = format!("http://{address}");
    let server = Server::start(&["--otlp-endpoint", &endpoint, "--services", "queue"], &[]);
    client()
        .get(format!(
            "{}/devstoreaccount1?comp=list",
            server.url("queue")
        ))
        .send()
        .unwrap();
    drop(server);
    let deadline = Instant::now() + Duration::from_secs(10);
    let trace = loop {
        let found = received
            .lock()
            .unwrap()
            .iter()
            .find(|(path, _)| path == "/opentelemetry.proto.collector.trace.v1.TraceService/Export")
            .cloned();
        if let Some((_, body)) = found {
            break body;
        }
        assert!(Instant::now() < deadline, "no gRPC trace export arrived");
        std::thread::sleep(Duration::from_millis(50));
    };
    assert!(contains(&trace, "azuifer.service"));
}
