//! Runtime metrics from inside the stores, read from the Prometheus endpoint and OTLP:
//! queue depth, active leases, metadata lock contention, content reclamation, and backend
//! failures. Each test drives the built binary and asserts the counts that result.

use super::*;
use hmac::{Hmac, KeyInit as _, Mac as _};
use reqwest::Url;
use std::collections::BTreeMap;

const ACCOUNT: &str = "devstoreaccount1";
const VERSION: &str = "2023-11-03";

struct Reply {
    status: u16,
    headers: HashMap<String, String>,
    body: String,
}

/// A Shared Key signed request to one of the server's listeners.
fn call(
    server: &Server,
    service: &str,
    method: &str,
    path: &str,
    extra: &[(&str, &str)],
    body: &[u8],
) -> Reply {
    let url = Url::parse(&format!("{}{path}", server.url(service))).unwrap();
    let mut headers = BTreeMap::from([
        (
            "x-ms-date".to_owned(),
            httpdate::fmt_http_date(std::time::SystemTime::now()),
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
    let mut mac =
        Hmac::<sha2::Sha256>::new_from_slice(&STANDARD.decode(account_key()).unwrap()).unwrap();
    mac.update(message.as_bytes());
    let authorization = format!(
        "SharedKey {ACCOUNT}:{}",
        STANDARD.encode(mac.finalize().into_bytes())
    );
    let mut request = client().request(method.parse().unwrap(), url);
    for (name, value) in &headers {
        request = request.header(name, value);
    }
    request = request.header("authorization", authorization);
    if matches!(method, "PUT" | "POST") {
        request = request.body(body.to_vec());
    }
    let response = request.send().unwrap();
    Reply {
        status: response.status().as_u16(),
        headers: response
            .headers()
            .iter()
            .map(|(name, value)| {
                (
                    name.as_str().to_owned(),
                    value.to_str().unwrap_or("").to_owned(),
                )
            })
            .collect(),
        body: response.text().unwrap(),
    }
}

fn expect(reply: Reply, status: u16) -> Reply {
    assert_eq!(reply.status, status, "{}", reply.body);
    reply
}

fn scrape(server: &Server) -> String {
    client()
        .get(format!("{}/metrics", server.url("admin")))
        .send()
        .unwrap()
        .text()
        .unwrap()
}

/// The value of the sample whose name and labels are exactly `series`.
fn sample(text: &str, series: &str) -> Option<f64> {
    text.lines().find_map(|line| {
        line.strip_prefix(series)?
            .strip_prefix(' ')?
            .trim()
            .parse()
            .ok()
    })
}

fn queue_depth(text: &str, queue: &str, state: &str) -> Option<f64> {
    sample(
        text,
        &format!(
            "azuifer_queue_messages{{account=\"{ACCOUNT}\",queue=\"{queue}\",state=\"{state}\"}}"
        ),
    )
}

fn leases(text: &str, kind: &str) -> Option<f64> {
    sample(text, &format!("azuifer_active_leases{{kind=\"{kind}\"}}"))
}

fn message(text: &str) -> Vec<u8> {
    format!("<QueueMessage><MessageText>{text}</MessageText></QueueMessage>").into_bytes()
}

fn started(extra: &[&str]) -> Server {
    let key = account_key();
    let mut args = vec!["--prometheus"];
    args.extend_from_slice(extra);
    Server::start(&args, &[("AZUIFER_ACCOUNT_KEY", &key)])
}

#[test]
fn queue_depth_follows_puts_receives_and_clears() {
    let server = started(&[]);
    let before = scrape(&server);
    assert_eq!(queue_depth(&before, "depth", "visible"), None, "{before}");

    let queue = format!("/{ACCOUNT}/depth");
    expect(call(&server, "queue", "PUT", &queue, &[], b""), 201);
    let empty = scrape(&server);
    assert_eq!(
        queue_depth(&empty, "depth", "visible"),
        Some(0.0),
        "{empty}"
    );
    assert_eq!(queue_depth(&empty, "depth", "invisible"), Some(0.0));

    let messages = format!("{queue}/messages");
    for text in ["a", "b", "c"] {
        expect(
            call(&server, "queue", "POST", &messages, &[], &message(text)),
            201,
        );
    }
    let put = scrape(&server);
    assert_eq!(queue_depth(&put, "depth", "visible"), Some(3.0), "{put}");

    let received = expect(
        call(
            &server,
            "queue",
            "GET",
            &format!("{messages}?numofmessages=1&visibilitytimeout=600"),
            &[],
            b"",
        ),
        200,
    );
    assert!(
        received.body.contains("<MessageText>a</MessageText>"),
        "{}",
        received.body
    );
    let received = scrape(&server);
    assert_eq!(
        queue_depth(&received, "depth", "visible"),
        Some(2.0),
        "{received}"
    );
    assert_eq!(queue_depth(&received, "depth", "invisible"), Some(1.0));

    expect(call(&server, "queue", "DELETE", &messages, &[], b""), 204);
    let cleared = scrape(&server);
    assert_eq!(
        queue_depth(&cleared, "depth", "visible"),
        Some(0.0),
        "{cleared}"
    );
    assert_eq!(queue_depth(&cleared, "depth", "invisible"), Some(0.0));

    expect(call(&server, "queue", "DELETE", &queue, &[], b""), 204);
    assert_eq!(queue_depth(&scrape(&server), "depth", "visible"), None);
}

#[test]
fn active_leases_follow_acquire_and_release_on_blobs_containers_shares_and_files() {
    let server = started(&[]);
    let kinds = ["blob", "container", "share", "file"];
    let text = scrape(&server);
    for kind in kinds {
        assert_eq!(leases(&text, kind), Some(0.0), "{kind}:\n{text}");
    }

    let container = format!("/{ACCOUNT}/leased");
    let blob = format!("{container}/item");
    let share = format!("/{ACCOUNT}/share");
    let file = format!("{share}/f.txt");
    expect(
        call(
            &server,
            "blob",
            "PUT",
            &format!("{container}?restype=container"),
            &[],
            b"",
        ),
        201,
    );
    expect(
        call(
            &server,
            "blob",
            "PUT",
            &blob,
            &[("x-ms-blob-type", "BlockBlob")],
            b"data",
        ),
        201,
    );
    expect(
        call(
            &server,
            "file",
            "PUT",
            &format!("{share}?restype=share"),
            &[],
            b"",
        ),
        201,
    );
    expect(
        call(
            &server,
            "file",
            "PUT",
            &file,
            &[
                ("x-ms-type", "file"),
                ("x-ms-content-length", "4"),
                ("x-ms-file-attributes", "None"),
                ("x-ms-file-creation-time", "now"),
                ("x-ms-file-last-write-time", "now"),
                ("x-ms-file-permission", "inherit"),
            ],
            b"",
        ),
        201,
    );

    let targets = [
        ("blob", format!("{blob}?comp=lease")),
        ("blob", format!("{container}?restype=container&comp=lease")),
        ("file", format!("{share}?restype=share&comp=lease")),
        ("file", format!("{file}?comp=lease")),
    ];
    let acquire = [
        ("x-ms-lease-action", "acquire"),
        ("x-ms-lease-duration", "-1"),
    ];
    let ids: Vec<String> = targets
        .iter()
        .map(|(service, path)| {
            let reply = expect(call(&server, service, "PUT", path, &acquire, b""), 201);
            reply.headers["x-ms-lease-id"].clone()
        })
        .collect();
    let held = scrape(&server);
    for kind in kinds {
        assert_eq!(leases(&held, kind), Some(1.0), "{kind}:\n{held}");
    }

    for ((service, path), id) in targets.iter().zip(&ids) {
        let release = [
            ("x-ms-lease-action", "release"),
            ("x-ms-lease-id", id.as_str()),
        ];
        expect(call(&server, service, "PUT", path, &release, b""), 200);
    }
    let released = scrape(&server);
    for kind in kinds {
        assert_eq!(leases(&released, kind), Some(0.0), "{kind}:\n{released}");
    }
}

#[test]
fn every_store_counts_its_lock_acquisitions_and_exposes_the_wait() {
    let server = started(&[]);
    expect(
        call(
            &server,
            "queue",
            "PUT",
            &format!("/{ACCOUNT}/locks"),
            &[],
            b"",
        ),
        201,
    );
    expect(
        call(
            &server,
            "blob",
            "PUT",
            &format!("/{ACCOUNT}/locks?restype=container"),
            &[],
            b"",
        ),
        201,
    );
    expect(
        call(
            &server,
            "file",
            "PUT",
            &format!("/{ACCOUNT}/locks?restype=share"),
            &[],
            b"",
        ),
        201,
    );
    let text = scrape(&server);
    for store in ["queue", "namespace", "files"] {
        let series = |name: &str| {
            sample(
                &text,
                &format!("azuifer_store_lock_{name}{{store=\"{store}\"}}"),
            )
        };
        let acquisitions = series("acquisitions_total").unwrap_or(0.0);
        assert!(acquisitions >= 1.0, "{store}:\n{text}");
        assert!(
            series("contended_total").unwrap() <= acquisitions,
            "{store}"
        );
        assert!(series("wait_seconds_total").unwrap() >= 0.0, "{store}");
    }
    assert!(
        sample(
            &text,
            "azuifer_store_lock_acquisitions_total{store=\"table\"}"
        )
        .is_none(),
        "a store nothing has used is not reported:\n{text}"
    );
    assert!(text.contains("# TYPE azuifer_store_lock_wait_seconds_total counter"));
}

fn removed(text: &str, what: &str, reason: &str) -> f64 {
    sample(
        text,
        &format!("azuifer_gc_{what}_total{{reason=\"{reason}\"}}"),
    )
    .unwrap_or_else(|| panic!("no gc series in:\n{text}"))
}

#[test]
fn overwritten_and_deleted_content_is_reclaimed_and_a_crash_leftover_is_recovered() {
    let dir = tempfile::tempdir().unwrap();
    let location = dir.path().join("data");
    let location = location.to_str().unwrap();
    let args = ["--location", location, "--services", "blob"];
    {
        let server = started(&args);
        let idle = scrape(&server);
        assert_eq!(removed(&idle, "extents", "reclaimed"), 0.0, "{idle}");
        let container = format!("/{ACCOUNT}/reclaim");
        expect(
            call(
                &server,
                "blob",
                "PUT",
                &format!("{container}?restype=container"),
                &[],
                b"",
            ),
            201,
        );
        let put = |bytes: usize| {
            let headers = [("x-ms-blob-type", "BlockBlob")];
            let path = format!("{container}/item");
            expect(
                call(&server, "blob", "PUT", &path, &headers, &vec![b'x'; bytes]),
                201,
            );
        };
        put(1000);
        assert_eq!(removed(&scrape(&server), "extents", "reclaimed"), 0.0);
        put(3000);
        let overwritten = scrape(&server);
        assert_eq!(
            removed(&overwritten, "extents", "reclaimed"),
            1.0,
            "{overwritten}"
        );
        assert_eq!(removed(&overwritten, "bytes", "reclaimed"), 1000.0);
        expect(
            call(
                &server,
                "blob",
                "DELETE",
                &format!("{container}/item"),
                &[],
                b"",
            ),
            202,
        );
        let deleted = scrape(&server);
        assert_eq!(removed(&deleted, "extents", "reclaimed"), 2.0, "{deleted}");
        assert_eq!(removed(&deleted, "bytes", "reclaimed"), 4000.0);
        assert_eq!(removed(&deleted, "extents", "recovered"), 0.0);
    }
    let content = std::path::Path::new(location).join("content");
    let orphan = format!("extent-{}", uuid::Uuid::new_v4().simple());
    std::fs::write(content.join(orphan), b"12345").unwrap();
    std::fs::write(content.join("incoming-leftover"), b"123").unwrap();

    let server = started(&args);
    let recovered = scrape(&server);
    assert_eq!(
        removed(&recovered, "extents", "recovered"),
        2.0,
        "{recovered}"
    );
    assert_eq!(removed(&recovered, "bytes", "recovered"), 8.0);
    assert_eq!(
        removed(&recovered, "extents", "reclaimed"),
        0.0,
        "counters start with the process"
    );
    assert!(
        std::fs::read_dir(&content).unwrap().next().is_none(),
        "the leftovers are gone"
    );
}

#[test]
fn damaged_content_is_counted_as_a_backend_failure_of_the_namespace_store() {
    let dir = tempfile::tempdir().unwrap();
    let location = dir.path().join("data");
    let location = location.to_str().unwrap();
    let args = ["--location", location, "--services", "blob"];
    {
        let server = started(&args);
        expect(
            call(
                &server,
                "blob",
                "PUT",
                &format!("/{ACCOUNT}/bad?restype=container"),
                &[],
                b"",
            ),
            201,
        );
        let headers = [("x-ms-blob-type", "BlockBlob")];
        expect(
            call(
                &server,
                "blob",
                "PUT",
                &format!("/{ACCOUNT}/bad/item"),
                &headers,
                b"0123456789",
            ),
            201,
        );
    }
    let extent = std::fs::read_dir(std::path::Path::new(location).join("content"))
        .unwrap()
        .map(|entry| entry.unwrap().path())
        .next()
        .unwrap();
    std::fs::OpenOptions::new()
        .write(true)
        .open(extent)
        .unwrap()
        .set_len(4)
        .unwrap();

    let server = started(&args);
    let failures = |text: &str, kind: &str| {
        sample(
            text,
            &format!("azuifer_backend_failures_total{{store=\"namespace\",kind=\"{kind}\"}}"),
        )
    };
    expect(
        call(
            &server,
            "blob",
            "GET",
            &format!("/{ACCOUNT}/bad?restype=container&comp=list"),
            &[],
            b"",
        ),
        200,
    );
    let healthy = scrape(&server);
    assert_eq!(failures(&healthy, "internal"), Some(0.0), "{healthy}");

    let damaged = expect(
        call(
            &server,
            "blob",
            "GET",
            &format!("/{ACCOUNT}/bad/item"),
            &[],
            b"",
        ),
        500,
    );
    assert_eq!(damaged.headers["x-ms-error-code"], "InternalError");
    let text = scrape(&server);
    assert_eq!(failures(&text, "internal"), Some(1.0), "{text}");
    assert_eq!(failures(&text, "database"), Some(0.0));
    assert_eq!(failures(&text, "busy"), Some(0.0));
    assert_eq!(
        sample(
            &text,
            "azuifer_http_requests_total{service=\"blob\",status=\"500\"}"
        ),
        Some(1.0),
        "{text}"
    );
}

#[test]
fn logs_and_runtime_metrics_never_carry_credentials() {
    let dir = tempfile::tempdir().unwrap();
    let log = dir.path().join("secrets.log");
    let key = account_key();
    let server = started(&[
        "--log-file",
        log.to_str().unwrap(),
        "--services",
        "blob,queue",
    ]);
    let client = client();
    for (service, path) in [
        (
            "blob",
            format!(
                "/{ACCOUNT}/{key}?restype=container&sig=SEEDEDSASSIGNATURE&token={key}&sv=2023-11-03&sp=r"
            ),
        ),
        (
            "queue",
            format!("/{ACCOUNT}/{key}/messages?sig=SEEDEDSASSIGNATURE&sas={key}"),
        ),
    ] {
        for authorization in [
            "SharedKey devstoreaccount1:SEEDEDSHAREDKEYSIGNATURE",
            "Bearer SEEDEDBEARERTOKEN",
        ] {
            client
                .get(format!("{}{path}", server.url(service)))
                .header("authorization", authorization)
                .header("x-ms-version", VERSION)
                .send()
                .unwrap();
        }
    }
    expect(
        call(
            &server,
            "queue",
            "PUT",
            &format!("/{ACCOUNT}/redaction"),
            &[],
            b"",
        ),
        201,
    );
    let metrics = scrape(&server);
    assert!(
        metrics.contains("azuifer_queue_messages{account=\"devstoreaccount1\",queue=\"redaction\"")
    );
    drop(server);

    let logs = std::fs::read_to_string(&log).unwrap();
    assert!(
        logs.contains("REDACTED"),
        "the requests were logged:\n{logs}"
    );
    for secret in [
        key.as_str(),
        "SEEDEDSASSIGNATURE",
        "SEEDEDSHAREDKEYSIGNATURE",
        "SEEDEDBEARERTOKEN",
    ] {
        assert!(!logs.contains(secret), "the log leaked `{secret}`:\n{logs}");
        assert!(
            !metrics.contains(secret),
            "the metrics leaked `{secret}`:\n{metrics}"
        );
    }
}

#[test]
fn runtime_metrics_reach_a_configured_otlp_collector_without_secrets() {
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
        &[
            ("AZUIFER_ACCOUNT_KEY", &key),
            ("OTEL_METRIC_EXPORT_INTERVAL", "200"),
        ],
    );
    expect(
        call(
            &server,
            "queue",
            "PUT",
            &format!("/{ACCOUNT}/otlp"),
            &[],
            b"",
        ),
        201,
    );
    expect(
        call(
            &server,
            "queue",
            "POST",
            &format!("/{ACCOUNT}/otlp/messages"),
            &[],
            &message("hello"),
        ),
        201,
    );
    expect(
        call(
            &server,
            "blob",
            "PUT",
            &format!("/{ACCOUNT}/otlp?restype=container"),
            &[],
            b"",
        ),
        201,
    );
    // Gauges are read at each collection, so wait for one that saw the queue.
    let deadline = Instant::now() + Duration::from_secs(10);
    let metrics = loop {
        let metrics = payloads(&collector, "/v1/metrics").concat();
        if contains(&metrics, "visible") || Instant::now() > deadline {
            break metrics;
        }
        std::thread::sleep(Duration::from_millis(100));
    };
    drop(server);
    for name in [
        "azuifer.queue.messages",
        "azuifer.leases.active",
        "azuifer.store.lock.acquisitions",
        "azuifer.store.lock.contended",
        "azuifer.store.lock.wait",
        "azuifer.gc.extents",
        "azuifer.gc.bytes",
        "azuifer.backend.failures",
    ] {
        assert!(
            contains(&metrics, name),
            "no `{name}` in the exported metrics"
        );
    }
    assert!(contains(&metrics, "visible") && contains(&metrics, "otlp"));
    assert!(!contains(&metrics, &key));
}
