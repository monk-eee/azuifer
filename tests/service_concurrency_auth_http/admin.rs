use super::{CLIENTS, KEY, Method, STANDARD, Server, race};
use base64::Engine as _;
use serde_json::json;
use std::time::Instant;

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
