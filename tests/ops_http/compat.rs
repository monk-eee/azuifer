//! Named compatibility mode (ADR-0038): what `lenient` ignores, what it never does, and
//! what it logs.

use super::*;
use hmac::{Hmac, Mac as _};
use std::collections::BTreeMap;

const ACCOUNT: &str = "devstoreaccount1";
const VERSION: &str = "2023-11-03";

struct Probe {
    label: &'static str,
    method: &'static str,
    service: &'static str,
    target: &'static str,
    headers: &'static [(&'static str, &'static str)],
}

/// A request signed with the account's Shared Key: headers named in `extra` are signed too.
fn signed(
    key: &str,
    method: &str,
    path: &str,
    query: &[(&str, &str)],
    extra: &[(&str, &str)],
) -> BTreeMap<String, String> {
    let mut headers: BTreeMap<String, String> = BTreeMap::from([
        (
            "x-ms-date".into(),
            httpdate::fmt_http_date(std::time::SystemTime::now()),
        ),
        ("x-ms-version".into(), VERSION.into()),
    ]);
    for (name, value) in extra {
        headers.insert((*name).into(), (*value).into());
    }
    let canonical_headers: String = headers
        .iter()
        .filter(|(name, _)| name.starts_with("x-ms-"))
        .map(|(name, value)| format!("{name}:{value}\n"))
        .collect();
    let canonical_query: BTreeMap<_, _> = query.iter().copied().collect();
    let canonical_query: String = canonical_query
        .iter()
        .map(|(name, value)| format!("\n{name}:{value}"))
        .collect();
    let message = format!(
        "{method}\n\n\n\n\n\n\n\n\n\n\n\n{canonical_headers}/{ACCOUNT}{path}{canonical_query}"
    );
    let mut mac = Hmac::<sha2::Sha256>::new_from_slice(&STANDARD.decode(key).unwrap()).unwrap();
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

fn send(
    server: &Server,
    key: &str,
    service: &str,
    method: &str,
    target: &str,
    extra: &[(&str, &str)],
) -> reqwest::blocking::Response {
    let (path, query) = target.split_once('?').unwrap_or((target, ""));
    let pairs: Vec<(&str, &str)> = query
        .split('&')
        .filter(|pair| !pair.is_empty())
        .filter_map(|pair| pair.split_once('='))
        .collect();
    let headers = signed(key, method, path, &pairs, extra);
    let mut request = client().request(
        reqwest::Method::from_bytes(method.as_bytes()).unwrap(),
        format!("{}{target}", server.url(service)),
    );
    for (name, value) in headers {
        request = request.header(name, value);
    }
    if method == "PUT" {
        request = request.body(Vec::new());
    }
    request.send().unwrap()
}

fn request_id(response: &reqwest::blocking::Response) -> String {
    response.headers()["x-ms-request-id"]
        .to_str()
        .unwrap()
        .to_owned()
}

/// Requests whose unknown name the mode must never excuse, because it is not a name `lenient`
/// can list, or because something else about the request is wrong.
const NEVER_RELAXED: &[Probe] = &[
    Probe {
        label: "encryption scope",
        method: "GET",
        service: "blob",
        target: "/devstoreaccount1?comp=list",
        headers: &[("x-ms-encryption-scope", "scope")],
    },
    Probe {
        label: "customer-provided key",
        method: "GET",
        service: "blob",
        target: "/devstoreaccount1?comp=list",
        headers: &[("x-ms-encryption-key", "AAAA")],
    },
    Probe {
        label: "blob tags",
        method: "GET",
        service: "blob",
        target: "/devstoreaccount1?comp=list",
        headers: &[("x-ms-tags", "a=b")],
    },
    Probe {
        label: "checksum",
        method: "GET",
        service: "blob",
        target: "/devstoreaccount1?comp=list",
        headers: &[("content-md5", "AAAAAAAAAAAAAAAAAAAAAA==")],
    },
    Probe {
        label: "CRC64",
        method: "GET",
        service: "blob",
        target: "/devstoreaccount1?comp=list",
        headers: &[("x-ms-content-crc64", "AAAAAAAAAAA=")],
    },
    Probe {
        label: "conditional header",
        method: "GET",
        service: "blob",
        target: "/devstoreaccount1?comp=list",
        headers: &[("if-match", "*")],
    },
    Probe {
        label: "lease",
        method: "GET",
        service: "blob",
        target: "/devstoreaccount1?comp=list",
        headers: &[("x-ms-lease-id", "id")],
    },
    Probe {
        label: "immutability",
        method: "GET",
        service: "blob",
        target: "/devstoreaccount1?comp=list",
        headers: &[("x-ms-immutability-policy-mode", "Unlocked")],
    },
    Probe {
        label: "copy source",
        method: "GET",
        service: "blob",
        target: "/devstoreaccount1?comp=list",
        headers: &[("x-ms-copy-source", "http://example.test/a")],
    },
    Probe {
        label: "header nobody listed",
        method: "GET",
        service: "blob",
        target: "/devstoreaccount1?comp=list",
        headers: &[("x-ms-unlisted-hint", "1")],
    },
    Probe {
        label: "a query parameter of the protocol",
        method: "GET",
        service: "blob",
        target: "/devstoreaccount1?comp=list&snapshot=2020-01-01T00:00:00.0000000Z",
        headers: &[],
    },
    Probe {
        label: "query parameter nobody listed",
        method: "GET",
        service: "blob",
        target: "/devstoreaccount1?comp=list&unlisted=1",
        headers: &[],
    },
    Probe {
        label: "a recognized unsupported operation",
        method: "PUT",
        service: "blob",
        target: "/devstoreaccount1/container?restype=container&comp=rename",
        headers: &[("x-ms-useragent", "azsdk-js")],
    },
    Probe {
        label: "DFS encryption scope",
        method: "GET",
        service: "dfs",
        target: "/devstoreaccount1?resource=account",
        headers: &[("x-ms-encryption-scope", "scope")],
    },
    Probe {
        label: "DFS header nobody listed",
        method: "GET",
        service: "dfs",
        target: "/devstoreaccount1?resource=account",
        headers: &[("x-ms-unlisted-hint", "1")],
    },
];

fn statuses(server: &Server, key: &str) -> Vec<(&'static str, u16)> {
    NEVER_RELAXED
        .iter()
        .map(|probe| {
            let response = send(
                server,
                key,
                probe.service,
                probe.method,
                probe.target,
                probe.headers,
            );
            (probe.label, response.status().as_u16())
        })
        .collect()
}

fn log_records(path: &std::path::Path) -> Vec<serde_json::Value> {
    std::fs::read_to_string(path)
        .unwrap()
        .lines()
        .filter_map(|line| serde_json::from_str(line).ok())
        .collect()
}

fn relaxations(records: &[serde_json::Value]) -> Vec<&serde_json::Value> {
    records
        .iter()
        .filter(|record| {
            record["fields"]["message"]
                .as_str()
                .is_some_and(|text| text.contains("compatibility mode ignored"))
        })
        .collect()
}

#[test]
fn strict_mode_refuses_unknown_names_and_reports_itself() {
    let key = account_key();
    let server = Server::start(
        &["--hns-accounts", ACCOUNT],
        &[("AZUIFER_ACCOUNT_KEY", &key)],
    );
    let browser = send(
        &server,
        &key,
        "blob",
        "GET",
        "/devstoreaccount1?comp=list",
        &[("x-ms-useragent", "azsdk-js")],
    );
    assert_eq!(browser.status(), 501, "{}", browser.text().unwrap());
    let unknown_query = send(
        &server,
        &key,
        "blob",
        "GET",
        "/devstoreaccount1?comp=list&cachebust=7",
        &[],
    );
    assert_eq!(unknown_query.status(), 501);
    let plain = send(
        &server,
        &key,
        "blob",
        "GET",
        "/devstoreaccount1?comp=list",
        &[],
    );
    assert_eq!(plain.status(), 200, "{}", plain.text().unwrap());

    let status = status_json(&client(), &server);
    assert_eq!(status["compatibility"]["mode"], "strict");
    assert_eq!(
        status["compatibility"]["ignored_headers"],
        serde_json::json!([])
    );
    assert_eq!(
        status["compatibility"]["ignored_query_parameters"],
        serde_json::json!([])
    );
}

#[test]
fn lenient_mode_ignores_listed_names_logs_them_by_name_and_relaxes_nothing_else() {
    let key = account_key();
    let dir = tempfile::tempdir().unwrap();
    let log = dir.path().join("compat.log");
    let strict = Server::start(
        &["--hns-accounts", ACCOUNT],
        &[("AZUIFER_ACCOUNT_KEY", &key)],
    );
    let strict_statuses = statuses(&strict, &key);
    drop(strict);

    let server = Server::start(
        &[
            "--hns-accounts",
            ACCOUNT,
            "--compatibility-mode",
            "lenient",
            "--compatibility-allow",
            "x-ms-trace-hint, cachebust",
            "--log-format",
            "json",
            "--log-file",
            log.to_str().unwrap(),
        ],
        &[("AZUIFER_ACCOUNT_KEY", &key)],
    );
    let ignored = send(
        &server,
        &key,
        "blob",
        "GET",
        "/devstoreaccount1?comp=list&cachebust=SECRET-QUERY-VALUE",
        &[
            ("x-ms-useragent", "SECRET-AGENT-VALUE"),
            ("x-ms-trace-hint", "SECRET-HINT-VALUE"),
        ],
    );
    assert_eq!(ignored.status(), 200, "{}", ignored.text().unwrap());
    let blob_id = request_id(&ignored);
    let dfs = send(
        &server,
        &key,
        "dfs",
        "GET",
        "/devstoreaccount1?resource=account",
        &[("x-ms-useragent", "SECRET-AGENT-VALUE")],
    );
    assert_eq!(dfs.status(), 200, "{}", dfs.text().unwrap());
    let dfs_id = request_id(&dfs);

    let lenient_statuses = statuses(&server, &key);
    assert_eq!(
        lenient_statuses, strict_statuses,
        "lenient answers every protected probe exactly as strict does"
    );
    assert!(
        lenient_statuses.iter().all(|(_, status)| *status >= 400),
        "{lenient_statuses:?}"
    );
    for (name, extra) in [
        ("an invalid SAS", None),
        (
            "a wrong Shared Key",
            Some("SharedKey devstoreaccount1:AAAA"),
        ),
    ] {
        let mut request = client().get(format!(
            "{}/devstoreaccount1?comp=list&sv=2023-11-03&ss=b&srt=sco&sp=rl&se=2099-01-01T00%3A00%3A00Z&sig=AAAA",
            server.url("blob")
        ));
        request = request
            .header("x-ms-version", VERSION)
            .header("x-ms-useragent", "azsdk-js");
        if let Some(authorization) = extra {
            request = client()
                .get(format!("{}/devstoreaccount1?comp=list", server.url("blob")))
                .header("x-ms-version", VERSION)
                .header(
                    "x-ms-date",
                    httpdate::fmt_http_date(std::time::SystemTime::now()),
                )
                .header("x-ms-useragent", "azsdk-js")
                .header("authorization", authorization);
        }
        assert_eq!(request.send().unwrap().status(), 403, "{name}");
    }
    let status = status_json(&client(), &server);
    assert_eq!(status["compatibility"]["mode"], "lenient");
    assert_eq!(
        status["compatibility"]["ignored_headers"],
        serde_json::json!(["x-ms-trace-hint", "x-ms-useragent"])
    );
    assert_eq!(
        status["compatibility"]["ignored_query_parameters"],
        serde_json::json!(["cachebust"])
    );
    drop(server);

    let text = std::fs::read_to_string(&log).unwrap();
    for secret in [
        "SECRET-QUERY-VALUE",
        "SECRET-AGENT-VALUE",
        "SECRET-HINT-VALUE",
    ] {
        assert!(!text.contains(secret), "a value reached the log: {secret}");
    }
    let records = log_records(&log);
    let mut seen: Vec<(String, String, String, String)> = relaxations(&records)
        .iter()
        .map(|record| {
            let field = |name: &str| record["fields"][name].as_str().unwrap().to_owned();
            assert_eq!(record["level"], "WARN");
            assert_eq!(record["fields"]["compatibility_mode"], "lenient");
            (
                field("service"),
                field("kind"),
                field("name"),
                field("request_id"),
            )
        })
        .collect();
    seen.sort();
    let mut expected = vec![
        ("blob", "header", "x-ms-trace-hint", blob_id.as_str()),
        ("blob", "header", "x-ms-useragent", blob_id.as_str()),
        ("blob", "query", "cachebust", blob_id.as_str()),
        ("dfs", "header", "x-ms-useragent", dfs_id.as_str()),
    ]
    .into_iter()
    .map(|(a, b, c, d)| (a.to_owned(), b.to_owned(), c.to_owned(), d.to_owned()))
    .collect::<Vec<_>>();
    expected.sort();
    assert_eq!(
        seen, expected,
        "each ignored name is logged once with its service and request ID, and nothing else is"
    );
}

#[test]
fn queue_table_and_files_ignore_unknown_names_in_both_modes() {
    let key = account_key();
    for args in [&[][..], &["--compatibility-mode", "lenient"][..]] {
        let dir = tempfile::tempdir().unwrap();
        let log = dir.path().join("other.log");
        let mut all = args.to_vec();
        all.extend(["--log-format", "json", "--log-file", log.to_str().unwrap()]);
        let server = Server::start(&all, &[("AZUIFER_ACCOUNT_KEY", &key)]);
        for (service, target) in [
            ("queue", "/devstoreaccount1?comp=list&unknown-name=1"),
            ("file", "/devstoreaccount1?comp=list&unknown-name=1"),
        ] {
            let response = send(
                &server,
                &key,
                service,
                "GET",
                target,
                &[("x-ms-unknown-name", "1")],
            );
            assert_eq!(
                response.status(),
                200,
                "{service} {args:?}: {}",
                response.text().unwrap()
            );
        }
        let date = httpdate::fmt_http_date(std::time::SystemTime::now());
        let message = format!("{date}\n/{ACCOUNT}/{ACCOUNT}/Tables");
        let mut mac =
            Hmac::<sha2::Sha256>::new_from_slice(&STANDARD.decode(&key).unwrap()).unwrap();
        mac.update(message.as_bytes());
        let table = client()
            .get(format!(
                "{}/{ACCOUNT}/Tables?unknown-name=1",
                server.url("table")
            ))
            .header("x-ms-date", &date)
            .header("x-ms-version", VERSION)
            .header("x-ms-unknown-name", "1")
            .header("accept", "application/json;odata=nometadata")
            .header(
                "authorization",
                format!(
                    "SharedKeyLite {ACCOUNT}:{}",
                    STANDARD.encode(mac.finalize().into_bytes())
                ),
            )
            .send()
            .unwrap();
        assert_eq!(
            table.status(),
            200,
            "table {args:?}: {}",
            table.text().unwrap()
        );
        drop(server);
        assert!(
            relaxations(&log_records(&log)).is_empty(),
            "{args:?}: these services have nothing for the mode to relax"
        );
    }
}
