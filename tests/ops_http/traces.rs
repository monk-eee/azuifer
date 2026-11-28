use super::{Server, account_key, client, collector, contains, payloads, shared_key_get};
use base64::{
    Engine as _,
    engine::general_purpose::{STANDARD, URL_SAFE_NO_PAD},
};
use hmac::{Hmac, KeyInit as _, Mac as _};
use reqwest::{Method, blocking::RequestBuilder};
use std::{
    collections::BTreeSet,
    time::{SystemTime, UNIX_EPOCH},
};

const ACCOUNT: &str = "devstoreaccount1";
const VERSION: &str = "2023-11-03";

// Read the OTLP trace envelope, span identity and string attributes without adding
// a protobuf dependency to the test workspace.
enum Wire<'a> {
    Number(u64),
    Bytes(&'a [u8]),
    Fixed,
}

fn varint(bytes: &mut &[u8]) -> u64 {
    let mut value = 0;
    for shift in (0..64).step_by(7) {
        let (&first, rest) = bytes.split_first().expect("complete OTLP varint");
        *bytes = rest;
        value |= u64::from(first & 0x7f) << shift;
        if first & 0x80 == 0 {
            return value;
        }
    }
    panic!("invalid OTLP varint");
}

fn fields(mut bytes: &[u8]) -> impl Iterator<Item = (u64, Wire<'_>)> {
    std::iter::from_fn(move || {
        if bytes.is_empty() {
            return None;
        }
        let tag = varint(&mut bytes);
        let field = match tag & 7 {
            0 => Wire::Number(varint(&mut bytes)),
            1 => {
                bytes = &bytes[8..];
                Wire::Fixed
            }
            2 => {
                let len = usize::try_from(varint(&mut bytes)).unwrap();
                let (value, rest) = bytes.split_at(len);
                bytes = rest;
                Wire::Bytes(value)
            }
            5 => {
                bytes = &bytes[4..];
                Wire::Fixed
            }
            kind => panic!("unexpected OTLP wire type {kind}"),
        };
        Some((tag >> 3, field))
    })
}

fn messages(bytes: &[u8], tag: u64) -> impl Iterator<Item = &[u8]> {
    fields(bytes).filter_map(move |(number, wire)| match wire {
        Wire::Bytes(value) if number == tag => Some(value),
        _ => None,
    })
}

fn text(bytes: &[u8], tag: u64) -> Option<&str> {
    messages(bytes, tag)
        .next()
        .map(|value| std::str::from_utf8(value).unwrap())
}

struct Span<'a> {
    trace_id: &'a [u8],
    span_id: &'a [u8],
    parent: &'a [u8],
    name: &'a str,
    kind: u64,
    wire: &'a [u8],
}

impl<'a> Span<'a> {
    fn decode(wire: &'a [u8]) -> Self {
        let kind = fields(wire).find_map(|(tag, value)| match value {
            Wire::Number(kind) if tag == 6 => Some(kind),
            _ => None,
        });
        Self {
            trace_id: messages(wire, 1).next().expect("trace ID"),
            span_id: messages(wire, 2).next().expect("span ID"),
            parent: messages(wire, 4).next().unwrap_or_default(),
            name: text(wire, 5).expect("span name"),
            kind: kind.expect("span kind"),
            wire,
        }
    }

    fn attribute(&self, name: &str) -> Option<&'a str> {
        let field = messages(self.wire, 9).find(|kv| text(kv, 1) == Some(name))?;
        text(messages(field, 2).next()?, 1)
    }
}

fn request_id(request: RequestBuilder, status: u16) -> String {
    let response = request.send().expect("data plane response");
    assert_eq!(response.status().as_u16(), status, "unexpected response");
    response.headers()["x-ms-request-id"]
        .to_str()
        .unwrap()
        .to_owned()
}

fn bearer() -> String {
    let expiry = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs()
        + 3600;
    let claims = serde_json::json!({
        "iss": "https://sts.windows.net/11111111-2222-3333-4444-555555555555/",
        "aud": "https://storage.azure.com",
        "exp": expiry,
        "oid": "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee",
    });
    format!(
        "{}.{}.",
        URL_SAFE_NO_PAD.encode(br#"{"alg":"none"}"#),
        URL_SAFE_NO_PAD.encode(claims.to_string()),
    )
}

fn source_signature(key: &str) -> (String, String) {
    const EXPIRY: &str = "2100-01-01T00:00:00Z";
    let mut mac = Hmac::<sha2::Sha256>::new_from_slice(&STANDARD.decode(key).unwrap()).unwrap();
    mac.update(format!("{ACCOUNT}\nr\nbf\no\n\n{EXPIRY}\n\n\n{VERSION}\n\n").as_bytes());
    let signature = STANDARD.encode(mac.finalize().into_bytes());
    let encoded =
        percent_encoding::utf8_percent_encode(&signature, percent_encoding::NON_ALPHANUMERIC)
            .to_string();
    (
        signature,
        format!("sv={VERSION}&ss=bf&srt=o&sp=r&se={EXPIRY}&sig={encoded}"),
    )
}

#[test]
fn all_services_export_correlated_request_phases_and_copy_spans() {
    let collector = collector();
    let endpoint = format!("http://{}", collector.address);
    let key = account_key();
    let server = Server::start(
        &[
            "--otlp-endpoint",
            &endpoint,
            "--otlp-protocol",
            "http",
            "--oauth",
            "basic",
            "--hns-accounts",
            ACCOUNT,
        ],
        &[("AZUIFER_ACCOUNT_KEY", &key)],
    );
    let client = client();
    let bearer = bearer();
    let url = |service, path| format!("{}/{ACCOUNT}{path}", server.url(service));
    let send = |method, service, path| {
        client
            .request(method, url(service, path))
            .header("x-ms-version", VERSION)
            .bearer_auth(&bearer)
    };
    let account_path = format!("/{ACCOUNT}");
    let (date, shared) = shared_key_get(&key, &account_path, "comp:list");
    let blob_list = request_id(
        client
            .get(url("blob", "?comp=list"))
            .header("x-ms-version", VERSION)
            .header("x-ms-date", date)
            .header("authorization", &shared),
        200,
    );
    let mut cases = vec![("blob", blob_list, None)];
    for (service, path) in [
        ("dfs", "?resource=account"),
        ("file", "?comp=list"),
        ("queue", "?comp=list"),
        ("table", "/Tables"),
    ] {
        cases.push((
            service,
            request_id(send(Method::GET, service, path), 200),
            None,
        ));
    }
    let source = "/traces/source";
    let destination = "/traces/copy";
    request_id(send(Method::PUT, "blob", "/traces?restype=container"), 201);
    request_id(
        send(Method::PUT, "blob", source)
            .header("x-ms-blob-type", "BlockBlob")
            .body("blob bytes"),
        201,
    );
    request_id(send(Method::PUT, "file", "/traces?restype=share"), 201);
    request_id(
        send(Method::PUT, "file", source)
            .header("x-ms-type", "file")
            .header("x-ms-content-length", 0),
        201,
    );
    let (signature, sas) = source_signature(&key);
    for (service, operation) in [("blob", "Copy Blob"), ("file", "Copy File")] {
        let id = request_id(
            send(Method::PUT, service, destination)
                .header(
                    "x-ms-copy-source",
                    format!("{}?{sas}", url(service, source)),
                )
                .header("x-ms-client-request-id", format!("copy-identity {key}")),
            202,
        );
        cases.push((service, id, Some(operation)));
    }
    drop(server);

    let payloads = payloads(&collector, "/v1/traces");
    let spans: Vec<_> = payloads
        .iter()
        .flat_map(|payload| messages(payload, 1))
        .flat_map(|resource| messages(resource, 2))
        .flat_map(|scope| messages(scope, 2))
        .map(Span::decode)
        .collect();
    let mut trace_ids = BTreeSet::new();
    for (service, request_id, copy) in cases {
        let servers: Vec<_> = spans
            .iter()
            .filter(|span| span.attribute("azuifer.request_id") == Some(request_id.as_str()))
            .collect();
        assert_eq!(servers.len(), 1, "{service} request {request_id}");
        let root = servers[0];
        assert_eq!(root.kind, 2, "{service} request is an OTLP server span");
        assert!(root.parent.is_empty());
        assert_eq!(root.attribute("azuifer.service"), Some(service));
        assert!(root.name.starts_with(&format!("{service} ")));
        assert_eq!(root.trace_id.len(), 16);
        assert_eq!(root.span_id.len(), 8);
        assert!(
            trace_ids.insert(root.trace_id),
            "{service} reused a trace ID"
        );

        let mut children: Vec<_> = spans
            .iter()
            .filter(|span| span.trace_id == root.trace_id && span.span_id != root.span_id)
            .collect();
        children.sort_unstable_by_key(|span| span.name);
        let expected = if copy.is_some() {
            &["authenticate", "copy", "storage"][..]
        } else {
            &["authenticate", "storage"][..]
        };
        assert_eq!(
            children.iter().map(|span| span.name).collect::<Vec<_>>(),
            expected,
            "{service} request {request_id}"
        );
        let mut ids = BTreeSet::from([root.span_id]);
        for child in children {
            assert_eq!(child.parent, root.span_id, "{service} {}", child.name);
            assert_eq!(child.kind, 1);
            assert_eq!(child.span_id.len(), 8);
            assert!(ids.insert(child.span_id));
            if child.name == "copy" {
                assert_eq!(child.attribute("azuifer.copy.operation"), copy);
                assert_eq!(child.attribute("azuifer.copy.source_kind"), Some("local"));
                assert_eq!(
                    root.attribute("azuifer.client_request_id"),
                    Some("copy-identity REDACTED")
                );
            }
        }
    }
    let raw = payloads.concat();
    for (name, value) in [
        ("account key", key.as_str()),
        ("SAS signature", signature.as_str()),
        ("encoded SAS signature", sas.rsplit_once("sig=").unwrap().1),
        ("source SAS query", sas.as_str()),
        ("Shared Key signature", shared.split_once(':').unwrap().1),
        ("Bearer token", bearer.as_str()),
    ] {
        assert!(!contains(&raw, value), "exported spans leaked the {name}");
    }
}
