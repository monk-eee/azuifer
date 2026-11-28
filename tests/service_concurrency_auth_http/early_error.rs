use super::{ACCOUNT, KEY, Method, Server};
use base64::{Engine as _, engine::general_purpose::STANDARD};
use hmac::{Hmac, KeyInit as _, Mac as _};
use reqwest::{
    Url,
    blocking::{Body, Client},
};
use sha2::Sha256;
use std::{
    collections::BTreeMap,
    io::{BufRead as _, BufReader, Cursor, Read as _, Write as _},
    net::TcpStream,
    process::{Child, Command, Stdio},
    sync::mpsc,
    thread,
    time::{Duration, Instant, SystemTime},
};

const PAYLOAD_BYTES: usize = 512 * 1024;

struct AllServices {
    child: Child,
    urls: BTreeMap<String, String>,
    client: Client,
}

impl AllServices {
    fn start() -> Self {
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
            .env("TOKIO_WORKER_THREADS", "2")
            .args([
                "serve",
                "--in-memory",
                "--port",
                "0",
                "--admin-port",
                "0",
                "--skip-api-version-check",
                "--hns-accounts",
                ACCOUNT,
                "--services",
                "blob,dfs,file,queue,table",
                "--shutdown-on-stdin-eof",
            ])
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .spawn()
            .expect("start Azuifer");
        let (send, receive) = mpsc::channel();
        let stdout = child.stdout.take().expect("piped startup addresses");
        thread::spawn(move || {
            let mut lines = BufReader::new(stdout).lines();
            let _ = send.send(lines.by_ref().take(6).collect::<std::io::Result<Vec<_>>>());
            lines.for_each(drop);
        });
        let lines = receive
            .recv_timeout(Duration::from_secs(20))
            .expect("running emulator")
            .expect("read listener URLs");
        let mut urls = BTreeMap::new();
        for line in lines {
            if let Some((key, value)) = line.split_once("_url=") {
                urls.insert(key.to_owned(), value.to_owned());
            }
        }
        let client = Client::builder()
            .no_proxy()
            .timeout(Duration::from_secs(15))
            .build()
            .unwrap();
        let admin = urls.get("admin").expect("admin listener");
        let ready = client
            .get(format!("{admin}/readyz"))
            .send()
            .expect("readyz");
        assert_eq!(ready.status(), 200);
        Self {
            child,
            urls,
            client,
        }
    }

    fn url(&self, service: &str, path: &str) -> Url {
        let base = self.urls.get(service).expect("service listener");
        Url::parse(&format!("{base}/{ACCOUNT}{path}")).unwrap()
    }

    fn signed_headers(
        &self,
        service: &str,
        method: &str,
        url: &Url,
        extra: &[(&str, &str)],
        content_length: Option<usize>,
    ) -> BTreeMap<String, String> {
        let version = if service == "file" {
            "2025-07-05"
        } else {
            "2023-11-03"
        };
        let date = httpdate::fmt_http_date(SystemTime::now());
        let mut headers = BTreeMap::from([
            ("x-ms-date".to_owned(), date.clone()),
            ("x-ms-version".to_owned(), version.to_owned()),
        ]);
        if let Some(len) = content_length
            && len > 0
        {
            headers.insert("content-length".to_owned(), len.to_string());
        }
        for (name, value) in extra {
            headers.insert(name.to_ascii_lowercase(), (*value).to_owned());
        }
        let value = |name: &str| headers.get(name).map(String::as_str).unwrap_or("");
        let message = if service == "table" {
            format!(
                "{method}\n\n{}\n{date}\n/{ACCOUNT}{}",
                value("content-type"),
                url.path()
            )
        } else {
            let mut canonical_headers = String::new();
            for (name, value) in &headers {
                if name.starts_with("x-ms-") {
                    canonical_headers.push_str(&format!("{name}:{value}\n"));
                }
            }
            let mut params: BTreeMap<String, Vec<String>> = BTreeMap::new();
            for (key, value) in url.query_pairs() {
                params
                    .entry(key.to_ascii_lowercase())
                    .or_default()
                    .push(value.into_owned());
            }
            let mut canonical_resource = format!("/{ACCOUNT}{}", url.path());
            for (key, mut values) in params {
                values.sort();
                canonical_resource.push_str(&format!("\n{key}:{}", values.join(",")));
            }
            format!(
                "{method}\n{}\n{}\n{}\n{}\n{}\n{}\n{}\n{}\n{}\n{}\n{}\n{canonical_headers}{canonical_resource}",
                value("content-encoding"),
                value("content-language"),
                value("content-length"),
                value("content-md5"),
                value("content-type"),
                value("date"),
                value("if-modified-since"),
                value("if-match"),
                value("if-none-match"),
                value("if-unmodified-since"),
                value("range"),
            )
        };
        let mut mac = Hmac::<Sha256>::new_from_slice(&KEY).unwrap();
        mac.update(message.as_bytes());
        let signature = STANDARD.encode(mac.finalize().into_bytes());
        headers.insert(
            "authorization".to_owned(),
            format!("SharedKey {ACCOUNT}:{signature}"),
        );
        headers
    }

    fn send_sized(
        &self,
        service: &str,
        method: Method,
        path: &str,
        extra: &[(&str, &str)],
        payload: Vec<u8>,
    ) -> (u16, String) {
        let url = self.url(service, path);
        let len = payload.len();
        let headers = self.signed_headers(service, method.as_str(), &url, extra, Some(len));
        let mut request = self.client.request(method, url);
        for (name, value) in headers {
            if name != "content-length" {
                request = request.header(name, value);
            }
        }
        let response = request
            .body(Body::sized(Cursor::new(payload), len as u64))
            .send()
            .unwrap_or_else(|error| {
                panic!("{service} early-error request failed at transport layer: {error:?}")
            });
        let status = response.status().as_u16();
        let code = response
            .headers()
            .get("x-ms-error-code")
            .and_then(|value| value.to_str().ok())
            .map(str::to_owned);
        let body = response
            .text()
            .unwrap_or_else(|error| panic!("{service} early-error body read failed: {error:?}"));
        let error_code = code.unwrap_or_else(|| {
            serde_json::from_str::<serde_json::Value>(&body)
                .ok()
                .and_then(|json| json["odata.error"]["code"].as_str().map(str::to_owned))
                .unwrap_or_default()
        });
        (status, error_code)
    }

    fn send_ok(&self, service: &str, path: &str) {
        let url = self.url(service, path);
        let headers = self.signed_headers(service, "GET", &url, &[], Some(0));
        let mut request = self.client.get(url);
        for (name, value) in headers {
            request = request.header(name, value);
        }
        let response = request
            .send()
            .unwrap_or_else(|error| panic!("{service} follow-up request failed: {error:?}"));
        assert_eq!(
            response.status(),
            200,
            "{service} follow-up response: {}",
            response.text().unwrap_or_default()
        );
    }
}

impl Drop for AllServices {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

fn read_http_response(stream: &mut TcpStream) -> (u16, BTreeMap<String, String>, Vec<u8>) {
    let mut raw = Vec::new();
    let mut byte = [0u8; 1];
    while !raw.ends_with(b"\r\n\r\n") {
        let read = stream.read(&mut byte).expect("read response header byte");
        assert_ne!(
            read,
            0,
            "connection closed before headers completed: {:?}",
            String::from_utf8_lossy(&raw)
        );
        raw.push(byte[0]);
    }
    let header_text = String::from_utf8(raw).expect("utf-8 HTTP headers");
    let mut lines = header_text.split("\r\n");
    let status_line = lines.next().expect("status line");
    let status: u16 = status_line
        .split_whitespace()
        .nth(1)
        .and_then(|code| code.parse().ok())
        .unwrap_or_else(|| panic!("malformed status line: {status_line:?}"));
    let mut headers = BTreeMap::new();
    for line in lines {
        if let Some((name, value)) = line.split_once(':') {
            headers.insert(name.trim().to_ascii_lowercase(), value.trim().to_owned());
        }
    }
    let body = if let Some(len) = headers
        .get("content-length")
        .and_then(|value| value.parse::<usize>().ok())
    {
        let mut buf = vec![0u8; len];
        stream.read_exact(&mut buf).expect("read response body");
        buf
    } else if headers
        .get("transfer-encoding")
        .is_some_and(|value| value.eq_ignore_ascii_case("chunked"))
    {
        let mut out = Vec::new();
        loop {
            let mut size_line = Vec::new();
            while !size_line.ends_with(b"\r\n") {
                stream.read_exact(&mut byte).expect("chunk size byte");
                size_line.push(byte[0]);
            }
            let size_hex = std::str::from_utf8(&size_line)
                .expect("utf-8 chunk size")
                .trim();
            let size = usize::from_str_radix(size_hex, 16).expect("hex chunk size");
            if size == 0 {
                let mut trailer = [0u8; 2];
                stream.read_exact(&mut trailer).expect("chunk terminator");
                break;
            }
            let start = out.len();
            out.resize(start + size, 0);
            stream.read_exact(&mut out[start..]).expect("chunk bytes");
            let mut crlf = [0u8; 2];
            stream.read_exact(&mut crlf).expect("chunk crlf");
        }
        out
    } else {
        let mut buf = Vec::new();
        stream.read_to_end(&mut buf).expect("read body to EOF");
        buf
    };
    (status, headers, body)
}

#[test]
fn early_error_responses_with_bodies_do_not_reset_connections_across_all_services() {
    let server = AllServices::start();
    let payload = vec![b'x'; PAYLOAD_BYTES];

    // Prepare a DFS filesystem + file so chunked Append Data hits 411 early without reading body.
    let fs_url = server.url("dfs", "/lake?resource=filesystem");
    let fs_headers = server.signed_headers("dfs", "PUT", &fs_url, &[], Some(0));
    let mut fs_req = server.client.put(fs_url);
    for (name, value) in fs_headers {
        fs_req = fs_req.header(name, value);
    }
    assert_eq!(fs_req.send().unwrap().status(), 201);
    let file_url = server.url("dfs", "/lake/f.bin?resource=file");
    let file_headers = server.signed_headers("dfs", "PUT", &file_url, &[], Some(0));
    let mut file_req = server.client.put(file_url);
    for (name, value) in file_headers {
        file_req = file_req.header(name, value);
    }
    assert_eq!(file_req.send().unwrap().status(), 201);

    struct EarlyErrorCase<'a> {
        service: &'a str,
        method: Method,
        bad_path: &'a str,
        extra: &'a [(&'a str, &'a str)],
        ok_path: &'a str,
        expected_status: u16,
        expected_code: &'a str,
    }

    let cases = [
        EarlyErrorCase {
            service: "blob",
            method: Method::PUT,
            bad_path: "/Not_Valid/blob",
            extra: &[("x-ms-blob-type", "BlockBlob")],
            ok_path: "/?comp=list",
            expected_status: 400,
            expected_code: "InvalidResourceName",
        },
        EarlyErrorCase {
            service: "dfs",
            method: Method::PATCH,
            bad_path: "/Not_Valid/file?action=append&position=0",
            extra: &[],
            ok_path: "/?resource=account",
            expected_status: 400,
            expected_code: "InvalidResourceName",
        },
        EarlyErrorCase {
            service: "file",
            method: Method::PUT,
            bad_path: "/Not_Valid/file?comp=range",
            extra: &[("x-ms-write", "update"), ("x-ms-range", "bytes=0-524287")],
            ok_path: "/?comp=list",
            expected_status: 400,
            expected_code: "InvalidResourceName",
        },
        EarlyErrorCase {
            service: "queue",
            method: Method::POST,
            bad_path: "/Not_Valid/messages",
            extra: &[],
            ok_path: "/?comp=list",
            expected_status: 400,
            expected_code: "InvalidResourceName",
        },
        EarlyErrorCase {
            service: "table",
            method: Method::POST,
            bad_path: "/Not_Valid",
            extra: &[
                ("content-type", "application/json"),
                ("accept", "application/json;odata=minimalmetadata"),
            ],
            ok_path: "/Tables",
            expected_status: 400,
            expected_code: "InvalidResourceName",
        },
    ];

    for round in 0..4 {
        for case in &cases {
            let (status, code) = server.send_sized(
                case.service,
                case.method.clone(),
                case.bad_path,
                case.extra,
                payload.clone(),
            );
            assert_eq!(
                (status, code.as_str()),
                (case.expected_status, case.expected_code),
                "round {round} on {}",
                case.service
            );
            // A subsequent request on the pooled client must also succeed cleanly.
            server.send_ok(case.service, case.ok_path);
        }

        // Streaming chunked DFS Append Data (exact shape of the intermittent 411 CI failure).
        let url = server.url("dfs", "/lake/f.bin?action=append&position=0");
        let headers = server.signed_headers("dfs", "PATCH", &url, &[], None);
        let mut request = server.client.request(Method::PATCH, url);
        for (name, value) in headers {
            request = request.header(name, value);
        }
        let reply = request
            .body(Body::new(Cursor::new(payload.clone())))
            .send()
            .unwrap_or_else(|error| {
                panic!("round {round} chunked DFS append failed at transport layer: {error:?}")
            });
        assert_eq!(reply.status(), 411, "round {round} chunked DFS append");
        assert_eq!(
            reply
                .headers()
                .get("x-ms-error-code")
                .and_then(|value| value.to_str().ok()),
            Some("MissingContentLengthHeader")
        );
        let _ = reply.bytes().expect("complete 411 body");
        server.send_ok("dfs", "/?resource=account");
    }
}

#[test]
fn early_error_preserves_http1_keep_alive_when_body_fits_drain_cap() {
    let server = AllServices::start();
    let payload = vec![b'a'; 64 * 1024];

    for (service, method, bad_path, extra, ok_path) in [
        (
            "blob",
            "PUT",
            "/Not_Valid/blob",
            &[("x-ms-blob-type", "BlockBlob")][..],
            "/?comp=list",
        ),
        (
            "dfs",
            "PATCH",
            "/Not_Valid/file?action=append&position=0",
            &[][..],
            "/?resource=account",
        ),
        (
            "file",
            "PUT",
            "/Not_Valid/file?comp=range",
            &[("x-ms-write", "update"), ("x-ms-range", "bytes=0-65535")][..],
            "/?comp=list",
        ),
        (
            "queue",
            "POST",
            "/Not_Valid/messages",
            &[][..],
            "/?comp=list",
        ),
        (
            "table",
            "POST",
            "/Not_Valid",
            &[
                ("content-type", "application/json"),
                ("accept", "application/json;odata=minimalmetadata"),
            ][..],
            "/Tables",
        ),
    ] {
        let bad_url = server.url(service, bad_path);
        let address = bad_url.socket_addrs(|| None).unwrap()[0];
        let mut socket = TcpStream::connect(address).unwrap();
        socket
            .set_read_timeout(Some(Duration::from_secs(5)))
            .unwrap();
        socket
            .set_write_timeout(Some(Duration::from_secs(5)))
            .unwrap();

        let bad_headers =
            server.signed_headers(service, method, &bad_url, extra, Some(payload.len()));
        let bad_target = match bad_url.query() {
            Some(query) => format!("{}?{query}", bad_url.path()),
            None => bad_url.path().to_owned(),
        };
        write!(
            socket,
            "{method} {bad_target} HTTP/1.1\r\nHost: {address}\r\nConnection: keep-alive\r\n"
        )
        .unwrap();
        for (name, value) in bad_headers {
            write!(socket, "{name}: {value}\r\n").unwrap();
        }
        socket.write_all(b"\r\n").unwrap();
        socket.write_all(&payload).unwrap();
        socket.flush().unwrap();

        let (status, headers, _body) = read_http_response(&mut socket);
        assert_eq!(status, 400, "{service} first request should return 400");
        assert_ne!(
            headers.get("connection").map(String::as_str),
            Some("close"),
            "{service} should keep connection alive after draining bounded body"
        );

        // Reuse the exact same TCP connection for a follow-up request.
        let ok_url = server.url(service, ok_path);
        let ok_headers = server.signed_headers(service, "GET", &ok_url, &[], Some(0));
        let ok_target = match ok_url.query() {
            Some(query) => format!("{}?{query}", ok_url.path()),
            None => ok_url.path().to_owned(),
        };
        write!(
            socket,
            "GET {ok_target} HTTP/1.1\r\nHost: {address}\r\nConnection: close\r\n"
        )
        .unwrap();
        for (name, value) in ok_headers {
            write!(socket, "{name}: {value}\r\n").unwrap();
        }
        socket.write_all(b"\r\n").unwrap();
        socket.flush().unwrap();

        let (second_status, _, second_body) = read_http_response(&mut socket);
        assert_eq!(
            second_status,
            200,
            "{service} reused keep-alive connection failed: {}",
            String::from_utf8_lossy(&second_body)
        );
    }
}

#[test]
fn oversized_stalled_and_expect_continue_early_errors_close_promptly_without_hanging() {
    let server = Server::start("blob", None, &[]);
    let url = Url::parse(&server.url("/valid/blob")).unwrap();
    let address = url.socket_addrs(|| None).unwrap()[0];

    let send_raw = |extra: &[(&str, &str)], declared: usize, partial: &[u8]| {
        let mut socket = TcpStream::connect(address).unwrap();
        socket
            .set_read_timeout(Some(Duration::from_secs(5)))
            .unwrap();
        let date = httpdate::fmt_http_date(SystemTime::now());
        write!(
            socket,
            "PUT {} HTTP/1.1\r\nHost: {address}\r\nx-ms-date: {date}\r\nx-ms-version: 2023-11-03\r\nx-ms-blob-type: BlockBlob\r\nContent-Length: {declared}\r\n",
            url.path()
        )
        .unwrap();
        for (name, value) in extra {
            write!(socket, "{name}: {value}\r\n").unwrap();
        }
        socket.write_all(b"\r\n").unwrap();
        if !partial.is_empty() {
            socket.write_all(partial).unwrap();
        }
        socket.flush().unwrap();
        let started = Instant::now();
        let reply = read_http_response(&mut socket);
        (started.elapsed(), reply)
    };

    // 1. Oversized body (> drain cap): do not wait for 4 MiB; reply promptly with Connection: close.
    let (elapsed, (status, headers, _)) = send_raw(&[], 4 * 1024 * 1024, b"partial");
    assert_eq!(status, 403);
    assert_eq!(headers.get("connection").map(String::as_str), Some("close"));
    assert!(
        elapsed < Duration::from_secs(1),
        "oversized early error should not block draining: {elapsed:?}"
    );

    // 2. Stalled small body (slow-loris): bounded drain timeout fires promptly and closes.
    let (elapsed, (status, headers, _)) = send_raw(&[], 4096, b"only-a-few-bytes");
    assert_eq!(status, 403);
    assert_eq!(headers.get("connection").map(String::as_str), Some("close"));
    assert!(
        elapsed < Duration::from_secs(2),
        "stalled early error should hit bounded drain timeout promptly: {elapsed:?}"
    );

    // 3. Expect: 100-continue early rejection: never send 100 Continue, reply immediately.
    let (elapsed, (status, headers, _)) = send_raw(&[("Expect", "100-continue")], 65536, b"");
    assert_eq!(
        status, 403,
        "must receive 403 directly without an intermediate 100 Continue"
    );
    assert_eq!(headers.get("connection").map(String::as_str), Some("close"));
    assert!(
        elapsed < Duration::from_secs(1),
        "Expect: 100-continue early rejection should not wait for body: {elapsed:?}"
    );

    // 4. Small --max-blob-bytes rejection (413 RequestBodyTooLarge) within the drain cap still
    // delivers the Azure error cleanly over a pooled client without resetting the socket.
    let capped = Server::start("blob", None, &["--max-blob-bytes", "1024"]);
    capped
        .send(Method::PUT, "/box?restype=container", &[], b"")
        .status(201);
    let payload = vec![b'z'; 256 * 1024];
    capped
        .send(
            Method::PUT,
            "/box/too-big",
            &[("x-ms-blob-type", "BlockBlob")],
            &payload,
        )
        .error(413, "RequestBodyTooLarge");
    capped
        .send(Method::GET, "/box?restype=container&comp=list", &[], b"")
        .status(200);

    // 5. Chunked body exceeding the 1 MiB drain cap stops draining and sets Connection: close.
    let mut socket = TcpStream::connect(address).unwrap();
    socket
        .set_read_timeout(Some(Duration::from_secs(5)))
        .unwrap();
    socket
        .set_write_timeout(Some(Duration::from_secs(5)))
        .unwrap();
    let date = httpdate::fmt_http_date(SystemTime::now());
    write!(
        socket,
        "PUT {} HTTP/1.1\r\nHost: {address}\r\nx-ms-date: {date}\r\nx-ms-version: 2023-11-03\r\nx-ms-blob-type: BlockBlob\r\nTransfer-Encoding: chunked\r\n\r\n",
        url.path()
    )
    .unwrap();
    let chunk = vec![b'q'; 64 * 1024];
    // Write 1088 KiB (just past the 1 MiB drain cap) without terminating the chunked body.
    for _ in 0..17 {
        if write!(socket, "{:x}\r\n", chunk.len()).is_err()
            || socket.write_all(&chunk).is_err()
            || socket.write_all(b"\r\n").is_err()
        {
            break;
        }
    }
    let _ = socket.flush();
    let (status, headers, _) = read_http_response(&mut socket);
    assert_eq!(status, 411);
    assert_eq!(headers.get("connection").map(String::as_str), Some("close"));
}
