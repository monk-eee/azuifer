use base64::{Engine as _, engine::general_purpose::STANDARD};
use hmac::{Hmac, Mac as _};
use reqwest::{
    Method, Url,
    blocking::{Client, Response},
};
use sha2::Sha256;
use std::{
    collections::BTreeMap,
    io::{BufRead as _, BufReader},
    path::Path,
    process::{Child, Command, ExitStatus, Stdio},
    sync::mpsc,
    thread,
    time::{Duration, Instant, SystemTime},
};

const ACCOUNT: &str = "testaccount";
const VERSION: &str = "2023-11-03";
const KEY: [u8; 32] = [41; 32];
const FAR_FUTURE: &str = "2100-01-01T00:00:00Z";

struct TestProcess(Child);

impl TestProcess {
    fn shutdown(&mut self) -> std::io::Result<Option<ExitStatus>> {
        drop(self.0.stdin.take());
        let deadline = Instant::now() + Duration::from_secs(5);
        loop {
            if let Some(status) = self.0.try_wait()? {
                return Ok(Some(status));
            }
            if Instant::now() >= deadline {
                return Ok(None);
            }
            thread::sleep(Duration::from_millis(10));
        }
    }

    fn crash(&mut self) {
        self.0.kill().expect("terminate the running emulator");
        self.0.wait().expect("reap the crashed emulator");
    }
}

impl Drop for TestProcess {
    fn drop(&mut self) {
        if !matches!(self.shutdown(), Ok(Some(_))) {
            let _ = self.0.kill();
            let _ = self.0.wait();
        }
    }
}

struct Emulator {
    process: TestProcess,
    queue: String,
    client: Client,
}

fn emulator_command() -> Command {
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

fn client() -> Client {
    Client::builder()
        .no_proxy()
        .timeout(Duration::from_secs(10))
        .build()
        .unwrap()
}

impl Emulator {
    fn start(location: Option<&Path>, extra: &[&str]) -> Self {
        let mut command = emulator_command();
        command.args([
            "serve",
            "--port",
            "0",
            "--admin-port",
            "0",
            "--services",
            "queue",
        ]);
        if let Some(location) = location {
            command.arg("--location").arg(location);
        } else {
            command.arg("--in-memory");
        }
        command.args(extra);
        Self::spawn(command)
    }

    fn spawn(mut command: Command) -> Self {
        command
            .arg("--shutdown-on-stdin-eof")
            .stdin(Stdio::piped())
            .stdout(Stdio::piped());
        let mut process = TestProcess(command.spawn().expect("start Azuifer"));
        let stdout = process.0.stdout.take().expect("piped startup addresses");
        let (sender, receiver) = mpsc::channel();
        thread::spawn(move || {
            let lines = BufReader::new(stdout)
                .lines()
                .take(2)
                .collect::<std::io::Result<Vec<_>>>();
            sender.send(lines).ok();
        });
        let lines = receiver
            .recv_timeout(Duration::from_secs(10))
            .expect("server bound its ports")
            .expect("read startup addresses");
        let [queue, _admin]: [String; 2] = lines.try_into().expect("two listener addresses");
        Self {
            process,
            queue: queue.strip_prefix("queue_url=").unwrap().to_owned(),
            client: client(),
        }
    }

    fn restart(self, location: &Path) -> Self {
        drop(self);
        Self::start(Some(location), &[])
    }

    fn url(&self, target: &str) -> Url {
        Url::parse(&format!("{}/{ACCOUNT}{target}", self.queue)).unwrap()
    }

    fn call(&self, method: Method, target: &str, extra: &[(&str, &str)], body: &str) -> Response {
        self.send(method, target, extra, body, Scheme::SharedKey(&KEY))
    }

    fn send(
        &self,
        method: Method,
        target: &str,
        extra: &[(&str, &str)],
        body: &str,
        scheme: Scheme,
    ) -> Response {
        let url = self.url(target);
        let has_body = !body.is_empty();
        let mut headers: BTreeMap<String, String> = BTreeMap::from([
            (
                "x-ms-date".into(),
                httpdate::fmt_http_date(SystemTime::now()),
            ),
            ("x-ms-version".into(), VERSION.into()),
        ]);
        if has_body {
            headers.insert("content-type".into(), "application/xml".into());
            headers.insert("content-length".into(), body.len().to_string());
        }
        for (name, value) in extra {
            headers.insert((*name).into(), (*value).into());
        }
        let signature = sign(&method, &url, &headers, scheme);
        headers.insert("authorization".into(), signature);
        let mut request = self.client.request(method, url);
        for (name, value) in headers {
            request = request.header(name, value);
        }
        if has_body {
            request = request.body(body.to_owned());
        }
        request.send().expect("HTTP request completed")
    }

    /// A request carrying a SAS token and no Authorization header.
    fn sas(
        &self,
        method: Method,
        target: &str,
        token: &[(String, String)],
        body: &str,
    ) -> Response {
        let mut url = self.url(target);
        url.query_pairs_mut().extend_pairs(token);
        let mut request = self.client.request(method, url);
        if !body.is_empty() {
            request = request.body(body.to_owned());
        }
        request.send().expect("HTTP request completed")
    }

    fn create_queue(&self, name: &str) {
        let response = self.call(Method::PUT, &format!("/{name}"), &[], "");
        assert_eq!(response.status(), 201);
        assert_eq!(response.text().unwrap(), "");
    }

    fn put(&self, queue: &str, query: &str, text: &str) -> Response {
        self.call(
            Method::POST,
            &format!("/{queue}/messages{query}"),
            &[],
            &message_xml(text),
        )
    }

    fn messages(&self, queue: &str, query: &str) -> String {
        let response = self.call(Method::GET, &format!("/{queue}/messages{query}"), &[], "");
        assert_eq!(response.status(), 200);
        response.text().unwrap()
    }
}

#[derive(Clone, Copy)]
enum Scheme<'a> {
    SharedKey(&'a [u8]),
    SharedKeyLite(&'a [u8]),
}

fn hmac(key: &[u8], message: &str) -> String {
    let mut mac = Hmac::<Sha256>::new_from_slice(key).unwrap();
    mac.update(message.as_bytes());
    STANDARD.encode(mac.finalize().into_bytes())
}

fn sign(method: &Method, url: &Url, headers: &BTreeMap<String, String>, scheme: Scheme) -> String {
    let value = |name| headers.get(name).map_or("", String::as_str);
    let extensions: String = headers
        .iter()
        .filter(|(name, _)| name.starts_with("x-ms-"))
        .map(|(name, value)| format!("{name}:{value}\n"))
        .collect();
    match scheme {
        Scheme::SharedKey(key) => {
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
            format!("SharedKey {ACCOUNT}:{}", hmac(key, &message))
        }
        Scheme::SharedKeyLite(key) => {
            let comp = url
                .query_pairs()
                .find(|(name, _)| name == "comp")
                .map_or_else(String::new, |(_, value)| format!("?comp={value}"));
            let message = format!(
                "{}\n\n{}\n\n{extensions}/{ACCOUNT}{}{comp}",
                method.as_str(),
                value("content-type"),
                url.path()
            );
            format!("SharedKeyLite {ACCOUNT}:{}", hmac(key, &message))
        }
    }
}

fn message_xml(text: &str) -> String {
    let escaped = text
        .replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;");
    format!("<QueueMessage><MessageText>{escaped}</MessageText></QueueMessage>")
}

fn error(response: Response, status: u16, code: &str) -> String {
    assert_eq!(response.status().as_u16(), status);
    assert_eq!(response.headers()["x-ms-error-code"], code);
    let body = response.text().unwrap();
    assert!(body.contains(&format!("<Code>{code}</Code>")), "{body}");
    body
}

/// The text of the first `<tag>` element, so tests read Azure's XML without a parser.
fn tag<'a>(body: &'a str, name: &str) -> &'a str {
    let open = format!("<{name}>");
    let start = body
        .find(&open)
        .unwrap_or_else(|| panic!("<{name}> in {body}"))
        + open.len();
    let end = body[start..].find(&format!("</{name}>")).unwrap() + start;
    &body[start..end]
}

fn account_sas(
    services: &str,
    types: &str,
    permissions: &str,
    start: Option<&str>,
    expiry: &str,
    protocol: &str,
) -> Vec<(String, String)> {
    let message = format!(
        "{ACCOUNT}\n{permissions}\n{services}\n{types}\n{}\n{expiry}\n\n{protocol}\n{VERSION}\n\n",
        start.unwrap_or("")
    );
    let mut token = vec![
        ("sv".to_owned(), VERSION.to_owned()),
        ("ss".to_owned(), services.to_owned()),
        ("srt".to_owned(), types.to_owned()),
        ("sp".to_owned(), permissions.to_owned()),
        ("se".to_owned(), expiry.to_owned()),
    ];
    if let Some(start) = start {
        token.push(("st".to_owned(), start.to_owned()));
    }
    if !protocol.is_empty() {
        token.push(("spr".to_owned(), protocol.to_owned()));
    }
    token.push(("sig".to_owned(), hmac(&KEY, &message)));
    token
}

fn service_sas(
    queue: &str,
    permissions: &str,
    expiry: &str,
    identifier: &str,
) -> Vec<(String, String)> {
    let message =
        format!("{permissions}\n\n{expiry}\n/queue/{ACCOUNT}/{queue}\n{identifier}\n\n\n{VERSION}");
    let mut token = vec![("sv".to_owned(), VERSION.to_owned())];
    for (name, value) in [("sp", permissions), ("se", expiry), ("si", identifier)] {
        if !value.is_empty() {
            token.push((name.to_owned(), value.to_owned()));
        }
    }
    token.push(("sig".to_owned(), hmac(&KEY, &message)));
    token
}

fn assert_http_date(value: &str) {
    httpdate::parse_http_date(value).unwrap_or_else(|_| panic!("RFC 1123 date: {value}"));
}

#[test]
fn queue_lifecycle_metadata_and_listing() {
    let server = Emulator::start(None, &[]);
    let created = server.call(Method::PUT, "/lifecycle", &[("x-ms-meta-team", "red")], "");
    assert_eq!(created.status(), 201);
    assert_eq!(created.headers()["x-ms-version"], VERSION);
    assert_eq!(created.headers()["x-ms-request-id"].len(), 32);
    assert_http_date(created.headers()["date"].to_str().unwrap());
    assert_eq!(
        server
            .call(Method::PUT, "/lifecycle", &[("x-ms-meta-team", "red")], "")
            .status(),
        204,
        "same metadata is idempotent"
    );
    error(
        server.call(Method::PUT, "/lifecycle", &[("x-ms-meta-team", "blue")], ""),
        409,
        "QueueAlreadyExists",
    );
    error(
        server.call(Method::PUT, "/lifecycle", &[], ""),
        409,
        "QueueAlreadyExists",
    );

    let properties = server.call(Method::GET, "/lifecycle?comp=metadata", &[], "");
    assert_eq!(properties.status(), 200);
    assert_eq!(properties.headers()["x-ms-meta-team"], "red");
    assert_eq!(properties.headers()["x-ms-approximate-messages-count"], "0");
    let head = server.call(Method::HEAD, "/lifecycle?comp=metadata", &[], "");
    assert_eq!(head.status(), 200);
    assert_eq!(head.headers()["x-ms-meta-team"], "red");

    let set = server.call(
        Method::PUT,
        "/lifecycle?comp=metadata",
        &[("x-ms-meta-a", "1"), ("x-ms-meta-b", "2")],
        "",
    );
    assert_eq!(set.status(), 204);
    server.put("lifecycle", "", "one");
    server.put("lifecycle", "", "two");
    let after = server.call(Method::GET, "/lifecycle?comp=metadata", &[], "");
    assert_eq!(after.headers()["x-ms-meta-a"], "1");
    assert!(!after.headers().contains_key("x-ms-meta-team"));
    assert_eq!(after.headers()["x-ms-approximate-messages-count"], "2");
    let cleared = server.call(Method::PUT, "/lifecycle?comp=metadata", &[], "");
    assert_eq!(cleared.status(), 204);
    let none = server.call(Method::GET, "/lifecycle?comp=metadata", &[], "");
    assert!(!none.headers().contains_key("x-ms-meta-a"));

    for name in ["alpha1", "alpha2", "alpha3", "beta1"] {
        server.create_queue(name);
    }
    server.call(
        Method::PUT,
        "/alpha2?comp=metadata",
        &[("x-ms-meta-k", "v & w")],
        "",
    );
    let first = server
        .call(
            Method::GET,
            "?comp=list&prefix=alpha&maxresults=2&include=metadata",
            &[],
            "",
        )
        .text()
        .unwrap();
    assert!(first.contains(&format!("ServiceEndpoint=\"{}/{ACCOUNT}/\"", server.queue)));
    assert_eq!(tag(&first, "Prefix"), "alpha");
    assert_eq!(tag(&first, "MaxResults"), "2");
    assert!(first.contains("<Name>alpha1</Name>") && first.contains("<Name>alpha2</Name>"));
    assert!(first.contains("<Metadata><k>v &amp; w</k></Metadata>"));
    let marker = tag(&first, "NextMarker").to_owned();
    assert!(!marker.is_empty());
    let second = server
        .call(
            Method::GET,
            &format!("?comp=list&prefix=alpha&maxresults=2&marker={marker}"),
            &[],
            "",
        )
        .text()
        .unwrap();
    assert!(second.contains("<Name>alpha3</Name>") && !second.contains("alpha2"));
    assert!(second.contains("<NextMarker></NextMarker>"));
    assert!(!second.contains("<Metadata>"), "metadata only on request");
    let all = server
        .call(Method::GET, "?comp=list", &[], "")
        .text()
        .unwrap();
    assert_eq!(all.matches("<Queue>").count(), 5);
    error(
        server.call(Method::GET, "?comp=list&maxresults=5001", &[], ""),
        400,
        "OutOfRangeQueryParameterValue",
    );
    error(
        server.call(Method::GET, "?comp=list&include=bogus", &[], ""),
        400,
        "InvalidQueryParameterValue",
    );

    assert_eq!(
        server.call(Method::DELETE, "/lifecycle", &[], "").status(),
        204
    );
    error(
        server.call(Method::GET, "/lifecycle?comp=metadata", &[], ""),
        404,
        "QueueNotFound",
    );
    error(
        server.call(Method::DELETE, "/lifecycle", &[], ""),
        404,
        "QueueNotFound",
    );
    let head_missing = server.call(Method::HEAD, "/lifecycle?comp=metadata", &[], "");
    assert_eq!(head_missing.status(), 404);
    assert_eq!(head_missing.headers()["x-ms-error-code"], "QueueNotFound");
    assert_eq!(head_missing.text().unwrap(), "");
    error(
        server.call(Method::PUT, "/ab", &[], ""),
        400,
        "OutOfRangeInput",
    );
    error(
        server.call(Method::PUT, "/Upper", &[], ""),
        400,
        "InvalidResourceName",
    );
    error(
        server.call(Method::PUT, "/dou--ble", &[], ""),
        400,
        "InvalidResourceName",
    );
    error(
        server.call(Method::PUT, "/badmeta", &[("x-ms-meta-1bad", "v")], ""),
        400,
        "InvalidMetadata",
    );
    error(
        server.call(Method::POST, "/alpha1", &[], ""),
        405,
        "UnsupportedHttpVerb",
    );
}

#[test]
fn message_operations_receipts_and_errors() {
    let server = Emulator::start(None, &[]);
    server.create_queue("messages");
    let put = server.put("messages", "", "hello <&> world");
    assert_eq!(put.status(), 201);
    let body = put.text().unwrap();
    assert!(body.starts_with(
        "<?xml version=\"1.0\" encoding=\"utf-8\"?><QueueMessagesList><QueueMessage>"
    ));
    let id = tag(&body, "MessageId").to_owned();
    assert_eq!(id.len(), 36);
    for name in ["InsertionTime", "ExpirationTime", "TimeNextVisible"] {
        assert_http_date(tag(&body, name));
    }
    assert!(!tag(&body, "PopReceipt").is_empty());
    assert!(!body.contains("MessageText"));
    let inserted = httpdate::parse_http_date(tag(&body, "InsertionTime")).unwrap();
    let expires = httpdate::parse_http_date(tag(&body, "ExpirationTime")).unwrap();
    let seven_days = expires.duration_since(inserted).unwrap();
    assert!(
        seven_days >= Duration::from_secs(7 * 86_400 - 1)
            && seven_days <= Duration::from_secs(7 * 86_400 + 1)
    );

    let peek = server.messages("messages", "?peekonly=true");
    assert_eq!(tag(&peek, "MessageId"), id);
    assert_eq!(tag(&peek, "MessageText"), "hello &lt;&amp;&gt; world");
    assert_eq!(tag(&peek, "DequeueCount"), "0");
    assert!(!peek.contains("PopReceipt"));

    let got = server.messages("messages", "?visibilitytimeout=60");
    assert_eq!(tag(&got, "DequeueCount"), "1");
    let receipt = tag(&got, "PopReceipt").to_owned();
    assert_http_date(tag(&got, "TimeNextVisible"));
    assert!(!server.messages("messages", "").contains("<QueueMessage>"));
    assert!(
        !server
            .messages("messages", "?peekonly=true")
            .contains("<QueueMessage>"),
        "invisible messages are not peeked"
    );

    let encoded = |value: &str| {
        Url::parse_with_params("http://x/", [("popreceipt", value)])
            .unwrap()
            .query()
            .unwrap()
            .to_owned()
    };
    let target =
        |receipt: &str, extra: &str| format!("/messages/messages/{id}?{}{extra}", encoded(receipt));
    error(
        server.call(Method::DELETE, &target("bogus", ""), &[], ""),
        400,
        "PopReceiptMismatch",
    );
    error(
        server.call(
            Method::PUT,
            &target("bogus", "&visibilitytimeout=5"),
            &[],
            &message_xml("x"),
        ),
        400,
        "PopReceiptMismatch",
    );
    error(
        server.call(Method::DELETE, &format!("/messages/messages/{id}"), &[], ""),
        400,
        "MissingRequiredQueryParameter",
    );
    error(
        server.call(Method::PUT, &target(&receipt, ""), &[], ""),
        400,
        "MissingRequiredQueryParameter",
    );

    let update = server.call(
        Method::PUT,
        &target(&receipt, "&visibilitytimeout=0"),
        &[],
        &message_xml("updated & new"),
    );
    assert_eq!(update.status(), 204);
    let new_receipt = update.headers()["x-ms-popreceipt"]
        .to_str()
        .unwrap()
        .to_owned();
    assert_ne!(new_receipt, receipt);
    assert_http_date(update.headers()["x-ms-time-next-visible"].to_str().unwrap());
    error(
        server.call(Method::DELETE, &target(&receipt, ""), &[], ""),
        400,
        "PopReceiptMismatch",
    );

    let again = server.messages("messages", "?visibilitytimeout=60");
    assert_eq!(tag(&again, "MessageText"), "updated &amp; new");
    assert_eq!(tag(&again, "DequeueCount"), "2");
    let latest = tag(&again, "PopReceipt").to_owned();
    let keep_text = server.call(
        Method::PUT,
        &target(&latest, "&visibilitytimeout=0"),
        &[],
        "",
    );
    assert_eq!(
        keep_text.status(),
        204,
        "an empty update body keeps the text"
    );
    let peek = server.messages("messages", "?peekonly=true");
    assert_eq!(tag(&peek, "MessageText"), "updated &amp; new");
    let after_update = keep_text.headers()["x-ms-popreceipt"]
        .to_str()
        .unwrap()
        .to_owned();
    assert_eq!(
        server
            .call(Method::DELETE, &target(&after_update, ""), &[], "")
            .status(),
        204
    );
    error(
        server.call(Method::DELETE, &target(&after_update, ""), &[], ""),
        404,
        "MessageNotFound",
    );
    error(
        server.call(
            Method::DELETE,
            "/messages/messages/no-such-id?popreceipt=x",
            &[],
            "",
        ),
        404,
        "MessageNotFound",
    );

    for n in 0..5 {
        server.put("messages", "", &format!("m{n}"));
    }
    let batch = server.messages("messages", "?numofmessages=3&visibilitytimeout=60");
    assert_eq!(batch.matches("<QueueMessage>").count(), 3);
    let texts: Vec<_> = batch
        .split("<MessageText>")
        .skip(1)
        .map(|s| s.split('<').next().unwrap())
        .collect();
    assert_eq!(texts, ["m0", "m1", "m2"], "insertion order");
    let peek_all = server.messages("messages", "?peekonly=true&numofmessages=32");
    assert_eq!(peek_all.matches("<QueueMessage>").count(), 2);
    let count = server.call(Method::HEAD, "/messages?comp=metadata", &[], "");
    assert_eq!(count.headers()["x-ms-approximate-messages-count"], "5");
    assert_eq!(
        server
            .call(Method::DELETE, "/messages/messages", &[], "")
            .status(),
        204
    );
    assert!(
        !server
            .messages("messages", "?peekonly=true")
            .contains("<QueueMessage>")
    );
    let empty = server.call(Method::GET, "/messages/messages", &[], "");
    assert_eq!(empty.status(), 200);
    assert!(empty.text().unwrap().contains("<QueueMessagesList>"));

    error(
        server.call(Method::GET, "/messages/messages?numofmessages=33", &[], ""),
        400,
        "OutOfRangeQueryParameterValue",
    );
    error(
        server.call(
            Method::GET,
            "/messages/messages?visibilitytimeout=0",
            &[],
            "",
        ),
        400,
        "OutOfRangeQueryParameterValue",
    );
    error(
        server.call(
            Method::GET,
            "/messages/messages?visibilitytimeout=x",
            &[],
            "",
        ),
        400,
        "InvalidQueryParameterValue",
    );
    error(
        server.call(Method::GET, "/messages/messages?peekonly=false", &[], ""),
        400,
        "InvalidQueryParameterValue",
    );
    error(
        server.put("messages", "?messagettl=0", "x"),
        400,
        "InvalidQueryParameterValue",
    );
    error(
        server.put("messages", "?messagettl=10&visibilitytimeout=10", "x"),
        400,
        "InvalidQueryParameterValue",
    );
    error(
        server.put("messages", "?visibilitytimeout=604801", "x"),
        400,
        "OutOfRangeQueryParameterValue",
    );
    error(
        server.call(Method::POST, "/messages/messages", &[], "<not-a-message/>"),
        400,
        "InvalidXmlDocument",
    );
    error(
        server.call(
            Method::POST,
            "/messages/messages",
            &[],
            "<QueueMessage><MessageText>x</QueueMessage>",
        ),
        400,
        "InvalidXmlDocument",
    );
    error(
        server.call(Method::POST, "/messages/messages", &[], "<QueueMessage/>"),
        400,
        "InvalidXmlDocument",
    );
    error(server.put("nosuchq", "", "x"), 404, "QueueNotFound");
    error(
        server.call(Method::GET, "/nosuchq/messages", &[], ""),
        404,
        "QueueNotFound",
    );
}

#[test]
fn message_size_limit_and_special_text() {
    let server = Emulator::start(None, &[]);
    server.create_queue("sizes");
    let limit = "x".repeat(64 * 1024);
    assert_eq!(server.put("sizes", "", &limit).status(), 201);
    error(
        server.put("sizes", "", &format!("{limit}x")),
        413,
        "RequestBodyTooLarge",
    );
    let multibyte = "é".repeat(32 * 1024 + 1);
    error(
        server.put("sizes", "", &multibyte),
        413,
        "RequestBodyTooLarge",
    );
    let fifty_ampersands = "&".repeat(1000);
    assert_eq!(server.put("sizes", "", &fifty_ampersands).status(), 201);
    assert_eq!(
        server.put("sizes", "", "").status(),
        201,
        "empty text is a valid message"
    );
    let unicode = "日本語 \u{1F600} <b64>YQ==</b64>";
    assert_eq!(server.put("sizes", "?messagettl=-1", unicode).status(), 201);
    let batch = server.messages("sizes", "?numofmessages=32&visibilitytimeout=60");
    assert!(batch.contains(&format!("<MessageText>{limit}</MessageText>")));
    assert!(batch.contains("<MessageText></MessageText>"));
    assert!(batch.contains("日本語 \u{1F600} &lt;b64&gt;YQ==&lt;/b64&gt;"));
    assert!(batch.contains("<ExpirationTime>Fri, 31 Dec 9999 23:59:59 GMT</ExpirationTime>"));
    let still_visible = server
        .messages("sizes", "?peekonly=true")
        .contains("<QueueMessage>");
    assert!(!still_visible, "everything is invisible after the batch");
}

#[test]
fn visibility_timeout_and_ttl_elapse_in_real_time() {
    let server = Emulator::start(None, &[]);
    server.create_queue("timing");
    let delayed = server.put("timing", "?visibilitytimeout=1&messagettl=30", "delayed");
    assert_eq!(delayed.status(), 201);
    let delayed = delayed.text().unwrap();
    assert!(
        !server
            .messages("timing", "?peekonly=true")
            .contains("<QueueMessage>"),
        "a delayed message is invisible"
    );
    thread::sleep(Duration::from_millis(1300));
    let visible = server.messages("timing", "?visibilitytimeout=1");
    assert_eq!(tag(&visible, "MessageId"), tag(&delayed, "MessageId"));
    assert_eq!(tag(&visible, "DequeueCount"), "1");
    let first_receipt = tag(&visible, "PopReceipt").to_owned();
    assert!(!server.messages("timing", "").contains("<QueueMessage>"));
    thread::sleep(Duration::from_millis(1300));
    let again = server.messages("timing", "?visibilitytimeout=30");
    assert_eq!(tag(&again, "DequeueCount"), "2");
    assert_ne!(tag(&again, "PopReceipt"), first_receipt);

    server.put("timing", "?messagettl=1", "short-lived");
    thread::sleep(Duration::from_millis(2100));
    let peek = server.messages("timing", "?peekonly=true&numofmessages=10");
    assert!(
        !peek.contains("short-lived"),
        "an expired message is gone: {peek}"
    );
    let count = server.call(Method::HEAD, "/timing?comp=metadata", &[], "");
    assert_eq!(count.headers()["x-ms-approximate-messages-count"], "1");
}

#[test]
fn queue_state_and_receipts_survive_restart_and_a_crash() {
    let dir = tempfile::tempdir().unwrap();
    let mut server = Emulator::start(Some(dir.path()), &[]);
    server.call(Method::PUT, "/durable", &[("x-ms-meta-keep", "yes")], "");
    server.put("durable", "?messagettl=-1", "first");
    server.put("durable", "", "second");
    let got = server.messages("durable", "?visibilitytimeout=600");
    let id = tag(&got, "MessageId").to_owned();
    let receipt = tag(&got, "PopReceipt").to_owned();
    let url_receipt = Url::parse_with_params("http://x/", [("popreceipt", &receipt)])
        .unwrap()
        .query()
        .unwrap()
        .to_owned();
    let second = Emulator::spawn_conflict(dir.path());
    assert!(
        second.is_some_and(|status| !status),
        "a second process is refused"
    );

    server.process.crash();
    drop(server);
    server = Emulator::start(Some(dir.path()), &[]);
    let metadata = server.call(Method::GET, "/durable?comp=metadata", &[], "");
    assert_eq!(metadata.headers()["x-ms-meta-keep"], "yes");
    assert_eq!(metadata.headers()["x-ms-approximate-messages-count"], "2");
    let next = server.messages("durable", "?visibilitytimeout=600");
    assert_eq!(
        tag(&next, "MessageText"),
        "second",
        "the first message is still invisible"
    );
    assert!(!server.messages("durable", "").contains("<QueueMessage>"));

    let update = server.call(
        Method::PUT,
        &format!("/durable/messages/{id}?{url_receipt}&visibilitytimeout=0"),
        &[],
        "",
    );
    assert_eq!(
        update.status(),
        204,
        "the pre-restart pop receipt is still valid"
    );
    let new_receipt = update.headers()["x-ms-popreceipt"]
        .to_str()
        .unwrap()
        .to_owned();
    let server = server.restart(dir.path());
    let visible = server.messages("durable", "?visibilitytimeout=600");
    assert_eq!(tag(&visible, "MessageId"), id);
    assert_eq!(tag(&visible, "DequeueCount"), "2");
    assert_ne!(tag(&visible, "PopReceipt"), new_receipt);
    assert_eq!(
        tag(&visible, "ExpirationTime"),
        "Fri, 31 Dec 9999 23:59:59 GMT"
    );
}

#[test]
fn shared_key_lite_and_credential_failures() {
    let server = Emulator::start(None, &[]);
    server.create_queue("secured");

    let lite = server.send(
        Method::GET,
        "/secured?comp=metadata&timeout=20",
        &[],
        "",
        Scheme::SharedKeyLite(&KEY),
    );
    assert_eq!(lite.status(), 200, "{}", lite.text().unwrap());
    let lite_put = server.send(
        Method::POST,
        "/secured/messages",
        &[],
        &message_xml("via lite"),
        Scheme::SharedKeyLite(&KEY),
    );
    assert_eq!(lite_put.status(), 201);
    let wrong_lite = server.send(
        Method::GET,
        "/secured?comp=metadata",
        &[],
        "",
        Scheme::SharedKeyLite(&[1; 32]),
    );
    error(wrong_lite, 403, "AuthenticationFailed");

    error(
        server.send(
            Method::GET,
            "/secured?comp=metadata",
            &[],
            "",
            Scheme::SharedKey(&[7; 32]),
        ),
        403,
        "AuthenticationFailed",
    );
    let anonymous = server
        .client
        .get(server.url("/secured?comp=metadata"))
        .header("x-ms-version", VERSION)
        .send()
        .unwrap();
    error(anonymous, 403, "AuthenticationFailed");
    let stale = server
        .client
        .get(server.url("/secured?comp=metadata"))
        .header("x-ms-version", VERSION)
        .header("x-ms-date", "Fri, 26 Jun 2015 23:39:12 GMT")
        .header(
            "authorization",
            format!("SharedKey {ACCOUNT}:{}", STANDARD.encode([0u8; 32])),
        )
        .send()
        .unwrap();
    error(stale, 403, "AuthenticationFailed");
    let other_account = server
        .client
        .get(format!(
            "{}/otheraccount/secured?comp=metadata",
            server.queue
        ))
        .header("x-ms-version", VERSION)
        .header("x-ms-date", httpdate::fmt_http_date(SystemTime::now()))
        .header(
            "authorization",
            format!("SharedKey otheraccount:{}", STANDARD.encode([0u8; 32])),
        )
        .send()
        .unwrap();
    error(other_account, 403, "AuthenticationFailed");
    let bearer = server
        .client
        .get(server.url("/secured?comp=metadata"))
        .header("x-ms-version", VERSION)
        .header("authorization", "Bearer abc")
        .send()
        .unwrap();
    error(bearer, 400, "InvalidAuthenticationInfo");
    let both = server
        .client
        .get(server.url("/secured?comp=metadata&sig=abc&se=2100-01-01"))
        .header("x-ms-version", VERSION)
        .header("authorization", "SharedKey x:y")
        .send()
        .unwrap();
    error(both, 400, "InvalidAuthenticationInfo");

    let no_version = server
        .client
        .get(server.url("/secured?comp=metadata"))
        .header("x-ms-date", httpdate::fmt_http_date(SystemTime::now()))
        .header("authorization", format!("SharedKey {ACCOUNT}:abc"))
        .send()
        .unwrap();
    error(no_version, 400, "MissingRequiredHeader");
    let client_id = server.call(
        Method::GET,
        "/secured?comp=metadata",
        &[("x-ms-client-request-id", "client-123")],
        "",
    );
    assert_eq!(client_id.headers()["x-ms-client-request-id"], "client-123");
}

#[test]
fn account_sas_enforces_service_resource_type_permission_and_window() {
    let server = Emulator::start(None, &[]);
    server.create_queue("accountsas");
    let token = |services: &str, types: &str, permissions: &str| {
        account_sas(services, types, permissions, None, FAR_FUTURE, "")
    };

    let list = token("q", "s", "l");
    assert_eq!(
        server.sas(Method::GET, "?comp=list", &list, "").status(),
        200
    );
    error(
        server.sas(Method::GET, "?comp=list", &token("b", "s", "l"), ""),
        403,
        "AuthorizationServiceMismatch",
    );
    error(
        server.sas(Method::GET, "?comp=list", &token("q", "co", "l"), ""),
        403,
        "AuthorizationResourceTypeMismatch",
    );
    error(
        server.sas(Method::GET, "?comp=list", &token("q", "s", "r"), ""),
        403,
        "AuthorizationPermissionMismatch",
    );
    let properties = server.sas(
        Method::GET,
        "?restype=service&comp=properties",
        &token("q", "s", "r"),
        "",
    );
    assert_eq!(properties.status(), 200);

    let create = token("q", "c", "c");
    assert_eq!(
        server.sas(Method::PUT, "/madebysas", &create, "").status(),
        201
    );
    let write = token("q", "c", "w");
    assert_eq!(
        server
            .sas(Method::PUT, "/madebysas?comp=metadata", &write, "")
            .status(),
        204
    );
    error(
        server.sas(Method::DELETE, "/madebysas", &create, ""),
        403,
        "AuthorizationPermissionMismatch",
    );
    assert_eq!(
        server
            .sas(Method::DELETE, "/madebysas", &token("q", "c", "d"), "")
            .status(),
        204
    );

    let add = token("q", "o", "a");
    let put = server.sas(
        Method::POST,
        "/accountsas/messages",
        &add,
        &message_xml("sas message"),
    );
    assert_eq!(put.status(), 201);
    error(
        server.sas(Method::GET, "/accountsas/messages?peekonly=true", &add, ""),
        403,
        "AuthorizationPermissionMismatch",
    );
    let peek = server.sas(
        Method::GET,
        "/accountsas/messages?peekonly=true",
        &token("q", "o", "r"),
        "",
    );
    assert!(peek.text().unwrap().contains("sas message"));
    let got = server.sas(
        Method::GET,
        "/accountsas/messages?visibilitytimeout=30",
        &token("q", "o", "p"),
        "",
    );
    let body = got.text().unwrap();
    let encoded = Url::parse_with_params("http://x/", [("popreceipt", tag(&body, "PopReceipt"))])
        .unwrap()
        .query()
        .unwrap()
        .to_owned();
    let id = tag(&body, "MessageId");
    let update = server.sas(
        Method::PUT,
        &format!("/accountsas/messages/{id}?{encoded}&visibilitytimeout=0"),
        &token("q", "o", "u"),
        "",
    );
    assert_eq!(update.status(), 204);
    assert_eq!(
        server
            .sas(
                Method::DELETE,
                "/accountsas/messages",
                &token("q", "o", "p"),
                ""
            )
            .status(),
        403,
        "clear needs delete, not process"
    );
    assert_eq!(
        server
            .sas(
                Method::DELETE,
                "/accountsas/messages",
                &token("q", "o", "d"),
                ""
            )
            .status(),
        204
    );

    let expired = account_sas("q", "sco", "rwdlacup", None, "2001-01-01T00:00:00Z", "");
    error(
        server.sas(Method::GET, "?comp=list", &expired, ""),
        403,
        "AuthenticationFailed",
    );
    let early = account_sas(
        "q",
        "sco",
        "rwdlacup",
        Some("2099-01-01T00:00:00Z"),
        FAR_FUTURE,
        "",
    );
    error(
        server.sas(Method::GET, "?comp=list", &early, ""),
        403,
        "AuthenticationFailed",
    );
    let https_only = account_sas("q", "sco", "rwdlacup", None, FAR_FUTURE, "https");
    error(
        server.sas(Method::GET, "?comp=list", &https_only, ""),
        403,
        "AuthorizationProtocolMismatch",
    );
    let either = account_sas("q", "sco", "rwdlacup", None, FAR_FUTURE, "https,http");
    assert_eq!(
        server.sas(Method::GET, "?comp=list", &either, "").status(),
        200
    );

    let mut tampered = list.clone();
    for (name, value) in &mut tampered {
        if name == "sp" {
            *value = "rwdlacup".into();
        }
    }
    error(
        server.sas(Method::GET, "?comp=list", &tampered, ""),
        403,
        "AuthenticationFailed",
    );
    let mut wrong_key = list;
    for (name, value) in &mut wrong_key {
        if name == "sig" {
            *value = hmac(&[3; 32], "anything");
        }
    }
    error(
        server.sas(Method::GET, "?comp=list", &wrong_key, ""),
        403,
        "AuthenticationFailed",
    );
}

#[test]
fn service_sas_uses_queue_resource_permissions_and_stored_policies() {
    let server = Emulator::start(None, &[]);
    server.create_queue("servicesas");
    server.create_queue("othersas");

    let all = service_sas("servicesas", "raup", FAR_FUTURE, "");
    let put = server.sas(
        Method::POST,
        "/servicesas/messages",
        &all,
        &message_xml("svc"),
    );
    assert_eq!(put.status(), 201);
    let metadata = server.sas(Method::GET, "/servicesas?comp=metadata", &all, "");
    assert_eq!(metadata.status(), 200);
    assert_eq!(metadata.headers()["x-ms-approximate-messages-count"], "1");
    error(
        server.sas(Method::POST, "/othersas/messages", &all, &message_xml("x")),
        403,
        "AuthenticationFailed",
    );
    let read_only = service_sas("servicesas", "r", FAR_FUTURE, "");
    assert_eq!(
        server
            .sas(
                Method::GET,
                "/servicesas/messages?peekonly=true",
                &read_only,
                ""
            )
            .status(),
        200
    );
    error(
        server.sas(
            Method::POST,
            "/servicesas/messages",
            &read_only,
            &message_xml("x"),
        ),
        403,
        "AuthorizationPermissionMismatch",
    );
    error(
        server.sas(Method::GET, "/servicesas/messages", &read_only, ""),
        403,
        "AuthorizationPermissionMismatch",
    );
    for (method, target) in [
        (Method::DELETE, "/servicesas/messages"),
        (Method::PUT, "/servicesas?comp=metadata"),
        (Method::GET, "/servicesas?comp=acl"),
        (Method::DELETE, "/servicesas"),
        (Method::GET, "?comp=list"),
    ] {
        error(
            server.sas(method, target, &all, ""),
            403,
            "AuthorizationPermissionMismatch",
        );
    }
    let expired = service_sas("servicesas", "raup", "2001-01-01T00:00:00Z", "");
    error(
        server.sas(Method::GET, "/servicesas?comp=metadata", &expired, ""),
        403,
        "AuthenticationFailed",
    );

    let policies = format!(
        "<SignedIdentifiers><SignedIdentifier><Id>reader</Id><AccessPolicy><Start>2020-01-01T00:00:00Z</Start><Expiry>{FAR_FUTURE}</Expiry><Permission>r</Permission></AccessPolicy></SignedIdentifier><SignedIdentifier><Id>old</Id><AccessPolicy><Expiry>2001-01-01T00:00:00Z</Expiry><Permission>raup</Permission></AccessPolicy></SignedIdentifier></SignedIdentifiers>"
    );
    assert_eq!(
        server
            .call(Method::PUT, "/servicesas?comp=acl", &[], &policies)
            .status(),
        204
    );
    let stored = service_sas("servicesas", "", "", "reader");
    let ok = server.sas(Method::GET, "/servicesas?comp=metadata", &stored, "");
    assert_eq!(
        ok.status(),
        200,
        "the policy supplies permissions and expiry"
    );
    error(
        server.sas(
            Method::POST,
            "/servicesas/messages",
            &stored,
            &message_xml("x"),
        ),
        403,
        "AuthorizationPermissionMismatch",
    );
    let old = service_sas("servicesas", "", "", "old");
    error(
        server.sas(Method::GET, "/servicesas?comp=metadata", &old, ""),
        403,
        "AuthenticationFailed",
    );
    let unknown = service_sas("servicesas", "", "", "revoked");
    error(
        server.sas(Method::GET, "/servicesas?comp=metadata", &unknown, ""),
        403,
        "AuthenticationFailed",
    );
    assert_eq!(
        server
            .call(Method::PUT, "/servicesas?comp=acl", &[], "")
            .status(),
        204,
        "clearing the ACL revokes tokens that rely on policies"
    );
    error(
        server.sas(Method::GET, "/servicesas?comp=metadata", &stored, ""),
        403,
        "AuthenticationFailed",
    );
}

#[test]
fn acl_round_trips_and_validates() {
    let server = Emulator::start(None, &[]);
    server.create_queue("aclq");
    let empty = server.call(Method::GET, "/aclq?comp=acl", &[], "");
    assert_eq!(empty.status(), 200);
    assert!(empty.text().unwrap().contains("<SignedIdentifiers>"));
    let body = "<SignedIdentifiers><SignedIdentifier><Id>one</Id><AccessPolicy><Start>2024-01-01T00:00:00Z</Start><Expiry>2030-06-01T12:30:00.1230000Z</Expiry><Permission>raup</Permission></AccessPolicy></SignedIdentifier><SignedIdentifier><Id>two</Id><AccessPolicy><Permission>r</Permission></AccessPolicy></SignedIdentifier></SignedIdentifiers>";
    assert_eq!(
        server
            .call(Method::PUT, "/aclq?comp=acl", &[], body)
            .status(),
        204
    );
    let stored = server
        .call(Method::GET, "/aclq?comp=acl", &[], "")
        .text()
        .unwrap();
    assert!(stored.contains("<Id>one</Id>"));
    assert!(stored.contains("<Start>2024-01-01T00:00:00.0000000Z</Start>"));
    assert!(stored.contains("<Expiry>2030-06-01T12:30:00.1230000Z</Expiry>"));
    assert!(stored.contains("<Permission>raup</Permission>"));
    assert!(stored.contains("<Id>two</Id>"));
    let six = format!(
        "<SignedIdentifiers>{}</SignedIdentifiers>",
        (0..6)
            .map(|n| format!("<SignedIdentifier><Id>id{n}</Id></SignedIdentifier>"))
            .collect::<String>()
    );
    error(
        server.call(Method::PUT, "/aclq?comp=acl", &[], &six),
        400,
        "InvalidXmlDocument",
    );
    let bad_permission = "<SignedIdentifiers><SignedIdentifier><Id>a</Id><AccessPolicy><Permission>xyz</Permission></AccessPolicy></SignedIdentifier></SignedIdentifiers>";
    error(
        server.call(Method::PUT, "/aclq?comp=acl", &[], bad_permission),
        400,
        "InvalidXmlDocument",
    );
    assert_eq!(
        server
            .call(Method::GET, "/aclq?comp=acl", &[], "")
            .text()
            .unwrap(),
        stored,
        "a rejected update leaves the ACL unchanged"
    );
    error(
        server.call(Method::GET, "/missingq?comp=acl", &[], ""),
        404,
        "QueueNotFound",
    );
}

#[test]
fn service_properties_stats_and_cors() {
    let server = Emulator::start(None, &[]);
    let defaults = server
        .call(Method::GET, "?restype=service&comp=properties", &[], "")
        .text()
        .unwrap();
    assert!(defaults.contains("<Logging><Version>1.0</Version><Read>false</Read>"));
    assert!(defaults.contains(
        "<HourMetrics><Version>1.0</Version><Enabled>true</Enabled><IncludeAPIs>true</IncludeAPIs>"
    ));
    assert!(defaults.contains("<Cors></Cors>"));

    let body = "<StorageServiceProperties><Logging><Version>1.0</Version><Read>true</Read><Write>true</Write><Delete>false</Delete><RetentionPolicy><Enabled>true</Enabled><Days>3</Days></RetentionPolicy></Logging><MinuteMetrics><Version>1.0</Version><Enabled>true</Enabled><IncludeAPIs>false</IncludeAPIs><RetentionPolicy><Enabled>false</Enabled></RetentionPolicy></MinuteMetrics><Cors><CorsRule><AllowedOrigins>http://app.example</AllowedOrigins><AllowedMethods>GET,PUT,OPTIONS</AllowedMethods><MaxAgeInSeconds>120</MaxAgeInSeconds><ExposedHeaders>x-ms-meta-*</ExposedHeaders><AllowedHeaders>x-ms-meta-*,content-type</AllowedHeaders></CorsRule></Cors></StorageServiceProperties>";
    let set = server.call(Method::PUT, "?restype=service&comp=properties", &[], body);
    assert_eq!(set.status(), 202);
    let stored = server
        .call(Method::GET, "?restype=service&comp=properties", &[], "")
        .text()
        .unwrap();
    assert!(stored.contains("<Logging><Version>1.0</Version><Read>true</Read><Write>true</Write><Delete>false</Delete><RetentionPolicy><Enabled>true</Enabled><Days>3</Days></RetentionPolicy></Logging>"));
    assert!(stored.contains("<HourMetrics><Version>1.0</Version><Enabled>true</Enabled><IncludeAPIs>true</IncludeAPIs>"), "unsent sections are unchanged");
    assert!(stored.contains("<MinuteMetrics><Version>1.0</Version><Enabled>true</Enabled><IncludeAPIs>false</IncludeAPIs>"));
    assert!(stored.contains(
        "<AllowedMethods>GET,PUT,OPTIONS</AllowedMethods><MaxAgeInSeconds>120</MaxAgeInSeconds>"
    ));
    error(
        server.call(
            Method::PUT,
            "?restype=service&comp=properties",
            &[],
            "<StorageServiceProperties><Cors><CorsRule><AllowedOrigins>*</AllowedOrigins><AllowedMethods>FETCH</AllowedMethods><MaxAgeInSeconds>1</MaxAgeInSeconds><ExposedHeaders/><AllowedHeaders/></CorsRule></Cors></StorageServiceProperties>",
        ),
        400,
        "InvalidXmlDocument",
    );

    let stats = server
        .call(Method::GET, "?restype=service&comp=stats", &[], "")
        .text()
        .unwrap();
    assert_eq!(tag(&stats, "Status"), "live");
    assert_http_date(tag(&stats, "LastSyncTime"));

    server.create_queue("corsq");
    let preflight = |origin: &str, method: &str, headers: &str| {
        let mut request = server
            .client
            .request(Method::OPTIONS, server.url("/corsq/messages"))
            .header("origin", origin)
            .header("access-control-request-method", method);
        if !headers.is_empty() {
            request = request.header("access-control-request-headers", headers);
        }
        request.send().unwrap()
    };
    let ok = preflight("http://app.example", "PUT", "x-ms-meta-name,Content-Type");
    assert_eq!(ok.status(), 200);
    assert_eq!(
        ok.headers()["access-control-allow-origin"],
        "http://app.example"
    );
    assert_eq!(ok.headers()["access-control-allow-methods"], "PUT");
    assert_eq!(ok.headers()["access-control-max-age"], "120");
    assert_eq!(ok.headers()["access-control-allow-credentials"], "true");
    assert_eq!(ok.headers()["x-ms-version"], VERSION);
    error(
        preflight("http://evil.example", "PUT", ""),
        403,
        "CorsPreflightFailure",
    );
    error(
        preflight("http://app.example", "DELETE", ""),
        403,
        "CorsPreflightFailure",
    );
    error(
        preflight("http://app.example", "GET", "authorization"),
        403,
        "CorsPreflightFailure",
    );
    let no_origin = server
        .client
        .request(Method::OPTIONS, server.url("/corsq/messages"))
        .send()
        .unwrap();
    assert_eq!(no_origin.status(), 400);

    let actual = server.call(
        Method::GET,
        "/corsq?comp=metadata",
        &[("origin", "http://app.example")],
        "",
    );
    assert_eq!(actual.status(), 200);
    assert_eq!(
        actual.headers()["access-control-allow-origin"],
        "http://app.example"
    );
    assert_eq!(
        actual.headers()["access-control-expose-headers"],
        "x-ms-meta-*"
    );
    let other = server.call(
        Method::GET,
        "/corsq?comp=metadata",
        &[("origin", "http://evil.example")],
        "",
    );
    assert!(!other.headers().contains_key("access-control-allow-origin"));

    let clear = "<StorageServiceProperties><Cors /></StorageServiceProperties>";
    assert_eq!(
        server
            .call(Method::PUT, "?restype=service&comp=properties", &[], clear)
            .status(),
        202
    );
    error(
        preflight("http://app.example", "PUT", ""),
        403,
        "CorsPreflightFailure",
    );
}

#[test]
fn api_version_policy_matches_the_blob_service() {
    let strict = Emulator::start(None, &[]);
    strict.create_queue("versions");
    let newer = strict.call(
        Method::GET,
        "/versions?comp=metadata",
        &[("x-ms-version", "2099-01-01")],
        "",
    );
    let body = error(newer, 400, "InvalidHeaderValue");
    assert!(body.contains("<HeaderName>x-ms-version</HeaderName>"));
    assert!(body.contains("<HeaderValue>2099-01-01</HeaderValue>"));
    error(
        strict.call(
            Method::GET,
            "/versions?comp=metadata",
            &[("x-ms-version", "2015-04-05")],
            "",
        ),
        400,
        "InvalidHeaderValue",
    );
    error(
        strict.call(
            Method::GET,
            "/versions?comp=metadata",
            &[("x-ms-version", "not-a-date")],
            "",
        ),
        400,
        "InvalidHeaderValue",
    );

    let lenient = Emulator::start(None, &["--skip-api-version-check"]);
    lenient.create_queue("versions");
    let newer = lenient.call(
        Method::GET,
        "/versions?comp=metadata",
        &[("x-ms-version", "2099-01-01")],
        "",
    );
    assert_eq!(newer.status(), 200);
    assert_eq!(
        newer.headers()["x-ms-version"],
        VERSION,
        "the effective version is reported"
    );
    error(
        lenient.call(
            Method::GET,
            "/versions?comp=metadata",
            &[("x-ms-version", "2015-04-05")],
            "",
        ),
        400,
        "InvalidHeaderValue",
    );
}

impl Emulator {
    /// Starts a second process on a directory that is already in use and reports
    /// whether it started successfully (`Some(false)` means it was refused).
    fn spawn_conflict(location: &Path) -> Option<bool> {
        let mut command = emulator_command();
        command
            .args([
                "serve",
                "--port",
                "0",
                "--admin-port",
                "0",
                "--services",
                "queue",
            ])
            .arg("--location")
            .arg(location)
            .stdin(Stdio::piped())
            .stdout(Stdio::null())
            .stderr(Stdio::null());
        let mut child = command.spawn().ok()?;
        let deadline = Instant::now() + Duration::from_secs(10);
        loop {
            if let Some(status) = child.try_wait().ok()? {
                return Some(status.success());
            }
            if Instant::now() >= deadline {
                let _ = child.kill();
                let _ = child.wait();
                return Some(true);
            }
            thread::sleep(Duration::from_millis(20));
        }
    }
}
