use base64::{Engine as _, engine::general_purpose::STANDARD};
use hmac::{Hmac, Mac as _};
use percent_encoding::{NON_ALPHANUMERIC, utf8_percent_encode};
use reqwest::{Method, blocking::Client};
use serde_json::{Value, json};
use sha2::Sha256;
use std::{
    io::{BufRead as _, BufReader},
    path::Path,
    process::{Child, Command, Stdio},
    time::{Duration, SystemTime},
};

const ACCOUNT: &str = "testaccount";
const KEY: [u8; 32] = [41; 32];
const JSON: &str = "application/json";

struct Server {
    child: Child,
    url: String,
    client: Client,
}

impl Server {
    fn start(location: Option<&Path>) -> Self {
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
                "table",
            ]);
        match location {
            Some(path) => command.arg("--location").arg(path),
            None => command.arg("--in-memory"),
        };
        let mut child = command
            .arg("--shutdown-on-stdin-eof")
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .spawn()
            .expect("start Azuifer");
        let mut lines = BufReader::new(child.stdout.take().expect("piped stdout")).lines();
        let mut url = None;
        for line in lines.by_ref() {
            let line = line.expect("startup line");
            if let Some(value) = line.strip_prefix("table_url=") {
                url = Some(value.to_owned());
            }
            if line.starts_with("admin_url=") {
                break;
            }
        }
        std::thread::spawn(move || lines.for_each(drop));
        Self {
            child,
            url: url.expect("table_url line"),
            client: Client::builder()
                .no_proxy()
                .timeout(Duration::from_secs(10))
                .build()
                .unwrap(),
        }
    }

    /// Stops the process by closing stdin and waits for a clean exit.
    fn stop(mut self) {
        drop(self.child.stdin.take());
        assert!(self.child.wait().expect("server exit").success());
    }

    fn send(&self, call: Call) -> Reply {
        let (path, query) = call.target.split_once('?').unwrap_or((call.target, ""));
        let full = format!("/{ACCOUNT}{path}");
        let url = if query.is_empty() {
            format!("{}{full}", self.url)
        } else {
            format!("{}{full}?{query}", self.url)
        };
        let date = httpdate::fmt_http_date(call.date.unwrap_or_else(SystemTime::now));
        let comp = query
            .split('&')
            .find_map(|pair| pair.strip_prefix("comp="))
            .map(|value| format!("?comp={value}"))
            .unwrap_or_default();
        let content_type = call
            .headers
            .iter()
            .find(|(name, _)| name.eq_ignore_ascii_case("content-type"))
            .map_or("", |(_, value)| *value);
        let resource = format!("/{ACCOUNT}{full}{comp}");
        let mut request = self
            .client
            .request(Method::from_bytes(call.method.as_bytes()).unwrap(), url)
            .header("x-ms-date", &date);
        if !call
            .headers
            .iter()
            .any(|(name, _)| name.eq_ignore_ascii_case("x-ms-version"))
        {
            request = request.header("x-ms-version", "2023-11-03");
        }
        match call.auth {
            Auth::SharedKey => {
                let sts = format!("{}\n\n{content_type}\n{date}\n{resource}", call.method);
                request = request.header(
                    "authorization",
                    format!("SharedKey {ACCOUNT}:{}", sign(&KEY, &sts)),
                );
            }
            Auth::Lite => {
                let sts = format!("{date}\n{resource}");
                request = request.header(
                    "authorization",
                    format!("SharedKeyLite {ACCOUNT}:{}", sign(&KEY, &sts)),
                );
            }
            Auth::WrongKey => {
                let sts = format!("{}\n\n{content_type}\n{date}\n{resource}", call.method);
                request = request.header(
                    "authorization",
                    format!("SharedKey {ACCOUNT}:{}", sign(&[1; 32], &sts)),
                );
            }
            Auth::None => {}
        }
        for (name, value) in call.headers {
            request = request.header(name, value);
        }
        if !call.body.is_empty() {
            request = request.body(call.body);
        }
        let response = request.send().expect("HTTP request completed");
        Reply {
            status: response.status().as_u16(),
            headers: response
                .headers()
                .iter()
                .map(|(name, value)| {
                    (
                        name.as_str().to_owned(),
                        value.to_str().unwrap_or_default().to_owned(),
                    )
                })
                .collect(),
            text: response.text().unwrap_or_default(),
        }
    }

    fn get(&self, target: &str) -> Reply {
        self.send(Call::new("GET", target))
    }

    fn post_json(
        &self,
        target: &str,
        body: &Value,
        extra: &[(&'static str, &'static str)],
    ) -> Reply {
        let mut call = Call::new("POST", target).json(body);
        call.headers.extend_from_slice(extra);
        self.send(call)
    }

    fn create_table(&self, name: &str) {
        let reply = self.post_json(
            "/Tables",
            &json!({ "TableName": name }),
            &[("prefer", "return-no-content")],
        );
        assert_eq!(reply.status, 204, "{}", reply.text);
    }

    fn insert(&self, table: &str, entity: &Value) -> Reply {
        self.post_json(
            &format!("/{table}"),
            entity,
            &[("prefer", "return-no-content")],
        )
    }
}

impl Drop for Server {
    fn drop(&mut self) {
        drop(self.child.stdin.take());
        let _ = self.child.wait();
    }
}

fn sign(key: &[u8], message: &str) -> String {
    let mut mac = Hmac::<Sha256>::new_from_slice(key).unwrap();
    mac.update(message.as_bytes());
    STANDARD.encode(mac.finalize().into_bytes())
}

enum Auth {
    SharedKey,
    Lite,
    WrongKey,
    None,
}

struct Call<'a> {
    method: &'a str,
    target: &'a str,
    headers: Vec<(&'a str, &'a str)>,
    body: Vec<u8>,
    auth: Auth,
    date: Option<SystemTime>,
}

impl<'a> Call<'a> {
    fn new(method: &'a str, target: &'a str) -> Self {
        Self {
            method,
            target,
            headers: Vec::new(),
            body: Vec::new(),
            auth: Auth::SharedKey,
            date: None,
        }
    }

    fn json(mut self, body: &Value) -> Self {
        self.headers.push(("content-type", JSON));
        self.body = body.to_string().into_bytes();
        self
    }

    fn header(mut self, name: &'a str, value: &'a str) -> Self {
        self.headers.push((name, value));
        self
    }

    fn auth(mut self, auth: Auth) -> Self {
        self.auth = auth;
        self
    }
}

struct Reply {
    status: u16,
    headers: Vec<(String, String)>,
    text: String,
}

impl Reply {
    fn header(&self, name: &str) -> Option<&str> {
        self.headers
            .iter()
            .find(|(candidate, _)| candidate.eq_ignore_ascii_case(name))
            .map(|(_, value)| value.as_str())
    }

    fn json(&self) -> Value {
        serde_json::from_str(&self.text).unwrap_or_else(|_| panic!("JSON body: {}", self.text))
    }

    fn error_code(&self) -> String {
        if let Some(code) = self.header("x-ms-error-code") {
            return code.to_owned();
        }
        self.json()["odata.error"]["code"]
            .as_str()
            .expect("OData error code")
            .to_owned()
    }
}

fn row(table: &str, partition: &str, row: &str) -> String {
    format!("/{table}(PartitionKey='{partition}',RowKey='{row}')")
}

fn encode(text: &str) -> String {
    utf8_percent_encode(text, NON_ALPHANUMERIC).to_string()
}

#[test]
fn table_catalog_responses_and_auth_errors_carry_standard_azure_headers() {
    let server = Server::start(None);
    let reply = server.get("/Tables");
    assert_eq!(reply.status, 200);
    assert_eq!(reply.header("x-ms-version"), Some("2023-11-03"));
    assert_eq!(reply.header("dataserviceversion"), None);
    assert_eq!(reply.header("x-ms-request-id").map(str::len), Some(36));
    assert!(
        reply
            .header("date")
            .is_some_and(|date| date.ends_with("GMT"))
    );
    assert!(
        reply
            .header("content-type")
            .unwrap()
            .starts_with("application/json;odata=minimalmetadata")
    );
    let error = server.send(Call::new("GET", "/Tables").auth(Auth::None));
    assert_eq!(error.status, 403);
    assert_eq!(error.error_code(), "AuthenticationFailed");
    assert_eq!(error.header("x-ms-version"), Some("2023-11-03"));
    assert_eq!(error.header("dataserviceversion"), Some("3.0;"));
    let body = error.json();
    assert_eq!(body["odata.error"]["code"], "AuthenticationFailed");
    assert!(
        body["odata.error"]["message"]["value"]
            .as_str()
            .unwrap()
            .contains("RequestId:")
    );
    server.stop();
}

#[test]
fn table_lifecycle_naming_prefer_and_paging() {
    let server = Server::start(None);
    let created = server.post_json("/Tables", &json!({ "TableName": "MyTable" }), &[]);
    assert_eq!(created.status, 201);
    assert_eq!(created.json()["TableName"], "MyTable");
    assert_eq!(created.header("preference-applied"), Some("return-content"));
    let none = server.post_json(
        "/Tables",
        &json!({ "TableName": "Other" }),
        &[("prefer", "return-no-content")],
    );
    assert_eq!((none.status, none.text.as_str()), (204, ""));
    assert_eq!(none.header("preference-applied"), Some("return-no-content"));
    for name in ["MyTable", "mytable"] {
        let duplicate = server.post_json("/Tables", &json!({ "TableName": name }), &[]);
        assert_eq!(
            (duplicate.status, duplicate.error_code().as_str()),
            (409, "TableAlreadyExists")
        );
    }
    for bad in ["ab", "1abc", "has-dash", "tables", &"a".repeat(64)] {
        let reply = server.post_json("/Tables", &json!({ "TableName": bad }), &[]);
        assert_eq!(
            (reply.status, reply.error_code().as_str()),
            (400, "InvalidResourceName"),
            "{bad}"
        );
    }
    let missing = server.post_json("/Tables", &json!({}), &[]);
    assert_eq!(missing.status, 400);

    for name in ["alpha1", "alpha2", "alpha3", "beta"] {
        server.create_table(name);
    }
    let all = server.get("/Tables").json();
    let names: Vec<_> = all["value"]
        .as_array()
        .unwrap()
        .iter()
        .map(|t| t["TableName"].as_str().unwrap())
        .collect();
    assert_eq!(
        names,
        ["alpha1", "alpha2", "alpha3", "beta", "MyTable", "Other"]
    );

    let first = server.get("/Tables?$top=2");
    assert_eq!(first.json()["value"].as_array().unwrap().len(), 2);
    let token = first
        .header("x-ms-continuation-nexttablename")
        .expect("continuation")
        .to_owned();
    assert_eq!(token, "alpha3");
    let rest = server.get(&format!("/Tables?$top=2&NextTableName={token}"));
    let rest_names: Vec<_> = rest.json()["value"]
        .as_array()
        .unwrap()
        .iter()
        .map(|t| t["TableName"].as_str().unwrap().to_owned())
        .collect();
    assert_eq!(rest_names, ["alpha3", "beta"]);

    let filtered = server.get(&format!(
        "/Tables?$filter={}",
        encode("TableName ge 'alpha' and TableName lt 'b'")
    ));
    assert_eq!(filtered.json()["value"].as_array().unwrap().len(), 3);
    let one = server.get("/Tables('mytable')");
    assert_eq!(
        one.json()["TableName"],
        "MyTable",
        "names keep their case but match case-insensitively"
    );
    let full = server
        .send(Call::new("GET", "/Tables").header("accept", "application/json;odata=fullmetadata"))
        .json();
    assert_eq!(full["value"][0]["odata.type"], format!("{ACCOUNT}.Tables"));
    assert!(
        full["value"][0]["odata.id"]
            .as_str()
            .unwrap()
            .ends_with("/testaccount/Tables('alpha1')")
    );
    let none = server
        .send(Call::new("GET", "/Tables").header("accept", "application/json;odata=nometadata"))
        .json();
    assert!(none.get("odata.metadata").is_none());

    assert_eq!(
        server.send(Call::new("DELETE", "/Tables('beta')")).status,
        204
    );
    let gone = server.send(Call::new("DELETE", "/Tables('beta')"));
    assert_eq!(
        (gone.status, gone.error_code().as_str()),
        (404, "ResourceNotFound")
    );
    assert_eq!(server.get("/Tables('beta')").status, 404);
    let atom = server.send(Call::new("GET", "/Tables").header("accept", "application/atom+xml"));
    assert_eq!(
        (atom.status, atom.error_code().as_str()),
        (415, "AtomFormatNotSupported")
    );
    server.stop();
}

#[test]
fn entity_operations_and_etag_concurrency() {
    let server = Server::start(None);
    server.create_table("people");
    let inserted = server.post_json(
        "/people",
        &json!({ "PartitionKey": "p", "RowKey": "r", "Name": "one", "Age": 30 }),
        &[],
    );
    assert_eq!(inserted.status, 201);
    assert_eq!(
        inserted.header("preference-applied"),
        Some("return-content")
    );
    let etag = inserted.header("etag").expect("ETag header").to_owned();
    assert!(
        etag.starts_with("W/\"datetime'") && etag.ends_with("Z'\""),
        "{etag}"
    );
    let body = inserted.json();
    assert_eq!(body["odata.etag"], etag);
    assert!(
        body["odata.metadata"]
            .as_str()
            .unwrap()
            .ends_with("/people/$metadata#people/@Element")
    );
    assert!(body["Timestamp"].as_str().unwrap().ends_with('Z'));

    let duplicate = server.insert("people", &json!({ "PartitionKey": "p", "RowKey": "r" }));
    assert_eq!(
        (duplicate.status, duplicate.error_code().as_str()),
        (409, "EntityAlreadyExists")
    );
    let found = server.get(&row("people", "p", "r"));
    assert_eq!(found.status, 200);
    assert_eq!(found.header("etag"), Some(etag.as_str()));
    assert_eq!(found.json()["Age"], 30);
    let missing = server.get(&row("people", "p", "nope"));
    assert_eq!(
        (missing.status, missing.error_code().as_str()),
        (404, "ResourceNotFound")
    );
    let no_table = server.get(&row("absent", "p", "r"));
    assert_eq!(
        (no_table.status, no_table.error_code().as_str()),
        (404, "TableNotFound")
    );

    // Merge keeps properties; the new ETag differs.
    let merge = server.send(
        Call::new("MERGE", &row("people", "p", "r"))
            .json(&json!({ "City": "Oslo" }))
            .header("if-match", &etag),
    );
    assert_eq!(merge.status, 204);
    let merged_etag = merge.header("etag").unwrap().to_owned();
    assert_ne!(merged_etag, etag);
    let current = server.get(&row("people", "p", "r")).json();
    assert_eq!(
        (current["Name"].as_str(), current["City"].as_str()),
        (Some("one"), Some("Oslo"))
    );

    // The old ETag no longer matches, for update, merge, and delete.
    for method in ["PUT", "MERGE", "PATCH"] {
        let stale = server.send(
            Call::new(method, &row("people", "p", "r"))
                .json(&json!({ "X": 1 }))
                .header("if-match", &etag),
        );
        assert_eq!(
            (stale.status, stale.error_code().as_str()),
            (412, "UpdateConditionNotSatisfied"),
            "{method}"
        );
    }
    let stale_delete =
        server.send(Call::new("DELETE", &row("people", "p", "r")).header("if-match", &etag));
    assert_eq!(stale_delete.status, 412);

    // Replace removes unspecified properties; a strong form of the ETag also matches.
    let strong = merged_etag.trim_start_matches("W/").to_owned();
    let replace = server.send(
        Call::new("PUT", &row("people", "p", "r"))
            .json(&json!({ "Only": true }))
            .header("if-match", &strong),
    );
    assert_eq!(replace.status, 204);
    let current = server.get(&row("people", "p", "r")).json();
    assert!(current.get("Name").is_none() && current["Only"] == true);

    // PATCH merges and the X-HTTP-Method override works on POST.
    let patch = server.send(
        Call::new("PATCH", &row("people", "p", "r"))
            .json(&json!({ "P": 1 }))
            .header("if-match", "*"),
    );
    assert_eq!(patch.status, 204);
    let overridden = server.send(
        Call::new("POST", &row("people", "p", "r"))
            .json(&json!({ "Q": 2 }))
            .header("if-match", "*")
            .header("x-http-method", "MERGE"),
    );
    assert_eq!(overridden.status, 204);
    let current = server.get(&row("people", "p", "r")).json();
    assert_eq!(
        (
            current["Only"].as_bool(),
            current["P"].as_i64(),
            current["Q"].as_i64()
        ),
        (Some(true), Some(1), Some(2))
    );

    // Conditional writes need an existing entity; unconditional ones upsert.
    for method in ["PUT", "MERGE"] {
        let reply = server.send(
            Call::new(method, &row("people", "p", "ghost"))
                .json(&json!({ "A": 1 }))
                .header("if-match", "*"),
        );
        assert_eq!(
            (reply.status, reply.error_code().as_str()),
            (404, "ResourceNotFound"),
            "{method}"
        );
    }
    assert_eq!(
        server
            .send(Call::new("PUT", &row("people", "p", "up1")).json(&json!({ "A": 1 })))
            .status,
        204
    );
    assert_eq!(
        server
            .send(Call::new("MERGE", &row("people", "p", "up1")).json(&json!({ "B": 2 })))
            .status,
        204
    );
    let upserted = server.get(&row("people", "p", "up1")).json();
    assert_eq!(
        (upserted["A"].as_i64(), upserted["B"].as_i64()),
        (Some(1), Some(2))
    );
    assert_eq!(
        server
            .send(Call::new("PUT", &row("people", "p", "up1")).json(&json!({ "C": 3 })))
            .status,
        204
    );
    assert!(
        server
            .get(&row("people", "p", "up1"))
            .json()
            .get("A")
            .is_none()
    );

    // Header and body validation.
    let none_match = server.send(
        Call::new("PUT", &row("people", "p", "r"))
            .json(&json!({}))
            .header("if-none-match", "*"),
    );
    assert_eq!(
        (none_match.status, none_match.error_code().as_str()),
        (400, "InvalidInput")
    );
    let bad_etag = server.send(
        Call::new("PUT", &row("people", "p", "r"))
            .json(&json!({}))
            .header("if-match", "garbage"),
    );
    assert_eq!(bad_etag.status, 400);
    let mismatch = server.send(
        Call::new("PUT", &row("people", "p", "r"))
            .json(&json!({ "PartitionKey": "other" }))
            .header("if-match", "*"),
    );
    assert_eq!(mismatch.status, 400);
    let no_condition = server.send(Call::new("DELETE", &row("people", "p", "r")));
    assert_eq!(
        (no_condition.status, no_condition.error_code().as_str()),
        (400, "InvalidInput")
    );

    // Delete: unconditional and conditional.
    assert_eq!(
        server
            .send(Call::new("DELETE", &row("people", "p", "r")).header("if-match", "*"))
            .status,
        204
    );
    let again = server.send(Call::new("DELETE", &row("people", "p", "r")).header("if-match", "*"));
    assert_eq!(
        (again.status, again.error_code().as_str()),
        (404, "ResourceNotFound")
    );
    let current = server
        .get(&row("people", "p", "up1"))
        .header("etag")
        .unwrap()
        .to_owned();
    assert_eq!(
        server
            .send(Call::new("DELETE", &row("people", "p", "up1")).header("if-match", &current))
            .status,
        204
    );

    // Empty keys and special characters round-trip through the URL form.
    server.insert("people", &json!({ "PartitionKey": "", "RowKey": "" }));
    assert_eq!(server.get("/people(PartitionKey='',RowKey='')").status, 200);
    server.insert(
        "people",
        &json!({ "PartitionKey": "o'k é", "RowKey": "a,b)(c" }),
    );
    let special = format!(
        "/people(PartitionKey='{}',RowKey='{}')",
        encode("o''k é"),
        encode("a,b)(c")
    );
    assert_eq!(server.get(&special).json()["PartitionKey"], "o'k é");
    server.stop();
}

#[test]
fn metadata_levels_and_edm_types_round_trip() {
    let server = Server::start(None);
    server.create_table("types");
    let entity = json!({
        "PartitionKey": "p", "RowKey": "r",
        "S": "text", "B": true, "I": 7, "D": 1.0, "F": 3.25,
        "L@odata.type": "Edm.Int64", "L": "9223372036854775807",
        "LMin@odata.type": "Edm.Int64", "LMin": "-9223372036854775808",
        "T@odata.type": "Edm.DateTime", "T": "2013-08-02T17:37:43.9004348Z",
        "TMax@odata.type": "Edm.DateTime", "TMax": "9999-12-31T23:59:59.9999999Z",
        "G@odata.type": "Edm.Guid", "G": "4185404a-5818-48c3-b9be-f217df0dba6f",
        "Bin@odata.type": "Edm.Binary", "Bin": "AQIDBA==",
        "NaN@odata.type": "Edm.Double", "NaN": "NaN",
        "Inf@odata.type": "Edm.Double", "Inf": "Infinity",
        "NegInf@odata.type": "Edm.Double", "NegInf": "-Infinity",
        "I32Min": -2147483648, "Gone": null
    });
    assert_eq!(server.insert("types", &entity).status, 204);
    let get = |accept: &str| {
        server
            .send(Call::new("GET", &row("types", "p", "r")).header("accept", accept))
            .json()
    };

    let minimal = get("application/json;odata=minimalmetadata");
    assert_eq!(minimal["L"], "9223372036854775807");
    assert_eq!(minimal["L@odata.type"], "Edm.Int64");
    assert_eq!(minimal["T"], "2013-08-02T17:37:43.9004348Z");
    assert_eq!(minimal["T@odata.type"], "Edm.DateTime");
    assert_eq!(minimal["TMax"], "9999-12-31T23:59:59.9999999Z");
    assert_eq!(minimal["G@odata.type"], "Edm.Guid");
    assert_eq!(minimal["Bin"], "AQIDBA==");
    assert_eq!(
        (
            minimal["NaN"].as_str(),
            minimal["Inf"].as_str(),
            minimal["NegInf"].as_str()
        ),
        (Some("NaN"), Some("Infinity"), Some("-Infinity"))
    );
    assert_eq!(minimal["D"].to_string(), "1.0");
    assert_eq!(minimal["I"], 7);
    assert_eq!(minimal["I32Min"], -2147483648_i64);
    assert!(minimal.get("Gone").is_none());
    assert!(minimal.get("odata.etag").is_some());
    assert!(minimal.get("Timestamp@odata.type").is_none() && minimal.get("odata.id").is_none());

    let none = get("application/json;odata=nometadata");
    assert!(
        none.as_object()
            .unwrap()
            .keys()
            .all(|k| !k.contains("odata")),
        "{none}"
    );
    assert_eq!(none["L"], "9223372036854775807");

    let full = get("application/json;odata=fullmetadata");
    assert_eq!(full["odata.type"], format!("{ACCOUNT}.types"));
    assert!(
        full["odata.id"]
            .as_str()
            .unwrap()
            .ends_with("/types(PartitionKey='p',RowKey='r')")
    );
    assert_eq!(full["odata.editLink"], "types(PartitionKey='p',RowKey='r')");
    assert_eq!(full["Timestamp@odata.type"], "Edm.DateTime");

    // The $format query option overrides Accept; a bare application/json is minimal.
    let format = server.get(&format!(
        "{}?$format={}",
        row("types", "p", "r"),
        encode("application/json;odata=nometadata")
    ));
    assert!(format.json().get("odata.etag").is_none());
    assert!(get("application/json").get("odata.metadata").is_some());

    // $select returns only the chosen properties, with null for absent ones.
    let selected = server
        .get(&format!("{}?$select=S,Absent", row("types", "p", "r")))
        .json();
    assert_eq!(selected["S"], "text");
    assert_eq!(selected["Absent"], Value::Null);
    assert!(selected.get("RowKey").is_none() && selected.get("I").is_none());
    server.stop();
}

#[test]
fn entity_validation_limits_and_error_codes() {
    let server = Server::start(None);
    server.create_table("limits");
    let kind = |body: Value| {
        let reply = server.insert("limits", &body);
        (reply.status, reply.error_code())
    };
    assert_eq!(
        kind(json!({ "RowKey": "r" })),
        (400, "PropertiesNeedValue".into())
    );
    assert_eq!(
        kind(json!({ "PartitionKey": "p" })),
        (400, "PropertiesNeedValue".into())
    );
    assert_eq!(
        kind(json!({ "PartitionKey": "a/b", "RowKey": "r" })),
        (400, "InvalidInput".into())
    );
    assert_eq!(
        kind(json!({ "PartitionKey": "p", "RowKey": "a\u{7}" })),
        (400, "InvalidInput".into())
    );
    assert_eq!(
        kind(json!({ "PartitionKey": "k".repeat(1025), "RowKey": "r" })),
        (400, "InvalidInput".into())
    );
    assert_eq!(
        kind(json!({ "PartitionKey": "p", "RowKey": "r", "bad-name": 1 })),
        (400, "PropertyNameInvalid".into())
    );
    assert_eq!(
        kind(json!({ "PartitionKey": "p", "RowKey": "r", "n".repeat(256): 1 })),
        (400, "PropertyNameTooLong".into())
    );
    assert_eq!(
        kind(json!({ "PartitionKey": "p", "RowKey": "r", "S": "x".repeat(32 * 1024 + 1) })),
        (400, "PropertyValueTooLarge".into())
    );
    assert_eq!(
        kind(
            json!({ "PartitionKey": "p", "RowKey": "r", "B@odata.type": "Edm.Binary", "B": STANDARD.encode(vec![0u8; 64 * 1024 + 1]) })
        ),
        (400, "PropertyValueTooLarge".into())
    );
    assert_eq!(
        kind(
            json!({ "PartitionKey": "p", "RowKey": "r", "A@odata.type": "Edm.Int32", "A": "nope" })
        ),
        (400, "InvalidValueType".into())
    );
    assert_eq!(
        kind(json!({ "PartitionKey": "p", "RowKey": "r", "A@odata.type": "Edm.Int64" })),
        (400, "PropertiesNeedValue".into())
    );
    assert_eq!(
        kind(
            json!({ "PartitionKey": "p", "RowKey": "r", "T@odata.type": "Edm.DateTime", "T": "1600-01-01T00:00:00Z" })
        ),
        (400, "InvalidValueType".into())
    );
    let mut many = serde_json::Map::new();
    many.insert("PartitionKey".into(), json!("p"));
    many.insert("RowKey".into(), json!("many"));
    for i in 0..253 {
        many.insert(format!("P{i}"), json!(i));
    }
    assert_eq!(
        kind(Value::Object(many.clone())),
        (400, "TooManyProperties".into())
    );
    many.remove("P0");
    assert_eq!(
        server.insert("limits", &Value::Object(many)).status,
        204,
        "252 properties are allowed"
    );
    // 17 strings of 32K characters (64 KiB each) exceed the 1 MiB entity limit.
    let mut large = serde_json::Map::new();
    large.insert("PartitionKey".into(), json!("p"));
    large.insert("RowKey".into(), json!("large"));
    for i in 0..17 {
        large.insert(format!("S{i}"), json!("x".repeat(32 * 1024)));
    }
    assert_eq!(kind(Value::Object(large)), (400, "EntityTooLarge".into()));
    let raw = server.send(
        Call::new("POST", "/limits")
            .header("content-type", JSON)
            .header("accept", JSON),
    );
    assert_eq!(raw.status, 400);
    let mut malformed = Call::new("POST", "/limits").header("content-type", JSON);
    malformed.body = b"{not json".to_vec();
    assert_eq!(server.send(malformed).status, 400);
    let mut duplicate = Call::new("POST", "/limits").header("content-type", JSON);
    duplicate.body = br#"{"PartitionKey":"p","RowKey":"r","A":1,"A":2}"#.to_vec();
    let duplicate = server.send(duplicate);
    assert_eq!(
        (duplicate.status, duplicate.error_code().as_str()),
        (400, "DuplicatePropertiesSpecified")
    );
    let mut atom = Call::new("POST", "/limits").header("content-type", "application/atom+xml");
    atom.body = b"<entry/>".to_vec();
    assert_eq!(server.send(atom).status, 415);
    // Timestamp in a request is ignored; unsupported OData options are refused.
    let ts = server.post_json(
        "/limits",
        &json!({ "PartitionKey": "p", "RowKey": "ts", "Timestamp": "2000-01-01T00:00:00Z" }),
        &[],
    );
    assert_ne!(ts.json()["Timestamp"], "2000-01-01T00:00:00Z");
    let orderby = server.get("/limits()?$orderby=RowKey");
    assert_eq!(
        (orderby.status, orderby.error_code().as_str()),
        (501, "NotImplemented")
    );
    assert_eq!(server.send(Call::new("PUT", "/Tables")).status, 405);
    server.stop();
}

fn seed(server: &Server, table: &str) {
    server.create_table(table);
    for partition in 0..4 {
        for index in 0..5 {
            let entity = json!({
                "PartitionKey": format!("part{partition}"), "RowKey": format!("row{index:02}"),
                "N": partition * 10 + index, "Even": index % 2 == 0, "Name": format!("n{index}"),
                "Big@odata.type": "Edm.Int64", "Big": (5_000_000_000_i64 + index).to_string(),
            });
            assert_eq!(server.insert(table, &entity).status, 204);
        }
    }
}

fn keys(reply: &Reply) -> Vec<String> {
    reply.json()["value"]
        .as_array()
        .unwrap()
        .iter()
        .map(|e| {
            format!(
                "{}/{}",
                e["PartitionKey"].as_str().unwrap_or("?"),
                e["RowKey"].as_str().unwrap_or("?")
            )
        })
        .collect()
}

#[test]
fn queries_filter_select_and_continue_across_partitions() {
    let server = Server::start(None);
    seed(&server, "query");
    let query = |q: &str| server.get(&format!("/query()?{q}"));
    let filter = |expr: &str| keys(&query(&format!("$filter={}", encode(expr))));

    let all = keys(&query(""));
    assert_eq!(all.len(), 20);
    let mut sorted = all.clone();
    sorted.sort();
    assert_eq!(all, sorted, "ordered by partition then row key");

    assert_eq!(
        filter("PartitionKey eq 'part1' and RowKey ge 'row03'"),
        ["part1/row03", "part1/row04"]
    );
    assert_eq!(
        filter("N gt 31 and Even eq true"),
        ["part3/row02", "part3/row04"]
    );
    assert_eq!(
        filter("(PartitionKey eq 'part0' or PartitionKey eq 'part3') and not (N lt 33)"),
        ["part3/row03", "part3/row04"]
    );
    assert_eq!(
        filter("Name eq 'n2' and PartitionKey lt 'part2'"),
        ["part0/row02", "part1/row02"]
    );
    assert_eq!(filter("Big eq 5000000002L").len(), 4);
    assert!(
        filter("N eq 1L").is_empty(),
        "Int64 literals do not match Int32 properties"
    );
    assert!(
        filter("Big eq 5000000002.0").is_empty(),
        "Double literals do not match Int64 properties"
    );
    assert!(filter("PartitionKey eq 'a' and PartitionKey eq 'b'").is_empty());
    assert_eq!(filter("Missing ne 'x'").len(), 20);
    assert!(filter("Missing eq 'x'").is_empty());
    assert_eq!(
        filter("Timestamp gt datetime'2000-01-01T00:00:00Z'").len(),
        20
    );
    assert_eq!(
        filter("'part2' eq PartitionKey and RowKey eq 'row00'"),
        ["part2/row00"]
    );

    for bad in [
        "N eq",
        "N eq 1 foo",
        "startswith(Name,'n') eq true",
        "N eq M",
        "(N eq 1",
        &vec!["N eq 1"; 16].join(" or "),
    ] {
        let reply = query(&format!("$filter={}", encode(bad)));
        assert_eq!(
            (reply.status, reply.error_code().as_str()),
            (400, "InvalidInput"),
            "{bad}"
        );
    }
    assert_eq!(query("$top=0").status, 400);
    assert_eq!(query("$top=abc").status, 400);
    assert_eq!(query("NextPartitionKey=garbage").status, 400);

    // $top pages carry continuation headers that resume exactly after the page.
    let mut paged = Vec::new();
    let mut next = String::new();
    loop {
        let reply = query(&format!("$top=7{next}"));
        assert_eq!(reply.status, 200);
        paged.extend(keys(&reply));
        match (
            reply.header("x-ms-continuation-nextpartitionkey"),
            reply.header("x-ms-continuation-nextrowkey"),
        ) {
            (Some(partition), Some(row)) => {
                next = format!(
                    "&NextPartitionKey={}&NextRowKey={}",
                    encode(partition),
                    encode(row)
                )
            }
            _ => break,
        }
    }
    assert_eq!(paged, all);
    let exact = query("$top=20");
    assert!(
        exact.header("x-ms-continuation-nextpartitionkey").is_none(),
        "no token when nothing is left"
    );
    let filtered_page = query(&format!("$top=3&$filter={}", encode("Even eq true")));
    assert_eq!(
        keys(&filtered_page),
        ["part0/row00", "part0/row02", "part0/row04"]
    );
    assert!(
        filtered_page
            .header("x-ms-continuation-nextpartitionkey")
            .is_some()
    );

    let selected = query(&format!(
        "$select=Name,N&$filter={}",
        encode("PartitionKey eq 'part0' and RowKey eq 'row01'")
    ))
    .json();
    assert_eq!(selected["value"][0]["Name"], "n1");
    assert_eq!(selected["value"][0]["N"], 1);
    assert!(selected["value"][0].get("PartitionKey").is_none());

    let none = server
        .send(
            Call::new("GET", "/query()?$top=1")
                .header("accept", "application/json;odata=nometadata"),
        )
        .json();
    assert!(none.get("odata.metadata").is_none() && none["value"][0].get("odata.etag").is_none());
    let full = server
        .send(
            Call::new("GET", "/query()?$top=1")
                .header("accept", "application/json;odata=fullmetadata"),
        )
        .json();
    assert!(
        full["value"][0]["odata.id"]
            .as_str()
            .unwrap()
            .contains("/query(PartitionKey='part0',RowKey='row00')")
    );
    assert!(server.get("/missing()").status == 404);
    server.stop();
}

fn batch_body(operations: &[(&str, String, &str, &str)]) -> (String, Vec<u8>) {
    let mut body =
        String::from("--batch_1\r\nContent-Type: multipart/mixed; boundary=changeset_1\r\n\r\n");
    for (method, path, headers, json) in operations {
        body.push_str(&format!(
            "--changeset_1\r\nContent-Type: application/http\r\nContent-Transfer-Encoding: binary\r\n\r\n{method} http://127.0.0.1/{ACCOUNT}{path} HTTP/1.1\r\nContent-Type: application/json\r\nAccept: application/json;odata=minimalmetadata\r\n{headers}\r\n{json}\r\n"
        ));
    }
    body.push_str("--changeset_1--\r\n--batch_1--\r\n");
    (
        "multipart/mixed; boundary=batch_1".into(),
        body.into_bytes(),
    )
}

fn send_batch(server: &Server, operations: &[(&str, String, &str, &str)]) -> Reply {
    let (content_type, body) = batch_body(operations);
    let mut call = Call::new("POST", "/$batch").header("content-type", &content_type);
    call.body = body;
    server.send(call)
}

fn insert_op(
    table: &str,
    partition: &str,
    row: &str,
) -> (&'static str, String, &'static str, &'static str) {
    let json: &'static str = Box::leak(
        format!(r#"{{"PartitionKey":"{partition}","RowKey":"{row}","V":1}}"#).into_boxed_str(),
    );
    (
        "POST",
        format!("/{table}"),
        "Prefer: return-no-content\r\n",
        json,
    )
}

fn status_lines(reply: &Reply) -> Vec<String> {
    reply
        .text
        .lines()
        .filter(|l| l.starts_with("HTTP/1.1 "))
        .map(str::to_owned)
        .collect()
}

#[test]
fn batches_are_atomic_and_report_the_failing_index() {
    let server = Server::start(None);
    server.create_table("batch");
    server.insert(
        "batch",
        &json!({ "PartitionKey": "p", "RowKey": "existing", "V": 0 }),
    );
    server.insert(
        "batch",
        &json!({ "PartitionKey": "p", "RowKey": "doomed", "V": 0 }),
    );

    let merge_json = r#"{"Added":true}"#;
    let ok = send_batch(
        &server,
        &[
            insert_op("batch", "p", "a"),
            ("PUT", row("batch", "p", "b"), "", r#"{"V":2}"#),
            (
                "MERGE",
                row("batch", "p", "existing"),
                "If-Match: *\r\n",
                merge_json,
            ),
            ("DELETE", row("batch", "p", "doomed"), "If-Match: *\r\n", ""),
        ],
    );
    assert_eq!(ok.status, 202, "{}", ok.text);
    assert!(
        ok.header("content-type")
            .unwrap()
            .starts_with("multipart/mixed; boundary=batchresponse_")
    );
    assert!(ok.text.contains("boundary=changesetresponse_"));
    assert_eq!(status_lines(&ok), ["HTTP/1.1 204 No Content"; 4]);
    assert!(ok.text.contains("Content-ID: 1") && ok.text.contains("Content-ID: 4"));
    assert!(ok.text.contains("ETag: W/\"datetime'"));
    assert!(ok.text.contains("Preference-Applied: return-no-content"));
    assert_eq!(
        server.get(&row("batch", "p", "existing")).json()["Added"],
        true
    );
    assert_eq!(server.get(&row("batch", "p", "doomed")).status, 404);

    // Insert-with-content in a batch returns 201 and the entity.
    let content = send_batch(
        &server,
        &[(
            "POST",
            "/batch".into(),
            "",
            r#"{"PartitionKey":"p","RowKey":"echo","V":5}"#,
        )],
    );
    assert!(
        content.text.contains("HTTP/1.1 201 Created") && content.text.contains(r#""V":5"#),
        "{}",
        content.text
    );

    // A failing operation rolls back the whole set and is named by index.
    let before = server.get("/batch()").json()["value"]
        .as_array()
        .unwrap()
        .len();
    let failed = send_batch(
        &server,
        &[
            insert_op("batch", "p", "n1"),
            insert_op("batch", "p", "n2"),
            insert_op("batch", "p", "a"),
            insert_op("batch", "p", "n3"),
        ],
    );
    assert_eq!(failed.status, 202);
    assert_eq!(status_lines(&failed), ["HTTP/1.1 409 Conflict"]);
    let error: Value = serde_json::from_str(
        failed
            .text
            .lines()
            .find(|l| l.starts_with("{\"odata.error"))
            .unwrap(),
    )
    .unwrap();
    assert_eq!(error["odata.error"]["code"], "EntityAlreadyExists");
    assert!(
        error["odata.error"]["message"]["value"]
            .as_str()
            .unwrap()
            .starts_with("2:The specified entity already exists.")
    );
    assert!(failed.text.contains("Content-ID: 3"));
    assert_eq!(
        server.get("/batch()").json()["value"]
            .as_array()
            .unwrap()
            .len(),
        before,
        "no partial writes"
    );

    let stale = send_batch(
        &server,
        &[
            insert_op("batch", "p", "s1"),
            (
                "PUT",
                row("batch", "p", "a"),
                "If-Match: W/\"datetime'2000-01-01T00%3A00%3A00.0000000Z'\"\r\n",
                "{}",
            ),
        ],
    );
    assert_eq!(status_lines(&stale), ["HTTP/1.1 412 Precondition Failed"]);
    assert!(stale.text.contains("1:The update condition"));
    assert_eq!(server.get(&row("batch", "p", "s1")).status, 404);
    let missing = send_batch(
        &server,
        &[("DELETE", row("batch", "p", "ghost"), "If-Match: *\r\n", "")],
    );
    assert_eq!(status_lines(&missing), ["HTTP/1.1 404 Not Found"]);

    // Structural violations.
    let cross = send_batch(
        &server,
        &[insert_op("batch", "p", "x1"), insert_op("batch", "q", "x2")],
    );
    assert_eq!(status_lines(&cross), ["HTTP/1.1 400 Bad Request"]);
    assert!(
        cross
            .text
            .contains("CommandsInBatchActOnDifferentPartitions")
            && cross.text.contains("1:")
    );
    let dup = send_batch(
        &server,
        &[insert_op("batch", "p", "d"), insert_op("batch", "p", "d")],
    );
    assert!(dup.text.contains("InvalidDuplicateRow"));
    let invalid = send_batch(
        &server,
        &[
            insert_op("batch", "p", "ok"),
            ("POST", "/batch".into(), "", "{broken"),
        ],
    );
    assert!(invalid.text.contains("1:"), "{}", invalid.text);
    assert_eq!(server.get(&row("batch", "p", "ok")).status, 404);
    let hundred: Vec<_> = (0..100)
        .map(|i| insert_op("batch", "big", &format!("r{i:03}")))
        .collect();
    assert_eq!(status_lines(&send_batch(&server, &hundred)).len(), 100);
    let over: Vec<_> = (0..101)
        .map(|i| insert_op("batch", "huge", &format!("r{i:03}")))
        .collect();
    let too_many = send_batch(&server, &over);
    assert_eq!(
        (too_many.status, too_many.error_code().as_str()),
        (400, "InvalidInput")
    );
    assert_eq!(
        server
            .get("/batch()?$filter=PartitionKey%20eq%20'huge'")
            .json()["value"]
            .as_array()
            .unwrap()
            .len(),
        0
    );
    let wrong_table = send_batch(&server, &[insert_op("absent", "p", "a")]);
    assert!(wrong_table.text.contains("TableNotFound"));

    // A lone query is allowed outside a change set.
    let query = format!(
        "--batch_1\r\nContent-Type: application/http\r\nContent-Transfer-Encoding: binary\r\n\r\nGET http://127.0.0.1/{ACCOUNT}{} HTTP/1.1\r\nAccept: application/json;odata=minimalmetadata\r\n\r\n\r\n--batch_1--\r\n",
        row("batch", "p", "a")
    );
    let mut call =
        Call::new("POST", "/$batch").header("content-type", "multipart/mixed; boundary=batch_1");
    call.body = query.into_bytes();
    let reply = server.send(call);
    assert_eq!(reply.status, 202);
    assert_eq!(status_lines(&reply), ["HTTP/1.1 200 OK"]);
    assert!(reply.text.contains(r#""RowKey":"a""#));
    let mut call = Call::new("POST", "/$batch").header("content-type", "text/plain");
    call.body = b"x".to_vec();
    assert_eq!(server.send(call).status, 400);
    server.stop();
}

#[test]
fn acl_and_service_properties_round_trip() {
    let server = Server::start(None);
    server.create_table("acl");
    let empty = server.get("/acl?comp=acl");
    assert_eq!(empty.status, 200);
    assert!(empty.text.contains("<SignedIdentifiers"));
    let policy = "<?xml version=\"1.0\" encoding=\"utf-8\"?><SignedIdentifiers><SignedIdentifier><Id>reader</Id><AccessPolicy><Start>2020-01-01T00:00:00.0000000Z</Start><Expiry>2099-01-01T00:00:00.0000000Z</Expiry><Permission>r</Permission></AccessPolicy></SignedIdentifier></SignedIdentifiers>";
    let mut put = Call::new("PUT", "/acl?comp=acl").header("content-type", "application/xml");
    put.body = policy.as_bytes().to_vec();
    assert_eq!(server.send(put).status, 204);
    let stored = server.get("/acl?comp=acl");
    assert!(
        stored.text.contains("<Id>reader</Id>")
            && stored.text.contains("<Permission>r</Permission>"),
        "{}",
        stored.text
    );
    let mut bad = Call::new("PUT", "/acl?comp=acl").header("content-type", "application/xml");
    bad.body = b"<SignedIdentifiers><SignedIdentifier><Id>a</Id><AccessPolicy><Permission>z</Permission></AccessPolicy></SignedIdentifier></SignedIdentifiers>".to_vec();
    let bad = server.send(bad);
    assert_eq!(
        (bad.status, bad.error_code().as_str()),
        (400, "InvalidXmlDocument")
    );
    assert_eq!(server.get("/nothere?comp=acl").status, 404);
    let mut clear = Call::new("PUT", "/acl?comp=acl").header("content-type", "application/xml");
    clear.body = Vec::new();
    assert_eq!(server.send(clear).status, 204);
    assert!(!server.get("/acl?comp=acl").text.contains("reader"));

    let defaults = server.get("/?restype=service&comp=properties");
    assert_eq!(defaults.status, 200);
    assert!(defaults.text.contains("<HourMetrics>") && defaults.text.contains("<Cors />"));
    let update = "<StorageServiceProperties><Logging><Version>1.0</Version><Read>true</Read><Write>true</Write><Delete>false</Delete><RetentionPolicy><Enabled>true</Enabled><Days>3</Days></RetentionPolicy></Logging></StorageServiceProperties>";
    let mut set = Call::new("PUT", "/?restype=service&comp=properties")
        .header("content-type", "application/xml");
    set.body = update.as_bytes().to_vec();
    assert_eq!(server.send(set).status, 202);
    let after = server.get("/?restype=service&comp=properties").text;
    assert!(after.contains("<Read>true</Read>") && after.contains("<Days>3</Days>"));
    assert!(
        after.contains("<HourMetrics>"),
        "unspecified sections are kept"
    );
    let mut invalid = Call::new("PUT", "/?restype=service&comp=properties")
        .header("content-type", "application/xml");
    invalid.body = b"<StorageServiceProperties><Bogus/></StorageServiceProperties>".to_vec();
    assert_eq!(server.send(invalid).status, 400);
    let stats = server.get("/?restype=service&comp=stats");
    assert!(stats.text.contains("<Status>live</Status>"));
    server.stop();
}

#[test]
fn cors_rules_answer_preflights_and_decorate_responses() {
    let server = Server::start(None);
    let rules = "<StorageServiceProperties><Cors><CorsRule>\
        <AllowedOrigins>http://app.example</AllowedOrigins>\
        <AllowedMethods>GET,OPTIONS</AllowedMethods><MaxAgeInSeconds>120</MaxAgeInSeconds>\
        <ExposedHeaders>x-ms-request-id</ExposedHeaders><AllowedHeaders>x-ms-*,accept</AllowedHeaders>\
        </CorsRule></Cors></StorageServiceProperties>";
    let mut set = Call::new("PUT", "/?restype=service&comp=properties")
        .header("content-type", "application/xml");
    set.body = rules.as_bytes().to_vec();
    assert_eq!(server.send(set).status, 202);
    let mut bad = Call::new("PUT", "/?restype=service&comp=properties")
        .header("content-type", "application/xml");
    bad.body = b"<StorageServiceProperties><Cors><CorsRule><AllowedOrigins>*</AllowedOrigins>\
        <AllowedMethods>FETCH</AllowedMethods><MaxAgeInSeconds>1</MaxAgeInSeconds></CorsRule>\
        </Cors></StorageServiceProperties>"
        .to_vec();
    assert_eq!(server.send(bad).status, 400);

    let preflight = |origin: &'static str, method: &'static str, headers: &'static str| {
        let mut call = Call::new("OPTIONS", "/Tables")
            .header("origin", origin)
            .header("access-control-request-method", method)
            .auth(Auth::None);
        if !headers.is_empty() {
            call = call.header("access-control-request-headers", headers);
        }
        server.send(call)
    };
    let allowed = preflight("http://app.example", "GET", "x-ms-date");
    assert_eq!(allowed.status, 200);
    assert_eq!(
        allowed.header("access-control-allow-origin"),
        Some("http://app.example")
    );
    assert_eq!(allowed.header("access-control-max-age"), Some("120"));
    assert_eq!(
        preflight("http://other.example", "GET", "").error_code(),
        "CorsPreflightFailure"
    );
    assert_eq!(preflight("http://app.example", "DELETE", "").status, 403);
    assert_eq!(
        preflight("http://app.example", "GET", "x-secret").status,
        403
    );
    let missing = server.send(Call::new("OPTIONS", "/Tables").auth(Auth::None));
    assert_eq!(missing.status, 400);
    assert_eq!(missing.error_code(), "MissingRequiredHeader");

    let with_origin =
        server.send(Call::new("GET", "/Tables").header("origin", "http://app.example"));
    assert_eq!(with_origin.status, 200);
    assert_eq!(
        with_origin.header("access-control-allow-origin"),
        Some("http://app.example")
    );
    assert!(
        with_origin
            .header("access-control-expose-headers")
            .is_some()
    );
    let stranger =
        server.send(Call::new("GET", "/Tables").header("origin", "http://other.example"));
    assert!(stranger.header("access-control-allow-origin").is_none());
    server.stop();
}
fn account_sas(
    permissions: &str,
    resource_types: &str,
    start: Option<&str>,
    expiry: &str,
) -> String {
    let (version, services) = ("2023-11-03", "t");
    let sts = format!(
        "{ACCOUNT}\n{permissions}\n{services}\n{resource_types}\n{}\n{expiry}\n\n\n{version}\n\n",
        start.unwrap_or("")
    );
    let mut token = format!(
        "sv={version}&ss={services}&srt={resource_types}&sp={permissions}&se={}",
        encode(expiry)
    );
    if let Some(start) = start {
        token.push_str(&format!("&st={}", encode(start)));
    }
    format!("{token}&sig={}", encode(&sign(&KEY, &sts)))
}

fn service_sas(table: &str, permissions: &str, extra: &[(&str, &str)], expiry: &str) -> String {
    let field = |name: &str| {
        extra
            .iter()
            .find(|(n, _)| *n == name)
            .map_or("", |(_, v)| *v)
    };
    let sts = format!(
        "{permissions}\n\n{expiry}\n/table/{ACCOUNT}/{}\n{}\n\n\n2023-11-03\n{}\n{}\n{}\n{}",
        table.to_ascii_lowercase(),
        field("si"),
        field("spk"),
        field("srk"),
        field("epk"),
        field("erk")
    );
    let mut token = format!("sv=2023-11-03&tn={table}&se={}", encode(expiry));
    if !permissions.is_empty() {
        token.push_str(&format!("&sp={permissions}"));
    }
    for (name, value) in extra {
        token.push_str(&format!("&{name}={}", encode(value)));
    }
    format!("{token}&sig={}", encode(&sign(&KEY, &sts)))
}

fn anonymous(server: &Server, method: &str, target: &str, body: Option<&Value>) -> Reply {
    let mut call = Call::new(method, target).auth(Auth::None);
    if let Some(body) = body {
        call = call.json(body);
    }
    server.send(call)
}

#[test]
fn authentication_modes_and_failures() {
    let server = Server::start(None);
    server.create_table("auth");
    server.insert(
        "auth",
        &json!({ "PartitionKey": "a", "RowKey": "1", "V": 1 }),
    );
    server.insert(
        "auth",
        &json!({ "PartitionKey": "b", "RowKey": "1", "V": 2 }),
    );

    assert_eq!(
        server
            .send(Call::new("GET", "/Tables").auth(Auth::Lite))
            .status,
        200
    );
    let lite_comp = server.send(Call::new("GET", "/auth?comp=acl").auth(Auth::Lite));
    assert_eq!(lite_comp.status, 200, "Lite signs ?comp=");
    for auth in [Auth::WrongKey, Auth::None] {
        let reply = server.send(Call::new("GET", "/Tables").auth(auth));
        assert_eq!(
            (reply.status, reply.error_code().as_str()),
            (403, "AuthenticationFailed")
        );
    }
    let old = SystemTime::now() - Duration::from_secs(3600);
    let mut stale = Call::new("GET", "/Tables");
    stale.date = Some(old);
    assert_eq!(server.send(stale).status, 403);
    let forged = server.send(
        Call::new("GET", "/Tables")
            .auth(Auth::None)
            .header("authorization", "SharedKey testaccount:AAAA"),
    );
    assert_eq!(forged.status, 403);
    let wrong_account = server.send(
        Call::new("GET", "/Tables")
            .auth(Auth::None)
            .header("authorization", "SharedKey otheraccount:AAAA"),
    );
    assert_eq!(wrong_account.status, 403);
    let bearer = server.send(
        Call::new("GET", "/Tables")
            .auth(Auth::None)
            .header("authorization", "Bearer token"),
    );
    assert_eq!(bearer.status, 401);
    assert_eq!(bearer.error_code(), "InvalidAuthenticationInfo");

    // Versions: older and equal are echoed; unknown newer ones are rejected by default.
    let older = server.send(Call::new("GET", "/Tables").header("x-ms-version", "2019-02-02"));
    assert_eq!(
        (older.status, older.header("x-ms-version")),
        (200, Some("2019-02-02"))
    );
    let newer = server.send(Call::new("GET", "/Tables").header("x-ms-version", "2099-01-01"));
    assert_eq!(
        (newer.status, newer.error_code().as_str()),
        (400, "InvalidHeaderValue")
    );
    let garbage = server.send(Call::new("GET", "/Tables").header("x-ms-version", "latest"));
    assert_eq!(garbage.status, 400);

    // Account SAS.
    let expiry = "2099-01-01T00:00:00Z";
    let read_objects = account_sas("r", "o", None, expiry);
    assert_eq!(
        anonymous(&server, "GET", &format!("/auth()?{read_objects}"), None).status,
        200
    );
    assert_eq!(
        anonymous(
            &server,
            "GET",
            &format!("{}?{read_objects}", row("auth", "a", "1")),
            None
        )
        .status,
        200
    );
    let denied = anonymous(
        &server,
        "POST",
        &format!("/auth?{read_objects}"),
        Some(&json!({ "PartitionKey": "z", "RowKey": "1" })),
    );
    assert_eq!(
        (denied.status, denied.error_code().as_str()),
        (403, "AuthorizationFailure")
    );
    assert_eq!(
        anonymous(&server, "GET", &format!("/Tables?{read_objects}"), None).status,
        403
    );
    let tables = account_sas("rwdlacu", "sco", None, expiry);
    assert_eq!(
        anonymous(&server, "GET", &format!("/Tables?{tables}"), None).status,
        200
    );
    assert_eq!(
        anonymous(
            &server,
            "POST",
            &format!("/Tables?{tables}"),
            Some(&json!({ "TableName": "viasas" }))
        )
        .status,
        201
    );
    assert_eq!(
        anonymous(
            &server,
            "DELETE",
            &format!("/Tables('viasas')?{tables}"),
            None
        )
        .status,
        204
    );
    assert_eq!(
        anonymous(
            &server,
            "GET",
            &format!("/?restype=service&comp=properties&{tables}"),
            None
        )
        .status,
        200
    );
    assert_eq!(
        anonymous(&server, "GET", &format!("/auth?comp=acl&{tables}"), None).status,
        403,
        "ACLs need Shared Key"
    );
    let expired = account_sas("r", "o", None, "2001-01-01T00:00:00Z");
    assert_eq!(
        anonymous(&server, "GET", &format!("/auth()?{expired}"), None).status,
        403
    );
    let future = account_sas("r", "o", Some("2098-01-01T00:00:00Z"), expiry);
    assert_eq!(
        anonymous(&server, "GET", &format!("/auth()?{future}"), None).status,
        403
    );
    let forged = read_objects.replace("sp=r", "sp=rwdlacu");
    assert_eq!(
        anonymous(&server, "GET", &format!("/Tables?{forged}"), None).status,
        403
    );
    let both = server.send(Call::new("GET", &format!("/auth()?{read_objects}")));
    assert_eq!(
        both.status, 403,
        "a SAS together with an Authorization header is refused"
    );

    // Service SAS: permission, table, and key-range checks.
    let ranged = service_sas("auth", "rau", &[("spk", "a"), ("epk", "a")], expiry);
    assert_eq!(
        keys(&anonymous(
            &server,
            "GET",
            &format!("/auth()?{ranged}"),
            None
        )),
        ["a/1"]
    );
    assert_eq!(
        anonymous(
            &server,
            "GET",
            &format!("{}?{ranged}", row("auth", "a", "1")),
            None
        )
        .status,
        200
    );
    assert_eq!(
        anonymous(
            &server,
            "GET",
            &format!("{}?{ranged}", row("auth", "b", "1")),
            None
        )
        .status,
        403
    );
    assert_eq!(
        anonymous(
            &server,
            "POST",
            &format!("/auth?{ranged}"),
            Some(&json!({ "PartitionKey": "a", "RowKey": "2" }))
        )
        .status,
        201
    );
    assert_eq!(
        anonymous(
            &server,
            "POST",
            &format!("/auth?{ranged}"),
            Some(&json!({ "PartitionKey": "b", "RowKey": "2" }))
        )
        .status,
        403
    );
    let upsert = server.send(
        Call::new("PUT", &format!("{}?{ranged}", row("auth", "a", "1")))
            .json(&json!({ "V": 9 }))
            .auth(Auth::None),
    );
    assert_eq!(upsert.status, 204, "add plus update permits an upsert");
    let delete = server.send(
        Call::new("DELETE", &format!("{}?{ranged}", row("auth", "a", "1")))
            .header("if-match", "*")
            .auth(Auth::None),
    );
    assert_eq!(delete.status, 403, "no delete permission");
    assert_eq!(
        anonymous(&server, "GET", &format!("/Tables?{ranged}"), None).status,
        403
    );
    assert_eq!(
        anonymous(&server, "GET", &format!("/other()?{ranged}"), None).status,
        403
    );
    let read_only = service_sas("auth", "r", &[], expiry);
    let ro_upsert = server.send(
        Call::new("PUT", &format!("{}?{read_only}", row("auth", "a", "1")))
            .json(&json!({ "V": 9 }))
            .auth(Auth::None),
    );
    assert_eq!(ro_upsert.status, 403);
    let row_range = service_sas(
        "auth",
        "r",
        &[("spk", "a"), ("srk", "1"), ("epk", "a"), ("erk", "1")],
        expiry,
    );
    assert_eq!(
        keys(&anonymous(
            &server,
            "GET",
            &format!("/auth()?{row_range}"),
            None
        )),
        ["a/1"]
    );
    let tampered = ranged.replace("epk=a", "epk=z");
    assert_eq!(
        anonymous(&server, "GET", &format!("/auth()?{tampered}"), None).status,
        403
    );

    // Stored access policy.
    let policy = "<SignedIdentifiers><SignedIdentifier><Id>p1</Id><AccessPolicy><Expiry>2099-01-01T00:00:00Z</Expiry><Permission>r</Permission></AccessPolicy></SignedIdentifier></SignedIdentifiers>";
    let mut put = Call::new("PUT", "/auth?comp=acl").header("content-type", "application/xml");
    put.body = policy.as_bytes().to_vec();
    assert_eq!(server.send(put).status, 204);
    let sts = format!("\n\n\n/table/{ACCOUNT}/auth\np1\n\n\n2023-11-03\n\n\n\n");
    let by_policy = format!(
        "sv=2023-11-03&tn=auth&si=p1&sig={}",
        encode(&sign(&KEY, &sts))
    );
    assert_eq!(
        anonymous(
            &server,
            "GET",
            &format!("{}?{by_policy}", row("auth", "b", "1")),
            None
        )
        .status,
        200
    );
    let write = anonymous(
        &server,
        "POST",
        &format!("/auth?{by_policy}"),
        Some(&json!({ "PartitionKey": "b", "RowKey": "9" })),
    );
    assert_eq!(write.status, 403);
    let unknown = by_policy.replace("si=p1", "si=nope");
    assert_eq!(
        anonymous(
            &server,
            "GET",
            &format!("{}?{unknown}", row("auth", "b", "1")),
            None
        )
        .status,
        403
    );
    let mut clear = Call::new("PUT", "/auth?comp=acl").header("content-type", "application/xml");
    clear.body = b"<SignedIdentifiers />".to_vec();
    server.send(clear);
    assert_eq!(
        anonymous(
            &server,
            "GET",
            &format!("{}?{by_policy}", row("auth", "b", "1")),
            None
        )
        .status,
        403,
        "revoked policy"
    );
    server.stop();
}

#[test]
fn state_survives_restart_with_a_location() {
    let directory = tempfile::tempdir().unwrap();
    let server = Server::start(Some(directory.path()));
    server.create_table("durable");
    server.insert("durable", &json!({ "PartitionKey": "p", "RowKey": "r", "N": 1, "L@odata.type": "Edm.Int64", "L": "5000000000" }));
    let policy =
        "<SignedIdentifiers><SignedIdentifier><Id>keep</Id></SignedIdentifier></SignedIdentifiers>";
    let mut put = Call::new("PUT", "/durable?comp=acl").header("content-type", "application/xml");
    put.body = policy.as_bytes().to_vec();
    assert_eq!(server.send(put).status, 204);
    let etag = server
        .get(&row("durable", "p", "r"))
        .header("etag")
        .unwrap()
        .to_owned();
    let mut set = Call::new("PUT", "/?restype=service&comp=properties")
        .header("content-type", "application/xml");
    set.body = b"<StorageServiceProperties><Cors><CorsRule><AllowedOrigins>*</AllowedOrigins><AllowedMethods>GET</AllowedMethods><MaxAgeInSeconds>5</MaxAgeInSeconds><ExposedHeaders>x</ExposedHeaders><AllowedHeaders>x</AllowedHeaders></CorsRule></Cors></StorageServiceProperties>".to_vec();
    assert_eq!(server.send(set).status, 202);
    server.stop();

    assert!(
        directory
            .path()
            .join("table")
            .join("table.sqlite3")
            .exists()
    );
    let second = Server::start(Some(directory.path()));
    let entity = second.get(&row("durable", "p", "r"));
    assert_eq!(entity.status, 200);
    assert_eq!(
        entity.header("etag"),
        Some(etag.as_str()),
        "ETags are stable across restarts"
    );
    assert_eq!(entity.json()["L"], "5000000000");
    assert!(
        second
            .get("/durable?comp=acl")
            .text
            .contains("<Id>keep</Id>")
    );
    assert!(
        second
            .get("/?restype=service&comp=properties")
            .text
            .contains("<AllowedOrigins>*</AllowedOrigins>")
    );
    // Writes after the restart advance the ETag.
    let merged = second.send(
        Call::new("MERGE", &row("durable", "p", "r"))
            .json(&json!({ "M": 1 }))
            .header("if-match", &etag),
    );
    assert_eq!(merged.status, 204);
    assert_ne!(merged.header("etag"), Some(etag.as_str()));

    // A second process cannot open the same directory.
    let mut command = Command::new(env!("CARGO_BIN_EXE_azuifer"));
    command
        .args([
            "serve",
            "--port",
            "0",
            "--admin-port",
            "0",
            "--services",
            "table",
            "--location",
        ])
        .arg(directory.path())
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null());
    assert!(!command.status().unwrap().success());
    second.stop();
}
