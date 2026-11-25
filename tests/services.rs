use reqwest::blocking::Client;
use std::{
    collections::HashMap,
    io::{BufRead as _, BufReader},
    process::{Child, Command, Stdio},
    time::Duration,
};

struct Server {
    child: Child,
    urls: HashMap<String, String>,
}

impl Server {
    fn start(services: Option<&str>) -> Self {
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
        command.args([
            "serve",
            "--port",
            "0",
            "--admin-port",
            "0",
            "--in-memory",
            "--shutdown-on-stdin-eof",
        ]);
        if let Some(services) = services {
            command.args(["--services", services]);
        }
        let mut child = command
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .spawn()
            .expect("start Azuifer");
        // Lines are read on this thread, so it never outlives the child's stdout.
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
        // Keep draining so the server never fails writing to a closed pipe.
        std::thread::spawn(move || lines.for_each(drop));
        Self { child, urls }
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

#[test]
fn every_enabled_service_listens_on_its_own_port() {
    let server = Server::start(None);
    let mut names: Vec<_> = server.urls.keys().map(String::as_str).collect();
    names.sort_unstable();
    assert_eq!(names, ["admin", "blob", "dfs", "file", "queue", "table"]);
    let mut ports: Vec<_> = server.urls.values().collect();
    ports.sort_unstable();
    ports.dedup();
    assert_eq!(ports.len(), 6, "each listener has its own address");

    let client = client();
    let queue = client
        .get(format!(
            "{}/devstoreaccount1?comp=list",
            server.urls["queue"]
        ))
        .send()
        .unwrap();
    assert_eq!(queue.status(), 403, "Queue rejects anonymous requests");
    assert_eq!(queue.headers()["x-ms-error-code"], "AuthenticationFailed");
    for name in ["table", "file"] {
        let response = client
            .get(format!("{}/devstoreaccount1", server.urls[name]))
            .send()
            .unwrap();
        assert_eq!(response.status(), 501, "{name}");
        assert_eq!(response.headers()["x-ms-error-code"], "NotImplemented");
        let json = response.headers()["content-type"]
            .to_str()
            .unwrap()
            .contains("json");
        assert_eq!(json, name == "table", "{name} error format");
    }
    let dfs = client
        .get(format!(
            "{}/devstoreaccount1?resource=account",
            server.urls["dfs"]
        ))
        .header("x-ms-version", "2023-11-03")
        .send()
        .unwrap();
    assert_eq!(dfs.status(), 403);
    assert_eq!(dfs.headers()["x-ms-error-code"], "AuthorizationFailure");
    let blob = client
        .get(format!("{}/devstoreaccount1", server.urls["blob"]))
        .send()
        .unwrap();
    assert!(
        blob.status().is_client_error(),
        "Blob requires a version and auth"
    );
}

#[test]
fn disabled_services_are_not_started() {
    let server = Server::start(Some("queue"));
    let mut names: Vec<_> = server.urls.keys().map(String::as_str).collect();
    names.sort_unstable();
    assert_eq!(names, ["admin", "queue"]);
}
