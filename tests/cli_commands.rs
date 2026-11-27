use std::{
    io::{BufRead as _, BufReader, Read as _, Write as _},
    net::TcpListener,
    path::Path,
    process::{Child, Command, Output, Stdio},
};

fn azuifer() -> Command {
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
}

fn run(args: &[&str]) -> Output {
    azuifer().args(args).output().expect("run Azuifer")
}

fn stdout(output: &Output) -> String {
    String::from_utf8_lossy(&output.stdout).into_owned()
}

fn stderr(output: &Output) -> String {
    String::from_utf8_lossy(&output.stderr).into_owned()
}

struct Server {
    child: Child,
    admin: String,
}

impl Server {
    fn start(args: &[&str]) -> Self {
        let mut child = azuifer()
            .args([
                "serve",
                "--port",
                "0",
                "--admin-port",
                "0",
                "--shutdown-on-stdin-eof",
            ])
            .args(args)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::null())
            .spawn()
            .expect("start Azuifer");
        let mut lines = BufReader::new(child.stdout.take().expect("piped stdout")).lines();
        let mut admin = String::new();
        for line in lines.by_ref() {
            let line = line.expect("startup line");
            if let Some(url) = line.strip_prefix("admin_url=") {
                admin = url.to_owned();
                break;
            }
        }
        std::thread::spawn(move || lines.for_each(drop));
        Self { child, admin }
    }
}

impl Drop for Server {
    fn drop(&mut self) {
        drop(self.child.stdin.take());
        let _ = self.child.wait();
    }
}

fn path(path: &Path) -> &str {
    path.to_str().expect("UTF-8 path")
}

#[test]
fn status_reports_a_running_instance() {
    let server = Server::start(&["--in-memory", "--services", "queue,table", "--prometheus"]);
    let output = run(&["status", "--admin-url", &server.admin]);
    assert!(output.status.success(), "{}", stderr(&output));
    let text = stdout(&output);
    assert!(
        text.contains(&format!("Azuifer {} is running", env!("CARGO_PKG_VERSION"))),
        "{text}"
    );
    assert!(text.contains("Storage:   in-memory"), "{text}");
    assert!(
        text.contains("queue  http://127.0.0.1:") && text.contains("table  http://127.0.0.1:"),
        "{text}"
    );
    assert!(!text.contains("blob "), "{text}");
    assert!(
        text.contains(&format!("Metrics:   {}/metrics", server.admin)),
        "{text}"
    );

    let output = run(&["status", "--admin-url", &server.admin, "--json"]);
    let json: serde_json::Value = serde_json::from_str(&stdout(&output)).unwrap();
    assert_eq!(json["services"].as_array().unwrap().len(), 2);
    assert_eq!(json["prometheus"], true);

    let output = run(&["status", "--admin-url", &server.admin, "--ready"]);
    assert!(output.status.success() && output.stdout.is_empty());
}

#[test]
fn status_fails_when_nothing_is_listening() {
    let closed = TcpListener::bind("127.0.0.1:0").unwrap();
    let url = format!("http://{}", closed.local_addr().unwrap());
    drop(closed);
    let output = run(&["status", "--admin-url", &url]);
    assert!(!output.status.success());
    assert!(
        stderr(&output).contains("not reachable"),
        "{}",
        stderr(&output)
    );
    assert!(
        !run(&["status", "--ready", "--admin-url", &url])
            .status
            .success()
    );
}

#[test]
fn doctor_passes_for_in_memory_and_persistent_storage() {
    let output = run(&["doctor", "--in-memory", "--port", "0", "--admin-port", "0"]);
    assert!(
        output.status.success(),
        "{}{}",
        stdout(&output),
        stderr(&output)
    );
    let text = stdout(&output);
    assert!(text.contains("[PASS] Configuration: valid"), "{text}");
    assert!(text.contains("[PASS] Storage: in-memory"), "{text}");

    let dir = tempfile::tempdir().unwrap();
    let data = dir.path().join("data");
    let output = run(&[
        "doctor",
        "--location",
        path(&data),
        "--port",
        "0",
        "--admin-port",
        "0",
    ]);
    assert!(
        output.status.success(),
        "{}{}",
        stdout(&output),
        stderr(&output)
    );
    let text = stdout(&output);
    for expected in [
        "[PASS] Data directory:",
        "[PASS] SQLite WAL:",
        "[PASS] Directory lock:",
        "[PASS] Free disk:",
        "[PASS] Telemetry: no external export is configured",
    ] {
        assert!(text.contains(expected), "missing `{expected}` in:\n{text}");
    }
    assert!(!data.exists(), "doctor must not create the data directory");
    assert_eq!(
        std::fs::read_dir(dir.path()).unwrap().count(),
        0,
        "probe files are removed"
    );
}

#[test]
fn doctor_fails_on_invalid_configuration() {
    let output = run(&["doctor", "--in-memory", "--services", "nonsense"]);
    assert!(!output.status.success());
    assert!(
        stdout(&output).contains("[FAIL] Configuration:"),
        "{}",
        stdout(&output)
    );
}

#[test]
fn doctor_fails_when_a_port_is_taken() {
    let taken = TcpListener::bind("127.0.0.1:0").unwrap();
    let port = taken.local_addr().unwrap().port().to_string();
    let output = run(&[
        "doctor",
        "--in-memory",
        "--services",
        "blob",
        "--port",
        &port,
        "--admin-port",
        "0",
    ]);
    assert!(!output.status.success());
    let text = stdout(&output);
    assert!(text.contains("[FAIL] Port: blob"), "{text}");
    assert!(text.contains("already in use"), "{text}");
}

#[test]
fn doctor_and_reset_see_the_directory_lock_of_a_running_instance() {
    let dir = tempfile::tempdir().unwrap();
    let data = dir.path().join("data");
    let _server = Server::start(&["--location", path(&data), "--services", "blob"]);

    let output = run(&[
        "doctor",
        "--location",
        path(&data),
        "--services",
        "blob",
        "--port",
        "0",
        "--admin-port",
        "0",
    ]);
    assert!(!output.status.success());
    assert!(
        stdout(&output).contains("[FAIL] Directory lock:"),
        "{}",
        stdout(&output)
    );

    let output = run(&["reset", "--location", path(&data), "--yes"]);
    assert!(!output.status.success());
    assert!(
        stderr(&output).contains("held by a running Azuifer process"),
        "{}",
        stderr(&output)
    );
    assert!(
        data.join("metadata.sqlite3").exists(),
        "a locked directory is left intact"
    );
}

#[test]
fn doctor_fails_when_the_location_is_not_a_directory() {
    let dir = tempfile::tempdir().unwrap();
    let file = dir.path().join("occupied");
    std::fs::write(&file, b"x").unwrap();
    let output = run(&[
        "doctor",
        "--location",
        path(&file),
        "--port",
        "0",
        "--admin-port",
        "0",
    ]);
    assert!(!output.status.success());
    assert!(
        stdout(&output).contains("[FAIL] Storage:"),
        "{}",
        stdout(&output)
    );
}

#[test]
fn reset_requires_confirmation_then_removes_only_emulator_state() {
    let dir = tempfile::tempdir().unwrap();
    let data = dir.path().join("data");
    drop(Server::start(&["--location", path(&data)]));
    std::fs::write(data.join("notes.txt"), b"mine").unwrap();
    assert!(data.join("metadata.sqlite3").exists());
    assert!(data.join("queue").is_dir() && data.join("table").is_dir());

    let output = run(&["reset", "--location", path(&data)]);
    assert!(!output.status.success());
    assert!(stderr(&output).contains("--yes"), "{}", stderr(&output));
    assert!(
        data.join("metadata.sqlite3").exists(),
        "nothing is deleted without --yes"
    );

    let output = run(&["reset", "--location", path(&data), "--yes"]);
    assert!(output.status.success(), "{}", stderr(&output));
    let mut left: Vec<_> = std::fs::read_dir(&data)
        .unwrap()
        .map(|entry| entry.unwrap().file_name().into_string().unwrap())
        .collect();
    left.sort();
    assert_eq!(left, ["notes.txt"]);

    let output = run(&["reset", "--location", path(&data), "--yes"]);
    assert!(output.status.success());
    assert!(
        stdout(&output).contains("No emulator state"),
        "{}",
        stdout(&output)
    );
}

#[test]
fn reset_in_memory_mode_has_nothing_to_delete() {
    let output = run(&["reset", "--in-memory", "--yes"]);
    assert!(output.status.success());
    assert!(
        stdout(&output).contains("Nothing persists"),
        "{}",
        stdout(&output)
    );
}

/// A stand-in admin listener: answers each request with the canned reply for its path, and
/// the first reply in `replies` named `*` for any other.
fn fake_admin(replies: &[(&'static str, &'static str)]) -> String {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let url = format!("http://{}", listener.local_addr().unwrap());
    let replies = replies.to_vec();
    std::thread::spawn(move || {
        for stream in listener.incoming() {
            let Ok(mut stream) = stream else { return };
            // The client writes its request in pieces: read it all before answering, or
            // closing on unread data would reset the connection.
            let mut request = Vec::new();
            let mut chunk = [0; 256];
            while !request.windows(4).any(|window| window == b"\r\n\r\n") {
                match stream.read(&mut chunk) {
                    Ok(0) | Err(_) => break,
                    Ok(read) => request.extend_from_slice(&chunk[..read]),
                }
            }
            let head = String::from_utf8_lossy(&request);
            let target = head.split_whitespace().nth(1).unwrap_or("").to_owned();
            let reply = replies
                .iter()
                .find(|(path, _)| *path == target)
                .or_else(|| replies.iter().find(|(path, _)| *path == "*"));
            if let Some((_, reply)) = reply {
                let _ = stream.write_all(reply.as_bytes());
            }
        }
    });
    url
}

fn http(status: &str, body: &str) -> &'static str {
    Box::leak(
        format!(
            "HTTP/1.0 {status}\r\nContent-Length: {}\r\nContent-Type: text/plain\r\n\r\n{body}",
            body.len()
        )
        .into_boxed_str(),
    )
}

#[test]
fn status_names_what_is_wrong_with_an_admin_listener_that_answers_badly() {
    let unhealthy = fake_admin(&[("*", http("503 Service Unavailable", "starting"))]);
    let output = run(&["status", "--admin-url", &unhealthy]);
    assert!(!output.status.success());
    assert!(
        stderr(&output).contains(&format!("{unhealthy}/healthz returned HTTP 503")),
        "{}",
        stderr(&output)
    );

    let no_status = fake_admin(&[
        ("/healthz", http("200 OK", "ok")),
        ("*", http("500 Internal Server Error", "boom")),
    ]);
    let output = run(&["status", "--admin-url", &no_status]);
    assert!(
        stderr(&output).contains("/status returned HTTP 500"),
        "{}",
        stderr(&output)
    );

    let not_json = fake_admin(&[("*", http("200 OK", "not json"))]);
    let output = run(&["status", "--admin-url", &not_json]);
    assert!(!output.status.success());
    assert!(
        stderr(&output).contains("unexpected /status response"),
        "{}",
        stderr(&output)
    );
    let output = run(&["status", "--admin-url", &not_json, "--json"]);
    assert_eq!(
        stdout(&output).trim(),
        "not json",
        "--json prints the body as sent"
    );

    let not_http = fake_admin(&[("*", "garbage with no header terminator")]);
    let output = run(&["status", "--admin-url", &not_http]);
    assert!(!output.status.success());
    assert!(
        stderr(&output).contains("malformed admin response"),
        "{}",
        stderr(&output)
    );
    let no_code = fake_admin(&[("*", "HTTP/1.0\r\n\r\nbody")]);
    let output = run(&["status", "--admin-url", &no_code]);
    assert!(
        stderr(&output).contains("malformed admin status line"),
        "{}",
        stderr(&output)
    );

    let starting = fake_admin(&[("*", http("200 OK", "starting"))]);
    let output = run(&["status", "--admin-url", &starting, "--ready"]);
    assert!(
        stderr(&output).contains("is not ready"),
        "a 200 that does not say ready is not ready: {}",
        stderr(&output)
    );

    let output = run(&["status", "--admin-url", "https://127.0.0.1:1"]);
    assert!(!output.status.success());
    assert!(
        stderr(&output).contains("must start with http://"),
        "{}",
        stderr(&output)
    );
}

#[test]
fn status_reports_storage_exporters_and_a_long_uptime() {
    let body = r#"{"version":"9.9.9","uptime_seconds":7384,"storage":"persistent",
        "location":"/var/lib/azuifer","services":[{"name":"blob","url":"http://127.0.0.1:1"}],
        "admin_url":"http://127.0.0.1:2","prometheus":false,"otlp":true}"#;
    let admin = fake_admin(&[("*", http("200 OK", body))]);
    let output = run(&["status", "--admin-url", &admin]);
    assert!(output.status.success(), "{}", stderr(&output));
    let text = stdout(&output);
    assert!(
        text.contains("Azuifer 9.9.9 is running at http://127.0.0.1:2 (up 2h 3m 4s)"),
        "{text}"
    );
    assert!(
        text.contains("Storage:   persistent (/var/lib/azuifer)"),
        "{text}"
    );
    assert!(
        text.contains("OTLP:      exporting traces and metrics"),
        "{text}"
    );
    assert!(!text.contains("Metrics:"), "{text}");
}

#[test]
fn doctor_recognises_the_running_instance_it_is_asked_about() {
    let dir = tempfile::tempdir().unwrap();
    let data = dir.path().join("data");
    let server = Server::start(&["--location", path(&data), "--services", "blob"]);
    let admin_port = server.admin.rsplit(':').next().unwrap().to_owned();

    let output = run(&[
        "doctor",
        "--location",
        path(&data),
        "--services",
        "blob",
        "--port",
        "0",
        "--admin-port",
        &admin_port,
    ]);
    let text = stdout(&output);
    assert!(output.status.success(), "{text}{}", stderr(&output));
    assert!(
        text.contains("is served by the running Azuifer instance"),
        "{text}"
    );
    assert!(
        text.contains("[PASS] Directory lock: held by the running Azuifer instance"),
        "{text}"
    );
}

#[test]
fn doctor_plans_a_missing_data_directory_and_reports_the_telemetry_transport() {
    let dir = tempfile::tempdir().unwrap();
    let data = dir.path().join("a").join("b");
    for (protocol, label) in [("grpc", "OTLP/gRPC"), ("http", "OTLP/HTTP")] {
        let output = run(&[
            "doctor",
            "--location",
            path(&data),
            "--port",
            "0",
            "--admin-port",
            "0",
            "--otlp-endpoint",
            "http://127.0.0.1:1",
            "--otlp-protocol",
            protocol,
        ]);
        let text = stdout(&output);
        assert!(output.status.success(), "{text}{}", stderr(&output));
        assert!(
            text.contains(&format!(
                "[PASS] Telemetry: {label} export is configured; the collector is not contacted by doctor"
            )),
            "{text}"
        );
        assert!(
            text.contains(&format!(
                "(it will be created under {})",
                dir.path().display()
            )),
            "{text}"
        );
    }
    assert!(!data.exists());
}

#[cfg(unix)]
#[test]
fn reset_removes_a_symlinked_state_entry_without_following_it() {
    let dir = tempfile::tempdir().unwrap();
    let outside = dir.path().join("outside");
    std::fs::create_dir_all(&outside).unwrap();
    std::fs::write(outside.join("keep.txt"), b"precious").unwrap();
    let data = dir.path().join("data");
    std::fs::create_dir_all(&data).unwrap();
    std::os::unix::fs::symlink(&outside, data.join("content")).unwrap();
    std::fs::write(data.join("metadata.sqlite3"), b"x").unwrap();

    let output = run(&["reset", "--location", path(&data), "--yes"]);
    assert!(output.status.success(), "{}", stderr(&output));
    assert!(data.join("content").symlink_metadata().is_err());
    assert!(!data.join("metadata.sqlite3").exists());
    assert_eq!(
        std::fs::read(outside.join("keep.txt")).unwrap(),
        b"precious",
        "the link is removed, not what it points at"
    );
}
