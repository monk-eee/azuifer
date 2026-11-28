//! The operational commands: `azuifer status`, `azuifer doctor`, and `azuifer reset`.

use crate::{
    admin::Status,
    config::{Config, Options, Service},
};
use anyhow::{Context as _, Result, bail, ensure};
use std::{
    fs::{self, OpenOptions, TryLockError},
    io::{Read as _, Write as _},
    net::{SocketAddr, TcpListener, TcpStream, ToSocketAddrs as _},
    path::{Path, PathBuf},
    time::Duration,
};

const GIB: u64 = 1024 * 1024 * 1024;
const MIB: u64 = 1024 * 1024;
type LockFile = (&'static str, &'static [&'static str]);
/// Lock files taken by the services that persist state, relative to the location.
const LOCK_FILES: [LockFile; 4] = [
    ("azuifer.lock", &["blob", "dfs"]),
    ("queue/queue.lock", &["queue"]),
    ("table/table.lock", &["table"]),
    ("file/azuifer.lock", &["file"]),
];
/// Everything Azuifer writes directly under the location. Other files are never touched.
const STATE_ENTRIES: [&str; 8] = [
    "azuifer.lock",
    "metadata.sqlite3",
    "metadata.sqlite3-wal",
    "metadata.sqlite3-shm",
    "content",
    "queue",
    "table",
    "file",
];

fn http_get(base: &str, path: &str) -> Result<(u16, String)> {
    let authority = base
        .strip_prefix("http://")
        .context("the admin URL must start with http://")?
        .trim_end_matches('/');
    let target = if authority.contains(':') {
        authority.to_owned()
    } else {
        format!("{authority}:80")
    };
    let address = target
        .to_socket_addrs()
        .with_context(|| format!("invalid admin address `{authority}`"))?
        .next()
        .context("the admin address did not resolve")?;
    let timeout = Duration::from_secs(3);
    let mut stream = TcpStream::connect_timeout(&address, timeout)?;
    stream.set_read_timeout(Some(timeout))?;
    stream.set_write_timeout(Some(timeout))?;
    write!(
        stream,
        "GET {path} HTTP/1.0\r\nHost: {authority}\r\nConnection: close\r\n\r\n"
    )?;
    let mut response = String::new();
    stream.read_to_string(&mut response)?;
    let (head, body) = response
        .split_once("\r\n\r\n")
        .context("malformed admin response")?;
    let status = head
        .split_whitespace()
        .nth(1)
        .and_then(|code| code.parse().ok())
        .context("malformed admin status line")?;
    Ok((status, body.to_owned()))
}

pub(crate) fn status(admin_url: &str, json: bool, ready: bool) -> Result<()> {
    let unreachable = |error: &dyn std::fmt::Display| {
        anyhow::anyhow!("Azuifer is not reachable at {admin_url}: {error}")
    };
    if ready {
        let (code, body) = http_get(admin_url, "/readyz").map_err(|error| unreachable(&error))?;
        ensure!(
            code == 200 && body.trim() == "ready",
            "Azuifer is not ready at {admin_url}"
        );
        return Ok(());
    }
    let (code, _) = http_get(admin_url, "/healthz").map_err(|error| unreachable(&error))?;
    ensure!(code == 200, "{admin_url}/healthz returned HTTP {code}");
    let (code, body) = http_get(admin_url, "/status").map_err(|error| unreachable(&error))?;
    ensure!(code == 200, "{admin_url}/status returned HTTP {code}");
    if json {
        println!("{}", body.trim_end());
        return Ok(());
    }
    let status: Status = serde_json::from_str(&body).context("unexpected /status response")?;
    println!(
        "Azuifer {} is running at {} (up {})",
        status.version,
        status.admin_url,
        uptime(status.uptime_seconds)
    );
    match &status.location {
        Some(location) => println!("Storage:   persistent ({location})"),
        None => println!("Storage:   in-memory"),
    }
    println!("Services:");
    for service in &status.services {
        println!("  {:<6} {}", service.name, service.url);
    }
    if status.prometheus {
        println!("Metrics:   {}/metrics", status.admin_url);
    }
    if status.otlp {
        println!("OTLP:      exporting traces and metrics");
    }
    if let Some(compatibility) = &status.compatibility {
        let ignored: Vec<&str> = compatibility
            .ignored_headers
            .iter()
            .chain(&compatibility.ignored_query_parameters)
            .map(String::as_str)
            .collect();
        if ignored.is_empty() {
            println!("Compat:    {}", compatibility.mode);
        } else {
            println!(
                "Compat:    {} (ignores unknown {})",
                compatibility.mode,
                ignored.join(", ")
            );
        }
    }
    Ok(())
}

fn uptime(seconds: u64) -> String {
    let (hours, minutes, seconds) = (seconds / 3600, seconds / 60 % 60, seconds % 60);
    match (hours, minutes) {
        (0, 0) => format!("{seconds}s"),
        (0, _) => format!("{minutes}m {seconds}s"),
        _ => format!("{hours}h {minutes}m {seconds}s"),
    }
}

#[derive(Clone, Copy, Eq, PartialEq)]
enum Outcome {
    Pass,
    Warn,
    Fail,
}

#[derive(Default)]
struct Report {
    passed: usize,
    warned: usize,
    failed: usize,
}

impl Report {
    fn add(&mut self, outcome: Outcome, name: &str, detail: impl std::fmt::Display) {
        let label = match outcome {
            Outcome::Pass => {
                self.passed += 1;
                "PASS"
            }
            Outcome::Warn => {
                self.warned += 1;
                "WARN"
            }
            Outcome::Fail => {
                self.failed += 1;
                "FAIL"
            }
        };
        println!("[{label}] {name}: {detail}");
    }
}

pub(crate) fn doctor(options: Options) -> Result<()> {
    let mut report = Report::default();
    match Config::load(options) {
        Ok(config) => {
            report.add(Outcome::Pass, "Configuration", "valid");
            let running = running_instance(&config);
            check_ports(&config, running.as_ref(), &mut report);
            check_storage(&config, running.as_ref(), &mut report);
            check_telemetry(&config, &mut report);
            check_container(&config, &mut report);
        }
        Err(error) => report.add(Outcome::Fail, "Configuration", format!("{error:#}")),
    }
    println!(
        "{} passed, {} warnings, {} failed",
        report.passed, report.warned, report.failed
    );
    ensure!(report.failed == 0, "{} check(s) failed", report.failed);
    Ok(())
}

fn probe_address(address: SocketAddr) -> String {
    if address.ip().is_unspecified() {
        format!("http://127.0.0.1:{}", address.port())
    } else {
        format!("http://{address}")
    }
}

/// Reads the instance's actual listeners and data location, not just its health.
fn running_instance(config: &Config) -> Option<Status> {
    if config.admin.port() == 0 {
        return None;
    }
    let (200, body) = http_get(&probe_address(config.admin), "/status").ok()? else {
        return None;
    };
    let status: Status = serde_json::from_str(&body).ok()?;
    (status.admin_url == format!("http://{}", config.admin)).then_some(status)
}

fn check_ports(config: &Config, running: Option<&Status>, report: &mut Report) {
    let listeners = Service::ALL
        .into_iter()
        .filter(|service| config.services.contains(service))
        .map(|service| {
            let address = match service {
                Service::Blob => config.blob,
                Service::Queue => config.queue,
                Service::Table => config.table,
                Service::Dfs => config.dfs,
                Service::File => config.file,
            };
            (service.name(), address)
        })
        .chain([("admin", config.admin)]);
    for (name, address) in listeners {
        if address.port() == 0 {
            report.add(
                Outcome::Pass,
                "Port",
                format!("{name} uses an ephemeral port"),
            );
            continue;
        }
        match TcpListener::bind(address) {
            Ok(_) => report.add(Outcome::Pass, "Port", format!("{name} {address} is free")),
            Err(error)
                if error.kind() == std::io::ErrorKind::AddrInUse
                    && running.is_some_and(|status| {
                        name == "admin"
                            || status.services.iter().any(|listener| {
                                listener.name == name
                                    && listener.url == format!("{}://{address}", config.scheme())
                            })
                    }) =>
            {
                report.add(
                    Outcome::Pass,
                    "Port",
                    format!("{name} {address} is served by the running Azuifer instance"),
                )
            }
            Err(error) if error.kind() == std::io::ErrorKind::AddrInUse => report.add(
                Outcome::Fail,
                "Port",
                format!(
                    "{name} {address} is already in use by another process; choose another port or stop it"
                ),
            ),
            Err(error) => report.add(
                Outcome::Fail,
                "Port",
                format!("{name} {address} cannot be bound: {error}"),
            ),
        }
    }
}

fn nearest_existing(path: &Path) -> &Path {
    path.ancestors()
        .find(|ancestor| !ancestor.as_os_str().is_empty() && ancestor.exists())
        .unwrap_or_else(|| Path::new("."))
}

/// Paths of the lock files that are currently held by another process.
fn held_locks(location: &Path) -> Result<Vec<LockFile>> {
    let mut held = Vec::new();
    for (name, services) in LOCK_FILES {
        let path = location.join(name);
        let file = match OpenOptions::new().read(true).write(true).open(&path) {
            Ok(file) => file,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => continue,
            Err(error) => {
                return Err(error).with_context(|| format!("could not open {}", path.display()));
            }
        };
        match file.try_lock() {
            Ok(()) => {}
            Err(TryLockError::WouldBlock) => held.push((name, services)),
            Err(TryLockError::Error(error)) => {
                return Err(error).with_context(|| format!("could not lock {}", path.display()));
            }
        }
    }
    Ok(held)
}

fn check_storage(config: &Config, running: Option<&Status>, report: &mut Report) {
    let Some(location) = &config.location else {
        report.add(
            Outcome::Pass,
            "Storage",
            "in-memory mode; nothing is written to disk and state is lost on exit",
        );
        return;
    };
    if location.exists() && !location.is_dir() {
        report.add(
            Outcome::Fail,
            "Storage",
            format!("{} exists and is not a directory", location.display()),
        );
        return;
    }
    let probe = nearest_existing(location);
    match tempfile::Builder::new()
        .prefix(".azuifer-doctor-")
        .tempdir_in(probe)
    {
        Ok(directory) => {
            let note = if probe == location.as_path() {
                String::new()
            } else {
                format!(" (it will be created under {})", probe.display())
            };
            report.add(
                Outcome::Pass,
                "Data directory",
                format!("{} is writable{note}", location.display()),
            );
            check_wal(directory.path(), report);
        }
        Err(error) => report.add(
            Outcome::Fail,
            "Data directory",
            format!(
                "{} is not writable: {error}. In a container, the volume must be writable by the image user (65532)",
                probe.display()
            ),
        ),
    }
    check_lock(location, running, report);
    check_stores(location, report);
    check_space(probe, report);
}

/// Looks inside each store's directory for what would stop it opening: links, a database from
/// a newer release, or corruption.
fn check_stores(location: &Path, report: &mut Report) {
    for layout in crate::store::guard::layouts(location) {
        let name = format!("{} store", layout.store);
        match crate::store::guard::inspect(&layout) {
            Ok(None) => {}
            Ok(Some(note)) => report.add(Outcome::Pass, &name, note),
            Err(error) => report.add(Outcome::Fail, &name, format!("{error:#}")),
        }
    }
}

fn check_wal(directory: &Path, report: &mut Report) {
    let journal = rusqlite::Connection::open(directory.join("probe.sqlite3"))
        .and_then(|db| db.query_row("PRAGMA journal_mode=WAL", [], |row| row.get::<_, String>(0)));
    match journal {
        Ok(mode) if mode.eq_ignore_ascii_case("wal") => {
            report.add(Outcome::Pass, "SQLite WAL", "supported on this file system");
        }
        Ok(mode) => report.add(
            Outcome::Fail,
            "SQLite WAL",
            format!("the file system selected journal mode `{mode}`; use a local disk or volume, not a network share"),
        ),
        Err(error) => report.add(Outcome::Fail, "SQLite WAL", format!("probe failed: {error}")),
    }
}

fn check_lock(location: &Path, running: Option<&Status>, report: &mut Report) {
    match held_locks(location) {
        Ok(held) if held.is_empty() => {
            report.add(
                Outcome::Pass,
                "Directory lock",
                "not held by another process",
            );
        }
        Ok(held) => {
            let owner = running.filter(|instance| {
                let Some(path) = instance.location.as_deref() else {
                    return false;
                };
                location.canonicalize().ok().is_some_and(|location| {
                    Path::new(path)
                        .canonicalize()
                        .is_ok_and(|path| path == location)
                })
            });
            let foreign = held.into_iter().find(|(_, services)| {
                owner.is_none_or(|instance| {
                    !instance
                        .services
                        .iter()
                        .any(|service| services.contains(&service.name.as_str()))
                })
            });
            if let Some((name, _)) = foreign {
                report.add(
                    Outcome::Fail,
                    "Directory lock",
                    format!(
                        "{} is held by another process; stop the other Azuifer instance or use a different --location",
                        location.join(name).display()
                    ),
                );
            } else {
                report.add(
                    Outcome::Pass,
                    "Directory lock",
                    "held by the running Azuifer instance",
                );
            }
        }
        Err(error) => report.add(Outcome::Fail, "Directory lock", format!("{error:#}")),
    }
}

fn check_space(path: &Path, report: &mut Report) {
    match fs4::available_space(path) {
        Ok(free) if free < 100 * MIB => report.add(
            Outcome::Fail,
            "Free disk",
            format!("only {} MiB free under {}", free / MIB, path.display()),
        ),
        Ok(free) if free < GIB => report.add(
            Outcome::Warn,
            "Free disk",
            format!("{} MiB free; large blobs may not fit", free / MIB),
        ),
        Ok(free) => report.add(
            Outcome::Pass,
            "Free disk",
            format!("{} GiB free", free / GIB),
        ),
        Err(error) => report.add(
            Outcome::Warn,
            "Free disk",
            format!("could not be determined: {error}"),
        ),
    }
}

fn check_telemetry(config: &Config, report: &mut Report) {
    let telemetry = &config.telemetry;
    match &telemetry.otlp {
        Some(otlp) => report.add(
            Outcome::Pass,
            "Telemetry",
            format!(
                "OTLP/{} export is configured; the collector is not contacted by doctor",
                match otlp.protocol {
                    crate::telemetry::OtlpProtocol::Grpc => "gRPC",
                    crate::telemetry::OtlpProtocol::Http => "HTTP",
                }
            ),
        ),
        None => report.add(
            Outcome::Pass,
            "Telemetry",
            "no external export is configured",
        ),
    }
}

fn in_container() -> bool {
    Path::new("/.dockerenv").exists() || Path::new("/run/.containerenv").exists()
}

fn is_mount_point(path: &Path) -> bool {
    let Ok(path) = path.canonicalize() else {
        return false;
    };
    fs::read_to_string("/proc/self/mountinfo")
        .map(|mounts| {
            mounts
                .lines()
                .filter_map(|line| line.split_whitespace().nth(4))
                .any(|mount| Path::new(mount) == path)
        })
        .unwrap_or(false)
}

fn check_container(config: &Config, report: &mut Report) {
    if !in_container() {
        return;
    }
    if config.admin.ip().is_loopback() {
        report.add(
            Outcome::Warn,
            "Container",
            "listeners bind to loopback, so published ports are unreachable; start with `serve --bind 0.0.0.0` and set AZUIFER_ACCOUNT_KEY",
        );
    } else {
        report.add(
            Outcome::Pass,
            "Container",
            "listeners bind to a non-loopback address",
        );
    }
    match &config.location {
        Some(location) if !is_mount_point(location) => report.add(
            Outcome::Warn,
            "Container storage",
            format!(
                "{} is not a mounted volume, so state is lost when the container is removed",
                location.display()
            ),
        ),
        Some(location) => report.add(
            Outcome::Pass,
            "Container storage",
            format!("{} is a mounted volume", location.display()),
        ),
        None => {}
    }
}

pub(crate) fn reset(config: &Config, yes: bool) -> Result<()> {
    let Some(location) = &config.location else {
        println!("Storage is in memory. Nothing persists, so there is nothing to reset.");
        return Ok(());
    };
    let present: Vec<PathBuf> = STATE_ENTRIES
        .iter()
        .map(|name| location.join(name))
        .filter(|path| path.symlink_metadata().is_ok())
        .collect();
    if present.is_empty() {
        println!("No emulator state under {}.", location.display());
        return Ok(());
    }
    let mut locks = Vec::new();
    for (name, _) in LOCK_FILES {
        let path = location.join(name);
        if path.symlink_metadata().is_err() {
            continue;
        }
        let file = OpenOptions::new()
            .read(true)
            .write(true)
            .open(&path)
            .with_context(|| format!("could not open {}", path.display()))?;
        match file.try_lock() {
            Ok(()) => locks.push((path, file)),
            Err(TryLockError::WouldBlock) => bail!(
                "{} is held by a running Azuifer process; stop it before resetting",
                path.display()
            ),
            Err(TryLockError::Error(error)) => {
                return Err(error).with_context(|| format!("could not lock {}", path.display()));
            }
        }
    }
    ensure!(
        yes,
        "reset deletes all emulator state under {}; rerun with --yes to confirm",
        location.display()
    );
    let kept: Vec<PathBuf> = locks.iter().map(|(path, _)| path.clone()).collect();
    for path in &present {
        remove_tree(path, &kept)?;
    }
    drop(locks);
    for path in &present {
        remove_tree(path, &[])?;
    }
    println!("Removed emulator state under {}.", location.display());
    Ok(())
}

/// Deletes `path` recursively, except the `kept` files (and the directories holding them).
fn remove_tree(path: &Path, kept: &[PathBuf]) -> Result<()> {
    let removing =
        |error: std::io::Error| anyhow::anyhow!("could not remove {}: {error}", path.display());
    let metadata = match fs::symlink_metadata(path) {
        Ok(metadata) => metadata,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(()),
        Err(error) => return Err(removing(error)),
    };
    if metadata.is_dir() {
        for entry in fs::read_dir(path).map_err(removing)? {
            remove_tree(&entry.map_err(removing)?.path(), kept)?;
        }
        if !kept.iter().any(|keep| keep.starts_with(path)) {
            fs::remove_dir(path).map_err(removing)?;
        }
    } else if !kept.iter().any(|keep| keep == path) {
        fs::remove_file(path)
            .or_else(|_| fs::remove_dir(path))
            .map_err(removing)?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs::File;

    #[test]
    fn uptime_is_human_readable() {
        assert_eq!(uptime(5), "5s");
        assert_eq!(uptime(125), "2m 5s");
        assert_eq!(uptime(3725), "1h 2m 5s");
    }

    #[test]
    fn remove_tree_keeps_locked_files_until_released() {
        let dir = tempfile::tempdir().unwrap();
        let queue = dir.path().join("queue");
        fs::create_dir_all(queue.join("nested")).unwrap();
        fs::write(queue.join("queue.sqlite3"), b"x").unwrap();
        fs::write(queue.join("nested").join("f"), b"x").unwrap();
        let lock = queue.join("queue.lock");
        let file = File::create(&lock).unwrap();
        remove_tree(&queue, std::slice::from_ref(&lock)).unwrap();
        assert!(lock.exists() && !queue.join("nested").exists());
        drop(file);
        remove_tree(&queue, &[]).unwrap();
        assert!(!queue.exists());
    }
}
