use super::{CLIENTS, Method, Reply, Server, race};
use std::{collections::BTreeSet, fs};

fn tags<'a>(xml: &'a str, tag: &str) -> Vec<&'a str> {
    let open = format!("<{tag}>");
    let close = format!("</{tag}>");
    xml.split(&open)
        .skip(1)
        .map(|part| part.split_once(&close).unwrap().0)
        .collect()
}

fn create_file(server: &Server, path: &str, len: usize) {
    server
        .send(
            Method::PUT,
            path,
            &[
                ("x-ms-type", "file"),
                ("x-ms-content-length", &len.to_string()),
            ],
            b"",
        )
        .status(201);
}

fn put_range(server: &Server, path: &str, start: usize, data: &[u8]) -> Reply {
    let range = format!("bytes={start}-{}", start + data.len() - 1);
    server.send(
        Method::PUT,
        &format!("{path}?comp=range"),
        &[("x-ms-write", "update"), ("x-ms-range", &range)],
        data,
    )
}

fn usage(server: &Server, share: &str) -> usize {
    let reply = server
        .send(
            Method::GET,
            &format!("{share}?restype=share&comp=stats"),
            &[],
            b"",
        )
        .status(200);
    let bytes = tags(reply.text(), "ShareUsageBytes");
    assert_eq!(bytes.len(), 1);
    bytes[0].parse().unwrap()
}

fn rename(server: &Server, source: &str, target: &str) -> Reply {
    server.send(
        Method::PUT,
        &format!("{target}?comp=rename"),
        &[("x-ms-file-rename-source", &server.url(source))],
        b"",
    )
}

fn hard_link(server: &Server, name: &str, target: &str) -> Reply {
    server.send(
        Method::PUT,
        &format!("/links/{name}?restype=hardlink"),
        &[("x-ms-type", "file"), ("x-ms-file-target-file", target)],
        b"",
    )
}

fn snapshot(server: &Server) -> String {
    server
        .send(Method::PUT, "/links?restype=share&comp=snapshot", &[], b"")
        .status(201)
        .header("x-ms-snapshot")
        .into()
}

fn check_inode(
    server: &Server,
    snapshot: Option<&str>,
    file_id: &str,
) -> (BTreeSet<String>, Vec<u8>) {
    let suffix = snapshot
        .map(|id| format!("&sharesnapshot={id}"))
        .unwrap_or_default();
    let list = server
        .send(
            Method::GET,
            &format!("/links?restype=directory&comp=list{suffix}"),
            &[],
            b"",
        )
        .status(200);
    let names = tags(list.text(), "Name");
    let unique: BTreeSet<_> = names.iter().map(|name| (*name).to_owned()).collect();
    assert_eq!(names.len(), unique.len(), "a name must appear at most once");
    assert!(unique.contains("anchor"));
    let read = |name: &str| {
        let target = snapshot.map_or_else(
            || format!("/links/{name}"),
            |id| format!("/links/{name}?sharesnapshot={id}"),
        );
        server.send(Method::GET, &target, &[], b"").status(200)
    };
    let anchor = read("anchor");
    for name in &unique {
        let reply = read(name);
        assert_eq!(reply.header("x-ms-file-id"), file_id, "{name}");
        assert_eq!(
            reply.header("x-ms-link-count").parse::<usize>().unwrap(),
            unique.len(),
            "{name}"
        );
        assert_eq!(reply.body, anchor.body, "{name}");
    }
    (unique, anchor.body)
}

#[test]
fn files_link_writes_deletes_and_snapshots_keep_exact_references_after_restart() {
    let root = tempfile::tempdir().unwrap();
    let start = || Server::start("file", Some(root.path()), &[]);
    let server = start();
    server
        .send(
            Method::PUT,
            "/links?restype=share",
            &[("x-ms-enabled-protocols", "NFS")],
            b"",
        )
        .status(201);
    create_file(&server, "/links/other", 4 * (CLIENTS + 1));
    put_range(&server, "/links/other", 0, b"seed").status(201);
    let file_id = hard_link(&server, "anchor", "/other")
        .status(201)
        .header("x-ms-file-id")
        .to_owned();

    let mut snapshots = BTreeSet::new();
    for (i, response) in race(2 * CLIENTS + 5, |i| match i {
        i if i < CLIENTS => hard_link(&server, &format!("link-{i}"), "/anchor"),
        i if i < 2 * CLIENTS => {
            let segment = i - CLIENTS;
            put_range(
                &server,
                "/links/anchor",
                4 * (segment + 1),
                &[segment as u8 + 1; 4],
            )
        }
        i if i < 2 * CLIENTS + 3 => {
            server.send(Method::PUT, "/links?restype=share&comp=snapshot", &[], b"")
        }
        i if i == 2 * CLIENTS + 3 => server.send(Method::DELETE, "/links/other", &[], b""),
        _ => rename(&server, "/links/anchor", "/links/not-renamed"),
    })
    .into_iter()
    .enumerate()
    {
        if i < 2 * CLIENTS {
            response.status(201);
        } else if i < 2 * CLIENTS + 3 {
            assert!(snapshots.insert(response.status(201).header("x-ms-snapshot").to_owned()));
        } else if i == 2 * CLIENTS + 3 {
            response.status(202);
        } else {
            response.error(403, "XNfs4ShareDeniedException");
        }
    }
    let final_snapshot = snapshot(&server);
    assert!(!snapshots.contains(&final_snapshot));
    drop(server);

    let mut server = start();
    let expected_names: BTreeSet<_> = std::iter::once("anchor".to_owned())
        .chain((0..CLIENTS).map(|i| format!("link-{i}")))
        .collect();
    let expected_bytes = [
        b"seed".to_vec(),
        (1..=CLIENTS as u8).flat_map(|i| [i; 4]).collect(),
    ]
    .concat();
    let (names, data) = check_inode(&server, None, &file_id);
    assert_eq!(names, expected_names);
    assert_eq!(data, expected_bytes);
    assert_eq!(
        usage(&server, "/links"),
        expected_bytes.len(),
        "links do not allocate another copy"
    );

    let names: Vec<_> = names.into_iter().collect();
    let mut counts: Vec<usize> = race(names.len(), |i| {
        server
            .send(Method::DELETE, &format!("/links/{}", names[i]), &[], b"")
            .status(202)
            .header("x-ms-link-count")
            .parse()
            .unwrap()
    });
    counts.sort_unstable();
    assert_eq!(counts, (0..names.len()).collect::<Vec<_>>());
    assert_eq!(usage(&server, "/links"), 0);
    server.crash();
    drop(server);

    let server = start();
    assert_eq!(usage(&server, "/links"), 0);
    for name in &names {
        server
            .send(Method::GET, &format!("/links/{name}"), &[], b"")
            .error(404, "ResourceNotFound");
    }
    let unlink_snapshot = |id: &str| {
        server
            .send(
                Method::DELETE,
                &format!("/links?restype=share&sharesnapshot={id}"),
                &[],
                b"",
            )
            .status(202);
    };
    for id in &snapshots {
        let (captured, bytes) = check_inode(&server, Some(id), &file_id);
        assert!(
            captured
                .iter()
                .all(|n| expected_names.contains(n) || n == "other")
        );
        assert_eq!(&bytes[..4], b"seed");
        assert_eq!(bytes.len(), expected_bytes.len());
        for (i, chunk) in bytes[4..].as_chunks::<4>().0.iter().enumerate() {
            assert!(
                *chunk == [0; 4] || *chunk == [i as u8 + 1; 4],
                "snapshot saw a torn write at {i}"
            );
        }
        unlink_snapshot(id);
    }
    assert_eq!(
        check_inode(&server, Some(&final_snapshot), &file_id),
        (expected_names, expected_bytes)
    );
    unlink_snapshot(&final_snapshot);
    assert!(
        fs::read_dir(root.path().join("file").join("content"))
            .unwrap()
            .next()
            .is_none(),
        "last snapshot deletion should release every extent"
    );
}

#[test]
fn files_quota_is_atomic_with_concurrent_ranges_rename_and_delete() {
    const GIB: usize = 1 << 30;
    const CHUNK: usize = 4 << 20;
    let root = tempfile::tempdir().unwrap();
    let start = || Server::start("file", Some(root.path()), &[]);
    let server = start();
    server
        .send(
            Method::PUT,
            "/capped?restype=share",
            &[("x-ms-share-quota", "1")],
            b"",
        )
        .status(201);
    create_file(&server, "/capped/seed", CHUNK);
    let data = vec![b'x'; CHUNK];
    put_range(&server, "/capped/seed", 0, &data).status(201);
    let source = server.url("/capped/seed");
    // Copies fill the logical quota while referencing the same 4 MiB extent.
    race(CLIENTS, |lane| {
        for i in (lane..GIB / CHUNK - 2).step_by(CLIENTS) {
            server
                .send(
                    Method::PUT,
                    &format!("/capped/copy-{i}"),
                    &[("x-ms-copy-source", &source)],
                    b"",
                )
                .status(202);
        }
    });
    assert_eq!(usage(&server, "/capped"), GIB - CHUNK);
    let paths = ["/capped/first", "/capped/second"];
    for path in paths {
        create_file(&server, path, CHUNK + 1);
    }
    let mut outcomes = race(paths.len(), |i| put_range(&server, paths[i], 0, &data));
    let loser = match (outcomes[0].status, outcomes[1].status) {
        (201, 403) => 1,
        (403, 201) => 0,
        other => panic!("exactly one allocation fits, got {other:?}"),
    };
    outcomes.remove(loser).error(403, "ShareSizeLimitReached");
    assert_eq!(usage(&server, "/capped"), GIB);
    let loser = paths[loser];
    let [retry, removed, renamed, ranged]: [Reply; 4] = race(4, |i| match i {
        0 => put_range(&server, loser, 0, &data),
        1 => server.send(Method::DELETE, "/capped/copy-0", &[], b""),
        2 => rename(&server, "/capped/seed", "/capped/renamed"),
        _ => put_range(&server, "/capped/seed", 0, b"y"),
    })
    .try_into()
    .unwrap_or_else(|_| unreachable!());
    removed.status(202);
    renamed.status(200);
    let allocated = retry.status == 201;
    if !allocated {
        retry.error(403, "ShareSizeLimitReached");
    }
    let first = if ranged.status == 201 {
        b'y'
    } else {
        ranged.error(404, "ResourceNotFound");
        b'x'
    };
    let expected_usage = if allocated { GIB } else { GIB - CHUNK };
    assert_eq!(usage(&server, "/capped"), expected_usage);
    drop(server);

    let server = start();
    assert_eq!(usage(&server, "/capped"), expected_usage);
    for path in ["/capped/seed", "/capped/copy-0"] {
        server
            .send(Method::GET, path, &[], b"")
            .error(404, "ResourceNotFound");
    }
    let read_first = |path| {
        server
            .send(Method::GET, path, &[("x-ms-range", "bytes=0-0")], b"")
            .status(206)
            .body[0]
    };
    assert_eq!(read_first("/capped/renamed"), first);
    assert_eq!(
        read_first("/capped/copy-1"),
        b'x',
        "rename or write changed a shared copy"
    );
    assert_eq!(read_first(loser), if allocated { b'x' } else { 0 });
    if !allocated {
        put_range(&server, loser, 0, &data).status(201);
    }
    put_range(&server, loser, CHUNK, b"y").error(403, "ShareSizeLimitReached");
    assert_eq!(usage(&server, "/capped"), GIB);
    assert_eq!(read_first(loser), b'x');
}
