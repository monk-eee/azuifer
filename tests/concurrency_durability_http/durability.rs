//! State across graceful restarts, crashes and damaged content, and downloads in flight.

use super::harness::*;
use reqwest::Url;
use std::{
    fs,
    io::{Read as _, Write as _},
    net::TcpStream,
    thread,
    time::Duration,
};

fn in_flight_upload(server: &Server, path: &str) -> TcpStream {
    let url = Url::parse(&format!("{}{path}", server.blob)).unwrap();
    let headers = signed(
        "PUT",
        &url,
        &[("x-ms-blob-type", "BlockBlob")],
        Some(1 << 20),
        server.now(),
    );
    let mut socket = TcpStream::connect(url.socket_addrs(|| None).unwrap()[0]).unwrap();
    write!(
        socket,
        "PUT {path} HTTP/1.1\r\nHost: {}\r\n",
        url.host_str().unwrap()
    )
    .unwrap();
    for (name, value) in headers {
        write!(socket, "{name}: {value}\r\n").unwrap();
    }
    socket.write_all(b"\r\n").unwrap();
    socket.write_all(&[7; 4096]).unwrap();
    thread::sleep(Duration::from_millis(300));
    socket
}

#[test]
fn versioned_state_survives_restarts_and_a_crash() {
    let root = tempfile::tempdir().unwrap();
    let location = root.path().join("store");
    let flags = ["--versioning-accounts", ACCOUNT];
    let snapshot = |reply: Reply| reply.header("x-ms-snapshot").to_owned();
    let page = "/testaccount/dur/disk";
    let (snap, page_snap, first, gone) = {
        let server = Server::flat(Some(&location), &flags);
        server.container("dur");
        let first = must(server.put("/testaccount/dur/plain", b"alpha"), 201);
        let first = first.header("x-ms-version-id").to_owned();
        let snap = snapshot(must(
            server.blob("PUT", "/testaccount/dur/plain?comp=snapshot", &[], b""),
            201,
        ));
        must(server.put("/testaccount/dur/plain", b"beta"), 201);

        let made = [
            ("x-ms-blob-type", "PageBlob"),
            ("x-ms-blob-content-length", "4096"),
        ];
        must(server.blob("PUT", page, &made, b""), 201);
        let write = |byte: u8| {
            let headers = [("x-ms-page-write", "update"), ("x-ms-range", "bytes=0-511")];
            server.blob("PUT", &format!("{page}?comp=page"), &headers, &[byte; 512])
        };
        must(write(b'P'), 201);
        let page_snap = snapshot(must(
            server.blob("PUT", &format!("{page}?comp=snapshot"), &[], b""),
            201,
        ));
        must(write(b'Q'), 201);

        let log = "/testaccount/dur/log";
        must(
            server.blob("PUT", log, &[("x-ms-blob-type", "AppendBlob")], b""),
            201,
        );
        for chunk in [&b"one,"[..], b"two"] {
            must(
                server.blob("PUT", &format!("{log}?comp=appendblock"), &[], chunk),
                201,
            );
        }
        let gone = must(server.put("/testaccount/dur/gone", b"bye"), 201);
        let gone = gone.header("x-ms-version-id").to_owned();
        must(
            server.blob("DELETE", "/testaccount/dur/gone", &[], b""),
            202,
        );
        let stage = "/testaccount/dur/staged?comp=block&blockid=czE%3D";
        must(server.blob("PUT", stage, &[], b"staged bytes"), 201);
        (snap, page_snap, first, gone)
    };

    let verify = |server: &Server| {
        let read = |path: &str| server.blob("GET", path, &[], b"");
        assert_eq!(read("/testaccount/dur/plain").text(), "beta");
        let at =
            |query: &str, value: &str| format!("/testaccount/dur/plain?{query}={}", encode(value));
        assert_eq!(read(&at("snapshot", &snap)).text(), "alpha");
        assert_eq!(read(&at("versionid", &first)).text(), "alpha");
        assert_eq!(read(page).body[..512], [b'Q'; 512]);
        assert_eq!(
            read(&format!("{page}?snapshot={}", encode(&page_snap))).body[..512],
            [b'P'; 512]
        );
        assert_eq!(read("/testaccount/dur/log").text(), "one,two");
        assert_eq!(read("/testaccount/dur/gone").code, "BlobNotFound");
        let old = read(&format!(
            "/testaccount/dur/gone?versionid={}",
            encode(&gone)
        ));
        assert_eq!(old.text(), "bye", "a deleted blob's version stays readable");
        let blocks = read("/testaccount/dur/staged?comp=blocklist&blocklisttype=uncommitted");
        assert!(
            blocks.text().contains("<Name>czE=</Name>"),
            "{}",
            blocks.text()
        );
    };
    let server = Server::flat(Some(&location), &flags);
    verify(&server);
    let commit = "<BlockList><Uncommitted>czE=</Uncommitted></BlockList>";
    must(
        server.blob(
            "PUT",
            "/testaccount/dur/staged?comp=blocklist",
            &[],
            commit.as_bytes(),
        ),
        201,
    );
    assert_eq!(
        server
            .blob("GET", "/testaccount/dur/staged", &[], b"")
            .text(),
        "staged bytes"
    );

    // A crash with an upload in flight loses only that upload.
    let _socket = in_flight_upload(&server, "/testaccount/dur/partial");
    server.crash();
    let server = Server::flat(Some(&location), &flags);
    assert_eq!(
        server
            .blob("GET", "/testaccount/dur/staged", &[], b"")
            .text(),
        "staged bytes"
    );
    assert_eq!(
        server
            .blob("GET", "/testaccount/dur/partial", &[], b"")
            .code,
        "BlobNotFound"
    );
    let names = extents(&location);
    assert!(
        names.iter().all(|name| name.starts_with("extent-")),
        "a torn upload remains: {names:?}"
    );
    drop(server);
    let server = Server::flat(Some(&location), &flags);
    verify_after_commit(&server);
}

fn verify_after_commit(server: &Server) {
    assert_eq!(
        server
            .blob("GET", "/testaccount/dur/plain", &[], b"")
            .text(),
        "beta"
    );
    assert_eq!(
        server.blob("GET", "/testaccount/dur/log", &[], b"").text(),
        "one,two"
    );
}

#[test]
fn soft_deleted_blobs_and_containers_survive_restarts_and_leave_nothing_once_purged() {
    let root = tempfile::tempdir().unwrap();
    let location = root.path().join("store");
    let flags = ["--test-clock"];
    {
        let server = Server::flat(Some(&location), &flags);
        server.container("dur");
        must(
            server.blob(
                "PUT",
                &format!("/{ACCOUNT}?restype=service&comp=properties"),
                &[],
                b"<StorageServiceProperties><DeleteRetentionPolicy><Enabled>true</Enabled><Days>1</Days></DeleteRetentionPolicy></StorageServiceProperties>",
            ),
            202,
        );
        must(server.put("/testaccount/dur/gone", b"bye"), 201);
        must(
            server.blob("PUT", "/testaccount/dur/gone?comp=snapshot", &[], b""),
            201,
        );
        must(
            server.blob(
                "DELETE",
                "/testaccount/dur/gone?",
                &[("x-ms-delete-snapshots", "include")],
                b"",
            ),
            202,
        );
        server.container("dur2");
        must(
            server.put("/testaccount/dur2/inside", b"in a container"),
            201,
        );
        must(
            server.blob("DELETE", "/testaccount/dur2?restype=container", &[], b""),
            202,
        );
    }
    let server = Server::flat(Some(&location), &flags);
    let listed = server
        .blob(
            "GET",
            "/testaccount/dur?restype=container&comp=list&include=deleted,snapshots",
            &[],
            b"",
        )
        .text();
    assert!(listed.contains("<Name>gone</Name>"), "{listed}");
    must(
        server.blob("PUT", "/testaccount/dur/gone?comp=undelete", &[], b""),
        200,
    );
    assert_eq!(
        server.blob("GET", "/testaccount/dur/gone", &[], b"").text(),
        "bye"
    );
    let containers = server
        .blob(
            "GET",
            &format!("/{ACCOUNT}?comp=list&include=deleted"),
            &[],
            b"",
        )
        .text();
    let version = containers
        .split("<Version>")
        .nth(1)
        .and_then(|v| v.split("</Version>").next())
        .expect("a deleted container");
    let restore = [
        ("x-ms-deleted-container-name", "dur2"),
        ("x-ms-deleted-container-version", version),
    ];
    must(
        server.blob(
            "PUT",
            &format!("/{ACCOUNT}/dur2?restype=container&comp=undelete"),
            &restore,
            b"",
        ),
        201,
    );
    assert_eq!(
        server
            .blob("GET", "/testaccount/dur2/inside", &[], b"")
            .text(),
        "in a container"
    );

    // Delete it all again; once the retention ends nothing is left on disk.
    must(
        server.blob("DELETE", "/testaccount/dur2?restype=container", &[], b""),
        202,
    );
    must(
        server.blob("DELETE", "/testaccount/dur?restype=container", &[], b""),
        202,
    );
    assert!(
        !extents(&location).is_empty(),
        "retained while the retention lasts"
    );
    server.advance(2 * 86_400);
    server.blob(
        "GET",
        &format!("/{ACCOUNT}?comp=list&include=deleted"),
        &[],
        b"",
    );
    drop(server);
    let _server = Server::flat(Some(&location), &flags);
    assert_eq!(
        extents(&location),
        Vec::<String>::new(),
        "purged content left files behind"
    );
}

#[test]
fn deleting_everything_reclaims_every_extent_even_after_a_crash() {
    let root = tempfile::tempdir().unwrap();
    let location = root.path().join("store");
    let server = Server::start(Some(&location), &[]);
    server.container("race");
    for index in 0..3 {
        let name = format!("{C}/plain{index}");
        must(
            server.put(&name, format!("content {index}").as_bytes()),
            201,
        );
        must(
            server.blob(
                "PUT",
                &format!("{name}?comp=block&blockid=czE%3D"),
                &[],
                b"staged",
            ),
            201,
        );
    }
    let page = format!("{C}/page");
    let made = [
        ("x-ms-blob-type", "PageBlob"),
        ("x-ms-blob-content-length", "1024"),
    ];
    must(server.blob("PUT", &page, &made, b""), 201);
    let write = [("x-ms-page-write", "update"), ("x-ms-range", "bytes=0-511")];
    must(
        server.blob("PUT", &format!("{page}?comp=page"), &write, &[1; 512]),
        201,
    );
    let log = format!("{C}/log");
    must(
        server.blob("PUT", &log, &[("x-ms-blob-type", "AppendBlob")], b""),
        201,
    );
    must(
        server.blob("PUT", &format!("{log}?comp=appendblock"), &[], b"entry"),
        201,
    );
    // DFS data that was appended and never flushed.
    let path = format!("{C}/dir/unflushed");
    must(
        server.dfs("PUT", &format!("{path}?resource=file"), &[], b""),
        201,
    );
    must(
        server.dfs(
            "PATCH",
            &format!("{path}?action=append&position=0"),
            &[],
            b"pending",
        ),
        202,
    );
    let flushed = format!("{C}/dir/flushed");
    must(
        server.dfs("PUT", &format!("{flushed}?resource=file"), &[], b""),
        201,
    );
    must(
        server.dfs(
            "PATCH",
            &format!("{flushed}?action=append&position=0"),
            &[],
            b"done",
        ),
        202,
    );
    must(
        server.dfs(
            "PATCH",
            &format!("{flushed}?action=flush&position=4"),
            &[],
            b"",
        ),
        200,
    );

    let _socket = in_flight_upload(&server, &format!("{C}/partial"));
    server.crash();
    let server = Server::start(Some(&location), &[]);
    let kept = extents(&location);
    assert!(
        kept.iter().all(|name| name.starts_with("extent-")),
        "{kept:?}"
    );
    assert_eq!(
        server.blob("GET", &format!("{C}/plain1"), &[], b"").text(),
        "content 1"
    );
    assert_eq!(server.blob("GET", &flushed, &[], b"").text(), "done");
    must(
        server.dfs(
            "PATCH",
            &format!("{path}?action=flush&position=7"),
            &[],
            b"",
        ),
        200,
    );
    assert_eq!(
        server.blob("GET", &path, &[], b"").text(),
        "pending",
        "unflushed data survived the crash"
    );

    must(
        server.blob("DELETE", "/testaccount/race?restype=container", &[], b""),
        202,
    );
    assert_eq!(
        extents(&location),
        Vec::<String>::new(),
        "deleting the container left content behind"
    );
}

#[test]
fn missing_or_damaged_content_answers_cleanly_and_does_not_stop_the_server() {
    let root = tempfile::tempdir().unwrap();
    let location = root.path().join("store");
    {
        let server = Server::flat(Some(&location), &[]);
        server.container("dur");
        must(server.put("/testaccount/dur/short", b"0123456789"), 201);
        must(
            server.put("/testaccount/dur/missing", b"01234567890123456789"),
            201,
        );
        must(
            server.put("/testaccount/dur/intact", b"012345678901234567890123456789"),
            201,
        );
    }
    let by_length = |length: u64| {
        fs::read_dir(location.join("content"))
            .unwrap()
            .map(|entry| entry.unwrap().path())
            .find(|path| fs::metadata(path).unwrap().len() == length)
            .unwrap_or_else(|| panic!("no content of length {length}"))
    };
    fs::OpenOptions::new()
        .write(true)
        .open(by_length(10))
        .unwrap()
        .set_len(4)
        .unwrap();
    fs::remove_file(by_length(20)).unwrap();

    let mut server = Server::flat(Some(&location), &[]);
    for name in ["short", "missing"] {
        let path = format!("/testaccount/dur/{name}");
        assert_eq!(
            server.blob("HEAD", &path, &[], b"").status,
            200,
            "{name} keeps its metadata"
        );
        for read in [
            server.blob("GET", &path, &[], b""),
            server.blob("GET", &path, &[("x-ms-range", "bytes=0-3")], b""),
        ] {
            assert_eq!(
                (read.status, read.code.as_str()),
                (500, "InternalError"),
                "{name}"
            );
            assert!(read.text().contains("<Code>InternalError</Code>"));
        }
    }
    let source = format!("{}/testaccount/dur/missing", server.blob);
    let copy = [("x-ms-copy-source", source.as_str())];
    assert!(
        server
            .blob("PUT", "/testaccount/dur/copied", &copy, b"")
            .status
            >= 400
    );
    assert_eq!(
        server
            .blob("HEAD", "/testaccount/dur/copied", &[], b"")
            .status,
        404,
        "a failed copy leaves nothing"
    );
    assert_eq!(
        server
            .blob("GET", "/testaccount/dur/intact", &[], b"")
            .text(),
        "012345678901234567890123456789"
    );
    assert_eq!(server.names("dur", "").len(), 3);
    assert!(server.alive());

    must(server.put("/testaccount/dur/short", b"replaced"), 201);
    assert_eq!(
        server
            .blob("GET", "/testaccount/dur/short", &[], b"")
            .text(),
        "replaced"
    );
    must(
        server.blob("DELETE", "/testaccount/dur/missing", &[], b""),
        202,
    );
    must(
        server.blob("DELETE", "/testaccount/dur?restype=container", &[], b""),
        202,
    );
    assert_eq!(extents(&location), Vec::<String>::new());
}

/// A page blob of `ranges` 4 MiB ranges, each written on its own so that each is an extent.
fn fragmented_page_blob(server: &Server, path: &str, ranges: usize, letter: u8) {
    let size = ((ranges * 4) << 20).to_string();
    let made = [
        ("x-ms-blob-type", "PageBlob"),
        ("x-ms-blob-content-length", size.as_str()),
    ];
    must(server.blob("PUT", path, &made, b""), 201);
    for range in 0..ranges {
        let bytes = format!(
            "bytes={}-{}",
            (range * 4) << 20,
            (((range + 1) * 4) << 20) - 1
        );
        let headers = [
            ("x-ms-page-write", "update"),
            ("x-ms-range", bytes.as_str()),
        ];
        let data = vec![letter + range as u8; 4 << 20];
        must(
            server.blob("PUT", &format!("{path}?comp=page"), &headers, &data),
            201,
        );
    }
}

#[test]
fn a_download_in_flight_survives_the_blob_being_overwritten_and_deleted() {
    let root = tempfile::tempdir().unwrap();
    let location = root.path().join("store");
    let server = Server::flat(Some(&location), &[]);
    server.container("dur");
    let path = "/testaccount/dur/big";
    let ranges = 16;
    fragmented_page_blob(&server, path, ranges, b'A');

    // Start the download, take the first bytes, and leave the rest unread.
    let url = Url::parse(&format!("{}{path}", server.blob)).unwrap();
    let headers = signed("GET", &url, &[], None, server.now());
    let mut request = server.client.get(url);
    for (name, value) in headers {
        request = request.header(name, value);
    }
    let mut response = request.send().unwrap();
    assert_eq!(response.status(), 200);
    let mut head = vec![0; 1024];
    response.read_exact(&mut head).unwrap();

    // The blob is overwritten range by range, then deleted, while the download waits.
    for range in 0..ranges {
        let bytes = format!(
            "bytes={}-{}",
            (range * 4) << 20,
            (((range + 1) * 4) << 20) - 1
        );
        let headers = [
            ("x-ms-page-write", "update"),
            ("x-ms-range", bytes.as_str()),
        ];
        must(
            server.blob(
                "PUT",
                &format!("{path}?comp=page"),
                &headers,
                &vec![b'z'; 4 << 20],
            ),
            201,
        );
    }
    must(server.blob("DELETE", path, &[], b""), 202);

    let mut rest = Vec::new();
    response
        .read_to_end(&mut rest)
        .expect("the download completes");
    let body = [head, rest].concat();
    assert_eq!(body.len(), (ranges * 4) << 20);
    for range in 0..ranges {
        let part = &body[(range * 4) << 20..((range + 1) * 4) << 20];
        assert!(
            part.iter().all(|byte| *byte == b'A' + range as u8),
            "range {range} was not the content the download began with"
        );
    }
    drop(response);
    must(
        server.blob("DELETE", "/testaccount/dur?restype=container", &[], b""),
        202,
    );
    assert_eq!(
        extents(&location),
        Vec::<String>::new(),
        "an extent outlived its last reader"
    );
}
