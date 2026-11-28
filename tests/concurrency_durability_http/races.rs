//! Races of Blob, DFS and lease operations: an outcome no interleaving may break.

use super::harness::*;
use base64::{Engine as _, engine::general_purpose::STANDARD};
use std::{
    collections::{BTreeMap, BTreeSet},
    sync::atomic::{AtomicBool, Ordering},
    thread,
    time::Duration,
};

#[test]
fn exclusive_creates_and_conditional_overwrites_have_exactly_one_winner() {
    in_both_modes(|server| {
        let made = race(THREADS, |_| {
            server.blob("PUT", "/testaccount/only?restype=container", &[], b"")
        });
        assert_clean(&made);
        assert_eq!(count(&made, 201), 1);
        assert!(
            made.iter()
                .all(|r| r.status == 201 || r.code == "ContainerAlreadyExists")
        );
        server.container("race");

        let blob = format!("{C}/exclusive");
        let creates = race(THREADS, |i| {
            server.blob(
                "PUT",
                &blob,
                &[("x-ms-blob-type", "BlockBlob"), ("if-none-match", "*")],
                format!("writer-{i}").as_bytes(),
            )
        });
        assert_clean(&creates);
        assert_eq!(count(&creates, 201), 1, "one writer creates it");
        assert!(
            creates
                .iter()
                .all(|r| r.status == 201 || r.code == "BlobAlreadyExists")
        );
        let winner = creates.iter().position(|r| r.status == 201).unwrap();
        let read = server.blob("GET", &blob, &[], b"");
        assert_eq!(read.text(), format!("writer-{winner}"));

        let etag = read.header("etag").to_owned();
        let updates = race(THREADS, |i| {
            server.blob(
                "PUT",
                &blob,
                &[("x-ms-blob-type", "BlockBlob"), ("if-match", &etag)],
                format!("update-{i}").as_bytes(),
            )
        });
        assert_clean(&updates);
        assert_eq!(
            count(&updates, 201),
            1,
            "one update sees the ETag it expected"
        );
        assert!(
            updates
                .iter()
                .all(|r| r.status == 201 || r.code == "ConditionNotMet")
        );
        let winner = updates.iter().position(|r| r.status == 201).unwrap();
        assert_eq!(
            server.blob("GET", &blob, &[], b"").text(),
            format!("update-{winner}")
        );

        let dfs = race(THREADS, |_| {
            server.dfs(
                "PUT",
                &format!("{C}/made.txt?resource=file"),
                &[("if-none-match", "*")],
                b"",
            )
        });
        assert_clean(&dfs);
        assert_eq!(
            count(&dfs, 201),
            1,
            "one DFS create wins: {:?}",
            dfs.iter().map(|r| &r.code).collect::<Vec<_>>()
        );
    });
}

#[test]
fn block_commits_never_mix_the_content_of_two_writers() {
    in_both_modes(|server| {
        server.container("race");
        let blob = format!("{C}/blocks");
        let results = race(THREADS, |i| {
            let content = format!("{i:02}").repeat(32);
            let staged = server.blob(
                "PUT",
                &format!("{blob}?comp=block&blockid={}", block_id(i)),
                &[],
                content.as_bytes(),
            );
            let list = format!(
                "<BlockList><Latest>{}</Latest></BlockList>",
                STANDARD.encode(format!("block-{i:04}"))
            );
            let committed = server.blob(
                "PUT",
                &format!("{blob}?comp=blocklist"),
                &[],
                list.as_bytes(),
            );
            (staged, committed)
        });
        let staged: Vec<Reply> = results
            .iter()
            .map(|(s, _)| Reply {
                status: s.status,
                code: s.code.clone(),
                headers: BTreeMap::new(),
                body: Vec::new(),
            })
            .collect();
        assert_clean(&staged);
        assert_eq!(count(&staged, 201), THREADS);
        // A commit may find its block already discarded by another writer's commit.
        for (_, commit) in &results {
            assert!(
                commit.status == 201 || commit.code == "InvalidBlockList",
                "{}",
                commit.text()
            );
        }
        let winners: Vec<usize> = (0..THREADS)
            .filter(|i| results[*i].1.status == 201)
            .collect();
        assert!(!winners.is_empty());
        let content = server.blob("GET", &blob, &[], b"").text();
        assert!(
            winners
                .iter()
                .any(|i| content == format!("{i:02}").repeat(32)),
            "the blob holds exactly one writer's block: {content}"
        );
        let list = server.blob(
            "GET",
            &format!("{blob}?comp=blocklist&blocklisttype=committed"),
            &[],
            b"",
        );
        assert_eq!(list.text().matches("<Block>").count(), 1, "{}", list.text());
    });
}

#[test]
fn appends_never_lose_or_interleave_and_their_conditions_hold() {
    in_both_modes(|server| {
        server.container("race");
        let log = format!("{C}/log");
        assert_eq!(
            server
                .blob("PUT", &log, &[("x-ms-blob-type", "AppendBlob")], b"")
                .status,
            201
        );
        let rounds = 20;
        let appends = race(THREADS, |i| {
            let chunk = vec![b'a' + i as u8; 16];
            (0..rounds)
                .map(|_| server.blob("PUT", &format!("{log}?comp=appendblock"), &[], &chunk))
                .collect::<Vec<_>>()
        });
        let all: Vec<Reply> = appends.into_iter().flatten().collect();
        assert_clean(&all);
        assert_eq!(count(&all, 201), THREADS * rounds, "no append is lost");
        let content = server.blob("GET", &log, &[], b"").body;
        assert_eq!(content.len(), THREADS * rounds * 16);
        let mut per_writer = [0usize; THREADS];
        for chunk in content.chunks(16) {
            assert!(
                chunk.iter().all(|byte| *byte == chunk[0]),
                "a chunk was torn: {chunk:?}"
            );
            per_writer[usize::from(chunk[0] - b'a')] += 1;
        }
        assert!(per_writer.iter().all(|n| *n == rounds), "{per_writer:?}");

        let positioned = format!("{C}/positioned");
        server.blob("PUT", &positioned, &[("x-ms-blob-type", "AppendBlob")], b"");
        let first = race(THREADS, |_| {
            server.blob(
                "PUT",
                &format!("{positioned}?comp=appendblock"),
                &[("x-ms-blob-condition-appendpos", "0")],
                b"12345678",
            )
        });
        assert_clean(&first);
        assert_eq!(count(&first, 201), 1, "one append claims position 0");
        assert!(
            first
                .iter()
                .all(|r| r.status == 201 || r.code == "AppendPositionConditionNotMet")
        );
        assert_eq!(server.blob("GET", &positioned, &[], b"").body.len(), 8);

        let capped = format!("{C}/capped");
        server.blob("PUT", &capped, &[("x-ms-blob-type", "AppendBlob")], b"");
        let limited = race(THREADS, |_| {
            server.blob(
                "PUT",
                &format!("{capped}?comp=appendblock"),
                &[("x-ms-blob-condition-maxsize", "100")],
                &[b'z'; 30],
            )
        });
        assert_clean(&limited);
        assert_eq!(
            count(&limited, 201),
            3,
            "100 bytes hold three 30-byte appends"
        );
        assert!(
            limited
                .iter()
                .all(|r| r.status == 201 || r.code == "MaxBlobSizeConditionNotMet")
        );
        assert_eq!(server.blob("GET", &capped, &[], b"").body.len(), 90);
    });
}

#[test]
fn page_writes_land_whole_and_sequence_number_conditions_hold() {
    in_both_modes(|server| {
        server.container("race");
        let disk = format!("{C}/disk");
        let size = (THREADS * 512).to_string();
        let made = server.blob(
            "PUT",
            &disk,
            &[
                ("x-ms-blob-type", "PageBlob"),
                ("x-ms-blob-content-length", &size),
            ],
            b"",
        );
        assert_eq!(made.status, 201);
        let write = |page: usize, extra: &[(&str, &str)]| {
            let range = format!("bytes={}-{}", page * 512, page * 512 + 511);
            let mut headers = vec![
                ("x-ms-page-write", "update"),
                ("x-ms-range", range.as_str()),
            ];
            headers.extend_from_slice(extra);
            server.blob(
                "PUT",
                &format!("{disk}?comp=page"),
                &headers,
                &[b'A' + page as u8; 512],
            )
        };
        let writes = race(THREADS, |page| write(page, &[]));
        assert_clean(&writes);
        assert_eq!(count(&writes, 201), THREADS);
        let content = server.blob("GET", &disk, &[], b"").body;
        for page in 0..THREADS {
            assert!(
                content[page * 512..(page + 1) * 512]
                    .iter()
                    .all(|b| *b == b'A' + page as u8)
            );
        }

        // Writes conditioned on sequence number 0 race a change of that number.
        let results = race(THREADS + 1, |i| {
            if i == THREADS {
                server.blob(
                    "PUT",
                    &format!("{disk}?comp=properties"),
                    &[
                        ("x-ms-sequence-number-action", "update"),
                        ("x-ms-blob-sequence-number", "5"),
                    ],
                    b"",
                )
            } else {
                write(i, &[("x-ms-if-sequence-number-eq", "0")])
            }
        });
        assert_clean(&results);
        assert_eq!(results[THREADS].status, 200);
        assert!(
            results[..THREADS]
                .iter()
                .all(|r| r.status == 201 || r.code == "SequenceNumberConditionNotMet")
        );
        let after = write(0, &[("x-ms-if-sequence-number-eq", "0")]);
        assert_eq!(
            after.code, "SequenceNumberConditionNotMet",
            "the new number is in force"
        );
        assert_eq!(
            server
                .blob("HEAD", &disk, &[], b"")
                .header("x-ms-blob-sequence-number"),
            "5"
        );
    });
}

#[test]
fn only_one_caller_acquires_a_lease_and_the_holder_keeps_exclusive_access() {
    in_both_modes(|server| {
        server.container("race");
        let blob = format!("{C}/leased");
        let path = format!("{C}/leased-path");
        server.put(&blob, b"initial");
        server.dfs("PUT", &format!("{path}?resource=file"), &[], b"");
        let id = |i: usize| format!("{i:08}-0000-0000-0000-000000000000");
        let acquire = |i: usize| -> [(&'static str, String); 3] {
            [
                ("x-ms-lease-action", "acquire".to_owned()),
                ("x-ms-lease-duration", "-1".to_owned()),
                ("x-ms-proposed-lease-id", id(i)),
            ]
        };
        let on_blob = race(THREADS, |i| {
            server.blob(
                "PUT",
                &format!("{blob}?comp=lease"),
                &borrowed(&acquire(i)),
                b"",
            )
        });
        let on_container = race(THREADS, |i| {
            server.blob(
                "PUT",
                &format!("{C}?restype=container&comp=lease"),
                &borrowed(&acquire(i)),
                b"",
            )
        });
        let on_path = race(THREADS, |i| {
            server.dfs("POST", &path, &borrowed(&acquire(i)), b"")
        });
        for (label, replies) in [
            ("blob", &on_blob),
            ("container", &on_container),
            ("dfs path", &on_path),
        ] {
            assert_clean(replies);
            assert_eq!(count(replies, 201), 1, "{label}: one acquire wins");
            assert!(
                replies
                    .iter()
                    .all(|r| r.status == 201 || r.code == "LeaseAlreadyPresent"),
                "{label}"
            );
        }

        // The holder renews and writes while everyone else is refused.
        let holder = id(on_blob.iter().position(|r| r.status == 201).unwrap());
        let results = race(THREADS * 2, |i| match i % 4 {
            0 => ("attack", server.put(&blob, b"stolen")),
            1 => ("attack", server.blob("DELETE", &blob, &[], b"")),
            2 => (
                "attack",
                server.dfs(
                    "PUT",
                    &format!("{C}/moved"),
                    &[("x-ms-rename-source", "/race/leased")],
                    b"",
                ),
            ),
            _ => (
                "holder",
                server.blob(
                    "PUT",
                    &format!("{blob}?comp=lease"),
                    &[("x-ms-lease-action", "renew"), ("x-ms-lease-id", &holder)],
                    b"",
                ),
            ),
        });
        for (role, reply) in &results {
            assert!(reply.status < 500, "{}", reply.text());
            match *role {
                "attack" => assert_eq!(
                    reply.status,
                    412,
                    "an unleased write got through: {}",
                    reply.text()
                ),
                _ => assert_eq!(reply.status, 200, "{}", reply.text()),
            }
        }
        assert_eq!(server.blob("GET", &blob, &[], b"").text(), "initial");
    });
}

#[test]
fn a_release_races_deletes_without_ever_letting_one_through_early() {
    in_both_modes(|server| {
        server.container("race");
        for round in 0..5 {
            let blob = format!("{C}/release-{round}");
            server.put(&blob, b"x");
            let held = "33333333-3333-3333-3333-333333333333";
            let lease = server.blob(
                "PUT",
                &format!("{blob}?comp=lease"),
                &[
                    ("x-ms-lease-action", "acquire"),
                    ("x-ms-lease-duration", "-1"),
                    ("x-ms-proposed-lease-id", held),
                ],
                b"",
            );
            assert_eq!(lease.status, 201);
            let results = race(THREADS, |i| {
                if i == 0 {
                    server.blob(
                        "PUT",
                        &format!("{blob}?comp=lease"),
                        &[("x-ms-lease-action", "release"), ("x-ms-lease-id", held)],
                        b"",
                    )
                } else {
                    server.blob("DELETE", &blob, &[], b"")
                }
            });
            assert_clean(&results);
            assert_eq!(results[0].status, 200, "{}", results[0].text());
            let deleted = count(&results[1..], 202);
            assert!(deleted <= 1, "a blob is deleted once");
            for reply in &results[1..] {
                assert!(
                    matches!(
                        (reply.status, reply.code.as_str()),
                        (202, _) | (412, "LeaseIdMissing") | (404, "BlobNotFound")
                    ),
                    "{} {}",
                    reply.status,
                    reply.code
                );
                if reply.status == 404 {
                    assert_eq!(deleted, 1, "a 404 means an earlier delete succeeded");
                }
            }
            let head = server.blob("HEAD", &blob, &[], b"");
            assert_eq!(head.status, if deleted == 1 { 404 } else { 200 });
        }
    });
}

#[test]
fn a_directory_rename_is_atomic_to_listings_reads_and_deletes() {
    in_both_modes(|server| {
        server.container("race");
        let files = tree(server, "tree");
        let before = set(server.names("race", ""));
        let after: BTreeSet<String> = before
            .iter()
            .map(|name| name.replacen("tree", "tree2", 1))
            .collect();
        assert!(before.iter().all(|name| name.starts_with("tree")));

        let renamed = AtomicBool::new(false);
        let results = race(THREADS, |i| {
            if i == 0 {
                thread::sleep(Duration::from_millis(30));
                let reply = rename(server, "tree", "tree2");
                renamed.store(true, Ordering::SeqCst);
                return (vec![reply], 0, 0);
            }
            let (mut replies, mut old, mut new) = (Vec::new(), 0, 0);
            let mut after_rename = 0;
            while after_rename < 5 {
                after_rename += usize::from(renamed.load(Ordering::SeqCst));
                let seen = set(server.names("race", ""));
                if seen == before {
                    old += 1;
                } else if seen == after {
                    new += 1;
                } else {
                    panic!("a listing saw a half-renamed tree: {seen:?}");
                }
                let (path, content) = &files[i % files.len()];
                for prefix in ["tree/", "tree2/"] {
                    let reply = server.blob("GET", &path.replacen("tree/", prefix, 1), &[], b"");
                    if reply.status == 200 {
                        assert_eq!(reply.text(), *content);
                    }
                    replies.push(reply);
                }
            }
            (replies, old, new)
        });
        assert_eq!(results[0].0[0].status, 201, "{}", results[0].0[0].text());
        let all: Vec<Reply> = results
            .into_iter()
            .skip(1)
            .flat_map(|(replies, ..)| replies)
            .collect();
        assert_clean(&all);
        for reply in &all {
            assert!(
                reply.status == 200 || reply.code == "BlobNotFound",
                "{} {} {}",
                reply.status,
                reply.code,
                reply.text()
            );
        }
        assert_eq!(set(server.names("race", "")), after);
    });
}

#[test]
fn a_directory_rename_never_hides_a_file_from_a_concurrent_delete() {
    in_both_modes(|server| {
        server.container("race");
        let files = tree(server, "t2");
        let results = race(files.len() + 1, |i| {
            if i == files.len() {
                return (vec![rename(server, "t2", "t3")], false);
            }
            let name = &files[i].0;
            let old = server.blob("DELETE", name, &[], b"");
            if old.status == 202 {
                return (vec![old], i % 2 == 0);
            }
            // Not found under the old name means the rename got there first.
            let new = server.blob("DELETE", &name.replacen("/t2/", "/t3/", 1), &[], b"");
            (vec![old, new], i % 2 == 0)
        });
        assert_eq!(results[files.len()].0[0].status, 201);
        for (i, (replies, _)) in results[..files.len()].iter().enumerate() {
            assert_clean(replies);
            let deleted = count(replies, 202);
            assert_eq!(
                deleted,
                1,
                "file {i} was deleted exactly once: {:?}",
                replies
                    .iter()
                    .map(|r| (r.status, &r.code))
                    .collect::<Vec<_>>()
            );
        }
        let left = set(server.names("race", ""));
        assert!(left.iter().all(|name| name.starts_with("t3")), "{left:?}");
        assert!(
            left.iter().all(|name| !name.contains("/f")),
            "no file survived: {left:?}"
        );
    });
}
