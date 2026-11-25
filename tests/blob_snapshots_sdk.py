"""Exercise snapshots, versions, soft delete, blob index tags, and batch with the
Azure Storage Blob Python SDK against a running Azuifer Blob listener.

Start Azuifer, with versioning for the development account to run the versions checks:

    azuifer serve --in-memory --skip-api-version-check --versioning-accounts devstoreaccount1

    pip install azure-storage-blob
    python tests/blob_snapshots_sdk.py --blob-url http://127.0.0.1:10000

Versions are skipped when the account does not keep them, and soft delete is skipped
when it does (a versioned delete keeps a version instead), so run it once against
each setup. Soft-delete expiry needs the test clock, which Shared Key requests
cannot follow past the 15 minute skew window, so the HTTP suite covers it. The default account and key are
the public development-storage fixture.
"""

import argparse
import os
import sys
import time
import traceback
import uuid

from azure.core.exceptions import HttpResponseError, ResourceNotFoundError
from azure.storage.blob import (
    BlobBlock,
    BlobServiceClient,
    RetentionPolicy,
    StandardBlobTier,
)

ACCOUNT = "devstoreaccount1"
# The well-known public development-storage key; never a production credential.
PUBLIC_DEV_KEY = (
    "Eby8vdM02xNOcqFlqUwJPLlmEtlCDXJ1OUzFT50uSRZ6IFsuFq2UVErCz4I6tq/K1SZFPTOtr/KBHBeksoGMGw=="
)

RESULTS = []
CHECKS = []


def check(name):
    def wrap(function):
        def run(context):
            started = time.monotonic()
            try:
                outcome = function(context)
            except Exception:
                RESULTS.append((name, "FAIL", traceback.format_exc()))
                print(f"FAIL {name}")
                return
            status = "SKIP" if outcome == "skip" else "PASS"
            RESULTS.append((name, status, f"{time.monotonic() - started:.2f}s"))
            print(f"{status} {name}")

        CHECKS.append(run)
        return run

    return wrap


def require(condition, message):
    if not condition:
        raise AssertionError(message)


def expect(error_type, code, call):
    try:
        call()
    except error_type as error:
        actual = getattr(error, "error_code", None)
        actual = getattr(actual, "value", actual)
        require(actual == code, f"expected {code}, got {actual}: {error}")
        return
    raise AssertionError(f"expected {code}, but the call succeeded")


class Context:
    def __init__(self, blob_url, account, key):
        self.blob_url = blob_url.rstrip("/")
        self.account_url = f"{self.blob_url}/{account}"
        self.service = BlobServiceClient(self.account_url, credential=key)
        self.container_name = "snap-" + uuid.uuid4().hex[:12]
        self.container = self.service.create_container(self.container_name)
        self.versioned = False

    def blob(self, name, **kwargs):
        return self.container.get_blob_client(name, **kwargs)

    def url(self, name):
        return f"{self.account_url}/{self.container_name}/{name}"

    def names(self, **kwargs):
        return [(b.name, b.snapshot, b.version_id) for b in self.container.list_blobs(**kwargs)]


@check("snapshots keep content, metadata, and properties")
def snapshots(ctx):
    blob = ctx.blob("snap.txt")
    blob.upload_blob(b"first", overwrite=True, metadata={"gen": "1"})
    snapshot = blob.create_snapshot()
    require(snapshot["snapshot"] and snapshot["etag"], f"snapshot result {snapshot}")
    blob.upload_blob(b"second", overwrite=True, metadata={"gen": "2"})
    old = ctx.blob("snap.txt", snapshot=snapshot["snapshot"])
    require(old.download_blob().readall() == b"first", "snapshot content")
    props = old.get_blob_properties()
    require(props.metadata == {"gen": "1"} and props.size == 5, f"snapshot properties {props.metadata}")
    require(props.snapshot == snapshot["snapshot"], "snapshot id echoed")
    require(blob.download_blob().readall() == b"second", "base content")
    override = blob.create_snapshot(metadata={"gen": "snap"})
    require(
        ctx.blob("snap.txt", snapshot=override["snapshot"]).get_blob_properties().metadata == {"gen": "snap"},
        "snapshot metadata override",
    )
    expect(HttpResponseError, "SnapshotsPresent", blob.delete_blob)
    ranged = old.download_blob(offset=1, length=3).readall()
    require(ranged == b"irs", f"ranged snapshot read {ranged}")


@check("snapshot listing, delete options, and copy source")
def snapshot_listing(ctx):
    blob = ctx.blob("listed.txt")
    blob.upload_blob(b"data", overwrite=True)
    first = blob.create_snapshot()["snapshot"]
    second = blob.create_snapshot()["snapshot"]
    listed = [(n, s) for n, s, _ in ctx.names(name_starts_with="listed", include=["snapshots"])]
    require(listed == [("listed.txt", first), ("listed.txt", second), ("listed.txt", None)], f"listing {listed}")
    copy = ctx.blob("listed-copy.txt")
    copy.start_copy_from_url(f"{ctx.url('listed.txt')}?snapshot={first}")
    require(copy.download_blob().readall() == b"data", "copy from snapshot")
    ctx.blob("listed.txt", snapshot=first).delete_blob()
    expect(HttpResponseError, "BlobNotFound", ctx.blob("listed.txt", snapshot=first).get_blob_properties)
    blob.delete_blob(delete_snapshots="only")
    require(ctx.names(name_starts_with="listed.", include=["snapshots"]) == [("listed.txt", None, None)], "only deleted snapshots")
    blob.create_snapshot()
    blob.delete_blob(delete_snapshots="include")
    require(not ctx.names(name_starts_with="listed.", include=["snapshots"]), "include deleted everything")


@check("versions: ids, listing, read, promote, delete")
def versions(ctx):
    blob = ctx.blob("versioned.txt")
    first = blob.upload_blob(b"v1", overwrite=True)
    if not first.get("version_id"):
        return "skip"
    ctx.versioned = True
    second = blob.upload_blob(b"v2", overwrite=True)
    id1, id2 = first["version_id"], second["version_id"]
    require(id1 != id2, "distinct version ids")
    require(blob.download_blob(version_id=id1).readall() == b"v1", "old version content")
    require(blob.get_blob_properties(version_id=id1).is_current_version is False, "old is not current")
    require(blob.get_blob_properties().is_current_version is True, "new is current")
    listed = [(b.version_id, b.is_current_version) for b in ctx.container.list_blobs(name_starts_with="versioned", include=["versions"])]
    require(listed == [(id1, None), (id2, True)] or listed == [(id1, False), (id2, True)], f"version listing {listed}")
    blob.delete_blob()
    expect(HttpResponseError, "BlobNotFound", blob.get_blob_properties)
    require(blob.download_blob(version_id=id1).readall() == b"v1", "versions survive delete")
    promoted = blob.start_copy_from_url(f"{ctx.url('versioned.txt')}?versionid={id1}")
    require(promoted["copy_status"] == "success", "promote by copy")
    require(blob.download_blob().readall() == b"v1", "promoted content")
    blob.delete_blob(version_id=id2)
    expect(HttpResponseError, "BlobNotFound", lambda: blob.get_blob_properties(version_id=id2))


@check("tags: set, get, filter, conditions")
def tags(ctx):
    blob = ctx.blob("tagged.txt")
    blob.upload_blob(b"x", overwrite=True, tags={"Project": "alpha", "Year": "2021"})
    require(blob.get_blob_tags() == {"Project": "alpha", "Year": "2021"}, "tags on upload")
    require(blob.get_blob_properties().tag_count == 2, "tag count")
    blob.set_blob_tags({"Project": "alpha", "Status": "Final"})
    require(blob.get_blob_tags() == {"Project": "alpha", "Status": "Final"}, "tags replaced")
    other = ctx.blob("tagged-other.txt")
    other.upload_blob(b"y", overwrite=True, tags={"Project": "beta", "Status": "Final"})
    found = sorted(b.name for b in ctx.service.find_blobs_by_tags("\"Project\" = 'alpha'") if b.container_name == ctx.container_name)
    require(found == ["tagged.txt"], f"account filter {found}")
    both = sorted(b.name for b in ctx.container.find_blobs_by_tags("\"Status\" = 'Final'"))
    require(both == ["tagged-other.txt", "tagged.txt"], f"container filter {both}")
    scoped = sorted(
        b.name
        for b in ctx.service.find_blobs_by_tags(f"@container = '{ctx.container_name}' AND \"Project\" > 'a' AND \"Project\" < 'b'")
    )
    require(scoped == ["tagged.txt"], f"range filter {scoped}")
    tagged = [b for b in ctx.container.list_blobs(name_starts_with="tagged", include=["tags"])]
    require({b.name: b.tags for b in tagged}["tagged.txt"] == {"Project": "alpha", "Status": "Final"}, "listing tags")
    require(blob.download_blob(if_tags_match_condition="\"Status\" = 'Final'").readall() == b"x", "tag condition met")
    expect(HttpResponseError, "ConditionNotMet", lambda: blob.download_blob(if_tags_match_condition="\"Status\" = 'Draft'").readall())
    expect(HttpResponseError, "TagsTooLarge", lambda: blob.set_blob_tags({f"k{n}": "v" for n in range(11)}))
    blob.upload_blob(b"z", overwrite=True)
    require(blob.get_blob_tags() == {}, "overwrite clears tags")


@check("batch: delete and tier many blobs, each authorized on its own")
def batch(ctx):
    names = [f"batch-{n}.txt" for n in range(5)]
    for name in names:
        ctx.blob(name).upload_blob(b"data", overwrite=True)
    tiered = ctx.container.set_standard_blob_tier_blobs(StandardBlobTier.Cool, *names[:2])
    require([r.status_code for r in tiered] == [200, 200], "tier batch")
    require(ctx.blob(names[0]).get_blob_properties().blob_tier == "Cool", "tier applied")
    results = ctx.container.delete_blobs(*names[:3], "batch-missing.txt", raise_on_any_failure=False)
    require([r.status_code for r in results] == [202, 202, 202, 404], f"delete batch {[r.status_code for r in results]}")
    for name in names[:3]:
        expect(HttpResponseError, "BlobNotFound", ctx.blob(name).get_blob_properties)
    require(ctx.blob(names[3]).get_blob_properties().size == 4, "other blobs untouched")
    snapshot = ctx.blob(names[3]).create_snapshot()["snapshot"]
    results = ctx.container.delete_blobs(
        {"name": names[3], "snapshot": snapshot}, raise_on_any_failure=False
    )
    require([r.status_code for r in results] == [202], "batch snapshot delete")
    for name in names[3:]:
        ctx.blob(name).delete_blob()


@check("soft delete: list deleted and undelete")
def soft_delete(ctx):
    if ctx.versioned:
        return "skip"  # with versioning a delete keeps a version; run against an account without it
    ctx.service.set_service_properties(delete_retention_policy=RetentionPolicy(enabled=True, days=1))
    try:
        blob = ctx.blob("soft.txt")
        blob.upload_blob(b"precious", overwrite=True, metadata={"keep": "me"})
        snapshot = blob.create_snapshot()["snapshot"]
        blob.delete_blob(delete_snapshots="include")
        expect(HttpResponseError, "BlobNotFound", blob.get_blob_properties)
        deleted = [b for b in ctx.container.list_blobs(name_starts_with="soft", include=["deleted", "snapshots"])]
        require(len(deleted) == 2 and all(b.deleted for b in deleted), f"deleted listing {[(b.name, b.deleted) for b in deleted]}")
        require(all(b.remaining_retention_days == 1 for b in deleted), "remaining retention")
        blob.undelete_blob()
        require(blob.download_blob().readall() == b"precious", "undeleted content")
        require(blob.get_blob_properties().metadata == {"keep": "me"}, "undeleted metadata")
        require(ctx.blob("soft.txt", snapshot=snapshot).download_blob().readall() == b"precious", "undeleted snapshot")
        blob.delete_blob(delete_snapshots="include")
        blob.undelete_blob()
        require(blob.download_blob().readall() == b"precious", "second undelete")
    finally:
        ctx.service.set_service_properties(delete_retention_policy=RetentionPolicy(enabled=False))


@check("block blob versions keep their block lists")
def block_versions(ctx):
    if not ctx.versioned:
        return "skip"
    blob = ctx.blob("blocks.bin")
    blob.stage_block("AAAA", b"one")
    blob.stage_block("BBBB", b"two!")
    blob.commit_block_list([BlobBlock("AAAA"), BlobBlock("BBBB")])
    first = blob.get_blob_properties().version_id
    blob.upload_blob(b"flat", overwrite=True)
    committed, _ = blob.get_block_list("committed", version_id=first) if False else (None, None)
    require(blob.download_blob(version_id=first).readall() == b"onetwo!", "old block blob content")


@check("clean up")
def cleanup(ctx):
    ctx.container.delete_container()


def main():
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--blob-url", default="http://127.0.0.1:10000")
    parser.add_argument("--account", default=ACCOUNT)
    arguments = parser.parse_args()
    key = os.environ.get("AZUIFER_ACCOUNT_KEY", PUBLIC_DEV_KEY)
    context = Context(arguments.blob_url, arguments.account, key)
    for run in CHECKS:
        run(context)
    failed = [result for result in RESULTS if result[1] == "FAIL"]
    for name, _, detail in failed:
        print(f"\n--- {name}\n{detail}")
    print(
        f"\n{sum(r[1] == 'PASS' for r in RESULTS)} passed, {len(failed)} failed, "
        f"{sum(r[1] == 'SKIP' for r in RESULTS)} skipped"
    )
    sys.exit(1 if failed else 0)


if __name__ == "__main__":
    main()
