"""Exercise the third wave of Blob features with the Azure Storage Blob Python SDK against Azuifer.

Start Azuifer first, with the test clock, SDK-compatible API versions, and (for the
external copy check) a copy-source allowlist:

    azuifer serve --in-memory --skip-api-version-check --test-clock --allow-external-copy-sources 127.0.0.1

    pip install azure-storage-blob
    python tests/blob3_sdk.py --blob-url http://127.0.0.1:10000

Checks: page and append blob snapshots with page range diffs, Incremental Copy Blob,
unchanged tier operations, Set Blob Expiry (the SDK has no wrapper, so the generated
operation is used), immutability policies and legal holds, container soft delete with
Restore Container, copy-source tags, service statistics, and a copy from an external
HTTP source. The default account and key are the public development-storage fixture.
"""

import argparse
import http.server
import os
import sys
import threading
import time
import traceback
import urllib.request
import uuid
from datetime import datetime, timedelta, timezone

import requests
from azure.core.exceptions import HttpResponseError
from azure.storage.blob import (
    AccountSasPermissions,
    BlobClient,
    BlobImmutabilityPolicyMode,
    BlobServiceClient,
    BlobType,
    DelimitedJsonDialect,
    DelimitedTextDialect,
    ImmutabilityPolicy,
    ResourceTypes,
    RetentionPolicy,
    StandardBlobTier,
    generate_account_sas,
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
                function(context)
            except Exception:
                RESULTS.append((name, "FAIL", traceback.format_exc()))
                print(f"FAIL {name}")
                return
            RESULTS.append((name, "PASS", f"{time.monotonic() - started:.2f}s"))
            print(f"PASS {name}")

        CHECKS.append(run)
        return run

    return wrap


def require(condition, message):
    if not condition:
        raise AssertionError(message)


def expect(code, call):
    try:
        call()
    except HttpResponseError as error:
        actual = getattr(error, "error_code", None)
        actual = getattr(actual, "value", actual)
        require(actual == code, f"expected {code}, got {actual}: {error}")
        return
    raise AssertionError(f"expected {code}, but the call succeeded")


def dense(total, parts):
    data = bytearray(total)
    for offset, value, length in parts:
        data[offset : offset + length] = bytes([value]) * length
    return bytes(data)


class Context:
    def __init__(self, blob_url, account, key, external):
        self.blob_url = blob_url.rstrip("/")
        self.account = account
        self.key = key
        self.external = external
        self.account_url = f"{self.blob_url}/{account}"
        self.service = BlobServiceClient(self.account_url, credential=key)
        self.container_name = "b3-" + uuid.uuid4().hex[:12]
        self.container = self.service.create_container(self.container_name)

    def blob(self, name):
        return self.container.get_blob_client(name)

    def snapshot_client(self, name, snapshot):
        return BlobClient(
            self.account_url, self.container_name, name, snapshot=snapshot, credential=self.key
        )

    def advance(self, seconds):
        request = urllib.request.Request(
            f"{self.blob_url}/_azuifer/clock/advance?seconds={seconds}", method="POST"
        )
        urllib.request.urlopen(request).read()


@check("page blob snapshots and page range diffs")
def page_snapshots(ctx):
    blob = ctx.blob("disk.vhd")
    blob.create_page_blob(4096, sequence_number=3)
    for offset, value in ((0, b"a"), (1024, b"b"), (2048, b"c")):
        blob.upload_page(value * 512, offset=offset, length=512)
    first = blob.create_snapshot()["snapshot"]
    blob.upload_page(b"d" * 512, offset=0, length=512)
    blob.clear_page(offset=1024, length=512)
    blob.upload_page(b"e" * 512, offset=3072, length=512)
    second = blob.create_snapshot()["snapshot"]

    filled, cleared = blob.get_page_ranges(previous_snapshot_diff=first)
    require(filled == [{"start": 0, "end": 511}, {"start": 3072, "end": 3583}], f"changed {filled}")
    require(cleared == [{"start": 1024, "end": 1535}], f"cleared {cleared}")
    between = ctx.snapshot_client("disk.vhd", second)
    filled, cleared = between.get_page_ranges(previous_snapshot_diff=first)
    require(len(filled) == 2 and len(cleared) == 1, f"snapshot diff {filled} {cleared}")
    listed = list(blob.list_page_ranges(previous_snapshot=first))
    require([(r.start, r.end, r.cleared) for r in listed] == [
        (0, 511, False), (1024, 1535, True), (3072, 3583, False)
    ], f"list_page_ranges {[(r.start, r.end, r.cleared) for r in listed]}")

    original = ctx.snapshot_client("disk.vhd", first)
    require(
        original.download_blob().readall() == dense(4096, [(0, 97, 512), (1024, 98, 512), (2048, 99, 512)]),
        "the first snapshot keeps its bytes",
    )
    props = original.get_blob_properties()
    require(props.blob_type == BlobType.PAGEBLOB and props.page_blob_sequence_number == 3, "snapshot properties")
    ctx.blob("disk.vhd").delete_blob(delete_snapshots="include")
    expect("BlobNotFound", lambda: original.get_blob_properties())


@check("append blob snapshots keep their blocks")
def append_snapshots(ctx):
    blob = ctx.blob("log.txt")
    blob.create_append_blob()
    blob.append_block(b"abc")
    blob.append_block(b"def")
    snapshot = blob.create_snapshot()["snapshot"]
    blob.append_block(b"ghi")
    at_snapshot = ctx.snapshot_client("log.txt", snapshot)
    require(at_snapshot.download_blob().readall() == b"abcdef", "the snapshot keeps two blocks")
    require(at_snapshot.get_blob_properties().append_blob_committed_block_count == 2, "committed block count")
    require(blob.download_blob().readall() == b"abcdefghi", "the blob moved on")


@check("incremental copy blob with a page blob snapshot source")
def incremental_copy(ctx):
    source = ctx.blob("source.vhd")
    source.create_page_blob(4096)
    source.upload_page(b"a" * 512, offset=0, length=512)
    source.upload_page(b"b" * 512, offset=1024, length=512)
    one = source.create_snapshot()["snapshot"]
    source.upload_page(b"c" * 512, offset=0, length=512)
    source.upload_page(b"d" * 512, offset=2048, length=512)
    two = source.create_snapshot()["snapshot"]
    dest = ctx.blob("backup.vhd")

    copied = dest.start_copy_from_url(f"{source.url}?snapshot={one}", incremental_copy=True)
    require(copied["copy_status"] == "success", f"copy status {copied}")
    require(
        dest.download_blob().readall() == dense(4096, [(0, 97, 512), (1024, 98, 512)]),
        "the destination holds the first snapshot",
    )
    props = dest.get_blob_properties()
    require(props.copy.incremental_copy is True, "the destination is an incremental copy blob")
    first_destination = props.copy.destination_snapshot
    require(first_destination, "the destination took a snapshot")

    dest.start_copy_from_url(f"{source.url}?snapshot={two}", incremental_copy=True)
    require(
        dest.download_blob().readall() == dense(4096, [(0, 99, 512), (1024, 98, 512), (2048, 100, 512)]),
        "the destination holds the second snapshot",
    )
    second_destination = dest.get_blob_properties().copy.destination_snapshot
    require(second_destination != first_destination, "each copy takes its own snapshot")
    diff_client = ctx.snapshot_client("backup.vhd", second_destination)
    filled, cleared = diff_client.get_page_ranges(previous_snapshot_diff=first_destination)
    require(
        filled == [{"start": 0, "end": 511}, {"start": 2048, "end": 2559}] and not cleared,
        f"changed ranges {filled} {cleared}",
    )
    expect("IncrementalCopyOfEarlierVersionSnapshotNotAllowed",
           lambda: dest.start_copy_from_url(f"{source.url}?snapshot={one}", incremental_copy=True))


@check("set_standard_blob_tier and premium tiers are unaffected")
def tiers(ctx):
    block = ctx.blob("tiered.txt")
    block.upload_blob(b"tier me")
    block.set_standard_blob_tier(StandardBlobTier.COOL)
    require(block.get_blob_properties().blob_tier == "Cool", "block blob tier")
    page = ctx.blob("tiered.vhd")
    page.create_page_blob(4096)
    page.create_snapshot()
    page.set_premium_page_blob_tier("P20")
    require(page.get_blob_properties().blob_tier == "P20", "page blob tier with a snapshot")


def expiry_header(blob):
    """The `x-ms-expiry-time` of Get Blob Properties, which the SDK model does not expose."""
    headers = blob._client.blob.get_properties(cls=lambda response, _, __: response.http_response.headers)
    return headers.get("x-ms-expiry-time")


@check("set blob expiry through the generated operation expires on the clock")
def expiry(ctx):
    blob = ctx.blob("fleeting.txt")
    blob.upload_blob(b"here for now")
    blob._client.blob.set_expiry(expiry_options="RelativeToNow", expires_on="3000")
    require(expiry_header(blob) is not None, "the expiry time is reported")
    ctx.advance(5)
    expect("BlobNotFound", lambda: blob.get_blob_properties())
    require("fleeting.txt" not in [item.name for item in ctx.container.list_blobs()], "the listing drops it")
    kept = ctx.blob("kept.txt")
    kept.upload_blob(b"x")
    kept._client.blob.set_expiry(expiry_options="RelativeToNow", expires_on="3000")
    kept._client.blob.set_expiry(expiry_options="NeverExpire")
    ctx.advance(5)
    require(expiry_header(kept) is None, "NeverExpire removes the deadline")


@check("immutability policies and legal holds")
def immutability(ctx):
    blob = ctx.blob("ledger.txt")
    blob.upload_blob(b"entry")
    until = datetime.now(timezone.utc) + timedelta(hours=1)
    result = blob.set_immutability_policy(
        ImmutabilityPolicy(expiry_time=until, policy_mode=BlobImmutabilityPolicyMode.UNLOCKED)
    )
    require(result["immutability_policy_mode"] == "unlocked", f"policy {result}")
    props = blob.get_blob_properties()
    require(props.immutability_policy.policy_mode == "unlocked", "the policy is reported")
    require(props.has_legal_hold is False, "no legal hold")
    expect("BlobImmutableDueToPolicy", lambda: blob.delete_blob())
    expect("BlobImmutableDueToPolicy", lambda: blob.upload_blob(b"rewrite", overwrite=True))
    blob.delete_immutability_policy()
    require(blob.get_blob_properties().immutability_policy.policy_mode is None, "the policy is gone")

    hold = blob.set_legal_hold(True)
    require(hold["legal_hold"] is True, f"hold {hold}")
    require(blob.get_blob_properties().has_legal_hold is True, "the hold is reported")
    expect("BlobImmutableDueToLegalHold", lambda: blob.delete_blob())
    blob.set_legal_hold(False)
    blob.delete_blob()


@check("container soft delete and restore container")
def restore_container(ctx):
    ctx.service.set_service_properties(delete_retention_policy=RetentionPolicy(enabled=True, days=1))
    try:
        name = "b3-del-" + uuid.uuid4().hex[:10]
        container = ctx.service.create_container(name, metadata={"team": "blue"})
        container.get_blob_client("a.txt").upload_blob(b"inside", tags={"k": "v"})
        container.delete_container()
        require(name not in [c.name for c in ctx.service.list_containers()], "a deleted container is not listed")
        deleted = [c for c in ctx.service.list_containers(include_deleted=True) if c.name == name]
        require(len(deleted) == 1 and deleted[0].deleted and deleted[0].version, f"deleted listing {deleted}")
        restored = ctx.service.undelete_container(name, deleted[0].version)
        require(restored.get_blob_client("a.txt").download_blob().readall() == b"inside", "blobs come back")
        require(restored.get_container_properties().metadata == {"team": "blue"}, "metadata comes back")
        found = [b.name for b in ctx.service.find_blobs_by_tags("\"k\"='v'") if b.container_name == name]
        require(found == ["a.txt"], f"tags come back {found}")
        restored.delete_container()
        still = [c for c in ctx.service.list_containers(include_deleted=True) if c.name == name]
        require(still and all(c.deleted for c in still), "a deleted container is listed again")
    finally:
        ctx.service.set_service_properties(delete_retention_policy=RetentionPolicy(enabled=False))


@check("copy source tags and service statistics")
def tags_and_stats(ctx):
    source = ctx.blob("tagged.txt")
    source.upload_blob(b"data", tags={"env": "prod"})
    dest = ctx.blob("tagged-copy.txt")
    dest.start_copy_from_url(source.url, requires_sync=True, tags="COPY")
    require(dest.get_blob_tags() == {"env": "prod"}, f"copied tags {dest.get_blob_tags()}")
    dest.start_copy_from_url(source.url, requires_sync=True, tags={"own": "1"})
    require(dest.get_blob_tags() == {"own": "1"}, f"replaced tags {dest.get_blob_tags()}")

    # The SDK sends statistics requests to Azure's secondary host name, so call the endpoint directly.
    sas = generate_account_sas(
        ctx.account,
        ctx.key,
        resource_types=ResourceTypes(service=True),
        permission=AccountSasPermissions(read=True),
        expiry=datetime.now(timezone.utc) + timedelta(hours=1),
    )
    primary = requests.get(f"{ctx.account_url}/?restype=service&comp=stats&{sas}")
    require(primary.status_code == 403 and "InsufficientAccountPermissions" in primary.text, f"primary {primary.status_code}")
    port = ctx.blob_url.rsplit(":", 1)[1]
    secondary = requests.get(f"http://{ctx.account}-secondary.blob.localhost:{port}/?restype=service&comp=stats&{sas}")
    require(secondary.status_code == 200 and "<Status>live</Status>" in secondary.text, f"secondary {secondary.status_code} {secondary.text}")


@check("query blob contents over delimited text and JSON")
def query_contents(ctx):
    people = ctx.blob("people.csv")
    people.upload_blob(b"name,age\nann,31\nbob,25\ncy,40\n")
    with_header = DelimitedTextDialect(has_header=True)
    reader = people.query_blob(
        "SELECT name FROM BlobStorage WHERE age > 30", blob_format=with_header, output_format=with_header
    )
    require(reader.readall() == b"ann\ncy\n", "filtered rows")
    counted = people.query_blob("SELECT COUNT(*) FROM BlobStorage", blob_format=with_header)
    require(counted.readall() == b"3\n", "aggregate")
    as_json = people.query_blob(
        "SELECT name, CAST(age AS INT) + 1 AS next FROM BlobStorage LIMIT 2",
        blob_format=with_header,
        output_format=DelimitedJsonDialect(),
    )
    require(
        as_json.readall() == b'{"name":"ann","next":32}\n{"name":"bob","next":26}\n', "json output"
    )
    events = ctx.blob("events.json")
    events.upload_blob(b'{"a":1,"b":{"c":"x"}}\n{"a":2,"b":{"c":"y"}}\n')
    nested = events.query_blob(
        "SELECT s.b.c FROM BlobStorage s WHERE s.a = 2",
        blob_format=DelimitedJsonDialect(),
        output_format=DelimitedTextDialect(),
    )
    require(nested.readall() == b"y\n", "json input")
    errors = []
    failing = people.query_blob(
        "SELECT CAST(name AS INT) FROM BlobStorage",
        blob_format=with_header,
        on_error=errors.append,
    )
    failing.readall()
    require(errors and errors[0].error == "CastFailed" and errors[0].is_fatal, f"error callback {errors}")
    expect("ParseError", lambda: people.query_blob("SELEC 1 FROM BlobStorage"))


@check("copy from an external http source (opt-in)")
def external_copy(ctx):
    if not ctx.external:
        print("  skipped: start Azuifer with --allow-external-copy-sources 127.0.0.1 and pass --external")
        return

    class Handler(http.server.BaseHTTPRequestHandler):
        def do_GET(self):
            body = b"served from outside"
            self.send_response(200)
            self.send_header("Content-Type", "text/x-outside")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def log_message(self, *args):
            pass

    server = http.server.ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    try:
        blob = ctx.blob("outside.txt")
        copied = blob.start_copy_from_url(f"http://127.0.0.1:{server.server_port}/data?sig=abc")
        require(copied["copy_status"] == "success", f"copy status {copied}")
        require(blob.download_blob().readall() == b"served from outside", "the bytes arrived")
        props = blob.get_blob_properties()
        require(props.content_settings.content_type == "text/x-outside", "the source content type is kept")
        require("sig=" not in props.copy.source, "the source SAS is not recorded")
    finally:
        server.shutdown()


def main():
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--blob-url", default="http://127.0.0.1:10000")
    parser.add_argument("--account", default=ACCOUNT)
    parser.add_argument("--external", action="store_true", help="run the external copy check")
    arguments = parser.parse_args()
    key = os.environ.get("AZUIFER_ACCOUNT_KEY", PUBLIC_DEV_KEY)
    context = Context(arguments.blob_url, arguments.account, key, arguments.external)
    for run in CHECKS:
        run(context)
    failed = [result for result in RESULTS if result[1] == "FAIL"]
    for name, _, detail in failed:
        print(f"\n--- {name}\n{detail}")
    print(f"\n{sum(r[1] == 'PASS' for r in RESULTS)} passed, {len(failed)} failed")
    sys.exit(1 if failed else 0)


if __name__ == "__main__":
    main()
