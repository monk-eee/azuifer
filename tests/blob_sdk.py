"""Exercise the Azure Storage Blob Python SDK against a running Azuifer Blob listener.

Start Azuifer first, for example:

    azuifer serve --in-memory --skip-api-version-check --test-clock

The SDK requests a newer service version than the Blob baseline, hence
--skip-api-version-check. --test-clock lets the lease section advance the
server clock instead of sleeping; without it that section is skipped.

    pip install azure-storage-blob
    python tests/blob_sdk.py --blob-url http://127.0.0.1:10000

The default account and key are the public development-storage fixture that
Azuifer serves when it is not configured otherwise.
"""

import argparse
import os
import sys
import time
import traceback
import urllib.request
import uuid
from datetime import datetime, timedelta, timezone

from azure.core import MatchConditions
from azure.core.exceptions import (
    HttpResponseError,
    ResourceExistsError,
    ResourceModifiedError,
    ResourceNotFoundError,
)
from azure.storage.blob import (
    AccessPolicy,
    AccountSasPermissions,
    BlobBlock,
    BlobClient,
    BlobLeaseClient,
    BlobPrefix,
    BlobSasPermissions,
    BlobServiceClient,
    ContainerClient,
    ContainerSasPermissions,
    ContentSettings,
    CorsRule,
    ResourceTypes,
    StandardBlobTier,
    generate_account_sas,
    generate_blob_sas,
    generate_container_sas,
)

ACCOUNT = "devstoreaccount1"
# The well-known public development-storage key; never a production credential.
PUBLIC_DEV_KEY = (
    "Eby8vdM02xNOcqFlqUwJPLlmEtlCDXJ1OUzFT50uSRZ6IFsuFq2UVErCz4I6tq/K1SZFPTOtr/KBHBeksoGMGw=="
)

RESULTS = []


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

        run.check_name = name
        CHECKS.append(run)
        return run

    return wrap


CHECKS = []


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
    def __init__(self, blob_url, account, key, admin_clock):
        self.blob_url = blob_url.rstrip("/")
        self.account = account
        self.key = key
        self.account_url = f"{self.blob_url}/{account}"
        self.service = BlobServiceClient(self.account_url, credential=key)
        self.admin_clock = admin_clock
        self.container_name = "sdk-" + uuid.uuid4().hex[:12]
        self.container = self.service.create_container(
            self.container_name, metadata={"purpose": "sdk"}
        )

    def blob(self, name):
        return self.container.get_blob_client(name)

    def url(self, name):
        return f"{self.account_url}/{self.container_name}/{name}"

    def advance(self, seconds):
        request = urllib.request.Request(
            f"{self.blob_url}/_azuifer/clock/advance?seconds={seconds}", method="POST"
        )
        opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))
        opener.open(request, timeout=10).read()

    def far(self):
        return datetime.now(timezone.utc) + timedelta(days=1)


@check("container lifecycle, metadata, listing")
def container_lifecycle(ctx):
    props = ctx.container.get_container_properties()
    require(props.metadata == {"purpose": "sdk"}, f"metadata {props.metadata}")
    require(props.lease.state == "available" and props.lease.status == "unlocked", "lease")
    ctx.container.set_container_metadata({"owner": "tests"})
    require(ctx.container.get_container_properties().metadata == {"owner": "tests"}, "set metadata")
    listed = list(ctx.service.list_containers(name_starts_with=ctx.container_name, include_metadata=True))
    require([c.name for c in listed] == [ctx.container_name], "list containers")
    require(listed[0].metadata == {"owner": "tests"}, "list metadata")
    expect(ResourceExistsError, "ContainerAlreadyExists",
           lambda: ctx.service.create_container(ctx.container_name))


@check("upload, download, ranges, properties, metadata")
def blobs(ctx):
    blob = ctx.blob("docs/hello.txt")
    blob.upload_blob(
        b"hello world",
        content_settings=ContentSettings(
            content_type="text/plain",
            content_language="en-AU",
            content_disposition="attachment; filename=hello.txt",
            cache_control="no-cache",
        ),
        metadata={"origin": "sdk"},
    )
    expect(ResourceExistsError, "BlobAlreadyExists", lambda: blob.upload_blob(b"again", overwrite=False))
    require(blob.download_blob().readall() == b"hello world", "download")
    require(blob.download_blob(offset=6, length=5).readall() == b"world", "range")
    props = blob.get_blob_properties()
    require(props.size == 11, "size")
    require(props.content_settings.content_type == "text/plain", "content type")
    require(props.content_settings.content_language == "en-AU", "language")
    require(props.content_settings.cache_control == "no-cache", "cache control")
    require(props.metadata == {"origin": "sdk"}, f"metadata {props.metadata}")
    require(props.blob_tier == "Hot" and props.blob_tier_inferred, "inferred tier")
    require(props.lease.state == "available", "lease state")
    etag = props.etag
    blob.set_http_headers(ContentSettings(content_type="text/csv"))
    changed = blob.get_blob_properties()
    require(changed.etag != etag, "etag changes with properties")
    require(changed.content_settings.content_type == "text/csv", "set http headers")
    require(changed.content_settings.content_language is None, "unspecified properties are cleared")
    require(changed.metadata == {"origin": "sdk"}, "metadata kept")
    blob.set_blob_metadata({"stage": "two"})
    require(blob.get_blob_properties().metadata == {"stage": "two"}, "set metadata")
    blob.set_standard_blob_tier(StandardBlobTier.COOL)
    require(blob.get_blob_properties().blob_tier == "Cool", "tier")
    expect(ResourceModifiedError, "ConditionNotMet",
           lambda: blob.upload_blob(b"stale", overwrite=True, etag=etag,
                                    match_condition=MatchConditions.IfNotModified))
    expect(ResourceNotFoundError, "BlobNotFound", lambda: ctx.blob("absent").get_blob_properties())
    blob.delete_blob()
    expect(ResourceNotFoundError, "BlobNotFound", lambda: blob.get_blob_properties())


@check("block blobs: stage, commit, block list")
def block_blobs(ctx):
    blob = ctx.blob("blocks.bin")
    blob.stage_block("block-1".ljust(8, "_"), b"first-")
    blob.stage_block("block-2".ljust(8, "_"), b"second")
    blob.commit_block_list(
        [BlobBlock("block-1".ljust(8, "_")), BlobBlock("block-2".ljust(8, "_"))],
        content_settings=ContentSettings(content_type="application/x-blocks"),
        metadata={"blocks": "2"},
    )
    require(blob.download_blob().readall() == b"first-second", "assembled bytes")
    committed, uncommitted = blob.get_block_list("all")
    require([b.size for b in committed] == [6, 6] and not uncommitted, "block list")
    require(blob.get_blob_properties().metadata == {"blocks": "2"}, "commit metadata")


@check("listings: prefix, delimiter walk, include options")
def listings(ctx):
    for name in ["a/1", "a/2", "b", "c/d/e", "c/f"]:
        ctx.blob(name).upload_blob(b"x", metadata={"n": name.replace("/", "_")})
    flat = [b.name for b in ctx.container.list_blobs(name_starts_with="c/")]
    require(flat == ["c/d/e", "c/f"], f"prefix listing {flat}")
    walked = [(type(item).__name__, item.name) for item in ctx.container.walk_blobs(delimiter="/")]
    names = sorted(name for kind, name in walked if name in ("a/", "b", "c/"))
    require(names == ["a/", "b", "c/"], f"walk {walked}")
    require(any(isinstance(item, BlobPrefix) for item in ctx.container.walk_blobs(delimiter="/")), "BlobPrefix")
    with_meta = {b.name: b.metadata for b in ctx.container.list_blobs(name_starts_with="a/", include=["metadata"])}
    require(with_meta == {"a/1": {"n": "a_1"}, "a/2": {"n": "a_2"}}, f"metadata {with_meta}")
    paged = list(ctx.container.list_blobs(results_per_page=2))
    require(len(paged) >= 5, "paged listing")
    stage = ctx.blob("uncommitted")
    stage.stage_block("QQ==", b"abc")
    shown = [b.name for b in ctx.container.list_blobs(include=["uncommittedblobs"], name_starts_with="uncommitted")]
    require(shown == ["uncommitted"], f"uncommitted {shown}")
    require(not list(ctx.container.list_blobs(name_starts_with="uncommitted")), "hidden by default")


@check("leases: blob and container state machine")
def leases(ctx):
    if not ctx.admin_clock:
        return "skip"
    blob = ctx.blob("leased.txt")
    blob.upload_blob(b"v1")
    lease = BlobLeaseClient(blob)
    lease.acquire(lease_duration=15)
    props = blob.get_blob_properties()
    require((props.lease.state, props.lease.status, props.lease.duration) == ("leased", "locked", "fixed"), "view")
    expect(HttpResponseError, "LeaseIdMissing", lambda: blob.upload_blob(b"v2", overwrite=True))
    blob.upload_blob(b"v2", overwrite=True, lease=lease)
    expect(HttpResponseError, "LeaseAlreadyPresent",
           lambda: BlobLeaseClient(blob).acquire(lease_duration=15))
    lease.renew()
    new_id = str(uuid.uuid4())
    lease.change(new_id)
    require(lease.id == new_id, "changed id")
    lease.break_lease(lease_break_period=5)
    require(blob.get_blob_properties().lease.state == "breaking", "breaking")
    ctx.advance(6)
    require(blob.get_blob_properties().lease.state == "broken", "broken")
    blob.upload_blob(b"v3", overwrite=True)
    lease.release()
    require(blob.get_blob_properties().lease.state == "available", "released")
    infinite = BlobLeaseClient(blob)
    infinite.acquire(lease_duration=-1)
    require(blob.get_blob_properties().lease.duration == "infinite", "infinite")
    # Signed requests carry the real date, so keep the total clock shift under the 15 minute skew.
    ctx.advance(600)
    require(blob.get_blob_properties().lease.state == "leased", "infinite never expires")
    infinite.release()

    container_lease = BlobLeaseClient(ctx.container)
    container_lease.acquire(lease_duration=15)
    require(ctx.container.get_container_properties().lease.state == "leased", "container leased")
    expect(HttpResponseError, "LeaseIdMissing", lambda: ctx.container.delete_container())
    ctx.advance(16)
    require(ctx.container.get_container_properties().lease.state == "expired", "container lease expires")
    container_lease.release()


@check("SAS tokens generated by the SDK")
def sas(ctx):
    blob = ctx.blob("sas.txt")
    blob.upload_blob(b"sas body", metadata={"k": "v"})
    expiry = ctx.far()
    token = generate_blob_sas(ctx.account, ctx.container_name, "sas.txt", account_key=ctx.key,
                              permission=BlobSasPermissions(read=True), expiry=expiry)
    reader = BlobClient.from_blob_url(f"{ctx.url('sas.txt')}?{token}")
    require(reader.download_blob().readall() == b"sas body", "blob SAS read")
    require(reader.get_blob_properties().metadata == {"k": "v"}, "blob SAS properties")
    expect(HttpResponseError, "AuthorizationPermissionMismatch", lambda: reader.upload_blob(b"x", overwrite=True))
    writer_token = generate_blob_sas(ctx.account, ctx.container_name, "sas.txt", account_key=ctx.key,
                                     permission=BlobSasPermissions(write=True, create=True, delete=True), expiry=expiry)
    writer = BlobClient.from_blob_url(f"{ctx.url('sas.txt')}?{writer_token}")
    writer.upload_blob(b"rewritten", overwrite=True)
    require(blob.download_blob().readall() == b"rewritten", "blob SAS write")
    container_token = generate_container_sas(ctx.account, ctx.container_name, account_key=ctx.key,
                                             permission=ContainerSasPermissions(read=True, list=True), expiry=expiry)
    container = ContainerClient(ctx.account_url, ctx.container_name, credential=container_token)
    require("sas.txt" in [b.name for b in container.list_blobs()], "container SAS list")
    require(container.get_blob_client("sas.txt").download_blob().readall() == b"rewritten", "container SAS read")
    account_token = generate_account_sas(ctx.account, ctx.key, resource_types=ResourceTypes(service=True, container=True, object=True),
                                         permission=AccountSasPermissions(read=True, write=True, list=True, create=True, delete=True),
                                         expiry=expiry)
    by_account = BlobServiceClient(ctx.account_url, credential=account_token)
    require(ctx.container_name in [c.name for c in by_account.list_containers()], "account SAS list containers")
    made = by_account.create_container(ctx.container_name + "-acct")
    made.delete_container()
    expired = generate_blob_sas(ctx.account, ctx.container_name, "sas.txt", account_key=ctx.key,
                                permission=BlobSasPermissions(read=True),
                                expiry=datetime.now(timezone.utc) - timedelta(hours=1),
                                start=datetime.now(timezone.utc) - timedelta(hours=2))
    expect(HttpResponseError, "AuthenticationFailed",
           lambda: BlobClient.from_blob_url(f"{ctx.url('sas.txt')}?{expired}").download_blob())
    other = generate_blob_sas(ctx.account, ctx.container_name, "different.txt", account_key=ctx.key,
                              permission=BlobSasPermissions(read=True), expiry=expiry)
    expect(HttpResponseError, "AuthenticationFailed",
           lambda: BlobClient.from_blob_url(f"{ctx.url('sas.txt')}?{other}").download_blob())


@check("stored access policies and anonymous public access")
def policies_and_public_access(ctx):
    blob = ctx.blob("public.txt")
    blob.upload_blob(b"public body")
    expect(HttpResponseError, "ResourceNotFound",
           lambda: BlobClient.from_blob_url(ctx.url("public.txt")).download_blob())
    policy = AccessPolicy(permission=ContainerSasPermissions(read=True, list=True),
                          start=datetime.now(timezone.utc) - timedelta(hours=1), expiry=ctx.far())
    ctx.container.set_container_access_policy({"reader": policy}, public_access="blob")
    acl = ctx.container.get_container_access_policy()
    require(acl["public_access"] == "blob", f"public access {acl['public_access']}")
    require([p.id for p in acl["signed_identifiers"]] == ["reader"], "identifiers")
    anonymous = BlobClient.from_blob_url(ctx.url("public.txt"))
    require(anonymous.download_blob().readall() == b"public body", "anonymous blob read")
    expect(HttpResponseError, "AuthenticationFailed",
           lambda: list(ContainerClient(ctx.account_url, ctx.container_name).list_blobs()))
    token = generate_container_sas(ctx.account, ctx.container_name, account_key=ctx.key, policy_id="reader")
    by_policy = ContainerClient(ctx.account_url, ctx.container_name, credential=token)
    require("public.txt" in [b.name for b in by_policy.list_blobs()], "policy-based SAS")
    ctx.container.set_container_access_policy({}, public_access=None)
    expect(HttpResponseError, "AuthenticationFailed", lambda: list(by_policy.list_blobs()))


@check("copy, put blob from URL, stage block from URL")
def copies(ctx):
    source = ctx.blob("copy-source.txt")
    source.upload_blob(b"0123456789", metadata={"from": "source"},
                       content_settings=ContentSettings(content_type="text/x-src"))
    token = generate_blob_sas(ctx.account, ctx.container_name, "copy-source.txt", account_key=ctx.key,
                              permission=BlobSasPermissions(read=True), expiry=ctx.far())
    source_url = f"{ctx.url('copy-source.txt')}?{token}"
    target = ctx.blob("copy-target.txt")
    result = target.start_copy_from_url(source_url)
    require(result["copy_status"] == "success" and result["copy_id"], f"copy result {result}")
    props = target.get_blob_properties()
    require(props.copy.status == "success" and props.copy.id == result["copy_id"], "copy properties")
    require(props.metadata == {"from": "source"}, "copy metadata")
    require(target.download_blob().readall() == b"0123456789", "copy content")
    expect(HttpResponseError, "NoPendingCopyOperation", lambda: target.abort_copy(result["copy_id"]))
    keyed = ctx.blob("copy-keyed.txt")
    keyed.start_copy_from_url(ctx.url("copy-source.txt"))
    require(keyed.download_blob().readall() == b"0123456789", "same-account copy by key")
    from_url = ctx.blob("from-url.txt")
    from_url.upload_blob_from_url(source_url, overwrite=True)
    require(from_url.download_blob().readall() == b"0123456789", "put blob from url")
    staged = ctx.blob("staged-from-url.bin")
    staged.stage_block_from_url("QQ==", source_url, source_offset=2, source_length=3)
    staged.commit_block_list([BlobBlock("QQ==")])
    require(staged.download_blob().readall() == b"234", "put block from url")
    expect(HttpResponseError, "CannotVerifyCopySource",
           lambda: ctx.blob("denied.txt").start_copy_from_url(f"{ctx.url('copy-source.txt')}?{token}x"))


@check("service properties, CORS, account information")
def service_properties(ctx):
    rule = CorsRule(["https://app.test"], ["GET", "PUT"], allowed_headers=["x-ms-*"],
                    exposed_headers=["x-ms-meta-*"], max_age_in_seconds=60)
    ctx.service.set_service_properties(cors=[rule])
    stored = ctx.service.get_service_properties()
    require(len(stored["cors"]) == 1 and stored["cors"][0].allowed_origins == "https://app.test", f"cors {stored['cors']}")
    require(stored["hour_metrics"].enabled, "defaults kept")
    request = urllib.request.Request(
        ctx.url("x"), method="OPTIONS",
        headers={"Origin": "https://app.test", "Access-Control-Request-Method": "GET"})
    opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))
    response = opener.open(request, timeout=10)
    require(response.headers["Access-Control-Allow-Origin"] == "https://app.test", "preflight")
    ctx.service.set_service_properties(cors=[])
    info = ctx.service.get_account_information()
    require(info["sku_name"] and info["account_kind"], f"account info {info}")


@check("clean up")
def cleanup(ctx):
    try:
        ctx.container.delete_container()
    except HttpResponseError:
        BlobLeaseClient(ctx.container).break_lease(lease_break_period=0)
        ctx.container.delete_container()


def main():
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--blob-url", default="http://127.0.0.1:10000")
    parser.add_argument("--account", default=ACCOUNT)
    parser.add_argument("--no-test-clock", action="store_true", help="skip checks that need --test-clock")
    arguments = parser.parse_args()
    key = os.environ.get("AZUIFER_ACCOUNT_KEY", PUBLIC_DEV_KEY)
    context = Context(arguments.blob_url, arguments.account, key, not arguments.no_test_clock)
    for run in CHECKS:
        run(context)
    failed = [result for result in RESULTS if result[1] == "FAIL"]
    for name, status, detail in failed:
        print(f"\n--- {name}\n{detail}")
    print(f"\n{sum(r[1] == 'PASS' for r in RESULTS)} passed, {len(failed)} failed, "
          f"{sum(r[1] == 'SKIP' for r in RESULTS)} skipped")
    sys.exit(1 if failed else 0)


if __name__ == "__main__":
    main()
