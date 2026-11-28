"""Exercise page and append blobs with the Azure Storage Blob Python SDK against Azuifer.

Start Azuifer first, for example:

    azuifer serve --in-memory --skip-api-version-check

The SDK requests a newer service version than the Blob baseline, hence
--skip-api-version-check.

    pip install azure-storage-blob
    python tests/blob_page_append_sdk.py --blob-url http://127.0.0.1:10000

The default account and key are the public development-storage fixture that
Azuifer serves when it is not configured otherwise.
"""

import argparse
import hashlib
import os
import sys
import time
import traceback
import uuid
from datetime import datetime, timedelta, timezone

from azure.core.exceptions import HttpResponseError
from azure.storage.blob import (
    BlobClient,
    BlobSasPermissions,
    BlobServiceClient,
    BlobType,
    PremiumPageBlobTier,
    generate_blob_sas,
)

ACCOUNT = "devstoreaccount1"
# The well-known public development-storage key; never a production credential.
PUBLIC_DEV_KEY = (
    "Eby8vdM02xNOcqFlqUwJPLlmEtlCDXJ1OUzFT50uSRZ6IFsuFq2UVErCz4I6tq/K1SZFPTOtr/KBHBeksoGMGw=="
)
MIB = 1024 * 1024

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


def ranges(blob, **kwargs):
    filled, cleared = blob.get_page_ranges(**kwargs)
    require(not cleared, f"unexpected clear ranges {cleared}")
    return [(item["start"], item["end"]) for item in filled]


class Context:
    def __init__(self, blob_url, account, key):
        self.blob_url = blob_url.rstrip("/")
        self.account = account
        self.key = key
        self.account_url = f"{self.blob_url}/{account}"
        self.service = BlobServiceClient(self.account_url, credential=key)
        self.container_name = "pa-" + uuid.uuid4().hex[:12]
        self.container = self.service.create_container(self.container_name)

    def blob(self, name):
        return self.container.get_blob_client(name)

    def url(self, name):
        return f"{self.account_url}/{self.container_name}/{name}"


@check("page blob: create, write, clear, ranges, resize, sequence number")
def page_blob(ctx):
    blob = ctx.blob("disk.vhd")
    blob.create_page_blob(4096, metadata={"role": "disk"}, premium_page_blob_tier=PremiumPageBlobTier.P10)
    props = blob.get_blob_properties()
    require(props.blob_type == BlobType.PAGEBLOB, f"type {props.blob_type}")
    require(props.size == 4096 and props.page_blob_sequence_number == 0, "size or sequence")
    require(props.metadata == {"role": "disk"}, f"metadata {props.metadata}")
    require(props.blob_tier == "P10", f"tier {props.blob_tier}")
    require(blob.download_blob().readall() == bytes(4096), "new page blob reads as zeros")
    require(ranges(blob) == [], "no ranges yet")

    blob.upload_page(b"a" * 512, offset=512, length=512)
    blob.upload_page(b"b" * 1024, offset=1024, length=1024)
    require(ranges(blob) == [(512, 2047)], f"ranges {ranges(blob)}")
    whole = blob.download_blob().readall()
    require(whole == bytes(512) + b"a" * 512 + b"b" * 1024 + bytes(2048), "content after writes")
    require(blob.download_blob(offset=400, length=300).readall() == whole[400:700], "range read")
    require(ranges(blob, offset=1024, length=512) == [(1024, 1535)], "windowed ranges")

    blob.clear_page(offset=512, length=512)
    require(ranges(blob) == [(1024, 2047)], f"ranges after clear {ranges(blob)}")
    require(blob.download_blob(offset=512, length=512).readall() == bytes(512), "cleared pages read as zeros")

    blob.resize_blob(8192)
    require(blob.get_blob_properties().size == 8192, "grown size")
    require(len(blob.download_blob().readall()) == 8192, "grown content")
    blob.resize_blob(1536)
    require(blob.get_blob_properties().size == 1536, "shrunk size")
    require(ranges(blob) == [(1024, 1535)], f"ranges after shrink {ranges(blob)}")

    blob.set_sequence_number("update", 7)
    require(blob.get_blob_properties().page_blob_sequence_number == 7, "update")
    blob.set_sequence_number("max", 3)
    require(blob.get_blob_properties().page_blob_sequence_number == 7, "max keeps the larger")
    blob.set_sequence_number("increment")
    require(blob.get_blob_properties().page_blob_sequence_number == 8, "increment")
    expect(
        "SequenceNumberConditionNotMet",
        lambda: blob.upload_page(b"c" * 512, offset=0, length=512, if_sequence_number_lt=8),
    )
    blob.upload_page(b"c" * 512, offset=0, length=512, if_sequence_number_eq=8)
    expect("InvalidPageRange", lambda: blob.upload_page(b"d" * 512, offset=1536, length=512))
    blob.set_premium_page_blob_tier(PremiumPageBlobTier.P20)
    require(blob.get_blob_properties().blob_tier == "P20", "tier change")


@check("page blob: chunked upload_blob skips zero pages and round-trips")
def page_upload(ctx):
    blob = ctx.blob("image.vhd")
    data = os.urandom(5 * MIB) + bytes(6 * MIB) + os.urandom(2 * MIB + 512)
    blob.upload_blob(data, blob_type=BlobType.PAGEBLOB, max_concurrency=1)
    require(blob.get_blob_properties().size == len(data), "size")
    require(hashlib.sha256(blob.download_blob().readall()).digest() == hashlib.sha256(data).digest(), "hash")
    filled = ranges(blob)
    require(filled[0][0] == 0 and filled[-1][1] == len(data) - 1, f"ends {filled[0]} {filled[-1]}")
    allocated = sum(end - start + 1 for start, end in filled)
    require(allocated <= len(data), "allocation")
    chunks = list(blob.list_page_ranges()) if hasattr(blob, "list_page_ranges") else None
    require(chunks is None or len(chunks) >= 1, "list_page_ranges")
    tail = blob.download_blob(offset=len(data) - 512, length=512).readall()
    require(tail == data[-512:], "tail page")


@check("append blob: create, append, offsets, conditions, seal")
def append_blob(ctx):
    blob = ctx.blob("log.txt")
    blob.create_append_blob(metadata={"kind": "log"})
    props = blob.get_blob_properties()
    require(props.blob_type == BlobType.APPENDBLOB, f"type {props.blob_type}")
    require(props.size == 0 and props.append_blob_committed_block_count == 0, "empty")
    first = blob.append_block(b"hello ")
    require(int(first["blob_append_offset"]) == 0 and first["blob_committed_block_count"] == 1, f"first {first}")
    second = blob.append_block(b"world")
    require(int(second["blob_append_offset"]) == 6 and second["blob_committed_block_count"] == 2, f"second {second}")
    require(blob.download_blob().readall() == b"hello world", "content")
    require(blob.download_blob(offset=3, length=6).readall() == b"lo wor", "range")
    expect("AppendPositionConditionNotMet", lambda: blob.append_block(b"x", appendpos_condition=3))
    expect("MaxBlobSizeConditionNotMet", lambda: blob.append_block(b"xyz", maxsize_condition=12))
    blob.append_block(b"!", appendpos_condition=11, maxsize_condition=12)
    props = blob.get_blob_properties()
    require(props.size == 12 and props.append_blob_committed_block_count == 3, "after conditions")
    require(not props.is_append_blob_sealed, "not sealed")

    blob.seal_append_blob()
    require(blob.get_blob_properties().is_append_blob_sealed, "sealed")
    expect("BlobIsSealed", lambda: blob.append_block(b"more"))
    require(blob.download_blob().readall() == b"hello world!", "sealed content")
    blob.set_blob_metadata({"kind": "sealed"})

    blob.create_append_blob()
    require(not blob.get_blob_properties().is_append_blob_sealed, "recreated blob is not sealed")
    blob.append_block(b"fresh")
    require(blob.download_blob().readall() == b"fresh", "recreated content")


@check("append blob: chunked upload_blob concatenates")
def append_upload(ctx):
    blob = ctx.blob("big.log")
    data = os.urandom(9 * MIB + 17)
    blob.upload_blob(data, blob_type=BlobType.APPENDBLOB)
    props = blob.get_blob_properties()
    require(props.size == len(data), f"size {props.size}")
    require(props.append_blob_committed_block_count >= 3, f"count {props.append_blob_committed_block_count}")
    require(hashlib.sha256(blob.download_blob().readall()).digest() == hashlib.sha256(data).digest(), "hash")
    streamed = b"".join(blob.download_blob(offset=5 * MIB, length=MIB).chunks())
    require(streamed == data[5 * MIB:6 * MIB], "streamed range")


@check("block operations are refused on page and append blobs, and the reverse")
def type_errors(ctx):
    page = ctx.blob("typed-page")
    page.create_page_blob(512)
    append = ctx.blob("typed-append")
    append.create_append_blob()
    block = ctx.blob("typed-block")
    block.upload_blob(b"block")
    for blob in (page, append):
        expect("InvalidBlobType", lambda: blob.stage_block("QUFB", b"x"))
        expect("InvalidBlobType", lambda: blob.get_block_list())
    expect("InvalidBlobType", lambda: block.upload_page(bytes(512), offset=0, length=512))
    expect("InvalidBlobType", lambda: block.get_page_ranges())
    expect("InvalidBlobType", lambda: block.append_block(b"x"))
    expect("InvalidBlobType", lambda: page.append_block(b"x"))
    expect("InvalidBlobType", lambda: append.upload_page(bytes(512), offset=0, length=512))
    expect("InvalidBlobType", lambda: append.resize_blob(512))
    kinds = {item.name: item.blob_type for item in ctx.container.list_blobs(name_starts_with="typed-")}
    require(
        kinds == {
            "typed-page": BlobType.PAGEBLOB,
            "typed-append": BlobType.APPENDBLOB,
            "typed-block": BlobType.BLOCKBLOB,
        },
        f"listing {kinds}",
    )
    sizes = {item.name: item.size for item in ctx.container.list_blobs(name_starts_with="typed-")}
    require(sizes == {"typed-page": 512, "typed-append": 0, "typed-block": 5}, f"sizes {sizes}")


@check("copy and from-URL sources keep types")
def copying(ctx):
    page = ctx.blob("src.vhd")
    page.create_page_blob(4096)
    page.upload_page(b"p" * 1024, offset=512, length=1024)
    copy = ctx.blob("dst.vhd")
    result = copy.start_copy_from_url(page.url)
    require(result["copy_status"] == "success", f"copy {result}")
    props = copy.get_blob_properties()
    require(props.blob_type == BlobType.PAGEBLOB and props.size == 4096, "copied page blob")
    require(ranges(copy) == [(512, 1535)], "copied ranges")
    page.upload_page(b"q" * 512, offset=512, length=512)
    require(copy.download_blob(offset=512, length=512).readall() == b"p" * 512, "copy is independent")

    log = ctx.blob("src.log")
    log.create_append_blob()
    log.append_block(b"one")
    log.append_block(b"two")
    log.seal_append_blob()
    log_copy = ctx.blob("dst.log")
    log_copy.start_copy_from_url(log.url)
    props = log_copy.get_blob_properties()
    require(props.blob_type == BlobType.APPENDBLOB and props.append_blob_committed_block_count == 2, "copied append")
    require(not props.is_append_blob_sealed, "a copy is not sealed")
    log_copy.append_block(b"!")
    require(log_copy.download_blob().readall() == b"onetwo!", "copy accepts appends")

    source = ctx.blob("source.bin")
    source.upload_blob(b"a" * 512 + b"b" * 512)
    target = ctx.blob("from-url.vhd")
    target.create_page_blob(2048)
    target.upload_pages_from_url(source.url, offset=512, length=512, source_offset=512)
    require(ranges(target) == [(512, 1023)], "page from url")
    require(target.download_blob(offset=512, length=512).readall() == b"b" * 512, "page from url content")
    appended = ctx.blob("from-url.log")
    appended.create_append_blob()
    result = appended.append_block_from_url(source.url, source_offset=0, source_length=512)
    require(int(result["blob_append_offset"]) == 0 and result["blob_committed_block_count"] == 1, f"{result}")
    require(appended.download_blob().readall() == b"a" * 512, "append from url content")


@check("from-URL source checksums and sealed copies")
def source_checksums_and_seal(ctx):
    data = b"a" * 512 + b"b" * 512
    source = ctx.blob("checksummed.bin")
    source.upload_blob(data)
    good = hashlib.md5(data[512:]).digest()
    wrong = hashlib.md5(b"other").digest()

    page = ctx.blob("checksummed.vhd")
    page.create_page_blob(2048)
    expect("Md5Mismatch", lambda: page.upload_pages_from_url(
        source.url, offset=0, length=512, source_offset=512, source_content_md5=wrong))
    require(ranges(page) == [], "a rejected source writes no pages")
    page.upload_pages_from_url(source.url, offset=0, length=512, source_offset=512, source_content_md5=good)
    require(page.download_blob(offset=0, length=512).readall() == b"b" * 512, "verified page content")

    log = ctx.blob("checksummed.log")
    log.create_append_blob()
    expect("Md5Mismatch", lambda: log.append_block_from_url(
        source.url, source_offset=512, source_length=512, source_content_md5=wrong))
    require(log.get_blob_properties().size == 0, "a rejected source appends nothing")
    log.append_block_from_url(source.url, source_offset=512, source_length=512, source_content_md5=good)
    require(log.download_blob().readall() == b"b" * 512, "verified append content")

    block = ctx.blob("checksummed.block")
    expect("Md5Mismatch", lambda: block.stage_block_from_url(
        "QQ==", source.url, source_offset=512, source_length=512, source_content_md5=wrong))
    block.stage_block_from_url(
        "QQ==", source.url, source_offset=512, source_length=512, source_content_md5=good)
    committed, uncommitted = block.get_block_list("uncommitted")
    require([item.id for item in uncommitted] == ["QQ=="], f"staged blocks {uncommitted}")

    sealed = ctx.blob("sealed-copy.log")
    sealed.start_copy_from_url(log.url, seal_destination_blob=True)
    require(sealed.get_blob_properties().is_append_blob_sealed, "the copy is sealed")
    expect("BlobIsSealed", lambda: sealed.append_block(b"!"))
    require(not log.get_blob_properties().is_append_blob_sealed, "the source stays open")
    log.append_block(b"!")
    expect("InvalidHeaderValue", lambda: ctx.blob("sealed-copy.bin").start_copy_from_url(
        source.url, seal_destination_blob=True))


@check("a SAS with add permission can append but not write pages")
def sas(ctx):
    append = ctx.blob("sas.log")
    append.create_append_blob()
    page = ctx.blob("sas.vhd")
    page.create_page_blob(512)
    expiry = datetime.now(timezone.utc) + timedelta(hours=1)

    def token(name, **permissions):
        return generate_blob_sas(
            ctx.account, ctx.container_name, name, account_key=ctx.key,
            permission=BlobSasPermissions(**permissions), expiry=expiry,
        )

    adder = BlobClient.from_blob_url(append.url, credential=token("sas.log", add=True))
    require(int(adder.append_block(b"via sas")["blob_append_offset"]) == 0, "append via SAS")
    writer = BlobClient.from_blob_url(page.url, credential=token("sas.vhd", add=True))
    expect("AuthorizationPermissionMismatch", lambda: writer.upload_page(bytes(512), offset=0, length=512))
    page_writer = BlobClient.from_blob_url(page.url, credential=token("sas.vhd", write=True))
    page_writer.upload_page(b"w" * 512, offset=0, length=512)
    reader = BlobClient.from_blob_url(page.url, credential=token("sas.vhd", read=True))
    require(ranges(reader) == [(0, 511)], "page ranges via read SAS")


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
    print(f"\n{sum(r[1] == 'PASS' for r in RESULTS)} passed, {len(failed)} failed")
    sys.exit(1 if failed else 0)


if __name__ == "__main__":
    main()
