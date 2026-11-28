"""Drive Azuifer's FileREST service with the official azure-storage-file-share SDK and
the Azure CLI.

Usage (from the repository root, after `cargo build`):

    python -m venv .venv && .venv/bin/pip install azure-storage-file-share
    .venv/bin/python tests/files_sdk.py [--binary target/debug/azuifer] [--skip-cli]

The script starts the built binary on ephemeral ports with an in-memory store, runs
the SDK flows, then repeats a persistence check against a data directory. It is a
manual compatibility check and is not part of `cargo test`.
"""

import argparse
import base64
import datetime
import hashlib
import json
import os
import shutil
import subprocess
import sys
import tempfile
import uuid

from azure.core.exceptions import ResourceExistsError, ResourceNotFoundError, HttpResponseError
from azure.storage.fileshare import (
    AccountSasPermissions,
    ContentSettings,
    FileSasPermissions,
    ResourceTypes,
    ShareDirectoryClient,
    ShareFileClient,
    ShareServiceClient,
    generate_account_sas,
    generate_file_sas,
)

ACCOUNT = "testaccount"
KEY = base64.b64encode(bytes(range(32))).decode()
# A second configured account, the source of the cross-account copies.
OTHER = "otheraccount"
OTHER_KEY = base64.b64encode(bytes(range(32, 64))).decode()
API_VERSION = "2023-11-03"
PASSED = []


def check(name, condition, detail=""):
    if not condition:
        raise AssertionError(f"{name} failed {detail}")
    PASSED.append(name)
    print(f"ok  {name}")


class Server:
    def __init__(self, binary, location=None):
        env = {k: v for k, v in os.environ.items() if not k.startswith("AZUIFER_")}
        env["AZUIFER_ACCOUNT_NAME"] = ACCOUNT
        env["AZUIFER_ACCOUNT_KEY"] = KEY
        handle, self.config = tempfile.mkstemp(suffix=".toml")
        with os.fdopen(handle, "w") as accounts:
            accounts.write(f'[[accounts]]\nname = "{OTHER}"\nkeys = ["{OTHER_KEY}"]\n')
        command = [binary, "serve", "--port", "0", "--admin-port", "0", "--services", "file",
                   "--skip-api-version-check", "--shutdown-on-stdin-eof", "--config", self.config]
        command += ["--location", location] if location else ["--in-memory"]
        self.process = subprocess.Popen(command, stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                                        stderr=subprocess.DEVNULL, env=env, text=True)
        self.urls = {}
        while True:
            line = self.process.stdout.readline()
            if not line:
                raise RuntimeError("server exited during startup")
            name, _, url = line.strip().partition("_url=")
            self.urls[name] = url
            if name == "admin":
                break

    @property
    def endpoint(self):
        return f"{self.urls['file']}/{ACCOUNT}"

    @property
    def connection_string(self):
        return (f"DefaultEndpointsProtocol=http;AccountName={ACCOUNT};AccountKey={KEY};"
                f"FileEndpoint={self.endpoint};")

    def service(self):
        return ShareServiceClient.from_connection_string(self.connection_string,
                                                         api_version=API_VERSION)

    def other_service(self):
        connection = (f"DefaultEndpointsProtocol=http;AccountName={OTHER};AccountKey={OTHER_KEY};"
                      f"FileEndpoint={self.urls['file']}/{OTHER};")
        return ShareServiceClient.from_connection_string(connection, api_version=API_VERSION)

    def stop(self):
        self.process.stdin.close()
        self.process.wait(timeout=15)
        os.unlink(self.config)


def sdk_flows(server):
    service = server.service()
    share = service.create_share("sdkshare", quota=2, metadata={"purpose": "test"})
    props = share.get_share_properties()
    check("share properties", props.quota == 2 and props.metadata == {"purpose": "test"})
    try:
        service.create_share("sdkshare")
        check("duplicate share rejected", False)
    except ResourceExistsError as error:
        check("duplicate share rejected", error.error_code == "ShareAlreadyExists")
    check("list shares with metadata",
          [s.name for s in service.list_shares(include_metadata=True)] == ["sdkshare"])
    share.set_share_quota(3)
    share.set_share_metadata({"stage": "two"})
    props = share.get_share_properties()
    check("share update", props.quota == 3 and props.metadata == {"stage": "two"})

    root = share.get_directory_client("")
    directory = share.create_directory("Reports")
    nested = directory.create_subdirectory("2026")
    check("directory props", directory.get_directory_properties().is_directory)
    try:
        share.create_directory("reports")
        check("directories are case-insensitive", False)
    except ResourceExistsError:
        check("directories are case-insensitive", True)

    data = os.urandom(5 * 1024 * 1024 + 123)
    file_client = nested.get_file_client("Data.bin")
    file_client.upload_file(data, content_settings=ContentSettings(content_type="application/x-test"),
                            metadata={"origin": "sdk"})
    check("upload and download",
          hashlib.sha256(file_client.download_file().readall()).digest() == hashlib.sha256(data).digest())
    lower = share.get_file_client("reports/2026/data.BIN")
    check("case-insensitive lookup", lower.get_file_properties().size == len(data))
    props = file_client.get_file_properties()
    check("file properties", props.content_settings.content_type == "application/x-test"
          and props.metadata == {"origin": "sdk"} and props.name == "Data.bin")
    check("ranged download",
          file_client.download_file(offset=1000, length=2000).readall() == data[1000:3000])

    sparse = nested.get_file_client("sparse.bin")
    sparse.create_file(1024 * 1024)
    sparse.upload_range(b"hello", offset=512, length=5)
    sparse.upload_range(b"world", offset=2048, length=5)
    ranges = sparse.get_ranges()
    check("list ranges", [(r["start"], r["end"]) for r in ranges] == [(512, 516), (2048, 2052)], ranges)
    sparse.clear_range(offset=512, length=512)
    check("clear range", [(r["start"], r["end"]) for r in sparse.get_ranges()] == [(2048, 2052)])
    content = sparse.download_file(offset=0, length=2060).readall()
    check("holes read as zeros", content[:600] == b"\0" * 600 and content[2048:2052] == b"worl")
    sparse.resize_file(2050)
    check("resize", sparse.get_file_properties().size == 2050
          and sparse.download_file().readall()[2048:] == b"wo")

    listing = list(nested.list_directories_and_files())
    check("list directories and files", sorted(i["name"] for i in listing) == ["Data.bin", "sparse.bin"])
    check("share root listing", [i["name"] for i in root.list_directories_and_files()] == ["Reports"])
    check("name prefix", [i["name"] for i in nested.list_directories_and_files(name_starts_with="sp")]
          == ["sparse.bin"])

    snapshot = share.create_snapshot()
    sparse.upload_range(b"HELLO", offset=512, length=5)
    snap_file = ShareFileClient.from_connection_string(
        server.connection_string, "sdkshare", "Reports/2026/sparse.bin",
        snapshot=snapshot["snapshot"], api_version=API_VERSION)
    check("snapshot keeps old bytes", snap_file.download_file(offset=512, length=5).readall() == b"\0" * 5)
    diff = sparse.get_ranges_diff(previous_sharesnapshot=snapshot["snapshot"])
    check("range diff", [(r["start"], r["end"]) for r in diff[0]] == [(512, 516)], diff)
    check("snapshot listing",
          sorted(s.snapshot is not None for s in service.list_shares(include_snapshots=True)) == [False, True])
    try:
        share.delete_share()
        check("delete share with snapshots refused", False)
    except HttpResponseError as error:
        check("delete share with snapshots refused", error.error_code == "ShareHasSnapshots")

    copy = nested.get_file_client("copy.bin")
    copy.start_copy_from_url(file_client.url)
    check("copy file", copy.download_file().readall() == data
          and copy.get_file_properties().copy.status == "success")

    renamed = file_client.rename_file("Reports/2026/Moved.bin")
    check("rename file", renamed.get_file_properties().size == len(data))
    moved = directory.rename_directory("Archive")
    check("rename directory", moved.get_directory_properties().is_directory
          and share.get_file_client("archive/2026/copy.bin").get_file_properties().size == len(data))
    try:
        share.get_directory_client("Archive").delete_directory()
        check("non-empty directory refused", False)
    except HttpResponseError as error:
        check("non-empty directory refused", error.error_code == "DirectoryNotEmpty")

    leased = share.get_file_client("lease.txt")
    leased.upload_file(b"leased")
    lease = leased.acquire_lease()
    try:
        leased.upload_file(b"nope")
        check("lease blocks writes", False)
    except HttpResponseError as error:
        check("lease blocks writes", error.status_code == 412)
    leased.upload_file(b"again", lease=lease)
    lease.release()
    leased.upload_file(b"free")
    share_lease = share.acquire_lease(lease_duration=15)
    try:
        service.delete_share("sdkshare")
        check("share lease blocks delete", False)
    except HttpResponseError as error:
        check("share lease blocks delete", error.status_code == 412)
    share_lease.release()

    sas = generate_account_sas(ACCOUNT, KEY, resource_types=ResourceTypes(service=True, container=True, object=True),
                               permission=AccountSasPermissions(read=True, list=True),
                               expiry=datetime.datetime.now(datetime.timezone.utc) + datetime.timedelta(hours=1))
    via_sas = ShareServiceClient(server.endpoint, credential=sas, api_version=API_VERSION)
    check("account SAS list", [s.name for s in via_sas.list_shares()] == ["sdkshare"])
    file_sas = generate_file_sas(ACCOUNT, "sdkshare", ["lease.txt"], KEY,
                                 permission=FileSasPermissions(read=True),
                                 expiry=datetime.datetime.now(datetime.timezone.utc) + datetime.timedelta(hours=1))
    reader = ShareFileClient(server.endpoint, "sdkshare", "lease.txt", credential=file_sas,
                                           api_version=API_VERSION)
    check("service SAS read", reader.download_file().readall() == b"free")
    try:
        reader.upload_file(b"x")
        check("service SAS write denied", False)
    except HttpResponseError as error:
        check("service SAS write denied", error.status_code == 403)

    bad = ShareServiceClient(server.endpoint, credential={"account_name": ACCOUNT,
                                                          "account_key": base64.b64encode(b"x" * 32).decode()},
                             api_version=API_VERSION)
    try:
        list(bad.list_shares())
        check("bad key rejected", False)
    except HttpResponseError as error:
        check("bad key rejected", error.status_code == 403)

    service.delete_share("sdkshare", delete_snapshots=True)
    try:
        share.get_share_properties()
        check("share deleted", False)
    except ResourceNotFoundError:
        check("share deleted", True)


def permission_format_flows(server):
    """Binary security descriptors and a source-URL SAS, at the versions that introduce them."""
    service = ShareServiceClient.from_connection_string(server.connection_string,
                                                        api_version="2025-01-05")
    share = service.create_share("binshare")
    sddl = "O:SYG:SYD:(A;;FA;;;SY)"
    sid = bytes([1, 1, 0, 0, 0, 0, 0, 5, 18, 0, 0, 0])
    descriptor = (bytes([1, 0, 0x04, 0x80]) + (48).to_bytes(4, "little") + (60).to_bytes(4, "little")
                  + bytes(4) + (20).to_bytes(4, "little") + bytes([2, 0, 28, 0, 1, 0, 0, 0, 0, 0, 20, 0])
                  + (0x001F01FF).to_bytes(4, "little") + sid * 3)
    binary = base64.b64encode(descriptor).decode()
    # The share-level permission calls ignore or mishandle file_permission_format in this
    # SDK release, so the binary form is driven through the directory and file calls, and
    # the share-level read-back confirms what was stored.
    key = share.create_permission_for_share(sddl)
    created = share.get_directory_client("").create_subdirectory(
        "secured", file_permission=binary, file_permission_format="binary")
    check("directory created from a binary descriptor",
          created.get_directory_properties().permission_key == key)
    check("binary descriptor stored as sddl", share.get_permission_for_share(key) == sddl)
    try:
        share.get_directory_client("").create_subdirectory(
            "broken", file_permission="AAAA", file_permission_format="binary")
        check("invalid binary descriptor rejected", False)
    except HttpResponseError as error:
        check("invalid binary descriptor rejected", error.error_code == "FileInvalidPermission")

    source = share.get_file_client("source.txt")
    source.upload_file(b"copy me")
    expiry = datetime.datetime.now(datetime.timezone.utc) + datetime.timedelta(hours=1)
    read = generate_file_sas(ACCOUNT, "binshare", ["source.txt"], KEY,
                             permission=FileSasPermissions(read=True), expiry=expiry)
    write = generate_file_sas(ACCOUNT, "binshare", ["source.txt"], KEY,
                              permission=FileSasPermissions(write=True), expiry=expiry)
    copy = share.get_file_client("copy.txt")
    copy.start_copy_from_url(f"{source.url}?{read}")
    check("copy with a read SAS", copy.download_file().readall() == b"copy me")
    try:
        share.get_file_client("refused.txt").start_copy_from_url(f"{source.url}?{write}")
        check("copy with a write-only SAS refused", False)
    except HttpResponseError as error:
        check("copy with a write-only SAS refused",
              error.status_code == 403 and error.error_code == "CannotVerifyCopySource")
    service.delete_share("binshare")

def crc64_nvme(data):
    """CRC-64/NVME, the checksum Azuifer compares source ranges with, as the 8 bytes the SDK sends."""
    crc = 0xFFFFFFFFFFFFFFFF
    for byte in data:
        crc ^= byte
        for _ in range(8):
            crc = (crc >> 1) ^ (0x9A6C9329AC4BC9B5 if crc & 1 else 0)
    return (crc ^ 0xFFFFFFFFFFFFFFFF).to_bytes(8, "little")


def expect_error(call, status, code):
    try:
        call()
    except HttpResponseError as error:
        check(f"{code} ({status})", error.status_code == status and error.error_code == code,
              f"{error.status_code} {error.error_code}")
        return
    raise AssertionError(f"expected {status} {code}, but the call succeeded")


def source_checksum_and_cross_account_flows(server):
    check("crc64 test vector", crc64_nvme(b"123456789") == (0xAE8B14860A799888).to_bytes(8, "little"))
    source = server.other_service().create_share("crosssrc").get_file_client("data.bin")
    source.upload_file(b"0123456789")
    expiry = datetime.datetime.now(datetime.timezone.utc) + datetime.timedelta(hours=1)
    read = generate_file_sas(OTHER, "crosssrc", ["data.bin"], OTHER_KEY,
                             permission=FileSasPermissions(read=True), expiry=expiry)
    local = generate_file_sas(ACCOUNT, "crosssrc", ["data.bin"], KEY,
                              permission=FileSasPermissions(read=True), expiry=expiry)
    share = server.service().create_share("crossdst")

    copy = share.get_file_client("copied.bin")
    copy.start_copy_from_url(f"{source.url}?{read}")
    check("copy from another account with its SAS", copy.download_file().readall() == b"0123456789")
    expect_error(lambda: share.get_file_client("refused.bin").start_copy_from_url(source.url),
                 403, "CannotVerifyCopySource")
    expect_error(lambda: share.get_file_client("refused.bin").start_copy_from_url(
        f"{source.url}?{local}"), 403, "CannotVerifyCopySource")

    target = share.get_file_client("ranged.bin")
    target.create_file(10)
    url = f"{source.url}?{read}"
    expect_error(lambda: target.upload_range_from_url(
        url, offset=0, length=5, source_offset=5, source_content_crc64=crc64_nvme(b"other")),
        400, "Crc64Mismatch")
    check("a rejected source range writes nothing", target.download_file().readall() == bytes(10))
    target.upload_range_from_url(
        url, offset=0, length=5, source_offset=5, source_content_crc64=crc64_nvme(b"56789"))
    check("range from another account with a verified CRC64",
          target.download_file(offset=0, length=5).readall() == b"56789")
    server.service().delete_share("crossdst")
    server.other_service().delete_share("crosssrc")


def cli_flows(server, workdir):
    az = shutil.which("az") or shutil.which("az.cmd")
    if not az:
        print("skip az (not installed)")
        return
    env = {**os.environ, "AZURE_STORAGE_CONNECTION_STRING": server.connection_string,
           "AZURE_CORE_COLLECT_TELEMETRY": "false"}

    def run(*args):
        result = subprocess.run([az, "storage", *args, "--only-show-errors", "-o", "json"], env=env,
                                capture_output=True, text=True, timeout=180)
        if result.returncode != 0:
            raise AssertionError(f"az {' '.join(args)} failed: {result.stderr}")
        return json.loads(result.stdout) if result.stdout.strip() else None

    run("share", "create", "-n", "clishare", "--quota", "1")
    check("az share exists", run("share", "exists", "-n", "clishare")["exists"])
    run("directory", "create", "-s", "clishare", "-n", "docs")
    source = os.path.join(workdir, "upload.bin")
    payload = os.urandom(300_000)
    with open(source, "wb") as handle:
        handle.write(payload)
    run("file", "upload", "-s", "clishare", "--source", source, "--path", "docs/upload.bin")
    names = [item["name"] for item in run("file", "list", "-s", "clishare", "-p", "docs")]
    check("az file list", names == ["upload.bin"], names)
    target = os.path.join(workdir, "download.bin")
    run("file", "download", "-s", "clishare", "-p", "docs/upload.bin", "--dest", target)
    with open(target, "rb") as handle:
        check("az file download", handle.read() == payload)
    run("file", "metadata", "update", "-s", "clishare", "-p", "docs/upload.bin", "--metadata", "k=v")
    check("az file metadata", run("file", "metadata", "show", "-s", "clishare", "-p", "docs/upload.bin") == {"k": "v"})
    run("file", "copy", "start", "-s", "clishare", "-p", "docs/copy.bin", "--source-share", "clishare",
        "--source-path", "docs/upload.bin")
    check("az file copy", run("file", "exists", "-s", "clishare", "-p", "docs/copy.bin")["exists"])
    run("file", "delete", "-s", "clishare", "-p", "docs/copy.bin")
    check("az file delete", not run("file", "exists", "-s", "clishare", "-p", "docs/copy.bin")["exists"])
    run("share", "delete", "-n", "clishare", "--delete-snapshots", "include")


def persistence(binary, workdir):
    location = os.path.join(workdir, "data")
    server = Server(binary, location)
    try:
        share = server.service().create_share("persist")
        file_client = share.get_directory_client("").create_subdirectory("Keep").get_file_client("a.bin")
        file_client.create_file(100)
        file_client.upload_range(b"durable", offset=50, length=7)
    finally:
        server.stop()
    server = Server(binary, location)
    try:
        client = server.service().get_share_client("persist").get_file_client("keep/A.BIN")
        check("state survives restart", client.download_file(offset=50, length=7).readall() == b"durable")
    finally:
        server.stop()


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--binary", default=os.path.join("target", "debug", "azuifer.exe" if os.name == "nt" else "azuifer"))
    parser.add_argument("--skip-cli", action="store_true")
    args = parser.parse_args()
    workdir = tempfile.mkdtemp(prefix="azuifer-files-")
    try:
        server = Server(args.binary)
        try:
            sdk_flows(server)
            permission_format_flows(server)
            source_checksum_and_cross_account_flows(server)
            if not args.skip_cli:
                cli_flows(server, workdir)
        finally:
            server.stop()
        persistence(args.binary, workdir)
    finally:
        shutil.rmtree(workdir, ignore_errors=True)
    print(f"{len(PASSED)} checks passed")


if __name__ == "__main__":
    sys.exit(main())
