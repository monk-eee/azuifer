"""Data Lake Storage Gen2 through the official Python SDK and the Azure CLI.

Usage (from the repository root, after `cargo build`):

    python -m venv target/sdkenv
    target/sdkenv/bin/pip install azure-storage-file-datalake azure-storage-blob
    target/sdkenv/bin/python tests/dfs_sdk.py [--binary target/debug/azuifer] [--az az]

The Data Lake SDK cannot address path-style local endpoints, so every client gets the
host-style URL `http://testaccount.dfs.localhost:PORT` with an explicit account name and
key. The SDK reaches Blob through the `testaccount.blob.localhost` host with the same
port, which the DFS listener serves. `*.localhost` must resolve to the loopback address
(Windows and macOS do; so does glibc with systemd-resolved or nss-myhostname).
`--az` runs the `az storage fs` checks against the same server; pass `--skip-az` to omit
them. This is a manual check, not part of `cargo test`.
"""

import argparse
import base64
import json
import os
import shutil
import subprocess
import sys
import tempfile
import urllib.request
from datetime import datetime, timedelta, timezone
from azure.core.exceptions import ResourceExistsError, ResourceNotFoundError
from azure.storage.blob import BlobServiceClient
from azure.storage.filedatalake import DataLakeServiceClient

ACCOUNT = "testaccount"
KEY = base64.b64encode(bytes(range(32))).decode()
CREDENTIAL = {"account_name": ACCOUNT, "account_key": KEY}
PASSED = []
MIB = 1024 * 1024


def check(name, condition, detail=""):
    if not condition:
        raise AssertionError(f"{name} failed {detail}")
    PASSED.append(name)
    print(f"ok  {name}")


class Server:
    def __init__(self, binary):
        env = {k: v for k, v in os.environ.items() if not k.startswith("AZUIFER_")}
        env["AZUIFER_ACCOUNT_NAME"] = ACCOUNT
        env["AZUIFER_ACCOUNT_KEY"] = KEY
        command = [binary, "serve", "--port", "0", "--admin-port", "0", "--in-memory",
                   "--services", "blob,dfs", "--hns-accounts", ACCOUNT,
                   "--skip-api-version-check", "--test-clock", "--shutdown-on-stdin-eof"]
        self.process = subprocess.Popen(command, stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                                        stderr=subprocess.DEVNULL, env=env, text=True)
        self.ports = {}
        while True:
            line = self.process.stdout.readline()
            if not line:
                raise RuntimeError("server exited during startup")
            name, _, url = line.strip().partition("_url=")
            self.ports[name] = url.rsplit(":", 1)[1]
            if name == "admin":
                break

    def url(self, service):
        return f"http://{ACCOUNT}.{service}.localhost:{self.ports[service]}"

    def advance(self, seconds):
        request = urllib.request.Request(
            f"http://127.0.0.1:{self.ports['admin']}/_azuifer/clock/advance?seconds={seconds}",
            method="POST")
        with urllib.request.urlopen(request) as response:
            assert response.status == 200

    def stop(self):
        self.process.stdin.close()
        self.process.wait(timeout=15)


def names(paths):
    return sorted(path.name for path in paths)


def lifecycle_flow(server):
    service = DataLakeServiceClient(server.url("dfs"), credential=CREDENTIAL)
    check("service account", service.account_name == ACCOUNT)
    fs = service.create_file_system("lake", metadata={"origin": "sdk"})
    check("filesystem list", [f.name for f in service.list_file_systems()] == ["lake"])
    check("filesystem metadata", fs.get_file_system_properties().metadata == {"origin": "sdk"})
    try:
        service.create_file_system("lake")
        check("filesystem exists error", False)
    except ResourceExistsError:
        check("filesystem exists error", True)

    docs = fs.create_directory("docs/sub", metadata={"kind": "folder"})
    check("directory properties",
          docs.get_directory_properties().metadata.get("kind") == "folder")
    check("parent created", fs.get_directory_client("docs").exists())

    data = os.urandom(5 * MIB + 123)
    file = fs.get_file_client("docs/sub/big.bin")
    file.upload_data(data, overwrite=True, chunk_size=MIB, max_concurrency=3)
    properties = file.get_file_properties()
    check("upload size", properties.size == len(data))
    check("download", file.download_file().readall() == data)
    check("ranged download", file.download_file(offset=MIB + 5, length=1000).readall()
          == data[MIB + 5:MIB + 1005])
    try:
        file.upload_data(b"x", overwrite=False)
        check("no overwrite", False)
    except ResourceExistsError:
        check("no overwrite", True)

    blob = BlobServiceClient(server.url("blob"), credential=CREDENTIAL)
    blob_client = blob.get_blob_client("lake", "docs/sub/big.bin")
    blob_properties = blob_client.get_blob_properties()
    check("blob sees the DFS file", blob_client.download_blob().readall() == data)
    check("blob etag matches", blob_properties.etag == properties.etag)

    manual = fs.get_file_client("docs/manual.txt")
    manual.create_file()
    manual.append_data(b"abc", offset=0, length=3)
    manual.append_data(b"def", offset=3, length=3)
    check("unflushed data is invisible", manual.get_file_properties().size == 0)
    manual.flush_data(6)
    check("flushed data", manual.download_file().readall() == b"abcdef")
    lease = manual.acquire_lease()
    try:
        manual.delete_file()
        check("lease blocks delete", False)
    except Exception:
        check("lease blocks delete", True)
    lease.release()

    upload = blob.get_blob_client("lake", "viablob/one.txt")
    upload.upload_blob(b"from blob")
    check("dfs reads the blob", fs.get_file_client("viablob/one.txt").download_file().readall()
          == b"from blob")

    listed = names(fs.get_paths(recursive=True))
    check("recursive listing", listed == ["docs", "docs/manual.txt", "docs/sub",
                                          "docs/sub/big.bin", "viablob", "viablob/one.txt"],
          listed)
    pages = list(fs.get_paths(recursive=True, max_results=2).by_page())
    check("paged listing", len(pages) == 3, len(pages))
    shallow = names(fs.get_paths(path="docs", recursive=False))
    check("directory listing", shallow == ["docs/manual.txt", "docs/sub"], shallow)

    fs.get_directory_client("docs").rename_directory(f"lake/archive")
    check("renamed tree", names(fs.get_paths(recursive=True)) == [
        "archive", "archive/manual.txt", "archive/sub", "archive/sub/big.bin",
        "viablob", "viablob/one.txt"])
    check("old path gone", not fs.get_directory_client("docs").exists())
    check("renamed bytes",
          blob.get_blob_client("lake", "archive/sub/big.bin").download_blob().readall() == data)
    return service, fs


def acl_flow(fs):
    directory = fs.get_directory_client("archive")
    oid = "11111111-2222-3333-4444-555555555555"
    acl = f"user::rwx,user:{oid}:r-x,group::r-x,mask::r-x,other::---"
    directory.set_access_control(acl=acl)
    got = directory.get_access_control()
    check("acl round trip", got["acl"] == acl, got["acl"])
    check("permissions follow the mask", got["permissions"] == "rwxr-x---", got["permissions"])
    check("default owner", got["owner"] == "$superuser", got["owner"])
    directory.set_access_control(permissions="rwx-w-r--")
    check("chmod", directory.get_access_control()["permissions"] == "rwx-w-r--")

    recursive = f"user::rwx,group::r-x,other::---,default:user::rwx,default:user:{oid}:rwx,default:group::r-x,default:other::---"
    result = directory.set_access_control_recursive(acl=recursive, batch_size=2)
    counters = (result.counters.directories_successful, result.counters.files_successful,
                result.counters.failure_count)
    check("recursive set counters", counters == (2, 2, 0), counters)
    file_acl = fs.get_file_client("archive/sub/big.bin").get_access_control()["acl"]
    check("recursive set reaches files", file_acl == "user::rwx,group::r-x,other::---", file_acl)
    modified = directory.update_access_control_recursive(acl=f"user:{oid}:r--", batch_size=1)
    check("recursive modify counters", modified.counters.files_successful == 2)
    removed = directory.remove_access_control_recursive(
        acl=f"user:{oid},default:user:{oid}", batch_size=3)
    check("recursive remove", removed.counters.failure_count == 0
          and removed.counters.directories_successful == 2)
    check("remove drops the named entry",
          oid not in directory.get_access_control()["acl"])

    inherited = fs.get_directory_client("archive").create_sub_directory("child")
    inherited_acl = inherited.get_access_control()["acl"]
    check("default ACL inheritance", "default:user::rwx" in inherited_acl
          and "default:group::r-x" in inherited_acl, inherited_acl)


def expiry_flow(server, service, fs):
    """`create_file(expires_on=...)` sends RelativeToNow for an int and Absolute for a
    datetime. A file with a deadline disappears for the DFS and Blob SDK clients alike once
    the shared test clock passes it, and a flush after the create keeps the deadline."""
    blobs = BlobServiceClient(server.url("blob"), credential=CREDENTIAL)
    files = {
        "ttl/relative.txt": {"expires_on": 60_000},
        "ttl/absolute.txt": {"expires_on": datetime.now(timezone.utc) + timedelta(minutes=10)},
        "ttl/plain.txt": {},
    }
    for path, options in files.items():
        client = fs.get_file_client(path)
        client.create_file(**options)
        client.append_data(b"payload", 0)
        client.flush_data(len(b"payload"))
    relative_properties = fs.get_file_client("ttl/relative.txt").get_file_properties()
    check("the SDK reads the relative deadline", relative_properties.expiry_time is not None)
    check("blob reads the deadline file",
          blobs.get_blob_client("lake", "ttl/relative.txt").get_blob_properties().size
          == relative_properties.size)
    check("plain file has no deadline",
          fs.get_file_client("ttl/plain.txt").get_file_properties().expiry_time is None)
    check("deadline file keeps its bytes", fs.get_file_client("ttl/relative.txt").download_file().readall() == b"payload")
    fs.get_file_client("ttl/relative.txt").rename_file("lake/ttl/renamed.txt")
    check("rename keeps the deadline",
          fs.get_file_client("ttl/renamed.txt").get_file_properties().expiry_time is not None)

    server.advance(90)
    check("expired file is gone for DFS", not fs.get_file_client("ttl/renamed.txt").exists())
    check("expired file is gone for Blob", not blobs.get_blob_client("lake", "ttl/renamed.txt").exists())
    check("later deadline still holds", fs.get_file_client("ttl/absolute.txt").exists())
    check("plain file never expires", fs.get_file_client("ttl/plain.txt").exists())
    fs.delete_directory("ttl")


def delete_flow(service, fs):
    fs.delete_directory("archive")
    check("recursive delete", names(fs.get_paths(recursive=True)) == ["viablob", "viablob/one.txt"])
    try:
        fs.get_file_client("archive/sub/big.bin").get_file_properties()
        check("deleted file is gone", False)
    except ResourceNotFoundError:
        check("deleted file is gone", True)
    service.delete_file_system("lake")
    check("filesystem delete", list(service.list_file_systems()) == [])


def az_flow(server, az):
    """`az storage fs` commands. The CLI derives its DFS URL from the Blob endpoint, so the
    connection string names the `blob` host on the DFS port, which the DFS listener also
    serves for the Blob calls the CLI makes (properties, downloads)."""
    connection = (
        f"DefaultEndpointsProtocol=http;AccountName={ACCOUNT};AccountKey={KEY};"
        f"BlobEndpoint={server.url('dfs').replace('.dfs.', '.blob.')};"
    )
    env = dict(os.environ, AZURE_STORAGE_CONNECTION_STRING=connection)

    def run(*arguments):
        command = [az, "storage", "fs", *arguments, "--auth-mode", "key", "--output", "json",
                   "--only-show-errors"]
        result = subprocess.run(command, env=env, capture_output=True, text=True,
                                timeout=120, shell=os.name == "nt")
        if result.returncode != 0:
            raise AssertionError(
                f"az storage fs {' '.join(arguments[:3])}: {result.stderr.replace(KEY, '***').strip()[:600]}")
        return json.loads(result.stdout) if result.stdout.strip() else None

    run("create", "-n", "azlake")
    check("az fs list", "azlake" in [item["name"] for item in run("list")])
    run("directory", "create", "-f", "azlake", "-n", "dir/inner")
    check("az directory exists", run("directory", "exists", "-f", "azlake", "-n", "dir/inner")["exists"])
    with tempfile.TemporaryDirectory() as temp:
        source = os.path.join(temp, "in.txt")
        with open(source, "wb") as handle:
            handle.write(b"azure cli bytes")
        run("file", "upload", "-f", "azlake", "-p", "dir/inner/a.txt", "-s", source, "--overwrite")
        target = os.path.join(temp, "out.txt")
        run("file", "download", "-f", "azlake", "-p", "dir/inner/a.txt", "-d", target, "--overwrite")
        with open(target, "rb") as handle:
            check("az file round trip", handle.read() == b"azure cli bytes")
    shown = run("file", "show", "-f", "azlake", "-p", "dir/inner/a.txt")
    check("az file show", shown["size"] == len(b"azure cli bytes"), shown)
    listing = [item["name"] for item in run("file", "list", "-f", "azlake", "--path", "dir")]
    check("az file list", "dir/inner/a.txt" in listing or "dir/inner" in listing, listing)
    run("file", "move", "-f", "azlake", "-p", "dir/inner/a.txt", "--new-path", "azlake/dir/b.txt")
    moved = [item["name"] for item in run("file", "list", "-f", "azlake", "--path", "dir")]
    check("az file move", "dir/b.txt" in moved, moved)
    acl = "user::rwx,group::r-x,other::---"
    run("access", "set", "-f", "azlake", "-p", "dir", "--acl", acl)
    check("az access round trip", run("access", "show", "-f", "azlake", "-p", "dir")["acl"] == acl)
    recursive = run("access", "set-recursive", "-f", "azlake", "-p", "dir", "--acl",
                    "user::rwx,group::r-x,other::r--")
    check("az access set-recursive", recursive["counters"]["failureCount"] == 0, recursive)
    run("directory", "delete", "-f", "azlake", "-n", "dir", "--yes")
    run("delete", "-n", "azlake", "--yes")
    check("az cleanup", "azlake" not in [item["name"] for item in run("list")])


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--binary", default="target/debug/azuifer")
    parser.add_argument("--az", default=shutil.which("az") or "az")
    parser.add_argument("--skip-az", action="store_true")
    arguments = parser.parse_args()
    server = Server(arguments.binary)
    try:
        service, fs = lifecycle_flow(server)
        acl_flow(fs)
        expiry_flow(server, service, fs)
        delete_flow(service, fs)
        if not arguments.skip_az:
            az_flow(server, arguments.az)
    finally:
        server.stop()
    print(f"{len(PASSED)} checks passed")


if __name__ == "__main__":
    sys.exit(main())
