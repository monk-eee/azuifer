"""Exercise the installed Azure CLI against an isolated Azuifer listener."""

import argparse
import base64
import hashlib
import json
import os
import shutil
import subprocess
import tempfile
import time
import uuid
from pathlib import Path
from urllib.error import URLError
from urllib.parse import urlsplit
from urllib.request import ProxyHandler, build_opener

ACCOUNT = "devstoreaccount1"


def require(condition, message):
    if not condition:
        raise AssertionError(message)


def loopback_url(value):
    parsed = urlsplit(value)
    if (
        parsed.scheme != "http"
        or parsed.hostname != "127.0.0.1"
        or not parsed.port
        or parsed.netloc != f"127.0.0.1:{parsed.port}"
        or parsed.path not in ("", "/")
        or parsed.query
        or parsed.fragment
    ):
        raise ValueError("the CLI fixture only accepts http://127.0.0.1:<port>")
    return value.rstrip("/")


def wait_ready(admin):
    opener = build_opener(ProxyHandler({}))
    deadline = time.monotonic() + 15
    while True:
        try:
            with opener.open(admin + "/readyz", timeout=2) as response:
                require(response.read() == b"ready\n", "unexpected readiness response")
            return
        except URLError:
            if time.monotonic() >= deadline:
                raise
            time.sleep(0.2)


def connection_string(endpoint, key):
    return (
        f"DefaultEndpointsProtocol=http;AccountName={ACCOUNT};AccountKey={key};"
        f"BlobEndpoint={endpoint}/{ACCOUNT};"
    )


def exercise(az, env, root, key, dfs_url):
    def run(*args, expected_error=None, timeout=45, endpoint=None):
        command = [az, "storage", *args, "--auth-mode", "key", "--output", "json", "--only-show-errors"]
        command_env = env if endpoint is None else dict(
            env, AZURE_STORAGE_CONNECTION_STRING=connection_string(endpoint, key),
        )
        result = subprocess.run(command, env=command_env, capture_output=True, text=True, timeout=timeout)
        name = "az storage " + " ".join(args[:2])
        errors = result.stderr.replace(key, "[redacted]").strip()
        if expected_error is not None:
            require(result.returncode != 0 and expected_error in errors,
                    f"{name}: expected {expected_error}, got exit {result.returncode}: {errors}")
            return None
        require(result.returncode == 0, f"{name}: {errors}")
        return json.loads(result.stdout) if result.stdout.strip() else None

    container = "cli-" + uuid.uuid4().hex[:12]
    blob = "folder/a sample.txt"
    scope = ["--container-name", container, "--name", blob]
    path = root / "payload.txt"
    contents = b"actual Azure CLI storage workflow\n"
    path.write_bytes(contents)

    require(run("container", "create", "--name", container)["created"], "container was not created")
    seen = run("container", "list", "--prefix", container)
    require([item["name"] for item in seen] == [container], "container list did not reflect the create")

    run("blob", "upload", *scope, "--file", str(path), "--overwrite", "false",
        "--content-type", "text/plain", "--metadata", "purpose=contract")
    properties = run("blob", "show", *scope)
    tag = properties["properties"]["etag"]
    require(properties["properties"]["contentLength"] == len(contents), "wrong stored length")
    require(properties["properties"]["contentSettings"]["contentType"] == "text/plain", "wrong content type")
    require(properties["metadata"] == {"purpose": "contract"}, "metadata was not stored")

    path.write_bytes(b"this overwrite must not be committed")
    run("blob", "upload", *scope, "--file", str(path), "--overwrite", "false",
        expected_error="ErrorCode:BlobAlreadyExists")
    full = root / "full.txt"
    run("blob", "download", *scope, "--file", str(full), "--if-match", tag)
    require(full.read_bytes() == contents, "failed overwrite changed the stored bytes")
    partial = root / "range.txt"
    run("blob", "download", *scope, "--file", str(partial), "--start-range", "2", "--end-range", "8")
    require(partial.read_bytes() == contents[2:9], "range flags returned the wrong bytes")

    listed = run("blob", "list", "--container-name", container, "--prefix", "folder/",
                 "--num-results", "1", "--include", "m")
    require([(entry["name"], entry["metadata"]) for entry in listed] == [(blob, {"purpose": "contract"})],
            "listing flags did not return the stored name and metadata")

    run("blob", "delete", *scope, "--if-match", tag)
    require(not run("blob", "exists", *scope)["exists"], "blob remained visible after delete")

    multipart = ["--container-name", container, "--name", "folder/multipart.bin"]
    source = root / "multipart.bin"
    size = 256 * 1024 * 1024 + 1
    with source.open("wb") as file:
        file.write(b"first block")
        file.seek(8 * 1024 * 1024 - 3)
        file.write(b"cross the block boundary")
        file.seek(size - 4)
        file.write(b"last")
    # One byte beyond the pinned Azure CLI's 256 MiB single-PUT threshold.
    run("blob", "upload", *multipart, "--file", str(source), "--overwrite", "false", timeout=180)
    require(run("blob", "show", *multipart)["properties"]["contentLength"] == size,
            "multipart commit reported the wrong size")
    downloaded = root / "multipart-download.bin"
    run("blob", "download", *multipart, "--file", str(downloaded), timeout=180)
    with source.open("rb") as original, downloaded.open("rb") as actual:
        uploaded_sha256 = hashlib.file_digest(original, "sha256").hexdigest()
        downloaded_sha256 = hashlib.file_digest(actual, "sha256").hexdigest()
    require(downloaded_sha256 == uploaded_sha256, "multipart download did not match the uploaded bytes")

    run("container", "delete", "--name", container)
    require(not run("container", "exists", "--name", container)["exists"], "container remained visible after delete")
    evidence = {
        "checks": [
            "container lifecycle",
            "blob properties and metadata",
            "rejected overwrite and unchanged bytes",
            "ETag-conditioned read and delete",
            "exact byte-range download",
            "prefixed listing with metadata",
            "multipart upload and download",
        ],
        "multipart": {
            "bytes": size,
            "uploaded_sha256": uploaded_sha256,
            "downloaded_sha256": downloaded_sha256,
        },
    }
    if dfs_url is not None:
        evidence["dfs"] = exercise_dfs(run, root, dfs_url, key)
        evidence["checks"].extend([
            "Azure CLI filesystem listing, file metadata, and download",
            "DFS filesystem lifecycle and read of CLI-uploaded Blob bytes",
            "Azure CLI directory create and paged listing on the DFS endpoint",
        ])
    return evidence


def exercise_dfs(run, root, dfs_url, key):
    from azure.storage.filedatalake import DataLakeFileClient, FileSystemClient, __version__

    filesystem = "hns-cli-" + uuid.uuid4().hex[:12]
    blob = "folder/a sample.txt"
    contents = b"same bytes on Blob and DFS\n"
    source = root / "dfs-upload.txt"
    source.write_bytes(contents)
    endpoint = f"{dfs_url}/{ACCOUNT}"
    credential = {"account_name": ACCOUNT, "account_key": key}
    client_options = {
        "retry_total": 0, "connection_timeout": 5, "read_timeout": 10, "use_env_settings": False,
    }

    def result(pipeline, value, _headers):
        response = pipeline.http_response
        return response.status_code, response.headers, value

    # The high-level SDK used by `az storage fs` routes these operations to
    # Blob. Use its generated REST client to independently hit the DFS port.
    with FileSystemClient(endpoint, filesystem, credential, **client_options) as fs:
        dfs = fs._client.file_system
        status, created, _ = dfs.create(cls=result)
        require(status == 201 and created["x-ms-namespace-enabled"] == "true",
                "DFS did not create an HNS filesystem")
        status, properties, _ = dfs.get_properties(cls=result)
        require(status == 200 and properties["etag"] == created["etag"],
                "DFS returned different filesystem identity")
        listed = run("fs", "list", "--prefix", filesystem)
        require([item["name"] for item in listed] == [filesystem],
                "az storage fs list did not see the filesystem created through DFS")

        scope = ["--container-name", filesystem, "--name", blob]
        run("blob", "upload", *scope, "--file", str(source), "--overwrite", "false",
            "--metadata", "origin=cli")
        uploaded = run("blob", "show", *scope)
        tag = uploaded["properties"]["etag"]
        address = ["--file-system", filesystem, "--path", blob]
        metadata = run("fs", "file", "metadata", "show", *address)
        require(metadata == {"origin": "cli"}, "az storage fs file metadata show did not see Blob metadata")
        downloaded = root / "dfs-download.txt"
        run("fs", "file", "download", *address, "--destination", str(downloaded))
        require(downloaded.read_bytes() == contents, "az storage fs file download returned different bytes")

        with DataLakeFileClient(endpoint, filesystem, blob, credential, **client_options) as file:
            path = file._client.path
            status, properties, _ = path.get_properties(cls=result)
            require(status == 200 and properties["etag"] == tag
                    and properties["x-ms-resource-type"] == "file"
                    and properties["x-ms-properties"] == "origin=Y2xp",
                    "DFS and Blob did not return the same file identity and metadata")
            # The pinned Python DFS SDK doesn't sign the standard Range header.
            # The signed HTTP tests cover DFS range reads separately.
            status, headers, chunks = path.read(cls=result)
            require(status == 200 and headers["etag"] == tag, "DFS returned a different file")
            received = b"".join(chunks)
            require(received == contents, "DFS returned different bytes from the Blob uploaded by CLI")

        run("fs", "directory", "create", "--file-system", filesystem,
            "--name", "empty/child", endpoint=dfs_url)
        scope = ["fs", "file", "list", "--file-system", filesystem, "--recursive", "false"]
        first = run(*scope, "--num-results", "1", "--show-next-marker", endpoint=dfs_url)
        require(len(first) == 2 and first[0]["name"] == "empty" and first[0]["isDirectory"],
                "DFS root page did not contain the new directory")
        marker = first[1]["nextMarker"]
        require(bool(marker), "DFS listing did not provide a continuation token")
        next_page = run(*scope, "--num-results", "1", "--marker", marker, endpoint=dfs_url)
        require(len(next_page) == 1 and next_page[0]["name"] == "folder" and next_page[0]["isDirectory"],
                "DFS second page did not contain the implicit parent of the CLI upload")
        children = run(*scope, "--path", "empty", endpoint=dfs_url)
        require(len(children) == 1 and children[0]["name"] == "empty/child" and children[0]["isDirectory"],
                "DFS listing did not see the empty child")

        status, _, _ = dfs.delete(cls=result)
        require(status == 202, "DFS did not delete the filesystem")
    require(not run("container", "exists", "--name", filesystem)["exists"],
            "Blob still sees the filesystem deleted through DFS")
    return {
        "sdk_version": __version__,
        "read_bytes": len(received),
        "read_sha256": hashlib.sha256(received).hexdigest(),
        "root_directories": [first[0]["name"], next_page[0]["name"]],
    }


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--blob-url", default="http://127.0.0.1:10000", type=loopback_url)
    parser.add_argument("--dfs-url", type=loopback_url,
                        help="also test an HNS-enabled DFS listener using the Azure Data Lake Python SDK")
    parser.add_argument("--admin-url", default="http://127.0.0.1:10005", type=loopback_url)
    parser.add_argument("--expected-version")
    parser.add_argument("--json", action="store_true", help="print machine-readable evidence")
    args = parser.parse_args()
    az = shutil.which("az")
    if az is None:
        parser.error("Azure CLI is required")
    key = os.environ.get("AZUIFER_ACCOUNT_KEY", "")
    try:
        key_size = len(base64.b64decode(key, validate=True))
    except ValueError:
        key_size = 0
    if not 32 <= key_size <= 64:
        parser.error("AZUIFER_ACCOUNT_KEY must be a synthetic Base64 key for the test listener")
    with tempfile.TemporaryDirectory(prefix="azuifer-cli-") as directory:
        root = Path(directory)
        env = {name: value for name, value in os.environ.items() if not name.upper().startswith("AZURE_")}
        env.update(
            AZURE_CONFIG_DIR=str(root / "azure"),
            AZURE_CORE_COLLECT_TELEMETRY="no",
            AZURE_EXTENSION_USE_DYNAMIC_INSTALL="no",
            NO_PROXY="127.0.0.1",
            no_proxy="127.0.0.1",
            AZURE_STORAGE_CONNECTION_STRING=connection_string(args.blob_url, key),
        )
        version = subprocess.run([az, "version", "--output", "json"], env=env, capture_output=True, text=True, timeout=30)
        require(version.returncode == 0, f"az version: {version.stderr.replace(key, '[redacted]').strip()}")
        version = json.loads(version.stdout)["azure-cli"]
        require(args.expected_version is None or version == args.expected_version,
                f"expected Azure CLI {args.expected_version}, found {version}")
        wait_ready(args.admin_url)
        evidence = exercise(az, env, root, key, args.dfs_url)
    if args.json:
        print(json.dumps({"cli_version": version, **evidence}))
    else:
        print(f"Azure CLI {version}: {', '.join(evidence['checks'])} passed.")


if __name__ == "__main__":
    main()
