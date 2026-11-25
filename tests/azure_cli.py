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


def exercise(az, env, root, key):
    def run(*args, expected_error=None, timeout=45):
        command = [az, "storage", *args, "--auth-mode", "key", "--output", "json", "--only-show-errors"]
        result = subprocess.run(command, env=env, capture_output=True, text=True, timeout=timeout)
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
    return {
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


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--blob-url", default="http://127.0.0.1:10000", type=loopback_url)
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
            AZURE_STORAGE_CONNECTION_STRING=(
                f"DefaultEndpointsProtocol=http;AccountName={ACCOUNT};AccountKey={key};"
                f"BlobEndpoint={args.blob_url}/{ACCOUNT};"
            ),
        )
        version = subprocess.run([az, "version", "--output", "json"], env=env, capture_output=True, text=True, timeout=30)
        require(version.returncode == 0, f"az version: {version.stderr.replace(key, '[redacted]').strip()}")
        version = json.loads(version.stdout)["azure-cli"]
        require(args.expected_version is None or version == args.expected_version,
                f"expected Azure CLI {args.expected_version}, found {version}")
        wait_ready(args.admin_url)
        evidence = exercise(az, env, root, key)
    if args.json:
        print(json.dumps({"cli_version": version, **evidence}))
    else:
        print(f"Azure CLI {version}: Blob lifecycle, guarded overwrite, ETag, range, metadata, and 256 MiB + 1 multipart upload passed.")


if __name__ == "__main__":
    main()
