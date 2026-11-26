"""Run `az storage blob` workflows for the third Blob wave against a running Azuifer.

Start Azuifer with the SDK-compatible API versions (Azure CLI requests a newer
version than the Blob baseline):

    azuifer serve --in-memory --skip-api-version-check

    python tests/blob3_az.py --blob-url http://127.0.0.1:10000

Covers page blob snapshots, listing snapshots, Copy Blob of a snapshot, immutability policy,
set-tier, and soft-deleted containers (list --include-deleted, restore). Not covered because
the CLI cannot reach an emulator: `az storage blob incremental-copy start` ignores a custom
endpoint, and `az storage blob legal-hold` needs the storage-blob-preview extension (the SDK
script covers both). The default account and key are the public development-storage fixture.
"""

import argparse
import json
import os
import shutil
import subprocess
import sys
import tempfile
import uuid
from datetime import datetime, timedelta, timezone

ACCOUNT = "devstoreaccount1"
# The well-known public development-storage key; never a production credential.
PUBLIC_DEV_KEY = (
    "Eby8vdM02xNOcqFlqUwJPLlmEtlCDXJ1OUzFT50uSRZ6IFsuFq2UVErCz4I6tq/K1SZFPTOtr/KBHBeksoGMGw=="
)
AZ = shutil.which("az") or shutil.which("az.cmd")
FAILURES = []


def az(environment, *arguments, check=True):
    command = [AZ, "storage", *arguments, "--output", "json", "--only-show-errors"]
    result = subprocess.run(command, env=environment, capture_output=True, text=True, timeout=180)
    if check and result.returncode != 0:
        raise AssertionError(f"az {' '.join(arguments)} failed: {result.stderr.strip()}")
    if result.returncode != 0:
        return None, result.stderr
    return (json.loads(result.stdout) if result.stdout.strip() else None), result.stderr


def step(name, function):
    try:
        function()
    except Exception as error:
        FAILURES.append(name)
        print(f"FAIL {name}: {error}")
    else:
        print(f"PASS {name}")


def main():
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--blob-url", default="http://127.0.0.1:10000")
    arguments = parser.parse_args()
    if AZ is None:
        print("SKIP: the Azure CLI is not installed")
        return
    key = os.environ.get("AZUIFER_ACCOUNT_KEY", PUBLIC_DEV_KEY)
    base = arguments.blob_url.rstrip("/")
    environment = dict(os.environ)
    environment["AZURE_STORAGE_CONNECTION_STRING"] = (
        f"DefaultEndpointsProtocol=http;AccountName={ACCOUNT};AccountKey={key};BlobEndpoint={base}/{ACCOUNT}"
    )
    container = "az3-" + uuid.uuid4().hex[:10]
    workdir = tempfile.mkdtemp()
    disk = os.path.join(workdir, "disk.vhd")
    with open(disk, "wb") as handle:
        handle.write(b"a" * 512 + bytes(512) + b"b" * 512 + bytes(512))
    state = {}

    def create():
        az(environment, "container", "create", "--name", container)
        az(environment, "blob", "upload", "--container-name", container, "--name", "disk.vhd",
           "--file", disk, "--type", "page", "--overwrite")

    def snapshot():
        result, _ = az(environment, "blob", "snapshot", "--container-name", container, "--name", "disk.vhd")
        state["snapshot"] = result["snapshot"]
        assert state["snapshot"], result

    def list_snapshots():
        blobs, _ = az(environment, "blob", "list", "--container-name", container, "--include", "s")
        snapshots = [blob for blob in blobs if blob.get("snapshot")]
        assert len(snapshots) == 1 and snapshots[0]["properties"]["blobType"] == "PageBlob", blobs
        shown, _ = az(environment, "blob", "show", "--container-name", container, "--name", "disk.vhd",
                      "--snapshot", state["snapshot"])
        assert shown["properties"]["contentLength"] == 2048, shown

    def copy_snapshot():
        # `az storage blob incremental-copy start` ignores a custom endpoint and talks to
        # blob.core.windows.net, so the snapshot copy uses Copy Blob, which keeps the page blob type.
        source = f"{base}/{ACCOUNT}/{container}/disk.vhd?snapshot={state['snapshot']}"
        az(environment, "blob", "copy", "start", "--source-uri", source,
           "--destination-container", container, "--destination-blob", "backup.vhd")
        shown, _ = az(environment, "blob", "show", "--container-name", container, "--name", "backup.vhd")
        assert shown["properties"]["copy"]["status"] == "success", shown
        assert shown["properties"]["blobType"] == "PageBlob", shown
        assert shown["properties"]["contentLength"] == 2048, shown

    def tiers():
        az(environment, "blob", "upload", "--container-name", container, "--name", "block.txt",
           "--data", "tier me", "--overwrite")
        az(environment, "blob", "set-tier", "--container-name", container, "--name", "block.txt", "--tier", "Cool")
        shown, _ = az(environment, "blob", "show", "--container-name", container, "--name", "block.txt")
        assert shown["properties"]["blobTier"] == "Cool", shown

    def protection():
        until = (datetime.now(timezone.utc) + timedelta(hours=1)).strftime("%Y-%m-%dT%H:%M:%SZ")
        az(environment, "blob", "immutability-policy", "set", "--container-name", container, "--name",
           "block.txt", "--expiry-time", until, "--policy-mode", "Unlocked")
        shown, _ = az(environment, "blob", "show", "--container-name", container, "--name", "block.txt")
        assert shown["immutabilityPolicy"]["policyMode"].lower() == "unlocked", shown
        _, error = az(environment, "blob", "delete", "--container-name", container, "--name", "block.txt", check=False)
        assert "BlobImmutableDueToPolicy" in error, error
        az(environment, "blob", "immutability-policy", "delete", "--container-name", container, "--name", "block.txt")
        az(environment, "blob", "delete", "--container-name", container, "--name", "block.txt")

    def soft_deleted_container():
        az(environment, "blob", "service-properties", "delete-policy", "update", "--enable", "true",
           "--days-retained", "1")
        try:
            az(environment, "container", "delete", "--name", container)
            listed, _ = az(environment, "container", "list", "--include-deleted")
            deleted = [item for item in listed if item["name"] == container and item.get("deleted")]
            assert len(deleted) == 1 and deleted[0]["version"], listed
            az(environment, "container", "restore", "--name", container, "--deleted-version", deleted[0]["version"])
            blobs, _ = az(environment, "blob", "list", "--container-name", container)
            assert "disk.vhd" in [blob["name"] for blob in blobs], blobs
        finally:
            az(environment, "blob", "service-properties", "delete-policy", "update", "--enable", "false")

    try:
        step("create a container and upload a page blob", create)
        step("snapshot the page blob", snapshot)
        step("list and show snapshots", list_snapshots)
        step("copy start of a page blob snapshot", copy_snapshot)
        step("set-tier on a block blob is unchanged", tiers)
        step("immutability policy", protection)
        step("soft-deleted container: list --include-deleted and restore", soft_deleted_container)
    finally:
        az(environment, "container", "delete", "--name", container, check=False)
        shutil.rmtree(workdir, ignore_errors=True)
    print(f"\n{'FAILED' if FAILURES else 'all passed'}: {len(FAILURES)} failed")
    sys.exit(1 if FAILURES else 0)


if __name__ == "__main__":
    main()
