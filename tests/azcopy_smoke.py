"""Run a compact AzCopy scenario against a running Azuifer and print PASS/FAIL per step.

Azuifer must serve Blob and Files, for example (the 300 MiB-class transfers need
more than the default 64 MiB in-memory budget; this script uses far less):

    azuifer serve --in-memory --memory-limit 1073741824 --skip-api-version-check \\
        --services blob,file

Then, with an AzCopy v10 binary you downloaded yourself:

    pip install azure-storage-blob azure-storage-file-share   # only to generate SAS
    python tests/azcopy_smoke.py --azcopy /path/to/azcopy

Pass --blob-sas/--file-sas to use your own SAS tokens instead of the SDK; the default
account and key are the public development-storage fixture, valid on loopback only.
The DFS steps need an account with the namespace on (--hns-accounts devstoreaccount1) and
the Blob steps need one without it, so run them as two passes against two servers:
--skip-dfs, then --skip-blob --skip-files. The DFS pass uses --dfs-url (default port 10003).
AzCopy cannot take an account key, so every step authenticates with SAS. AzCopy infers
the service from the host name and does not recognise a bare IP endpoint, so the
script always passes --from-to (and `azcopy make` cannot be used). Containers and
shares are therefore created, and removed at the end, with plain HTTP.

AzCopy's logs and job plans go to a temporary directory; it still writes `~/.azcopy/installation_id` and `pids`.
"""

import argparse
import base64
import hashlib
import json
import os
import random
import re
import shutil
import subprocess
import sys
import tempfile
import threading
import time
import urllib.error
import urllib.parse
import urllib.request
import uuid
from datetime import datetime, timedelta, timezone
from pathlib import Path

ACCOUNT = "devstoreaccount1"
# The well-known public development-storage key; never a production credential.
PUBLIC_DEV_KEY = (
    "Eby8vdM02xNOcqFlqUwJPLlmEtlCDXJ1OUzFT50uSRZ6IFsuFq2UVErCz4I6tq/K1SZFPTOtr/KBHBeksoGMGw=="
)
API_VERSION = "2023-11-03"
MIB = 1024 * 1024

RESULTS = []


def step(name, ok, detail=""):
    RESULTS.append((name, ok))
    print(f"{'PASS' if ok else 'FAIL'} {name}" + (f": {detail}" if detail and not ok else ""), flush=True)


def generate_sas(account, key):
    from azure.storage.blob import (
        AccountSasPermissions,
        ResourceTypes,
        generate_account_sas as blob_sas,
    )
    from azure.storage.fileshare import generate_account_sas as file_sas

    start = datetime.now(timezone.utc) - timedelta(minutes=5)
    expiry = datetime.now(timezone.utc) + timedelta(days=1)
    permission = AccountSasPermissions(
        read=True, write=True, delete=True, list=True, add=True, create=True, update=True,
        process=True, tag=True, filter_by_tags=True,
    )
    kinds = ResourceTypes(service=True, container=True, object=True)
    return (
        blob_sas(account, key, resource_types=kinds, permission=permission, expiry=expiry, start=start),
        file_sas(account, key, resource_types=kinds, permission=permission, expiry=expiry, start=start),
    )


def http(method, url, headers=None, data=b""):
    request = urllib.request.Request(url, data=data if method == "PUT" else None, method=method)
    request.add_header("x-ms-version", API_VERSION)
    for name, value in (headers or {}).items():
        request.add_header(name, value)
    if method == "PUT":
        request.add_header("Content-Length", str(len(data)))
    try:
        with urllib.request.urlopen(request) as response:
            return response.status, response.headers
    except urllib.error.HTTPError as error:
        return error.code, error.headers


class AzCopy:
    def __init__(self, binary, work):
        self.binary = binary
        self.env = dict(os.environ)
        self.env.update(
            AZCOPY_LOG_LOCATION=str(work / "azcopy-logs"),
            AZCOPY_JOB_PLAN_LOCATION=str(work / "azcopy-plans"),
            AZCOPY_DISABLE_SYSLOG="true",
        )
        self.env.pop("AZCOPY_AUTO_LOGIN_TYPE", None)
        help_text = subprocess.run(
            [binary, "copy", "--help"], env=self.env, capture_output=True, text=True
        ).stdout
        self.global_flags = [
            flag
            for flag in ("--disable-telemetry=true", "--check-version=false")
            if flag.split("=")[0] in help_text
        ]
        self.version = subprocess.run(
            [binary, "--version"], env=self.env, capture_output=True, text=True
        ).stdout.strip()

    def command(self, *args):
        return [self.binary, *args, *self.global_flags]

    def run(self, *args):
        process = subprocess.run(
            self.command(*args), env=self.env, capture_output=True, text=True, timeout=600
        )
        return process.returncode, process.stdout + process.stderr


def job_ok(result):
    code, output = result
    return code == 0 and "Final Job Status: Completed" in output


def transferred(output):
    match = re.search(r"Total Number of Bytes Transferred: (\d+)", output)
    return int(match.group(1)) if match else -1


def tree_hashes(root):
    hashes = {}
    for path in sorted(Path(root).rglob("*")):
        if path.is_file():
            hashes[path.relative_to(root).as_posix()] = hashlib.sha256(path.read_bytes()).hexdigest()
    return hashes


def make_data(root, big_mib):
    rng = random.Random(7)
    tree = root / "tree"
    for directory in ("a", "a/b"):
        (tree / directory).mkdir(parents=True, exist_ok=True)
    for index in range(30):
        directory = ["", "a", "a/b"][index % 3]
        (tree / directory / f"f{index:03}.txt").write_bytes(rng.randbytes(rng.randint(0, 20000)))
    (tree / "big.bin").write_bytes(rng.randbytes(big_mib * MIB))
    (root / "single.bin").write_bytes(rng.randbytes(123457))
    (root / "odd names").mkdir()
    (root / "odd names" / "sp ace+plus#hash&amp.txt").write_bytes(b"odd")
    (root / "odd names" / "empty.dat").write_bytes(b"")
    return tree


def smoke_blob(azcopy, base, sas, data, tree, work):
    container = f"azcopysmoke{uuid.uuid4().hex[:8]}"
    other = container + "b"
    sas_url = lambda path="", query="": f"{base}/{container}{path}?{query}{sas}"
    status, _ = http("PUT", f"{base}/{container}?restype=container&{sas}")
    step("blob: create container (HTTP; azcopy make rejects IP endpoints)", status == 201, status)
    http("PUT", f"{base}/{other}?restype=container&{sas}")
    count = len(tree_hashes(tree))

    ok = job_ok(azcopy.run("copy", str(data / "single.bin"), sas_url("/single.bin"), "--from-to", "LocalBlob"))
    step("blob: copy single file up", ok)

    result = azcopy.run("copy", str(tree), sas_url(), "--from-to", "LocalBlob", "--recursive")
    step("blob: copy directory tree up (block upload of the large file)", job_ok(result), result[1][-300:])

    code, output = azcopy.run("list", sas_url(), "--location", "Blob", "--running-tally")
    found = re.search(r"File count: (\d+)", output)
    step("blob: list", code == 0 and found is not None and int(found.group(1)) == count + 1,
         f"expected {count + 1}, got {found and found.group(1)}")

    down = work / "blob-down"
    down.mkdir()
    result = azcopy.run("copy", sas_url("/tree"), str(down), "--from-to", "BlobLocal", "--recursive",
                        "--check-md5", "FailIfDifferent")
    step("blob: copy down with --check-md5 FailIfDifferent", job_ok(result), result[1][-300:])
    step("blob: downloaded tree matches SHA-256", tree_hashes(down / "tree") == tree_hashes(tree))

    result = azcopy.run("sync", str(tree), sas_url("/tree"), "--from-to", "LocalBlob", "--recursive")
    step("blob: sync up transfers nothing when unchanged", job_ok(result) and transferred(result[1]) == 0,
         f"transferred {transferred(result[1])} bytes")
    time.sleep(1.1)
    (tree / "f000.txt").write_bytes(b"changed locally")
    (tree / "new.txt").write_bytes(b"new locally")
    result = azcopy.run("sync", str(tree), sas_url("/tree"), "--from-to", "LocalBlob", "--recursive")
    step("blob: sync up sends exactly the changed and new files",
         job_ok(result) and transferred(result[1]) == len(b"changed locally") + len(b"new locally"),
         f"transferred {transferred(result[1])} bytes")
    mirror = work / "blob-sync-down"
    mirror.mkdir()
    result = azcopy.run("sync", sas_url("/tree"), str(mirror), "--from-to", "BlobLocal", "--recursive")
    step("blob: sync down", job_ok(result) and tree_hashes(mirror) == tree_hashes(tree), result[1][-300:])
    result = azcopy.run("sync", sas_url("/tree"), str(mirror), "--from-to", "BlobLocal", "--recursive")
    step("blob: sync down transfers nothing when unchanged", job_ok(result) and transferred(result[1]) == 0,
         f"transferred {transferred(result[1])} bytes")

    result = azcopy.run("copy", sas_url("/tree"), f"{base}/{other}?{sas}", "--from-to", "BlobBlob", "--recursive")
    step("blob: server-side copy (BlobBlob) in one account", job_ok(result), result[1][-300:])
    copied = work / "blob-s2s"
    copied.mkdir()
    azcopy.run("copy", f"{base}/{other}/tree?{sas}", str(copied), "--from-to", "BlobLocal", "--recursive")
    step("blob: server-side copy content matches", tree_hashes(copied / "tree") == tree_hashes(mirror))

    ok = all(
        job_ok(azcopy.run("copy", str(tree / "big.bin"), sas_url(f"/types/{kind}.bin"), "--from-to", "LocalBlob",
                          "--blob-type", kind, "--put-md5"))
        for kind in ("PageBlob", "AppendBlob", "BlockBlob")
    )
    step("blob: upload as PageBlob, AppendBlob and BlockBlob with --put-md5", ok)
    ok = all(
        job_ok(azcopy.run("copy", str(tree / "big.bin"), sas_url(f"/nomd5/{kind}.bin"), "--from-to", "LocalBlob",
                          "--blob-type", kind))
        for kind in ("PageBlob", "AppendBlob")
    )
    step("blob: upload as PageBlob and AppendBlob without --put-md5", ok)
    code, output = azcopy.run("list", sas_url("/types"), "--location", "Blob", "--properties", "BlobType;ContentMD5")
    md5 = base64.b64encode(hashlib.md5((tree / "big.bin").read_bytes()).digest()).decode()
    step("blob: list reports the blob types and the uploaded Content-MD5",
         all(f"{kind}.bin; BlobType: {kind}; ContentMD5: {md5}" in output
             for kind in ("PageBlob", "AppendBlob", "BlockBlob")), output[-400:])
    typed = work / "blob-types"
    typed.mkdir()
    result = azcopy.run("copy", sas_url("/types"), str(typed), "--from-to", "BlobLocal", "--recursive",
                        "--check-md5", "FailIfDifferent")
    expected = hashlib.sha256((tree / "big.bin").read_bytes()).hexdigest()
    step("blob: typed blobs download and match", job_ok(result) and all(
        value == expected for value in tree_hashes(typed / "types").values()), result[1][-300:])
    result = azcopy.run("copy", sas_url("/types"), f"{base}/{other}?{sas}", "--from-to", "BlobBlob", "--recursive")
    paged = work / "blob-types-s2s"
    paged.mkdir()
    azcopy.run("copy", f"{base}/{other}/types?{sas}", str(paged), "--from-to", "BlobLocal", "--recursive")
    step("blob: server-side copy of page, append and block blobs",
         job_ok(result) and tree_hashes(paged / "types") == tree_hashes(typed / "types"), result[1][-300:])
    status, _ = http("PUT", sas_url("/types/BlockBlob.bin", "comp=properties&"),
                     {"x-ms-blob-content-md5": "AAAAAAAAAAAAAAAAAAAAAA=="})
    bad = work / "blob-badmd5"
    bad.mkdir()
    code, output = azcopy.run("copy", sas_url("/types/BlockBlob.bin"), str(bad), "--from-to", "BlobLocal",
                              "--check-md5", "FailIfDifferent")
    step("blob: --check-md5 FailIfDifferent rejects a wrong Content-MD5",
         status == 200 and "Final Job Status: Completed" not in output)

    resume_blob(azcopy, sas_url, sas, work)


    result = azcopy.run("remove", sas_url("/tree"), "--from-to", "BlobTrash", "--recursive")
    code, output = azcopy.run("list", sas_url("/tree"), "--location", "Blob")
    step("blob: remove --recursive", job_ok(result) and "tree/" not in output and "big.bin" not in output)

    for name in (container, other):
        http("DELETE", f"{base}/{name}?restype=container&{sas}")


def resume_blob(azcopy, sas_url, sas, work):
    source = work / "resume.bin"
    source.write_bytes(random.Random(3).randbytes(16 * MIB))
    process = subprocess.Popen(
        azcopy.command("copy", str(source), sas_url("/resume/resume.bin"), "--from-to", "LocalBlob",
                       "--cap-mbps", "20", "--output-type", "json"),
        env=azcopy.env, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True,
    )
    job = {}

    def reader():
        for line in process.stdout:
            try:
                message = json.loads(line)
            except ValueError:
                continue
            if message.get("MessageType") == "Init":
                job["id"] = json.loads(message["MessageContent"])["JobID"]

    thread = threading.Thread(target=reader, daemon=True)
    thread.start()
    time.sleep(2.5)
    interrupted = process.poll() is None
    process.kill()
    process.wait()
    thread.join(timeout=5)
    if not interrupted or "id" not in job:
        step("blob: resume a killed transfer", False, "the transfer ended before it could be interrupted")
        return
    result = azcopy.run("jobs", "resume", job["id"], "--destination-sas", f"?{sas}")
    down = work / "blob-resumed"
    down.mkdir()
    azcopy.run("copy", sas_url("/resume/resume.bin"), str(down / "resume.bin"), "--from-to", "BlobLocal")
    same = (down / "resume.bin").exists() and (
        tree_hashes(down)["resume.bin"] == hashlib.sha256(source.read_bytes()).hexdigest())
    step("blob: resume a killed transfer (jobs resume), content matches", job_ok(result) and same, result[1][-300:])


def smoke_files(azcopy, base, sas, data, tree, work):
    share = f"azcopysmoke{uuid.uuid4().hex[:8]}"
    peer = share + "b"
    url = lambda path="", name=None: f"{base}/{name or share}{path}?{sas}"
    status, _ = http("PUT", f"{base}/{share}?restype=share&{sas}")
    step("files: create share (HTTP; azcopy make rejects IP endpoints)", status == 201, status)
    http("PUT", f"{base}/{peer}?restype=share&{sas}")
    count = len(tree_hashes(tree))

    ok = job_ok(azcopy.run("copy", str(data / "single.bin"), url("/single.bin"), "--from-to", "LocalFile"))
    step("files: copy single file up (Put Range with x-ms-file-last-write-time: Preserve)", ok)
    result = azcopy.run("copy", str(tree), url(), "--from-to", "LocalFile", "--recursive")
    step("files: copy directory tree up", job_ok(result), result[1][-300:])
    code, output = azcopy.run("list", url(), "--location", "File", "--running-tally")
    entries = re.search(r"File count: (\d+)", output)
    step("files: list", code == 0 and entries is not None and int(entries.group(1)) >= count + 1,
         f"got {entries and entries.group(1)}")
    down = work / "file-down"
    down.mkdir()
    result = azcopy.run("copy", url("/tree"), str(down), "--from-to", "FileLocal", "--recursive")
    step("files: copy down and match SHA-256", job_ok(result) and tree_hashes(down / "tree") == tree_hashes(tree),
         result[1][-300:])

    result = azcopy.run("sync", str(tree), url("/tree"), "--from-to", "LocalFile", "--recursive")
    step("files: sync up transfers nothing when unchanged (100 ns timestamps)",
         job_ok(result) and transferred(result[1]) == 0, f"transferred {transferred(result[1])} bytes")
    time.sleep(1.1)
    (tree / "f001.txt").write_bytes(b"changed again")
    result = azcopy.run("sync", str(tree), url("/tree"), "--from-to", "LocalFile", "--recursive")
    step("files: sync up sends only the changed file",
         job_ok(result) and transferred(result[1]) == len(b"changed again"), f"transferred {transferred(result[1])} bytes")
    result = azcopy.run("sync", url("/tree"), str(tree), "--from-to", "FileLocal", "--recursive")
    step("files: sync down transfers nothing when unchanged",
         job_ok(result) and transferred(result[1]) == 0, f"transferred {transferred(result[1])} bytes")

    result = azcopy.run("copy", url("/tree"), url(name=peer), "--from-to", "FileFile", "--recursive")
    peer_down = work / "file-peer"
    peer_down.mkdir()
    azcopy.run("copy", url("/tree", peer), str(peer_down), "--from-to", "FileLocal", "--recursive")
    step("files: copy between shares (Put Range From URL)",
         job_ok(result) and tree_hashes(peer_down / "tree") == tree_hashes(tree), result[1][-300:])

    result = azcopy.run("remove", url("/tree"), "--from-to", "FileTrash", "--recursive")
    code, output = azcopy.run("list", url(), "--location", "File")
    step("files: remove --recursive", job_ok(result) and "big.bin" not in output)
    surviving_copy = work / "file-peer-survivor.txt"
    result = azcopy.run("copy", url("/tree/f001.txt", peer), str(surviving_copy), "--from-to", "FileLocal")
    step("files: cross-share copy survives source removal",
         job_ok(result) and surviving_copy.read_bytes() == (tree / "f001.txt").read_bytes(),
         result[1][-300:])
    for name in (share, peer):
        http("DELETE", f"{base}/{name}?restype=share&{sas}")


def smoke_dfs(azcopy, base, sas, data, tree, work):
    filesystem = f"azcopysmoke{uuid.uuid4().hex[:8]}"
    url = lambda path="": f"{base}/{filesystem}{path}?{sas}"
    status, _ = http("PUT", f"{base}/{filesystem}?resource=filesystem&{sas}")
    step("dfs: create filesystem (HTTP; azcopy make rejects IP endpoints)", status == 201, status)
    count = len(tree_hashes(tree))

    ok = job_ok(azcopy.run("copy", str(data / "single.bin"), url("/single.bin"), "--from-to", "LocalBlobFS"))
    step("dfs: copy single file up (Create, Append, Flush)", ok)
    result = azcopy.run("copy", str(tree), url(), "--from-to", "LocalBlobFS", "--recursive")
    step("dfs: copy directory tree up", job_ok(result), result[1][-400:])
    code, output = azcopy.run("list", url(), "--location", "BlobFS", "--running-tally")
    entries = re.search(r"File count: (\d+)", output)
    step("dfs: list", code == 0 and entries is not None and int(entries.group(1)) >= count + 1,
         f"got {entries and entries.group(1)}: {output[-300:]}")
    down = work / "dfs-down"
    down.mkdir()
    result = azcopy.run("copy", url("/tree"), str(down), "--from-to", "BlobFSLocal", "--recursive")
    step("dfs: copy down and match SHA-256", job_ok(result) and tree_hashes(down / "tree") == tree_hashes(tree),
         result[1][-400:])
    result = azcopy.run("sync", str(tree), url("/tree"), "--from-to", "LocalBlobFS", "--recursive")
    step("dfs: sync up transfers nothing when unchanged",
         job_ok(result) and transferred(result[1]) == 0, f"transferred {transferred(result[1])} bytes: {result[1][-300:]}")
    result = azcopy.run("remove", url("/tree"), "--from-to", "BlobFSTrash", "--recursive")
    code, output = azcopy.run("list", url(), "--location", "BlobFS")
    step("dfs: remove --recursive", job_ok(result) and "big.bin" not in output, result[1][-400:])
    http("DELETE", f"{base}/{filesystem}?resource=filesystem&{sas}")


def main():
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--azcopy", required=True, help="path to the AzCopy v10 binary")
    parser.add_argument("--blob-url", default=f"http://127.0.0.1:10000/{ACCOUNT}")
    parser.add_argument("--file-url", default=f"http://127.0.0.1:10004/{ACCOUNT}")
    parser.add_argument("--dfs-url", default=f"http://127.0.0.1:10003/{ACCOUNT}")
    parser.add_argument("--blob-sas", help="account SAS query string for Blob (default: generated)")
    parser.add_argument("--file-sas", help="account SAS query string for Files (default: generated)")
    parser.add_argument("--account", default=ACCOUNT)
    parser.add_argument("--key", default=PUBLIC_DEV_KEY)
    parser.add_argument("--big-mib", type=int, default=20, help="size of the large file (default 20)")
    parser.add_argument("--skip-blob", action="store_true")
    parser.add_argument("--skip-files", action="store_true")
    parser.add_argument("--skip-dfs", action="store_true")
    options = parser.parse_args()

    blob_sas, file_sas = options.blob_sas, options.file_sas
    if not blob_sas or not file_sas:
        generated_blob, generated_file = generate_sas(options.account, options.key)
        blob_sas, file_sas = blob_sas or generated_blob, file_sas or generated_file

    work = Path(tempfile.mkdtemp(prefix="azcopy-smoke-"))
    try:
        azcopy = AzCopy(options.azcopy, work)
        print(f"AzCopy: {azcopy.version}", flush=True)
        data = work / "data"
        data.mkdir()
        tree = make_data(data, options.big_mib)
        files_tree = work / "files-data" / "tree"
        shutil.copytree(tree, files_tree)
        if not options.skip_blob:
            smoke_blob(azcopy, options.blob_url, blob_sas, data, tree, work)
        if not options.skip_files:
            smoke_files(azcopy, options.file_url, file_sas, data, files_tree, work)
        if not options.skip_dfs:
            dfs_tree = work / "dfs-data" / "tree"
            shutil.copytree(tree, dfs_tree)
            smoke_dfs(azcopy, options.dfs_url, blob_sas, data, dfs_tree, work)
    finally:
        shutil.rmtree(work, ignore_errors=True)
    failed = [name for name, ok in RESULTS if not ok]
    print(f"{len(RESULTS) - len(failed)} passed, {len(failed)} failed")
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())
