"""Drive Azuifer's NFS file shares with the official azure-storage-file-share SDK (ADR-0029).

Usage (from the repository root, after `cargo build`):

    pip install "azure-storage-file-share>=12.22" requests
    python tests/files_nfs_sdk.py [--binary target/debug/azuifer] [--transcript out.json]

The SDK speaks its newest API version (2026-10-06 in 12.27), so the server runs with
--skip-api-version-check, as every current SDK needs. The script starts the binary on
ephemeral ports, runs the workflow below against an in-memory store, then repeats a
persistence check against a data directory. It records every request and response of the
SDK's HTTP pipeline and, with --transcript, writes them to a JSON file that the evidence
report is built from. Nothing here is compared with real Azure.
"""

import argparse
import base64
import json
import os
import subprocess
import sys
import tempfile

from azure.core.exceptions import HttpResponseError, ResourceExistsError, ResourceNotFoundError
from azure.core.pipeline.policies import SansIOHTTPPolicy
from azure.storage.fileshare import ContentSettings, ShareServiceClient

ACCOUNT = "testaccount"
KEY = base64.b64encode(bytes(range(32))).decode()
PASSED = []
TRANSCRIPT = []
CURRENT = {"step": ""}
REFUSED = "XNfs4FileTypeUnsupportedException"


def check(name, condition, detail=""):
    CURRENT["step"] = name
    if not condition:
        raise AssertionError(f"{name} failed {detail}")
    PASSED.append(name)
    print(f"ok  {name}", flush=True)


def code_of(call):
    """The Azure error code of a call that must fail, or None if it succeeded."""
    try:
        call()
    except HttpResponseError as error:
        return error.error_code
    return None


class Recorder(SansIOHTTPPolicy):
    """Keeps method, URL, selected headers and status of every exchange, in order."""

    KEEP = ("x-ms-version", "x-ms-type", "x-ms-mode", "x-ms-owner", "x-ms-group",
            "x-ms-file-file-type", "x-ms-link-text", "x-ms-file-target-file",
            "x-ms-link-count", "x-ms-enabled-protocols", "x-ms-root-squash",
            "x-ms-file-id", "x-ms-file-parent-id", "x-ms-error-code", "x-ms-content-length",
            "x-ms-file-mode-copy-mode", "x-ms-copy-source", "content-length")

    def on_request(self, request):
        request.context["recorded"] = {
            "method": request.http_request.method,
            "url": request.http_request.url.split("?", 1)[0].split(ACCOUNT, 1)[-1] or "/",
            "query": request.http_request.url.split("?", 1)[1] if "?" in request.http_request.url else "",
            "request": {k: v for k, v in request.http_request.headers.items() if k.lower() in self.KEEP},
        }

    def on_response(self, request, response):
        entry = request.context.get("recorded")
        if entry is None:
            return
        entry["status"] = response.http_response.status_code
        entry["response"] = {k.lower(): v for k, v in response.http_response.headers.items()
                             if k.lower() in self.KEEP}
        entry["step"] = CURRENT["step"]
        TRANSCRIPT.append(entry)


class Server:
    def __init__(self, binary, location=None):
        env = {k: v for k, v in os.environ.items() if not k.startswith("AZUIFER_")}
        env["AZUIFER_ACCOUNT_NAME"] = ACCOUNT
        env["AZUIFER_ACCOUNT_KEY"] = KEY
        command = [binary, "serve", "--port", "0", "--admin-port", "0", "--services", "file",
                   "--skip-api-version-check", "--shutdown-on-stdin-eof"]
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

    def service(self):
        return ShareServiceClient(self.endpoint, credential={"account_name": ACCOUNT, "account_key": KEY},
                                  per_call_policies=[Recorder()])

    def stop(self):
        self.process.stdin.close()
        self.process.wait(timeout=15)


def workflow(server):
    service = server.service()

    CURRENT["step"] = "create shares"
    nfs = service.create_share("nfs", protocols="NFS", root_squash="RootSquash")
    smb = service.create_share("smb")
    props = nfs.get_share_properties()
    check("an NFS share reports NFS and its root squash",
          props.protocols == ["NFS"] and props.root_squash == "RootSquash", repr(props.protocols))
    check("an SMB share reports SMB", smb.get_share_properties().protocols == ["SMB"])
    nfs.set_share_properties(root_squash="AllSquash")
    check("root squash can be changed on an NFS share",
          nfs.get_share_properties().root_squash == "AllSquash")
    listed = {s.name: s for s in service.list_shares()}
    check("List Shares reports each share's protocol",
          listed["nfs"].protocols == ["NFS"] and listed["smb"].protocols == ["SMB"])
    try:
        service.create_share("bad", protocols="SMB", root_squash="RootSquash")
        check("root squash on SMB is refused by the client", False)
    except ValueError:
        check("root squash on SMB is refused by the client", True)

    CURRENT["step"] = "directories and files"
    directory = nfs.create_directory("data", file_mode="0750", owner="1000", group="100")
    dprops = nfs.get_directory_client("data").get_directory_properties()
    check("a directory keeps its mode, owner and group",
          (dprops.file_mode, dprops.owner, dprops.group, dprops.nfs_file_type) ==
          ("0750", "1000", "100", "Directory"), repr((dprops.file_mode, dprops.owner, dprops.group)))
    default_dir = nfs.create_directory("plain")
    check("a directory defaults to 0755 and root",
          nfs.get_directory_client("plain").get_directory_properties().file_mode == "0755")

    original = nfs.get_file_client("data/original.txt")
    original.create_file(11, file_mode="0640", owner="7", group="8")
    original.upload_range(b"hello world", offset=0, length=11)
    fprops = original.get_file_properties()
    check("a file keeps its mode, owner, group, type and link count",
          (fprops.file_mode, fprops.owner, fprops.group, fprops.nfs_file_type, fprops.link_count) ==
          ("0640", "7", "8", "Regular", 1),
          repr((fprops.file_mode, fprops.owner, fprops.group, fprops.nfs_file_type, fprops.link_count)))
    original.set_http_headers(ContentSettings(), file_mode="0600")
    fprops = original.get_file_properties()
    check("Set File Properties changes the mode and keeps the owner",
          (fprops.file_mode, fprops.owner) == ("0600", "7"))
    check("the SMB attribute and permission properties are absent on an NFS file",
          getattr(fprops, "file_attributes", None) is None
          and getattr(fprops, "permission_key", None) is None,
          repr((getattr(fprops, "file_attributes", None), getattr(fprops, "permission_key", None))))
    names = [item.name for item in nfs.get_directory_client("data").list_directories_and_files()]
    check("the directory lists its file", names == ["original.txt"], repr(names))

    CURRENT["step"] = "hard links"
    alias = nfs.get_file_client("plain/alias.txt")
    made = alias.create_hardlink("data/original.txt")
    check("Create Hard Link returns an ETag", bool(made.get("etag")))
    a, b = original.get_file_properties(), alias.get_file_properties()
    check("both names are the same file",
          a.file_id == b.file_id and a.link_count == 2 and b.link_count == 2 and a.parent_id != b.parent_id,
          repr((a.file_id, b.file_id, a.link_count, b.link_count)))
    check("the link reads the file's bytes", alias.download_file().readall() == b"hello world")
    alias.upload_range(b"HELLO", offset=0, length=5)
    check("a write through one name shows through the other",
          original.download_file().readall() == b"HELLO world")
    check("a hard link to a missing file is a 404",
          code_of(lambda: nfs.get_file_client("plain/x.txt").create_hardlink("data/missing.txt"))
          == "ResourceNotFound")
    check("a hard link onto an existing name is a 409",
          code_of(lambda: alias.create_hardlink("data/original.txt")) == "ResourceAlreadyExists")
    check("a hard link under a missing directory is a 404",
          code_of(lambda: nfs.get_file_client("nowhere/x.txt").create_hardlink("data/original.txt"))
          == "ParentNotFound")
    check("a hard link on an SMB share is refused",
          code_of(lambda: smb.get_file_client("x.txt").create_hardlink("y.txt")) is not None)
    original.delete_file()
    check("deleting the first name leaves the file under the other",
          alias.get_file_properties().link_count == 1 and alias.download_file().readall() == b"HELLO world")

    CURRENT["step"] = "symbolic links"
    link = nfs.get_file_client("plain/link")
    link.create_symlink("../data/original.txt", owner="12", group="34", metadata={"made": "by sdk"})
    check("Read Symbolic Link returns the text as stored",
          link.get_symlink().get("link_text") == "../data/original.txt", repr(link.get_symlink()))
    lprops = link.get_file_properties()
    check("a symbolic link reports its file type, owner and group",
          (lprops.nfs_file_type, lprops.owner, lprops.group) == ("SymLink", "12", "34"),
          repr((lprops.nfs_file_type, lprops.owner, lprops.group)))
    check("a symbolic link to nothing is allowed",
          nfs.get_file_client("dangling").create_symlink("/no/such/file") is not None)
    check("reading the bytes of a symbolic link is refused",
          code_of(lambda: link.download_file().readall()) == REFUSED)
    check("writing a range of a symbolic link is refused",
          code_of(lambda: link.upload_range(b"x", offset=0, length=1)) == REFUSED)
    check("a hard link to a symbolic link is refused",
          code_of(lambda: nfs.get_file_client("plain/h").create_hardlink("plain/link")) == REFUSED)
    check("a symbolic link onto an existing name is a 409",
          code_of(lambda: link.create_symlink("x")) == "ResourceAlreadyExists")
    check("Read Symbolic Link on a regular file is refused",
          code_of(lambda: alias.get_symlink()) == REFUSED)
    link.delete_file()
    check("a symbolic link deletes like a file and leaves its target",
          code_of(lambda: link.get_file_properties()) is not None
          and alias.get_file_properties().link_count == 1)

    CURRENT["step"] = "copy"
    source = nfs.get_file_client("plain/alias.txt")
    target = nfs.get_file_client("plain/copied.txt")
    target.start_copy_from_url(source.url, file_mode_copy_mode="override", file_mode="0444")
    copied = target.get_file_properties()
    check("Copy File applies the mode override and makes an independent file",
          copied.file_mode == "0444" and copied.link_count == 1 and copied.file_id != source.get_file_properties().file_id
          and target.download_file().readall() == b"HELLO world", repr((copied.file_mode, copied.link_count)))

    CURRENT["step"] = "snapshot"
    nfs.get_file_client("plain/second.txt").create_hardlink("plain/alias.txt")
    snapshot = nfs.create_snapshot()
    nfs.get_file_client("plain/second.txt").delete_file()
    at_snapshot = server.service().get_share_client("nfs", snapshot=snapshot["snapshot"])
    kept = at_snapshot.get_file_client("plain/alias.txt").get_file_properties()
    check("a share snapshot keeps both names of a hard-linked file", kept.link_count == 2, repr(kept.link_count))

    CURRENT["step"] = "refused operations"
    check("Get Share ACL is refused on an NFS share", code_of(nfs.get_share_access_policy) == "XNfs4ShareDeniedException")
    check("Rename File is refused on an NFS share",
          code_of(lambda: nfs.get_file_client("plain/copied.txt").rename_file("plain/renamed.txt"))
          == "XNfs4ShareDeniedException")
    check("Get Share ACL still works on an SMB share", smb.get_share_access_policy() is not None)


def persistence(binary):
    with tempfile.TemporaryDirectory() as location:
        server = Server(binary, location)
        try:
            share = server.service().create_share("keep", protocols="NFS")
            file = share.get_file_client("a.txt")
            file.create_file(5, file_mode="0640", owner="42", group="43")
            file.upload_range(b"state", offset=0, length=5)
            share.get_file_client("b.txt").create_hardlink("a.txt")
            share.get_file_client("s").create_symlink("a.txt")
        finally:
            server.stop()
        server = Server(binary, location)
        try:
            share = server.service().get_share_client("keep")
            file = share.get_file_client("a.txt")
            props = file.get_file_properties()
            check("a restart keeps the protocol, properties and links",
                  share.get_share_properties().protocols == ["NFS"]
                  and (props.file_mode, props.owner, props.link_count) == ("0640", "42", 2)
                  and share.get_file_client("b.txt").download_file().readall() == b"state"
                  and share.get_file_client("s").get_symlink().get("link_text") == "a.txt")
        finally:
            server.stop()


def main():
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--binary", default=os.path.join("target", "debug", "azuifer.exe" if os.name == "nt" else "azuifer"))
    parser.add_argument("--transcript", help="write the recorded exchanges to this JSON file")
    arguments = parser.parse_args()
    server = Server(arguments.binary)
    try:
        workflow(server)
    finally:
        server.stop()
    persistence(arguments.binary)
    if arguments.transcript:
        with open(arguments.transcript, "w", encoding="utf-8") as handle:
            json.dump({"checks": PASSED, "exchanges": TRANSCRIPT}, handle, indent=1)
    print(f"{len(PASSED)} checks passed")
    return 0


if __name__ == "__main__":
    sys.exit(main())
