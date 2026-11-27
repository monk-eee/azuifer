"""Build docs/compatibility/files-nfs-evidence.md for ADR-0029 from things that actually ran.

    python tests/files_nfs_evidence.py [--binary target/debug/azuifer] [--mutations results.json]

It runs the official Python SDK workflow (tests/files_nfs_sdk.py) and records the requests
and responses the SDK's pipeline saw, runs the NFS HTTP tests, and renders:

  * a table of every FileREST operation with how NFS changes it and the tests that cover it;
    every test named in the table must exist, so a renamed or deleted test fails this script;
  * wire examples taken from the recorded exchanges, not typed in;
  * the mutation results, when given (`tests/files_nfs_mutations.py` breaks the implementation
    on purpose and lists the tests that notice);
  * what has not been verified against Azure.

Nothing here is a comparison with real Azure Storage.
"""

import argparse
import json
import os
import re
import subprocess
import sys
import tempfile
from datetime import date
from importlib import metadata
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
HTTP = "tests/files_nfs_http.rs"
H = "http"        # tests/files_nfs_http.rs
U = "unit"        # a Rust unit test, by path
S = "sdk"         # a check of tests/files_nfs_sdk.py
J = "js"          # a step of tests/js_sdk/probe.js
N = "dotnet"      # a step of tests/dotnet_sdk/Program.cs

JS_STEP = "files nfs: share, posix properties, hard and symbolic links"
SHARE = "a_share_reports_its_protocol_and_nfs_settings"
POSIX = "files_and_directories_carry_posix_properties_instead_of_smb_ones"
LISTING = "an_nfs_listing_has_only_ids_names_and_lengths"
LINKS = "hard_links_are_names_of_one_file"
ORDER = "a_hard_linked_name_can_be_replaced_and_listed_in_order"
GATE = "link_operations_need_an_nfs_share_and_a_new_enough_version"
SYMBOLIC = "symbolic_links_keep_their_text_and_refuse_data_operations"
REFUSED = "smb_only_operations_are_refused_on_nfs_shares"
LEASES = "file_leases_do_not_exist_on_nfs_shares"
COPY = "copy_file_takes_mode_and_owner_from_the_source_or_the_request"
SNAPSHOT = "a_share_snapshot_keeps_hard_links_and_symbolic_links"
RESTART = "nfs_state_survives_a_restart"
OLDER = "an_older_data_directory_gains_the_nfs_columns_and_stays_smb"
RANGES = "ranges_and_aborted_copies_work_on_nfs_files"
METADATA = "metadata_and_soft_delete_keep_the_protocol"
MODES = "files::model::tests::modes_parse_from_octal_and_rwx_and_render_as_four_digits"
DEFAULTS = "files::model::tests::posix_defaults_and_updates_follow_the_documentation"
EXTENTS = "files::store::tests::a_hard_linked_file_keeps_its_extents_until_the_last_name_is_deleted"
MANIFEST = "files::request::tests::manifest_lists_every_recognised_operation_with_a_matching_state"

# (operation, what NFS changes, tests that cover it)
OPERATIONS = [
    ("List Shares", "adds EnabledProtocols, RootSquash, EnableSnapshotVirtualDirectoryAccess",
     [(H, SHARE), (S, "List Shares reports each share's protocol")]),
    ("Create Share", "protocol, root squash and snapshot-directory settings",
     [(H, SHARE), (S, "an NFS share reports NFS and its root squash"), (J, JS_STEP), (N, JS_STEP)]),
    ("Get Share Properties", "reports the three settings",
     [(H, SHARE), (S, "an SMB share reports SMB")]),
    ("Set Share Properties", "changes root squash and snapshot-directory access",
     [(H, SHARE), (S, "root squash can be changed on an NFS share")]),
    ("Get Share Metadata", "same headers as Get Share Properties", [(H, METADATA)]),
    ("Set Share Metadata", "unchanged", [(H, METADATA)]),
    ("Delete Share", "unchanged; frees links and content", [(H, SNAPSHOT)]),
    ("Snapshot Share", "keeps links, symbolic links and the protocol",
     [(H, SNAPSHOT), (S, "a share snapshot keeps both names of a hard-linked file")]),
    ("Restore Share", "keeps the protocol and settings", [(H, METADATA)]),
    ("Get Share Stats", "a hard-linked file counts once", [(H, LINKS), (U, EXTENTS)]),
    ("Lease Share", "unchanged; works on NFS", [(H, REFUSED)]),
    ("Get Share ACL", "SMB only: 403 XNfs4ShareDeniedException",
     [(H, REFUSED), (S, "Get Share ACL is refused on an NFS share"),
      (S, "Get Share ACL still works on an SMB share")]),
    ("Set Share ACL", "SMB only: 403 XNfs4ShareDeniedException", [(H, REFUSED)]),
    ("Create Permission", "SMB only: 403 XNfs4ShareDeniedException", [(H, REFUSED)]),
    ("Get Permission", "SMB only: 403 XNfs4ShareDeniedException", [(H, REFUSED)]),
    ("Create Directory", "mode, owner, group, file type; no SMB headers",
     [(H, POSIX), (S, "a directory keeps its mode, owner and group"), (J, JS_STEP), (N, JS_STEP)]),
    ("Get Directory Properties", "POSIX headers",
     [(H, POSIX), (S, "a directory defaults to 0755 and root")]),
    ("Set Directory Properties", "mode, owner, group; an omitted one is kept", [(H, POSIX)]),
    ("Get Directory Metadata", "POSIX headers", [(H, METADATA)]),
    ("Set Directory Metadata", "unchanged", [(H, METADATA)]),
    ("Delete Directory", "a directory holding only a link is not empty", [(H, LINKS)]),
    ("List Directories and Files", "id, name and length only; links under every name",
     [(H, LISTING), (H, ORDER), (S, "the directory lists its file")]),
    ("Rename Directory", "SMB only: 403 XNfs4ShareDeniedException", [(H, REFUSED)]),
    ("List Handles", "SMB only: 403 XNfs4ShareDeniedException", [(H, REFUSED)]),
    ("Force Close Handles", "SMB only: 403 XNfs4ShareDeniedException", [(H, REFUSED)]),
    ("Create File", "mode, owner, group, file type Regular; replacing a symbolic link refused",
     [(H, POSIX), (H, ORDER), (H, SYMBOLIC),
      (S, "a file keeps its mode, owner, group, type and link count")]),
    ("Get File", "POSIX headers and link count; a symbolic link is refused",
     [(H, LINKS), (H, SYMBOLIC), (S, "reading the bytes of a symbolic link is refused"), (J, JS_STEP)]),
    ("Get File Properties", "POSIX headers, file type, link count",
     [(H, POSIX), (S, "both names are the same file"), (N, JS_STEP)]),
    ("Set File Properties", "mode, owner, group, link count; resizing a symbolic link refused",
     [(H, POSIX), (H, SYMBOLIC), (S, "Set File Properties changes the mode and keeps the owner")]),
    ("Get File Metadata", "POSIX headers", [(H, POSIX)]),
    ("Set File Metadata", "visible through every name", [(H, LINKS)]),
    ("Delete File", "returns the new link count; the last name frees the content",
     [(H, LINKS), (U, EXTENTS), (S, "deleting the first name leaves the file under the other")]),
    ("Put Range", "a symbolic link is refused; file leases ignored",
     [(H, SYMBOLIC), (H, LEASES), (S, "a write through one name shows through the other"),
      (S, "writing a range of a symbolic link is refused")]),
    ("Put Range From URL", "a symbolic link as source or destination is refused", [(H, RANGES)]),
    ("List Ranges", "a symbolic link is refused", [(H, RANGES), (H, SYMBOLIC)]),
    ("Copy File", "mode and owner copy modes; a symbolic link is refused",
     [(H, COPY), (S, "Copy File applies the mode override and makes an independent file")]),
    ("Abort Copy File", "unchanged: nothing is ever pending", [(H, RANGES)]),
    ("Rename File", "SMB only: 403 XNfs4ShareDeniedException",
     [(H, REFUSED), (S, "Rename File is refused on an NFS share")]),
    ("Lease File", "SMB only: 403 XNfs4ShareDeniedException", [(H, REFUSED), (H, LEASES)]),
    ("Create Hard Link", "new: another name for one inode",
     [(H, LINKS), (H, ORDER), (H, GATE), (S, "Create Hard Link returns an ETag"),
      (S, "a hard link to a missing file is a 404"), (S, "a hard link onto an existing name is a 409"),
      (S, "a hard link under a missing directory is a 404"),
      (S, "a hard link on an SMB share is refused"), (J, JS_STEP), (N, JS_STEP)]),
    ("Create Symbolic Link", "new: stores unresolved link text",
     [(H, SYMBOLIC), (H, GATE), (S, "a symbolic link reports its file type, owner and group"),
      (S, "a symbolic link to nothing is allowed"), (J, JS_STEP), (N, JS_STEP)]),
    ("Read Symbolic Link", "new: returns the link text, on a live share or a snapshot",
     [(H, SYMBOLIC), (H, SNAPSHOT), (S, "Read Symbolic Link returns the text as stored"),
      (S, "Read Symbolic Link on a regular file is refused"), (J, JS_STEP), (N, JS_STEP)]),
    ("Get File Service Properties", "account level; not NFS related, unchanged", []),
    ("Set File Service Properties", "account level; not NFS related, unchanged", []),
]
CROSS_CUTTING = [
    ("old data directories are upgraded and stay SMB", [(H, OLDER)]),
    ("state survives a restart", [(H, RESTART), (S, "a restart keeps the protocol, properties and links")]),
    ("POSIX modes parse and render", [(U, MODES), (U, DEFAULTS)]),
    ("the manifest lists every operation and none as unsupported", [(U, MANIFEST)]),
    ("version gate on the link operations", [(H, GATE)]),
    ("file leases are ignored on NFS", [(H, LEASES)]),
]
EXAMPLES = [
    ("Create Share (NFS)", lambda e: e["method"] == "PUT" and "restype=share" in e["query"] and "NFS" in json.dumps(e["request"]) and e["status"] == 201),
    ("Get Share Properties", lambda e: e["method"] == "HEAD" and "restype=share" in e["query"] and e["response"].get("x-ms-enabled-protocols") == "NFS"),
    ("Create Directory", lambda e: e["method"] == "PUT" and "restype=directory" in e["query"] and e["request"].get("x-ms-mode")),
    ("Create File", lambda e: e["method"] == "PUT" and e["request"].get("x-ms-type") == "file" and e["request"].get("x-ms-mode") and "comp" not in e["query"]),
    ("Create Hard Link", lambda e: "restype=hardlink" in e["query"] and e["status"] == 201),
    ("Get File Properties on a hard-linked file", lambda e: e["method"] == "HEAD" and e["response"].get("x-ms-link-count") == "2"),
    ("Create Symbolic Link", lambda e: "restype=symboliclink" in e["query"] and e["method"] == "PUT" and e["status"] == 201),
    ("Read Symbolic Link", lambda e: "restype=symboliclink" in e["query"] and e["method"] == "GET" and e["status"] == 200),
    ("Get File on a symbolic link", lambda e: e["method"] == "GET" and e["response"].get("x-ms-error-code") == "XNfs4FileTypeUnsupportedException"),
    ("Hard link to a missing file", lambda e: "restype=hardlink" in e["query"] and e["response"].get("x-ms-error-code") == "ResourceNotFound"),
    ("Get Share ACL on an NFS share", lambda e: "comp=acl" in e["query"] and e["response"].get("x-ms-error-code") == "XNfs4ShareDeniedException"),
]
UNVERIFIED = [
    "The status and code of an SMB-only operation on an NFS share (chosen: 403 XNfs4ShareDeniedException), and of an NFS-only operation or header on an SMB share (chosen: 400 InvalidQueryParameterValue or InvalidHeaderValue).",
    "What an NFS share does below x-ms-version 2025-05-05 (chosen: behaves the same; only the link operations are version gated).",
    "Whether SMB-only headers are rejected or ignored on NFS, and POSIX headers on SMB (chosen: ignored).",
    "Get File, Put Range, Put Range From URL, List Ranges, Copy File, Create File and Set File Properties (resize) on a symbolic link, and a hard link to a symbolic link or a directory (chosen: XNfs4FileTypeUnsupportedException, InvalidHeaderValue).",
    "The default mode of a symbolic link (chosen: 0777), the link count of a directory (not reported), and the casing of the file type on Get File Properties (SymLink).",
    "Whether a missing parent on Create File and Create Directory is 404 ParentNotFound, as here, or the 412 that one Learn page names.",
    "The default x-ms-file-mode-copy-mode and x-ms-file-owner-copy-mode when omitted (chosen: source).",
    "How symbolic links are listed, and whether their Content-Length is the text length (chosen: listed as files, length of the text).",
    "The access tier and quota Azure reports for a premium NFS share.",
    "Whether Create File over a hard-linked name truncates the shared file (chosen) or replaces the name.",
]


def run(command, **options):
    return subprocess.run(command, cwd=ROOT, capture_output=True, text=True, **options)


def rust_functions(path):
    return set(re.findall(r"\bfn (\w+)\(", (ROOT / path).read_text(encoding="utf-8")))


def verify_tests(sdk_checks):
    """Every test the table names must exist; returns the list of problems."""
    http = rust_functions(HTTP)
    units = set()
    for source in ROOT.glob("src/files/**/*.rs"):
        module = "files::" + ".".join(source.relative_to(ROOT / "src/files").with_suffix("").parts).replace(".mod", "")
        for name in re.findall(r"\bfn (\w+)\(", source.read_text(encoding="utf-8")):
            units.add(f"{module.replace('.', '::')}::tests::{name}")
    js = (ROOT / "tests/js_sdk/probe.js").read_text(encoding="utf-8")
    dotnet = (ROOT / "tests/dotnet_sdk/Program.cs").read_text(encoding="utf-8")
    problems = []
    entries = [pair for _, _, tests in OPERATIONS for pair in tests]
    entries += [pair for _, tests in CROSS_CUTTING for pair in tests]
    for kind, name in entries:
        found = {
            H: name in http,
            U: name in units or name.rsplit("::", 1)[-1] in {u.rsplit("::", 1)[-1] for u in units},
            S: name in sdk_checks,
            J: f'step("{name}"' in js,
            N: f'Step("{name}"' in dotnet,
        }[kind]
        if not found:
            problems.append(f"{kind}: {name}")
    return problems


def render_exchange(entry):
    request = " ".join(f"{k}: {v}" for k, v in entry["request"].items() if k != "x-ms-version")
    response = " ".join(f"{k}: {v}" for k, v in entry["response"].items())
    query = f"?{entry['query']}" if entry["query"] else ""
    return (f"```\n{entry['method']} {entry['url']}{query}\n"
            f"  request:  {request or '-'}\n"
            f"  response: {entry['status']} {response or '-'}\n```")


def main():
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--binary", default=str(ROOT / "target" / "debug" / ("azuifer.exe" if os.name == "nt" else "azuifer")))
    parser.add_argument("--mutations", help="results of mutation_check.py")
    parser.add_argument("--out", default=str(ROOT / "docs" / "compatibility" / "files-nfs-evidence.md"))
    arguments = parser.parse_args()

    with tempfile.TemporaryDirectory() as scratch:
        transcript_path = Path(scratch) / "transcript.json"
        sdk = run([sys.executable, "tests/files_nfs_sdk.py", "--binary", arguments.binary, "--transcript", str(transcript_path)])
        if sdk.returncode != 0:
            print(sdk.stdout + sdk.stderr)
            raise SystemExit("the SDK workflow failed; no evidence report written")
        transcript = json.loads(transcript_path.read_text(encoding="utf-8"))
    checks, exchanges = transcript["checks"], transcript["exchanges"]

    problems = verify_tests(set(checks))
    if problems:
        raise SystemExit("tests named in the evidence table do not exist:\n  " + "\n  ".join(problems))

    cargo = run(["cargo", "test", "--test", "files_nfs_http"])
    passed = re.search(r"test result: (\w+)\. (\d+) passed; (\d+) failed", cargo.stdout + cargo.stderr)
    if not passed or passed.group(1) != "ok":
        print(cargo.stdout + cargo.stderr)
        raise SystemExit("the NFS HTTP tests failed; no evidence report written")
    units = run(["cargo", "test", "--bin", "azuifer", "files::"])
    unit_passed = re.search(r"test result: (\w+)\. (\d+) passed; (\d+) failed", units.stdout + units.stderr)
    if not unit_passed or unit_passed.group(1) != "ok":
        raise SystemExit("the Files unit tests failed; no evidence report written")

    commit = run(["git", "rev-parse", "--short", "HEAD"]).stdout.strip()
    sdk_version = metadata.version("azure-storage-file-share")
    versions = sorted({e["request"].get("x-ms-version") for e in exchanges if e["request"].get("x-ms-version")})
    lines = [
        "# Files NFS evidence",
        "",
        f"Generated by [`tests/files_nfs_evidence.py`](../../tests/files_nfs_evidence.py) on {date.today().isoformat()} at commit `{commit}`. "
        "Everything below ran: the SDK exchanges are recorded from the SDK's HTTP pipeline, and the test names are checked to exist. "
        "None of it is compared with real Azure Storage; [what is unverified](#not-verified-against-azure) is listed at the end. "
        "Design: [ADR-0029](../adr.d/0029-serve-nfs-file-shares-with-posix-properties-and-links.md). Behavior: [Files compatibility](files.md#nfs-shares).",
        "",
        "## What ran",
        "",
        "| Suite | Result |",
        "| --- | --- |",
        f"| HTTP protocol tests, real binary ([`tests/files_nfs_http.rs`](../../tests/files_nfs_http.rs)) | {passed.group(2)} passed, {passed.group(3)} failed |",
        f"| Files unit tests, including the store, mode parser and manifest tests | {unit_passed.group(2)} passed, {unit_passed.group(3)} failed |",
        f"| `azure-storage-file-share` {sdk_version} ([`tests/files_nfs_sdk.py`](../../tests/files_nfs_sdk.py)), API version `{', '.join(versions)}` | {len(checks)} checks passed, {len(exchanges)} exchanges recorded |",
        "| JavaScript `@azure/storage-file-share` and .NET `Azure.Storage.Files.Shares` | one `files nfs` scenario each, in their CI jobs |",
        "",
        "## Every operation",
        "",
        f"All {len(OPERATIONS)} FileREST operations are classified. *Test* names are checked to exist when this report is generated: "
        "**http** is a test of the real binary, **unit** a Rust unit test, **sdk** a check of the Python script, **js** and **dotnet** a scenario of those suites.",
        "",
        "| Operation | On an NFS share | Covered by |",
        "| --- | --- | --- |",
    ]
    for operation, change, tests in OPERATIONS:
        covered = "<br>".join(f"{kind}: `{name}`" for kind, name in tests) if tests else "not NFS related"
        lines.append(f"| {operation} | {change} | {covered} |")
    lines += ["", "Cross-cutting behavior:", "", "| Behavior | Covered by |", "| --- | --- |"]
    for behavior, tests in CROSS_CUTTING:
        lines.append(f"| {behavior} | " + "<br>".join(f"{kind}: `{name}`" for kind, name in tests) + " |")

    lines += ["", "## Wire examples", "",
              f"Taken from the exchanges `azure-storage-file-share` {sdk_version} made against the running binary.", ""]
    for title, matches in EXAMPLES:
        entry = next((e for e in exchanges if matches(e)), None)
        lines += [f"**{title}**", "", render_exchange(entry) if entry else "_not seen in this run_", ""]

    if arguments.mutations:
        results = json.loads(Path(arguments.mutations).read_text(encoding="utf-8"))
        caught = sum(1 for r in results if r["status"] == "caught")
        lines += ["## Do the tests notice a broken implementation?", "",
                  f"`tests/files_nfs_mutations.py` broke the code in {len(results)} specific ways, one at a time, and ran the NFS tests each time. "
                  f"{caught} of {len(results)} were caught.", "",
                  "| Mutation | Result | Tests that failed |", "| --- | --- | --- |"]
        for r in results:
            tests = "<br>".join(f"`{t}`" for t in r.get("failing_tests", [])) or "-"
            lines.append(f"| {r['mutation']} | {r['status']} | {tests} |")
        lines.append("")

    lines += ["## Not verified against Azure", "",
              "These choices rest on Microsoft Learn, which is silent or inconsistent on them. A recording from a premium NFS share would settle each:", ""]
    lines += [f"{i}. {text}" for i, text in enumerate(UNVERIFIED, 1)]
    lines += ["", "Until then every NFS operation is `known-difference` in [the manifest](../../specs/conformance/file.json), and none is `exact`.", ""]
    Path(arguments.out).write_text("\n".join(lines), encoding="utf-8", newline="\n")
    print(f"wrote {arguments.out}: {len(OPERATIONS)} operations, {len(checks)} SDK checks, {len(exchanges)} exchanges")


if __name__ == "__main__":
    main()
