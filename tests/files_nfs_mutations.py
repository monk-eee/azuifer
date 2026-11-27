"""Break the NFS implementation on purpose, one way at a time, and record which tests notice.

    python tests/files_nfs_mutations.py [--out mutations.json]

Each mutation replaces one exact snippet in a source file, runs the NFS HTTP tests and the
Files unit tests, and puts the file back (also on error, so run it on a committed tree). A
mutation that no test notices is a hole in the tests. `tests/files_nfs_evidence.py --mutations`
renders the result into the evidence report. It rebuilds the binary eleven times, so it is a
check to run when the tests change, not part of CI.
"""

import argparse
import json
import re
import shutil
import subprocess
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent

MUTATIONS = [
    ("deleting the first name of a hard-linked file loses the file",
     "src/files/store/nodes.rs",
     "WHERE share_id=?1 AND file_id=?2 ORDER BY entry_id LIMIT 1",
     "WHERE share_id=?1 AND file_id=?2 AND 0 ORDER BY entry_id LIMIT 1"),
    ("a directory holding only a hard link counts as empty",
     "src/files/store/nodes.rs",
     "\n                         OR EXISTS(SELECT 1 FROM links WHERE share_id=?1 AND parent_id=?2)",
     ""),
    ("symbolic links can be read and written like files",
     "src/files/store/nodes.rs",
     "(Want::Regular, false) if is_symlink(&node) =>",
     "(Want::Regular, false) if false =>"),
    ("a path never resolves to a hard link name",
     "src/files/store/mod.rs",
     "WHERE a.share_id=?1 AND a.parent_id=?2 AND a.key=?3",
     "WHERE a.share_id=?1 AND a.parent_id=?2 AND a.key=?3 AND 0"),
    ("a file lease is enforced on NFS shares",
     "src/files/store/nodes.rs",
     "    if node.nfs.is_some() {\n        return Ok(());\n    }\n    lease::check_use(Kind::File,",
     "    if false {\n        return Ok(());\n    }\n    lease::check_use(Kind::File,"),
    ("octal modes are read as decimal",
     "src/files/model.rs",
     "u32::from_str_radix(value, 8)",
     "u32::from_str_radix(value, 10)"),
    ("link operations ignore the request's version",
     "src/files/ops.rs",
     "if self.version.as_str() < minimum {",
     "if false {"),
    ("SMB-only operations work on NFS shares",
     "src/files/ops.rs",
     "if share.protocol == Protocol::Nfs {\n            return Err(Error::XNfs4ShareDeniedException);",
     "if false {\n            return Err(Error::XNfs4ShareDeniedException);"),
    ("an older data directory is not upgraded",
     "src/files/store/mod.rs",
     "if !present.iter().any(|column| column == name) {",
     "if false {"),
    ("a share snapshot drops the links",
     "src/files/store/shares.rs",
     "SELECT ?2, entry_id, file_id, parent_id, name, key FROM links WHERE share_id=?1",
     "SELECT ?2, entry_id, file_id, parent_id, name, key FROM links WHERE share_id=?1 AND 0"),
    ("a hard link's content is counted twice in the share's usage",
     "src/files/store/shares.rs",
     "SELECT COALESCE(SUM(length), 0) FROM ranges WHERE share_id=?1",
     "SELECT COALESCE(SUM(length), 0) * (1 + (SELECT COUNT(*) FROM links WHERE share_id=?1)) FROM ranges WHERE share_id=?1"),
    ("saving a share forgets its root squash setting",
     "src/files/store/shares.rs",
     "root_squash=?10,",
     "root_squash=NULL,"),
]


def cargo(*arguments):
    process = subprocess.run([shutil.which("cargo") or "cargo", *arguments], cwd=ROOT,
                             capture_output=True, text=True)
    return process.stdout + process.stderr


def failing(output):
    return sorted(set(re.findall(r"^test (\S+) \.\.\. FAILED", output, re.MULTILINE)))


def main():
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--out", default="mutation-results.json")
    arguments = parser.parse_args()
    results = []
    for name, relative, old, new in MUTATIONS:
        path = ROOT / relative
        original = path.read_bytes()
        text = original.decode("utf-8")
        crlf = "\r\n" in text
        needle = old.replace("\n", "\r\n") if crlf else old
        replacement = new.replace("\n", "\r\n") if crlf else new
        if text.count(needle) != 1:
            results.append({"mutation": name, "file": relative, "status": "not applicable",
                            "detail": f"snippet found {text.count(needle)} times"})
            print(f"SKIP {name}: snippet found {text.count(needle)} times", flush=True)
            continue
        try:
            path.write_bytes(text.replace(needle, replacement).encode("utf-8"))
            output = cargo("test", "--test", "files_nfs_http", "--no-fail-fast")
            output += cargo("test", "--bin", "azuifer", "files::", "--no-fail-fast")
            failed = failing(output)
            compiled = "could not compile" not in output
            status = "caught" if failed else ("did not compile" if not compiled else "NOT CAUGHT")
            results.append({"mutation": name, "file": relative, "status": status, "failing_tests": failed})
            print(f"{status.upper():12} {name}: {', '.join(failed) or '-'}", flush=True)
        finally:
            path.write_bytes(original)
    Path(arguments.out).write_text(json.dumps(results, indent=1), encoding="utf-8")
    caught = sum(1 for r in results if r["status"] == "caught")
    print(f"{caught} of {len(results)} mutations caught")


if __name__ == "__main__":
    main()
