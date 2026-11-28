# /// script
# requires-python = ">=3.10"
# dependencies = []
# ///
"""Check that public docs resolve and do not contradict the conformance evidence.

Checks, all offline and deterministic:

* every relative Markdown link (and Markdown anchor) in root, ``docs/`` and
  ``.github/`` Markdown files resolves, with exact letter case;
* every ``docs/adr.d/NNNN-*.md`` record is linked from the ADR index;
* no conformance manifest rates an operation ``exact``;
* numeric claims in the docs (operations, cassettes, planned and matched
  exchanges, wire discrepancies) equal what ``specs/conformance/*.json`` and
  ``docs/compatibility/wire-discrepancies.json`` record.
"""

from __future__ import annotations

import argparse
from dataclasses import dataclass
import json
import os
from pathlib import Path
import re
import sys
from urllib.parse import unquote

ROOT = Path(__file__).resolve().parents[1]
SERVICES = ("blob", "dfs", "file", "queue", "table")
FENCE_RE = re.compile(r"^\s*(```|~~~)")
CODE_SPAN_RE = re.compile(r"`[^`\n]*`")
INLINE_LINK_RE = re.compile(r"\]\(\s*(<[^>\n]+>|[^)\s]+)(?:\s+\"[^\"]*\")?\s*\)")
REFERENCE_LINK_RE = re.compile(r"^\s{0,3}\[[^\]\n]+\]:\s+(<[^>\n]+>|\S+)")
HEADING_RE = re.compile(r"^\s{0,3}(#{1,6})\s+(.*?)\s*#*\s*$")
EXTERNAL_RE = re.compile(r"^[a-zA-Z][a-zA-Z0-9+.-]*:")
CODE_PATH_RE = re.compile(
    r"`((?:src|tests|scripts|docs|specs|packaging|fuzz|\.github)/[^`\s]*)`"
)
PLACEHOLDER_RE = re.compile(r"[*{<>$]")
ADR_FILE_RE = re.compile(r"^\d{4}-.+\.md$")
OVERCLAIM_RE = re.compile(
    r"\b(?:exact|full|100%|complete)\s+(?:wire\s+)?(?:parity|compatibility)\b", re.I
)
NEGATION_RE = re.compile(r"\b(?:no|not|never|without|until|does not|do not|cannot)\b", re.I)


def read_text(path: Path) -> str:
    return path.read_text(encoding="utf-8")


def markdown_files(root: Path) -> list[Path]:
    files = set(root.glob("*.md"))
    for folder in ("docs", ".github"):
        files.update((root / folder).glob("**/*.md"))
    return sorted(files)


def prose_lines(text: str) -> list[tuple[int, str]]:
    """Return ``(line number, line)`` pairs outside fenced code blocks."""
    lines: list[tuple[int, str]] = []
    fence = ""
    for number, line in enumerate(text.splitlines(), start=1):
        match = FENCE_RE.match(line)
        if match:
            marker = match.group(1)
            if not fence:
                fence = marker
            elif fence == marker:
                fence = ""
            continue
        if not fence:
            lines.append((number, line))
    return lines


def slugify(heading: str) -> str:
    text = re.sub(r"!?\[([^\]]*)\]\([^)]*\)", r"\1", heading)
    text = re.sub(r"[`*_~]", "", text).strip().lower()
    text = re.sub(r"[^\w\- ]", "", text)
    return text.replace(" ", "-")


def anchors(text: str) -> set[str]:
    seen: dict[str, int] = {}
    found: set[str] = set()
    for _, line in prose_lines(text):
        match = HEADING_RE.match(line)
        if not match:
            continue
        slug = slugify(match.group(2))
        count = seen.get(slug, 0)
        seen[slug] = count + 1
        found.add(slug if count == 0 else f"{slug}-{count}")
    return found


def link_targets(text: str) -> list[tuple[int, str]]:
    targets: list[tuple[int, str]] = []
    for number, line in prose_lines(text):
        stripped = CODE_SPAN_RE.sub("", line)
        found = [m.group(1) for m in INLINE_LINK_RE.finditer(stripped)]
        reference = REFERENCE_LINK_RE.match(stripped)
        if reference:
            found.append(reference.group(1))
        for target in found:
            targets.append((number, target.strip("<>")))
    return targets


def exists_exact(root: Path, path: Path) -> bool:
    """Return whether ``path`` exists under ``root`` with exact letter case."""
    try:
        relative = path.relative_to(root)
    except ValueError:
        return False
    current = root
    for part in relative.parts:
        if part in ("", "."):
            continue
        if not current.is_dir() or part not in {child.name for child in current.iterdir()}:
            return False
        current = current / part
    return True


def check_links(root: Path) -> list[str]:
    errors: list[str] = []
    anchor_cache: dict[Path, set[str]] = {}
    for source in markdown_files(root):
        label = source.relative_to(root).as_posix()
        for number, target in link_targets(read_text(source)):
            if not target or EXTERNAL_RE.match(target) or target.startswith("//"):
                continue
            raw_path, _, fragment = target.partition("#")
            base = root if raw_path.startswith("/") else source.parent
            normalized = Path(os.path.normpath(base / unquote(raw_path).lstrip("/"))) if raw_path else source
            if raw_path and not exists_exact(root, normalized):
                errors.append(f"{label}:{number}: broken link {target}")
                continue
            if fragment and normalized.suffix == ".md" and normalized.is_file():
                if normalized not in anchor_cache:
                    anchor_cache[normalized] = anchors(read_text(normalized))
                if unquote(fragment).lower() not in anchor_cache[normalized]:
                    errors.append(f"{label}:{number}: missing anchor {target}")
    return errors


def check_code_paths(root: Path) -> list[str]:
    """Report code-formatted repository paths that no longer exist.

    The specification names planned paths, so it is exempt.
    """
    errors: list[str] = []
    for source in markdown_files(root):
        label = source.relative_to(root).as_posix()
        if label == "docs/specs/azuifer.md":
            continue
        for number_, line in prose_lines(read_text(source)):
            for span in CODE_PATH_RE.findall(line):
                path = span.split("::")[0].split("#")[0]
                if PLACEHOLDER_RE.search(path):
                    continue
                if not exists_exact(root, root / path.rstrip("/")):
                    errors.append(f"{label}:{number_}: `{span}` does not exist")
    return errors


def check_adr_index(root: Path) -> list[str]:
    folder = root / "docs" / "adr.d"
    index = folder / "README.md"
    if not index.is_file():
        return ["docs/adr.d/README.md: ADR index is missing"]
    linked = {
        Path(unquote(target.partition("#")[0])).name
        for _, target in link_targets(read_text(index))
        if not EXTERNAL_RE.match(target)
    }
    return [
        f"docs/adr.d/README.md: {record.name} is not indexed"
        for record in sorted(folder.glob("*.md"))
        if ADR_FILE_RE.match(record.name) and record.name not in linked
    ]


@dataclass(frozen=True)
class Facts:
    operations: dict[str, int]
    implemented: dict[str, int]
    states: dict[str, dict[str, int]]
    cassettes: dict[str, int]
    matched: dict[str, int]
    planned: dict[str, int]
    wire_discrepancies: int
    ledger_entries: int | None

    @property
    def total_operations(self) -> int:
        return sum(self.operations.values())

    @property
    def total_implemented(self) -> int:
        return sum(self.implemented.values())

    @property
    def total_cassettes(self) -> int:
        return sum(self.cassettes.values())

    @property
    def total_matched(self) -> int:
        return sum(self.matched.values())

    @property
    def total_planned(self) -> int:
        return sum(self.planned.values())


def load_facts(root: Path) -> tuple[Facts | None, list[str]]:
    errors: list[str] = []
    facts: dict[str, dict[str, object]] = {
        key: {}
        for key in ("operations", "implemented", "states", "cassettes", "matched", "planned")
    }
    wire = 0
    for service in SERVICES:
        path = root / "specs" / "conformance" / f"{service}.json"
        try:
            manifest = json.loads(read_text(path))
            operations = manifest["operations"]
            evidence = manifest["live_azure_evidence"]
            states: dict[str, int] = {}
            for operation in operations:
                states[operation["state"]] = states.get(operation["state"], 0) + 1
            facts["operations"][service] = len(operations)
            facts["implemented"][service] = len(operations) - states.get("unsupported", 0)
            facts["states"][service] = states
            facts["cassettes"][service] = int(evidence["cassettes"])
            facts["matched"][service] = int(evidence["matched_exchanges"])
            facts["planned"][service] = int(evidence["target_exchanges"])
            wire += int(evidence["wire_discrepancies"])
        except (OSError, KeyError, TypeError, ValueError) as error:
            errors.append(f"specs/conformance/{service}.json: unreadable manifest ({error})")
    if errors:
        return None, errors
    ledger_entries: int | None = None
    ledger = root / "docs" / "compatibility" / "wire-discrepancies.json"
    try:
        ledger_entries = len(json.loads(read_text(ledger))["entries"])
    except (OSError, KeyError, TypeError, ValueError) as error:
        errors.append(f"docs/compatibility/wire-discrepancies.json: unreadable ledger ({error})")
    return Facts(**facts, wire_discrepancies=wire, ledger_entries=ledger_entries), errors  # type: ignore[arg-type]


def check_manifest_states(facts: Facts) -> list[str]:
    return [
        f"specs/conformance/{service}.json: {count} operation(s) rated exact without live evidence"
        for service, states in facts.states.items()
        if (count := states.get("exact", 0))
    ]


def check_ledger(facts: Facts) -> list[str]:
    if facts.ledger_entries is None or facts.ledger_entries == facts.wire_discrepancies:
        return []
    return [
        "docs/compatibility/wire-discrepancies.json: "
        f"{facts.ledger_entries} entries but the manifests count {facts.wire_discrepancies}"
    ]


def number(text: str) -> int:
    return int(text.replace(",", ""))


@dataclass(frozen=True)
class Claim:
    path: str
    pattern: str
    expected: tuple[int, ...]
    note: str


def claims(facts: Facts) -> list[Claim]:
    f = facts
    comp = "docs/compatibility/"
    stated: list[Claim] = [
        Claim("README.md", r"implements \*\*(\d+) of (\d+) recognized operations\*\*",
              (f.total_implemented, f.total_operations), "implemented operations"),
        Claim("README.md", r"\*\*(\d+) reviewed Azure cassettes\*\* and \*\*(\d+) of ([\d,]+) planned exchanges matched\*\*",
              (f.total_cassettes, f.total_matched, f.total_planned), "cassettes and exchanges"),
        Claim("README.md", r"tracks (\d+) pinned discrepancies",
              (f.wire_discrepancies,), "wire discrepancies"),
        Claim("ONBOARDING.md", r"of the (\d+) recognized operations are implemented \((\d+)\)",
              (f.total_operations, f.total_implemented), "implemented operations"),
        Claim(comp + "azure-contracts.md", r"tracks \*\*(\d+) of ([\d,]+) planned exchanges matched\*\*",
              (f.total_matched, f.total_planned), "planned exchanges"),
        Claim(comp + "azure-contracts.md", r": (\d+) Blob, (\d+) Queue, and (\d+) Table\.",
              (f.matched["blob"], f.matched["queue"], f.matched["table"]), "matched by service"),
        Claim(comp + "azure-contracts.md", r"\*\*(\d+) reviewed cassette files\*\* \((\d+) Blob, (\d+) Queue, (\d+) Table\)",
              (f.total_cassettes, f.cassettes["blob"], f.cassettes["queue"], f.cassettes["table"]),
              "cassette files"),
        Claim(comp + "azure-contracts.md", r"tracks (\d+) pinned entries",
              (f.wire_discrepancies,), "wire discrepancies"),
        Claim(comp + "azure-recording-plan.md", r"\| \*\*Total\*\* \| \*\*(\d+)\*\* \| \*\*([\d,]+)\*\* \| \*\*(\d+)\*\* \| \*\*([\d,]+)\*\* \| \*\*([\d,]+)\*\* \| \*\*([\d,]+)\*\*",
              (f.total_operations, -1, sum(f.operations[s] - f.implemented[s] for s in SERVICES), -1, -1, f.total_planned),
              "recording-plan total"),
        Claim(comp + "azure-recording-plan.md", r"full \*\*([\d,]+)-exchange\*\*",
              (f.total_planned,), "planned exchanges"),
        Claim(comp + "blob.md", r"lists (\d+) operations, (\d+) implemented locally",
              (f.operations["blob"], f.implemented["blob"]), "Blob operations"),
        Claim(comp + "blob.md", r"The (\d+) reviewed Blob cassettes match (\d+) of ([\d,]+) planned",
              (f.cassettes["blob"], f.matched["blob"], f.planned["blob"]), "Blob evidence"),
        Claim(comp + "queue.md", r"lists (\d+) implemented operations",
              (f.implemented["queue"],), "Queue operations"),
        Claim(comp + "queue.md", r"cassettes match (\d+) of ([\d,]+) planned",
              (f.matched["queue"], f.planned["queue"]), "Queue evidence"),
        Claim(comp + "table.md", r"Of the (\d+) operations in the \[manifest\]\([^)]*\), (\d+) are implemented",
              (f.operations["table"], f.implemented["table"]), "Table operations"),
        Claim(comp + "table.md", r"cassettes match (\d+) of ([\d,]+) planned",
              (f.matched["table"], f.planned["table"]), "Table evidence"),
        Claim(comp + "dfs.md", r"All (\d+) operations in the \[DFS manifest\]",
              (f.operations["dfs"],), "DFS operations"),
        Claim(comp + "dfs.md", r"\[([\d,]+) planned live DFS exchanges\]",
              (f.planned["dfs"],), "DFS planned exchanges"),
        Claim(comp + "files.md", r"lists (\d+) locally implemented operations",
              (f.implemented["file"],), "FileREST operations"),
        Claim(comp + "files.md", r"\[([\d,]+) planned exchanges\]",
              (f.planned["file"],), "FileREST planned exchanges"),
        Claim(comp + "files-nfs-evidence.md", r"All (\d+) FileREST operations are classified",
              (f.operations["file"],), "FileREST operations"),
    ]
    return stated


def check_claims(root: Path, facts: Facts) -> list[str]:
    errors: list[str] = []
    texts: dict[str, str] = {}
    for claim in claims(facts):
        if claim.path not in texts:
            path = root / claim.path
            texts[claim.path] = read_text(path) if path.is_file() else ""
        match = re.search(claim.pattern, texts[claim.path])
        if not match:
            errors.append(f"{claim.path}: no longer states {claim.note}; update scripts/audit-docs.py or restore the claim")
            continue
        for index, (group, expected) in enumerate(zip(match.groups(), claim.expected), start=1):
            if expected >= 0 and number(group) != expected:
                errors.append(
                    f"{claim.path}: {claim.note} claims {group} (value {index}) "
                    f"but the manifests record {expected}"
                )
    errors.extend(check_recording_plan_rows(root, facts))
    return errors


def check_recording_plan_rows(root: Path, facts: Facts) -> list[str]:
    path = root / "docs" / "compatibility" / "azure-recording-plan.md"
    if not path.is_file():
        return []
    names = {"Blob": "blob", "DFS": "dfs", "FileREST": "file", "Queue": "queue", "Table": "table"}
    errors: list[str] = []
    for label, service in names.items():
        row = re.search(
            rf"^\| {label} \| (\d+) \| ([\d,]+) \| (\d+) \| ([\d,]+) \| ([\d,]+) \| ([\d,]+) \|",
            read_text(path),
            re.M,
        )
        if not row:
            errors.append(f"docs/compatibility/azure-recording-plan.md: no summary row for {label}")
            continue
        operations, _, unsupported, _, _, target = (number(group) for group in row.groups())
        expected = (
            facts.operations[service],
            facts.operations[service] - facts.implemented[service],
            facts.planned[service],
        )
        if (operations, unsupported, target) != expected:
            errors.append(
                f"docs/compatibility/azure-recording-plan.md: {label} row says "
                f"{(operations, unsupported, target)} but the manifest records {expected}"
            )
    return errors


def check_overclaims(root: Path) -> list[str]:
    errors: list[str] = []
    for source in markdown_files(root):
        label = source.relative_to(root).as_posix()
        if label.startswith("docs/adr.d/"):
            continue
        for number_, line in prose_lines(read_text(source)):
            if OVERCLAIM_RE.search(line) and not NEGATION_RE.search(line):
                errors.append(f"{label}:{number_}: unqualified parity claim; the manifests rate no operation exact")
    return errors


def audit(root: Path) -> list[str]:
    errors = check_links(root) + check_code_paths(root)
    errors += check_adr_index(root) + check_overclaims(root)
    facts, fact_errors = load_facts(root)
    errors.extend(fact_errors)
    if facts is not None:
        errors.extend(check_manifest_states(facts))
        errors.extend(check_ledger(facts))
        errors.extend(check_claims(root, facts))
    return errors


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--root", type=Path, default=ROOT, help="repository root to audit")
    args = parser.parse_args(argv)
    root = args.root.resolve()
    errors = audit(root)
    for error in errors:
        print(f"error: {error}", file=sys.stderr)
    if errors:
        print(f"{len(errors)} documentation problem(s)", file=sys.stderr)
        return 1
    print(f"docs ok: {len(markdown_files(root))} Markdown files audited")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
