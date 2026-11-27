# /// script
# requires-python = ">=3.10"
# dependencies = []
# ///
"""Validate and summarize docs/compatibility/wire-discrepancies.json."""

from __future__ import annotations

import argparse
from collections import Counter
import json
from pathlib import Path
import re
import sys
from urllib.parse import urlparse

ROOT = Path(__file__).resolve().parents[1]
LEDGER = ROOT / "docs" / "compatibility" / "wire-discrepancies.json"
VALID_SERVICES = frozenset({"blob", "dfs", "file", "queue", "table", "shared"})
VALID_STATUSES = frozenset(
    {"observed", "awaiting_live_recording", "open_gap", "wont_fix"}
)
VALID_CATEGORIES = frozenset(
    {"live_vs_docs", "sdk_vs_docs", "live_vs_sdk", "docs_inconsistency", "undocumented_live"}
)
OBSERVATION_CATEGORIES = frozenset({"documented_match", "needs_evidence"})
REQUIRED_FIELDS = (
    "id",
    "service",
    "operation",
    "category",
    "summary",
    "expected_by_docs_or_sdk",
    "observed_behavior",
    "status",
)
ID_RE = re.compile(r"^WD-\d{3,}$")
LIVE_REFERENCE_RE = re.compile(r"^[0-9a-f]{40}:tests/contracts/cassettes/[^:#]+\.json#[\w-]+$")
EVIDENCE_KINDS = {
    "live_vs_docs": {"live", "docs"},
    "sdk_vs_docs": {"sdk", "docs"},
    "live_vs_sdk": {"live", "sdk"},
    "docs_inconsistency": {"docs"},
    "undocumented_live": {"live", "docs"},
    "documented_match": {"docs"},
    "needs_evidence": {"docs"},
}


def validate_evidence(entry: dict[str, object], label: str) -> list[str]:
    errors: list[str] = []
    evidence = entry.get("evidence")
    if not isinstance(evidence, list) or not evidence:
        return [f"{label}: evidence must be a non-empty list of sources"]
    kinds: list[str] = []
    for source in evidence:
        if not isinstance(source, dict):
            errors.append(f"{label}: evidence source must be an object")
            continue
        kind = source.get("kind")
        if kind not in ("docs", "sdk", "live"):
            errors.append(f"{label}: invalid evidence kind")
            continue
        kinds.append(kind)
        reference = source.get("reference")
        detail = source.get("detail")
        if not isinstance(detail, str) or not detail.strip():
            errors.append(f"{label}: evidence requires a non-empty detail")
        if not isinstance(reference, str):
            errors.append(f"{label}: evidence requires a reference")
            continue
        if kind == "live":
            if not LIVE_REFERENCE_RE.fullmatch(reference):
                errors.append(f"{label}: live evidence requires commit:path.json#step")
            if source.get("source") != "azure":
                errors.append(f"{label}: live evidence must have source=azure")
            for field in ("api_version", "auth_mode"):
                value = source.get(field)
                if not isinstance(value, str) or not value.strip():
                    errors.append(f"{label}: live evidence requires {field}")
        else:
            try:
                url = urlparse(reference)
            except ValueError:
                errors.append(f"{label}: docs/SDK evidence requires a valid HTTPS URL")
                continue
            if url.scheme != "https" or not url.netloc:
                errors.append(f"{label}: docs/SDK evidence requires an HTTPS URL")
    category = entry.get("category")
    required = EVIDENCE_KINDS.get(category) if isinstance(category, str) else None
    if required and not required.issubset(kinds):
        errors.append(f"{label}: evidence requires {', '.join(sorted(required))} sources")
    if category == "docs_inconsistency" and kinds.count("docs") < 2:
        errors.append(f"{label}: docs_inconsistency requires two documented claims")
    return errors


def validate(path: Path) -> tuple[list[dict[str, object]], list[str]]:
    errors: list[str] = []
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        return [], [f"{path}: {exc}"]
    if not isinstance(data, dict):
        return [], ["ledger root must be a JSON object"]
    if type(data.get("schema_version")) is not int or data["schema_version"] != 1:
        errors.append("schema_version must be 1")

    categories = data.get("categories")
    if (
        not isinstance(categories, list)
        or not all(isinstance(c, str) for c in categories)
        or len(categories) != len(VALID_CATEGORIES)
        or set(categories) != VALID_CATEGORIES
    ):
        errors.append("categories must list the five supported discrepancy categories once")

    entries = data.get("entries")
    observations = data.get("observations", [])
    if not isinstance(entries, list) or not isinstance(observations, list):
        return [], errors + ["entries and observations must be lists"]

    valid_entries: list[dict[str, object]] = []
    seen_ids: set[str] = set()
    for idx, entry in enumerate(entries + observations):
        if not isinstance(entry, dict):
            errors.append(f"entry[{idx}] must be an object")
            continue
        is_discrepancy = idx < len(entries)
        if is_discrepancy:
            valid_entries.append(entry)
        for field in REQUIRED_FIELDS:
            val = entry.get(field)
            if not isinstance(val, str) or not val.strip():
                errors.append(f"entry[{idx}] missing non-empty string field '{field}'")
        entry_id = str(entry.get("id", ""))
        if entry_id and not ID_RE.fullmatch(entry_id):
            errors.append(f"{entry_id}: id must match WD-NNN")
        if entry_id in seen_ids:
            errors.append(f"{entry_id}: duplicate id")
        seen_ids.add(entry_id)

        service = str(entry.get("service", ""))
        if service and service not in VALID_SERVICES:
            errors.append(f"{entry_id}: invalid service '{service}'")
        category = str(entry.get("category", ""))
        allowed = VALID_CATEGORIES if is_discrepancy else OBSERVATION_CATEGORIES
        if category and category not in allowed:
            errors.append(f"{entry_id}: invalid category '{category}'")
        status = str(entry.get("status", ""))
        allowed_statuses = VALID_STATUSES if is_discrepancy else OBSERVATION_CATEGORIES
        if status and status not in allowed_statuses:
            errors.append(f"{entry_id}: invalid status '{status}'")
        errors.extend(validate_evidence(entry, entry_id))

    return valid_entries, errors


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--ledger", default=str(LEDGER), help="Path to wire-discrepancies.json")
    args = parser.parse_args()

    path = Path(args.ledger).resolve()
    entries, errors = validate(path)
    if errors:
        for err in errors:
            print(f"ERROR: {err}", file=sys.stderr)
        return 1

    by_cat = Counter(str(e["category"]) for e in entries)
    by_svc = Counter(str(e["service"]) for e in entries)
    by_status = Counter(str(e["status"]) for e in entries)

    cats = ", ".join(f"{k}={v}" for k, v in sorted(by_cat.items()))
    svcs = ", ".join(f"{k}={v}" for k, v in sorted(by_svc.items()))
    statuses = ", ".join(f"{k}={v}" for k, v in sorted(by_status.items()))
    print(
        f"Wire discrepancies: total={len(entries)} | categories: {cats}"
        f" | services: {svcs} | status: {statuses}"
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
