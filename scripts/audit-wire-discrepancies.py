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

ROOT = Path(__file__).resolve().parents[1]
LEDGER = ROOT / "docs" / "compatibility" / "wire-discrepancies.json"
VALID_SERVICES = frozenset({"blob", "dfs", "file", "queue", "table", "shared"})
VALID_STATUSES = frozenset(
    {"aligned_in_azuifer", "awaiting_live_recording", "open_gap", "wont_fix"}
)
REQUIRED_FIELDS = (
    "id",
    "service",
    "operation",
    "category",
    "summary",
    "expected_by_docs_or_sdk",
    "observed_behavior",
    "evidence",
    "status",
)
ID_RE = re.compile(r"^WD-\d{3,}$")


def validate(path: Path) -> tuple[list[dict[str, object]], list[str]]:
    errors: list[str] = []
    data = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(data, dict):
        return [], ["ledger root must be a JSON object"]

    categories = data.get("categories")
    if not isinstance(categories, list) or not all(isinstance(c, str) for c in categories):
        return [], ["'categories' must be a list of strings"]
    allowed_categories = set(categories)

    entries = data.get("entries")
    if not isinstance(entries, list):
        return [], ["'entries' must be a list"]

    seen_ids: set[str] = set()
    for idx, entry in enumerate(entries):
        if not isinstance(entry, dict):
            errors.append(f"entry[{idx}] must be an object")
            continue
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
        if category and category not in allowed_categories:
            errors.append(f"{entry_id}: invalid category '{category}'")
        status = str(entry.get("status", ""))
        if status and status not in VALID_STATUSES:
            errors.append(f"{entry_id}: invalid status '{status}'")

    return entries, errors


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
    print(f"Wire discrepancies: total={len(entries)} | categories: {cats}")
    print(f"  services: {svcs} | status: {statuses}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
