"""Reconcile the recording plan, manifest auth grid, and reviewed fixtures."""

import argparse
from collections import Counter
import json
from pathlib import Path
import re
import sys


ROOT = Path(__file__).resolve().parents[1]
SERVICES = {"B": "blob", "D": "dfs", "F": "file", "Q": "queue", "T": "table"}
ROW = re.compile(r"^\| ([BDFQT]-\d+) \| ([^|]+) \| (\w+) \| ([^|]+) \| (\d+) \| ([^|]+) \|$")
CREDIT = re.compile(r"^(!?)`([^`]+)`")
LINK = re.compile(r"\]\(([^)]+)\)")


def check(condition, message):
    if not condition:
        raise ValueError(message)


def audit(show_grid, *, write_evidence=False, root=ROOT):
    compatibility = root / "docs" / "compatibility"
    plan = compatibility / "azure-recording-plan.md"
    fixtures = root / "tests" / "contracts" / "cassettes"
    manifest_paths = {
        service: root / "specs" / "conformance" / f"{service}.json"
        for service in SERVICES.values()
    }
    text = plan.read_text(encoding="utf-8")
    manifests = {
        service: json.loads(path.read_bytes())
        for service, path in manifest_paths.items()
    }
    definitions = {
        (service, operation["name"]): operation
        for service, manifest in manifests.items()
        for operation in manifest["operations"]
    }
    pairs = {
        (service, name, auth)
        for (service, name), operation in definitions.items()
        for auth in operation["authorization"]
    }
    unsupported = {
        key for key, operation in definitions.items() if operation["state"] == "unsupported"
    }
    seen_ids, credited, boundaries, reviewed = set(), set(), set(), set()
    planned, recorded, matched, cassettes = Counter(), Counter(), Counter(), Counter()
    matched_auth = {service: {} for service in manifests}
    matched_boundaries = {service: {} for service in manifests}
    for line in text.splitlines():
        if not re.match(r"^\| [BDFQT]-", line):
            continue
        match = ROW.fullmatch(line)
        check(match is not None, f"invalid row: {line}")
        row, _, auth, journey, count, evidence = match.groups()
        service = SERVICES[row[0]]
        check(row not in seen_ids, f"{row}: duplicate row")
        seen_ids.add(row)
        steps = journey.split("; ")
        check(len(steps) == int(count), f"{row}: {len(steps)} steps != {count}")
        planned[service] += len(steps)
        is_matched = evidence != "pending" and not evidence.startswith("gap ")
        for step in steps:
            credit = CREDIT.match(step)
            if credit is None:
                continue
            boundary, label = credit.groups()
            name, mode = label.split("@", 1) if "@" in label else (label, auth)
            target, name = name.split(":", 1) if ":" in name else (service, name)
            operation = (target, name)
            check(operation in definitions, f"{row}: unknown operation {operation}")
            if is_matched:
                check(
                    manifests[target]["api_version"] == manifests[service]["api_version"],
                    f"{row}: cannot credit {target} at a different API baseline",
                )
            if boundary:
                check(operation in unsupported, f"{row}: {operation} is not unsupported")
                check(operation not in boundaries, f"{row}: duplicate boundary {operation}")
                boundaries.add(operation)
                if is_matched:
                    matched_boundaries[target][name] = row
            else:
                pair = (*operation, mode)
                check(pair in pairs, f"{row}: {pair} is not an advertised pair")
                check(pair not in credited, f"{row}: duplicate credit for {pair}")
                credited.add(pair)
                if is_matched:
                    matched_auth[target].setdefault(name, {})[mode] = row
        if evidence == "pending":
            continue
        link = LINK.search(evidence)
        check(link is not None, f"{row}: evidence requires a fixture link")
        path = (plan.parent / link[1]).resolve()
        check(path.parent == fixtures and path not in reviewed, f"{row}: invalid or reused fixture")
        cassette = json.loads(path.read_bytes())
        check(cassette.get("source") == "azure", f"{row}: evidence is not from Azure")
        check(
            cassette.get("api_version") == manifests[service]["api_version"],
            f"{row}: incorrect Azure API version",
        )
        responses = cassette.get("responses", cassette.get("exchanges"))
        actual = len(responses) if responses is not None else int("response" in cassette)
        check(actual == len(steps), f"{row}: fixture has {actual} exchanges, not {len(steps)}")
        reviewed.add(path)
        cassettes[service] += 1
        recorded[service] += actual
        if is_matched:
            matched[service] += actual

    check(boundaries == unsupported, f"missing unsupported boundary rows: {sorted(unsupported - boundaries)}")
    check(
        reviewed == set(fixtures.glob("*.json")),
        "every reviewed cassette must be linked from exactly one row",
    )
    ledger = json.loads((compatibility / "wire-discrepancies.json").read_bytes())
    entries = ledger.get("entries") if isinstance(ledger, dict) else None
    check(isinstance(entries, list), "wire ledger is missing its entries list")
    discrepancies = Counter()
    for entry in entries:
        service = entry.get("service") if isinstance(entry, dict) else None
        check(isinstance(service, str) and service in manifests, "wire ledger names an unknown service")
        discrepancies[service] += 1
    remaining = pairs - credited
    stats = []
    for service in SERVICES.values():
        operations = sum(s == service for s, _ in definitions)
        auth_pairs = sum(s == service for s, _, _ in pairs)
        grid = sum(s == service for s, _, _ in remaining)
        target = planned[service] + grid
        projection = {
            "cassettes": cassettes[service],
            "target_exchanges": target,
            "recorded_exchanges": recorded[service],
            "matched_exchanges": matched[service],
            "matched_operation_auth": matched_auth[service],
            "matched_unsupported_boundaries": matched_boundaries[service],
            "wire_discrepancies": discrepancies[service],
        }
        manifest = manifests[service]
        if manifest.get("live_azure_evidence") != projection:
            path = manifest_paths[service]
            check(
                write_evidence,
                f"{path.name}: missing or stale live_azure_evidence; "
                "run python scripts/audit-azure-recording-plan.py --write-evidence",
            )
            manifest["live_azure_evidence"] = projection
            path.write_bytes((json.dumps(manifest, ensure_ascii=False, indent=2) + "\n").encode())
        values = (
            operations, auth_pairs, planned[service], grid, target,
            recorded[service], matched[service], target - recorded[service],
        )
        stats.append((service, values))
    print("Service          Ops Auth pairs  Journeys* Extra grid     Target   Recorded    Matched Unrecorded")
    for service, values in stats:
        print(f"{service:<10}" + "".join(f"{n:>10}" for n in values))
    totals = zip(*(values for _, values in stats), strict=True)
    print(f"{'total':<10}" + "".join(f"{sum(column):>10}" for column in totals))
    print(f"*{len(seen_ids)} journey rows, counted here as their projected exchanges.")
    if show_grid:
        for service, name, auth in sorted(remaining):
            print(f"{service}\t{name}\t{auth}")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--grid", action="store_true", help="list every remaining operation/auth cell")
    parser.add_argument(
        "--write-evidence", action="store_true", help="refresh each service manifest's live evidence"
    )
    options = parser.parse_args()
    try:
        audit(options.grid, write_evidence=options.write_evidence)
    except (ValueError, OSError) as exc:
        sys.exit(f"Recording plan: {exc}")
