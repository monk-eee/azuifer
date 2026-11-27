"""Reconcile the recording plan, manifest auth grid, and reviewed fixtures."""

import argparse
from collections import Counter
import json
from pathlib import Path
import re
import sys


ROOT = Path(__file__).resolve().parents[1]
PLAN = ROOT / "docs" / "compatibility" / "azure-recording-plan.md"
FIXTURES = ROOT / "tests" / "contracts" / "cassettes"
SERVICES = {"B": "blob", "D": "dfs", "F": "file", "Q": "queue", "T": "table"}
ROW = re.compile(r"^\| ([BDFQT]-\d+) \| ([^|]+) \| (\w+) \| ([^|]+) \| (\d+) \| ([^|]+) \|$")
CREDIT = re.compile(r"^(!?)`([^`]+)`")
LINK = re.compile(r"\]\(([^)]+)\)")


def check(condition, message):
    if not condition:
        raise ValueError(message)


def audit(show_grid):
    text = PLAN.read_text(encoding="utf-8")
    manifests = {
        service: json.loads(
            (ROOT / "specs" / "conformance" / f"{service}.json").read_bytes()
        )
        for service in SERVICES.values()
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
    planned, recorded, matched = Counter(), Counter(), Counter()
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
        for step in steps:
            credit = CREDIT.match(step)
            if credit is None:
                continue
            boundary, label = credit.groups()
            name, mode = label.split("@", 1) if "@" in label else (label, auth)
            target, name = name.split(":", 1) if ":" in name else (service, name)
            operation = (target, name)
            check(operation in definitions, f"{row}: unknown operation {operation}")
            if boundary:
                check(operation in unsupported, f"{row}: {operation} is not unsupported")
                check(operation not in boundaries, f"{row}: duplicate boundary {operation}")
                boundaries.add(operation)
            else:
                pair = (*operation, mode)
                check(pair in pairs, f"{row}: {pair} is not an advertised pair")
                check(pair not in credited, f"{row}: duplicate credit for {pair}")
                credited.add(pair)
        if evidence == "pending":
            continue
        link = LINK.search(evidence)
        check(link is not None, f"{row}: evidence requires a fixture link")
        path = (PLAN.parent / link[1]).resolve()
        check(path.parent == FIXTURES and path not in reviewed, f"{row}: invalid or reused fixture")
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
        recorded[service] += actual
        if not evidence.startswith("gap "):
            matched[service] += actual

    check(boundaries == unsupported, f"missing unsupported boundary rows: {sorted(unsupported - boundaries)}")
    check(
        reviewed == set(FIXTURES.glob("*.json")),
        "every reviewed cassette must be linked from exactly one row",
    )
    remaining = pairs - credited
    print("Service          Ops Auth pairs  Journeys* Extra grid     Target   Recorded    Matched Unrecorded")
    stats = []
    for service in SERVICES.values():
        operations = sum(s == service for s, _ in definitions)
        auth_pairs = sum(s == service for s, _, _ in pairs)
        grid = sum(s == service for s, _, _ in remaining)
        target = planned[service] + grid
        values = (
            operations, auth_pairs, planned[service], grid, target,
            recorded[service], matched[service], target - recorded[service],
        )
        stats.append(values)
        print(f"{service:<10}" + "".join(f"{n:>10}" for n in values))
    print(f"{'total':<10}" + "".join(f"{sum(column):>10}" for column in zip(*stats, strict=True)))
    print(f"*{len(seen_ids)} journey rows, counted here as their projected exchanges.")
    if show_grid:
        for service, name, auth in sorted(remaining):
            print(f"{service}\t{name}\t{auth}")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--grid", action="store_true", help="list every remaining operation/auth cell")
    options = parser.parse_args()
    try:
        audit(options.grid)
    except (ValueError, OSError) as exc:
        sys.exit(f"Recording plan: {exc}")
