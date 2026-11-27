# /// script
# requires-python = ">=3.10"
# dependencies = []
# ///
"""Unit tests for scripts/audit-wire-discrepancies.py."""

from __future__ import annotations

import importlib.util
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

SCRIPT = Path(__file__).resolve().parent / "audit-wire-discrepancies.py"
SPEC = importlib.util.spec_from_file_location("audit_wire_discrepancies", SCRIPT)
assert SPEC is not None and SPEC.loader is not None
MODULE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(MODULE)


class WireDiscrepancyLedgerTests(unittest.TestCase):
    def write_ledger(self, data: object, folder: str) -> Path:
        path = Path(folder) / "ledger.json"
        path.write_text(json.dumps(data), encoding="utf-8")
        return path

    def test_rejects_self_declared_categories_and_schema_versions(self) -> None:
        data = {
            "schema_version": 99,
            "categories": ["made_up"],
            "entries": [],
            "observations": [],
        }
        with tempfile.TemporaryDirectory() as folder:
            _, errors = MODULE.validate(self.write_ledger(data, folder))
        self.assertTrue(any("schema_version" in e for e in errors))
        self.assertTrue(any("categories" in e for e in errors))

    def test_rejects_unstructured_live_evidence(self) -> None:
        data = json.loads(MODULE.LEDGER.read_text(encoding="utf-8"))
        entry = dict(data["entries"][0])
        entry["category"] = "undocumented_live"
        entry["evidence"] = "An earlier agent said this happened."
        data["entries"] = [entry]
        with tempfile.TemporaryDirectory() as folder:
            _, errors = MODULE.validate(self.write_ledger(data, folder))
        self.assertTrue(any("evidence" in e for e in errors))

    def test_cli_reports_malformed_json_without_traceback(self) -> None:
        with tempfile.TemporaryDirectory() as folder:
            path = Path(folder) / "ledger.json"
            path.write_text("{", encoding="utf-8")
            result = subprocess.run(
                [sys.executable, str(SCRIPT), "--ledger", str(path)],
                capture_output=True,
                text=True,
                check=False,
            )
        self.assertEqual(result.returncode, 1)
        self.assertIn("ERROR:", result.stderr)
        self.assertNotIn("Traceback", result.stderr)

    def test_rejects_synthetic_or_unscoped_live_evidence(self) -> None:
        data = json.loads(MODULE.LEDGER.read_text(encoding="utf-8"))
        data["entries"] = [data["entries"][0]]
        live = next(e for e in data["entries"][0]["evidence"] if e["kind"] == "live")
        live["source"] = "synthetic"
        live.pop("auth_mode")
        with tempfile.TemporaryDirectory() as folder:
            _, errors = MODULE.validate(self.write_ledger(data, folder))
        self.assertTrue(any("source=azure" in e for e in errors))
        self.assertTrue(any("auth_mode" in e for e in errors))

    def test_rejects_malformed_evidence_url(self) -> None:
        data = json.loads(MODULE.LEDGER.read_text(encoding="utf-8"))
        data["entries"] = [data["entries"][0]]
        data["entries"][0]["evidence"][0]["reference"] = "https://["
        with tempfile.TemporaryDirectory() as folder:
            _, errors = MODULE.validate(self.write_ledger(data, folder))
        self.assertTrue(any("HTTPS URL" in e for e in errors))

    def test_cli_excludes_observations_from_tally(self) -> None:
        data = json.loads(MODULE.LEDGER.read_text(encoding="utf-8"))
        data["entries"] = [data["entries"][0]]
        with tempfile.TemporaryDirectory() as folder:
            path = self.write_ledger(data, folder)
            result = subprocess.run(
                [sys.executable, str(SCRIPT), "--ledger", str(path)],
                capture_output=True,
                text=True,
                check=False,
            )
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("total=1", result.stdout)
        self.assertNotIn("documented_match=", result.stdout)
        self.assertNotIn("needs_evidence=", result.stdout)

    def test_repo_ledger_is_valid(self) -> None:
        entries, errors = MODULE.validate(MODULE.LEDGER)
        self.assertEqual(errors, [])
        self.assertTrue(entries)

    def test_rejects_duplicate_ids_and_unknown_category(self) -> None:
        bad = json.loads(MODULE.LEDGER.read_text(encoding="utf-8"))
        duplicate = dict(bad["entries"][0])
        duplicate["category"] = "made_up"
        bad["entries"] = [bad["entries"][0], duplicate]
        with tempfile.TemporaryDirectory() as folder:
            path = Path(folder) / "ledger.json"
            path.write_text(json.dumps(bad), encoding="utf-8")
            _, errors = MODULE.validate(path)
        self.assertTrue(any("duplicate id" in e for e in errors))
        self.assertTrue(any("invalid category" in e for e in errors))


if __name__ == "__main__":
    unittest.main()
