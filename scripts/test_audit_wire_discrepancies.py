# /// script
# requires-python = ">=3.10"
# dependencies = []
# ///
"""Unit tests for scripts/audit-wire-discrepancies.py."""

from __future__ import annotations

import importlib.util
import json
from pathlib import Path
import tempfile
import unittest

SCRIPT = Path(__file__).resolve().parent / "audit-wire-discrepancies.py"
SPEC = importlib.util.spec_from_file_location("audit_wire_discrepancies", SCRIPT)
assert SPEC is not None and SPEC.loader is not None
MODULE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(MODULE)


class WireDiscrepancyLedgerTests(unittest.TestCase):
    def test_repo_ledger_is_valid(self) -> None:
        entries, errors = MODULE.validate(MODULE.LEDGER)
        self.assertEqual(errors, [])
        self.assertGreaterEqual(len(entries), 10)

    def test_rejects_duplicate_ids_and_unknown_category(self) -> None:
        bad = {
            "schema_version": 1,
            "categories": ["live_vs_docs"],
            "entries": [
                {
                    "id": "WD-001",
                    "service": "blob",
                    "operation": "Get Blob",
                    "category": "live_vs_docs",
                    "summary": "a",
                    "expected_by_docs_or_sdk": "b",
                    "observed_behavior": "c",
                    "evidence": "d",
                    "status": "aligned_in_azuifer",
                },
                {
                    "id": "WD-001",
                    "service": "blob",
                    "operation": "Get Blob",
                    "category": "made_up",
                    "summary": "a",
                    "expected_by_docs_or_sdk": "b",
                    "observed_behavior": "c",
                    "evidence": "d",
                    "status": "aligned_in_azuifer",
                },
            ],
        }
        with tempfile.TemporaryDirectory() as folder:
            path = Path(folder) / "ledger.json"
            path.write_text(json.dumps(bad), encoding="utf-8")
            _, errors = MODULE.validate(path)
        self.assertTrue(any("duplicate id" in e for e in errors))
        self.assertTrue(any("invalid category" in e for e in errors))


if __name__ == "__main__":
    unittest.main()
