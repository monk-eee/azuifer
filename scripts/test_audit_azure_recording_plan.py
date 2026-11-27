# /// script
# requires-python = ">=3.10"
# dependencies = []
# ///
"""Live evidence projection coverage and drift checks."""

from contextlib import redirect_stdout
import importlib.util
import io
import json
from pathlib import Path
import tempfile
import unittest

SCRIPT = Path(__file__).with_name("audit-azure-recording-plan.py")
SPEC = importlib.util.spec_from_file_location("audit_azure_recording_plan", SCRIPT)
assert SPEC is not None and SPEC.loader is not None
AUDITOR = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(AUDITOR)


class RecordingPlanTests(unittest.TestCase):
    def setUp(self):
        directory = tempfile.TemporaryDirectory()
        self.addCleanup(directory.cleanup)
        self.root = Path(directory.name).resolve()
        version = "2023-11-03"
        for service, operations in {
            "blob": [("Get Blob", ["Bearer", "SharedKey"]), ("Rename Container", [])],
            "dfs": [("Read File", ["Bearer"])],
            "queue": [("Get Messages", ["Bearer"])],
            "file": [],
            "table": [],
        }.items():
            self.write_json(f"specs/conformance/{service}.json", {
                "service": service,
                "api_version": version,
                "operations": [
                    {"name": name, "state": "known-difference" if modes else "unsupported",
                     "authorization": modes}
                    for name, modes in operations
                ],
            })
        self.write_json("docs/compatibility/wire-discrepancies.json", {
            "entries": [{"service": "blob"}],
            "observations": [{"service": "queue"}],
        })
        for name, count in (("read", 2), ("rename", 1), ("queue-gap", 1)):
            self.write_json(f"tests/contracts/cassettes/{name}.json", {
                "source": "azure", "api_version": version, "responses": [{}] * count,
            })
        self.plan = self.root / "docs" / "compatibility" / "azure-recording-plan.md"
        self.plan.write_text(
            "| B-01 | flat | Bearer | `Get Blob`; `dfs:Read File@Bearer` | 2 | "
            "[fixture](../../tests/contracts/cassettes/read.json) |\n"
            "| B-02 | flat | Bearer | !`Rename Container` | 1 | "
            "[fixture](../../tests/contracts/cassettes/rename.json) |\n"
            "| Q-01 | queue | Bearer | `Get Messages` | 1 | "
            "gap [fixture](../../tests/contracts/cassettes/queue-gap.json) |\n"
            "| B-03 | flat + keys | SharedKey | `Get Blob` | 1 | pending |\n",
            encoding="utf-8",
        )

    def write_json(self, path, value):
        output = self.root / path
        output.parent.mkdir(parents=True, exist_ok=True)
        output.write_text(json.dumps(value), encoding="utf-8")

    def evidence(self, service):
        path = self.root / "specs" / "conformance" / f"{service}.json"
        return json.loads(path.read_bytes())["live_azure_evidence"]

    def audit(self, *, write=False):
        with redirect_stdout(io.StringIO()):
            AUDITOR.audit(False, write_evidence=write, root=self.root)

    def test_only_matched_rows_credit_operations_and_auth(self):
        self.audit(write=True)
        blob = self.evidence("blob")
        self.assertEqual(blob["matched_operation_auth"], {"Get Blob": {"Bearer": "B-01"}})
        self.assertEqual(blob["matched_unsupported_boundaries"], {"Rename Container": "B-02"})
        self.assertEqual(blob["target_exchanges"], 4)
        self.assertEqual(blob["matched_exchanges"], 3)
        self.assertEqual(blob["wire_discrepancies"], 1)
        dfs = self.evidence("dfs")
        self.assertEqual(dfs["matched_operation_auth"], {"Read File": {"Bearer": "B-01"}})
        self.assertEqual(dfs["matched_exchanges"], 0)  # Exchanges belong to the journey service.
        queue = self.evidence("queue")
        self.assertEqual(queue["recorded_exchanges"], 1)
        self.assertEqual(queue["matched_exchanges"], 0)
        self.assertEqual(queue["matched_operation_auth"], {})
        self.assertEqual(queue["wire_discrepancies"], 0)

    def test_audit_rejects_stale_evidence_until_refreshed(self):
        with self.assertRaisesRegex(ValueError, "missing or stale live_azure_evidence"):
            self.audit()
        self.audit(write=True)
        self.audit()
        plan = self.plan.read_text(encoding="utf-8").replace("gap [fixture]", "[fixture]")
        self.plan.write_text(plan, encoding="utf-8")
        with self.assertRaisesRegex(ValueError, "queue.json: missing or stale"):
            self.audit()
        self.audit(write=True)
        self.audit()
        self.assertEqual(self.evidence("queue")["matched_operation_auth"],
                         {"Get Messages": {"Bearer": "Q-01"}})

    def test_matched_cross_service_credit_requires_the_same_api_baseline(self):
        path = self.root / "specs" / "conformance" / "dfs.json"
        manifest = json.loads(path.read_bytes())
        manifest["api_version"] = "2024-11-04"
        path.write_text(json.dumps(manifest), encoding="utf-8")
        with self.assertRaisesRegex(ValueError, "B-01: cannot credit dfs at a different API baseline"):
            self.audit(write=True)


if __name__ == "__main__":
    unittest.main()
