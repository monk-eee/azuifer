# /// script
# requires-python = ">=3.10"
# dependencies = []
# ///
"""Unit tests for scripts/audit-docs.py."""

from __future__ import annotations

import importlib.util
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import sys
import tempfile
import unittest

SCRIPT = Path(__file__).resolve().parent / "audit-docs.py"
SPEC = importlib.util.spec_from_file_location("audit_docs", SCRIPT)
assert SPEC is not None and SPEC.loader is not None
MODULE = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = MODULE
SPEC.loader.exec_module(MODULE)
REPO = Path(__file__).resolve().parents[1]
SKIPPED_DIRECTORIES = {".git", "target", "node_modules", "dist", "__pycache__", "bin", "obj"}


class RepositoryTests(unittest.TestCase):
    def test_repository_docs_pass_the_audit(self) -> None:
        self.assertEqual(MODULE.audit(REPO), [])

    def test_command_line_reports_success(self) -> None:
        result = subprocess.run(
            [sys.executable, str(SCRIPT)], capture_output=True, text=True, check=False
        )
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("docs ok", result.stdout)


class FixtureTests(unittest.TestCase):
    """Break a copy of the real docs one way at a time."""

    @classmethod
    def setUpClass(cls) -> None:
        cls.folder = tempfile.TemporaryDirectory()
        cls.root = Path(cls.folder.name)
        cls.pristine: dict[Path, bytes] = {}
        for directory, names, files in os.walk(REPO):
            names[:] = [n for n in names if n not in SKIPPED_DIRECTORIES]
            relative = Path(directory).relative_to(REPO)
            (cls.root / relative).mkdir(parents=True, exist_ok=True)
            for name in files:
                source = Path(directory) / name
                target = cls.root / relative / name
                if source.suffix == ".md" or relative.parts[:1] in (("specs",), ("docs",)):
                    shutil.copy(source, target)
                    cls.pristine[target] = target.read_bytes()
                else:
                    target.touch()

    @classmethod
    def tearDownClass(cls) -> None:
        cls.folder.cleanup()

    def tearDown(self) -> None:
        for path in [*self.root.glob("*.md"), *self.root.glob("docs/**/*.md")]:
            if path not in self.pristine:
                path.unlink()
        for path, content in self.pristine.items():
            if not path.exists() or path.read_bytes() != content:
                path.write_bytes(content)

    def replace(self, relative: str, old: str, new: str) -> None:
        path = self.root / relative
        text = path.read_text(encoding="utf-8")
        self.assertIn(old, text)
        path.write_text(text.replace(old, new, 1), encoding="utf-8")

    def bump(self, relative: str, pattern: str) -> int:
        """Add one to the first number the pattern captures and return the new value."""
        path = self.root / relative
        text = path.read_text(encoding="utf-8")
        match = re.search(pattern, text)
        self.assertIsNotNone(match, pattern)
        value = int(match.group(1).replace(",", "")) + 1
        path.write_text(
            text[: match.start(1)] + f"{value:,}" + text[match.end(1) :], encoding="utf-8"
        )
        return value

    def errors(self) -> list[str]:
        return MODULE.audit(self.root)

    def assert_error(self, fragment: str) -> None:
        errors = self.errors()
        self.assertTrue(any(fragment in e for e in errors), errors)

    def test_broken_link_is_reported(self) -> None:
        self.replace("CONTRIBUTING.md", "(SECURITY.md)", "(SECURITY-MISSING.md)")
        self.assert_error("broken link SECURITY-MISSING.md")

    def test_link_with_the_wrong_letter_case_is_reported(self) -> None:
        self.replace("CONTRIBUTING.md", "(SECURITY.md)", "(security.md)")
        self.assert_error("broken link security.md")

    def test_missing_anchor_is_reported_and_real_anchor_is_accepted(self) -> None:
        self.replace("ONBOARDING.md", "README.md#run-locally", "README.md#no-such-heading")
        self.assert_error("missing anchor README.md#no-such-heading")
        self.replace("ONBOARDING.md", "README.md#no-such-heading", "README.md#run-locally")
        self.assertEqual(self.errors(), [])

    def test_links_inside_code_are_ignored(self) -> None:
        text = "`[x](missing.md)`\n\n```\n[y](also-missing.md)\n```\n"
        (self.root / "NOTES.md").write_text(text, encoding="utf-8")
        self.assertEqual(self.errors(), [])

    def test_unindexed_adr_is_reported(self) -> None:
        (self.root / "docs" / "adr.d" / "0099-new-decision.md").write_text("# ADR\n", encoding="utf-8")
        self.assert_error("0099-new-decision.md is not indexed")

    def test_stale_code_path_is_reported(self) -> None:
        (self.root / "NOTES.md").write_text("See `src/gone.rs`.\n", encoding="utf-8")
        self.assert_error("`src/gone.rs` does not exist")

    def test_operation_count_contradicting_the_manifests_is_reported(self) -> None:
        value = self.bump("README.md", r"implements \*\*(\d+) of \d+ recognized operations")
        self.assert_error(f"README.md: implemented operations claims {value}")

    def test_exchange_and_cassette_counts_are_checked(self) -> None:
        contracts = "docs/compatibility/azure-contracts.md"
        value = self.bump(contracts, r"tracks \*\*(\d+) of [\d,]+ planned exchanges matched")
        self.assert_error(f"azure-contracts.md: planned exchanges claims {value}")
        value = self.bump("README.md", r"\*\*(\d+) reviewed Azure cassettes\*\*")
        self.assert_error(f"README.md: cassettes and exchanges claims {value}")

    def test_recording_plan_rows_are_checked(self) -> None:
        self.bump("docs/compatibility/azure-recording-plan.md", r"\| DFS \| (\d+) \|")
        self.assert_error("DFS row says")

    def test_wire_discrepancy_count_is_checked_against_the_ledger(self) -> None:
        value = self.bump("README.md", r"tracks (\d+) pinned")
        self.assert_error(f"wire discrepancies claims {value}")
        ledger = self.root / "docs" / "compatibility" / "wire-discrepancies.json"
        data = json.loads(ledger.read_text(encoding="utf-8"))
        data["entries"].pop()
        ledger.write_text(json.dumps(data), encoding="utf-8")
        self.assert_error(f"{len(data['entries'])} entries but the manifests count {value - 1}")

    def test_exact_rating_without_evidence_is_reported(self) -> None:
        path = self.root / "specs" / "conformance" / "queue.json"
        data = json.loads(path.read_text(encoding="utf-8"))
        data["operations"][0]["state"] = "exact"
        path.write_text(json.dumps(data), encoding="utf-8")
        self.assert_error("queue.json: 1 operation(s) rated exact")

    def test_unqualified_parity_claim_is_reported_but_a_negated_one_is_not(self) -> None:
        (self.root / "NOTES.md").write_text("Azuifer has full parity with Azure.\n", encoding="utf-8")
        self.assert_error("NOTES.md:1: unqualified parity claim")
        (self.root / "NOTES.md").write_text("Azuifer does not claim full parity.\n", encoding="utf-8")
        self.assertEqual(self.errors(), [])

    def test_a_removed_claim_is_reported_instead_of_skipped(self) -> None:
        self.replace("README.md", "recognized operations", "operations")
        self.assert_error("README.md: no longer states implemented operations")

    def test_unreadable_manifest_is_reported(self) -> None:
        (self.root / "specs" / "conformance" / "blob.json").write_text("{", encoding="utf-8")
        self.assert_error("blob.json: unreadable manifest")


class SlugTests(unittest.TestCase):
    def test_slugs_follow_github_rules(self) -> None:
        text = "# Run locally\n## A `code` & more!\n## Run locally\n```\n# not a heading\n```\n"
        self.assertEqual(
            MODULE.anchors(text), {"run-locally", "a-code--more", "run-locally-1"}
        )


if __name__ == "__main__":
    unittest.main()
