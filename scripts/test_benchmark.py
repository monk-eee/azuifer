# /// script
# requires-python = ">=3.11"
# dependencies = []
# ///
"""Deterministic benchmark/report checks and an opt-in real-binary smoke test."""

import copy
import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

if __package__:
    from . import benchmark
else:
    import benchmark

SCRIPT = Path(__file__).with_name("benchmark.py").resolve()
COMMIT = "a" * 40


def run_cli(*args):
    return subprocess.run([sys.executable, "-B", SCRIPT, *args], capture_output=True,
                          encoding="utf-8", timeout=90)


def report():
    operations = {
        op: benchmark.summarize([1_000_000] * 2, 2 * 1024 * 1024 if op.endswith("_stream") else 0)
        for op in benchmark.OPERATIONS
    }
    return {
        "schema_version": 1,
        "commit_sha": COMMIT,
        "azuifer_version": "0.1.0",
        "binary_sha256": "b" * 64,
        "platform": {
            "system": "Linux", "release": "test", "version": "test", "arch": "x86_64",
            "processor": "test", "logical_cpus": 4, "python": "3.13.0", "rss_source": "ru_maxrss_kib",
        },
        "parameters": {
            "api_version": "2023-11-03", "server_threads": 2, "warmup_iterations": 1,
            "measured_iterations": 2, "stream_iterations": 2, "stream_bytes": 2 * 1024 * 1024,
            "memory_limit_mib": 64, "peak_rss_limits_kib": {"persistent": 12_500, "in_memory": 30_000},
        },
        "modes": {
            "persistent": {"peak_rss_kib": 10_000, "operations": operations},
            "in_memory": {"peak_rss_kib": 20_000, "operations": copy.deepcopy(operations)},
        },
    }


class BenchmarkTests(unittest.TestCase):
    def test_summary_uses_total_time_and_nearest_rank_for_small_and_large_samples(self):
        samples_ns = [n * 1_000_000 for n in range(100, 0, -1)]
        result = benchmark.summarize(samples_ns, 2 * 1024 * 1024)
        self.assertEqual(result["latency_ms"], {"p50": 50.0, "p95": 95.0, "p99": 99.0})
        self.assertAlmostEqual(result["ops_per_second"], 100 / 5.05)
        self.assertAlmostEqual(result["mib_per_second"], 200 / 5.05)
        result = benchmark.summarize([2_000_000, 1_000_000])
        self.assertEqual(result["latency_ms"], {"p50": 1.0, "p95": 2.0, "p99": 2.0})
        self.assertIsNone(result["mib_per_second"])

    def test_schema_rejects_bad_versions_missing_operations_and_invalid_data(self):
        benchmark.validate(json.loads(json.dumps(report(), allow_nan=False)))
        for name, modify, error in (
            ("version", lambda r: r.update(schema_version=True), "schema_version"),
            ("mode", lambda r: r["modes"].pop("persistent"), "both benchmark modes"),
            ("RSS", lambda r: r["modes"]["in_memory"].update(peak_rss_kib=0), "peak RSS"),
            ("operation", lambda r: r["modes"]["persistent"]["operations"].pop("dfs.create"),
             "incomplete operations"),
            ("throughput", lambda r: r["modes"]["persistent"]["operations"]["table.batch"].update(
                ops_per_second=float("nan")), "invalid sample count or throughput"),
            ("percentile", lambda r: r["modes"]["persistent"]["operations"]["table.batch"]["latency_ms"].update(
                p99=0.1), "invalid percentiles"),
        ):
            with self.subTest(name=name):
                invalid = report()
                modify(invalid)
                with self.assertRaisesRegex(ValueError, error):
                    benchmark.validate(invalid)

    def test_cli_fails_a_regression_and_honors_each_tolerance(self):
        baseline = report()
        current = copy.deepcopy(baseline)
        current["commit_sha"] = "c" * 40
        data = current["modes"]["persistent"]
        data["operations"]["blob.put_stream"].update(ops_per_second=800, mib_per_second=1600)
        data["operations"]["table.batch"]["latency_ms"]["p99"] = 1.25
        data["peak_rss_kib"] = 12_000
        with tempfile.TemporaryDirectory() as directory:
            a, b = [Path(directory) / f"{name}.json" for name in ("baseline", "current")]
            a.write_text(json.dumps(baseline), encoding="utf-8")
            b.write_text(json.dumps(current), encoding="utf-8")
            result = run_cli("--compare", a, b)
            self.assertEqual(result.returncode, 1, result.stderr)
            self.assertIn("| Mode | Operation | ops/s | MiB/s | p50 ms | p95 ms | p99 ms |", result.stdout)
            self.assertIn("REGRESSION: ops/s, MiB/s", result.stdout)
            self.assertIn("REGRESSION: p99", result.stdout)
            self.assertIn("REGRESSION: RSS", result.stdout)
            result = run_cli("--compare", a, b, "--throughput-tolerance-pct", "20",
                             "--latency-tolerance-pct", "25", "--rss-tolerance-pct", "20")
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertNotIn("REGRESSION", result.stdout)

    def test_compare_rejects_incomparable_reports_and_enforces_absolute_peak_limit(self):
        baseline = report()
        current = copy.deepcopy(baseline)
        current["platform"]["arch"] = "arm64"
        with self.assertRaisesRegex(ValueError, "different platform"):
            benchmark.compare(baseline, current, 10, 15, 15)
        current = copy.deepcopy(baseline)
        current["parameters"]["stream_bytes"] *= 2
        with self.assertRaisesRegex(ValueError, "different parameters"):
            benchmark.compare(baseline, current, 10, 15, 15)
        with self.assertRaisesRegex(ValueError, "current: expected benchmark schema_version"):
            benchmark.compare(baseline, {}, 10, 15, 15)
        current = copy.deepcopy(baseline)
        current["modes"]["persistent"]["peak_rss_kib"] = 13_000
        table, failed = benchmark.compare(baseline, current, 100, 100, 100)
        self.assertTrue(failed)
        self.assertIn("REGRESSION: absolute RSS limit", table)


@unittest.skipUnless(os.environ.get("AZUIFER_BENCHMARK_BINARY"), "set AZUIFER_BENCHMARK_BINARY for real smoke")
class BenchmarkSmokeTest(unittest.TestCase):
    def test_quick_runs_all_workloads_in_both_storage_modes(self):
        binary = Path(os.environ["AZUIFER_BENCHMARK_BINARY"])
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            output = root / "report.json"
            result = run_cli("--quick", "--binary", binary, "--commit", COMMIT,
                             "--output", output, "--data-root", root)
            self.assertEqual(result.returncode, 0, result.stderr)
            report = json.loads(output.read_text(encoding="utf-8"))
            self.assertEqual(list(root.iterdir()), [output], "temporary emulator data must be removed")
        benchmark.validate(report)
        self.assertEqual(report["commit_sha"], COMMIT)
        with binary.open("rb") as file:
            self.assertEqual(report["binary_sha256"], hashlib.file_digest(file, "sha256").hexdigest())
        self.assertEqual(report["parameters"]["stream_bytes"], 2 * 1024 * 1024)
        self.assertEqual(report["parameters"]["warmup_iterations"], 1)
        for mode, data in report["modes"].items():
            self.assertGreater(data["peak_rss_kib"], 0, mode)
            self.assertLessEqual(data["peak_rss_kib"], report["parameters"]["peak_rss_limits_kib"][mode], mode)
            operations = data["operations"]
            self.assertEqual(len(operations), 19)
            self.assertEqual({name.split(".")[0] for name in operations}, {"blob", "dfs", "file", "queue", "table"})
            self.assertEqual(operations["table.batch"]["samples"], 2)
            for name in ("blob.put_stream", "blob.get_stream"):
                self.assertEqual(operations[name]["samples"], 1)
                self.assertGreater(operations[name]["mib_per_second"], 0)
        self.assertGreaterEqual(
            report["modes"]["in_memory"]["peak_rss_kib"], report["parameters"]["stream_bytes"] // 1024,
            "an in-memory run must account for at least one resident payload",
        )


if __name__ == "__main__":
    unittest.main()
