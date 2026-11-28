# /// script
# requires-python = ">=3.11"
# dependencies = []
# ///
"""Measure local Azuifer releases or compare two benchmark reports."""

import argparse
import base64
import contextlib
import hashlib
import http.client
import json
import math
import os
from pathlib import Path
import platform
import re
import subprocess
import sys
import tempfile
import time
import xml.etree.ElementTree as ET

if __package__:
    from . import benchmark_workloads as workload
else:
    import benchmark_workloads as workload

SCHEMA_VERSION = 1
MODES = ("persistent", "in_memory")
PERCENTILES = (50, 95, 99)
OPERATIONS = {f"{service}.{op}" for service, ops in workload.OPERATIONS.items() for op in ops}
RSS_SOURCES = {
    "Linux": "ru_maxrss_kib",
    "Darwin": "ru_maxrss_bytes",
    "Windows": "peak_working_set_bytes",
}


def percentile(sorted_samples, percent):
    """Nearest rank: use the first sample at or above the requested rank."""
    return sorted_samples[(len(sorted_samples) * percent + 99) // 100 - 1]


def summarize(samples_ns, transfer_bytes=0):
    samples = sorted(samples_ns)
    if not samples or samples[0] <= 0:
        raise ValueError("benchmark samples must be positive")
    ops = len(samples) * 1_000_000_000 / sum(samples)
    return {
        "samples": len(samples),
        "ops_per_second": ops,
        "mib_per_second": ops * transfer_bytes / workload.MIB if transfer_bytes else None,
        "latency_ms": {f"p{p}": percentile(samples, p) / 1_000_000 for p in PERCENTILES},
    }


def windows_peak_kib(pid):
    import ctypes
    from ctypes import wintypes

    class Counters(ctypes.Structure):
        _fields_ = [
            ("size", wintypes.DWORD),
            ("page_fault_count", wintypes.DWORD),
            ("peak_working_set_size", ctypes.c_size_t),
            ("other_counters", ctypes.c_size_t * 7),
        ]

    kernel = ctypes.WinDLL("kernel32", use_last_error=True)
    open_process = kernel.OpenProcess
    open_process.argtypes = (wintypes.DWORD, wintypes.BOOL, wintypes.DWORD)
    open_process.restype = wintypes.HANDLE
    close_handle = kernel.CloseHandle
    close_handle.argtypes = (wintypes.HANDLE,)
    close_handle.restype = wintypes.BOOL
    memory_info = kernel.K32GetProcessMemoryInfo
    memory_info.argtypes = (wintypes.HANDLE, ctypes.POINTER(Counters), wintypes.DWORD)
    memory_info.restype = wintypes.BOOL
    handle = open_process(0x1000, False, pid)  # PROCESS_QUERY_LIMITED_INFORMATION
    if not handle:
        raise ctypes.WinError(ctypes.get_last_error())
    try:
        counters = Counters(size=ctypes.sizeof(Counters))
        if not memory_info(handle, ctypes.byref(counters), counters.size):
            raise ctypes.WinError(ctypes.get_last_error())
        return (counters.peak_working_set_size + 1023) // 1024
    finally:
        close_handle(handle)


def unix_peak_kib():
    import resource

    peak = resource.getrusage(resource.RUSAGE_CHILDREN).ru_maxrss
    return (peak + 1023) // 1024 if sys.platform == "darwin" else peak


def server_environment():
    return {
        name: value for name, value in os.environ.items()
        if not name.upper().startswith(("AZUIFER_", "OTEL_"))
    }


def ready_ports(process, output):
    deadline = time.monotonic() + 20
    expected = {*workload.SERVICES, "admin"}
    while time.monotonic() < deadline:
        if process.poll() is not None:
            raise ValueError(f"Azuifer exited with code {process.returncode} before readiness")
        ports = {}
        for line in output.read_text(encoding="utf-8").splitlines():
            name, _, address = line.partition("_url=")
            if name in expected:
                match = re.fullmatch(r"http://127\.0\.0\.1:(\d{1,5})", address)
                if match is not None and 0 < int(match[1]) <= 65535:
                    ports[name] = int(match[1])
        if ports.keys() == expected:
            probe = http.client.HTTPConnection("127.0.0.1", ports["admin"], timeout=1)
            try:
                probe.request("GET", "/readyz")
                with probe.getresponse() as response:
                    if response.status == 200 and response.read(64).strip() == b"ready":
                        return ports
            except (OSError, http.client.HTTPException):
                pass  # The listeners can be printed just before they accept requests.
            finally:
                probe.close()
        time.sleep(0.025)
    raise ValueError("Azuifer did not become ready on all five loopback listeners within 20 seconds")


@contextlib.contextmanager
def server(binary, mode, root, key, memory_limit_mib):
    command = [
        str(binary), "serve", "--bind", "127.0.0.1", "--port", "0", "--admin-port", "0",
        "--services", ",".join(workload.SERVICES), "--hns-accounts", workload.ACCOUNT,
        "--memory-limit", str(memory_limit_mib * workload.MIB), "--shutdown-on-stdin-eof",
    ]
    command += ["--location", str(root / "data")] if mode == "persistent" else ["--in-memory"]
    env = dict(server_environment(), AZUIFER_ACCOUNT_NAME=workload.ACCOUNT,
               AZUIFER_ACCOUNT_KEY=base64.b64encode(key).decode("ascii"), TOKIO_WORKER_THREADS="2")
    output = root / "listeners.txt"
    with output.open("wb") as listeners:
        process = subprocess.Popen(command, cwd=root, env=env, stdin=subprocess.PIPE,
                                   stdout=listeners, stderr=subprocess.DEVNULL)
        finished = False
        try:
            yield process, ready_ports(process, output)
            finished = True
        finally:
            process.stdin.close()
            try:
                process.wait(timeout=10)
            except subprocess.TimeoutExpired:
                process.kill()
                process.wait()
                if finished:
                    raise ValueError("Azuifer did not shut down after closing stdin") from None
            if finished and process.returncode:
                raise ValueError(f"Azuifer exited with code {process.returncode} after benchmarking")


def run_mode(binary, mode, data_root, parameters):
    # This isolated worker spawns only the emulator. On Unix RUSAGE_CHILDREN then
    # reports its high-water mark, not that of Git, --version, or another run.
    with tempfile.TemporaryDirectory(prefix="azuifer-bench-", dir=data_root) as directory:
        key = os.urandom(32)
        with server(binary, mode, Path(directory), key, parameters["memory_limit_mib"]) as (process, ports):
            client = workload.Workloads(ports, key, parameters["stream_bytes"])
            try:
                client.setup()
                for measuring in (False, True):
                    client.measuring = measuring
                    warmup = parameters["warmup_iterations"]
                    for _ in range(parameters["measured_iterations"] if measuring else warmup):
                        for service in workload.SERVICES:
                            getattr(client, service)()
                    for _ in range(parameters["stream_iterations"] if measuring else warmup):
                        client.stream()
                if sys.platform == "win32":
                    peak = windows_peak_kib(process.pid)
            finally:
                client.close()
        if sys.platform != "win32":
            peak = unix_peak_kib()
    operations = {
        op: summarize(samples, parameters["stream_bytes"] if op in workload.STREAM_OPERATIONS else 0)
        for op, samples in client.samples.items()
    }
    return {"peak_rss_kib": peak, "operations": operations}


def host_platform():
    system = platform.system()
    if system not in RSS_SOURCES:
        raise ValueError("benchmark RSS is supported on macOS, Linux, and Windows")
    return {
        "system": system, "release": platform.release(), "version": platform.version(),
        "arch": platform.machine(), "processor": platform.processor(), "logical_cpus": os.cpu_count(),
        "python": platform.python_version(), "rss_source": RSS_SOURCES[system],
    }


def settings(args):
    defaults = (1, 2, 1, 2) if args.quick else (5, 100, 10, 32)
    warmup, measured, streaming, size = [
        value if value is not None else default
        for value, default in zip((args.warmup, args.iterations, args.stream_iterations, args.stream_mib), defaults)
    ]
    if not (0 <= warmup <= 1000 and 1 <= measured <= 10000 and 1 <= streaming <= 1000
            and 2 <= size <= 1024):
        raise ValueError("require 0-1000 warmups, 1-10000 iterations, 1-1000 stream iterations and 2-1024 MiB")
    memory_rss = args.max_in_memory_rss_mib if args.max_in_memory_rss_mib is not None else 128 + 4 * size
    if min(args.max_persistent_rss_mib, memory_rss) <= 0:
        raise ValueError("RSS limits must be positive")
    return {
        "api_version": workload.API_VERSION, "server_threads": 2,
        "warmup_iterations": warmup, "measured_iterations": measured,
        "stream_iterations": streaming, "stream_bytes": size * workload.MIB,
        "memory_limit_mib": max(64, 3 * size),
        "peak_rss_limits_kib": {
            "persistent": args.max_persistent_rss_mib * 1024,
            "in_memory": memory_rss * 1024,
        },
    }


def measure(binary, commit, data_root, parameters):
    host = host_platform()
    version = subprocess.run([binary, "--version"], env=server_environment(),
                             capture_output=True, check=True, timeout=10, encoding="utf-8").stdout.strip()
    if not re.fullmatch(r"azuifer \S+", version):
        raise ValueError("expected an Azuifer executable that reports 'azuifer <version>'")
    with binary.open("rb") as file:
        digest = hashlib.file_digest(file, "sha256").hexdigest()
    modes = {}
    for mode in MODES:
        worker = [
            sys.executable, "-E", "-B", "-S", str(Path(__file__).resolve()), "--worker", mode,
            "--binary", str(binary),
        ]
        if data_root is not None:
            worker.extend(("--data-root", str(data_root)))
        result = subprocess.run(worker, input=json.dumps(parameters), capture_output=True, encoding="utf-8")
        if result.returncode:
            raise ValueError(f"{mode}: {result.stderr.strip() or f'worker exited {result.returncode}'}")
        modes[mode] = json.loads(result.stdout)
    return {
        "schema_version": SCHEMA_VERSION, "commit_sha": commit, "azuifer_version": version.split(" ", 1)[1],
        "binary_sha256": digest, "platform": host, "parameters": parameters, "modes": modes,
    }


def positive(value):
    return type(value) in (int, float) and 0 < value <= sys.float_info.max


def has_keys(value, keys):
    return isinstance(value, dict) and value.keys() == set(keys)


def validate(report):
    """Reject incomplete or incompatible schema data before evaluating thresholds."""
    require = workload.require
    require(has_keys(report, ("schema_version", "commit_sha", "azuifer_version", "binary_sha256",
                             "platform", "parameters", "modes"))
            and type(report["schema_version"]) is int and report["schema_version"] == SCHEMA_VERSION,
            f"expected benchmark schema_version {SCHEMA_VERSION}")
    for name in ("commit_sha", "binary_sha256"):
        require(isinstance(report[name], str)
                and re.fullmatch(r"[a-f0-9]{40}" if name == "commit_sha" else r"[a-f0-9]{64}", report[name]),
                f"invalid {name}")
    require(isinstance(report["azuifer_version"], str) and report["azuifer_version"], "missing Azuifer version")
    host = report["platform"]
    require(has_keys(host, ("system", "release", "version", "arch", "processor",
                            "logical_cpus", "python", "rss_source"))
            and all(isinstance(host[k], str) for k in host if k != "logical_cpus")
            and host["system"] in RSS_SOURCES and host["arch"]
            and host["rss_source"] == RSS_SOURCES[host["system"]]
            and (host["logical_cpus"] is None or (type(host["logical_cpus"]) is int and host["logical_cpus"] > 0)),
            "invalid platform or RSS source")
    params = report["parameters"]
    require(has_keys(params, ("api_version", "server_threads", "warmup_iterations", "measured_iterations",
                              "stream_iterations", "stream_bytes", "memory_limit_mib", "peak_rss_limits_kib"))
            and params["api_version"] == workload.API_VERSION, "invalid benchmark parameters")
    require(all(type(params[k]) is int and params[k] > 0 for k in
                ("server_threads", "measured_iterations", "stream_iterations", "stream_bytes", "memory_limit_mib"))
            and type(params["warmup_iterations"]) is int and params["warmup_iterations"] >= 0,
            "invalid iteration, payload, or memory settings")
    caps = params["peak_rss_limits_kib"]
    require(has_keys(caps, MODES) and all(type(cap) is int and cap > 0 for cap in caps.values()),
            "both modes need a positive RSS limit")
    require(has_keys(report["modes"], MODES), "report must contain both benchmark modes")
    for mode, data in report["modes"].items():
        require(has_keys(data, ("peak_rss_kib", "operations")) and type(data["peak_rss_kib"]) is int
                and positive(data["peak_rss_kib"]) and has_keys(data["operations"], OPERATIONS),
                f"{mode}: invalid peak RSS or incomplete operations")
        for op, item in data["operations"].items():
            streaming = op in workload.STREAM_OPERATIONS
            expected = params["stream_iterations" if streaming else "measured_iterations"]
            require(has_keys(item, ("samples", "ops_per_second", "mib_per_second", "latency_ms"))
                    and type(item["samples"]) is int and item["samples"] == expected
                    and positive(item["ops_per_second"])
                    and (positive(item["mib_per_second"]) if streaming else item["mib_per_second"] is None),
                    f"{mode}/{op}: invalid sample count or throughput")
            ms = item["latency_ms"]
            require(has_keys(ms, ("p50", "p95", "p99")) and all(positive(value) for value in ms.values())
                    and ms["p50"] <= ms["p95"] <= ms["p99"], f"{mode}/{op}: invalid percentiles")


def rss_failures(report):
    limits = report["parameters"]["peak_rss_limits_kib"]
    return [mode for mode in MODES if report["modes"][mode]["peak_rss_kib"] > limits[mode]]


def compare(baseline, current, throughput, latency, rss):
    for label, report in (("baseline", baseline), ("current", current)):
        try:
            validate(report)
        except ValueError as error:
            raise ValueError(f"{label}: {error}") from None
    for key in ("platform", "parameters"):
        if baseline[key] != current[key]:
            raise ValueError(f"reports use different {key}; rerun on matched settings and hardware")
    if rss_failures(baseline):
        raise ValueError("baseline exceeds its absolute peak RSS limit")

    rows = [
        f"Baseline `{baseline['commit_sha'][:12]}` -> current `{current['commit_sha'][:12]}`",
        f"Allowed regression: {throughput:g}% throughput loss, {latency:g}% latency increase, {rss:g}% RSS increase.",
        "",
        "| Mode | Operation | ops/s | MiB/s | p50 ms | p95 ms | p99 ms | Peak RSS KiB | Result |",
        "| --- | --- | --- | --- | --- | --- | --- | --- | --- |",
    ]
    failed = False
    over_limit = rss_failures(current)

    def row(mode, op, metrics, *, capped=False):
        nonlocal failed
        cells, regressions = [], []
        for name, before, after, tolerance, lower_is_better in metrics:
            if before is None:
                cells.append("-")
                continue
            change = 100 * ((after - before) / before)
            cells.append(f"{before:.3g} -> {after:.3g} ({change:+.1f}%)")
            if (change if lower_is_better else -change) > tolerance:
                regressions.append(name)
        if capped:
            regressions.append("absolute RSS limit")
        failed |= bool(regressions)
        result = "REGRESSION: " + ", ".join(regressions) if regressions else "PASS"
        rows.append(f"| {mode} | {op} | " + " | ".join(cells) + f" | {result} |")

    for mode in MODES:
        a, b = baseline["modes"][mode], current["modes"][mode]
        for op in sorted(OPERATIONS):
            x, y = a["operations"][op], b["operations"][op]
            metrics = [(label, x[key], y[key], throughput, False) for label, key in
                       (("ops/s", "ops_per_second"), ("MiB/s", "mib_per_second"))]
            metrics.extend((f"p{p}", x["latency_ms"][f"p{p}"], y["latency_ms"][f"p{p}"], latency, True)
                           for p in PERCENTILES)
            row(mode, op, [*metrics, ("RSS", None, None, rss, True)])
        row(mode, "server peak", [("", None, None, rss, True)] * 5 + [
            ("RSS", a["peak_rss_kib"], b["peak_rss_kib"], rss, True)
        ], capped=mode in over_limit)
    return "\n".join(rows), failed


def percentage(value):
    number = float(value)
    if not math.isfinite(number) or not 0 <= number <= 100:
        raise argparse.ArgumentTypeError("tolerance must be between 0 and 100 percent")
    return number


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    action = parser.add_mutually_exclusive_group(required=True)
    action.add_argument("--binary", type=Path, help="path to the compiled azuifer executable")
    action.add_argument("--compare", type=Path, nargs=2, metavar=("BASELINE", "CURRENT"))
    parser.add_argument("--commit", help="full SHA of the commit that built --binary")
    parser.add_argument("--output", type=Path, help="write JSON here instead of stdout")
    parser.add_argument("--data-root", type=Path, help="existing directory for temporary state (default: system temp)")
    parser.add_argument("--quick", action="store_true", help="small smoke workload, not a performance baseline")
    parser.add_argument("--warmup", type=int, help="warmup passes per workload (default: 5)")
    parser.add_argument("--iterations", type=int, help="measured passes per small workload (default: 100)")
    parser.add_argument("--stream-iterations", type=int, help="measured streaming pairs (default: 10)")
    parser.add_argument("--stream-mib", type=int, help="streaming blob size in MiB (default: 32)")
    parser.add_argument("--max-persistent-rss-mib", type=int, default=128)
    parser.add_argument("--max-in-memory-rss-mib", type=int, help="default: 128 + 4 times --stream-mib")
    parser.add_argument("--throughput-tolerance-pct", type=percentage, default=10)
    parser.add_argument("--latency-tolerance-pct", type=percentage, default=15)
    parser.add_argument("--rss-tolerance-pct", type=percentage, default=15)
    parser.add_argument("--worker", choices=MODES, help=argparse.SUPPRESS)
    args = parser.parse_args(argv)
    try:
        if args.compare:
            baseline, current = [json.loads(path.read_text(encoding="utf-8")) for path in args.compare]
            table, failed = compare(baseline, current, args.throughput_tolerance_pct,
                                    args.latency_tolerance_pct, args.rss_tolerance_pct)
            print(table)
            return int(failed)
        binary = args.binary.resolve(strict=True)
        data_root = args.data_root.resolve(strict=True) if args.data_root else None
        if args.worker:
            print(json.dumps(run_mode(binary, args.worker, data_root, json.load(sys.stdin))))
            return 0
        if not args.commit or not re.fullmatch(r"[a-fA-F0-9]{40}", args.commit):
            parser.error("--binary requires --commit with the full 40-character source SHA")
        report = measure(binary, args.commit.lower(), data_root, settings(args))
        validate(report)
        output = json.dumps(report, indent=2, sort_keys=True, allow_nan=False) + "\n"
        if args.output:
            args.output.write_text(output, encoding="utf-8")
        else:
            print(output, end="")
        failures = rss_failures(report)
        for mode in failures:
            peak = report["modes"][mode]["peak_rss_kib"]
            limit = report["parameters"]["peak_rss_limits_kib"][mode]
            print(f"benchmark: {mode} peak RSS {peak} KiB exceeds {limit} KiB", file=sys.stderr)
        return int(bool(failures))
    except (OSError, subprocess.SubprocessError, http.client.HTTPException, ET.ParseError, ValueError) as error:
        print(f"benchmark: {error}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
