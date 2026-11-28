# Azuifer performance regressions

The [benchmark runner](../scripts/benchmark.py) measures one native Azuifer binary on loopback. It requires Python 3.11 or later and no packages, SDKs, Azure account, or collector. Use it for release-over-release regression measurements, not Azure performance equivalence.

## Run and compare

Build the candidate with the pinned Rust toolchain, or extract a verified archive using the [release guide](releases.md). Run the same revision of the harness against both binaries. Replace `CANDIDATE_SHA` and `BASELINE_SHA` with the full source commits that built the binaries, not the commit that contains the harness. Use `azuifer.exe` for native Windows builds.

```sh
cargo build --locked --release
python scripts/benchmark.py --binary target/release/azuifer --commit CANDIDATE_SHA --output current.json
python scripts/benchmark.py --binary /path/to/previous/azuifer --commit BASELINE_SHA --output baseline.json
python scripts/benchmark.py --compare baseline.json current.json
```

The script also runs with `uv run --script scripts/benchmark.py`. Without `--output`, a benchmark writes JSON to stdout. The comparison prints a Markdown table with baseline, current, and percentage change for each operation and the process peaks. Defaults allow throughput to fall at most 10%, and latency or RSS to increase at most 15%. Change these with `--throughput-tolerance-pct`, `--latency-tolerance-pct`, and `--rss-tolerance-pct`. A breach returns exit 1; an invalid, failed, or incomparable run returns exit 2. A run that exceeds an absolute RSS limit still writes its report but exits 1.

Keep the baseline and candidate on the same host and architecture, with the same OS, Python, build profile, CPU power settings, and filesystem. Use `--data-root` to place temporary state on the same volume for both runs; a system temp directory backed by RAM is not a disk benchmark. Use a quiet host, repeat runs, and investigate jitter before enforcing tight tolerances. The comparator refuses different recorded host metadata or settings; it cannot detect differences in local load, storage hardware, or power policy.

## Workloads and timing

Each mode starts a fresh process with a synthetic local account key, fixed API version `2023-11-03`, two Tokio workers, opt-in telemetry disabled, and ephemeral ports. The client issues one request at a time using persistent HTTP connections and a synthetic account SAS. Disk mode creates disposable SQLite and content state; in-memory mode uses `--in-memory`. Setup, cleanup, and extra correctness checks do not count as samples. Each round overwrites or cleans up its data so listings and queries do not grow with iteration count.

| Surface | Timed requests |
| --- | --- |
| Blob | 1 KiB block Blob PUT, GET and list; separate streaming PUT and GET |
| DFS | Create a file, append and flush 4 KiB, rename the enclosing directory |
| FileREST | Create a file, PUT and GET a 64 KiB range, list files |
| Queue | Enqueue, dequeue and delete using the returned receipt |
| Table | Insert, query a partition and commit a two-entity changeset in that partition |

Time is measured with `perf_counter_ns()` from sending the request until the body has been consumed. The Blob stream uses 64 KiB client chunks without buffering the payload, and the timed GET hashes the received bytes. `ops_per_second` is sample count divided by the summed request durations, not total workflow throughput or load at saturation. `mib_per_second` uses the transferred payload size and those same durations for streaming PUT and GET; it is `null` for other operations. Latencies are nearest-rank p50, p95 and p99 in milliseconds. A small sample set makes tail percentiles discrete: with ten samples the p95 and p99 are both the maximum.

The defaults are five warmups per workload, 100 measured passes for small requests, and ten measured 32 MiB streaming PUT/GET pairs. Set `--warmup`, `--iterations`, `--stream-iterations`, or `--stream-mib` to change them. `--quick` defaults to one warmup, two measured small-workload passes, and one measured 2 MiB streaming pair. CI runs `--quick` against the real binary on Linux, macOS, and Windows to check behavior and unit conversions, not to compare performance across shared runners.

## Peak memory and the JSON report

`peak_rss_kib` is the kernel high-water mark for the emulator process in each mode, not a sampled approximation or a per-operation allocation estimate. It includes startup, warmup and the large transfer. Linux and macOS use the reaped child's `ru_maxrss` (converted from bytes on macOS), including shutdown. Windows reads `PeakWorkingSetSize` after the workloads, before closing stdin. These counters do not measure total OS page cache or Python memory. Reported values are comparable only on the same platform.

The persistent peak limit defaults to 128 MiB. In-memory peak defaults to 128 MiB plus four times the streaming payload: that mode intentionally retains payload bytes. Override the bounds with `--max-persistent-rss-mib` and `--max-in-memory-rss-mib`. The storage quota is separate and is the larger of 64 MiB or three times the payload. For a stronger persistent-streaming check, run e.g. `--stream-mib 128 --stream-iterations 1 --warmup 1` with the same persistent cap. An absolute cap detects excessive memory for the chosen workload; it does not prove memory scales independently of size.

Report schema version `1` includes `commit_sha`, `azuifer_version`, `binary_sha256`, the `platform` and `parameters` used, and `modes.persistent` and `modes.in_memory`. Each mode holds `peak_rss_kib` and keyed `operations` with `samples`, throughput, and `latency_ms`. Commit and binary hash identify the inputs, but they do not prove that the declared source built the binary. Preserve both reports with the same runner version when comparing releases; changes to workload or metric semantics require a new report version or a new baseline.
