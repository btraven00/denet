# Denet JSON Data Format

Denet outputs JSON in a streaming format optimized for efficiency and time-series analysis.

## Format Structure

Every line carries a `"kind"` discriminator so downstream tooling can dispatch by type. The possible values are `env`, `metadata`, `sample`, and `tree`.

**Optional first line** (when `--write-env` is set): host/NUMA/affinity snapshot, emitted once.
```json
{"kind":"env","ts_ms":1748542000000,"host":"omnibenchmark","kernel":"6.18.7-...","lscpu":{...},"numa":{...},"affinity_inherited":"0-127", ...}
```

**Header line**: Process metadata, emitted once.
```json
{"kind":"metadata","pid":1234,"cmd":["sleep","5"],"executable":"/usr/bin/sleep","t0_ms":1748542000000}
```

**Subsequent lines**: Process tree metrics, streamed continuously.
```json
{"kind":"tree","ts_ms":1748542001000,"parent":{...},"children":[...],"aggregated":{...}}
```

Single-process mode (`--exclude-children`) emits `{"kind":"sample",...}` records instead.

> **Back-compat:** files written before the `kind` field existed are still readable by the `stats` / `summary` subcommands and by the Python reader — parsers fall back to the legacy untagged shapes when no `kind` is present.

## Env Record (reproducibility snapshot)

Enabled with `--write-env` on the CLI or `write_env=True` in the Python binding. Captured once at the start of monitoring; useful for benchmark reproducibility (NUMA placement, CPU governor, hyperthreading, cgroup limits).

| Field | Type | Description |
|-------|------|-------------|
| `ts_ms` | number | Capture timestamp (Unix milliseconds) |
| `host` | string | Hostname (`/proc/sys/kernel/hostname`) |
| `kernel` | string | Kernel release (`/proc/sys/kernel/osrelease`) |
| `lscpu.sockets` | number | Physical sockets |
| `lscpu.cores_per_socket` | number | Cores per socket |
| `lscpu.threads_per_core` | number | Threads per core (SMT siblings) |
| `lscpu.model` | string | First `model name` from `/proc/cpuinfo` |
| `numa.nodes` | number | NUMA node count |
| `numa.distances` | number[][] | Square distance matrix from `/sys/.../node*/distance` |
| `numa.node_sizes_mb` | number[] | `MemTotal` per node, in MB |
| `affinity_inherited` | string | CPU affinity of the monitor process as a range list (e.g. `"0-3,7-9"`) |
| `cpu_governor` | string[]? | `scaling_governor` per CPU (omitted if cpufreq is unavailable) |
| `cpu_freq_khz` | number[]? | `scaling_cur_freq` per CPU |
| `thp_enabled` | string? | `/sys/kernel/mm/transparent_hugepage/enabled` raw value |
| `smt_active` | bool? | `/sys/devices/system/cpu/smt/active` |
| `cgroup` | string? | `/proc/<pid>/cgroup` of the monitored process |

Optional fields degrade to `null`/absent on kernels, distros, or containers where the source file is missing. On non-Linux platforms only `ts_ms`/`host`/`kernel` are populated.

## Metadata Fields

| Field | Type | Description |
|-------|------|-------------|
| `pid` | number | Process ID |
| `cmd` | string[] | Command line arguments |
| `executable` | string | Executable path |
| `t0_ms` | number | Process start time (Unix milliseconds) |
| `capabilities` | object? | Manifest of optional metric sources detected at startup. See below. |

### Capabilities (optional)

Tells consumers which optional per-sample fields to expect. Each entry is `{available, reason?}` plus source-specific metadata.

| Source | Per-sample field | Notes |
|---|---|---|
| `psi` | `psi_mem` | `/proc/pressure/memory` (system or per-process). Always Linux-only. |
| `perf_hw` | `perf` | `perf_event_open` hardware counters. Requires `perf_event_paranoid <= 2` or `CAP_PERFMON`. The `events` array lists which counters opened — `cycles` and `instructions` are required, the rest degrade gracefully if the CPU doesn't expose them. |

## Metrics Fields

### Tree Structure
| Field | Type | Description |
|-------|------|-------------|
| `ts_ms` | number | Sample timestamp (Unix milliseconds) |
| `parent` | Metrics? | Parent process metrics (null if terminated) |
| `children` | ChildMetrics[] | Child process metrics |
| `aggregated` | AggregatedMetrics? | Combined parent + children metrics |

### Individual Process Metrics
| Field | Type | Description |
|-------|------|-------------|
| `ts_ms` | number | Sample timestamp |
| `cpu_usage` | number | CPU usage percentage |
| `mem_rss_kb` | number | Resident memory (KB) |
| `mem_vms_kb` | number | Virtual memory (KB) |
| `disk_read_bytes` | number | Disk bytes read |
| `disk_write_bytes` | number | Disk bytes written |
| `net_rx_bytes` | number | Network bytes received |
| `net_tx_bytes` | number | Network bytes transmitted |
| `thread_count` | number | Number of threads |
| `uptime_secs` | number | Process uptime (seconds) |

### Child Process Metrics
| Field | Type | Description |
|-------|------|-------------|
| `pid` | number | Child process ID |
| `command` | string | Child process name |
| `metrics` | Metrics | Child process metrics |

### Optional Memory-Characterization Fields

Both Individual and Aggregated metrics may include these when the corresponding source resolved at startup (see `capabilities` in the header):

| Field | Type | Description |
|-------|------|-------------|
| `psi_mem` | object? | `{some_avg10, full_avg10}` — fraction of the last 10s window in which at least one task / every task stalled on memory. |
| `perf` | object? | `{cycles, instructions, cache_refs, cache_misses, stalled_backend}` — counter **deltas since the previous sample**. IPC = `instructions/cycles`. LLC miss rate = `cache_misses/cache_refs`. |

### Aggregated Metrics
Includes all fields from Individual Process Metrics plus:
| Field | Type | Description |
|-------|------|-------------|
| `process_count` | number | Total processes (parent + children) |

## I/O Accounting

- **Default**: Shows delta I/O since monitoring started
- **`--since-process-start`**: Shows cumulative I/O since process start
- **Network I/O**: System-wide approximation (not per-process)

## Output Options

- **Default**: Update metrics in-place in the terminal and write JSON to `out.json`
- **`--json`**: Output JSON format to stdout
- **`--no-update`**: Print new lines instead of updating in-place
- **`--quiet`**: Suppress stdout output (except when used with `--json`)
- **`--nodump`**: Disable automatic JSON dump to `out.json`
- **`--out FILE`**: Write JSON output to specified file
- **`--stats FILE`**: Write summary statistics to specified file
- **`--write-env`**: Prepend a one-shot `env` record (host/NUMA/affinity/governor/THP/SMT/cgroup) for reproducibility

## Example Complete Record

The output is [JSON Lines](https://jsonlines.org/) — one JSON object per line, newline-delimited. Each line is a self-contained record and can be parsed independently (e.g. with `jq`).

Lines are tagged with `"kind"`. When `--write-env` is set, an `env` header precedes the `metadata` header; otherwise the file starts at `metadata`. All subsequent lines are `sample` (single-process) or `tree` (process tree, default).

Timestamps use Unix milliseconds (ms since 1970-01-01 00:00:00 UTC):
- `t0_ms`: process start time, in the `metadata` line only
- `ts_ms`: capture/sample timestamp in every other line

To get the elapsed time of a sample relative to process start: `elapsed_ms = ts_ms - t0_ms`.

```json
{"kind":"env","ts_ms":1748542000000,"host":"omnibenchmark","kernel":"6.18.7-76061807-generic","lscpu":{"sockets":1,"cores_per_socket":64,"threads_per_core":2,"model":"AMD EPYC 7742 64-Core Processor"},"numa":{"nodes":4,"distances":[[10,12,12,12],[12,10,12,12],[12,12,10,12],[12,12,12,10]],"node_sizes_mb":[64272,64500,64500,64481]},"affinity_inherited":"0-127","cpu_governor":["performance"],"thp_enabled":"always [madvise] never","smt_active":true,"cgroup":"0::/user.slice"}
{"kind":"metadata","pid":1234,"cmd":["python","script.py"],"executable":"/usr/bin/python3","t0_ms":1748542000000}
{"kind":"tree","ts_ms":1748542001000,"parent":{"ts_ms":1748542001050,"cpu_usage":15.2,"mem_rss_kb":8192,"mem_vms_kb":32768,"disk_read_bytes":1024,"disk_write_bytes":2048,"sys_net_rx_bytes":512,"sys_net_tx_bytes":256,"thread_count":3,"uptime_secs":1},"children":[{"pid":1235,"command":"worker","metrics":{"ts_ms":1748542001060,"cpu_usage":5.1,"mem_rss_kb":4096,"mem_vms_kb":16384,"disk_read_bytes":512,"disk_write_bytes":0,"sys_net_rx_bytes":0,"sys_net_tx_bytes":0,"thread_count":1,"uptime_secs":1}}],"aggregated":{"ts_ms":1748542001000,"cpu_usage":20.3,"mem_rss_kb":12288,"mem_vms_kb":49152,"disk_read_bytes":1536,"disk_write_bytes":2048,"sys_net_rx_bytes":512,"sys_net_tx_bytes":256,"thread_count":4,"process_count":2,"uptime_secs":1}}
```

## Statistics Output

When a monitoring session completes, statistics are calculated and can be shown or saved:

```json
{
  "total_time_secs": 10.5,
  "sample_count": 42,
  "max_processes": 3,
  "max_threads": 8,
  "total_disk_read_bytes": 1536,
  "total_disk_write_bytes": 2048, 
  "total_net_rx_bytes": 512,
  "total_net_tx_bytes": 256,
  "peak_mem_rss_kb": 12288,
  "avg_cpu_usage": 18.7,
  "memory_characterization": {
    "mean_ipc": 4.73,
    "llc_miss_rate": 0.128,
    "backend_stall_ratio": 0.61,
    "psi_some_fraction": 0.0,
    "verdict": "memory-bound"
  }
}
```

`memory_characterization` is also exposed via `denet::MemoryCharacterization::from_metrics(&[Metrics])` and `from_aggregated(&[AggregatedMetrics])`, so downstream code can compute the same roll-up over arbitrary windows (e.g. per pipeline stage), not just end-of-run. The `verdict` is a coarse classification: `memory-bound`, `cpu-bound`, `mixed`, or `insufficient-data`.

The `stats` command can be used to generate these statistics from a saved JSON file.
