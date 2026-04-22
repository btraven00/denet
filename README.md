# denet: a streaming process monitor

**denet** /de.net/ _v._ 1. _Turkish_: to monitor, to supervise, to audit. 2. to track metrics of a running process.

Denet is a streaming process monitoring tool that provides detailed metrics on running processes, including CPU, memory, I/O, and thread usage. Built with Rust, with Python bindings.

[![PyPI version](https://badge.fury.io/py/denet.svg)](https://badge.fury.io/py/denet)
[![Crates.io](https://img.shields.io/crates/v/denet.svg)](https://crates.io/crates/denet)
[![codecov](https://codecov.io/gh/btraven00/denet/branch/main/graph/badge.svg)](https://codecov.io/gh/btraven00/denet)
[![Ruff](https://img.shields.io/badge/code%20style-ruff-black)](https://github.com/astral-sh/ruff)
[![License: GPL v3](https://img.shields.io/badge/License-GPLv3-blue.svg)](https://www.gnu.org/licenses/gpl-3.0)

## Features

- Lightweight, cross-platform process monitoring
- Adaptive sampling intervals that automatically adjust based on runtime
- Memory usage tracking (RSS, VMS)
- CPU usage monitoring with accurate multi-core support
- I/O bytes read/written tracking
- Thread count monitoring
- **GPU monitoring with NVIDIA NVML support (optional)** — see [docs/gpu.md](docs/gpu.md)
- **eBPF-based profiling on Linux: off-CPU time and syscall tracking (optional)**
- Recursive child process tracking
- Command-line interface with colorized output
- In-memory sample collection for Python API — see [docs/python-api.md](docs/python-api.md)
- Analysis utilities for metrics aggregation, peak detection, and resource utilization
- Process metadata preserved in output files (pid, command, executable path)

## Installation

```bash
pip install denet    # Python package (GPU support included)
cargo install denet  # Rust binary

# For GPU monitoring support in the Rust binary (requires NVIDIA drivers)
cargo install denet --features gpu

# For eBPF profiling support (Linux only, requires clang)
cargo install denet --features ebpf
```

See [docs/gpu.md](docs/gpu.md) for GPU monitoring details and [docs/dev.md](docs/dev.md) for development setup requirements.

## Usage

### Understanding CPU Utilization

CPU usage is reported in a `top`-compatible format where 100% represents one fully utilized CPU core:

- 100% = one core fully utilized
- 400% = four cores fully utilized
- Child processes are tracked separately and aggregated for total resource usage
- Process trees are monitored by default, tracking all child processes spawned by the main process

This is consistent with standard tools like `top` and `htop`. For example, a process using 3 CPU cores at full capacity will show 300% CPU usage, regardless of how many cores your system has.

### Understanding Network Metrics (`sys_net_rx_bytes` / `sys_net_tx_bytes`)

Network I/O is reported as **namespace-wide** totals, not per-process. The values come from `/proc/<pid>/net/dev` when it exists, falling back to `/proc/net/dev`. This means:

- **Containers (Docker, Podman, etc.)**: each container gets its own network namespace, so `sys_net_rx_bytes`/`sys_net_tx_bytes` reflect only traffic on that container's interfaces. Values are accurate for the monitored workload.
- **Conda environments / venvs / bare processes**: these share the host network namespace. The numbers reflect all traffic on the host's interfaces, not just the monitored process. The `sys_net_` prefix signals this: it is a system-level counter scoped to the network namespace, not a process-level counter.

If you need per-process socket-level attribution, eBPF (enabled with `--features ebpf --enable-ebpf`) tracks individual syscalls and can give more precise network activity signals via the syscall intensity metrics.

### Understanding Disk I/O Metrics

denet reports three signals for disk activity on Linux: block-layer bytes (`disk_read_bytes`/`disk_write_bytes`), syscall bytes (`syscall_read_bytes`/`syscall_write_bytes`), and page-fault counts (`page_faults_cached`/`page_faults_disk`). They answer different questions — most importantly, `disk_read_bytes` shows `0` for cached reads and `mmap` access, which surprises users. See [docs/disk-io.md](docs/disk-io.md) for how to interpret and combine them.

### Command-Line Interface

```bash
# Basic monitoring with colored output
denet run sleep 5

# Output as JSON (actually JSONL format with metadata on first line)
denet --json run sleep 5 > metrics.json

# Write output to a file
denet --out metrics.log run sleep 5

# Custom sampling interval (in milliseconds)
denet --interval 500 run sleep 5

# Specify max sampling interval for adaptive mode
denet --max-interval 2000 run sleep 5

# Monitor existing process by PID
denet attach 1234

# Monitor just for 10 seconds
denet --duration 10 attach 1234

# Quiet mode (suppress process output)
denet --quiet --json --out metrics.jsonl run python script.py

# Monitor a CPU-intensive workload (shows aggregated metrics for all children)
denet run python cpu_intensive_script.py

# Monitor a GPU workload (Python wheel includes GPU support; Rust binary requires --features gpu)
denet run python gpu_training_script.py

# Enable eBPF profiling — off-CPU time and syscall tracking (Linux only, requires root or CAP_BPF)
sudo denet --enable-ebpf run python io_bound_script.py

# Disable child process monitoring (only track the parent process)
denet --no-include-children run python multi_process_script.py
```

### Python API

See [docs/python-api.md](docs/python-api.md) for the full Python API reference, including `ProcessMonitor`, `execute_with_monitoring`, and analysis utilities.

## Adaptive Sampling

Denet adjusts its sampling interval based on how long the process has been running:

| Elapsed time | Interval |
|---|---|
| < 1 s | base interval (default **100 ms**) |
| 1 – 10 s | linearly interpolated between base and max |
| > 10 s | max interval (default **1000 ms**) |

This keeps resolution high for short processes and cuts overhead for long-running ones without any manual tuning.

Override the defaults with `-i` / `--interval` (base, in ms) and `-m` / `--max-interval` (max, in ms):

```bash
# Sample every 50 ms for the first second, ramp to 500 ms after 10 s
denet -i 50 -m 500 run python train.py
```

## GPU Monitoring

Denet supports NVIDIA GPU monitoring via NVML when built with the `gpu` feature. See [docs/gpu.md](docs/gpu.md) for features, requirements, usage examples, and the GPU data structure.

## eBPF Profiling

Denet provides optional eBPF-based profiling on Linux for deeper insight into
what processes are doing when they're not running on a CPU.

### Features

- **Off-CPU profiling**: Captures every `sched_switch` event to measure how long
  threads are blocked — waiting for I/O, locks, or sleep. Useful for diagnosing
  latency in I/O-bound workloads.
- **Syscall tracking**: Counts syscall frequency by category (file I/O, memory,
  network, …) and classifies process behaviour (I/O-bound, CPU-bound, etc.).

### Requirements

- Linux kernel 5.5+
- `clang` available at build time
- `CAP_BPF` + `CAP_PERFMON` + `CAP_DAC_READ_SEARCH` capabilities, or root at runtime

### Build

```bash
cargo build --features ebpf
```

### Usage

```bash
# Monitor an I/O-bound workload
sudo denet --enable-ebpf run python io_bound_script.py

# With JSON output
sudo denet --enable-ebpf --json run sleep 5

# Set capabilities on the binary to avoid running as root every time:
#   cap_bpf             – load BPF programs and create maps
#   cap_perfmon         – perf_event_open for tracepoints
#   cap_dac_read_search – read /sys/kernel/tracing/events/*/id (root-owned 0400)
sudo ./scripts/setup_ebpf_caps.sh ./target/release/denet
denet --enable-ebpf run sleep 5
```

### Sample JSON output

```json
{
  "ts_ms": 1714000000000,
  "cpu_usage": 12.5,
  "mem_rss_kb": 8192,
  "ebpf": {
    "offcpu": {
      "total_time_ns": 1500000000,
      "total_events": 30,
      "avg_time_ns": 50000000,
      "max_time_ns": 500000000,
      "top_blocking_threads": [
        { "pid": 1234, "tid": 1234, "time_ms": 500.0, "percentage": 33.33 }
      ]
    },
    "syscalls": {
      "total": 1500,
      "by_category": { "file_io": 900, "memory": 300, "time": 200, "other": 100 },
      "top_syscalls": [
        { "name": "read", "count": 450 },
        { "name": "write", "count": 350 }
      ]
    }
  }
}
```

## Development

For detailed developer documentation — including development requirements, project structure, workflow, testing, and release process — see [docs/dev.md](docs/dev.md).

## License

GPL-3

## Acknowledgements

- [sysinfo](https://github.com/GuillaumeGomez/sysinfo) - Rust library for system information
- [PyO3](https://github.com/PyO3/pyo3) - Rust bindings for Python
