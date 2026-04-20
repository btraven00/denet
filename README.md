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
- **GPU monitoring with NVIDIA NVML support (optional)**
- **eBPF-based profiling on Linux: off-CPU time and syscall tracking (optional)**
- Recursive child process tracking
- Command-line interface with colorized output
- Multiple output formats (JSON, JSONL, CSV)
- In-memory sample collection for Python API
- Analysis utilities for metrics aggregation, peak detection, and resource utilization
- Process metadata preserved in output files (pid, command, executable path)

## Requirements

- Python 3.6+ (Python 3.12 recommended for best performance)
- Rust (for development)
- [pixi](https://prefix.dev/docs/pixi/overview) (for development only)
- **eBPF features**: Linux kernel 5.5+, `clang` at build time, `CAP_BPF` + `CAP_PERFMON` or root at runtime

## Installation

```bash
pip install denet    # Python package
cargo install denet  # Rust binary

# For GPU monitoring support (requires NVIDIA drivers and CUDA)
pip install denet[gpu]  # Python package with GPU support
cargo install denet --features gpu  # Rust binary with GPU support

# For eBPF profiling support (Linux only, requires clang)
cargo install denet --features ebpf
```

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

# Monitor a GPU workload (requires --features gpu or denet[gpu])
denet run python gpu_training_script.py

# Enable eBPF profiling — off-CPU time and syscall tracking (Linux only, requires root or CAP_BPF)
sudo denet --enable-ebpf run python io_bound_script.py

# Disable child process monitoring (only track the parent process)
denet --no-include-children run python multi_process_script.py
```

### Python API

#### Basic Usage

```python
import json
import denet

# Create a monitor for a process
monitor = denet.ProcessMonitor(
    cmd=["python", "-c", "import time; time.sleep(10)"],
    base_interval_ms=100,    # Start sampling every 100ms
    max_interval_ms=1000,    # Sample at most every 1000ms
    store_in_memory=True,    # Keep samples in memory
    output_file=None,        # Optional file output
    include_children=True    # Monitor child processes (default True)
)

# Let the monitor run automatically until the process completes
# Samples are collected at the specified sampling rate in the background
monitor.run()

# Access all collected samples after process completion
samples = monitor.get_samples()
print(f"Collected {len(samples)} samples")

# Get summary statistics
summary_json = monitor.get_summary()
summary = json.loads(summary_json)
print(f"Average CPU usage: {summary['avg_cpu_usage']}%")
print(f"Peak memory: {summary['peak_mem_rss_kb']/1024:.2f} MB")
print(f"Total time: {summary['total_time_secs']:.2f} seconds")
print(f"Sample count: {summary['sample_count']}")
print(f"Max processes: {summary['max_processes']}")

# Save samples to different formats
monitor.save_samples("metrics.jsonl")          # Default JSONL
monitor.save_samples("metrics.json", "json")   # JSON array format
monitor.save_samples("metrics.csv", "csv")     # CSV format

# JSONL files include a metadata line at the beginning with process info
# {"pid": 1234, "cmd": ["python"], "executable": "/usr/bin/python", "t0_ms": 1625184000000}

# GPU monitoring example (when GPU support is available)
if monitor.is_gpu_enabled():
    print(f"GPU devices: {monitor.gpu_device_count()}")
    gpu_summary = json.loads(monitor.get_gpu_summary())
    print(f"GPU memory: {gpu_summary['total_memory_gb']:.2f} GB")
```

```python
# For more controlled execution with monitoring, use execute_with_monitoring:
import denet
import json
import subprocess

# Execute a command with monitoring and capture the result
exit_code, monitor = denet.execute_with_monitoring(
    cmd=["python", "script.py"],
    base_interval_ms=100,
    max_interval_ms=1000,
    store_in_memory=True,    # Store samples in memory
    output_file=None,        # Optional file output
    write_metadata=False,    # Write metadata as first line to output file (default False)
    include_children=True    # Monitor child processes (default True)
)

# Access collected metrics after execution
samples = monitor.get_samples()
print(f"Collected {len(samples)} samples")
print(f"Exit code: {exit_code}")

# Generate and print summary
summary_json = monitor.get_summary()
summary = json.loads(summary_json)
print(f"Average CPU usage: {summary['avg_cpu_usage']}%")
print(f"Peak memory: {summary['peak_mem_rss_kb']/1024:.2f} MB")

# Save samples to a file (includes metadata line in JSONL format)
monitor.save_samples("metrics.jsonl", "jsonl")  # First line contains process metadata

# GPU monitoring in controlled execution
if monitor.is_gpu_enabled():
    print("GPU monitoring enabled")
    # GPU metrics are automatically included in samples when available
```

## Adaptive Sampling

Denet uses an intelligent adaptive sampling strategy to balance detail and efficiency:

1. **First second**: Samples at the base interval rate (fast sampling for short processes)
2. **1-10 seconds**: Gradually increases from base to max interval
3. **After 10 seconds**: Uses the maximum interval rate

This approach ensures high-resolution data for short-lived processes while reducing overhead for long-running ones.

## GPU Monitoring

Denet provides comprehensive GPU monitoring for NVIDIA GPUs using the NVIDIA Management Library (NVML):

### Features

- **GPU Utilization**: Real-time GPU compute utilization percentage
- **Memory Monitoring**: GPU memory usage, both total and per-process when available
- **Temperature Tracking**: GPU temperature monitoring
- **Power Consumption**: GPU power usage in watts
- **Multi-GPU Support**: Monitor all NVIDIA GPUs in the system
- **Process-Specific**: Track GPU memory usage per monitored process
- **Graceful Fallback**: Continues working without GPU support if NVML is unavailable

### Requirements

- NVIDIA GPU with driver support
- NVIDIA CUDA toolkit or driver with NVML support
- Rust compilation with `--features gpu` or Python installation with `pip install denet[gpu]`

### Usage Examples

```python
import denet
import json

# Create monitor with GPU support
monitor = denet.ProcessMonitor(
    cmd=["python", "gpu_workload.py"],
    base_interval_ms=100,
    max_interval_ms=1000,
    store_in_memory=True
)

# Check GPU availability
if monitor.is_gpu_enabled():
    print(f"Found {monitor.gpu_device_count()} GPU(s)")
    
    # Get GPU summary
    gpu_summary = json.loads(monitor.get_gpu_summary())
    print(f"Total GPU memory: {gpu_summary['total_memory_gb']:.2f} GB")
    
    # Run monitoring
    monitor.run()
    
    # Analyze GPU usage in samples
    samples = monitor.get_samples()
    for sample_str in samples:
        sample = json.loads(sample_str)
        if sample.get("gpu"):
            gpu_data = sample["gpu"]
            max_util = gpu_data.get("max_gpu_utilization", 0)
            if max_util > 0:
                print(f"GPU utilization: {max_util}%")
                break
else:
    print("GPU monitoring not available")
```

### Command Line GPU Output

When GPU monitoring is enabled, the command line interface automatically includes GPU information:

```bash
# Example output with GPU monitoring
denet run python train_model.py
CPU: 45.2% | Memory: 2.1 GB | Threads: 8 | GPU: 85%, 3.2GB | Disk: 1.2MB rd, 856KB wr
```

### GPU Data Structure

GPU metrics are included in the JSON output:

```json
{
  "ts_ms": 1625184000000,
  "cpu_usage": 45.2,
  "mem_rss_kb": 2147483,
  "gpu": {
    "devices": [
      {
        "device_index": 0,
        "name": "NVIDIA GeForce RTX 4090",
        "utilization_gpu": 85,
        "utilization_memory": 78,
        "memory_total": 25757220864,
        "memory_used": 3221225472,
        "temperature": 65,
        "power_usage": 320,
        "process_memory_usage": 1073741824
      }
    ],
    "total_memory_used": 3221225472,
    "total_memory_available": 25757220864,
    "max_gpu_utilization": 85,
    "max_memory_utilization": 78
  }
}
```

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
- `CAP_BPF` + `CAP_PERFMON` capabilities, or root at runtime

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

# Set capabilities on the binary to avoid running as root every time
sudo setcap cap_bpf,cap_perfmon=ep ./target/debug/denet
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

### Notes on stack traces

Stack symbolication uses `/proc/{pid}/maps` and `addr2line`. For best results:

- Build monitored programs with debug symbols (`-g`)
- JIT-compiled languages (Python, Java, Node.js) produce limited stack information
- See `docs/offcpu.md` for troubleshooting and architecture details

## Analysis Utilities

The Python API includes utilities for analyzing metrics:

```python
import denet
import json

# Load metrics from a file (automatically skips metadata line)
metrics = denet.load_metrics("metrics.jsonl")

# If you want to include the metadata in the results
metrics_with_metadata = denet.load_metrics("metrics.jsonl", include_metadata=True)

# Access the executable path from metadata
executable_path = metrics_with_metadata[0]["executable"]  # First item is metadata when include_metadata=True

# Direct command execution with monitoring
exit_code, monitor = denet.execute_with_monitoring(["python", "script.py"])

# Execute with metadata written to output file
exit_code, monitor = denet.execute_with_monitoring(
    cmd=["python", "script.py"],
    output_file="metrics.jsonl",
    write_metadata=True  # Includes metadata as first line: {"pid": 1234, "cmd": ["python", "script.py"], "executable": "/usr/bin/python", "t0_ms": 1625184000000}
)

# execute_with_monitoring also accepts subprocess.run arguments:
exit_code, monitor = denet.execute_with_monitoring(
    cmd=["python", "script.py"],
    base_interval_ms=100,
    store_in_memory=True,
    # Any subprocess.run arguments can be passed through:
    timeout=30,              # Process timeout in seconds
    stdout=subprocess.PIPE,  # Capture stdout
    stderr=subprocess.PIPE,  # Capture stderr
    cwd="/path/to/workdir",  # Working directory
    env={"PATH": "/usr/bin"} # Environment variables
)

# Aggregate metrics to reduce data size
aggregated = denet.aggregate_metrics(metrics, window_size=5, method="mean")

# Find peaks in resource usage
cpu_peaks = denet.find_peaks(metrics, field='cpu_usage', threshold=50)
print(f"Found {len(cpu_peaks)} CPU usage peaks above 50%")

# Get comprehensive resource utilization statistics
stats = denet.resource_utilization(metrics)
print(f"Average CPU: {stats['avg_cpu']}%")
print(f"Total I/O: {stats['total_io_bytes']} bytes")

# Convert between formats
csv_data = denet.convert_format(metrics, to_format="csv")
with open("metrics.csv", "w") as f:
    f.write(csv_data)

# Save metrics with custom options
denet.save_metrics(metrics, "data.jsonl", format="jsonl", include_metadata=True)

# Analyze process tree patterns
tree_analysis = denet.process_tree_analysis(metrics)

# Example: Analyze CPU usage from multi-process workload
# See scripts/analyze_cpu.py for detailed CPU analysis example
```

## Development

For detailed developer documentation, including project structure, development workflow, testing, and release process, see [Developer Documentation](docs/dev.md).

## GPU Support Notes

- GPU monitoring requires NVIDIA GPUs and drivers
- NVML (NVIDIA Management Library) must be available on the system
- If GPU support is compiled in but no GPUs are detected, denet continues working normally
- GPU metrics are automatically included when available, no configuration needed
- Process-specific GPU memory tracking may not be available on all driver versions

## License

GPL-3

## Acknowledgements

- [sysinfo](https://github.com/GuillaumeGomez/sysinfo) - Rust library for system information
- [PyO3](https://github.com/PyO3/pyo3) - Rust bindings for Python
