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

## Installation

```bash
pip install denet    # Python package
cargo install denet  # Rust binary
```

## Usage

### Understanding CPU Utilization

CPU usage is reported in a `top`-compatible format where 100% represents one fully utilized CPU core:

- 100% = one core fully utilized
- 400% = four cores fully utilized
- Child processes are tracked separately and aggregated for total resource usage
- Process trees are monitored by default, tracking all child processes spawned by the main process

This is consistent with standard tools like `top` and `htop`. For example, a process using 3 CPU cores at full capacity will show 300% CPU usage, regardless of how many cores your system has.

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
```

## Adaptive Sampling

Denet uses an intelligent adaptive sampling strategy to balance detail and efficiency:

1. **First second**: Samples at the base interval rate (fast sampling for short processes)
2. **1-10 seconds**: Gradually increases from base to max interval
3. **After 10 seconds**: Uses the maximum interval rate

This approach ensures high-resolution data for short-lived processes while reducing overhead for long-running ones.

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

## License

GPL-3

## Acknowledgements

- [sysinfo](https://github.com/GuillaumeGomez/sysinfo) - Rust library for system information
- [PyO3](https://github.com/PyO3/pyo3) - Rust bindings for Python
