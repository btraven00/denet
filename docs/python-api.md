# Python API

## Basic Usage

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
    write_env=False,         # Prepend a host/NUMA/affinity `env` record (default False)
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

# Capture host/NUMA/affinity reproducibility info as the very first line.
# Useful when comparing benchmark runs across machines or affinity settings.
exit_code, monitor = denet.execute_with_monitoring(
    cmd=["python", "bench.py"],
    output_file="metrics.jsonl",
    write_env=True,
    write_metadata=True,
)
# Or grab it as a string on demand:
env_line = monitor.get_env()  # tagged JSON: {"kind":"env","host":...,"numa":{...},"affinity_inherited":"0-127",...}

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

# Save metrics with custom options
denet.save_metrics(metrics, "data.jsonl", format="jsonl", include_metadata=True)

# Analyze process tree patterns
tree_analysis = denet.process_tree_analysis(metrics)

# Example: Analyze CPU usage from multi-process workload
# See scripts/analyze_cpu.py for detailed CPU analysis example
```
