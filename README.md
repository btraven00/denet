# denet: a streaming process monitor

Denet is a streaming process monitoring tool that provides detailed metrics on running processes, including CPU, memory, I/O, and thread usage. Built with a Rust core and Python bindings, it follows a Rust-first development approach while providing convenient Python access.

[![PyPI version](https://badge.fury.io/py/denet.svg)](https://badge.fury.io/py/denet)
[![License: GPL v3](https://img.shields.io/badge/License-GPLv3-blue.svg)](https://www.gnu.org/licenses/gpl-3.0)

## Features

- Lightweight, cross-platform process monitoring
- Adaptive sampling intervals that automatically adjust based on runtime
- Memory usage tracking (RSS, VMS)
- CPU usage monitoring
- I/O bytes read/written tracking
- Thread count monitoring
- Recursive child process tracking
- Command-line interface with colorized output
- Multiple output formats (JSON, JSONL, CSV)
- In-memory sample collection for Python API
- Python decorator and context manager for easy profiling
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

### Command-Line Interface

```bash
# Basic monitoring with colored output
denet run sleep 5

# Output as JSON
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
    output_file=None         # Optional file output
)

# Option 1: Run the monitor until the process completes
monitor.run()

# Option 2: Sample on demand and collect metrics
while monitor.is_running():
    # Sample once and get metrics as JSON string
    metrics_json = monitor.sample_once()
    if metrics_json:
        metrics = json.loads(metrics_json)
        print(f"CPU: {metrics['cpu_usage']}%, Memory: {metrics['mem_rss_kb']/1024:.2f} MB")

# Access all collected samples
samples = monitor.get_samples()
print(f"Collected {len(samples)} samples")

# Get summary statistics
summary_json = monitor.get_summary()
summary = json.loads(summary_json)
print(f"Average CPU usage: {summary['avg_cpu_usage']}%")
print(f"Peak memory: {summary['peak_mem_rss_kb']/1024:.2f} MB")
print(f"Total time: {summary['total_time_secs']:.2f} seconds")
print(f"Process runtime: {metrics[-1]['uptime_secs']} seconds")
print(f"Sample count: {summary['sample_count']}")

# Save samples to different formats
monitor.save_samples("metrics.jsonl")          # Default JSONL
monitor.save_samples("metrics.json", "json")   # JSON array format
monitor.save_samples("metrics.csv", "csv")     # CSV format

# JSONL files include a metadata line at the beginning with process info
# {"pid": 1234, "cmd": ["python"], "executable": "/usr/bin/python", "t0_ms": 1625184000000}
```

#### Function Decorator

```python
import denet

# Profile a function with the decorator
@denet.profile(
    base_interval_ms=100,
    max_interval_ms=1000,
    output_file="profile_results.jsonl",
    store_in_memory=True     # Store samples in memory (default)
)
def expensive_calculation():
    # Long-running calculation
    result = 0
    for i in range(10_000_000):
        result += i
    return result

# Call the function and get both result and metrics
result, metrics = expensive_calculation()
print(f"Result: {result}, Collected {len(metrics)} samples")

# The decorator can also be used without parameters
@denet.profile
def simple_function():
    return sum(range(1000000))
    
result, metrics = simple_function()
```

#### Context Manager

```python
import denet
import json

# Monitor a block of code
with denet.monitor(
    base_interval_ms=100,
    max_interval_ms=1000,
    output_file=None,         # Optional file output
    store_in_memory=True      # Store samples in memory (default)
) as mon:
    # Code to profile
    for i in range(5):
        # Do something CPU intensive
        result = sum(i*i for i in range(1_000_000))
        
# Access collected metrics after the block
samples = mon.get_samples()
print(f"Collected {len(samples)} samples")
print(f"Peak CPU usage: {max(sample['cpu_usage'] for sample in samples)}%")

# Generate and print summary
summary_json = mon.get_summary()
summary = json.loads(summary_json)
print(f"Average CPU usage: {summary['avg_cpu_usage']}%")
print(f"Peak memory: {summary['peak_mem_rss_kb']/1024:.2f} MB")

# Save samples to a file (includes metadata line in JSONL format)
mon.save_samples("metrics.jsonl", "jsonl")  # First line contains process metadata

## Development

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
```


Denet follows a Rust-first development approach, with Python bindings as a secondary interface.

### Setting Up the Development Environment

1. Clone the repository
2. Install pixi if you don't have it already: [Pixi Installation Guide](https://prefix.dev/docs/pixi/overview)
3. Set up the development environment:

```bash
pixi install
```

### Development Workflow

1. Make changes to Rust code in `src/`
2. Test with Cargo: `pixi run test-rust`
3. Build and install Python bindings: `pixi run develop`
4. Test Python bindings: `pixi run test`

### Running Tests

```bash
# Run Rust tests only (primary development testing)
pixi run test-rust

# Run Python tests only (after building with "develop")
pixi run test

# Run all tests together
pixi run test-all
```

### Helper Scripts

The project includes scripts to help with development:

```bash
# Build and install the extension in the current Python environment
./scripts/build_and_install.sh

# Run tests in CI environment
./ci/run_tests.sh
```

## Project Structure

```
denet/
├── src/              # Rust source code (primary development focus)
│   ├── lib.rs        # Core library and Python binding interface (PyO3)
│   ├── bin/          # CLI executables
│   │   └── denet.rs  # Command-line interface implementation
│   └── process_monitor.rs  # Core implementation with Rust tests
├── python/           # Python package
│   └── denet/        # Python module
│       ├── __init__.py    # Python API (decorator and context manager)
│       └── analysis.py    # Analysis utilities
├── tests/            # Tests
│   ├── python/       # Python binding tests
│   │   ├── test_convenience.py  # Tests for decorator and context manager
│   │   ├── test_process_monitor.py  # Tests for ProcessMonitor class
│   │   └── test_analysis.py  # Tests for analysis utilities
│   └── cli/          # Command-line interface tests
├── ci/               # Continuous Integration scripts
├── scripts/          # Helper scripts for development
├── Cargo.toml        # Rust dependencies and configuration
└── pyproject.toml    # Python build configuration (maturin settings)
```

## License

GPL-3

## Acknowledgements

- [sysinfo](https://github.com/GuillaumeGomez/sysinfo) - Rust library for system information
- [PyO3](https://github.com/PyO3/pyo3) - Rust bindings for Python
