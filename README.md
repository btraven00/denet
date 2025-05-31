# denet: a streaming process monitor

Denet is a streaming process monitoring tool that provides detailed metrics on running processes, including CPU, memory, I/O, and thread usage. Built with a Rust core and Python bindings, it follows a Rust-first development approach while providing convenient Python access.

## Features

- Lightweight, cross-platform process monitoring
- Adaptive sampling intervals that automatically adjust based on runtime
- Memory usage tracking (RSS, VMS)
- CPU usage monitoring
- I/O bytes read/written tracking
- Thread count monitoring
- Recursive child process tracking
- Command-line interface with colorized output
- JSON output option for data processing

## Requirements

- Python 3.6+
- Rust (for development only)
- [pixi](https://prefix.dev/docs/pixi/overview) (for development only)

## Installation

```bash
pip install denet  # Python package
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

```python
import json
import denet

# Create a monitor for a process
monitor = denet.ProcessMonitor(
    cmd=["python", "-c", "import time; time.sleep(10)"],
    base_interval_ms=100,  # Start sampling every 100ms
    max_interval_ms=1000   # Sample at most every 1000ms
)

# Option 1: Run the monitor until the process completes
# This will print JSON metrics to stdout
monitor.run()

# Option 2: Sample on demand
while monitor.is_running():
    # Get metrics as JSON string
    metrics_json = monitor.sample_once()
    if metrics_json:
        metrics = json.loads(metrics_json)
        print(f"CPU: {metrics['cpu_usage']}%, Memory: {metrics['mem_rss_kb']/1024:.2f} MB")
```

## Development

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
│   ├── lib.rs        # Python binding interface
│   ├── bin/          # CLI executables
│   │   └── denet.rs  # Command-line interface implementation
│   └── process_monitor.rs  # Core implementation with Rust tests
├── tests/            # Python binding tests
│   └── cli/          # Command-line interface tests
├── ci/               # Continuous Integration scripts
├── scripts/          # Helper scripts for development
├── Cargo.toml        # Rust dependencies and configuration
└── pyproject.toml    # Python build configuration
```

## License

GPL-3

## Acknowledgements

- [sysinfo](https://github.com/GuillaumeGomez/sysinfo) - Rust library for system information
- [PyO3](https://github.com/PyO3/pyo3) - Rust bindings for Python
