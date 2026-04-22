# denet: a streaming process monitor

**denet** /de.net/ _v._ 1. _Turkish_: to monitor, to supervise, to audit. 2. to track metrics of a running process.

Denet is a lightweight streaming process monitor. It tracks CPU, memory, I/O, and threads for a running process (and its children), with adaptive sampling and optional GPU / eBPF support.

[![PyPI version](https://badge.fury.io/py/denet.svg)](https://badge.fury.io/py/denet)
[![Crates.io](https://img.shields.io/crates/v/denet.svg)](https://crates.io/crates/denet)
[![codecov](https://codecov.io/gh/btraven00/denet/branch/main/graph/badge.svg)](https://codecov.io/gh/btraven00/denet)
[![Ruff](https://img.shields.io/badge/code%20style-ruff-black)](https://github.com/astral-sh/ruff)
[![License: GPL v3](https://img.shields.io/badge/License-GPLv3-blue.svg)](https://www.gnu.org/licenses/gpl-3.0)

## Installation

```bash
pip install denet    # Python package
cargo install denet  # Rust binary
```

Optional features for the Rust binary:

```bash
cargo install denet --features gpu   # NVIDIA GPU monitoring (requires drivers)
cargo install denet --features ebpf  # eBPF profiling (Linux only, requires clang)
```

## Usage

```bash
# Run a command and monitor it
denet run python train.py

# Attach to an existing process
denet attach 1234

# Save metrics as JSONL
denet --json --out metrics.jsonl run python train.py
```

CPU usage follows the `top` convention: 100% = one fully utilized core, so a 4-core workload shows 400%.

Sampling starts at 100 ms and ramps up to 1 s after 10 s of runtime (adaptive). Override with `-i` / `-m`:

```bash
denet -i 50 -m 500 run python train.py
```

## Further reading

| Topic | Doc |
|---|---|
| Python API (`ProcessMonitor`, `execute_with_monitoring`, analysis) | [docs/python-api.md](docs/python-api.md) |
| GPU monitoring | [docs/gpu.md](docs/gpu.md) |
| eBPF profiling (off-CPU, syscall tracking) | [docs/ebpf.md](docs/ebpf.md) |
| Disk I/O metrics and how to interpret them | [docs/disk-io.md](docs/disk-io.md) |
| Output data format | [docs/data-format.md](docs/data-format.md) |
| Development setup | [docs/dev.md](docs/dev.md) |

## License

GPL-3

## Acknowledgements

- [sysinfo](https://github.com/GuillaumeGomez/sysinfo) - Rust library for system information
- [PyO3](https://github.com/PyO3/pyo3) - Rust bindings for Python
