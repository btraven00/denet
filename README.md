# denet: a streaming process monitor

**denet** /de.net/ _v._ 1. _Turkish_: to monitor, to supervise, to audit. 2. to track metrics of a running process.

Denet is a lightweight streaming process monitor. It tracks CPU, memory, I/O, and threads for a running process (and its children), with adaptive sampling and optional GPU / eBPF support.

[![docs](https://img.shields.io/badge/docs-btraven00.github.io%2Fdenet-blue)](https://btraven00.github.io/denet/)
[![PyPI version](https://badge.fury.io/py/denet.svg)](https://badge.fury.io/py/denet)
[![Crates.io](https://img.shields.io/crates/v/denet.svg)](https://crates.io/crates/denet)
[![conda-forge](https://img.shields.io/conda/vn/conda-forge/denet.svg)](https://anaconda.org/channels/conda-forge/packages/denet/overview)
[![codecov](https://codecov.io/gh/btraven00/denet/branch/main/graph/badge.svg)](https://codecov.io/gh/btraven00/denet)
[![Ruff](https://img.shields.io/badge/code%20style-ruff-black)](https://github.com/astral-sh/ruff)
[![License: GPL v3](https://img.shields.io/badge/License-GPLv3-blue.svg)](https://www.gnu.org/licenses/gpl-3.0)
[![DOI](https://img.shields.io/badge/DOI-10.48550%2FarXiv.2510.13818-b31b1b.svg)](https://doi.org/10.48550/arXiv.2510.13818)

## Installation

`denet` is primarily used as a CLI tool.

### With Cargo

You can compile it yourself with cargo:

```bash
cargo install denet
```

And enable some optional features:

```bash
cargo install denet --features gpu       # GPU monitoring: NVIDIA (requires drivers) or Apple Silicon (experimental); enable per run with --gpu
cargo install denet --features ebpf      # eBPF profiling (Linux only, requires clang)
cargo install denet --features gpu,ebpf  # both: each install replaces the previous one
```

### Debian-based

On Debian 12+ and Ubuntu 22.04+, download the `.deb` from the [latest release](https://github.com/btraven00/denet/releases/latest) and `sudo apt install ./denet_*_amd64.deb`. It includes GPU and eBPF support.

### RHEL-based

On RHEL, Rocky and AlmaLinux 8+ and Fedora, download the `.rpm` from the [latest release](https://github.com/btraven00/denet/releases/latest) and `sudo dnf install ./denet-*.x86_64.rpm`. It also includes GPU and eBPF support.

### Static binary

On any other Linux (x86_64 or aarch64), there is a static binary with eBPF support but no GPU support:

```bash
VERSION=0.11.2 # x-release-please-version
curl -L -o denet "https://github.com/btraven00/denet/releases/download/v$VERSION/denet-$VERSION-$(uname -m)-linux-musl"
chmod +x denet
```

### Nix

With Nix, run a release straight from the flake: `nix run github:btraven00/denet/v0.11.2 -- --help`. <!-- x-release-please-version -->

### Conda

Conda users can use [conda-forge](https://anaconda.org/channels/conda-forge/packages/denet/overview):

```bash
pixi add denet                        # pixi
conda install -c conda-forge denet    # conda
```

### As a python package

You can install the python package from pypi to write your custom scripts. It is a library: it does not install the `denet` command.

```bash
pip install denet
```

The `report` extra adds the `denet-report` command, which turns a saved run into an HTML report with timelines:

```bash
pip install 'denet[report]'
```

## Usage

```bash
# Run a command and monitor it
denet run python train.py

# Attach to an existing process
denet attach 1234

# Watch it live: full-screen graphs of CPU, memory, disk and TCP (add --gpu for GPU)
denet --tui run python train.py

# Save metrics as JSONL
denet --json --out metrics.jsonl run python train.py

# Turn a saved run into a report (timelines, regime detection, eBPF syscalls)
pip install 'denet[report]'
denet-report metrics.jsonl -o report.html
```

CPU usage follows the `top` convention: 100% = one fully utilized core, so a 4-core workload shows 400%.

Sampling starts at 100 ms and ramps up to 1 s after 10 s of runtime (adaptive). Override with `-i` / `-m`:

```bash
denet -i 50 -m 500 run python train.py
```

## Further reading

Full documentation: <https://btraven00.github.io/denet/>

| Topic | Doc |
|---|---|
| Python API (`ProcessMonitor`, `execute_with_monitoring`, analysis) | [docs/python-api.md](docs/python-api.md) |
| HTML/PNG/SVG reports (`denet-report`) | [docs/python-api.md#reports](docs/python-api.md#reports) |
| GPU monitoring | [GPU guide](https://btraven00.github.io/denet/guides/gpu/) |
| eBPF profiling (off-CPU, syscall tracking) | [eBPF guide](https://btraven00.github.io/denet/guides/ebpf/) |
| Disk I/O metrics and how to interpret them | [docs/disk-io.md](docs/disk-io.md) |
| Output data format | [docs/data-format.md](docs/data-format.md) |
| Development setup | [docs/dev.md](docs/dev.md) |
| Worked example: a Snakemake workflow profiled end to end | [btraven00/denet_example](https://github.com/btraven00/denet_example) |

## License

GPL-3

## Acknowledgements

- [sysinfo](https://github.com/GuillaumeGomez/sysinfo) - Rust library for system information
- [PyO3](https://github.com/PyO3/pyo3) - Rust bindings for Python
- [aya](https://github.com/aya-rs/aya) - Rust library for eBPF programs
