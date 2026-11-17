# Get started

## Install

denet is mainly a command-line tool. Pick one:

=== "Cargo"

    ```bash
    cargo install denet
    ```

    Optional features are chosen at build time:

    ```bash
    cargo install denet --features gpu       # GPU monitoring
    cargo install denet --features ebpf      # eBPF profiling (Linux, needs clang)
    cargo install denet --features gpu,ebpf  # both
    ```

=== "Conda / pixi"

    ```bash
    conda install -c conda-forge denet
    pixi add denet
    ```

=== "Debian, Ubuntu, RHEL, Fedora"

    Download the `.deb` or `.rpm` from the
    [latest release](https://github.com/btraven00/denet/releases/latest). Both
    include GPU and eBPF support.

    ```bash
    sudo apt install ./denet_*_amd64.deb     # Debian 12+, Ubuntu 22.04+
    sudo dnf install ./denet-*.x86_64.rpm    # RHEL, Rocky, AlmaLinux 8+, Fedora
    ```

=== "Static binary"

    For any other Linux (x86_64 or aarch64), the
    [latest release](https://github.com/btraven00/denet/releases/latest) has a
    static binary, with eBPF support but no GPU support.

`denet --version` lists the optional features a binary was built with.

There is also a Python package, `pip install denet`. It is a library for your
own scripts and does not install the `denet` command.

## Monitor a command

```bash
denet run python train.py
```

denet prints a live line while the command runs, and a summary when it exits.
CPU usage follows the `top` convention: 100% is one fully used core, so a job
using four cores shows 400%.

To monitor a process that is already running:

```bash
denet attach 1234
```

To watch full-screen graphs of CPU, memory, disk and network:

```bash
denet --tui run python train.py
```

## Save a run

```bash
denet --json --out metrics.jsonl run python train.py
```

The file has one JSON record per line. Print its summary again later, on any
machine:

```bash
denet stats metrics.jsonl
```

Or turn it into an HTML report with timelines:

```bash
pip install 'denet[report]'
denet-report metrics.jsonl -o report.html
```

## Sampling

Sampling starts every 100 ms and backs off to every second after 10 s of
runtime. Set the two intervals with `-i` and `-m`, in milliseconds:

```bash
denet -i 50 -m 500 run python train.py
```

## Next

- [GPU monitoring](guides/gpu.md)
- [eBPF profiling](guides/ebpf.md)
