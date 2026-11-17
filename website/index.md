# denet

**denet** /de.net/ _v._ 1. _Turkish_: to monitor, to supervise, to audit.
2. to track metrics of a running process.

denet is a lightweight streaming process monitor. It tracks the CPU, memory,
disk I/O, threads and network bytes of a running process and its children,
with adaptive sampling, and can add GPU and eBPF metrics.

```bash
denet run python train.py
```

- **One command.** Wrap a command with `denet run`, or attach to a running
  process with `denet attach PID`.
- **The whole process tree.** Children are followed and their usage is added
  up.
- **Streaming records.** Samples are written as JSON lines while the job
  runs, and can be turned into a summary or an HTML report afterwards.
- **Optional depth.** GPU utilisation, memory and energy with `--gpu`;
  syscalls, per-process network bytes and off-CPU waits with `--enable-ebpf`.

[Get started](get-started.md){ .md-button .md-button--primary }
[Source on GitHub](https://github.com/btraven00/denet){ .md-button }

## Guides

- [GPU monitoring](guides/gpu.md): NVIDIA, and Apple Silicon (experimental)
- [eBPF profiling](guides/ebpf.md): syscalls, network bytes and off-CPU waits

The rest of the documentation (Python API, data format, disk I/O,
development) is in the
[`docs/` folder of the repository](https://github.com/btraven00/denet/tree/main/docs).

## Citing

If you use denet in your work, please cite
[arXiv:2510.13818](https://doi.org/10.48550/arXiv.2510.13818).
