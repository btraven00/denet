# GPU Monitoring

Denet provides comprehensive GPU monitoring for NVIDIA GPUs using the NVIDIA Management Library (NVML).

**GPU monitoring is opt-in**: pass `--gpu` (CLI) or `enable_gpu=True` (Python).
Loading the NVIDIA driver library maps tens of MB of driver state into denet
(about 19 MB extra peak memory on a laptop RTX 2000), so denet doesn't load it
unless asked. All data comes from NVML directly; denet never runs `nvidia-smi`.

## Features

- **GPU Utilization**: Real-time GPU compute utilization percentage
- **Memory Monitoring**: GPU memory usage, both total and per-process when available
- **Temperature Tracking**: GPU temperature monitoring
- **Power Consumption**: GPU power usage in watts
- **Multi-GPU Support**: Monitor all NVIDIA GPUs in the system
- **Process-Specific**: Track GPU memory usage per monitored process
- **Graceful Fallback**: With `--gpu` but no usable GPU/NVML, denet warns and carries on

## Requirements

- NVIDIA GPU with driver support
- NVIDIA CUDA toolkit or driver with NVML support
- A build with the `gpu` feature: the conda package's CLI and `cargo install denet --features gpu`. The PyPI wheels are built without it.

## Installation

```bash
# CLI with GPU support (the conda package on prefix.dev, or from source)
cargo install denet --features gpu
```

## Usage Examples

```python
import denet
import json

# Create monitor with GPU monitoring turned on (off by default)
monitor = denet.ProcessMonitor(
    cmd=["python", "gpu_workload.py"],
    base_interval_ms=100,
    max_interval_ms=1000,
    store_in_memory=True,
    enable_gpu=True,
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

## Command Line GPU Output

With `--gpu`, the command line interface includes GPU information:

```bash
denet --gpu run python train_model.py
CPU: 45.2% | Memory: 2.1 GB | Threads: 8 | GPU: 85%, 3.2GB | Disk: 1.2MB rd, 856KB wr
```

## GPU Data Structure

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

## Energy (`gpu_energy`)

When the GPU exposes NVML's cumulative energy counter (`total_energy_consumption`,
**Volta and newer**, ~2017+), each `gpu` block also carries:

```json
"gpu_energy": { "package_joules": 12.4, "process_joules": 8.1 }
```

- **`package_joules`** — whole-board energy over the sample interval (all
  processes + memory + static/idle draw), diffed from the NVML counter. Ground
  truth, measured.
- **`process_joules`** — the slice attributed to the monitored process(es) by
  summed GPU-utilization share `(Σ proc_util) / 100`, clamped to the board total.

**Caveat — whole-card vs per-process.** NVML has *no* per-process energy counter;
the counter is always the entire board. So `process_joules` is an estimate, and a
coarser one than the CPU/RAPL equivalent: NVML's per-process "SM utilization"
is the fraction of *time* a kernel was resident, not how many SMs or how much
power it drew, and under MPS/concurrent contexts the per-process utilizations may
not cleanly partition. Trust `package_joules`; treat `process_joules` as a guide.
No counter (pre-Volta) → `gpu_energy` is omitted. No root or extra capability is
needed (NVML runs as the invoking user).

**Shared GPU.** `package_joules` is the whole board, so on a multi-tenant GPU it
*includes* other users' and the display's draw — it is not scoped to you. But
`process_joules` **is** scoped: it multiplies the board total by the summed GPU
utilization of *your monitored pids only* (NVML reports SM utilization
per-pid, the same data `nvidia-smi pmon` shows). So a neighbor's kernels are never charged to you — they raise the board
total while your util share stays what your kernels actually used, i.e. you're
attributed your fraction of a larger pie, not their energy. Accuracy still hinges
on the per-pid util proxy, which is coarse under MPS/MIG.

**Counter reliability.** The absolute values come straight from the driver's
counter and are accurate on datacenter GPUs (A100/H100). On some laptop/Optimus
dGPUs the counter is noisy and NVML polling itself perturbs the power state, so
treat laptop readings as indicative, not billable.

## Notes

- GPU monitoring requires NVIDIA GPUs and drivers
- NVML (NVIDIA Management Library) must be available on the system
- If `--gpu` is given but no GPU is detected, denet warns and continues working normally
- Without `--gpu`, the NVIDIA library is never loaded and no GPU fields are written
- Per-process GPU utilization needs a Maxwell or newer GPU
- Process-specific GPU memory tracking may not be available on all driver versions
