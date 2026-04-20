# GPU Monitoring

Denet provides comprehensive GPU monitoring for NVIDIA GPUs using the NVIDIA Management Library (NVML).

## Features

- **GPU Utilization**: Real-time GPU compute utilization percentage
- **Memory Monitoring**: GPU memory usage, both total and per-process when available
- **Temperature Tracking**: GPU temperature monitoring
- **Power Consumption**: GPU power usage in watts
- **Multi-GPU Support**: Monitor all NVIDIA GPUs in the system
- **Process-Specific**: Track GPU memory usage per monitored process
- **Graceful Fallback**: Continues working without GPU support if NVML is unavailable

## Requirements

- NVIDIA GPU with driver support
- NVIDIA CUDA toolkit or driver with NVML support
- Rust compilation with `--features gpu` or Python installation with `pip install denet[gpu]`

## Installation

```bash
# Python package with GPU support
pip install denet[gpu]

# Rust binary with GPU support
cargo install denet --features gpu
```

## Usage Examples

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

## Command Line GPU Output

When GPU monitoring is enabled, the command line interface automatically includes GPU information:

```bash
# Example output with GPU monitoring
denet run python train_model.py
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

## Notes

- GPU monitoring requires NVIDIA GPUs and drivers
- NVML (NVIDIA Management Library) must be available on the system
- If GPU support is compiled in but no GPUs are detected, denet continues working normally
- GPU metrics are automatically included when available, no configuration needed
- Process-specific GPU memory tracking may not be available on all driver versions
