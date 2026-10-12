# Plan: Apple Silicon GPU monitoring (experimental)

Status: in progress. Behind the `gpu` feature, opt-in at runtime (`--gpu`,
`enable_gpu=True`), and reported as **experimental** everywhere it surfaces.

## Data sources (verified on an M1 Mac mini, macOS 26.2, no root)

| Source | What it gives | Notes |
|---|---|---|
| `AGXDeviceUserClient.AppUsage[].accumulatedGPUTime` (IORegistry) | Cumulative GPU time per Metal client, **ns** | Owner pid in `IOUserClientCreator = "pid N, name"`. A 5 s Metal burn read 4.92 s against Metal's own 5.01 s. |
| `AGXAccelerator.PerformanceStatistics` (IORegistry) | `Device Utilization %`, `In use system memory` | Public IOKit, device-wide. |
| IOReport `Energy Model / GPU Energy` | GPU energy, nJ | Private framework (`libIOReport`), works unprivileged. About 8 W under full load on M1. |
| IOReport `GPU Stats / GPU Performance States` (`GPUPH`) | Residency per P-state, 24 MHz ticks | Needs a P-state→MHz table, probably `voltage-states9` on `pmgr` (unverified). |

Pitfall: the user clients are `!registered`, so `IOServiceGetMatchingServices`
finds none. Walk the `AGXAccelerator`'s children in the `IOService` plane.

## Mapping onto existing types (`src/gpu/mod.rs`)

- `ProcessGpuData.gpu_time_ns` (new): cumulative, summed over a pid's clients and queues.
- `ProcessGpuData.gpu_utilization`: ΔGPU-ns / Δwall-ns, clamped to 100.
- `ProcessGpuData.memory_usage`: `None` (not exposed per process).
- `SystemGpuMetrics.system_utilization_gpu` ← `Device Utilization %`; `memory_used` ← `In use system memory`.
- `power_usage` (mW), `board_energy_delta_joules()` ← IOReport GPU energy.
- `collection_method = "apple-ioregistry (experimental)"`.

Counter quirks to document: a client vanishes when its process drops its Metal
device (keep a per-pid max); the counter advances when a command buffer
completes, so one long kernel shows up lumpy; the last interval before exit is
lost, like CPU time. `sample_metrics` runs more than once per tick (parent and
tree), so derive the rates from one snapshot per emitted sample.

## Checklist

### Phase 1: per-process GPU time + device utilisation (IORegistry)
- [x] `src/gpu/apple.rs`: walk the accelerator's children, collect pid → GPU ns, read `PerformanceStatistics`
- [x] Pure parser for `IOUserClientCreator`, with a unit test
- [x] Wire into `GpuMonitor` under `cfg(apple_gpu)` (set by `build.rs` for `gpu` on macOS; NVML code is now `cfg(nvml)`)
- [x] `gpu_time_ns` on `ProcessGpuData`; utilisation from one snapshot per tick
- [x] Mark it experimental: CLI notice on `--gpu`, `collection_method`, docs
- [x] Builds and passes tests on macOS (macmini) and Linux
- [x] Manual check on macmini: GPU-seconds within 5% of wall time under a Metal burn (4.94 s vs Metal's 5.00 s; utilisation 90–100%)

### Phase 2: energy and power (IOReport)
- [x] `extern "C"` bindings, `#[link(name = "IOReport")]` (subscription and dicts are owned CF objects, released on drop; 2000 create/release cycles clean)
- [x] `board_energy_delta_joules()` and `power_usage` (mW, as NVML records carry) from `GPU Energy`, read once per tick in `refresh()`
- [x] Degrade to `None` if the subscription fails
- [x] Manual check on macmini: ~8 W under a Metal burn, 40 J over 5 s, idle 0–30 mW
- [x] Brittleness note in `apple.rs`: M1-only verification; add overrides per hardware model if names or units drift

### Phase 3: frequency (optional, for throttling)
- [ ] Verify the P-state→MHz table source
- [ ] Residency-weighted MHz per sample

### Alongside
- [ ] `scripts/stress_gpu.py`: `mps` fallback
- [x] `docs/gpu.md`: Apple Silicon section, marked experimental
- [ ] Summary: total process GPU-seconds

### Found along the way (not Apple-specific)
- [x] `--features python,gpu` didn't build on any OS: `PyProcessMonitor` must be
  `Sync`, and `GpuMonitor` held `RefCell`s. Now `Mutex`es (never contended:
  sampling is single-threaded). Checked on macmini: `enable_gpu=True` from
  Python returns Apple GPU data. The PyPI wheels still build with `python`
  only, so wheel users get no GPU data until the wheel build adds `gpu`.
- [x] `SystemGpuMetrics.power_usage` was documented as watts, but NVML returns
  milliwatts and real records carry mW (e.g. 34993). The Apple backend emits mW
  to match. Comment and `docs/gpu.md` now say milliwatts.
- [x] PyPI wheels now build with `gpu` (`publish.yml`, `[tool.maturin]`, pixi
  `build`/`publish-pypi`). No new runtime dependency: Linux `.so` has no
  `libnvidia-ml` NEEDED (NVML is dlopen'd on `enable_gpu`); macOS arm64 links
  system `/usr/lib/libIOReport.dylib`; the Apple backend is aarch64-only so
  the x86_64 wheel doesn't link it. Smoke-tested the arm64 wheel in a clean
  venv on macmini. Not yet tested: the arm64 wheel on macOS 11/12 (wheel
  floor is 11.0; libIOReport is long-standing but unverified there).
