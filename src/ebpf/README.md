# eBPF Profiling Module

This module provides fine-grained profiling capabilities using eBPF (Extended Berkeley Packet Filter) for Linux systems. It enhances process monitoring with low-overhead kernel-level instrumentation.

## Current Implementation

### Off-CPU Profiling
- **Purpose**: Measure time threads spend waiting (blocked on I/O, locks, sleep, scheduling)
- **Mechanism**: `tracepoint/sched/sched_switch` captures every context switch
- **Output**: Per-thread blocked time, event counts, top blocking threads
- **Symbolication**: User-space stack frames resolved via `/proc/pid/maps` + `addr2line`
- **Overhead**: Low — event-driven, only fires on context switches

### Syscall Tracking
- **Purpose**: Track system call frequency across process trees
- **Mechanism**: `tracepoint/syscalls/sys_enter_*` tracepoints
- **Output**: Syscall counts by category (file_io, memory, network, time, …), top-10 syscalls, behavior classification
- **Overhead**: Very low — counts only, no data copying

## Architecture

```
src/ebpf/
├── mod.rs                # Module interface, re-exports, non-Linux stubs
├── metrics.rs            # EbpfMetrics, OffCpuMetrics, SyscallMetrics types
├── offcpu_profiler.rs    # Off-CPU profiler (sched_switch tracepoint)
├── memory_map_cache.rs   # /proc/pid/maps caching for symbolication
├── syscall_tracker.rs    # Syscall frequency tracking
├── debug.rs              # Debug logging utilities
└── programs/
    ├── offcpu_profiler.c # eBPF program: sched_switch → perf event ring buffer
    ├── syscall_tracer.c  # eBPF program: syscall entry counting
    └── simple_test.c     # Minimal tracepoint for smoke testing
```

Data flow for off-CPU:

```
sched_switch tracepoint
  └─▶ offcpu_profiler.c (kernel)
        └─▶ PerfEventArray (ring buffer)
              └─▶ OffCpuProfiler::poll_events() (userspace thread)
                    └─▶ stats HashMap + symbolication
                          └─▶ OffCpuMetrics → JSON output
```

## Usage

```bash
# Build with eBPF support
cargo build --features ebpf

# Run with off-CPU profiling (requires root or CAP_BPF + CAP_PERFMON)
sudo denet --enable-ebpf run sleep 5

# JSON output with eBPF metrics
sudo denet --enable-ebpf --json run python io_bound.py
```

## Requirements

- Linux kernel 5.5+ (for `sched_switch` perf buffer support)
- `CAP_BPF` + `CAP_PERFMON` capabilities, or root
- `clang` available at build time (to compile eBPF C programs)
- Feature flag: `cargo build --features ebpf`

## Output Schema

Off-CPU data appears under `ebpf.offcpu` in the JSON output:

```json
{
  "ebpf": {
    "offcpu": {
      "total_time_ns": 1234567890,
      "total_events": 42,
      "avg_time_ns": 29394000,
      "max_time_ns": 500000000,
      "min_time_ns": 1000000,
      "top_blocking_threads": [
        { "pid": 1234, "tid": 1234, "time_ms": 500.0, "percentage": 40.52 }
      ],
      "thread_stats": {
        "1234:1234": { "tid": 1234, "total_time_ns": 500000000, "count": 10, ... }
      }
    }
  }
}
```

## Future Exploration

- **Cache miss tracking**: L1/L2/L3 miss rates via perf hardware counters
- **Memory profiling**: Allocation tracking via `uprobe` on malloc/free
- **Lock contention**: `futex` wait times
- **Block I/O latency**: Per-operation disk latency via `block_rq_*` tracepoints
- **Network packet latency**: Socket send/receive latency

## Development Notes

```bash
# Run tests (some require root for eBPF attachment)
cargo test --features ebpf
sudo -E cargo test --features ebpf -- --nocapture

# Inspect loaded eBPF programs at runtime
sudo bpftool prog list
sudo bpftool map list

# Read bpf_printk debug output from eBPF programs
sudo cat /sys/kernel/debug/tracing/trace_pipe
```

### References
- [Aya Book](https://aya-rs.dev/book/)
- [BPF Performance Tools – Brendan Gregg](http://www.brendangregg.com/bpf-performance-tools-book.html)
- [Linux kernel tracepoints](https://www.kernel.org/doc/html/latest/trace/tracepoints.html)
