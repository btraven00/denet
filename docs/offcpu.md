# Off-CPU Profiling

Off-CPU profiling measures the time a thread spends *not running* on a CPU — blocked
on I/O, waiting for a lock, sleeping, or descheduled. This complements CPU profiling,
which only captures time when threads are actively executing.

## How it works

The off-CPU profiler attaches an eBPF program to the `tracepoint/sched/sched_switch`
kernel tracepoint. Every context switch fires the program, which records:

- the outgoing PID and TID
- a timestamp (from `bpf_ktime_get_ns()`)
- the id of the kernel stack the thread is about to wait in (from `bpf_get_stackid()`)

When the same thread is scheduled back in, the difference in timestamps is the
off-CPU duration. Events are streamed to userspace via a `PerfEventArray`
(one ring buffer per CPU).

The userspace `OffCpuProfiler` collects these events in a background thread,
updates per-thread statistics, and adds up the off-CPU time per process and
kernel stack. The frames of each stack are named from `/proc/kallsyms`.

User-space stacks are not captured: a wait is attributed to a process and to
the kernel path it blocked in (`pipe_write`, `do_nanosleep`, ...), not to a
function of the program.

## Data flow

```
kernel: sched_switch tracepoint
  └─▶ offcpu_profiler.c
        records: (pid, tid, ts_ns, kernel_stack_id)
        └─▶ PerfEventArray (per-CPU ring buffer)
              └─▶ userspace polling thread
                    updates: HashMap<(pid, tid), OffCpuStats>
                             and time per (pid, kernel stack)
                    └─▶ build_offcpu_metrics()
                          └─▶ EbpfMetrics.offcpu → JSON
```

## Requirements

- Linux kernel 5.5+
- `CAP_BPF` + `CAP_PERFMON` capabilities, or root
- Build with `--features ebpf` and `clang` available

```bash
cargo build --features ebpf
sudo denet --enable-ebpf run <command>
```

## Known limitations

- **No user-space stacks.** Only the kernel side of a wait is recorded.
- **Minimum threshold**: waits of 1 ms or less are dropped in the BPF program.
- **Stack map slots**: kernel stacks are stored by hash, with an overflow map
  for stacks whose slot is taken. A stack that finds both slots taken is
  reported as `[stack unavailable]` (stack id 4294967295); its time is still
  counted. Ids of stacks in the overflow map are above 2^30.
- **Frame names** need a readable `/proc/kallsyms`; without it frames are
  hexadecimal addresses.

## JSON output

Off-CPU data appears under `ebpf.offcpu` in each aggregated sample:

```json
{
  "ts_ms": 1714000000000,
  "ebpf": {
    "offcpu": {
      "total_time_ns": 1500000000,
      "total_events": 30,
      "avg_time_ns": 50000000,
      "max_time_ns": 500000000,
      "min_time_ns": 1000000,
      "top_blocking_threads": [
        { "pid": 1234, "tid": 1234, "time_ms": 500.0, "percentage": 33.33 },
        { "pid": 1234, "tid": 1235, "time_ms": 400.0, "percentage": 26.67 }
      ],
      "thread_stats": {
        "1234:1234": {
          "tid": 1234,
          "total_time_ns": 500000000,
          "count": 10,
          "avg_time_ns": 50000000,
          "max_time_ns": 200000000,
          "min_time_ns": 5000000
        }
      },
      "waits": [
        { "pid": 1234, "stack": 7914, "time_ns": 2083845198, "count": 2 }
      ],
      "kernel_stacks": {
        "7914": ["__schedule", "schedule", "pipe_write", "vfs_write", "ksys_write"]
      }
    }
  }
}
```

### Field reference

| Field | Description |
|-------|-------------|
| `total_time_ns` | Sum of all off-CPU durations across all threads since profiling started |
| `total_events` | Number of off-CPU events (sched_switch wakeups) observed |
| `avg_time_ns` | `total_time_ns / total_events` |
| `max_time_ns` / `min_time_ns` | Longest / shortest single off-CPU duration seen |
| `top_blocking_threads` | Up to 10 threads ranked by `time_ms` descending — derived directly from `thread_stats`, not a separate analysis |
| `top_blocking_threads[].percentage` | Thread's share of `total_time_ns` across all monitored threads — **not** a share of wall-clock time |
| `thread_stats` | Full per-thread breakdown keyed by `"PID:TID"` |
| `thread_stats[].count` | How many times this thread was scheduled out and back in |
| `waits` | Off-CPU time credited since the previous sample, per process and kernel stack. A wait is credited when the thread wakes up |
| `waits[].stack` | Key into `kernel_stacks` |
| `waits[].time_ns` / `count` | Time waited in that stack, and number of waits |
| `kernel_stacks` | Frames of each stack, innermost first. A stack is written once, in the first sample that refers to it |

## Aya-specific notes (v0.13+)

The `Bpf` and `BpfLoader` types were renamed to `Ebpf` and `EbpfLoader` in Aya 0.13.
The old names remain as deprecated aliases. Use the new names in new code.

`include_bytes_aligned!` is needed when embedding compiled eBPF bytecode, because
the verifier requires 8-byte alignment:

```rust
const BYTECODE: &[u8] = include_bytes_aligned!(concat!(env!("OUT_DIR"), "/ebpf/offcpu_profiler.o"));
```

`PerfEventArray` is used for event delivery (one buffer per CPU). Attach a reader
per logical CPU to avoid dropping events under load.

## Debugging

**Enable debug logging** at runtime:

```bash
RUST_LOG=debug sudo denet --enable-ebpf --debug run <command>
```

**Read `bpf_printk` output** from the eBPF programs:

```bash
sudo cat /sys/kernel/debug/tracing/trace_pipe
```

**Common errors:**

| Error | Cause | Fix |
|-------|-------|-----|
| `Operation not permitted` | Missing capabilities | Run with `sudo` or set `cap_bpf,cap_perfmon` |
| `EFAULT` on stack walk | Process exited mid-collection | Expected; events for dead PIDs are skipped |
| `ENOMEM` on stack map | Stack map full | Reduce monitored PID count or increase map size |
| `Invalid argument` | Kernel too old or missing feature | Requires kernel 5.5+ with BPF tracepoint support |

**Verify capabilities are set:**

```bash
sudo setcap cap_bpf,cap_perfmon=ep ./target/debug/denet
getcap ./target/debug/denet
```
