# Interpreting disk I/O metrics

denet reports three related but distinct signals for disk activity on Linux. They answer different questions, and looking at only one can be disorienting — especially for workloads that rely on the page cache or `mmap`. This document explains each field, where it comes from, and how to use them together.

All three signals are Linux-only; on other platforms the syscall and page-fault fields are omitted from the output.

## The three signals

### `disk_read_bytes` / `disk_write_bytes` — block-layer bytes

Source: `/proc/<pid>/io` — `read_bytes` and `write_bytes`.

> "The number of bytes which this task has caused to be fetched from / sent to the storage layer." — kernel docs.

These are the bytes that actually moved across the block layer. Cache hits do **not** count here. A process that re-reads a file already in the page cache will show `disk_read_bytes: 0` no matter how much data it consumes. Writes are counted when pages are submitted to the block layer, not necessarily when they are issued by the application.

### `syscall_read_bytes` / `syscall_write_bytes` — syscall bytes

Source: `/proc/<pid>/io` — `rchar` and `wchar`.

Bytes that flowed through `read()`/`write()`-family syscalls, regardless of whether the data came from disk or the page cache. This is closer to "what the application actually consumed".

- **Does** include cache hits.
- **Does not** include `mmap` access, because memory-mapped reads don't go through a syscall per access — they're served by the VM subsystem via page faults.

### `page_faults_cached` / `page_faults_disk` — page-fault counts

Source: `/proc/<pid>/stat` — `minflt` (field 10) and `majflt` (field 12).

- `page_faults_cached` (kernel name: minor fault) — a page fault served without a block-layer read. Includes warm `mmap` accesses and first-touch of lazily-allocated anonymous memory (stack growth, heap expansion).
- `page_faults_disk` (kernel name: major fault) — a page fault that required a block-layer read. Includes cold `mmap` reads and swap-ins.

These are **event counts**, not byte sizes. A single fault typically brings in one 4 KiB page, but readahead can bring in more, so multiplying by page size gives a lower bound on bytes — not an exact figure.

## How the signals combine

| Scenario                 | `disk_read_bytes` | `syscall_read_bytes` | `page_faults_cached` | `page_faults_disk` |
|--------------------------|:----------------:|:--------------------:|:--------------------:|:------------------:|
| Cold `read()` from disk  | ↑                | ↑                    | —                    | —                  |
| Cached `read()`          | 0                | ↑                    | —                    | —                  |
| Cold `mmap` access       | ↑                | 0                    | ↑                    | ↑                  |
| Cached `mmap` access     | 0                | 0                    | ↑                    | 0                  |

"—" means the signal is not a useful indicator for that scenario (it may move slightly due to unrelated activity, but it's not what the counter is tracking).

## Troubleshooting: "why is `disk_read_bytes` zero?"

If your workload is clearly reading files but `disk_read_bytes` stays at `0`, the kernel probably isn't going to disk. Check in this order:

1. **`syscall_read_bytes`** — if it's non-zero, your process is consuming data via `read()` from the page cache. That's expected behavior for any repeat access to a file, and for any short-lived process whose inputs are already warm.
2. **`page_faults_cached`** — if it's non-zero and `syscall_read_bytes` is zero, the process is reading via `mmap`. Common in Arrow/Parquet readers, some `data.table`/`fread` paths, R's `bigmemory`/`ff`, and many ML data loaders.
3. **`page_faults_disk`** — non-zero here is the clearest signal that *something* actually hit the storage layer, regardless of access method.

To confirm from outside denet:

- `cat /proc/<pid>/io` — `rchar`/`wchar` vs `read_bytes`/`write_bytes` side by side.
- `sync && echo 3 | sudo tee /proc/sys/vm/drop_caches` then rerun. The first run should show non-zero `disk_read_bytes`; subsequent runs should go back to ~0.
- `iostat -x 1` while the workload runs — if the device shows no `r/s`, the kernel is genuinely not reading from disk.
- `biotop` / `biosnoop` (bcc tools) — block-layer request tracing, attributable to the process.

## Related

- [eBPF profiling](ebpf.md) — for per-syscall counts and categorized I/O intensity signals, built on eBPF.
