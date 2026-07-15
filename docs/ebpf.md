# eBPF Support

This is an experimental, gated feature that enables advanced system monitoring using eBPF tracepoints for tracking syscalls and other low-level events. The eBPF support provides detailed insights into a process's syscall patterns and resource utilization behaviors by tracking individual syscall types and frequencies.

## Prerequisites

To build with eBPF support, you need:

```bash
sudo apt install clang libcap2-bin
```

libbpf headers are vendored in the repo (`src/ebpf/include/bpf/`), so
`libbpf-dev` is no longer required. See [portability.md](portability.md)
for details on other distros and what the `.o` bytecode needs at
runtime.

### Critical Kernel Settings

For eBPF to work with capabilities (non-root), you **MUST** configure these kernel settings:

```bash
# Check current values
cat /proc/sys/kernel/unprivileged_bpf_disabled
cat /proc/sys/kernel/kptr_restrict
cat /proc/sys/kernel/perf_event_paranoid

# Required settings for non-root eBPF access:
sudo sysctl kernel.unprivileged_bpf_disabled=0  # Allow unprivileged BPF
sudo sysctl kernel.kptr_restrict=0               # CRITICAL: Allow kernel pointer access

# Make settings persistent across reboots
echo "kernel.unprivileged_bpf_disabled=0" | sudo tee -a /etc/sysctl.conf
echo "kernel.kptr_restrict=0" | sudo tee -a /etc/sysctl.conf

# Optional: Check perf_event_paranoid (may affect some eBPF operations)
cat /proc/sys/kernel/perf_event_paranoid
# If value is > 1, you may need to lower it for full functionality:
# sudo sysctl kernel.perf_event_paranoid=1
```

**Important**: The `kptr_restrict=0` setting is essential. Without it, eBPF will fail with obscure errors even with proper capabilities.

## Building with eBPF Support

```bash
cargo build --release --features ebpf
```

## System Configuration for eBPF Access

### Option 1: Run with sudo (simplest approach)

You can run denet with sudo to get full access to eBPF features:

```bash
sudo target/release/denet --enable-ebpf run -- your_command_here
```

### Option 2: Set Up Non-Root Access (recommended for production)

eBPF tracepoints require:
1. The `CAP_BPF`, `CAP_PERFMON`, and `CAP_DAC_READ_SEARCH` capabilities
2. Access to the tracefs filesystem in `/sys/kernel/debug/tracing`
3. Proper kernel settings (see Prerequisites above)

#### 1. Add Required Capabilities to the Binary

```bash
# Required capabilities for eBPF tracepoint access
sudo setcap cap_bpf,cap_perfmon,cap_dac_read_search=ep /path/to/denet/target/release/denet

# Verify capabilities are set
getcap /path/to/denet/target/release/denet
# Should show: cap_dac_read_search,cap_perfmon,cap_bpf=ep
```

**Note**: On modern kernels (5.8+) tracepoint access needs:
- `CAP_BPF` — create/load BPF maps and programs.
- `CAP_PERFMON` — `perf_event_open(PERF_TYPE_TRACEPOINT, …)` to attach the program.
- `CAP_DAC_READ_SEARCH` — read `/sys/kernel/tracing/events/<subsystem>/<event>/id`,
  which is mode `0400` root-owned on most distros. Without this cap the attach
  step fails with `No such file or directory` (misleading; it's really EACCES
  when userspace follows the symlink). Dropping this cap means you must add
  your user to a group with read access to tracefs (see section 2).

#### 2. Configure tracefs Access (Non-Persistent)

These commands will work until the next system reboot:

```bash
# Create a tracing group and add your user to it
sudo groupadd -r tracing
sudo usermod -aG tracing $USER

# Set permissions on debugfs and tracefs
sudo mount -o remount,mode=755 /sys/kernel/debug
sudo chgrp -R tracing /sys/kernel/debug/tracing
sudo chmod -R g+rwx /sys/kernel/debug/tracing

# Log out and log back in for group changes to take effect
```

#### 3. Configure Persistent tracefs Access

For persistent configuration that survives system reboots, we provide setup tools in the `setup/` directory:

```bash
# Run the automated setup script
sudo ./setup/setup_tracefs_permissions.sh

# Log out and log back in for group changes to take effect
```

The setup script:
- Creates a 'tracing' group
- Adds your user to the group
- Creates a systemd service for persistent tracefs permissions
- Sets up systemd mount overrides for debugfs
- Configures kernel parameters for eBPF access
- Sets permissions for the current session

## Troubleshooting

If you encounter issues with eBPF:

1. **Verify kernel support**:
   ```bash
   grep CONFIG_BPF /boot/config-$(uname -r)
   ```
   Should show `CONFIG_BPF=y` and related options.

2. **Check ALL critical kernel settings**:
   ```bash
   # All of these must be correct for non-root eBPF to work
   cat /proc/sys/kernel/unprivileged_bpf_disabled  # Must be 0
   cat /proc/sys/kernel/kptr_restrict              # Must be 0 (CRITICAL!)
   cat /proc/sys/kernel/perf_event_paranoid        # Check value (2 may cause issues)
   ```

3. **Test tracefs access**:
   ```bash
   ls -la /sys/kernel/debug/tracing/events/syscalls
   ```
   You should be able to read this directory.

4. **Verify capabilities**:
   ```bash
   getcap /path/to/denet/target/release/denet
   ```
   Should show `cap_dac_read_search,cap_perfmon,cap_bpf=ep`.

5. **Check if you're in the tracing group**:
   ```bash
   groups $USER | grep tracing
   ```

6. **Run the eBPF diagnostic tool**:
   ```bash
   # Build the diagnostic tool
   cargo build --release --bin ebpf_diag --features ebpf
   
   # Set capabilities
   sudo setcap cap_bpf,cap_perfmon,cap_dac_read_search=ep target/release/ebpf_diag
   
   # Run diagnostics
   ./target/release/ebpf_diag --debug
   ```

### Common Issues and Solutions

1. **"Invalid ELF header size or alignment" error**:
   - Check `kernel.kptr_restrict` is set to 0
   - Verify both CAP_BPF and CAP_PERFMON are set

2. **"No eBPF data available from monitored PIDs"**:
   - Make sure the monitored process actually makes syscalls
   - Commands like `sleep` make very few syscalls - try `wget` or file operations instead

3. **Works with sudo but not with capabilities**:
   - Almost always due to `kernel.kptr_restrict` not being 0
   - Check all kernel settings listed above

## Using eBPF Features

To enable eBPF profiling when running denet:

```bash
denet --enable-ebpf run -- your_command_here
```

This will provide additional metrics about syscall usage and process behavior.

## Syscall Tracking and Categorization

Denet tracks individual syscalls using eBPF tracepoints and categorizes them into functional groups to help analyze application behavior patterns. The system monitors the following syscalls:

- read, write, openat, close (file operations)
- mmap (memory management)
- socket, connect, recvfrom, sendto (network operations)

The syscalls are then categorized into these functional groups:

| Category    | Description                                              | Example Syscalls                                         |
|-------------|----------------------------------------------------------|----------------------------------------------------------|
| `file_io`   | File and I/O operations                                  | read, write, open, close, lseek, openat                   |
| `memory`    | Memory allocation and management                         | mmap, munmap, brk, rt_sigaction                           |
| `process`   | Process and thread management                            | clone, fork, execve, exit, wait4                          |
| `network`   | Network-related operations                               | socket, connect, accept, sendto, recvfrom                 |
| `time`      | Time and scheduling operations                           | nanosleep, gettimeofday, clock_gettime                    |
| `ipc`       | Inter-process communication                              | msgget, semget, shmget, msgsnd, semop                     |
| `security`  | Permission and security operations                       | chmod, chown, capget, capset                              |
| `signal`    | Signal handling operations                               | rt_sigaction, rt_sigprocmask, kill                        |
| `system`    | System configuration and information                     | sysinfo, uname, reboot                                    |
| `other`     | Uncategorized syscalls                                   | Any syscall not in the above categories                   |

### Example Output

When eBPF profiling is enabled, JSON output will include additional fields:

```json
"ebpf": {
  "syscalls": {
    "total": 270795,
    "by_category": {
      "file_io": 162477,
      "memory": 40619,
      "network": 27080,
      "time": 13540,
      "process": 8124,
      "signal": 5416,
      "system": 5416,
      "security": 2708,
      "ipc": 2708,
      "other": 2708
    },
    "top_syscalls": [
      {"name": "read", "count": 81239},
      {"name": "write", "count": 54159},
      {"name": "openat", "count": 27080},
      {"name": "close", "count": 21664},
      {"name": "mmap", "count": 13540},
      {"name": "socket", "count": 13540}
    ],
    "analysis": {
      "syscall_rate_per_sec": 32295.16,
      "io_intensity": 0.6,
      "memory_intensity": 0.15,
      "cpu_intensity": 0.0,
      "network_intensity": 0.1
    }
  }
}
```

The `top_syscalls` field shows the most frequently called syscalls with their actual counts, and the `by_category` field shows how these syscalls are distributed across functional categories. The intensity fields are fractions of total tracked syscalls (uncategorized syscalls are excluded, so they do not sum to 1.0).

## Per-Process Network Bytes

With eBPF enabled, denet reports network bytes attributed to the monitored
process tree — unlike the `sys_net_rx_bytes`/`sys_net_tx_bytes` fields, which
remain a system-wide approximation from `/proc/net/dev` and are kept as the
fallback when eBPF is unavailable.

**How it works:** kprobes on the socket-layer send/receive paths
(`tcp_sendmsg`/`tcp_recvmsg`, `udp_sendmsg`/`udp_recvmsg`) run in process
context, so every byte is attributed by the kernel to the calling process. A
BPF-side PID filter, synced with the process tree each sample, restricts
accounting to the monitored tree.

**Semantics:**

- Cumulative since monitoring started, including bytes from children that
  have already exited (totals never decrease).
- RX counts bytes actually returned to userspace; TX counts bytes requested
  at the socket layer (a failed send may overcount slightly).
- Socket-layer application bytes: no TCP/IP headers, no retransmissions.
- Covers TCP over IPv4 and IPv6, and UDP over IPv4. UDP over IPv6 uses
  separate kernel entry points (`udpv6_sendmsg`) and is not yet counted.
- Children that transfer bytes between fork and the next sample are picked
  up at the next PID-filter sync (same window as syscall tracking).

**JSON output** (inside the aggregated metrics' `ebpf` object):

```json
"network": {
  "rx_bytes": 10019992,
  "tx_bytes": 747,
  "per_pid": {
    "4123": { "rx_bytes": 10019992, "tx_bytes": 512 },
    "4130": { "rx_bytes": 0, "tx_bytes": 235 }
  },
  "retired": { "rx_bytes": 0, "tx_bytes": 0 }
}
```

`rx_bytes`/`tx_bytes` are the tree totals (authoritative). `per_pid` breaks
the bytes out by live PID (root + current children), omitted while empty.
`retired` holds bytes from children that have already exited and are no longer
attributable to a live PID, omitted while zero. The three reconcile exactly:
`sum(per_pid) + retired == {rx,tx}_bytes`, so a report's breakdown always adds
up to the totals. If eBPF could not attach (missing capabilities), the object
carries an `error` string instead of silently reporting zeros as real data.

**From Python:** pass `enable_ebpf=True` to `execute_with_monitoring` (or the
`ProcessMonitor` constructors). This only does anything when the extension was
built with the eBPF feature — the published wheels are eBPF-free, so build it
yourself on Linux with `pixi run develop-ebpf` (needs clang). Without the
feature, or without capabilities, the flag degrades to a logged warning. See
`python/examples/network_children.sh` for an end-to-end run.

**Required capabilities** are the same as the rest of the eBPF features
(`cap_bpf,cap_perfmon,cap_dac_read_search` — see above). To verify the whole
capability matrix, including graceful degradation without caps and real data
with caps-but-no-root:

```bash
./scripts/test_ebpf_caps.sh            # Phases A (no caps) + B (setcap)
./scripts/test_ebpf_caps.sh --with-root
```

The privileged integration tests can also be run directly:

```bash
sudo -E cargo test --features ebpf --test ebpf_net_monitor_tests -- --ignored
```

## Implementation Details

The eBPF implementation works by:

1. **Tracepoint Attachment**: Attaching to syscall tracepoints (sys_enter_read, sys_enter_write, etc.)
2. **Per-syscall Tracking**: Maintaining a map of (PID, syscall_nr) → count
3. **Category Mapping**: Categorizing each syscall into functional groups
4. **Runtime Analysis**: Analyzing syscall patterns to detect performance bottlenecks

## Current Limitations

The current eBPF implementation has some limitations:

1. **Limited Syscall Coverage**: Only tracks a subset of common syscalls (read, write, openat, close, mmap, socket, connect, recvfrom, sendto).

2. **Sampling Windows**: The implementation shows syscalls that occurred during the monitoring window, which may not represent the application's entire execution profile for short-lived processes.

3. **Linux-only**: The eBPF functionality is only available on Linux systems with kernel version 4.18+ for full functionality.

## Future Enhancements

Planned improvements include:
1. Expanded syscall tracepoint coverage
2. More detailed syscall arguments analysis
3. Per-thread tracking in addition to per-process
4. Flame graph visualization of syscall patterns
