# eBPF Support

This is an experimental, gated feature that enables advanced system monitoring using eBPF tracepoints for tracking syscalls and other low-level events. The eBPF support provides detailed insights into a process's syscall patterns and resource utilization behaviors by tracking individual syscall types and frequencies.

## Prerequisites

To build with eBPF support, you need:

```bash
sudo apt install libbpf-dev clang libcap2-bin
```

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
1. The `CAP_BPF` and `CAP_PERFMON` capabilities
2. Access to the tracefs filesystem in `/sys/kernel/debug/tracing`
3. Proper kernel settings (see Prerequisites above)

#### 1. Add Required Capabilities to the Binary

```bash
# Required capabilities for eBPF tracepoint access
sudo setcap cap_bpf,cap_perfmon=ep /path/to/denet/target/release/denet

# Verify capabilities are set
getcap /path/to/denet/target/release/denet
# Should show: cap_perfmon,cap_bpf=ep
```

**Note**: Both `CAP_BPF` and `CAP_PERFMON` are required for tracepoint access on modern kernels (5.8+).

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
   Should show `cap_perfmon,cap_bpf=ep`.

5. **Check if you're in the tracing group**:
   ```bash
   groups $USER | grep tracing
   ```

6. **Run the eBPF diagnostic tool**:
   ```bash
   # Build the diagnostic tool
   cargo build --release --bin ebpf_diag --features ebpf
   
   # Set capabilities
   sudo setcap cap_bpf,cap_perfmon=ep target/release/ebpf_diag
   
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
      "behavior_classification": "io_bound",
      "syscall_rate_per_sec": 32295.16,
      "io_intensity": 0.6,
      "memory_intensity": 0.15,
      "cpu_intensity": 0.0,
      "network_intensity": 0.1
    }
  }
}
```

The `top_syscalls` field shows the most frequently called syscalls with their actual counts, and the `by_category` field shows how these syscalls are distributed across functional categories.

### Process Behavior Classification

Based on syscall patterns, denet classifies process behavior as:

- `io_bound`: Process primarily limited by I/O operations
- `cpu_bound`: Process primarily limited by CPU processing
- `memory_bound`: Process primarily limited by memory operations
- `network_bound`: Process primarily limited by network activity
- `mixed`: Process shows mixed resource utilization patterns
- `unknown`: Unable to determine clear behavior pattern

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
