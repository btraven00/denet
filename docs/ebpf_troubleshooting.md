# eBPF Troubleshooting Guide

This guide provides comprehensive troubleshooting steps for diagnosing and fixing eBPF-related issues in denet.

## Using Debug Mode

Most tools in this guide support a `--debug` flag that enables verbose output:

```bash
# Enable debug mode for detailed eBPF diagnostic information
denet --enable-ebpf --debug run -- your_command

# Run setup script with verbose output
sudo ./setup/setup_tracefs_permissions.sh --debug

# Run diagnostic tool with verbose output
cargo run --bin ebpf_diag --features ebpf -- --debug
```

## Quick Diagnosis Tool

We've included a diagnostic tool specifically for eBPF issues:

```bash
# Build and run the diagnostic tool
cargo run --bin ebpf_diag --features ebpf

# For even more verbose debugging output
cargo run --bin ebpf_diag --features ebpf -- --debug
```

This will perform a comprehensive check of your system's eBPF capabilities and provide specific recommendations to fix any issues.

## Common Issues and Solutions

### 1. Permission Denied Errors

**Symptoms:**
- "Permission denied" error messages
- eBPF features don't work even with sudo
- Error logs mention "operation not permitted"

**Solutions:**

#### Check if running as root
```bash
# Run with sudo
sudo denet --enable-ebpf run -- your_command
```

#### Verify CAP_BPF capability
```bash
# Check if the binary has the capability
getcap $(which denet)

# Add the capability if missing
sudo setcap cap_bpf+ep $(which denet)
```

#### Check tracefs permissions
```bash
# See if you can access tracefs
ls -la /sys/kernel/debug/tracing/events/syscalls

# Fix permissions using the setup script
sudo ./setup/setup_tracefs_permissions.sh
```

### 2. Missing Maps or Programs

**Symptoms:**
- "Map not found" or "Program not found" errors
- eBPF loads but doesn't track any syscalls

**Solutions:**

#### Check if the eBPF bytecode is properly built
```bash
# Clean and rebuild with eBPF feature
cargo clean
cargo build --release --features ebpf
```

#### Verify bytecode content
The diagnostic output will show information about the embedded bytecode. Make sure it contains:
- Proper ELF header
- Maps named "syscall_counts" and "pid_syscall_map"
- Tracepoint programs for syscalls

### 3. Kernel Support Issues

**Symptoms:**
- "Feature not supported" errors
- eBPF loads but fails to attach to tracepoints

**Solutions:**

#### Check kernel version
```bash
uname -r
```
You need kernel 4.18 or newer for full eBPF support.

#### Verify BPF is enabled in the kernel
```bash
grep CONFIG_BPF /boot/config-$(uname -r)
```
Should show `CONFIG_BPF=y`

#### Check JIT compilation
```bash
cat /proc/sys/net/core/bpf_jit_enable
```
Should be `1`

#### Check unprivileged BPF setting
```bash
cat /proc/sys/kernel/unprivileged_bpf_disabled
```
Should be `0` for non-root usage with capabilities.

### 4. Tracepoint Attachment Issues

**Symptoms:**
- "Failed to attach tracepoint" errors
- No syscalls being tracked

**Solutions:**

#### Check if tracefs is properly mounted
```bash
mount | grep debugfs
```

#### Verify specific tracepoints exist
```bash
ls -la /sys/kernel/debug/tracing/events/syscalls/sys_enter_read
```

#### Try with a simple syscall first
```bash
# Test just the read syscall
cargo run --bin ebpf_test --features ebpf
```

## Advanced Debugging

For detailed logging during eBPF initialization:

```bash
# Run with verbose logging
RUST_LOG=debug denet --enable-ebpf --debug run -- your_command 2>&1 | tee ebpf_debug.log
```

The enhanced debug output will show:
- Bytecode loading details
- Specific error messages and analysis
- Kernel configuration information
- Permissions and capability checks
- Map and program verification

## Recovering from Previous eBPF Sessions

If you've had a successful eBPF session that later stopped working:

1. Check for kernel updates that may have changed eBPF behavior
   ```bash
   dpkg -l | grep linux-image
   ```

2. Verify if any system configuration changed
   ```bash
   # Check if debugfs is still properly mounted
   mount | grep debugfs
   
   # Check if permissions changed
   ls -la /sys/kernel/debug/tracing
   ```

3. Run the setup script again
   ```bash
   sudo ./setup/setup_tracefs_permissions.sh

   # For verbose debugging output
   sudo ./setup/setup_tracefs_permissions.sh --debug
   ```

4. Reboot your system to reset any stuck eBPF state
   ```bash
   sudo reboot
   ```

## Regression Debugging

If eBPF was working previously but stopped working:

1. Check the diagnostic tool output first
   ```bash
   cargo run --bin ebpf_diag --features ebpf
   ```

2. Look for kernel log messages related to BPF
   ```bash
   dmesg | grep -i bpf
   ```

3. Verify if the binary still has the correct capabilities
   ```bash
   getcap $(which denet)
   ```

4. Test with the simplest eBPF program
   ```bash
   cargo run --bin ebpf_test --features ebpf
   ```

5. Check if another process might be using conflicting BPF resources
   ```bash
   sudo bpftool prog list
   ```

## Detailed Error Analysis

The enhanced debugging now automatically analyzes error types:

1. **Permission denied**: Indicates capability or privilege issues
2. **Not found**: Typically means tracefs or debugfs is not properly mounted
3. **Invalid argument**: Often caused by kernel version incompatibility
4. **Resource busy**: Another process may be using the same BPF resources

## Getting Help

If you've tried all these steps and still have issues:

1. Generate a complete diagnostic report:
   ```bash
   cargo run --bin ebpf_diag --features ebpf --debug > ebpf_report.txt
   ```

2. Share the report along with:
   - Your kernel version (`uname -r`)
   - OS distribution (`lsb_release -a`)
   - How you built denet (`cargo --version`)
   - Steps to reproduce the issue