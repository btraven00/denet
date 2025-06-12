# eBPF Setup Tools for DeNet

This directory contains tools and configuration files to help set up the necessary permissions for DeNet to use eBPF tracepoints without requiring root privileges.

## Problem

By default, eBPF tracepoints require:

1. The `CAP_BPF` and `CAP_PERFMON` capabilities (for loading eBPF programs and accessing performance monitoring)
2. Access to the tracefs filesystem at `/sys/kernel/debug/tracing` (typically restricted to root)
3. Proper kernel settings, particularly `kernel.kptr_restrict=0` (CRITICAL!)

While capabilities can be added to the binary with `setcap`, the tracefs filesystem permissions are not persistent across system reboots when modified manually.

## Solution

This directory provides several tools to configure persistent permissions:

### `setup_tracefs_permissions.sh`

A comprehensive setup script that:

- Creates a 'tracing' group
- Adds the current user to the group
- Creates and enables a systemd service for persistent tracefs permissions
- Sets up systemd mount overrides for debugfs
- Configures kernel parameters for eBPF access
- Sets permissions for the current session

Usage:

```bash
sudo ./setup_tracefs_permissions.sh
```

After running, log out and log back in for the group changes to take effect.

### `tracefs-permissions.service`

A systemd service that sets the appropriate permissions on the tracefs filesystem during system boot.

### `99-tracefs.rules`

A udev rules file that sets permissions on tracefs directories when they're created.

## Manual Installation

If the automated script doesn't work for your system, you can manually install the components:

1. Create the tracing group:
   ```bash
   sudo groupadd -r tracing
   ```

2. Add your user to the group:
   ```bash
   sudo usermod -aG tracing $USER
   ```

3. Install the systemd service:
   ```bash
   sudo cp tracefs-permissions.service /etc/systemd/system/
   sudo systemctl daemon-reload
   sudo systemctl enable tracefs-permissions.service
   sudo systemctl start tracefs-permissions.service
   ```

4. Install the udev rules:
   ```bash
   sudo cp 99-tracefs.rules /etc/udev/rules.d/
   sudo udevadm control --reload-rules
   sudo udevadm trigger
   ```

5. Create a systemd mount override for debugfs:
   ```bash
   sudo mkdir -p /etc/systemd/system/sys-kernel-debug.mount.d/
   echo -e "[Mount]\nOptions=mode=755" | sudo tee /etc/systemd/system/sys-kernel-debug.mount.d/override.conf
   sudo systemctl daemon-reload
   ```

6. Set kernel parameters (CRITICAL):
   ```bash
   # These are REQUIRED for eBPF to work with capabilities
   echo "kernel.unprivileged_bpf_disabled=0" | sudo tee /etc/sysctl.d/10-ebpf.conf
   echo "kernel.kptr_restrict=0" | sudo tee -a /etc/sysctl.d/10-ebpf.conf
   
   # Apply immediately
   sudo sysctl -w kernel.unprivileged_bpf_disabled=0
   sudo sysctl -w kernel.kptr_restrict=0
   
   # Check perf_event_paranoid (warn if > 1)
   sysctl kernel.perf_event_paranoid
   ```

## Verifying the Setup

After installation and logging back in, you can verify that the setup is working:

```bash
ls -la /sys/kernel/debug/tracing/events/syscalls
```

If you can access this directory, the permissions are set correctly.

Set the required capabilities on the binary:

```bash
sudo setcap cap_bpf,cap_perfmon=ep target/release/denet
```

Then try running DeNet with eBPF enabled (use a command that makes syscalls):

```bash
denet --enable-ebpf run -- wget https://example.com
```

## Troubleshooting

If you still encounter issues:

1. Make sure you've logged out and back in after running the setup
2. Check if your user is in the tracing group: `groups $USER`
3. Verify the critical kernel settings:
   ```bash
   sysctl kernel.unprivileged_bpf_disabled  # Must be 0
   sysctl kernel.kptr_restrict              # Must be 0 (CRITICAL!)
   sysctl kernel.perf_event_paranoid        # Warn if > 1
   ```
4. Verify capabilities are set: `getcap target/release/denet`
5. Check the systemd service status: `systemctl status tracefs-permissions.service`
6. Try running with `sudo` to see if the issue is permissions-related
7. Use the diagnostic tool: `./target/release/ebpf_diag --debug`