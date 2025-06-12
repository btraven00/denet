#!/bin/bash
#
# Setup script for configuring tracefs permissions to allow
# non-root users to use eBPF tracepoints
#

set -e

# Parse command line arguments
DEBUG_MODE=false
for arg in "$@"; do
  case "$arg" in
    --debug)
      DEBUG_MODE=true
      ;;
  esac
done

# Logging functions
function log_info() {
    echo "[INFO] $1"
}

function log_debug() {
    if [ "$DEBUG_MODE" = true ]; then
        echo "[DEBUG] $1"
    fi
}

function log_error() {
    echo "[ERROR] $1" >&2
}

function log_success() {
    echo "[SUCCESS] $1"
}

if [ "$DEBUG_MODE" = true ]; then
    log_info "Debug mode enabled - showing verbose output"
fi

log_info "Starting eBPF permissions setup script (use --debug for verbose output)"

# Check if running as root
if [ "$EUID" -ne 0 ]; then
  log_error "This script must be run as root"
  log_error "Please run with: sudo $0"
  exit 1
fi

log_info "Setting up persistent tracefs permissions for eBPF..."

# Check kernel version
KERNEL_VERSION=$(uname -r)
log_debug "Kernel version: $KERNEL_VERSION"
log_debug "Debug mode: $DEBUG_MODE"

# Check if debugfs is mounted
if mount | grep -q "debugfs on /sys/kernel/debug"; then
    log_debug "Debugfs is mounted at /sys/kernel/debug"
else
    log_debug "Debugfs is not mounted, attempting to mount..."
    mount -t debugfs none /sys/kernel/debug 2>/dev/null || log_error "Failed to mount debugfs"
fi

# Check current debugfs permissions
log_debug "Current debugfs permissions: $(ls -la /sys/kernel/debug | head -n 1)"

# Check if tracefs exists
if [ -d "/sys/kernel/debug/tracing" ]; then
    log_debug "Tracefs exists at /sys/kernel/debug/tracing"
    log_debug "Current tracefs permissions: $(ls -la /sys/kernel/debug/tracing | head -n 1)"
else
    log_error "Tracefs directory does not exist at /sys/kernel/debug/tracing"
    log_error "Your kernel may not support eBPF tracing features"
    exit 1
fi

# Check BPF support
if [ -e "/proc/sys/kernel/bpf_jit_enable" ]; then
    BPF_JIT=$(cat /proc/sys/kernel/bpf_jit_enable)
    log_debug "BPF JIT compilation is $([ "$BPF_JIT" -eq 1 ] && echo "enabled" || echo "disabled")"
else
    log_debug "BPF JIT compilation status cannot be determined"
fi

if [ -e "/proc/sys/kernel/unprivileged_bpf_disabled" ]; then
    UNPRIV_BPF=$(cat /proc/sys/kernel/unprivileged_bpf_disabled)
    log_debug "Unprivileged BPF is $([ "$UNPRIV_BPF" -eq 0 ] && echo "enabled" || echo "disabled")"
else
    log_debug "Unprivileged BPF status cannot be determined"
fi

# Create tracing group if it doesn't exist
if ! getent group tracing > /dev/null; then
    log_info "Creating 'tracing' group..."
    if groupadd -r tracing; then
        log_debug "Tracing group created successfully"
    else
        log_error "Failed to create tracing group"
        exit 1
    fi
else
    log_info "'tracing' group already exists"
    log_debug "Tracing group details: $(getent group tracing)"
fi

# Add current user to tracing group
if [ -n "$SUDO_USER" ]; then
    log_info "Adding user $SUDO_USER to 'tracing' group..."
    if usermod -aG tracing "$SUDO_USER"; then
        log_debug "User $SUDO_USER added to tracing group"
        log_debug "User groups: $(groups $SUDO_USER)"
    else
        log_error "Failed to add user to tracing group"
    fi
else
    log_error "Could not determine original user, not adding to 'tracing' group"
    log_error "You may need to manually run: sudo usermod -aG tracing YOUR_USERNAME"
fi

# Create systemd service file for persistent permissions
log_info "Creating systemd service for persistent tracefs permissions..."
log_debug "Writing to /etc/systemd/system/tracefs-permissions.service"
cat > /etc/systemd/system/tracefs-permissions.service << 'EOF'
[Unit]
Description=Set permissions on tracefs for eBPF access
After=sys-kernel-debug.mount
Requires=sys-kernel-debug.mount

[Service]
Type=oneshot
ExecStart=/bin/bash -c "mount -o remount,mode=755 /sys/kernel/debug && chmod -R g+rwx /sys/kernel/debug/tracing && chgrp -R tracing /sys/kernel/debug/tracing"
RemainAfterExit=yes

[Install]
WantedBy=multi-user.target
EOF

# Create systemd mount override for debugfs
log_info "Creating systemd mount override for debugfs..."
log_debug "Creating directory /etc/systemd/system/sys-kernel-debug.mount.d/"
mkdir -p /etc/systemd/system/sys-kernel-debug.mount.d/
log_debug "Writing to /etc/systemd/system/sys-kernel-debug.mount.d/override.conf"
cat > /etc/systemd/system/sys-kernel-debug.mount.d/override.conf << 'EOF'
[Mount]
Options=mode=755
EOF

# Reload systemd configuration
log_info "Reloading systemd configuration..."
if systemctl daemon-reload; then
    log_debug "Systemd configuration reloaded successfully"
else
    log_error "Failed to reload systemd configuration"
fi

# Enable and start the service
log_info "Enabling and starting tracefs-permissions service..."
if systemctl enable tracefs-permissions.service; then
    log_debug "Service enabled successfully"
else
    log_error "Failed to enable service"
fi

if systemctl start tracefs-permissions.service; then
    log_debug "Service started successfully"
    log_debug "Service status: $(systemctl is-active tracefs-permissions.service)"
else
    log_error "Failed to start service"
    log_debug "Service status output: $(systemctl status tracefs-permissions.service 2>&1 | head -n 10)"
fi

# Set permissions for current session
log_info "Setting permissions for current session..."
log_debug "Remounting debugfs with mode=755..."
if mount -o remount,mode=755 /sys/kernel/debug; then
    log_debug "Debugfs remounted successfully"
    log_debug "New debugfs permissions: $(ls -la /sys/kernel/debug | head -n 1)"
else
    log_error "Failed to remount debugfs"
fi

log_debug "Setting group permissions on tracefs..."
if chmod -R g+rwx /sys/kernel/debug/tracing; then
    log_debug "Chmod successful"
else
    log_error "Failed to set permissions on tracefs"
fi

log_debug "Changing group ownership to tracing..."
if chgrp -R tracing /sys/kernel/debug/tracing; then
    log_debug "Chgrp successful"
    log_debug "New tracefs permissions: $(ls -la /sys/kernel/debug/tracing | head -n 1)"
else
    log_error "Failed to change group ownership"
fi

# Verify permissions
log_debug "Verifying permissions..."
if [ -r "/sys/kernel/debug/tracing/events/syscalls" ]; then
    log_debug "Syscalls events directory is readable"
else
    log_error "Syscalls events directory is not readable"
fi

# Test actual eBPF access
log_debug "Testing write access to tracefs..."
if touch /sys/kernel/debug/tracing/test_file 2>/dev/null; then
    log_debug "Successfully created test file"
    rm -f /sys/kernel/debug/tracing/test_file
else
    log_error "Failed to create test file in tracefs"
fi

# Check critical kernel settings for eBPF
log_info "Checking critical kernel settings for eBPF..."

# 1. Check unprivileged_bpf_disabled
UNPRIVILEGED_BPF=$(sysctl -n kernel.unprivileged_bpf_disabled 2>/dev/null || echo "unknown")
log_debug "kernel.unprivileged_bpf_disabled: $UNPRIVILEGED_BPF"

if [ "$UNPRIVILEGED_BPF" != "0" ]; then
    log_info "Setting kernel.unprivileged_bpf_disabled=0..."
    echo "kernel.unprivileged_bpf_disabled=0" >> /etc/sysctl.d/10-ebpf.conf
    if sysctl -w kernel.unprivileged_bpf_disabled=0; then
        log_debug "unprivileged_bpf_disabled set successfully"
    else
        log_error "Failed to set unprivileged_bpf_disabled"
    fi
else
    log_info "kernel.unprivileged_bpf_disabled is already set to 0"
fi

# 2. Check kptr_restrict (CRITICAL!)
KPTR_RESTRICT=$(sysctl -n kernel.kptr_restrict 2>/dev/null || echo "unknown")
log_debug "kernel.kptr_restrict: $KPTR_RESTRICT"

if [ "$KPTR_RESTRICT" != "0" ]; then
    log_info "Setting kernel.kptr_restrict=0 (CRITICAL for eBPF with capabilities)..."
    echo "kernel.kptr_restrict=0" >> /etc/sysctl.d/10-ebpf.conf
    if sysctl -w kernel.kptr_restrict=0; then
        log_success "kptr_restrict set to 0 - this is essential for non-root eBPF!"
    else
        log_error "Failed to set kptr_restrict - eBPF will NOT work without sudo!"
    fi
else
    log_info "kernel.kptr_restrict is already set to 0"
fi

# 3. Check perf_event_paranoid (warning only)
PERF_PARANOID=$(sysctl -n kernel.perf_event_paranoid 2>/dev/null || echo "unknown")
log_debug "kernel.perf_event_paranoid: $PERF_PARANOID"

if [ "$PERF_PARANOID" = "unknown" ]; then
    log_error "Could not read kernel.perf_event_paranoid"
elif [ "$PERF_PARANOID" -gt 1 ]; then
    log_error "WARNING: kernel.perf_event_paranoid is set to $PERF_PARANOID"
    log_error "This may prevent some eBPF operations from working properly"
    log_error "If you experience issues, consider lowering it:"
    log_error "  sudo sysctl kernel.perf_event_paranoid=1"
    log_error "  echo 'kernel.perf_event_paranoid=1' | sudo tee -a /etc/sysctl.conf"
else
    log_info "kernel.perf_event_paranoid is permissive ($PERF_PARANOID)"
fi

# Remove duplicates from sysctl config
if [ -f /etc/sysctl.d/10-ebpf.conf ]; then
    sort -u /etc/sysctl.d/10-ebpf.conf -o /etc/sysctl.d/10-ebpf.conf
    log_debug "Cleaned up /etc/sysctl.d/10-ebpf.conf"
fi

# Check BPF filesystem
if [ -d "/sys/fs/bpf" ]; then
    log_debug "BPF filesystem exists at /sys/fs/bpf"
    log_debug "Permissions: $(ls -la /sys/fs/bpf | head -n 1)"
else
    log_debug "BPF filesystem does not exist, attempting to mount..."
    if mount -t bpf bpffs /sys/fs/bpf 2>/dev/null; then
        log_debug "BPF filesystem mounted successfully"
    else
        log_debug "Failed to mount BPF filesystem (this is often normal)"
    fi
fi

# Final diagnostic checks
log_info "Performing final diagnostic checks..."

# Check if CAP_BPF capability is available
if grep -q cap_bpf /usr/include/linux/capability.h 2>/dev/null; then
    log_debug "CAP_BPF capability is defined in the system"
else
    log_error "CAP_BPF capability may not be supported on this kernel"
    log_error "Your kernel may be too old for proper eBPF support"
fi

# Test denet binary if available
DENET_PATH=$(which denet 2>/dev/null || echo "./target/release/denet")
if [ -f "$DENET_PATH" ]; then
    log_debug "Setting capabilities on denet binary at $DENET_PATH"
    if setcap cap_bpf,cap_perfmon=ep "$DENET_PATH" 2>/dev/null; then
        log_success "Set CAP_BPF and CAP_PERFMON on denet binary"
        log_debug "Current capabilities: $(getcap "$DENET_PATH" 2>/dev/null || echo "none")"
    else
        log_error "Failed to set capabilities on denet"
    fi
fi

# Also check for ebpf_diag binary
DIAG_PATH="./target/release/ebpf_diag"
if [ -f "$DIAG_PATH" ]; then
    log_debug "Setting capabilities on ebpf_diag binary at $DIAG_PATH"
    if setcap cap_bpf,cap_perfmon=ep "$DIAG_PATH" 2>/dev/null; then
        log_debug "Set capabilities on ebpf_diag"
    fi
fi

log_success "Setup complete! You may need to log out and log back in for group changes to take effect."
log_success "After that, you should be able to run denet with eBPF features without root privileges."
echo ""
log_info "Critical kernel settings configured:"
log_info "  - kernel.unprivileged_bpf_disabled = 0"
log_info "  - kernel.kptr_restrict = 0 (ESSENTIAL!)"
if [ "$PERF_PARANOID" -gt 1 ]; then
    log_info "  - kernel.perf_event_paranoid = $PERF_PARANOID (WARNING: may need adjustment)"
fi
echo ""
log_info "Usage: denet --enable-ebpf run -- your_command_here"
log_info "For verbose debugging: denet --enable-ebpf --debug run -- your_command_here"
echo ""
log_info "Setting capabilities on binaries:"
log_info "  sudo setcap cap_bpf,cap_perfmon=ep target/release/denet"
echo ""
log_info "To verify setup:"
log_info "  - Permissions: ls -la /sys/kernel/debug/tracing"
log_info "  - Capabilities: getcap target/release/denet"
log_info "  - Kernel settings: sysctl kernel.kptr_restrict kernel.unprivileged_bpf_disabled"
log_info "  - Run diagnostics: ./target/release/ebpf_diag --debug"
echo ""
log_debug "Final system state:"
log_debug "- Kernel version: $(uname -r)"
log_debug "- Debugfs mount: $(mount | grep debugfs || echo "not mounted")"
log_debug "- Tracefs permissions: $(ls -la /sys/kernel/debug/tracing | head -n 1)"
log_debug "- Unprivileged BPF: $(sysctl -n kernel.unprivileged_bpf_disabled 2>/dev/null || echo "unknown")"
log_debug "- Kptr restrict: $(sysctl -n kernel.kptr_restrict 2>/dev/null || echo "unknown")"
log_debug "- Perf paranoid: $(sysctl -n kernel.perf_event_paranoid 2>/dev/null || echo "unknown")"
log_debug "- User in tracing group: $(id -Gn $SUDO_USER 2>/dev/null | grep -q tracing && echo "yes" || echo "no (logout/login required)")"
log_debug "- Denet capabilities: $(getcap ./target/release/denet 2>/dev/null || echo "not set")"
