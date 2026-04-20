#!/usr/bin/env bash
# Grant the capabilities denet needs for eBPF tracepoint access without root.
#
# Required caps:
#   cap_bpf                - load BPF programs, create maps
#   cap_perfmon            - perf_event_open for tracepoints
#   cap_dac_read_search    - read /sys/kernel/tracing/events/*/id (root-owned 0400)
#
# Usage: sudo ./scripts/setup_ebpf_caps.sh [path/to/denet]
# Defaults to ./target/release/denet.

set -euo pipefail

BIN="${1:-./target/release/denet}"
CAPS="cap_bpf,cap_perfmon,cap_dac_read_search=ep"

if [[ $EUID -ne 0 ]]; then
    echo "error: must run as root (try: sudo $0 $*)" >&2
    exit 1
fi

if [[ ! -x "$BIN" ]]; then
    echo "error: $BIN not found or not executable" >&2
    exit 1
fi

BIN_ABS="$(readlink -f "$BIN")"
setcap "$CAPS" "$BIN_ABS"

echo "granted $CAPS on $BIN_ABS"
echo -n "verified: "
getcap "$BIN_ABS"
