#!/usr/bin/env bash
# Exercise the eBPF capability matrix for the net monitor:
#
#   Phase A  no caps, no root   → must degrade gracefully (error in metrics)
#   Phase B  setcap, no root    → must produce real data (the case that has
#                                 bitten us: caps instead of root)
#   Phase C  root (--with-root) → optional sanity pass
#
# Only the setcap calls use sudo; the tests themselves run as the invoking
# user. Usage: ./scripts/test_ebpf_caps.sh [--with-root]

set -uo pipefail

CAPS="cap_bpf,cap_perfmon,cap_dac_read_search=ep"
WITH_ROOT=0
[[ "${1:-}" == "--with-root" ]] && WITH_ROOT=1

if [[ $EUID -eq 0 ]]; then
    echo "error: run as a regular user (Phase A must be unprivileged); sudo is used only for setcap" >&2
    exit 1
fi

# --- preflight ---------------------------------------------------------------
KERNEL_MAJ_MIN=$(uname -r | cut -d. -f1-2)
if ! awk -v v="$KERNEL_MAJ_MIN" 'BEGIN{split(v,a,"."); exit !(a[1]>5 || (a[1]==5 && a[2]>=8))}'; then
    echo "warn: kernel $KERNEL_MAJ_MIN < 5.8 — CAP_BPF/CAP_PERFMON unavailable, Phase B will fail" >&2
fi
PARANOID=$(sysctl -n kernel.perf_event_paranoid 2>/dev/null || echo "?")
if [[ "$PARANOID" != "?" && "$PARANOID" -ge 3 ]]; then
    echo "warn: kernel.perf_event_paranoid=$PARANOID — the Ubuntu >=3 patch can block" >&2
    echo "      perf_event_open even with CAP_PERFMON; Phase B may fail" >&2
fi

# --- locate test binary ------------------------------------------------------
echo "building test binary..."
BIN=$(cargo test --features ebpf --test ebpf_net_monitor_tests --no-run --message-format=json 2>/dev/null \
    | jq -r 'select(.executable != null and .target.name == "ebpf_net_monitor_tests") | .executable')
if [[ -z "$BIN" || ! -x "$BIN" ]]; then
    echo "error: could not locate ebpf_net_monitor_tests binary" >&2
    exit 1
fi
echo "test binary: $BIN"

cleanup() { sudo setcap -r "$BIN" 2>/dev/null || true; }
trap cleanup EXIT

FAILED=0
LOG=$(mktemp)
report() { # name, exit_code — on failure, show the test output
    if [[ $2 -eq 0 ]]; then
        echo "PASS  $1"
    else
        echo "FAIL  $1"
        sed 's/^/      /' "$LOG"
        FAILED=1
    fi
}

# --- Phase A: no caps → graceful degradation --------------------------------
sudo setcap -r "$BIN" 2>/dev/null || true
DENET_EXPECT_EBPF_DENIED=1 "$BIN" test_net_monitor_graceful_degradation >"$LOG" 2>&1
report "Phase A: no caps degrades gracefully" $?

# --- Phase B: caps without root → real data ----------------------------------
echo "granting $CAPS (sudo)..."
if sudo setcap "$CAPS" "$BIN"; then
    DENET_EXPECT_EBPF=1 "$BIN" --include-ignored >"$LOG" 2>&1
    report "Phase B: caps without root, all tests incl. privileged" $?
else
    echo "FAIL  Phase B: setcap failed"; FAILED=1
fi

# --- Phase C: root (optional) -------------------------------------------------
if [[ $WITH_ROOT -eq 1 ]]; then
    sudo setcap -r "$BIN" 2>/dev/null || true
    sudo DENET_EXPECT_EBPF=1 "$BIN" --include-ignored >"$LOG" 2>&1
    report "Phase C: root, all tests incl. privileged" $?
fi
rm -f "$LOG"

exit $FAILED
