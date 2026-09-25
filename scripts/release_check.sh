#!/usr/bin/env bash
# Pre-release gate for the features CI can't exercise: GPU, RAPL, and eBPF
# end to end through the CLI, on this host and across the kernels in /boot.
#
#   1. cargo test (unprivileged)
#   2. eBPF capability matrix on the host kernel (scripts/test_ebpf_caps.sh)
#   3. End-to-end CLI run as root: eBPF net bytes > 0, GPU found (if
#      nvidia-smi works), RAPL energy > 0 (if powercap exists)
#   4. eBPF net tests + end-to-end eBPF check under every kernel in /boot,
#      via virtme-ng (skipped if `vng` is not installed)
#
# Usage: ./scripts/release_check.sh [KERNEL_GLOB]   (default: /boot/vmlinuz-*)
# Internal: --as-root NAME GPU RAPL [NET_TEST_BIN] is what steps 3 and 4 run
# as root (on the host via sudo, in each guest via vng).

set -uo pipefail
cd "$(dirname "$0")/.."

DENET=target/release/denet
OUT_DIR=$(mktemp -d)
FAILED=0
pass() { echo "PASS  $1"; }
fail() { echo "FAIL  $1"; FAILED=1; }

# One process sends and receives ~2 MB over loopback, so its own pid (the
# one denet seeds the BPF filter with) must see both rx and tx.
TRAFFIC='import http.server,threading,urllib.request,time
s=http.server.HTTPServer(("127.0.0.1",0),type("H",(http.server.BaseHTTPRequestHandler,),{"do_GET":lambda h:(h.send_response(200),h.end_headers(),h.wfile.write(b"x"*(1<<20))),"log_message":lambda *a:None}))
threading.Thread(target=s.serve_forever,daemon=True).start()
time.sleep(0.5)
[urllib.request.urlopen("http://127.0.0.1:%d/"%s.server_port).read() for _ in range(2)]
time.sleep(1)'

# e2e JSONL_PATH EXPECT_GPU EXPECT_RAPL — assert on the last tree sample.
check_jsonl() {
    python3 - "$@" <<'EOF'
import json, sys
path, want_gpu, want_rapl = sys.argv[1], sys.argv[2] == "1", sys.argv[3] == "1"
samples = [d["aggregated"] for d in map(json.loads, open(path)) if "aggregated" in d]
if not samples:
    sys.exit("no samples recorded")
last, errs = samples[-1], []
net = (last.get("ebpf") or {}).get("network") or {}
if net.get("error"):
    errs.append(f"eBPF net error: {net['error']}")
if net.get("rx_bytes", 0) < 1 << 20 or net.get("tx_bytes", 0) == 0:
    errs.append(f"eBPF net bytes too low: rx={net.get('rx_bytes')} tx={net.get('tx_bytes')}")
if want_gpu and not (last.get("gpu") or {}).get("system_metrics"):
    errs.append("no GPU devices in samples")
if want_rapl and not (last.get("rapl") or {}).get("package_joules"):
    errs.append("no RAPL energy in samples")
if errs:
    sys.exit("; ".join(errs))
EOF
}

e2e() { # name, expect_gpu, expect_rapl
    local out="$OUT_DIR/e2e.jsonl" msg=""
    if "$DENET" --enable-ebpf -q -o "$out" run -- python3 -c "$TRAFFIC" >/dev/null 2>&1 \
        && msg=$(check_jsonl "$out" "$2" "$3" 2>&1); then
        pass "$1"
    else
        fail "$1: ${msg:-denet run failed}"
    fi
}

net_test_bin() {
    cargo test --release --features ebpf,gpu --test ebpf_net_monitor_tests --no-run \
        --message-format=json 2>/dev/null |
        jq -r 'select(.executable != null and .target.name == "ebpf_net_monitor_tests") | .executable'
}

if [[ "${1:-}" == "--as-root" ]]; then
    ip link set lo up 2>/dev/null
    if [[ -n "${5:-}" ]]; then
        DENET_EXPECT_EBPF=1 "$5" --include-ignored >"$OUT_DIR/log" 2>&1 \
            && pass "$2: net tests" || { fail "$2: net tests"; sed 's/^/      /' "$OUT_DIR/log"; }
    fi
    e2e "$2: e2e" "$3" "$4"
    rm -rf "$OUT_DIR"
    exit $FAILED
fi

KERNELS=${1:-/boot/vmlinuz-*}
sudo -v || exit 1

echo "== build"
cargo build --release --features gpu,ebpf --bin denet || exit 1
NET_BIN=$(net_test_bin)
[[ -x "$NET_BIN" ]] || { echo "error: net test binary not found" >&2; exit 1; }

echo "== 1. cargo test"
cargo test --release --features ebpf,gpu >"$OUT_DIR/cargo.log" 2>&1 \
    && pass "cargo test" || { fail "cargo test"; grep -E 'FAILED|panicked' "$OUT_DIR/cargo.log" | sed 's/^/      /'; }

echo "== 2. eBPF capability matrix ($(uname -r))"
./scripts/test_ebpf_caps.sh --with-root || FAILED=1

echo "== 3. end to end ($(uname -r))"
GPU=0; nvidia-smi -L >/dev/null 2>&1 && GPU=1
RAPL=0; [[ -e /sys/class/powercap/intel-rapl:0/energy_uj ]] && RAPL=1
echo "      expecting GPU=$GPU RAPL=$RAPL"
sudo ./scripts/release_check.sh --as-root host "$GPU" "$RAPL" || FAILED=1

echo "== 4. kernels"
if ! command -v vng >/dev/null; then
    echo "SKIP  vng not installed (pipx install virtme-ng)"
else
    for k in $KERNELS; do
        echo "-- $k"
        # ponytail: one guest boot per kernel, sequential; parallelise if the list grows
        vng --user root -r "$k" -- "$PWD/scripts/release_check.sh" --as-root "$(basename "$k")" 0 0 "$NET_BIN" || FAILED=1
    done
fi

rm -rf "$OUT_DIR"
echo
[[ $FAILED -eq 0 ]] && echo "ALL CHECKS PASSED" || echo "SOME CHECKS FAILED"
exit $FAILED
