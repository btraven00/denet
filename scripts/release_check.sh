#!/usr/bin/env bash
# Pre-release gate for the features CI can't exercise: GPU, RAPL, and eBPF
# end to end through the CLI, on this host and across kernels.
#
#   1. cargo test (unprivileged)
#   2. eBPF capability matrix on the host kernel (scripts/test_ebpf_caps.sh)
#   3. End-to-end CLI run as root: eBPF net bytes > 0, GPU found (if
#      nvidia-smi works), RAPL energy > 0 (if powercap exists)
#  3b. Same with a static musl build (no GPU: NVML can't be loaded from a
#      static binary). Skipped if the x86_64-unknown-linux-musl target is
#      not installed (rustup target add x86_64-unknown-linux-musl)
#   4. eBPF net tests + end-to-end eBPF check under each KERNEL in a
#      virtme-ng VM (skipped if `vng` is not installed)
#
# Usage: ./scripts/release_check.sh [KERNEL...]
#   KERNEL is a kernel image (/boot/vmlinuz-6.8.0-1062-nvidia) or an upstream
#   version (v6.6.17), which vng downloads from the Ubuntu mainline builds.
#   Default: every /boot/vmlinuz-*. Needs sudo; see docs/dev.md.
#
# Internal: --as-root NAME GPU RAPL [NET_TEST_BIN] is what steps 3 and 4 run
# as root (on the host via sudo, in each guest via vng).

set -uo pipefail
cd "$(dirname "$0")/.."

DENET=${DENET:-target/release/denet}
MUSL=x86_64-unknown-linux-musl
OUT_DIR=$(mktemp -d)
FAILED=0
pass() { echo "PASS  $1"; }
fail() { echo "FAIL  $1"; FAILED=1; }
step() { # title, what it proves
    printf '\n== %s\n' "$1"
    printf '   %s\n' "$2" | fold -s -w 76 | sed '2,$s/^/   /'
}

if [[ "${1:-}" == "-h" || "${1:-}" == "--help" ]]; then
    sed -n '2,/^$/s/^# \{0,1\}//p' "$0"
    exit 0
fi

# One process sends and receives ~2 MB over loopback, so its own pid (the
# one denet seeds the BPF filter with) must see both rx and tx. Traffic starts
# immediately on purpose: bytes sent before the probes attach are lost, and a
# short job must still be counted.
TRAFFIC='import http.server,threading,urllib.request,time
s=http.server.HTTPServer(("127.0.0.1",0),type("H",(http.server.BaseHTTPRequestHandler,),{"do_GET":lambda h:(h.send_response(200),h.end_headers(),h.wfile.write(b"x"*(1<<20))),"log_message":lambda *a:None}))
threading.Thread(target=s.serve_forever,daemon=True).start()
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
    if "$DENET" --enable-ebpf -q -o "$out" run -- python3 -c "$TRAFFIC" >/dev/null 2>"$OUT_DIR/denet.err" \
        && msg=$(check_jsonl "$out" "$2" "$3" 2>&1); then
        pass "$1"
    else
        fail "$1: ${msg:-denet run failed}"
        tail -5 "$OUT_DIR/denet.err" | sed 's/^/      denet: /'
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

if [[ $# -gt 0 ]]; then KERNELS=("$@"); else KERNELS=(/boot/vmlinuz-*); fi
sudo -v || exit 1

step "build" "denet and the eBPF test binary, release mode, with gpu+ebpf."
cargo build --release --features gpu,ebpf --bin denet || exit 1
NET_BIN=$(net_test_bin)
[[ -x "$NET_BIN" ]] || { echo "error: net test binary not found" >&2; exit 1; }

step "1. cargo test" "Full Rust suite, unprivileged. eBPF-dependent tests must degrade cleanly without permissions."
cargo test --release --features ebpf,gpu >"$OUT_DIR/cargo.log" 2>&1 \
    && pass "cargo test" || { fail "cargo test"; grep -E 'FAILED|panicked' "$OUT_DIR/cargo.log" | sed 's/^/      /'; }

step "2. eBPF permissions ($(uname -r))" "The net monitor must degrade with no capabilities (A), and count real bytes with setcap (B) and as root (C), incl. the root-only tests."
./scripts/test_ebpf_caps.sh --with-root || FAILED=1

GPU=0; nvidia-smi -L >/dev/null 2>&1 && GPU=1
RAPL=0; [[ -e /sys/class/powercap/intel-rapl:0/energy_uj ]] && RAPL=1
step "3. end to end ($(uname -r))" "\`denet run --enable-ebpf\` as root on a job that moves 2 MB over loopback from its first instant. Must record eBPF net bytes$( ((GPU)) && echo ", a GPU")$( ((RAPL)) && echo ", RAPL energy")."
sudo ./scripts/release_check.sh --as-root host "$GPU" "$RAPL" || FAILED=1

step "3b. end to end, static musl binary" "Same as 3 with a fully static build. eBPF and RAPL must work; GPU is not expected (NVML is a glibc library a static binary can't load)."
if ! rustup target list --installed 2>/dev/null | grep -qx "$MUSL"; then
    echo "SKIP  $MUSL target not installed (rustup target add $MUSL)"
elif ! cargo build -q --release --target "$MUSL" --features ebpf --bin denet; then
    fail "musl build"
else
    sudo env DENET="target/$MUSL/release/denet" ./scripts/release_check.sh --as-root host-musl 0 "$RAPL" || FAILED=1
fi

step "4. kernels (${#KERNELS[@]})" "Step 2's root-only net tests and step 3's eBPF check, inside a VM per kernel (no GPU/RAPL in guests)."
if ! command -v vng >/dev/null; then
    echo "SKIP  vng not installed (pipx install virtme-ng)"
else
    for k in "${KERNELS[@]}"; do
        echo "-- $k"
        # ponytail: one guest boot per kernel, sequential; parallelise if the list grows
        if [[ -f "$k" ]]; then
            # distro kernels in /boot are root-only (0600); vng runs as us
            run="$OUT_DIR/$(basename "$k")"
            sudo install -m 0644 "$k" "$run" || { fail "$k: copy"; continue; }
        else
            run=$k # upstream version: vng downloads it (first run only)
        fi
        vng --user root -r "$run" -- "$PWD/scripts/release_check.sh" --as-root "$(basename "$k")" 0 0 "$NET_BIN" || FAILED=1
    done
fi

rm -rf "$OUT_DIR"
echo
[[ $FAILED -eq 0 ]] && echo "ALL CHECKS PASSED" || echo "SOME CHECKS FAILED"
exit $FAILED
