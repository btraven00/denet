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
#  3d. Off-CPU stacks: a pipe writer and a sleeping reader must each be
#      charged with their wait and the kernel stack they waited in
#  3c. eBPF across a process tree: a job whose work is done by child
#      processes that exit before the end. Syscalls and off-CPU time must be
#      attributed to the children and survive their exit; run on the host
#      and again inside a new PID namespace (as in a container, kernel >= 5.7)
#  3e. GPU PCIe throughput: a CUDA host<->device copy loop must show up in
#      pcie_tx_kbps/pcie_rx_kbps (skipped without a GPU or nvcc)
#   4. eBPF net tests + end-to-end eBPF checks under each KERNEL in a
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
cd "$(dirname "$0")/.." || exit 1

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

# The work is done by children that exit before the job ends: dd makes
# ~2M read/write syscalls over ~0.7 s (long enough that denet's first samples
# find it), then ten short-lived sleeps go off-CPU for 0.1 s each. The parent
# shell does next to nothing itself.
TREE='dd if=/dev/zero of=/dev/null bs=1 count=1000000 status=none; for i in 1 2 3 4 5 6 7 8 9 10; do sleep 0.1; done'

# check_tree JSONL — assert on the last tree sample that eBPF followed the
# children (regressions fixed for 0.10.3: syscalls read only for live PIDs,
# off-CPU filtered against the start-time PID list, eBPF PIDs not in denet's
# namespace).
check_tree() {
    python3 - "$@" <<'EOF'
import json, sys
recs = [json.loads(l) for l in open(sys.argv[1])]
parent = next(r["pid"] for r in recs if r.get("kind") == "metadata")
samples = [r["aggregated"] for r in recs if "aggregated" in r]
if not samples:
    sys.exit("no samples recorded")
ebpf, errs = samples[-1].get("ebpf") or {}, []
calls = (ebpf.get("syscalls") or {}).get("total", 0)
# half of dd's ~2M: a child is added to the kernel filter at denet's next
# sample, so up to one interval of its syscalls can be missed
if calls < 1000000:
    errs.append(f"syscalls {calls} < 1000000: children's counts lost")
threads = (ebpf.get("offcpu") or {}).get("thread_stats") or {}
child_ns = sum(s["total_time_ns"] for k, s in threads.items() if int(k.split(":")[0]) != parent)
if child_ns < 5e8:
    errs.append(f"child off-CPU {child_ns / 1e9:.2f} s < 0.5 s: children not followed")
if errs:
    sys.exit("; ".join(errs))
EOF
}

e2e_tree() { # name, [wrapper...]: e.g. unshare --pid --fork --mount-proc
    local name=$1 out="$OUT_DIR/tree.jsonl" msg=""; shift
    if "$@" "$DENET" --enable-ebpf -q -o "$out" run -- bash -c "$TREE" >/dev/null 2>"$OUT_DIR/denet.err" \
        && msg=$(check_tree "$out" 2>&1); then
        pass "$name"
    else
        fail "$name: ${msg:-denet run failed}"
        tail -5 "$OUT_DIR/denet.err" | sed 's/^/      denet: /'
    fi
}

# A writer blocked on a full pipe and a sleeping reader: `yes` waits ~2 s in
# the kernel's pipe-write path and `sleep` in nanosleep, both children that
# block at once, before denet's first sample.
WAITS='yes | (sleep 2; head -c 1 >/dev/null)'

# check_waits JSONL — off-CPU time must be attributed to the process that
# waited, with the kernel stack it waited in, named from /proc/kallsyms
# (0.10.4: stacks were captured from the wrong task, never named, never
# written, and children were tracked only from denet's next sample).
check_waits() {
    python3 - "$@" <<'EOF'
import json, sys
from collections import defaultdict
recs = [json.loads(l) for l in open(sys.argv[1])]
name = {r["pid"]: r["cmd"][0] for r in recs if r.get("kind") == "child"}
stacks, waited = {}, defaultdict(float)
for r in recs:
    off = ((r.get("aggregated") or {}).get("ebpf") or {}).get("offcpu") or {}
    stacks.update({int(k): v for k, v in (off.get("kernel_stacks") or {}).items()})
    for w in off.get("waits") or []:
        waited[(name.get(w["pid"]), w["stack"])] += w["time_ns"] / 1e9
errs = []
for proc, frame in (("yes", "pipe_write"), ("sleep", "nanosleep")):
    t = sum(s for (p, k), s in waited.items() if p == proc and any(frame in f for f in stacks.get(k, [])))
    if t < 1.0:
        seen = {k: round(s, 2) for (p, k), s in waited.items() if p == proc}
        errs.append(f"{proc}: {t:.2f} s off-CPU in a stack with {frame} (want >= 1 s); "
                    f"its waits by stack: {seen}")
if errs:
    sys.exit("; ".join(errs))
EOF
}

e2e_waits() { # name, [wrapper...]
    local name=$1 out="$OUT_DIR/waits.jsonl" msg=""; shift
    if "$@" "$DENET" --enable-ebpf -q -i 50 -m 100 -o "$out" run -- bash -c "$WAITS" >/dev/null 2>"$OUT_DIR/denet.err" \
        && msg=$(check_waits "$out" 2>&1); then
        pass "$name"
    else
        fail "$name: ${msg:-denet run failed}"
        tail -5 "$OUT_DIR/denet.err" | sed 's/^/      denet: /'
    fi
}

e2e() { # name, expect_gpu, expect_rapl
    local out="$OUT_DIR/e2e.jsonl" msg="" gpu=()
    [[ "$2" == 1 ]] && gpu=(--gpu) # GPU monitoring is opt-in
    if "$DENET" --enable-ebpf "${gpu[@]}" -q -o "$out" run -- python3 -c "$TRAFFIC" >/dev/null 2>"$OUT_DIR/denet.err" \
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
    e2e_tree "$2: process tree"
    e2e_waits "$2: off-CPU stacks"
    # bpf_get_ns_current_pid_tgid() arrived in 5.7
    if [[ "$(printf '%s\n' 5.7 "$(uname -r)" | sort -V | head -1)" != 5.7 ]]; then
        echo "SKIP  $2: PID namespace (kernel $(uname -r) < 5.7)"
    elif ! command -v unshare >/dev/null; then
        echo "SKIP  $2: PID namespace (unshare not installed)"
    else
        e2e_tree "$2: process tree in a PID namespace" unshare --pid --fork --mount-proc
        e2e_waits "$2: off-CPU stacks in a PID namespace" unshare --pid --fork --mount-proc
    fi
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
step "3. end to end ($(uname -r))" "\`denet run --enable-ebpf\` as root on a job that moves 2 MB over loopback from its first instant. Must record eBPF net bytes$( ((GPU)) && echo ", a GPU")$( ((RAPL)) && echo ", RAPL energy"). Then (3c) a job whose work is done by short-lived children: their syscalls and off-CPU time must be attributed and kept after they exit, on the host and in a new PID namespace."
sudo ./scripts/release_check.sh --as-root host "$GPU" "$RAPL" || FAILED=1

step "3b. end to end, static musl binary" "Same as 3 with a fully static build. eBPF and RAPL must work; GPU is not expected (NVML is a glibc library a static binary can't load)."
if ! rustup target list --installed 2>/dev/null | grep -qx "$MUSL"; then
    echo "SKIP  $MUSL target not installed (rustup target add $MUSL)"
elif ! cargo build -q --release --target "$MUSL" --features ebpf --bin denet; then
    fail "musl build"
else
    sudo env DENET="target/$MUSL/release/denet" ./scripts/release_check.sh --as-root host-musl 0 "$RAPL" || FAILED=1
fi

step "3e. GPU PCIe throughput" "\`denet --gpu\` on a CUDA loop copying 256 MiB host<->device for 5 s. Peak pcie_tx_kbps and pcie_rx_kbps must both exceed 100 MB/s (idle is <1 MB/s; a laptop PCIe 4.0 x8 link reaches ~14 GB/s)."
if ((!GPU)); then
    echo "SKIP  no NVIDIA GPU"
elif ! command -v nvcc >/dev/null; then
    echo "SKIP  nvcc not installed"
else
    cat >"$OUT_DIR/h2d.cu" <<'EOF'
#include <cuda_runtime.h>
#include <time.h>
int main() {
    size_t n = 256 << 20; void *h, *d;
    if (cudaMallocHost(&h, n) || cudaMalloc(&d, n)) return 1;
    for (time_t end = time(0) + 5; time(0) < end;) {
        cudaMemcpy(d, h, n, cudaMemcpyHostToDevice);
        cudaMemcpy(h, d, n, cudaMemcpyDeviceToHost);
    }
    return 0;
}
EOF
    peak() { jq -s "[.. | .$1? // empty] | max // 0" "$OUT_DIR/pcie.jsonl"; }
    if ! nvcc -o "$OUT_DIR/h2d" "$OUT_DIR/h2d.cu" >"$OUT_DIR/nvcc.log" 2>&1; then
        fail "pcie: nvcc build"; tail -5 "$OUT_DIR/nvcc.log" | sed 's/^/      /'
    elif ! "$DENET" --gpu -q -o "$OUT_DIR/pcie.jsonl" run -- "$OUT_DIR/h2d" >/dev/null 2>"$OUT_DIR/denet.err"; then
        fail "pcie: denet run failed"; tail -5 "$OUT_DIR/denet.err" | sed 's/^/      denet: /'
    else
        tx=$(peak pcie_tx_kbps) rx=$(peak pcie_rx_kbps)
        if ((tx > 102400 && rx > 102400)); then
            pass "pcie: peak tx=${tx} rx=${rx} KB/s"
        else
            fail "pcie: peak tx=${tx} rx=${rx} KB/s, want > 102400"
        fi
    fi
fi

step "4. kernels (${#KERNELS[@]})" "Step 2's root-only net tests and step 3's eBPF check, inside a VM per kernel (no GPU/RAPL in guests). Include one kernel < 5.7 (e.g. v5.4.x) to check eBPF still loads where the PID-namespace helper is missing."
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
