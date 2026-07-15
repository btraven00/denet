#!/usr/bin/env bash
#
# Per-child network breakdown demo.
#
# Runs two curls as children under denet, each piped to sha256sum so every
# child does both network (curl) and CPU (hashing) work. With eBPF per-process
# accounting on, the two downloads land under separate PIDs, and the generated
# report grows a "per-PID network (eBPF)" widget — one small timeline per child.
#
# eBPF needs CAP_BPF+CAP_PERFMON: run this with sudo, or setcap the denet
# binary. Without caps the report still renders, just without the per-PID
# widget (the aggregate network panel is unaffected).
#
# Overridable via env: URL1, URL2, OUT, DENET.
set -euo pipefail

# Two different files (distinct sizes) from Cloudflare's speed endpoint — no
# account needed and reliably up. Swap for any two URLs you like.
URL1="${URL1:-https://speed.cloudflare.com/__down?bytes=20000000}"
URL2="${URL2:-https://speed.cloudflare.com/__down?bytes=40000000}"
OUT="${OUT:-network_children.jsonl}"

# Prefer an installed denet; fall back to building from this checkout.
DENET="${DENET:-denet}"
command -v "$DENET" >/dev/null 2>&1 || DENET="cargo run --release --features ebpf --bin denet --"

$DENET --enable-ebpf --out "$OUT" run -- \
    bash -c "curl -sL '$URL1' | sha256sum & curl -sL '$URL2' | sha256sum & wait"

python3 -m denet.report "$OUT"
echo "report written: ${OUT%.jsonl}.html"
