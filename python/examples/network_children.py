#!/usr/bin/env python3
"""Per-child network breakdown, driven from the Python API.

Runs two curls (each piped to sha256sum, so every child does network + CPU) as
children under denet with eBPF per-process accounting on, then renders a report.
The two downloads show up as separate PIDs in the report's "per-PID network
(eBPF)" widget.

Requires an eBPF-enabled build and CAP_BPF+CAP_PERFMON:
  - Linux pip wheels ship with eBPF; from a source checkout build it with
    `pixi run develop-ebpf` (needs clang).
  - Run with sudo, or `setcap cap_bpf,cap_perfmon+ep` on the python binary.
Without eBPF or caps the run still works — you just get the aggregate network
panel and no per-PID split (enable_ebpf degrades to a logged warning).
"""

import os

import denet
from denet.report import generate_report

# Two different files (distinct sizes) from Cloudflare's speed endpoint.
URL1 = os.environ.get("URL1", "https://speed.cloudflare.com/__down?bytes=20000000")
URL2 = os.environ.get("URL2", "https://speed.cloudflare.com/__down?bytes=40000000")
OUT = os.environ.get("OUT", "network_children.jsonl")

cmd = ["bash", "-c", f"curl -sL '{URL1}' | sha256sum & curl -sL '{URL2}' | sha256sum & wait"]

exit_code, _monitor = denet.execute_with_monitoring(
    cmd,
    base_interval_ms=100,
    output_file=OUT,
    enable_ebpf=True,
    quiet=True,
)
print(f"monitored command exited {exit_code}; samples written to {OUT}")

report = generate_report(OUT)
print(f"report written: {report}")
