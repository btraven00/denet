#!/usr/bin/env -S uv run --script
# /// script
# requires-python = ">=3.11"
# dependencies = [
#   "torch>=2.3",
# ]
#
# [tool.uv.sources]
# torch = [
#   { index = "pytorch-cu121", marker = "sys_platform == 'linux'" },
# ]
#
# [[tool.uv.index]]
# name = "pytorch-cu121"
# url = "https://download.pytorch.org/whl/cu121"
# explicit = true
# ///

"""GPU stress script — runs matrix multiplications on CUDA to saturate the GPU.

Usage:
    uv run scripts/stress_gpu.py               # run until Ctrl-C
    uv run scripts/stress_gpu.py --duration 30  # run for 30 seconds
    uv run scripts/stress_gpu.py --size 16384   # larger matrices = more VRAM

Profile with denet:
    ./target/release/denet run uv -- run scripts/stress_gpu.py --duration 30
"""

import argparse
import sys
import time


def parse_args():
    p = argparse.ArgumentParser(description="Stress the GPU with matrix multiplications")
    p.add_argument("--duration", type=float, default=0,
                   help="How long to run in seconds (0 = until Ctrl-C)")
    p.add_argument("--size", type=int, default=8192,
                   help="Matrix dimension N for NxN matmul (default: 8192)")
    p.add_argument("--dtype", choices=["float32", "float16"], default="float32",
                   help="Tensor dtype (float16 uses less VRAM, higher throughput)")
    return p.parse_args()


def main():
    args = parse_args()

    try:
        import torch
    except ImportError:
        print("torch not available — run via: uv run scripts/stress_gpu.py", file=sys.stderr)
        sys.exit(1)

    if not torch.cuda.is_available():
        print("No CUDA device found. Is the NVIDIA driver loaded?", file=sys.stderr)
        sys.exit(1)

    device = torch.device("cuda")
    dtype = torch.float16 if args.dtype == "float16" else torch.float32
    n = args.size

    print(f"Device  : {torch.cuda.get_device_name(0)}")
    print(f"VRAM    : {torch.cuda.get_device_properties(0).total_memory / 1024**3:.1f} GB total")
    print(f"Matrix  : {n}x{n} {args.dtype}")
    print(f"Duration: {'until Ctrl-C' if args.duration == 0 else f'{args.duration}s'}")
    print()

    a = torch.randn(n, n, dtype=dtype, device=device)
    b = torch.randn(n, n, dtype=dtype, device=device)

    vram_used = torch.cuda.memory_allocated() / 1024**2
    print(f"VRAM allocated for matrices: {vram_used:.0f} MB")
    print("Stressing... (Ctrl-C to stop)\n")

    start = time.monotonic()
    iterations = 0
    report_every = 5.0
    last_report = start

    try:
        while True:
            c = torch.matmul(a, b)
            torch.cuda.synchronize()
            iterations += 1

            now = time.monotonic()
            elapsed = now - start

            if now - last_report >= report_every:
                rate = iterations / elapsed
                peak_mb = torch.cuda.max_memory_allocated() / 1024**2
                print(f"  [{elapsed:6.1f}s] {iterations} iters | {rate:.1f} iters/s | peak VRAM {peak_mb:.0f} MB")
                last_report = now

            if args.duration > 0 and elapsed >= args.duration:
                break

    except KeyboardInterrupt:
        print("\nInterrupted.")

    elapsed = time.monotonic() - start
    peak_mb = torch.cuda.max_memory_allocated() / 1024**2
    print(f"\nDone: {iterations} iterations in {elapsed:.1f}s ({iterations/elapsed:.1f} iters/s)")
    print(f"Peak VRAM used: {peak_mb:.0f} MB")


if __name__ == "__main__":
    main()
