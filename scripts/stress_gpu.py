#!/usr/bin/env -S uv run --script
# /// script
# requires-python = ">=3.11"
# dependencies = [
#   "torch>=2.3",
# ]
#
# [tool.uv.sources]
# torch = [
#   { index = "pytorch-cu126", marker = "sys_platform == 'linux'" },
# ]
#
# [[tool.uv.index]]
# name = "pytorch-cu126"
# url = "https://download.pytorch.org/whl/cu126"
# explicit = true
# ///

"""GPU stress script — runs matrix multiplications on CUDA (or Apple MPS) to saturate the GPU.

Usage:
    uv run scripts/stress_gpu.py               # run until Ctrl-C
    uv run scripts/stress_gpu.py --duration 30  # run for 30 seconds
    uv run scripts/stress_gpu.py --size 16384   # larger matrices = more VRAM

Profile with denet:
    denet --gpu run uv run scripts/stress_gpu.py --duration 30
    denet --tui --gpu run uv run scripts/stress_gpu.py   # live graphs
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

    if torch.cuda.is_available():
        device = torch.device("cuda")
        sync = torch.cuda.synchronize
        name = torch.cuda.get_device_name(0)
        memory = f"{torch.cuda.get_device_properties(0).total_memory / 1024**3:.1f} GB VRAM"
        def peak_mb():
            return torch.cuda.max_memory_allocated() / 1024**2
    elif torch.backends.mps.is_available():
        # Apple Silicon: unified memory, and MPS tracks no peak, so report
        # what the Metal driver currently holds.
        device = torch.device("mps")
        sync = torch.mps.synchronize
        name = "Apple GPU (MPS)"
        memory = "unified with system RAM"
        def peak_mb():
            return torch.mps.driver_allocated_memory() / 1024**2
    else:
        print("No CUDA or Apple MPS device found. Is the NVIDIA driver loaded?", file=sys.stderr)
        sys.exit(1)

    dtype = torch.float16 if args.dtype == "float16" else torch.float32
    n = args.size

    print(f"Device  : {name}")
    print(f"Memory  : {memory}")
    print(f"Matrix  : {n}x{n} {args.dtype}")
    print(f"Duration: {'until Ctrl-C' if args.duration == 0 else f'{args.duration}s'}")
    print()

    a = torch.randn(n, n, dtype=dtype, device=device)
    b = torch.randn(n, n, dtype=dtype, device=device)

    print(f"GPU memory after allocating matrices: {peak_mb():.0f} MB")
    print("Stressing... (Ctrl-C to stop)\n")

    start = time.monotonic()
    iterations = 0
    report_every = 5.0
    last_report = start

    try:
        while True:
            c = torch.matmul(a, b)
            sync()
            iterations += 1

            now = time.monotonic()
            elapsed = now - start

            if now - last_report >= report_every:
                rate = iterations / elapsed
                print(f"  [{elapsed:6.1f}s] {iterations} iters | {rate:.1f} iters/s | GPU memory {peak_mb():.0f} MB")
                last_report = now

            if args.duration > 0 and elapsed >= args.duration:
                break

    except KeyboardInterrupt:
        print("\nInterrupted.")

    elapsed = time.monotonic() - start
    print(f"\nDone: {iterations} iterations in {elapsed:.1f}s ({iterations/elapsed:.1f} iters/s)")
    print(f"GPU memory: {peak_mb():.0f} MB")


if __name__ == "__main__":
    main()
