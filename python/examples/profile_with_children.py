#!/usr/bin/env python3
"""
Example demonstrating the use of the @profile decorator with child processes.

This example shows how to use denet's profile decorator to monitor
functions that spawn child processes, properly capturing metrics across
the entire process tree.
"""

import json
import os
import sys
import time
from denet import profile


@profile(
    base_interval_ms=100,
    max_interval_ms=500,
    output_file="profile_children.jsonl",
    include_children=True,  # Critical for monitoring child processes
)
def cpu_intensive_with_children():
    """Function that spawns child processes and performs CPU-intensive work."""
    print(f"Parent process: {os.getpid()}")

    # Create 3 child processes
    children = []
    for i in range(3):
        pid = os.fork()
        if pid == 0:  # Child process
            # Each child process does CPU-intensive work
            print(f"Child process {i + 1}: {os.getpid()}")
            start_time = time.time()

            # Child processes run for different durations
            duration = 1.0 + i * 0.5  # 1.0, 1.5, 2.0 seconds

            while time.time() - start_time < duration:
                # CPU-intensive calculation
                _ = [i * i * i for i in range(100000)]

            # Exit the child process
            print(f"Child {i + 1} finished")
            sys.exit(0)
        else:
            children.append(pid)

    # Parent process does some work too
    start_time = time.time()
    while time.time() - start_time < 1.5:
        # Less intensive work for parent
        _ = [i * i for i in range(50000)]

    # Wait for all children to complete
    print("Parent waiting for children...")
    for pid in children:
        os.waitpid(pid, 0)

    print("All child processes completed!")
    return "Completed successfully"


def main():
    """Run the example and analyze the results."""
    print("Starting profile decorator with child processes example...")

    # Run the profiled function
    result, samples = cpu_intensive_with_children()

    # Print the function result
    print(f"\nFunction result: {result}")

    # Count the number of samples
    print(f"Total samples collected: {len(samples)}")

    # Analyze the process count
    process_counts = []
    max_process_count = 1
    max_mem_kb = 0
    total_cpu = 0

    for sample in samples:
        # Parse the sample if it's a string
        if isinstance(sample, str):
            try:
                sample = json.loads(sample)
            except json.JSONDecodeError:
                continue

        # Check for process count in different formats
        process_count = 1
        if "aggregated" in sample:
            process_count = sample["aggregated"].get("process_count", 1)
        elif "process_count" in sample:
            process_count = sample["process_count"]
        elif "children" in sample:
            # Count parent (if present) + children
            process_count = len(sample.get("children", []))
            if sample.get("parent") is not None:
                process_count += 1

        process_counts.append(process_count)
        max_process_count = max(max_process_count, process_count)

        # Track memory usage
        if "aggregated" in sample and "mem_rss_kb" in sample["aggregated"]:
            max_mem_kb = max(max_mem_kb, sample["aggregated"]["mem_rss_kb"])
        elif "mem_rss_kb" in sample:
            max_mem_kb = max(max_mem_kb, sample["mem_rss_kb"])

        # Track CPU usage
        if "aggregated" in sample and "cpu_usage" in sample["aggregated"]:
            total_cpu += sample["aggregated"]["cpu_usage"]
        elif "cpu_usage" in sample:
            total_cpu += sample["cpu_usage"]

    # Print statistics
    print("\n===== Profile Results =====")
    print(f"Maximum processes detected: {max_process_count}")
    print(f"Peak memory usage: {max_mem_kb / 1024:.2f} MB")

    # Calculate average CPU usage if we have samples
    if samples:
        avg_cpu = total_cpu / len(samples)
        print(f"Average CPU usage: {avg_cpu:.2f}%")

    # Print process count over time
    if process_counts:
        print("\nProcess count over time:")
        for i, count in enumerate(process_counts):
            if i % 3 == 0:  # Only print every 3rd sample to keep output manageable
                print(f"Sample {i + 1}: {count} processes")

    print("\nExample complete. Full results written to profile_children.jsonl")
    return 0


if __name__ == "__main__":
    sys.exit(main())
