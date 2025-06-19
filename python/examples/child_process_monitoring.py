#!/usr/bin/env python3
"""
Example demonstrating child process monitoring with denet.

This example shows how to use denet to monitor a process that spawns child processes,
properly capturing and aggregating metrics across the entire process tree.
"""

import json
import os
import sys
import time
from denet import execute_with_monitoring


def run_stress_test():
    """Run a CPU-intensive stress test that spawns multiple child processes."""
    print(f"Parent process: {os.getpid()}")

    # Create child processes for CPU-intensive work
    # This is a simple way to spawn child processes in Python
    for i in range(4):
        pid = os.fork()
        if pid == 0:  # Child process
            # Each child process will do CPU-intensive work
            print(f"Child process {i + 1}: {os.getpid()}")
            start_time = time.time()
            # Run for about 2 seconds
            while time.time() - start_time < 2:
                # Do some CPU-intensive calculations
                _ = [i * i * i for i in range(100000)]

            # Exit the child process
            sys.exit(0)

    # Parent process waits for children to finish
    print("Parent waiting for children to complete...")
    for _ in range(4):
        os.wait()

    print("All child processes completed!")
    return 0


def main():
    """Run the example and display the monitoring results."""
    print("Starting child process monitoring example...")

    # Run the stress test with monitoring
    # Note the include_children=True parameter which is key for monitoring process trees
    exit_code, monitor = execute_with_monitoring(
        cmd=[
            sys.executable,
            "-c",
            "import os, sys, time; "
            "print(f'Parent: {os.getpid()}'); "
            # Create 4 child processes
            "for i in range(4): "
            "    pid = os.fork(); "
            "    if pid == 0: "  # Child process
            "        print(f'Child {i+1}: {os.getpid()}'); "
            "        start = time.time(); "
            "        while time.time() - start < 3: "  # Each child runs for 3 seconds
            "            _ = [i*i*i for i in range(50000)]; "  # CPU-intensive work
            "        sys.exit(0); "
            # Parent waits for all children
            "for _ in range(4): os.wait(); "
            "print('All children completed');",
        ],
        base_interval_ms=100,  # Sample every 100ms
        max_interval_ms=500,  # Maximum interval 500ms
        store_in_memory=True,  # Keep samples in memory
        output_file="stress_monitor.jsonl",  # Also write to file
        include_children=True,  # This is critical for monitoring child processes
    )

    # Process and display the results
    samples = monitor.get_samples()

    # Get summary statistics
    summary_json = monitor.get_summary()
    summary = json.loads(summary_json)

    print("\n===== Monitoring Results =====")
    print(f"Total samples collected: {len(samples)}")
    print(f"Average CPU usage: {summary['avg_cpu_usage']:.2f}%")
    print(f"Peak memory usage: {summary['peak_mem_rss_kb'] / 1024:.2f} MB")
    print(f"Maximum processes monitored: {summary['max_processes']}")

    # Show the process count over time
    process_counts = []
    for sample in samples:
        if isinstance(sample, str):
            sample = json.loads(sample)

        # Look for process_count in aggregated data
        if "aggregated" in sample:
            count = sample["aggregated"].get("process_count", 1)
            process_counts.append(count)
        elif "process_count" in sample:
            process_counts.append(sample["process_count"])

    if process_counts:
        print("\nProcess count over time:")
        for i, count in enumerate(process_counts):
            print(f"Sample {i + 1}: {count} processes")

    print("\nExample complete. Results written to stress_monitor.jsonl")

    return exit_code


if __name__ == "__main__":
    sys.exit(main())
