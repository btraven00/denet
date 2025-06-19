#!/usr/bin/env python3
"""
CPU-intensive child process monitoring example for denet.

This script demonstrates how to monitor an application that spawns
multiple CPU-intensive child processes using denet's process monitoring.

It shows the difference between monitoring with and without the
include_children option.
"""

import json
import sys
import time
from pathlib import Path

try:
    import denet
except ImportError:
    print("Error: denet package not found.")
    print("Make sure it's installed or PYTHONPATH is set correctly.")
    sys.exit(1)


def create_child_process_script():
    """Create a temporary script that spawns CPU-intensive child processes."""
    script_content = """
import os
import sys
import time
import multiprocessing

def cpu_intensive_work(duration):
    # CPU-intensive computation.
    start_time = time.time()
    while time.time() - start_time < duration:
        # Perform intensive calculation
        for _ in range(500000):
            x = 123.456
            for i in range(20):
                x = (x ** 1.1) % 10000

def main():
    print(f"Parent process PID: {os.getpid()}")

    # Create multiple child processes doing CPU-intensive work
    children = []
    for i in range(3):
        # Each child runs for a different duration
        duration = 2.0 + i * 0.5

        pid = os.fork()
        if pid == 0:  # Child process
            print(f"Child {i+1} PID: {os.getpid()} (running for {duration}s)")
            cpu_intensive_work(duration)
            print(f"Child {i+1} completed")
            sys.exit(0)
        else:
            children.append(pid)

    # Parent does some light work while waiting for children
    print(f"Parent waiting for {len(children)} children to complete...")

    # Do some light work while waiting
    for _ in range(10):
        time.sleep(0.2)

    # Wait for all children to finish
    for pid in children:
        os.waitpid(pid, 0)

    print("All children completed")
    return 0

if __name__ == "__main__":
    sys.exit(main())
"""

    # Create a temporary script file
    script_path = Path("child_processes.py")
    script_path.write_text(script_content)
    return script_path


def print_section(title):
    """Print a section header."""
    print("\n" + "=" * 50)
    print(f" {title}")
    print("=" * 50)


def format_metrics(metrics):
    """Format metrics for display."""
    if isinstance(metrics, str):
        try:
            metrics = json.loads(metrics)
        except json.JSONDecodeError:
            return "Invalid JSON"

    # Handle different format types
    result = {}

    # Handle process tree metrics
    if "aggregated" in metrics:
        result["process_count"] = metrics["aggregated"].get("process_count", 1)
        result["cpu_usage"] = metrics["aggregated"].get("cpu_usage", 0)
        result["mem_rss_kb"] = metrics["aggregated"].get("mem_rss_kb", 0)
        result["thread_count"] = metrics["aggregated"].get("thread_count", 0)

        # Count children
        children_count = len(metrics.get("children", []))
        result["children_count"] = children_count

        # Extract parent info if present
        if metrics.get("parent"):
            result["parent_cpu"] = metrics["parent"].get("cpu_usage", 0)
            result["parent_mem_kb"] = metrics["parent"].get("mem_rss_kb", 0)

    # Handle flat metrics
    elif "cpu_usage" in metrics:
        result["process_count"] = 1
        result["cpu_usage"] = metrics.get("cpu_usage", 0)
        result["mem_rss_kb"] = metrics.get("mem_rss_kb", 0)
        result["thread_count"] = metrics.get("thread_count", 0)
        result["children_count"] = 0
        result["parent_cpu"] = metrics.get("cpu_usage", 0)
        result["parent_mem_kb"] = metrics.get("mem_rss_kb", 0)

    return result


def run_with_monitoring(script_path, include_children=True):
    """Run script with process monitoring."""

    # Descriptive name for this run
    mode = "WITH" if include_children else "WITHOUT"
    print_section(f"Running {mode} child process monitoring")

    # Output file for the monitoring data
    output_file = f"monitoring_{mode.lower()}_children.jsonl"

    # Run the script with monitoring
    print(f"Starting monitoring (include_children={include_children})...")
    start_time = time.time()

    exit_code, monitor = denet.execute_with_monitoring(
        cmd=["python", str(script_path)],
        base_interval_ms=100,  # Sample every 100ms
        max_interval_ms=500,  # Maximum adaptive interval
        store_in_memory=True,  # Keep samples in memory
        output_file=output_file,  # Also write to file
        include_children=include_children,  # Key parameter!
    )

    elapsed = time.time() - start_time
    print(f"Script completed in {elapsed:.2f}s with exit code: {exit_code}")

    # Get and analyze samples
    samples = monitor.get_samples()
    print(f"Collected {len(samples)} samples")

    # Parse samples
    parsed_samples = []
    for sample in samples:
        if isinstance(sample, str):
            try:
                sample_data = format_metrics(sample)
                parsed_samples.append(sample_data)
            except json.JSONDecodeError:
                continue

    # Print sample summary
    if parsed_samples:
        # Calculate max values
        max_cpu = max(s.get("cpu_usage", 0) for s in parsed_samples)
        max_processes = max(s.get("process_count", 1) for s in parsed_samples)
        max_mem = max(s.get("mem_rss_kb", 0) for s in parsed_samples)

        print("\nMonitoring Results:")
        print(f"- Maximum processes detected: {max_processes}")
        print(f"- Maximum CPU usage: {max_cpu:.2f}%")
        print(f"- Maximum memory usage: {max_mem / 1024:.2f} MB")

        # Print process count over time
        print("\nProcess counts over time:")
        for i, sample in enumerate(parsed_samples):
            if i < 5 or i >= len(parsed_samples) - 5:  # First/last 5 samples
                proc_count = sample.get("process_count", 1)
                children = sample.get("children_count", 0)
                cpu = sample.get("cpu_usage", 0)
                print(f"  Sample {i + 1}: {proc_count} processes ({children} children), {cpu:.2f}% CPU")

    # Get summary
    summary_json = monitor.get_summary()
    summary = json.loads(summary_json)

    print("\nSummary Statistics:")
    print(f"- Total time: {summary.get('total_time_secs', 0):.2f}s")
    print(f"- Average CPU usage: {summary.get('avg_cpu_usage', 0):.2f}%")
    print(f"- Peak memory usage: {summary.get('peak_mem_rss_kb', 0) / 1024:.2f} MB")
    print(f"- Maximum processes: {summary.get('max_processes', 1)}")
    print(f"- Sample count: {summary.get('sample_count', 0)}")

    print(f"\nDetailed monitoring data written to: {output_file}")

    return summary, parsed_samples


def main():
    """Run the example demonstrating child process monitoring."""
    print("Denet Child Process Monitoring Example")
    print(f"Using denet version: {getattr(denet, '__version__', 'unknown')}")

    # Create the test script
    script_path = create_child_process_script()

    try:
        # Run with child process monitoring
        with_summary, with_samples = run_with_monitoring(script_path, include_children=True)

        # Run without child process monitoring
        without_summary, without_samples = run_with_monitoring(script_path, include_children=False)

        # Compare results
        print_section("Comparison")

        # Process count comparison
        with_processes = with_summary.get("max_processes", 1)
        without_processes = without_summary.get("max_processes", 1)

        print("Process Count:")
        print(f"- WITH child monitoring: {with_processes}")
        print(f"- WITHOUT child monitoring: {without_processes}")
        if with_processes > without_processes:
            print("✅ Child monitoring correctly detected multiple processes")
        else:
            print("❌ Child monitoring didn't detect additional processes")

        # CPU usage comparison
        with_cpu = with_summary.get("avg_cpu_usage", 0)
        without_cpu = without_summary.get("avg_cpu_usage", 0)

        print("\nCPU Usage:")
        print(f"- WITH child monitoring: {with_cpu:.2f}%")
        print(f"- WITHOUT child monitoring: {without_cpu:.2f}%")
        if with_cpu > without_cpu * 1.2:  # At least 20% more
            print("✅ Child monitoring captured more CPU usage")
        else:
            print("❌ Child monitoring didn't capture significantly more CPU usage")

        # Memory usage comparison
        with_mem = with_summary.get("peak_mem_rss_kb", 0)
        without_mem = without_summary.get("peak_mem_rss_kb", 0)

        print("\nMemory Usage:")
        print(f"- WITH child monitoring: {with_mem / 1024:.2f} MB")
        print(f"- WITHOUT child monitoring: {without_mem / 1024:.2f} MB")
        if with_mem > without_mem * 1.2:  # At least 20% more
            print("✅ Child monitoring captured more memory usage")
        else:
            print("❌ Child monitoring didn't capture significantly more memory usage")

        print("\nExample complete.")
        print("For more information, check the output JSONL files for detailed metrics.")

    finally:
        # Clean up
        if script_path.exists():
            script_path.unlink()


if __name__ == "__main__":
    main()
