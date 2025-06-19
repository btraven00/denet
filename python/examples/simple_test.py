#!/usr/bin/env python3
"""
Simple test script to verify child process monitoring functionality in denet.
"""

import json
import os
import sys
from pathlib import Path

try:
    import denet
except ImportError:
    print("Error: denet package not found. Make sure it's installed or PYTHONPATH is set correctly.")
    sys.exit(1)


def run_stress_test():
    """Run a simple test that spawns child processes and checks monitoring results."""
    print(f"Running stress test from {os.getpid()}")

    # Create a simple Python script that spawns child processes
    script = """
import os
import sys
import time

print(f"Parent process: {os.getpid()}")

# Define a CPU-intensive function that consumes a significant amount of CPU
def cpu_intensive_task(process_id, duration):
    print(f"Child process {process_id}: {os.getpid()} starting for {duration} seconds")
    start = time.time()

    # Use all CPU cores for maximum intensity
    cpu_count = max(1, multiprocessing.cpu_count() // 4)  # Use 1/4 of available cores
    threads = []

    # Create helper function for threads
    def burn_cpu():
        end_time = time.time() + duration
        while time.time() < end_time:
            # Computationally intensive work
            for _ in range(1000000):
                x = 1.01
                for i in range(100):
                    x = x ** 1.01 % 10000

    # Start multiple threads to maximize CPU usage
    for _ in range(cpu_count):
        t = threading.Thread(target=burn_cpu)
        t.daemon = True
        threads.append(t)
        t.start()

    # Wait for all threads to complete
    for t in threads:
        t.join()

    elapsed = time.time() - start
    print(f"Child {process_id} exiting after {elapsed:.2f} seconds")
    sys.exit(0)

# Create 3 child processes that do CPU-intensive work
for i in range(3):
    pid = os.fork()
    if pid == 0:  # Child process
        # Each child runs with different duration
        duration = 2.0 + (i * 0.5)  # 2.0, 2.5, 3.0 seconds
        cpu_intensive_task(i+1, duration)

# Parent process waits but does minimal work
# This makes it easier to see the difference between parent-only and child monitoring
print("Parent waiting for children...")
for _ in range(3):
    os.wait()

print("All children completed")
"""

    # Create a temporary script file
    script_path = Path("temp_script.py")
    script_path.write_text(script)

    try:
        # Run with monitoring, both with and without child process monitoring
        print("\n=== TEST 1: With include_children=True (should see multiple processes) ===")
        print("Running script with child process monitoring enabled...")
        exit_code, monitor_with = denet.execute_with_monitoring(
            cmd=[sys.executable, str(script_path)],
            base_interval_ms=100,
            max_interval_ms=500,
            store_in_memory=True,
            output_file="with_children.jsonl",
            include_children=True,  # Monitor child processes
        )
        print(f"Script completed with exit code: {exit_code}")

        print("\n=== TEST 2: With include_children=False (should see only parent process) ===")
        print("Running script with child process monitoring disabled...")
        exit_code, monitor_without = denet.execute_with_monitoring(
            cmd=[sys.executable, str(script_path)],
            base_interval_ms=100,
            max_interval_ms=500,
            store_in_memory=True,
            output_file="without_children.jsonl",
            include_children=False,  # Don't monitor child processes
        )
        print(f"Script completed with exit code: {exit_code}")

        # Process results with child monitoring
        summary_with = json.loads(monitor_with.get_summary())
        print("\nWith child monitoring (include_children=True):")
        print(f"- Max processes: {summary_with.get('max_processes', 1)}")
        print(f"- Avg CPU usage: {summary_with.get('avg_cpu_usage', 0):.2f}%")
        print(f"- Peak memory: {summary_with.get('peak_mem_rss_kb', 0) / 1024:.2f} MB")
        print(f"- Sample count: {summary_with.get('sample_count', 0)}")
        print(f"- Total time: {summary_with.get('total_time_secs', 0):.2f} seconds")
        print(f"- Total disk reads: {summary_with.get('total_disk_read_bytes', 0) / 1024:.2f} KB")
        print(f"- Total disk writes: {summary_with.get('total_disk_write_bytes', 0) / 1024:.2f} KB")

        # Analyze samples with child process monitoring
        samples_with = monitor_with.get_samples()
        process_counts_with = []
        cpu_usages_with = []

        print("\nDetailed samples with child monitoring:")
        for i, sample in enumerate(samples_with):
            if isinstance(sample, str):
                sample = json.loads(sample)

            # Get process count (look in various places)
            count = 1
            cpu = 0.0

            if "process_count" in sample:
                count = sample["process_count"]
                cpu = sample.get("cpu_usage", 0.0)
            elif "aggregated" in sample and "process_count" in sample["aggregated"]:
                count = sample["aggregated"]["process_count"]
                cpu = sample["aggregated"].get("cpu_usage", 0.0)
            elif "children" in sample:
                count = len(sample["children"]) + (1 if sample.get("parent") else 0)
                # Sum CPU from parent and children
                if sample.get("parent"):
                    cpu += sample["parent"].get("cpu_usage", 0.0)
                for child in sample.get("children", []):
                    if "metrics" in child:
                        cpu += child["metrics"].get("cpu_usage", 0.0)

            process_counts_with.append(count)
            cpu_usages_with.append(cpu)

            if i < 3:  # Only show first few samples to avoid cluttering output
                print(f"  Sample {i + 1}: {count} processes, {cpu:.2f}% CPU")

        # Show process count and CPU usage over time
        if process_counts_with:
            max_count = max(process_counts_with)
            max_cpu = max(cpu_usages_with) if cpu_usages_with else 0
            print(f"- Process count timeline: {process_counts_with[:5]}... (max: {max_count})")
            print(f"- CPU usage timeline: {[f'{cpu:.1f}%' for cpu in cpu_usages_with[:5]]}... (max: {max_cpu:.1f}%)")

        # Process results without child monitoring
        summary_without = json.loads(monitor_without.get_summary())
        print("\nWithout child monitoring (include_children=False):")
        print(f"- Max processes: {summary_without.get('max_processes', 1)}")
        print(f"- Avg CPU usage: {summary_without.get('avg_cpu_usage', 0):.2f}%")
        print(f"- Peak memory: {summary_without.get('peak_mem_rss_kb', 0) / 1024:.2f} MB")
        print(f"- Sample count: {summary_without.get('sample_count', 0)}")
        print(f"- Total time: {summary_without.get('total_time_secs', 0):.2f} seconds")
        print(f"- Total disk reads: {summary_without.get('total_disk_read_bytes', 0) / 1024:.2f} KB")
        print(f"- Total disk writes: {summary_without.get('total_disk_write_bytes', 0) / 1024:.2f} KB")

        # Output file details
        print("\nOutput files:")
        print("- With child monitoring: with_children.jsonl")
        print("- Without child monitoring: without_children.jsonl")

        # Validate results
        print("\n=== TEST RESULTS ===")

        # Check process count
        if summary_with.get("max_processes", 1) > 1:
            print("✅ TEST PASSED: Multiple processes detected with child monitoring enabled")
        else:
            print("❌ TEST FAILED: Child monitoring didn't detect multiple processes")

        # CPU usage should be higher with child monitoring since we capture work from all processes
        cpu_with = summary_with.get("avg_cpu_usage", 0)
        cpu_without = summary_without.get("avg_cpu_usage", 0)

        # Max CPU might be more reliable than average for this test
        max_cpu_with = max(cpu_usages_with) if cpu_usages_with else 0

        if cpu_with > cpu_without * 1.2 or max_cpu_with > cpu_without * 2:  # More CPU usage with children
            print(
                f"✅ TEST PASSED: Higher CPU usage with child monitoring ({cpu_with:.2f}% avg, {max_cpu_with:.2f}% max vs {cpu_without:.2f}% without)"
            )
        else:
            print(
                f"❌ TEST FAILED: Child monitoring didn't capture significantly higher CPU usage ({cpu_with:.2f}% avg, {max_cpu_with:.2f}% max vs {cpu_without:.2f}% without)"
            )

        # Memory usage should be higher with child monitoring
        mem_with = summary_with.get("peak_mem_rss_kb", 0)
        mem_without = summary_without.get("peak_mem_rss_kb", 0)
        if mem_with > mem_without * 1.2:  # At least 20% more memory usage
            print(
                f"✅ TEST PASSED: Higher memory usage with child monitoring ({mem_with / 1024:.2f} MB vs {mem_without / 1024:.2f} MB)"
            )
        else:
            print(
                f"❌ TEST FAILED: Child monitoring didn't capture significantly higher memory usage ({mem_with / 1024:.2f} MB vs {mem_without / 1024:.2f} MB)"
            )

    finally:
        # Clean up
        if script_path.exists():
            script_path.unlink()


if __name__ == "__main__":
    print("=== denet Child Process Monitoring Test ===")
    print(f"denet version: {getattr(denet, '__version__', 'unknown')}")
    run_stress_test()
