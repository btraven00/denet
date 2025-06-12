#!/usr/bin/env python3
"""
Demonstrate CPU core tracking functionality in denet.

This script shows how denet can track which CPU core a process is running on
(Linux only). This is useful for understanding CPU affinity and context switching.
"""

import json
import time
import multiprocessing as mp
import denet


def cpu_intensive_task(duration=2):
    """Run a CPU-intensive task for the specified duration."""
    end_time = time.time() + duration
    while time.time() < end_time:
        # Intensive computation
        _ = sum(i * i for i in range(10000))


def analyze_cpu_core_usage(samples):
    """Analyze CPU core usage patterns from samples."""
    core_usage = {}
    core_switches = 0
    last_core = None

    for sample_str in samples:
        sample = json.loads(sample_str)

        # Check if cpu_core field exists
        if 'cpu_core' in sample and sample['cpu_core'] is not None:
            core = sample['cpu_core']

            # Track core usage
            if core not in core_usage:
                core_usage[core] = 0
            core_usage[core] += 1

            # Track core switches
            if last_core is not None and last_core != core:
                core_switches += 1
            last_core = core

    return core_usage, core_switches


def test_single_process_core_tracking():
    """Test CPU core tracking for a single process."""
    print("Testing CPU core tracking for single process...")

    monitor = denet.ProcessMonitor(
        cmd=["python", "-c", "import time; start=time.time(); [sum(i*i for i in range(10000)) for _ in range(100000) if time.time()-start < 2]"],
        base_interval_ms=50,  # Fast sampling to catch core switches
        max_interval_ms=100,
        store_in_memory=True
    )

    monitor.run()
    samples = monitor.get_samples()

    core_usage, core_switches = analyze_cpu_core_usage(samples)

    print(f"  Total samples: {len(samples)}")
    print(f"  CPU cores used: {sorted(core_usage.keys())}")
    print(f"  Samples per core: {dict(sorted(core_usage.items()))}")
    print(f"  Core switches detected: {core_switches}")

    return samples


def test_multiprocess_core_distribution():
    """Test how multiple processes are distributed across CPU cores."""
    print("\nTesting CPU core distribution for multiple processes...")

    # Create a script that spawns multiple CPU-intensive processes
    test_script = """
import multiprocessing as mp
import time

def cpu_worker(worker_id):
    print(f"Worker {worker_id} started on PID {mp.current_process().pid}")
    end = time.time() + 1.5
    while time.time() < end:
        _ = sum(i * i for i in range(10000))

if __name__ == "__main__":
    processes = []
    for i in range(4):  # Create 4 worker processes
        p = mp.Process(target=cpu_worker, args=(i,))
        p.start()
        processes.append(p)

    for p in processes:
        p.join()
"""

    import tempfile
    import os

    with tempfile.NamedTemporaryFile(mode='w', suffix='.py', delete=False) as f:
        f.write(test_script)
        script_path = f.name

    try:
        monitor = denet.ProcessMonitor(
            cmd=["python", script_path],
            base_interval_ms=50,
            max_interval_ms=100,
            store_in_memory=True
        )

        monitor.run()
        samples = monitor.get_samples()

        # Analyze parent process
        parent_cores = {}

        # Analyze child processes
        child_cores = {}
        child_core_distribution = {}

        for sample_str in samples:
            sample = json.loads(sample_str)

            # Parent process core usage
            if 'cpu_core' in sample and sample['cpu_core'] is not None:
                core = sample['cpu_core']
                if core not in parent_cores:
                    parent_cores[core] = 0
                parent_cores[core] += 1

            # Child processes core usage
            if 'children' in sample:
                for child in sample['children']:
                    child_pid = child['pid']
                    if 'cpu_core' in child['metrics'] and child['metrics']['cpu_core'] is not None:
                        core = child['metrics']['cpu_core']

                        if child_pid not in child_cores:
                            child_cores[child_pid] = {}

                        if core not in child_cores[child_pid]:
                            child_cores[child_pid][core] = 0
                        child_cores[child_pid][core] += 1

                        if core not in child_core_distribution:
                            child_core_distribution[core] = set()
                        child_core_distribution[core].add(child_pid)

        print(f"  Total samples: {len(samples)}")
        print(f"  Parent process cores used: {sorted(parent_cores.keys())}")

        print("\n  Child process core distribution:")
        for pid, cores in sorted(child_cores.items()):
            primary_core = max(cores.items(), key=lambda x: x[1])[0]
            print(f"    PID {pid}: primarily on core {primary_core} ({cores})")

        print("\n  Cores and their processes:")
        for core, pids in sorted(child_core_distribution.items()):
            print(f"    Core {core}: PIDs {sorted(pids)}")

    finally:
        os.unlink(script_path)


def demonstrate_core_affinity():
    """Demonstrate tracking when a process has CPU affinity set."""
    print("\nDemonstrating CPU affinity tracking...")

    # This example uses taskset if available on Linux
    import platform
    import shutil

    if platform.system() != 'Linux':
        print("  CPU core tracking is only available on Linux")
        return

    if not shutil.which('taskset'):
        print("  'taskset' command not found. Skipping affinity demonstration.")
        return

    # Pin process to CPU core 0
    monitor = denet.ProcessMonitor(
        cmd=["taskset", "-c", "0", "python", "-c",
             "import time; start=time.time(); [sum(i*i for i in range(10000)) for _ in range(50000) if time.time()-start < 1]"],
        base_interval_ms=50,
        max_interval_ms=100,
        store_in_memory=True
    )

    monitor.run()
    samples = monitor.get_samples()

    core_usage, core_switches = analyze_cpu_core_usage(samples)

    print(f"  Process pinned to core 0")
    print(f"  Cores used: {sorted(core_usage.keys())}")
    print(f"  Core switches: {core_switches}")

    if core_usage and max(core_usage.keys()) == 0 and len(core_usage) == 1:
        print("  ✓ Process stayed on core 0 as expected")
    else:
        print("  ⚠ Process may have moved between cores despite affinity setting")


def main():
    """Run all CPU core tracking demonstrations."""
    print("CPU Core Tracking Demonstration")
    print("=" * 50)

    import platform
    if platform.system() != 'Linux':
        print("Note: CPU core tracking is currently only supported on Linux.")
        print("On other platforms, the cpu_core field will be None.")
        return

    # Test 1: Single process core tracking
    test_single_process_core_tracking()

    # Test 2: Multi-process core distribution
    test_multiprocess_core_distribution()

    # Test 3: CPU affinity demonstration
    demonstrate_core_affinity()

    print("\nCPU core tracking demonstration complete!")
    print("\nKey insights:")
    print("- Processes may switch between cores due to OS scheduling")
    print("- Multiple processes tend to be distributed across available cores")
    print("- CPU affinity can be used to pin processes to specific cores")
    print("- Core tracking helps identify scheduling patterns and potential bottlenecks")


if __name__ == "__main__":
    main()
