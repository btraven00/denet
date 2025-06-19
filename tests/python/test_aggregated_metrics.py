import json
import os
import time
import subprocess
import tempfile

import denet


def test_get_summary_with_process_tree():
    """Test that Monitor.get_summary correctly handles process tree metrics"""
    # Create fake samples as JSON strings (matching the format Monitor.get_samples() returns)
    samples = []

    # First sample is a metrics sample with ts_ms
    sample1 = {
        "ts_ms": 1100,
        "cpu_usage": 10.0,
        "mem_rss_kb": 5000,
        "mem_vms_kb": 10000,
        "disk_read_bytes": 1024,
        "disk_write_bytes": 2048,
        "net_rx_bytes": 512,
        "net_tx_bytes": 256,
        "thread_count": 1,
        "uptime_secs": 10,
    }
    samples.append(json.dumps(sample1))

    # Second sample is an aggregated metrics sample
    aggregated_sample = {
        "ts_ms": 1200,
        "cpu_usage": 30.0,
        "mem_rss_kb": 10000,
        "mem_vms_kb": 20000,
        "disk_read_bytes": 2048,
        "disk_write_bytes": 4096,
        "net_rx_bytes": 1024,
        "net_tx_bytes": 512,
        "thread_count": 3,
        "process_count": 3,  # Important: this is what tells us it's a process tree
        "uptime_secs": 20,
    }
    samples.append(json.dumps(aggregated_sample))

    # Create a Monitor instance and inject our fake samples
    monitor = denet.Monitor()
    monitor.samples = samples

    # Get the summary
    summary_json = monitor.get_summary()
    summary = json.loads(summary_json)
    print(f"Python Monitor.get_summary result: {summary}")

    # Verify the summary correctly includes the process tree information
    assert summary["max_processes"] == 3, "Summary should show 3 processes from aggregated metrics"
    assert summary["peak_mem_rss_kb"] == 10000, "Summary should use the max memory value"
    assert summary["avg_cpu_usage"] > 0.0, "Summary should calculate correct CPU usage"

    # Verify the process count is preserved when saving to a file
    with tempfile.NamedTemporaryFile(suffix=".json", delete=False) as tmp:
        temp_file = tmp.name

    try:
        monitor.save_samples(temp_file, "json")

        # Read the file back - need to handle JSONL or JSON format
        with open(temp_file) as f:
            content = f.read()

        try:
            # Try loading as a JSON array
            saved_data = json.loads(content)
        except json.JSONDecodeError:
            # Try loading as JSONL (one JSON object per line)
            saved_data = [json.loads(line) for line in content.strip().split("\n") if line.strip()]

        # Check that we have our metrics
        assert len(saved_data) == 2, "Should have two metrics samples"

        # Find the aggregated metrics
        aggregated_samples = []
        for s in saved_data:
            s_obj = json.loads(s) if isinstance(s, str) else s
            if "process_count" in s_obj:
                aggregated_samples.append(s_obj)

        assert len(aggregated_samples) > 0, "Should have at least one aggregated sample"
        assert aggregated_samples[0]["process_count"] == 3, "Process count should be 3"

    finally:
        # Clean up the temporary file
        if os.path.exists(temp_file):
            os.unlink(temp_file)


def test_aggregated_metrics_direct_binding(tmp_path):
    """Test that aggregated metrics are correctly handled in Python bindings using direct Rust calls"""

    # Create a command that spawns child processes
    # This script will create a parent process that spawns multiple child processes
    child_script = """
import time
import multiprocessing
import os
import sys

def cpu_intensive_task():
    # Make this more CPU intensive to ensure it's captured
    start = time.time()
    while time.time() - start < 0.5:
        _ = [i * i * i for i in range(10000)]
    print(f"Child process {os.getpid()} completed")

if __name__ == "__main__":
    print(f"Parent process: {os.getpid()}")
    sys.stdout.flush()

    # Start multiple child processes to ensure they're captured
    processes = []
    for i in range(3):  # Create 3 child processes
        p = multiprocessing.Process(target=cpu_intensive_task)
        processes.append(p)
        p.start()
        print(f"Started child process {p.pid}")
        sys.stdout.flush()
        # Small delay to ensure processes start separately
        time.sleep(0.1)

    # Make sure the main process stays alive long enough for monitoring
    time.sleep(0.5)

    # Wait for all children to finish
    for p in processes:
        p.join()

    print("All child processes completed")
    sys.stdout.flush()
"""

    # Create a temporary file for the script
    script_path = tmp_path / "child_process.py"
    script_path.write_text(child_script)

    # Start the Python process manually so we can monitor it directly
    proc = subprocess.Popen(
        ["python", str(script_path)],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
    )

    # Give it a moment to start and print its PID
    time.sleep(0.2)

    # Get the parent process PID
    parent_pid = proc.pid
    print(f"Monitoring parent process with PID: {parent_pid}")

    # Find child PIDs
    ps_output = subprocess.check_output(["ps", "--ppid", str(parent_pid), "-o", "pid="], text=True).strip()
    child_pids = [int(pid.strip()) for pid in ps_output.split("\n") if pid.strip()]
    print(f"Found {len(child_pids)} child processes: {child_pids}")

    # Create monitors for parent and each child process
    monitors = {}

    # Monitor for parent
    parent_monitor = denet.ProcessMonitor.from_pid(
        pid=parent_pid, base_interval_ms=100, max_interval_ms=1000, store_in_memory=True, include_children=True
    )
    monitors[parent_pid] = parent_monitor

    # Monitors for children
    for child_pid in child_pids:
        try:
            child_monitor = denet.ProcessMonitor.from_pid(
                pid=child_pid, base_interval_ms=100, max_interval_ms=1000, store_in_memory=True, include_children=True
            )
            monitors[child_pid] = child_monitor
        except Exception as e:
            print(f"Error monitoring child {child_pid}: {e}")

    # Sample all processes and manually create tree samples
    samples_with_tree = []

    # Sample for a few seconds to make sure we catch the processes
    start_time = time.time()
    running_pids = set(monitors.keys())

    while time.time() - start_time < 3.0 and proc.poll() is None and running_pids:
        # Remove non-running processes
        pids_to_remove = set()
        for pid in running_pids:
            if not monitors[pid].is_running():
                pids_to_remove.add(pid)
        running_pids -= pids_to_remove

        # Create a tree sample
        tree_sample = {
            "ts_ms": int(time.time() * 1000),
            "parent": None,
            "children": [],
            "aggregated": {
                "ts_ms": int(time.time() * 1000),
                "cpu_usage": 0.0,
                "mem_rss_kb": 0,
                "thread_count": 0,
                "process_count": len(running_pids),
            },
        }

        # Sample each process
        for pid in running_pids:
            monitor = monitors[pid]
            sample_json = monitor.sample_once()

            if sample_json:
                try:
                    sample = json.loads(sample_json)

                    # Skip metadata samples
                    if all(key in sample for key in ["pid", "cmd", "executable", "t0_ms"]):
                        continue

                    # Add parent or child metrics
                    if pid == parent_pid:
                        tree_sample["parent"] = sample
                    else:
                        tree_sample["children"].append({"pid": pid, "command": "python_child", "metrics": sample})

                    # Aggregate metrics
                    agg = tree_sample["aggregated"]
                    agg["cpu_usage"] += sample.get("cpu_usage", 0)
                    agg["mem_rss_kb"] += sample.get("mem_rss_kb", 0)
                    agg["thread_count"] += sample.get("thread_count", 0)
                except Exception as e:
                    print(f"Error processing sample: {e}")

        # Add sample if it has parent or children
        if tree_sample["parent"] or tree_sample["children"]:
            samples_with_tree.append(tree_sample)
            print(f"Created tree sample with {len(tree_sample['children'])} children")

        time.sleep(0.1)

    # Wait for the process to complete if it hasn't already
    if proc.poll() is None:
        proc.terminate()
        try:
            proc.wait(timeout=1.0)
        except subprocess.TimeoutExpired:
            proc.kill()

    # Get stdout/stderr for debugging
    stdout, stderr = proc.communicate()
    print(f"Process stdout: {stdout}")
    print(f"Process stderr: {stderr}")

    # Create aggregated metrics manually from the collected samples
    tree_metrics_json = []
    for sample in samples_with_tree:
        # Convert to a format that includes the aggregated field
        if "parent" in sample and "children" in sample:
            # Add the "aggregated" field if not present
            if "aggregated" not in sample:
                # Create a sample with manually computed aggregation
                metrics = []
                if sample["parent"]:
                    metrics.append(sample["parent"])
                for child in sample["children"]:
                    if "metrics" in child:
                        metrics.append(child["metrics"])

                # Manually compute process_count
                process_count = (1 if sample["parent"] else 0) + len(sample["children"])

                # Add a basic aggregated field for testing
                sample["aggregated"] = {
                    "ts_ms": sample.get("ts_ms", 0),
                    "process_count": process_count,
                    "cpu_usage": sum(m.get("cpu_usage", 0) for m in metrics),
                    "mem_rss_kb": sum(m.get("mem_rss_kb", 0) for m in metrics),
                    "thread_count": sum(m.get("thread_count", 0) for m in metrics),
                }

            # Use the full sample with aggregated metrics
            tree_metrics_json.append(json.dumps(sample))

    # Test if we collected any process tree samples
    assert len(samples_with_tree) > 0, "No process tree samples collected"

    # Test if at least one sample has multiple processes
    multi_process_samples = [s for s in samples_with_tree if len(s.get("children", [])) > 0]
    assert len(multi_process_samples) > 0, "No samples with child processes found"

    # Test if the aggregated metrics show multiple processes
    samples_with_multi_process = [s for s in samples_with_tree if s.get("aggregated", {}).get("process_count", 0) > 1]
    assert len(samples_with_multi_process) > 0, "No samples with multiple processes in aggregated metrics"

    # Now test the summary generation with our aggregated metrics
    if samples_with_tree:
        # Create a monitor and inject our samples
        monitor = denet.Monitor()

        # Convert samples to the format expected by Monitor.get_summary()
        monitor_samples = []
        for sample in samples_with_tree:
            monitor_samples.append(json.dumps(sample))

        monitor.samples = monitor_samples

        # Get summary using the fixed Monitor.get_summary() method
        summary_json = monitor.get_summary()
        summary = json.loads(summary_json)
        print(f"Generated summary: {summary}")

        # Verify summary has expected fields
        assert "avg_cpu_usage" in summary
        assert "peak_mem_rss_kb" in summary
        assert "max_processes" in summary

        # The key test: max_processes should reflect the process tree
        assert summary["max_processes"] > 1, "Summary doesn't show multiple processes, aggregation may not be working"


def test_single_process_summary():
    """Test that summary provides correct aggregated metrics even for single processes"""

    # Use execute_with_monitoring for consistency
    exit_code, monitor = denet.execute_with_monitoring(
        cmd=["python", "-c", "import time; time.sleep(0.5)"],
        base_interval_ms=100,
        max_interval_ms=1000,
        include_children=True,
    )

    # Get summary
    summary_json = monitor.get_summary()
    summary = json.loads(summary_json)
    print(f"Single process summary: {summary}")

    # Verify summary has expected fields
    assert "avg_cpu_usage" in summary
    assert "peak_mem_rss_kb" in summary
    assert "sample_count" in summary
    assert summary["sample_count"] > 0

    # The values should be valid
    assert summary["avg_cpu_usage"] >= 0
    assert summary["peak_mem_rss_kb"] >= 0

    # For a single process, max_processes should be 1
    assert summary["max_processes"] == 1


def test_manually_constructed_aggregated_metrics():
    """Test that manually constructed aggregated metrics are handled correctly"""

    # Create two aggregated metrics samples directly
    aggregated1 = {
        "ts_ms": 1000,
        "cpu_usage": 30.0,
        "mem_rss_kb": 10000,
        "mem_vms_kb": 20000,
        "thread_count": 3,
        "process_count": 3,  # Parent + 2 children
        "disk_read_bytes": 1792,
        "disk_write_bytes": 3584,
        "net_rx_bytes": 896,
        "net_tx_bytes": 448,
        "uptime_secs": 10,
    }

    aggregated2 = {
        "ts_ms": 2000,
        "cpu_usage": 55.0,
        "mem_rss_kb": 13000,
        "mem_vms_kb": 26000,
        "thread_count": 3,
        "process_count": 3,
        "disk_read_bytes": 3584,
        "disk_write_bytes": 7168,
        "net_rx_bytes": 1792,
        "net_tx_bytes": 896,
        "uptime_secs": 20,
    }

    # Convert to JSON strings
    aggregated_metrics = [json.dumps(aggregated1), json.dumps(aggregated2)]

    # Test using the Python Monitor class which has our fixes
    monitor = denet.Monitor()
    monitor.samples = aggregated_metrics

    # Get summary using the fixed Python method
    summary_json = monitor.get_summary()
    summary = json.loads(summary_json)
    print(f"Summary from Monitor.get_summary(): {summary}")

    # This should reflect the process tree correctly
    assert summary["max_processes"] == 3, "Summary should show 3 processes from aggregated metrics"
    assert summary["peak_mem_rss_kb"] == 13000, "Summary should use the max memory value"
    assert summary["avg_cpu_usage"] > 30.0, "Summary should calculate correct CPU usage"
    assert summary["sample_count"] == 2, "Summary should count samples correctly"

    # For completeness, also show the direct Rust binding result which doesn't handle process_count correctly
    elapsed_time = (aggregated2["ts_ms"] - aggregated1["ts_ms"]) / 1000.0
    rust_summary_json = denet._denet.generate_summary_from_metrics_json(aggregated_metrics, elapsed_time)
    rust_summary = json.loads(rust_summary_json)
    print(f"Summary from direct Rust binding: {rust_summary}")

    # Confirm our Python fix is working correctly
    assert summary["max_processes"] > rust_summary["max_processes"], "Python fix should increase max_processes"
