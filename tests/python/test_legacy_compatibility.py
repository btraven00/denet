"""
Test legacy compatibility and root level test conversion.

This module converts the original root-level tests to pytest style and ensures
backwards compatibility is maintained.
"""

import json
import time
import pytest
import denet
from tests.python.test_helpers import (
    extract_metrics_from_sample,
    is_valid_metrics_sample,
    assert_valid_metrics,
)


class TestLegacyProcessMonitorCompatibility:
    """Test backwards compatibility with legacy ProcessMonitor usage."""

    def test_create_monitor_legacy_style(self):
        """Test that legacy ProcessMonitor creation still works."""
        # This was the original test pattern
        monitor = denet.ProcessMonitor(["echo", "hello"], 100, 1000)
        assert monitor is not None

    def test_invalid_command_legacy(self):
        """Test error handling for invalid commands (legacy style)."""
        with pytest.raises(Exception):
            denet.ProcessMonitor([], 100, 1000)  # Empty command should fail

        with pytest.raises(Exception):
            denet.ProcessMonitor(["non_existent_command_123456"], 100, 1000)

    def test_run_short_process_legacy(self):
        """Test running a short process (converted from original unittest)."""
        # Use a command that outputs something predictable
        cmd = ["python", "-c", "import time; print('TEST OUTPUT'); time.sleep(0.5)"]

        monitor = denet.ProcessMonitor(cmd, 100, 1000)
        monitor.run()  # This should complete when the process ends

        # If we get here without hanging, the test passes
        assert True

    def test_long_running_process_legacy(self, tmp_path):
        """Test monitoring a longer running process (converted from unittest)."""
        # Create a separate test script that we'll run
        test_script_content = """
import time
import sys
for i in range(5):
    sys.stdout.write(f"MARKER: {i}\\n")
    sys.stdout.flush()
    time.sleep(0.2)
"""

        test_script = tmp_path / "test_script.py"
        with open(test_script, "w") as f:
            f.write(test_script_content)

        import threading

        # Create monitor with store_in_memory enabled for testing
        monitor = denet.ProcessMonitor(["python", str(test_script)], 100, 1000, store_in_memory=True)

        # Give the process time to start
        time.sleep(0.3)

        # Get a sample directly
        sample_json = monitor.sample_once()

        # Let the process finish
        thread = threading.Thread(target=monitor.run)
        thread.daemon = True  # Make sure thread doesn't block test exit
        thread.start()
        thread.join(timeout=5)  # Should finish in under 5 seconds

        assert not thread.is_alive(), "Monitor should have completed"

        # Verify we got a valid JSON output from our direct sample
        assert sample_json is not None, "Should have sample data"

        if sample_json:
            # Parse the JSON metrics
            data = json.loads(sample_json)

            # Skip metadata if this is a metadata sample
            if all(key in data for key in ["pid", "cmd", "executable", "t0_ms"]):
                # This is metadata, skip validation
                return

            # Verify the JSON has the expected fields for metrics
            if is_valid_metrics_sample(data):
                metrics = extract_metrics_from_sample(data)
                assert_valid_metrics(metrics)

                # Verify timestamp is reasonable (within last minute)
                now_ms = int(time.time() * 1000)
                assert abs(now_ms - metrics["ts_ms"]) < 60000, "Timestamp should be recent"

                # Verify memory metrics are reasonable
                assert metrics["mem_rss_kb"] > 0, "RSS memory should be positive"

    def test_timestamp_functionality_legacy(self):
        """Test that timestamps are included and monotonic (converted from unittest)."""
        monitor = denet.ProcessMonitor(["sleep", "2"], 100, 1000, store_in_memory=True)

        # Collect multiple samples
        samples = []
        for _ in range(3):
            result = monitor.sample_once()
            if result:
                data = json.loads(result)
                if is_valid_metrics_sample(data):
                    metrics = extract_metrics_from_sample(data)
                    samples.append(metrics)
            time.sleep(0.1)

        assert len(samples) > 0, "Should collect at least one sample"

        for sample in samples:
            # Verify timestamp is reasonable (within last minute)
            now_ms = int(time.time() * 1000)
            assert abs(now_ms - sample["ts_ms"]) < 60000, "Timestamp should be recent"

        # Verify timestamps are monotonic if we have multiple samples
        if len(samples) >= 2:
            for i in range(1, len(samples)):
                assert samples[i]["ts_ms"] >= samples[i - 1]["ts_ms"], "Timestamps should be monotonic"


class TestLegacySummaryCompatibility:
    """Test backwards compatibility with legacy summary functionality."""

    def test_generate_summary_from_metrics_json_legacy(self):
        """Test generating a summary from JSON metrics strings (converted from unittest)."""
        # Create sample metrics
        metrics = []

        # First sample
        metrics.append(
            json.dumps(
                {
                    "ts_ms": 1000,
                    "cpu_usage": 5.0,
                    "mem_rss_kb": 1024,
                    "mem_vms_kb": 2048,
                    "disk_read_bytes": 1000,
                    "disk_write_bytes": 2000,
                    "net_rx_bytes": 300,
                    "net_tx_bytes": 400,
                    "thread_count": 2,
                    "uptime_secs": 10,
                }
            )
        )

        # Second sample with higher values
        metrics.append(
            json.dumps(
                {
                    "ts_ms": 2000,
                    "cpu_usage": 15.0,
                    "mem_rss_kb": 2048,
                    "mem_vms_kb": 4096,
                    "disk_read_bytes": 2500,
                    "disk_write_bytes": 3000,
                    "net_rx_bytes": 800,
                    "net_tx_bytes": 900,
                    "thread_count": 3,
                    "uptime_secs": 20,
                }
            )
        )

        # Calculate duration from timestamps
        elapsed_time = (2000 - 1000) / 1000.0  # 1 second

        # Generate summary
        summary_json = denet.generate_summary_from_metrics_json(metrics, elapsed_time)
        summary = json.loads(summary_json)

        # Verify summary contents
        assert summary["total_time_secs"] == elapsed_time
        assert summary["sample_count"] == 2
        assert summary["max_processes"] == 1  # Default for regular metrics
        assert summary["max_threads"] == 3  # Highest value from samples
        assert summary["total_disk_read_bytes"] == 2500  # Highest value
        assert summary["total_disk_write_bytes"] == 3000  # Highest value
        assert summary["total_net_rx_bytes"] == 800  # Highest value
        assert summary["total_net_tx_bytes"] == 900  # Highest value
        assert summary["peak_mem_rss_kb"] == 2048  # Highest value
        assert summary["avg_cpu_usage"] == 10.0  # (5 + 15) / 2

    def test_generate_summary_from_tree_metrics_json_legacy(self):
        """Test generating summary from tree metrics JSON strings (converted from unittest)."""
        metrics = []

        # Create tree metrics with aggregated data - first sample
        tree_metric1 = {
            "ts_ms": 1000,
            "parent": {
                "ts_ms": 1000,
                "cpu_usage": 2.5,
                "mem_rss_kb": 1024,
                "mem_vms_kb": 2048,
                "disk_read_bytes": 500,
                "disk_write_bytes": 1000,
                "net_rx_bytes": 200,
                "net_tx_bytes": 300,
                "thread_count": 1,
                "uptime_secs": 5,
            },
            "children": [],
            "aggregated": {
                "ts_ms": 1000,
                "cpu_usage": 4.0,
                "mem_rss_kb": 1536,
                "mem_vms_kb": 3072,
                "disk_read_bytes": 600,
                "disk_write_bytes": 1200,
                "net_rx_bytes": 250,
                "net_tx_bytes": 360,
                "thread_count": 2,
                "process_count": 2,
                "uptime_secs": 5,
            },
        }
        metrics.append(json.dumps(tree_metric1))

        # Add a second sample with higher values
        tree_metric2 = {
            "ts_ms": 2000,
            "parent": {
                "ts_ms": 2000,
                "cpu_usage": 3.0,
                "mem_rss_kb": 1536,
                "mem_vms_kb": 3072,
                "disk_read_bytes": 600,
                "disk_write_bytes": 1200,
                "net_rx_bytes": 250,
                "net_tx_bytes": 360,
                "thread_count": 1,
                "uptime_secs": 6,
            },
            "children": [],
            "aggregated": {
                "ts_ms": 2000,
                "cpu_usage": 6.0,
                "mem_rss_kb": 2048,
                "mem_vms_kb": 4096,
                "disk_read_bytes": 800,
                "disk_write_bytes": 1500,
                "net_rx_bytes": 350,
                "net_tx_bytes": 460,
                "thread_count": 3,
                "process_count": 3,
                "uptime_secs": 6,
            },
        }
        metrics.append(json.dumps(tree_metric2))

        # Generate summary
        elapsed_time = 1.0  # 1 second
        summary_json = denet.generate_summary_from_metrics_json(metrics, elapsed_time)
        summary = json.loads(summary_json)

        # Verify summary contents
        assert summary["sample_count"] == 2
        assert summary["max_processes"] == 3  # Max from second sample
        assert summary["max_threads"] == 3  # Max from second sample
        assert summary["peak_mem_rss_kb"] == 2048  # Highest value
        assert summary["total_disk_read_bytes"] == 800  # Highest value
        assert summary["total_disk_write_bytes"] == 1500  # Highest value

    def test_generate_summary_from_file_legacy(self, tmp_path):
        """Test generating summary from a JSON file (converted from unittest)."""
        # Create a temporary file with test metrics
        temp_file = tmp_path / "test_metrics.json"
        with open(temp_file, "w") as f:
            # Write a few sample metrics
            f.write(
                json.dumps(
                    {
                        "ts_ms": 1000,
                        "cpu_usage": 5.0,
                        "mem_rss_kb": 1024,
                        "mem_vms_kb": 2048,
                        "disk_read_bytes": 1000,
                        "disk_write_bytes": 2000,
                        "net_rx_bytes": 300,
                        "net_tx_bytes": 400,
                        "thread_count": 2,
                        "uptime_secs": 10,
                    }
                )
                + "\n"
            )

            f.write(
                json.dumps(
                    {
                        "ts_ms": 2000,
                        "cpu_usage": 15.0,
                        "mem_rss_kb": 2048,
                        "mem_vms_kb": 4096,
                        "disk_read_bytes": 2500,
                        "disk_write_bytes": 3000,
                        "net_rx_bytes": 800,
                        "net_tx_bytes": 900,
                        "thread_count": 3,
                        "uptime_secs": 20,
                    }
                )
                + "\n"
            )

        # Generate summary from the file
        summary_json = denet.generate_summary_from_file(str(temp_file))
        summary = json.loads(summary_json)

        # Verify summary contents
        assert summary["sample_count"] == 2
        assert summary["total_time_secs"] == 1.0  # (2000-1000)/1000
        assert summary["max_threads"] == 3
        assert summary["peak_mem_rss_kb"] == 2048
        assert summary["avg_cpu_usage"] == 10.0  # (5 + 15) / 2


class TestBackwardsCompatibilityAPI:
    """Test that the old API patterns still work."""

    def test_old_constructor_signature(self):
        """Test that old constructor signatures still work."""
        # Old style: positional arguments
        monitor = denet.ProcessMonitor(["echo", "test"], 100, 1000)
        assert monitor is not None

        # New style: keyword arguments should also work
        monitor = denet.ProcessMonitor(cmd=["echo", "test"], base_interval_ms=100, max_interval_ms=1000)
        assert monitor is not None

    def test_old_method_names_work(self):
        """Test that old method names and patterns still work."""
        monitor = denet.ProcessMonitor(["sleep", "0.1"], 100, 1000, store_in_memory=True)

        # Old patterns should still work
        sample = monitor.sample_once()
        assert sample is not None

        pid = monitor.get_pid()
        assert isinstance(pid, int)

        is_running = monitor.is_running()
        assert isinstance(is_running, bool)

        samples = monitor.get_samples()
        assert isinstance(samples, list)

        summary = monitor.get_summary()
        assert isinstance(summary, str)

    def test_legacy_file_operations(self, tmp_path):
        """Test that legacy file operation patterns work."""
        monitor = denet.ProcessMonitor(["sleep", "0.1"], 100, 1000, store_in_memory=True)

        # Take a sample
        monitor.sample_once()

        # Test save operations in different formats
        formats = ["jsonl", "json", "csv"]
        for fmt in formats:
            temp_file = tmp_path / f"test_output.{fmt}"

            monitor.save_samples(str(temp_file), fmt)
            assert temp_file.exists()

            with open(temp_file, "r") as f:
                content = f.read()
                assert len(content.strip()) > 0
