"""
Test Python bindings to Rust core functionality.

This module tests that the Python bindings correctly interface with the Rust core,
focusing on data flow and API contracts rather than reimplementing functionality.
"""

import json
import os
import time
import pytest
import denet
from tests.python.test_helpers import (
    extract_metrics_from_sample,
    is_valid_metrics_sample,
    assert_valid_metrics,
    create_sample_metrics,
)


class TestProcessMonitorBindings:
    """Test ProcessMonitor Python bindings."""

    def test_create_process_monitor(self):
        """Test ProcessMonitor can be created with valid parameters."""
        monitor = denet.ProcessMonitor(cmd=["echo", "test"], base_interval_ms=100, max_interval_ms=1000)
        assert monitor is not None

    def test_create_from_pid(self):
        """Test ProcessMonitor can be created from PID."""
        current_pid = os.getpid()
        monitor = denet.ProcessMonitor.from_pid(pid=current_pid, base_interval_ms=100, max_interval_ms=1000)
        assert monitor is not None
        assert monitor.get_pid() == current_pid

    def test_invalid_command_raises_exception(self):
        """Test that invalid commands raise appropriate exceptions."""
        with pytest.raises(Exception):
            denet.ProcessMonitor(cmd=[], base_interval_ms=100, max_interval_ms=1000)

    def test_sample_once_returns_valid_json(self):
        """Test that sample_once returns valid JSON string."""
        monitor = denet.ProcessMonitor(cmd=["sleep", "1"], base_interval_ms=100, max_interval_ms=1000)

        sample = monitor.sample_once()
        assert sample is not None

        # Should be valid JSON
        data = json.loads(sample)
        assert isinstance(data, dict)

        # Should contain expected fields if it's a metrics sample
        if is_valid_metrics_sample(data):
            metrics = extract_metrics_from_sample(data)
            assert_valid_metrics(metrics)

    def test_get_pid_returns_integer(self):
        """Test that get_pid returns a valid PID."""
        monitor = denet.ProcessMonitor(cmd=["sleep", "1"], base_interval_ms=100, max_interval_ms=1000)

        pid = monitor.get_pid()
        assert isinstance(pid, int)
        assert pid > 0

    def test_is_running_returns_boolean(self):
        """Test that is_running returns a boolean."""
        monitor = denet.ProcessMonitor(cmd=["sleep", "0.1"], base_interval_ms=100, max_interval_ms=1000)

        # Should be running initially
        assert isinstance(monitor.is_running(), bool)

    def test_store_in_memory_functionality(self):
        """Test that store_in_memory parameter works correctly."""
        # Test with memory storage enabled
        monitor_with_memory = denet.ProcessMonitor(
            cmd=["sleep", "0.2"], base_interval_ms=50, max_interval_ms=1000, store_in_memory=True
        )

        # Take a few samples
        for _ in range(3):
            monitor_with_memory.sample_once()
            time.sleep(0.05)

        samples = monitor_with_memory.get_samples()
        assert len(samples) > 0

        # Test with memory storage disabled
        monitor_without_memory = denet.ProcessMonitor(
            cmd=["sleep", "0.2"], base_interval_ms=50, max_interval_ms=1000, store_in_memory=False
        )

        # Take a few samples
        for _ in range(3):
            monitor_without_memory.sample_once()
            time.sleep(0.05)

        samples = monitor_without_memory.get_samples()
        assert len(samples) == 0

    def test_get_samples_returns_list(self):
        """Test that get_samples returns a list of strings."""
        monitor = denet.ProcessMonitor(
            cmd=["sleep", "0.2"], base_interval_ms=100, max_interval_ms=1000, store_in_memory=True
        )

        monitor.sample_once()
        samples = monitor.get_samples()

        assert isinstance(samples, list)
        for sample in samples:
            assert isinstance(sample, str)
            # Should be valid JSON
            json.loads(sample)

    def test_clear_samples_functionality(self):
        """Test that clear_samples works correctly."""
        monitor = denet.ProcessMonitor(
            cmd=["sleep", "0.2"], base_interval_ms=100, max_interval_ms=1000, store_in_memory=True
        )

        monitor.sample_once()
        assert len(monitor.get_samples()) > 0

        monitor.clear_samples()
        assert len(monitor.get_samples()) == 0

    def test_get_summary_returns_valid_json(self):
        """Test that get_summary returns valid JSON string."""
        monitor = denet.ProcessMonitor(
            cmd=["sleep", "0.2"], base_interval_ms=100, max_interval_ms=1000, store_in_memory=True
        )

        # Take a few samples
        for _ in range(3):
            monitor.sample_once()
            time.sleep(0.05)

        summary_json = monitor.get_summary()
        assert isinstance(summary_json, str)

        summary = json.loads(summary_json)
        assert isinstance(summary, dict)

        # Should contain expected summary fields
        expected_fields = ["avg_cpu_usage", "peak_mem_rss_kb", "sample_count", "total_time_secs"]
        for field in expected_fields:
            assert field in summary

    def test_save_samples_creates_file(self, tmp_path):
        """Test that save_samples creates output files correctly."""
        monitor = denet.ProcessMonitor(
            cmd=["sleep", "0.2"], base_interval_ms=100, max_interval_ms=1000, store_in_memory=True
        )

        # Take a few samples
        for _ in range(3):
            monitor.sample_once()
            time.sleep(0.05)

        # Test JSONL format
        temp_file = tmp_path / "test_samples.jsonl"

        monitor.save_samples(str(temp_file), "jsonl")
        assert temp_file.exists()

        with open(temp_file, "r") as f:
            lines = [line.strip() for line in f if line.strip()]
            assert len(lines) > 0

            # Each line should be valid JSON
            for line in lines:
                json.loads(line)


class TestSummaryGenerationBindings:
    """Test summary generation function bindings."""

    def test_generate_summary_from_metrics_json(self):
        """Test generate_summary_from_metrics_json function."""
        # Create sample metrics as JSON strings
        sample_metrics = create_sample_metrics(3)
        metrics_json = [json.dumps(metric) for metric in sample_metrics]

        # Calculate elapsed time
        elapsed_time = (sample_metrics[-1]["ts_ms"] - sample_metrics[0]["ts_ms"]) / 1000.0

        # Generate summary
        summary_json = denet.generate_summary_from_metrics_json(metrics_json, elapsed_time)
        assert isinstance(summary_json, str)

        summary = json.loads(summary_json)
        assert isinstance(summary, dict)

        # Verify expected fields
        expected_fields = ["sample_count", "total_time_secs", "avg_cpu_usage", "peak_mem_rss_kb"]
        for field in expected_fields:
            assert field in summary

    def test_generate_summary_from_file(self, tmp_path):
        """Test generate_summary_from_file function."""
        # Create temporary file with sample metrics
        sample_metrics = create_sample_metrics(3)

        temp_file = tmp_path / "test_metrics.jsonl"
        with open(temp_file, "w") as f:
            for metric in sample_metrics:
                f.write(json.dumps(metric) + "\n")

        summary_json = denet.generate_summary_from_file(str(temp_file))
        assert isinstance(summary_json, str)

        summary = json.loads(summary_json)
        assert isinstance(summary, dict)

        # Verify expected fields
        expected_fields = ["sample_count", "total_time_secs", "avg_cpu_usage", "peak_mem_rss_kb"]
        for field in expected_fields:
            assert field in summary

    def test_empty_metrics_handling(self):
        """Test that empty metrics are handled gracefully."""
        summary_json = denet.generate_summary_from_metrics_json([], 0.0)
        summary = json.loads(summary_json)

        # Should still be valid JSON with sample_count = 0
        assert summary["sample_count"] == 0


class TestDataIntegrity:
    """Test data integrity between Python and Rust."""

    def test_metrics_data_types(self):
        """Test that metrics contain correct data types."""
        monitor = denet.ProcessMonitor(
            cmd=["sleep", "0.1"], base_interval_ms=100, max_interval_ms=1000, store_in_memory=True
        )

        sample = monitor.sample_once()
        data = json.loads(sample)

        if is_valid_metrics_sample(data):
            metrics = extract_metrics_from_sample(data)

            # Check data types
            assert isinstance(metrics["ts_ms"], (int, float))
            assert isinstance(metrics["cpu_usage"], (int, float))
            assert isinstance(metrics["mem_rss_kb"], (int, float))

            # Check reasonable value ranges
            assert metrics["ts_ms"] > 0
            assert metrics["cpu_usage"] >= 0
            assert metrics["mem_rss_kb"] > 0

    def test_json_serialization_roundtrip(self):
        """Test that data survives JSON serialization roundtrip."""
        monitor = denet.ProcessMonitor(
            cmd=["sleep", "0.1"], base_interval_ms=100, max_interval_ms=1000, store_in_memory=True
        )

        # Get original sample
        original_sample = monitor.sample_once()
        original_data = json.loads(original_sample)

        # Serialize and deserialize
        serialized = json.dumps(original_data)
        deserialized = json.loads(serialized)

        # Should be identical
        assert original_data == deserialized

    def test_concurrent_access_safety(self):
        """Test that concurrent access to monitor is safe."""
        import threading

        monitor = denet.ProcessMonitor(
            cmd=["sleep", "0.5"], base_interval_ms=50, max_interval_ms=1000, store_in_memory=True
        )

        results = []

        def sample_worker():
            try:
                for _ in range(5):
                    sample = monitor.sample_once()
                    if sample:
                        results.append(sample)
                    time.sleep(0.02)
            except Exception as e:
                results.append(f"ERROR: {e}")

        # Start multiple threads
        threads = [threading.Thread(target=sample_worker) for _ in range(3)]
        for thread in threads:
            thread.start()

        for thread in threads:
            thread.join()

        # Should have collected samples without errors
        assert len(results) > 0
        errors = [r for r in results if isinstance(r, str) and r.startswith("ERROR")]
        assert len(errors) == 0, f"Concurrent access errors: {errors}"
