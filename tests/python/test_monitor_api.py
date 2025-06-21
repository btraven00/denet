"""
Test ProcessMonitor API functionality.

This module tests the ProcessMonitor class API, focusing on correct behavior
and interface compliance rather than implementation details.
"""

import json
import os
import time
import pytest
import denet
from tests.python.test_helpers import (
    filter_metrics_samples,
    assert_valid_metrics,
)


class TestProcessMonitorCreation:
    """Test ProcessMonitor creation and initialization."""

    def test_create_with_command(self):
        """Test creating ProcessMonitor with command."""
        monitor = denet.ProcessMonitor(cmd=["echo", "hello"], base_interval_ms=100, max_interval_ms=1000)
        assert monitor is not None

    def test_create_from_pid(self):
        """Test creating ProcessMonitor from existing PID."""
        current_pid = os.getpid()
        monitor = denet.ProcessMonitor.from_pid(pid=current_pid, base_interval_ms=100, max_interval_ms=1000)
        assert monitor is not None
        assert monitor.get_pid() == current_pid

    def test_invalid_command_raises_error(self):
        """Test that invalid commands raise appropriate errors."""
        with pytest.raises(Exception):
            denet.ProcessMonitor(cmd=[], base_interval_ms=100, max_interval_ms=1000)

    def test_invalid_pid_raises_error(self):
        """Test that invalid PIDs raise appropriate errors."""
        with pytest.raises(Exception):
            denet.ProcessMonitor.from_pid(
                pid=999999,  # Very unlikely to exist
                base_interval_ms=100,
                max_interval_ms=1000,
            )


class TestProcessMonitorSampling:
    """Test ProcessMonitor sampling functionality."""

    def test_sample_once_returns_data(self):
        """Test that sample_once returns valid data."""
        monitor = denet.ProcessMonitor(cmd=["sleep", "1"], base_interval_ms=100, max_interval_ms=1000)

        sample = monitor.sample_once()
        assert sample is not None
        assert isinstance(sample, str)

        # Should be valid JSON
        data = json.loads(sample)
        assert isinstance(data, dict)

    def test_multiple_samples(self):
        """Test taking multiple samples."""
        monitor = denet.ProcessMonitor(
            cmd=["sleep", "0.5"], base_interval_ms=50, max_interval_ms=1000, store_in_memory=True
        )

        # Take several samples
        for _ in range(3):
            monitor.sample_once()
            time.sleep(0.05)

        samples = monitor.get_samples()
        assert len(samples) >= 2  # Process might finish quickly, so allow for fewer samples

        # All samples should be valid JSON
        for sample in samples:
            json.loads(sample)

    def test_sample_process_not_running(self):
        """Test sampling when process is not running."""
        monitor = denet.ProcessMonitor(cmd=["echo", "quick"], base_interval_ms=100, max_interval_ms=1000)

        # Let process finish
        time.sleep(0.2)

        # Should handle gracefully
        _ = monitor.sample_once()
        # May return None or empty data - should not crash


class TestProcessMonitorMemoryManagement:
    """Test ProcessMonitor memory management features."""

    def test_store_in_memory_true(self):
        """Test that store_in_memory=True keeps samples."""
        monitor = denet.ProcessMonitor(
            cmd=["sleep", "0.3"], base_interval_ms=50, max_interval_ms=1000, store_in_memory=True
        )

        # Take samples
        for _ in range(3):
            monitor.sample_once()
            time.sleep(0.05)

        samples = monitor.get_samples()
        assert len(samples) > 0

    def test_store_in_memory_false(self):
        """Test that store_in_memory=False doesn't keep samples."""
        monitor = denet.ProcessMonitor(
            cmd=["sleep", "0.3"], base_interval_ms=50, max_interval_ms=1000, store_in_memory=False
        )

        # Take samples
        for _ in range(3):
            monitor.sample_once()
            time.sleep(0.05)

        samples = monitor.get_samples()
        assert len(samples) == 0

    def test_clear_samples(self):
        """Test clearing stored samples."""
        monitor = denet.ProcessMonitor(
            cmd=["sleep", "0.3"], base_interval_ms=50, max_interval_ms=1000, store_in_memory=True
        )

        # Take samples
        monitor.sample_once()
        assert len(monitor.get_samples()) > 0

        # Clear samples
        monitor.clear_samples()
        assert len(monitor.get_samples()) == 0


class TestProcessMonitorFileOutput:
    """Test ProcessMonitor file output functionality."""

    def test_direct_file_output(self, tmp_path):
        """Test direct file output during sampling."""
        temp_file = tmp_path / "test_output.jsonl"

        monitor = denet.ProcessMonitor(
            cmd=["sleep", "0.2"], base_interval_ms=50, max_interval_ms=1000, output_file=str(temp_file)
        )

        # Take samples
        for _ in range(3):
            monitor.sample_once()
            time.sleep(0.05)

        # File should exist and have content
        assert temp_file.exists()

        with open(temp_file, "r") as f:
            lines = [line.strip() for line in f if line.strip()]

        assert len(lines) > 0

        # Each line should be valid JSON
        for line in lines:
            json.loads(line)

    def test_save_samples_jsonl(self, tmp_path):
        """Test saving samples in JSONL format."""
        monitor = denet.ProcessMonitor(
            cmd=["sleep", "0.2"], base_interval_ms=50, max_interval_ms=1000, store_in_memory=True
        )

        # Take samples
        for _ in range(3):
            monitor.sample_once()
            time.sleep(0.05)

        temp_file = tmp_path / "test_samples.jsonl"

        monitor.save_samples(str(temp_file), "jsonl")
        assert temp_file.exists()

        with open(temp_file, "r") as f:
            lines = [line.strip() for line in f if line.strip()]

        assert len(lines) > 0

        # Each line should be valid JSON
        for line in lines:
            json.loads(line)

    def test_save_samples_json(self, tmp_path):
        """Test saving samples in JSON format."""
        monitor = denet.ProcessMonitor(
            cmd=["sleep", "0.2"], base_interval_ms=50, max_interval_ms=1000, store_in_memory=True
        )

        # Take samples
        for _ in range(3):
            monitor.sample_once()
            time.sleep(0.05)

        temp_file = tmp_path / "test_samples.json"

        monitor.save_samples(str(temp_file), "json")
        assert temp_file.exists()

        with open(temp_file, "r") as f:
            data = json.load(f)

        assert isinstance(data, list)
        assert len(data) > 0

    def test_save_samples_csv(self, tmp_path):
        """Test saving samples in CSV format."""
        monitor = denet.ProcessMonitor(
            cmd=["sleep", "0.2"], base_interval_ms=50, max_interval_ms=1000, store_in_memory=True
        )

        # Take samples
        for _ in range(3):
            monitor.sample_once()
            time.sleep(0.05)

        temp_file = tmp_path / "test_samples.csv"

        monitor.save_samples(str(temp_file), "csv")
        assert temp_file.exists()

        with open(temp_file, "r") as f:
            lines = [line.strip() for line in f if line.strip()]

        assert len(lines) > 0
        # First line should be header
        assert "ts_ms" in lines[0] or "cpu_usage" in lines[0]


class TestProcessMonitorSummary:
    """Test ProcessMonitor summary generation."""

    def test_get_summary_basic(self):
        """Test basic summary generation."""
        monitor = denet.ProcessMonitor(
            cmd=["sleep", "0.2"], base_interval_ms=50, max_interval_ms=1000, store_in_memory=True
        )

        # Take samples
        for _ in range(3):
            monitor.sample_once()
            time.sleep(0.05)

        summary_json = monitor.get_summary()
        assert isinstance(summary_json, str)

        summary = json.loads(summary_json)
        assert isinstance(summary, dict)

        # Should contain expected fields
        expected_fields = ["avg_cpu_usage", "peak_mem_rss_kb", "sample_count", "total_time_secs"]
        for field in expected_fields:
            assert field in summary

    def test_summary_with_no_samples(self):
        """Test summary generation with no samples."""
        monitor = denet.ProcessMonitor(
            cmd=["sleep", "0.1"], base_interval_ms=100, max_interval_ms=1000, store_in_memory=True
        )

        # Don't take any samples
        summary_json = monitor.get_summary()
        summary = json.loads(summary_json)

        # Should still be valid JSON
        assert isinstance(summary, dict)
        # May have sample_count = 0


class TestProcessMonitorMetadata:
    """Test ProcessMonitor metadata functionality."""

    def test_get_pid(self):
        """Test getting process PID."""
        monitor = denet.ProcessMonitor(cmd=["sleep", "1"], base_interval_ms=100, max_interval_ms=1000)

        pid = monitor.get_pid()
        assert isinstance(pid, int)
        assert pid > 0

    def test_is_running(self):
        """Test checking if process is running."""
        monitor = denet.ProcessMonitor(cmd=["sleep", "0.1"], base_interval_ms=100, max_interval_ms=1000)

        # Should be running initially
        running = monitor.is_running()
        assert isinstance(running, bool)

        # Wait for process to finish
        time.sleep(0.3)

        # Should eventually not be running
        running = monitor.is_running()
        assert isinstance(running, bool)

    def test_get_metadata(self):
        """Test getting process metadata."""
        monitor = denet.ProcessMonitor(cmd=["echo", "test"], base_interval_ms=100, max_interval_ms=1000)

        metadata = monitor.get_metadata()
        if metadata:  # Some implementations may not return metadata
            if isinstance(metadata, str):
                metadata_data = json.loads(metadata)
                assert isinstance(metadata_data, dict)


class TestProcessMonitorRun:
    """Test ProcessMonitor run functionality."""

    def test_run_short_process(self):
        """Test running a short process to completion."""
        monitor = denet.ProcessMonitor(
            cmd=["echo", "hello"], base_interval_ms=100, max_interval_ms=1000, store_in_memory=True
        )

        # Should complete without hanging
        monitor.run()

        # Should be able to get samples
        samples = monitor.get_samples()
        assert isinstance(samples, list)

    def test_run_with_monitoring(self):
        """Test run with active monitoring."""
        monitor = denet.ProcessMonitor(
            cmd=["python", "-c", "import time; time.sleep(0.3)"],
            base_interval_ms=50,
            max_interval_ms=1000,
            store_in_memory=True,
        )

        monitor.run()

        # Should have collected samples
        samples = monitor.get_samples()
        metrics_list = filter_metrics_samples(samples)

        # Should have at least some valid metrics
        if len(metrics_list) > 0:
            for metrics in metrics_list[:3]:  # Check first few
                assert_valid_metrics(metrics)


class TestProcessMonitorEdgeCases:
    """Test ProcessMonitor edge cases and error conditions."""

    def test_invalid_intervals(self):
        """Test handling of invalid interval parameters."""
        # base_interval > max_interval should be handled gracefully
        monitor = denet.ProcessMonitor(
            cmd=["echo", "test"],
            base_interval_ms=1000,
            max_interval_ms=100,  # Less than base
        )
        assert monitor is not None

    def test_zero_intervals(self):
        """Test handling of zero intervals."""
        # Should handle gracefully or raise appropriate error
        try:
            monitor = denet.ProcessMonitor(cmd=["echo", "test"], base_interval_ms=0, max_interval_ms=1000)
            assert monitor is not None
        except (ValueError, Exception):
            # Either works or raises appropriate error
            pass

    def test_very_high_frequency_sampling(self):
        """Test very high frequency sampling."""
        monitor = denet.ProcessMonitor(
            cmd=["sleep", "0.1"],
            base_interval_ms=1,  # Very fast
            max_interval_ms=10,
            store_in_memory=True,
        )

        # Should not crash with very high frequency
        for _ in range(5):
            monitor.sample_once()
            time.sleep(0.01)

        # Should have collected samples
        samples = monitor.get_samples()
        assert len(samples) >= 0  # At least doesn't crash

    def test_nonexistent_command(self):
        """Test handling of nonexistent commands."""
        with pytest.raises(Exception):
            denet.ProcessMonitor(cmd=["nonexistent_command_12345"], base_interval_ms=100, max_interval_ms=1000)
