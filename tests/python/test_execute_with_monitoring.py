"""
Test the execute_with_monitoring function from denet module.

This module tests the functionality of the execute_with_monitoring function which
runs a command with performance monitoring from the very start.
"""

import json
import os
import pytest
import subprocess
import sys

from denet import execute_with_monitoring


@pytest.fixture
def temp_output_file(tmp_path):
    """Create a temporary file for output."""
    return str(tmp_path / "test_metrics.jsonl")


@pytest.fixture
def temp_stdout_file(tmp_path):
    """Create a temporary file for stdout redirection."""
    return str(tmp_path / "stdout.txt")


@pytest.fixture
def temp_stderr_file(tmp_path):
    """Create a temporary file for stderr redirection."""
    return str(tmp_path / "stderr.txt")


class TestExecuteWithMonitoring:
    """Test the execute_with_monitoring function."""

    def test_basic_execution(self, temp_output_file):
        """Test basic execution with a simple command."""
        cmd = [sys.executable, "-c", "import time; print('hello'); time.sleep(0.5)"]
        exit_code, monitor = execute_with_monitoring(
            cmd, output_file=temp_output_file, base_interval_ms=50, max_interval_ms=100
        )

        assert exit_code == 0
        assert monitor is not None
        assert os.path.exists(temp_output_file)

        # Get samples and check they contain expected metrics
        samples = monitor.get_samples()
        assert len(samples) > 0
        assert "cpu_usage" in samples[0]
        assert "mem_rss_kb" in samples[0]

    def test_string_command(self, temp_output_file):
        """Test execution with a string command instead of list."""
        # The execute_with_monitoring function parses strings into arguments
        # So we need a simple command that won't have parsing issues
        cmd = f"{sys.executable} -c print(123)"

        exit_code, monitor = execute_with_monitoring(cmd, output_file=temp_output_file, quiet=True)

        assert exit_code == 0
        assert monitor is not None
        # Don't assert on samples content as it might be empty depending on timing

    def test_stdout_stderr_redirection(self, temp_output_file, temp_stdout_file, temp_stderr_file):
        """Test redirection of stdout and stderr to files."""
        cmd = [sys.executable, "-c", "import sys; print('stdout test'); print('stderr test', file=sys.stderr)"]

        exit_code, _ = execute_with_monitoring(
            cmd, stdout_file=temp_stdout_file, stderr_file=temp_stderr_file, output_file=temp_output_file
        )

        assert exit_code == 0

        # Check stdout content
        with open(temp_stdout_file, "r") as f:
            stdout_content = f.read()
            assert "stdout test" in stdout_content

        # Check stderr content
        with open(temp_stderr_file, "r") as f:
            stderr_content = f.read()
            assert "stderr test" in stderr_content

    def test_timeout(self, temp_output_file):
        """Test timeout behavior."""
        # Use a very short timeout with a long sleep
        cmd = [sys.executable, "-c", "import time; time.sleep(10)"]

        with pytest.raises(subprocess.TimeoutExpired):
            execute_with_monitoring(
                cmd,
                timeout=0.1,  # Very short timeout to ensure it triggers
                output_file=temp_output_file,
            )

    def test_without_pausing(self, temp_output_file):
        """Test execution without pausing the process."""
        cmd = [sys.executable, "-c", "import time; print('no pause'); time.sleep(0.2)"]
        exit_code, monitor = execute_with_monitoring(cmd, output_file=temp_output_file, pause_for_attachment=False)

        assert exit_code == 0
        assert monitor is not None
        samples = monitor.get_samples()
        assert len(samples) > 0

    def test_since_process_start(self, temp_output_file):
        """Test with since_process_start=True."""
        cmd = [sys.executable, "-c", "import time; time.sleep(0.3)"]

        exit_code, monitor = execute_with_monitoring(cmd, output_file=temp_output_file, since_process_start=True)

        assert exit_code == 0
        assert monitor is not None

        # For since_process_start=True, we should have some samples
        # We can't make guarantees about specific timestamps as they depend on system timing
        samples = monitor.get_samples()
        assert len(samples) > 0

        # Get summary to verify it worked
        summary = monitor.get_summary()
        assert summary is not None

    def test_output_formats(self, tmp_path):
        """Test different output formats."""
        cmd = [sys.executable, "-c", "import time; time.sleep(0.2)"]

        # Test each format separately
        formats = ["jsonl", "json", "csv"]
        for fmt in formats:
            output_file = str(tmp_path / f"metrics.{fmt}")

            exit_code, monitor = execute_with_monitoring(cmd, output_file=output_file, output_format=fmt)

            assert exit_code == 0
            assert os.path.exists(output_file)

            # Basic content check based on format
            with open(output_file, "r") as f:
                content = f.read()
                assert len(content) > 0

                if fmt == "csv":
                    # CSV should have header with common fields
                    assert "ts_ms" in content
                    assert "cpu_usage" in content
                    assert "," in content
                elif fmt == "json":
                    # For denet, json format might not be an array but JSON object format
                    assert "{" in content
                    assert "}" in content
                elif fmt == "jsonl":
                    # JSONL has one JSON object per line
                    assert "{" in content
                    assert "}" in content

    def test_without_children(self, temp_output_file):
        """Test execution without monitoring child processes."""
        cmd = [sys.executable, "-c", "import subprocess, time; subprocess.Popen(['sleep', '0.1']); time.sleep(0.2)"]

        exit_code, monitor = execute_with_monitoring(cmd, output_file=temp_output_file, include_children=False)

        assert exit_code == 0
        samples = monitor.get_samples()
        assert len(samples) > 0

        # Verify no children are in the samples
        summary = monitor.get_summary()
        assert "child_processes" not in summary or not summary["child_processes"]

    def test_file_handle_cleanup(self, temp_stdout_file, temp_stderr_file):
        """Test that file handles are properly closed even if an exception occurs."""
        # This test ensures the finally block is covered for file handle cleanup
        cmd = [sys.executable, "-c", "print('test')"]

        # Normal execution should clean up properly
        exit_code, monitor = execute_with_monitoring(
            cmd, stdout_file=temp_stdout_file, stderr_file=temp_stderr_file, quiet=True
        )

        assert exit_code == 0

        # Files should exist and be accessible (handles closed properly)
        with open(temp_stdout_file, "r") as f:
            content = f.read()
            assert "test" in content

    def test_monitoring_exception_handling(self, temp_output_file):
        """Test exception handling in the monitoring loop."""
        import unittest.mock

        cmd = [sys.executable, "-c", "import time; time.sleep(0.3)"]

        # We'll test by making the monitor.sample_once() method raise an exception
        with unittest.mock.patch("denet.ProcessMonitor.from_pid") as mock_from_pid:
            # Create a mock monitor that raises an exception on sample_once
            mock_monitor = unittest.mock.MagicMock()
            mock_monitor.is_running.return_value = True
            mock_monitor.sample_once.side_effect = RuntimeError("Simulated monitoring error")
            mock_monitor.get_samples.return_value = []
            mock_monitor.get_summary.return_value = {}
            mock_from_pid.return_value = mock_monitor

            # This should still complete successfully despite the monitoring exception
            exit_code, monitor = execute_with_monitoring(cmd, output_file=temp_output_file)

            assert exit_code == 0
            assert mock_monitor.sample_once.called

    def test_timeout_with_process_cleanup(self, temp_output_file):
        """Test timeout behavior with process cleanup, including ProcessLookupError handling."""
        import unittest.mock

        # Use a command that will definitely timeout
        cmd = [sys.executable, "-c", "import time; time.sleep(10)"]

        # Mock os.killpg to simulate ProcessLookupError on the first call
        original_killpg = os.killpg
        call_count = 0

        def mock_killpg(pgid, sig):
            nonlocal call_count
            call_count += 1
            if call_count == 1:  # First call (SIGTERM) - simulate process already dead
                raise ProcessLookupError("Process group not found")
            return original_killpg(pgid, sig)

        with unittest.mock.patch("os.killpg", side_effect=mock_killpg):
            with pytest.raises(subprocess.TimeoutExpired):
                execute_with_monitoring(
                    cmd,
                    timeout=0.1,
                    output_file=temp_output_file,
                )

        # Verify the ProcessLookupError was caught and handled
        assert call_count >= 1

    def test_failed_command(self, temp_output_file):
        """Test execution with a command that returns non-zero exit code."""
        cmd = [sys.executable, "-c", "import sys; sys.exit(42)"]

        exit_code, monitor = execute_with_monitoring(cmd, output_file=temp_output_file)

        # Should return the actual exit code, not raise an exception
        assert exit_code == 42
        assert monitor is not None

    def test_invalid_command(self, temp_output_file):
        """Test execution with an invalid command."""
        cmd = ["nonexistent_command_that_should_fail"]

        # This should raise an exception during subprocess.Popen
        with pytest.raises((FileNotFoundError, OSError)):
            execute_with_monitoring(cmd, output_file=temp_output_file)

    def test_memory_only_monitoring(self):
        """Test monitoring with store_in_memory=True and no output file."""
        cmd = [sys.executable, "-c", "import time; print('memory test'); time.sleep(0.2)"]

        exit_code, monitor = execute_with_monitoring(
            cmd,
            store_in_memory=True,
            output_file=None,  # No file output
        )

        assert exit_code == 0
        samples = monitor.get_samples()
        assert len(samples) > 0

        # Verify we captured some monitoring data
        assert any("cpu_usage" in sample for sample in samples)

    def test_write_metadata_enabled(self, temp_output_file):
        """Test that metadata is written when write_metadata=True."""
        cmd = ["sleep", "1"]  # Use a longer-running process to ensure sampling

        exit_code, monitor = execute_with_monitoring(
            cmd, output_file=temp_output_file, write_metadata=True, base_interval_ms=200
        )

        assert exit_code == 0

        # Read the output file
        with open(temp_output_file, "r") as f:
            lines = f.readlines()

        assert len(lines) >= 2  # Should have metadata + at least one metrics line

        # First line should be metadata
        first_line = lines[0].strip()
        metadata = json.loads(first_line)

        # Check metadata structure
        assert "pid" in metadata
        assert "cmd" in metadata
        assert "executable" in metadata
        assert "t0_ms" in metadata

        # Verify it's actually metadata, not metrics
        assert isinstance(metadata["pid"], int)
        assert isinstance(metadata["cmd"], list)
        assert isinstance(metadata["executable"], str)
        assert isinstance(metadata["t0_ms"], int)

        # Second line should be metrics
        if len(lines) > 1:
            second_line = lines[1].strip()
            metrics = json.loads(second_line)
            # Should have metrics structure
            assert "ts_ms" in metrics
            assert any(key in metrics for key in ["parent", "cpu_usage", "mem_rss_kb"])

    def test_write_metadata_disabled(self, temp_output_file):
        """Test that metadata is NOT written when write_metadata=False."""
        cmd = ["sleep", "1"]  # Use a longer-running process to ensure sampling

        exit_code, monitor = execute_with_monitoring(
            cmd,
            output_file=temp_output_file,
            write_metadata=False,  # Explicitly disabled
            base_interval_ms=200,
        )

        assert exit_code == 0

        # Read the output file
        with open(temp_output_file, "r") as f:
            lines = f.readlines()

        assert len(lines) >= 1

        # First line should be metrics, not metadata
        first_line = lines[0].strip()
        first_data = json.loads(first_line)

        # Should look like metrics, not metadata
        metrics_keys = ["ts_ms", "parent", "cpu_usage", "mem_rss_kb"]
        has_metrics_keys = any(key in first_data for key in metrics_keys)
        assert has_metrics_keys

        # Should NOT look like metadata
        metadata_keys = ["pid", "cmd", "executable", "t0_ms"]
        has_metadata_keys = all(key in first_data for key in metadata_keys)
        assert not has_metadata_keys

    def test_write_metadata_default_false(self, temp_output_file):
        """Test that write_metadata defaults to False."""
        cmd = ["sleep", "1"]  # Use a longer-running process to ensure sampling

        exit_code, monitor = execute_with_monitoring(
            cmd,
            output_file=temp_output_file,
            # write_metadata not specified, should default to False
            base_interval_ms=200,
        )

        assert exit_code == 0

        # Read the output file
        with open(temp_output_file, "r") as f:
            lines = f.readlines()

        if len(lines) >= 1:
            # First line should be metrics, not metadata
            first_line = lines[0].strip()
            first_data = json.loads(first_line)

            # Should look like metrics
            metrics_keys = ["ts_ms", "parent", "cpu_usage", "mem_rss_kb"]
            has_metrics_keys = any(key in first_data for key in metrics_keys)
            assert has_metrics_keys

    def test_write_metadata_no_output_file(self):
        """Test that write_metadata doesn't affect in-memory only operation."""
        cmd = ["sleep", "1"]  # Use a longer-running process to ensure sampling

        exit_code, monitor = execute_with_monitoring(
            cmd,
            store_in_memory=True,
            output_file=None,  # No file output
            write_metadata=True,  # Should not affect in-memory storage
            base_interval_ms=200,
        )

        assert exit_code == 0

        samples = monitor.get_samples()
        assert len(samples) > 0

        # In-memory samples should still be metrics, not metadata
        first_sample = json.loads(samples[0])
        metrics_keys = ["ts_ms", "parent", "cpu_usage", "mem_rss_kb"]
        has_metrics_keys = any(key in first_sample for key in metrics_keys)
        assert has_metrics_keys
