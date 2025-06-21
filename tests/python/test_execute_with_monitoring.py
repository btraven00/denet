"""
Test the execute_with_monitoring function from denet module.

This module tests the functionality of the execute_with_monitoring function which
runs a command with performance monitoring from the very start.
"""

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
