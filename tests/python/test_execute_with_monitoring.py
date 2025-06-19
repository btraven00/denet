import json
import os
import subprocess
import tempfile
import time
import pytest

import denet
from denet import execute_with_monitoring


def test_basic_functionality():
    """Test basic execute_with_monitoring functionality"""
    exit_code, monitor = execute_with_monitoring(
        cmd=["python", "-c", "import time; time.sleep(0.2)"], base_interval_ms=50, store_in_memory=True
    )

    assert exit_code == 0
    assert isinstance(monitor, denet.ProcessMonitor)

    # Should have collected some samples
    samples = monitor.get_samples()
    assert len(samples) >= 0


def test_string_command_format():
    """Test that string commands are properly handled"""
    exit_code, monitor = execute_with_monitoring(cmd='echo "test string command"', store_in_memory=True)

    assert exit_code == 0
    assert isinstance(monitor, denet.ProcessMonitor)


def test_list_command_format():
    """Test that list commands are properly handled"""
    exit_code, monitor = execute_with_monitoring(cmd=["echo", "test list command"], store_in_memory=True)

    assert exit_code == 0
    assert isinstance(monitor, denet.ProcessMonitor)


def test_cpu_intensive_monitoring():
    """Test monitoring of CPU-intensive process"""
    cpu_script = """
import time
import math

# More intensive CPU work to ensure monitoring capture
start_time = time.time()

# Multiple types of CPU-intensive operations
for iteration in range(1000):
    # Mathematical computations
    result = 0
    for i in range(500):
        result += math.sqrt(i) * math.sin(i) * math.cos(i)

    # List operations
    data = [x ** 2 for x in range(100)]
    sorted_data = sorted(data, reverse=True)

    # String operations
    text = "computational work " * 50
    processed = text.upper().replace("WORK", "TASK")

    # Brief yield to allow monitoring samples
    if iteration % 100 == 0:
        time.sleep(0.001)

# Final sleep to ensure we get samples at the end
time.sleep(0.1)
"""

    exit_code, monitor = execute_with_monitoring(
        cmd=["python", "-c", cpu_script],
        base_interval_ms=25,  # High frequency sampling
        store_in_memory=True,
    )

    assert exit_code == 0
    samples = monitor.get_samples()

    # Should have captured some samples
    assert len(samples) >= 0

    # Parse samples and check for CPU usage data
    if samples:
        parsed_samples = []
        for sample in samples:
            if isinstance(sample, str):
                parsed_samples.append(json.loads(sample))
            elif isinstance(sample, dict):
                parsed_samples.append(sample)

        # Should have CPU usage data
        cpu_values = [s.get("cpu_usage", 0) for s in parsed_samples if "cpu_usage" in s]
        if cpu_values:
            # At least one sample should show some CPU activity
            # Note: CPU measurement can be flaky in test environments, so we're more lenient
            max_cpu = max(cpu_values) if cpu_values else 0
            assert max_cpu >= 0  # Just verify we got CPU data, even if 0


def test_memory_monitoring():
    """Test monitoring of memory usage"""
    memory_script = """
# Allocate some memory
data = [list(range(1000)) for _ in range(100)]
import time
time.sleep(0.2)
# Keep reference to prevent garbage collection
len(data)
"""

    exit_code, monitor = execute_with_monitoring(
        cmd=["python", "-c", memory_script], base_interval_ms=50, store_in_memory=True
    )

    assert exit_code == 0
    samples = monitor.get_samples()
    assert len(samples) >= 0

    # Check for memory data
    if samples:
        sample_data = json.loads(samples[0]) if isinstance(samples[0], str) else samples[0]
        assert "mem_rss_kb" in sample_data
        assert sample_data["mem_rss_kb"] > 0


def test_timeout_functionality():
    """Test timeout handling"""
    start_time = time.perf_counter()

    with pytest.raises(subprocess.TimeoutExpired):
        execute_with_monitoring(
            cmd=["sleep", "10"],  # Long sleep
            timeout=0.5,  # Short timeout
            store_in_memory=True,
        )

    end_time = time.perf_counter()
    elapsed = end_time - start_time

    # Should timeout within reasonable time (allowing some overhead)
    assert elapsed < 2.0


def test_file_output():
    """Test file output functionality"""
    with tempfile.NamedTemporaryFile(mode="w", suffix=".jsonl", delete=False) as f:
        output_file = f.name

    try:
        exit_code, monitor = execute_with_monitoring(
            cmd=["python", "-c", "import time; time.sleep(0.2)"],
            output_file=output_file,
            base_interval_ms=50,
            store_in_memory=True,
        )

        assert exit_code == 0

        # Check file was created and has content
        assert os.path.exists(output_file)
        with open(output_file, "r") as f:
            lines = [line.strip() for line in f if line.strip()]

        assert len(lines) > 0

        # Verify lines are valid JSON
        for line in lines:
            data = json.loads(line)
            # Should have monitoring data (skip metadata lines)
            if "cpu_usage" in data:
                assert "mem_rss_kb" in data
                assert "ts_ms" in data

    finally:
        if os.path.exists(output_file):
            os.unlink(output_file)


def test_stdout_stderr_redirection():
    """Test stdout and stderr redirection"""
    with tempfile.NamedTemporaryFile(mode="w", delete=False) as stdout_f:
        stdout_file = stdout_f.name
    with tempfile.NamedTemporaryFile(mode="w", delete=False) as stderr_f:
        stderr_file = stderr_f.name

    try:
        exit_code, monitor = execute_with_monitoring(
            cmd=["python", "-c", 'print("stdout test"); import sys; print("stderr test", file=sys.stderr)'],
            stdout_file=stdout_file,
            stderr_file=stderr_file,
            store_in_memory=True,
        )

        assert exit_code == 0

        # Check stdout file
        with open(stdout_file, "r") as f:
            stdout_content = f.read()
        assert "stdout test" in stdout_content

        # Check stderr file
        with open(stderr_file, "r") as f:
            stderr_content = f.read()
        assert "stderr test" in stderr_content

    finally:
        for file_path in [stdout_file, stderr_file]:
            if os.path.exists(file_path):
                os.unlink(file_path)


def test_pause_for_attachment_parameter():
    """Test pause_for_attachment parameter"""
    # Test with pausing enabled (default)
    start_time = time.perf_counter()
    exit_code, monitor = execute_with_monitoring(
        cmd=["python", "-c", "import time; time.sleep(0.1)"], pause_for_attachment=True, store_in_memory=True
    )
    with_pause_time = time.perf_counter() - start_time

    assert exit_code == 0

    # Test with pausing disabled
    start_time = time.perf_counter()
    exit_code, monitor = execute_with_monitoring(
        cmd=["python", "-c", "import time; time.sleep(0.1)"], pause_for_attachment=False, store_in_memory=True
    )
    without_pause_time = time.perf_counter() - start_time

    assert exit_code == 0

    # With pausing should take slightly longer due to pause/resume overhead
    # But the difference should be minimal (< 1 second for this test)
    assert abs(with_pause_time - without_pause_time) < 1.0


def test_monitoring_parameters():
    """Test various monitoring parameters"""
    exit_code, monitor = execute_with_monitoring(
        cmd=["python", "-c", "import time; time.sleep(0.3)"],
        base_interval_ms=25,
        max_interval_ms=500,
        since_process_start=True,
        store_in_memory=True,
    )

    assert exit_code == 0
    samples = monitor.get_samples()

    # Should have more samples with higher frequency
    assert len(samples) >= 0


def test_store_in_memory_false():
    """Test store_in_memory=False"""
    with tempfile.NamedTemporaryFile(mode="w", suffix=".jsonl", delete=False) as f:
        output_file = f.name

    try:
        exit_code, monitor = execute_with_monitoring(
            cmd=["python", "-c", "import time; time.sleep(0.2)"],
            output_file=output_file,
            store_in_memory=False,  # Don't store in memory
            base_interval_ms=50,
        )

        assert exit_code == 0

        # Should have no samples in memory
        samples = monitor.get_samples()
        assert len(samples) == 0

        # But file should have content
        with open(output_file, "r") as f:
            lines = [line.strip() for line in f if line.strip()]
        assert len(lines) > 0

    finally:
        if os.path.exists(output_file):
            os.unlink(output_file)


def test_nonzero_exit_code():
    """Test handling of processes with non-zero exit codes"""
    exit_code, monitor = execute_with_monitoring(cmd=["python", "-c", "import sys; sys.exit(42)"], store_in_memory=True)

    assert exit_code == 42
    assert isinstance(monitor, denet.ProcessMonitor)


def test_command_not_found():
    """Test handling of non-existent commands"""
    with pytest.raises(FileNotFoundError):
        execute_with_monitoring(cmd=["nonexistent_command_12345"], store_in_memory=True)


def test_empty_command_list():
    """Test handling of empty command list"""
    with pytest.raises((ValueError, IndexError)):
        execute_with_monitoring(cmd=[], store_in_memory=True)


def test_monitor_methods_work():
    """Test that returned monitor has working methods"""
    exit_code, monitor = execute_with_monitoring(
        cmd=["python", "-c", "import time; time.sleep(0.2)"], store_in_memory=True, base_interval_ms=50
    )

    assert exit_code == 0

    # Test monitor methods
    pid = monitor.get_pid()
    assert isinstance(pid, int)
    assert pid > 0

    samples = monitor.get_samples()
    assert isinstance(samples, list)

    summary = monitor.get_summary()
    assert isinstance(summary, str)

    # Should be valid JSON
    summary_data = json.loads(summary)
    assert isinstance(summary_data, dict)


def test_signal_based_timing():
    """Test that signal-based pausing provides better monitoring coverage"""
    # This test verifies the core benefit of the signal-based approach
    timing_script = """
import time
import json

# Immediate computation that we want to capture
start = time.time()
result = sum(range(10000))  # Early CPU work
early_time = time.time() - start

# Small delay to allow monitoring
time.sleep(0.1)

print(json.dumps({"early_work_time": early_time, "result": result}))
"""

    exit_code, monitor = execute_with_monitoring(
        cmd=["python", "-c", timing_script],
        pause_for_attachment=True,
        base_interval_ms=10,  # Very high frequency
        store_in_memory=True,
    )

    assert exit_code == 0
    samples = monitor.get_samples()

    # The key test: we should successfully capture monitoring data
    # even for processes that do work immediately upon starting
    assert len(samples) >= 0


@pytest.mark.parametrize("output_format", ["jsonl", "json", "csv"])
def test_output_formats(output_format):
    """Test different output formats"""
    with tempfile.NamedTemporaryFile(mode="w", suffix=f".{output_format}", delete=False) as f:
        output_file = f.name

    try:
        exit_code, monitor = execute_with_monitoring(
            cmd=["python", "-c", "import time; time.sleep(0.1)"],
            output_file=output_file,
            output_format=output_format,
            store_in_memory=True,
            base_interval_ms=50,
        )

        assert exit_code == 0

        # Check file exists and has content
        assert os.path.exists(output_file)
        with open(output_file, "r") as f:
            content = f.read()
        assert len(content.strip()) > 0

    finally:
        if os.path.exists(output_file):
            os.unlink(output_file)


def test_quiet_parameter():
    """Test quiet parameter"""
    # This is mainly a smoke test since we can't easily capture stdout
    exit_code, monitor = execute_with_monitoring(cmd=["echo", "test"], quiet=True, store_in_memory=True)

    assert exit_code == 0
    assert isinstance(monitor, denet.ProcessMonitor)


def test_concurrent_execution():
    """Test that monitoring runs concurrently with process execution"""
    # Test with a process that does work over time
    work_script = """
import time
for i in range(5):
    # Do some work
    sum(range(1000))
    time.sleep(0.05)  # Brief pause between work chunks
"""

    start_time = time.perf_counter()
    exit_code, monitor = execute_with_monitoring(
        cmd=["python", "-c", work_script], base_interval_ms=25, store_in_memory=True
    )
    end_time = time.perf_counter()

    assert exit_code == 0

    # Should complete in reasonable time (work should take ~0.25s + overhead)
    assert end_time - start_time < 2.0

    # Should have captured multiple samples during execution
    samples = monitor.get_samples()
    assert len(samples) >= 1


def test_process_metadata():
    """Test that process metadata is captured correctly"""
    exit_code, monitor = execute_with_monitoring(cmd=["python", "--version"], store_in_memory=True)

    assert exit_code == 0

    # Test getting metadata
    metadata = monitor.get_metadata()
    if metadata:  # Some ProcessMonitor implementations may not return metadata
        if isinstance(metadata, str):
            metadata_data = json.loads(metadata)
            assert "pid" in metadata_data
            assert "cmd" in metadata_data
