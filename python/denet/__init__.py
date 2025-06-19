# Import the compiled module
from denet._denet import (
    ProcessMonitor,
    generate_summary_from_file,
    generate_summary_from_metrics_json,
)

# Import analysis utilities
from .analysis import (
    aggregate_metrics,
    convert_format,
    find_peaks,
    load_metrics,
    process_tree_analysis,
    resource_utilization,
    save_metrics,
)

__version__ = "0.3.1"

__all__ = [
    "ProcessMonitor",
    "generate_summary_from_file",
    "generate_summary_from_metrics_json",
    "aggregate_metrics",
    "convert_format",
    "find_peaks",
    "load_metrics",
    "process_tree_analysis",
    "resource_utilization",
    "save_metrics",
    "profile",
    "Monitor",
    "monitor",
    "execute_with_monitoring",
]

import functools
import json
import os
import signal
import subprocess
import sys
import threading
import time
from collections.abc import Callable
from typing import List, Optional, Tuple, Union
# from typing import Any, Dict


def profile(
    func=None,
    *,
    base_interval_ms: int = 100,
    max_interval_ms: int = 1000,
    output_file: str | None = None,
    output_format: str = "jsonl",
    store_in_memory: bool = True,
    include_children: bool = True,
) -> Callable:
    """
    Decorator to profile a function's execution.

    Can be used as @profile or @profile(...)

    Args:
        func: The function to decorate (used internally for @profile without parentheses)
        base_interval_ms: Starting sampling interval in milliseconds
        max_interval_ms: Maximum sampling interval in milliseconds
        output_file: Optional file path to write samples directly
        output_format: Format for file output ('jsonl', 'json', 'csv')
        store_in_memory: Whether to keep samples in memory
        include_children: Whether to track child processes

    Returns:
        Decorated function that returns (original_result, metrics)
    """
    # Handle case where decorator is used without arguments: @profile
    if func is not None:

        @functools.wraps(func)
        def direct_wrapper(*args, **kwargs):
            pid = os.getpid()
            monitoring = True
            samples = []

            # Define monitoring thread
            def monitoring_thread():
                nonlocal samples
                try:
                    while monitoring:
                        # Sample metrics from current process
                        if os.name == "posix":  # Unix-based systems
                            tmp_monitor = ProcessMonitor.from_pid(
                                pid=pid,
                                base_interval_ms=base_interval_ms,
                                max_interval_ms=max_interval_ms,
                                output_file=None,
                                store_in_memory=False,
                            )
                            metrics_json = tmp_monitor.sample_once()
                            if metrics_json is not None:
                                metrics = json.loads(metrics_json)
                                samples.append(metrics)
                        time.sleep(base_interval_ms / 1000)
                except Exception as e:
                    print(f"Error in monitoring thread: {e}")

            # Start monitoring thread
            thread = threading.Thread(target=monitoring_thread, daemon=True)
            thread.start()

            # Execute the function
            try:
                result = func(*args, **kwargs)
            finally:
                monitoring = False
                thread.join(timeout=0.5)

            return result, samples

        return direct_wrapper

    # Case where decorator is used with arguments: @profile(...)
    def decorator(func: Callable) -> Callable:
        @functools.wraps(func)
        def wrapper(*args, **kwargs):
            # Create a unique identifier for this run
            _unique_id = f"func_{int(time.time() * 1000)}"

            # We need to create a monitoring thread since we can't directly monitor
            # the currently running Python process (we'd need to know its PID in advance)
            pid = os.getpid()
            monitoring = True
            samples = []
            output_file_path = output_file

            def monitoring_thread():
                nonlocal samples
                try:
                    while monitoring:
                        # Sample metrics from current process
                        if os.name == "posix":  # Unix-based systems
                            # Create a fresh monitor for each sample to avoid accumulation issues
                            tmp_monitor = ProcessMonitor.from_pid(
                                pid=pid,
                                base_interval_ms=base_interval_ms,
                                max_interval_ms=max_interval_ms,
                                output_file=None,  # We'll handle file output separately
                                store_in_memory=False,
                            )
                            metrics_json = tmp_monitor.sample_once()
                            if metrics_json is not None:
                                metrics = json.loads(metrics_json)
                                if store_in_memory:
                                    samples.append(metrics)
                                if output_file_path:
                                    # Check if file is empty/new and write metadata first
                                    is_new_file = (
                                        not os.path.exists(output_file_path) or os.path.getsize(output_file_path) == 0
                                    )

                                    with open(output_file_path, "a") as f:
                                        if is_new_file:
                                            # Add metadata as first line
                                            metadata = {
                                                "pid": pid,
                                                "cmd": ["python"],
                                                "executable": sys.executable,
                                                "t0_ms": int(time.time() * 1000),
                                            }
                                            f.write(json.dumps(metadata) + "\n")
                                        f.write(metrics_json + "\n")
                        time.sleep(base_interval_ms / 1000)
                except Exception as e:
                    print(f"Error in monitoring thread: {e}")

            # Start monitoring thread
            thread = threading.Thread(target=monitoring_thread, daemon=True)
            thread.start()

            # Execute the function
            try:
                result = func(*args, **kwargs)
            finally:
                # Stop monitoring thread
                monitoring = False
                thread.join(timeout=0.5)  # Wait for thread to finish, with timeout

            return result, samples

        return wrapper

    return decorator


class Monitor:
    """
    Context manager for monitoring the current process.

    Args:
        base_interval_ms: Starting sampling interval in milliseconds
        max_interval_ms: Maximum sampling interval in milliseconds
        output_file: Optional file path to write samples directly
        output_format: Format for file output ('jsonl', 'json', 'csv')
        store_in_memory: Whether to keep samples in memory
    """

    def __init__(
        self,
        base_interval_ms: int = 100,
        max_interval_ms: int = 1000,
        output_file: str | None = None,
        output_format: str = "jsonl",
        store_in_memory: bool = True,
        include_children: bool = True,
    ):
        self.base_interval_ms = base_interval_ms
        self.max_interval_ms = max_interval_ms
        self.output_file = output_file
        self.output_format = output_format
        self.store_in_memory = store_in_memory
        self.include_children = include_children
        self.pid = os.getpid()
        self.samples = []
        self.monitoring = False
        self.thread = None

    def __enter__(self):
        self.samples = []
        self.monitoring = True

        def monitor_thread():
            try:
                while self.monitoring:
                    # Create a fresh monitor for each sample
                    if os.name == "posix":  # Unix-based systems
                        tmp_monitor = ProcessMonitor.from_pid(
                            pid=self.pid,
                            base_interval_ms=self.base_interval_ms,
                            max_interval_ms=self.max_interval_ms,
                            output_file=None,
                            store_in_memory=False,
                            include_children=self.include_children,
                        )
                        metrics_json = tmp_monitor.sample_once()
                        if metrics_json is not None:
                            metrics = json.loads(metrics_json)
                            if self.store_in_memory:
                                self.samples.append(metrics)
                            if self.output_file:
                                # Check if file is empty/new and write metadata first
                                is_new_file = (
                                    not os.path.exists(self.output_file) or os.path.getsize(self.output_file) == 0
                                )

                                with open(self.output_file, "a") as f:
                                    if is_new_file:
                                        # Add metadata as first line
                                        metadata = {
                                            "pid": self.pid,
                                            "cmd": ["python"],
                                            "executable": sys.executable,
                                            "t0_ms": int(time.time() * 1000),
                                        }
                                        f.write(json.dumps(metadata) + "\n")
                                    f.write(metrics_json + "\n")
                    time.sleep(self.base_interval_ms / 1000)
            except Exception as e:
                print(f"Error in monitor thread: {e}")

        self.thread = threading.Thread(target=monitor_thread, daemon=True)
        self.thread.start()
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        self.monitoring = False
        if self.thread:
            self.thread.join(timeout=0.5)  # Wait for thread to finish, with timeout
        return False  # Don't suppress exceptions

    def get_samples(self):
        return self.samples

    def get_summary(self):
        if not self.samples:
            return "{}"

        # Parse JSON samples first
        parsed_samples = []
        for sample in self.samples:
            # If it's already a string, parse it into a Python object
            if isinstance(sample, str):
                try:
                    parsed_samples.append(json.loads(sample))
                except json.JSONDecodeError:
                    continue  # Skip invalid JSON
            else:
                parsed_samples.append(sample)  # Already a Python object

        if not parsed_samples:
            return "{}"

        # Calculate elapsed time
        if len(parsed_samples) > 1:
            elapsed = (parsed_samples[-1]["ts_ms"] - parsed_samples[0]["ts_ms"]) / 1000.0
        else:
            elapsed = 0.0

        # Prepare metrics for aggregation
        metrics_json = []
        for sample in parsed_samples:
            # Skip metadata samples
            if all(key in sample for key in ["pid", "cmd", "executable", "t0_ms"]):
                continue

            if "aggregated" in sample:
                # This is an aggregated sample - extract just the aggregated metrics
                agg_metric = sample["aggregated"]
                # Ensure process_count is preserved if present
                if "process_count" not in agg_metric and "children" in sample:
                    # Compute process count as parent (if exists) + children
                    process_count = len(sample.get("children", []))
                    if sample.get("parent") is not None:
                        process_count += 1
                    agg_metric["process_count"] = process_count

                metrics_json.append(json.dumps(agg_metric))
            elif "process_count" in sample:
                # This is already an aggregated metrics sample
                metrics_json.append(json.dumps(sample))
            elif all(key in sample for key in ["cpu_usage", "mem_rss_kb"]):
                # This is an individual process metrics sample
                metrics_json.append(json.dumps(sample))

        # If we found aggregated metrics, create a manual summary that includes process_count
        if any("process_count" in json.loads(m) for m in metrics_json if json.loads(m).get("process_count", 0) > 1):
            # Calculate max processes from all aggregated metrics
            max_processes = max(
                (json.loads(m).get("process_count", 1) for m in metrics_json if "process_count" in json.loads(m)),
                default=1,
            )

            # Get the summary from the Rust code
            summary_json = generate_summary_from_metrics_json(metrics_json, elapsed)
            summary = json.loads(summary_json)

            # Overwrite the max_processes field with our calculated value
            summary["max_processes"] = max_processes

            # Convert back to JSON
            return json.dumps(summary)
        else:
            # Use the existing summary generation logic
            return generate_summary_from_metrics_json(metrics_json, elapsed)

    def clear_samples(self):
        self.samples = []

    def save_samples(self, path, format=None):
        if not self.samples:
            return

        format = format or "jsonl"

        with open(path, "w") as f:
            # Add metadata as first line for jsonl format
            if format == "jsonl":
                metadata = {
                    "pid": self.pid,
                    "cmd": ["python"],
                    "executable": sys.executable,
                    "t0_ms": int(time.time() * 1000),
                }
                f.write(json.dumps(metadata) + "\n")
            if format == "json":
                # JSON array format
                json.dump(self.samples, f)
            elif format == "csv":
                # CSV format
                if self.samples:
                    # Write header
                    headers = list(self.samples[0].keys())
                    f.write(",".join(headers) + "\n")

                    # Write data rows
                    for sample in self.samples:
                        row = [str(sample.get(h, "")) for h in headers]
                        f.write(",".join(row) + "\n")
            else:
                # Default to JSONL
                for sample in self.samples:
                    f.write(json.dumps(sample) + "\n")

    def get_metadata(self):
        """
        Get process metadata.

        Returns:
            Dict containing process metadata
        """
        return {
            "pid": self.pid,
            "cmd": ["python"],
            "executable": sys.executable,
            "t0_ms": int(time.time() * 1000),
        }


# Function for creating a Monitor context manager
def monitor(
    base_interval_ms: int = 100,
    max_interval_ms: int = 1000,
    output_file: str | None = None,
    output_format: str = "jsonl",
    store_in_memory: bool = True,
    include_children: bool = True,
):
    """
    Context manager for monitoring the current process.

    Args:
        base_interval_ms: Starting sampling interval in milliseconds
        max_interval_ms: Maximum sampling interval in milliseconds
        output_file: Optional file path to write samples directly
        output_format: Format for file output ('jsonl', 'json', 'csv')
        store_in_memory: Whether to keep samples in memory
        include_children: Whether to monitor child processes (default True)

    Returns:
        A context manager that provides monitoring capabilities
    """
    return Monitor(
        base_interval_ms=base_interval_ms,
        max_interval_ms=max_interval_ms,
        output_file=output_file,
        output_format=output_format,
        store_in_memory=store_in_memory,
        include_children=include_children,
    )


def execute_with_monitoring(
    cmd: Union[str, List[str]],
    stdout_file: Optional[str] = None,
    stderr_file: Optional[str] = None,
    timeout: Optional[float] = None,
    base_interval_ms: int = 100,
    max_interval_ms: int = 1000,
    store_in_memory: bool = True,
    output_file: Optional[str] = None,
    output_format: str = "jsonl",
    since_process_start: bool = False,
    pause_for_attachment: bool = True,
    quiet: bool = False,
    include_children: bool = True,
) -> Tuple[int, "ProcessMonitor"]:
    """
    Execute a command with monitoring from the very start using signal-based process control.

    This function eliminates race conditions by:
    1. Creating the process with subprocess.Popen
    2. Immediately pausing it with SIGSTOP (if pause_for_attachment=True)
    3. Attaching monitoring while process is frozen
    4. Resuming the process with SIGCONT
    5. Running monitoring loop concurrently with process execution

    Args:
        cmd: Command to execute (string or list of strings)
        stdout_file: Optional file path for stdout redirection
        stderr_file: Optional file path for stderr redirection
        timeout: Optional timeout in seconds
        base_interval_ms: Starting sampling interval in milliseconds
        max_interval_ms: Maximum sampling interval in milliseconds
        store_in_memory: Whether to keep samples in memory
        output_file: Optional file path to write samples directly
        output_format: Format for file output ('jsonl', 'json', 'csv')
        since_process_start: Whether to measure from process start vs monitor start
        pause_for_attachment: Whether to use signal-based pausing (set False to disable)
        quiet: Whether to suppress output
        include_children: Whether to monitor child processes (default True)

    Returns:
        Tuple of (exit_code, monitor)

    Raises:
        subprocess.TimeoutExpired: If timeout is exceeded
        OSError: If process creation or signaling fails
        RuntimeError: If monitor attachment fails

    Example:
        >>> exit_code, monitor = execute_with_monitoring(['python', 'script.py'])
        >>> samples = monitor.get_samples()
        >>> summary = monitor.get_summary()
    """
    # Normalize command to list format
    if isinstance(cmd, str):
        cmd = cmd.split()

    # Prepare file handles for redirection
    stdout_handle = None
    stderr_handle = None

    try:
        if stdout_file:
            stdout_handle = open(stdout_file, "w")
        if stderr_file:
            stderr_handle = open(stderr_file, "w")

        # 1. Create the process
        with subprocess.Popen(
            cmd,
            stdout=stdout_handle or subprocess.PIPE,
            stderr=stderr_handle or subprocess.PIPE,
            text=True,
            start_new_session=True,  # Isolate the process group
        ) as process:
            # 2. Immediately pause the process if requested
            if pause_for_attachment:
                os.kill(process.pid, signal.SIGSTOP)

            # 3. Attach monitoring while process is frozen (or running if pause disabled)
            monitor = ProcessMonitor.from_pid(
                pid=process.pid,
                base_interval_ms=base_interval_ms,
                max_interval_ms=max_interval_ms,
                since_process_start=since_process_start,
                output_file=output_file,
                output_format=output_format,
                store_in_memory=store_in_memory,
                quiet=quiet,
                include_children=include_children,
            )

            # 4. Resume the process if it was paused
            if pause_for_attachment:
                os.kill(process.pid, signal.SIGCONT)

            # 5. Start monitoring in a separate thread
            monitoring_active = threading.Event()
            monitoring_active.set()

            def monitoring_loop():
                """Run monitoring loop in separate thread"""
                while monitoring_active.is_set() and monitor.is_running():
                    try:
                        monitor.sample_once()
                        time.sleep(base_interval_ms / 1000.0)
                    except Exception:
                        # Process might have ended, stop monitoring
                        break

            monitor_thread = threading.Thread(target=monitoring_loop, daemon=True)
            monitor_thread.start()

            try:
                # 6. Wait for completion with timeout
                exit_code = process.wait(timeout=timeout)

                # Stop monitoring
                monitoring_active.clear()
                monitor_thread.join(timeout=1.0)  # Give thread time to finish

                return exit_code, monitor

            except subprocess.TimeoutExpired:
                # Cleanup: stop monitoring and kill process
                monitoring_active.clear()

                # Kill the process and its children (since we used start_new_session=True)
                try:
                    os.killpg(os.getpgid(process.pid), signal.SIGTERM)
                    time.sleep(0.1)  # Give it a moment to terminate gracefully
                    os.killpg(os.getpgid(process.pid), signal.SIGKILL)
                except ProcessLookupError:
                    # Process already died
                    pass

                monitor_thread.join(timeout=1.0)
                raise

    finally:
        # Close file handles
        if stdout_handle:
            stdout_handle.close()
        if stderr_handle:
            stderr_handle.close()
