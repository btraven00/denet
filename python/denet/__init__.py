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

__version__ = "0.2.0"

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
]

import functools
import json
import os
import sys
import threading
import time
from collections.abc import Callable
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
    ):
        self.base_interval_ms = base_interval_ms
        self.max_interval_ms = max_interval_ms
        self.output_file = output_file
        self.output_format = output_format
        self.store_in_memory = store_in_memory
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

        # Calculate elapsed time
        if len(self.samples) > 1:
            elapsed = (self.samples[-1]["ts_ms"] - self.samples[0]["ts_ms"]) / 1000.0
        else:
            elapsed = 0.0

        # Convert samples to JSON strings
        metrics_json = [json.dumps(sample) for sample in self.samples]

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
):
    """
    Context manager for monitoring the current process.

    Args:
        base_interval_ms: Starting sampling interval in milliseconds
        max_interval_ms: Maximum sampling interval in milliseconds
        output_file: Optional file path to write samples directly
        output_format: Format for file output ('jsonl', 'json', 'csv')
        store_in_memory: Whether to keep samples in memory

    Returns:
        A context manager that provides monitoring capabilities
    """
    return Monitor(
        base_interval_ms=base_interval_ms,
        max_interval_ms=max_interval_ms,
        output_file=output_file,
        output_format=output_format,
        store_in_memory=store_in_memory,
    )
