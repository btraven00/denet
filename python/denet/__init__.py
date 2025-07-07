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

__version__ = "0.4.2"

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
    "execute_with_monitoring",
]

import os
import signal
import subprocess
import threading
import time
from typing import List, Optional, Tuple, Union


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
    write_metadata: bool = False,
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
        write_metadata: Whether to write metadata as first line to output file (default False)

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
                write_metadata=write_metadata,
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
