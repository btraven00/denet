"""
denet.analysis: Analysis utilities for processing denet metrics

This module provides tools for analyzing and processing metrics collected by denet,
including aggregation, peak detection, and resource utilization statistics.
"""

import json
import statistics
from typing import Any


def aggregate_metrics(
    metrics: list[dict[str, Any]], window_size: int = 10, method: str = "mean"
) -> list[dict[str, Any]]:
    """
    Aggregate metrics into windows to reduce data size.

    Args:
        metrics: List of metrics dictionaries to aggregate
        window_size: Number of samples to aggregate together
        method: Aggregation method ("mean", "max", or "min")

    Returns:
        List of aggregated metrics dictionaries
    """
    if not metrics:
        return []

    if window_size <= 1:
        return metrics

    result = []

    # Group metrics into windows
    for i in range(0, len(metrics), window_size):
        window = metrics[i : i + window_size]
        if not window:
            continue

        # Start with the first sample and update with aggregated values
        aggregated = window[0].copy()

        # Fields to aggregate (numeric fields only)
        numeric_fields = [
            "cpu_usage",
            "mem_rss_kb",
            "mem_vms_kb",
            "disk_read_bytes",
            "disk_write_bytes",
            "net_rx_bytes",
            "net_tx_bytes",
            "thread_count",
            "uptime_secs",
        ]

        # Apply aggregation method to each field
        for field in numeric_fields:
            if field not in window[0]:
                continue

            values = [sample.get(field, 0) for sample in window if field in sample]
            if not values:
                continue

            if method == "mean":
                aggregated[field] = sum(values) / len(values)
            elif method == "max":
                aggregated[field] = max(values)
            elif method == "min":
                aggregated[field] = min(values)
            else:
                # Default to mean
                aggregated[field] = sum(values) / len(values)

        # Use the timestamp of the last sample in the window
        if "ts_ms" in window[-1]:
            aggregated["ts_ms"] = window[-1]["ts_ms"]

        # Mark as aggregated data
        aggregated["_aggregated"] = True
        aggregated["_window_size"] = len(window)
        aggregated["_aggregation_method"] = method

        result.append(aggregated)

    return result


def find_peaks(
    metrics: list[dict[str, Any]],
    field: str = "cpu_usage",
    threshold: float = 0.8,
    window_size: int = 5,
) -> list[dict[str, Any]]:
    """
    Find peaks in metrics where a specific field exceeds a threshold.

    Args:
        metrics: List of metrics dictionaries
        field: Field name to analyze for peaks
        threshold: Threshold value (as proportion of max value) for peak detection
        window_size: Window size for smoothing

    Returns:
        List of peak metrics dictionaries
    """
    if not metrics:
        return []

    # Ensure the field exists in metrics
    if not all(field in metric for metric in metrics):
        return []

    # Get values for the field
    values = [metric[field] for metric in metrics]

    # Find absolute max to calibrate threshold
    max_value = max(values)
    absolute_threshold = max_value * threshold

    # Apply smoothing if window_size > 1
    if window_size > 1:
        smoothed_values = []
        for i in range(len(values)):
            window = values[max(0, i - window_size // 2) : min(len(values), i + window_size // 2 + 1)]
            smoothed_values.append(sum(window) / len(window))
        values = smoothed_values

    # Find peaks
    peaks = []
    for i in range(1, len(values) - 1):
        if values[i] > values[i - 1] and values[i] > values[i + 1] and values[i] >= absolute_threshold:
            peaks.append(metrics[i])

    return peaks


def resource_utilization(metrics: list[dict[str, Any]]) -> dict[str, Any]:
    """
    Generate comprehensive resource utilization statistics.

    Args:
        metrics: List of metrics dictionaries

    Returns:
        Dictionary of resource utilization statistics
    """
    if not metrics:
        return {}

    result = {}

    # CPU statistics
    if all("cpu_usage" in metric for metric in metrics):
        cpu_values = [metric["cpu_usage"] for metric in metrics]
        result["avg_cpu"] = statistics.mean(cpu_values)
        result["max_cpu"] = max(cpu_values)
        result["min_cpu"] = min(cpu_values)
        result["median_cpu"] = statistics.median(cpu_values)
        if len(cpu_values) > 1:
            result["stdev_cpu"] = statistics.stdev(cpu_values)

    # Memory statistics (RSS)
    if all("mem_rss_kb" in metric for metric in metrics):
        mem_values = [metric["mem_rss_kb"] for metric in metrics]
        result["avg_mem_mb"] = statistics.mean(mem_values) / 1024
        result["max_mem_mb"] = max(mem_values) / 1024
        result["min_mem_mb"] = min(mem_values) / 1024
        result["median_mem_mb"] = statistics.median(mem_values) / 1024
        if len(mem_values) > 1:
            result["stdev_mem_mb"] = statistics.stdev(mem_values) / 1024

    # I/O statistics
    if all("disk_read_bytes" in metric for metric in metrics):
        result["total_read_mb"] = metrics[-1]["disk_read_bytes"] / (1024 * 1024)

    if all("disk_write_bytes" in metric for metric in metrics):
        result["total_write_mb"] = metrics[-1]["disk_write_bytes"] / (1024 * 1024)

    # Network statistics
    if all("net_rx_bytes" in metric for metric in metrics):
        result["total_net_rx_mb"] = metrics[-1]["net_rx_bytes"] / (1024 * 1024)

    if all("net_tx_bytes" in metric for metric in metrics):
        result["total_net_tx_mb"] = metrics[-1]["net_tx_bytes"] / (1024 * 1024)

    # Thread statistics
    if all("thread_count" in metric for metric in metrics):
        thread_values = [metric["thread_count"] for metric in metrics]
        result["avg_threads"] = statistics.mean(thread_values)
        result["max_threads"] = max(thread_values)
        result["min_threads"] = min(thread_values)

    # Time statistics
    if "ts_ms" in metrics[0] and "ts_ms" in metrics[-1]:
        total_time_ms = metrics[-1]["ts_ms"] - metrics[0]["ts_ms"]
        result["total_time_sec"] = total_time_ms / 1000

    return result


def convert_format(metrics: list[dict[str, Any]] | str, to_format: str = "csv", indent: int | None = None) -> str:
    """
    Convert metrics to different formats.

    Args:
        metrics: List of metrics dictionaries or path to metrics file
        to_format: Target format ("json", "jsonl", "csv")
        indent: Indentation for json format (None for compact)

    Returns:
        String representation in the target format
    """
    # Load metrics from file if path is provided
    if isinstance(metrics, str):
        with open(metrics) as f:
            content = f.read()
            if content.startswith("[") and content.endswith("]"):
                # JSON array format
                metrics = json.loads(content)
            else:
                # JSONL format
                metrics = [json.loads(line) for line in content.split("\n") if line.strip()]

    if not metrics:
        return ""

    if to_format == "json":
        return json.dumps(metrics, indent=indent)

    elif to_format == "jsonl":
        return "\n".join(json.dumps(metric) for metric in metrics)

    elif to_format == "csv":
        # Extract all possible fields from the metrics
        all_fields = set()
        for metric in metrics:
            all_fields.update(metric.keys())

        # Sort fields with common ones first
        common_fields = ["ts_ms", "cpu_usage", "mem_rss_kb", "mem_vms_kb"]
        fields = [f for f in common_fields if f in all_fields]
        fields.extend(sorted(f for f in all_fields if f not in common_fields))

        # Generate CSV header
        result = ",".join(fields) + "\n"

        # Generate rows
        for metric in metrics:
            row = [str(metric.get(field, "")) for field in fields]
            result += ",".join(row) + "\n"

        return result

    else:
        raise ValueError(f"Unknown format: {to_format}")


def process_tree_analysis(metrics: list[dict[str, Any]]) -> dict[str, Any]:
    """
    Analyze process tree metrics to find resource usage patterns by process.

    Args:
        metrics: List of process tree metrics dictionaries

    Returns:
        Dictionary with process-specific resource utilization
    """
    if not metrics:
        return {}

    # Check if these are process tree metrics
    if "children" not in metrics[0] and "child_processes" not in metrics[0]:
        return {}

    result = {"main_process": {}, "child_processes": {}, "total": {}}

    # Track processes over time
    processes = {}
    for metric in metrics:
        # Main process stats
        main_pid = metric.get("pid", 0)
        if main_pid not in processes:
            processes[main_pid] = {"cpu": [], "memory": [], "threads": []}

        processes[main_pid]["cpu"].append(metric.get("cpu_usage", 0))
        processes[main_pid]["memory"].append(metric.get("mem_rss_kb", 0))
        processes[main_pid]["threads"].append(metric.get("thread_count", 1))

        # Child processes
        children = metric.get("children", metric.get("child_processes", []))
        for child in children:
            child_pid = child.get("pid", 0)
            if child_pid not in processes:
                processes[child_pid] = {"cpu": [], "memory": [], "threads": []}

            processes[child_pid]["cpu"].append(child.get("cpu_usage", 0))
            processes[child_pid]["memory"].append(child.get("mem_rss_kb", 0))
            processes[child_pid]["threads"].append(child.get("thread_count", 1))

    # Calculate statistics for each process
    total_cpu = []
    total_memory = []
    total_threads = []

    for pid, data in processes.items():
        if not data["cpu"]:
            continue

        process_stats = {
            "avg_cpu": statistics.mean(data["cpu"]),
            "max_cpu": max(data["cpu"]),
            "avg_memory_mb": statistics.mean(data["memory"]) / 1024,
            "max_memory_mb": max(data["memory"]) / 1024,
            "avg_threads": statistics.mean(data["threads"]),
            "max_threads": max(data["threads"]),
        }

        if pid == main_pid:
            result["main_process"] = process_stats
        else:
            result["child_processes"][pid] = process_stats

        # Accumulate for totals
        total_cpu.extend(data["cpu"])
        total_memory.extend(data["memory"])
        total_threads.extend(data["threads"])

    # Calculate totals
    if total_cpu:
        result["total"]["avg_cpu"] = statistics.mean(total_cpu)
        result["total"]["max_cpu"] = max(total_cpu)

    if total_memory:
        result["total"]["avg_memory_mb"] = statistics.mean(total_memory) / 1024
        result["total"]["max_memory_mb"] = max(total_memory) / 1024

    if total_threads:
        result["total"]["avg_threads"] = statistics.mean(total_threads)
        result["total"]["max_threads"] = max(total_threads)

    return result


def load_metrics(path: str, include_metadata: bool = False) -> list[dict[str, Any]]:
    """
    Load metrics from a file (supports JSON, JSONL).

    Args:
        path: Path to the metrics file
        include_metadata: Whether to include the metadata line in the result

    Returns:
        List of metrics dictionaries (excluding metadata line by default)
    """
    with open(path) as f:
        content = f.read()
        if not content:
            return []

        if content.startswith("[") and content.endswith("]"):
            # JSON array format
            return json.loads(content)
        else:
            # JSONL format (one JSON object per line)
            lines = [line for line in content.split("\n") if line.strip()]

            # Process metadata line
            metadata = None
            if lines and any(key in lines[0].lower() for key in ['"pid":', '"cmd":', '"executable":', '"t0_ms":']):
                metadata = json.loads(lines[0])
                metrics = [json.loads(line) for line in lines[1:]]

                # Include metadata in results if requested
                if include_metadata and metadata:
                    return [metadata] + metrics
                return metrics

            # If no metadata identified, process all lines
            return [json.loads(line) for line in lines]


def save_metrics(
    metrics: list[dict[str, Any]], path: str, format: str = "jsonl", include_metadata: bool = True
) -> None:
    """
    Save metrics to a file.

    Args:
        metrics: List of metrics dictionaries to save
        path: Path to save the file
        format: Format to save as ('jsonl', 'json', 'csv')
        include_metadata: Whether to include metadata line (JSONL format only)
    """
    import os
    import sys
    import time

    with open(path, "w") as f:
        if format == "json":
            json.dump(metrics, f, indent=2)
        elif format == "jsonl":
            # Add metadata as first line if requested
            if include_metadata:
                metadata = {
                    "pid": os.getpid(),
                    "cmd": ["python"],
                    "executable": sys.executable,
                    "t0_ms": int(time.time() * 1000),
                }
                f.write(json.dumps(metadata) + "\n")

            # Write metrics, one per line
            for metric in metrics:
                f.write(json.dumps(metric) + "\n")
        elif format == "csv":
            f.write(convert_format(metrics, "csv"))
        else:
            raise ValueError(f"Unknown format: {format}")
