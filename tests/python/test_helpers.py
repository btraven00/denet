"""
Test helper utilities for denet Python tests.

This module provides clean, focused utility functions for testing denet functionality.
"""

import json
from typing import Any, Dict, List, Union


def extract_metrics_from_sample(sample: Union[str, Dict[str, Any]]) -> Dict[str, Any]:
    """
    Extract metrics from a sample, handling different formats.

    Args:
        sample: Sample data as JSON string or dictionary

    Returns:
        Dictionary containing metrics, or empty dict if no metrics found
    """
    if isinstance(sample, str):
        try:
            sample = json.loads(sample)
        except json.JSONDecodeError:
            return {}

    if not isinstance(sample, dict):
        return {}

    # Skip metadata entries (contain pid, cmd, executable, t0_ms)
    if all(key in sample for key in ["pid", "cmd", "executable", "t0_ms"]):
        return {}

    # Return metrics directly if they're at the top level
    if "cpu_usage" in sample and "mem_rss_kb" in sample:
        return sample

    # Handle tree format with aggregated metrics
    if "aggregated" in sample and isinstance(sample["aggregated"], dict):
        return sample["aggregated"]

    return {}


def is_valid_metrics_sample(sample: Union[str, Dict[str, Any]]) -> bool:
    """
    Check if a sample contains valid metrics data.

    Args:
        sample: Sample data as JSON string or dictionary

    Returns:
        True if sample contains valid metrics
    """
    metrics = extract_metrics_from_sample(sample)
    required_fields = ["cpu_usage", "mem_rss_kb", "ts_ms"]
    return all(field in metrics for field in required_fields)


def filter_metrics_samples(samples: List[Union[str, Dict[str, Any]]]) -> List[Dict[str, Any]]:
    """
    Extract and filter valid metrics from a list of samples.

    Args:
        samples: List of samples

    Returns:
        List of valid metrics dictionaries
    """
    return [extract_metrics_from_sample(sample) for sample in samples if is_valid_metrics_sample(sample)]


def assert_valid_metrics(metrics: Dict[str, Any]) -> None:
    """
    Assert that metrics contain expected fields with valid values.

    Args:
        metrics: Metrics dictionary to validate

    Raises:
        AssertionError: If metrics are invalid
    """
    # Required fields
    required_fields = ["cpu_usage", "mem_rss_kb", "ts_ms"]
    for field in required_fields:
        assert field in metrics, f"Missing required field: {field}"

    # Value validations
    assert isinstance(metrics["cpu_usage"], (int, float)), "cpu_usage must be numeric"
    assert metrics["cpu_usage"] >= 0, "cpu_usage must be non-negative"

    assert isinstance(metrics["mem_rss_kb"], (int, float)), "mem_rss_kb must be numeric"
    assert metrics["mem_rss_kb"] >= 0, "mem_rss_kb must be non-negative"

    assert isinstance(metrics["ts_ms"], (int, float)), "ts_ms must be numeric"
    assert metrics["ts_ms"] > 0, "ts_ms must be positive"


def create_sample_metrics(count: int = 5) -> List[Dict[str, Any]]:
    """
    Create sample metrics for testing.

    Args:
        count: Number of sample metrics to create

    Returns:
        List of sample metrics dictionaries
    """
    base_time = 1000
    metrics = []

    for i in range(count):
        sample = {
            "ts_ms": base_time + (i * 100),
            "cpu_usage": 10.0 + (i * 5.0),
            "mem_rss_kb": 5000 + (i * 1000),
            "mem_vms_kb": 10000 + (i * 2000),
            "disk_read_bytes": 1024 * (i + 1),
            "disk_write_bytes": 2048 * (i + 1),
            "net_rx_bytes": 512 * (i + 1),
            "net_tx_bytes": 256 * (i + 1),
            "thread_count": 2 + i,
            "uptime_secs": 10 + i,
        }
        metrics.append(sample)

    return metrics
