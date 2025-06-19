"""
Helper functions for denet tests.

This module provides utility functions for working with denet test fixtures,
particularly to handle both the old flat metrics format and the new tree-structured
format that includes child process information.
"""

import json
from typing import Any, Dict, List, Union

__all__ = [
    "extract_metrics_from_sample",
    "check_sample_has_metrics",
    "get_metrics_from_samples",
    "get_max_processes",
]


def extract_metrics_from_sample(sample: Union[str, Dict[str, Any]], fallback_to_parent: bool = True) -> Dict[str, Any]:
    """
    Extract metrics from a sample, handling both old flat format and new tree format.

    This function handles the different formats that may be returned by denet:
    1. Old format: A flat dictionary with metrics at the top level
    2. New format: A tree structure with parent, children, and aggregated metrics

    Args:
        sample: Sample data, either as a JSON string or a dictionary
        fallback_to_parent: Whether to fallback to parent metrics if aggregated metrics not found

    Returns:
        Dictionary containing the metrics, either from the top level, aggregated field,
        or parent field (if fallback_to_parent is True)
    """
    # Parse if sample is a string
    if isinstance(sample, str):
        try:
            sample = json.loads(sample)
        except json.JSONDecodeError:
            return {}

    # Skip metadata entries
    if all(key in sample for key in ["pid", "cmd", "executable", "t0_ms"]):
        return {}

    # Case 1: Old flat format with metrics at top level
    if "cpu_usage" in sample and "mem_rss_kb" in sample:
        return sample

    # Case 2: New tree format with aggregated metrics
    if "aggregated" in sample:
        return sample["aggregated"]

    # Case 3: Fallback to parent metrics if requested
    if fallback_to_parent and "parent" in sample and isinstance(sample["parent"], dict):
        return sample["parent"]

    # If we can't find metrics, return empty dict
    return {}


def check_sample_has_metrics(sample: Union[str, Dict[str, Any]]) -> bool:
    """
    Check if a sample contains metrics data.

    Args:
        sample: Sample data, either as a JSON string or a dictionary

    Returns:
        True if sample contains metrics (cpu_usage, mem_rss_kb), False otherwise
    """
    metrics = extract_metrics_from_sample(sample)
    return "cpu_usage" in metrics and "mem_rss_kb" in metrics


def get_metrics_from_samples(samples: List[Union[str, Dict[str, Any]]]) -> List[Dict[str, Any]]:
    """
    Extract metrics from a list of samples, filtering out metadata entries.

    Args:
        samples: List of samples, each either as a JSON string or a dictionary

    Returns:
        List of metric dictionaries, with metadata entries filtered out
    """
    return [extract_metrics_from_sample(sample) for sample in samples if check_sample_has_metrics(sample)]


def get_max_processes(samples: List[Union[str, Dict[str, Any]]]) -> int:
    """
    Get the maximum number of processes from a list of samples.

    This looks for process_count in the aggregated field or defaults to 1
    for the old format.

    Args:
        samples: List of samples, each either as a JSON string or a dictionary

    Returns:
        Maximum number of processes found in the samples
    """
    max_processes = 1

    for sample in samples:
        # Parse if sample is a string
        if isinstance(sample, str):
            try:
                sample = json.loads(sample)
            except json.JSONDecodeError:
                continue

        # Look for process_count in aggregated data
        if "aggregated" in sample:
            process_count = sample["aggregated"].get("process_count", 1)
            max_processes = max(max_processes, process_count)
        elif "process_count" in sample:
            max_processes = max(max_processes, sample["process_count"])

    return max_processes
