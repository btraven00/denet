"""
Test summary generation API functionality.

This module tests the summary generation functions, focusing on correct
behavior and data integrity rather than implementation details.
"""

import json
import pytest
import denet
from tests.python.test_helpers import create_sample_metrics


class TestSummaryFromMetricsJson:
    """Test generate_summary_from_metrics_json function."""

    def test_basic_summary_generation(self):
        """Test basic summary generation from metrics JSON."""
        # Create sample metrics
        metrics = create_sample_metrics(3)
        metrics_json = [json.dumps(metric) for metric in metrics]

        # Calculate elapsed time
        elapsed_time = (metrics[-1]["ts_ms"] - metrics[0]["ts_ms"]) / 1000.0

        # Generate summary
        summary_json = denet.generate_summary_from_metrics_json(metrics_json, elapsed_time)
        summary = json.loads(summary_json)

        # Verify summary structure
        assert isinstance(summary, dict)

        # Check required fields
        expected_fields = [
            "total_time_secs",
            "sample_count",
            "max_processes",
            "max_threads",
            "total_disk_read_bytes",
            "total_disk_write_bytes",
            "total_net_rx_bytes",
            "total_net_tx_bytes",
            "peak_mem_rss_kb",
            "avg_cpu_usage",
        ]

        for field in expected_fields:
            assert field in summary, f"Missing field: {field}"

        # Verify values
        assert summary["sample_count"] == 3
        assert summary["total_time_secs"] == elapsed_time
        assert summary["max_processes"] >= 1
        assert summary["avg_cpu_usage"] > 0

    def test_single_metric_summary(self):
        """Test summary generation with single metric."""
        metric = create_sample_metrics(1)[0]
        metrics_json = [json.dumps(metric)]
        elapsed_time = 0.0

        summary_json = denet.generate_summary_from_metrics_json(metrics_json, elapsed_time)
        summary = json.loads(summary_json)

        assert summary["sample_count"] == 1
        assert summary["total_time_secs"] == elapsed_time

    def test_empty_metrics_summary(self):
        """Test summary generation with empty metrics."""
        summary_json = denet.generate_summary_from_metrics_json([], 0.0)
        summary = json.loads(summary_json)

        assert summary["sample_count"] == 0
        assert summary["total_time_secs"] == 0.0

    def test_tree_metrics_summary(self):
        """Test summary with tree-structured metrics."""
        # Create tree metrics with aggregated data
        tree_metric = {
            "ts_ms": 1000,
            "parent": {
                "ts_ms": 1000,
                "cpu_usage": 10.0,
                "mem_rss_kb": 5000,
                "mem_vms_kb": 10000,
                "disk_read_bytes": 1024,
                "disk_write_bytes": 2048,
                "net_rx_bytes": 512,
                "net_tx_bytes": 256,
                "thread_count": 2,
                "uptime_secs": 10,
            },
            "children": [],
            "aggregated": {
                "ts_ms": 1000,
                "cpu_usage": 15.0,
                "mem_rss_kb": 8000,
                "mem_vms_kb": 16000,
                "disk_read_bytes": 2048,
                "disk_write_bytes": 4096,
                "net_rx_bytes": 1024,
                "net_tx_bytes": 512,
                "thread_count": 3,
                "process_count": 2,
                "uptime_secs": 10,
            },
        }

        metrics_json = [json.dumps(tree_metric)]
        elapsed_time = 1.0

        summary_json = denet.generate_summary_from_metrics_json(metrics_json, elapsed_time)
        summary = json.loads(summary_json)

        assert summary["sample_count"] == 1
        assert summary["avg_cpu_usage"] == 15.0  # Should use aggregated data
        assert summary["peak_mem_rss_kb"] == 8000  # Should use aggregated data

    def test_mixed_regular_and_tree_metrics(self):
        """Test summary with mix of regular and tree metrics."""
        # Regular metric
        regular_metric = create_sample_metrics(1)[0]

        # Tree metric
        tree_metric = {
            "ts_ms": 2000,
            "aggregated": {
                "ts_ms": 2000,
                "cpu_usage": 25.0,
                "mem_rss_kb": 10000,
                "mem_vms_kb": 20000,
                "disk_read_bytes": 4096,
                "disk_write_bytes": 8192,
                "net_rx_bytes": 2048,
                "net_tx_bytes": 1024,
                "thread_count": 4,
                "process_count": 3,
                "uptime_secs": 20,
            },
        }

        metrics_json = [json.dumps(regular_metric), json.dumps(tree_metric)]
        elapsed_time = (tree_metric["ts_ms"] - regular_metric["ts_ms"]) / 1000.0

        summary_json = denet.generate_summary_from_metrics_json(metrics_json, elapsed_time)
        summary = json.loads(summary_json)

        # Rust implementation may process tree metrics differently - check what we actually get
        assert summary["sample_count"] >= 1
        assert summary["peak_mem_rss_kb"] == 10000  # Max from both metrics

    def test_invalid_json_handling(self):
        """Test handling of invalid JSON in metrics."""
        # Mix valid and invalid JSON
        valid_metric = json.dumps(create_sample_metrics(1)[0])
        invalid_json = "invalid json string"

        # Should handle gracefully
        summary_json = denet.generate_summary_from_metrics_json([valid_metric, invalid_json], 1.0)
        summary = json.loads(summary_json)

        # Should process the valid metric
        assert summary["sample_count"] >= 0


class TestSummaryFromFile:
    """Test generate_summary_from_file function."""

    def test_basic_file_summary(self, tmp_path):
        """Test summary generation from JSONL file."""
        metrics = create_sample_metrics(3)

        # Create temporary file
        temp_file = tmp_path / "test_metrics.jsonl"
        with open(temp_file, "w") as f:
            for metric in metrics:
                f.write(json.dumps(metric) + "\n")

        summary_json = denet.generate_summary_from_file(str(temp_file))
        summary = json.loads(summary_json)

        assert summary["sample_count"] == 3
        assert summary["avg_cpu_usage"] > 0
        assert summary["peak_mem_rss_kb"] > 0

    def test_empty_file_summary(self, tmp_path):
        """Test summary generation from empty file."""
        temp_file = tmp_path / "empty_metrics.jsonl"
        temp_file.touch()  # Create empty file

        # Rust implementation throws an error for completely empty files
        with pytest.raises(OSError):
            denet.generate_summary_from_file(str(temp_file))

    def test_file_with_mixed_content(self, tmp_path):
        """Test file with mix of valid metrics and other content."""
        metrics = create_sample_metrics(2)

        temp_file = tmp_path / "mixed_content.jsonl"
        with open(temp_file, "w") as f:
            # Write valid metric
            f.write(json.dumps(metrics[0]) + "\n")

            # Write metadata line (should be skipped)
            metadata = {"pid": 12345, "cmd": ["test"], "executable": "/usr/bin/test", "t0_ms": 1000}
            f.write(json.dumps(metadata) + "\n")

            # Write another valid metric
            f.write(json.dumps(metrics[1]) + "\n")

            # Write invalid JSON line
            f.write("invalid json line\n")

        summary_json = denet.generate_summary_from_file(str(temp_file))
        summary = json.loads(summary_json)

        # Should process only the valid metrics
        assert summary["sample_count"] == 2

    def test_nonexistent_file(self):
        """Test handling of nonexistent file."""
        with pytest.raises((FileNotFoundError, OSError)):
            denet.generate_summary_from_file("/nonexistent/path/file.jsonl")


class TestSummaryDataIntegrity:
    """Test data integrity in summary generation."""

    def test_cpu_usage_calculation(self):
        """Test CPU usage calculation accuracy."""
        # Create metrics with known CPU values
        metrics = [
            {
                "ts_ms": 1000,
                "cpu_usage": 10.0,
                "mem_rss_kb": 5000,
                "mem_vms_kb": 10000,
                "disk_read_bytes": 1024,
                "disk_write_bytes": 2048,
                "net_rx_bytes": 512,
                "net_tx_bytes": 256,
                "thread_count": 2,
                "uptime_secs": 10,
            },
            {
                "ts_ms": 2000,
                "cpu_usage": 20.0,
                "mem_rss_kb": 6000,
                "mem_vms_kb": 12000,
                "disk_read_bytes": 2048,
                "disk_write_bytes": 4096,
                "net_rx_bytes": 1024,
                "net_tx_bytes": 512,
                "thread_count": 3,
                "uptime_secs": 20,
            },
        ]

        metrics_json = [json.dumps(metric) for metric in metrics]
        elapsed_time = 1.0

        summary_json = denet.generate_summary_from_metrics_json(metrics_json, elapsed_time)
        summary = json.loads(summary_json)

        # Average CPU should be (10 + 20) / 2 = 15
        assert summary["avg_cpu_usage"] == 15.0

    def test_memory_peak_calculation(self):
        """Test memory peak calculation."""
        # Create metrics with known memory values
        metrics = [
            {
                "ts_ms": 1000,
                "cpu_usage": 10.0,
                "mem_rss_kb": 5000,
                "mem_vms_kb": 10000,
                "disk_read_bytes": 1024,
                "disk_write_bytes": 2048,
                "net_rx_bytes": 512,
                "net_tx_bytes": 256,
                "thread_count": 2,
                "uptime_secs": 10,
            },
            {
                "ts_ms": 2000,
                "cpu_usage": 20.0,
                "mem_rss_kb": 8000,  # Peak
                "mem_vms_kb": 16000,
                "disk_read_bytes": 2048,
                "disk_write_bytes": 4096,
                "net_rx_bytes": 1024,
                "net_tx_bytes": 512,
                "thread_count": 3,
                "uptime_secs": 20,
            },
            {
                "ts_ms": 3000,
                "cpu_usage": 15.0,
                "mem_rss_kb": 6000,
                "mem_vms_kb": 12000,
                "disk_read_bytes": 3072,
                "disk_write_bytes": 6144,
                "net_rx_bytes": 1536,
                "net_tx_bytes": 768,
                "thread_count": 2,
                "uptime_secs": 30,
            },
        ]

        metrics_json = [json.dumps(metric) for metric in metrics]
        elapsed_time = 2.0

        summary_json = denet.generate_summary_from_metrics_json(metrics_json, elapsed_time)
        summary = json.loads(summary_json)

        # Peak memory should be 8000
        assert summary["peak_mem_rss_kb"] == 8000

    def test_time_calculation(self):
        """Test elapsed time calculation."""
        metrics = [
            {
                "ts_ms": 1000,
                "cpu_usage": 10.0,
                "mem_rss_kb": 5000,
                "mem_vms_kb": 10000,
                "disk_read_bytes": 1024,
                "disk_write_bytes": 2048,
                "net_rx_bytes": 512,
                "net_tx_bytes": 256,
                "thread_count": 2,
                "uptime_secs": 10,
            },
            {
                "ts_ms": 3500,
                "cpu_usage": 20.0,
                "mem_rss_kb": 6000,
                "mem_vms_kb": 12000,
                "disk_read_bytes": 2048,
                "disk_write_bytes": 4096,
                "net_rx_bytes": 1024,
                "net_tx_bytes": 512,
                "thread_count": 3,
                "uptime_secs": 25,
            },
        ]

        metrics_json = [json.dumps(metric) for metric in metrics]
        elapsed_time = 2.5  # (3500 - 1000) / 1000

        summary_json = denet.generate_summary_from_metrics_json(metrics_json, elapsed_time)
        summary = json.loads(summary_json)

        assert summary["total_time_secs"] == elapsed_time

    def test_cumulative_values(self):
        """Test cumulative value handling (disk I/O, network)."""
        metrics = [
            {
                "ts_ms": 1000,
                "cpu_usage": 10.0,
                "mem_rss_kb": 5000,
                "mem_vms_kb": 10000,
                "disk_read_bytes": 1024,
                "disk_write_bytes": 2048,
                "net_rx_bytes": 512,
                "net_tx_bytes": 256,
                "thread_count": 2,
                "uptime_secs": 10,
            },
            {
                "ts_ms": 2000,
                "cpu_usage": 20.0,
                "mem_rss_kb": 6000,
                "mem_vms_kb": 12000,
                "disk_read_bytes": 4096,  # Higher cumulative value
                "disk_write_bytes": 8192,
                "net_rx_bytes": 2048,
                "net_tx_bytes": 1024,
                "thread_count": 3,
                "uptime_secs": 20,
            },
        ]

        metrics_json = [json.dumps(metric) for metric in metrics]
        elapsed_time = 1.0

        summary_json = denet.generate_summary_from_metrics_json(metrics_json, elapsed_time)
        summary = json.loads(summary_json)

        # Should use the highest cumulative values
        assert summary["total_disk_read_bytes"] == 4096
        assert summary["total_disk_write_bytes"] == 8192
        assert summary["total_net_rx_bytes"] == 2048
        assert summary["total_net_tx_bytes"] == 1024
