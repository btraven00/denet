"""
Test analysis utilities functionality.

This module tests the analysis functions provided by denet, focusing on
correct behavior and data integrity rather than reimplementing functionality.
"""

import json
import pytest
from denet.analysis import (
    aggregate_metrics,
    find_peaks,
    resource_utilization,
    convert_format,
    process_tree_analysis,
    save_metrics,
    load_metrics,
)


@pytest.fixture
def sample_metrics():
    """Generate sample metrics for testing."""
    return [
        {
            "ts_ms": 1000,
            "cpu_usage": 5.0,
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
            "ts_ms": 1100,
            "cpu_usage": 10.0,
            "mem_rss_kb": 6000,
            "mem_vms_kb": 12000,
            "disk_read_bytes": 2048,
            "disk_write_bytes": 4096,
            "net_rx_bytes": 1024,
            "net_tx_bytes": 512,
            "thread_count": 3,
            "uptime_secs": 11,
        },
        {
            "ts_ms": 1200,
            "cpu_usage": 15.0,
            "mem_rss_kb": 7000,
            "mem_vms_kb": 14000,
            "disk_read_bytes": 4096,
            "disk_write_bytes": 8192,
            "net_rx_bytes": 2048,
            "net_tx_bytes": 1024,
            "thread_count": 4,
            "uptime_secs": 12,
        },
        {
            "ts_ms": 1300,
            "cpu_usage": 10.0,
            "mem_rss_kb": 8000,
            "mem_vms_kb": 16000,
            "disk_read_bytes": 8192,
            "disk_write_bytes": 16384,
            "net_rx_bytes": 4096,
            "net_tx_bytes": 2048,
            "thread_count": 4,
            "uptime_secs": 13,
        },
        {
            "ts_ms": 1400,
            "cpu_usage": 5.0,
            "mem_rss_kb": 6000,
            "mem_vms_kb": 12000,
            "disk_read_bytes": 16384,
            "disk_write_bytes": 32768,
            "net_rx_bytes": 8192,
            "net_tx_bytes": 4096,
            "thread_count": 3,
            "uptime_secs": 14,
        },
    ]


@pytest.fixture
def tree_metrics():
    """Create sample process tree metrics."""
    return [
        {
            "ts_ms": 1000,
            "pid": 1000,
            "cpu_usage": 5.0,
            "mem_rss_kb": 5000,
            "thread_count": 2,
            "children": [{"pid": 1001, "cpu_usage": 2.0, "mem_rss_kb": 2000, "thread_count": 1}],
        },
        {
            "ts_ms": 1100,
            "pid": 1000,
            "cpu_usage": 10.0,
            "mem_rss_kb": 6000,
            "thread_count": 2,
            "children": [{"pid": 1001, "cpu_usage": 5.0, "mem_rss_kb": 3000, "thread_count": 2}],
        },
    ]


class TestAggregateMetrics:
    """Test metrics aggregation functionality."""

    def test_basic_aggregation(self, sample_metrics):
        """Test basic metrics aggregation with different window sizes and methods."""
        # Test with window size = 2 and mean method
        aggregated = aggregate_metrics(sample_metrics, window_size=2, method="mean")
        assert len(aggregated) == 3
        assert aggregated[0]["_window_size"] == 2
        assert aggregated[0]["_aggregation_method"] == "mean"
        assert aggregated[0]["cpu_usage"] == 7.5  # (5 + 10) / 2

    def test_aggregation_methods(self, sample_metrics):
        """Test different aggregation methods."""
        # Test max method
        aggregated = aggregate_metrics(sample_metrics, window_size=3, method="max")
        assert len(aggregated) == 2
        assert aggregated[0]["cpu_usage"] == 15.0  # max of 5, 10, 15

        # Test min method
        aggregated = aggregate_metrics(sample_metrics, window_size=3, method="min")
        assert aggregated[0]["cpu_usage"] == 5.0  # min of 5, 10, 15

    def test_edge_cases(self, sample_metrics):
        """Test edge cases for aggregation."""
        # Empty list
        assert aggregate_metrics([], window_size=2) == []

        # Window size <= 1 (should return original data)
        assert len(aggregate_metrics(sample_metrics, window_size=1)) == 5

        # Window size larger than data
        aggregated = aggregate_metrics(sample_metrics, window_size=10, method="mean")
        assert len(aggregated) == 1


class TestFindPeaks:
    """Test peak detection functionality."""

    def test_basic_peak_detection(self, sample_metrics):
        """Test basic peak detection."""
        peaks = find_peaks(sample_metrics, field="cpu_usage", threshold=0.7, window_size=1)
        assert len(peaks) == 1
        assert peaks[0]["cpu_usage"] == 15.0

    def test_different_thresholds(self, sample_metrics):
        """Test peak detection with different thresholds."""
        # Lower threshold should still find the same peak
        peaks = find_peaks(sample_metrics, field="cpu_usage", threshold=0.5, window_size=1)
        assert len(peaks) >= 1
        assert any(p["cpu_usage"] == 15.0 for p in peaks)

    def test_edge_cases(self, sample_metrics):
        """Test edge cases for peak detection."""
        # Non-existent field
        assert find_peaks(sample_metrics, field="nonexistent") == []

        # Empty list
        assert find_peaks([], field="cpu_usage") == []


class TestResourceUtilization:
    """Test resource utilization statistics."""

    def test_basic_statistics(self, sample_metrics):
        """Test generation of resource utilization statistics."""
        stats = resource_utilization(sample_metrics)

        # Check CPU statistics
        assert "avg_cpu" in stats
        assert "max_cpu" in stats
        assert stats["max_cpu"] == 15.0
        assert stats["avg_cpu"] == pytest.approx(9.0)

        # Check memory statistics
        assert "avg_mem_mb" in stats
        assert "max_mem_mb" in stats
        assert stats["max_mem_mb"] == pytest.approx(7.8125)  # 8000 KB = 7.8125 MB

        # Check I/O statistics
        assert "total_read_mb" in stats
        assert "total_write_mb" in stats

    def test_empty_metrics(self):
        """Test resource utilization with empty metrics."""
        assert resource_utilization([]) == {}

    def test_partial_metrics(self):
        """Test resource utilization with partial metrics."""
        partial_metrics = [
            {
                "ts_ms": 1000,
                "cpu_usage": 5.0,
                # Missing mem_rss_kb
            },
            {
                "ts_ms": 1100,
                # Missing cpu_usage
                "mem_rss_kb": 6000,
            },
        ]

        # Should still calculate stats for available fields
        stats = resource_utilization(partial_metrics)
        assert "avg_cpu" not in stats  # Not all metrics have cpu_usage
        assert "avg_mem_mb" not in stats  # Not all metrics have mem_rss_kb

    def test_single_sample_metrics(self):
        """Test resource utilization with just one sample."""
        single_sample = [
            {
                "ts_ms": 1000,
                "cpu_usage": 5.0,
                "mem_rss_kb": 5000,
                "disk_read_bytes": 1024,
                "disk_write_bytes": 2048,
                "net_rx_bytes": 512,
                "net_tx_bytes": 256,
                "thread_count": 2,
            }
        ]

        stats = resource_utilization(single_sample)
        assert stats["avg_cpu"] == 5.0
        assert stats["max_cpu"] == 5.0
        assert stats["min_cpu"] == 5.0
        assert stats["median_cpu"] == 5.0
        assert "stdev_cpu" not in stats  # Need more than one sample for stdev


class TestConvertFormat:
    """Test format conversion utilities."""

    def test_csv_conversion(self, sample_metrics):
        """Test conversion to CSV format."""
        csv_data = convert_format(sample_metrics, to_format="csv")
        assert "ts_ms,cpu_usage,mem_rss_kb" in csv_data
        assert csv_data.count("\n") == len(sample_metrics) + 1  # +1 for header

    def test_json_conversion(self, sample_metrics):
        """Test conversion to JSON format."""
        json_data = convert_format(sample_metrics, to_format="json")
        parsed_json = json.loads(json_data)
        assert len(parsed_json) == len(sample_metrics)

    def test_jsonl_conversion(self, sample_metrics):
        """Test conversion to JSONL format."""
        jsonl_data = convert_format(sample_metrics, to_format="jsonl")
        lines = jsonl_data.strip().split("\n")
        assert len(lines) == len(sample_metrics)

    def test_edge_cases(self, sample_metrics):
        """Test edge cases for format conversion."""
        # Empty list
        assert convert_format([], to_format="csv") == ""

        # Invalid format
        with pytest.raises(ValueError):
            convert_format(sample_metrics, to_format="invalid")

    def test_convert_from_file_path(self, sample_metrics, tmp_path):
        """Test converting from a file path instead of metrics list."""
        # First save metrics to a file
        jsonl_file = tmp_path / "test_metrics.jsonl"
        json_file = tmp_path / "test_metrics.json"

        # Save in both formats
        save_metrics(sample_metrics, str(jsonl_file), format="jsonl")
        save_metrics(sample_metrics, str(json_file), format="json")

        # Test converting from JSONL file path
        csv_from_jsonl = convert_format(str(jsonl_file), to_format="csv")
        assert "ts_ms,cpu_usage,mem_rss_kb" in csv_from_jsonl

        # Test converting from JSON file path
        csv_from_json = convert_format(str(json_file), to_format="csv")
        assert "ts_ms,cpu_usage,mem_rss_kb" in csv_from_json

    def test_json_with_indent(self, sample_metrics):
        """Test JSON conversion with indentation."""
        # With indent=2
        json_indented = convert_format(sample_metrics, to_format="json", indent=2)
        assert "  " in json_indented  # Should have 2-space indentation

        # With no indent
        json_compact = convert_format(sample_metrics, to_format="json", indent=None)
        assert "  " not in json_compact  # Should be compact without indentation


class TestProcessTreeAnalysis:
    """Test process tree analysis functionality."""

    def test_tree_analysis(self, tree_metrics):
        """Test analysis of process tree metrics."""
        analysis = process_tree_analysis(tree_metrics)

        # Check main process stats
        assert "main_process" in analysis
        assert "avg_cpu" in analysis["main_process"]
        assert analysis["main_process"]["avg_cpu"] == pytest.approx(7.5)

        # Check child process stats
        assert "child_processes" in analysis
        assert 1001 in analysis["child_processes"]
        assert analysis["child_processes"][1001]["avg_cpu"] == pytest.approx(3.5)

        # Check totals
        assert "total" in analysis

    def test_non_tree_metrics(self, sample_metrics):
        """Test tree analysis with regular (non-tree) metrics."""
        assert process_tree_analysis(sample_metrics) == {}

    def test_empty_metrics(self):
        """Test tree analysis with empty metrics."""
        assert process_tree_analysis([]) == {}

    def test_alternate_child_format(self):
        """Test tree analysis with alternate child_processes format."""
        alternate_tree_metrics = [
            {
                "ts_ms": 1000,
                "pid": 2000,
                "cpu_usage": 10.0,
                "mem_rss_kb": 8000,
                "thread_count": 3,
                "child_processes": [  # Using child_processes instead of children
                    {"pid": 2001, "cpu_usage": 4.0, "mem_rss_kb": 3000, "thread_count": 1}
                ],
            }
        ]

        analysis = process_tree_analysis(alternate_tree_metrics)
        assert "main_process" in analysis
        assert "child_processes" in analysis
        assert 2001 in analysis["child_processes"]
        assert analysis["child_processes"][2001]["avg_cpu"] == 4.0


class TestSaveLoadMetrics:
    """Test saving and loading metrics from files."""

    def test_save_and_load_jsonl(self, sample_metrics, tmp_path):
        """Test saving and loading metrics in JSONL format."""
        temp_file = tmp_path / "test_metrics.jsonl"

        # Save metrics
        save_metrics(sample_metrics, str(temp_file), format="jsonl")
        assert temp_file.exists()

        # Load metrics
        loaded_metrics = load_metrics(str(temp_file))
        assert len(loaded_metrics) == len(sample_metrics)
        assert loaded_metrics[0]["cpu_usage"] == sample_metrics[0]["cpu_usage"]

    def test_save_and_load_json(self, sample_metrics, tmp_path):
        """Test saving and loading metrics in JSON format."""
        temp_file = tmp_path / "test_metrics.json"

        # Save metrics
        save_metrics(sample_metrics, str(temp_file), format="json")
        assert temp_file.exists()

        # Load metrics
        loaded_metrics = load_metrics(str(temp_file))
        assert len(loaded_metrics) == len(sample_metrics)

    def test_save_csv_format(self, sample_metrics, tmp_path):
        """Test saving metrics in CSV format."""
        temp_file = tmp_path / "test_metrics.csv"

        # Save metrics
        save_metrics(sample_metrics, str(temp_file), format="csv")
        assert temp_file.exists()

        # Verify CSV content
        with open(temp_file, "r") as f:
            content = f.read()
            assert "ts_ms" in content
            assert "cpu_usage" in content

    def test_invalid_format(self, sample_metrics, tmp_path):
        """Test handling of invalid save formats."""
        temp_file = tmp_path / "test_metrics.txt"

        with pytest.raises(ValueError):
            save_metrics(sample_metrics, str(temp_file), format="invalid")

    def test_load_metrics_with_metadata(self, sample_metrics, tmp_path):
        """Test loading metrics with metadata included."""
        temp_file = tmp_path / "test_metrics_with_metadata.jsonl"

        # Save metrics with metadata
        save_metrics(sample_metrics, str(temp_file), format="jsonl", include_metadata=True)

        # Load with metadata
        loaded_with_metadata = load_metrics(str(temp_file), include_metadata=True)

        # First item should be metadata
        assert "pid" in loaded_with_metadata[0]
        assert "cmd" in loaded_with_metadata[0]
        assert "executable" in loaded_with_metadata[0]
        assert "t0_ms" in loaded_with_metadata[0]

        # Rest should be the metrics
        assert len(loaded_with_metadata) - 1 == len(sample_metrics)

    def test_load_metrics_empty_file(self, tmp_path):
        """Test loading metrics from an empty file."""
        temp_file = tmp_path / "empty.jsonl"

        # Create empty file
        with open(temp_file, "w"):
            pass

        # Should return empty list without error
        assert load_metrics(str(temp_file)) == []
