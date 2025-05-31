import unittest
import time
import json
import sys
import os
import tempfile
from pathlib import Path

# Add the package to the path if running tests directly
sys.path.insert(0, str(Path(__file__).parent.parent))

try:
    import denet
except ImportError:
    print("denet module not found. Run 'pixi run develop' first to build the extension.")
    sys.exit(1)

class TestSummary(unittest.TestCase):
    def test_generate_summary_from_metrics_json(self):
        """Test generating a summary from JSON metrics strings"""
        # Create sample metrics
        metrics = []

        # First sample
        metrics.append(json.dumps({
            "ts_ms": 1000,
            "cpu_usage": 5.0,
            "mem_rss_kb": 1024,
            "mem_vms_kb": 2048,
            "disk_read_bytes": 1000,
            "disk_write_bytes": 2000,
            "net_rx_bytes": 300,
            "net_tx_bytes": 400,
            "thread_count": 2,
            "uptime_secs": 10
        }))

        # Second sample with higher values
        metrics.append(json.dumps({
            "ts_ms": 2000,
            "cpu_usage": 15.0,
            "mem_rss_kb": 2048,
            "mem_vms_kb": 4096,
            "disk_read_bytes": 2500,
            "disk_write_bytes": 3000,
            "net_rx_bytes": 800,
            "net_tx_bytes": 900,
            "thread_count": 3,
            "uptime_secs": 20
        }))

        # Calculate duration from timestamps
        elapsed_time = (2000 - 1000) / 1000.0  # 1 second

        # Generate summary
        summary_json = denet.generate_summary_from_metrics_json(metrics, elapsed_time)
        summary = json.loads(summary_json)

        # Verify summary contents
        self.assertEqual(summary["total_time_secs"], elapsed_time)
        self.assertEqual(summary["sample_count"], 2)
        self.assertEqual(summary["max_processes"], 1)  # Default for regular metrics
        self.assertEqual(summary["max_threads"], 3)  # Highest value from samples
        self.assertEqual(summary["total_disk_read_bytes"], 2500)  # Highest value
        self.assertEqual(summary["total_disk_write_bytes"], 3000)  # Highest value
        self.assertEqual(summary["total_net_rx_bytes"], 800)  # Highest value
        self.assertEqual(summary["total_net_tx_bytes"], 900)  # Highest value
        self.assertEqual(summary["peak_mem_rss_kb"], 2048)  # Highest value
        self.assertEqual(summary["avg_cpu_usage"], 10.0)  # (5 + 15) / 2

    def test_generate_summary_from_tree_metrics_json(self):
        """Test generating summary from tree metrics JSON strings"""
        metrics = []

        # Create tree metrics with aggregated data - first sample
        tree_metric1 = {
            "ts_ms": 1000,
            "parent": {
                "ts_ms": 1000,
                "cpu_usage": 2.5,
                "mem_rss_kb": 1024,
                "mem_vms_kb": 2048,
                "disk_read_bytes": 500,
                "disk_write_bytes": 1000,
                "net_rx_bytes": 200,
                "net_tx_bytes": 300,
                "thread_count": 1,
                "uptime_secs": 5
            },
            "children": [],
            "aggregated": {
                "ts_ms": 1000,
                "cpu_usage": 4.0,
                "mem_rss_kb": 1536,
                "mem_vms_kb": 3072,
                "disk_read_bytes": 600,
                "disk_write_bytes": 1200,
                "net_rx_bytes": 250,
                "net_tx_bytes": 360,
                "thread_count": 2,
                "process_count": 2,
                "uptime_secs": 5
            }
        }
        metrics.append(json.dumps(tree_metric1))

        # Add a second sample with higher values
        tree_metric2 = {
            "ts_ms": 2000,
            "parent": {
                "ts_ms": 2000,
                "cpu_usage": 3.0,
                "mem_rss_kb": 1536,
                "mem_vms_kb": 3072,
                "disk_read_bytes": 600,
                "disk_write_bytes": 1200,
                "net_rx_bytes": 250,
                "net_tx_bytes": 360,
                "thread_count": 1,
                "uptime_secs": 6
            },
            "children": [],
            "aggregated": {
                "ts_ms": 2000,
                "cpu_usage": 6.0,
                "mem_rss_kb": 2048,
                "mem_vms_kb": 4096,
                "disk_read_bytes": 800,
                "disk_write_bytes": 1500,
                "net_rx_bytes": 350,
                "net_tx_bytes": 460,
                "thread_count": 3,
                "process_count": 3,
                "uptime_secs": 6
            }
        }
        metrics.append(json.dumps(tree_metric2))

        # Generate summary
        elapsed_time = 1.0  # 1 second
        summary_json = denet.generate_summary_from_metrics_json(metrics, elapsed_time)
        summary = json.loads(summary_json)

        # Verify summary contents
        self.assertEqual(summary["sample_count"], 2)
        self.assertEqual(summary["max_processes"], 3)  # Max from second sample
        self.assertEqual(summary["max_threads"], 3)  # Max from second sample
        self.assertEqual(summary["peak_mem_rss_kb"], 2048)  # Highest value
        self.assertEqual(summary["total_disk_read_bytes"], 800)  # Highest value
        self.assertEqual(summary["total_disk_write_bytes"], 1500)  # Highest value

    def test_generate_summary_from_file(self):
        """Test generating summary from a JSON file"""
        # Create a temporary file with test metrics
        with tempfile.NamedTemporaryFile(mode='w+', suffix='.json', delete=False) as tmp:
            # Write a few sample metrics
            tmp.write(json.dumps({
                "ts_ms": 1000,
                "cpu_usage": 5.0,
                "mem_rss_kb": 1024,
                "mem_vms_kb": 2048,
                "disk_read_bytes": 1000,
                "disk_write_bytes": 2000,
                "net_rx_bytes": 300,
                "net_tx_bytes": 400,
                "thread_count": 2,
                "uptime_secs": 10
            }) + "\n")

            tmp.write(json.dumps({
                "ts_ms": 2000,
                "cpu_usage": 15.0,
                "mem_rss_kb": 2048,
                "mem_vms_kb": 4096,
                "disk_read_bytes": 2500,
                "disk_write_bytes": 3000,
                "net_rx_bytes": 800,
                "net_tx_bytes": 900,
                "thread_count": 3,
                "uptime_secs": 20
            }) + "\n")

            tmp_path = tmp.name

        try:
            # Generate summary from the file
            summary_json = denet.generate_summary_from_file(tmp_path)
            summary = json.loads(summary_json)

            # Verify summary contents
            self.assertEqual(summary["sample_count"], 2)
            self.assertEqual(summary["total_time_secs"], 1.0)  # (2000-1000)/1000
            self.assertEqual(summary["max_threads"], 3)
            self.assertEqual(summary["peak_mem_rss_kb"], 2048)
            self.assertEqual(summary["avg_cpu_usage"], 10.0)  # (5 + 15) / 2

        finally:
            # Clean up
            try:
                os.unlink(tmp_path)
            except:
                pass


if __name__ == "__main__":
    unittest.main()
