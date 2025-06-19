import json
import os
import tempfile
import time
import unittest

import denet
from denet import ProcessMonitor
from tests.python.test_helpers import extract_metrics_from_sample, check_sample_has_metrics


class TestProcessMonitor(unittest.TestCase):
    def test_sample_storage(self):
        """Test that samples are stored when store_in_memory=True"""
        # Create a monitor with a simple sleep command
        monitor = denet.ProcessMonitor(
            cmd=["python", "-c", "import time; time.sleep(0.5)"],
            base_interval_ms=100,
            max_interval_ms=1000,
            store_in_memory=True,
        )

        # Sample a few times
        for _ in range(3):
            monitor.sample_once()
            time.sleep(0.1)

        # Check that samples were stored
        samples = monitor.get_samples()
        self.assertGreater(len(samples), 0)

        # Verify samples are valid JSON
        for sample in samples:
            data = json.loads(sample)
            metrics = extract_metrics_from_sample(data)
            self.assertIn("cpu_usage", metrics)
            self.assertIn("mem_rss_kb", metrics)

    def test_file_output(self):
        """Test direct file output option"""
        # Create a temporary file
        with tempfile.NamedTemporaryFile(delete=False) as tmp:
            temp_file = tmp.name

        try:
            # Create monitor with file output
            monitor = denet.ProcessMonitor(
                cmd=["python", "-c", "import time; time.sleep(0.5)"],
                base_interval_ms=100,
                max_interval_ms=1000,
                output_file=temp_file,
            )

            # Sample a few times
            for _ in range(3):
                monitor.sample_once()
                time.sleep(0.1)

            # Check that the file exists and has content
            self.assertTrue(os.path.exists(temp_file))
            with open(temp_file) as f:
                content = f.read()
                self.assertGreater(len(content), 0)

                # Verify each line is valid JSON
                lines = [line for line in content.split("\n") if line.strip()]
                self.assertGreater(len(lines), 0)

                # Skip metadata line if present
                metrics_found = False
                for line in lines:
                    data = json.loads(line)
                    # Skip metadata line (has pid, cmd, executable, t0_ms)
                    if all(key in data for key in ["pid", "cmd", "executable", "t0_ms"]):
                        continue
                    metrics = extract_metrics_from_sample(data)
                    self.assertIn("cpu_usage", metrics)
                    metrics_found = True

                # Ensure we found at least one metrics line
                self.assertTrue(metrics_found, "No metrics lines found in output")
        finally:
            # Clean up temporary file
            if os.path.exists(temp_file):
                os.unlink(temp_file)

    def test_memory_vs_file(self):
        """Verify store_in_memory=False keeps memory usage low"""
        # Create a monitor with memory storage disabled
        with tempfile.NamedTemporaryFile(delete=False) as tmp:
            temp_file = tmp.name

        try:
            # Create monitor with file output but no memory storage
            monitor = denet.ProcessMonitor(
                cmd=["python", "-c", "import time; time.sleep(0.5)"],
                base_interval_ms=100,
                max_interval_ms=1000,
                output_file=temp_file,
                store_in_memory=False,
            )

            # Sample a few times
            for _ in range(3):
                monitor.sample_once()
                time.sleep(0.1)

            # Check that no samples were stored in memory
            self.assertEqual(len(monitor.get_samples()), 0)

            # But file should have content
            with open(temp_file) as f:
                lines = [line for line in f.read().split("\n") if line.strip()]
                self.assertGreater(len(lines), 0)
        finally:
            # Clean up temporary file
            if os.path.exists(temp_file):
                os.unlink(temp_file)

    def test_backward_compatibility(self):
        """Verify that old code patterns still work"""
        # Create a monitor with the old signature
        monitor = denet.ProcessMonitor(
            cmd=["python", "-c", "import time; time.sleep(0.1)"],
            base_interval_ms=100,
            max_interval_ms=1000,
        )

        # Old usage pattern - get metrics as JSON string
        sample_json = monitor.sample_once()
        self.assertIsNotNone(sample_json)  # In new API, sample_once returns string directly

        # Verify it's valid JSON
        data = json.loads(sample_json)
        # Skip check if this is metadata
        if not all(key in data for key in ["pid", "cmd", "executable", "t0_ms"]):
            metrics = extract_metrics_from_sample(data)
            self.assertIn("cpu_usage", metrics)

    def test_summary_generation(self):
        """Test that summary is generated correctly from stored samples"""
        # Create a monitor and generate some samples
        monitor = denet.ProcessMonitor(
            cmd=["python", "-c", "import time; time.sleep(0.5)"],
            base_interval_ms=100,
            max_interval_ms=1000,
        )

        # Sample a few times
        for _ in range(3):
            monitor.sample_once()
            time.sleep(0.1)

        # Get summary
        summary_json = monitor.get_summary()
        summary = json.loads(summary_json)

        # Verify summary has expected fields
        self.assertIn("avg_cpu_usage", summary)
        self.assertIn("peak_mem_rss_kb", summary)
        self.assertIn("sample_count", summary)
        self.assertIn("total_time_secs", summary)

    def test_save_samples(self):
        """Test saving samples to different formats"""
        # Create a monitor and generate some samples
        monitor = denet.ProcessMonitor(
            cmd=["python", "-c", "import time; time.sleep(0.5)"],
            base_interval_ms=100,
            max_interval_ms=1000,
        )

        # Sample a few times
        for _ in range(3):
            monitor.sample_once()
            time.sleep(0.1)

        # Test saving as JSONL (default)
        with tempfile.NamedTemporaryFile(delete=False, suffix=".jsonl") as tmp:
            jsonl_file = tmp.name

        try:
            monitor.save_samples(jsonl_file)
            with open(jsonl_file) as f:
                lines = [line for line in f.read().split("\n") if line.strip()]
                self.assertGreater(len(lines), 0)
                for line in lines:
                    data = json.loads(line)
                    metrics = extract_metrics_from_sample(data)
                    self.assertIn("cpu_usage", metrics)
        finally:
            if os.path.exists(jsonl_file):
                os.unlink(jsonl_file)

        # Test saving as JSON
        with tempfile.NamedTemporaryFile(delete=False, suffix=".json") as tmp:
            json_file = tmp.name

        try:
            monitor.save_samples(json_file, "json")
            with open(json_file) as f:
                content = f.read()
                self.assertTrue(content.startswith("[") and content.endswith("]"))
                data = json.loads(content)
                self.assertIsInstance(data, list)
                self.assertGreater(len(data), 0)
                # Skip metadata items
                metrics_found = False
                for item in data:
                    # Skip metadata items
                    if all(key in item for key in ["pid", "cmd", "executable", "t0_ms"]):
                        continue
                    metrics = extract_metrics_from_sample(item)
                    self.assertIn("cpu_usage", metrics)
                    metrics_found = True

                # Ensure we found at least one metrics item
                self.assertTrue(metrics_found, "No metrics items found in output")
        finally:
            if os.path.exists(json_file):
                os.unlink(json_file)

        # Test saving as CSV
        with tempfile.NamedTemporaryFile(delete=False, suffix=".csv") as tmp:
            csv_file = tmp.name

        try:
            monitor.save_samples(csv_file, "csv")
            with open(csv_file) as f:
                lines = [line for line in f.read().split("\n") if line.strip()]
                self.assertGreater(len(lines), 0)
                # Check header
                self.assertTrue("ts_ms" in lines[0] and "cpu_usage" in lines[0])
                # Check data rows
                self.assertGreater(len(lines), 1)
        finally:
            if os.path.exists(csv_file):
                os.unlink(csv_file)

    def test_clear_samples(self):
        """Test clearing sample memory"""
        # Create a monitor and generate some samples
        monitor = denet.ProcessMonitor(
            cmd=["python", "-c", "import time; time.sleep(0.5)"],
            base_interval_ms=100,
            max_interval_ms=1000,
        )

        # Sample a few times
        for _ in range(3):
            monitor.sample_once()
            time.sleep(0.1)

        # Verify we have samples
        self.assertGreater(len(monitor.get_samples()), 0)

        # Clear samples
        monitor.clear_samples()

        # Verify samples are gone
        self.assertEqual(len(monitor.get_samples()), 0)


if __name__ == "__main__":
    unittest.main()
