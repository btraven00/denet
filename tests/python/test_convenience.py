import json
import os
import tempfile
import time
import unittest

import denet


class TestDecoratorInterface(unittest.TestCase):
    def test_decorator_basic(self):
        """Test basic decorator functionality"""

        @denet.profile()
        def sleep_func():
            time.sleep(0.5)
            return 42

        result, metrics = sleep_func()
        self.assertEqual(result, 42)
        self.assertIsInstance(metrics, list)
        self.assertGreater(len(metrics), 0)

        # Check that metrics contain expected fields
        # Skip metadata item if present
        for metric in metrics:
            if all(key in metric for key in ["pid", "cmd", "executable", "t0_ms"]):
                continue
            self.assertIn("cpu_usage", metric)
            self.assertIn("mem_rss_kb", metric)
            break
        else:
            self.fail("No valid metrics found in response")

    def test_decorator_file_output(self):
        """Test decorator with file output"""
        # Create a temporary file
        with tempfile.NamedTemporaryFile(delete=False) as tmp:
            temp_file = tmp.name

        try:

            @denet.profile(output_file=temp_file, store_in_memory=False)
            def sleep_func():
                time.sleep(0.5)

            result, metrics = sleep_func()
            # File should exist and have content
            self.assertTrue(os.path.exists(temp_file))
            with open(temp_file) as f:
                content = f.read()
                self.assertGreater(len(content), 0)

                # Verify each line is valid JSON
                lines = [line for line in content.split("\n") if line.strip()]
                self.assertGreater(len(lines), 0)
                # Verify at least one line has metrics data
                metrics_found = False
                for line in lines:
                    data = json.loads(line)
                    # Skip metadata line (has pid, cmd, executable, t0_ms)
                    if all(key in data for key in ["pid", "cmd", "executable", "t0_ms"]):
                        continue
                    self.assertIn("cpu_usage", data)
                    metrics_found = True
                    break
                self.assertTrue(metrics_found, "No metrics data found in output file")
        finally:
            # Clean up temporary file
            if os.path.exists(temp_file):
                os.unlink(temp_file)

    def test_decorator_adaptive_sampling(self):
        """Test with different sampling parameters"""

        @denet.profile(base_interval_ms=50, max_interval_ms=500)
        def long_task():
            # Sleep long enough to trigger adaptive sampling
            time.sleep(1.0)

        _, metrics = long_task()

        # Check if we have samples
        self.assertGreater(len(metrics), 1)

        # Check timestamps to see intervals
        timestamps = [m["ts_ms"] for m in metrics]
        self.assertGreater(len(timestamps), 1)

    def test_decorator_with_args(self):
        """Test decorator on function with arguments"""

        @denet.profile()
        def add_numbers(a, b):
            time.sleep(0.1)  # Small delay to ensure we get metrics
            return a + b

        result, metrics = add_numbers(5, 7)
        self.assertEqual(result, 12)
        self.assertGreater(len(metrics), 0)


class TestContextManagerInterface(unittest.TestCase):
    def test_context_manager(self):
        """Test basic context manager functionality"""
        with denet.monitor() as mon:
            time.sleep(0.5)

        samples = mon.get_samples()
        self.assertGreater(len(samples), 0)
        # Find and check first non-metadata sample
        for sample in samples:
            if all(key in sample for key in ["pid", "cmd", "executable", "t0_ms"]):
                continue
            self.assertIn("cpu_usage", sample)
            self.assertIn("mem_rss_kb", sample)
            break
        else:
            self.fail("No valid metrics found in samples")

    def test_context_manager_file_output(self):
        """Test context manager with file output"""
        # Create a temporary file
        with tempfile.NamedTemporaryFile(delete=False) as tmp:
            temp_file = tmp.name

        try:
            with denet.monitor(output_file=temp_file) as mon:
                time.sleep(0.5)

            # File should exist and have content
            self.assertTrue(os.path.exists(temp_file))
            with open(temp_file) as f:
                content = f.read()
                self.assertGreater(len(content), 0)

                # Verify each line is valid JSON
                lines = [line for line in content.split("\n") if line.strip()]
                self.assertGreater(len(lines), 0)
                # Verify at least one line has metrics data
                metrics_found = False
                for line in lines:
                    if not line.strip():
                        continue
                    data = json.loads(line)
                    # Skip metadata line (has pid, cmd, executable, t0_ms)
                    if all(key in data for key in ["pid", "cmd", "executable", "t0_ms"]):
                        continue
                    self.assertIn("cpu_usage", data)
                    metrics_found = True
                    break
                self.assertTrue(metrics_found, "No metrics data found in output file")
        finally:
            # Clean up temporary file
            if os.path.exists(temp_file):
                os.unlink(temp_file)

    def test_context_manager_summary(self):
        """Test summary generation from context manager"""
        with denet.monitor() as mon:
            # Perform some activity
            data = [i * i for i in range(10000)]
            time.sleep(0.2)

        # Get summary
        summary_json = mon.get_summary()
        summary = json.loads(summary_json)

        # Verify summary has expected fields
        self.assertIn("avg_cpu_usage", summary)
        self.assertIn("peak_mem_rss_kb", summary)

    def test_context_manager_save_samples(self):
        """Test saving samples from context manager"""
        with denet.monitor() as mon:
            time.sleep(0.5)

        # Test saving as JSON
        with tempfile.NamedTemporaryFile(delete=False, suffix=".json") as tmp:
            json_file = tmp.name

        try:
            mon.save_samples(json_file, "json")
            with open(json_file) as f:
                content = f.read()
                data = json.loads(content)
                self.assertIsInstance(data, list)
                self.assertGreater(len(data), 0)
        finally:
            if os.path.exists(json_file):
                os.unlink(json_file)

    def test_context_manager_clear_samples(self):
        """Test clearing samples in context manager"""
        with denet.monitor() as mon:
            time.sleep(0.5)

        # Verify we have samples
        self.assertGreater(len(mon.get_samples()), 0)

        # Clear samples
        mon.clear_samples()

        # Verify samples are gone
        self.assertEqual(len(mon.get_samples()), 0)


if __name__ == "__main__":
    unittest.main()
