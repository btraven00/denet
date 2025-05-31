import unittest
import time
import json
import sys
import os
from pathlib import Path

# Add the package to the path if running tests directly
sys.path.insert(0, str(Path(__file__).parent.parent))

try:
    import denet
except ImportError:
    print("denet module not found. Run 'pixi run develop' first to build the extension.")
    sys.exit(1)

class TestProcessMonitor(unittest.TestCase):
    def test_create_monitor(self):
        """Test that we can create a ProcessMonitor instance"""
        monitor = denet.PyProcessMonitor(["echo", "hello"], 100, 1000)
        self.assertIsNotNone(monitor, "ProcessMonitor should be created")

    def test_invalid_command(self):
        """Test error handling for invalid commands"""
        with self.assertRaises(Exception):
            denet.PyProcessMonitor([], 100, 1000)  # Empty command should fail

        with self.assertRaises(Exception):
            denet.PyProcessMonitor(["non_existent_command_123456"], 100, 1000)

    def test_run_short_process(self):
        """Test running a short process"""
        # Use a command that outputs something predictable
        cmd = ["python", "-c", "import time; print('TEST OUTPUT'); time.sleep(0.5)"]

        monitor = denet.PyProcessMonitor(cmd, 100, 1000)
        monitor.run()  # This should complete when the process ends

        # If we get here without hanging, the test passes
        self.assertTrue(True)

    def test_long_running_process(self):
        """Test monitoring a longer running process"""
        # Create a separate test script that we'll run
        test_script = Path("temp_test_script.py")
        with open(test_script, "w") as f:
            f.write("""
import time
import sys
for i in range(5):
    sys.stdout.write(f"MARKER: {i}\\n")
    sys.stdout.flush()
    time.sleep(0.2)
""")

        try:
            import threading
            import io
            from contextlib import redirect_stdout

            # We can't easily capture the monitor's output with redirect_stdout
            # because it comes from a C extension
            # Instead, let's use sample_once to get the metrics directly
            monitor = denet.PyProcessMonitor(["python", str(test_script)], 100, 1000)

            # Give the process time to start
            time.sleep(0.3)

            # Get a sample directly
            sample_json = monitor.sample_once()

            # Let the process finish
            thread = threading.Thread(target=monitor.run)
            thread.daemon = True  # Make sure thread doesn't block test exit
            thread.start()
            thread.join(timeout=5)  # Should finish in under 5 seconds

            self.assertFalse(thread.is_alive(), "Monitor should have completed")

            # Verify we got a valid JSON output from our direct sample
            self.assertIsNotNone(sample_json, "Should have sample data")

            if sample_json:
                # Parse the JSON metrics
                data = json.loads(sample_json)
                parsed = True

            # Verify the JSON has the expected fields
            self.assertIn("ts_ms", data)
            self.assertIn("cpu_usage", data)
            self.assertIn("mem_rss_kb", data)
            self.assertIn("mem_vms_kb", data)
            self.assertIn("thread_count", data)

            # Verify timestamp is reasonable (within last minute)
            now_ms = int(time.time() * 1000)
            self.assertLess(abs(now_ms - data["ts_ms"]), 60000, "Timestamp should be recent")

            # Verify memory metrics are reasonable
            self.assertGreater(data["mem_rss_kb"], 0, "RSS memory should be positive")
            self.assertGreaterEqual(data["mem_vms_kb"], data["mem_rss_kb"], "Virtual memory should be >= RSS")

            # Test start time via metadata (not in regular samples)
            # This is now available via get_metadata() method

            self.assertTrue(parsed, "At least one line should be valid JSON metrics")

        finally:
            # Clean up
            if test_script.exists():
                test_script.unlink()

    def test_timestamp_functionality(self):
        """Test that timestamps are included and monotonic"""
        monitor = denet.PyProcessMonitor(["sleep", "2"], 100, 1000)

        # Collect multiple samples
        samples = []
        for _ in range(3):
            result = monitor.sample_once()
            if result:
                data = json.loads(result)
                samples.append(data)
            time.sleep(0.1)

        self.assertGreater(len(samples), 0, "Should collect at least one sample")

        for sample in samples:
            # Verify timestamp field exists
            self.assertIn("ts_ms", sample)

            # Verify enhanced metrics exist
            self.assertIn("mem_vms_kb", sample)

            # Verify timestamp is reasonable (within last minute)
            now_ms = int(time.time() * 1000)
            self.assertLess(abs(now_ms - sample["ts_ms"]), 60000, "Timestamp should be recent")

            # Verify enhanced metrics are reasonable
            self.assertGreaterEqual(sample["mem_vms_kb"], sample["mem_rss_kb"], "VMS should be >= RSS")

        # Verify timestamps are monotonic if we have multiple samples
        if len(samples) >= 2:
            for i in range(1, len(samples)):
                self.assertGreaterEqual(samples[i]["ts_ms"], samples[i-1]["ts_ms"],
                                      "Timestamps should be monotonic")

if __name__ == "__main__":
    unittest.main()
