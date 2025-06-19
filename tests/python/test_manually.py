import functools
import json
import os
import tempfile
import threading
import time
from collections.abc import Callable

from tests.python.test_helpers import extract_metrics_from_sample


# For our pure Python implementation of the context manager and decorator
class Monitor:
    """
    Context manager for monitoring the current process.
    """

    def __init__(
        self,
        base_interval_ms: int = 100,
        max_interval_ms: int = 1000,
        output_file: str | None = None,
        output_format: str = "jsonl",
        store_in_memory: bool = True,
    ):
        self.base_interval_ms = base_interval_ms
        self.max_interval_ms = max_interval_ms
        self.output_file = output_file
        self.output_format = output_format
        self.store_in_memory = store_in_memory
        self.monitoring = False
        self.thread = None
        self.samples = []
        self.pid = os.getpid()

    def __enter__(self):
        self.monitoring = True
        import denet

        def monitor_thread():
            try:
                while self.monitoring:
                    # Create a fresh monitor for each sample
                    if os.name == "posix":  # Unix-based systems
                        tmp_monitor = denet.ProcessMonitor.from_pid(
                            pid=self.pid,
                            base_interval_ms=self.base_interval_ms,
                            max_interval_ms=self.max_interval_ms,
                            output_file=None,
                            store_in_memory=False,
                        )
                        metrics_json = tmp_monitor.sample_once()
                        if metrics_json is not None:
                            metrics = json.loads(metrics_json)
                            if self.store_in_memory:
                                self.samples.append(metrics)
                            if self.output_file:
                                with open(self.output_file, "a") as f:
                                    f.write(metrics_json + "\n")
                    time.sleep(self.base_interval_ms / 1000.0)
            except Exception as e:
                print(f"Monitoring error: {e}")

        # Start monitoring in background thread
        self.thread = threading.Thread(target=monitor_thread)
        self.thread.daemon = True
        self.thread.start()

        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        # Stop monitoring thread
        self.monitoring = False
        if self.thread:
            self.thread.join(timeout=1.0)

    def get_samples(self):
        return self.samples

    def get_summary(self):
        import denet

        if not self.samples:
            return "{}"

        # Calculate elapsed time
        if len(self.samples) > 1:
            elapsed = (self.samples[-1]["ts_ms"] - self.samples[0]["ts_ms"]) / 1000.0
        else:
            elapsed = 0.0

        # Convert samples to JSON strings
        metrics_json = [json.dumps(sample) for sample in self.samples]

        # Use the existing summary generation logic
        return denet.generate_summary_from_metrics_json(metrics_json, elapsed)

    def clear_samples(self):
        self.samples = []

    def save_samples(self, path, format=None):
        if not self.samples:
            return

        format = format or "jsonl"

        with open(path, "w") as f:
            if format == "json":
                # JSON array format
                json.dump(self.samples, f)
            elif format == "csv":
                # CSV format
                if self.samples:
                    # Write header
                    headers = list(self.samples[0].keys())
                    f.write(",".join(headers) + "\n")

                    # Write data rows
                    for sample in self.samples:
                        row = [str(sample.get(h, "")) for h in headers]
                        f.write(",".join(row) + "\n")
            else:
                # Default to JSONL
                for sample in self.samples:
                    f.write(json.dumps(sample) + "\n")


def profile(
    base_interval_ms: int = 100,
    max_interval_ms: int = 1000,
    output_file: str | None = None,
    output_format: str = "jsonl",
    store_in_memory: bool = True,
    include_children: bool = True,
) -> Callable:
    """Decorator for profiling functions"""

    def decorator(func: Callable) -> Callable:
        @functools.wraps(func)
        def wrapper(*args, **kwargs):
            import denet

            # Create a unique identifier for this run
            _unique_id = f"func_{int(time.time() * 1000)}"

            # We need to create a monitoring thread since we can't directly monitor
            # the currently running Python process (we'd need to know its PID in advance)
            pid = os.getpid()
            monitoring = True
            samples = []
            output_file_path = output_file

            def monitoring_thread():
                nonlocal samples
                try:
                    while monitoring:
                        # Sample metrics from current process
                        if os.name == "posix":  # Unix-based systems
                            # Create a fresh monitor for each sample to avoid accumulation issues
                            tmp_monitor = denet.ProcessMonitor.from_pid(
                                pid=pid,
                                base_interval_ms=base_interval_ms,
                                max_interval_ms=max_interval_ms,
                                output_file=None,  # We'll handle file output separately
                                store_in_memory=False,
                            )
                            metrics_json = tmp_monitor.sample_once()
                            if metrics_json is not None:
                                metrics = json.loads(metrics_json)
                                if store_in_memory:
                                    samples.append(metrics)
                                if output_file_path:
                                    with open(output_file_path, "a") as f:
                                        f.write(metrics_json + "\n")
                        time.sleep(base_interval_ms / 1000.0)  # Convert ms to seconds
                except Exception as e:
                    print(f"Monitoring error: {e}")

            # Start monitoring in a separate thread
            thread = threading.Thread(target=monitoring_thread)
            thread.daemon = True  # Thread won't block program exit
            thread.start()

            try:
                # Call the original function
                result = func(*args, **kwargs)
                return result, samples
            finally:
                # Stop monitoring thread
                monitoring = False
                thread.join(timeout=1.0)  # Wait up to 1 second for thread to finish

                # If we're not storing in memory but have a file, read it back
                if not store_in_memory and output_file_path and os.path.exists(output_file_path):
                    with open(output_file_path) as f:
                        samples = [json.loads(line) for line in f if line.strip()]

        return wrapper

    return decorator


def test_phase1():
    """Test Phase 1 functionality: Core ProcessMonitor class"""
    print("\n--- Testing Phase 1: Core ProcessMonitor functionality ---")
    import denet

    print("Testing sample storage in memory...")
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

    # Check samples
    samples = monitor.get_samples()
    assert len(samples) > 0, "No samples collected"
    print(f"Collected {len(samples)} samples")

    # Test file output
    with tempfile.NamedTemporaryFile(delete=False) as tmp:
        temp_file = tmp.name

    try:
        print("Testing direct file output...")
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

        # Check file content
        assert os.path.exists(temp_file), "Output file not created"
        with open(temp_file) as f:
            content = f.read()
            assert len(content) > 0, "Output file is empty"

            # Verify each line is valid JSON
            lines = [line for line in content.split("\n") if line.strip()]
            assert len(lines) > 0, "No JSON lines in output file"
            for line in lines:
                data = json.loads(line)
                metrics = extract_metrics_from_sample(data)
                assert "cpu_usage" in metrics, "Missing cpu_usage field"

        print(f"File output successful with {len(lines)} lines")
    finally:
        if os.path.exists(temp_file):
            os.unlink(temp_file)

    # Test saving samples
    print("Testing save_samples method...")
    monitor = denet.ProcessMonitor(
        cmd=["python", "-c", "import time; time.sleep(0.5)"],
        base_interval_ms=100,
        max_interval_ms=1000,
    )

    # Sample a few times
    for _ in range(3):
        monitor.sample_once()
        time.sleep(0.1)

    # Test different formats
    for fmt in ["jsonl", "json", "csv"]:
        with tempfile.NamedTemporaryFile(delete=False, suffix=f".{fmt}") as tmp:
            out_file = tmp.name

        try:
            monitor.save_samples(out_file, fmt)
            assert os.path.exists(out_file), f"Output file for {fmt} not created"
            with open(out_file) as f:
                content = f.read()
                assert len(content) > 0, f"Output file for {fmt} is empty"
            print(f"Successfully saved samples in {fmt} format")
        finally:
            if os.path.exists(out_file):
                os.unlink(out_file)

    # Test summary generation
    print("Testing summary generation...")
    summary_json = monitor.get_summary()
    summary = json.loads(summary_json)

    # Verify summary has expected fields
    assert "avg_cpu_usage" in summary, "Missing avg_cpu_usage in summary"
    assert "peak_mem_rss_kb" in summary, "Missing peak_mem_rss_kb in summary"
    print("Summary generation successful")

    print("Phase 1 tests completed successfully!")


def test_phase2():
    """Test Phase 2 functionality: Convenience interfaces"""
    print("\n--- Testing Phase 2: Convenience interfaces ---")

    print("Testing profile decorator...")

    # Define a function to profile
    @profile(base_interval_ms=100, max_interval_ms=500)
    def example_function():
        # Do some work
        result = 0
        for i in range(1000):
            result += i
        time.sleep(0.5)
        return result

    # Call the function and get metrics
    result, metrics = example_function()
    assert result == 499500, "Function result incorrect"
    assert len(metrics) > 0, "No metrics collected from decorator"
    print(f"Decorator collected {len(metrics)} samples")

    print("Testing context manager...")
    # Use the context manager
    with Monitor(base_interval_ms=100) as mon:
        # Do some work
        result = 0
        for i in range(1000):
            result += i
        time.sleep(0.5)

    samples = mon.get_samples()
    assert len(samples) > 0, "No samples collected from context manager"
    print(f"Context manager collected {len(samples)} samples")

    # Test file output with context manager
    with tempfile.NamedTemporaryFile(delete=False) as tmp:
        temp_file = tmp.name

    try:
        print("Testing context manager with file output...")
        with Monitor(base_interval_ms=100, output_file=temp_file) as mon:
            time.sleep(0.5)

        assert os.path.exists(temp_file), "Output file not created by context manager"
        with open(temp_file) as f:
            content = f.read()
            assert len(content) > 0, "Output file from context manager is empty"

            # Verify each line is valid JSON
            lines = [line for line in content.split("\n") if line.strip()]
            assert len(lines) > 0, "No JSON lines in context manager output file"
            print(f"Context manager wrote {len(lines)} lines to file")
    finally:
        if os.path.exists(temp_file):
            os.unlink(temp_file)

    print("Phase 2 tests completed successfully!")


if __name__ == "__main__":
    test_phase1()
    test_phase2()
    print("\nAll tests completed successfully!")
