class MonitorContextManager:
    def __init__(self, base_interval_ms, max_interval_ms, output_file, output_format, store_in_memory, include_children):
        self.base_interval_ms = base_interval_ms
        self.max_interval_ms = max_interval_ms
        self.output_file = output_file
        self.output_format = output_format
        self.store_in_memory = store_in_memory
        self.include_children = include_children
        self.monitoring = False
        self.thread = None
        self.samples = []

    def __enter__(self):
        import os
        import threading
        import time
        import json

        # Start monitoring the current process
        self.pid = os.getpid()
        self.monitoring = True

        def monitor_thread():
            try:
                while self.monitoring:
                    # Create a fresh monitor for each sample
                    if os.name == 'posix':  # Unix-based systems
                        tmp_monitor = ProcessMonitor.from_pid(
                            pid=self.pid,
                            base_interval_ms=self.base_interval_ms,
                            max_interval_ms=self.max_interval_ms,
                            output_file=None,
                            store_in_memory=False,
                            include_children=self.include_children
                        )
                        try:
                            metrics_json = tmp_monitor.sample_once()
                            if metrics_json is not None:
                                metrics = json.loads(metrics_json)
                                if self.store_in_memory:
                                    self.samples.append(metrics)
                                if self.output_file:
                                    with open(self.output_file, 'a') as f:
                                        f.write(metrics_json + '\n')
                        except Exception:
                            # Silently ignore monitoring errors
                            pass
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
        if not self.samples:
            return "{}"

        import json

        # Calculate elapsed time
        if len(self.samples) > 1:
            elapsed = (self.samples[-1]["ts_ms"] - self.samples[0]["ts_ms"]) / 1000.0
        else:
            elapsed = 0.0

        # Convert samples to JSON strings
        metrics_json = [json.dumps(sample) for sample in self.samples]

        # Use the existing summary generation logic
        try:
            from denet import generate_summary_from_metrics_json

            # If we have aggregated metrics with process counts, handle them specially
            if any("process_count" in json.loads(m) for m in metrics_json if json.loads(m).get("process_count", 0) > 1):
                # Calculate max processes from all aggregated metrics
                max_processes = max(
                    (json.loads(m).get("process_count", 1) for m in metrics_json if "process_count" in json.loads(m)),
                    default=1
                )

                # Get the summary from the Rust code
                summary_json = generate_summary_from_metrics_json(metrics_json, elapsed)
                summary = json.loads(summary_json)

                # Overwrite the max_processes field with our calculated value
                summary["max_processes"] = max_processes

                # Convert back to JSON
                return json.dumps(summary)
            else:
                return generate_summary_from_metrics_json(metrics_json, elapsed)
        except ImportError:
            # Fallback if the function is not available
            return json.dumps({
                "total_time_secs": elapsed,
                "sample_count": len(self.samples),
                "max_processes": 1,
                "max_threads": max(s.get('thread_count', 0) for s in self.samples) if self.samples else 0,
                "total_disk_read_bytes": self.samples[-1].get('disk_read_bytes', 0) if self.samples else 0,
                "total_disk_write_bytes": self.samples[-1].get('disk_write_bytes', 0) if self.samples else 0,
                "total_net_rx_bytes": self.samples[-1].get('net_rx_bytes', 0) if self.samples else 0,
                "total_net_tx_bytes": self.samples[-1].get('net_tx_bytes', 0) if self.samples else 0,
                "peak_mem_rss_kb": max(s.get('mem_rss_kb', 0) for s in self.samples) if self.samples else 0,
                "avg_cpu_usage": sum(s.get('cpu_usage', 0) for s in self.samples) / len(self.samples) if self.samples else 0.0
            })

    def clear_samples(self):
        self.samples = []

    def save_samples(self, path, format=None):
        if not self.samples:
            return

        format = format or "jsonl"
        import json

        with open(path, 'w') as f:
            if format == "json":
                # JSON array format
                json.dump(self.samples, f)
            elif format == "csv":
                # CSV format
                if self.samples:
                    # Write header
                    headers = list(self.samples[0].keys())
                    f.write(','.join(headers) + '\n')

                    # Write data rows
                    for sample in self.samples:
                        row = [str(sample.get(h, '')) for h in headers]
                        f.write(','.join(row) + '\n')
            else:
                # Default to JSONL
                for sample in self.samples:
                    f.write(json.dumps(sample) + '\n')

# Create and return an instance of the context manager
MonitorContextManager(base_interval_ms, max_interval_ms, output_file, output_format, store_in_memory, include_children)
