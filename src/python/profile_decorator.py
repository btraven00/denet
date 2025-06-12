def wrapper(*args, **kwargs):
    import os
    import time
    import functools
    import threading
    import json

    # Create monitoring process with settings
    monitor = None
    monitoring = True
    samples = []

    def monitoring_thread():
        nonlocal monitor, samples
        try:
            while monitoring:
                # Sample metrics from current process
                if os.name == 'posix':  # Unix-based systems
                    pid = os.getpid()
                    # Create a fresh monitor for each sample to avoid accumulation issues
                    tmp_monitor = ProcessMonitor.from_pid(
                        pid=pid,
                        base_interval_ms=base_interval_ms,
                        max_interval_ms=max_interval_ms,
                        output_file=None,  # We'll handle file output separately
                        store_in_memory=False
                    )
                    try:
                        metrics_json = tmp_monitor.sample_once()
                        if metrics_json is not None:
                            metrics = json.loads(metrics_json)
                            if store_in_memory:
                                samples.append(metrics)
                            if output_file:
                                with open(output_file, 'a') as f:
                                    f.write(metrics_json + '\n')
                    except Exception as e:
                        # Silently ignore monitoring errors
                        pass
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
        if not store_in_memory and output_file and os.path.exists(output_file):
            try:
                with open(output_file, 'r') as f:
                    samples = [json.loads(line) for line in f if line.strip()]
            except Exception:
                pass  # Ignore file read errors

    # Return original result and metrics
    return result, samples

# Return the wrapper function
wrapper = functools.wraps(func)(wrapper)
wrapper
