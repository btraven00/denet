#!/usr/bin/env python3
"""Integration tests for adaptive sampling functionality."""

import json
import denet


def test_adaptive_sampling_intervals():
    """Test that sampling intervals adapt over time as expected."""
    # Run a process for 3 seconds to test adaptive sampling
    monitor = denet.ProcessMonitor(
        cmd=["python", "-c", "import time; time.sleep(3)"],
        base_interval_ms=100,  # Start at 100ms
        max_interval_ms=1000,  # Max at 1s
        store_in_memory=True,
    )

    monitor.run()
    samples = monitor.get_samples()

    # Parse samples and calculate intervals
    timestamps = []
    for sample in samples:
        sample_data = json.loads(sample)
        timestamps.append(sample_data["ts_ms"])

    # Calculate intervals between samples
    intervals = []
    for i in range(1, len(timestamps)):
        intervals.append(timestamps[i] - timestamps[i - 1])

    # Verify we have enough samples
    assert len(intervals) >= 5, f"Expected at least 5 intervals, got {len(intervals)}"

    # Check intervals in different time periods
    # First second should have short intervals (base_interval + sampling overhead ~120ms)
    early_intervals = intervals[:5] if len(intervals) >= 5 else intervals
    avg_early = sum(early_intervals) / len(early_intervals)
    assert avg_early < 300, f"Early intervals should be < 300ms (base + overhead), got avg {avg_early:.0f}ms"

    # Later intervals should be longer
    if len(intervals) >= 10:
        late_intervals = intervals[-3:]
        avg_late = sum(late_intervals) / len(late_intervals)
        assert avg_late > avg_early * 1.5, (
            f"Late intervals ({avg_late:.0f}ms) should be > 1.5x early intervals ({avg_early:.0f}ms)"
        )


def test_adaptive_sampling_with_short_process():
    """Test adaptive sampling with a very short process."""
    # Process that runs for only 1 second (increased from 0.5s for sysinfo v0.35.2 compatibility)
    monitor = denet.ProcessMonitor(
        cmd=["python", "-c", "import time; time.sleep(1.0)"],
        base_interval_ms=25,  # Very fast initial sampling
        max_interval_ms=1000,
        store_in_memory=True,
    )

    monitor.run()
    samples = monitor.get_samples()

    # With a 1.0 second process and 25ms base interval, we should get several samples
    assert len(samples) >= 3, f"Expected at least 3 samples for 1.0s process, got {len(samples)}"

    # All intervals should be close to base_interval since process is short
    timestamps = [json.loads(s)["ts_ms"] for s in samples]
    intervals = [timestamps[i] - timestamps[i - 1] for i in range(1, len(timestamps))]

    if intervals:
        max_interval = max(intervals)
        # For a 1.0s process, intervals shouldn't have time to grow much (base + overhead)
        assert max_interval < 400, f"Max interval should be < 400ms for short process, got {max_interval}ms"


def test_adaptive_sampling_custom_parameters():
    """Test adaptive sampling with custom base and max intervals."""
    # Test with larger base and max intervals
    monitor = denet.ProcessMonitor(
        cmd=["python", "-c", "import time; time.sleep(2.5)"],
        base_interval_ms=200,  # Start at 200ms
        max_interval_ms=800,  # Max at 800ms
        store_in_memory=True,
    )

    monitor.run()
    samples = monitor.get_samples()

    timestamps = [json.loads(s)["ts_ms"] for s in samples]
    intervals = [timestamps[i] - timestamps[i - 1] for i in range(1, len(timestamps))]

    if intervals:
        min_interval = min(intervals)
        max_interval = max(intervals)

        # Verify intervals respect the configured bounds (accounting for sampling overhead)
        assert min_interval >= 150, f"Min interval should be >= 150ms (allowing some variance), got {min_interval}ms"
        assert max_interval <= 1000, f"Max interval should be <= 1000ms (allowing some variance), got {max_interval}ms"


def test_adaptive_sampling_transition():
    """Test the transition periods in adaptive sampling."""
    # Run for exactly 2.5 seconds to test the transition
    monitor = denet.ProcessMonitor(
        cmd=["python", "-c", "import time; time.sleep(2.5)"],
        base_interval_ms=100,
        max_interval_ms=500,
        store_in_memory=True,
    )

    monitor.run()
    samples = monitor.get_samples()

    # Group samples by elapsed time
    start_ts = json.loads(samples[0])["ts_ms"]

    first_second = []
    transition_period = []  # 1-2 seconds

    for sample in samples:
        sample_data = json.loads(sample)
        elapsed_ms = sample_data["ts_ms"] - start_ts

        if elapsed_ms < 1000:
            first_second.append(sample_data)
        elif elapsed_ms < 2000:
            transition_period.append(sample_data)

    # Verify we have samples in each period
    assert len(first_second) >= 5, f"Expected multiple samples in first second, got {len(first_second)}"
    assert len(transition_period) >= 2, f"Expected samples in transition period, got {len(transition_period)}"

    # Calculate average intervals for each period
    def calc_avg_interval(sample_list):
        if len(sample_list) < 2:
            return None
        intervals = []
        for i in range(1, len(sample_list)):
            intervals.append(sample_list[i]["ts_ms"] - sample_list[i - 1]["ts_ms"])
        return sum(intervals) / len(intervals) if intervals else None

    avg_first = calc_avg_interval(first_second)
    avg_transition = calc_avg_interval(transition_period)

    # Transition period should have longer intervals than first second
    if avg_first and avg_transition:
        assert avg_transition > avg_first, (
            f"Transition period intervals ({avg_transition:.0f}ms) should be > first second ({avg_first:.0f}ms)"
        )


if __name__ == "__main__":
    # Allow running tests directly
    test_adaptive_sampling_intervals()
    print("✓ Adaptive sampling intervals test passed")

    test_adaptive_sampling_with_short_process()
    print("✓ Short process adaptive sampling test passed")

    test_adaptive_sampling_custom_parameters()
    print("✓ Custom parameters test passed")

    test_adaptive_sampling_transition()
    print("✓ Sampling transition test passed")

    print("\nAll adaptive sampling tests passed!")
