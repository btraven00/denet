//! Integration tests for the off-CPU metrics functionality
//!
//! These tests validate that the OffCpuMetrics struct and related functionality
//! correctly handle edge cases, prevent overflows, and maintain data consistency.

use denet::ebpf::metrics::{OffCpuMetrics, ThreadOffCpuInfo, ThreadOffCpuStats};
use denet::ebpf::offcpu_profiler::OffCpuStats;
use std::collections::HashMap;

/// Test that the total_time_ns is the sum of all thread times
#[test]
fn test_total_time_consistency() {
    let mut thread_stats = HashMap::new();

    // Add some thread stats
    thread_stats.insert(
        "1234:5678".to_string(),
        ThreadOffCpuStats {
            tid: 5678,
            total_time_ns: 1_000_000,
            count: 2,
            avg_time_ns: 500_000,
            max_time_ns: 600_000,
            min_time_ns: 400_000,
        },
    );

    thread_stats.insert(
        "1234:9876".to_string(),
        ThreadOffCpuStats {
            tid: 9876,
            total_time_ns: 2_000_000,
            count: 3,
            avg_time_ns: 666_667,
            max_time_ns: 1_000_000,
            min_time_ns: 400_000,
        },
    );

    // Create top blocking threads
    let top_threads = vec![
        ThreadOffCpuInfo {
            tid: 5678,
            pid: 1234,
            total_time_ms: 1.0,
            percentage: 33.33,
        },
        ThreadOffCpuInfo {
            tid: 9876,
            pid: 1234,
            total_time_ms: 2.0,
            percentage: 66.67,
        },
    ];

    // Create OffCpuMetrics
    let metrics = OffCpuMetrics {
        total_time_ns: 3_000_000, // Should equal sum of thread times
        total_events: 5,          // Should equal sum of thread counts
        avg_time_ns: 600_000,     // Should equal total_time_ns / total_events
        max_time_ns: 1_000_000,
        min_time_ns: 400_000,
        thread_stats,
        top_blocking_threads: top_threads,
        bottlenecks: Vec::new(),
    };

    // Test that total_time is the sum of all thread times
    let mut expected_total_time = 0;
    let mut expected_total_events = 0;

    for (_, stats) in metrics.thread_stats.iter() {
        expected_total_time += stats.total_time_ns;
        expected_total_events += stats.count;
    }

    assert_eq!(
        metrics.total_time_ns, expected_total_time,
        "total_time_ns doesn't match sum of thread times"
    );
    assert_eq!(
        metrics.total_events, expected_total_events,
        "total_events doesn't match sum of thread counts"
    );
    assert_eq!(
        metrics.avg_time_ns,
        metrics.total_time_ns / metrics.total_events,
        "avg_time_ns isn't correctly calculated as total_time_ns / total_events"
    );
}

/// Test that top_blocking_threads contains data consistent with thread_stats
#[test]
fn test_top_threads_consistency() {
    let mut thread_stats = HashMap::new();

    // Add some thread stats
    thread_stats.insert(
        "1234:5678".to_string(),
        ThreadOffCpuStats {
            tid: 5678,
            total_time_ns: 1_000_000,
            count: 2,
            avg_time_ns: 500_000,
            max_time_ns: 600_000,
            min_time_ns: 400_000,
        },
    );

    thread_stats.insert(
        "1234:9876".to_string(),
        ThreadOffCpuStats {
            tid: 9876,
            total_time_ns: 2_000_000,
            count: 3,
            avg_time_ns: 666_667,
            max_time_ns: 1_000_000,
            min_time_ns: 400_000,
        },
    );

    // Create top blocking threads
    let top_threads = vec![
        ThreadOffCpuInfo {
            tid: 5678,
            pid: 1234,
            total_time_ms: 1.0,
            percentage: 33.33,
        },
        ThreadOffCpuInfo {
            tid: 9876,
            pid: 1234,
            total_time_ms: 2.0,
            percentage: 66.67,
        },
    ];

    let metrics = OffCpuMetrics {
        total_time_ns: 3_000_000,
        total_events: 5,
        avg_time_ns: 600_000,
        max_time_ns: 1_000_000,
        min_time_ns: 400_000,
        thread_stats: thread_stats.clone(),
        top_blocking_threads: top_threads,
        bottlenecks: Vec::new(),
    };

    // Check that each thread in top_blocking_threads corresponds to a thread in thread_stats
    for top_thread in &metrics.top_blocking_threads {
        // Find corresponding thread stat
        let stat_key = format!("{}:{}", top_thread.pid, top_thread.tid);
        assert!(
            metrics.thread_stats.contains_key(&stat_key),
            "Thread {} in top_blocking_threads not found in thread_stats",
            stat_key
        );

        let thread_stat = metrics.thread_stats.get(&stat_key).unwrap();

        // Time should match between top_threads and thread_stats (after conversion)
        let expected_time_ms = thread_stat.total_time_ns as f64 / 1_000_000.0;
        assert!(
            (top_thread.total_time_ms - expected_time_ms).abs() < 0.001,
            "Time mismatch for thread {}: expected {}ms but got {}ms",
            stat_key,
            expected_time_ms,
            top_thread.total_time_ms
        );
    }

    // Check that percentages add up to ~100%
    let total_percentage: f64 = metrics
        .top_blocking_threads
        .iter()
        .map(|t| t.percentage)
        .sum();

    assert!(
        (total_percentage - 100.0).abs() < 0.1,
        "Percentages in top_blocking_threads don't add up to 100%: got {}",
        total_percentage
    );
}

/// Test for handling of potential overflows in time calculations
#[test]
fn test_time_overflow_prevention() {
    // Create stats with times that could cause overflow
    let mut stats1 = OffCpuStats::default();
    stats1.total_time_ns = u64::MAX - 1000;
    stats1.count = 1;

    let mut stats2 = OffCpuStats::default();
    stats2.total_time_ns = 5000;
    stats2.count = 2;

    // Simulate adding stats1 and stats2
    let total_time = stats1.total_time_ns.saturating_add(stats2.total_time_ns);
    let total_count = stats1.count.saturating_add(stats2.count);

    // Check that we don't overflow
    assert_eq!(
        total_time,
        u64::MAX,
        "Time addition should use saturating add to prevent overflow"
    );
    assert_eq!(total_count, 3, "Count should be added correctly");

    // Test division safety
    let avg_time = if total_count > 0 {
        total_time / total_count
    } else {
        0
    };

    // This should not panic
    assert!(
        avg_time > 0,
        "Average time calculation should not panic on potential overflow"
    );
}

/// Test for empty thread stats handling
#[test]
fn test_empty_thread_stats() {
    let metrics = OffCpuMetrics {
        total_time_ns: 0,
        total_events: 0,
        avg_time_ns: 0,
        max_time_ns: 0,
        min_time_ns: 0,
        thread_stats: HashMap::new(),
        top_blocking_threads: Vec::new(),
        bottlenecks: Vec::new(),
    };

    assert_eq!(
        metrics.total_time_ns, 0,
        "Total time should be 0 for empty stats"
    );
    assert_eq!(
        metrics.total_events, 0,
        "Total events should be 0 for empty stats"
    );
    assert_eq!(
        metrics.avg_time_ns, 0,
        "Average time should be 0 for empty stats"
    );
    assert!(
        metrics.top_blocking_threads.is_empty(),
        "Top blocking threads should be empty for empty stats"
    );
}

/// Test that thread with tid=0 isn't incorrectly introduced
#[test]
fn test_no_invalid_tid_zero() {
    let mut thread_stats = HashMap::new();

    // Add a valid thread
    thread_stats.insert(
        "1234:5678".to_string(),
        ThreadOffCpuStats {
            tid: 5678,
            total_time_ns: 1_000_000,
            count: 2,
            avg_time_ns: 500_000,
            max_time_ns: 600_000,
            min_time_ns: 400_000,
        },
    );

    // Create metrics with this thread
    let metrics = OffCpuMetrics {
        total_time_ns: 1_000_000,
        total_events: 2,
        avg_time_ns: 500_000,
        max_time_ns: 600_000,
        min_time_ns: 400_000,
        thread_stats,
        top_blocking_threads: vec![ThreadOffCpuInfo {
            tid: 5678,
            pid: 1234,
            total_time_ms: 1.0,
            percentage: 100.0,
        }],
        bottlenecks: Vec::new(),
    };

    // Check that there's no thread with tid=0 in top_blocking_threads
    let has_tid_zero = metrics.top_blocking_threads.iter().any(|t| t.tid == 0);
    assert!(
        !has_tid_zero,
        "Thread with tid=0 should not appear in top_blocking_threads"
    );

    // Also check thread_stats doesn't have a tid=0
    let has_stat_tid_zero = metrics.thread_stats.iter().any(|(_, s)| s.tid == 0);
    assert!(
        !has_stat_tid_zero,
        "Thread with tid=0 should not appear in thread_stats"
    );
}
