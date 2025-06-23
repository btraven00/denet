//! Integration tests for the enhanced monitoring utilities
//!
//! These tests verify that the monitoring utilities work correctly
//! with real processes and provide proper integration coverage.

use denet::core::monitoring_utils::{
    monitor_for_test, monitor_until_completion, monitor_with_progress, MonitoringConfig,
    MonitoringLoop,
};
use denet::ProcessMonitor;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

/// Helper function to create a simple test process
fn create_test_process(duration_ms: u64) -> Vec<String> {
    let script = format!(
        "import time; time.sleep({}); print('test complete')",
        duration_ms as f64 / 1000.0
    );
    vec!["python".to_string(), "-c".to_string(), script]
}

/// Helper function to create a CPU-intensive test process
fn create_cpu_intensive_process(duration_ms: u64) -> Vec<String> {
    let script = format!(
        r#"
import time
import threading
end_time = time.time() + {}
def cpu_work():
    while time.time() < end_time:
        sum(range(1000))

for _ in range(2):
    threading.Thread(target=cpu_work).start()

time.sleep({})
"#,
        duration_ms as f64 / 1000.0,
        duration_ms as f64 / 1000.0
    );
    vec!["python".to_string(), "-c".to_string(), script]
}

#[test]
fn test_monitoring_loop_basic_functionality() {
    let cmd = create_test_process(200);
    let monitor = ProcessMonitor::new(cmd, Duration::from_millis(50), Duration::from_millis(1000))
        .expect("Failed to create monitor");

    let config = MonitoringConfig::new()
        .with_sample_interval(Duration::from_millis(50))
        .with_timeout(Duration::from_secs(5));

    let loop_monitor = MonitoringLoop::with_config(config);
    let result = loop_monitor.run(monitor);

    assert!(result.has_samples());
    assert!(result.sample_count() > 0);
    assert!(!result.timed_out);
    assert!(!result.interrupted);
    assert!(result.duration < Duration::from_secs(5));
}

#[test]
fn test_monitoring_loop_with_timeout() {
    let cmd = create_test_process(1000); // 1 second process
    let monitor = ProcessMonitor::new(cmd, Duration::from_millis(50), Duration::from_millis(1000))
        .expect("Failed to create monitor");

    let config = MonitoringConfig::new()
        .with_sample_interval(Duration::from_millis(50))
        .with_timeout(Duration::from_millis(200)); // Timeout before process completes

    let loop_monitor = MonitoringLoop::with_config(config);
    let result = loop_monitor.run(monitor);

    assert!(result.timed_out);
    assert!(!result.interrupted);
    assert!(result.duration >= Duration::from_millis(200));
}

#[test]
fn test_monitoring_loop_with_interrupt() {
    let cmd = create_test_process(1000); // 1 second process
    let monitor = ProcessMonitor::new(cmd, Duration::from_millis(50), Duration::from_millis(1000))
        .expect("Failed to create monitor");

    let interrupt_signal = Arc::new(AtomicBool::new(true));
    let interrupt_clone = interrupt_signal.clone();

    let config = MonitoringConfig::new().with_sample_interval(Duration::from_millis(50));

    let loop_monitor = MonitoringLoop::with_config(config).with_interrupt_signal(interrupt_signal);

    // Set up interrupt after a delay
    std::thread::spawn(move || {
        std::thread::sleep(Duration::from_millis(100));
        interrupt_clone.store(false, Ordering::SeqCst);
    });

    let result = loop_monitor.run(monitor);

    assert!(result.interrupted);
    assert!(!result.timed_out);
    assert!(result.duration >= Duration::from_millis(100));
    assert!(result.duration < Duration::from_millis(500));
}

#[test]
fn test_monitoring_loop_with_final_samples() {
    let cmd = create_test_process(200);
    let monitor = ProcessMonitor::new(cmd, Duration::from_millis(50), Duration::from_millis(1000))
        .expect("Failed to create monitor");

    let config = MonitoringConfig::new()
        .with_sample_interval(Duration::from_millis(50))
        .with_final_samples(3, Duration::from_millis(25));

    let loop_monitor = MonitoringLoop::with_config(config);
    let result = loop_monitor.run(monitor);

    assert!(result.has_samples());
    assert!(result.sample_count() >= 3); // Should have at least the final samples
    assert!(!result.timed_out);
    assert!(!result.interrupted);
}

#[test]
fn test_monitoring_loop_with_processor() {
    let cmd = create_test_process(200);
    let monitor = ProcessMonitor::new(cmd, Duration::from_millis(50), Duration::from_millis(1000))
        .expect("Failed to create monitor");

    let config = MonitoringConfig::new().with_sample_interval(Duration::from_millis(50));
    let loop_monitor = MonitoringLoop::with_config(config);

    let processed_count = Arc::new(std::sync::atomic::AtomicUsize::new(0));
    let processed_count_clone = processed_count.clone();

    let result = loop_monitor.run_with_processor(monitor, |_metrics| {
        processed_count_clone.fetch_add(1, Ordering::SeqCst);
    });

    assert!(result.has_samples());
    assert_eq!(
        result.sample_count(),
        processed_count.load(Ordering::SeqCst)
    );
}

#[test]
fn test_monitoring_loop_with_progress() {
    let cmd = create_test_process(200);
    let monitor = ProcessMonitor::new(cmd, Duration::from_millis(50), Duration::from_millis(1000))
        .expect("Failed to create monitor");

    let config = MonitoringConfig::new().with_sample_interval(Duration::from_millis(50));
    let loop_monitor = MonitoringLoop::with_config(config);

    let progress_calls = Arc::new(std::sync::atomic::AtomicUsize::new(0));
    let progress_calls_clone = progress_calls.clone();

    let result = loop_monitor.run_with_progress(monitor, |count, _metrics| {
        progress_calls_clone.fetch_add(1, Ordering::SeqCst);
        assert!(count > 0);
    });

    assert!(result.has_samples());
    assert_eq!(result.sample_count(), progress_calls.load(Ordering::SeqCst));
}

#[test]
fn test_convenience_function_monitor_until_completion() {
    let cmd = create_test_process(200);
    let monitor = ProcessMonitor::new(cmd, Duration::from_millis(50), Duration::from_millis(1000))
        .expect("Failed to create monitor");

    let result = monitor_until_completion(
        monitor,
        Duration::from_millis(50),
        Some(Duration::from_secs(5)),
    );

    assert!(result.has_samples());
    assert!(!result.timed_out);
    assert!(!result.interrupted);
}

#[test]
fn test_convenience_function_monitor_for_test() {
    let cmd = create_test_process(200);
    let monitor = ProcessMonitor::new(cmd, Duration::from_millis(50), Duration::from_millis(1000))
        .expect("Failed to create monitor");

    let result = monitor_for_test(monitor);

    assert!(result.has_samples());
    assert!(!result.timed_out);
    assert!(!result.interrupted);
}

#[test]
fn test_convenience_function_monitor_with_progress() {
    let cmd = create_test_process(200);
    let monitor = ProcessMonitor::new(cmd, Duration::from_millis(50), Duration::from_millis(1000))
        .expect("Failed to create monitor");

    let progress_calls = Arc::new(std::sync::atomic::AtomicUsize::new(0));
    let progress_calls_clone = progress_calls.clone();

    let result = monitor_with_progress(monitor, Duration::from_millis(50), |count, _metrics| {
        progress_calls_clone.fetch_add(1, Ordering::SeqCst);
        assert!(count > 0);
    });

    assert!(result.has_samples());
    assert_eq!(result.sample_count(), progress_calls.load(Ordering::SeqCst));
}

#[test]
fn test_monitoring_result_edge_cases() {
    let cmd = create_test_process(100);
    let monitor = ProcessMonitor::new(cmd, Duration::from_millis(10), Duration::from_millis(1000))
        .expect("Failed to create monitor");

    // Test with very fast sampling
    let config = MonitoringConfig::new().with_sample_interval(Duration::from_millis(10));

    let loop_monitor = MonitoringLoop::with_config(config);
    let result = loop_monitor.run(monitor);

    assert!(result.has_samples());
    assert!(result.sample_count() >= 1); // Should have at least some samples

    // Test first and last sample access
    let first = result.first_sample().unwrap();
    let last = result.last_sample().unwrap();
    assert!(first.ts_ms <= last.ts_ms);
}

#[test]
fn test_monitoring_with_cpu_intensive_process() {
    let cmd = create_cpu_intensive_process(300);
    let monitor = ProcessMonitor::new(cmd, Duration::from_millis(50), Duration::from_millis(1000))
        .expect("Failed to create monitor");

    let config = MonitoringConfig::new()
        .with_sample_interval(Duration::from_millis(50))
        .with_timeout(Duration::from_secs(5));

    let loop_monitor = MonitoringLoop::with_config(config);
    let result = loop_monitor.run(monitor);

    assert!(result.has_samples());
    assert!(!result.timed_out);

    // Should capture some CPU usage
    let has_cpu_usage = result.samples.iter().any(|sample| sample.cpu_usage > 0.0);
    assert!(has_cpu_usage, "Should capture some CPU usage");
}

#[test]
fn test_monitoring_config_presets_behavior() {
    let cmd = create_test_process(200);
    let monitor = ProcessMonitor::new(cmd, Duration::from_millis(50), Duration::from_millis(1000))
        .expect("Failed to create monitor");

    // Test fast sampling preset
    let fast_config = MonitoringConfig::fast_sampling();
    let loop_monitor = MonitoringLoop::with_config(fast_config);
    let result = loop_monitor.run(monitor);

    assert!(result.has_samples());
    assert!(result.sample_count() >= 1); // Should have at least one sample
    assert!(!result.timed_out);
}

#[test]
fn test_monitoring_config_for_tests_behavior() {
    let cmd = create_test_process(200);
    let monitor = ProcessMonitor::new(cmd, Duration::from_millis(50), Duration::from_millis(1000))
        .expect("Failed to create monitor");

    // Test configuration specifically designed for tests
    let test_config = MonitoringConfig::for_tests();
    let loop_monitor = MonitoringLoop::with_config(test_config);
    let result = loop_monitor.run(monitor);

    assert!(result.has_samples());
    assert!(!result.timed_out); // Should complete before timeout
    assert!(!result.interrupted);
}

#[test]
fn test_monitoring_duration_tracking() {
    let cmd = create_test_process(200);
    let monitor = ProcessMonitor::new(cmd, Duration::from_millis(50), Duration::from_millis(1000))
        .expect("Failed to create monitor");

    let config = MonitoringConfig::new().with_sample_interval(Duration::from_millis(50));
    let loop_monitor = MonitoringLoop::with_config(config);

    let start_time = Instant::now();
    let result = loop_monitor.run(monitor);
    let actual_duration = start_time.elapsed();

    // Result duration should be close to actual duration
    let duration_diff = if result.duration > actual_duration {
        result.duration - actual_duration
    } else {
        actual_duration - result.duration
    };

    assert!(duration_diff < Duration::from_millis(100)); // Should be within 100ms
}

#[test]
fn test_monitoring_with_no_samples() {
    // Test behavior when process exits immediately
    let cmd = vec!["python".to_string(), "-c".to_string(), "pass".to_string()]; // Immediate exit

    let monitor = ProcessMonitor::new(cmd, Duration::from_millis(100), Duration::from_millis(1000))
        .expect("Failed to create monitor");

    let config = MonitoringConfig::new().with_sample_interval(Duration::from_millis(100));
    let loop_monitor = MonitoringLoop::with_config(config);
    let result = loop_monitor.run(monitor);

    // Process may exit before we can sample, but that's OK
    assert!(!result.timed_out);
    assert!(!result.interrupted);
    assert!(result.duration < Duration::from_secs(1));
}

#[test]
fn test_monitoring_result_sample_access() {
    let cmd = create_test_process(200);
    let monitor = ProcessMonitor::new(cmd, Duration::from_millis(50), Duration::from_millis(1000))
        .expect("Failed to create monitor");

    let config = MonitoringConfig::new().with_sample_interval(Duration::from_millis(50));
    let loop_monitor = MonitoringLoop::with_config(config);
    let result = loop_monitor.run(monitor);

    if result.has_samples() {
        let first = result.first_sample().unwrap();
        let last = result.last_sample().unwrap();

        // Basic sanity checks on the metrics
        assert!(first.ts_ms > 0);
        assert!(last.ts_ms > 0);
        assert!(first.ts_ms <= last.ts_ms);
        // Basic sanity checks on memory values (they should be valid)
        assert!(first.mem_rss_kb < u64::MAX);
        assert!(last.mem_rss_kb < u64::MAX);
    }
}
