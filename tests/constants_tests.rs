//! Tests for the constants module in the denet crate

use denet::core::constants::{defaults, delays, sampling, system, timeouts};
use std::time::Duration;

#[test]
fn test_sampling_constants() {
    // Test that sampling intervals are ordered correctly
    assert!(sampling::FAST < sampling::STANDARD);
    assert!(sampling::STANDARD < sampling::SLOW);
    assert!(sampling::SLOW < sampling::VERY_SLOW);
    assert!(sampling::VERY_SLOW < sampling::MAX_ADAPTIVE);

    // Test specific values
    assert_eq!(sampling::FAST, Duration::from_millis(50));
    assert_eq!(sampling::STANDARD, Duration::from_millis(100));
    assert_eq!(sampling::SLOW, Duration::from_millis(200));
    assert_eq!(sampling::VERY_SLOW, Duration::from_millis(500));
    assert_eq!(sampling::MAX_ADAPTIVE, Duration::from_millis(1000));
}

#[test]
fn test_timeout_constants() {
    // Test that timeouts are ordered correctly
    assert!(timeouts::SHORT < timeouts::MEDIUM);
    assert!(timeouts::MEDIUM < timeouts::LONG);

    // Test specific values
    assert_eq!(timeouts::SHORT, Duration::from_secs(5));
    assert_eq!(timeouts::MEDIUM, Duration::from_secs(10));
    assert_eq!(timeouts::LONG, Duration::from_secs(30));
    assert_eq!(timeouts::TEST, Duration::from_secs(30));

    // Test timeout is same as long timeout
    assert_eq!(timeouts::TEST, timeouts::LONG);
}

#[test]
fn test_delay_constants() {
    // Test that delays are ordered correctly
    assert!(delays::MINIMAL < delays::SHORT);
    assert!(delays::SHORT < delays::STANDARD);
    assert!(delays::STANDARD < delays::STARTUP);
    assert!(delays::STARTUP <= delays::FINAL_SAMPLE);

    // Test specific values
    assert_eq!(delays::MINIMAL, Duration::from_millis(10));
    assert_eq!(delays::SHORT, Duration::from_millis(25));
    assert_eq!(delays::STANDARD, Duration::from_millis(50));
    assert_eq!(delays::STARTUP, Duration::from_millis(500));
    assert_eq!(delays::FINAL_SAMPLE, Duration::from_millis(500));
    assert_eq!(delays::CPU_MEASUREMENT, Duration::from_millis(100));
}

#[test]
fn test_system_constants() {
    // Test ordering where applicable
    assert!(system::PROCESS_DETECTION < system::SYSTEM_REFRESH);
    assert!(system::SYSTEM_REFRESH < system::EBPF_INIT);

    // Test specific values
    assert_eq!(system::PROCESS_DETECTION, Duration::from_millis(10));
    assert_eq!(system::SYSTEM_REFRESH, Duration::from_millis(100));
    assert_eq!(system::EBPF_INIT, Duration::from_secs(5));
}

#[test]
fn test_default_constants() {
    // Test that defaults match expected sampling values
    assert_eq!(defaults::BASE_INTERVAL, sampling::STANDARD);
    assert_eq!(defaults::MAX_INTERVAL, sampling::MAX_ADAPTIVE);

    // Test specific values
    assert_eq!(defaults::BASE_INTERVAL, Duration::from_millis(100));
    assert_eq!(defaults::MAX_INTERVAL, Duration::from_millis(1000));
    assert_eq!(defaults::TEST_READY_TIMEOUT, Duration::from_secs(5));

    // Test relationships
    assert!(defaults::BASE_INTERVAL < defaults::MAX_INTERVAL);
    assert_eq!(defaults::TEST_READY_TIMEOUT, timeouts::SHORT);
}

#[test]
fn test_constant_relationships() {
    // Test that sampling and delay constants have sensible relationships
    assert!(delays::STANDARD <= sampling::STANDARD);
    assert!(delays::CPU_MEASUREMENT <= sampling::STANDARD);
    assert!(system::SYSTEM_REFRESH <= sampling::STANDARD);

    // Test that timeouts are longer than delays
    assert!(timeouts::SHORT.as_millis() > delays::STARTUP.as_millis());
    assert!(timeouts::MEDIUM.as_millis() > delays::FINAL_SAMPLE.as_millis());

    // Test that defaults are within sampling range
    assert!(defaults::BASE_INTERVAL >= sampling::FAST);
    assert!(defaults::BASE_INTERVAL <= sampling::MAX_ADAPTIVE);
    assert!(defaults::MAX_INTERVAL <= sampling::MAX_ADAPTIVE);
}

#[test]
fn test_constants_non_zero() {
    // All constants should be non-zero
    assert!(!sampling::FAST.is_zero());
    assert!(!sampling::STANDARD.is_zero());
    assert!(!sampling::SLOW.is_zero());
    assert!(!sampling::VERY_SLOW.is_zero());
    assert!(!sampling::MAX_ADAPTIVE.is_zero());

    assert!(!timeouts::SHORT.is_zero());
    assert!(!timeouts::MEDIUM.is_zero());
    assert!(!timeouts::LONG.is_zero());
    assert!(!timeouts::TEST.is_zero());

    assert!(!delays::MINIMAL.is_zero());
    assert!(!delays::SHORT.is_zero());
    assert!(!delays::STANDARD.is_zero());
    assert!(!delays::STARTUP.is_zero());
    assert!(!delays::FINAL_SAMPLE.is_zero());
    assert!(!delays::CPU_MEASUREMENT.is_zero());

    assert!(!system::PROCESS_DETECTION.is_zero());
    assert!(!system::SYSTEM_REFRESH.is_zero());
    assert!(!system::EBPF_INIT.is_zero());

    assert!(!defaults::BASE_INTERVAL.is_zero());
    assert!(!defaults::MAX_INTERVAL.is_zero());
    assert!(!defaults::TEST_READY_TIMEOUT.is_zero());
}

#[test]
fn test_constants_reasonable_ranges() {
    // Test that constants are within reasonable ranges for monitoring

    // Sampling intervals should be between 10ms and 5 seconds
    let min_sampling = Duration::from_millis(10);
    let max_sampling = Duration::from_secs(5);

    assert!(sampling::FAST >= min_sampling && sampling::FAST <= max_sampling);
    assert!(sampling::STANDARD >= min_sampling && sampling::STANDARD <= max_sampling);
    assert!(sampling::SLOW >= min_sampling && sampling::SLOW <= max_sampling);
    assert!(sampling::VERY_SLOW >= min_sampling && sampling::VERY_SLOW <= max_sampling);
    assert!(sampling::MAX_ADAPTIVE >= min_sampling && sampling::MAX_ADAPTIVE <= max_sampling);

    // Timeouts should be between 1 and 300 seconds
    let min_timeout = Duration::from_secs(1);
    let max_timeout = Duration::from_secs(300);

    assert!(timeouts::SHORT >= min_timeout && timeouts::SHORT <= max_timeout);
    assert!(timeouts::MEDIUM >= min_timeout && timeouts::MEDIUM <= max_timeout);
    assert!(timeouts::LONG >= min_timeout && timeouts::LONG <= max_timeout);
    assert!(timeouts::TEST >= min_timeout && timeouts::TEST <= max_timeout);

    // Delays should be between 1ms and 10 seconds
    let min_delay = Duration::from_millis(1);
    let max_delay = Duration::from_secs(10);

    assert!(delays::MINIMAL >= min_delay && delays::MINIMAL <= max_delay);
    assert!(delays::SHORT >= min_delay && delays::SHORT <= max_delay);
    assert!(delays::STANDARD >= min_delay && delays::STANDARD <= max_delay);
    assert!(delays::STARTUP >= min_delay && delays::STARTUP <= max_delay);
    assert!(delays::FINAL_SAMPLE >= min_delay && delays::FINAL_SAMPLE <= max_delay);
    assert!(delays::CPU_MEASUREMENT >= min_delay && delays::CPU_MEASUREMENT <= max_delay);
}

#[test]
fn test_constants_for_adaptive_behavior() {
    // Test that constants support good adaptive monitoring behavior

    // Base should be fast enough for responsive monitoring
    assert!(defaults::BASE_INTERVAL <= Duration::from_millis(200));

    // Max should allow for reasonable resource usage under load
    assert!(defaults::MAX_INTERVAL >= Duration::from_millis(500));
    assert!(defaults::MAX_INTERVAL <= Duration::from_secs(2));

    // CPU measurement delay should be sufficient for accuracy
    assert!(delays::CPU_MEASUREMENT >= Duration::from_millis(50));
    assert!(delays::CPU_MEASUREMENT <= delays::STANDARD * 2);

    // Startup delay should give processes time to initialize
    assert!(delays::STARTUP >= Duration::from_millis(100));
    assert!(delays::STARTUP <= Duration::from_secs(1));
}
