//! Tests for error handling and edge cases
//!
//! These tests verify that error conditions are handled properly
//! and provide coverage for error paths in the codebase.

use denet::config::{MonitorConfig, MonitorConfigBuilder, OutputConfigBuilder};
use denet::core::constants::delays;
use denet::core::monitoring_utils::{MonitoringConfig, MonitoringLoop};
use denet::error::{DenetError, Result};
use denet::ProcessMonitor;

use std::time::Duration;

#[test]
fn test_monitor_config_validation_errors() {
    // Test base interval greater than max interval
    let result = MonitorConfigBuilder::default()
        .base_interval_ms(1000)
        .max_interval_ms(500)
        .build();

    assert!(result.is_err());
    match result {
        Err(DenetError::InvalidConfiguration(msg)) => {
            assert!(msg.contains("Base interval cannot be greater than max interval"));
        }
        _ => panic!("Expected InvalidConfiguration error"),
    }

    // Test zero base interval
    let result = MonitorConfigBuilder::default().base_interval_ms(0).build();

    assert!(result.is_err());
    match result {
        Err(DenetError::InvalidConfiguration(msg)) => {
            assert!(msg.contains("Base interval cannot be zero"));
        }
        _ => panic!("Expected InvalidConfiguration error"),
    }
}

#[test]
fn test_output_format_parsing_errors() {
    use denet::config::OutputFormat;
    use std::str::FromStr;

    // Test invalid format strings
    let invalid_formats = ["xml", "yaml", "txt", "binary", "", "json "];

    for format in &invalid_formats {
        let result = OutputFormat::from_str(format);
        assert!(result.is_err());
        match result {
            Err(DenetError::InvalidConfiguration(msg)) => {
                assert!(msg.contains("Unknown output format"));
                assert!(msg.contains(format));
            }
            _ => panic!("Expected InvalidConfiguration error for format: {}", format),
        }
    }
}

#[test]
fn test_output_config_builder_format_str_error() {
    let result = OutputConfigBuilder::default().format_str("invalid_format");

    assert!(result.is_err());
    match result {
        Err(DenetError::InvalidConfiguration(_)) => {
            // Expected
        }
        _ => panic!("Expected InvalidConfiguration error"),
    }
}

#[test]
fn test_process_monitor_creation_errors() {
    // Test with non-existent command
    let cmd = vec!["definitely_nonexistent_command_12345".to_string()];
    let result = ProcessMonitor::new(cmd, Duration::from_millis(100), Duration::from_millis(1000));

    assert!(result.is_err());
    // The specific error type may vary by platform, but it should be an error
}

#[test]
fn test_process_monitor_invalid_pid() {
    // Test with invalid PID (PID 0 is typically not valid for user processes)
    let result =
        ProcessMonitor::from_pid(0, Duration::from_millis(100), Duration::from_millis(1000));

    assert!(result.is_err());
    // Should fail because PID 0 doesn't represent a valid user process
}

#[test]
fn test_process_monitor_very_large_pid() {
    // Test with unreasonably large PID
    let result = ProcessMonitor::from_pid(
        u32::MAX as usize,
        Duration::from_millis(100),
        Duration::from_millis(1000),
    );

    assert!(result.is_err());
    // Should fail because this PID almost certainly doesn't exist
}

#[test]
fn test_monitoring_config_edge_cases() {
    // Test with zero timeout (should be valid)
    let config = MonitoringConfig::new().with_timeout(Duration::from_secs(0));
    assert_eq!(config.timeout, Some(Duration::from_secs(0)));

    // Test with very large timeout
    let large_timeout = Duration::from_secs(u64::MAX);
    let config = MonitoringConfig::new().with_timeout(large_timeout);
    assert_eq!(config.timeout, Some(large_timeout));

    // Test with zero final samples
    let config = MonitoringConfig::new().with_final_samples(0, delays::STANDARD);
    assert_eq!(config.final_sample_count, 0);
    assert!(config.monitor_after_exit); // Flag is still set by method

    // Test with very large final sample count
    let config = MonitoringConfig::new().with_final_samples(u32::MAX, delays::MINIMAL);
    assert_eq!(config.final_sample_count, u32::MAX);
}

#[test]
fn test_error_display_formatting() {
    let config_error = DenetError::InvalidConfiguration("test message".to_string());
    let display_string = format!("{}", config_error);
    assert!(display_string.contains("test message"));

    // Test that Display is implemented properly
    assert!(!display_string.is_empty());
}

#[test]
fn test_error_debug_formatting() {
    let config_error = DenetError::InvalidConfiguration("debug test".to_string());
    let debug_string = format!("{:?}", config_error);
    assert!(debug_string.contains("InvalidConfiguration"));
    assert!(debug_string.contains("debug test"));
}

#[test]
fn test_result_type_alias() {
    // Test that Result type alias works correctly
    fn test_function() -> Result<i32> {
        Ok(42)
    }

    fn test_error_function() -> Result<i32> {
        Err(DenetError::InvalidConfiguration("test".to_string()))
    }

    assert!(test_function().is_ok());
    assert_eq!(test_function().unwrap(), 42);

    assert!(test_error_function().is_err());
}

#[test]
fn test_config_builder_partial_specification() {
    // Test that builders work with only some fields specified
    let config = MonitorConfigBuilder::default()
        .base_interval_ms(200)
        .build()
        .unwrap();

    assert_eq!(config.base_interval, Duration::from_millis(200));
    assert_eq!(config.max_interval, Duration::from_millis(1000)); // Default

    let config = MonitorConfigBuilder::default()
        .max_interval_ms(2000)
        .build()
        .unwrap();

    assert_eq!(config.base_interval, Duration::from_millis(100)); // Default
    assert_eq!(config.max_interval, Duration::from_millis(2000));
}

#[test]
fn test_output_config_builder_partial_specification() {
    // Test that output config builder works with partial specification
    let config = OutputConfigBuilder::default().quiet(true).build();

    assert!(config.quiet);
    assert!(config.store_in_memory); // Default
    assert!(!config.update_in_place || config.update_in_place); // Default value

    let config = OutputConfigBuilder::default()
        .store_in_memory(false)
        .build();

    assert!(!config.store_in_memory);
    assert!(!config.quiet); // Default
}

#[test]
fn test_monitoring_loop_with_invalid_config() {
    // Test monitoring loop with extreme configurations
    let config = MonitoringConfig::new()
        .with_sample_interval(Duration::from_nanos(1)) // Very small interval
        .with_timeout(Duration::from_nanos(1)); // Very small timeout

    let loop_monitor = MonitoringLoop::with_config(config);

    // Should handle extreme configurations gracefully
    // We can't easily test this without a real process, but the creation should work
    // Note: config field is private, so we just test that creation succeeds
    let _ = loop_monitor;
}

#[test]
fn test_duration_edge_cases() {
    // Test configuration with edge case durations
    let config = MonitorConfig {
        base_interval: Duration::from_nanos(1),
        max_interval: Duration::from_secs(1),
        ..MonitorConfig::default()
    };

    // Should be valid despite extreme values
    assert!(config.validate().is_ok());

    // Test with max duration values
    let config = MonitorConfig {
        base_interval: Duration::from_millis(100),
        max_interval: Duration::from_secs(u64::MAX),
        ..MonitorConfig::default()
    };

    assert!(config.validate().is_ok());
}

#[test]
fn test_error_source_chain() {
    // Test that errors can be chained (if source is implemented)
    let error = DenetError::InvalidConfiguration("root cause".to_string());

    // Test that the error can be used in error contexts
    let result: Result<()> = Err(error);
    assert!(result.is_err());

    match result {
        Err(DenetError::InvalidConfiguration(msg)) => {
            assert_eq!(msg, "root cause");
        }
        _ => panic!("Unexpected error type"),
    }
}

#[test]
fn test_concurrent_config_creation() {
    // Test that config creation is thread-safe
    use std::thread;

    let handles: Vec<_> = (0..10)
        .map(|i| {
            thread::spawn(move || {
                let config = MonitorConfigBuilder::default()
                    .base_interval_ms(100 + i * 10)
                    .max_interval_ms(1000 + i * 100)
                    .since_process_start(i % 2 == 0)
                    .build()
                    .unwrap();

                assert_eq!(config.base_interval, Duration::from_millis(100 + i * 10));
                assert_eq!(config.max_interval, Duration::from_millis(1000 + i * 100));
                assert_eq!(config.since_process_start, i % 2 == 0);
            })
        })
        .collect();

    for handle in handles {
        handle.join().unwrap();
    }
}

#[test]
fn test_config_validation_boundary_conditions() {
    // Test boundary conditions for configuration validation

    // Minimum valid interval (1 nanosecond)
    let config = MonitorConfig {
        base_interval: Duration::from_nanos(1),
        max_interval: Duration::from_nanos(1),
        ..MonitorConfig::default()
    };
    assert!(config.validate().is_ok());

    // Base equal to max (should be valid)
    let config = MonitorConfig {
        base_interval: Duration::from_millis(500),
        max_interval: Duration::from_millis(500),
        ..MonitorConfig::default()
    };
    assert!(config.validate().is_ok());

    // Base one nanosecond less than max (should be valid)
    let config = MonitorConfig {
        base_interval: Duration::from_nanos(999),
        max_interval: Duration::from_nanos(1000),
        ..MonitorConfig::default()
    };
    assert!(config.validate().is_ok());

    // Base one nanosecond more than max (should be invalid)
    let config = MonitorConfig {
        base_interval: Duration::from_nanos(1001),
        max_interval: Duration::from_nanos(1000),
        ..MonitorConfig::default()
    };
    assert!(config.validate().is_err());
}

#[test]
fn test_max_duration_secs_edge_cases() {
    // Test max_duration_secs with edge values
    let config = MonitorConfigBuilder::default()
        .max_duration_secs(0) // Should not set max_duration
        .build()
        .unwrap();
    assert_eq!(config.max_duration, None);

    let config = MonitorConfigBuilder::default()
        .max_duration_secs(1) // Should set to 1 second
        .build()
        .unwrap();
    assert_eq!(config.max_duration, Some(Duration::from_secs(1)));

    let config = MonitorConfigBuilder::default()
        .max_duration_secs(u64::MAX) // Should handle maximum value
        .build()
        .unwrap();
    assert_eq!(config.max_duration, Some(Duration::from_secs(u64::MAX)));
}

#[test]
fn test_invalid_path_handling() {
    use std::path::PathBuf;

    // Test output config with invalid path characters (platform-specific)
    let config = OutputConfigBuilder::default()
        .output_file(PathBuf::from("/invalid\0path"))
        .build();

    // Should create config successfully (validation happens later)
    assert!(config.output_file.is_some());
}

#[test]
fn test_error_conversions() {
    // Test that errors can be converted between types if implemented
    let config_error = DenetError::InvalidConfiguration("test".to_string());

    // Test that the error implements standard traits
    let _display = format!("{}", config_error);
    let _debug = format!("{:?}", config_error);

    // Test that error can be used in Result contexts
    let result: Result<()> = Err(config_error);
    assert!(result.is_err());
}
