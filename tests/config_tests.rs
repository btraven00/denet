//! Tests for the configuration module in the denet crate

use denet::config::{
    DenetConfig, DenetConfigBuilder, MonitorConfig, MonitorConfigBuilder, OutputConfig,
    OutputConfigBuilder, OutputFormat,
};
use denet::error::DenetError;
use std::path::PathBuf;
use std::str::FromStr;
use std::time::Duration;

#[test]
fn test_output_format_from_str() {
    // Test valid format strings
    assert_eq!(OutputFormat::from_str("json").unwrap(), OutputFormat::Json);
    assert_eq!(
        OutputFormat::from_str("jsonl").unwrap(),
        OutputFormat::JsonLines
    );
    assert_eq!(
        OutputFormat::from_str("jsonlines").unwrap(),
        OutputFormat::JsonLines
    );
    assert_eq!(OutputFormat::from_str("csv").unwrap(), OutputFormat::Csv);

    // Test case insensitivity
    assert_eq!(OutputFormat::from_str("JSON").unwrap(), OutputFormat::Json);
    assert_eq!(
        OutputFormat::from_str("JSONL").unwrap(),
        OutputFormat::JsonLines
    );
    assert_eq!(OutputFormat::from_str("CSV").unwrap(), OutputFormat::Csv);

    // Test invalid format
    let result = OutputFormat::from_str("invalid");
    assert!(result.is_err());
    match result {
        Err(DenetError::InvalidConfiguration(msg)) => {
            assert!(msg.contains("Unknown output format"));
        }
        _ => panic!("Expected InvalidConfiguration error"),
    }
}

#[test]
fn test_output_format_display() {
    assert_eq!(OutputFormat::Json.to_string(), "json");
    assert_eq!(OutputFormat::JsonLines.to_string(), "jsonl");
    assert_eq!(OutputFormat::Csv.to_string(), "csv");
}

#[test]
fn test_monitor_config_defaults() {
    let config = MonitorConfig::default();
    assert_eq!(config.base_interval, Duration::from_millis(100));
    assert_eq!(config.max_interval, Duration::from_millis(1000));
    assert!(!config.since_process_start);
    assert!(config.include_children);
    assert!(config.max_duration.is_none());
    assert!(!config.enable_ebpf);
}

#[test]
fn test_monitor_config_validation() {
    // Valid config
    let valid_config = MonitorConfig {
        base_interval: Duration::from_millis(100),
        max_interval: Duration::from_millis(1000),
        ..MonitorConfig::default()
    };
    assert!(valid_config.validate().is_ok());

    // Invalid: base > max
    let invalid_config = MonitorConfig {
        base_interval: Duration::from_millis(1000),
        max_interval: Duration::from_millis(100),
        ..MonitorConfig::default()
    };
    let result = invalid_config.validate();
    assert!(result.is_err());
    match result {
        Err(DenetError::InvalidConfiguration(msg)) => {
            assert!(msg.contains("Base interval cannot be greater than max interval"));
        }
        _ => panic!("Expected InvalidConfiguration error"),
    }

    // Invalid: base is zero
    let invalid_config = MonitorConfig {
        base_interval: Duration::from_millis(0),
        ..MonitorConfig::default()
    };
    let result = invalid_config.validate();
    assert!(result.is_err());
    match result {
        Err(DenetError::InvalidConfiguration(msg)) => {
            assert!(msg.contains("Base interval cannot be zero"));
        }
        _ => panic!("Expected InvalidConfiguration error"),
    }
}

#[test]
fn test_monitor_config_builder() {
    // Test with all values specified
    let config = MonitorConfigBuilder::default()
        .base_interval(Duration::from_millis(200))
        .max_interval(Duration::from_millis(2000))
        .since_process_start(true)
        .include_children(false)
        .max_duration(Duration::from_secs(60))
        .enable_ebpf(true)
        .build()
        .unwrap();

    assert_eq!(config.base_interval, Duration::from_millis(200));
    assert_eq!(config.max_interval, Duration::from_millis(2000));
    assert!(config.since_process_start);
    assert!(!config.include_children);
    assert_eq!(config.max_duration, Some(Duration::from_secs(60)));
    assert!(config.enable_ebpf);

    // Test with millisecond-based methods
    let config = MonitorConfigBuilder::default()
        .base_interval_ms(300)
        .max_interval_ms(3000)
        .build()
        .unwrap();

    assert_eq!(config.base_interval, Duration::from_millis(300));
    assert_eq!(config.max_interval, Duration::from_millis(3000));

    // Test max_duration_secs
    let config = MonitorConfigBuilder::default()
        .max_duration_secs(120)
        .build()
        .unwrap();

    assert_eq!(config.max_duration, Some(Duration::from_secs(120)));

    // Test zero max_duration_secs (should not set)
    let config = MonitorConfigBuilder::default()
        .max_duration_secs(0)
        .build()
        .unwrap();

    assert_eq!(config.max_duration, None);

    // Test builder validation failure
    let result = MonitorConfigBuilder::default()
        .base_interval_ms(2000)
        .max_interval_ms(1000)
        .build();

    assert!(result.is_err());
}

#[test]
fn test_output_config_defaults() {
    let config = OutputConfig::default();
    assert_eq!(config.output_file, None);
    assert_eq!(config.format, OutputFormat::JsonLines);
    assert!(config.store_in_memory);
    assert!(!config.quiet);
    assert!(config.update_in_place);
    assert!(!config.write_metadata);
}

#[test]
fn test_output_config_builder() {
    // Test with all values specified
    let config = OutputConfigBuilder::default()
        .output_file(PathBuf::from("output.json"))
        .format(OutputFormat::Json)
        .store_in_memory(false)
        .quiet(true)
        .update_in_place(false)
        .write_metadata(true)
        .build();

    assert_eq!(config.output_file, Some(PathBuf::from("output.json")));
    assert_eq!(config.format, OutputFormat::Json);
    assert!(!config.store_in_memory);
    assert!(config.quiet);
    assert!(!config.update_in_place);
    assert!(config.write_metadata);

    // Test format_str method
    let result = OutputConfigBuilder::default().format_str("csv");

    assert!(result.is_ok());
    let config = result.unwrap().build();
    assert_eq!(config.format, OutputFormat::Csv);

    // Test format_str with invalid value
    let result = OutputConfigBuilder::default().format_str("invalid");

    assert!(result.is_err());
}

#[test]
fn test_output_config_builder_write_metadata() {
    let config = OutputConfigBuilder::default().write_metadata(true).build();
    assert!(config.write_metadata);

    let config = OutputConfigBuilder::default().write_metadata(false).build();
    assert!(!config.write_metadata);
}

#[test]
fn test_output_config_builder_write_metadata_default() {
    let config = OutputConfigBuilder::default().build();
    assert!(!config.write_metadata); // Should default to false
}

#[test]
fn test_denet_config_defaults() {
    let config = DenetConfig::default();
    assert_eq!(config.monitor.base_interval, Duration::from_millis(100));
    assert_eq!(config.output.format, OutputFormat::JsonLines);
}

#[test]
fn test_denet_config_builder() {
    let monitor_config = MonitorConfig {
        base_interval: Duration::from_millis(250),
        max_interval: Duration::from_millis(2500),
        ..MonitorConfig::default()
    };

    let output_config = OutputConfig {
        format: OutputFormat::Csv,
        quiet: true,
        ..OutputConfig::default()
    };

    let config = DenetConfigBuilder::default()
        .monitor(monitor_config.clone())
        .output(output_config.clone())
        .build();

    assert_eq!(config.monitor.base_interval, monitor_config.base_interval);
    assert_eq!(config.monitor.max_interval, monitor_config.max_interval);
    assert_eq!(config.output.format, output_config.format);
    assert_eq!(config.output.quiet, output_config.quiet);

    // Test with default values when not specified
    let config = DenetConfigBuilder::default()
        .monitor(monitor_config)
        .build();

    assert_eq!(config.monitor.base_interval, Duration::from_millis(250));
    assert_eq!(config.output.format, OutputFormat::JsonLines); // Default
}
