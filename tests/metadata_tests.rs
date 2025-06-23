//! Integration tests for write_metadata functionality
//!
//! These tests verify that the write_metadata feature works correctly
//! by testing the core functionality without going through Python bindings.

use denet::config::OutputConfigBuilder;
use denet::monitor::metrics::ProcessMetadata;
use std::time::{SystemTime, UNIX_EPOCH};
use tempfile::NamedTempFile;

#[test]
fn test_write_metadata_enabled() {
    let temp_file = NamedTempFile::new().unwrap();
    let temp_path = temp_file.path().to_path_buf();

    // Create output config with write_metadata enabled
    let output_config = OutputConfigBuilder::default()
        .output_file(temp_path.clone())
        .write_metadata(true)
        .build();

    assert!(output_config.write_metadata);
    assert_eq!(output_config.output_file, Some(temp_path));
}

#[test]
fn test_write_metadata_disabled_by_default() {
    let output_config = OutputConfigBuilder::default().build();
    assert!(!output_config.write_metadata);
}

#[test]
fn test_write_metadata_builder_chaining() {
    let temp_file = NamedTempFile::new().unwrap();
    let temp_path = temp_file.path().to_path_buf();

    let output_config = OutputConfigBuilder::default()
        .output_file(temp_path.clone())
        .write_metadata(true)
        .store_in_memory(false)
        .quiet(true)
        .build();

    assert!(output_config.write_metadata);
    assert!(!output_config.store_in_memory);
    assert!(output_config.quiet);
    assert_eq!(output_config.output_file, Some(temp_path));
}

#[test]
fn test_process_metadata_creation() {
    let cmd = vec!["sleep".to_string(), "1".to_string()];
    let executable = "/bin/sleep".to_string();
    let pid = 12345;
    let t0_ms = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_millis() as u64;

    let metadata = ProcessMetadata {
        pid,
        cmd: cmd.clone(),
        executable: executable.clone(),
        t0_ms,
    };

    assert_eq!(metadata.pid, pid);
    assert_eq!(metadata.cmd, cmd);
    assert_eq!(metadata.executable, executable);
    assert_eq!(metadata.t0_ms, t0_ms);
}

#[test]
fn test_process_metadata_serialization() {
    let metadata = ProcessMetadata {
        pid: 12345,
        cmd: vec!["python".to_string(), "script.py".to_string()],
        executable: "/usr/bin/python".to_string(),
        t0_ms: 1625184000000,
    };

    let json = serde_json::to_string(&metadata).unwrap();
    assert!(json.contains("\"pid\":12345"));
    assert!(json.contains("\"cmd\":[\"python\",\"script.py\"]"));
    assert!(json.contains("\"executable\":\"/usr/bin/python\""));
    assert!(json.contains("\"t0_ms\":1625184000000"));

    // Test deserialization
    let deserialized: ProcessMetadata = serde_json::from_str(&json).unwrap();
    assert_eq!(deserialized.pid, metadata.pid);
    assert_eq!(deserialized.cmd, metadata.cmd);
    assert_eq!(deserialized.executable, metadata.executable);
    assert_eq!(deserialized.t0_ms, metadata.t0_ms);
}

#[test]
fn test_output_config_with_metadata_various_formats() {
    use denet::config::OutputFormat;

    // Test with JSON format
    let config = OutputConfigBuilder::default()
        .format(OutputFormat::Json)
        .write_metadata(true)
        .build();

    assert_eq!(config.format, OutputFormat::Json);
    assert!(config.write_metadata);

    // Test with CSV format
    let config = OutputConfigBuilder::default()
        .format(OutputFormat::Csv)
        .write_metadata(true)
        .build();

    assert_eq!(config.format, OutputFormat::Csv);
    assert!(config.write_metadata);

    // Test with JSONL format (default)
    let config = OutputConfigBuilder::default().write_metadata(true).build();

    assert_eq!(config.format, OutputFormat::JsonLines);
    assert!(config.write_metadata);
}

#[test]
fn test_write_metadata_toggle() {
    // Test enabling then disabling
    let config = OutputConfigBuilder::default()
        .write_metadata(true)
        .write_metadata(false) // Override previous setting
        .build();

    assert!(!config.write_metadata);

    // Test disabling then enabling
    let config = OutputConfigBuilder::default()
        .write_metadata(false)
        .write_metadata(true) // Override previous setting
        .build();

    assert!(config.write_metadata);
}

#[test]
fn test_output_config_clone_and_debug() {
    let config = OutputConfigBuilder::default()
        .write_metadata(true)
        .quiet(true)
        .store_in_memory(false)
        .build();

    // Test Clone trait
    let cloned_config = config.clone();
    assert_eq!(config.write_metadata, cloned_config.write_metadata);
    assert_eq!(config.quiet, cloned_config.quiet);
    assert_eq!(config.store_in_memory, cloned_config.store_in_memory);

    // Test Debug trait (should not panic)
    let debug_string = format!("{:?}", config);
    assert!(debug_string.contains("write_metadata"));
}

// Note: Integration with ProcessMonitor is tested via Python tests
// since the core functionality requires process spawning

#[test]
fn test_process_metadata_edge_cases() {
    // Test with empty command
    let metadata = ProcessMetadata {
        pid: 1,
        cmd: vec![],
        executable: String::new(),
        t0_ms: 0,
    };

    let json = serde_json::to_string(&metadata).unwrap();
    let deserialized: ProcessMetadata = serde_json::from_str(&json).unwrap();
    assert_eq!(deserialized.cmd.len(), 0);
    assert!(deserialized.executable.is_empty());

    // Test with very long command
    let long_cmd = vec!["very_long_command_name_that_exceeds_normal_length".to_string(); 100];
    let metadata = ProcessMetadata {
        pid: 999999,
        cmd: long_cmd.clone(),
        executable: "/very/long/path/to/executable/that/might/cause/issues".to_string(),
        t0_ms: u64::MAX,
    };

    let json = serde_json::to_string(&metadata).unwrap();
    let deserialized: ProcessMetadata = serde_json::from_str(&json).unwrap();
    assert_eq!(deserialized.cmd, long_cmd);
    assert_eq!(deserialized.t0_ms, u64::MAX);
}
