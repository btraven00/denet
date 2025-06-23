//! Tests for core library functionality in the denet crate

use denet::{DenetConfig, MonitorConfig, OutputConfig, Result};

/// Test that the re-exports from the lib module work correctly
#[test]
fn test_reexports() {
    // Test the config re-exports
    let monitor_config = MonitorConfig::builder()
        .base_interval_ms(200)
        .max_interval_ms(2000)
        .build()
        .unwrap();

    let output_config = OutputConfig::builder()
        .store_in_memory(true)
        .quiet(false)
        .build();

    let config = DenetConfig {
        monitor: monitor_config,
        output: output_config,
    };

    assert_eq!(
        config.monitor.base_interval,
        std::time::Duration::from_millis(200)
    );
    assert_eq!(
        config.monitor.max_interval,
        std::time::Duration::from_millis(2000)
    );
    assert!(config.output.store_in_memory);
    assert!(!config.output.quiet);

    // Test Result type re-export
    let _result: Result<()> = Ok(());
}

/// Test the run_monitor function for non-Python builds
#[cfg(not(feature = "python"))]
#[test]
fn test_run_monitor_basic() {
    use denet::run_monitor;

    // This command should fail quickly and return an error
    let result = run_monitor(vec!["non_existent_command".to_string()], 100, 1000, false);

    assert!(result.is_err());

    // This command should run but exit immediately
    // Using `true` command which exists on most Unix systems
    #[cfg(target_family = "unix")]
    {
        let result = run_monitor(vec!["true".to_string()], 100, 1000, false);

        // The command should succeed
        assert!(result.is_ok());
    }
}

/// Test ProcessMonitor re-export
#[test]
fn test_process_monitor_reexport() {
    use denet::ProcessMonitor;
    use std::time::Duration;

    // Current process id
    let pid = std::process::id() as usize;

    // Test the constructor without running
    let monitor_result = ProcessMonitor::from_pid_with_options(
        pid,
        Duration::from_millis(100),
        Duration::from_millis(1000),
        false,
    );

    // The current process should exist
    assert!(monitor_result.is_ok());

    // Get the process monitor
    let mut monitor = monitor_result.unwrap();

    // Test basic API
    assert_eq!(monitor.get_pid(), pid);
    assert!(monitor.is_running());
}

/// Test legacy ProcessMonitor re-export
#[test]
fn test_process_monitor_legacy_reexport() {
    use denet::ProcessMonitor;
    use std::time::Duration;

    // Create a basic process monitor for the current process
    let pid = std::process::id() as usize;
    // Use the legacy from_pid constructor with the correct parameters
    let monitor_result =
        ProcessMonitor::from_pid(pid, Duration::from_millis(100), Duration::from_millis(1000));

    // The monitor should be created successfully
    assert!(monitor_result.is_ok());

    // Get the process monitor
    let mut monitor = monitor_result.unwrap();

    // The process should be running
    assert!(monitor.is_running());

    // Test pid accessor
    assert_eq!(monitor.get_pid(), pid);
}
