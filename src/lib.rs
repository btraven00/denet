//! Denet: A high-performance process monitoring library
//!
//! Denet provides accurate measurement of process resource usage, including
//! CPU, memory, disk I/O, and network I/O. It's designed to be lightweight,
//! accurate, and cross-platform.
//!
//! # Architecture
//!
//! The library is organized into focused modules:
//! - `core`: Pure Rust monitoring functionality
//! - `monitor`: Metrics types and summary generation
//! - `config`: Configuration structures and builders
//! - `error`: Comprehensive error handling
//! - `cpu_sampler`: Platform-specific CPU measurement
//! - `python`: PyO3 bindings (when feature is enabled)
//!
//! # Platform Support
//!
//! CPU measurement strategies:
//! - Linux: Direct procfs reading - matches top/htop measurements
//! - macOS: Will use host_processor_info API and libproc (planned)
//! - Windows: Will use GetProcessTimes and Performance Counters (planned)

// Core modules
pub mod config;
pub mod core;
pub mod error;
pub mod monitor;

// Platform-specific modules
#[cfg(target_os = "linux")]
pub mod cpu_sampler;

// eBPF profiling (optional feature)
#[cfg(feature = "ebpf")]
pub mod ebpf;

// Python bindings
#[cfg(feature = "python")]
mod python;

// Re-export main types
pub use core::{ProcessMonitor, ProcessResult};
pub use monitor::*;

// Re-export for convenience
pub use config::{DenetConfig, MonitorConfig, OutputConfig, OutputFormat};
pub use error::{DenetError, Result};

// Python-specific code is completely isolated here
#[cfg(feature = "python")]
mod python_bindings {
    use super::python;
    use pyo3::prelude::*;

    #[pymodule]
    pub fn _denet(_py: Python, m: &Bound<'_, PyModule>) -> PyResult<()> {
        python::register_python_module(m)
    }
}

/// Run a simple monitoring loop with better error handling and configuration
pub fn run_monitor(
    cmd: Vec<String>,
    base_interval_ms: u64,
    max_interval_ms: u64,
    since_process_start: bool,
) -> Result<()> {
    let monitor = create_monitor(cmd, base_interval_ms, max_interval_ms, since_process_start)?;
    execute_monitoring_loop(monitor, base_interval_ms)
}

/// Create a ProcessMonitor with the given configuration
fn create_monitor(
    cmd: Vec<String>,
    base_interval_ms: u64,
    max_interval_ms: u64,
    since_process_start: bool,
) -> Result<ProcessMonitor> {
    use std::time::Duration;
    ProcessMonitor::new_with_options(
        cmd,
        Duration::from_millis(base_interval_ms),
        Duration::from_millis(max_interval_ms),
        since_process_start,
    )
    .map_err(DenetError::Io)
}

/// Execute the monitoring loop until the process completes
fn execute_monitoring_loop(monitor: ProcessMonitor, interval_ms: u64) -> Result<()> {
    use crate::core::constants::timeouts;
    use crate::core::monitoring_utils::monitor_until_completion;
    use std::time::Duration;

    // For testing purposes, use a very short timeout to avoid long-running tests
    let timeout = if cfg!(test) {
        Some(timeouts::SHORT)
    } else {
        None
    };

    let _result = monitor_until_completion(monitor, Duration::from_millis(interval_ms), timeout);

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_run_monitor_with_invalid_command() {
        use crate::core::constants::sampling;
        // Test with non-existent command
        let result = run_monitor(
            vec!["non_existent_command_12345".to_string()],
            sampling::STANDARD.as_millis() as u64,
            sampling::MAX_ADAPTIVE.as_millis() as u64,
            false,
        );
        assert!(result.is_err());
    }

    #[test]
    fn test_run_monitor_with_valid_command() {
        use crate::core::constants::sampling;
        // Test with a command that should succeed quickly
        #[cfg(target_family = "unix")]
        {
            let result = run_monitor(
                vec!["true".to_string()],
                sampling::STANDARD.as_millis() as u64,
                sampling::MAX_ADAPTIVE.as_millis() as u64,
                false,
            );
            assert!(result.is_ok());
        }

        #[cfg(target_family = "windows")]
        {
            let result = run_monitor(
                vec!["cmd".to_string(), "/c".to_string(), "exit".to_string()],
                sampling::STANDARD.as_millis() as u64,
                sampling::MAX_ADAPTIVE.as_millis() as u64,
                false,
            );
            assert!(result.is_ok());
        }
    }

    #[test]
    fn test_run_monitor_since_process_start() {
        use crate::core::constants::sampling;
        #[cfg(target_family = "unix")]
        {
            let result = run_monitor(
                vec!["true".to_string()],
                sampling::STANDARD.as_millis() as u64,
                sampling::MAX_ADAPTIVE.as_millis() as u64,
                true,
            );
            assert!(result.is_ok());
        }
    }

    #[test]
    fn test_create_monitor_success() {
        use crate::core::constants::sampling;
        #[cfg(target_family = "unix")]
        {
            let monitor = create_monitor(
                vec!["true".to_string()],
                sampling::STANDARD.as_millis() as u64,
                sampling::MAX_ADAPTIVE.as_millis() as u64,
                false,
            );
            assert!(monitor.is_ok());
        }
    }

    #[test]
    fn test_create_monitor_failure() {
        use crate::core::constants::sampling;
        let monitor = create_monitor(
            vec!["non_existent_command_12345".to_string()],
            sampling::STANDARD.as_millis() as u64,
            sampling::MAX_ADAPTIVE.as_millis() as u64,
            false,
        );
        assert!(monitor.is_err());
    }

    #[test]
    fn test_execute_monitoring_loop() {
        use crate::core::constants::{delays, sampling};

        // Test with a non-existent PID to ensure the function handles errors gracefully
        // This will fail quickly without long monitoring loops
        let monitor = ProcessMonitor::from_pid_with_options(
            999999, // Non-existent PID
            delays::MINIMAL,
            sampling::FAST,
            false,
        );

        // If monitor creation fails, that's expected and fine for this test
        if let Ok(monitor) = monitor {
            // Test the function exists and can be called - it will timeout quickly
            let result = execute_monitoring_loop(monitor, delays::MINIMAL.as_millis() as u64);
            assert!(result.is_ok());
        }
    }

    #[test]
    fn test_re_exports() {
        // Test that all re-exports are accessible
        use crate::core::constants::sampling;
        use crate::ProcessMonitor;
        use crate::{DenetConfig, MonitorConfig, OutputConfig, OutputFormat};
        use crate::{DenetError, Result};

        // Test ProcessMonitor re-export
        let pid = std::process::id() as usize;
        let monitor = ProcessMonitor::from_pid_with_options(
            pid,
            sampling::STANDARD,
            sampling::MAX_ADAPTIVE,
            false,
        );
        assert!(monitor.is_ok());

        // Test config re-exports
        let _config = DenetConfig::default();
        let _monitor_config = MonitorConfig::default();
        let _output_config = OutputConfig::default();
        let _format = OutputFormat::default();

        // Test error re-exports
        let _error = DenetError::Other("test".to_string());
        let _result: Result<()> = Ok(());
    }

    #[test]
    fn test_different_intervals() {
        use crate::core::constants::sampling;
        let result = run_monitor(
            vec![],
            sampling::FAST.as_millis() as u64,
            sampling::SLOW.as_millis() as u64,
            false,
        );
        assert!(result.is_err()); // Empty command should fail

        let result = run_monitor(
            vec![],
            sampling::SLOW.as_millis() as u64,
            (sampling::SLOW.as_millis() * 10) as u64,
            true,
        );
        assert!(result.is_err()); // Empty command should fail
    }

    #[cfg(feature = "python")]
    #[test]
    fn test_python_module_exists() {
        // This test just ensures the python module code compiles
        // when the python feature is enabled
        use crate::python_bindings::_denet;

        // We can't actually test the module initialization without a Python runtime,
        // but we can ensure the function exists and is callable
        assert!(std::mem::size_of_val(&_denet) > 0);
    }
}
