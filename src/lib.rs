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

// Memory-characterization sources (Linux-only internals; PSI module exposes
// portable no-op stubs on other platforms so callers don't need cfg guards).
#[cfg(target_os = "linux")]
pub mod perf;
pub mod psi;
pub mod rapl;
#[cfg(target_os = "linux")]
pub mod tcp_diag;

// eBPF profiling (optional feature)
#[cfg(feature = "ebpf")]
pub mod ebpf;

// GPU monitoring (optional feature)
#[cfg(feature = "gpu")]
pub mod gpu;
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

#[cfg(test)]
mod tests {
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
