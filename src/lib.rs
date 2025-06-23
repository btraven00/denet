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

/// Run a simple monitoring loop
pub fn run_monitor(
    cmd: Vec<String>,
    base_interval_ms: u64,
    max_interval_ms: u64,
    since_process_start: bool,
) -> Result<()> {
    use std::time::Duration;
    let mut monitor = ProcessMonitor::new_with_options(
        cmd,
        Duration::from_millis(base_interval_ms),
        Duration::from_millis(max_interval_ms),
        since_process_start,
    )
    .map_err(|e| DenetError::Io(e))?;

    while monitor.is_running() {
        let _ = monitor.sample_metrics();
        std::thread::sleep(Duration::from_millis(base_interval_ms));
    }
    Ok(())
}
