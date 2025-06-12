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

// Legacy process_monitor for backward compatibility
// TODO: Remove after migration is complete
pub mod process_monitor;

// Python bindings
#[cfg(feature = "python")]
mod python;

// Re-export main types for backward compatibility
pub use core::ProcessMonitor as CoreProcessMonitor;
pub use monitor::*;
pub use process_monitor::{ProcessMonitor, ProcessResult};

// Re-export for convenience
pub use config::{DenetConfig, MonitorConfig, OutputConfig, OutputFormat};
pub use error::{DenetError, Result};

// Python module export
#[cfg(feature = "python")]
use pyo3::prelude::*;

#[cfg(feature = "python")]
#[pymodule]
fn _denet(_py: Python, m: &Bound<'_, PyModule>) -> PyResult<()> {
    python::register_python_module(m)
}

/// Run a simple monitoring loop (non-Python API)
#[cfg(not(feature = "python"))]
pub fn run_monitor(
    cmd: Vec<String>,
    base_interval_ms: u64,
    max_interval_ms: u64,
    since_process_start: bool,
) -> Result<()> {
    let config = DenetConfig {
        monitor: MonitorConfig::builder()
            .base_interval_ms(base_interval_ms)
            .max_interval_ms(max_interval_ms)
            .since_process_start(since_process_start)
            .build()?,
        output: OutputConfig::default(),
    };

    core::run_monitor(cmd, config)
}
