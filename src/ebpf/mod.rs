//! eBPF profiling module for fine-grained process monitoring
//!
//! This module provides optional eBPF-based profiling capabilities that can be enabled
//! with the `ebpf` feature flag. It requires appropriate permissions (CAP_BPF or root)
//! and is Linux-only.

#[cfg(target_os = "linux")]
pub mod debug;
#[cfg(target_os = "linux")]
pub mod metrics;
#[cfg(target_os = "linux")]
pub mod syscall_tracker;

pub use metrics::*;

#[cfg(target_os = "linux")]
pub use debug::debug_println;
#[cfg(target_os = "linux")]
pub use syscall_tracker::SyscallTracker;

#[cfg(not(target_os = "linux"))]
/// Placeholder for non-Linux platforms
pub struct SyscallTracker;

#[cfg(not(target_os = "linux"))]
impl SyscallTracker {
    pub fn new(_pids: Vec<u32>) -> Result<Self, crate::error::DenetError> {
        Err(crate::error::DenetError::EbpfNotSupported(
            "eBPF profiling is only supported on Linux".to_string(),
        ))
    }

    pub fn get_metrics(&self) -> EbpfMetrics {
        EbpfMetrics::error("eBPF not supported on this platform")
    }

    pub fn update_pids(&mut self, _pids: Vec<u32>) -> Result<(), crate::error::DenetError> {
        Ok(())
    }
}
