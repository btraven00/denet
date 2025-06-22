//! eBPF profiling module for fine-grained process monitoring
//!
//! This module provides optional eBPF-based profiling capabilities that can be enabled
//! with the `ebpf` feature flag. It requires appropriate permissions (CAP_BPF or root)
//! and is Linux-only.

#[cfg(target_os = "linux")]
pub mod debug;
#[cfg(target_os = "linux")]
pub mod memory_map_cache;
#[cfg(target_os = "linux")]
pub mod metrics;
#[cfg(target_os = "linux")]
pub mod offcpu_profiler;
#[cfg(target_os = "linux")]
pub mod syscall_tracker;

pub use metrics::*;

#[cfg(target_os = "linux")]
pub use debug::debug_println;
#[cfg(target_os = "linux")]
pub use memory_map_cache::MemoryMapCache;
#[cfg(target_os = "linux")]
pub use offcpu_profiler::{OffCpuProfiler, OffCpuStats};
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

#[cfg(not(target_os = "linux"))]
/// Placeholder for non-Linux platforms
pub struct OffCpuProfiler;

#[cfg(not(target_os = "linux"))]
impl OffCpuProfiler {
    pub fn new(_pids: Vec<u32>) -> Result<Self, crate::error::DenetError> {
        Err(crate::error::DenetError::EbpfNotSupported(
            "eBPF profiling is only supported on Linux".to_string(),
        ))
    }

    pub fn get_stats(&self) -> std::collections::HashMap<(u32, u32), offcpu_profiler::OffCpuStats> {
        std::collections::HashMap::new()
    }

    pub fn update_pids(&mut self, _pids: Vec<u32>) {
        // No-op on non-Linux platforms
    }
}
