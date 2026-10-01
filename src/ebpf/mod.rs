//! eBPF profiling module for fine-grained process monitoring
//!
//! This module provides optional eBPF-based profiling capabilities that can be enabled
//! with the `ebpf` feature flag. It requires appropriate permissions (CAP_BPF or root)
//! and is Linux-only.

#[cfg(target_os = "linux")]
pub mod debug;
#[cfg(target_os = "linux")]
pub mod kallsyms;
#[cfg(target_os = "linux")]
pub mod memory_map_cache;
#[cfg(target_os = "linux")]
pub mod metrics;
#[cfg(target_os = "linux")]
pub mod net_monitor;
#[cfg(target_os = "linux")]
pub mod offcpu_profiler;
#[cfg(target_os = "linux")]
pub mod syscall_tracker;

pub use metrics::*;

/// Loader for denet's eBPF programs, with the `pidns_dev`/`pidns_ino` globals
/// set to denet's own PID namespace so the programs report PIDs as /proc shows
/// them to denet (see `programs/pidns.h`). In the initial namespace both stay
/// zero and the programs use initial-namespace PIDs, as before.
#[cfg(target_os = "linux")]
pub(crate) fn pidns_loader() -> aya::EbpfLoader<'static> {
    use std::os::unix::fs::MetadataExt;
    use std::sync::OnceLock;

    // Inode of the initial PID namespace (PROC_PID_INIT_INO in the kernel)
    const PROC_PID_INIT_INO: u64 = 0xEFFF_FFFC;
    static NS: OnceLock<(u64, u64)> = OnceLock::new();
    let (dev, ino) = NS.get_or_init(|| match std::fs::metadata("/proc/self/ns/pid") {
        Ok(m) if m.ino() != PROC_PID_INIT_INO => (m.dev(), m.ino()),
        _ => (0, 0),
    });
    let mut loader = aya::EbpfLoader::new();
    loader
        .set_global("pidns_dev", dev, true)
        .set_global("pidns_ino", ino, true);
    loader
}

#[cfg(target_os = "linux")]
pub use debug::debug_println;
#[cfg(target_os = "linux")]
pub use memory_map_cache::MemoryMapCache;
#[cfg(target_os = "linux")]
pub use net_monitor::NetMonitor;
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

    pub fn get_stats(&self) -> std::collections::HashMap<(u32, u32), OffCpuStats> {
        std::collections::HashMap::new()
    }

    pub fn update_pids(&mut self, _pids: Vec<u32>) {}
}

#[cfg(not(target_os = "linux"))]
/// Placeholder stats type for non-Linux platforms
#[derive(Debug, Clone, Default)]
pub struct OffCpuStats {
    pub count: u64,
    pub total_time_ns: u64,
    pub max_time_ns: u64,
}
