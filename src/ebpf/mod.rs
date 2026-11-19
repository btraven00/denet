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
/// zero and the programs use initial-namespace PIDs, as before. Also sets
/// `fork_child_pid_off` for `programs/proctree.h`.
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
        .set_global("pidns_ino", ino, true)
        .set_global("fork_child_pid_off", fork_child_pid_offset(), true);
    loader
}

/// Offset of `child_pid` in a sched_process_fork record, from the tracepoint's
/// format file (`field:pid_t child_pid;\toffset:20;...`)
#[cfg(target_os = "linux")]
fn parse_fork_child_pid_offset(format: &str) -> Option<u32> {
    format
        .lines()
        .find(|l| l.contains(" child_pid;"))?
        .split(';')
        .find_map(|f| f.trim().strip_prefix("offset:"))?
        .parse()
        .ok()
}

/// The running kernel's offset, or the pre-6.10 layout's if unreadable
#[cfg(target_os = "linux")]
fn fork_child_pid_offset() -> &'static u32 {
    static OFF: std::sync::OnceLock<u32> = std::sync::OnceLock::new();
    OFF.get_or_init(|| {
        ["/sys/kernel/tracing", "/sys/kernel/debug/tracing"]
            .iter()
            .find_map(|d| {
                std::fs::read_to_string(format!("{d}/events/sched/sched_process_fork/format")).ok()
            })
            .and_then(|f| parse_fork_child_pid_offset(&f))
            .unwrap_or(44)
    })
}

/// Attach the fork and exit programs of `programs/proctree.h`, which keep the
/// kernel's `pid_filter` on the whole process tree between samples. Call it
/// before attaching the program's own probes, so no child forks unseen.
#[cfg(target_os = "linux")]
pub(crate) fn attach_proctree(bpf: &mut aya::Ebpf) -> crate::error::Result<()> {
    let err = |what: &str, e: &dyn std::fmt::Display| {
        crate::error::DenetError::EbpfInitError(format!("{what}: {e}"))
    };
    for (prog_name, event) in [
        ("trace_process_fork", "sched_process_fork"),
        ("trace_process_exit", "sched_process_exit"),
    ] {
        let tp: &mut aya::programs::TracePoint = bpf
            .program_mut(prog_name)
            .ok_or_else(|| err(prog_name, &"not in eBPF object"))?
            .try_into()
            .map_err(|e| err(prog_name, &e))?;
        tp.load()
            .map_err(|e| err(&format!("load {prog_name}"), &e))?;
        // ponytail: 6.6.0's eventfs can fail a concurrent first lookup of an
        // events/ dir after boot with ENOENT; a short retry gets past it
        let mut res = tp.attach("sched", event);
        for _ in 0..3 {
            if res.is_ok() {
                break;
            }
            std::thread::sleep(std::time::Duration::from_millis(20));
            res = tp.attach("sched", event);
        }
        res.map_err(|e| {
            // aya's Display shows only the file; the io error is the source
            let src = std::error::Error::source(&e).map(|s| format!(" ({s})"));
            err(
                &format!("attach {prog_name}"),
                &format!("{e}{}", src.unwrap_or_default()),
            )
        })?;
    }
    Ok(())
}

#[cfg(target_os = "linux")]
pub use debug::debug_println;
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

#[cfg(all(test, target_os = "linux"))]
mod tests {
    #[test]
    fn test_fork_child_pid_offset_both_layouts() {
        // kernel >= 6.10: comm fields are __data_loc strings
        let new = "\tfield:__data_loc char[] parent_comm;\toffset:8;\tsize:4;\tsigned:0;\n\
                   \tfield:pid_t parent_pid;\toffset:12;\tsize:4;\tsigned:1;\n\
                   \tfield:__data_loc char[] child_comm;\toffset:16;\tsize:4;\tsigned:0;\n\
                   \tfield:pid_t child_pid;\toffset:20;\tsize:4;\tsigned:1;\n";
        assert_eq!(super::parse_fork_child_pid_offset(new), Some(20));
        // before: char[16] arrays
        let old = "\tfield:char parent_comm[16];\toffset:8;\tsize:16;\tsigned:0;\n\
                   \tfield:pid_t parent_pid;\toffset:24;\tsize:4;\tsigned:1;\n\
                   \tfield:char child_comm[16];\toffset:28;\tsize:16;\tsigned:0;\n\
                   \tfield:pid_t child_pid;\toffset:44;\tsize:4;\tsigned:1;\n";
        assert_eq!(super::parse_fork_child_pid_offset(old), Some(44));
        assert_eq!(super::parse_fork_child_pid_offset("no such field"), None);
    }
}
