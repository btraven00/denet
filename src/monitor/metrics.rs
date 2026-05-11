//! Metrics data structures and utilities
//!
//! This module contains all the data structures used to represent
//! process monitoring metrics and summaries.

use serde::{Deserialize, Serialize};
use std::time::{SystemTime, UNIX_EPOCH};

/// Capability manifest emitted once in the JSONL header line. Tells downstream
/// tooling which optional metric sources resolved at startup so it knows which
/// per-sample fields to expect.
#[derive(Serialize, Deserialize, Debug, Clone, Default)]
pub struct Capabilities {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub psi: Option<crate::psi::PsiCapability>,
    #[cfg(target_os = "linux")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub perf_hw: Option<crate::perf::PerfCapability>,
    #[cfg(not(target_os = "linux"))]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub perf_hw: Option<serde_json::Value>,
}

/// Metadata about a monitored process
#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct ProcessMetadata {
    pub pid: usize,
    pub cmd: Vec<String>,
    pub executable: String,
    pub t0_ms: u64,
    /// Manifest of optional metric sources detected at startup. Absent in
    /// older logs; present here is purely additive.
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub capabilities: Option<Capabilities>,
}

impl ProcessMetadata {
    pub fn new(pid: usize, cmd: Vec<String>, executable: String) -> Self {
        let t0_ms = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_millis() as u64)
            .unwrap_or(0);

        Self {
            pid,
            cmd,
            executable,
            t0_ms,
            capabilities: None,
        }
    }
}

/// Single point-in-time metrics for a process
#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct Metrics {
    pub ts_ms: u64,
    pub cpu_usage: f32,
    pub mem_rss_kb: u64,
    pub mem_vms_kb: u64,
    pub disk_read_bytes: u64,
    pub disk_write_bytes: u64,
    /// Bytes read via read()-family syscalls (rchar from /proc/pid/io on Linux).
    /// Includes page-cache hits; `disk_read_bytes` does not. `None` on non-Linux.
    /// Does NOT include mmap access — see `page_faults_cached`/`page_faults_disk` for that.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub syscall_read_bytes: Option<u64>,
    /// Bytes written via write()-family syscalls (wchar from /proc/pid/io on Linux).
    /// Counts data moved into the kernel, not bytes actually flushed to storage.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub syscall_write_bytes: Option<u64>,
    /// Count of page faults satisfied without a block-layer read (minor faults).
    /// Includes warm-mmap accesses and first-touch of lazily allocated anonymous
    /// memory. Event count, not a byte size. Linux only.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub page_faults_cached: Option<u64>,
    /// Count of page faults that required a block-layer read (major faults).
    /// Includes cold-mmap reads and swap-ins. Event count, not a byte size.
    /// Linux only.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub page_faults_disk: Option<u64>,
    #[serde(alias = "net_rx_bytes")]
    pub sys_net_rx_bytes: u64,
    #[serde(alias = "net_tx_bytes")]
    pub sys_net_tx_bytes: u64,
    pub thread_count: usize,
    pub uptime_secs: u64,
    pub cpu_core: Option<u32>,

    /// GPU metrics (optional, only present when gpu feature is enabled)
    #[cfg(feature = "gpu")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub gpu: Option<crate::gpu::GpuMetrics>,

    #[cfg(not(feature = "gpu"))]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub gpu: Option<serde_json::Value>,

    /// Memory pressure (PSI) — last `avg10` window, fraction in [0, 1].
    /// Per-process if `/proc/<pid>/pressure/memory` was readable, otherwise
    /// the system-wide value (see manifest in header for which).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub psi_mem: Option<crate::psi::PsiMem>,

    /// Hardware perf-counter deltas since the previous sample. Linux-only,
    /// requires `perf_event_paranoid <= 2` or `CAP_PERFMON`. Consumer can
    /// derive IPC = `instructions/cycles` and LLC miss rate from a single
    /// sample without needing global state.
    #[cfg(target_os = "linux")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub perf: Option<crate::perf::PerfCounters>,

    #[cfg(not(target_os = "linux"))]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub perf: Option<serde_json::Value>,
}

impl Metrics {
    /// Create a new metrics instance with current timestamp
    pub fn new() -> Self {
        let ts_ms = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_millis() as u64)
            .unwrap_or(0);

        Self {
            ts_ms,
            cpu_usage: 0.0,
            mem_rss_kb: 0,
            mem_vms_kb: 0,
            disk_read_bytes: 0,
            disk_write_bytes: 0,
            syscall_read_bytes: None,
            syscall_write_bytes: None,
            page_faults_cached: None,
            page_faults_disk: None,
            sys_net_rx_bytes: 0,
            sys_net_tx_bytes: 0,
            thread_count: 0,
            uptime_secs: 0,
            cpu_core: None,
            gpu: None,
            psi_mem: None,
            perf: None,
        }
    }
}

impl Default for Metrics {
    fn default() -> Self {
        Self::new()
    }
}

/// Metrics for a process tree (parent + children)
#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct ProcessTreeMetrics {
    pub ts_ms: u64,
    pub parent: Option<Metrics>,
    pub children: Vec<ChildProcessMetrics>,
    pub aggregated: Option<AggregatedMetrics>,
}

/// Metrics for a child process
#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct ChildProcessMetrics {
    pub pid: usize,
    pub command: String,
    pub metrics: Metrics,
}

/// Aggregated metrics across multiple processes
#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct AggregatedMetrics {
    pub ts_ms: u64,
    pub cpu_usage: f32,
    pub mem_rss_kb: u64,
    pub mem_vms_kb: u64,
    pub disk_read_bytes: u64,
    pub disk_write_bytes: u64,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub syscall_read_bytes: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub syscall_write_bytes: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub page_faults_cached: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub page_faults_disk: Option<u64>,
    #[serde(alias = "net_rx_bytes")]
    pub sys_net_rx_bytes: u64,
    #[serde(alias = "net_tx_bytes")]
    pub sys_net_tx_bytes: u64,
    pub thread_count: usize,
    pub process_count: usize,
    pub uptime_secs: u64,

    /// eBPF profiling data (optional)
    #[cfg(feature = "ebpf")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ebpf: Option<crate::ebpf::EbpfMetrics>,

    #[cfg(not(feature = "ebpf"))]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ebpf: Option<serde_json::Value>,

    /// GPU metrics aggregated across all processes
    #[cfg(feature = "gpu")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub gpu: Option<crate::gpu::GpuMetrics>,

    #[cfg(not(feature = "gpu"))]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub gpu: Option<serde_json::Value>,

    /// Memory pressure for the whole tree. PSI is sampled once per tick (system
    /// or per-process root); we just propagate the parent's value rather than
    /// inventing an aggregation.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub psi_mem: Option<crate::psi::PsiMem>,

    /// Sum of per-process perf-counter deltas across the tree. Sums are
    /// meaningful for IPC/miss-rate ratios because we sum numerator and
    /// denominator together.
    #[cfg(target_os = "linux")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub perf: Option<crate::perf::PerfCounters>,

    #[cfg(not(target_os = "linux"))]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub perf: Option<serde_json::Value>,
}

impl AggregatedMetrics {
    /// Create aggregated metrics from a collection of individual metrics
    pub fn from_metrics(metrics: &[Metrics]) -> Self {
        if metrics.is_empty() {
            return Self::default();
        }

        let ts_ms = metrics[0].ts_ms;
        let mut cpu_usage = 0.0;
        let mut mem_rss_kb = 0;
        let mut mem_vms_kb = 0;
        let mut disk_read_bytes = 0;
        let mut disk_write_bytes = 0;
        let mut syscall_read_bytes: Option<u64> = None;
        let mut syscall_write_bytes: Option<u64> = None;
        let mut page_faults_cached: Option<u64> = None;
        let mut page_faults_disk: Option<u64> = None;
        let mut sys_net_rx_bytes = 0;
        let mut sys_net_tx_bytes = 0;
        let mut thread_count = 0;
        let mut max_uptime = 0;

        for metric in metrics {
            cpu_usage += metric.cpu_usage;
            mem_rss_kb += metric.mem_rss_kb;
            mem_vms_kb += metric.mem_vms_kb;
            disk_read_bytes += metric.disk_read_bytes;
            disk_write_bytes += metric.disk_write_bytes;
            if let Some(v) = metric.syscall_read_bytes {
                syscall_read_bytes = Some(syscall_read_bytes.unwrap_or(0) + v);
            }
            if let Some(v) = metric.syscall_write_bytes {
                syscall_write_bytes = Some(syscall_write_bytes.unwrap_or(0) + v);
            }
            if let Some(v) = metric.page_faults_cached {
                page_faults_cached = Some(page_faults_cached.unwrap_or(0) + v);
            }
            if let Some(v) = metric.page_faults_disk {
                page_faults_disk = Some(page_faults_disk.unwrap_or(0) + v);
            }
            sys_net_rx_bytes += metric.sys_net_rx_bytes;
            sys_net_tx_bytes += metric.sys_net_tx_bytes;
            thread_count += metric.thread_count;
            max_uptime = max_uptime.max(metric.uptime_secs);
        }

        Self {
            ts_ms,
            cpu_usage,
            mem_rss_kb,
            mem_vms_kb,
            disk_read_bytes,
            disk_write_bytes,
            syscall_read_bytes,
            syscall_write_bytes,
            page_faults_cached,
            page_faults_disk,
            sys_net_rx_bytes,
            sys_net_tx_bytes,
            thread_count,
            process_count: metrics.len(),
            uptime_secs: max_uptime,
            ebpf: None, // eBPF metrics are added separately
            gpu: None,  // GPU metrics are added separately
            psi_mem: metrics.iter().find_map(|m| m.psi_mem),
            #[cfg(target_os = "linux")]
            perf: aggregate_perf(metrics),
            #[cfg(not(target_os = "linux"))]
            perf: None,
        }
    }
}

#[cfg(target_os = "linux")]
fn aggregate_perf(metrics: &[Metrics]) -> Option<crate::perf::PerfCounters> {
    let mut acc = crate::perf::PerfCounters::default();
    let mut any = false;
    for m in metrics {
        if let Some(p) = m.perf {
            acc.cycles += p.cycles;
            acc.instructions += p.instructions;
            acc.cache_refs += p.cache_refs;
            acc.cache_misses += p.cache_misses;
            acc.stalled_backend += p.stalled_backend;
            any = true;
        }
    }
    if any {
        Some(acc)
    } else {
        None
    }
}

impl Default for AggregatedMetrics {
    fn default() -> Self {
        let ts_ms = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_millis() as u64)
            .unwrap_or(0);

        Self {
            ts_ms,
            cpu_usage: 0.0,
            mem_rss_kb: 0,
            mem_vms_kb: 0,
            disk_read_bytes: 0,
            disk_write_bytes: 0,
            syscall_read_bytes: None,
            syscall_write_bytes: None,
            page_faults_cached: None,
            page_faults_disk: None,
            sys_net_rx_bytes: 0,
            sys_net_tx_bytes: 0,
            thread_count: 0,
            process_count: 0,
            uptime_secs: 0,
            ebpf: None,
            gpu: None,
            psi_mem: None,
            perf: None,
        }
    }
}

/// Average syscall category fractions and rate across a monitoring run.
/// Each `avg_*_syscall_fraction` field is the mean of (category_count / total_syscalls)
/// across all samples — a value in [0.0, 1.0]. They do not sum to 1.0 because
/// uncategorized syscalls are excluded. `avg_syscall_rate_per_sec` is unbounded.
#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct SyscallIntensitySummary {
    pub avg_syscall_rate_per_sec: f64,
    pub avg_io_syscall_fraction: f64,
    pub avg_memory_syscall_fraction: f64,
    pub avg_cpu_syscall_fraction: f64,
    pub avg_network_syscall_fraction: f64,
}

/// End-of-run memory-boundedness verdict, derived from accumulated perf
/// counters and PSI fractions. Each field is only present when the underlying
/// signal was collected for at least one sample.
#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct MemoryCharacterization {
    /// instructions / cycles, summed across the run.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub mean_ipc: Option<f64>,
    /// cache_misses / cache_refs.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub llc_miss_rate: Option<f64>,
    /// stalled_backend / cycles. The most direct memory-bound signal.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub backend_stall_ratio: Option<f64>,
    /// Fraction of samples in which PSI `some_avg10 > 0`.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub psi_some_fraction: Option<f64>,
    /// Coarse classification: "memory-bound", "cpu-bound", "mixed", or
    /// "insufficient-data". Threshold rule documented in the source.
    pub verdict: String,
}

// Classification thresholds. Backend-stall ratio and IPC thresholds are
// derived from common microarchitecture profiling rules of thumb; PSI threshold
// is chosen conservatively (majority of samples showing any stall).
const MEMORY_BOUND_STALL_THRESHOLD: f64 = 0.5;
const MEMORY_BOUND_IPC_CEILING: f64 = 1.0;
const CPU_BOUND_STALL_CEILING: f64 = 0.2;
const CPU_BOUND_IPC_FLOOR: f64 = 1.5;
const PSI_PRESSURE_THRESHOLD: f64 = 0.5;

impl MemoryCharacterization {
    /// Compute the roll-up over any window of per-process samples. Caller
    /// chooses the window — end-of-run, per pipeline stage, sliding, etc.
    /// Returns `None` if no perf nor PSI data appears in the slice.
    pub fn from_metrics(metrics: &[Metrics]) -> Option<Self> {
        memchar_from(metrics, metric_perf, |m: &&Metrics| {
            m.psi_mem.map(|p| p.some_avg10)
        })
    }

    /// Same as `from_metrics`, for tree-aggregated samples.
    pub fn from_aggregated(metrics: &[AggregatedMetrics]) -> Option<Self> {
        memchar_from(metrics, agg_perf, |m: &&AggregatedMetrics| {
            m.psi_mem.map(|p| p.some_avg10)
        })
    }

    fn classify(
        mean_ipc: Option<f64>,
        backend_stall_ratio: Option<f64>,
        psi_some_fraction: Option<f64>,
    ) -> String {
        // Perf counters give the strongest signal: high backend stalls with low
        // IPC is memory-bound; low stalls with high IPC is cpu-bound. PSI acts
        // as a tiebreaker when perf is inconclusive, and as the sole signal when
        // perf counters aren't available.
        match (mean_ipc, backend_stall_ratio) {
            (Some(ipc), Some(stalls)) => {
                if stalls > MEMORY_BOUND_STALL_THRESHOLD && ipc < MEMORY_BOUND_IPC_CEILING {
                    "memory-bound".to_string()
                } else if stalls < CPU_BOUND_STALL_CEILING && ipc > CPU_BOUND_IPC_FLOOR {
                    "cpu-bound".to_string()
                } else if psi_some_fraction.unwrap_or(0.0) > PSI_PRESSURE_THRESHOLD {
                    "memory-bound".to_string()
                } else {
                    "mixed".to_string()
                }
            }
            _ => {
                // No perf counters — use PSI alone if available.
                if psi_some_fraction.unwrap_or(0.0) > PSI_PRESSURE_THRESHOLD {
                    "memory-bound".to_string()
                } else {
                    "insufficient-data".to_string()
                }
            }
        }
    }
}

/// Summarizes metrics collected during a monitoring session
#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct Summary {
    /// Total time elapsed in seconds
    pub total_time_secs: f64,
    /// Number of samples collected
    pub sample_count: usize,
    /// Maximum number of processes observed
    pub max_processes: usize,
    /// Maximum number of threads observed
    pub max_threads: usize,
    /// Cumulative disk read bytes
    pub total_disk_read_bytes: u64,
    /// Cumulative disk write bytes
    pub total_disk_write_bytes: u64,
    /// Cumulative bytes read via read()-family syscalls (Linux only).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub total_syscall_read_bytes: Option<u64>,
    /// Cumulative bytes written via write()-family syscalls (Linux only).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub total_syscall_write_bytes: Option<u64>,
    /// Peak minor page fault count observed (Linux only).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub peak_page_faults_cached: Option<u64>,
    /// Peak major page fault count observed (Linux only).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub peak_page_faults_disk: Option<u64>,
    /// Cumulative network received bytes
    pub total_sys_net_rx_bytes: u64,
    /// Cumulative network transmitted bytes
    pub total_sys_net_tx_bytes: u64,
    /// Maximum memory RSS observed across all processes (in KB)
    pub peak_mem_rss_kb: u64,
    /// Average CPU usage (percent)
    pub avg_cpu_usage: f32,
    /// Averaged syscall intensity ratios (only present when eBPF data was collected)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub syscalls: Option<SyscallIntensitySummary>,

    /// GPU monitoring summary
    #[cfg(feature = "gpu")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub gpu: Option<crate::gpu::GpuSummary>,

    #[cfg(not(feature = "gpu"))]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub gpu: Option<serde_json::Value>,

    /// End-of-run memory-boundedness roll-up. Absent if no perf or PSI data
    /// was collected.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub memory_characterization: Option<MemoryCharacterization>,
}

/// Compute the memory-characterization roll-up from any iterable of samples
/// that expose perf-counter deltas and PSI fractions. Returns `None` when
/// neither source produced data.
fn memchar_from<F1, F2, I>(metrics: I, perf_of: F1, psi_of: F2) -> Option<MemoryCharacterization>
where
    I: IntoIterator,
    F1: Fn(&I::Item) -> Option<PerfSnapshot>,
    F2: Fn(&I::Item) -> Option<f32>,
{
    let mut sum = PerfSnapshot::default();
    let mut perf_seen = false;
    let mut psi_total = 0usize;
    let mut psi_pressured = 0usize;
    for m in metrics {
        if let Some(p) = perf_of(&m) {
            sum.cycles += p.cycles;
            sum.instructions += p.instructions;
            sum.cache_refs += p.cache_refs;
            sum.cache_misses += p.cache_misses;
            sum.stalled_backend += p.stalled_backend;
            perf_seen = true;
        }
        if let Some(some_avg10) = psi_of(&m) {
            psi_total += 1;
            if some_avg10 > 0.0 {
                psi_pressured += 1;
            }
        }
    }
    if !perf_seen && psi_total == 0 {
        return None;
    }

    let div = |num: u64, den: u64| -> Option<f64> {
        if den == 0 {
            None
        } else {
            Some(num as f64 / den as f64)
        }
    };
    let mean_ipc = if perf_seen {
        div(sum.instructions, sum.cycles)
    } else {
        None
    };
    let llc_miss_rate = if perf_seen {
        div(sum.cache_misses, sum.cache_refs)
    } else {
        None
    };
    let backend_stall_ratio = if perf_seen {
        div(sum.stalled_backend, sum.cycles)
    } else {
        None
    };
    let psi_some_fraction = if psi_total > 0 {
        Some(psi_pressured as f64 / psi_total as f64)
    } else {
        None
    };
    Some(MemoryCharacterization {
        verdict: MemoryCharacterization::classify(mean_ipc, backend_stall_ratio, psi_some_fraction),
        mean_ipc,
        llc_miss_rate,
        backend_stall_ratio,
        psi_some_fraction,
    })
}

#[derive(Default, Clone, Copy)]
struct PerfSnapshot {
    cycles: u64,
    instructions: u64,
    cache_refs: u64,
    cache_misses: u64,
    stalled_backend: u64,
}

#[cfg(target_os = "linux")]
fn perf_snapshot(p: &crate::perf::PerfCounters) -> PerfSnapshot {
    PerfSnapshot {
        cycles: p.cycles,
        instructions: p.instructions,
        cache_refs: p.cache_refs,
        cache_misses: p.cache_misses,
        stalled_backend: p.stalled_backend,
    }
}

#[cfg(target_os = "linux")]
fn metric_perf(m: &&Metrics) -> Option<PerfSnapshot> {
    m.perf.as_ref().map(perf_snapshot)
}
#[cfg(not(target_os = "linux"))]
fn metric_perf(_m: &&Metrics) -> Option<PerfSnapshot> {
    None
}

#[cfg(target_os = "linux")]
fn agg_perf(m: &&AggregatedMetrics) -> Option<PerfSnapshot> {
    m.perf.as_ref().map(perf_snapshot)
}
#[cfg(not(target_os = "linux"))]
fn agg_perf(_m: &&AggregatedMetrics) -> Option<PerfSnapshot> {
    None
}

impl Summary {
    /// Create a new empty summary
    pub fn new() -> Self {
        Self::default()
    }

    /// Create summary from a collection of individual metrics
    pub fn from_metrics(metrics: &[Metrics], elapsed_time: f64) -> Self {
        if metrics.is_empty() {
            return Self::new();
        }

        let mut total_cpu = 0.0;
        let mut max_threads = 0;
        let mut peak_mem_rss_kb = 0;
        let last_metrics = &metrics[metrics.len() - 1];

        for metric in metrics {
            total_cpu += metric.cpu_usage;
            max_threads = max_threads.max(metric.thread_count);
            peak_mem_rss_kb = peak_mem_rss_kb.max(metric.mem_rss_kb);
        }

        #[cfg(feature = "gpu")]
        let gpu = {
            let gpu_samples: Vec<crate::gpu::GpuMetrics> =
                metrics.iter().filter_map(|m| m.gpu.clone()).collect();
            if gpu_samples.is_empty() {
                None
            } else {
                let monitor = crate::gpu::GpuMonitor::new();
                let summary = monitor.get_summary(&gpu_samples);
                if summary.enabled {
                    Some(summary)
                } else {
                    None
                }
            }
        };
        #[cfg(not(feature = "gpu"))]
        let gpu = None;

        Self {
            total_time_secs: elapsed_time,
            sample_count: metrics.len(),
            max_processes: 1, // Single process monitoring
            max_threads,
            total_disk_read_bytes: last_metrics.disk_read_bytes,
            total_disk_write_bytes: last_metrics.disk_write_bytes,
            total_syscall_read_bytes: last_metrics.syscall_read_bytes,
            total_syscall_write_bytes: last_metrics.syscall_write_bytes,
            peak_page_faults_cached: metrics.iter().filter_map(|m| m.page_faults_cached).max(),
            peak_page_faults_disk: metrics.iter().filter_map(|m| m.page_faults_disk).max(),
            total_sys_net_rx_bytes: last_metrics.sys_net_rx_bytes,
            total_sys_net_tx_bytes: last_metrics.sys_net_tx_bytes,
            peak_mem_rss_kb,
            avg_cpu_usage: if metrics.is_empty() {
                0.0
            } else {
                total_cpu / metrics.len() as f32
            },
            syscalls: None,
            gpu,
            memory_characterization: MemoryCharacterization::from_metrics(metrics),
        }
    }

    /// Create summary from aggregated metrics
    pub fn from_aggregated_metrics(metrics: &[AggregatedMetrics], elapsed_time: f64) -> Self {
        if metrics.is_empty() {
            return Self::new();
        }

        let mut total_cpu = 0.0;
        let mut max_processes = 0;
        let mut max_threads = 0;
        let mut peak_mem_rss_kb = 0;
        let last_metrics = &metrics[metrics.len() - 1];

        for metric in metrics {
            total_cpu += metric.cpu_usage;
            max_processes = max_processes.max(metric.process_count);
            max_threads = max_threads.max(metric.thread_count);
            peak_mem_rss_kb = peak_mem_rss_kb.max(metric.mem_rss_kb);
        }

        #[cfg(feature = "gpu")]
        let gpu = {
            let gpu_samples: Vec<crate::gpu::GpuMetrics> =
                metrics.iter().filter_map(|m| m.gpu.clone()).collect();
            if gpu_samples.is_empty() {
                None
            } else {
                let monitor = crate::gpu::GpuMonitor::new();
                let summary = monitor.get_summary(&gpu_samples);
                if summary.enabled {
                    Some(summary)
                } else {
                    None
                }
            }
        };
        #[cfg(not(feature = "gpu"))]
        let gpu = None;

        #[cfg(feature = "ebpf")]
        let syscalls = {
            let analyses: Vec<&crate::ebpf::metrics::SyscallAnalysis> = metrics
                .iter()
                .filter_map(|m| m.ebpf.as_ref())
                .filter_map(|e| e.syscalls.as_ref())
                .filter_map(|s| s.analysis.as_ref())
                .collect();
            if analyses.is_empty() {
                None
            } else {
                let n = analyses.len() as f64;
                Some(SyscallIntensitySummary {
                    avg_syscall_rate_per_sec: analyses
                        .iter()
                        .map(|a| a.syscall_rate_per_sec)
                        .sum::<f64>()
                        / n,
                    avg_io_syscall_fraction: analyses.iter().map(|a| a.io_intensity).sum::<f64>()
                        / n,
                    avg_memory_syscall_fraction: analyses
                        .iter()
                        .map(|a| a.memory_intensity)
                        .sum::<f64>()
                        / n,
                    avg_cpu_syscall_fraction: analyses.iter().map(|a| a.cpu_intensity).sum::<f64>()
                        / n,
                    avg_network_syscall_fraction: analyses
                        .iter()
                        .map(|a| a.network_intensity)
                        .sum::<f64>()
                        / n,
                })
            }
        };
        #[cfg(not(feature = "ebpf"))]
        let syscalls: Option<SyscallIntensitySummary> = None;

        Self {
            total_time_secs: elapsed_time,
            sample_count: metrics.len(),
            max_processes,
            max_threads,
            total_disk_read_bytes: last_metrics.disk_read_bytes,
            total_disk_write_bytes: last_metrics.disk_write_bytes,
            total_syscall_read_bytes: last_metrics.syscall_read_bytes,
            total_syscall_write_bytes: last_metrics.syscall_write_bytes,
            peak_page_faults_cached: metrics.iter().filter_map(|m| m.page_faults_cached).max(),
            peak_page_faults_disk: metrics.iter().filter_map(|m| m.page_faults_disk).max(),
            total_sys_net_rx_bytes: last_metrics.sys_net_rx_bytes,
            total_sys_net_tx_bytes: last_metrics.sys_net_tx_bytes,
            peak_mem_rss_kb,
            avg_cpu_usage: if metrics.is_empty() {
                0.0
            } else {
                total_cpu / metrics.len() as f32
            },
            syscalls,
            gpu,
            memory_characterization: MemoryCharacterization::from_aggregated(metrics),
        }
    }
}

impl Default for Summary {
    fn default() -> Self {
        Self {
            total_time_secs: 0.0,
            sample_count: 0,
            max_processes: 0,
            max_threads: 0,
            total_disk_read_bytes: 0,
            total_disk_write_bytes: 0,
            total_syscall_read_bytes: None,
            total_syscall_write_bytes: None,
            peak_page_faults_cached: None,
            peak_page_faults_disk: None,
            total_sys_net_rx_bytes: 0,
            total_sys_net_tx_bytes: 0,
            peak_mem_rss_kb: 0,
            avg_cpu_usage: 0.0,
            syscalls: None,
            gpu: None,
            memory_characterization: None,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::psi::PsiMem;

    // ---- classify unit tests ------------------------------------------------

    #[test]
    fn classify_memory_bound_via_perf() {
        assert_eq!(
            MemoryCharacterization::classify(Some(0.5), Some(0.7), None),
            "memory-bound"
        );
    }

    #[test]
    fn classify_cpu_bound_via_perf() {
        assert_eq!(
            MemoryCharacterization::classify(Some(2.0), Some(0.1), None),
            "cpu-bound"
        );
    }

    #[test]
    fn classify_mixed_inconclusive_perf() {
        assert_eq!(
            MemoryCharacterization::classify(Some(1.2), Some(0.3), None),
            "mixed"
        );
    }

    #[test]
    fn classify_psi_tiebreaker_tips_to_memory_bound() {
        // Inconclusive perf, but high PSI → memory-bound.
        assert_eq!(
            MemoryCharacterization::classify(Some(1.2), Some(0.3), Some(0.8)),
            "memory-bound"
        );
    }

    #[test]
    fn classify_psi_only_high_pressure() {
        assert_eq!(
            MemoryCharacterization::classify(None, None, Some(0.8)),
            "memory-bound"
        );
    }

    #[test]
    fn classify_psi_only_low_pressure() {
        // PSI available but below threshold → not enough to call it memory-bound.
        assert_eq!(
            MemoryCharacterization::classify(None, None, Some(0.2)),
            "insufficient-data"
        );
    }

    #[test]
    fn classify_psi_only_zero_pressure() {
        assert_eq!(
            MemoryCharacterization::classify(None, None, Some(0.0)),
            "insufficient-data"
        );
    }

    #[test]
    fn classify_no_data() {
        assert_eq!(
            MemoryCharacterization::classify(None, None, None),
            "insufficient-data"
        );
    }

    // ---- from_metrics integration tests -------------------------------------

    #[test]
    fn from_metrics_empty_slice_returns_none() {
        assert!(MemoryCharacterization::from_metrics(&[]).is_none());
    }

    #[test]
    fn from_metrics_no_signals_returns_none() {
        assert!(MemoryCharacterization::from_metrics(&[Metrics::new()]).is_none());
    }

    #[test]
    fn from_metrics_psi_only_high_pressure() {
        let mut m = Metrics::new();
        m.psi_mem = Some(PsiMem {
            some_avg10: 0.9,
            full_avg10: 0.4,
        });
        let mc = MemoryCharacterization::from_metrics(&[m]).unwrap();
        assert_eq!(mc.verdict, "memory-bound");
        assert!((mc.psi_some_fraction.unwrap() - 1.0).abs() < f64::EPSILON);
        assert!(mc.mean_ipc.is_none());
        assert!(mc.llc_miss_rate.is_none());
        assert!(mc.backend_stall_ratio.is_none());
    }

    #[test]
    fn from_metrics_psi_fraction_counts_pressured_samples() {
        let pressured = {
            let mut m = Metrics::new();
            m.psi_mem = Some(PsiMem {
                some_avg10: 1.0,
                full_avg10: 0.0,
            });
            m
        };
        let calm = {
            let mut m = Metrics::new();
            m.psi_mem = Some(PsiMem {
                some_avg10: 0.0,
                full_avg10: 0.0,
            });
            m
        };
        // 1 pressured out of 4 → fraction = 0.25, below PSI_PRESSURE_THRESHOLD.
        let mc =
            MemoryCharacterization::from_metrics(&[pressured, calm.clone(), calm.clone(), calm])
                .unwrap();
        assert!((mc.psi_some_fraction.unwrap() - 0.25).abs() < 1e-9);
        assert_eq!(mc.verdict, "insufficient-data");
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn from_metrics_with_perf_computes_ratios() {
        let mut m = Metrics::new();
        m.perf = Some(crate::perf::PerfCounters {
            cycles: 1000,
            instructions: 500,
            cache_refs: 200,
            cache_misses: 50,
            stalled_backend: 700,
        });
        let mc = MemoryCharacterization::from_metrics(&[m]).unwrap();
        assert!((mc.mean_ipc.unwrap() - 0.5).abs() < 1e-9);
        assert!((mc.llc_miss_rate.unwrap() - 0.25).abs() < 1e-9);
        assert!((mc.backend_stall_ratio.unwrap() - 0.7).abs() < 1e-9);
        // High stall + low IPC → memory-bound.
        assert_eq!(mc.verdict, "memory-bound");
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn from_metrics_perf_with_zero_denominators() {
        // Counters present but all zero — ratios should be None, not panic.
        let mut m = Metrics::new();
        m.perf = Some(crate::perf::PerfCounters::default());
        let mc = MemoryCharacterization::from_metrics(&[m]).unwrap();
        assert!(mc.mean_ipc.is_none());
        assert!(mc.llc_miss_rate.is_none());
        assert!(mc.backend_stall_ratio.is_none());
    }

    #[test]
    fn from_aggregated_empty_returns_none() {
        assert!(MemoryCharacterization::from_aggregated(&[]).is_none());
    }

    #[test]
    fn from_aggregated_psi_pressure_classifies_memory_bound() {
        let a = AggregatedMetrics {
            psi_mem: Some(PsiMem {
                some_avg10: 0.8,
                full_avg10: 0.3,
            }),
            ..Default::default()
        };
        let mc = MemoryCharacterization::from_aggregated(&[a]).unwrap();
        assert_eq!(mc.verdict, "memory-bound");
        assert!((mc.psi_some_fraction.unwrap() - 1.0).abs() < f64::EPSILON);
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn from_aggregated_perf_sums_across_samples() {
        let make = |cycles, instr| AggregatedMetrics {
            perf: Some(crate::perf::PerfCounters {
                cycles,
                instructions: instr,
                cache_refs: 0,
                cache_misses: 0,
                stalled_backend: 0,
            }),
            ..Default::default()
        };
        let mc =
            MemoryCharacterization::from_aggregated(&[make(100, 200), make(100, 200)]).unwrap();
        // (200 + 200) / (100 + 100) = 2.0 — high IPC, no stalls → cpu-bound.
        assert!((mc.mean_ipc.unwrap() - 2.0).abs() < 1e-9);
        assert_eq!(mc.verdict, "cpu-bound");
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn aggregated_metrics_from_metrics_aggregates_perf() {
        let mut m1 = Metrics::new();
        m1.perf = Some(crate::perf::PerfCounters {
            cycles: 100,
            instructions: 50,
            cache_refs: 10,
            cache_misses: 2,
            stalled_backend: 30,
        });
        let mut m2 = Metrics::new();
        m2.perf = Some(crate::perf::PerfCounters {
            cycles: 200,
            instructions: 150,
            cache_refs: 20,
            cache_misses: 4,
            stalled_backend: 60,
        });
        let agg = AggregatedMetrics::from_metrics(&[m1, m2]);
        let p = agg.perf.expect("perf should aggregate");
        assert_eq!(p.cycles, 300);
        assert_eq!(p.instructions, 200);
        assert_eq!(p.cache_refs, 30);
        assert_eq!(p.cache_misses, 6);
        assert_eq!(p.stalled_backend, 90);
    }

    #[test]
    fn aggregated_metrics_propagates_psi_from_first_sample() {
        let mut m = Metrics::new();
        m.psi_mem = Some(PsiMem {
            some_avg10: 0.42,
            full_avg10: 0.10,
        });
        let agg = AggregatedMetrics::from_metrics(&[m]);
        let p = agg.psi_mem.expect("psi should propagate");
        assert!((p.some_avg10 - 0.42).abs() < 1e-6);
    }

    // ---- existing tests -----------------------------------------------------

    #[test]
    fn test_process_metadata_new() {
        let pid = 12345;
        let cmd = vec!["test".to_string(), "command".to_string()];
        let executable = "/usr/bin/test".to_string();

        let metadata = ProcessMetadata::new(pid, cmd.clone(), executable.clone());

        assert_eq!(metadata.pid, pid);
        assert_eq!(metadata.cmd, cmd);
        assert_eq!(metadata.executable, executable);
        assert!(metadata.t0_ms > 0);
    }

    #[test]
    fn test_metrics_new() {
        let metrics = Metrics::new();

        assert!(metrics.ts_ms > 0);
        assert_eq!(metrics.cpu_usage, 0.0);
        assert_eq!(metrics.mem_rss_kb, 0);
        assert_eq!(metrics.mem_vms_kb, 0);
        assert_eq!(metrics.disk_read_bytes, 0);
        assert_eq!(metrics.disk_write_bytes, 0);
        assert_eq!(metrics.sys_net_rx_bytes, 0);
        assert_eq!(metrics.sys_net_tx_bytes, 0);
        assert_eq!(metrics.thread_count, 0);
        assert_eq!(metrics.uptime_secs, 0);
        assert_eq!(metrics.cpu_core, None);
    }

    #[test]
    fn test_metrics_default() {
        let metrics = Metrics::default();
        assert!(metrics.ts_ms > 0);
        assert_eq!(metrics.cpu_usage, 0.0);
    }

    #[test]
    fn test_aggregated_metrics_from_empty_metrics() {
        let metrics = vec![];
        let aggregated = AggregatedMetrics::from_metrics(&metrics);

        assert_eq!(aggregated.cpu_usage, 0.0);
        assert_eq!(aggregated.process_count, 0);
        assert_eq!(aggregated.thread_count, 0);
        assert_eq!(aggregated.uptime_secs, 0);
    }

    #[test]
    fn test_aggregated_metrics_from_single_metric() {
        let mut metric = Metrics::new();
        metric.cpu_usage = 25.5;
        metric.mem_rss_kb = 1024;
        metric.mem_vms_kb = 2048;
        metric.disk_read_bytes = 512;
        metric.disk_write_bytes = 256;
        metric.sys_net_rx_bytes = 128;
        metric.sys_net_tx_bytes = 64;
        metric.thread_count = 4;
        metric.uptime_secs = 60;

        let metrics = vec![metric];
        let aggregated = AggregatedMetrics::from_metrics(&metrics);

        assert_eq!(aggregated.cpu_usage, 25.5);
        assert_eq!(aggregated.mem_rss_kb, 1024);
        assert_eq!(aggregated.mem_vms_kb, 2048);
        assert_eq!(aggregated.disk_read_bytes, 512);
        assert_eq!(aggregated.disk_write_bytes, 256);
        assert_eq!(aggregated.sys_net_rx_bytes, 128);
        assert_eq!(aggregated.sys_net_tx_bytes, 64);
        assert_eq!(aggregated.thread_count, 4);
        assert_eq!(aggregated.process_count, 1);
        assert_eq!(aggregated.uptime_secs, 60);
    }

    #[test]
    fn test_aggregated_metrics_from_multiple_metrics() {
        let mut metric1 = Metrics::new();
        metric1.cpu_usage = 10.0;
        metric1.mem_rss_kb = 500;
        metric1.thread_count = 2;
        metric1.uptime_secs = 30;

        let mut metric2 = Metrics::new();
        metric2.cpu_usage = 15.0;
        metric2.mem_rss_kb = 750;
        metric2.thread_count = 3;
        metric2.uptime_secs = 60;

        let metrics = vec![metric1, metric2];
        let aggregated = AggregatedMetrics::from_metrics(&metrics);

        assert_eq!(aggregated.cpu_usage, 25.0);
        assert_eq!(aggregated.mem_rss_kb, 1250);
        assert_eq!(aggregated.thread_count, 5);
        assert_eq!(aggregated.process_count, 2);
        assert_eq!(aggregated.uptime_secs, 60); // Max uptime
    }

    #[test]
    fn test_aggregated_metrics_default() {
        let aggregated = AggregatedMetrics::default();

        assert!(aggregated.ts_ms > 0);
        assert_eq!(aggregated.cpu_usage, 0.0);
        assert_eq!(aggregated.mem_rss_kb, 0);
        assert_eq!(aggregated.process_count, 0);
        assert_eq!(aggregated.thread_count, 0);
        assert_eq!(aggregated.uptime_secs, 0);
        assert!(aggregated.ebpf.is_none());
    }

    #[test]
    fn test_summary_new() {
        let summary = Summary::new();

        assert_eq!(summary.total_time_secs, 0.0);
        assert_eq!(summary.sample_count, 0);
        assert_eq!(summary.max_processes, 0);
        assert_eq!(summary.max_threads, 0);
        assert_eq!(summary.total_disk_read_bytes, 0);
        assert_eq!(summary.total_disk_write_bytes, 0);
        assert_eq!(summary.total_sys_net_rx_bytes, 0);
        assert_eq!(summary.total_sys_net_tx_bytes, 0);
        assert_eq!(summary.peak_mem_rss_kb, 0);
        assert_eq!(summary.avg_cpu_usage, 0.0);
    }

    #[test]
    fn test_summary_default() {
        let summary = Summary::default();
        assert_eq!(summary.total_time_secs, 0.0);
        assert_eq!(summary.sample_count, 0);
    }

    #[test]
    fn test_summary_from_empty_metrics() {
        let metrics = vec![];
        let summary = Summary::from_metrics(&metrics, 10.0);

        assert_eq!(summary.total_time_secs, 0.0);
        assert_eq!(summary.sample_count, 0);
        assert_eq!(summary.avg_cpu_usage, 0.0);
    }

    #[test]
    fn test_summary_from_metrics() {
        let mut metric1 = Metrics::new();
        metric1.cpu_usage = 20.0;
        metric1.mem_rss_kb = 1000;
        metric1.disk_read_bytes = 500;
        metric1.disk_write_bytes = 250;
        metric1.sys_net_rx_bytes = 100;
        metric1.sys_net_tx_bytes = 50;
        metric1.thread_count = 4;

        let mut metric2 = Metrics::new();
        metric2.cpu_usage = 30.0;
        metric2.mem_rss_kb = 1500;
        metric2.disk_read_bytes = 1000;
        metric2.disk_write_bytes = 500;
        metric2.sys_net_rx_bytes = 200;
        metric2.sys_net_tx_bytes = 100;
        metric2.thread_count = 6;

        let metrics = vec![metric1, metric2];
        let summary = Summary::from_metrics(&metrics, 15.5);

        assert_eq!(summary.total_time_secs, 15.5);
        assert_eq!(summary.sample_count, 2);
        assert_eq!(summary.max_processes, 1);
        assert_eq!(summary.max_threads, 6);
        assert_eq!(summary.total_disk_read_bytes, 1000);
        assert_eq!(summary.total_disk_write_bytes, 500);
        assert_eq!(summary.total_sys_net_rx_bytes, 200);
        assert_eq!(summary.total_sys_net_tx_bytes, 100);
        assert_eq!(summary.peak_mem_rss_kb, 1500);
        assert_eq!(summary.avg_cpu_usage, 25.0);
    }

    #[test]
    fn test_summary_from_empty_aggregated_metrics() {
        let metrics = vec![];
        let summary = Summary::from_aggregated_metrics(&metrics, 10.0);

        assert_eq!(summary.total_time_secs, 0.0);
        assert_eq!(summary.sample_count, 0);
        assert_eq!(summary.avg_cpu_usage, 0.0);
    }

    #[test]
    fn test_summary_from_aggregated_metrics() {
        let metric1 = AggregatedMetrics {
            cpu_usage: 40.0,
            mem_rss_kb: 2000,
            disk_read_bytes: 800,
            disk_write_bytes: 400,
            sys_net_rx_bytes: 150,
            sys_net_tx_bytes: 75,
            thread_count: 8,
            process_count: 2,
            ..Default::default()
        };

        let metric2 = AggregatedMetrics {
            cpu_usage: 60.0,
            mem_rss_kb: 3000,
            disk_read_bytes: 1600,
            disk_write_bytes: 800,
            sys_net_rx_bytes: 300,
            sys_net_tx_bytes: 150,
            thread_count: 12,
            process_count: 3,
            ..Default::default()
        };

        let metrics = vec![metric1, metric2];
        let summary = Summary::from_aggregated_metrics(&metrics, 25.0);

        assert_eq!(summary.total_time_secs, 25.0);
        assert_eq!(summary.sample_count, 2);
        assert_eq!(summary.max_processes, 3);
        assert_eq!(summary.max_threads, 12);
        assert_eq!(summary.total_disk_read_bytes, 1600);
        assert_eq!(summary.total_disk_write_bytes, 800);
        assert_eq!(summary.total_sys_net_rx_bytes, 300);
        assert_eq!(summary.total_sys_net_tx_bytes, 150);
        assert_eq!(summary.peak_mem_rss_kb, 3000);
        assert_eq!(summary.avg_cpu_usage, 50.0);
    }

    #[test]
    fn test_serialization() {
        let metadata = ProcessMetadata::new(123, vec!["test".to_string()], "test".to_string());
        let json = serde_json::to_string(&metadata).unwrap();
        let deserialized: ProcessMetadata = serde_json::from_str(&json).unwrap();
        assert_eq!(metadata.pid, deserialized.pid);
        assert_eq!(metadata.cmd, deserialized.cmd);

        let metrics = Metrics::new();
        let json = serde_json::to_string(&metrics).unwrap();
        let deserialized: Metrics = serde_json::from_str(&json).unwrap();
        assert_eq!(metrics.cpu_usage, deserialized.cpu_usage);

        let aggregated = AggregatedMetrics::default();
        let json = serde_json::to_string(&aggregated).unwrap();
        let deserialized: AggregatedMetrics = serde_json::from_str(&json).unwrap();
        assert_eq!(aggregated.cpu_usage, deserialized.cpu_usage);

        let summary = Summary::default();
        let json = serde_json::to_string(&summary).unwrap();
        let deserialized: Summary = serde_json::from_str(&json).unwrap();
        assert_eq!(summary.avg_cpu_usage, deserialized.avg_cpu_usage);
    }

    #[test]
    fn test_child_process_metrics() {
        let mut metrics = Metrics::new();
        metrics.cpu_usage = 15.0;

        let child = ChildProcessMetrics {
            pid: 456,
            command: "child_process".to_string(),
            metrics,
        };

        assert_eq!(child.pid, 456);
        assert_eq!(child.command, "child_process");
        assert_eq!(child.metrics.cpu_usage, 15.0);
    }

    #[test]
    fn test_process_tree_metrics() {
        let parent = Some(Metrics::new());
        let children = vec![ChildProcessMetrics {
            pid: 456,
            command: "child".to_string(),
            metrics: Metrics::new(),
        }];
        let aggregated = Some(AggregatedMetrics::default());

        let tree_metrics = ProcessTreeMetrics {
            ts_ms: 1234567890,
            parent,
            children,
            aggregated,
        };

        assert_eq!(tree_metrics.ts_ms, 1234567890);
        assert!(tree_metrics.parent.is_some());
        assert_eq!(tree_metrics.children.len(), 1);
        assert!(tree_metrics.aggregated.is_some());
    }
}
