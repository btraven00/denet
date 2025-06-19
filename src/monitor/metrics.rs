//! Metrics data structures and utilities
//!
//! This module contains all the data structures used to represent
//! process monitoring metrics and summaries.

use serde::{Deserialize, Serialize};
use std::time::{SystemTime, UNIX_EPOCH};

/// Metadata about a monitored process
#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct ProcessMetadata {
    pub pid: usize,
    pub cmd: Vec<String>,
    pub executable: String,
    pub t0_ms: u64,
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
    pub net_rx_bytes: u64,
    pub net_tx_bytes: u64,
    pub thread_count: usize,
    pub uptime_secs: u64,
    pub cpu_core: Option<u32>,
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
            net_rx_bytes: 0,
            net_tx_bytes: 0,
            thread_count: 0,
            uptime_secs: 0,
            cpu_core: None,
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
    pub net_rx_bytes: u64,
    pub net_tx_bytes: u64,
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
        let mut net_rx_bytes = 0;
        let mut net_tx_bytes = 0;
        let mut thread_count = 0;
        let mut max_uptime = 0;

        for metric in metrics {
            cpu_usage += metric.cpu_usage;
            mem_rss_kb += metric.mem_rss_kb;
            mem_vms_kb += metric.mem_vms_kb;
            disk_read_bytes += metric.disk_read_bytes;
            disk_write_bytes += metric.disk_write_bytes;
            net_rx_bytes += metric.net_rx_bytes;
            net_tx_bytes += metric.net_tx_bytes;
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
            net_rx_bytes,
            net_tx_bytes,
            thread_count,
            process_count: metrics.len(),
            uptime_secs: max_uptime,
            ebpf: None, // eBPF metrics are added separately
        }
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
            net_rx_bytes: 0,
            net_tx_bytes: 0,
            thread_count: 0,
            process_count: 0,
            uptime_secs: 0,
            ebpf: None,
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
    /// Cumulative network received bytes
    pub total_net_rx_bytes: u64,
    /// Cumulative network transmitted bytes
    pub total_net_tx_bytes: u64,
    /// Maximum memory RSS observed across all processes (in KB)
    pub peak_mem_rss_kb: u64,
    /// Average CPU usage (percent)
    pub avg_cpu_usage: f32,
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

        Self {
            total_time_secs: elapsed_time,
            sample_count: metrics.len(),
            max_processes: 1, // Single process monitoring
            max_threads,
            total_disk_read_bytes: last_metrics.disk_read_bytes,
            total_disk_write_bytes: last_metrics.disk_write_bytes,
            total_net_rx_bytes: last_metrics.net_rx_bytes,
            total_net_tx_bytes: last_metrics.net_tx_bytes,
            peak_mem_rss_kb,
            avg_cpu_usage: if metrics.is_empty() {
                0.0
            } else {
                total_cpu / metrics.len() as f32
            },
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

        Self {
            total_time_secs: elapsed_time,
            sample_count: metrics.len(),
            max_processes,
            max_threads,
            total_disk_read_bytes: last_metrics.disk_read_bytes,
            total_disk_write_bytes: last_metrics.disk_write_bytes,
            total_net_rx_bytes: last_metrics.net_rx_bytes,
            total_net_tx_bytes: last_metrics.net_tx_bytes,
            peak_mem_rss_kb,
            avg_cpu_usage: if metrics.is_empty() {
                0.0
            } else {
                total_cpu / metrics.len() as f32
            },
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
            total_net_rx_bytes: 0,
            total_net_tx_bytes: 0,
            peak_mem_rss_kb: 0,
            avg_cpu_usage: 0.0,
        }
    }
}
