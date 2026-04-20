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
    pub sys_net_rx_bytes: u64,
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
            sys_net_rx_bytes: 0,
            sys_net_tx_bytes: 0,
            thread_count: 0,
            uptime_secs: 0,
            cpu_core: None,
            gpu: None,
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
    pub sys_net_rx_bytes: u64,
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
            sys_net_rx_bytes,
            sys_net_tx_bytes,
            thread_count,
            process_count: metrics.len(),
            uptime_secs: max_uptime,
            ebpf: None, // eBPF metrics are added separately
            gpu: None,  // GPU metrics are added separately
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
            sys_net_rx_bytes: 0,
            sys_net_tx_bytes: 0,
            thread_count: 0,
            process_count: 0,
            uptime_secs: 0,
            ebpf: None,
            gpu: None,
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
            total_sys_net_rx_bytes: 0,
            total_sys_net_tx_bytes: 0,
            peak_mem_rss_kb: 0,
            avg_cpu_usage: 0.0,
            syscalls: None,
            gpu: None,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

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
