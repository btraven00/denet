//! GPU monitoring module with per-process utilization support
//!
//! This module provides GPU metrics collection for NVIDIA GPUs through NVML, the
//! driver's monitoring library. It separates system-wide metrics from
//! process-specific metrics to provide accurate monitoring for individual processes.
//!
//! # Opt-in
//!
//! GPU monitoring is off unless asked for (`--gpu`, `enable_gpu=True`):
//! [`GpuMonitor::disabled`] touches nothing, and only [`GpuMonitor::new`] loads
//! `libnvidia-ml.so`, which maps tens of MB of driver state into the process.
//! Nothing here ever spawns `nvidia-smi`.
//!
//! # Per-Process vs System-Wide
//!
//! - System-wide: Overall GPU utilization, total memory usage, temperature
//! - Process-specific: GPU utilization by specific PID, process GPU memory usage
//!
//! NVML's `utilization_rates()` is system-wide. Per-process SM/memory
//! utilization comes from `nvmlDeviceGetProcessUtilization` (the data behind
//! `nvidia-smi pmon`), read incrementally from the last timestamp seen.
//!
//! # Energy
//!
//! NVML's `total_energy_consumption` is a cumulative millijoule counter for the
//! **whole board** (all processes + static/idle draw) — there is no per-process
//! energy counter. We diff it per sample for `package_joules` (ground truth) and
//! attribute a `process_joules` slice by GPU-utilization share (an estimate, as
//! coarse as the util proxy that feeds it). Volta+ only; older GPUs report no
//! counter and `gpu_energy` is omitted.

#[cfg(feature = "gpu")]
use nvml_wrapper::enums::device::UsedGpuMemory;
#[cfg(feature = "gpu")]
use nvml_wrapper::Nvml;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

/// Per-process GPU utilization data
#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct ProcessGpuData {
    /// Process ID
    pub pid: u32,
    /// Process-specific GPU utilization percentage (0-100)
    pub gpu_utilization: Option<u32>,
    /// Process-specific GPU memory usage in bytes
    pub memory_usage: Option<u64>,
    /// GPU memory utilization percentage (0-100) for this process
    pub memory_utilization_pct: Option<u32>,
}

/// System-wide GPU device metrics
#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct SystemGpuMetrics {
    /// GPU device index
    pub device_index: u32,
    /// GPU name/model
    pub name: String,
    /// System-wide GPU utilization percentage (0-100)
    pub system_utilization_gpu: Option<u32>,
    /// System-wide memory utilization percentage (0-100)
    pub system_utilization_memory: Option<u32>,
    /// Total GPU memory in bytes
    pub memory_total: Option<u64>,
    /// Total used GPU memory in bytes (all processes)
    pub memory_used: Option<u64>,
    /// Free GPU memory in bytes
    pub memory_free: Option<u64>,
    /// GPU temperature in Celsius
    pub temperature: Option<u32>,
    /// Power usage in watts
    pub power_usage: Option<u32>,
}

/// GPU energy over one sample interval, in joules.
///
/// `package_joules` is whole-card energy (all processes + static draw), measured
/// via NVML's cumulative counter. `process_joules` is the slice attributed to the
/// monitored process(es) by GPU-utilization share — an estimate, not a
/// per-process measurement (NVML exposes no such counter). See module docs.
#[derive(Serialize, Deserialize, Debug, Clone, Copy, Default, PartialEq)]
pub struct GpuEnergy {
    /// Total board energy over the interval — all processes, all draw.
    pub package_joules: f64,
    /// Estimated slice for the monitored process(es) by GPU-util share.
    pub process_joules: f64,
}

/// Split whole-board energy (joules over the interval) into total and the slice
/// attributed to the monitored process(es) by summed GPU-util share (clamped).
/// `package_joules` covers every process on the board; only `process_joules` is
/// scoped to our pids — via `proc_utils`, which NVML reports per-pid, so
/// other users' load lowers our util share rather than being charged to us.
#[cfg(any(feature = "gpu", test))]
pub(crate) fn attribute_gpu_energy(package_joules: f64, proc_utils: &[u32]) -> GpuEnergy {
    let util_share = (proc_utils.iter().map(|&u| u as f64 / 100.0).sum::<f64>()).clamp(0.0, 1.0);
    GpuEnergy {
        package_joules,
        process_joules: package_joules * util_share + 0.0, // `+ 0.0` normalizes -0.0
    }
}

/// Complete GPU monitoring data for a single process
#[derive(Serialize, Deserialize, Debug, Clone, Default)]
pub struct GpuMetrics {
    /// System-wide GPU metrics for each device
    pub system_metrics: Vec<SystemGpuMetrics>,
    /// Process-specific data for the monitored process(es)
    pub process_data: Vec<ProcessGpuData>,
    /// Whether per-process data is available
    pub has_process_data: bool,
    /// Method used for process data collection
    pub collection_method: String,
    /// Board energy this interval + attributed slice. Present only when NVML's
    /// `total_energy_consumption` counter is available (Volta+, ~2017 on).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub gpu_energy: Option<GpuEnergy>,
}

/// GPU monitoring summary
#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct GpuSummary {
    /// Whether GPU monitoring was enabled
    pub enabled: bool,
    /// Number of GPU devices detected
    pub device_count: u32,
    /// Total GPU memory across all devices (GB)
    pub total_memory_gb: f64,
    /// Peak used GPU memory observed across all devices (GB)
    pub peak_used_memory_gb: f64,
    /// Maximum system-wide GPU utilization observed (%)
    pub max_system_gpu_utilization: u32,
    /// Maximum process-specific GPU utilization observed (%)
    pub max_process_gpu_utilization: Option<u32>,
    /// Total process GPU memory usage (GB)
    pub process_memory_usage_gb: f64,
    /// Maximum GPU temperature observed across all devices (degrees Celsius).
    /// `None` when the driver did not report temperature for any sample.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub max_temperature_c: Option<u32>,
}

impl Default for GpuSummary {
    fn default() -> Self {
        Self {
            enabled: false,
            device_count: 0,
            total_memory_gb: 0.0,
            peak_used_memory_gb: 0.0,
            max_system_gpu_utilization: 0,
            max_process_gpu_utilization: None,
            process_memory_usage_gb: 0.0,
            max_temperature_c: None,
        }
    }
}

/// Main GPU monitoring interface
#[derive(Debug)]
pub struct GpuMonitor {
    #[cfg(feature = "gpu")]
    nvml: Option<Nvml>,
    #[cfg(feature = "gpu")]
    device_count: u32,
    enabled: bool,
    /// Last per-process utilization timestamp seen per device (NVML µs), so each
    /// sample only reads samples newer than the previous one. Same `RefCell`
    /// rationale as `prev_energy_mj`.
    #[cfg(feature = "gpu")]
    last_util_ts: std::cell::RefCell<HashMap<u32, u64>>,
    /// Previous cumulative energy per device (millijoules) for delta computation.
    /// `RefCell` because `sample_metrics` takes `&self`; single-threaded sampling
    /// so no contention. ponytail: RefCell over threading the state through every
    /// caller — swap to `&mut self` only if sampling ever goes concurrent.
    #[cfg(feature = "gpu")]
    prev_energy_mj: std::cell::RefCell<std::collections::HashMap<u32, u64>>,
}

impl Default for GpuMonitor {
    fn default() -> Self {
        Self::disabled()
    }
}

impl GpuMonitor {
    /// A monitor that collects nothing and loads no NVIDIA library.
    pub fn disabled() -> Self {
        Self {
            #[cfg(feature = "gpu")]
            nvml: None,
            #[cfg(feature = "gpu")]
            device_count: 0,
            enabled: false,
            #[cfg(feature = "gpu")]
            last_util_ts: Default::default(),
            #[cfg(feature = "gpu")]
            prev_energy_mj: Default::default(),
        }
    }

    /// Load NVML and enable monitoring if an NVIDIA GPU is present. Falls back
    /// to [`Self::disabled`] (logged) when the build lacks the `gpu` feature,
    /// the driver library is missing, or no device is found.
    pub fn new() -> Self {
        #[cfg(feature = "gpu")]
        match Self::initialize_nvml() {
            Ok((nvml, device_count)) => {
                log::info!("GPU monitoring enabled: {} device(s)", device_count);
                return Self {
                    nvml: Some(nvml),
                    device_count,
                    enabled: true,
                    ..Self::disabled()
                };
            }
            Err(e) => log::info!("GPU monitoring disabled: {}", e),
        }
        Self::disabled()
    }

    /// Initialize NVML and get device count
    #[cfg(feature = "gpu")]
    fn initialize_nvml() -> Result<(Nvml, u32), String> {
        let nvml = Nvml::init().map_err(|e| format!("NVML initialization failed: {:?}", e))?;

        let device_count = nvml
            .device_count()
            .map_err(|e| format!("Failed to get device count: {:?}", e))?;

        if device_count == 0 {
            return Err("No NVIDIA GPUs found".to_string());
        }

        Ok((nvml, device_count))
    }

    /// Check if GPU monitoring is enabled
    pub fn is_enabled(&self) -> bool {
        self.enabled
    }

    /// Get the number of available GPU devices
    pub fn device_count(&self) -> u32 {
        #[cfg(feature = "gpu")]
        {
            self.device_count
        }
        #[cfg(not(feature = "gpu"))]
        {
            0
        }
    }

    /// Whole-board energy since the previous call, in joules, summed across
    /// devices. Reads NVML's cumulative `total_energy_consumption` counter and
    /// advances the per-device baseline — so call it **exactly once per emitted
    /// sample** (`sample_metrics` may run several times per tick and must not
    /// touch the counter). Returns `None` if no device exposes the counter
    /// (pre-Volta) or the GPU is disabled.
    pub fn board_energy_delta_joules(&self) -> Option<f64> {
        #[cfg(feature = "gpu")]
        {
            let nvml = self.nvml.as_ref()?;
            let mut delta_mj: u64 = 0;
            let mut seen = false;
            let mut prev = self.prev_energy_mj.borrow_mut();
            for device_index in 0..self.device_count {
                if let Ok(device) = nvml.device_by_index(device_index) {
                    if let Ok(cur_mj) = device.total_energy_consumption() {
                        seen = true;
                        // Cumulative since driver reload; monotonic, so a decrease
                        // only means the driver reset — treat as 0.
                        if let Some(&last) = prev.get(&device_index) {
                            delta_mj += cur_mj.saturating_sub(last);
                        }
                        prev.insert(device_index, cur_mj);
                    }
                }
            }
            seen.then(|| delta_mj as f64 / 1000.0)
        }
        #[cfg(not(feature = "gpu"))]
        {
            None
        }
    }

    /// Sample GPU metrics for specific processes
    pub fn sample_metrics(&self, process_pids: &[u32]) -> GpuMetrics {
        #[cfg(feature = "gpu")]
        {
            if !self.enabled {
                return GpuMetrics::default();
            }

            let mut system_metrics = Vec::new();
            let mut process_data = Vec::new();
            let mut has_process_data = false;
            let mut collection_method = "none".to_string();

            // Collect system-wide metrics using NVML if available
            if let Some(ref nvml) = self.nvml {
                for device_index in 0..self.device_count {
                    if let Ok(device) = nvml.device_by_index(device_index) {
                        let system_gpu_metrics = SystemGpuMetrics {
                            device_index,
                            name: device
                                .name()
                                .unwrap_or_else(|_| format!("GPU {}", device_index)),
                            system_utilization_gpu: device.utilization_rates().ok().map(|u| u.gpu),
                            system_utilization_memory: device
                                .utilization_rates()
                                .ok()
                                .map(|u| u.memory),
                            memory_total: device.memory_info().ok().map(|m| m.total),
                            memory_used: device.memory_info().ok().map(|m| m.used),
                            memory_free: device.memory_info().ok().map(|m| m.free),
                            temperature: device
                                .temperature(
                                    nvml_wrapper::enum_wrappers::device::TemperatureSensor::Gpu,
                                )
                                .ok(),
                            power_usage: device.power_usage().ok(),
                        };
                        system_metrics.push(system_gpu_metrics);
                    }
                }
            }

            if !process_pids.is_empty() {
                let process_utils = self.get_process_utilizations(process_pids);
                let process_memory = self.get_process_memory_usage(process_pids);
                for &pid in process_pids {
                    let util = process_utils.get(&pid).copied();
                    let memory_usage = process_memory.get(&pid).copied();
                    if util.is_none() && memory_usage.is_none() {
                        continue;
                    }
                    has_process_data = true;
                    if util.is_some() {
                        collection_method = "nvml".to_string();
                    } else if collection_method == "none" {
                        collection_method = "nvml-memory-only".to_string();
                    }
                    process_data.push(ProcessGpuData {
                        pid,
                        gpu_utilization: util.map(|(sm, _)| sm),
                        memory_usage,
                        memory_utilization_pct: util.map(|(_, mem)| mem),
                    });
                }
            }

            GpuMetrics {
                system_metrics,
                process_data,
                has_process_data,
                collection_method,
                // Energy is read once per tick via `board_energy_delta_joules`
                // (this method is called several times per tick); the caller
                // attaches it. See ProcessMonitor sampling.
                gpu_energy: None,
            }
        }

        #[cfg(not(feature = "gpu"))]
        {
            let _ = process_pids; // Suppress unused warning
            GpuMetrics::default()
        }
    }

    /// Per-process SM and memory utilization (%) from NVML, newest sample per
    /// pid since the previous call: pid -> (sm, mem). Pids with no new sample
    /// (idle on the GPU since last time) are absent. Needs Maxwell or newer;
    /// older devices simply return nothing.
    #[cfg(feature = "gpu")]
    fn get_process_utilizations(&self, process_pids: &[u32]) -> HashMap<u32, (u32, u32)> {
        let mut newest: HashMap<u32, (u64, u32, u32)> = HashMap::new();
        let Some(ref nvml) = self.nvml else {
            return HashMap::new();
        };
        let mut last_ts = self.last_util_ts.borrow_mut();
        for device_index in 0..self.device_count {
            let Ok(device) = nvml.device_by_index(device_index) else {
                continue;
            };
            let since = last_ts.get(&device_index).copied();
            // NotFound just means no new samples since `since`.
            let Ok(samples) = device.process_utilization_stats(since) else {
                continue;
            };
            for s in samples {
                last_ts
                    .entry(device_index)
                    .and_modify(|t| *t = (*t).max(s.timestamp))
                    .or_insert(s.timestamp);
                if process_pids.contains(&s.pid)
                    && newest.get(&s.pid).is_none_or(|&(t, _, _)| s.timestamp > t)
                {
                    newest.insert(s.pid, (s.timestamp, s.sm_util, s.mem_util));
                }
            }
        }
        newest
            .into_iter()
            .map(|(pid, (_, sm, mem))| (pid, (sm, mem)))
            .collect()
    }

    /// Get process GPU memory usage from NVML (compute + graphics contexts)
    #[cfg(feature = "gpu")]
    fn get_process_memory_usage(&self, process_pids: &[u32]) -> HashMap<u32, u64> {
        let mut result = HashMap::new();

        // Try NVML first
        if let Some(ref nvml) = self.nvml {
            for device_index in 0..self.device_count {
                if let Ok(device) = nvml.device_by_index(device_index) {
                    // Get compute processes
                    if let Ok(processes) = device.running_compute_processes() {
                        for process in processes {
                            if process_pids.contains(&process.pid) {
                                if let UsedGpuMemory::Used(bytes) = process.used_gpu_memory {
                                    result.insert(process.pid, bytes);
                                }
                            }
                        }
                    }

                    // Get graphics processes too
                    if let Ok(processes) = device.running_graphics_processes() {
                        for process in processes {
                            if process_pids.contains(&process.pid) {
                                if let UsedGpuMemory::Used(bytes) = process.used_gpu_memory {
                                    // If we already have data from compute processes, sum them
                                    let current = result.get(&process.pid).unwrap_or(&0);
                                    result.insert(process.pid, current + bytes);
                                }
                            }
                        }
                    }
                }
            }
        }

        result
    }

    /// Get a summary of the current GPU monitoring session
    pub fn get_summary(&self, metrics_history: &[GpuMetrics]) -> GpuSummary {
        if !self.enabled || metrics_history.is_empty() {
            return GpuSummary::default();
        }
        let mut summary = summarize_samples(metrics_history);
        // Live path: trust the driver's device count over what the samples show.
        summary.device_count = self.device_count();
        summary
    }
}

/// Summarise already-collected GPU samples without consulting NVML.
///
/// `GpuMonitor::get_summary` requires a live, initialised NVML handle, which is
/// wrong when rebuilding a summary from a stored JSONL run: `denet stats` is
/// routinely executed on a login node or laptop that has no GPU, and gating on
/// live NVML silently discarded GPU data that was present in the file. This
/// function derives everything, including the device count, from the samples.
pub fn summarize_samples(metrics_history: &[GpuMetrics]) -> GpuSummary {
    if metrics_history.is_empty() {
        return GpuSummary::default();
    }
    {
        let mut max_system_gpu_utilization = 0;
        let mut max_process_gpu_utilization = None;
        let mut total_memory_gb = 0.0;
        let mut peak_used_memory_gb = 0.0;
        let mut max_process_memory = 0;
        let mut max_temperature_c: Option<u32> = None;
        let mut device_count = 0u32;

        for metrics in metrics_history {
            device_count = device_count.max(metrics.system_metrics.len() as u32);
            // Track maximum system utilization
            for system_metric in &metrics.system_metrics {
                if let Some(util) = system_metric.system_utilization_gpu {
                    max_system_gpu_utilization = max_system_gpu_utilization.max(util);
                }
                if let Some(total_mem) = system_metric.memory_total {
                    total_memory_gb = (total_mem as f64) / (1024.0 * 1024.0 * 1024.0);
                }
                if let Some(used_mem) = system_metric.memory_used {
                    let used_gb = (used_mem as f64) / (1024.0 * 1024.0 * 1024.0);
                    if used_gb > peak_used_memory_gb {
                        peak_used_memory_gb = used_gb;
                    }
                }
                if let Some(temp) = system_metric.temperature {
                    max_temperature_c = Some(max_temperature_c.unwrap_or(0).max(temp));
                }
            }

            // Track maximum process utilization and memory
            for process_data in &metrics.process_data {
                if let Some(util) = process_data.gpu_utilization {
                    max_process_gpu_utilization =
                        Some(max_process_gpu_utilization.unwrap_or(0).max(util));
                }
                if let Some(mem) = process_data.memory_usage {
                    max_process_memory = max_process_memory.max(mem);
                }
            }
        }

        GpuSummary {
            enabled: true,
            device_count,
            total_memory_gb,
            peak_used_memory_gb,
            max_system_gpu_utilization,
            max_process_gpu_utilization,
            process_memory_usage_gb: (max_process_memory as f64) / (1024.0 * 1024.0 * 1024.0),
            max_temperature_c,
        }
    }
}

impl GpuMetrics {
    /// Check if this metric sample has process-specific GPU utilization data
    pub fn has_process_utilization(&self) -> bool {
        self.process_data
            .iter()
            .any(|p| p.gpu_utilization.is_some())
    }

    /// Get the maximum process GPU utilization from this sample
    pub fn max_process_utilization(&self) -> Option<u32> {
        self.process_data
            .iter()
            .filter_map(|p| p.gpu_utilization)
            .max()
    }

    /// Get total process GPU memory usage in bytes
    pub fn total_process_memory_usage(&self) -> u64 {
        self.process_data
            .iter()
            .filter_map(|p| p.memory_usage)
            .sum()
    }

    /// Get maximum system-wide GPU utilization
    pub fn max_system_utilization(&self) -> Option<u32> {
        self.system_metrics
            .iter()
            .filter_map(|s| s.system_utilization_gpu)
            .max()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Regression test: rebuilding a summary from stored samples must not
    /// depend on a live NVML handle. `denet stats run.jsonl` is routinely run
    /// on a machine with no GPU, and the summary previously came back empty,
    /// silently discarding GPU data that was present in the file.
    #[test]
    fn test_summarize_samples_without_live_nvml() {
        let sample = GpuMetrics {
            system_metrics: vec![SystemGpuMetrics {
                device_index: 0,
                name: "test-device".to_string(),
                system_utilization_gpu: Some(73),
                system_utilization_memory: Some(40),
                memory_total: Some(8 * 1024 * 1024 * 1024),
                memory_used: Some(2 * 1024 * 1024 * 1024),
                memory_free: Some(6 * 1024 * 1024 * 1024),
                temperature: Some(61),
                power_usage: Some(120),
            }],
            process_data: vec![],
            has_process_data: false,
            collection_method: "test".to_string(),
            gpu_energy: None,
        };

        let summary = summarize_samples(std::slice::from_ref(&sample));

        assert!(
            summary.enabled,
            "summary must be enabled from samples alone"
        );
        assert_eq!(
            summary.device_count, 1,
            "device count comes from the samples"
        );
        assert_eq!(summary.max_system_gpu_utilization, 73);
        assert_eq!(summary.max_temperature_c, Some(61));
        assert!((summary.peak_used_memory_gb - 2.0).abs() < 1e-6);
        assert!((summary.total_memory_gb - 8.0).abs() < 1e-6);
    }

    #[test]
    fn test_summarize_samples_empty_is_disabled() {
        assert!(!summarize_samples(&[]).enabled);
    }

    #[test]
    fn test_gpu_monitor_creation() {
        let monitor = GpuMonitor::new();
        // Should not panic regardless of GPU availability
        let _device_count = monitor.device_count();
        let _enabled = monitor.is_enabled();
    }

    /// GPU monitoring is opt-in: the default monitor must not load NVML or
    /// collect anything (it costs tens of MB of memory per run).
    #[test]
    fn test_default_monitor_is_disabled_and_inert() {
        for monitor in [GpuMonitor::default(), GpuMonitor::disabled()] {
            assert!(!monitor.is_enabled());
            assert_eq!(monitor.device_count(), 0);
            let m = monitor.sample_metrics(&[std::process::id()]);
            assert!(m.system_metrics.is_empty() && m.process_data.is_empty());
            assert!(monitor.board_energy_delta_joules().is_none());
            assert!(!monitor.get_summary(&[m]).enabled);
        }
    }

    #[test]
    fn test_gpu_energy_attribution() {
        // 5 J board energy; one proc at 40% util → 2 J attributed.
        let e = attribute_gpu_energy(5.0, &[40]);
        assert!((e.package_joules - 5.0).abs() < 1e-9);
        assert!((e.process_joules - 2.0).abs() < 1e-9);

        // Multiple procs sum; over-100% clamps to the whole board.
        let e = attribute_gpu_energy(5.0, &[80, 70]);
        assert!((e.process_joules - 5.0).abs() < 1e-9);

        // No per-process util → total known, nothing attributed.
        let e = attribute_gpu_energy(5.0, &[]);
        assert_eq!(e.process_joules, 0.0);
        assert!((e.package_joules - 5.0).abs() < 1e-9);
    }

    #[test]
    fn test_gpu_metrics_sampling() {
        let monitor = GpuMonitor::new();
        let metrics = monitor.sample_metrics(&[std::process::id()]);

        // Should return valid metrics structure even if no GPU
        assert!(metrics.system_metrics.len() <= monitor.device_count() as usize);
    }

    #[test]
    fn test_gpu_summary() {
        let monitor = GpuMonitor::new();
        let metrics = vec![monitor.sample_metrics(&[std::process::id()])];
        let summary = monitor.get_summary(&metrics);

        // Should return valid summary
        assert_eq!(summary.enabled, monitor.is_enabled());
        assert_eq!(summary.device_count, monitor.device_count());
        assert!(summary.total_memory_gb >= 0.0);
    }

    #[test]
    fn test_gpu_metrics_methods() {
        let metrics = GpuMetrics::default();

        assert!(!metrics.has_process_utilization());
        assert_eq!(metrics.max_process_utilization(), None);
        assert_eq!(metrics.total_process_memory_usage(), 0);
        assert_eq!(metrics.max_system_utilization(), None);
    }

    #[test]
    fn test_gpu_summary_default() {
        let summary = GpuSummary::default();

        assert!(!summary.enabled);
        assert_eq!(summary.device_count, 0);
        assert_eq!(summary.total_memory_gb, 0.0);
        assert_eq!(summary.max_process_gpu_utilization, None);
    }
}
