//! GPU monitoring module with per-process utilization support
//!
//! This module provides GPU metrics collection for NVIDIA GPUs using NVML and nvidia-smi.
//! It separates system-wide metrics from process-specific metrics to provide accurate
//! monitoring for individual processes.
//!
//! # Architecture
//!
//! - Uses NVML for system-wide GPU metrics (temperature, memory, etc.)
//! - Falls back to nvidia-smi for per-process GPU utilization when NVML doesn't support it
//! - Provides graceful fallback when GPU monitoring is unavailable
//!
//! # Per-Process vs System-Wide
//!
//! - System-wide: Overall GPU utilization, total memory usage, temperature
//! - Process-specific: GPU utilization by specific PID, process GPU memory usage
//!
//! The key insight is that NVML's device.utilization_rates() returns system-wide
//! utilization, not per-process. For true per-process monitoring, we need nvidia-smi.

#[cfg(feature = "gpu")]
use nvml_wrapper::enums::device::UsedGpuMemory;
#[cfg(feature = "gpu")]
use nvml_wrapper::Nvml;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::process::Command;

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
    pub memory_utilization: Option<u32>,
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
    nvidia_smi_available: bool,
}

impl Default for GpuMonitor {
    fn default() -> Self {
        Self::new()
    }
}

impl GpuMonitor {
    /// Create a new GPU monitor with automatic initialization
    pub fn new() -> Self {
        #[cfg(feature = "gpu")]
        {
            let nvidia_smi_available = Self::check_nvidia_smi_available();

            match Self::initialize_nvml() {
                Ok((nvml, device_count)) => {
                    log::info!(
                        "GPU monitoring enabled: {} device(s), nvidia-smi: {}",
                        device_count,
                        nvidia_smi_available
                    );
                    Self {
                        nvml: Some(nvml),
                        device_count,
                        enabled: true,
                        nvidia_smi_available,
                    }
                }
                Err(e) => {
                    if nvidia_smi_available {
                        log::info!("NVML failed but nvidia-smi available: {}", e);
                        Self {
                            nvml: None,
                            device_count: Self::get_device_count_nvidia_smi(),
                            enabled: true,
                            nvidia_smi_available: true,
                        }
                    } else {
                        log::info!("GPU monitoring disabled: {}", e);
                        Self {
                            nvml: None,
                            device_count: 0,
                            enabled: false,
                            nvidia_smi_available: false,
                        }
                    }
                }
            }
        }

        #[cfg(not(feature = "gpu"))]
        {
            Self {
                enabled: false,
                nvidia_smi_available: false,
            }
        }
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

    /// Check if nvidia-smi is available
    #[cfg(feature = "gpu")]
    fn check_nvidia_smi_available() -> bool {
        Command::new("nvidia-smi")
            .arg("--version")
            .output()
            .map(|output| output.status.success())
            .unwrap_or(false)
    }

    /// Get device count using nvidia-smi
    #[cfg(feature = "gpu")]
    fn get_device_count_nvidia_smi() -> u32 {
        let output = Command::new("nvidia-smi").args(&["-L"]).output();

        if let Ok(output) = output {
            if output.status.success() {
                let output_str = String::from_utf8_lossy(&output.stdout);
                return output_str
                    .lines()
                    .filter(|line| line.contains("GPU "))
                    .count() as u32;
            }
        }
        0
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

            // Collect per-process data using nvidia-smi if available
            if self.nvidia_smi_available && !process_pids.is_empty() {
                let process_utils = self.get_process_utilizations_nvidia_smi(process_pids);
                let process_memory = self.get_process_memory_usage(process_pids);

                for &pid in process_pids {
                    let gpu_utilization = process_utils.get(&pid).copied();
                    let memory_usage = process_memory.get(&pid).copied();

                    if gpu_utilization.is_some() || memory_usage.is_some() {
                        has_process_data = true;
                        collection_method = "nvidia-smi".to_string();

                        process_data.push(ProcessGpuData {
                            pid,
                            gpu_utilization,
                            memory_usage,
                            memory_utilization: None, // Could be calculated if needed
                        });
                    }
                }
            }

            // Fallback: get process memory from NVML if nvidia-smi failed
            if !has_process_data && self.nvml.is_some() {
                let process_memory = self.get_process_memory_usage(process_pids);
                for &pid in process_pids {
                    if let Some(memory_usage) = process_memory.get(&pid).copied() {
                        has_process_data = true;
                        collection_method = "nvml-memory-only".to_string();

                        process_data.push(ProcessGpuData {
                            pid,
                            gpu_utilization: None,
                            memory_usage: Some(memory_usage),
                            memory_utilization: None,
                        });
                    }
                }
            }

            GpuMetrics {
                system_metrics,
                process_data,
                has_process_data,
                collection_method,
            }
        }

        #[cfg(not(feature = "gpu"))]
        {
            let _ = process_pids; // Suppress unused warning
            GpuMetrics::default()
        }
    }

    /// Get per-process GPU utilization using nvidia-smi
    #[cfg(feature = "gpu")]
    fn get_process_utilizations_nvidia_smi(&self, process_pids: &[u32]) -> HashMap<u32, u32> {
        let mut result = HashMap::new();

        // Use nvidia-smi pmon to get per-process utilization
        let output = Command::new("nvidia-smi")
            .args(&["pmon", "-c", "1", "-s", "u"])
            .output();

        if let Ok(output) = output {
            if output.status.success() {
                if let Ok(output_str) = String::from_utf8(output.stdout) {
                    for line in output_str.lines() {
                        let line = line.trim();

                        // Skip headers and comments
                        if line.starts_with('#') || line.is_empty() {
                            continue;
                        }

                        let fields: Vec<&str> = line.split_whitespace().collect();
                        if fields.len() >= 4 {
                            // Format: gpu pid type sm_util mem_util enc_util dec_util command
                            if let Ok(pid) = fields[1].parse::<u32>() {
                                if process_pids.contains(&pid) {
                                    // Parse SM utilization (compute utilization)
                                    if let Ok(utilization) = fields[3].parse::<u32>() {
                                        result.insert(pid, utilization);
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }

        result
    }

    /// Get process GPU memory usage (works with both NVML and nvidia-smi)
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

        let mut max_system_gpu_utilization = 0;
        let mut max_process_gpu_utilization = None;
        let mut total_memory_gb = 0.0;
        let mut peak_used_memory_gb = 0.0;
        let mut max_process_memory = 0;

        for metrics in metrics_history {
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
            device_count: self.device_count(),
            total_memory_gb,
            peak_used_memory_gb,
            max_system_gpu_utilization,
            max_process_gpu_utilization,
            process_memory_usage_gb: (max_process_memory as f64) / (1024.0 * 1024.0 * 1024.0),
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

    #[test]
    fn test_gpu_monitor_creation() {
        let monitor = GpuMonitor::new();
        // Should not panic regardless of GPU availability
        let _device_count = monitor.device_count();
        let _enabled = monitor.is_enabled();
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
