//! Core denet functionality without Python dependencies
//!
//! This module contains the pure Rust API for process monitoring,
//! separated from Python bindings for better modularity.

use crate::config::{DenetConfig, MonitorConfig};
use crate::error::{DenetError, Result};
use crate::monitor::metrics::{Metrics, ProcessMetadata};

use std::process::{Child, Command, Stdio};
use std::thread;
use std::time::{Duration, Instant};
use sysinfo::{Pid, ProcessRefreshKind, ProcessesToUpdate, System};

/// Core process monitor without Python dependencies
pub struct ProcessMonitor {
    pid: usize,
    config: MonitorConfig,
    metadata: Option<ProcessMetadata>,
    child_process: Option<Child>,
    start_time: Instant,
    last_sample_time: Instant,
    adaptive_interval: Duration,
}

impl ProcessMonitor {
    /// Create a new process monitor for a command
    pub fn new_with_config(cmd: Vec<String>, config: MonitorConfig) -> Result<Self> {
        config.validate()?;

        if cmd.is_empty() {
            return Err(DenetError::InvalidConfiguration(
                "Command cannot be empty".to_string(),
            ));
        }

        let mut command = Command::new(&cmd[0]);
        command.args(&cmd[1..]);

        // Configure process to be easily monitored
        command.stdout(Stdio::piped());
        command.stderr(Stdio::piped());
        command.stdin(Stdio::null());

        let child = command.spawn()?;
        let pid = child.id() as usize;

        let metadata = ProcessMetadata::new(pid, cmd.clone(), cmd[0].clone());
        let now = Instant::now();

        let adaptive_interval = config.base_interval;
        Ok(Self {
            pid,
            config,
            metadata: Some(metadata),
            child_process: Some(child),
            start_time: now,
            last_sample_time: now,
            adaptive_interval,
        })
    }

    /// Create a process monitor for an existing PID
    pub fn from_pid_with_config(pid: usize, config: MonitorConfig) -> Result<Self> {
        config.validate()?;

        // Verify the process exists
        if !Self::process_exists(pid) {
            return Err(DenetError::ProcessNotFound(pid));
        }

        let now = Instant::now();

        let adaptive_interval = config.base_interval;
        Ok(Self {
            pid,
            config,
            metadata: None, // Will be populated on first sample
            child_process: None,
            start_time: now,
            last_sample_time: now,
            adaptive_interval,
        })
    }

    /// Check if the monitored process is still running
    pub fn is_running(&mut self) -> bool {
        if let Some(ref mut child) = self.child_process {
            // For spawned processes, check if child is still running
            match child.try_wait() {
                Ok(Some(_)) => false, // Process has exited
                Ok(None) => true,     // Process is still running
                Err(_) => false,      // Error checking status
            }
        } else {
            // For existing processes, check if PID still exists
            Self::process_exists(self.pid)
        }
    }

    /// Get the PID of the monitored process
    pub fn get_pid(&self) -> usize {
        self.pid
    }

    /// Get process metadata
    pub fn get_metadata(&mut self) -> Option<ProcessMetadata> {
        if self.metadata.is_none() {
            self.metadata = self.collect_metadata();
        }
        self.metadata.clone()
    }

    /// Sample current metrics
    pub fn sample_metrics(&mut self) -> Option<Metrics> {
        if !self.is_running() {
            return None;
        }

        let now = Instant::now();
        let sample_result = self.collect_metrics();

        // Update adaptive interval based on sampling success
        self.update_adaptive_interval(sample_result.is_some(), now);
        self.last_sample_time = now;

        sample_result
    }

    /// Get the current adaptive sampling interval
    pub fn adaptive_interval(&self) -> Duration {
        self.adaptive_interval
    }

    /// Check if a process exists
    fn process_exists(pid: usize) -> bool {
        #[cfg(target_os = "linux")]
        {
            std::path::Path::new(&format!("/proc/{}", pid)).exists()
        }

        #[cfg(not(target_os = "linux"))]
        {
            // For non-Linux platforms, use sysinfo as fallback
            let mut system = System::new();
            system.refresh_processes_specifics(
                ProcessesToUpdate::Some(&[Pid::from(pid)]),
                true,
                ProcessRefreshKind::nothing(),
            );
            system.process(Pid::from(pid)).is_some()
        }
    }

    /// Collect process metadata
    fn collect_metadata(&self) -> Option<ProcessMetadata> {
        let mut system = System::new();
        system.refresh_processes_specifics(
            ProcessesToUpdate::Some(&[Pid::from(self.pid)]),
            true,
            ProcessRefreshKind::everything(),
        );

        if let Some(process) = system.process(Pid::from(self.pid)) {
            let cmd: Vec<String> = process
                .cmd()
                .iter()
                .map(|s| s.to_string_lossy().to_string())
                .collect();
            let executable = process
                .exe()
                .map(|p| p.to_string_lossy().to_string())
                .unwrap_or_default();
            Some(ProcessMetadata::new(self.pid, cmd, executable))
        } else {
            None
        }
    }

    /// Collect current metrics for the process
    fn collect_metrics(&self) -> Option<Metrics> {
        let mut system = System::new();
        system.refresh_processes_specifics(
            ProcessesToUpdate::Some(&[Pid::from(self.pid)]),
            true,
            ProcessRefreshKind::everything(),
        );

        if let Some(process) = system.process(Pid::from(self.pid)) {
            let mut metrics = Metrics::new();

            // Basic metrics from sysinfo
            metrics.cpu_usage = process.cpu_usage();
            metrics.mem_rss_kb = process.memory() / 1024; // Convert to KB
            metrics.mem_vms_kb = process.virtual_memory() / 1024; // Convert to KB
            metrics.uptime_secs = self.start_time.elapsed().as_secs();

            // Platform-specific metrics
            #[cfg(target_os = "linux")]
            {
                // Use our CPU sampler for more accurate CPU measurements
                if let Ok(cpu_usage) =
                    crate::cpu_sampler::CpuSampler::get_cpu_usage_static(self.pid)
                {
                    metrics.cpu_usage = cpu_usage;
                }

                // Get thread count
                metrics.thread_count = self.get_thread_count();

                // Get I/O metrics
                if let Ok((disk_read, disk_write)) = self.get_io_metrics() {
                    metrics.disk_read_bytes = disk_read;
                    metrics.disk_write_bytes = disk_write;
                }
            }

            #[cfg(not(target_os = "linux"))]
            {
                metrics.thread_count = 1; // Default for non-Linux
                                          // TODO: Implement platform-specific I/O metrics
            }

            Some(metrics)
        } else {
            None
        }
    }

    /// Get thread count for the process (Linux-specific)
    #[cfg(target_os = "linux")]
    fn get_thread_count(&self) -> usize {
        let task_dir = format!("/proc/{}/task", self.pid);
        match std::fs::read_dir(task_dir) {
            Ok(entries) => entries.count(),
            Err(_) => 0,
        }
    }

    /// Get I/O metrics for the process (Linux-specific)
    #[cfg(target_os = "linux")]
    fn get_io_metrics(&self) -> Result<(u64, u64)> {
        let io_path = format!("/proc/{}/io", self.pid);
        let contents = std::fs::read_to_string(io_path)?;

        let mut read_bytes = 0;
        let mut write_bytes = 0;

        for line in contents.lines() {
            if let Some(value) = line.strip_prefix("read_bytes: ") {
                read_bytes = value.parse().unwrap_or(0);
            } else if let Some(value) = line.strip_prefix("write_bytes: ") {
                write_bytes = value.parse().unwrap_or(0);
            }
        }

        Ok((read_bytes, write_bytes))
    }

    /// Update the adaptive sampling interval based on recent sampling results
    fn update_adaptive_interval(&mut self, sample_success: bool, now: Instant) {
        let time_since_last = now.duration_since(self.last_sample_time);

        if sample_success {
            // Successful sample - we can potentially increase frequency (decrease interval)
            if time_since_last < self.adaptive_interval * 2 {
                self.adaptive_interval =
                    (self.adaptive_interval * 9 / 10).max(self.config.base_interval);
            }
        } else {
            // Failed sample - back off to reduce system load
            self.adaptive_interval =
                (self.adaptive_interval * 11 / 10).min(self.config.max_interval);
        }
    }
}

/// Run a simple monitoring loop
pub fn run_monitor(cmd: Vec<String>, config: DenetConfig) -> Result<()> {
    let monitor_config = config.monitor.clone();
    let mut monitor = ProcessMonitor::new_with_config(cmd, monitor_config)?;

    let start_time = Instant::now();

    while monitor.is_running() {
        if let Some(metrics) = monitor.sample_metrics() {
            let json = serde_json::to_string(&metrics)?;
            if !config.output.quiet {
                println!("{}", json);
            }
        }

        // Check max duration
        if let Some(max_duration) = config.monitor.max_duration {
            if start_time.elapsed() >= max_duration {
                break;
            }
        }

        thread::sleep(monitor.adaptive_interval());
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;

    #[test]
    fn test_monitor_config_validation() {
        let config = MonitorConfig::builder()
            .base_interval_ms(100)
            .max_interval_ms(50) // Invalid: max < base
            .build();

        assert!(config.is_err());
    }

    #[test]
    fn test_monitor_config_builder() -> Result<()> {
        let config = MonitorConfig::builder()
            .base_interval_ms(200)
            .max_interval_ms(2000)
            .since_process_start(true)
            .include_children(false)
            .build()?;

        assert_eq!(config.base_interval, Duration::from_millis(200));
        assert_eq!(config.max_interval, Duration::from_millis(2000));
        assert_eq!(config.since_process_start, true);
        assert_eq!(config.include_children, false);

        Ok(())
    }
}
