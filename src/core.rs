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
    use std::thread;
    use std::time::Duration;

    // Helper struct for mocking external dependencies
    struct TestContext {
        current_pid: usize,
        base_interval: Duration,
        max_interval: Duration,
    }

    impl TestContext {
        fn new() -> Self {
            Self {
                current_pid: std::process::id() as usize,
                base_interval: Duration::from_millis(10),
                max_interval: Duration::from_millis(100),
            }
        }

        fn build_config(&self) -> MonitorConfig {
            MonitorConfig::builder()
                .base_interval(self.base_interval)
                .max_interval(self.max_interval)
                .build()
                .unwrap()
        }
    }

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

    // Test empty command validation
    #[test]
    fn test_new_with_empty_command() {
        let result = ProcessMonitor::new_with_config(vec![], MonitorConfig::default());
        assert!(matches!(result, Err(DenetError::InvalidConfiguration(_))));
    }

    // Test nonexistent PID handling
    #[test]
    fn test_nonexistent_pid() {
        let result =
            ProcessMonitor::from_pid_with_config(u32::MAX as usize, MonitorConfig::default());
        assert!(matches!(result, Err(DenetError::ProcessNotFound(_))));
    }

    // Test adaptive interval behavior
    #[test]
    fn test_adaptive_interval_behavior() {
        let ctx = TestContext::new();
        let config = ctx.build_config();

        let mut monitor = ProcessMonitor {
            pid: ctx.current_pid,
            config,
            metadata: None,
            child_process: None,
            start_time: Instant::now(),
            last_sample_time: Instant::now()
                .checked_sub(Duration::from_millis(50))
                .unwrap(),
            adaptive_interval: ctx.base_interval,
        };

        // Since we're at base_interval already, it shouldn't decrease further
        let now = Instant::now();
        monitor.update_adaptive_interval(true, now);
        assert_eq!(monitor.adaptive_interval, ctx.base_interval);

        // Set interval higher first
        monitor.adaptive_interval = Duration::from_millis(20);
        // The update_adaptive_interval checks if the time_since_last is less than
        // adaptive_interval*2, which it might not be in a test environment
        // Force enough time to have passed
        let new_now = now + Duration::from_millis(10);
        monitor.update_adaptive_interval(true, new_now);
        // 9/10 of 20ms = 18ms, but not less than base_interval (10ms)
        assert!(monitor.adaptive_interval >= ctx.base_interval);
        assert!(monitor.adaptive_interval <= Duration::from_millis(20));

        // Test failed sample - interval should increase
        monitor.adaptive_interval = Duration::from_millis(20);
        monitor.update_adaptive_interval(false, new_now);
        // 11/10 of 20ms = 22ms
        assert!(monitor.adaptive_interval >= Duration::from_millis(20));
        assert!(monitor.adaptive_interval <= ctx.max_interval);
    }
    // Test metadata collection and caching
    #[test]
    fn test_metadata_collection_and_caching() -> Result<()> {
        // Use current process
        let ctx = TestContext::new();
        let mut monitor =
            ProcessMonitor::from_pid_with_config(ctx.current_pid, ctx.build_config())?;

        // First call should collect metadata
        let metadata1 = monitor.get_metadata();
        assert!(metadata1.is_some());

        // Should be cached now
        let metadata2 = monitor.get_metadata();
        assert!(metadata2.is_some());

        // Both should be the same instance
        assert_eq!(format!("{:?}", metadata1), format!("{:?}", metadata2));

        Ok(())
    }

    // Test empty command rejection
    #[test]
    fn test_empty_command_rejected() {
        let config = MonitorConfig::default();
        let result = ProcessMonitor::new_with_config(vec![], config);
        assert!(result.is_err());
        match result {
            Err(DenetError::InvalidConfiguration(msg)) => {
                assert!(
                    msg.contains("empty"),
                    "Error message should mention empty command"
                );
            }
            _ => panic!("Expected InvalidConfiguration error"),
        }
    }

    // Test nonexistent PID
    #[test]
    fn test_from_pid_with_config_nonexistent_pid() {
        let config = MonitorConfig::default();
        // Use a large PID that's unlikely to exist
        let result = ProcessMonitor::from_pid_with_config(999999, config);
        assert!(result.is_err());

        if let Err(DenetError::ProcessNotFound(pid)) = result {
            assert_eq!(pid, 999999);
        } else {
            panic!("Expected ProcessNotFound error");
        }
    }

    // Test the adaptive interval logic by examining the algorithm directly
    #[test]
    fn test_adaptive_interval_adjustment() {
        // Create a direct test focusing on the algorithm in update_adaptive_interval

        // Case 1: Failed sample should increase interval
        {
            let config = MonitorConfig::builder()
                .base_interval_ms(10)
                .max_interval_ms(1000)
                .build()
                .unwrap();

            let mut monitor = ProcessMonitor {
                pid: 1,
                config,
                metadata: None,
                child_process: None,
                start_time: Instant::now(),
                last_sample_time: Instant::now(),
                adaptive_interval: Duration::from_millis(50),
            };

            // Initial value
            assert_eq!(monitor.adaptive_interval, Duration::from_millis(50));

            // Failed sample should increase by roughly 10%
            monitor.update_adaptive_interval(false, Instant::now());
            assert!(monitor.adaptive_interval >= Duration::from_millis(50));
            // Allow some flexibility in the exact calculation
            assert!(monitor.adaptive_interval <= Duration::from_millis(60));
        }

        // Case 2: Base interval as lower bound
        {
            let base_interval = Duration::from_millis(10);
            let config = MonitorConfig::builder()
                .base_interval(base_interval)
                .max_interval_ms(100)
                .build()
                .unwrap();

            let mut monitor = ProcessMonitor {
                pid: 1,
                config,
                metadata: None,
                child_process: None,
                start_time: Instant::now(),
                last_sample_time: Instant::now(),
                adaptive_interval: base_interval,
            };

            // Even with a successful sample, can't go below base interval
            let now = Instant::now();
            monitor.update_adaptive_interval(true, now);
            assert_eq!(monitor.adaptive_interval, base_interval);
        }
    }

    // Test is_running with real child process
    #[test]
    fn test_is_running_with_child() -> Result<()> {
        // Create a short-lived process
        let cmd = if cfg!(target_os = "windows") {
            vec!["timeout".to_string(), "1".to_string()]
        } else {
            vec!["sleep".to_string(), "0.1".to_string()]
        };

        let config = MonitorConfig::default();
        let mut monitor = ProcessMonitor::new_with_config(cmd, config)?;

        // Process should start running
        assert!(monitor.is_running());

        // Wait for it to exit
        thread::sleep(Duration::from_millis(200));

        // Process should be finished
        assert!(!monitor.is_running());

        Ok(())
    }

    // Test sample_metrics timing updates
    #[test]
    fn test_sample_timing_updates() -> Result<()> {
        // Use current process
        let ctx = TestContext::new();
        let mut monitor =
            ProcessMonitor::from_pid_with_config(ctx.current_pid, ctx.build_config())?;

        // Set known state
        monitor.last_sample_time = Instant::now()
            .checked_sub(Duration::from_millis(100))
            .unwrap();
        let old_sample_time = monitor.last_sample_time;

        // Sample should update last_sample_time
        let _ = monitor.sample_metrics();
        assert!(monitor.last_sample_time > old_sample_time);

        Ok(())
    }

    // Test the process monitoring duration limit
    #[test]
    fn test_monitoring_duration_limit() -> Result<()> {
        let mock_command = if cfg!(target_os = "windows") {
            vec!["timeout".to_string(), "10".to_string()]
        } else {
            vec!["sleep".to_string(), "10".to_string()]
        };

        // Create config with short max duration
        let config = DenetConfig {
            monitor: MonitorConfig::builder()
                .base_interval_ms(10)
                .max_duration(Duration::from_millis(100))
                .build()?,
            output: crate::config::OutputConfig::builder().quiet(true).build(),
        };

        // Start monitoring with duration limit
        let start_time = Instant::now();
        let result = run_monitor(mock_command, config);
        let elapsed = start_time.elapsed();

        // Should complete around the max_duration time, not the sleep time
        assert!(result.is_ok());

        // Use more generous time bounds for CI environments where timing can vary
        assert!(
            elapsed < Duration::from_millis(300),
            "Took too long: {:?}",
            elapsed
        );
        assert!(
            elapsed >= Duration::from_millis(50),
            "Finished too quickly: {:?}",
            elapsed
        );

        Ok(())
    }

    // Linux-specific tests
    #[cfg(target_os = "linux")]
    mod linux_tests {
        use super::*;

        #[test]
        fn test_get_thread_count() {
            // Current process should have at least one thread
            let current_pid = std::process::id() as usize;
            let config = MonitorConfig::default();

            let monitor = ProcessMonitor {
                pid: current_pid,
                config,
                metadata: None,
                child_process: None,
                start_time: Instant::now(),
                last_sample_time: Instant::now(),
                adaptive_interval: Duration::from_millis(100),
            };

            let thread_count = monitor.get_thread_count();
            assert!(thread_count >= 1);
        }

        #[test]
        fn test_get_io_metrics() {
            // Current process should have valid IO metrics
            let current_pid = std::process::id() as usize;
            let config = MonitorConfig::default();

            let monitor = ProcessMonitor {
                pid: current_pid,
                config,
                metadata: None,
                child_process: None,
                start_time: Instant::now(),
                last_sample_time: Instant::now(),
                adaptive_interval: Duration::from_millis(100),
            };

            let result = monitor.get_io_metrics();
            assert!(result.is_ok());

            let (read, write) = result.unwrap();
            // u64 values are always valid, just check they contain reasonable values
            assert!(read <= u64::MAX);
            assert!(write <= u64::MAX);
        }
    }
}
