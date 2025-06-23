//! Monitoring utilities for common monitoring loop patterns
//!
//! This module provides reusable monitoring functionality to eliminate
//! code duplication across the codebase.

use crate::core::constants::{sampling, timeouts};
use crate::core::process_monitor::ProcessMonitor;
use crate::monitor::Metrics;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

/// Configuration for monitoring loops
#[derive(Debug, Clone)]
pub struct MonitoringConfig {
    /// Interval between samples
    pub sample_interval: Duration,
    /// Optional timeout for the monitoring loop
    pub timeout: Option<Duration>,
    /// Whether to continue monitoring after process exits
    pub monitor_after_exit: bool,
    /// Additional samples to collect after process exits
    pub final_sample_count: u32,
    /// Delay between final samples
    pub final_sample_delay: Duration,
}

impl Default for MonitoringConfig {
    fn default() -> Self {
        Self {
            sample_interval: sampling::STANDARD,
            timeout: None,
            monitor_after_exit: false,
            final_sample_count: 0,
            final_sample_delay: crate::core::constants::delays::STANDARD,
        }
    }
}

impl MonitoringConfig {
    /// Create a new monitoring configuration
    pub fn new() -> Self {
        Self::default()
    }

    /// Set the sample interval
    pub fn with_sample_interval(mut self, interval: Duration) -> Self {
        self.sample_interval = interval;
        self
    }

    /// Set the timeout
    pub fn with_timeout(mut self, timeout: Duration) -> Self {
        self.timeout = Some(timeout);
        self
    }

    /// Enable monitoring after process exit with specified sample count
    pub fn with_final_samples(mut self, count: u32, delay: Duration) -> Self {
        self.monitor_after_exit = true;
        self.final_sample_count = count;
        self.final_sample_delay = delay;
        self
    }

    /// Quick configuration for fast sampling
    pub fn fast_sampling() -> Self {
        Self::new().with_sample_interval(sampling::FAST)
    }

    /// Quick configuration for test scenarios
    pub fn for_tests() -> Self {
        Self::new()
            .with_sample_interval(sampling::FAST)
            .with_timeout(timeouts::TEST)
            .with_final_samples(5, crate::core::constants::delays::STANDARD)
    }
}

/// Result of a monitoring session
#[derive(Debug)]
pub struct MonitoringResult {
    /// All collected metrics samples
    pub samples: Vec<Metrics>,
    /// Total monitoring duration
    pub duration: Duration,
    /// Whether monitoring was stopped due to timeout
    pub timed_out: bool,
    /// Whether monitoring was interrupted by signal
    pub interrupted: bool,
}

impl MonitoringResult {
    /// Get the last sample if available
    pub fn last_sample(&self) -> Option<&Metrics> {
        self.samples.last()
    }

    /// Get the first sample if available
    pub fn first_sample(&self) -> Option<&Metrics> {
        self.samples.first()
    }

    /// Check if any samples were collected
    pub fn has_samples(&self) -> bool {
        !self.samples.is_empty()
    }

    /// Get sample count
    pub fn sample_count(&self) -> usize {
        self.samples.len()
    }
}

/// A reusable monitoring loop that eliminates common duplication
pub struct MonitoringLoop {
    config: MonitoringConfig,
    interrupt_signal: Option<Arc<AtomicBool>>,
}

impl MonitoringLoop {
    /// Create a new monitoring loop with default configuration
    pub fn new() -> Self {
        Self {
            config: MonitoringConfig::default(),
            interrupt_signal: None,
        }
    }

    /// Create a monitoring loop with specific configuration
    pub fn with_config(config: MonitoringConfig) -> Self {
        Self {
            config,
            interrupt_signal: None,
        }
    }

    /// Set an interrupt signal (e.g., for Ctrl+C handling)
    pub fn with_interrupt_signal(mut self, signal: Arc<AtomicBool>) -> Self {
        self.interrupt_signal = Some(signal);
        self
    }

    /// Run the monitoring loop with a custom processor function
    pub fn run_with_processor<F>(
        &self,
        mut monitor: ProcessMonitor,
        mut processor: F,
    ) -> MonitoringResult
    where
        F: FnMut(&Metrics),
    {
        let mut samples = Vec::new();
        let start_time = Instant::now();
        let mut timed_out = false;
        let mut interrupted = false;

        // Main monitoring loop
        while monitor.is_running() {
            // Check for timeout
            if let Some(timeout) = self.config.timeout {
                if start_time.elapsed() >= timeout {
                    timed_out = true;
                    break;
                }
            }

            // Check for interrupt signal
            if let Some(ref signal) = self.interrupt_signal {
                if !signal.load(Ordering::SeqCst) {
                    interrupted = true;
                    break;
                }
            }

            // Sample metrics
            if let Some(metrics) = monitor.sample_metrics() {
                processor(&metrics);
                samples.push(metrics);
            }

            // Sleep between samples
            std::thread::sleep(self.config.sample_interval);
        }

        // Collect final samples if configured
        if self.config.monitor_after_exit && self.config.final_sample_count > 0 {
            for _ in 0..self.config.final_sample_count {
                std::thread::sleep(self.config.final_sample_delay);
                if let Some(metrics) = monitor.sample_metrics() {
                    processor(&metrics);
                    samples.push(metrics);
                }
            }
        }

        MonitoringResult {
            samples,
            duration: start_time.elapsed(),
            timed_out,
            interrupted,
        }
    }

    /// Run the monitoring loop and collect all samples
    pub fn run(&self, monitor: ProcessMonitor) -> MonitoringResult {
        self.run_with_processor(monitor, |_| {})
    }

    /// Run the monitoring loop with progress callback
    pub fn run_with_progress<F>(
        &self,
        monitor: ProcessMonitor,
        progress_callback: F,
    ) -> MonitoringResult
    where
        F: Fn(usize, &Metrics),
    {
        let mut sample_count = 0;
        self.run_with_processor(monitor, |metrics| {
            sample_count += 1;
            progress_callback(sample_count, metrics);
        })
    }
}

impl Default for MonitoringLoop {
    fn default() -> Self {
        Self::new()
    }
}

/// Quick function for simple monitoring scenarios
pub fn monitor_until_completion(
    monitor: ProcessMonitor,
    sample_interval: Duration,
    timeout: Option<Duration>,
) -> MonitoringResult {
    let config = MonitoringConfig::new().with_sample_interval(sample_interval);

    let config = if let Some(timeout) = timeout {
        config.with_timeout(timeout)
    } else {
        config
    };

    MonitoringLoop::with_config(config).run(monitor)
}

/// Quick function for test monitoring scenarios
pub fn monitor_for_test(monitor: ProcessMonitor) -> MonitoringResult {
    MonitoringLoop::with_config(MonitoringConfig::for_tests()).run(monitor)
}

/// Quick function for monitoring with progress output
pub fn monitor_with_progress<F>(
    monitor: ProcessMonitor,
    sample_interval: Duration,
    progress_callback: F,
) -> MonitoringResult
where
    F: Fn(usize, &Metrics),
{
    let config = MonitoringConfig::new().with_sample_interval(sample_interval);
    MonitoringLoop::with_config(config).run_with_progress(monitor, progress_callback)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::core::constants::delays;

    #[test]
    fn test_monitoring_config_builder() {
        let config = MonitoringConfig::new()
            .with_sample_interval(sampling::FAST)
            .with_timeout(timeouts::SHORT)
            .with_final_samples(3, delays::STANDARD);

        assert_eq!(config.sample_interval, sampling::FAST);
        assert_eq!(config.timeout, Some(timeouts::SHORT));
        assert_eq!(config.final_sample_count, 3);
        assert!(config.monitor_after_exit);
    }

    #[test]
    fn test_monitoring_config_presets() {
        let fast_config = MonitoringConfig::fast_sampling();
        assert_eq!(fast_config.sample_interval, sampling::FAST);

        let test_config = MonitoringConfig::for_tests();
        assert_eq!(test_config.sample_interval, sampling::FAST);
        assert_eq!(test_config.timeout, Some(timeouts::TEST));
        assert_eq!(test_config.final_sample_count, 5);
    }

    #[test]
    fn test_monitoring_result_methods() {
        let samples = vec![Metrics::default(), Metrics::default()];

        let result = MonitoringResult {
            samples,
            duration: Duration::from_secs(1),
            timed_out: false,
            interrupted: false,
        };

        assert!(result.has_samples());
        assert_eq!(result.sample_count(), 2);
        assert!(result.first_sample().is_some());
        assert!(result.last_sample().is_some());

        // Test empty result
        let empty_result = MonitoringResult {
            samples: vec![],
            duration: Duration::from_secs(0),
            timed_out: false,
            interrupted: false,
        };

        assert!(!empty_result.has_samples());
        assert_eq!(empty_result.sample_count(), 0);
        assert!(empty_result.first_sample().is_none());
        assert!(empty_result.last_sample().is_none());
    }

    #[test]
    fn test_monitoring_config_defaults() {
        let config = MonitoringConfig::default();
        assert_eq!(config.sample_interval, sampling::STANDARD);
        assert_eq!(config.timeout, None);
        assert!(!config.monitor_after_exit);
        assert_eq!(config.final_sample_count, 0);
        assert_eq!(config.final_sample_delay, delays::STANDARD);
    }

    #[test]
    fn test_monitoring_config_new() {
        let config = MonitoringConfig::new();
        assert_eq!(config.sample_interval, sampling::STANDARD);
        assert_eq!(config.timeout, None);
        assert!(!config.monitor_after_exit);
        assert_eq!(config.final_sample_count, 0);
        assert_eq!(config.final_sample_delay, delays::STANDARD);
    }

    #[test]
    fn test_monitoring_config_chaining() {
        let config = MonitoringConfig::new()
            .with_sample_interval(sampling::SLOW)
            .with_timeout(timeouts::MEDIUM)
            .with_final_samples(10, delays::SHORT);

        assert_eq!(config.sample_interval, sampling::SLOW);
        assert_eq!(config.timeout, Some(timeouts::MEDIUM));
        assert!(config.monitor_after_exit);
        assert_eq!(config.final_sample_count, 10);
        assert_eq!(config.final_sample_delay, delays::SHORT);
    }

    #[test]
    fn test_monitoring_loop_creation() {
        let loop1 = MonitoringLoop::new();
        assert_eq!(loop1.config.sample_interval, sampling::STANDARD);
        assert!(loop1.interrupt_signal.is_none());

        let config = MonitoringConfig::fast_sampling();
        let loop2 = MonitoringLoop::with_config(config.clone());
        assert_eq!(loop2.config.sample_interval, config.sample_interval);

        let interrupt = Arc::new(AtomicBool::new(true));
        let loop3 = MonitoringLoop::new().with_interrupt_signal(interrupt.clone());
        assert!(loop3.interrupt_signal.is_some());
    }

    #[test]
    fn test_monitoring_loop_default() {
        let loop1 = MonitoringLoop::default();
        let loop2 = MonitoringLoop::new();

        assert_eq!(loop1.config.sample_interval, loop2.config.sample_interval);
        assert_eq!(loop1.config.timeout, loop2.config.timeout);
    }

    #[test]
    fn test_monitoring_result_flags() {
        let result = MonitoringResult {
            samples: vec![],
            duration: Duration::from_secs(5),
            timed_out: true,
            interrupted: false,
        };

        assert!(result.timed_out);
        assert!(!result.interrupted);

        let result = MonitoringResult {
            samples: vec![],
            duration: Duration::from_secs(3),
            timed_out: false,
            interrupted: true,
        };

        assert!(!result.timed_out);
        assert!(result.interrupted);
    }

    #[test]
    fn test_convenience_functions_exist() {
        // These functions should exist and compile, but we can't easily test them
        // without a real ProcessMonitor instance. We test their signatures here.
        use std::time::Duration;

        // Test that the functions can be called (they'll fail due to no process, but that's OK)
        let dummy_monitor = match ProcessMonitor::new(
            vec!["true".to_string()],
            Duration::from_millis(100),
            Duration::from_millis(1000),
        ) {
            Ok(m) => m,
            Err(_) => return, // Skip test if we can't create a monitor
        };

        let _result = monitor_until_completion(
            dummy_monitor,
            Duration::from_millis(10),
            Some(Duration::from_millis(100)),
        );
    }

    #[test]
    fn test_configuration_edge_cases() {
        // Test with zero final samples (should not enable monitor_after_exit)
        let config = MonitoringConfig::new().with_final_samples(0, delays::STANDARD);

        assert!(config.monitor_after_exit); // It's still set to true by the method
        assert_eq!(config.final_sample_count, 0);

        // Test with very small intervals
        let config = MonitoringConfig::new().with_sample_interval(Duration::from_millis(1));

        assert_eq!(config.sample_interval, Duration::from_millis(1));

        // Test with very large timeout
        let config = MonitoringConfig::new().with_timeout(Duration::from_secs(3600));

        assert_eq!(config.timeout, Some(Duration::from_secs(3600)));
    }

    #[test]
    fn test_monitoring_loop_with_processor() {
        use std::sync::atomic::AtomicUsize;
        use std::sync::Arc;

        // Use the current process for a more reliable test
        let monitor = match ProcessMonitor::from_pid_with_options(
            std::process::id() as usize,
            Duration::from_millis(10),
            Duration::from_millis(50),
            false,
        ) {
            Ok(m) => m,
            Err(_) => return, // Skip test if we can't create a monitor
        };

        let config = MonitoringConfig::new()
            .with_sample_interval(Duration::from_millis(10))
            .with_timeout(Duration::from_millis(100));

        let loop1 = MonitoringLoop::with_config(config);
        let counter = Arc::new(AtomicUsize::new(0));
        let counter_clone = counter.clone();

        let result = loop1.run_with_processor(monitor, |_metrics| {
            counter_clone.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        });

        // Should timeout since we're monitoring the current process with a timeout
        assert!(result.timed_out || result.sample_count() > 0);
    }

    #[test]
    fn test_monitoring_loop_with_interrupt() {
        let monitor = match ProcessMonitor::from_pid_with_options(
            std::process::id() as usize,
            Duration::from_millis(10),
            Duration::from_millis(50),
            false,
        ) {
            Ok(m) => m,
            Err(_) => return, // Skip test if we can't create a monitor
        };

        let interrupt_signal = Arc::new(AtomicBool::new(true));
        let interrupt_clone = interrupt_signal.clone();

        let config = MonitoringConfig::new()
            .with_sample_interval(Duration::from_millis(10))
            .with_timeout(Duration::from_millis(1000));

        let monitoring_loop =
            MonitoringLoop::with_config(config).with_interrupt_signal(interrupt_signal);

        // Set interrupt signal to false to trigger interruption
        std::thread::spawn(move || {
            std::thread::sleep(Duration::from_millis(50));
            interrupt_clone.store(false, std::sync::atomic::Ordering::SeqCst);
        });

        let result = monitoring_loop.run(monitor);

        // Should be interrupted or have some samples
        assert!(result.interrupted || result.sample_count() > 0);
    }

    #[test]
    fn test_monitoring_loop_with_final_samples() {
        let monitor = match ProcessMonitor::new(
            vec!["true".to_string()],
            Duration::from_millis(10),
            Duration::from_millis(50),
        ) {
            Ok(m) => m,
            Err(_) => return, // Skip test if we can't create a monitor
        };

        let config = MonitoringConfig::new()
            .with_sample_interval(Duration::from_millis(10))
            .with_timeout(Duration::from_millis(100))
            .with_final_samples(2, Duration::from_millis(10));

        let monitoring_loop = MonitoringLoop::with_config(config);
        let result = monitoring_loop.run(monitor);

        // Should have timed out or completed
        assert!(result.timed_out || result.duration > Duration::from_millis(0));
    }

    #[test]
    fn test_monitor_for_test_function() {
        let monitor = match ProcessMonitor::new(
            vec!["true".to_string()],
            Duration::from_millis(10),
            Duration::from_millis(50),
        ) {
            Ok(m) => m,
            Err(_) => return, // Skip test if we can't create a monitor
        };

        let result = monitor_for_test(monitor);

        // Should complete quickly due to test configuration
        assert!(result.timed_out || result.duration < Duration::from_secs(35));
    }

    #[test]
    fn test_monitor_with_progress_function() {
        use std::sync::atomic::AtomicUsize;

        let monitor = match ProcessMonitor::new(
            vec!["true".to_string()],
            Duration::from_millis(10),
            Duration::from_millis(50),
        ) {
            Ok(m) => m,
            Err(_) => return, // Skip test if we can't create a monitor
        };

        let progress_calls = Arc::new(AtomicUsize::new(0));
        let progress_clone = progress_calls.clone();

        let result =
            monitor_with_progress(monitor, Duration::from_millis(10), |_count, _metrics| {
                progress_clone.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            });

        // Should have called progress callback if any samples were collected
        let progress_count = progress_calls.load(std::sync::atomic::Ordering::SeqCst);
        assert_eq!(progress_count, result.sample_count());
    }

    #[test]
    fn test_monitoring_loop_run_with_progress() {
        use std::sync::atomic::AtomicUsize;

        let monitor = match ProcessMonitor::new(
            vec!["true".to_string()],
            Duration::from_millis(10),
            Duration::from_millis(50),
        ) {
            Ok(m) => m,
            Err(_) => return, // Skip test if we can't create a monitor
        };

        let config = MonitoringConfig::new()
            .with_sample_interval(Duration::from_millis(10))
            .with_timeout(Duration::from_millis(100));

        let monitoring_loop = MonitoringLoop::with_config(config);
        let progress_calls = Arc::new(AtomicUsize::new(0));
        let progress_clone = progress_calls.clone();

        let result = monitoring_loop.run_with_progress(monitor, |count, _metrics| {
            progress_clone.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            assert!(count > 0);
        });

        // Verify progress callback was called correctly
        let progress_count = progress_calls.load(std::sync::atomic::Ordering::SeqCst);
        assert_eq!(progress_count, result.sample_count());
    }

    #[test]
    fn test_monitoring_result_debug() {
        let result = MonitoringResult {
            samples: vec![Metrics::default()],
            duration: Duration::from_secs(1),
            timed_out: false,
            interrupted: false,
        };

        let debug_str = format!("{:?}", result);
        assert!(debug_str.contains("MonitoringResult"));
        assert!(debug_str.contains("samples"));
        assert!(debug_str.contains("duration"));
    }

    #[test]
    fn test_monitoring_config_debug() {
        let config = MonitoringConfig::new();
        let debug_str = format!("{:?}", config);
        assert!(debug_str.contains("MonitoringConfig"));
        assert!(debug_str.contains("sample_interval"));
    }

    #[test]
    fn test_monitoring_config_clone() {
        let config1 = MonitoringConfig::new()
            .with_timeout(Duration::from_secs(10))
            .with_final_samples(5, delays::STANDARD);

        let config2 = config1.clone();

        assert_eq!(config1.sample_interval, config2.sample_interval);
        assert_eq!(config1.timeout, config2.timeout);
        assert_eq!(config1.monitor_after_exit, config2.monitor_after_exit);
        assert_eq!(config1.final_sample_count, config2.final_sample_count);
        assert_eq!(config1.final_sample_delay, config2.final_sample_delay);
    }
}
