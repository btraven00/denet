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
    }
}
