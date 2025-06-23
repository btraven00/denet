//! CPU usage measurement module
//!
//! This module provides accurate CPU usage measurement by directly reading
//! process statistics from the operating system. The current implementation
//! is Linux-specific and uses the procfs crate to read from /proc.
//!
//! # Cross-platform Strategy
//!
//! We should implement platform-specific CPU measurement backends:
//!
//! ## Linux (Current Implementation)
//! - Uses procfs to read /proc/[pid]/stat
//! - Gets CPU jiffies and calculates percentage based on time delta
//! - Matches the calculation method used by tools like 'top' and 'htop'
//!
//! ## macOS (Planned)
//! - Will use host_processor_info() from libproc
//! - Will use proc_pidinfo() to get task_info
//! - Calculation is based on CPU ticks delta / time delta
//! - Reference implementation: psutil's cpu_percent for macOS
//!
//! ## Windows (Planned)
//! - Will use GetProcessTimes() for process CPU times
//! - Will use GetSystemTimes() for system-wide times
//! - Performance Counters API as fallback
//! - Will match calculation method from psutil and Process Explorer
//!
//! This strategy will allow us to have accurate CPU measurements
//! across all major platforms without relying on sysinfo.

use procfs::process::Process;
use std::collections::HashMap;
use std::io::{Error, ErrorKind};
use std::time::{Duration, Instant};

/// Store CPU times for delta calculation
///
/// This structure holds the CPU time values from a single measurement point,
/// allowing us to calculate the delta between two measurements.
#[derive(Clone, Debug)]
struct CpuTimes {
    user: u64,   // User mode CPU time in clock ticks
    system: u64, // System mode CPU time in clock ticks
    timestamp: Instant,
}

/// CpuSampler provides accurate per-process CPU usage measurement
///
/// This struct tracks process CPU times and calculates usage percentages
/// based on the delta between measurements. The calculation matches what
/// tools like top/htop use, providing more accurate values than sysinfo.
///
/// # Note
///
/// On Linux, CPU percentages can exceed 100% for multi-threaded processes
/// that utilize multiple cores. 100% represents full utilization of one core.
#[derive(Debug)]
pub struct CpuSampler {
    /// Previous measurements for each PID
    previous_times: HashMap<usize, CpuTimes>,
    /// System CPU info - clock ticks per second (usually 100)
    clock_ticks_per_sec: u64,
}

impl Default for CpuSampler {
    fn default() -> Self {
        Self::new()
    }
}

impl CpuSampler {
    /// Create a new CpuSampler instance
    ///
    /// This initializes the sampler with the system's clock ticks per second
    /// value, which is needed for accurate CPU percentage calculation.
    pub fn new() -> Self {
        // Get clock ticks per second (usually 100)
        let clock_ticks = unsafe { libc::sysconf(libc::_SC_CLK_TCK) } as u64;

        Self {
            previous_times: HashMap::new(),
            clock_ticks_per_sec: clock_ticks,
        }
    }

    /// Static method to get CPU usage for a single measurement
    /// This creates a temporary sampler instance for one-off measurements
    pub fn get_cpu_usage_static(pid: usize) -> Result<f32, std::io::Error> {
        // For static usage, we use procfs directly
        let process = Process::new(pid as i32).map_err(|e| {
            std::io::Error::new(
                std::io::ErrorKind::NotFound,
                format!("Process not found: {e}"),
            )
        })?;

        let stat = process
            .stat()
            .map_err(|e| std::io::Error::other(format!("Failed to read process stat: {e}")))?;

        // For a single measurement, we can't calculate delta, so return approximate CPU usage
        let total_time = stat.utime + stat.stime;
        let _clock_ticks = unsafe { libc::sysconf(libc::_SC_CLK_TCK) } as u64;
        let uptime_ticks = stat.starttime;

        if uptime_ticks > 0 {
            let cpu_usage = (total_time as f64 / uptime_ticks as f64) * 100.0;
            Ok(cpu_usage.min(100.0) as f32)
        } else {
            Ok(0.0)
        }
    }

    /// Get CPU usage percentage for a process (0-100% per core)
    ///
    /// Returns the CPU usage as a percentage, where:
    /// - 0% means no CPU usage
    /// - 100% means full utilization of one CPU core
    /// - >100% possible for multi-threaded processes using multiple cores
    ///
    /// The first call for a PID will return None as it establishes a baseline.
    /// Subsequent calls will return the CPU usage since the previous call.
    ///
    /// # Arguments
    ///
    /// * `pid` - Process ID to measure
    ///
    /// # Returns
    ///
    /// * `Some(f32)` - CPU usage percentage if available
    /// * `None` - If this is the first measurement or the process doesn't exist
    pub fn get_cpu_usage(&mut self, pid: usize) -> Option<f32> {
        let current = Self::read_process_times(pid).ok()?;

        if let Some(previous) = self.previous_times.get(&pid) {
            let time_delta = current.timestamp.duration_since(previous.timestamp);
            if time_delta < Duration::from_millis(10) {
                return None; // Too soon for accurate measurement
            }

            let cpu_delta = (current.user + current.system) - (previous.user + previous.system);
            let time_delta_ticks = time_delta.as_secs_f64() * self.clock_ticks_per_sec as f64;

            // CPU usage as percentage (0-100 per core)
            // No need to multiply by num_cpus - we want per-core percentage
            let usage = (cpu_delta as f64 / time_delta_ticks) * 100.0;

            self.previous_times.insert(pid, current);
            Some(usage as f32)
        } else {
            // First measurement - store for next time
            self.previous_times.insert(pid, current);
            None
        }
    }

    /// Read CPU times using procfs crate
    ///
    /// This function reads the user and system CPU times for a process
    /// from /proc/[pid]/stat using the procfs crate.
    ///
    /// # Arguments
    ///
    /// * `pid` - Process ID to read
    ///
    /// # Returns
    ///
    /// * `Result<CpuTimes, std::io::Error>` - CPU times or error if process not found
    fn read_process_times(pid: usize) -> Result<CpuTimes, std::io::Error> {
        // Use procfs to get process stat information
        let process = Process::new(pid as i32).map_err(|e| {
            Error::new(
                ErrorKind::NotFound,
                format!("Failed to access process {pid}: {e}"),
            )
        })?;

        let stat = process.stat().map_err(|e| {
            Error::new(
                ErrorKind::InvalidData,
                format!("Failed to read process stats: {e}"),
            )
        })?;

        Ok(CpuTimes {
            user: stat.utime,
            system: stat.stime,
            timestamp: Instant::now(),
        })
    }

    /// Clean up stale entries from the CPU sampler
    ///
    /// Removes tracking data for processes that no longer exist or are no
    /// longer being monitored. This prevents memory leaks when processes
    /// terminate.
    ///
    /// # Arguments
    ///
    /// * `active_pids` - List of PIDs that are still active and should be kept
    pub fn cleanup_stale_entries(&mut self, active_pids: &[usize]) {
        self.previous_times
            .retain(|pid, _| active_pids.contains(pid));
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::process::{Child, Command};

    /// Tests that CPU measurement using procfs is accurate
    ///
    /// This test creates a CPU-intensive process and verifies that
    /// our measurement shows non-zero CPU usage.
    #[test]
    #[cfg(target_os = "linux")]
    fn test_cpu_measurement_accuracy() {
        let mut sampler = CpuSampler::new();

        // Spawn a CPU-burning process
        let child = Command::new("sh")
            .arg("-c")
            .arg("for i in $(seq 1 10000000); do let j=i*i; done")
            .spawn()
            .expect("Failed to spawn test process");

        let pid = child.id() as usize;

        // First measurement (baseline)
        assert!(sampler.get_cpu_usage(pid).is_none());

        // Wait a bit longer to ensure CPU usage is registered
        std::thread::sleep(Duration::from_millis(500));

        // Measure multiple times if needed
        let mut usage = 0.0;
        for _ in 0..5 {
            if let Some(u) = sampler.get_cpu_usage(pid) {
                usage = u;
                if usage > 0.0 {
                    break;
                }
            }
            std::thread::sleep(Duration::from_millis(100));
        }

        // Should have some measurable CPU usage for the calculation process
        assert!(usage > 0.0, "CPU usage should be greater than 0: {}", usage);

        // Kill the child process
        kill_child(child);
    }

    /// Tests that we can read process CPU times from procfs
    ///
    /// This test reads the CPU times for the current process
    /// and verifies that we get valid data.
    #[test]
    #[cfg(target_os = "linux")]
    fn test_read_process_times() {
        // Try to read our own process's times
        let pid = std::process::id() as usize;

        let times = CpuSampler::read_process_times(pid).expect("Failed to read process times");

        // Print CPU times for debugging
        println!(
            "User CPU time: {}, System CPU time: {}",
            times.user, times.system
        );

        // Do some CPU work to ensure non-zero values
        for _ in 0..1000000 {
            let _ = std::time::SystemTime::now();
        }

        // Read again after doing work
        let times_after =
            CpuSampler::read_process_times(pid).expect("Failed to read process times");

        // At least one of them should have increased
        assert!(
            times_after.user > times.user || times_after.system > times.system,
            "Either user or system CPU time should increase after doing work"
        );
    }

    /// Tests that stale PIDs are properly cleaned up
    ///
    /// This test verifies that the cleanup_stale_entries method
    /// correctly removes entries for PIDs that are no longer
    /// in the active list.
    #[test]
    #[cfg(target_os = "linux")]
    fn test_cleanup_stale_entries() {
        let mut sampler = CpuSampler::new();

        // Create some test processes
        let child1 = Command::new("sh")
            .arg("-c")
            .arg("sleep 2")
            .spawn()
            .expect("Failed to spawn test process");

        let child2 = Command::new("sh")
            .arg("-c")
            .arg("sleep 2")
            .spawn()
            .expect("Failed to spawn test process");

        let pid1 = child1.id() as usize;
        let pid2 = child2.id() as usize;

        // Make initial measurements to populate the map
        sampler.get_cpu_usage(pid1);
        sampler.get_cpu_usage(pid2);

        assert!(sampler.previous_times.contains_key(&pid1));
        assert!(sampler.previous_times.contains_key(&pid2));

        // Cleanup keeping only pid1
        sampler.cleanup_stale_entries(&[pid1]);

        assert!(sampler.previous_times.contains_key(&pid1));
        assert!(!sampler.previous_times.contains_key(&pid2));

        // Kill the child processes
        kill_child(child1);
        kill_child(child2);
    }

    /// Helper function to safely kill a child process
    ///
    /// This ensures that test processes are properly terminated
    /// and don't become zombies or continue running after tests.
    fn kill_child(mut child: Child) {
        child.kill().ok();
        child.wait().ok();
    }

    #[test]
    fn test_cpu_sampler_new() {
        let sampler = CpuSampler::new();
        assert_eq!(sampler.previous_times.len(), 0);
        assert!(sampler.clock_ticks_per_sec > 0);
    }

    #[test]
    fn test_cpu_sampler_default() {
        let sampler = CpuSampler::default();
        assert_eq!(sampler.previous_times.len(), 0);
        assert!(sampler.clock_ticks_per_sec > 0);
    }

    #[test]
    #[cfg(target_os = "linux")]
    fn test_get_cpu_usage_static() {
        let pid = std::process::id() as usize;

        // Test with current process
        let result = CpuSampler::get_cpu_usage_static(pid);
        assert!(result.is_ok());
        let usage = result.unwrap();
        assert!(usage >= 0.0);
        assert!(usage <= 1000.0); // Allow for high CPU usage in tests
    }

    #[test]
    #[cfg(target_os = "linux")]
    fn test_get_cpu_usage_static_invalid_pid() {
        // Test with non-existent PID
        let result = CpuSampler::get_cpu_usage_static(999999);
        assert!(result.is_err());
    }

    #[test]
    #[cfg(target_os = "linux")]
    fn test_read_process_times_invalid_pid() {
        // Test with non-existent PID
        let result = CpuSampler::read_process_times(999999);
        assert!(result.is_err());
    }

    #[test]
    #[cfg(target_os = "linux")]
    fn test_cpu_usage_first_measurement_returns_none() {
        let mut sampler = CpuSampler::new();
        let pid = std::process::id() as usize;

        // First measurement should return None
        let result = sampler.get_cpu_usage(pid);
        assert!(result.is_none());

        // Should have stored the measurement for next time
        assert!(sampler.previous_times.contains_key(&pid));
    }

    #[test]
    #[cfg(target_os = "linux")]
    fn test_cpu_usage_quick_successive_calls() {
        let mut sampler = CpuSampler::new();
        let pid = std::process::id() as usize;

        // First measurement
        sampler.get_cpu_usage(pid);

        // Immediate second measurement should return None (too quick)
        let result = sampler.get_cpu_usage(pid);
        assert!(result.is_none());
    }

    #[test]
    #[cfg(target_os = "linux")]
    fn test_cpu_usage_with_delay() {
        let mut sampler = CpuSampler::new();
        let pid = std::process::id() as usize;

        // First measurement
        sampler.get_cpu_usage(pid);

        // Wait long enough for a valid measurement
        std::thread::sleep(Duration::from_millis(50));

        // Do some CPU work
        for _ in 0..100000 {
            let _ = std::time::SystemTime::now();
        }

        // Second measurement should return a value
        let result = sampler.get_cpu_usage(pid);
        assert!(result.is_some());
        let usage = result.unwrap();
        assert!(usage >= 0.0);
    }

    #[test]
    #[cfg(target_os = "linux")]
    fn test_cleanup_stale_entries_empty_active_list() {
        let mut sampler = CpuSampler::new();
        let pid = std::process::id() as usize;

        // Add a measurement
        sampler.get_cpu_usage(pid);
        assert!(sampler.previous_times.contains_key(&pid));

        // Cleanup with empty active list
        sampler.cleanup_stale_entries(&[]);
        assert!(!sampler.previous_times.contains_key(&pid));
        assert_eq!(sampler.previous_times.len(), 0);
    }

    #[test]
    #[cfg(target_os = "linux")]
    fn test_multiple_pids_tracking() {
        let mut sampler = CpuSampler::new();

        let child1 = Command::new("sleep")
            .arg("1")
            .spawn()
            .expect("Failed to spawn test process");

        let child2 = Command::new("sleep")
            .arg("1")
            .spawn()
            .expect("Failed to spawn test process");

        let pid1 = child1.id() as usize;
        let pid2 = child2.id() as usize;

        // Make measurements for both processes
        sampler.get_cpu_usage(pid1);
        sampler.get_cpu_usage(pid2);

        assert!(sampler.previous_times.contains_key(&pid1));
        assert!(sampler.previous_times.contains_key(&pid2));
        assert_eq!(sampler.previous_times.len(), 2);

        kill_child(child1);
        kill_child(child2);
    }

    #[test]
    fn test_cpu_times_clone() {
        let times = CpuTimes {
            user: 100,
            system: 200,
            timestamp: Instant::now(),
        };

        let cloned = times.clone();
        assert_eq!(times.user, cloned.user);
        assert_eq!(times.system, cloned.system);
    }

    #[test]
    fn test_cpu_times_debug() {
        let times = CpuTimes {
            user: 100,
            system: 200,
            timestamp: Instant::now(),
        };

        let debug_str = format!("{:?}", times);
        assert!(debug_str.contains("CpuTimes"));
        assert!(debug_str.contains("user"));
        assert!(debug_str.contains("system"));
    }

    #[test]
    #[cfg(target_os = "linux")]
    fn test_sampler_with_terminated_process() {
        let mut sampler = CpuSampler::new();

        let child = Command::new("true")
            .spawn()
            .expect("Failed to spawn test process");

        let pid = child.id() as usize;

        // Wait for process to terminate
        std::thread::sleep(Duration::from_millis(100));

        // Try to measure CPU usage of terminated process
        let result = sampler.get_cpu_usage(pid);
        // Should return None because process doesn't exist
        assert!(result.is_none());
    }
}
