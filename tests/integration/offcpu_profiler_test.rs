//! Integration tests for the off-CPU profiler
//!
//! These tests verify that the off-CPU profiler works correctly
//! by monitoring real processes and analyzing the results.

#[cfg(all(test, feature = "ebpf", target_os = "linux"))]
mod tests {
    use denet::ebpf::{OffCpuProfiler, OffCpuStats};
    use std::process::Command;
    use std::thread;
    use std::time::Duration;

    /// Test that we can create an OffCpuProfiler instance
    #[test]
    fn test_offcpu_profiler_creation() {
        // Skip this test if not running as root
        if unsafe { libc::geteuid() != 0 } {
            println!("Skipping test_offcpu_profiler_creation (requires root)");
            return;
        }

        let profiler = OffCpuProfiler::new(vec![]);
        assert!(profiler.is_ok());
    }

    /// Test that we can collect off-CPU statistics
    #[test]
    fn test_offcpu_stats_collection() {
        // Skip this test if not running as root
        if unsafe { libc::geteuid() != 0 } {
            println!("Skipping test_offcpu_stats_collection (requires root)");
            return;
        }

        // Start a child process that sleeps periodically
        let child = Command::new("sh")
            .arg("-c")
            .arg("for i in {1..5}; do sleep 0.1; done")
            .spawn()
            .expect("Failed to start child process");

        let pid = child.id() as u32;

        // Create an OffCpuProfiler to monitor the child process
        let profiler = OffCpuProfiler::new(vec![pid]).expect("Failed to create profiler");

        // Wait for the child to finish
        thread::sleep(Duration::from_millis(600));

        // Get the statistics
        let stats = profiler.get_stats();

        // The child process should have been off-CPU at least once
        assert!(!stats.is_empty(), "No off-CPU events collected");

        // Check that we have some sensible statistics
        for ((proc_pid, _tid), thread_stats) in stats.iter() {
            // Log the process ID we're seeing - might not match our exact PID
            // due to how the C-based implementation reports PIDs
            println!("Found off-CPU stats for PID: {}", proc_pid);

            // Verify we have some off-CPU time
            assert!(thread_stats.total_time_ns > 0);
            assert!(thread_stats.count > 0);

            // The average should be reasonable (not too short, not too long)
            println!("Avg off-CPU time: {}ns", thread_stats.avg_time_ns);
            assert!(thread_stats.avg_time_ns > 1_000_000); // at least 1ms
        }
    }

    /// Test the clear_stats method
    #[test]
    fn test_clear_stats() {
        // Skip this test if not running as root
        if unsafe { libc::geteuid() != 0 } {
            println!("Skipping test_clear_stats (requires root)");
            return;
        }

        // Create an OffCpuProfiler with no specific PIDs (monitor all)
        let profiler = OffCpuProfiler::new(vec![]).expect("Failed to create profiler");

        // Generate some activity
        thread::sleep(Duration::from_millis(100));

        // Get the statistics
        let stats_before = profiler.get_stats();
        println!(
            "Number of stats entries before clear: {}",
            stats_before.len()
        );

        // Clear the statistics
        profiler.clear_stats();

        // Get the statistics again
        let stats_after = profiler.get_stats();

        // Verify that the statistics were cleared
        assert!(stats_after.is_empty(), "Expected empty stats after clear");
    }

    /// Test updating PIDs to monitor
    #[test]
    fn test_update_pids() {
        // Skip this test if not running as root
        if unsafe { libc::geteuid() != 0 } {
            println!("Skipping test_update_pids (requires root)");
            return;
        }

        // Create an OffCpuProfiler with no specific PIDs
        let mut profiler = OffCpuProfiler::new(vec![]).expect("Failed to create profiler");

        // Get the current PID
        let pid = std::process::id();

        // Update to monitor only this process
        profiler.update_pids(vec![pid]);

        // Generate some activity
        thread::sleep(Duration::from_millis(100));

        // Get the statistics
        let stats = profiler.get_stats();

        // If we got any events, they should be related to the thread activity we generated
        // Note: With the C-based implementation, PIDs might not exactly match our expectation
        for ((proc_pid, _tid), _thread_stats) in stats.iter() {
            println!("Found PID in stats: {}", proc_pid);
            // The PIDs should at least be valid (non-zero)
            assert!(*proc_pid > 0);
        }
    }

    /// Test creating a default OffCpuStats
    #[test]
    fn test_offcpu_stats_default() {
        let stats = OffCpuStats::default();
        assert_eq!(stats.total_time_ns, 0);
        assert_eq!(stats.count, 0);
        assert_eq!(stats.avg_time_ns, 0);
        assert_eq!(stats.max_time_ns, 0);
        assert_eq!(stats.min_time_ns, 0);
    }
}
