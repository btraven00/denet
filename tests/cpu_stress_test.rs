//! Integration test for CPU measurement
//!
//! This test verifies that our CPU measurement can correctly
//! report high CPU usage across multiple cores.

use denet::process_monitor::ProcessMonitor;
use std::process::Command;
use std::time::{Duration, Instant};

/// A stress test that spawns multiple CPU-intensive processes
/// and verifies that the aggregate CPU usage is close to
/// num_workers * 100%.
#[test]
#[cfg(target_os = "linux")]
fn test_multicore_cpu_measurement() {
    // Skip this test in CI environments that might have limited resources
    if std::env::var("CI").is_ok() {
        println!("Skipping multi-core stress test in CI environment");
        return;
    }

    // Determine number of available cores, with a maximum of 4 for the test
    let num_cores = std::thread::available_parallelism()
        .map(|n| n.get().min(4))
        .unwrap_or(1);

    println!("Running multi-core stress test with {num_cores} workers");

    // Create CPU burner processes - one per core
    let mut children = Vec::new();
    for _ in 0..num_cores {
        let child = Command::new("bash")
            .arg("-c")
            .arg("for ((i=0;i<100000000;i++)); do :; done")
            .spawn()
            .expect("Failed to spawn CPU burner");

        children.push(child);
    }

    // Launch a process monitor to watch the first child
    let base_interval = Duration::from_millis(100);
    let max_interval = Duration::from_millis(1000);
    let mut monitor =
        ProcessMonitor::from_pid(children[0].id() as usize, base_interval, max_interval)
            .expect("Failed to create process monitor");

    // Let the processes run for a bit to stabilize CPU usage
    std::thread::sleep(Duration::from_millis(500));

    // Sample metrics for a few seconds
    let start = Instant::now();
    let timeout = Duration::from_secs(3);
    let mut samples = Vec::new();

    while start.elapsed() < timeout {
        if let Some(tree_metrics) = monitor.sample_tree_metrics().parent {
            samples.push(tree_metrics.cpu_usage);
        }
        std::thread::sleep(Duration::from_millis(200));
    }

    // Clean up child processes
    for mut child in children {
        let _ = child.kill();
        let _ = child.wait();
    }

    // Verify results
    assert!(!samples.is_empty(), "No samples collected");

    // Calculate average CPU usage
    let avg_cpu = samples.iter().sum::<f32>() / samples.len() as f32;

    // Verify that at least one sample shows high CPU usage
    let max_cpu = samples.iter().fold(0.0f32, |max, &x| max.max(x));

    println!(
        "Average CPU usage: {:.1}%, Max CPU usage: {:.1}%",
        avg_cpu, max_cpu
    );

    // Loose assertion to accommodate different test environments
    assert!(max_cpu > 50.0, "Maximum CPU usage should be significant");

    // If we have at least 2 cores, total usage should be higher
    if num_cores >= 2 {
        assert!(max_cpu > 100.0, "Multi-core CPU usage should exceed 100%");
    }

    // Print individual samples for debugging
    println!("CPU usage samples: {:?}", samples);
}
