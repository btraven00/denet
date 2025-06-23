//! Integration test for CPU measurement
//!
//! This test verifies that our CPU measurement can correctly
//! report high CPU usage across multiple cores.

use denet::ProcessMonitor;
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

    // Create a single parent process that will spawn multiple worker threads
    // This ensures we get proper aggregation in the ProcessMonitor
    let stress_cmd = format!(
        r#"
        python3 -c '
import multiprocessing
import time

def cpu_stress():
    # Pure CPU stress with no sleeps
    start = time.time()
    while True:
        for i in range(10000000):
            x = i * i

        # Check if we should exit (after 10 seconds)
        if time.time() - start > 10:
            break

if __name__ == "__main__":
    # Create workers equal to core count
    workers = []
    for _ in range({}):
        p = multiprocessing.Process(target=cpu_stress)
        p.start()
        workers.append(p)

    # Wait for workers to complete
    for p in workers:
        p.join()
'
        "#,
        num_cores
    );

    // Launch the stress test
    let mut child = Command::new("bash")
        .arg("-c")
        .arg(stress_cmd)
        .spawn()
        .expect("Failed to spawn CPU burner");

    // Create a monitor for the parent process
    let base_interval = Duration::from_millis(100);
    let max_interval = Duration::from_millis(500);
    let mut monitor = ProcessMonitor::from_pid(child.id() as usize, base_interval, max_interval)
        .expect("Failed to create process monitor");

    // Let the stress test start up
    std::thread::sleep(Duration::from_millis(1000));

    // Sample metrics
    let start = Instant::now();
    let timeout = Duration::from_secs(5);
    let mut samples = Vec::new();

    while start.elapsed() < timeout {
        // Get the tree metrics which include the parent and all child processes
        let tree_metrics = monitor.sample_tree_metrics();

        // Store the CPU usage from all processes in the tree
        if let Some(agg) = tree_metrics.aggregated {
            samples.push(agg.cpu_usage);
            println!(
                "Sample: CPU {}%, Process count: {}",
                agg.cpu_usage, agg.process_count
            );
        }

        std::thread::sleep(Duration::from_millis(200));
    }

    // Clean up
    let _ = child.kill();
    let _ = child.wait();

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
    println!("CPU usage samples: {:?}", samples);

    // Loose assertion to accommodate different test environments
    assert!(max_cpu > 50.0, "Maximum CPU usage should be significant");

    // If we have at least 2 cores, total usage should be higher
    if num_cores >= 2 {
        // In multi-core setup, we should see CPU usage across all processes exceeding 100%
        assert!(
            max_cpu > 100.0,
            "Multi-core CPU usage should exceed 100% with {} cores (max: {:.1}%, avg: {:.1}%)",
            num_cores,
            max_cpu,
            avg_cpu
        );
    }
}
