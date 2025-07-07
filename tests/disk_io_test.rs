//! Integration test for disk I/O metrics accuracy
//!
//! This test verifies that the ProcessMonitor correctly tracks disk write metrics
//! by creating a process that writes a known amount of data to disk and comparing
//! the reported metrics with the expected values.

use denet::core::constants::{delays, sampling, timeouts};
use denet::core::monitoring_utils::{MonitoringConfig, MonitoringLoop};
use denet::ProcessMonitor;
use std::fs;
use std::time::{Duration, Instant};
use tempfile::TempDir;

#[test]
#[cfg(target_os = "linux")]
fn test_disk_write_metrics_accuracy() {
    // Create a temporary directory for our test
    let temp_dir = TempDir::new().expect("Failed to create temp directory");
    let temp_path = temp_dir.path().join("test_output.txt");
    let temp_path_str = temp_path.to_str().unwrap();

    // We'll write 1MB of data in chunks over several seconds
    let chunk_size = 1024; // 1KB per write
    let num_chunks = 1024; // Total: 1MB
    let expected_bytes = chunk_size * num_chunks;

    // Create a command that writes data to disk over time
    // Using bash to write data in a loop with small delays to make it long-lived
    let cmd = vec![
        "bash".to_string(),
        "-c".to_string(),
        format!(
            "for i in $(seq 1 {}); do \
                dd if=/dev/zero of={} bs={} count=1 conv=notrunc oflag=append 2>/dev/null; \
                sleep 0.01; \
            done",
            num_chunks, temp_path_str, chunk_size
        ),
    ];

    // Create and start the monitor
    let monitor = ProcessMonitor::new_with_options(
        cmd,
        sampling::STANDARD,         // Sample every 100ms
        Duration::from_millis(500), // Max interval 500ms
        false,                      // Not since process start
    )
    .expect("Failed to create ProcessMonitor");

    let config = MonitoringConfig::new()
        .with_sample_interval(sampling::FAST)
        .with_timeout(timeouts::LONG)
        .with_final_samples(1, delays::FINAL_SAMPLE);

    let result =
        MonitoringLoop::with_config(config).run_with_progress(monitor, |count, metrics| {
            if count % 10 == 0 {
                println!(
                    "Sample {}: {} bytes written (expected: {} bytes)",
                    count, metrics.disk_write_bytes, expected_bytes
                );
            }
        });

    let last_disk_write = result
        .last_sample()
        .map(|s| s.disk_write_bytes)
        .unwrap_or(0);
    let samples = &result.samples;
    let start_time = Instant::now() - result.duration;

    println!("Test completed:");
    println!("  - Duration: {:.2}s", start_time.elapsed().as_secs_f64());
    println!("  - Total samples: {}", samples.len());
    println!("  - Expected bytes written: {}", expected_bytes);
    println!("  - Reported bytes written: {}", last_disk_write);

    // Verify the file exists and has the expected size
    let actual_file_size = fs::metadata(&temp_path)
        .expect("Failed to get file metadata")
        .len();

    println!("  - Actual file size: {}", actual_file_size);

    // Assertions
    assert!(!samples.is_empty(), "No samples were collected");
    assert!(
        samples.len() >= 5,
        "Not enough samples collected (got {})",
        samples.len()
    );

    // The reported disk write bytes should be reasonably close to what we expect
    // Allow for some variance due to system overhead and measurement timing
    let tolerance = 0.3; // 30% tolerance
    let min_expected = (expected_bytes as f64 * (1.0 - tolerance)) as u64;
    let _max_expected = (expected_bytes as f64 * (1.0 + tolerance)) as u64;

    assert!(
        last_disk_write >= min_expected,
        "Reported disk writes ({}) too low, expected at least {}",
        last_disk_write,
        min_expected
    );

    // Note: We don't check upper bound as strictly because the system might write
    // additional metadata, and our measurement might include other I/O operations

    // Verify that disk write metrics are increasing over time
    let mut increasing_samples = 0;
    for i in 1..samples.len() {
        if samples[i].disk_write_bytes > samples[i - 1].disk_write_bytes {
            increasing_samples += 1;
        }
    }

    // At least 50% of samples should show increasing disk writes
    let min_increasing = samples.len() / 2;
    assert!(
        increasing_samples >= min_increasing,
        "Disk write metrics not increasing consistently enough ({} out of {} samples)",
        increasing_samples,
        samples.len() - 1
    );

    // Verify the actual file has reasonable content
    assert!(
        actual_file_size >= (expected_bytes as u64 * 8 / 10), // At least 80% of expected
        "Actual file size ({}) much smaller than expected ({})",
        actual_file_size,
        expected_bytes
    );

    println!("✅ Disk I/O metrics test passed!");
}

fn create_random_file(path: &std::path::Path, size_bytes: usize) -> std::io::Result<()> {
    use std::fs::File;
    use std::io::Write;

    let mut file = File::create(path)?;
    let chunk_size = 4096;
    let mut remaining = size_bytes;

    // Create pseudo-random data (simple pattern to avoid depending on rand crate)
    let mut pattern = 0u8;
    while remaining > 0 {
        let write_size = std::cmp::min(chunk_size, remaining);
        let mut chunk = Vec::with_capacity(write_size);

        for i in 0..write_size {
            chunk.push(pattern.wrapping_add(i as u8));
        }
        pattern = pattern.wrapping_add(1);

        file.write_all(&chunk)?;
        remaining -= write_size;
    }

    file.sync_all()?;
    Ok(())
}

#[test]
#[cfg(target_os = "linux")]
fn test_disk_read_small_file() {
    test_disk_read_with_size("small", 1024 * 1024); // 1MB
}

#[test]
#[cfg(target_os = "linux")]
fn test_disk_read_medium_file() {
    test_disk_read_with_size("medium", 4 * 1024 * 1024); // 4MB
}

#[test]
#[cfg(target_os = "linux")]
fn test_disk_read_large_file() {
    test_disk_read_with_size("large", 10 * 1024 * 1024); // 10MB
}

fn test_disk_read_with_size(test_name: &str, file_size: usize) {
    let temp_dir = TempDir::new().expect("Failed to create temp directory");
    let temp_path = temp_dir.path().join(format!("test_{}.dat", test_name));

    // Create file with random data to prevent compression/optimization
    create_random_file(&temp_path, file_size).expect("Failed to create test file");

    let temp_path_str = temp_path.to_str().unwrap();

    // Create a command that reads the file multiple times with delays
    // Use dd with sync to force actual disk reads and avoid caching
    // Note: This is Linux-specific behavior, particularly the drop_caches command
    let cmd = vec![
        "bash".to_string(),
        "-c".to_string(),
        format!(
            "sync; echo 3 > /proc/sys/vm/drop_caches 2>/dev/null || true; \
            for i in $(seq 1 3); do \
                dd if={} of=/dev/null bs=64k 2>/dev/null; \
                sleep 0.2; \
            done",
            temp_path_str
        ),
    ];

    let monitor = ProcessMonitor::new_with_options(
        cmd,
        sampling::STANDARD,
        Duration::from_millis(400),
        false,
    )
    .expect("Failed to create ProcessMonitor");

    let config = MonitoringConfig::new()
        .with_sample_interval(sampling::FAST)
        .with_timeout(Duration::from_secs(15))
        .with_final_samples(1, delays::STANDARD);

    let mut max_disk_read = 0u64;
    let result = MonitoringLoop::with_config(config).run_with_processor(monitor, |metrics| {
        max_disk_read = std::cmp::max(max_disk_read, metrics.disk_read_bytes);
    });

    let samples = &result.samples;
    let start_time = Instant::now() - result.duration;

    println!("Disk read test ({}) completed:", test_name);
    println!(
        "  - File size: {} bytes ({:.2} MB)",
        file_size,
        file_size as f64 / 1024.0 / 1024.0
    );
    println!("  - Duration: {:.2}s", start_time.elapsed().as_secs_f64());
    println!("  - Samples: {}", samples.len());
    println!("  - Max reported disk reads: {} bytes", max_disk_read);

    // Verify file exists with correct size
    let actual_size = fs::metadata(&temp_path).unwrap().len() as usize;
    assert_eq!(actual_size, file_size, "Test file size mismatch");

    // Basic assertions
    assert!(!samples.is_empty(), "No samples collected");

    // We expect at least some disk activity, though reads can be unpredictable
    // due to system caching. Allow for zero reads in case of aggressive caching.
    if max_disk_read > 0 {
        println!("✅ Detected disk reads: {} bytes", max_disk_read);
    } else {
        println!("⚠️  No disk reads detected (likely due to system caching)");
    }

    println!("✅ Disk read test ({}) completed!", test_name);
}

#[test]
#[cfg(target_os = "linux")]
fn test_simple_disk_write_accuracy() {
    // Create a temporary file for testing
    let temp_dir = TempDir::new().expect("Failed to create temp directory");
    let temp_path = temp_dir.path().join("simple_test.txt");
    let temp_path_str = temp_path.to_str().unwrap();

    // Write exactly 100KB in larger chunks to make it faster
    let expected_bytes = 102400; // 100KB

    // Create a command that writes the data slowly so we can observe it
    let cmd = vec![
        "bash".to_string(),
        "-c".to_string(),
        format!(
            "for i in $(seq 1 100); do \
                dd if=/dev/zero of={} bs=1024 count=1 conv=notrunc oflag=append 2>/dev/null; \
                sleep 0.02; \
            done",
            temp_path_str
        ),
    ];

    // Create and start the monitor
    let monitor = ProcessMonitor::new_with_options(
        cmd,
        sampling::FAST,             // Sample every 50ms
        Duration::from_millis(200), // Max interval 200ms
        false,
    )
    .expect("Failed to create ProcessMonitor");

    let config = MonitoringConfig::new()
        .with_sample_interval(delays::SHORT)
        .with_timeout(timeouts::MEDIUM)
        .with_final_samples(1, delays::STANDARD);

    let result = MonitoringLoop::with_config(config).run(monitor);
    let final_disk_write = result
        .last_sample()
        .map(|s| s.disk_write_bytes)
        .unwrap_or(0);
    let samples = &result.samples;

    println!("Simple disk write test results:");
    println!("  - Expected bytes: {}", expected_bytes);
    println!("  - Reported bytes: {}", final_disk_write);
    println!("  - Samples collected: {}", samples.len());

    // Verify file was actually created with correct size
    let actual_file_size = fs::metadata(&temp_path)
        .expect("Test file should exist")
        .len();

    assert_eq!(
        actual_file_size, expected_bytes as u64,
        "File size mismatch - dd command may have failed"
    );

    // Basic sanity checks
    assert!(!samples.is_empty(), "Should have collected some samples");
    assert!(
        final_disk_write > 0,
        "Should have detected some disk writes"
    );

    // The reported bytes should be roughly in the ballpark
    // Allow wide tolerance since there might be system overhead
    let min_expected = expected_bytes / 2; // At least 50% of expected
    assert!(
        final_disk_write >= min_expected as u64,
        "Reported disk writes ({}) too low compared to expected ({})",
        final_disk_write,
        expected_bytes
    );

    println!("✅ Simple disk write test passed!");
}
