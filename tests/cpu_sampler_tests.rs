//! Tests for the CPU sampler module in denet

use std::thread;
use std::time::Duration;

#[cfg(target_os = "linux")]
mod linux_tests {
    use super::*;
    use denet::cpu_sampler::CpuSampler;
    use std::path::Path;

    // We'll use CpuSampler methods directly instead of these helper functions

    #[test]
    fn test_cpu_sampler_creation() {
        let _sampler = CpuSampler::new();
        // Just testing that we can create a sampler without errors
        assert!(true, "CpuSampler should be created successfully");
    }

    // Basic CPU usage test
    #[test]
    fn test_basic_cpu_usage() {
        let mut sampler = CpuSampler::new();
        let pid = std::process::id() as usize;

        // First call should return None (baseline)
        let first_measurement = sampler.get_cpu_usage(pid);
        assert!(
            first_measurement.is_none(),
            "First measurement should return None"
        );

        // Do some CPU work
        for _ in 0..1000000 {
            let _ = std::time::SystemTime::now();
        }

        // Sleep to allow for CPU usage to change
        thread::sleep(Duration::from_millis(100));

        // Second call should return Some
        let second_measurement = sampler.get_cpu_usage(pid);
        assert!(
            second_measurement.is_some(),
            "Second measurement should return Some value"
        );
    }

    #[test]
    fn test_cpu_sample_current_process() {
        // Skip if we can't access /proc filesystem
        if !Path::new("/proc/self/stat").exists() {
            println!("Skipping test as /proc/self/stat is not accessible");
            return;
        }

        // Test that we can use the static method instead
        let result = CpuSampler::get_cpu_usage_static(std::process::id() as usize);
        assert!(result.is_ok(), "Failed to get static CPU usage");
    }

    #[test]
    fn test_cpu_usage_measurement() {
        // Skip if we can't access /proc filesystem
        if !Path::new("/proc/self/stat").exists() {
            println!("Skipping test as /proc/self/stat is not accessible");
            return;
        }

        // Test the static method
        let result = CpuSampler::get_cpu_usage_static(std::process::id() as usize);

        assert!(result.is_ok(), "Should be able to measure process CPU");

        let usage = result.unwrap();

        // The usage should be a percentage between 0 and 100
        assert!(
            usage >= 0.0 && usage <= 100.0,
            "CPU usage should be between 0-100%, got: {}",
            usage
        );
    }

    #[test]
    fn test_cpu_usage_with_real_load() {
        // Skip if we can't access /proc filesystem
        if !Path::new("/proc/self/stat").exists() {
            println!("Skipping test as /proc/self/stat is not accessible");
            return;
        }

        let mut sampler = CpuSampler::new();
        let pid = std::process::id() as usize;

        // Take initial measurement to establish baseline
        let _ = sampler.get_cpu_usage(pid);

        // Generate some CPU load
        let start = std::time::Instant::now();
        while start.elapsed() < Duration::from_millis(100) {
            // Busy loop to consume CPU
            let _ = (0..10000).fold(0, |acc, x| acc + x);
        }

        // Wait a bit to ensure the CPU usage is registered
        thread::sleep(Duration::from_millis(50));

        // Measure CPU usage after load
        let cpu_percent = sampler.get_cpu_usage(pid);
        assert!(cpu_percent.is_some(), "Should be able to measure CPU usage");

        let cpu_value = cpu_percent.unwrap();

        // The usage should be a valid percentage
        assert!(
            cpu_value >= 0.0 && cpu_value <= 100.0,
            "CPU usage should be between 0-100%, got: {}",
            cpu_value
        );
    }

    #[test]
    fn test_multi_sample() {
        // Skip if we can't access /proc filesystem
        if !Path::new("/proc/self/stat").exists() {
            println!("Skipping test as /proc/self/stat is not accessible");
            return;
        }

        let mut sampler = CpuSampler::new();
        let pid = std::process::id() as usize;

        // First call establishes baseline
        assert!(sampler.get_cpu_usage(pid).is_none());

        // Take multiple samples and ensure they're all valid
        for _ in 0..3 {
            // Do some work to generate CPU usage
            for _ in 0..100000 {
                let _ = std::time::SystemTime::now();
            }

            // Short delay between samples
            thread::sleep(Duration::from_millis(50));

            // These subsequent calls should return Some
            assert!(
                sampler.get_cpu_usage(pid).is_some(),
                "Failed to get CPU usage"
            );
        }
    }
}

#[test]
fn test_platform_specific_cpu_sampler() {
    // This test simply ensures the CPU sampler module is correctly
    // configured for the current platform

    #[cfg(target_os = "linux")]
    {
        // On Linux, we should be able to create a CPU sampler
        use denet::cpu_sampler::CpuSampler;
        let _sampler = CpuSampler::new();

        // Test static method - it should at least run without error
        let pid = std::process::id() as usize;
        let result = CpuSampler::get_cpu_usage_static(pid);
        assert!(
            result.is_ok(),
            "Failed to use static CPU usage method on Linux"
        );
    }

    // If we're not on Linux, this test will still pass
    // but won't actually test anything - this is intentional
    // as other platforms aren't implemented yet
    #[cfg(not(target_os = "linux"))]
    {
        // This code path is just a placeholder for when other platforms are supported
        println!("CPU sampler tests are only implemented for Linux");
    }
}
