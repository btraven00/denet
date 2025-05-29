use serde::Serialize;
use std::process::{Command, Child};
use std::time::{Duration, Instant};
use sysinfo::{ProcessExt, System, SystemExt};
use std::fs;

// In a real-world implementation, we might want this function to be more robust
// or use platform-specific APIs. For now, we'll keep it simple.
pub(crate) fn get_thread_count(pid: usize) -> usize {
    #[cfg(target_os = "linux")]
    {
        let task_dir = format!("/proc/{}/task", pid);
        match fs::read_dir(task_dir) {
            Ok(entries) => entries.count(),
            Err(_) => 0,
        }
    }

    #[cfg(not(target_os = "linux"))]
    {
        // Default implementation for non-Linux platforms
        // In a real implementation, we'd use platform-specific APIs here
        // For now, just return 1 as a default value
        1
    }
}

#[derive(Serialize, Debug)]
pub struct Metrics {
    pub cpu_usage: f32,
    pub mem_rss_kb: u64,
    pub read_bytes: u64,
    pub write_bytes: u64,
    pub thread_count: usize,
    pub uptime_secs: u64,
}

// Main process monitor implementation
pub struct ProcessMonitor {
    pub child: Child,
    pub sys: System,
    pub base_interval: Duration,
    pub max_interval: Duration,
    pub start_time: Instant,
}

// We'll use a Result type directly instead of a custom ErrorType to avoid orphan rule issues
pub type ProcessResult<T> = std::result::Result<T, std::io::Error>;

// Helper function to convert IO errors to Python errors when needed
#[cfg(feature = "python")]
pub fn io_err_to_py_err(err: std::io::Error) -> pyo3::PyErr {
    pyo3::exceptions::PyRuntimeError::new_err(format!("IO Error: {}", err))
}

impl ProcessMonitor {
    // Use the same implementation for both Python and non-Python builds
    pub fn new(cmd: Vec<String>, base_interval: Duration, max_interval: Duration) -> ProcessResult<Self> {
        if cmd.is_empty() {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                "Command cannot be empty",
            ));
        }

        let child = Command::new(&cmd[0]).args(&cmd[1..]).spawn()?;

        Ok(Self {
            child,
            sys: System::new_all(),
            base_interval,
            max_interval,
            start_time: Instant::now(),
        })
    }

    pub fn adaptive_interval(&self) -> Duration {
        // Simple linear increase capped at max_interval
        let elapsed = self.start_time.elapsed().as_secs_f64();
        let scale = 1.0 + elapsed / 10.0; // Grows every 10 seconds
        let interval_secs = (self.base_interval.as_secs_f64() * scale).min(self.max_interval.as_secs_f64());
        Duration::from_secs_f64(interval_secs)
    }

    pub fn sample_metrics(&mut self) -> Option<Metrics> {
        self.sys.refresh_process((self.child.id() as usize).into());

        if let Some(proc) = self.sys.process((self.child.id() as usize).into()) {
            Some(Metrics {
                cpu_usage: proc.cpu_usage(),
                mem_rss_kb: proc.memory(),
                read_bytes: proc.disk_usage().total_read_bytes,
                write_bytes: proc.disk_usage().total_written_bytes,
                thread_count: get_thread_count(usize::from(proc.pid())),
                uptime_secs: proc.run_time(),
            })
        } else {
            None
        }
    }

    pub fn is_running(&mut self) -> bool {
        match self.child.try_wait() {
            Ok(Some(_)) => false,
            Ok(None) => true,
            Err(_) => false,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::thread;

    // Helper function for creating a test monitor with standard parameters
    fn create_test_monitor(cmd: Vec<String>) -> Result<ProcessMonitor, std::io::Error> {
        let base_interval = Duration::from_millis(100);
        let max_interval = Duration::from_millis(1000);
        ProcessMonitor::new(cmd, base_interval, max_interval)
    }

    #[test]
    fn test_adaptive_interval() {
        let cmd = vec!["sleep".to_string(), "10".to_string()];
        let monitor = create_test_monitor(cmd).unwrap();
        
        let base_interval = monitor.base_interval;
        
        // Initial interval should be close to base_interval
        let initial = monitor.adaptive_interval();
        assert!(initial >= base_interval);
        assert!(initial <= base_interval * 2); // Allow for some time passing during test
        
        // After waiting, interval should increase but not exceed max
        thread::sleep(Duration::from_secs(2));
        let later = monitor.adaptive_interval();
        assert!(later > initial); // Should increase
        assert!(later <= monitor.max_interval); // Should not exceed max
    }
    
    #[test]
    fn test_is_running() {
        // Test with a short-lived process
        let cmd = vec!["echo".to_string(), "hello".to_string()];
        let mut monitor = create_test_monitor(cmd).unwrap();
        
        // Process may complete quickly, so give it a moment to finish
        thread::sleep(Duration::from_millis(50));
        
        // Check if the echo process finished (it should)
        let still_running = monitor.is_running();
        assert!(!still_running, "Short process should have terminated");
        
        // Test with a longer running process
        let cmd = vec!["sleep".to_string(), "1".to_string()];
        let mut monitor = create_test_monitor(cmd).unwrap();
        
        // Check immediately - should be running
        assert!(monitor.is_running(), "Sleep process should be running initially");
        
        // Wait for it to complete
        thread::sleep(Duration::from_secs(2));
        assert!(!monitor.is_running(), "Sleep process should have terminated");
    }
    
    #[test]
    fn test_metrics_collection() {
        // Start a simple CPU-bound process
        let cmd = if cfg!(target_os = "windows") {
            vec!["powershell".to_string(), "-Command".to_string(), "Start-Sleep -Seconds 3".to_string()]
        } else {
            vec!["sleep".to_string(), "3".to_string()]
        };
        
        let mut monitor = create_test_monitor(cmd).unwrap();
        
        // Allow more time for the process to start and register uptime
        thread::sleep(Duration::from_millis(500));
        
        // Sample metrics
        let metrics = monitor.sample_metrics();
        assert!(metrics.is_some(), "Should collect metrics from running process");
        
        if let Some(m) = metrics {
            // Check thread count first
            assert!(m.thread_count > 0, "Process should have at least one thread");
            
            // Handle uptime which might be 0 initially
            if m.uptime_secs == 0 {
                // If uptime is 0, wait a bit and check again to ensure it increases
                thread::sleep(Duration::from_millis(1000));
                if let Some(m2) = monitor.sample_metrics() {
                    // After the delay, uptime should definitely be positive
                    assert!(m2.uptime_secs > 0, "Process uptime should increase after delay");
                }
            } else {
                // Uptime is already positive, which is what we want
                assert!(m.uptime_secs > 0, "Process uptime should be positive");
            }
        }
    }
}