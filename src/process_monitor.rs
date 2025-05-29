use serde::Serialize;
use std::process::{Command, Child};
use std::time::{Duration, Instant};
use sysinfo::{ProcessExt, System, SystemExt};
use std::fs;
use std::io::Read;
use std::collections::HashMap;

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

#[derive(Serialize, Debug, Clone)]
pub struct Metrics {
    pub cpu_usage: f32,
    pub mem_rss_kb: u64,
    pub disk_read_bytes: u64,
    pub disk_write_bytes: u64,
    pub net_rx_bytes: u64,
    pub net_tx_bytes: u64,
    pub thread_count: usize,
    pub uptime_secs: u64,
}

#[derive(Debug, Clone)]
pub struct IoBaseline {
    pub disk_read_bytes: u64,
    pub disk_write_bytes: u64,
    pub net_rx_bytes: u64,
    pub net_tx_bytes: u64,
}

// Main process monitor implementation
pub struct ProcessMonitor {
    pub child: Option<Child>,
    pub pid: usize,
    pub sys: System,
    pub base_interval: Duration,
    pub max_interval: Duration,
    pub start_time: Instant,
    pub io_baseline: Option<IoBaseline>,
    pub since_process_start: bool,
}

// We'll use a Result type directly instead of a custom ErrorType to avoid orphan rule issues
pub type ProcessResult<T> = std::result::Result<T, std::io::Error>;

// Helper function to convert IO errors to Python errors when needed
#[cfg(feature = "python")]
pub fn io_err_to_py_err(err: std::io::Error) -> pyo3::PyErr {
    pyo3::exceptions::PyRuntimeError::new_err(format!("IO Error: {}", err))
}

impl ProcessMonitor {
    // Create a new process monitor by launching a command
    pub fn new(cmd: Vec<String>, base_interval: Duration, max_interval: Duration) -> ProcessResult<Self> {
        Self::new_with_options(cmd, base_interval, max_interval, false)
    }

    // Create a new process monitor with I/O accounting options
    pub fn new_with_options(cmd: Vec<String>, base_interval: Duration, max_interval: Duration, since_process_start: bool) -> ProcessResult<Self> {
        if cmd.is_empty() {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                "Command cannot be empty",
            ));
        }

        let child = Command::new(&cmd[0]).args(&cmd[1..]).spawn()?;
        let pid = child.id() as usize;

        let mut sys = System::new_all();
        // Initialize the system with process information
        sys.refresh_all();
        
        Ok(Self {
            child: Some(child),
            pid,
            sys,
            base_interval,
            max_interval,
            start_time: Instant::now(),
            io_baseline: None,
            since_process_start,
        })
    }

    // Create a process monitor for an existing process
    pub fn from_pid(pid: usize, base_interval: Duration, max_interval: Duration) -> ProcessResult<Self> {
        Self::from_pid_with_options(pid, base_interval, max_interval, false)
    }

    // Create a process monitor for an existing process with I/O accounting options
    pub fn from_pid_with_options(pid: usize, base_interval: Duration, max_interval: Duration, since_process_start: bool) -> ProcessResult<Self> {
        // Check if the process exists
        let mut sys = System::new_all();
        sys.refresh_all();
        
        // Give the system time to fully refresh, especially on some systems
        std::thread::sleep(Duration::from_millis(10));
        sys.refresh_processes();

        if sys.process(pid.into()).is_none() {
            return Err(std::io::Error::new(
                std::io::ErrorKind::NotFound,
                format!("Process with PID {} not found", pid),
            ));
        }

        // Initialize the system with process information
        sys.refresh_all();

        Ok(Self {
            child: None,
            pid,
            sys,
            base_interval,
            max_interval,
            start_time: Instant::now(),
            io_baseline: None,
            since_process_start,
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
        // For accurate CPU calculation, refresh all processes first
        // This gives sysinfo the data it needs to calculate CPU percentages
        self.sys.refresh_processes();
        
        // Wait a small moment for the system to settle
        std::thread::sleep(Duration::from_millis(50));
        
        // Refresh again to get the CPU calculation
        self.sys.refresh_process(self.pid.into());

        if let Some(proc) = self.sys.process(self.pid.into()) {
            // sysinfo returns memory in bytes, so we need to convert to KB
            let mem_rss_kb = proc.memory() / 1024;
            let cpu_usage = proc.cpu_usage();
            
            let current_disk_read = proc.disk_usage().total_read_bytes;
            let current_disk_write = proc.disk_usage().total_written_bytes;
            
            // Get network I/O - for now, we'll use 0 as sysinfo doesn't provide per-process network stats
            // TODO: Implement platform-specific network I/O collection
            let current_net_rx = self.get_process_net_rx_bytes();
            let current_net_tx = self.get_process_net_tx_bytes();
            
            // Handle I/O baseline for delta calculation
            let (disk_read_bytes, disk_write_bytes, net_rx_bytes, net_tx_bytes) = if self.since_process_start {
                // Show cumulative I/O since process start
                (current_disk_read, current_disk_write, current_net_rx, current_net_tx)
            } else {
                // Show delta I/O since monitoring start
                if self.io_baseline.is_none() {
                    // First sample - establish baseline
                    self.io_baseline = Some(IoBaseline {
                        disk_read_bytes: current_disk_read,
                        disk_write_bytes: current_disk_write,
                        net_rx_bytes: current_net_rx,
                        net_tx_bytes: current_net_tx,
                    });
                    (0, 0, 0, 0) // First sample shows 0 delta
                } else {
                    // Calculate delta from baseline
                    let baseline = self.io_baseline.as_ref().unwrap();
                    (
                        current_disk_read.saturating_sub(baseline.disk_read_bytes),
                        current_disk_write.saturating_sub(baseline.disk_write_bytes),
                        current_net_rx.saturating_sub(baseline.net_rx_bytes),
                        current_net_tx.saturating_sub(baseline.net_tx_bytes)
                    )
                }
            };
            
            Some(Metrics {
                cpu_usage,
                mem_rss_kb,
                disk_read_bytes,
                disk_write_bytes,
                net_rx_bytes,
                net_tx_bytes,
                thread_count: get_thread_count(usize::from(proc.pid())),
                uptime_secs: proc.run_time(),
            })
        } else {
            None
        }
    }

    pub fn is_running(&mut self) -> bool {
        // If we have a child process, use try_wait to check its status
        if let Some(child) = &mut self.child {
            match child.try_wait() {
                Ok(Some(_)) => false,
                Ok(None) => true,
                Err(_) => false,
            }
        } else {
            // For existing processes, check if it still exists
            self.sys.refresh_process(self.pid.into());
            
            // If specific refresh doesn't work, try refreshing all processes
            if self.sys.process(self.pid.into()).is_none() {
                self.sys.refresh_processes();
            }
            
            self.sys.process(self.pid.into()).is_some()
        }
    }

    // Get the process ID
    pub fn get_pid(&self) -> usize {
        self.pid
    }

    // Get network receive bytes for the process
    fn get_process_net_rx_bytes(&self) -> u64 {
        #[cfg(target_os = "linux")]
        {
            self.get_linux_process_net_stats().0
        }
        #[cfg(not(target_os = "linux"))]
        {
            0 // Not implemented for non-Linux platforms yet
        }
    }

    // Get network transmit bytes for the process
    fn get_process_net_tx_bytes(&self) -> u64 {
        #[cfg(target_os = "linux")]
        {
            self.get_linux_process_net_stats().1
        }
        #[cfg(not(target_os = "linux"))]
        {
            0 // Not implemented for non-Linux platforms yet
        }
    }

    #[cfg(target_os = "linux")]
    fn get_linux_process_net_stats(&self) -> (u64, u64) {
        // Parse /proc/[pid]/net/dev if it exists (in network namespaces)
        // Fall back to system-wide /proc/net/dev as approximation
        
        let net_dev_path = format!("/proc/{}/net/dev", self.pid);
        let net_stats = if std::path::Path::new(&net_dev_path).exists() {
            self.parse_net_dev(&net_dev_path)
        } else {
            // Fall back to system-wide stats
            // This is less accurate but better than nothing
            self.parse_net_dev("/proc/net/dev")
        };

        // Get interface statistics (sum all interfaces except loopback)
        let mut total_rx = 0u64;
        let mut total_tx = 0u64;
        
        for (interface, (rx, tx)) in net_stats {
            if interface != "lo" { // Skip loopback
                total_rx += rx;
                total_tx += tx;
            }
        }
        
        (total_rx, total_tx)
    }

    #[cfg(target_os = "linux")]
    fn parse_net_dev(&self, path: &str) -> HashMap<String, (u64, u64)> {
        let mut stats = HashMap::new();
        
        if let Ok(mut file) = std::fs::File::open(path) {
            let mut contents = String::new();
            if file.read_to_string(&mut contents).is_ok() {
                for line in contents.lines().skip(2) { // Skip header lines
                    let parts: Vec<&str> = line.split_whitespace().collect();
                    if parts.len() >= 10 {
                        if let Some(interface) = parts[0].strip_suffix(':') {
                            if let (Ok(rx_bytes), Ok(tx_bytes)) = (
                                parts[1].parse::<u64>(),
                                parts[9].parse::<u64>()
                            ) {
                                stats.insert(interface.to_string(), (rx_bytes, tx_bytes));
                            }
                        }
                    }
                }
            }
        }
        
        stats
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
    
    // Helper function for creating a test monitor from PID
    fn create_test_monitor_from_pid(pid: usize) -> Result<ProcessMonitor, std::io::Error> {
        let base_interval = Duration::from_millis(100);
        let max_interval = Duration::from_millis(1000);
        ProcessMonitor::from_pid(pid, base_interval, max_interval)
    }

    // Test attaching to existing process
    #[test]
    fn test_from_pid() {
        // Start a process and get its PID
        let cmd = if cfg!(target_os = "windows") {
            vec!["powershell".to_string(), "-Command".to_string(), "Start-Sleep -Seconds 3".to_string()]
        } else {
            vec!["sleep".to_string(), "3".to_string()]
        };
        
        // Create a process directly
        let mut direct_monitor = create_test_monitor(cmd).unwrap();
        let pid = direct_monitor.get_pid();
        
        // Now create a monitor attached to that PID
        let pid_monitor = create_test_monitor_from_pid(pid);
        assert!(pid_monitor.is_ok(), "Should be able to attach to running process");
        
        // Both monitors should report the process as running
        assert!(direct_monitor.is_running(), "Direct monitor should show process running");
        assert!(pid_monitor.unwrap().is_running(), "PID monitor should show process running");
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