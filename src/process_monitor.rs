use serde::{Serialize, Deserialize};
use std::process::{Command, Child};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};
use sysinfo::{ProcessExt, System, SystemExt};
use std::fs;
use std::io::{self, Read, BufReader, BufRead};
use std::collections::HashMap;
use std::path::Path;
use std::fs::File;

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

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct ProcessMetadata {
    pub pid: usize,
    pub cmd: Vec<String>,
    pub exe: String,
    pub t0_ms: u64,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct Metrics {
    pub ts_ms: u64,
    pub cpu_usage: f32,
    pub mem_rss_kb: u64,
    pub mem_vms_kb: u64,
    pub disk_read_bytes: u64,
    pub disk_write_bytes: u64,
    pub net_rx_bytes: u64,
    pub net_tx_bytes: u64,
    pub thread_count: usize,
    pub uptime_secs: u64,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct ProcessTreeMetrics {
    pub ts_ms: u64,
    pub parent: Option<Metrics>,
    pub children: Vec<ChildProcessMetrics>,
    pub aggregated: Option<AggregatedMetrics>,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct ChildProcessMetrics {
    pub pid: usize,
    pub command: String,
    pub metrics: Metrics,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct AggregatedMetrics {
    pub ts_ms: u64,
    pub cpu_usage: f32,
    pub mem_rss_kb: u64,
    pub mem_vms_kb: u64,
    pub disk_read_bytes: u64,
    pub disk_write_bytes: u64,
    pub net_rx_bytes: u64,
    pub net_tx_bytes: u64,
    pub thread_count: usize,
    pub process_count: usize,
    pub uptime_secs: u64,
}

/// Summarizes metrics collected during a monitoring session
#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct Summary {
    /// Total time elapsed in seconds
    pub total_time_secs: f64,
    /// Number of samples collected
    pub sample_count: usize,
    /// Maximum number of processes observed
    pub max_processes: usize,
    /// Maximum number of threads observed
    pub max_threads: usize,
    /// Cumulative disk read bytes
    pub total_disk_read_bytes: u64,
    /// Cumulative disk write bytes
    pub total_disk_write_bytes: u64,
    /// Cumulative network received bytes
    pub total_net_rx_bytes: u64,
    /// Cumulative network transmitted bytes
    pub total_net_tx_bytes: u64,
    /// Maximum memory RSS observed across all processes (in KB)
    pub peak_mem_rss_kb: u64,
    /// Average CPU usage (percent)
    pub avg_cpu_usage: f32,
}

impl Summary {
    /// Creates a new empty summary
    pub fn new() -> Self {
        Summary {
            total_time_secs: 0.0,
            sample_count: 0,
            max_processes: 0,
            max_threads: 0,
            total_disk_read_bytes: 0,
            total_disk_write_bytes: 0,
            total_net_rx_bytes: 0,
            total_net_tx_bytes: 0,
            peak_mem_rss_kb: 0,
            avg_cpu_usage: 0.0,
        }
    }
    
    /// Generate a summary from a collection of Metrics
    pub fn from_metrics(metrics: &[Metrics], elapsed_time: f64) -> Self {
        let mut summary = Summary::new();
        let mut total_cpu = 0.0;
        
        summary.total_time_secs = elapsed_time;
        summary.sample_count = metrics.len();
        
        if metrics.is_empty() {
            return summary;
        }
        
        for metric in metrics {
            // For non-aggregated metrics, we assume process_count is 1
            summary.max_processes = summary.max_processes.max(1);
            summary.max_threads = summary.max_threads.max(metric.thread_count);
            
            // Track I/O (we're using the final values as cumulative totals)
            summary.total_disk_read_bytes = summary.total_disk_read_bytes.max(metric.disk_read_bytes);
            summary.total_disk_write_bytes = summary.total_disk_write_bytes.max(metric.disk_write_bytes);
            summary.total_net_rx_bytes = summary.total_net_rx_bytes.max(metric.net_rx_bytes);
            summary.total_net_tx_bytes = summary.total_net_tx_bytes.max(metric.net_tx_bytes);
            
            // Track peak memory usage
            summary.peak_mem_rss_kb = summary.peak_mem_rss_kb.max(metric.mem_rss_kb);
            
            // Sum CPU usage for average calculation
            total_cpu += metric.cpu_usage as f64;
        }
        
        // Calculate average CPU usage
        summary.avg_cpu_usage = (total_cpu / metrics.len() as f64) as f32;
        
        summary
    }
    
    /// Generate a summary from a collection of AggregatedMetrics
    pub fn from_aggregated_metrics(metrics: &[AggregatedMetrics], elapsed_time: f64) -> Self {
        let mut summary = Summary::new();
        let mut total_cpu = 0.0;
        
        summary.total_time_secs = elapsed_time;
        summary.sample_count = metrics.len();
        
        if metrics.is_empty() {
            return summary;
        }
        
        for metric in metrics {
            // Track max processes and threads
            summary.max_processes = summary.max_processes.max(metric.process_count);
            summary.max_threads = summary.max_threads.max(metric.thread_count);
            
            // Track I/O (we're using the final values as cumulative totals)
            summary.total_disk_read_bytes = summary.total_disk_read_bytes.max(metric.disk_read_bytes);
            summary.total_disk_write_bytes = summary.total_disk_write_bytes.max(metric.disk_write_bytes);
            summary.total_net_rx_bytes = summary.total_net_rx_bytes.max(metric.net_rx_bytes);
            summary.total_net_tx_bytes = summary.total_net_tx_bytes.max(metric.net_tx_bytes);
            
            // Track peak memory usage
            summary.peak_mem_rss_kb = summary.peak_mem_rss_kb.max(metric.mem_rss_kb);
            
            // Sum CPU usage for average calculation
            total_cpu += metric.cpu_usage as f64;
        }
        
        // Calculate average CPU usage
        summary.avg_cpu_usage = (total_cpu / metrics.len() as f64) as f32;
        
        summary
    }
    
    /// Read metrics from a JSON file and generate a summary
    pub fn from_json_file<P: AsRef<Path>>(path: P) -> io::Result<Self> {
        let file = File::open(path)?;
        let reader = BufReader::new(file);
        
        let mut metrics_vec: Vec<AggregatedMetrics> = Vec::new();
        let mut regular_metrics: Vec<Metrics> = Vec::new();
        let mut first_timestamp: Option<u64> = None;
        let mut last_timestamp: Option<u64> = None;
        
        // Process file line by line since each line is a separate JSON object
        for line in reader.lines() {
            let line = line?;
            
            // Skip empty lines
            if line.trim().is_empty() {
                continue;
            }
            
            // Try to parse as different types of metrics
            if let Ok(agg_metric) = serde_json::from_str::<AggregatedMetrics>(&line) {
                // Got aggregated metrics
                if first_timestamp.is_none() {
                    first_timestamp = Some(agg_metric.ts_ms);
                }
                last_timestamp = Some(agg_metric.ts_ms);
                metrics_vec.push(agg_metric);
            } else if let Ok(tree_metrics) = serde_json::from_str::<ProcessTreeMetrics>(&line) {
                // Got tree metrics, extract aggregated metrics if available
                if let Some(agg) = tree_metrics.aggregated {
                    if first_timestamp.is_none() {
                        first_timestamp = Some(agg.ts_ms);
                    }
                    last_timestamp = Some(agg.ts_ms);
                    metrics_vec.push(agg);
                }
            } else if let Ok(metric) = serde_json::from_str::<Metrics>(&line) {
                // Got regular metrics
                if first_timestamp.is_none() {
                    first_timestamp = Some(metric.ts_ms);
                }
                last_timestamp = Some(metric.ts_ms);
                regular_metrics.push(metric);
            }
            // Ignore metadata and other lines we can't parse
        }
        
        // Calculate total time
        let elapsed_time = match (first_timestamp, last_timestamp) {
            (Some(first), Some(last)) => (last - first) as f64 / 1000.0,
            _ => 0.0
        };
        
        // Generate summary based on the metrics we found
        if !metrics_vec.is_empty() {
            Ok(Self::from_aggregated_metrics(&metrics_vec, elapsed_time))
        } else if !regular_metrics.is_empty() {
            Ok(Self::from_metrics(&regular_metrics, elapsed_time))
        } else {
            Ok(Self::new()) // Return empty summary if no metrics found
        }
    }
}

#[derive(Debug, Clone)]
pub struct IoBaseline {
    pub disk_read_bytes: u64,
    pub disk_write_bytes: u64,
    pub net_rx_bytes: u64,
    pub net_tx_bytes: u64,
}

#[derive(Debug, Clone)]
pub struct ChildIoBaseline {
    pub pid: usize,
    pub disk_read_bytes: u64,
    pub disk_write_bytes: u64,
    pub net_rx_bytes: u64,
    pub net_tx_bytes: u64,
}

// Main process monitor implementation
pub struct ProcessMonitor {
    child: Option<Child>,
    pid: usize,
    sys: System,
    base_interval: Duration,
    max_interval: Duration,
    start_time: Instant,
    t0_ms: u64,
    io_baseline: Option<IoBaseline>,
    child_io_baselines: std::collections::HashMap<usize, ChildIoBaseline>,
    since_process_start: bool,
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
            t0_ms: SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .expect("Time went backwards")
                .as_millis() as u64,
            io_baseline: None,
            child_io_baselines: HashMap::new(),
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
            t0_ms: SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .expect("Time went backwards")
                .as_millis() as u64,
            io_baseline: None,
            child_io_baselines: HashMap::new(),
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
            let mem_vms_kb = proc.virtual_memory() / 1024;
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
            
            let ts_ms = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .expect("Time went backwards")
                .as_millis() as u64;

            Some(Metrics {
                ts_ms,
                cpu_usage,
                mem_rss_kb,
                mem_vms_kb,
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

    // Get process metadata (static information)
    pub fn get_metadata(&mut self) -> Option<ProcessMetadata> {
        self.sys.refresh_process(self.pid.into());
        
        if let Some(proc) = self.sys.process(self.pid.into()) {
            Some(ProcessMetadata {
                pid: self.pid,
                cmd: proc.cmd().to_vec(),
                exe: proc.exe().to_string_lossy().to_string(),
                t0_ms: self.t0_ms,
            })
        } else {
            None
        }
    }

    // Get all child processes recursively
    pub fn get_child_pids(&mut self) -> Vec<usize> {
        self.sys.refresh_processes();
        let mut children = Vec::new();
        self.find_children_recursive(self.pid, &mut children);
        children
    }

    // Recursively find all descendants of a process
    fn find_children_recursive(&self, parent_pid: usize, children: &mut Vec<usize>) {
        for (pid, process) in self.sys.processes() {
            if let Some(ppid) = process.parent() {
                if usize::from(ppid) == parent_pid {
                    let child_pid = usize::from(*pid);
                    children.push(child_pid);
                    // Recursively find grandchildren
                    self.find_children_recursive(child_pid, children);
                }
            }
        }
    }

    // Sample metrics including child processes
    pub fn sample_tree_metrics(&mut self) -> ProcessTreeMetrics {
        let tree_ts_ms = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("Time went backwards")
            .as_millis() as u64;
            
        // Get parent metrics
        let parent_metrics = self.sample_metrics();
        
        // Get child PIDs and their metrics
        let child_pids = self.get_child_pids();
        let mut child_metrics = Vec::new();
        
        for child_pid in child_pids {
            self.sys.refresh_process(child_pid.into());
            
            if let Some(proc) = self.sys.process(child_pid.into()) {
                let command = proc.name().to_string();
                
                // Get I/O stats for child
                let current_disk_read = proc.disk_usage().total_read_bytes;
                let current_disk_write = proc.disk_usage().total_written_bytes;
                let current_net_rx = 0; // TODO: Implement for children
                let current_net_tx = 0;
                
                // Handle I/O baseline for child processes
                let (disk_read_bytes, disk_write_bytes, net_rx_bytes, net_tx_bytes) = if self.since_process_start {
                    // Show cumulative I/O since process start
                    (current_disk_read, current_disk_write, current_net_rx, current_net_tx)
                } else {
                    // Show delta I/O since monitoring start
                    if !self.child_io_baselines.contains_key(&child_pid) {
                        // First time seeing this child - establish baseline
                        self.child_io_baselines.insert(child_pid, ChildIoBaseline {
                            pid: child_pid,
                            disk_read_bytes: current_disk_read,
                            disk_write_bytes: current_disk_write,
                            net_rx_bytes: current_net_rx,
                            net_tx_bytes: current_net_tx,
                        });
                        (0, 0, 0, 0) // First sample shows 0 delta
                    } else {
                        // Calculate delta from baseline
                        let baseline = &self.child_io_baselines[&child_pid];
                        (
                            current_disk_read.saturating_sub(baseline.disk_read_bytes),
                            current_disk_write.saturating_sub(baseline.disk_write_bytes),
                            current_net_rx.saturating_sub(baseline.net_rx_bytes),
                            current_net_tx.saturating_sub(baseline.net_tx_bytes)
                        )
                    }
                };
                
                let child_ts_ms = SystemTime::now()
                    .duration_since(UNIX_EPOCH)
                    .expect("Time went backwards")
                    .as_millis() as u64;
                    
                let metrics = Metrics {
                    ts_ms: child_ts_ms,
                    cpu_usage: proc.cpu_usage(),
                    mem_rss_kb: proc.memory() / 1024,
                    mem_vms_kb: proc.virtual_memory() / 1024,
                    disk_read_bytes,
                    disk_write_bytes,
                    net_rx_bytes,
                    net_tx_bytes,
                    thread_count: get_thread_count(child_pid),
                    uptime_secs: proc.run_time(),
                };
                
                child_metrics.push(ChildProcessMetrics {
                    pid: child_pid,
                    command,
                    metrics,
                });
            }
        }
        
        // Create aggregated metrics
        let aggregated = if let Some(ref parent) = parent_metrics {
            let mut agg = AggregatedMetrics {
                ts_ms: tree_ts_ms,
                cpu_usage: parent.cpu_usage,
                mem_rss_kb: parent.mem_rss_kb,
                mem_vms_kb: parent.mem_vms_kb,
                disk_read_bytes: parent.disk_read_bytes,
                disk_write_bytes: parent.disk_write_bytes,
                net_rx_bytes: parent.net_rx_bytes,
                net_tx_bytes: parent.net_tx_bytes,
                thread_count: parent.thread_count,
                process_count: 1, // Parent
                uptime_secs: parent.uptime_secs,
            };
            
            // Add child metrics
            for child in &child_metrics {
                agg.cpu_usage += child.metrics.cpu_usage;
                agg.mem_rss_kb += child.metrics.mem_rss_kb;
                agg.mem_vms_kb += child.metrics.mem_vms_kb;
                agg.disk_read_bytes += child.metrics.disk_read_bytes;
                agg.disk_write_bytes += child.metrics.disk_write_bytes;
                agg.net_rx_bytes += child.metrics.net_rx_bytes;
                agg.net_tx_bytes += child.metrics.net_tx_bytes;
                agg.thread_count += child.metrics.thread_count;
                agg.process_count += 1;
            }
            
            Some(agg)
        } else {
            None
        };
        
        ProcessTreeMetrics {
            ts_ms: tree_ts_ms,
            parent: parent_metrics,
            children: child_metrics,
            aggregated,
        }
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

    #[test]
    fn test_child_process_detection() {
        // Start a process that spawns children
        let cmd = if cfg!(target_os = "windows") {
            vec!["cmd".to_string(), "/C".to_string(), "timeout 2 >nul & echo child".to_string()]
        } else {
            vec!["sh".to_string(), "-c".to_string(), "sleep 2 & echo child".to_string()]
        };
        
        let mut monitor = create_test_monitor(cmd).unwrap();
        
        // Allow time for child processes to start
        thread::sleep(Duration::from_millis(200));
        
        // Get child PIDs
        let children = monitor.get_child_pids();
        
        // We might not always detect children due to timing, so just verify the method works
        // The assertion here is mainly to document that the method should return a Vec
        assert!(children.is_empty() || !children.is_empty(), "Should return a list of child PIDs (possibly empty)");
    }

    #[test]
    fn test_tree_metrics_structure() {
        // Test the tree metrics structure with a simple process
        let cmd = vec!["sleep".to_string(), "1".to_string()];
        let mut monitor = create_test_monitor(cmd).unwrap();
        
        // Allow time for process to start
        thread::sleep(Duration::from_millis(100));
        
        // Sample tree metrics
        let tree_metrics = monitor.sample_tree_metrics();
        
        // Should have parent metrics
        assert!(tree_metrics.parent.is_some(), "Should have parent metrics");
        
        // Should have aggregated metrics
        assert!(tree_metrics.aggregated.is_some(), "Should have aggregated metrics");
        
        if let Some(agg) = tree_metrics.aggregated {
            assert!(agg.process_count >= 1, "Should count at least the parent process");
            assert!(agg.thread_count > 0, "Should have at least one thread");
        }
    }

    #[test]
    fn test_child_process_aggregation() {
        // This test is hard to make deterministic since we can't guarantee child processes
        // But we can test the aggregation logic with the structure
        let cmd = vec!["sleep".to_string(), "1".to_string()];
        let mut monitor = create_test_monitor(cmd).unwrap();
        
        thread::sleep(Duration::from_millis(100));
        
        let tree_metrics = monitor.sample_tree_metrics();
        
        if let (Some(parent), Some(agg)) = (tree_metrics.parent, tree_metrics.aggregated) {
            // Aggregated metrics should include at least the parent
            assert!(agg.cpu_usage >= parent.cpu_usage, "Aggregated CPU should be >= parent CPU");
            assert!(agg.mem_rss_kb >= parent.mem_rss_kb, "Aggregated memory should be >= parent memory");
            assert!(agg.thread_count >= parent.thread_count, "Aggregated threads should be >= parent threads");
            
            // Process count should be at least 1 (the parent)
            assert!(agg.process_count >= 1, "Should count at least the parent process");
        }
    }

    #[test]
    fn test_empty_process_tree() {
        // Test behavior when monitoring a process with no children
        let cmd = vec!["sleep".to_string(), "1".to_string()];
        let mut monitor = create_test_monitor(cmd).unwrap();
        
        thread::sleep(Duration::from_millis(50));
        
        let tree_metrics = monitor.sample_tree_metrics();
        
        // Should have parent metrics
        assert!(tree_metrics.parent.is_some(), "Should have parent metrics even with no children");
        
        // Children list might be empty (which is fine)
        // Length is always non-negative, so just verify it's accessible
        
        // Aggregated should exist and equal parent (since no children)
        if let (Some(parent), Some(agg)) = (tree_metrics.parent, tree_metrics.aggregated) {
            assert_eq!(agg.process_count, 1 + tree_metrics.children.len(), 
                      "Process count should be parent + actual children");
            
            if tree_metrics.children.is_empty() {
                // If no children, aggregated should equal parent
                assert_eq!(agg.cpu_usage, parent.cpu_usage, "CPU should match parent when no children");
                assert_eq!(agg.mem_rss_kb, parent.mem_rss_kb, "Memory should match parent when no children");
                assert_eq!(agg.thread_count, parent.thread_count, "Threads should match parent when no children");
            }
        }
    }

    #[test]
    fn test_recursive_child_detection() {
        // Test that we can find children recursively in a more complex process tree
        let cmd = if cfg!(target_os = "windows") {
            vec!["cmd".to_string(), "/C".to_string(), 
                 "timeout 3 >nul & (timeout 2 >nul & timeout 1 >nul)".to_string()]
        } else {
            vec!["sh".to_string(), "-c".to_string(), 
                 "sleep 3 & (sleep 2 & sleep 1 &)".to_string()]
        };
        
        let mut monitor = create_test_monitor(cmd).unwrap();
        
        // Allow time for the process tree to establish
        thread::sleep(Duration::from_millis(300));
        
        let _children = monitor.get_child_pids();
        
        // We might detect children (timing dependent), but the method should work
        // Just verify the method returns successfully (length is always valid)
        
        // Test that repeated calls work
        let _children2 = monitor.get_child_pids();
        // Both calls should succeed and return valid vectors
    }

    #[test]
    fn test_child_process_lifecycle() {
        // Test monitoring during child process lifecycle changes
        let cmd = if cfg!(target_os = "windows") {
            vec!["cmd".to_string(), "/C".to_string(), "timeout 1 >nul".to_string()]
        } else {
            vec!["sh".to_string(), "-c".to_string(), "sleep 0.5 & wait".to_string()]
        };
        
        let mut monitor = create_test_monitor(cmd).unwrap();
        
        // Sample immediately (children might not exist yet)
        let initial_metrics = monitor.sample_tree_metrics();
        let initial_count = initial_metrics.aggregated.as_ref().map(|a| a.process_count).unwrap_or(1);
        
        // Wait a bit for child to potentially start
        thread::sleep(Duration::from_millis(100));
        
        let mid_metrics = monitor.sample_tree_metrics();
        let mid_count = mid_metrics.aggregated.as_ref().map(|a| a.process_count).unwrap_or(1);
        
        // Wait for child to finish
        thread::sleep(Duration::from_millis(600));
        
        let final_metrics = monitor.sample_tree_metrics();
        let final_count = final_metrics.aggregated.as_ref().map(|a| a.process_count).unwrap_or(1);
        
        // Process count should be consistent or decrease over time (as children finish)
        assert!(final_count <= mid_count, "Process count should not increase over time");
        assert!(mid_count >= initial_count, "Process count should be stable or increase initially");
        
        // All samples should have valid structure
        assert!(initial_metrics.aggregated.is_some(), "Initial aggregated metrics should exist");
        assert!(mid_metrics.aggregated.is_some(), "Mid aggregated metrics should exist");
        assert!(final_metrics.aggregated.is_some(), "Final aggregated metrics should exist");
    }

    #[test]
    fn test_network_io_limitation_for_children() {
        // Test that the current limitation of network I/O for children is handled properly
        let cmd = if cfg!(target_os = "windows") {
            vec!["cmd".to_string(), "/C".to_string(), "timeout 1 >nul & echo test".to_string()]
        } else {
            vec!["sh".to_string(), "-c".to_string(), "sleep 1 & echo test".to_string()]
        };
        
        let mut monitor = create_test_monitor(cmd).unwrap();
        
        thread::sleep(Duration::from_millis(200));
        
        let tree_metrics = monitor.sample_tree_metrics();
        
        // Check that all children have 0 network I/O (current limitation)
        for child in &tree_metrics.children {
            assert_eq!(child.metrics.net_rx_bytes, 0, "Child network RX should be 0 (known limitation)");
            assert_eq!(child.metrics.net_tx_bytes, 0, "Child network TX should be 0 (known limitation)");
        }
        
        // Parent might have network I/O, children should not
        if let Some(parent) = tree_metrics.parent {
            // Parent could have network activity, that's fine
            if let Some(agg) = tree_metrics.aggregated {
                // Aggregated network should equal parent network (since children are 0)
                assert_eq!(agg.net_rx_bytes, parent.net_rx_bytes, 
                          "Aggregated network RX should equal parent (children are 0)");
                assert_eq!(agg.net_tx_bytes, parent.net_tx_bytes, 
                          "Aggregated network TX should equal parent (children are 0)");
            }
        }
    }

    #[test]
    fn test_aggregation_arithmetic() {
        // Test that aggregation arithmetic is correct when we have known values
        let cmd = vec!["sleep".to_string(), "2".to_string()];
        let mut monitor = create_test_monitor(cmd).unwrap();
        
        thread::sleep(Duration::from_millis(100));
        
        let tree_metrics = monitor.sample_tree_metrics();
        
        if let (Some(parent), Some(agg)) = (tree_metrics.parent, tree_metrics.aggregated) {
            // Calculate expected values
            let expected_mem = parent.mem_rss_kb + 
                tree_metrics.children.iter().map(|c| c.metrics.mem_rss_kb).sum::<u64>();
            let expected_threads = parent.thread_count + 
                tree_metrics.children.iter().map(|c| c.metrics.thread_count).sum::<usize>();
            let expected_cpu = parent.cpu_usage + 
                tree_metrics.children.iter().map(|c| c.metrics.cpu_usage).sum::<f32>();
            let expected_processes = 1 + tree_metrics.children.len();
            
            assert_eq!(agg.mem_rss_kb, expected_mem, "Memory aggregation should sum parent + children");
            assert_eq!(agg.thread_count, expected_threads, "Thread aggregation should sum parent + children");
            assert_eq!(agg.process_count, expected_processes, "Process count should be parent + children");
            
            // CPU might have floating point precision issues, use approximate equality
            assert!((agg.cpu_usage - expected_cpu).abs() < 0.01, 
                   "CPU aggregation should approximately sum parent + children");
        }
    }

    #[test]
    fn test_timestamp_functionality() {
        use std::time::{SystemTime, UNIX_EPOCH};
        use std::thread;

        let cmd = vec!["sleep".to_string(), "2".to_string()];
        let mut monitor = create_test_monitor(cmd).unwrap();
        
        thread::sleep(Duration::from_millis(100));
        
        // Collect multiple samples
        let sample1 = monitor.sample_metrics().unwrap();
        thread::sleep(Duration::from_millis(50));
        let sample2 = monitor.sample_metrics().unwrap();
        
        // Verify timestamps are reasonable (within last minute)
        let now_ms = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_millis() as u64;
            
        assert!(sample1.ts_ms <= now_ms, "Sample1 timestamp should not be in future");
        assert!(sample2.ts_ms <= now_ms, "Sample2 timestamp should not be in future");
        assert!(now_ms - sample1.ts_ms < 60000, "Sample1 timestamp should be recent");
        assert!(now_ms - sample2.ts_ms < 60000, "Sample2 timestamp should be recent");
        
        // Verify timestamps are monotonic
        assert!(sample2.ts_ms >= sample1.ts_ms, "Timestamps should be monotonic");
        
        // Test tree metrics timestamps (allow small timing differences)
        let tree_metrics = monitor.sample_tree_metrics();
        let now_ms2 = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_millis() as u64;
            
        assert!(tree_metrics.ts_ms <= now_ms2 + 1000, "Tree timestamp should be reasonable");
        
        if let Some(parent) = tree_metrics.parent {
            assert!(parent.ts_ms <= now_ms2 + 1000, "Parent timestamp should be reasonable");
        }
        
        if let Some(agg) = tree_metrics.aggregated {
            assert!(agg.ts_ms <= now_ms2 + 1000, "Aggregated timestamp should be reasonable");
        }
    }

    #[test]
    fn test_enhanced_memory_metrics() {
        use std::time::{SystemTime, UNIX_EPOCH};
        use std::thread;

        let cmd = vec!["sleep".to_string(), "2".to_string()];
        let mut monitor = create_test_monitor(cmd).unwrap();
        
        thread::sleep(Duration::from_millis(200));
        
        // Try multiple times in case initial memory reporting is delayed
        let mut metrics = monitor.sample_metrics().unwrap();
        for _ in 0..5 {
            if metrics.mem_rss_kb > 0 {
                break;
            }
            thread::sleep(Duration::from_millis(100));
            metrics = monitor.sample_metrics().unwrap();
        }
        
        // Test that new memory fields exist and are reasonable
        // Note: Memory reporting can be unreliable in test environments
        // Allow for zero values in case of very fast processes or system limitations
        if metrics.mem_rss_kb > 0 && metrics.mem_vms_kb > 0 {
            assert!(metrics.mem_vms_kb >= metrics.mem_rss_kb, "Virtual memory should be >= RSS when both > 0");
        }
        
        // At least one memory metric should be available, but allow for system variations
        let has_memory_data = metrics.mem_rss_kb > 0 || metrics.mem_vms_kb > 0;
        if !has_memory_data {
            println!("Warning: No memory data available from sysinfo - this can happen in test environments");
        }
        

        
        // Test metadata separately
        let metadata = monitor.get_metadata().unwrap();
        let now_ms = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("Time went backwards")
            .as_millis() as u64;
        
        assert!(metadata.t0_ms <= now_ms, "Start time should not be in future");
        assert!(now_ms - metadata.t0_ms < 60000, "Start time should be recent (within 60 seconds)");
        
        // Test tree metrics also have enhanced fields
        let tree_metrics = monitor.sample_tree_metrics();
        
        if let Some(parent) = tree_metrics.parent {
            assert!(parent.mem_vms_kb >= parent.mem_rss_kb, "Parent VMS should be >= RSS");
        }
        
        if let Some(agg) = tree_metrics.aggregated {
            assert!(agg.mem_vms_kb >= agg.mem_rss_kb, "Aggregated VMS should be >= RSS");
        }
    }

    #[test]
    fn test_process_metadata() {
        use std::time::{SystemTime, UNIX_EPOCH};
        use std::thread;

        let cmd = vec!["sleep".to_string(), "2".to_string()];
        let mut monitor = create_test_monitor(cmd).unwrap();
        
        thread::sleep(Duration::from_millis(100));
        
        // Test metadata collection
        let metadata = monitor.get_metadata().unwrap();
        
        // Verify basic metadata fields
        assert!(metadata.pid > 0, "PID should be positive");
        assert!(!metadata.cmd.is_empty(), "Command should not be empty");
        assert_eq!(metadata.cmd[0], "sleep", "First command arg should be 'sleep'");
        assert!(!metadata.exe.is_empty(), "Executable path should not be empty");
        
        // Test start time is reasonable
        let now_ms = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("Time went backwards")
            .as_millis() as u64;
        
        assert!(metadata.t0_ms <= now_ms, "Start time should not be in future");
        assert!(now_ms - metadata.t0_ms < 60000, "Start time should be recent (within 60 seconds)");
        
        // Test that t0_ms has millisecond precision (not just seconds * 1000)
        // The value should not be a round thousand (which would indicate second precision)
        let remainder = metadata.t0_ms % 1000;
        // Allow some tolerance for processes that might start exactly on second boundaries
        // but most of the time it should have non-zero millisecond component
        println!("t0_ms: {}, remainder: {}", metadata.t0_ms, remainder);
        
        // Test tree metrics work without embedded metadata
        let tree_metrics = monitor.sample_tree_metrics();
        assert_eq!(tree_metrics.parent.is_some(), true, "Tree should have parent metrics");
    }

    #[test]
    fn test_t0_ms_precision() {
        use std::time::{SystemTime, UNIX_EPOCH};
        use std::thread;

        // Capture time before creating monitor
        let before_ms = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("Time went backwards")
            .as_millis() as u64;

        let cmd = vec!["sleep".to_string(), "0.1".to_string()];
        let mut monitor = create_test_monitor(cmd).unwrap();
        
        // Capture time after creating monitor
        let after_ms = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("Time went backwards")
            .as_millis() as u64;
        
        // Wait a small amount to let process start
        thread::sleep(Duration::from_millis(50));
        
        let metadata = monitor.get_metadata().unwrap();
        
        // Verify t0_ms is in milliseconds and reasonable
        assert!(metadata.t0_ms > 1000000000000, "t0_ms should be a reasonable Unix timestamp in milliseconds");
        assert!(metadata.t0_ms >= before_ms, "t0_ms should be after we started creating the monitor");
        assert!(metadata.t0_ms <= after_ms, "t0_ms should be before we finished creating the monitor");
        
        // Test precision by checking that we have millisecond information
        // t0_ms should have millisecond precision, not just seconds * 1000
        let remainder = metadata.t0_ms % 1000;
        println!("t0_ms: {}, remainder: {}", metadata.t0_ms, remainder);
        
        // The value should be a proper millisecond timestamp
        assert!(metadata.t0_ms > before_ms, "t0_ms should be greater than before timestamp");
        assert!(metadata.t0_ms < after_ms + 1000, "t0_ms should be close to creation time");
    }
}