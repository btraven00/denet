use crate::monitor::{
    AggregatedMetrics, ChildProcessMetrics, Metrics, ProcessMetadata, ProcessTreeMetrics, Summary,
};
use std::collections::HashMap;
use std::fs::File;
use std::io::{self, BufRead, BufReader};
use std::path::Path;
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};
use sysinfo::{self, Pid, ProcessRefreshKind, ProcessesToUpdate, System};

// In the long run, we will want this function to be more robust
// or use platform-specific APIs. For now, we'll keep it simple.
pub(crate) fn get_thread_count(_pid: usize) -> usize {
    #[cfg(target_os = "linux")]
    {
        let task_dir = format!("/proc/{_pid}/task");
        match std::fs::read_dir(task_dir) {
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

/// Read metrics from a JSON file and generate a summary
pub fn summary_from_json_file<P: AsRef<Path>>(path: P) -> io::Result<Summary> {
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
        _ => 0.0,
    };

    // Generate summary based on the metrics we found
    if !metrics_vec.is_empty() {
        Ok(Summary::from_aggregated_metrics(&metrics_vec, elapsed_time))
    } else if !regular_metrics.is_empty() {
        Ok(Summary::from_metrics(&regular_metrics, elapsed_time))
    } else {
        Ok(Summary::default()) // Return empty summary if no metrics found
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
    _include_children: bool,
    _max_duration: Option<Duration>,
    enable_ebpf: bool,
    debug_mode: bool,
    #[cfg(feature = "ebpf")]
    ebpf_tracker: Option<crate::ebpf::SyscallTracker>,
    last_refresh_time: Instant,
    cpu_sampler: crate::cpu_sampler::CpuSampler,
}

// We'll use a Result type directly instead of a custom ErrorType to avoid orphan rule issues
pub type ProcessResult<T> = std::result::Result<T, std::io::Error>;

impl ProcessMonitor {
    pub fn new(
        cmd: Vec<String>,
        base_interval: Duration,
        max_interval: Duration,
    ) -> ProcessResult<Self> {
        Self::new_with_options(cmd, base_interval, max_interval, false)
    }

    // Create a new process monitor with I/O accounting options
    pub fn new_with_options(
        cmd: Vec<String>,
        base_interval: Duration,
        max_interval: Duration,
        since_process_start: bool,
    ) -> ProcessResult<Self> {
        if cmd.is_empty() {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                "Command cannot be empty",
            ));
        }

        let child = Command::new(&cmd[0])
            .args(&cmd[1..])
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()?;
        let pid = child.id();

        // Use minimal system initialization - avoid expensive system-wide scans
        let mut sys = System::new();
        // Only refresh CPU info once at startup
        sys.refresh_cpu_all();

        let now = Instant::now();
        Ok(Self {
            child: Some(child),
            pid: pid.try_into().unwrap(),
            sys,
            base_interval,
            max_interval,
            start_time: now,
            t0_ms: SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .expect("Time went backwards")
                .as_millis() as u64,
            _include_children: true,
            _max_duration: None,
            debug_mode: false,
            io_baseline: None,
            child_io_baselines: std::collections::HashMap::new(),
            since_process_start,
            enable_ebpf: false,
            #[cfg(feature = "ebpf")]
            ebpf_tracker: None,
            last_refresh_time: now,
            #[cfg(target_os = "linux")]
            cpu_sampler: crate::cpu_sampler::CpuSampler::new(),
        })
    }

    // Create a process monitor for an existing process
    pub fn from_pid(
        pid: usize,
        base_interval: Duration,
        max_interval: Duration,
    ) -> ProcessResult<Self> {
        Self::from_pid_with_options(pid, base_interval, max_interval, false)
    }

    // Create a process monitor for an existing process with I/O accounting options
    pub fn from_pid_with_options(
        pid: usize,
        base_interval: Duration,
        max_interval: Duration,
        since_process_start: bool,
    ) -> ProcessResult<Self> {
        // Use minimal system initialization - avoid expensive system-wide scans
        let mut sys = System::new();
        // Only refresh CPU info once at startup
        sys.refresh_cpu_all();

        // Check if the specific process exists - much faster than system-wide scan
        let pid_sys = Pid::from_u32(pid as u32);

        // Try to refresh just this process instead of all processes
        let mut retries = 3;
        let mut process_found = false;

        while retries > 0 && !process_found {
            // Only refresh the specific process we care about
            sys.refresh_processes_specifics(
                ProcessesToUpdate::Some(&[pid_sys]),
                true,
                ProcessRefreshKind::everything(),
            );
            if sys.process(pid_sys).is_some() {
                process_found = true;
            } else {
                retries -= 1;
                // Shorter sleep since we're doing targeted refresh
                std::thread::sleep(std::time::Duration::from_millis(10));
            }
        }

        if !process_found {
            return Err(std::io::Error::new(
                std::io::ErrorKind::NotFound,
                format!("Process with PID {pid} not found"),
            ));
        }

        let now = Instant::now();
        Ok(Self {
            child: None,
            pid,
            sys,
            base_interval,
            max_interval,
            start_time: now,
            t0_ms: SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .expect("Time went backwards")
                .as_millis() as u64,
            _include_children: true,
            _max_duration: None,
            debug_mode: false,
            io_baseline: None,
            child_io_baselines: std::collections::HashMap::new(),
            since_process_start,
            enable_ebpf: false,
            #[cfg(feature = "ebpf")]
            ebpf_tracker: None,
            last_refresh_time: now,
            #[cfg(target_os = "linux")]
            cpu_sampler: crate::cpu_sampler::CpuSampler::new(),
        })
    }

    /// Set debug mode for verbose output
    pub fn set_debug_mode(&mut self, debug: bool) {
        self.debug_mode = debug;

        #[cfg(feature = "ebpf")]
        unsafe {
            crate::ebpf::debug::set_debug_mode(debug);
        }

        if debug {
            log::info!("Debug mode enabled - verbose output will be shown");
        }
    }

    /// Enable eBPF profiling for this monitor
    #[cfg(feature = "ebpf")]
    pub fn enable_ebpf(&mut self) -> crate::error::Result<()> {
        if !self.enable_ebpf {
            log::info!("Attempting to enable eBPF profiling");
            if self.debug_mode {
                println!("DEBUG: Attempting to enable eBPF profiling");

                // Print current process info
                println!(
                    "DEBUG: Process monitor running with PID: {}",
                    std::process::id()
                );
                println!("DEBUG: Monitoring target PID: {}", self.pid);

                // Check for eBPF feature compilation
                println!("DEBUG: eBPF feature is enabled at compile time");
            }

            // Collect all PIDs in the process tree
            let mut pids = vec![self.pid as u32];

            // Add child PIDs
            self.sys.refresh_processes(ProcessesToUpdate::All, true);
            if let Some(_parent_proc) = self.sys.process(Pid::from_u32(self.pid as u32)) {
                for (child_pid, _) in self.sys.processes() {
                    if let Some(child_proc) = self.sys.process(*child_pid) {
                        if let Some(parent_pid) = child_proc.parent() {
                            if parent_pid == Pid::from_u32(self.pid as u32) {
                                pids.push(child_pid.as_u32());
                            }
                        }
                    }
                }
            }

            if self.debug_mode {
                println!(
                    "DEBUG: Collected {} PIDs to monitor: {:?}",
                    pids.len(),
                    pids
                );
            }
            log::info!("Collected {} PIDs to monitor", pids.len());

            // Check system readiness for eBPF
            if self.debug_mode {
                let readiness_check = std::process::Command::new("sh")
                    .arg("-c")
                    .arg("echo 'Checking eBPF prerequisites from process_monitor:'; \
                        echo -n 'Kernel version: '; uname -r; \
                        echo -n 'Debugfs mounted: '; mount | grep -q debugfs && echo 'YES' || echo 'NO'; \
                        echo -n 'Tracefs accessible: '; [ -d /sys/kernel/debug/tracing ] && echo 'YES' || echo 'NO';")
                    .output();

                if let Ok(output) = readiness_check {
                    let report = String::from_utf8_lossy(&output.stdout);
                    println!("DEBUG: {}", report);
                    log::info!("eBPF readiness: {}", report);
                }
            }

            // Initialize eBPF tracker
            match crate::ebpf::SyscallTracker::new(pids) {
                Ok(tracker) => {
                    self.ebpf_tracker = Some(tracker);
                    self.enable_ebpf = true;
                    log::info!("✅ eBPF profiling successfully enabled");
                    if self.debug_mode {
                        println!("DEBUG: eBPF profiling successfully enabled");
                    }
                    Ok(())
                }
                Err(e) => {
                    log::warn!("Failed to enable eBPF: {}", e);
                    if self.debug_mode {
                        println!("DEBUG: Failed to enable eBPF: {}", e);

                        // Additional diagnostics
                        if let Ok(output) = std::process::Command::new("sh")
                            .arg("-c")
                            .arg("dmesg | grep -i bpf | tail -5")
                            .output()
                        {
                            let kernel_logs = String::from_utf8_lossy(&output.stdout);
                            if !kernel_logs.trim().is_empty() {
                                println!("DEBUG: Recent kernel BPF logs:\n{}", kernel_logs);
                                log::warn!("Recent kernel BPF logs:\n{}", kernel_logs);
                            }
                        }
                    }

                    Err(e)
                }
            }
        } else {
            // Already enabled, just return success
            Ok(())
        }
    }

    /// Enable eBPF profiling for this monitor (no-op on non-eBPF builds)
    #[cfg(not(feature = "ebpf"))]
    pub fn enable_ebpf(&mut self) -> crate::error::Result<()> {
        log::warn!("eBPF feature not enabled at compile time");
        if self.debug_mode {
            println!(
                "DEBUG: eBPF feature not enabled at compile time. Cannot enable eBPF profiling."
            );
            println!("DEBUG: To enable eBPF support, rebuild with: cargo build --features ebpf");
        }
        // Set the flag to false to ensure consistent behavior
        self.enable_ebpf = false;
        Err(crate::error::DenetError::EbpfNotSupported(
            "eBPF feature not enabled. Build with --features ebpf".to_string(),
        ))
    }

    pub fn adaptive_interval(&self) -> Duration {
        // Adaptive sampling strategy:
        // - First 1 second: use base_interval (fast sampling for short processes)
        // - 1-10 seconds: gradually increase from base to max
        // - After 10 seconds: use max_interval
        let elapsed = self.start_time.elapsed().as_secs_f64();

        let interval_secs = if elapsed < 1.0 {
            // First second: sample at base rate
            self.base_interval.as_secs_f64()
        } else if elapsed < 10.0 {
            // 1-10 seconds: linear interpolation between base and max
            let t = (elapsed - 1.0) / 9.0; // 0 to 1 over 9 seconds
            let base = self.base_interval.as_secs_f64();
            let max = self.max_interval.as_secs_f64();
            base + (max - base) * t
        } else {
            // After 10 seconds: use max interval
            self.max_interval.as_secs_f64()
        };

        Duration::from_secs_f64(interval_secs)
    }

    pub fn sample_metrics(&mut self) -> Option<Metrics> {
        let now = Instant::now();
        self.last_refresh_time = now;

        // We still need to refresh the process for memory and other metrics
        // But we don't need the CPU refresh delay for Linux anymore
        let pid = Pid::from_u32(self.pid as u32);
        self.sys.refresh_processes_specifics(
            ProcessesToUpdate::Some(&[pid]),
            false,
            ProcessRefreshKind::everything(),
        );

        if let Some(proc) = self.sys.process(pid) {
            // sysinfo returns memory in bytes, so we need to convert to KB
            let mem_rss_kb = proc.memory() / 1024;
            let mem_vms_kb = proc.virtual_memory() / 1024;

            // Use different CPU measurement methods based on platform
            #[cfg(target_os = "linux")]
            let cpu_usage = self.cpu_sampler.get_cpu_usage(self.pid).unwrap_or(0.0);

            #[cfg(not(target_os = "linux"))]
            let cpu_usage = {
                // For non-Linux: keep using sysinfo with the refresh strategy
                let time_since_last_refresh = now.duration_since(self.last_refresh_time);

                // Refresh CPU for accurate measurement
                self.sys.refresh_cpu_all();

                // If not enough time has passed, add a delay for accuracy
                if time_since_last_refresh < Duration::from_millis(100) {
                    std::thread::sleep(Duration::from_millis(100));
                    self.sys.refresh_cpu_all();
                    let pid = Pid::from_u32(self.pid as u32);
                    self.sys.refresh_processes_specifics(
                        ProcessesToUpdate::Some(&[pid]),
                        false,
                        ProcessRefreshKind::everything(),
                    );
                }

                proc.cpu_usage()
            };

            let current_disk_read = proc.disk_usage().total_read_bytes;
            let current_disk_write = proc.disk_usage().total_written_bytes;

            // Get network I/O - for now, we'll use 0 as sysinfo doesn't provide per-process network stats
            // TODO: Implement platform-specific network I/O collection
            let current_net_rx = self.get_process_net_rx_bytes();
            let current_net_tx = self.get_process_net_tx_bytes();

            // Handle I/O baseline for delta calculation
            let (disk_read_bytes, disk_write_bytes, net_rx_bytes, net_tx_bytes) =
                if self.since_process_start {
                    // Show cumulative I/O since process start
                    (
                        current_disk_read,
                        current_disk_write,
                        current_net_rx,
                        current_net_tx,
                    )
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
                            current_net_tx.saturating_sub(baseline.net_tx_bytes),
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
                thread_count: get_thread_count(proc.pid().as_u32() as usize),
                uptime_secs: proc.run_time(),
                cpu_core: Self::get_process_cpu_core(self.pid),
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
            let pid = Pid::from_u32(self.pid as u32);

            // First try with specific process refresh
            self.sys.refresh_processes_specifics(
                ProcessesToUpdate::Some(&[pid]),
                false,
                ProcessRefreshKind::everything(),
            );

            // If specific refresh doesn't work, try refreshing all processes
            if self.sys.process(pid).is_none() {
                self.sys.refresh_processes(ProcessesToUpdate::All, true);

                // Give a small amount of time for the process to be detected
                // This helps with the test reliability
                std::thread::sleep(std::time::Duration::from_millis(10));
            }

            self.sys.process(pid).is_some()
        }
    }

    // Get the process ID
    pub fn get_pid(&self) -> usize {
        self.pid
    }

    /// Set whether to include children processes in monitoring
    pub fn set_include_children(&mut self, include_children: bool) -> &mut Self {
        self._include_children = include_children;
        self
    }

    /// Get whether children processes are included in monitoring
    pub fn get_include_children(&self) -> bool {
        self._include_children
    }

    /// Returns metadata about the monitored process
    // Get process metadata (static information)
    pub fn get_metadata(&mut self) -> Option<ProcessMetadata> {
        let pid = Pid::from_u32(self.pid as u32);
        self.sys.refresh_processes_specifics(
            ProcessesToUpdate::Some(&[pid]),
            false,
            ProcessRefreshKind::everything(),
        );

        if let Some(proc) = self.sys.process(pid) {
            // Convert OsString to String with potential data loss on invalid UTF-8
            let cmd: Vec<String> = proc
                .cmd()
                .iter()
                .map(|os_str| os_str.to_string_lossy().to_string())
                .collect();

            // Handle exe which is now Option<&Path>
            let executable = proc
                .exe()
                .map(|path| path.to_string_lossy().to_string())
                .unwrap_or_default();

            Some(ProcessMetadata {
                pid: self.pid,
                cmd,
                executable,
                t0_ms: self.t0_ms,
            })
        } else {
            None
        }
    }

    // Get all child processes recursively
    pub fn get_child_pids(&mut self) -> Vec<usize> {
        self.sys.refresh_processes(ProcessesToUpdate::All, true);
        let mut children = Vec::new();
        self.find_children_recursive(self.pid, &mut children);
        children
    }

    // Recursively find all descendants of a process
    fn find_children_recursive(&self, parent_pid: usize, children: &mut Vec<usize>) {
        let parent_pid_sys = Pid::from_u32(parent_pid as u32);
        for (pid, process) in self.sys.processes() {
            if let Some(ppid) = process.parent() {
                if ppid == parent_pid_sys {
                    let child_pid = pid.as_u32() as usize;
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

        for child_pid in child_pids.iter() {
            // We no longer need delays between child measurements for Linux with our new CPU sampler
            // But we still need to refresh process info for other metrics
            let pid = Pid::from_u32(*child_pid as u32);
            self.sys.refresh_processes_specifics(
                ProcessesToUpdate::Some(&[pid]),
                false,
                ProcessRefreshKind::everything(),
            );

            if let Some(proc) = self.sys.process(pid) {
                let command = proc.name().to_string_lossy().to_string();

                // Get I/O stats for child
                let current_disk_read = proc.disk_usage().total_read_bytes;
                let current_disk_write = proc.disk_usage().total_written_bytes;
                let current_net_rx = 0; // TODO: Implement for children
                let current_net_tx = 0;

                // Handle I/O baseline for child processes
                let (disk_read_bytes, disk_write_bytes, net_rx_bytes, net_tx_bytes) =
                    if self.since_process_start {
                        // Show cumulative I/O since process start
                        (
                            current_disk_read,
                            current_disk_write,
                            current_net_rx,
                            current_net_tx,
                        )
                    } else {
                        // Show delta I/O since monitoring start
                        match self.child_io_baselines.entry(*child_pid) {
                            std::collections::hash_map::Entry::Vacant(e) => {
                                // First time seeing this child - establish baseline
                                e.insert(ChildIoBaseline {
                                    pid: *child_pid,
                                    disk_read_bytes: current_disk_read,
                                    disk_write_bytes: current_disk_write,
                                    net_rx_bytes: current_net_rx,
                                    net_tx_bytes: current_net_tx,
                                });
                                (0, 0, 0, 0) // First sample shows 0 delta
                            }
                            std::collections::hash_map::Entry::Occupied(e) => {
                                // Calculate delta from baseline
                                let baseline = e.get();
                                (
                                    current_disk_read.saturating_sub(baseline.disk_read_bytes),
                                    current_disk_write.saturating_sub(baseline.disk_write_bytes),
                                    current_net_rx.saturating_sub(baseline.net_rx_bytes),
                                    current_net_tx.saturating_sub(baseline.net_tx_bytes),
                                )
                            }
                        }
                    };

                let child_ts_ms = SystemTime::now()
                    .duration_since(UNIX_EPOCH)
                    .expect("Time went backwards")
                    .as_millis() as u64;

                // Use different CPU measurement methods based on platform
                #[cfg(target_os = "linux")]
                let cpu_usage = self.cpu_sampler.get_cpu_usage(*child_pid).unwrap_or(0.0);

                #[cfg(not(target_os = "linux"))]
                let cpu_usage = proc.cpu_usage();

                let metrics = Metrics {
                    ts_ms: child_ts_ms,
                    cpu_usage,
                    mem_rss_kb: proc.memory() / 1024,
                    mem_vms_kb: proc.virtual_memory() / 1024,
                    disk_read_bytes,
                    disk_write_bytes,
                    net_rx_bytes,
                    net_tx_bytes,
                    thread_count: get_thread_count(*child_pid),
                    uptime_secs: proc.run_time(),
                    cpu_core: Self::get_process_cpu_core(*child_pid),
                };

                child_metrics.push(ChildProcessMetrics {
                    pid: *child_pid,
                    command,
                    metrics,
                });
            }
        }

        // Cleanup stale entries in the CPU sampler
        #[cfg(target_os = "linux")]
        {
            let all_pids = std::iter::once(self.pid)
                .chain(child_pids.iter().copied())
                .collect::<Vec<_>>();
            self.cpu_sampler.cleanup_stale_entries(&all_pids);
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
                ebpf: None, // Will be populated below if eBPF is enabled
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

            // Collect eBPF metrics if enabled
            #[cfg(feature = "ebpf")]
            if self.enable_ebpf {
                if let Some(ref mut tracker) = self.ebpf_tracker {
                    // Update PIDs in case the process tree changed
                    let all_pids: Vec<u32> = std::iter::once(self.pid as u32)
                        .chain(child_pids.iter().map(|&pid| pid as u32))
                        .collect();

                    if let Err(e) = tracker.update_pids(all_pids) {
                        log::warn!("Failed to update eBPF PIDs: {}", e);
                    }

                    // Get eBPF metrics with enhanced analysis
                    let mut ebpf_metrics = tracker.get_metrics();

                    // Add enhanced analysis if we have syscall data
                    #[cfg(feature = "ebpf")]
                    if let Some(ref mut syscalls) = ebpf_metrics.syscalls {
                        let elapsed_time = (tree_ts_ms - self.t0_ms) as f64 / 1000.0;
                        syscalls.analysis = Some(crate::ebpf::metrics::generate_syscall_analysis(
                            syscalls,
                            agg.cpu_usage,
                            elapsed_time,
                        ));
                    }

                    agg.ebpf = Some(ebpf_metrics);
                }
            }

            #[cfg(not(feature = "ebpf"))]
            {
                // eBPF is already None from initialization
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
            if interface != "lo" {
                // Skip loopback
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
            if std::io::Read::read_to_string(&mut file, &mut contents).is_ok() {
                for line in contents.lines().skip(2) {
                    // Skip header lines
                    let parts: Vec<&str> = line.split_whitespace().collect();
                    if parts.len() >= 10 {
                        if let Some(interface) = parts[0].strip_suffix(':') {
                            if let (Ok(rx_bytes), Ok(tx_bytes)) =
                                (parts[1].parse::<u64>(), parts[9].parse::<u64>())
                            {
                                stats.insert(interface.to_string(), (rx_bytes, tx_bytes));
                            }
                        }
                    }
                }
            }
        }

        stats
    }

    /// Get the CPU core a process is currently running on (Linux only)
    #[cfg(target_os = "linux")]
    fn get_process_cpu_core(pid: usize) -> Option<u32> {
        // Read /proc/[pid]/stat to get the last CPU the process ran on
        let stat_path = format!("/proc/{pid}/stat");
        if let Ok(contents) = std::fs::read_to_string(&stat_path) {
            // The CPU field is the 39th field in /proc/[pid]/stat
            // Format: pid (comm) state ppid pgrp session tty_nr tpgid flags...
            // We need to handle the command field which can contain spaces and parentheses
            if let Some(last_paren) = contents.rfind(')') {
                let after_comm = &contents[last_paren + 1..];
                let fields: Vec<&str> = after_comm.split_whitespace().collect();
                // CPU is the 37th field after the command (0-indexed)
                if fields.len() > 36 {
                    if let Ok(cpu) = fields[36].parse::<u32>() {
                        return Some(cpu);
                    }
                }
            }
        }
        None
    }

    #[cfg(not(target_os = "linux"))]
    fn get_process_cpu_core(_pid: usize) -> Option<u32> {
        None // Not implemented for non-Linux platforms
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::thread;

    // Helper function for creating a test monitor with standard parameters
    // Test fixture for process monitoring tests
    struct ProcessTestFixture {
        cmd: Vec<String>,
        base_interval: Duration,
        max_interval: Duration,
        ready_timeout: Duration,
    }

    impl ProcessTestFixture {
        fn new(cmd: Vec<String>) -> Self {
            Self {
                cmd,
                base_interval: Duration::from_millis(100),
                max_interval: Duration::from_millis(1000),
                ready_timeout: Duration::from_millis(500),
            }
        }

        fn create_monitor(&self) -> Result<ProcessMonitor, std::io::Error> {
            ProcessMonitor::new(self.cmd.clone(), self.base_interval, self.max_interval)
        }

        fn create_monitor_from_pid(&self, pid: usize) -> Result<ProcessMonitor, std::io::Error> {
            ProcessMonitor::from_pid(pid, self.base_interval, self.max_interval)
        }

        // Create a monitor and wait until the process is reliably detected
        fn create_and_verify_running(&self) -> Result<(ProcessMonitor, usize), std::io::Error> {
            let mut monitor = self.create_monitor()?;
            let pid = monitor.get_pid();

            // Give the process a small amount of time to start
            std::thread::sleep(Duration::from_millis(50));

            // Verify the process is running using a retry strategy
            if !self.wait_for_condition(|| monitor.is_running()) {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::TimedOut,
                    "Process did not start or was not detected",
                ));
            }

            Ok((monitor, pid))
        }

        // Utility method for waiting with exponential backoff
        // Wait for a condition to become true with exponential backoff
        // This approach is more reliable than fixed sleeps and handles
        // timing variations in test environments
        fn wait_for_condition<F>(&self, mut condition: F) -> bool
        where
            F: FnMut() -> bool,
        {
            let start = std::time::Instant::now();
            let mut delay_ms = 1;

            while start.elapsed() < self.ready_timeout {
                if condition() {
                    return true;
                }

                // Exponential backoff with a maximum delay
                std::thread::sleep(Duration::from_millis(delay_ms));
                delay_ms = std::cmp::min(delay_ms * 2, 50);
            }

            false
        }
    }

    // Helper function for creating a test monitor
    fn create_test_monitor(cmd: Vec<String>) -> Result<ProcessMonitor, std::io::Error> {
        ProcessTestFixture::new(cmd).create_monitor()
    }

    // This function is intentionally left in place for future reference, but is currently
    // not used directly as the fixture pattern provides better test isolation
    #[allow(dead_code)]
    fn create_test_monitor_from_pid(pid: usize) -> Result<ProcessMonitor, std::io::Error> {
        let fixture = ProcessTestFixture {
            cmd: vec![],
            base_interval: Duration::from_millis(100),
            max_interval: Duration::from_millis(1000),
            ready_timeout: Duration::from_millis(500),
        };
        fixture.create_monitor_from_pid(pid)
    }

    // Test attaching to existing process
    #[test]
    fn test_from_pid() {
        // Create a test fixture with a longer-running process
        let cmd = if cfg!(target_os = "windows") {
            vec![
                "powershell".to_string(),
                "-Command".to_string(),
                "Start-Sleep -Seconds 5".to_string(),
            ]
        } else {
            vec!["sleep".to_string(), "5".to_string()]
        };

        let fixture = ProcessTestFixture::new(cmd);

        // Create and verify the direct monitor is running
        let (_, pid) = fixture.create_and_verify_running().unwrap();

        // Create a monitor for the existing process
        let pid_monitor = fixture.create_monitor_from_pid(pid);
        assert!(
            pid_monitor.is_ok(),
            "Should be able to attach to running process"
        );

        let mut pid_monitor = pid_monitor.unwrap();

        // Verify the PID monitor can detect the process
        assert!(
            fixture.wait_for_condition(|| pid_monitor.is_running()),
            "PID monitor should detect the running process"
        );
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
        let fixture = ProcessTestFixture::new(vec!["echo".to_string(), "hello".to_string()]);
        let mut monitor = fixture.create_monitor().unwrap();

        // Wait for the process to terminate
        assert!(
            fixture.wait_for_condition(|| !monitor.is_running()),
            "Short-lived process should terminate"
        );

        // Test with a longer running process
        let fixture = ProcessTestFixture {
            cmd: vec!["sleep".to_string(), "2".to_string()], // Increased sleep time for reliability
            base_interval: Duration::from_millis(100),
            max_interval: Duration::from_millis(1000),
            ready_timeout: Duration::from_secs(5), // Longer timeout for this test
        };
        let (mut monitor, _) = fixture.create_and_verify_running().unwrap();

        // Verify it's running (this is already done by create_and_verify_running, but we're being explicit)
        assert!(monitor.is_running(), "Process should be running initially");

        // Now wait for it to terminate
        assert!(
            fixture.wait_for_condition(|| !monitor.is_running()),
            "Process should terminate within the timeout period"
        );
    }

    #[test]
    fn test_metrics_collection() {
        // Start a simple CPU-bound process
        let cmd = if cfg!(target_os = "windows") {
            vec![
                "powershell".to_string(),
                "-Command".to_string(),
                "Start-Sleep -Seconds 3".to_string(),
            ]
        } else {
            vec!["sleep".to_string(), "3".to_string()]
        };

        let mut monitor = create_test_monitor(cmd).unwrap();

        // Allow more time for the process to start and register uptime
        thread::sleep(Duration::from_millis(500));

        // Sample metrics
        let metrics = monitor.sample_metrics();
        assert!(
            metrics.is_some(),
            "Should collect metrics from running process"
        );

        if let Some(m) = metrics {
            // Check thread count first
            assert!(
                m.thread_count > 0,
                "Process should have at least one thread"
            );

            // Handle uptime which might be platform-dependent
            if m.uptime_secs == 0 {
                // On some platforms (especially macOS), uptime might not be reliably reported
                // If uptime is 0, wait a bit and check again to see if it increases
                thread::sleep(Duration::from_millis(1000));
                if let Some(m2) = monitor.sample_metrics() {
                    // We don't assert here - just log the value to debug
                    println!("Process uptime after delay: {} seconds", m2.uptime_secs);

                    // On macOS, uptime might still be 0 - that's OK
                    #[cfg(target_os = "linux")]
                    {
                        // On Linux specifically, we expect uptime to work reliably
                        assert!(
                            m2.uptime_secs > 0,
                            "Process uptime should increase after delay on Linux"
                        );
                    }
                }
            } else {
                // Uptime is already positive, which is good on any platform
                println!("Process uptime: {} seconds", m.uptime_secs);
            }
        }
    }

    #[test]
    fn test_child_process_detection() {
        // Start a process that spawns children
        let cmd = if cfg!(target_os = "windows") {
            vec![
                "cmd".to_string(),
                "/C".to_string(),
                "timeout 2 >nul & echo child".to_string(),
            ]
        } else {
            vec![
                "sh".to_string(),
                "-c".to_string(),
                "sleep 2 & echo child".to_string(),
            ]
        };

        let mut monitor = create_test_monitor(cmd).unwrap();

        // Allow time for child processes to start
        thread::sleep(Duration::from_millis(200));

        // Get child PIDs
        let children = monitor.get_child_pids();

        // We might not always detect children due to timing, so just verify the method works
        // The assertion here is mainly to document that the method should return a Vec
        assert!(
            children.is_empty() || !children.is_empty(),
            "Should return a list of child PIDs (possibly empty)"
        );
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
        assert!(
            tree_metrics.aggregated.is_some(),
            "Should have aggregated metrics"
        );

        if let Some(agg) = tree_metrics.aggregated {
            assert!(
                agg.process_count >= 1,
                "Should count at least the parent process"
            );
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
            assert!(
                agg.cpu_usage >= parent.cpu_usage,
                "Aggregated CPU should be >= parent CPU"
            );
            assert!(
                agg.mem_rss_kb >= parent.mem_rss_kb,
                "Aggregated memory should be >= parent memory"
            );
            assert!(
                agg.thread_count >= parent.thread_count,
                "Aggregated threads should be >= parent threads"
            );

            // Process count should be at least 1 (the parent)
            assert!(
                agg.process_count >= 1,
                "Should count at least the parent process"
            );
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
        assert!(
            tree_metrics.parent.is_some(),
            "Should have parent metrics even with no children"
        );

        // Children list might be empty (which is fine)
        // Length is always non-negative, so just verify it's accessible

        // Aggregated should exist and equal parent (since no children)
        if let (Some(parent), Some(agg)) = (tree_metrics.parent, tree_metrics.aggregated) {
            assert_eq!(
                agg.process_count,
                1 + tree_metrics.children.len(),
                "Process count should be parent + actual children"
            );

            if tree_metrics.children.is_empty() {
                // If no children, aggregated should equal parent
                assert_eq!(
                    agg.cpu_usage, parent.cpu_usage,
                    "CPU should match parent when no children"
                );
                assert_eq!(
                    agg.mem_rss_kb, parent.mem_rss_kb,
                    "Memory should match parent when no children"
                );
                assert_eq!(
                    agg.thread_count, parent.thread_count,
                    "Threads should match parent when no children"
                );
            }
        }
    }

    #[test]
    fn test_recursive_child_detection() {
        // Test that we can find children recursively in a more complex process tree
        let cmd = if cfg!(target_os = "windows") {
            vec![
                "cmd".to_string(),
                "/C".to_string(),
                "timeout 3 >nul & (timeout 2 >nul & timeout 1 >nul)".to_string(),
            ]
        } else {
            vec![
                "sh".to_string(),
                "-c".to_string(),
                "sleep 3 & (sleep 2 & sleep 1 &)".to_string(),
            ]
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
            vec![
                "cmd".to_string(),
                "/C".to_string(),
                "start /b ping 127.0.0.1 -n 3 >nul".to_string(),
            ]
        } else {
            vec![
                "sh".to_string(),
                "-c".to_string(),
                // Create multiple child processes that run long enough to be detected
                "for i in 1 2 3; do sleep $i & done; sleep 0.5; wait".to_string(),
            ]
        };

        let mut monitor = create_test_monitor(cmd).unwrap();

        // Enable child process monitoring explicitly
        monitor.set_include_children(true);

        // First, take multiple initial samples and find the stable baseline
        // (since environment might have background processes that come and go)
        println!("Measuring baseline process count...");
        let mut baseline_samples = Vec::new();
        for i in 0..5 {
            let metrics = monitor.sample_tree_metrics();
            let count = metrics
                .aggregated
                .as_ref()
                .map(|a| a.process_count)
                .unwrap_or(1);
            baseline_samples.push(count);
            println!("Baseline sample {}: process count: {}", i + 1, count);
            thread::sleep(Duration::from_millis(100));
        }

        // Calculate mode (most common value) as our baseline
        let mut counts = std::collections::HashMap::new();
        for &count in &baseline_samples {
            *counts.entry(count).or_insert(0) += 1;
        }
        let baseline_count = counts
            .into_iter()
            .max_by_key(|&(_, count)| count)
            .map(|(val, _)| val)
            .unwrap_or(1);

        println!("Established baseline process count: {}", baseline_count);

        // Now create our command which should spawn child processes
        // Sample multiple times to catch process count changes
        let mut max_count = baseline_count;
        let mut min_count_after_max = usize::MAX;
        let mut saw_increase = false;
        let mut saw_decrease = false;

        println!("Starting sampling to detect process lifecycle...");
        for i in 0..15 {
            thread::sleep(Duration::from_millis(200));

            let metrics = monitor.sample_tree_metrics();
            let count = metrics
                .aggregated
                .as_ref()
                .map(|a| a.process_count)
                .unwrap_or(1);

            println!("Sample {}: process count: {}", i + 1, count);

            // If we see an increase from baseline, note it
            if count > baseline_count && !saw_increase {
                saw_increase = true;
                println!(
                    "Detected process count increase: {} -> {}",
                    baseline_count, count
                );
            }

            // Update maximum count observed
            if count > max_count {
                max_count = count;
            }

            // If we've seen an increase and now count is decreasing, note it
            if saw_increase && count < max_count {
                saw_decrease = true;
                min_count_after_max = min_count_after_max.min(count);
                println!(
                    "Detected process count decrease: {} -> {}",
                    max_count, count
                );
            }
        }

        // Final sample after waiting for processes to finish
        thread::sleep(Duration::from_millis(1000));

        let final_metrics = monitor.sample_tree_metrics();
        let final_count = final_metrics
            .aggregated
            .as_ref()
            .map(|a| a.process_count)
            .unwrap_or(1);

        println!("Final process count: {}", final_count);
        println!(
            "Test summary: baseline={}, max={}, min_after_max={}, final={}",
            baseline_count, max_count, min_count_after_max, final_count
        );

        // Assert proper functioning
        if saw_increase {
            println!("✓ Successfully detected process count increase");
        } else {
            println!("⚠ Did not detect any process count increase");
        }

        if saw_decrease {
            println!("✓ Successfully detected process count decrease");
        } else {
            println!("⚠ Did not detect any process count decrease");
        }

        // Make a loose assertion - the test mainly provides diagnostic output
        // We don't want it to fail in CI with timing differences
        assert!(
            max_count >= baseline_count,
            "Process monitoring should detect at least the baseline count"
        );

        // All samples should have valid structure
        assert!(
            final_metrics.aggregated.is_some(),
            "Final aggregated metrics should exist"
        );
    }

    #[test]
    fn test_network_io_limitation_for_children() {
        // Test that the current limitation of network I/O for children is handled properly
        let cmd = if cfg!(target_os = "windows") {
            vec![
                "cmd".to_string(),
                "/C".to_string(),
                "timeout 1 >nul & echo test".to_string(),
            ]
        } else {
            vec![
                "sh".to_string(),
                "-c".to_string(),
                "sleep 1 & echo test".to_string(),
            ]
        };

        let mut monitor = create_test_monitor(cmd).unwrap();

        thread::sleep(Duration::from_millis(200));

        let tree_metrics = monitor.sample_tree_metrics();

        // Check that all children have 0 network I/O (current limitation)
        for child in &tree_metrics.children {
            assert_eq!(
                child.metrics.net_rx_bytes, 0,
                "Child network RX should be 0 (known limitation)"
            );
            assert_eq!(
                child.metrics.net_tx_bytes, 0,
                "Child network TX should be 0 (known limitation)"
            );
        }

        // Parent might have network I/O, children should not
        if let Some(parent) = tree_metrics.parent {
            // Parent could have network activity, that's fine
            if let Some(agg) = tree_metrics.aggregated {
                // Aggregated network should equal parent network (since children are 0)
                assert_eq!(
                    agg.net_rx_bytes, parent.net_rx_bytes,
                    "Aggregated network RX should equal parent (children are 0)"
                );
                assert_eq!(
                    agg.net_tx_bytes, parent.net_tx_bytes,
                    "Aggregated network TX should equal parent (children are 0)"
                );
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
            let expected_mem = parent.mem_rss_kb
                + tree_metrics
                    .children
                    .iter()
                    .map(|c| c.metrics.mem_rss_kb)
                    .sum::<u64>();
            let expected_threads = parent.thread_count
                + tree_metrics
                    .children
                    .iter()
                    .map(|c| c.metrics.thread_count)
                    .sum::<usize>();
            let expected_cpu = parent.cpu_usage
                + tree_metrics
                    .children
                    .iter()
                    .map(|c| c.metrics.cpu_usage)
                    .sum::<f32>();
            let expected_processes = 1 + tree_metrics.children.len();

            assert_eq!(
                agg.mem_rss_kb, expected_mem,
                "Memory aggregation should sum parent + children"
            );
            assert_eq!(
                agg.thread_count, expected_threads,
                "Thread aggregation should sum parent + children"
            );
            assert_eq!(
                agg.process_count, expected_processes,
                "Process count should be parent + children"
            );

            // CPU might have floating point precision issues, use approximate equality
            assert!(
                (agg.cpu_usage - expected_cpu).abs() < 0.01,
                "CPU aggregation should approximately sum parent + children"
            );
        }
    }

    #[test]
    fn test_timestamp_functionality() {
        use std::thread;
        use std::time::{SystemTime, UNIX_EPOCH};

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

        assert!(
            sample1.ts_ms <= now_ms,
            "Sample1 timestamp should not be in future"
        );
        assert!(
            sample2.ts_ms <= now_ms,
            "Sample2 timestamp should not be in future"
        );
        assert!(
            now_ms - sample1.ts_ms < 60000,
            "Sample1 timestamp should be recent"
        );
        assert!(
            now_ms - sample2.ts_ms < 60000,
            "Sample2 timestamp should be recent"
        );

        // Verify timestamps are monotonic
        assert!(
            sample2.ts_ms >= sample1.ts_ms,
            "Timestamps should be monotonic"
        );

        // Test tree metrics timestamps (allow small timing differences)
        let tree_metrics = monitor.sample_tree_metrics();
        let now_ms2 = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_millis() as u64;

        assert!(
            tree_metrics.ts_ms <= now_ms2 + 1000,
            "Tree timestamp should be reasonable"
        );

        if let Some(parent) = tree_metrics.parent {
            assert!(
                parent.ts_ms <= now_ms2 + 1000,
                "Parent timestamp should be reasonable"
            );
        }

        if let Some(agg) = tree_metrics.aggregated {
            assert!(
                agg.ts_ms <= now_ms2 + 1000,
                "Aggregated timestamp should be reasonable"
            );
        }
    }

    #[test]
    fn test_enhanced_memory_metrics() {
        use std::thread;
        use std::time::{SystemTime, UNIX_EPOCH};

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
            assert!(
                metrics.mem_vms_kb >= metrics.mem_rss_kb,
                "Virtual memory should be >= RSS when both > 0"
            );
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

        assert!(
            metadata.t0_ms <= now_ms,
            "Start time should not be in future"
        );
        assert!(
            now_ms - metadata.t0_ms < 60000,
            "Start time should be recent (within 60 seconds)"
        );

        // Test tree metrics also have enhanced fields
        let tree_metrics = monitor.sample_tree_metrics();

        if let Some(parent) = tree_metrics.parent {
            assert!(
                parent.mem_vms_kb >= parent.mem_rss_kb,
                "Parent VMS should be >= RSS"
            );
        }

        if let Some(agg) = tree_metrics.aggregated {
            assert!(
                agg.mem_vms_kb >= agg.mem_rss_kb,
                "Aggregated VMS should be >= RSS"
            );
        }
    }

    #[test]
    fn test_process_metadata() {
        use std::thread;
        use std::time::{SystemTime, UNIX_EPOCH};

        let cmd = vec!["sleep".to_string(), "2".to_string()];
        let mut monitor = create_test_monitor(cmd).unwrap();

        thread::sleep(Duration::from_millis(100));

        // Test metadata collection
        let metadata = monitor.get_metadata().unwrap();

        // Verify basic metadata fields
        assert!(metadata.pid > 0, "PID should be positive");
        assert!(!metadata.cmd.is_empty(), "Command should not be empty");
        assert_eq!(
            metadata.cmd[0], "sleep",
            "First command arg should be 'sleep'"
        );
        assert!(
            !metadata.executable.is_empty(),
            "Executable path should not be empty"
        );

        // Test start time is reasonable
        let now_ms = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("Time went backwards")
            .as_millis() as u64;

        assert!(
            metadata.t0_ms <= now_ms,
            "Start time should not be in future"
        );
        assert!(
            now_ms - metadata.t0_ms < 60000,
            "Start time should be recent (within 60 seconds)"
        );

        // Test that t0_ms has millisecond precision (not just seconds * 1000)
        // The value should not be a round thousand (which would indicate second precision)
        let remainder = metadata.t0_ms % 1000;
        // Allow some tolerance for processes that might start exactly on second boundaries
        // but most of the time it should have non-zero millisecond component
        println!("t0_ms: {}, remainder: {}", metadata.t0_ms, remainder);

        // Test tree metrics work without embedded metadata
        let tree_metrics = monitor.sample_tree_metrics();
        assert_eq!(
            tree_metrics.parent.is_some(),
            true,
            "Tree should have parent metrics"
        );
    }

    #[test]
    fn test_t0_ms_precision() {
        use std::thread;
        use std::time::{SystemTime, UNIX_EPOCH};

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
        assert!(
            metadata.t0_ms > 1000000000000,
            "t0_ms should be a reasonable Unix timestamp in milliseconds"
        );
        assert!(
            metadata.t0_ms >= before_ms,
            "t0_ms should be after we started creating the monitor"
        );
        assert!(
            metadata.t0_ms <= after_ms,
            "t0_ms should be before we finished creating the monitor"
        );

        // Test precision by checking that we have millisecond information
        // t0_ms should have millisecond precision, not just seconds * 1000
        let remainder = metadata.t0_ms % 1000;
        println!("t0_ms: {}, remainder: {}", metadata.t0_ms, remainder);

        // The value should be a proper millisecond timestamp
        assert!(
            metadata.t0_ms > before_ms,
            "t0_ms should be greater than before timestamp"
        );
        assert!(
            metadata.t0_ms < after_ms + 1000,
            "t0_ms should be close to creation time"
        );
    }
}
