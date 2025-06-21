#[cfg(feature = "ebpf")]
use crate::ebpf::metrics::AggregatedStacks;
#[cfg(feature = "ebpf")]
use crate::ebpf::offcpu_profiler::{ProcessedOffCpuEvent, StackFrame};
use crate::error::{self, Result};
use crate::monitor::summary::SummaryGenerator;
use crate::monitor::{
    AggregatedMetrics, ChildProcessMetrics, Metrics, ProcessMetadata, ProcessTreeMetrics, Summary,
};
use std::collections::HashMap;
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};
use sysinfo::{self, Pid, ProcessesToUpdate, System};

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

pub fn summary_from_json_file(file_path: &str) -> Result<Summary> {
    SummaryGenerator::from_json_file(file_path)
}

// Basic I/O baseline for the main process
#[derive(Debug, Clone)]
pub struct IoBaseline {
    pub disk_read_bytes: u64,
    pub disk_write_bytes: u64,
    pub net_rx_bytes: u64,
    pub net_tx_bytes: u64,
}

// I/O baseline for child processes
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
    io_baseline: Option<IoBaseline>,
    child_io_baselines: HashMap<usize, ChildIoBaseline>,
    since_process_start: bool,
    _include_children: bool,
    _max_duration: Option<Duration>,
    debug_mode: bool,
    #[cfg(feature = "ebpf")]
    ebpf_tracker: Option<crate::ebpf::SyscallTracker>,
    #[cfg(feature = "ebpf")]
    offcpu_profiler: Option<crate::ebpf::offcpu_profiler::OffCpuProfiler>,
    cpu_sampler: Option<crate::cpu_sampler::CpuSampler>,
}

// Type for Python bindings
pub type ProcessResult = Result<Metrics>;

// Convert errors to Python error
#[cfg(feature = "python")]
pub fn io_err_to_py_err<E: std::fmt::Display>(err: E) -> pyo3::PyErr {
    pyo3::exceptions::PyIOError::new_err(err.to_string())
}

// Create aggregated stacks for visualization
#[cfg(feature = "ebpf")]
fn create_aggregated_stacks(
    events: Vec<ProcessedOffCpuEvent>,
    min_occurrences: usize,
) -> AggregatedStacks {
    let mut aggregated = AggregatedStacks {
        user_stack: Vec::new(),
        kernel_stack: Vec::new(),
    };

    // Track thread IDs separately
    let mut thread_ids: Vec<(u32, u32)> = Vec::new();

    // Count occurrences of each stack
    let mut user_stack_counts = HashMap::new();
    let mut kernel_stack_counts = HashMap::new();

    for event in events {
        // Process user stack
        if let Some(user_stack) = &event.user_stack {
            let key = user_stack
                .iter()
                .map(|frame| {
                    frame
                        .symbol
                        .clone()
                        .unwrap_or_else(|| format!("0x{:x}", frame.address))
                })
                .collect::<Vec<String>>()
                .join(";");

            *user_stack_counts.entry(key).or_insert(0) += 1;
        }

        // Record thread IDs
        if !thread_ids.contains(&(event.event.pid, event.event.tid)) {
            thread_ids.push((event.event.pid, event.event.tid));
        }

        // Process kernel stack
        if let Some(kernel_stack) = &event.kernel_stack {
            let key = kernel_stack
                .iter()
                .map(|frame| {
                    frame
                        .symbol
                        .clone()
                        .unwrap_or_else(|| format!("0x{:x}", frame.address))
                })
                .collect::<Vec<String>>()
                .join(";");

            *kernel_stack_counts.entry(key).or_insert(0) += 1;
        }
    }

    // Filter stacks by minimum occurrences and convert to StackFrame format
    for (stack_str, count) in user_stack_counts {
        if count >= min_occurrences {
            let frames: Vec<String> = stack_str.split(';').map(String::from).collect();
            let stack_frames: Vec<StackFrame> = frames
                .iter()
                .map(|symbol| StackFrame {
                    address: 0, // We don't have the address information here
                    symbol: Some(symbol.clone()),
                    source_location: None,
                })
                .collect();

            aggregated.user_stack.extend(stack_frames);
        }
    }

    for (stack_str, count) in kernel_stack_counts {
        if count >= min_occurrences {
            let frames: Vec<String> = stack_str.split(';').map(String::from).collect();
            let stack_frames: Vec<StackFrame> = frames
                .iter()
                .map(|symbol| StackFrame {
                    address: 0, // We don't have the address information here
                    symbol: Some(symbol.clone()),
                    source_location: None,
                })
                .collect();

            aggregated.kernel_stack.extend(stack_frames);
        }
    }

    aggregated
}

impl ProcessMonitor {
    pub fn new(cmd: Vec<String>) -> Result<Self> {
        Self::new_with_options(
            cmd,
            Duration::from_millis(100),
            Duration::from_secs(1),
            false,
        )
    }

    pub fn new_with_options(
        cmd: Vec<String>,
        base_interval: Duration,
        max_interval: Duration,
        since_process_start: bool,
    ) -> Result<Self> {
        if cmd.is_empty() {
            return Err(error::DenetError::Other(
                "Command cannot be empty".to_string(),
            ));
        }

        // Create command with inherited stdout/stderr
        let mut command = Command::new(&cmd[0]);
        if cmd.len() > 1 {
            command.args(&cmd[1..]);
        }

        // Inherited I/O - allows users to see stdout/stderr
        command.stdout(Stdio::inherit());
        command.stderr(Stdio::inherit());

        let child = command.spawn()?;
        let pid = child.id() as usize;

        // Create system information collector
        let mut sys = System::new();
        sys.refresh_processes(ProcessesToUpdate::All, true);

        // Initialize CPU sampler
        let cpu_sampler = Some(crate::cpu_sampler::CpuSampler::new());

        let start_time = Instant::now();

        Ok(Self {
            child: Some(child),
            pid,
            sys,
            base_interval,
            max_interval,
            start_time,
            io_baseline: None,
            child_io_baselines: HashMap::new(),
            since_process_start,
            _include_children: true,
            _max_duration: None,
            debug_mode: false,
            #[cfg(feature = "ebpf")]
            ebpf_tracker: None,
            #[cfg(feature = "ebpf")]
            offcpu_profiler: None,
            cpu_sampler,
        })
    }

    pub fn from_pid(pid: usize) -> Result<Self> {
        Self::from_pid_with_options(
            pid,
            Duration::from_millis(100),
            Duration::from_secs(1),
            false,
        )
    }

    pub fn from_pid_with_options(
        pid: usize,
        base_interval: Duration,
        max_interval: Duration,
        since_process_start: bool,
    ) -> Result<Self> {
        let mut sys = System::new();
        sys.refresh_processes(ProcessesToUpdate::All, true);

        if sys.process(Pid::from_u32(pid as u32)).is_none() {
            return Err(error::DenetError::Other(format!(
                "Process with PID {} not found",
                pid
            )));
        }

        // Initialize CPU sampler
        let cpu_sampler = Some(crate::cpu_sampler::CpuSampler::new());
        let start_time = Instant::now();

        Ok(Self {
            child: None,
            pid,
            sys,
            base_interval,
            max_interval,
            start_time,
            io_baseline: None,
            child_io_baselines: HashMap::new(),
            since_process_start,
            _include_children: true,
            _max_duration: None,
            debug_mode: false,
            #[cfg(feature = "ebpf")]
            ebpf_tracker: None,
            #[cfg(feature = "ebpf")]
            offcpu_profiler: None,
            cpu_sampler,
        })
    }

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
    #[cfg(not(feature = "ebpf"))]
    pub fn enable_ebpf(&mut self) -> crate::error::Result<()> {
        log::warn!("eBPF feature not enabled at compile time");
        if self.debug_mode {
            println!("DEBUG: eBPF feature not enabled at compile time");
        }
        return Err(crate::error::DenetError::EbpfNotSupported(
            "eBPF feature not enabled at compile time".to_string(),
        ));
    }

    /// Enable eBPF profiling for this monitor
    #[cfg(feature = "ebpf")]
    pub fn enable_ebpf(&mut self) -> crate::error::Result<()> {
        if self.ebpf_tracker.is_none() {
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
            match crate::ebpf::SyscallTracker::new(pids.clone()) {
                Ok(tracker) => {
                    self.ebpf_tracker = Some(tracker);

                    // Initialize off-CPU profiler
                    match crate::ebpf::OffCpuProfiler::new(pids) {
                        Ok(mut profiler) => {
                            // Enable debug mode if needed
                            if self.debug_mode {
                                profiler.enable_debug_mode();
                            }
                            self.offcpu_profiler = Some(profiler);
                            log::info!("✅ Off-CPU profiler successfully enabled");
                            if self.debug_mode {
                                println!("DEBUG: Off-CPU profiler successfully enabled");
                            }
                        }
                        Err(e) => {
                            log::warn!("Failed to enable off-CPU profiler: {}", e);
                            if self.debug_mode {
                                println!("DEBUG: Failed to enable off-CPU profiler: {}", e);
                                // Still continue even if off-CPU profiler fails
                            }
                        }
                    }

                    // eBPF is now enabled via the tracker
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

    /// Calculate adaptive interval based on process runtime
    pub fn adaptive_interval(&self) -> Duration {
        let elapsed = self.start_time.elapsed();

        // Gradually increase the interval as the process runs longer
        let factor = (elapsed.as_secs_f64() / 60.0).min(10.0); // Cap at 10x after 10 minutes
        let adaptive = self.base_interval.as_secs_f64() * (1.0 + factor);

        // Ensure we don't exceed max_interval
        let capped = adaptive.min(self.max_interval.as_secs_f64());

        Duration::from_secs_f64(capped)
    }

    /// Sample metrics for the process and its children
    pub fn sample_metrics(&mut self) -> Option<Metrics> {
        // Check if process is still running
        if !self.is_running() {
            return None;
        }

        // Get current time for timestamps
        let now = Instant::now();
        let elapsed_ms = now.duration_since(self.start_time).as_millis() as u64;

        // Update system info
        self.sys.refresh_processes(ProcessesToUpdate::All, true);

        // Get process from system
        let process = match self.sys.process(Pid::from_u32(self.pid as u32)) {
            Some(p) => p,
            None => return None, // Process not found
        };

        // Gather CPU metrics
        let cpu_usage = process.cpu_usage();
        let cpu_percent = match &mut self.cpu_sampler {
            Some(sampler) => sampler.get_cpu_usage(self.pid).unwrap_or(cpu_usage),
            None => cpu_usage,
        };

        // Gather memory metrics
        let memory_used = process.memory() * 1024; // Convert KB to bytes
        let virtual_memory = process.virtual_memory() * 1024; // Convert KB to bytes

        // Get additional metrics like resident set size if available
        let resident_set_size = memory_used; // For simplicity

        // Get disk I/O metrics
        let disk_read = process.disk_usage().read_bytes;
        let disk_write = process.disk_usage().written_bytes;

        // Get network I/O (platform-specific)
        let (net_rx, net_tx) = if cfg!(target_os = "linux") {
            // On Linux, we can get per-process network stats
            (
                self.get_process_net_rx_bytes(self.pid),
                self.get_process_net_tx_bytes(self.pid),
            )
        } else {
            // On other platforms, default to zero for now
            (0, 0)
        };

        // Initialize I/O baseline if needed
        if self.io_baseline.is_none() {
            self.io_baseline = Some(IoBaseline {
                disk_read_bytes: disk_read,
                disk_write_bytes: disk_write,
                net_rx_bytes: net_rx,
                net_tx_bytes: net_tx,
            });
        }

        // Calculate deltas if using since_process_start mode
        let (disk_read_delta, disk_write_delta, net_rx_delta, net_tx_delta) =
            if let Some(baseline) = &self.io_baseline {
                if self.since_process_start {
                    (
                        disk_read - baseline.disk_read_bytes,
                        disk_write - baseline.disk_write_bytes,
                        net_rx - baseline.net_rx_bytes,
                        net_tx - baseline.net_tx_bytes,
                    )
                } else {
                    (disk_read, disk_write, net_rx, net_tx)
                }
            } else {
                (disk_read, disk_write, net_rx, net_tx)
            };

        // Gather process metadata
        let executable = process
            .exe()
            .and_then(|p| p.to_str())
            .unwrap_or("")
            .to_string();
        let cmd = process
            .cmd()
            .iter()
            .map(|s| s.to_string_lossy().into_owned())
            .collect::<Vec<String>>();

        let _metadata = ProcessMetadata::new(self.pid, cmd, executable);

        // Create metrics object
        let mut metrics = Metrics::new();
        metrics.ts_ms = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_millis() as u64)
            .unwrap_or(0);
        metrics.cpu_usage = cpu_percent;
        metrics.mem_rss_kb = resident_set_size;
        metrics.mem_vms_kb = virtual_memory;
        metrics.disk_read_bytes = disk_read_delta;
        metrics.disk_write_bytes = disk_write_delta;
        metrics.net_rx_bytes = net_rx_delta;
        metrics.net_tx_bytes = net_tx_delta;
        metrics.thread_count = get_thread_count(self.pid);
        metrics.uptime_secs = elapsed_ms / 1000;

        // Add eBPF metrics if available
        #[cfg(feature = "ebpf")]
        if let Some(tracker) = &self.ebpf_tracker {
            // We don't directly set syscalls and io_metrics on Metrics anymore
            // They're part of AggregatedMetrics now
            let _ebpf_metrics = tracker.get_metrics();
        }

        #[cfg(feature = "ebpf")]
        if let Some(profiler) = &mut self.offcpu_profiler {
            let off_cpu_stats = profiler.get_stats();
            if !off_cpu_stats.is_empty() {
                // We now work directly with the off-CPU stats for stack traces
                // Instead of trying to extract processed events (which are no longer available)
                // we'll gather the stack traces directly from the profiler
                let stack_traces = profiler.get_stack_traces();

                // If we have any stack traces, create aggregated stacks
                // In the current Metrics structure, we don't directly store stacks
                // They will be handled in AggregatedMetrics instead
                if !stack_traces.is_empty() {
                    let _stacks = create_aggregated_stacks(stack_traces, 1);
                    // We'll handle these stacks in AggregatedMetrics
                }
            }
        }

        Some(metrics)
    }

    /// Check if the process is still running
    pub fn is_running(&mut self) -> bool {
        // First, refresh process list
        self.sys.refresh_processes(ProcessesToUpdate::All, true);

        // Check if child process has exited
        if let Some(child) = &mut self.child {
            match child.try_wait() {
                Ok(Some(_)) => {
                    // Child has exited
                    return false;
                }
                Ok(None) => {
                    // Child is still running
                    return true;
                }
                Err(_) => {
                    // Error checking child status
                    // Fall back to checking via sysinfo
                }
            }
        }

        // Check via sysinfo
        self.sys.process(Pid::from_u32(self.pid as u32)).is_some()
    }

    /// Get the process ID
    pub fn get_pid(&self) -> usize {
        self.pid
    }

    /// Set whether to include children in metrics
    pub fn set_include_children(&mut self, include: bool) {
        self._include_children = include;
    }

    /// Check if children are included in metrics
    pub fn get_include_children(&self) -> bool {
        self._include_children
    }

    /// Get process metadata
    ///
    /// Returns information about the process being monitored,
    /// including command line, start time, etc.
    /// Get metadata for the current process
    pub fn get_metadata(&self) -> Option<ProcessMetadata> {
        if let Some(process) = self.sys.process(Pid::from_u32(self.pid as u32)) {
            let executable = process
                .exe()
                .and_then(|p| p.to_str())
                .unwrap_or("")
                .to_string();
            let cmd = process
                .cmd()
                .iter()
                .map(|s| s.to_string_lossy().into_owned())
                .collect::<Vec<String>>();

            Some(ProcessMetadata::new(self.pid, cmd, executable))
        } else {
            None
        }
    }

    /// Get the PIDs of child processes
    pub fn get_child_pids(&self) -> Vec<usize> {
        let mut children = Vec::new();
        self.find_children_recursive(self.pid, &mut children);
        children
    }

    /// Recursively find all children of a process
    fn find_children_recursive(&self, parent_pid: usize, children: &mut Vec<usize>) {
        for (pid, _) in self.sys.processes() {
            if let Some(process) = self.sys.process(*pid) {
                if let Some(ppid) = process.parent() {
                    if ppid.as_u32() as usize == parent_pid && pid.as_u32() as usize != parent_pid {
                        children.push(pid.as_u32() as usize);
                        // Recursively find children of this child
                        self.find_children_recursive(pid.as_u32() as usize, children);
                    }
                }
            }
        }
    }

    /// Sample metrics for the process tree
    pub fn sample_tree_metrics(&mut self) -> Option<ProcessTreeMetrics> {
        // Check if process is still running
        if !self.is_running() {
            return None;
        }

        // Get current time for timestamps
        let now = Instant::now();
        let elapsed_ms = now.duration_since(self.start_time).as_millis() as u64;

        // Update system info
        self.sys.refresh_processes(ProcessesToUpdate::All, true);

        // Get process from system
        let process = match self.sys.process(Pid::from_u32(self.pid as u32)) {
            Some(p) => p,
            None => return None, // Process not found
        };

        // Gather CPU metrics
        let cpu_usage = process.cpu_usage();
        let cpu_percent = match &mut self.cpu_sampler {
            Some(sampler) => sampler.get_cpu_usage(self.pid).unwrap_or(cpu_usage),
            None => cpu_usage,
        };

        // Gather memory metrics
        let memory_used = process.memory() * 1024; // Convert KB to bytes
        let virtual_memory = process.virtual_memory() * 1024; // Convert KB to bytes

        // Get additional metrics like resident set size if available
        let resident_set_size = memory_used; // For simplicity

        // Get disk I/O metrics
        let disk_read = process.disk_usage().read_bytes;
        let disk_write = process.disk_usage().written_bytes;

        // Get network I/O (platform-specific)
        let (net_rx, net_tx) = if cfg!(target_os = "linux") {
            // On Linux, we can get per-process network stats
            (
                self.get_process_net_rx_bytes(self.pid),
                self.get_process_net_tx_bytes(self.pid),
            )
        } else {
            // On other platforms, default to zero for now
            (0, 0)
        };

        // Initialize I/O baseline if needed
        if self.io_baseline.is_none() {
            self.io_baseline = Some(IoBaseline {
                disk_read_bytes: disk_read,
                disk_write_bytes: disk_write,
                net_rx_bytes: net_rx,
                net_tx_bytes: net_tx,
            });
        }

        // Calculate deltas if using since_process_start mode
        let (disk_read_delta, disk_write_delta, net_rx_delta, net_tx_delta) =
            if let Some(baseline) = &self.io_baseline {
                if self.since_process_start {
                    (
                        disk_read - baseline.disk_read_bytes,
                        disk_write - baseline.disk_write_bytes,
                        net_rx - baseline.net_rx_bytes,
                        net_tx - baseline.net_tx_bytes,
                    )
                } else {
                    (disk_read, disk_write, net_rx, net_tx)
                }
            } else {
                (disk_read, disk_write, net_rx, net_tx)
            };

        // Gather process metadata
        let executable = process
            .exe()
            .and_then(|p| p.to_str())
            .unwrap_or("")
            .to_string();
        let cmd = process
            .cmd()
            .iter()
            .map(|s| s.to_string_lossy().into_owned())
            .collect::<Vec<String>>();

        let _metadata = ProcessMetadata::new(process.pid().as_u32() as usize, cmd, executable);

        // Create metrics for the parent process
        let mut parent_metrics = Metrics::new();
        parent_metrics.ts_ms = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_millis() as u64)
            .unwrap_or(0);
        parent_metrics.cpu_usage = cpu_percent;
        parent_metrics.mem_rss_kb = resident_set_size;
        parent_metrics.mem_vms_kb = virtual_memory;
        parent_metrics.disk_read_bytes = disk_read_delta;
        parent_metrics.disk_write_bytes = disk_write_delta;
        parent_metrics.net_rx_bytes = net_rx_delta;
        parent_metrics.net_tx_bytes = net_tx_delta;
        parent_metrics.thread_count = get_thread_count(self.pid);
        parent_metrics.uptime_secs = elapsed_ms / 1000;
        // Set CPU core if available
        parent_metrics.cpu_core = self.get_process_cpu_core(self.pid);

        // Add eBPF metrics if available
        #[cfg(feature = "ebpf")]
        if let Some(tracker) = &self.ebpf_tracker {
            // Get eBPF metrics but don't attach them directly
            // They're handled separately through AggregatedMetrics
            let _ebpf_metrics = tracker.get_metrics();
        }

        // Get child processes
        let child_pids = self.get_child_pids();
        let mut child_metrics_list = Vec::new();

        // Aggregate child process metrics
        for child_pid in child_pids {
            if let Some(child_proc) = self.sys.process(Pid::from_u32(child_pid as u32)) {
                // Get CPU metrics for child
                let child_cpu = child_proc.cpu_usage();

                // Get memory metrics for child
                let child_memory = child_proc.memory() * 1024; // Convert KB to bytes
                let child_virtual_memory = child_proc.virtual_memory() * 1024; // Convert KB to bytes

                // Get disk I/O metrics for child
                let child_disk_read = child_proc.disk_usage().read_bytes;
                let child_disk_write = child_proc.disk_usage().written_bytes;

                // Get network I/O for child (platform-specific)
                let (child_net_rx, child_net_tx) = if cfg!(target_os = "linux") {
                    (
                        self.get_process_net_rx_bytes(child_pid),
                        self.get_process_net_tx_bytes(child_pid),
                    )
                } else {
                    (0, 0)
                };

                // Initialize I/O baseline for child if needed
                if !self.child_io_baselines.contains_key(&child_pid) {
                    self.child_io_baselines.insert(
                        child_pid,
                        ChildIoBaseline {
                            pid: child_pid,
                            disk_read_bytes: child_disk_read,
                            disk_write_bytes: child_disk_write,
                            net_rx_bytes: child_net_rx,
                            net_tx_bytes: child_net_tx,
                        },
                    );
                }

                // Calculate deltas if using since_process_start mode
                let (
                    child_disk_read_delta,
                    child_disk_write_delta,
                    child_net_rx_delta,
                    child_net_tx_delta,
                ) = if let Some(baseline) = self.child_io_baselines.get(&child_pid) {
                    if self.since_process_start {
                        (
                            child_disk_read - baseline.disk_read_bytes,
                            child_disk_write - baseline.disk_write_bytes,
                            child_net_rx - baseline.net_rx_bytes,
                            child_net_tx - baseline.net_tx_bytes,
                        )
                    } else {
                        (
                            child_disk_read,
                            child_disk_write,
                            child_net_rx,
                            child_net_tx,
                        )
                    }
                } else {
                    (
                        child_disk_read,
                        child_disk_write,
                        child_net_rx,
                        child_net_tx,
                    )
                };

                // Get CPU core for child process
                let cpu_core = self.get_process_cpu_core(child_pid);

                // Create child metrics
                let command = child_proc
                    .cmd()
                    .iter()
                    .map(|s| s.to_string_lossy().into_owned())
                    .collect::<Vec<String>>()
                    .join(" ");

                let mut child_metrics_data = Metrics::new();
                child_metrics_data.ts_ms = SystemTime::now()
                    .duration_since(UNIX_EPOCH)
                    .map(|d| d.as_millis() as u64)
                    .unwrap_or(0);
                child_metrics_data.cpu_usage = child_cpu;
                child_metrics_data.mem_rss_kb = child_memory;
                child_metrics_data.mem_vms_kb = child_virtual_memory;
                child_metrics_data.disk_read_bytes = child_disk_read_delta;
                child_metrics_data.disk_write_bytes = child_disk_write_delta;
                child_metrics_data.net_rx_bytes = child_net_rx_delta;
                child_metrics_data.net_tx_bytes = child_net_tx_delta;
                child_metrics_data.thread_count = get_thread_count(child_pid);
                child_metrics_data.cpu_core = cpu_core;

                let child_process_metrics = ChildProcessMetrics {
                    pid: child_pid,
                    command,
                    metrics: child_metrics_data,
                };

                child_metrics_list.push(child_process_metrics);
            }
        }

        // Create aggregated metrics for the process tree
        let mut all_metrics = vec![parent_metrics.clone()];
        for child in &child_metrics_list {
            all_metrics.push(child.metrics.clone());
        }
        let mut aggregated = AggregatedMetrics::from_metrics(&all_metrics);
        aggregated.process_count = 1 + child_metrics_list.len();

        // Get current time in ms since epoch
        let ts_ms = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_millis() as u64)
            .unwrap_or(0);

        // Create the tree metrics object
        Some(ProcessTreeMetrics {
            ts_ms,
            parent: Some(parent_metrics),
            children: child_metrics_list,
            aggregated: Some(aggregated),
        })
    }

    fn get_process_net_rx_bytes(&self, pid: usize) -> u64 {
        if cfg!(target_os = "linux") {
            self.get_linux_process_net_stats(pid).0
        } else {
            0
        }
    }

    fn get_process_net_tx_bytes(&self, pid: usize) -> u64 {
        if cfg!(target_os = "linux") {
            self.get_linux_process_net_stats(pid).1
        } else {
            0
        }
    }

    #[cfg(target_os = "linux")]
    fn get_linux_process_net_stats(&self, pid: usize) -> (u64, u64) {
        // Read /proc/net/dev for system-wide network stats
        let net_stats = match std::fs::read_to_string("/proc/net/dev") {
            Ok(content) => content,
            Err(_) => return (0, 0),
        };

        // Get the process's file descriptors for sockets
        let fd_dir = format!("/proc/{}/fd", pid);
        let sockets = match std::fs::read_dir(fd_dir) {
            Ok(entries) => entries
                .filter_map(|res| res.ok())
                .filter_map(|entry| {
                    let fd_path = entry.path();
                    match std::fs::read_link(&fd_path) {
                        Ok(link) => {
                            let link_str = link.to_string_lossy();
                            if link_str.starts_with("socket:") {
                                Some(link_str.to_string())
                            } else {
                                None
                            }
                        }
                        Err(_) => None,
                    }
                })
                .collect::<Vec<String>>(),
            Err(_) => return (0, 0),
        };

        // For now, as a simple heuristic, just divide system-wide network stats
        // by the number of active processes with network activity
        let (total_rx, total_tx) = self.parse_net_dev(&net_stats);
        let process_count = self.sys.processes().len();
        if process_count > 0 && !sockets.is_empty() {
            (
                total_rx / process_count as u64,
                total_tx / process_count as u64,
            )
        } else {
            (0, 0)
        }
    }

    #[cfg(not(target_os = "linux"))]
    fn get_linux_process_net_stats(&self, _pid: usize) -> (u64, u64) {
        (0, 0)
    }

    fn parse_net_dev(&self, content: &str) -> (u64, u64) {
        let mut total_rx = 0;
        let mut total_tx = 0;

        for line in content.lines().skip(2) {
            // Skip header lines
            let parts: Vec<&str> = line.split_whitespace().collect();
            if parts.len() >= 10 {
                // Format is: Interface: rx_bytes rx_packets ... tx_bytes tx_packets ...
                if let Ok(rx) = parts[1].parse::<u64>() {
                    total_rx += rx;
                }
                if let Ok(tx) = parts[9].parse::<u64>() {
                    total_tx += tx;
                }
            }
        }

        (total_rx, total_tx)
    }

    // Get the CPU core a process is running on
    #[cfg(target_os = "linux")]
    fn get_process_cpu_core(&self, pid: usize) -> Option<u32> {
        let stat_path = format!("/proc/{}/stat", pid);
        if let Ok(content) = std::fs::read_to_string(stat_path) {
            let parts: Vec<&str> = content.split_whitespace().collect();
            // The CPU core is at index 38 (0-indexed)
            if parts.len() >= 39 {
                if let Ok(core) = parts[38].parse::<u32>() {
                    return Some(core);
                }
            }
        }
        None
    }

    #[cfg(not(target_os = "linux"))]
    fn get_process_cpu_core(&self, _pid: usize) -> Option<u32> {
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::env;
    use std::thread;
    use std::time::{Duration, Instant};

    struct ProcessTestFixture {
        cmd: Vec<String>,
        base_interval: Duration,
        max_interval: Duration,
        ready_timeout: Duration,
    }

    impl ProcessTestFixture {
        fn new() -> Self {
            Self {
                cmd: vec!["sleep".to_string(), "1".to_string()],
                base_interval: Duration::from_millis(100),
                max_interval: Duration::from_millis(200),
                ready_timeout: Duration::from_secs(5),
            }
        }

        fn create_monitor(&self) -> Result<ProcessMonitor, std::io::Error> {
            ProcessMonitor::new_with_options(
                self.cmd.clone(),
                self.base_interval,
                self.max_interval,
                false,
            )
        }

        fn create_monitor_from_pid(&self, pid: usize) -> Result<ProcessMonitor, std::io::Error> {
            ProcessMonitor::from_pid_with_options(pid, self.base_interval, self.max_interval, false)
        }

        fn create_and_verify_running(&self) -> Result<ProcessMonitor, std::io::Error> {
            let monitor = self.create_monitor()?;
            let pid = monitor.get_pid();
            assert!(pid > 0, "PID should be positive");

            // Verify process is running
            let mut sys = System::new();
            sys.refresh_processes(ProcessesToUpdate::All, true);
            assert!(
                sys.process(Pid::from_u32(pid as u32)).is_some(),
                "Process should be running"
            );

            Ok(monitor)
        }

        fn wait_for_condition<F>(&self, mut condition: F) -> bool
        where
            F: FnMut() -> bool,
        {
            let start = Instant::now();
            while start.elapsed() < self.ready_timeout {
                if condition() {
                    return true;
                }
                thread::sleep(Duration::from_millis(50));
            }
            false
        }
    }

    fn create_test_monitor() -> Result<ProcessMonitor, std::io::Error> {
        ProcessTestFixture::new().create_monitor()
    }

    #[cfg(target_os = "linux")]
    fn create_test_monitor_from_pid() -> Result<ProcessMonitor, std::io::Error> {
        let fixture = ProcessTestFixture::new();
        let pid = std::process::id() as usize;
        let mut sys = System::new();
        sys.refresh_processes(ProcessesToUpdate::All, true);
        if sys.process(Pid::from_u32(pid as u32)).is_some() {
            fixture.create_monitor_from_pid(pid)
        } else {
            Err(std::io::Error::new(
                std::io::ErrorKind::NotFound,
                "Current process not found",
            ))
        }
    }

    #[test]
    fn test_from_pid() -> Result<(), std::io::Error> {
        let pid = std::process::id() as usize;
        let monitor = ProcessMonitor::from_pid(pid)?;
        assert_eq!(monitor.get_pid(), pid);

        // Test invalid PID
        let result = ProcessMonitor::from_pid(0);
        assert!(result.is_err());

        // Test non-existent PID (using a very large value)
        let result = ProcessMonitor::from_pid(u32::MAX as usize);
        assert!(result.is_err());
        if let Err(e) = result {
            assert_eq!(e.kind(), std::io::ErrorKind::NotFound);
        }

        Ok(())
    }

    #[test]
    fn test_adaptive_interval() -> Result<(), std::io::Error> {
        let mut monitor = create_test_monitor()?;
        let initial = monitor.adaptive_interval();
        assert_eq!(initial, monitor.base_interval);

        // Wait a bit to allow the interval to adapt
        thread::sleep(Duration::from_millis(500));
        let adapted = monitor.adaptive_interval();
        assert!(adapted >= initial);
        assert!(adapted <= monitor.max_interval);

        Ok(())
    }

    #[test]
    fn test_is_running() -> Result<(), std::io::Error> {
        let fixture = ProcessTestFixture::new();
        let cmd = if cfg!(target_os = "windows") {
            vec!["timeout".to_string(), "2".to_string()]
        } else {
            vec!["sleep".to_string(), "2".to_string()]
        };
        let test_fixture = ProcessTestFixture { cmd, ..fixture };

        let mut monitor = test_fixture.create_monitor()?;
        assert!(monitor.is_running());

        // Wait for process to exit
        assert!(fixture.wait_for_condition(|| !monitor.is_running()));

        // Test from PID with a short-lived process
        if cfg!(target_os = "linux") {
            if let Ok(mut monitor) = create_test_monitor_from_pid() {
                assert!(monitor.is_running());
            }
        }

        Ok(())
    }

    #[test]
    fn test_metrics_collection() -> Result<(), std::io::Error> {
        let fixture = ProcessTestFixture::new();

        // Create a slightly longer-running process for more reliable metrics
        let cmd = if cfg!(target_os = "windows") {
            vec!["timeout".to_string(), "2".to_string()]
        } else {
            vec!["sleep".to_string(), "2".to_string()]
        };
        let test_fixture = ProcessTestFixture { cmd, ..fixture };

        let mut monitor = test_fixture.create_monitor()?;
        assert!(monitor.is_running());

        // Sample metrics
        let metrics = monitor.sample_metrics();
        assert!(metrics.is_some());
        let metrics = metrics.unwrap();

        // Basic validation
        assert_eq!(metrics.pid, monitor.get_pid());
        assert!(metrics.cpu_percent >= 0.0);
        assert!(metrics.memory_used > 0);
        assert!(metrics.thread_count > 0);
        assert!(metrics.timestamp_ms > 0);
        assert!(metrics.elapsed_ms >= 0);
        assert_eq!(metrics.t0_ms, monitor.t0_ms);

        // Check metadata
        assert!(metrics.metadata.is_some());
        let metadata = metrics.metadata.unwrap();
        assert_eq!(metadata.pid, monitor.get_pid());
        assert!(!metadata.name.is_empty());
        assert!(!metadata.command.is_empty());
        assert_eq!(metadata.start_time, monitor.t0_ms);

        Ok(())
    }

    // More tests would normally be implemented here
}
