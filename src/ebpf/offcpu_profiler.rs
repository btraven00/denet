//! Off-CPU profiler implementation using eBPF
//!
//! This module implements a profiler that tracks time spent by threads
//! while they are not running on a CPU (i.e., blocked, waiting for I/O,
//! or sleeping). This information can be used to identify bottlenecks
//! related to I/O, locks, and other blocking operations.

use std::collections::HashMap;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::Duration;

#[cfg(feature = "ebpf")]
use crate::ebpf::debug;
#[cfg(feature = "ebpf")]
use aya::{include_bytes_aligned, programs::TracePoint, Ebpf};
#[cfg(feature = "ebpf")]
use log::{debug, error, info};

/// The raw eBPF bytecode for the offcpu profiler
///
/// This is embedded in the binary during compilation
#[cfg(feature = "ebpf")]
const OFFCPU_PROFILER_BYTECODE: &[u8] =
    include_bytes_aligned!(concat!(env!("OUT_DIR"), "/ebpf/offcpu_profiler.o"));

#[cfg(feature = "ebpf")]
use crate::ebpf::memory_map_cache::MemoryMapCache;
#[cfg(feature = "ebpf")]
use aya::maps::perf::PerfEventArray;
#[cfg(feature = "ebpf")]
use aya::maps::stack_trace::StackTraceMap;
use aya::util::online_cpus;
#[cfg(feature = "ebpf")]
use bytes::BytesMut;

/// Represents a single frame in a stack trace
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StackFrame {
    /// Memory address of the instruction
    pub address: u64,
    /// Symbol name (if available through symbolication)
    pub symbol: Option<String>,
    /// Source file and line information (if available)
    pub source_location: Option<String>,
}

/// The OffCpuEvent structure that matches the eBPF program's output
#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
#[repr(C)]
pub struct OffCpuEvent {
    /// Process ID
    pub pid: u32,
    /// Thread ID
    pub tid: u32,
    /// Previous thread state when it was scheduled out
    pub prev_state: u32,
    /// Time spent off-CPU in nanoseconds
    pub offcpu_time_ns: u64,
    /// Timestamp when the thread was scheduled out
    pub start_time_ns: u64,
    /// Timestamp when the thread was scheduled back in
    pub end_time_ns: u64,
    /// User-space stack trace ID
    pub user_stack_id: u32,
    /// Kernel-space stack trace ID
    pub kernel_stack_id: u32,
}

/// Processed off-CPU event with stack trace information
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProcessedOffCpuEvent {
    /// Raw off-CPU event
    pub event: OffCpuEvent,
    /// User-space stack frames (if available)
    pub user_stack: Option<Vec<StackFrame>>,
    /// Kernel-space stack frames (if available)
    pub kernel_stack: Option<Vec<StackFrame>>,
    /// Process name
    pub process_name: Option<String>,
    /// Thread name
    pub thread_name: Option<String>,
    /// Error information for user stack trace (if an error occurred)
    pub user_stack_error: Option<String>,
    /// Error information for kernel stack trace (if an error occurred)
    pub kernel_stack_error: Option<String>,
    /// List of threads that experienced this stack trace
    pub threads: Vec<(u32, u32)>,
}

/// Summary statistics for a stack trace
#[derive(Debug, Clone)]
pub struct StackTraceSummary {
    /// User-space stack trace ID
    pub user_stack_id: u32,
    /// Kernel-space stack trace ID
    pub kernel_stack_id: u32,
    /// Total time spent off-CPU with this stack trace (ns)
    pub total_time_ns: u64,
    /// Number of occurrences of this stack trace
    pub count: u64,
    /// User-space stack frames (if available)
    pub user_stack: Option<Vec<StackFrame>>,
    /// Kernel-space stack frames (if available)
    pub kernel_stack: Option<Vec<StackFrame>>,
    /// List of (pid, tid) pairs that experienced this stack trace
    pub threads: Vec<(u32, u32)>,
}

/// Thread-specific stack trace statistics
#[derive(Debug, Clone)]
pub struct ThreadStackStats {
    /// Process ID
    pub pid: u32,
    /// Thread ID
    pub tid: u32,
    /// Total time spent off-CPU with this stack trace (ns)
    pub total_time_ns: u64,
    /// Number of occurrences of this stack trace
    pub count: u64,
}

impl From<OffCpuEvent> for ProcessedOffCpuEvent {
    fn from(event: OffCpuEvent) -> Self {
        Self {
            event,
            user_stack: None,
            kernel_stack: None,
            process_name: None,
            thread_name: None,
            user_stack_error: None,
            kernel_stack_error: None,
            threads: Vec::new(),
        }
    }
}

/// Aggregated off-CPU statistics for a thread
#[derive(Debug, Clone, Default)]
pub struct OffCpuStats {
    /// Total time spent off-CPU (nanoseconds)
    pub total_time_ns: u64,
    /// Number of times the thread was scheduled out
    pub count: u64,
    /// Average time spent off-CPU (nanoseconds)
    pub avg_time_ns: u64,
    /// Maximum time spent off-CPU (nanoseconds)
    pub max_time_ns: u64,
    /// Minimum time spent off-CPU (nanoseconds)
    pub min_time_ns: u64,
}

/// Off-CPU profiler that uses eBPF to track thread scheduling
/// The OffCpuProfiler structure that manages the eBPF off-CPU profiling
pub struct OffCpuProfiler {
    /// eBPF program and maps
    #[cfg(feature = "ebpf")]
    bpf: Option<Ebpf>,

    /// Monitored process IDs
    monitored_pids: Vec<u32>,

    /// Off-CPU statistics by thread
    stats: Arc<Mutex<HashMap<(u32, u32), OffCpuStats>>>,

    /// Collected events
    events: Arc<Mutex<Vec<ProcessedOffCpuEvent>>>,

    /// Whether the eBPF programs are attached
    #[cfg(feature = "ebpf")]
    _attached_programs: bool,

    /// Running flag for event handler threads
    #[cfg(feature = "ebpf")]
    running: Arc<AtomicBool>,

    /// Perf reader handles for the perf event maps
    #[cfg(feature = "ebpf")]
    _perf_readers: Vec<std::thread::JoinHandle<()>>,

    /// Debug mode flag
    debug_mode: bool,

    /// Memory map cache for symbolication
    #[cfg(feature = "ebpf")]
    memory_map_cache: MemoryMapCache,
}

/// Global debug mode flag for the OffCpuProfiler
#[cfg(feature = "ebpf")]
static DEBUG_MODE: AtomicBool = AtomicBool::new(false);

// Helper function to create a default OffCpuEvent
impl Default for OffCpuEvent {
    fn default() -> Self {
        Self {
            pid: 0,
            tid: 0,
            prev_state: 0,
            offcpu_time_ns: 0,
            start_time_ns: 0,
            end_time_ns: 0,
            user_stack_id: 0,
            kernel_stack_id: 0,
        }
    }
}

// Helper to create off-CPU stats entries for a thread
fn create_offcpu_stats() -> OffCpuStats {
    OffCpuStats {
        total_time_ns: 0,
        count: 0,
        avg_time_ns: 0,
        max_time_ns: 0,
        min_time_ns: u64::MAX,
    }
}

impl OffCpuProfiler {
    /// Create a new Off-CPU profiler
    pub fn new(pids: Vec<u32>) -> crate::error::Result<Self> {
        // Create memory map cache with debug mode if enabled
        #[cfg(feature = "ebpf")]
        let debug_enabled = unsafe { debug::is_debug_mode() };

        #[cfg(feature = "ebpf")]
        let memory_map_cache = if DEBUG_MODE.load(Ordering::Relaxed) || debug_enabled {
            MemoryMapCache::with_debug()
        } else {
            MemoryMapCache::new()
        };

        let mut profiler = OffCpuProfiler {
            #[cfg(feature = "ebpf")]
            bpf: None,
            monitored_pids: pids.clone(),
            stats: Arc::new(Mutex::new(HashMap::new())),
            events: Arc::new(Mutex::new(Vec::new())),
            #[cfg(feature = "ebpf")]
            _attached_programs: false,
            #[cfg(feature = "ebpf")]
            running: Arc::new(AtomicBool::new(true)),
            #[cfg(feature = "ebpf")]
            _perf_readers: Vec::new(),
            debug_mode: debug_enabled,
            #[cfg(feature = "ebpf")]
            memory_map_cache,
        };

        // Cache memory maps for all monitored PIDs immediately
        #[cfg(feature = "ebpf")]
        {
            for pid in &pids {
                profiler.memory_map_cache.refresh_maps_for_pid(*pid);
                if profiler.debug_mode {
                    debug::debug_println(&format!("Pre-cached memory maps for PID {}", pid));
                }
            }
        }

        // Cache memory maps for all monitored PIDs
        #[cfg(feature = "ebpf")]
        for pid in &pids {
            profiler.memory_map_cache.refresh_maps_for_pid(*pid);
        }

        // Cache memory maps for all monitored PIDs
        #[cfg(feature = "ebpf")]
        for pid in &pids {
            profiler.memory_map_cache.refresh_maps_for_pid(*pid);
        }

        // Cache memory maps for all monitored PIDs
        #[cfg(feature = "ebpf")]
        for pid in &pids {
            profiler.memory_map_cache.refresh_maps_for_pid(*pid);
        }

        // Initialize eBPF if the feature is enabled
        #[cfg(feature = "ebpf")]
        {
            match Self::init_ebpf() {
                Ok(bpf) => {
                    profiler.bpf = Some(bpf);
                    profiler.attach_tracepoint()?;
                    profiler._attached_programs = true;
                    profiler.start_perf_buffer()?;
                }
                Err(e) => {
                    error!("Failed to initialize eBPF for off-CPU profiling: {}", e);
                    return Err(e.into());
                }
            }
        }

        Ok(profiler)
    }

    /// Enable debug mode for eBPF operations
    pub fn set_debug_mode(enable: bool) {
        unsafe {
            debug::set_debug_mode(enable);
        }
        #[cfg(feature = "ebpf")]
        DEBUG_MODE.store(enable, Ordering::SeqCst);
    }

    /// Set debug mode for this profiler instance
    pub fn enable_debug_mode(&mut self) {
        self.debug_mode = true;
        debug::debug_println("Off-CPU profiler debug mode enabled");

        #[cfg(feature = "ebpf")]
        self.memory_map_cache.set_debug_mode(true);

        if self.debug_mode {
            #[cfg(feature = "ebpf")]
            debug::debug_println(&format!(
                "Memory map cache contains {} PIDs",
                self.memory_map_cache.cache_size()
            ));
        }
    }

    /// Initialize the eBPF program for off-CPU profiling
    #[cfg(feature = "ebpf")]
    fn init_ebpf() -> crate::error::Result<Ebpf> {
        info!("Loading eBPF program for off-CPU profiling...");
        debug::debug_println("Starting off-CPU profiler eBPF initialization");

        // Check if we can access tracefs
        if let Ok(output) = std::process::Command::new("sh")
            .arg("-c")
            .arg("ls -la /sys/kernel/debug/tracing/events/sched/sched_switch 2>/dev/null || echo 'Not available'")
            .output()
        {
            let output_str = String::from_utf8_lossy(&output.stdout);
            debug::debug_println(&format!("Tracepoint availability: {}", output_str));
        }

        // Debug information
        debug::debug_println(&format!(
            "eBPF bytecode size: {} bytes",
            OFFCPU_PROFILER_BYTECODE.len()
        ));

        // Dump first few bytes of bytecode for debugging
        let preview_size = std::cmp::min(OFFCPU_PROFILER_BYTECODE.len(), 32);
        let hex_bytes: Vec<String> = OFFCPU_PROFILER_BYTECODE[..preview_size]
            .iter()
            .map(|b| format!("{:02x}", b))
            .collect();
        debug::debug_println(&format!("eBPF bytecode preview: {}", hex_bytes.join(" ")));

        // Load the eBPF program
        let bpf = match Ebpf::load(OFFCPU_PROFILER_BYTECODE) {
            Ok(bpf) => {
                debug::debug_println("Successfully loaded off-CPU profiler eBPF program");
                bpf
            }
            Err(e) => {
                let err_msg = format!("Failed to load off-CPU profiler eBPF program: {}", e);
                debug::debug_println(&err_msg);
                error!("{}", err_msg);
                return Err(std::io::Error::new(std::io::ErrorKind::Other, err_msg).into());
            }
        };

        Ok(bpf)
    }

    /// Attach to the sched_switch tracepoint
    #[cfg(feature = "ebpf")]
    fn attach_tracepoint(&mut self) -> crate::error::Result<()> {
        let bpf = match &mut self.bpf {
            Some(bpf) => bpf,
            None => {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::Other,
                    "eBPF program not loaded",
                )
                .into())
            }
        };

        // List available programs
        let program_names: Vec<String> = bpf
            .programs()
            .map(|(name, _)| name.to_string())
            .collect::<Vec<_>>();
        debug::debug_println(&format!("Available eBPF programs: {:?}", program_names));

        // Get the sched_switch program
        let program = match bpf.program_mut("trace_sched_switch") {
            Some(prog) => prog,
            None => {
                let prog_names = bpf
                    .programs()
                    .map(|(name, _)| name.to_string())
                    .collect::<Vec<_>>()
                    .join(", ");

                let err_msg = format!(
                    "trace_sched_switch program not found in eBPF object. Available programs: {}",
                    prog_names
                );
                debug::debug_println(&err_msg);
                error!("{}", err_msg);
                return Err(std::io::Error::new(std::io::ErrorKind::Other, err_msg).into());
            }
        };

        let program: &mut TracePoint = match program.try_into() {
            Ok(tp) => tp,
            Err(e) => {
                let err_msg = format!("Failed to convert program to TracePoint: {}", e);
                debug::debug_println(&err_msg);
                error!("{}", err_msg);
                return Err(std::io::Error::new(std::io::ErrorKind::Other, err_msg).into());
            }
        };

        // Load and attach the program
        debug::debug_println("Loading sched_switch program");
        if let Err(e) = program.load() {
            let err_msg = format!("Failed to load sched_switch program: {}", e);
            debug::debug_println(&err_msg);
            error!("{}", err_msg);
            return Err(std::io::Error::new(std::io::ErrorKind::Other, err_msg).into());
        }

        debug::debug_println("Attaching sched_switch program to tracepoint");
        if let Err(e) = program.attach("sched", "sched_switch") {
            let err_msg = format!("Failed to attach sched_switch program: {}", e);
            debug::debug_println(&err_msg);
            error!("{}", err_msg);
            return Err(std::io::Error::new(std::io::ErrorKind::Other, err_msg).into());
        }

        info!("Attached to sched:sched_switch tracepoint");
        debug::debug_println("Attached to sched:sched_switch tracepoint");

        Ok(())
    }

    /// Start the perf buffer to receive events from the eBPF program
    #[cfg(feature = "ebpf")]
    fn start_perf_buffer(&mut self) -> crate::error::Result<()> {
        let bpf = match &mut self.bpf {
            Some(bpf) => bpf,
            None => {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::Other,
                    "eBPF program not loaded",
                )
                .into())
            }
        };

        // Get the events perf buffer
        let map_names = bpf
            .maps()
            .map(|(name, _)| name.to_string())
            .collect::<Vec<_>>()
            .join(", ");

        debug::debug_println(&format!("Available maps: {}", map_names));

        // Get a handle to the "events" perf buffer
        let events = match bpf.take_map("events") {
            Some(map) => {
                debug::debug_println("Found 'events' perf buffer map");
                map
            }
            None => {
                let err_msg = format!(
                    "Failed to find 'events' map in BPF program. Available maps: {}",
                    map_names
                );
                debug::debug_println(&err_msg);
                return Err(std::io::Error::new(std::io::ErrorKind::Other, err_msg).into());
            }
        };

        // Convert the generic map to a perf event array
        let mut perf_array = match PerfEventArray::try_from(events) {
            Ok(array) => {
                debug::debug_println("Successfully created PerfEventArray");
                array
            }
            Err(e) => {
                let err_msg = format!("Failed to create PerfEventArray: {}", e);
                debug::debug_println(&err_msg);
                return Err(std::io::Error::new(std::io::ErrorKind::Other, err_msg).into());
            }
        };

        // Get the current online CPUs
        let cpus = match online_cpus() {
            Ok(cpus) => cpus,
            Err(e) => {
                let err_msg = format!("Failed to get online CPUs: {:?}", e);
                debug::debug_println(&err_msg);
                return Err(std::io::Error::new(std::io::ErrorKind::Other, err_msg).into());
            }
        };

        // Get a copy of the stats mutex for the event handlers
        let stats = self.stats.clone();
        let events = self.events.clone();
        let running = self.running.clone();
        let debug_mode = self.debug_mode;
        let monitored_pids = self.monitored_pids.clone();

        let mut perf_readers = Vec::new();

        // Create a perf reader for each CPU
        for cpu_id in cpus {
            // Open the perf event array for this CPU
            let mut buf = match perf_array.open(cpu_id, Some(128)) {
                Ok(buf) => buf,
                Err(e) => {
                    let err_msg = format!("Failed to open perf buffer for CPU {}: {}", cpu_id, e);
                    debug::debug_println(&err_msg);
                    continue;
                }
            };

            // Clone resources for this CPU's handler
            let cpu_stats = stats.clone();
            let cpu_events = events.clone();
            let cpu_running = running.clone();
            let cpu_debug = debug_mode;
            let cpu_monitored_pids = monitored_pids.clone();

            // Spawn a thread to handle events from this CPU
            let handler = thread::spawn(move || {
                // Create buffers for reading events
                let mut buffers: Vec<BytesMut> = vec![BytesMut::with_capacity(1024); 10];

                debug::debug_println(&format!("Started event handler for CPU {}", cpu_id));

                while cpu_running.load(Ordering::Relaxed) {
                    // Read events from the perf buffer
                    match buf.read_events(&mut buffers) {
                        Ok(events) => {
                            if cpu_debug && events.read > 0 {
                                debug::debug_println(&format!(
                                    "CPU {}: Received {} events, lost {}",
                                    cpu_id, events.read, events.lost
                                ));
                            }

                            if events.read > 0 {
                                // Process each buffer that contains events
                                for i in 0..events.read {
                                    let buf = &buffers[i];

                                    // Only process if buffer contains at least one complete event
                                    if buf.len() >= std::mem::size_of::<OffCpuEvent>() {
                                        // Safety: We're assuming the events from eBPF match our OffCpuEvent struct
                                        let event = unsafe {
                                            std::ptr::read_unaligned(
                                                buf.as_ptr() as *const OffCpuEvent
                                            )
                                        };

                                        // Process the event if it's from a monitored PID
                                        if cpu_monitored_pids.is_empty()
                                            || cpu_monitored_pids.contains(&event.pid)
                                        {
                                            if cpu_debug {
                                                debug::debug_println(&format!(
                                                    "Received off-CPU event: PID={}, TID={}, time={}ms",
                                                    event.pid,
                                                    event.tid,
                                                    event.offcpu_time_ns / 1_000_000
                                                ));
                                            }

                                            // Store events with valid stack IDs
                                            if event.user_stack_id != 0
                                                || event.kernel_stack_id != 0
                                            {
                                                if let Ok(mut events_guard) = cpu_events.lock() {
                                                    if cpu_debug {
                                                        debug::debug_println(&format!(
                                                            "Storing event with stack IDs: user={}, kernel={}",
                                                            event.user_stack_id,
                                                            event.kernel_stack_id
                                                        ));
                                                    }
                                                    let processed_event =
                                                        ProcessedOffCpuEvent::from(event);
                                                    events_guard.push(processed_event);
                                                }
                                            }

                                            // Update statistics
                                            // Handle poisoned mutex gracefully
                                            let stats_result = cpu_stats.lock();
                                            let mut stats_guard = match stats_result {
                                                Ok(guard) => guard,
                                                Err(poisoned) => {
                                                    // Recover from poison by using the poisoned guard
                                                    if cpu_debug {
                                                        debug::debug_println("Recovered from poisoned mutex in CPU stats");
                                                    }
                                                    poisoned.into_inner()
                                                }
                                            };

                                            // Get or create the stats entry for this thread
                                            let entry = stats_guard
                                                .entry((event.pid, event.tid))
                                                .or_insert_with(create_offcpu_stats);

                                            // Update with the real event data
                                            entry.count = entry.count.saturating_add(1);

                                            // Use saturating_add to prevent overflow
                                            entry.total_time_ns = entry
                                                .total_time_ns
                                                .saturating_add(event.offcpu_time_ns);

                                            // Calculate average safely
                                            if entry.count > 0 {
                                                entry.avg_time_ns =
                                                    entry.total_time_ns / entry.count;
                                            }

                                            entry.max_time_ns = std::cmp::max(
                                                entry.max_time_ns,
                                                event.offcpu_time_ns,
                                            );
                                            entry.min_time_ns = if entry.min_time_ns == 0 {
                                                event.offcpu_time_ns
                                            } else {
                                                std::cmp::min(
                                                    entry.min_time_ns,
                                                    event.offcpu_time_ns,
                                                )
                                            };

                                            if cpu_debug {
                                                debug::debug_println(&format!(
                                                    "Updated stats for PID={}, TID={}: count={}, total={}ms",
                                                    event.pid,
                                                    event.tid,
                                                    entry.count,
                                                    entry.total_time_ns / 1_000_000
                                                ));
                                            }
                                        }
                                    }
                                }
                            }
                        }
                        Err(e) => {
                            if cpu_debug {
                                debug::debug_println(&format!(
                                    "Error reading events from CPU {}: {}",
                                    cpu_id, e
                                ));
                            }
                            // Sleep a bit to prevent tight error loops
                            thread::sleep(Duration::from_millis(100));
                        }
                    }

                    // Small sleep to prevent 100% CPU usage while polling
                    thread::sleep(Duration::from_millis(10));
                }

                debug::debug_println(&format!("Stopped event handler for CPU {}", cpu_id));
            });

            perf_readers.push(handler);
        }

        // Store the handlers for cleanup later
        self._perf_readers = perf_readers;

        info!("Initialized eBPF off-CPU profiler with live event processing");
        debug::debug_println("Off-CPU profiler ready - collecting live events");

        Ok(())
    }

    /// Update the list of monitored PIDs
    pub fn update_pids(&mut self, pids: Vec<u32>) {
        self.monitored_pids = pids.clone();

        #[cfg(feature = "ebpf")]
        {
            for pid in &pids {
                self.memory_map_cache.refresh_maps_for_pid(*pid);
            }
        }
    }

    /// Add a single PID to the monitored list and cache its memory maps
    /// This is useful when we discover new processes during profiling
    #[cfg(feature = "ebpf")]
    fn add_pid_to_monitor(&mut self, pid: u32) {
        // Only add if it's not already being monitored
        if !self.monitored_pids.contains(&pid) {
            if self.debug_mode {
                debug::debug_println(&format!("Adding PID {} to monitored processes", pid));
            }

            // Add to the monitored list
            self.monitored_pids.push(pid);

            // Cache memory maps immediately
            let success = self.memory_map_cache.refresh_maps_for_pid(pid);

            if self.debug_mode {
                if success {
                    debug::debug_println(&format!(
                        "Successfully cached memory maps for PID {}",
                        pid
                    ));
                } else {
                    debug::debug_println(&format!("Failed to cache memory maps for PID {}", pid));
                }
            }
        }
    }

    /// Get the current off-CPU statistics
    pub fn get_stats(&self) -> HashMap<(u32, u32), OffCpuStats> {
        // We're now capturing real events from the perf buffer in the background
        // Just return the current stats that have been collected

        #[cfg(feature = "ebpf")]
        {
            // The stats are already being updated in real-time by the perf buffer handlers
            // No need to sample process states manually anymore

            // Optionally, we could add any additional processing here if needed
        }

        // Handle poisoned mutex gracefully when getting stats
        let stats_result = self.stats.lock();
        let stats = match stats_result {
            Ok(guard) => guard.clone(),
            Err(poisoned) => {
                debug::debug_println("Recovered from poisoned mutex in get_stats");
                poisoned.into_inner().clone()
            }
        };
        if self.debug_mode {
            debug::debug_println(&format!("Returning {} off-CPU stats entries", stats.len()));

            // Log a summary of the stats
            if !stats.is_empty() {
                let mut total_time_ns: u64 = 0;
                let mut total_count: u64 = 0;

                for ((pid, tid), stat) in stats.iter() {
                    total_time_ns = total_time_ns.saturating_add(stat.total_time_ns);
                    total_count = total_count.saturating_add(stat.count);

                    debug::debug_println(&format!(
                        "PID={}, TID={}: count={}, time={}ms, avg={}ms",
                        pid,
                        tid,
                        stat.count,
                        stat.total_time_ns.checked_div(1_000_000).unwrap_or(0),
                        stat.avg_time_ns.checked_div(1_000_000).unwrap_or(0)
                    ));
                }

                debug::debug_println(&format!(
                    "Total: {} events, {}ms off-CPU time",
                    total_count,
                    total_time_ns.checked_div(1_000_000).unwrap_or(0)
                ));
            } else {
                debug::debug_println("No off-CPU stats collected");
            }
        }

        stats
    }

    /// Get processed stack traces from collected events
    #[cfg(feature = "ebpf")]
    pub fn get_stack_traces(&mut self) -> Vec<ProcessedOffCpuEvent> {
        // Clone all events out of the mutex before mutably borrowing self
        let events = {
            let events_result = self.events.lock();
            match events_result {
                Ok(guard) => guard.clone(),
                Err(poisoned) => {
                    debug::debug_println("Recovered from poisoned mutex in get_stack_traces");
                    poisoned.into_inner().clone()
                }
            }
        };

        if self.debug_mode {
            debug::debug_println(&format!(
                "Processing {} events with stack traces",
                events.len()
            ));
        }

        // Process and symbolicate each event
        let mut processed_events = Vec::new();

        // Ensure we're monitoring all PIDs we encounter
        let event_pids: Vec<u32> = events
            .iter()
            .map(|e| e.event.pid)
            .collect::<std::collections::HashSet<_>>()
            .into_iter()
            .collect();

        // Pre-cache memory maps for all PIDs
        for pid in &event_pids {
            if !self.monitored_pids.contains(pid) {
                self.add_pid_to_monitor(*pid);
            }
        }

        if self.debug_mode && !events.is_empty() {
            debug::debug_println(&format!(
                "Pre-cached memory maps for {} PIDs before processing stack traces",
                event_pids.len()
            ));
        }

        for mut event in events {
            // Check for error codes in stack IDs and record the error
            // BPF stack trace error codes are returned as large u32 values (which are negative when cast to i32)
            if event.event.user_stack_id > 0 {
                // Check if it's actually an error code (large u32 value close to u32::MAX)
                if event.event.user_stack_id > 0xfffffff0 {
                    // Convert to error code (as negative i32)
                    let error_code = -((event.event.user_stack_id as i32) * -1);
                    let error_msg = match error_code {
                        -1 => "EPERM: Operation not permitted",
                        -2 => "ENOENT: No such file or directory",
                        -4 => "EINTR: Interrupted system call",
                        -9 => "EBADF: Bad file descriptor",
                        -12 => "ENOMEM: Out of memory",
                        -14 => "EFAULT: Bad address",
                        -22 => "EINVAL: Invalid argument",
                        -105 => "ENOBUFS: No buffer space available",
                        _ => "Unknown error",
                    };
                    if self.debug_mode {
                        debug::debug_println(&format!(
                            "User stack error for PID={}, TID={}: {} (code: {})",
                            event.event.pid, event.event.tid, error_msg, error_code
                        ));

                        // Additional diagnostic information for common errors
                        if error_code == -1 {
                            debug::debug_println(
                                "EPERM usually indicates insufficient capabilities.",
                            );
                            debug::debug_println(
                                "Ensure the process has CAP_BPF and CAP_PERFMON capabilities.",
                            );
                            debug::debug_println(
                                "Try: sudo setcap cap_bpf,cap_perfmon=ep ./target/debug/denet",
                            );
                        } else if error_code == -14 {
                            debug::debug_println(
                                "EFAULT is common with interpreted languages (Python, Java, etc.)",
                            );
                            debug::debug_println("These processes have complex stack frames that eBPF may struggle with");
                        }

                        // For EFAULT, check if the process has debug symbols
                        if error_code == -14 {
                            // Try running 'file' on the executable to check for debug symbols
                            let proc_exe = format!("/proc/{}/exe", event.event.pid);
                            if let Ok(output) =
                                std::process::Command::new("file").arg(&proc_exe).output()
                            {
                                let output_str = String::from_utf8_lossy(&output.stdout);
                                debug::debug_println(&format!(
                                    "Executable information: {}",
                                    output_str
                                ));

                                if output_str.contains("with debug_info") {
                                    debug::debug_println("Executable has debug symbols, which should help with stack traces");
                                    debug::debug_println("However, EFAULT indicates memory access issues during stack unwinding");

                                    // Check if this is an interpreter process
                                    if let Some(process_name) =
                                        self.get_process_name(event.event.pid)
                                    {
                                        if process_name.contains("python")
                                            || process_name.contains("java")
                                            || process_name.contains("node")
                                        {
                                            debug::debug_println("This appears to be an interpreter process, which often has complex stack frames");
                                            debug::debug_println("Consider using language-specific profiling tools for better results");
                                        }
                                    }
                                } else {
                                    debug::debug_println(
                                        "Executable does not appear to have debug symbols",
                                    );
                                    debug::debug_println(
                                        "Compile with -g flag to include debug information for better stack traces"
                                    );
                                }
                            }
                        }
                    }
                    event.user_stack_error = Some(format!("{} (code: {})", error_msg, error_code));
                } else {
                    // Valid stack ID - symbolicate
                    // Make sure memory maps are fresh before symbolicating
                    if !self.monitored_pids.contains(&event.event.pid) {
                        self.add_pid_to_monitor(event.event.pid);
                    }

                    event.user_stack = Some(self.get_symbolicated_stack_frames(
                        event.event.user_stack_id,
                        true,
                        event.event.pid,
                    ));
                }
            }

            // Similar check for kernel stack ID
            if event.event.kernel_stack_id > 0 {
                if event.event.kernel_stack_id > 0xfffffff0 {
                    // Convert to error code (as negative i32)
                    let error_code = -((event.event.kernel_stack_id as i32) * -1);
                    let error_msg = match error_code {
                        -1 => "EPERM: Operation not permitted",
                        -2 => "ENOENT: No such file or directory",
                        -4 => "EINTR: Interrupted system call",
                        -9 => "EBADF: Bad file descriptor",
                        -12 => "ENOMEM: Out of memory",
                        -14 => "EFAULT: Bad address",
                        -22 => "EINVAL: Invalid argument",
                        -105 => "ENOBUFS: No buffer space available",
                        _ => "Unknown error",
                    };
                    if self.debug_mode {
                        debug::debug_println(&format!(
                            "Kernel stack error for PID={}, TID={}: {} (code: {})",
                            event.event.pid, event.event.tid, error_msg, error_code
                        ));
                    }
                    event.kernel_stack_error =
                        Some(format!("{} (code: {})", error_msg, error_code));
                } else {
                    // Valid stack ID - symbolicate
                    // Make sure memory maps are fresh before symbolicating
                    if !self.monitored_pids.contains(&event.event.pid) {
                        self.add_pid_to_monitor(event.event.pid);
                    }

                    event.kernel_stack = Some(self.get_symbolicated_stack_frames(
                        event.event.kernel_stack_id,
                        false,
                        event.event.pid,
                    ));
                }
            }

            // Add thread/process names if available
            if event.process_name.is_none() {
                event.process_name = self.get_process_name(event.event.pid);
            }
            if event.thread_name.is_none() {
                event.thread_name = self.get_thread_name(event.event.pid, event.event.tid);
            }

            // Add PID and TID to threads list
            event.threads.push((event.event.pid, event.event.tid));

            processed_events.push(event);
        }
        processed_events
    }

    /// Get a summary of stack traces grouped by their IDs
    /// This provides aggregated off-CPU time for each unique stack trace
    #[cfg(feature = "ebpf")]
    pub fn get_stack_trace_summary(&mut self) -> HashMap<(u32, u32), Vec<ThreadStackStats>> {
        // This maps (user_stack_id, kernel_stack_id) -> [ThreadStackStats, ...]
        let mut summary = HashMap::new();

        // Get all processed events
        let events = self.get_stack_traces();

        // Aggregate events by stack IDs
        for event in events {
            let user_stack_id = event.event.user_stack_id;
            let kernel_stack_id = event.event.kernel_stack_id;
            let time_ns = event.event.offcpu_time_ns;

            // Skip invalid stack IDs
            if user_stack_id == 0 && kernel_stack_id == 0 {
                continue;
            }

            // Use the stack IDs as the key
            let key = (user_stack_id, kernel_stack_id);

            // Update the summary
            let entry = summary
                .entry(key)
                .or_insert_with(Vec::<ThreadStackStats>::new);

            // Check if we already have an entry for this (pid, tid)
            let pid_tid = (event.event.pid, event.event.tid);
            let mut found = false;

            for stats in entry.iter_mut() {
                if stats.pid == pid_tid.0 && stats.tid == pid_tid.1 {
                    // Update existing entry
                    stats.total_time_ns += time_ns;
                    stats.count += 1;
                    found = true;
                    break;
                }
            }

            if !found {
                // Add new entry
                entry.push(ThreadStackStats {
                    pid: pid_tid.0,
                    tid: pid_tid.1,
                    total_time_ns: time_ns,
                    count: 1,
                });
            }
        }

        if self.debug_mode {
            debug::debug_println(&format!(
                "Generated summary for {} unique stack traces",
                summary.len()
            ));

            // Print some sample summary data
            for ((user_id, kernel_id), stats) in summary.iter().take(5) {
                let total_time: u64 = stats.iter().map(|s| s.total_time_ns).sum();
                let total_count: u64 = stats.iter().map(|s| s.count).sum();

                debug::debug_println(&format!(
                    "Stack ID (user={}, kernel={}): {} events, {}ms total off-CPU time",
                    user_id,
                    kernel_id,
                    total_count,
                    total_time / 1_000_000
                ));
            }
        }

        summary
    }

    #[cfg(feature = "ebpf")]
    fn get_symbolicated_stack_frames(
        &mut self,
        stack_id: u32,
        is_user_stack: bool,
        target_pid: u32,
    ) -> Vec<StackFrame> {
        #[cfg(feature = "ebpf")]
        use crate::symbolication::{find_region_for_address, get_symbol_info_with_addr2line};

        let mut frames = Vec::new();

        #[cfg(feature = "ebpf")]
        {
            // Check for invalid stack IDs
            // Note: BPF stack trace errors are returned as negative numbers, which appear as large u32 values
            // Common error codes: -14 (EFAULT), -22 (EINVAL), -12 (ENOMEM)
            // We now pass these through from eBPF for better diagnostics
            if stack_id == 0 {
                if self.debug_mode {
                    debug::debug_println("Stack ID is 0 (empty stack)");
                    debug::debug_println(
                        "This might indicate a permission issue - check capabilities",
                    );
                }
                return frames;
            }

            // Handle potential error codes (large u32 values that are negative when interpreted as i32)
            if stack_id >= 0xFFFFFFF0 {
                let err_code = -((stack_id as i32) * -1);

                if self.debug_mode {
                    debug::debug_println(&format!(
                        "Stack ID {} is likely an error code ({})",
                        stack_id, err_code
                    ));

                    // Provide more specific error information
                    match err_code {
                        -14 => debug::debug_println(
                            "EFAULT: Failed to access memory during stack unwinding. This is common with:
                             - JIT-compiled code (like Python, Java)
                             - Complex stack frames
                             - Insufficient permissions"
                        ),
                        -22 => debug::debug_println(
                            "EINVAL: Invalid argument passed to BPF function"
                        ),
                        -12 => debug::debug_println(
                            "ENOMEM: Out of memory in BPF stack map"
                        ),
                        -1 => debug::debug_println(
                            "EPERM: Permission denied. Check capabilities."
                        ),
                        -2 => debug::debug_println(
                            "ENOENT: No such file or directory"
                        ),
                        _ => debug::debug_println(&format!(
                            "Unknown error code: {}", err_code
                        )),
                    }

                    // For EFAULT specifically, provide more diagnostics
                    if err_code == -14 && is_user_stack {
                        // This is likely a JIT/interpreter issue
                        if let Some(process_name) = self.get_process_name(target_pid) {
                            if process_name.contains("python")
                                || process_name.contains("java")
                                || process_name.contains("node")
                                || process_name.contains("ruby")
                            {
                                debug::debug_println(
                                    "Detected interpreted/JIT language process. Stack unwinding often fails for these."
                                );
                            }
                        }

                        // Check if process has debug symbols
                        let proc_exe = format!("/proc/{}/exe", target_pid);
                        if let Ok(output) = std::process::Command::new("readelf")
                            .args(&["-S", &proc_exe])
                            .output()
                        {
                            let output_str = String::from_utf8_lossy(&output.stdout);
                            if !output_str.contains(".debug_") {
                                debug::debug_println("Process does not have debug symbols, which can cause stack trace failures");
                            }
                        }
                    }
                }

                // Despite errors, try to proceed with stack tracing anyway
                // In some cases we might get partial data even with errors
            }

            if self.debug_mode {
                debug::debug_println(&format!(
                    "Attempting to resolve {} stack ID: {}",
                    if is_user_stack { "user" } else { "kernel" },
                    stack_id
                ));
            }

            // Choose the appropriate stack map based on stack type
            let map_name = if is_user_stack {
                "user_stackmap"
            } else {
                "kernel_stackmap"
            };

            let stack_map = match self.bpf.as_mut() {
                Some(bpf) => match bpf.map_mut(map_name) {
                    Some(map) => {
                        match StackTraceMap::try_from(map) {
                            Ok(stack_map) => stack_map,
                            Err(e) => {
                                if self.debug_mode {
                                    debug::debug_println(&format!(
                                        "Failed to convert {} to StackTraceMap: {}",
                                        map_name, e
                                    ));
                                    debug::debug_println("This may indicate BPF permission issues or improper map setup");
                                }
                                return frames;
                            }
                        }
                    }
                    None => {
                        if self.debug_mode {
                            debug::debug_println(&format!("Stack map '{}' not found", map_name));
                            // List available maps for debugging
                            let maps: Vec<String> =
                                bpf.maps().map(|(name, _)| name.to_string()).collect();
                            debug::debug_println(&format!("Available maps: {}", maps.join(", ")));
                        }
                        return frames;
                    }
                },
                None => {
                    if self.debug_mode {
                        debug::debug_println("eBPF program not loaded");
                    }
                    return frames;
                }
            };

            // Lookup stack addresses for this stack_id
            match stack_map.get(&stack_id, 0) {
                Ok(stack) => {
                    let stack_frames = stack.frames();
                    if self.debug_mode {
                        debug::debug_println(&format!(
                            "Retrieved {} stack frames for {} stack ID {}",
                            stack_frames.len(),
                            if is_user_stack { "user" } else { "kernel" },
                            stack_id
                        ));

                        // Print first few addresses for debugging
                        if !stack_frames.is_empty() {
                            let preview: Vec<String> = stack_frames
                                .iter()
                                .take(3)
                                .map(|f| format!("0x{:x}", f.ip))
                                .collect();
                            debug::debug_println(&format!(
                                "First few addresses: {}",
                                preview.join(", ")
                            ));
                        }
                    }

                    // Only symbolicate user stacks for now (kernel symbolication is more complex)
                    if is_user_stack {
                        // Use cached memory maps for the target process
                        // Ensure we're monitoring this process
                        if !self.monitored_pids.contains(&target_pid) {
                            self.add_pid_to_monitor(target_pid);
                        }
                        // Refresh maps if they're empty (might have been added dynamically)
                        else if self.memory_map_cache.get_memory_maps(target_pid).is_empty() {
                            if self.debug_mode {
                                debug::debug_println(&format!(
                                    "No cached memory maps for PID {}. Attempting to refresh...",
                                    target_pid
                                ));
                            }
                            self.memory_map_cache.refresh_maps_for_pid(target_pid);
                        }

                        let regions = self.memory_map_cache.get_memory_maps(target_pid);

                        if self.debug_mode {
                            debug::debug_println(&format!(
                                "Symbolicating stack for PID {}, found {} memory regions (from cache)",
                                target_pid,
                                regions.len()
                            ));

                            if regions.is_empty() {
                                debug::debug_println(&format!(
                                    "WARNING: No memory regions found for PID {}. Process may have exited.",
                                    target_pid
                                ));

                                // Try one more time with /proc directly as a last resort
                                let proc_path = format!("/proc/{}/maps", target_pid);
                                match std::fs::File::open(&proc_path) {
                                    Ok(_) => {
                                        debug::debug_println(
                                            "Maps file exists, trying to refresh cache again",
                                        );
                                        self.memory_map_cache.refresh_maps_for_pid(target_pid);
                                        // Update regions variable with the latest attempt
                                        let new_regions =
                                            self.memory_map_cache.get_memory_maps(target_pid);
                                        if !new_regions.is_empty() {
                                            debug::debug_println(&format!(
                                                "Successfully refreshed maps, found {} regions",
                                                new_regions.len()
                                            ));
                                        }
                                    }
                                    Err(e) => {
                                        debug::debug_println(&format!(
                                            "Process {} likely exited, cannot access maps: {}",
                                            target_pid, e
                                        ));
                                    }
                                }
                            } else {
                                // Log some executable regions for debugging
                                let exec_regions: Vec<_> = regions
                                    .iter()
                                    .filter(|r| r.permissions.contains('x'))
                                    .take(3)
                                    .collect();

                                if !exec_regions.is_empty() {
                                    debug::debug_println("Sample executable regions:");
                                    for (i, region) in exec_regions.iter().enumerate() {
                                        debug::debug_println(&format!(
                                            "  Region {}: 0x{:x}-0x{:x} {} {:?}",
                                            i,
                                            region.start_addr,
                                            region.end_addr,
                                            region.permissions,
                                            region.pathname
                                        ));
                                    }
                                }
                            }
                        }

                        // Track how many frames we process
                        let total_frames = stack_frames.len();
                        let mut processed_frames = 0;
                        let mut symbolicated_frames = 0;

                        if self.debug_mode {
                            debug::debug_println(&format!(
                                "Processing {} stack frames for PID {} (processed: {}, symbolicated: {})",
                                total_frames, target_pid, processed_frames, symbolicated_frames
                            ));

                            if total_frames == 0 && is_user_stack {
                                debug::debug_println("WARNING: Empty user stack - this may indicate a permission issue");
                                debug::debug_println(
                                    "Check capabilities with: getcap ./target/debug/denet",
                                );
                                debug::debug_println(
                                    "Make sure the process has CAP_BPF and CAP_PERFMON",
                                );
                            }
                        }

                        for frame in stack_frames {
                            let addr = frame.ip;

                            // Skip invalid addresses (0 or near max value can indicate errors)
                            if addr == 0 || addr > 0xFFFFFFFF00000000 {
                                if self.debug_mode {
                                    debug::debug_println(&format!(
                                        "Skipping invalid address: 0x{:x}",
                                        addr
                                    ));
                                }
                                continue;
                            }

                            processed_frames += 1;

                            let mut stack_frame = StackFrame {
                                address: addr,
                                symbol: None,
                                source_location: None,
                            };

                            if let Some(region) = find_region_for_address(addr, &regions) {
                                symbolicated_frames += 1;
                                if let Some(path) = &region.pathname {
                                    let offset = addr - region.start_addr + region.offset;
                                    if self.debug_mode {
                                        debug::debug_println(&format!(
                                            "Trying to symbolicate addr {:x} in {} (offset {:x})",
                                            addr, path, offset
                                        ));
                                    }
                                    if let Some(sym) = get_symbol_info_with_addr2line(path, offset)
                                    {
                                        stack_frame.symbol = sym.function;
                                        if let (Some(file), Some(line)) = (sym.file, sym.line) {
                                            stack_frame.source_location =
                                                Some(format!("{}:{}", file, line));
                                        }
                                        if self.debug_mode {
                                            debug::debug_println(&format!(
                                                "Symbolicated: addr 0x{:x} -> {:?} at {:?}",
                                                addr,
                                                stack_frame.symbol,
                                                stack_frame.source_location
                                            ));
                                        }
                                        symbolicated_frames += 1;
                                    } else if self.debug_mode {
                                        debug::debug_println(&format!(
                                            "No symbol found for addr 0x{:x} (offset 0x{:x}) in {}",
                                            addr, offset, path
                                        ));

                                        // Try alternate address calculation methods
                                        let alt_offset = addr - region.start_addr;
                                        debug::debug_println(&format!(
                                            "Trying alternate offset calculation: 0x{:x}",
                                            alt_offset
                                        ));

                                        if let Some(sym) =
                                            get_symbol_info_with_addr2line(path, alt_offset)
                                        {
                                            debug::debug_println(&format!(
                                                    "Symbol found with alternate offset: function={:?}, file={:?}, line={:?}",
                                                    sym.function, sym.file, sym.line
                                                ));
                                            stack_frame.symbol = sym.function;
                                            if let (Some(file), Some(line)) = (sym.file, sym.line) {
                                                stack_frame.source_location =
                                                    Some(format!("{}:{}", file, line));
                                            }
                                        } else {
                                            // Try to check if the binary has debug info
                                            let _ = std::process::Command::new("readelf")
                                                    .args(["-S", path])
                                                    .output()
                                                    .map(|output| {
                                                        if std::str::from_utf8(&output.stdout)
                                                            .unwrap_or("")
                                                            .contains(".debug_info")
                                                        {
                                                            debug::debug_println(&format!(
                                                                "Binary {} has debug info but symbol lookup failed",
                                                                path
                                                            ));
                                                            debug::debug_println(
                                                                "This could be due to address mapping issues or incomplete debug info"
                                                            );
                                                        } else {
                                                            debug::debug_println(&format!(
                                                                "Binary {} does not have debug info",
                                                                path
                                                            ));
                                                            debug::debug_println(
                                                                "Consider compiling with debug symbols (-g flag) for better symbolication"
                                                            );
                                                        }
                                                    });
                                        }
                                    }
                                } else if self.debug_mode {
                                    debug::debug_println(&format!(
                                        "No memory region found for addr 0x{:x} in PID {}",
                                        addr, target_pid
                                    ));

                                    // Dump first few memory regions for debugging
                                    if !regions.is_empty() {
                                        debug::debug_println("First few memory regions:");
                                        for (i, region) in regions.iter().take(3).enumerate() {
                                            debug::debug_println(&format!(
                                                "  Region {}: 0x{:x}-0x{:x} {} {:?}",
                                                i,
                                                region.start_addr,
                                                region.end_addr,
                                                region.permissions,
                                                region.pathname
                                            ));
                                        }
                                    }
                                }
                            } else if self.debug_mode {
                                debug::debug_println(&format!(
                                    "No memory region found for addr 0x{:x} in PID {}",
                                    addr, target_pid
                                ));

                                // Dump first few memory regions for debugging
                                if !regions.is_empty() {
                                    debug::debug_println("First few memory regions:");
                                    for (i, region) in regions.iter().take(3).enumerate() {
                                        debug::debug_println(&format!(
                                            "  Region {}: 0x{:x}-0x{:x} {} {:?}",
                                            i,
                                            region.start_addr,
                                            region.end_addr,
                                            region.permissions,
                                            region.pathname
                                        ));
                                    }
                                }
                            }
                            frames.push(stack_frame);
                        }
                    } else {
                        // For kernel stacks, just capture the addresses without symbolication
                        for frame in stack_frames {
                            let stack_frame = StackFrame {
                                address: frame.ip,
                                symbol: None,
                                source_location: None,
                            };
                            frames.push(stack_frame);
                        }

                        // Log summary of symbolication results
                        if self.debug_mode && is_user_stack {
                            debug::debug_println(&format!(
                                "Stack trace symbolication completed for PID {}",
                                target_pid
                            ));
                        }
                    }
                }
                Err(e) => {
                    if self.debug_mode {
                        debug::debug_println(&format!(
                            "Failed to get stack trace for {} stack ID {}: {}",
                            if is_user_stack { "user" } else { "kernel" },
                            stack_id,
                            e
                        ));

                        // Check if this is a special ID that might need different handling
                        if stack_id == u32::MAX - 13 || stack_id == u32::MAX - 14 {
                            debug::debug_println(
                                "This is likely an EFAULT error - access to user memory failed",
                            );
                            debug::debug_println(
                                "This commonly happens with:
                                 - Interpreted languages (Python, Java, JavaScript)
                                 - JIT-compiled code with unusual stack layouts
                                 - Applications without frame pointers
                                 - Processes with different memory layouts",
                            );

                            // Check for language-specific issues
                            let is_interpreter = match self.get_process_name(target_pid) {
                                Some(name) => {
                                    name.contains("python")
                                        || name.contains("java")
                                        || name.contains("node")
                                        || name.contains("ruby")
                                        || name.contains("perl")
                                }
                                None => false,
                            };

                            if is_interpreter {
                                debug::debug_println(
                                    "This process appears to be an interpreter. Consider using language-specific
                                     profiling tools instead, as BPF stack traces are limited for interpreters."
                                );
                            }
                        } else if stack_id == u32::MAX - 22 {
                            debug::debug_println(
                                "This is likely an EINVAL error - invalid argument passed to BPF function"
                            );
                        } else if stack_id == u32::MAX - 12 {
                            debug::debug_println(
                                "This is likely an ENOMEM error - out of memory in BPF stack map",
                            );
                        }
                    }
                }
            }
        }
        frames
    }

    /// Get process name from /proc/{pid}/comm
    fn get_process_name(&mut self, pid: u32) -> Option<String> {
        use std::fs::File;
        use std::io::Read;

        // Check cache first (we might already have memory maps with executable paths)
        #[cfg(feature = "ebpf")]
        {
            let regions = self.memory_map_cache.get_memory_maps(pid);
            for region in &regions {
                if let Some(path) = &region.pathname {
                    if path.starts_with("/")
                        && !path.contains("[")
                        && region.permissions.contains('x')
                    {
                        // Extract the executable name from the path
                        if let Some(exe_name) = path.split('/').last() {
                            if !exe_name.is_empty() {
                                return Some(exe_name.to_string());
                            }
                        }
                    }
                }
            }
        }

        // Fallback to reading from /proc
        let comm_path = format!("/proc/{}/comm", pid);

        // Read the process name
        match File::open(&comm_path) {
            Ok(mut file) => {
                let mut name = String::new();
                if file.read_to_string(&mut name).is_ok() {
                    Some(name.trim().to_string())
                } else {
                    None
                }
            }
            Err(_) => None,
        }
    }

    /// Get thread name from /proc/{pid}/task/{tid}/comm
    fn get_thread_name(&mut self, pid: u32, tid: u32) -> Option<String> {
        use std::fs::File;
        use std::io::Read;

        // For main thread (pid == tid), try to reuse process name if available
        if pid == tid {
            if let Some(proc_name) = self.get_process_name(pid) {
                return Some(proc_name);
            }
        }

        // Build the path to the comm file
        let comm_path = if pid == tid {
            format!("/proc/{}/comm", pid)
        } else {
            format!("/proc/{}/task/{}/comm", pid, tid)
        };

        // Read the thread name
        match File::open(&comm_path) {
            Ok(mut file) => {
                let mut name = String::new();
                if file.read_to_string(&mut name).is_ok() {
                    let trimmed = name.trim().to_string();
                    if !trimmed.is_empty() {
                        return Some(trimmed);
                    }
                }

                // If name is empty, use tid as fallback
                Some(format!("thread-{}", tid))
            }
            Err(_) => {
                // Process or thread might no longer exist
                // Return a synthetic name as fallback
                Some(format!("thread-{}", tid))
            }
        }
    }

    /// Clear all collected statistics and events
    /// Clear all collected statistics and events
    pub fn clear_stats(&self) {
        // Handle poisoned mutex gracefully
        let stats_result = self.stats.lock();
        match stats_result {
            Ok(mut guard) => {
                if self.debug_mode {
                    debug::debug_println(&format!("Clearing {} stat entries", guard.len()));
                }
                guard.clear();
            }
            Err(poisoned) => {
                debug::debug_println("Recovered from poisoned mutex in clear_stats");
                poisoned.into_inner().clear();
            }
        };

        // Also clear collected events with stack traces
        let events_result = self.events.lock();
        match events_result {
            Ok(mut guard) => {
                if self.debug_mode {
                    debug::debug_println(&format!("Clearing {} event entries", guard.len()));
                }
                guard.clear();
            }
            Err(poisoned) => {
                debug::debug_println("Recovered from poisoned mutex when clearing events");
                poisoned.into_inner().clear();
            }
        };

        if self.debug_mode {
            debug::debug_println("Cleared all off-CPU stats and events");
        }
    }
}

impl Drop for OffCpuProfiler {
    fn drop(&mut self) {
        // Clean up eBPF programs and maps
        #[cfg(feature = "ebpf")]
        {
            if self._attached_programs {
                debug!("Cleaning up off-CPU profiler eBPF resources");

                // Signal the event handler threads to stop
                self.running.store(false, Ordering::SeqCst);

                // Give threads a chance to exit
                thread::sleep(Duration::from_millis(100));

                debug::debug_println("Off-CPU profiler resources cleaned up");
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_offcpu_stats_default() {
        let stats = OffCpuStats::default();
        assert_eq!(stats.total_time_ns, 0);
        assert_eq!(stats.count, 0);
        assert_eq!(stats.avg_time_ns, 0);
        assert_eq!(stats.max_time_ns, 0);
        assert_eq!(stats.min_time_ns, 0);
    }

    // TODO: Add more tests for the OffCpuProfiler
}
