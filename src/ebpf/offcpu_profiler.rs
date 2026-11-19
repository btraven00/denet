//! Off-CPU profiler implementation using eBPF
//!
//! This module implements a profiler that tracks time spent by threads
//! while they are not running on a CPU (i.e., blocked, waiting for I/O,
//! or sleeping). This information can be used to identify bottlenecks
//! related to I/O, locks, and other blocking operations.

use std::collections::{BTreeMap, HashMap, HashSet};

use crate::ebpf::metrics::OffCpuWait;
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
use crate::ebpf::kallsyms::KernelSymbols;
#[cfg(feature = "ebpf")]
#[cfg(feature = "ebpf")]
use aya::maps::perf::PerfEventArray;
#[cfg(feature = "ebpf")]
use aya::maps::stack_trace::StackTraceMap;
use aya::util::online_cpus;
#[cfg(feature = "ebpf")]
use bytes::BytesMut;

use serde::{Deserialize, Serialize};

/// The OffCpuEvent structure that matches the eBPF program's output
#[derive(Debug, Clone, Copy, Default, Serialize, Deserialize)]
#[repr(C)]
pub struct OffCpuEvent {
    /// Process ID
    pub pid: u32,
    /// Thread ID
    pub tid: u32,
    /// Previous thread state when it was scheduled out
    pub prev_state: u32,
    /// Kernel stack it waited in: a stack map id, or a negative errno
    pub kernel_stack_id: u32,
    /// Time spent off-CPU in nanoseconds
    pub offcpu_time_ns: u64,
    /// Timestamp when the thread was scheduled out
    pub start_time_ns: u64,
    /// Timestamp when the thread was scheduled back in
    pub end_time_ns: u64,
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

    /// Off-CPU time and count per (pid, kernel stack id), kept by the event
    /// threads; `take_waits` reports what accrued since its last call
    wait_totals: Arc<Mutex<WaitTotals>>,

    /// `wait_totals` as of the last `take_waits`
    last_waits: WaitTotals,

    /// Kernel stack ids already named in an earlier sample
    named_stacks: HashSet<u32>,

    /// Poll loops completed by the event threads, for `settle`
    polls: Arc<std::sync::atomic::AtomicU64>,

    /// Kernel symbols, loaded on first use; `Some(None)` if unavailable
    #[cfg(feature = "ebpf")]
    kernel_syms: Option<Option<KernelSymbols>>,

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
}

/// Global debug mode flag for the OffCpuProfiler
#[cfg(feature = "ebpf")]
static DEBUG_MODE: AtomicBool = AtomicBool::new(false);

// Helper to create off-CPU stats entries for a thread
/// Cumulative off-CPU (time, count) per (pid, kernel stack id)
type WaitTotals = HashMap<(u32, u32), (u64, u64)>;

/// A stack id from bpf_get_stackid: an index, or a negative errno cast to u32
fn valid_stack_id(id: u32) -> bool {
    (id as i32) >= 0
}

/// Set by the BPF program in the ids of kernel stacks it stored in
/// `kernel_stackmap2` because their slot in `kernel_stackmap` was taken
const KSTACK_OVERFLOW: u32 = 1 << 30;

/// Stack id under which waits whose kernel stack couldn't be captured are
/// reported, so that no off-CPU time goes missing from `waits`
pub const STACK_UNAVAILABLE: u32 = u32::MAX;

/// Off-CPU time and count that accrued per (pid, stack) between two snapshots
/// of the cumulative totals, most time first
fn wait_deltas(prev: &WaitTotals, cur: &WaitTotals) -> Vec<OffCpuWait> {
    let mut out: Vec<OffCpuWait> = cur
        .iter()
        .filter_map(|(&(pid, stack), &(t, c))| {
            let (pt, pc) = prev.get(&(pid, stack)).copied().unwrap_or((0, 0));
            (t > pt).then(|| OffCpuWait {
                pid,
                stack,
                time_ns: t - pt,
                count: c.saturating_sub(pc),
            })
        })
        .collect();
    out.sort_by(|a, b| b.time_ns.cmp(&a.time_ns).then(a.pid.cmp(&b.pid)));
    out
}

fn create_offcpu_stats() -> OffCpuStats {
    OffCpuStats {
        total_time_ns: 0,
        count: 0,
        avg_time_ns: 0,
        max_time_ns: 0,
        min_time_ns: u64::MAX,
    }
}

impl std::fmt::Debug for OffCpuProfiler {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("OffCpuProfiler")
            .field("monitored_pids", &self.monitored_pids)
            .field("debug_mode", &self.debug_mode)
            .finish()
    }
}

impl OffCpuProfiler {
    /// Create a new Off-CPU profiler
    pub fn new(pids: Vec<u32>) -> crate::error::Result<Self> {
        #[cfg(feature = "ebpf")]
        let debug_enabled = unsafe { debug::is_debug_mode() };

        let mut profiler = OffCpuProfiler {
            #[cfg(feature = "ebpf")]
            bpf: None,
            monitored_pids: pids.clone(),
            stats: Arc::new(Mutex::new(HashMap::new())),
            wait_totals: Arc::new(Mutex::new(HashMap::new())),
            last_waits: HashMap::new(),
            named_stacks: HashSet::new(),
            polls: Arc::new(std::sync::atomic::AtomicU64::new(0)),
            #[cfg(feature = "ebpf")]
            kernel_syms: None,
            #[cfg(feature = "ebpf")]
            _attached_programs: false,
            #[cfg(feature = "ebpf")]
            running: Arc::new(AtomicBool::new(true)),
            #[cfg(feature = "ebpf")]
            _perf_readers: Vec::new(),
            debug_mode: debug_enabled,
        };

        // Initialize eBPF if the feature is enabled
        #[cfg(feature = "ebpf")]
        {
            match Self::init_ebpf() {
                Ok(bpf) => {
                    profiler.bpf = Some(bpf);
                    // seed the in-kernel filter before attaching, so the tree's
                    // first waits are recorded
                    profiler.sync_pid_filter(&[], &pids);
                    profiler.attach_tracepoint()?;
                    profiler._attached_programs = true;
                    profiler.start_perf_buffer()?;
                }
                Err(e) => {
                    error!("Failed to initialize eBPF for off-CPU profiling: {}", e);
                    return Err(e);
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
        let bpf = match crate::ebpf::pidns_loader().load(OFFCPU_PROFILER_BYTECODE) {
            Ok(bpf) => {
                debug::debug_println("Successfully loaded off-CPU profiler eBPF program");
                bpf
            }
            Err(e) => {
                let err_msg = format!("Failed to load off-CPU profiler eBPF program: {}", e);
                debug::debug_println(&err_msg);
                error!("{}", err_msg);
                return Err(std::io::Error::other(err_msg).into());
            }
        };

        Ok(bpf)
    }

    /// Attach to the sched_switch tracepoint
    #[cfg(feature = "ebpf")]
    fn attach_tracepoint(&mut self) -> crate::error::Result<()> {
        let bpf = match &mut self.bpf {
            Some(bpf) => bpf,
            None => return Err(std::io::Error::other("eBPF program not loaded").into()),
        };

        // List available programs
        let program_names: Vec<String> = bpf
            .programs()
            .map(|(name, _)| name.to_string())
            .collect::<Vec<_>>();
        debug::debug_println(&format!("Available eBPF programs: {:?}", program_names));

        // Fork and exit first, so no child of the tree forks unseen once
        // sched_switch starts recording
        crate::ebpf::attach_proctree(bpf)?;

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
                return Err(std::io::Error::other(err_msg).into());
            }
        };

        let program: &mut TracePoint = match program.try_into() {
            Ok(tp) => tp,
            Err(e) => {
                let err_msg = format!("Failed to convert program to TracePoint: {}", e);
                debug::debug_println(&err_msg);
                error!("{}", err_msg);
                return Err(std::io::Error::other(err_msg).into());
            }
        };

        // Load and attach the program
        debug::debug_println("Loading sched_switch program");
        if let Err(e) = program.load() {
            let err_msg = format!("Failed to load sched_switch program: {}", e);
            debug::debug_println(&err_msg);
            error!("{}", err_msg);
            return Err(std::io::Error::other(err_msg).into());
        }

        debug::debug_println("Attaching sched_switch program to tracepoint");
        if let Err(e) = program.attach("sched", "sched_switch") {
            let err_msg = format!("Failed to attach sched_switch program: {}", e);
            debug::debug_println(&err_msg);
            error!("{}", err_msg);
            return Err(std::io::Error::other(err_msg).into());
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
            None => return Err(std::io::Error::other("eBPF program not loaded").into()),
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
                return Err(std::io::Error::other(err_msg).into());
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
                return Err(std::io::Error::other(err_msg).into());
            }
        };

        // Get the current online CPUs
        let cpus = match online_cpus() {
            Ok(cpus) => cpus,
            Err(e) => {
                let err_msg = format!("Failed to get online CPUs: {:?}", e);
                debug::debug_println(&err_msg);
                return Err(std::io::Error::other(err_msg).into());
            }
        };

        // Get a copy of the stats mutex for the event handlers
        let stats = self.stats.clone();
        let waits = self.wait_totals.clone();
        let polls = self.polls.clone();
        let running = self.running.clone();
        let debug_mode = self.debug_mode;

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
            let cpu_waits = waits.clone();
            let cpu_polls = polls.clone();
            let cpu_running = running.clone();
            let cpu_debug = debug_mode;

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
                                for buf in buffers.iter().take(events.read) {
                                    // Only process if buffer contains at least one complete event
                                    if buf.len() >= std::mem::size_of::<OffCpuEvent>() {
                                        // Safety: We're assuming the events from eBPF match our OffCpuEvent struct
                                        let event = unsafe {
                                            std::ptr::read_unaligned(
                                                buf.as_ptr() as *const OffCpuEvent
                                            )
                                        };

                                        // Process the event if it's from the monitored tree.
                                        // Only the monitored tree's threads reach here: the
                                        // kernel filters them (pid_filter, following forks)
                                        {
                                            if cpu_debug {
                                                debug::debug_println(&format!(
                                                    "Received off-CPU event: PID={}, TID={}, time={}ms",
                                                    event.pid,
                                                    event.tid,
                                                    event.offcpu_time_ns / 1_000_000
                                                ));
                                            }

                                            // Time per (process, kernel stack waited in)
                                            let stack = if valid_stack_id(event.kernel_stack_id) {
                                                event.kernel_stack_id
                                            } else {
                                                STACK_UNAVAILABLE
                                            };
                                            {
                                                if let Ok(mut w) = cpu_waits.lock() {
                                                    let e = w
                                                        .entry((event.pid, stack))
                                                        .or_insert((0, 0));
                                                    e.0 = e.0.saturating_add(event.offcpu_time_ns);
                                                    e.1 += 1;
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

                                            if let Some(avg) =
                                                entry.total_time_ns.checked_div(entry.count)
                                            {
                                                entry.avg_time_ns = avg;
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

                    cpu_polls.fetch_add(1, Ordering::Relaxed);
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
        #[cfg(feature = "ebpf")]
        {
            let old = std::mem::take(&mut self.monitored_pids);
            self.sync_pid_filter(&old, &pids);
        }
        self.monitored_pids = pids;
    }

    /// Keep the in-kernel `pid_filter` equal to the monitored tree: only its
    /// threads are timed and have their stacks captured.
    #[cfg(feature = "ebpf")]
    fn sync_pid_filter(&mut self, old: &[u32], new: &[u32]) {
        let Some(map) = self.bpf.as_mut().and_then(|b| b.map_mut("pid_filter")) else {
            return;
        };
        let Ok(mut filter) = aya::maps::HashMap::<_, u32, u8>::try_from(map) else {
            return;
        };
        for pid in old.iter().filter(|p| !new.contains(p)) {
            let _ = filter.remove(pid);
        }
        for pid in new.iter().filter(|p| !old.contains(p)) {
            let _ = filter.insert(pid, 1, 0);
        }
    }

    /// Wait until every event thread has completed two more polls (at most
    /// 200 ms), so that events the kernel sent before now have been read.
    /// For the final sample: the tree's last waits end as it exits, and their
    /// events would otherwise still be in the perf buffers.
    pub fn settle(&self) {
        let readers = self.perf_reader_count() as u64;
        let target = self.polls.load(Ordering::Relaxed) + 2 * readers;
        let deadline = std::time::Instant::now() + Duration::from_millis(200);
        while self.polls.load(Ordering::Relaxed) < target && std::time::Instant::now() < deadline {
            thread::sleep(Duration::from_millis(2));
        }
    }

    fn perf_reader_count(&self) -> usize {
        #[cfg(feature = "ebpf")]
        return self._perf_readers.len();
        #[cfg(not(feature = "ebpf"))]
        0
    }

    /// Off-CPU time per (process, kernel stack) since the previous call, and
    /// the function names of the stacks among them not reported before
    /// (innermost first). Frames are named from /proc/kallsyms; where the
    /// kernel hides addresses they are given as hex addresses.
    pub fn take_waits(&mut self) -> (Vec<OffCpuWait>, BTreeMap<u32, Vec<String>>) {
        let cur = self
            .wait_totals
            .lock()
            .map(|g| g.clone())
            .unwrap_or_default();
        let waits = wait_deltas(&self.last_waits, &cur);
        self.last_waits = cur;
        let mut stacks = BTreeMap::new();
        #[cfg(feature = "ebpf")]
        for w in &waits {
            if self.named_stacks.insert(w.stack) {
                stacks.insert(w.stack, self.kernel_stack_names(w.stack));
            }
        }
        (waits, stacks)
    }

    #[cfg(feature = "ebpf")]
    fn kernel_stack_names(&mut self, stack_id: u32) -> Vec<String> {
        if stack_id == STACK_UNAVAILABLE {
            return vec!["[stack unavailable]".to_string()];
        }
        let addrs = self.kernel_stack_addrs(stack_id);
        let syms = self.kernel_syms.get_or_insert_with(KernelSymbols::load);
        addrs
            .into_iter()
            .map(|addr| {
                syms.as_ref()
                    .and_then(|s| s.resolve(addr))
                    .map(str::to_string)
                    .unwrap_or_else(|| format!("0x{addr:x}"))
            })
            .collect()
    }

    /// Instruction addresses of a kernel stack, innermost first, read from
    /// the stack map the BPF program stored it in
    #[cfg(feature = "ebpf")]
    fn kernel_stack_addrs(&mut self, stack_id: u32) -> Vec<u64> {
        let (map_name, key) = if stack_id & KSTACK_OVERFLOW != 0 {
            ("kernel_stackmap2", stack_id & !KSTACK_OVERFLOW)
        } else {
            ("kernel_stackmap", stack_id)
        };
        let Some(map) = self.bpf.as_mut().and_then(|bpf| bpf.map_mut(map_name)) else {
            return Vec::new();
        };
        let Ok(stacks) = StackTraceMap::try_from(map) else {
            return Vec::new();
        };
        stacks
            .get(&key, 0)
            .map(|stack| stack.frames().iter().map(|f| f.ip).collect())
            .unwrap_or_default()
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
    #[test]
    fn test_wait_deltas_report_only_new_time() {
        use std::collections::HashMap;
        let prev: HashMap<(u32, u32), (u64, u64)> = [((10, 7), (100, 2))].into();
        let cur: HashMap<(u32, u32), (u64, u64)> =
            [((10, 7), (350, 5)), ((10, 8), (40, 1)), ((11, 7), (900, 3))].into();
        let d = super::wait_deltas(&prev, &cur);
        // most time first; (10, 7) reports only what accrued since prev
        let got: Vec<_> = d
            .iter()
            .map(|w| (w.pid, w.stack, w.time_ns, w.count))
            .collect();
        assert_eq!(got, vec![(11, 7, 900, 3), (10, 7, 250, 3), (10, 8, 40, 1)]);
        // nothing new: nothing reported
        assert!(super::wait_deltas(&cur, &cur).is_empty());
    }

    #[test]
    fn test_valid_stack_id() {
        assert!(super::valid_stack_id(0));
        assert!(super::valid_stack_id(1023));
        assert!(!super::valid_stack_id(-14i32 as u32)); // EFAULT from bpf_get_stackid
        assert!(!super::valid_stack_id(-17i32 as u32)); // EEXIST
    }

    #[test]
    fn test_waits_serialize_compactly() {
        use crate::ebpf::metrics::{OffCpuMetrics, OffCpuWait};
        let mut m = OffCpuMetrics::default();
        let empty = serde_json::to_value(&m).unwrap();
        assert!(empty.get("waits").is_none() && empty.get("kernel_stacks").is_none());
        m.waits = vec![OffCpuWait {
            pid: 10,
            stack: 7,
            time_ns: 250,
            count: 3,
        }];
        m.kernel_stacks
            .insert(7, vec!["schedule".into(), "pipe_write".into()]);
        let v = serde_json::to_value(&m).unwrap();
        assert_eq!(v["waits"][0]["stack"], 7);
        assert_eq!(v["kernel_stacks"]["7"][1], "pipe_write");
        let back: Vec<OffCpuWait> = serde_json::from_value(v["waits"].clone()).unwrap();
        assert_eq!(back, m.waits);
    }

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
