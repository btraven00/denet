//! eBPF-specific metrics structures

use serde::{Deserialize, Serialize};
use std::collections::HashMap;

/// eBPF profiling metrics
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct EbpfMetrics {
    /// Syscall frequency counts
    #[serde(skip_serializing_if = "Option::is_none")]
    pub syscalls: Option<SyscallMetrics>,

    /// Error message if eBPF collection failed
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
}

impl EbpfMetrics {
    /// Create metrics with an error message
    pub fn error(message: &str) -> Self {
        Self {
            syscalls: None,
            error: Some(message.to_string()),
        }
    }

    /// Create metrics with syscall data
    pub fn with_syscalls(syscalls: SyscallMetrics) -> Self {
        Self {
            syscalls: Some(syscalls),
            error: None,
        }
    }

    /// Check if there's an error
    pub fn has_error(&self) -> bool {
        self.error.is_some()
    }
}

/// System call frequency metrics with enhanced analysis
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct SyscallMetrics {
    /// Total number of syscalls
    pub total: u64,

    /// Syscalls by category
    pub by_category: HashMap<String, u64>,

    /// Top 10 most frequent individual syscalls
    pub top_syscalls: Vec<SyscallCount>,

    /// Enhanced syscall analysis for bottleneck diagnosis
    #[serde(skip_serializing_if = "Option::is_none")]
    pub analysis: Option<SyscallAnalysis>,
}

/// Enhanced syscall analysis for process behavior diagnosis
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SyscallAnalysis {
    /// Process behavior classification
    pub behavior_classification: ProcessBehavior,

    /// Syscalls per second rate
    pub syscall_rate_per_sec: f64,

    /// I/O intensity (0.0 to 1.0)
    pub io_intensity: f64,

    /// Memory management intensity (0.0 to 1.0)
    pub memory_intensity: f64,

    /// CPU-related syscall intensity (0.0 to 1.0)
    pub cpu_intensity: f64,

    /// Network activity intensity (0.0 to 1.0)
    pub network_intensity: f64,

    /// Detected bottleneck indicators
    pub bottleneck_indicators: Vec<String>,

    /// Performance characteristics
    pub performance_profile: PerformanceProfile,
}

/// Process behavior classification based on syscall patterns
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "snake_case")]
pub enum ProcessBehavior {
    /// High I/O syscall activity
    IoBound,
    /// Low syscall activity, high CPU usage
    CpuBound,
    /// High memory management syscalls
    MemoryBound,
    /// High network syscall activity
    NetworkBound,
    /// Mixed workload
    Mixed,
    /// Insufficient data for classification
    Unknown,
}

/// Performance profile characteristics
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PerformanceProfile {
    /// Estimated workload type
    pub workload_type: String,

    /// Performance bottleneck likelihood (0.0 to 1.0)
    pub bottleneck_likelihood: f64,

    /// Optimization suggestions
    pub optimization_hints: Vec<String>,
}

/// Individual syscall count
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SyscallCount {
    /// Syscall name
    pub name: String,
    /// Number of times called
    pub count: u64,
}

/// Syscall categories for grouping
pub const SYSCALL_CATEGORIES: &[(u64, &str)] = &[
    // File I/O
    (0, "read"),     // SYS_read
    (1, "write"),    // SYS_write
    (2, "open"),     // SYS_open
    (3, "close"),    // SYS_close
    (8, "lseek"),    // SYS_lseek
    (257, "openat"), // SYS_openat
    // Memory management
    (9, "mmap"),          // SYS_mmap
    (11, "munmap"),       // SYS_munmap
    (12, "brk"),          // SYS_brk
    (13, "rt_sigaction"), // SYS_rt_sigaction
    // Process/thread management
    (56, "clone"),  // SYS_clone
    (57, "fork"),   // SYS_fork
    (58, "vfork"),  // SYS_vfork
    (59, "execve"), // SYS_execve
    (60, "exit"),   // SYS_exit
    (61, "wait4"),  // SYS_wait4
    // Network
    (41, "socket"),   // SYS_socket
    (42, "connect"),  // SYS_connect
    (43, "accept"),   // SYS_accept
    (44, "sendto"),   // SYS_sendto
    (45, "recvfrom"), // SYS_recvfrom
    // Time/scheduling
    (35, "nanosleep"),      // SYS_nanosleep
    (96, "gettimeofday"),   // SYS_gettimeofday
    (201, "time"),          // SYS_time
    (228, "clock_gettime"), // SYS_clock_gettime
];

/// Get syscall name by number
pub fn syscall_name(syscall_nr: u64) -> String {
    SYSCALL_CATEGORIES
        .iter()
        .find(|(nr, _)| *nr == syscall_nr)
        .map(|(_, name)| name.to_string())
        .unwrap_or_else(|| format!("syscall_{}", syscall_nr))
}

/// Categorize syscalls into functional groups
///
/// Categorizes Linux syscalls based on their primary functionality:
/// - `file_io`: File and I/O operations
/// - `memory`: Memory allocation and management
/// - `process`: Process and thread management
/// - `network`: Network-related operations
/// - `time`: Time and scheduling operations
/// - `ipc`: Inter-process communication
/// - `security`: Permission and security operations
/// - `signal`: Signal handling
/// - `system`: System configuration and information
/// - `other`: Uncategorized syscalls
pub fn categorize_syscall(syscall_nr: u64) -> String {
    match syscall_nr {
        // File I/O operations
        0 | 1 | 2 | 3 | 4 | 5 | 6 | 8 | 16 | 17 | 18 | 19 | 20 | 21 | 22 | 40 | 82 | 83 | 84
        | 85 | 86 | 87 | 88 | 89 | 90 | 132 | 133 | 187 | 188 | 189 | 190 | 257 | 258 | 259
        | 260 | 263 | 264 | 265 | 285 | 286 | 293 | 294 | 295 | 296 | 304 | 305 | 306 | 307 => {
            "file_io".to_string()
        }

        // Memory management
        9 | 10 | 11 | 12 | 15 | 25 | 26 | 27 | 28 | 158 | 159 | 160 | 213 | 214 | 215 | 216
        | 217 | 218 | 226 | 273 | 274 | 275 | 276 | 317 | 318 | 319 => "memory".to_string(),

        // Process/thread management
        56 | 57 | 58 | 59 | 60 | 61 | 62 | 224 | 231 | 232 | 233 | 234 | 235 | 236 | 246 | 266
        | 267 | 268 | 269 | 270 | 271 | 272 => "process".to_string(),

        // Network operations
        41 | 42 | 43 | 44 | 45 | 46 | 47 | 48 | 49 | 50 | 51 | 52 | 53 | 54 | 55 | 198 | 199
        | 200 | 202 | 203 | 288 | 289 | 290 | 291 | 292 | 326 | 327 | 328 | 329 | 330 | 331
        | 332 => "network".to_string(),

        // Time and scheduling operations
        23 | 24 | 35 | 96 | 97 | 98 | 113 | 114 | 115 | 116 | 117 | 118 | 119 | 120 | 201 | 228
        | 229 | 230 | 249 | 252 | 277 | 278 | 279 | 280 => "time".to_string(),

        // Inter-process communication
        63 | 64 | 65 | 66 | 67 | 68 | 69 | 70 | 71 | 72 | 73 | 74 | 75 | 76 | 77 | 78 | 79 | 80
        | 81 => "ipc".to_string(),

        // Security, permissions, capabilities
        91 | 92 | 95 | 123 | 124 | 125 | 126 | 137 | 138 | 139 | 140 | 141 | 142 | 157 | 163
        | 164 | 165 | 166 | 281 | 282 | 283 | 284 => "security".to_string(),

        // Signal handling
        13 | 14 => "signal".to_string(),

        // System configuration and information
        99 | 100 | 101 | 102 | 103 | 153 | 154 | 155 | 156 | 168 | 169 | 170 | 171 | 172 | 173
        | 174 | 175 => "system".to_string(),

        // Unknown
        _ => "other".to_string(),
    }
}

/// Generate enhanced syscall analysis for bottleneck diagnosis
pub fn generate_syscall_analysis(
    metrics: &SyscallMetrics,
    cpu_usage: f32,
    elapsed_seconds: f64,
) -> SyscallAnalysis {
    let total = metrics.total as f64;

    if total < 1.0 || elapsed_seconds < 0.1 {
        return SyscallAnalysis {
            behavior_classification: ProcessBehavior::Unknown,
            syscall_rate_per_sec: 0.0,
            io_intensity: 0.0,
            memory_intensity: 0.0,
            cpu_intensity: 0.0,
            network_intensity: 0.0,
            bottleneck_indicators: vec![],
            performance_profile: PerformanceProfile {
                workload_type: "insufficient_data".to_string(),
                bottleneck_likelihood: 0.0,
                optimization_hints: vec![],
            },
        };
    }

    // Calculate intensities
    let io_intensity = *metrics.by_category.get("file_io").unwrap_or(&0) as f64 / total;
    let memory_intensity = *metrics.by_category.get("memory").unwrap_or(&0) as f64 / total;
    let network_intensity = *metrics.by_category.get("network").unwrap_or(&0) as f64 / total;
    let process_intensity = *metrics.by_category.get("process").unwrap_or(&0) as f64 / total;

    let syscall_rate_per_sec = total / elapsed_seconds;

    // Classify process behavior
    let behavior_classification = classify_process_behavior(
        io_intensity,
        memory_intensity,
        network_intensity,
        cpu_usage as f64,
        syscall_rate_per_sec,
    );

    // Detect bottleneck indicators
    let bottleneck_indicators =
        detect_bottleneck_indicators(&metrics.by_category, syscall_rate_per_sec, cpu_usage as f64);

    // Generate performance profile
    let performance_profile = generate_performance_profile(
        &behavior_classification,
        io_intensity,
        memory_intensity,
        network_intensity,
        syscall_rate_per_sec,
    );

    SyscallAnalysis {
        behavior_classification,
        syscall_rate_per_sec,
        io_intensity,
        memory_intensity,
        cpu_intensity: process_intensity, // Using process syscalls as CPU proxy
        network_intensity,
        bottleneck_indicators,
        performance_profile,
    }
}

/// Classify process behavior based on syscall patterns
fn classify_process_behavior(
    io_intensity: f64,
    memory_intensity: f64,
    network_intensity: f64,
    cpu_usage: f64,
    syscall_rate: f64,
) -> ProcessBehavior {
    // High I/O activity
    if io_intensity > 0.6 && syscall_rate > 100.0 {
        return ProcessBehavior::IoBound;
    }

    // High network activity
    if network_intensity > 0.4 {
        return ProcessBehavior::NetworkBound;
    }

    // High memory management activity
    if memory_intensity > 0.3 {
        return ProcessBehavior::MemoryBound;
    }

    // Low syscall activity but high CPU usage = CPU bound
    if syscall_rate < 50.0 && cpu_usage > 50.0 {
        return ProcessBehavior::CpuBound;
    }

    // Mixed or moderate activity
    if io_intensity > 0.2 && memory_intensity > 0.1 {
        return ProcessBehavior::Mixed;
    }

    ProcessBehavior::Unknown
}

/// Detect specific bottleneck indicators
fn detect_bottleneck_indicators(
    by_category: &HashMap<String, u64>,
    syscall_rate: f64,
    cpu_usage: f64,
) -> Vec<String> {
    let mut indicators = Vec::new();

    let file_io = *by_category.get("file_io").unwrap_or(&0) as f64;
    let memory = *by_category.get("memory").unwrap_or(&0) as f64;
    let network = *by_category.get("network").unwrap_or(&0) as f64;

    // I/O bottleneck indicators
    if file_io > 500.0 {
        indicators.push("high_file_io".to_string());
    }
    if syscall_rate > 1000.0 {
        indicators.push("very_high_syscall_rate".to_string());
    }

    // Memory bottleneck indicators
    if memory > 100.0 {
        indicators.push("frequent_memory_management".to_string());
    }

    // Network bottleneck indicators
    if network > 200.0 {
        indicators.push("high_network_activity".to_string());
    }

    // CPU bottleneck indicators
    if cpu_usage > 80.0 && syscall_rate < 100.0 {
        indicators.push("cpu_intensive".to_string());
    }

    // Mixed bottleneck
    if file_io > 300.0 && memory > 50.0 {
        indicators.push("io_memory_contention".to_string());
    }

    indicators
}

/// Generate performance profile with optimization hints
fn generate_performance_profile(
    behavior: &ProcessBehavior,
    _io_intensity: f64,
    _memory_intensity: f64,
    _network_intensity: f64,
    _syscall_rate: f64,
) -> PerformanceProfile {
    let (workload_type, bottleneck_likelihood, optimization_hints) = match behavior {
        ProcessBehavior::IoBound => {
            let hints = vec![
                "Consider I/O optimization strategies".to_string(),
                "Use async I/O or batching".to_string(),
                "Check for excessive file operations".to_string(),
            ];
            ("file_io_intensive".to_string(), 0.8, hints)
        }
        ProcessBehavior::CpuBound => {
            let hints = vec![
                "CPU optimization opportunities".to_string(),
                "Consider parallel processing".to_string(),
                "Profile for algorithmic improvements".to_string(),
            ];
            ("cpu_intensive".to_string(), 0.7, hints)
        }
        ProcessBehavior::MemoryBound => {
            let hints = vec![
                "Memory allocation optimization needed".to_string(),
                "Consider memory pooling".to_string(),
                "Check for memory leaks".to_string(),
            ];
            ("memory_intensive".to_string(), 0.75, hints)
        }
        ProcessBehavior::NetworkBound => {
            let hints = vec![
                "Network optimization opportunities".to_string(),
                "Consider connection pooling".to_string(),
                "Optimize network protocols".to_string(),
            ];
            ("network_intensive".to_string(), 0.8, hints)
        }
        ProcessBehavior::Mixed => {
            let hints = vec![
                "Mixed workload - profile individual components".to_string(),
                "Consider workload separation".to_string(),
            ];
            ("mixed_workload".to_string(), 0.5, hints)
        }
        ProcessBehavior::Unknown => ("unknown".to_string(), 0.0, vec![]),
    };

    PerformanceProfile {
        workload_type,
        bottleneck_likelihood,
        optimization_hints,
    }
}
