//! eBPF-specific metrics structures

use serde::{Deserialize, Serialize};
use std::collections::HashMap;

/// eBPF profiling metrics
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct EbpfMetrics {
    /// Syscall frequency counts
    #[serde(skip_serializing_if = "Option::is_none")]
    pub syscalls: Option<SyscallMetrics>,

    /// Off-CPU profiling data
    #[serde(skip_serializing_if = "Option::is_none")]
    pub offcpu: Option<OffCpuMetrics>,

    /// Error message if eBPF collection failed
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
}

impl EbpfMetrics {
    /// Create metrics with an error message
    pub fn error(message: &str) -> Self {
        Self {
            syscalls: None,
            offcpu: None,
            error: Some(message.to_string()),
        }
    }

    /// Create metrics with syscall data
    pub fn with_syscalls(syscalls: SyscallMetrics) -> Self {
        Self {
            syscalls: Some(syscalls),
            offcpu: None,
            error: None,
        }
    }

    /// Create metrics with off-CPU profiling data
    pub fn with_offcpu(offcpu: OffCpuMetrics) -> Self {
        Self {
            syscalls: None,
            offcpu: Some(offcpu),
            error: None,
        }
    }

    /// Create metrics with both syscalls and off-CPU data
    pub fn with_all(syscalls: SyscallMetrics, offcpu: OffCpuMetrics) -> Self {
        Self {
            syscalls: Some(syscalls),
            offcpu: Some(offcpu),
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

/// Raw syscall intensity metrics derived from observed syscall counts.
/// Classification is left to the caller.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SyscallAnalysis {
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
    // x86_64 syscall numbering. Categories are best-effort: read/write on
    // socket fds fall into file_io here because tracepoints cannot tell a
    // socket fd from a file fd without an auxiliary fd-type map.
    match syscall_nr {
        // file_io: read/write family, file lifecycle, fs metadata, fd ops
        0 | 1 | 2 | 3 | 4 | 5 | 6 | 8                                  // read,write,open,close,stat,fstat,lstat,lseek
        | 16 | 17 | 18 | 19 | 20 | 21                                  // ioctl,pread64,pwrite64,readv,writev,access
        | 32 | 33                                                       // dup,dup2
        | 40                                                            // sendfile
        | 72 | 73 | 74 | 75 | 76 | 77 | 78 | 79 | 80 | 81              // fcntl,flock,fsync,fdatasync,truncate,ftruncate,getdents,getcwd,chdir,fchdir
        | 82 | 83 | 84 | 85 | 86 | 87 | 88 | 89 | 90                   // rename,mkdir,rmdir,creat,link,unlink,symlink,readlink,chmod
        | 132 | 133                                                     // utime,mknod
        | 187 | 188 | 189 | 190                                         // readahead,setxattr,lsetxattr,fsetxattr
        | 217                                                           // getdents64
        | 257 | 258 | 259 | 260 | 263 | 264 | 265                       // openat,mkdirat,mknodat,fchownat,unlinkat,renameat,linkat
        | 266 | 267 | 268 | 269 | 270 | 271 | 272                       // symlinkat,readlinkat,fchmodat,faccessat,pselect6,ppoll,unshare
        | 285 | 286                                                     // fallocate,timerfd_settime
        | 294                                                           // inotify_init1
        | 295 | 296                                                     // preadv,pwritev
        | 303 | 304                                                     // name_to_handle_at,open_by_handle_at
        | 306                                                           // syncfs
        => "file_io".to_string(),

        // memory: allocation, mapping, protection
        9 | 10 | 11 | 12 | 25 | 26 | 27 | 28                            // mmap,mprotect,munmap,brk,mremap,msync,mincore,madvise
        | 158                                                           // arch_prctl
        | 213 | 214 | 215 | 216                                         // epoll_create,epoll_ctl_old,epoll_wait_old,remap_file_pages
        | 218                                                           // set_tid_address (memory-adjacent, low priority)
        | 237 | 238 | 239                                                // mbind,set_mempolicy,get_mempolicy
        | 273 | 274 | 275 | 276                                         // set_robust_list,get_robust_list,splice,tee
        | 318 | 319                                                      // getrandom,memfd_create
        => "memory".to_string(),

        // process: lifecycle, scheduling state
        56 | 57 | 58 | 59 | 60 | 61                                     // clone,fork,vfork,execve,exit,wait4
        | 231                                                           // exit_group
        | 247                                                           // waitid
        | 322                                                           // execveat
        | 435                                                           // clone3
        => "process".to_string(),

        // signal: signal delivery, masking, kill
        13 | 14 | 15                                                    // rt_sigaction,rt_sigprocmask,rt_sigreturn
        | 34                                                            // pause
        | 62                                                            // kill
        | 127 | 128 | 129 | 130 | 131                                    // rt_sigpending,rt_sigtimedwait,rt_sigqueueinfo,rt_sigsuspend,sigaltstack
        | 200                                                           // tkill
        | 234                                                           // tgkill
        | 282                                                           // signalfd
        | 297                                                           // rt_tgsigqueueinfo
        => "signal".to_string(),

        // ipc: pipes, SysV/POSIX IPC, futex, eventfd
        22                                                              // pipe
        | 29 | 30 | 31                                                  // shmget,shmat,shmctl
        | 64 | 65 | 66 | 67                                              // semget,semop,semctl,shmdt
        | 68 | 69 | 70 | 71                                              // msgget,msgsnd,msgrcv,msgctl
        | 202                                                           // futex
        | 240 | 241 | 242 | 243 | 244 | 245 | 246                       // mq_*
        | 283 | 284                                                     // timerfd_create,eventfd
        | 293                                                           // pipe2
        => "ipc".to_string(),

        // network: sockets and socket-level I/O
        41 | 42 | 43 | 44 | 45 | 46 | 47 | 48 | 49 | 50 | 51 | 52 | 53 | 54 | 55
                                                                         // socket,connect,accept,sendto,recvfrom,sendmsg,recvmsg,shutdown,bind,listen,getsockname,getpeername,socketpair,setsockopt,getsockopt
        | 288                                                           // accept4
        | 299                                                           // recvmmsg
        | 307                                                           // sendmmsg
        => "network".to_string(),

        // time: clocks, sleeps, timers
        23 | 24                                                         // select,sched_yield
        | 35                                                            // nanosleep
        | 96 | 97 | 98                                                  // gettimeofday,getrlimit,getrusage
        | 201                                                           // time
        | 203 | 204                                                     // sched_setaffinity,sched_getaffinity
        | 222 | 223 | 224 | 225 | 226 | 227                              // timer_create..clock_settime
        | 228 | 229 | 230                                               // clock_gettime,clock_getres,clock_nanosleep
        | 232 | 233 | 235                                                // epoll_wait,epoll_ctl,utimes
        | 249                                                           // clock_adjtime (close enough)
        | 277 | 278 | 279 | 280                                         // sync_file_range,vmsplice,move_pages,utimensat
        => "time".to_string(),

        // security: ownership, capabilities, namespaces
        91 | 92 | 93 | 94 | 95                                          // fchmod,chown,fchown,lchown,umask
        | 105 | 106                                                     // setuid,setgid
        | 117 | 119 | 120 | 122                                          // setresuid,setresgid,getresgid,setfsuid (approx)
        | 123 | 124 | 125 | 126                                         // setfsgid,getsid,capget,capset
        | 137 | 138 | 139 | 140 | 141 | 142                              // statfs,fstatfs,sysfs,getpriority,setpriority,sched_setparam
        | 157                                                           // prctl
        | 161 | 162 | 163 | 164 | 165 | 166                              // chroot,sync,acct,settimeofday,mount,umount2
        | 281                                                           // epoll_pwait
        => "security".to_string(),

        // system: identification, configuration
        63                                                              // uname
        | 99 | 100 | 101 | 102 | 103                                    // sysinfo,times,ptrace,getuid,syslog
        | 153 | 154 | 155 | 156                                         // vhangup,modify_ldt,pivot_root,_sysctl
        | 168 | 169 | 170 | 171 | 172 | 173 | 174 | 175                  // ioperm,create_module,init_module,delete_module,get_kernel_syms,query_module,quotactl,nfsservctl
        => "system".to_string(),

        _ => "other".to_string(),
    }
}

use super::offcpu_profiler::{ProcessedOffCpuEvent, StackFrame};

/// Aggregated stack trace information for display
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct AggregatedStacks {
    /// Aggregated user-space stack traces
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub user_stack: Vec<StackFrame>,

    /// Aggregated kernel-space stack traces
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub kernel_stack: Vec<StackFrame>,
}

/// Off-CPU profiling metrics
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct OffCpuMetrics {
    /// Total time spent off-CPU (nanoseconds)
    pub total_time_ns: u64,

    /// Number of off-CPU events
    pub total_events: u64,

    /// Average time spent off-CPU (nanoseconds)
    pub avg_time_ns: u64,

    /// Maximum time spent off-CPU (nanoseconds)
    pub max_time_ns: u64,

    /// Minimum time spent off-CPU (nanoseconds)
    pub min_time_ns: u64,

    /// Thread-specific off-CPU statistics
    #[serde(skip_serializing_if = "HashMap::is_empty")]
    pub thread_stats: HashMap<String, ThreadOffCpuStats>,

    /// Top threads ranked by total off-CPU time, descending (max 10 entries).
    ///
    /// Each entry is a summary across all off-CPU events for that thread since
    /// profiling started. `percentage` is the thread's share of the total
    /// off-CPU time accumulated across all monitored threads — not a share of
    /// wall-clock time.
    ///
    /// This is derived directly from the raw per-thread event counters in
    /// `thread_stats`, not from a separate analysis step.
    pub top_blocking_threads: Vec<ThreadOffCpuInfo>,

    /// Analysis of off-CPU bottlenecks
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub bottlenecks: Vec<String>,

    /// Symbolicated stack traces (very verbose, for debugging/export)
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub stack_traces: Vec<ProcessedOffCpuEvent>,

    /// Aggregated stack information (for display)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub stacks: Option<AggregatedStacks>,
}

/// Thread-specific off-CPU statistics
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct ThreadOffCpuStats {
    /// Thread ID
    pub tid: u32,

    /// Total time spent off-CPU (nanoseconds)
    pub total_time_ns: u64,

    /// Number of off-CPU events
    pub count: u64,

    /// Average time spent off-CPU (nanoseconds)
    pub avg_time_ns: u64,

    /// Maximum time spent off-CPU (nanoseconds)
    pub max_time_ns: u64,

    /// Minimum time spent off-CPU (nanoseconds)
    pub min_time_ns: u64,
}

/// One entry in `top_blocking_threads`: a per-thread off-CPU summary.
///
/// Appears in JSON as:
/// ```json
/// { "pid": 1234, "tid": 1235, "time_ms": 450.2, "percentage": 33.33 }
/// ```
///
/// `time_ms` is the cumulative off-CPU time for this thread since monitoring
/// started. `percentage` is its share of the combined off-CPU time across all
/// monitored threads (not of wall-clock time).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ThreadOffCpuInfo {
    /// Thread ID
    pub tid: u32,

    /// Process ID (TGID)
    pub pid: u32,

    /// Total time spent off-CPU in milliseconds
    #[serde(rename = "time_ms")]
    pub total_time_ms: f64,

    /// This thread's share of total off-CPU time across all monitored threads
    #[serde(serialize_with = "serialize_percentage_2dp")]
    pub percentage: f64,
}

/// Serialize a f64 percentage value with 2 decimal places
fn serialize_percentage_2dp<S>(value: &f64, serializer: S) -> Result<S::Ok, S::Error>
where
    S: serde::Serializer,
{
    let rounded = (value * 100.0).round() / 100.0;
    serializer.serialize_f64(rounded)
}

/// Analysis of off-CPU patterns
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OffCpuAnalysis {
    /// Classification of what's causing the most off-CPU time
    pub bottleneck_type: OffCpuBottleneckType,

    /// Percentage of time spent in I/O-related waits
    pub io_wait_percentage: f64,

    /// Percentage of time spent in lock contention
    pub lock_contention_percentage: f64,

    /// Percentage of time spent in sleep/idle
    pub sleep_percentage: f64,

    /// Optimization suggestions
    pub optimization_hints: Vec<String>,
}

/// Classification of off-CPU bottlenecks
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "snake_case")]
pub enum OffCpuBottleneckType {
    /// Blocking I/O operations
    IoBlocked,

    /// Lock contention
    LockContention,

    /// Voluntary sleep/yield
    Sleep,

    /// Various mixed causes
    Mixed,

    /// Unknown cause
    Unknown,
}

/// Compute raw syscall intensity ratios and rate from observed metrics.
pub fn generate_syscall_analysis(
    metrics: &SyscallMetrics,
    elapsed_seconds: f64,
) -> SyscallAnalysis {
    let total = metrics.total as f64;

    if total < 1.0 || elapsed_seconds < 0.1 {
        return SyscallAnalysis {
            syscall_rate_per_sec: 0.0,
            io_intensity: 0.0,
            memory_intensity: 0.0,
            cpu_intensity: 0.0,
            network_intensity: 0.0,
        };
    }

    SyscallAnalysis {
        syscall_rate_per_sec: total / elapsed_seconds,
        io_intensity: *metrics.by_category.get("file_io").unwrap_or(&0) as f64 / total,
        memory_intensity: *metrics.by_category.get("memory").unwrap_or(&0) as f64 / total,
        cpu_intensity: *metrics.by_category.get("process").unwrap_or(&0) as f64 / total,
        network_intensity: *metrics.by_category.get("network").unwrap_or(&0) as f64 / total,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // x86_64 syscall numbers, verified against
    // arch/x86/entry/syscalls/syscall_64.tbl.
    const READ: u64 = 0;
    const WRITE: u64 = 1;
    const CLOSE: u64 = 3;
    const FCNTL: u64 = 72;
    const FLOCK: u64 = 73;
    const FSYNC: u64 = 74;
    const GETDENTS: u64 = 78;
    const CHDIR: u64 = 80;
    const OPENAT: u64 = 257;

    const MMAP: u64 = 9;
    const MUNMAP: u64 = 11;
    const BRK: u64 = 12;

    const CLONE: u64 = 56;
    const FORK: u64 = 57;
    const EXECVE: u64 = 59;
    const EXIT: u64 = 60;
    const EXIT_GROUP: u64 = 231;
    const CLONE3: u64 = 435;

    const SOCKET: u64 = 41;
    const CONNECT: u64 = 42;
    const SENDTO: u64 = 44;
    const RECVFROM: u64 = 45;
    const SENDMSG: u64 = 46;
    const RECVMSG: u64 = 47;
    const ACCEPT4: u64 = 288;
    const SENDMMSG: u64 = 307;

    const PIPE: u64 = 22;
    const PIPE2: u64 = 293;
    const FUTEX: u64 = 202;
    const SHMGET: u64 = 29;
    const SEMOP: u64 = 65;
    const MSGSND: u64 = 69;

    const RT_SIGACTION: u64 = 13;
    const RT_SIGPROCMASK: u64 = 14;
    const KILL: u64 = 62;
    const TKILL: u64 = 200;
    const TGKILL: u64 = 234;

    const NANOSLEEP: u64 = 35;
    const CLOCK_GETTIME: u64 = 228;
    const CLOCK_NANOSLEEP: u64 = 230;
    const SCHED_SETAFFINITY: u64 = 203;

    const UNAME: u64 = 63;

    fn cat(nr: u64) -> String {
        categorize_syscall(nr)
    }

    #[test]
    fn file_io_basic_rw() {
        assert_eq!(cat(READ), "file_io");
        assert_eq!(cat(WRITE), "file_io");
        assert_eq!(cat(CLOSE), "file_io");
        assert_eq!(cat(OPENAT), "file_io");
    }

    /// Regression: the original code lumped 63..=81 into "ipc", which
    /// mis-bucketed fcntl/flock/fsync/getdents/chdir.
    #[test]
    fn regression_file_io_not_ipc() {
        assert_eq!(cat(FCNTL), "file_io");
        assert_eq!(cat(FLOCK), "file_io");
        assert_eq!(cat(FSYNC), "file_io");
        assert_eq!(cat(GETDENTS), "file_io");
        assert_eq!(cat(CHDIR), "file_io");
    }

    #[test]
    fn memory_basic() {
        assert_eq!(cat(MMAP), "memory");
        assert_eq!(cat(MUNMAP), "memory");
        assert_eq!(cat(BRK), "memory");
    }

    /// Workers forking via clone/clone3 must surface as "process".
    /// This was the original gap: tracepoints existed in metrics
    /// but the BPF program never attached to them.
    #[test]
    fn process_lifecycle() {
        assert_eq!(cat(CLONE), "process");
        assert_eq!(cat(FORK), "process");
        assert_eq!(cat(EXECVE), "process");
        assert_eq!(cat(EXIT), "process");
        assert_eq!(cat(EXIT_GROUP), "process");
        assert_eq!(cat(CLONE3), "process");
    }

    #[test]
    fn network_full_socket_family() {
        for nr in [
            SOCKET, CONNECT, SENDTO, RECVFROM, SENDMSG, RECVMSG, ACCEPT4, SENDMMSG,
        ] {
            assert_eq!(cat(nr), "network", "syscall {} should be network", nr);
        }
    }

    /// Regression: futex (202) and sched_setaffinity (203) used to be
    /// classified as "network".
    #[test]
    fn regression_futex_not_network() {
        assert_eq!(cat(FUTEX), "ipc");
        assert_ne!(cat(SCHED_SETAFFINITY), "network");
    }

    #[test]
    fn ipc_primitives() {
        assert_eq!(cat(PIPE), "ipc");
        assert_eq!(cat(PIPE2), "ipc");
        assert_eq!(cat(FUTEX), "ipc");
        assert_eq!(cat(SHMGET), "ipc");
        assert_eq!(cat(SEMOP), "ipc");
        assert_eq!(cat(MSGSND), "ipc");
    }

    #[test]
    fn signal_family() {
        assert_eq!(cat(RT_SIGACTION), "signal");
        assert_eq!(cat(RT_SIGPROCMASK), "signal");
        assert_eq!(cat(KILL), "signal");
        assert_eq!(cat(TKILL), "signal");
        assert_eq!(cat(TGKILL), "signal");
    }

    #[test]
    fn time_family() {
        assert_eq!(cat(NANOSLEEP), "time");
        assert_eq!(cat(CLOCK_GETTIME), "time");
        assert_eq!(cat(CLOCK_NANOSLEEP), "time");
    }

    #[test]
    fn system_uname() {
        // Regression: uname (63) used to be the first entry in the
        // 63..=81 range that incorrectly bucketed as "ipc".
        assert_eq!(cat(UNAME), "system");
    }

    #[test]
    fn unknown_falls_back_to_other() {
        assert_eq!(cat(9999), "other");
    }

    /// No syscall number should be classified into more than one
    /// category. This guards against future range overlaps when adding
    /// new entries.
    #[test]
    fn categories_are_disjoint() {
        // Spot-check a representative number from each category.
        let samples = [
            (READ, "file_io"),
            (MMAP, "memory"),
            (CLONE, "process"),
            (SOCKET, "network"),
            (FUTEX, "ipc"),
            (KILL, "signal"),
            (NANOSLEEP, "time"),
            (UNAME, "system"),
        ];
        for (nr, expected) in samples {
            assert_eq!(cat(nr), expected, "{} should map to {}", nr, expected);
        }
    }
}
