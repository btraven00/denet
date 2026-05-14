//! Host/NUMA/affinity environment snapshot for reproducibility.
//!
//! A one-shot `env` record captured at the start of monitoring. Fields are
//! best-effort: anything not readable (containers, non-x86, non-Linux)
//! degrades to `None` or empty.

use serde::{Deserialize, Serialize};
use std::fs;
use std::time::{SystemTime, UNIX_EPOCH};

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct EnvRecord {
    pub ts_ms: u64,
    pub host: String,
    pub kernel: String,
    pub lscpu: LsCpu,
    pub numa: Numa,
    /// CPU affinity inherited by the monitoring process, as a range list
    /// (e.g. "0-3,7-9"). Empty string if unknown.
    pub affinity_inherited: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub cpu_governor: Option<Vec<String>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub cpu_freq_khz: Option<Vec<u64>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub thp_enabled: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub smt_active: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub cgroup: Option<String>,
}

#[derive(Serialize, Deserialize, Debug, Clone, Default)]
pub struct LsCpu {
    pub sockets: u32,
    pub cores_per_socket: u32,
    pub threads_per_core: u32,
    pub model: String,
}

#[derive(Serialize, Deserialize, Debug, Clone, Default)]
pub struct Numa {
    pub nodes: u32,
    pub distances: Vec<Vec<u32>>,
    pub node_sizes_mb: Vec<u64>,
}

impl EnvRecord {
    /// Collect the environment snapshot. `pid` is used to look up cgroup
    /// membership; pass the monitored PID (not the monitor's own PID).
    pub fn collect(pid: u32) -> Self {
        let ts_ms = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_millis() as u64)
            .unwrap_or(0);

        Self {
            ts_ms,
            host: hostname(),
            kernel: kernel_release(),
            lscpu: lscpu(),
            numa: numa(),
            affinity_inherited: affinity_range_list(),
            cpu_governor: read_cpu_attr("scaling_governor", |s| s.trim().to_string()),
            cpu_freq_khz: read_cpu_attr("scaling_cur_freq", |s| s.trim().parse().ok())
                .map(|v: Vec<Option<u64>>| v.into_iter().flatten().collect()),
            thp_enabled: fs::read_to_string("/sys/kernel/mm/transparent_hugepage/enabled")
                .ok()
                .map(|s| s.trim().to_string()),
            smt_active: fs::read_to_string("/sys/devices/system/cpu/smt/active")
                .ok()
                .and_then(|s| s.trim().parse::<u8>().ok().map(|n| n != 0)),
            cgroup: fs::read_to_string(format!("/proc/{pid}/cgroup"))
                .ok()
                .map(|s| s.trim().to_string()),
        }
    }
}

// ---------- low-level collectors ----------

fn hostname() -> String {
    #[cfg(target_os = "linux")]
    {
        if let Ok(s) = fs::read_to_string("/proc/sys/kernel/hostname") {
            return s.trim().to_string();
        }
    }
    String::new()
}

fn kernel_release() -> String {
    #[cfg(target_os = "linux")]
    {
        if let Ok(s) = fs::read_to_string("/proc/sys/kernel/osrelease") {
            return s.trim().to_string();
        }
    }
    String::new()
}

fn lscpu() -> LsCpu {
    let model = fs::read_to_string("/proc/cpuinfo")
        .ok()
        .and_then(|s| parse_cpu_model(&s))
        .unwrap_or_default();

    let (sockets, cores_per_socket, threads_per_core) = cpu_topology().unwrap_or((0, 0, 0));

    LsCpu {
        sockets,
        cores_per_socket,
        threads_per_core,
        model,
    }
}

fn numa() -> Numa {
    let mut node_ids: Vec<u32> = match fs::read_dir("/sys/devices/system/node") {
        Ok(rd) => rd
            .filter_map(|e| e.ok())
            .filter_map(|e| {
                let n = e.file_name();
                let s = n.to_str()?;
                s.strip_prefix("node")?.parse::<u32>().ok()
            })
            .collect(),
        Err(_) => Vec::new(),
    };
    node_ids.sort_unstable();

    let nodes = node_ids.len() as u32;
    let distances: Vec<Vec<u32>> = node_ids
        .iter()
        .map(|id| {
            fs::read_to_string(format!("/sys/devices/system/node/node{id}/distance"))
                .ok()
                .map(|s| parse_distance_row(&s))
                .unwrap_or_default()
        })
        .collect();
    let node_sizes_mb: Vec<u64> = node_ids
        .iter()
        .map(|id| {
            fs::read_to_string(format!("/sys/devices/system/node/node{id}/meminfo"))
                .ok()
                .and_then(|s| parse_node_memtotal_mb(&s))
                .unwrap_or(0)
        })
        .collect();

    Numa {
        nodes,
        distances,
        node_sizes_mb,
    }
}

fn cpu_topology() -> Option<(u32, u32, u32)> {
    use std::collections::BTreeSet;
    let cpus = fs::read_dir("/sys/devices/system/cpu").ok()?;
    let mut sockets: BTreeSet<u32> = BTreeSet::new();
    let mut cores_per_socket: std::collections::HashMap<u32, BTreeSet<u32>> = Default::default();
    let mut siblings_count: Option<u32> = None;
    let mut total_cpus: u32 = 0;

    for entry in cpus.flatten() {
        let name = entry.file_name();
        let name = match name.to_str() {
            Some(s) => s.to_string(),
            None => continue,
        };
        if !name.starts_with("cpu") || !name[3..].chars().all(|c| c.is_ascii_digit()) {
            continue;
        }
        let topo = entry.path().join("topology");
        let pkg = fs::read_to_string(topo.join("physical_package_id"))
            .ok()
            .and_then(|s| s.trim().parse::<u32>().ok());
        let core = fs::read_to_string(topo.join("core_id"))
            .ok()
            .and_then(|s| s.trim().parse::<u32>().ok());
        let sibs = fs::read_to_string(topo.join("thread_siblings_list")).ok();

        if let (Some(p), Some(c)) = (pkg, core) {
            sockets.insert(p);
            cores_per_socket.entry(p).or_default().insert(c);
            total_cpus += 1;
            if siblings_count.is_none() {
                if let Some(list) = sibs {
                    siblings_count = Some(count_range_list(list.trim()) as u32);
                }
            }
        }
    }

    if total_cpus == 0 {
        return None;
    }
    let n_sockets = sockets.len() as u32;
    let cores = cores_per_socket
        .values()
        .map(|s| s.len() as u32)
        .max()
        .unwrap_or(0);
    let threads = siblings_count.unwrap_or(1).max(1);
    Some((n_sockets, cores, threads))
}

/// Read a per-cpu sysfs attribute (e.g. cpufreq/scaling_governor) for every
/// online CPU. Returns None if the attribute is unreadable for cpu0.
fn read_cpu_attr<T, F>(attr: &str, mut parse: F) -> Option<Vec<T>>
where
    F: FnMut(&str) -> T,
{
    let mut results = Vec::new();
    for cpu in 0u32.. {
        let path = format!("/sys/devices/system/cpu/cpu{cpu}/cpufreq/{attr}");
        match fs::read_to_string(&path) {
            Ok(s) => results.push(parse(&s)),
            Err(_) => break,
        }
    }
    if results.is_empty() {
        None
    } else {
        Some(results)
    }
}

#[cfg(target_os = "linux")]
fn affinity_range_list() -> String {
    let mut set = unsafe { std::mem::zeroed::<libc::cpu_set_t>() };
    let rc =
        unsafe { libc::sched_getaffinity(0, std::mem::size_of::<libc::cpu_set_t>(), &mut set) };
    if rc != 0 {
        return String::new();
    }
    let max = libc::CPU_SETSIZE as usize;
    let cpus: Vec<u32> = (0..max)
        .filter(|&i| unsafe { libc::CPU_ISSET(i, &set) })
        .map(|i| i as u32)
        .collect();
    format_range_list(&cpus)
}

#[cfg(not(target_os = "linux"))]
fn affinity_range_list() -> String {
    String::new()
}

// ---------- pure parsers (unit-testable) ----------

/// Parse the first `model name` line out of /proc/cpuinfo content.
pub fn parse_cpu_model(cpuinfo: &str) -> Option<String> {
    for line in cpuinfo.lines() {
        if let Some(rest) = line.strip_prefix("model name") {
            let v = rest.trim_start_matches(|c: char| c == ':' || c.is_whitespace());
            return Some(v.trim().to_string());
        }
    }
    None
}

/// Parse a `/sys/.../node{i}/distance` row: whitespace-separated u32s.
pub fn parse_distance_row(s: &str) -> Vec<u32> {
    s.split_whitespace()
        .filter_map(|t| t.parse::<u32>().ok())
        .collect()
}

/// Parse `MemTotal:` (in kB) out of a `/sys/.../node{i}/meminfo` and return MB.
pub fn parse_node_memtotal_mb(meminfo: &str) -> Option<u64> {
    for line in meminfo.lines() {
        // Format: "Node 0 MemTotal:       65814528 kB"
        let lower = line.to_ascii_lowercase();
        if let Some(idx) = lower.find("memtotal:") {
            let rest = &line[idx + "memtotal:".len()..];
            let mut it = rest.split_whitespace();
            if let Some(kb) = it.next().and_then(|t| t.parse::<u64>().ok()) {
                return Some(kb / 1024);
            }
        }
    }
    None
}

/// Format a sorted-or-unsorted list of CPU ids as a range list:
/// `[0,1,2,3,7,8,9] -> "0-3,7-9"`. Empty input returns "".
pub fn format_range_list(cpus: &[u32]) -> String {
    if cpus.is_empty() {
        return String::new();
    }
    let mut v = cpus.to_vec();
    v.sort_unstable();
    v.dedup();

    let mut out = String::new();
    let mut start = v[0];
    let mut prev = v[0];
    for &n in &v[1..] {
        if n == prev + 1 {
            prev = n;
            continue;
        }
        push_range(&mut out, start, prev);
        start = n;
        prev = n;
    }
    push_range(&mut out, start, prev);
    out
}

fn push_range(out: &mut String, start: u32, end: u32) {
    if !out.is_empty() {
        out.push(',');
    }
    if start == end {
        out.push_str(&start.to_string());
    } else {
        out.push_str(&format!("{start}-{end}"));
    }
}

/// Count the CPUs in a range-list string like "0,2-4,7" -> 5.
pub fn count_range_list(s: &str) -> usize {
    let mut total = 0;
    for part in s.split(',') {
        let part = part.trim();
        if part.is_empty() {
            continue;
        }
        if let Some((a, b)) = part.split_once('-') {
            let (a, b) = (a.parse::<u32>().ok(), b.parse::<u32>().ok());
            if let (Some(a), Some(b)) = (a, b) {
                if b >= a {
                    total += (b - a + 1) as usize;
                }
            }
        } else if part.parse::<u32>().is_ok() {
            total += 1;
        }
    }
    total
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn affinity_range_compression_basic() {
        assert_eq!(format_range_list(&[0, 1, 2, 3]), "0-3");
        assert_eq!(format_range_list(&[0, 1, 2, 3, 7, 8, 9]), "0-3,7-9");
        assert_eq!(format_range_list(&[5]), "5");
        assert_eq!(format_range_list(&[]), "");
    }

    #[test]
    fn affinity_range_compression_unsorted_and_duplicates() {
        assert_eq!(format_range_list(&[3, 0, 2, 1, 1]), "0-3");
        assert_eq!(format_range_list(&[7, 9, 8]), "7-9");
    }

    #[test]
    fn affinity_range_compression_singletons_mixed() {
        assert_eq!(format_range_list(&[0, 2, 4]), "0,2,4");
        assert_eq!(format_range_list(&[0, 1, 4, 5]), "0-1,4-5");
    }

    #[test]
    fn count_range_list_roundtrip() {
        assert_eq!(count_range_list("0-3,7-9"), 7);
        assert_eq!(count_range_list("0,2,4"), 3);
        assert_eq!(count_range_list("5"), 1);
        assert_eq!(count_range_list(""), 0);
    }

    #[test]
    fn count_range_list_handles_malformed_parts() {
        assert_eq!(count_range_list("0, ,2"), 2);
        assert_eq!(count_range_list("5-3"), 0); // inverted range
        assert_eq!(count_range_list("a-b,2"), 1);
    }

    #[test]
    fn numa_distance_parser_square_row() {
        assert_eq!(parse_distance_row("10 12 12 12"), vec![10, 12, 12, 12]);
        assert_eq!(parse_distance_row("10\n12\n12"), vec![10, 12, 12]);
        assert_eq!(parse_distance_row(""), Vec::<u32>::new());
    }

    #[test]
    fn meminfo_parses_memtotal_in_mb() {
        let s = "Node 0 MemTotal:       65814528 kB\nNode 0 Other: 0 kB\n";
        assert_eq!(parse_node_memtotal_mb(s), Some(64272));
    }

    #[test]
    fn meminfo_missing_returns_none() {
        assert_eq!(parse_node_memtotal_mb("Node 0 Free: 1 kB"), None);
    }

    #[test]
    fn cpu_model_parsed_from_proc_cpuinfo() {
        let s = "processor\t: 0\nvendor_id\t: AuthenticAMD\nmodel name\t: AMD EPYC 7742 64-Core Processor\ncache size\t: 512 KB\n";
        assert_eq!(
            parse_cpu_model(s),
            Some("AMD EPYC 7742 64-Core Processor".to_string())
        );
    }

    #[test]
    fn cpu_model_missing_returns_none() {
        assert_eq!(parse_cpu_model("processor: 0\n"), None);
    }

    #[test]
    fn env_record_serializes_with_optional_fields() {
        let env = EnvRecord {
            ts_ms: 1_700_000_000_000,
            host: "omnibenchmark".into(),
            kernel: "6.18.7-test".into(),
            lscpu: LsCpu {
                sockets: 1,
                cores_per_socket: 64,
                threads_per_core: 2,
                model: "AMD EPYC 7742".into(),
            },
            numa: Numa {
                nodes: 4,
                distances: vec![
                    vec![10, 12, 12, 12],
                    vec![12, 10, 12, 12],
                    vec![12, 12, 10, 12],
                    vec![12, 12, 12, 10],
                ],
                node_sizes_mb: vec![64272, 64500, 64500, 64481],
            },
            affinity_inherited: "0-127".into(),
            cpu_governor: Some(vec!["performance".into()]),
            cpu_freq_khz: Some(vec![2_400_000]),
            thp_enabled: Some("always [madvise] never".into()),
            smt_active: Some(true),
            cgroup: Some("0::/user.slice".into()),
        };
        let s = serde_json::to_string(&env).unwrap();
        assert!(s.contains("\"host\":\"omnibenchmark\""));
        assert!(s.contains("\"affinity_inherited\":\"0-127\""));
        assert!(s.contains("\"smt_active\":true"));

        // Optional Nones get elided.
        let mut env2 = env.clone();
        env2.cpu_governor = None;
        env2.cpu_freq_khz = None;
        env2.thp_enabled = None;
        env2.smt_active = None;
        env2.cgroup = None;
        let s2 = serde_json::to_string(&env2).unwrap();
        assert!(!s2.contains("cpu_governor"));
        assert!(!s2.contains("thp_enabled"));

        // Roundtrip preserves NUMA matrix.
        let back: EnvRecord = serde_json::from_str(&s).unwrap();
        assert_eq!(back.numa.distances[1][0], 12);
        assert_eq!(back.lscpu.cores_per_socket, 64);
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn collect_env_smoke_linux() {
        let env = EnvRecord::collect(std::process::id());
        assert!(!env.host.is_empty(), "host should be non-empty");
        assert!(!env.kernel.is_empty(), "kernel should be non-empty");
        assert!(
            !env.lscpu.model.is_empty(),
            "CPU model should be readable from /proc/cpuinfo"
        );
        assert!(env.ts_ms > 0);
        assert!(
            !env.affinity_inherited.is_empty(),
            "sched_getaffinity should populate affinity_inherited"
        );
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn affinity_range_list_returns_nonempty_on_linux() {
        let s = affinity_range_list();
        assert!(!s.is_empty());
        // Whatever subset is returned, count must match a positive number.
        assert!(count_range_list(&s) > 0);
    }

    #[test]
    fn cpu_topology_returns_some_on_linux_or_none_off() {
        // Non-fatal smoke test: the function shouldn't panic regardless.
        let _ = cpu_topology();
    }
}
