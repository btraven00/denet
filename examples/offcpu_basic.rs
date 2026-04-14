//! Basic off-CPU profiling example
//!
//! Starts a workload that generates off-CPU events (I/O waits), attaches the
//! off-CPU profiler, collects for 2 seconds, then prints per-thread statistics.
//!
//! Usage:
//!   sudo cargo run --example offcpu_basic --features ebpf

use denet::ebpf::{OffCpuProfiler, OffCpuStats};
use std::collections::HashMap;
use std::process::{Command, Stdio};
use std::thread;
use std::time::Duration;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Off-CPU profiling requires CAP_BPF + CAP_PERFMON or root.
    if unsafe { libc::geteuid() } != 0 {
        eprintln!("error: requires root or CAP_BPF/CAP_PERFMON");
        eprintln!("  sudo cargo run --example offcpu_basic --features ebpf");
        std::process::exit(1);
    }

    // Start a workload with I/O-bound behaviour to generate off-CPU events.
    let mut child = Command::new("dd")
        .args(["if=/dev/zero", "of=/dev/null", "bs=4k", "count=100000"])
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()?;

    let pid = child.id();
    println!("Monitoring PID {pid} for 2 seconds...");

    let profiler = OffCpuProfiler::new(vec![pid])?;

    thread::sleep(Duration::from_secs(2));

    let stats: HashMap<(u32, u32), OffCpuStats> = profiler.get_stats();

    if stats.is_empty() {
        println!("No off-CPU events recorded (process may have exited early).");
    } else {
        println!("Threads with off-CPU events: {}", stats.len());
        let mut entries: Vec<_> = stats.iter().collect();
        entries.sort_by(|a, b| b.1.total_time_ns.cmp(&a.1.total_time_ns));
        for ((pid, tid), s) in entries {
            println!(
                "  pid={pid} tid={tid}: events={} total={:.1}ms avg={:.1}ms max={:.1}ms",
                s.count,
                s.total_time_ns as f64 / 1_000_000.0,
                s.avg_time_ns as f64 / 1_000_000.0,
                s.max_time_ns as f64 / 1_000_000.0,
            );
        }
    }

    child.kill().ok();
    Ok(())
}
