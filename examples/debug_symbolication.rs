//! Debug program to test off-CPU profiler symbolication
//!
//! This program helps debug symbolication issues by running a simple workload
//! and showing detailed debug output for stack trace resolution.

use denet::ebpf::OffCpuProfiler;
use std::process::{Command, Stdio};
use std::thread;
use std::time::Duration;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    println!("=== Off-CPU Profiler Symbolication Debug ===");

    // Check if running as root
    if unsafe { libc::geteuid() != 0 } {
        println!("ERROR: This program requires root privileges for eBPF");
        println!("Please run with: sudo cargo run --example debug_symbolication --features ebpf");
        return Ok(());
    }

    // Enable debug mode
    OffCpuProfiler::set_debug_mode(true);
    println!("✓ Debug mode enabled");

    // Create profiler monitoring all processes
    println!("Creating off-CPU profiler...");
    let mut profiler = OffCpuProfiler::new(vec![])?;
    profiler.enable_debug_mode();
    println!("✓ Off-CPU profiler created");

    // Start a test workload that will generate off-CPU events
    println!("Starting test workload...");
    let mut child = Command::new("sh")
        .arg("-c")
        .arg("for i in {1..3}; do echo 'Sleep $i'; sleep 0.2; done")
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()?;

    let child_pid = child.id();
    println!("✓ Test process started with PID: {}", child_pid);

    // Let it run for a bit
    thread::sleep(Duration::from_millis(800));

    // Get statistics
    println!("\n=== Collecting Statistics ===");
    let stats = profiler.get_stats();
    println!("Found {} threads with off-CPU events", stats.len());

    for ((pid, tid), thread_stats) in stats.iter().take(5) {
        println!(
            "  PID {}, TID {}: {}ns total, {} events",
            pid, tid, thread_stats.total_time_ns, thread_stats.count
        );
    }

    // Get stack traces with detailed debugging
    println!("\n=== Collecting Stack Traces ===");
    let stack_traces = profiler.get_stack_traces();
    println!("Found {} stack traces", stack_traces.len());

    // Analyze the first few stack traces
    for (i, trace) in stack_traces.iter().take(3).enumerate() {
        println!("\n--- Stack Trace {} ---", i + 1);
        println!(
            "Event: PID {}, TID {}, off-CPU time: {}ns",
            trace.event.pid, trace.event.tid, trace.event.offcpu_time_ns
        );

        println!(
            "User stack ID: {}, Kernel stack ID: {}",
            trace.event.user_stack_id, trace.event.kernel_stack_id
        );

        if let Some(user_stack) = &trace.user_stack {
            println!("User stack ({} frames):", user_stack.len());
            for (j, frame) in user_stack.iter().enumerate() {
                println!("  Frame {}: addr={:x}", j, frame.address);
                if let Some(symbol) = &frame.symbol {
                    println!("    Symbol: {}", symbol);
                }
                if let Some(location) = &frame.source_location {
                    println!("    Location: {}", location);
                }
            }
        } else {
            println!("User stack: None");
        }

        if let Some(kernel_stack) = &trace.kernel_stack {
            println!("Kernel stack ({} frames):", kernel_stack.len());
            for (j, frame) in kernel_stack.iter().take(3).enumerate() {
                println!("  Frame {}: addr={:x}", j, frame.address);
            }
        } else {
            println!("Kernel stack: None");
        }
    }

    // Clean up
    if let Ok(status) = child.try_wait() {
        if status.is_none() {
            println!("\nTerminating test process...");
            let _ = child.kill();
            let _ = child.wait();
        }
    }

    println!("\n=== Debug Session Complete ===");
    println!("If you see stack frames but no symbols, check:");
    println!("1. The target process has debug symbols (-g flag during compilation)");
    println!("2. The binary is not stripped");
    println!("3. The process is still running when symbolication occurs");
    println!("4. The memory maps are accessible");

    Ok(())
}
