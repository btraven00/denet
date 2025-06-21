//! Simple stack trace test for debugging symbolication
//!
//! This program creates a specific workload and monitors just that process
//! to isolate symbolication issues.

use denet::ebpf::OffCpuProfiler;
use std::process::{Command, Stdio};
use std::thread;
use std::time::Duration;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    println!("=== Simple Stack Trace Test ===");

    // Check if running as root
    if unsafe { libc::geteuid() != 0 } {
        println!("ERROR: This program requires root privileges for eBPF");
        println!("Please run with: sudo cargo run --example simple_stack_test --features ebpf");
        return Ok(());
    }

    // Enable debug mode
    OffCpuProfiler::set_debug_mode(true);
    println!("✓ Debug mode enabled");

    // Start a test workload that will definitely generate off-CPU events
    println!("Starting test workload...");
    let mut child = Command::new("sleep")
        .arg("10")
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()?;

    let child_pid = child.id();
    println!("✓ Test process (sleep) started with PID: {}", child_pid);

    // Create profiler monitoring ALL processes first to see what PIDs are actually captured
    println!("Creating off-CPU profiler for ALL processes to debug PID capture...");
    let mut profiler = OffCpuProfiler::new(vec![])?;
    profiler.enable_debug_mode();
    println!("✓ Off-CPU profiler created");

    // Let it run for a bit to collect data
    thread::sleep(Duration::from_millis(3000));

    // Get statistics for all processes
    println!(
        "\n=== All Process Statistics (looking for PID {}) ===",
        child_pid
    );
    let stats = profiler.get_stats();

    let mut found_target = false;
    let mut similar_pids = Vec::new();

    for ((pid, tid), thread_stats) in &stats {
        // Look for our exact PID
        if *pid == child_pid {
            found_target = true;
            println!(
                "  ✓ FOUND Target process PID {}, TID {}: {}ms total, {} events",
                pid,
                tid,
                thread_stats.total_time_ns / 1_000_000,
                thread_stats.count
            );
        }
        // Also look for TID matches (since eBPF might use TID as PID)
        else if *tid == child_pid {
            found_target = true;
            println!(
                "  ✓ FOUND Target as TID - PID {}, TID {}: {}ms total, {} events",
                pid,
                tid,
                thread_stats.total_time_ns / 1_000_000,
                thread_stats.count
            );
        }
        // Also look for PIDs close to our target (in case of PID/TID confusion)
        else if (*pid as i32 - child_pid as i32).abs() < 10 {
            similar_pids.push((*pid, *tid, thread_stats.count));
        }
    }

    if !found_target {
        println!("❌ No off-CPU events found for target PID {}", child_pid);
        println!("📊 Total processes with events: {}", stats.len());

        if !similar_pids.is_empty() {
            println!("🔍 Similar PIDs found (within ±10 of target):");
            for (pid, tid, count) in &similar_pids {
                println!("    PID {}, TID {}: {} events", pid, tid, count);
            }
        }

        // Show first 10 PIDs for reference
        let sample_pids: Vec<u32> = stats
            .keys()
            .map(|(p, _)| *p)
            .collect::<std::collections::HashSet<_>>()
            .into_iter()
            .take(10)
            .collect();
        println!("📝 Sample PIDs with events: {:?}", sample_pids);
    }

    // Get stack traces
    println!("\n=== Stack Traces ===");
    let stack_traces = profiler.get_stack_traces();
    println!("Total stack traces collected: {}", stack_traces.len());

    // Look for traces from our target process (check both PID and TID)
    let mut target_traces = 0;
    for (i, trace) in stack_traces.iter().enumerate() {
        if trace.event.pid == child_pid || trace.event.tid == child_pid {
            target_traces += 1;
            if target_traces <= 3 {
                // Show first 3 traces from target
                println!("\n--- Target Process Stack Trace {} ---", target_traces);
                println!(
                    "PID: {}, TID: {}, off-CPU time: {}ms",
                    trace.event.pid,
                    trace.event.tid,
                    trace.event.offcpu_time_ns / 1_000_000
                );

                println!(
                    "Stack IDs - User: {}, Kernel: {}",
                    trace.event.user_stack_id, trace.event.kernel_stack_id
                );

                if let Some(user_stack) = &trace.user_stack {
                    println!("User stack frames: {}", user_stack.len());
                    for (j, frame) in user_stack.iter().take(5).enumerate() {
                        println!("  [{}] 0x{:016x}", j, frame.address);
                        if let Some(symbol) = &frame.symbol {
                            println!("      Symbol: {}", symbol);
                        }
                        if let Some(location) = &frame.source_location {
                            println!("      Source: {}", location);
                        }
                    }
                } else {
                    println!("User stack: None");
                }

                if let Some(kernel_stack) = &trace.kernel_stack {
                    println!("Kernel stack frames: {}", kernel_stack.len());
                    for (j, frame) in kernel_stack.iter().take(3).enumerate() {
                        println!("  [{}] 0x{:016x}", j, frame.address);
                    }
                } else {
                    println!("Kernel stack: None");
                }
            }
        }
    }

    if target_traces == 0 {
        println!("No stack traces found for target PID/TID {}", child_pid);
        println!(
            "PIDs found in traces: {:?}",
            stack_traces
                .iter()
                .map(|t| t.event.pid)
                .collect::<std::collections::HashSet<_>>()
        );
        println!(
            "TIDs found in traces: {:?}",
            stack_traces
                .iter()
                .map(|t| t.event.tid)
                .collect::<std::collections::HashSet<_>>()
        );
    } else {
        println!(
            "Found {} stack traces for target PID/TID {}",
            target_traces, child_pid
        );
    }

    // Clean up
    let _ = child.kill();
    let _ = child.wait();

    println!("\n=== Test Complete ===");
    Ok(())
}
