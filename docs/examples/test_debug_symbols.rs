//! Test program to demonstrate stack trace symbolication with debug symbols
//!
//! This program compiles and runs a debug-enabled C program, then monitors
//! it with the off-CPU profiler to demonstrate working symbolication.

use denet::ebpf::OffCpuProfiler;
use std::process::{Command, Stdio};
use std::thread;
use std::time::Duration;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    println!("=== Debug Symbol Symbolication Test ===");

    // Check if running as root
    if unsafe { libc::geteuid() != 0 } {
        println!("ERROR: This program requires root privileges for eBPF");
        println!("Please run with: sudo cargo run --example test_debug_symbols --features ebpf");
        return Ok(());
    }

    // Compile the test program with debug symbols
    println!("Compiling test program with debug symbols...");
    let compile_result = Command::new("gcc")
        .args(&["-g", "-O0", "-o", "test_program", "test_program.c"])
        .output()?;

    if !compile_result.status.success() {
        println!("Failed to compile test program:");
        println!("{}", String::from_utf8_lossy(&compile_result.stderr));
        return Ok(());
    }
    println!("✓ Test program compiled successfully");

    // Enable debug mode
    OffCpuProfiler::set_debug_mode(true);
    println!("✓ Debug mode enabled");

    // Start the test program
    println!("Starting debug-enabled test program...");
    let mut child = Command::new("./test_program")
        .args(&["2", "512000", "8"]) // 2 work iterations, 512KB memory, fibonacci(8)
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()?;

    let child_pid = child.id();
    println!("✓ Test program started with PID: {}", child_pid);

    // Create profiler monitoring this specific process
    println!("Creating off-CPU profiler for PID {}...", child_pid);
    let mut profiler = OffCpuProfiler::new(vec![child_pid])?;
    profiler.enable_debug_mode();
    println!("✓ Off-CPU profiler created and monitoring");

    // Let it run to collect substantial data
    println!("Collecting data for 8 seconds...");
    thread::sleep(Duration::from_millis(8000));

    // Get statistics
    println!("\n=== Process Statistics ===");
    let stats = profiler.get_stats();

    let mut found_events = false;
    for ((pid, tid), thread_stats) in &stats {
        if *pid == child_pid || *tid == child_pid {
            found_events = true;
            println!(
                "Target process PID {}, TID {}: {}ms total, {} events, avg {}ms",
                pid,
                tid,
                thread_stats.total_time_ns / 1_000_000,
                thread_stats.count,
                thread_stats.avg_time_ns / 1_000_000
            );
        }
    }

    if !found_events {
        println!("No off-CPU events found for target process");
        println!("Total processes with events: {}", stats.len());
    }

    // Get stack traces with symbolication
    println!("\n=== Stack Traces with Symbols ===");
    let stack_traces = profiler.get_stack_traces();
    println!("Total stack traces collected: {}", stack_traces.len());

    let mut symbolicated_traces = 0;
    let mut target_traces = 0;

    for trace in stack_traces.iter() {
        if trace.event.pid == child_pid || trace.event.tid == child_pid {
            target_traces += 1;

            if target_traces <= 5 {
                // Show first 5 traces
                println!("\n--- Stack Trace {} ---", target_traces);
                println!(
                    "PID: {}, TID: {}, off-CPU: {}ms",
                    trace.event.pid,
                    trace.event.tid,
                    trace.event.offcpu_time_ns / 1_000_000
                );

                if let Some(user_stack) = &trace.user_stack {
                    println!("User stack ({} frames):", user_stack.len());
                    let mut has_symbols = false;

                    for (i, frame) in user_stack.iter().take(10).enumerate() {
                        print!("  [{}] 0x{:016x}", i, frame.address);

                        if let Some(symbol) = &frame.symbol {
                            print!(" → {}", symbol);
                            has_symbols = true;
                        }

                        if let Some(location) = &frame.source_location {
                            print!(" ({})", location);
                        }

                        println!();
                    }

                    if has_symbols {
                        symbolicated_traces += 1;
                    }
                } else {
                    println!("No user stack");
                }

                if let Some(kernel_stack) = &trace.kernel_stack {
                    println!("Kernel stack ({} frames):", kernel_stack.len());
                    for (i, frame) in kernel_stack.iter().take(3).enumerate() {
                        println!("  [{}] 0x{:016x}", i, frame.address);
                    }
                } else {
                    println!("No kernel stack");
                }
            }
        }
    }

    // Clean up the child process
    match child.try_wait() {
        Ok(Some(_)) => println!("\nTest program completed normally"),
        Ok(None) => {
            println!("\nTerminating test program...");
            let _ = child.kill();
            let _ = child.wait();
        }
        Err(e) => println!("\nError checking child process: {}", e),
    }

    // Clean up compiled binary
    let _ = std::fs::remove_file("test_program");

    // Summary
    println!("\n=== Test Results ===");
    if target_traces > 0 {
        println!("✓ Found {} stack traces from target process", target_traces);

        if symbolicated_traces > 0 {
            println!("✓ Successfully symbolicated {} traces", symbolicated_traces);
            println!("✓ Symbolication is working correctly!");
        } else {
            println!("⚠ Found stack traces but no symbols resolved");
            println!("This could be due to:");
            println!("  - Process exited before symbolication");
            println!("  - Binary stripped or moved");
            println!("  - Missing debug information");
        }
    } else {
        println!("⚠ No stack traces found for target process");
        println!("This could be due to:");
        println!("  - Process completed too quickly");
        println!("  - Insufficient off-CPU time (< 1ms threshold)");
        println!("  - PID/TID filtering issues");
    }

    println!("\nTo verify debug symbols in the binary:");
    println!("  file test_program");
    println!("  objdump -h test_program | grep debug");
    println!("  readelf -S test_program | grep debug");

    Ok(())
}
