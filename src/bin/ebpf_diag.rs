//! eBPF Diagnostic Tool
//!
//! This tool performs a comprehensive diagnostic of eBPF capabilities on the current system.
//! It checks for permissions, kernel support, filesystem access, and attempts to load a minimal
//! eBPF program to verify functionality.
//!
//! Usage:
//! ```
//! cargo run --bin ebpf_diag --features ebpf
//! cargo run --bin ebpf_diag --features ebpf -- --debug  # For verbose output
//! ```

use aya::BpfLoader;
use std::env;

use std::process::{exit, Command};

// Include compiled eBPF bytecode
#[cfg(feature = "ebpf")]
const SYSCALL_TRACER_BYTECODE: &[u8] =
    include_bytes!(concat!(env!("OUT_DIR"), "/ebpf/syscall_tracer.o"));

fn separator() {
    println!("\n{}", "=".repeat(80));
}

fn section_title(title: &str) {
    separator();
    println!("[ {} ]", title);
    separator();
}

// Global debug flag
static mut DEBUG_MODE: bool = false;

fn debug_println(msg: &str) {
    unsafe {
        if DEBUG_MODE {
            println!("{}", msg);
        }
    }
}

fn run_command(cmd: &str) -> (bool, String) {
    println!("$ {}", cmd);

    match Command::new("sh").arg("-c").arg(cmd).output() {
        Ok(output) => {
            let stdout = String::from_utf8_lossy(&output.stdout).to_string();
            let stderr = String::from_utf8_lossy(&output.stderr).to_string();
            let result = if stderr.is_empty() {
                stdout
            } else {
                format!("{}\nERROR: {}", stdout, stderr)
            };
            let success = output.status.success();

            // Only print the result if in debug mode
            unsafe {
                if DEBUG_MODE || result.lines().count() <= 3 {
                    println!("{}", result);
                } else {
                    println!("[Output hidden, use --debug for details]");
                }
            }
            (success, result)
        }
        Err(e) => {
            println!("ERROR: Failed to execute command: {}", e);
            (false, format!("Error: {}", e))
        }
    }
}

fn check_permissions() -> bool {
    section_title("USER PERMISSIONS");

    println!("Checking user permissions for eBPF...");
    debug_println("Detailed permission checks will be performed...");

    // Check if running as root
    let is_root = unsafe { libc::geteuid() == 0 };
    println!("Running as root: {}", is_root);

    // Check capabilities of current binary
    let exe_path = std::env::current_exe().unwrap_or_default();
    println!("Current executable: {:?}", exe_path);

    let (_, cap_output) = run_command(&format!("getcap {}", exe_path.display()));
    let has_bpf_cap = cap_output.contains("cap_bpf");
    println!("Has CAP_BPF capability: {}", has_bpf_cap);

    // Check if user is in tracing group
    let (_, groups_output) = run_command("groups");
    let in_tracing_group = groups_output.contains("tracing");
    println!("User in tracing group: {}", in_tracing_group);

    is_root || has_bpf_cap
}

fn check_kernel_support() -> bool {
    section_title("KERNEL SUPPORT");

    println!("Checking kernel support for eBPF...");
    debug_println("Examining kernel configuration in detail...");

    // Check kernel version
    let (kernel_success, kernel_version) = run_command("uname -r");
    if !kernel_success {
        println!("Failed to determine kernel version");
        return false;
    }

    // Parse kernel version
    let version_parts: Vec<&str> = kernel_version.trim().split('.').collect();
    if version_parts.len() >= 2 {
        if let (Ok(major), Ok(minor)) = (
            version_parts[0].parse::<u32>(),
            version_parts[1].parse::<u32>(),
        ) {
            println!("Kernel version {}.{} detected", major, minor);
            let version_ok = (major > 4) || (major == 4 && minor >= 18);
            println!("Kernel version sufficient for eBPF: {}", version_ok);
            if !version_ok {
                println!("WARNING: eBPF features require kernel 4.18 or newer");
            }
        }
    }

    // Check BPF config in kernel
    let (_config_success, config_output) = run_command("grep CONFIG_BPF /boot/config-$(uname -r)");
    let bpf_enabled = config_output.contains("CONFIG_BPF=y");
    println!("BPF enabled in kernel: {}", bpf_enabled);

    // Check JIT compiler
    let (_jit_success, jit_output) = run_command(
        "grep -i jit /proc/sys/net/core/bpf_jit_enable 2>/dev/null || echo 'Not available'",
    );
    let jit_enabled = jit_output.trim() == "1";
    println!("BPF JIT compiler enabled: {}", jit_enabled);

    // Check unprivileged BPF setting
    let (_unpriv_success, unpriv_output) = run_command(
        "cat /proc/sys/kernel/unprivileged_bpf_disabled 2>/dev/null || echo 'Not available'",
    );
    println!("Unprivileged BPF disabled: {}", unpriv_output.trim());

    bpf_enabled
}

fn check_filesystem_access() -> bool {
    section_title("FILESYSTEM ACCESS");

    println!("Checking filesystem access for eBPF...");
    debug_println("Testing various filesystem paths and permissions...");

    // Check debugfs mount
    let (debugfs_success, debugfs_output) = run_command("mount | grep debugfs");
    let debugfs_mounted = debugfs_success && debugfs_output.contains("debugfs");
    println!("debugfs mounted: {}", debugfs_mounted);

    // Check tracefs access
    let (_tracefs_success, tracefs_output) = run_command("ls -la /sys/kernel/debug/tracing 2>&1");
    let tracefs_accessible =
        !tracefs_output.contains("Permission denied") && !tracefs_output.contains("No such file");
    println!("tracefs accessible: {}", tracefs_accessible);

    // Check tracefs/events/syscalls access
    let (_syscalls_success, syscalls_output) =
        run_command("ls -la /sys/kernel/debug/tracing/events/syscalls 2>&1");
    let syscalls_accessible =
        !syscalls_output.contains("Permission denied") && !syscalls_output.contains("No such file");
    println!("syscalls tracepoints accessible: {}", syscalls_accessible);

    // Check BPF filesystem
    let (_bpf_fs_success, bpf_fs_output) = run_command("ls -la /sys/fs/bpf 2>&1");
    let bpf_fs_accessible = !bpf_fs_output.contains("No such file");
    println!("BPF filesystem accessible: {}", bpf_fs_accessible);

    // Check if we can write to tracefs
    let (write_success, write_output) = run_command(
        "touch /sys/kernel/debug/tracing/test_file 2>&1 && echo 'Write successful' && rm /sys/kernel/debug/tracing/test_file"
    );
    let can_write = write_success && write_output.contains("Write successful");
    println!("Can write to tracefs: {}", can_write);

    tracefs_accessible && syscalls_accessible
}

fn try_load_ebpf() -> bool {
    section_title("EBPF PROGRAM LOADING");

    debug_println("Attempting to load and attach an eBPF program to verify functionality...");

    #[cfg(not(feature = "ebpf"))]
    {
        println!("ERROR: eBPF feature not enabled. Recompile with --features ebpf");
        return false;
    }

    #[cfg(feature = "ebpf")]
    {
        println!("Attempting to load eBPF program...");

        // Check bytecode
        println!("Bytecode size: {} bytes", SYSCALL_TRACER_BYTECODE.len());

        // Check if bytecode looks valid (dump first few bytes)
        let preview_size = std::cmp::min(SYSCALL_TRACER_BYTECODE.len(), 32);
        let hex_bytes: Vec<String> = SYSCALL_TRACER_BYTECODE[..preview_size]
            .iter()
            .map(|b| format!("{:02x}", b))
            .collect();
        println!("Bytecode preview: {}", hex_bytes.join(" "));

        // Create BPF loader
        println!("Creating BPF loader...");
        let mut loader = BpfLoader::new();

        // Try to load the bytecode
        match loader.load(SYSCALL_TRACER_BYTECODE) {
            Ok(mut bpf) => {
                println!("✓ eBPF bytecode loaded successfully!");

                // Check maps
                println!("Maps in loaded program:");
                let mut maps_found = false;
                for (name, _) in bpf.maps() {
                    println!("  - {}", name);
                    maps_found = true;
                }

                if !maps_found {
                    println!("WARNING: No maps found in the loaded program");
                }

                // Check for syscall_counts map
                let syscall_counts = bpf.take_map("syscall_counts");
                println!("syscall_counts map exists: {}", syscall_counts.is_some());

                // Check for pid_syscall_map
                let pid_syscall_map = bpf.take_map("pid_syscall_map");
                println!("pid_syscall_map exists: {}", pid_syscall_map.is_some());

                // Try to find a tracepoint program
                let mut has_tracepoint = false;
                let tracepoint_names = [
                    "trace_read_enter",
                    "trace_write_enter",
                    "trace_openat_enter",
                ];

                for name in tracepoint_names.iter() {
                    if let Some(prog) = bpf.program_mut(name) {
                        println!("Found program: {}", name);
                        has_tracepoint = true;

                        // Try to load it
                        match prog {
                            aya::programs::Program::TracePoint(tracepoint) => {
                                println!("Attempting to load {} program...", name);
                                match tracepoint.load() {
                                    Ok(_) => {
                                        println!("✓ Program loaded successfully");

                                        // Try to attach it
                                        let tracepoint_name =
                                            name.replace("trace_", "sys_").replace("_enter", "");
                                        println!(
                                            "Attempting to attach to syscalls/{}...",
                                            tracepoint_name
                                        );

                                        match tracepoint.attach("syscalls", &tracepoint_name) {
                                            Ok(_) => {
                                                println!("✓ Tracepoint attached successfully!");
                                                return true;
                                            }
                                            Err(e) => {
                                                println!("✗ Failed to attach tracepoint: {}", e);
                                                println!("Error details: {:?}", e);
                                            }
                                        }
                                    }
                                    Err(e) => {
                                        println!("✗ Failed to load program: {}", e);
                                        println!("Error details: {:?}", e);
                                    }
                                }
                            }
                            _ => {
                                println!("Program {} is not a tracepoint", name);
                            }
                        }
                        break;
                    }
                }

                if !has_tracepoint {
                    println!("✗ No tracepoint programs found!");
                    return false;
                }

                false
            }
            Err(e) => {
                println!("✗ Failed to load eBPF program: {}", e);
                println!("Error details: {:?}", e);
                false
            }
        }
    }
}

fn generate_report(perms_ok: bool, kernel_ok: bool, fs_ok: bool, load_ok: bool) -> bool {
    section_title("DIAGNOSTIC SUMMARY");

    println!(
        "Permissions check:   {}",
        if perms_ok { "✓ PASS" } else { "✗ FAIL" }
    );
    println!(
        "Kernel support:      {}",
        if kernel_ok { "✓ PASS" } else { "✗ FAIL" }
    );
    println!(
        "Filesystem access:   {}",
        if fs_ok { "✓ PASS" } else { "✗ FAIL" }
    );
    println!(
        "eBPF program loading: {}",
        if load_ok { "✓ PASS" } else { "✗ FAIL" }
    );

    let overall = perms_ok && kernel_ok && fs_ok && load_ok;
    println!(
        "\nOVERALL RESULT: {}",
        if overall {
            "✓ PASS - eBPF should work"
        } else {
            "✗ FAIL - eBPF will not work"
        }
    );

    if !overall {
        println!("\nRECOMMENDED ACTIONS:");

        if !perms_ok {
            println!("- Run with sudo privileges");
            println!("- OR add CAP_BPF capability: sudo setcap cap_bpf+ep /path/to/binary");
        }

        if !kernel_ok {
            println!("- Upgrade to kernel 4.18 or newer");
            println!("- Ensure CONFIG_BPF is enabled in kernel");
            println!("- Enable BPF JIT compilation: echo 1 > /proc/sys/net/core/bpf_jit_enable");
        }

        if !fs_ok {
            println!("- Ensure debugfs is mounted: mount -t debugfs none /sys/kernel/debug");
            println!("- Set correct permissions: chmod 755 /sys/kernel/debug");
            println!("- Set correct group permissions:");
            println!("  sudo groupadd -r tracing");
            println!("  sudo usermod -aG tracing $USER");
            println!("  sudo chgrp -R tracing /sys/kernel/debug/tracing");
            println!("  sudo chmod -R g+rwx /sys/kernel/debug/tracing");
        }
    }

    overall
}

fn main() {
    println!("eBPF Diagnostic Tool");
    println!("=====================");

    // Parse command line arguments
    let args: Vec<String> = env::args().collect();
    unsafe {
        DEBUG_MODE = args.iter().any(|arg| arg == "--debug");
        if DEBUG_MODE {
            println!("Debug mode enabled - verbose output will be shown");
        }
    }

    println!("Running comprehensive diagnostic checks for eBPF functionality...");
    debug_println("Detailed debugging information will be displayed");

    // Check if eBPF feature is enabled at compile time
    #[cfg(not(feature = "ebpf"))]
    {
        println!("\nERROR: This tool requires the 'ebpf' feature to be enabled.");
        println!("Recompile with: cargo build --features ebpf --bin ebpf_diag");
        exit(1);
    }

    #[cfg(feature = "ebpf")]
    // Run checks
    let perms_ok = check_permissions();
    let kernel_ok = check_kernel_support();
    let fs_ok = check_filesystem_access();

    // Only try loading if other checks pass
    let load_ok = if perms_ok && kernel_ok && fs_ok {
        try_load_ebpf()
    } else {
        println!("\nSkipping eBPF program loading due to failed prerequisites.");
        false
    };

    #[cfg(feature = "ebpf")]
    // Generate final report
    let success = generate_report(perms_ok, kernel_ok, fs_ok, load_ok);

    #[cfg(feature = "ebpf")]
    // Exit with appropriate code
    exit(if success { 0 } else { 1 });

    #[cfg(not(feature = "ebpf"))]
    unreachable!(); // This should never be reached as we exit(1) earlier
}
