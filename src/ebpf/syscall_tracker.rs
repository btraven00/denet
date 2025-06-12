//! Syscall tracking using eBPF
//!
//! This module implements system call frequency tracking across process trees
//! using eBPF tracepoints. It provides low-overhead monitoring of syscall patterns.

use crate::ebpf::metrics::*;
use crate::error::Result;
use std::collections::HashMap;

// Real eBPF implementation using aya
#[cfg(feature = "ebpf")]
use aya::{maps::HashMap as BpfHashMap, Bpf, BpfLoader};

// Include compiled eBPF bytecode at compile time
#[cfg(feature = "ebpf")]
const SYSCALL_TRACER_BYTECODE: &[u8] =
    include_bytes!(concat!(env!("OUT_DIR"), "/ebpf/syscall_tracer.o"));

/// Syscall tracker using eBPF
#[cfg(feature = "ebpf")]
pub struct SyscallTracker {
    #[cfg(feature = "ebpf")]
    bpf: Option<Bpf>,

    #[cfg(feature = "ebpf")]
    syscall_counts: Option<BpfHashMap<aya::maps::MapData, u32, u64>>,

    #[cfg(feature = "ebpf")]
    _pid_syscall_map: Option<BpfHashMap<aya::maps::MapData, u32, u32>>,

    /// PIDs to monitor (process tree)
    monitored_pids: Vec<u32>,

    /// Last collected metrics for delta calculation
    _last_metrics: HashMap<u32, u64>,

    #[cfg(feature = "ebpf")]
    _attached_programs: bool,
}

impl SyscallTracker {
    /// Set the debug mode for eBPF operations
    #[cfg(feature = "ebpf")]
    pub fn set_debug_mode(debug: bool) {
        unsafe {
            crate::ebpf::debug::set_debug_mode(debug);
            if debug {
                println!("eBPF debug mode enabled - verbose output will be shown");
            }
        }
    }

    /// Create a new syscall tracker for the given PIDs
    pub fn new(pids: Vec<u32>) -> Result<Self> {
        #[cfg(feature = "ebpf")]
        {
            log::info!("Initializing eBPF syscall tracker with feature enabled");
            crate::ebpf::debug::debug_println("eBPF feature is enabled during compilation");

            // Check binary permissions and capabilities
            crate::ebpf::debug::debug_println(&format!("Process ID: {}", std::process::id()));
            crate::ebpf::debug::debug_println(&format!(
                "Executable: {:?}",
                std::env::current_exe().unwrap_or_default()
            ));

            // Verify system eBPF readiness
            let readiness_check = std::process::Command::new("sh")
                .arg("-c")
                .arg("echo 'Checking eBPF prerequisites:'; \
                      echo -n 'Kernel BPF enabled: '; grep -q CONFIG_BPF=y /boot/config-$(uname -r) && echo 'YES' || echo 'NO'; \
                      echo -n 'Unprivileged BPF disabled: '; cat /proc/sys/kernel/unprivileged_bpf_disabled 2>/dev/null || echo 'N/A'; \
                      echo -n 'Root user: '; [ $(id -u) -eq 0 ] && echo 'YES' || echo 'NO'; \
                      echo -n 'CAP_BPF capability: '; getcap $(readlink -f /proc/$$/exe) 2>/dev/null | grep -q cap_bpf && echo 'YES' || echo 'NO'; \
                      echo -n 'tracefs accessible: '; [ -r /sys/kernel/debug/tracing/events/syscalls ] && echo 'YES' || echo 'NO';")
                .output();

            if let Ok(output) = readiness_check {
                let report = String::from_utf8_lossy(&output.stdout);
                crate::ebpf::debug::debug_println(&format!("System eBPF readiness:\n{}", report));
                log::info!("System eBPF readiness:\n{}", report);
            }

            match Self::init_ebpf() {
                Ok((bpf, pid_syscall_map, syscall_counts)) => {
                    log::info!("✓ eBPF syscall tracker successfully initialized");
                    crate::ebpf::debug::debug_println(
                        "eBPF syscall tracker successfully initialized",
                    );
                    Ok(Self {
                        bpf: Some(bpf),
                        syscall_counts: Some(syscall_counts),
                        _pid_syscall_map: Some(pid_syscall_map),
                        monitored_pids: pids.clone(),
                        _last_metrics: HashMap::new(),
                        _attached_programs: true,
                    })
                }
                Err(e) => {
                    log::warn!("Failed to initialize eBPF syscall tracking: {}", e);
                    crate::ebpf::debug::debug_println(&format!(
                        "Failed to initialize eBPF syscall tracking: {}",
                        e
                    ));

                    // Print additional debug info about capabilities
                    {
                        log::warn!("Current process ID: {}", std::process::id());
                    }
                    // Check if we're running as root
                    if unsafe { libc::geteuid() } == 0 {
                        crate::ebpf::debug::debug_println(
                            "Running as root but eBPF initialization still failed",
                        );

                        // Check if BPF is enabled in the kernel
                        if let Ok(output) = std::process::Command::new("sh")
                            .arg("-c")
                            .arg("test -e /sys/fs/bpf && echo 'BPF filesystem mounted' || echo 'BPF filesystem not mounted'")
                            .output()
                        {
                            let bpf_fs = String::from_utf8_lossy(&output.stdout);
                            crate::ebpf::debug::debug_println(&format!("{}", bpf_fs.trim()));
                            log::warn!("{}", bpf_fs.trim());
                        }
                    } else {
                        log::warn!("Not running as root - CAP_BPF capability required");
                        crate::ebpf::debug::debug_println(
                            "Not running as root - CAP_BPF capability required",
                        );

                        // Check if we have CAP_BPF capability
                        if let Ok(output) = std::process::Command::new("sh")
                            .arg("-c")
                            .arg(format!(
                                "getcap {}",
                                std::env::current_exe().unwrap_or_default().display()
                            ))
                            .output()
                        {
                            let caps = String::from_utf8_lossy(&output.stdout);
                            crate::ebpf::debug::debug_println(&format!(
                                "Current capabilities: {}",
                                caps.trim()
                            ));
                            log::warn!("Current capabilities: {}", caps.trim());
                        }
                    }

                    Ok(Self {
                        bpf: None,
                        syscall_counts: None,
                        _pid_syscall_map: None,
                        monitored_pids: pids.clone(),
                        _last_metrics: HashMap::new(),
                        _attached_programs: false,
                    })
                }
            }
        }

        #[cfg(not(feature = "ebpf"))]
        {
            Ok(Self {
                monitored_pids: pids,
                last_metrics: HashMap::new(),
            })
        }
    }

    /// Initialize eBPF program and maps
    /// For this implementation, we'll use a hybrid approach with real Linux interfaces
    #[cfg(feature = "ebpf")]
    fn init_ebpf() -> Result<(
        Bpf,
        BpfHashMap<aya::maps::MapData, u32, u32>,
        BpfHashMap<aya::maps::MapData, u32, u64>,
    )> {
        // Load real eBPF bytecode!
        log::info!("Loading real eBPF program for syscall tracking...");
        crate::ebpf::debug::debug_println("Starting eBPF initialization");

        // Check permissions
        let is_root = unsafe { libc::geteuid() == 0 };
        log::info!("Running as root: {}", is_root);
        crate::ebpf::debug::debug_println(&format!("Running as root: {}", is_root));

        // Check capabilities
        match std::process::Command::new("sh")
            .arg("-c")
            .arg(format!(
                "getcap {}",
                std::env::current_exe().unwrap_or_default().display()
            ))
            .output()
        {
            Ok(output) => {
                let caps = String::from_utf8_lossy(&output.stdout);
                log::info!("Current capabilities: {}", caps.trim());
                crate::ebpf::debug::debug_println(&format!(
                    "Current capabilities: {}",
                    caps.trim()
                ));
            }
            Err(e) => {
                log::warn!("Failed to check capabilities: {}", e);
                crate::ebpf::debug::debug_println(&format!("Failed to check capabilities: {}", e));
            }
        }

        // Check kernel BPF support early
        if let Ok(output) = std::process::Command::new("sh")
            .arg("-c")
            .arg("grep CONFIG_BPF /boot/config-$(uname -r)")
            .output()
        {
            let config = String::from_utf8_lossy(&output.stdout);
            log::info!("Kernel BPF configuration:\n{}", config);
            crate::ebpf::debug::debug_println(&format!("Kernel BPF configuration:\n{}", config));
        }

        // Check bytecode size to ensure it's loaded properly
        log::debug!(
            "eBPF bytecode size: {} bytes",
            SYSCALL_TRACER_BYTECODE.len()
        );

        // Dump first few bytes of bytecode for debugging
        let preview_size = std::cmp::min(SYSCALL_TRACER_BYTECODE.len(), 32);
        let hex_bytes: Vec<String> = SYSCALL_TRACER_BYTECODE[..preview_size]
            .iter()
            .map(|b| format!("{:02x}", b))
            .collect();
        log::debug!("eBPF bytecode preview: {}", hex_bytes.join(" "));

        // Write bytecode to a temp file for detailed inspection
        use std::io::Write;
        unsafe {
            if crate::ebpf::debug::is_debug_mode() {
                if let Ok(mut file) = std::fs::File::create("/tmp/syscall_tracer_dump.o") {
                    if let Err(e) = file.write_all(SYSCALL_TRACER_BYTECODE) {
                        crate::ebpf::debug::debug_println(&format!(
                            "Failed to write bytecode to temp file: {}",
                            e
                        ));
                    } else {
                        crate::ebpf::debug::debug_println(
                            "Wrote bytecode to /tmp/syscall_tracer_dump.o for inspection",
                        );

                        // Try to get ELF header info
                        if let Ok(output) = std::process::Command::new("sh")
                            .arg("-c")
                            .arg("readelf -h /tmp/syscall_tracer_dump.o 2>&1 || echo 'Failed to read ELF header'")
                            .output()
                        {
                            let header_info = String::from_utf8_lossy(&output.stdout);
                            crate::ebpf::debug::debug_println(&format!("ELF header info:\n{}", header_info));
                            log::debug!("ELF header info:\n{}", header_info);
                        }

                        // Try to get section info
                        if let Ok(output) = std::process::Command::new("sh")
                            .arg("-c")
                            .arg("readelf -S /tmp/syscall_tracer_dump.o 2>&1 || echo 'Failed to read ELF sections'")
                            .output()
                        {
                            let section_info = String::from_utf8_lossy(&output.stdout);
                            crate::ebpf::debug::debug_println(&format!("ELF section info:\n{}", section_info));
                            log::debug!("ELF section info:\n{}", section_info);
                        }

                        // Try to inspect with llvm-objdump if available
                        if let Ok(output) = std::process::Command::new("sh")
                            .arg("-c")
                            .arg("which llvm-objdump && llvm-objdump -d /tmp/syscall_tracer_dump.o 2>&1 || echo 'llvm-objdump not available'")
                            .output()
                        {
                            let objdump_info = String::from_utf8_lossy(&output.stdout);
                            if !objdump_info.contains("not available") {
                                crate::ebpf::debug::debug_println("llvm-objdump info available at /tmp/syscall_tracer_dump.objdump");
                                log::debug!("llvm-objdump info written to /tmp/syscall_tracer_dump.objdump");

                                // Write to a separate file as it can be very verbose
                                if let Ok(mut file) = std::fs::File::create("/tmp/syscall_tracer_dump.objdump") {
                                    let _ = file.write_all(objdump_info.as_bytes());
                                }
                            } else {
                                crate::ebpf::debug::debug_println(&format!("{}", objdump_info.trim()));
                            }
                        }
                    }
                }
            }
        }

        // Print path to the bytecode file
        log::debug!(
            "Bytecode source: {}",
            concat!(env!("OUT_DIR"), "/ebpf/syscall_tracer.o")
        );

        // Check if file exists
        let bytecode_path = std::path::Path::new(env!("OUT_DIR")).join("ebpf/syscall_tracer.o");
        log::debug!(
            "Bytecode file exists: {} (size: {})",
            bytecode_path.exists(),
            if bytecode_path.exists() {
                std::fs::metadata(&bytecode_path)
                    .map(|m| m.len().to_string())
                    .unwrap_or_else(|_| "unknown".to_string())
            } else {
                "N/A".to_string()
            }
        );

        crate::ebpf::debug::debug_println(&format!(
            "Bytecode file location: {}",
            bytecode_path.display()
        ));

        // Load the compiled eBPF program
        log::debug!("Creating BPF loader...");
        crate::ebpf::debug::debug_println("Creating BPF loader");

        // Check if we can read the file directly
        if bytecode_path.exists() {
            match std::fs::read(&bytecode_path) {
                Ok(bytes) => {
                    crate::ebpf::debug::debug_println(&format!(
                        "Successfully read {} bytes from disk bytecode file",
                        bytes.len()
                    ));

                    // Compare first few bytes with embedded bytecode
                    let disk_preview_size = std::cmp::min(bytes.len(), 32);
                    let disk_hex_bytes: Vec<String> = bytes[..disk_preview_size]
                        .iter()
                        .map(|b| format!("{:02x}", b))
                        .collect();
                    crate::ebpf::debug::debug_println(&format!(
                        "Disk bytecode preview: {}",
                        disk_hex_bytes.join(" ")
                    ));

                    // Check if embedded and disk bytecodes are identical
                    if bytes.len() == SYSCALL_TRACER_BYTECODE.len() {
                        let identical = bytes
                            .iter()
                            .zip(SYSCALL_TRACER_BYTECODE.iter())
                            .all(|(a, b)| a == b);
                        crate::ebpf::debug::debug_println(&format!(
                            "Embedded and disk bytecodes are identical: {}",
                            identical
                        ));
                    } else {
                        crate::ebpf::debug::debug_println(&format!(
                            "Bytecode size mismatch: disk={}, embedded={}",
                            bytes.len(),
                            SYSCALL_TRACER_BYTECODE.len()
                        ));
                    }
                }
                Err(e) => {
                    crate::ebpf::debug::debug_println(&format!(
                        "Failed to read bytecode file: {}",
                        e
                    ));
                }
            }
        }

        // Load the compiled eBPF program
        log::debug!("Creating BPF loader...");
        crate::ebpf::debug::debug_println("Creating BPF loader");

        // Create loader with default options
        let mut loader = BpfLoader::new();

        // Log the Aya usage
        crate::ebpf::debug::debug_println("Using Aya for eBPF loading");

        // Check if LLVM tools are available for diagnosing ELF issues
        if let Ok(output) = std::process::Command::new("sh")
            .arg("-c")
            .arg("which llvm-readelf || which readelf || echo 'No ELF tools found'")
            .output()
        {
            let elf_tools = String::from_utf8_lossy(&output.stdout);
            crate::ebpf::debug::debug_println(&format!(
                "Available ELF tools: {}",
                elf_tools.trim()
            ));
        }

        // Check system state before loading
        if let Ok(output) = std::process::Command::new("sh")
            .arg("-c")
            .arg("cat /proc/sys/kernel/bpf_stats_enabled 2>/dev/null || echo 'BPF stats not available'")
            .output()
        {
            let bpf_stats = String::from_utf8_lossy(&output.stdout);
            crate::ebpf::debug::debug_println(&format!("BPF stats enabled: {}", bpf_stats.trim()));
        }

        // Check kernel capabilities
        if let Ok(output) = std::process::Command::new("sh")
            .arg("-c")
            .arg("uname -r")
            .output()
        {
            let kernel_version = String::from_utf8_lossy(&output.stdout);
            crate::ebpf::debug::debug_println(&format!(
                "Kernel version: {}",
                kernel_version.trim()
            ));
        }

        // Check unprivileged BPF setting
        if let Ok(output) = std::process::Command::new("sh")
            .arg("-c")
            .arg("cat /proc/sys/kernel/unprivileged_bpf_disabled 2>/dev/null || echo 'N/A'")
            .output()
        {
            let unprivileged_bpf = String::from_utf8_lossy(&output.stdout);
            crate::ebpf::debug::debug_println(&format!(
                "Unprivileged BPF disabled: {}",
                unprivileged_bpf.trim()
            ));
        }

        if let Ok(output) = std::process::Command::new("sh")
            .arg("-c")
            .arg("ls -la /sys/fs/bpf/ 2>/dev/null || echo 'BPF filesystem not accessible'")
            .output()
        {
            let bpf_fs = String::from_utf8_lossy(&output.stdout);
            crate::ebpf::debug::debug_println(&format!("BPF filesystem content:\n{}", bpf_fs));
        }

        log::debug!("Attempting to load eBPF bytecode...");
        crate::ebpf::debug::debug_println(&format!(
            "Attempting to load eBPF bytecode (size: {} bytes)",
            SYSCALL_TRACER_BYTECODE.len()
        ));

        // Check for existing BPF programs
        if let Ok(output) = std::process::Command::new("sh")
            .arg("-c")
            .arg("bpftool prog list 2>/dev/null || echo 'bpftool not available'")
            .output()
        {
            let bpf_progs = String::from_utf8_lossy(&output.stdout);
            if !bpf_progs.contains("not available") {
                crate::ebpf::debug::debug_println(&format!(
                    "Existing BPF programs:\n{}",
                    bpf_progs
                ));
            } else {
                crate::ebpf::debug::debug_println("bpftool not available to list programs");
            }
        }

        // Try to load with detailed error handling
        crate::ebpf::debug::debug_println(
            "Attempting more verbose eBPF loading with error details",
        );

        // Print endianness information as it might affect ELF compatibility
        if cfg!(target_endian = "little") {
            crate::ebpf::debug::debug_println("Target machine is little-endian");
        } else {
            crate::ebpf::debug::debug_println("Target machine is big-endian");
        }

        // First try to load as a file
        let load_result = if bytecode_path.exists() {
            // Try loading from disk path first (better error messages)
            crate::ebpf::debug::debug_println(&format!(
                "Trying to load from file: {}",
                bytecode_path.display()
            ));
            let load_attempt = Bpf::load_file(&bytecode_path);
            if let Err(ref e) = load_attempt {
                crate::ebpf::debug::debug_println(&format!("File load error: {}", e));
                // Check error message for verifier logs
                let err_str = format!("{:?}", e);
                if err_str.contains("verifier") {
                    crate::ebpf::debug::debug_println(&format!(
                        "Error contains verifier information: {}",
                        err_str
                    ));
                }
            }
            load_attempt
        } else {
            // Fall back to memory loading
            crate::ebpf::debug::debug_println("File not found, loading from memory");
            loader.load(SYSCALL_TRACER_BYTECODE)
        };

        let mut bpf = match load_result {
            Ok(bpf) => {
                log::info!("✓ eBPF bytecode loaded successfully");
                crate::ebpf::debug::debug_println("eBPF bytecode loaded successfully");
                bpf
            }
            Err(e) => {
                log::error!("❌ Failed to load eBPF program: {}", e);
                log::error!("BPF load error details: {:?}", e);
                crate::ebpf::debug::debug_println(&format!(
                    "Failed to load eBPF program: {} ({:?})",
                    e, e
                ));

                // For Aya errors, we need to check the specific error string
                let error_string = format!("{:?}", e);
                if error_string.contains("verifier") {
                    crate::ebpf::debug::debug_println("BPF verifier error detected in message");
                    log::error!("BPF verifier error detected in message");
                }

                // Additional error analysis
                let error_string = format!("{:?}", e);
                if error_string.contains("permission denied") {
                    log::error!("💥 Permission denied error detected. Check capabilities and/or root access");
                    crate::ebpf::debug::debug_println(
                        "Permission denied error detected. Check capabilities and/or root access",
                    );
                } else if error_string.contains("not found") {
                    log::error!("💥 Resource not found error detected. Check if tracefs/debugfs is properly mounted");
                    crate::ebpf::debug::debug_println("Resource not found error detected. Check if tracefs/debugfs is properly mounted");
                } else if error_string.contains("invalid argument") {
                    log::error!("💥 Invalid argument error detected. This might be due to kernel version incompatibility");
                    crate::ebpf::debug::debug_println("Invalid argument error detected. This might be due to kernel version incompatibility");
                } else if error_string.contains("Invalid ELF header") {
                    log::error!("💥 Invalid ELF header detected. This suggests bytecode corruption or format incompatibility");
                    crate::ebpf::debug::debug_println("Invalid ELF header detected. This suggests bytecode corruption or format incompatibility. Try rebuilding with latest clang/LLVM.");

                    // Attempt to dump ELF header details
                    if let Ok(output) = std::process::Command::new("sh")
                        .arg("-c")
                        .arg("readelf -h /tmp/syscall_tracer_dump.o | head -20")
                        .output()
                    {
                        let header_details = String::from_utf8_lossy(&output.stdout);
                        crate::ebpf::debug::debug_println(&format!(
                            "ELF header details:\n{}",
                            header_details
                        ));
                    }

                    // Try using hexdump to check the first bytes of the file
                    if let Ok(output) = std::process::Command::new("sh")
                        .arg("-c")
                        .arg("hexdump -C -n 64 /tmp/syscall_tracer_dump.o")
                        .output()
                    {
                        let hex_dump = String::from_utf8_lossy(&output.stdout);
                        crate::ebpf::debug::debug_println(&format!(
                            "ELF binary hex dump (first 64 bytes):\n{}",
                            hex_dump
                        ));
                    }

                    // Check if it's a 32-bit vs 64-bit ELF issue
                    if let Ok(output) = std::process::Command::new("sh")
                        .arg("-c")
                        .arg("file /tmp/syscall_tracer_dump.o")
                        .output()
                    {
                        let file_type = String::from_utf8_lossy(&output.stdout);
                        crate::ebpf::debug::debug_println(&format!(
                            "File type information: {}",
                            file_type
                        ));
                    }

                    // Check clang version
                    if let Ok(output) = std::process::Command::new("sh")
                        .arg("-c")
                        .arg("clang --version | head -1")
                        .output()
                    {
                        let clang_version = String::from_utf8_lossy(&output.stdout);
                        crate::ebpf::debug::debug_println(&format!(
                            "Clang version: {}",
                            clang_version
                        ));
                    }
                }

                // Check kernel BPF configuration
                if let Ok(output) = std::process::Command::new("sh")
                    .arg("-c")
                    .arg("grep CONFIG_BPF /boot/config-$(uname -r)")
                    .output()
                {
                    if let Ok(config) = String::from_utf8(output.stdout) {
                        log::error!("Kernel BPF configuration:\n{}", config);
                        crate::ebpf::debug::debug_println(&format!(
                            "Kernel BPF configuration:\n{}",
                            config
                        ));
                    }
                }

                // Check unprivileged BPF setting
                if let Ok(output) = std::process::Command::new("sh")
                    .arg("-c")
                    .arg("cat /proc/sys/kernel/unprivileged_bpf_disabled 2>/dev/null || echo 'Not available'")
                    .output()
                {
                    let unprivileged_bpf = String::from_utf8_lossy(&output.stdout);
                    log::error!("Unprivileged BPF disabled: {}", unprivileged_bpf.trim());
                    crate::ebpf::debug::debug_println(&format!("Unprivileged BPF disabled: {}", unprivileged_bpf.trim()));
                }

                // Check kernel version
                if let Ok(output) = std::process::Command::new("uname").arg("-r").output() {
                    let kernel_version = String::from_utf8_lossy(&output.stdout);
                    log::error!("Kernel version: {}", kernel_version.trim());
                    crate::ebpf::debug::debug_println(&format!(
                        "Kernel version: {}",
                        kernel_version.trim()
                    ));
                }

                return Err(crate::error::DenetError::EbpfInitError(
                    format!("Failed to load eBPF program: {}. Ensure you have CAP_BPF capability or run as root.", e)
                ));
            }
        };
        // Verify bpf maps
        log::debug!("Verifying BPF maps...");

        // List all maps in the program
        crate::ebpf::debug::debug_println("Available maps in BPF program:");
        for (name, _) in bpf.maps() {
            crate::ebpf::debug::debug_println(&format!("- Map '{}' found", name));
        }

        // Get the syscall_counts map
        crate::ebpf::debug::debug_println("Getting syscall_counts map");
        let syscall_counts_map = bpf.take_map("syscall_counts");
        crate::ebpf::debug::debug_println(&format!(
            "syscall_counts map exists: {}",
            syscall_counts_map.is_some()
        ));

        if syscall_counts_map.is_none() {
            crate::ebpf::debug::debug_println(
                "WARNING - syscall_counts map not found in BPF program!",
            );

            // Try to dump the map names using bpftool if available
            if let Ok(output) = std::process::Command::new("sh")
                .arg("-c")
                .arg("bpftool map list 2>/dev/null || echo 'bpftool not available'")
                .output()
            {
                let map_list = String::from_utf8_lossy(&output.stdout);
                if !map_list.contains("not available") {
                    crate::ebpf::debug::debug_println(&format!("System BPF maps:\n{}", map_list));
                }
            }
        }

        let syscall_counts: BpfHashMap<_, u32, u64> =
            BpfHashMap::try_from(syscall_counts_map.ok_or_else(|| {
                crate::error::DenetError::EbpfInitError(
                    "syscall_counts map not found in eBPF program".to_string(),
                )
            })?)
            .map_err(|e| {
                crate::ebpf::debug::debug_println(&format!(
                    "Failed to create syscall_counts map: {}",
                    e
                ));
                crate::error::DenetError::EbpfInitError(format!(
                    "Failed to create syscall_counts map: {}",
                    e
                ))
            })?;
        crate::ebpf::debug::debug_println("syscall_counts map created successfully");

        // Get the pid_syscall_map map
        crate::ebpf::debug::debug_println("Getting pid_syscall_map map");
        let pid_syscall_map_obj = bpf.take_map("pid_syscall_map");
        crate::ebpf::debug::debug_println(&format!(
            "pid_syscall_map exists: {}",
            pid_syscall_map_obj.is_some()
        ));

        let pid_syscall_map: BpfHashMap<_, u32, u32> =
            BpfHashMap::try_from(pid_syscall_map_obj.ok_or_else(|| {
                crate::error::DenetError::EbpfInitError(
                    "pid_syscall_map map not found in eBPF program".to_string(),
                )
            })?)
            .map_err(|e| {
                crate::ebpf::debug::debug_println(&format!(
                    "Failed to create pid_syscall_map: {}",
                    e
                ));
                crate::error::DenetError::EbpfInitError(format!(
                    "Failed to create pid_syscall_map: {}",
                    e
                ))
            })?;
        crate::ebpf::debug::debug_println("pid_syscall_map created successfully");

        // Define the syscalls we want to trace
        let tracepoints = [
            "openat", "read", "write", "close", "mmap", "socket", "connect", "recvfrom", "sendto",
        ];

        // Load and attach all tracepoint programs
        let mut attached_count = 0;
        for syscall_name in tracepoints.iter() {
            let program_name = format!("trace_{}_enter", syscall_name);
            let tracepoint_name = format!("sys_enter_{}", syscall_name);

            // Get the program if it exists
            if let Some(prog) = bpf.program_mut(&program_name) {
                match prog {
                    aya::programs::Program::TracePoint(tracepoint) => {
                        // Load the program
                        if let Err(e) = tracepoint.load() {
                            log::warn!("Failed to load {} program: {}", syscall_name, e);
                            continue;
                        }

                        // Attach the tracepoint
                        match tracepoint.attach("syscalls", &tracepoint_name) {
                            Ok(_) => {
                                attached_count += 1;
                                log::info!("✓ Attached tracepoint for {}", syscall_name);
                            }
                            Err(e) => {
                                log::warn!("Failed to attach {} tracepoint: {}", syscall_name, e);
                            }
                        }
                    }
                    _ => {
                        log::warn!("Program {} is not a tracepoint", program_name);
                    }
                }
            } else {
                log::warn!("Program {} not found", program_name);
            }
        }

        if attached_count == 0 {
            crate::ebpf::debug::debug_println("CRITICAL ERROR - Failed to attach any tracepoints!");

            // Check tracefs permissions in detail
            if let Ok(output) = std::process::Command::new("sh")
                .arg("-c")
                .arg("ls -la /sys/kernel/debug/tracing/events/syscalls/sys_enter_read 2>/dev/null || echo 'Cannot access tracefs entry'")
                .output()
            {
                let tracefs_perms = String::from_utf8_lossy(&output.stdout);
                crate::ebpf::debug::debug_println(&format!("Tracefs sys_enter_read permissions: {}", tracefs_perms.trim()));
            }

            // Check mount options for debugfs
            if let Ok(output) = std::process::Command::new("sh")
                .arg("-c")
                .arg("mount | grep debugfs")
                .output()
            {
                let mount_info = String::from_utf8_lossy(&output.stdout);
                crate::ebpf::debug::debug_println(&format!(
                    "Debugfs mount details: {}",
                    mount_info.trim()
                ));
            }

            // Check dmesg for recent tracepoint errors
            if let Ok(output) = std::process::Command::new("sh")
                .arg("-c")
                .arg("dmesg | grep -i trace | tail -5")
                .output()
            {
                let dmesg_info = String::from_utf8_lossy(&output.stdout);
                if !dmesg_info.trim().is_empty() {
                    crate::ebpf::debug::debug_println(&format!(
                        "Recent tracepoint-related kernel messages:\n{}",
                        dmesg_info
                    ));
                }
            }

            return Err(crate::error::DenetError::EbpfInitError(
                "Failed to attach any tracepoints".to_string(),
            ));
        }

        log::info!(
            "✓ Real eBPF program loaded and attached to {} syscall tracepoints!",
            attached_count
        );

        // Check if all the maps are properly initialized
        log::info!("Verifying maps...");
        let map_count = bpf.maps().count();
        log::info!("Found {} maps in BPF program", map_count);
        for (name, _) in bpf.maps() {
            log::info!("  - Map '{}' is available", name);
        }

        // Check kernel BPF settings
        if let Ok(output) = std::process::Command::new("sh")
            .arg("-c")
            .arg("sysctl -a 2>/dev/null | grep bpf")
            .output()
        {
            if let Ok(out_str) = std::str::from_utf8(&output.stdout) {
                log::info!("BPF kernel settings: {}", out_str);
            }
        }

        // Check if we have permission to access tracefs
        if let Ok(output) = std::process::Command::new("sh")
            .arg("-c")
            .arg("ls -la /sys/kernel/debug/tracing/events/syscalls/ 2>&1 || echo 'Cannot access tracefs'")
            .output()
        {
            if let Ok(out_str) = std::str::from_utf8(&output.stdout) {
                log::info!("Tracefs access check: {}", out_str);
                crate::ebpf::debug::debug_println(&format!("Tracefs access check: {}", out_str));

                // Check if we can actually write to the tracefs
                let test_output = std::process::Command::new("sh")
                    .arg("-c")
                    .arg("touch /sys/kernel/debug/tracing/events/syscalls/test_file 2>&1 || echo 'Cannot write to tracefs'")
                    .output();

                if let Ok(test_result) = test_output {
                    let test_str = String::from_utf8_lossy(&test_result.stdout);
                    let test_err = String::from_utf8_lossy(&test_result.stderr);
                    log::info!("Tracefs write test: {}{}", test_str, test_err);
                    crate::ebpf::debug::debug_println(&format!("Tracefs write test: {}{}", test_str, test_err));

                    // Clean up test file
                    let _ = std::process::Command::new("sh")
                        .arg("-c")
                        .arg("rm -f /sys/kernel/debug/tracing/events/syscalls/test_file 2>/dev/null")
                        .output();
                }
            }
        }

        // Check debugfs mount properties
        if let Ok(output) = std::process::Command::new("sh")
            .arg("-c")
            .arg("mount | grep debugfs")
            .output()
        {
            let mount_info = String::from_utf8_lossy(&output.stdout);
            log::info!("Debugfs mount info: {}", mount_info);
            crate::ebpf::debug::debug_println(&format!("Debugfs mount info: {}", mount_info));
        }

        log::info!("✓ Real eBPF program loaded and attached to syscall tracepoints!");
        Ok((bpf, pid_syscall_map, syscall_counts))
    }

    /// Update the list of PIDs to monitor
    pub fn update_pids(&mut self, pids: Vec<u32>) -> Result<()> {
        self.monitored_pids = pids;
        // In a real implementation, we would update the eBPF program's PID filter
        Ok(())
    }

    /// Get current syscall metrics
    pub fn get_metrics(&self) -> EbpfMetrics {
        #[cfg(feature = "ebpf")]
        {
            if self.bpf.is_none() {
                // Check why we might not have initialized eBPF
                let euid = unsafe { libc::geteuid() };

                // Get capabilities in a more robust way
                let cap_output = std::process::Command::new("sh")
                    .arg("-c")
                    .arg("getcap /proc/self/exe 2>&1 || echo 'getcap failed'")
                    .output()
                    .ok();

                let cap_str = cap_output
                    .and_then(|o| String::from_utf8(o.stdout).ok())
                    .unwrap_or_else(|| "unknown".to_string());

                // Check kernel eBPF settings
                let kernel_bpf = std::process::Command::new("sh")
                    .arg("-c")
                    .arg("cat /proc/sys/kernel/unprivileged_bpf_disabled 2>/dev/null || echo 'unknown'")
                    .output()
                    .ok()
                    .and_then(|o| String::from_utf8(o.stdout).ok())
                    .unwrap_or_else(|| "unknown".to_string())
                    .trim()
                    .to_string();

                // Check if we have access to tracefs
                let tracefs_access = std::process::Command::new("sh")
                    .arg("-c")
                    .arg("test -r /sys/kernel/debug/tracing/events/syscalls && echo 'yes' || echo 'no'")
                    .output()
                    .ok()
                    .and_then(|o| String::from_utf8(o.stdout).ok())
                    .unwrap_or_else(|| "unknown".to_string())
                    .trim()
                    .to_string();

                return EbpfMetrics::error(&format!(
                    "eBPF not initialized. Running as root: {}, Capabilities: {}, unprivileged_bpf_disabled: {}, tracefs access: {}. Please run with root privileges or set CAP_BPF capability.",
                    euid == 0,
                    cap_str,
                    kernel_bpf,
                    tracefs_access
                ));
            }

            match self.collect_syscall_metrics() {
                Ok(metrics) => EbpfMetrics::with_syscalls(metrics),
                Err(e) => EbpfMetrics::error(&format!("Failed to collect syscall metrics: {}", e)),
            }
        }

        #[cfg(not(feature = "ebpf"))]
        {
            EbpfMetrics::error("eBPF feature not enabled at compile time")
        }
    }

    /// Collect syscall metrics from REAL eBPF maps!
    #[cfg(feature = "ebpf")]
    fn collect_syscall_metrics(&self) -> Result<SyscallMetrics> {
        if let Some(ref syscall_map) = self.syscall_counts {
            let mut total_syscalls = 0u64;
            let mut pid_syscall_counts = HashMap::new();
            let mut syscall_counts = HashMap::new();

            log::debug!("Attempting to read syscall counts from eBPF map");
            log::debug!(
                "Monitoring {} PIDs: {:?}",
                self.monitored_pids.len(),
                self.monitored_pids
            );

            // Read syscall counts from eBPF map for our monitored PIDs
            for &pid in &self.monitored_pids {
                match syscall_map.get(&pid, 0) {
                    Ok(count) => {
                        log::debug!("PID {}: {} syscalls", pid, count);
                        if count > 0 {
                            pid_syscall_counts.insert(pid, count);
                            total_syscalls += count;
                        }
                    }
                    Err(e) => {
                        log::debug!("Failed to get syscall count for PID {}: {:?}", pid, e);
                    }
                }

                // Read per-syscall counts from pid_syscall_map
                if let Some(ref pid_syscall_map) = self._pid_syscall_map {
                    // Track syscalls for supported syscall numbers
                    for &syscall_nr in &[0, 1, 3, 9, 41, 42, 44, 45, 257] {
                        // read, write, close, mmap, socket, connect, sendto, recvfrom, openat
                        let key = (pid << 16) | (syscall_nr & 0xFFFF) as u32;
                        match pid_syscall_map.get(&key, 0) {
                            Ok(count) => {
                                if count > 0 {
                                    *syscall_counts.entry(syscall_nr).or_insert(0) += count as u64;
                                }
                            }
                            Err(e) => {
                                log::debug!(
                                    "Failed to get count for PID {} syscall {}: {:?}",
                                    pid,
                                    syscall_nr,
                                    e
                                );
                            }
                        }
                    }
                }
            }

            if total_syscalls > 0 {
                // We have real eBPF data!
                log::debug!(
                    "Collected {} syscalls from eBPF for {} PIDs",
                    total_syscalls,
                    self.monitored_pids.len()
                );

                // Group by categories based on real syscall data
                let mut by_category = HashMap::new();

                // Categorize each syscall we tracked
                for (&syscall_nr, &count) in &syscall_counts {
                    let category = categorize_syscall(syscall_nr);
                    *by_category.entry(category).or_insert(0) += count;
                }

                // Ensure we have all categories even if empty
                for category in [
                    "file_io", "memory", "process", "network", "time", "ipc", "security", "signal",
                    "system", "other",
                ] {
                    by_category.entry(category.to_string()).or_insert(0);
                }

                // Get top syscalls from real data
                let mut syscall_vec: Vec<_> = syscall_counts.into_iter().collect();
                syscall_vec.sort_by_key(|(_, count)| std::cmp::Reverse(*count));

                let top_syscalls = syscall_vec
                    .into_iter()
                    .take(10)
                    .map(|(nr, count)| SyscallCount {
                        name: syscall_name(nr),
                        count,
                    })
                    .collect();

                return Ok(SyscallMetrics {
                    total: total_syscalls,
                    by_category,
                    top_syscalls,
                    analysis: None, // Will be added later with CPU data
                });
            }
        }

        // Return error if no eBPF data available
        log::debug!("No eBPF data available");
        Err(crate::error::DenetError::EbpfInitError(
            "No eBPF data available from monitored PIDs".to_string(),
        ))
    }
}

#[cfg(feature = "ebpf")]
impl Drop for SyscallTracker {
    fn drop(&mut self) {
        // Clean up eBPF resources
        if let Some(_bpf) = self.bpf.take() {
            log::debug!("Cleaning up eBPF syscall tracker");
            crate::ebpf::debug::debug_println("Cleaning up eBPF syscall tracker resources");

            // Check if any BPF programs are still loaded in the kernel
            if let Ok(output) = std::process::Command::new("sh")
                .arg("-c")
                .arg("ls -la /proc/sys/net/core/bpf_jit_enable 2>/dev/null || echo 'BPF JIT status not available'")
                .output()
            {
                let bpf_status = String::from_utf8_lossy(&output.stdout);
                crate::ebpf::debug::debug_println(&format!("BPF JIT status check on cleanup: {}", bpf_status.trim()));
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_syscall_tracker_creation() {
        let pids = vec![1234, 5678];
        let tracker = SyscallTracker::new(pids.clone());
        assert!(tracker.is_ok());

        let tracker = tracker.unwrap();
        assert_eq!(tracker.monitored_pids, pids);
    }

    #[test]
    fn test_syscall_metrics_structure() {
        let pids = vec![std::process::id()];
        let tracker = SyscallTracker::new(pids).unwrap();

        let metrics = tracker.get_metrics();

        // Should either have syscalls or an error, but not both
        assert!(metrics.syscalls.is_some() || metrics.error.is_some());
        assert!(!(metrics.syscalls.is_some() && metrics.error.is_some()));
    }

    #[test]
    fn test_pid_update() {
        let initial_pids = vec![1234];
        let mut tracker = SyscallTracker::new(initial_pids).unwrap();

        let new_pids = vec![5678, 9012];
        assert!(tracker.update_pids(new_pids.clone()).is_ok());
        assert_eq!(tracker.monitored_pids, new_pids);
    }
}
