//! Build script for denet
//!
//! When the 'ebpf' feature is enabled, this script:
//! 1. Checks for clang availability
//! 2. Compiles eBPF C programs to bytecode
//! 3. Makes bytecode available for embedding in the binary

use std::env;
use std::path::PathBuf;
use std::process::Command;

fn main() {
    println!("cargo:rerun-if-changed=build.rs");

    // Only compile eBPF when the feature is enabled
    if env::var("CARGO_FEATURE_EBPF").is_ok() {
        // Check if clang is available
        if !check_clang_available() {
            panic!(
                "\n\nERROR: clang is required to build eBPF programs!\n\n\
                Please install clang:\n\
                - Ubuntu/Debian: sudo apt install clang llvm libbpf-dev\n\
                - CentOS/RHEL: sudo yum install clang llvm-devel libbpf-devel\n\
                - macOS: brew install llvm\n\n\
                Or build without eBPF: cargo build (without --features ebpf)\n"
            );
        }

        // Compile eBPF programs
        compile_ebpf_programs();
    }
}

/// Check if clang is available and supports BPF target
fn check_clang_available() -> bool {
    // Check if clang command exists
    let clang_check = Command::new("clang").arg("--version").output();

    if clang_check.is_err() {
        return false;
    }

    // Check if clang supports BPF target
    let bpf_target_check = Command::new("clang")
        .arg("-target")
        .arg("bpf")
        .arg("--print-supported-cpus")
        .output();

    bpf_target_check.is_ok()
}

/// Debian/Ubuntu multiarch include dir for the given target arch, if one
/// exists for that arch. Returns None for arches where we don't know the
/// convention (caller treats as "no multiarch path").
fn debian_multiarch_include(cargo_arch: &str) -> Option<String> {
    let triple = match cargo_arch {
        "x86_64" => "x86_64-linux-gnu",
        "aarch64" => "aarch64-linux-gnu",
        "arm" => "arm-linux-gnueabihf",
        "powerpc64" => "powerpc64le-linux-gnu",
        "riscv64" => "riscv64-linux-gnu",
        "s390x" => "s390x-linux-gnu",
        _ => return None,
    };
    Some(format!("/usr/include/{triple}"))
}

/// Map Rust target arch (CARGO_CFG_TARGET_ARCH) to the `__TARGET_ARCH_*`
/// define that libbpf's `bpf_tracing.h` expects for PT_REGS macros.
fn target_arch_define(cargo_arch: &str) -> &'static str {
    match cargo_arch {
        "x86_64" => "__TARGET_ARCH_x86",
        "aarch64" => "__TARGET_ARCH_arm64",
        "arm" => "__TARGET_ARCH_arm",
        "powerpc64" => "__TARGET_ARCH_powerpc",
        "riscv64" => "__TARGET_ARCH_riscv",
        "s390x" => "__TARGET_ARCH_s390",
        other => panic!(
            "Unsupported target arch for eBPF: {other}. Add a mapping in build.rs."
        ),
    }
}

/// Compile eBPF C programs to bytecode
fn compile_ebpf_programs() {
    let out_dir = env::var("OUT_DIR").unwrap();
    let manifest_dir = env::var("CARGO_MANIFEST_DIR").unwrap();
    let ebpf_src_dir = "src/ebpf/programs";

    // Create eBPF programs directory in OUT_DIR
    let ebpf_out_dir = PathBuf::from(&out_dir).join("ebpf");
    std::fs::create_dir_all(&ebpf_out_dir).unwrap();

    // Vendored libbpf headers live at src/ebpf/include/bpf/.
    // Adding the parent dir (src/ebpf/include) to the include path lets
    // the programs keep their `#include <bpf/bpf_helpers.h>` spelling.
    let vendored_include = PathBuf::from(&manifest_dir).join("src/ebpf/include");

    let target_arch = env::var("CARGO_CFG_TARGET_ARCH")
        .expect("CARGO_CFG_TARGET_ARCH must be set by cargo");
    let arch_define = format!("-D{}", target_arch_define(&target_arch));

    // On Debian/Ubuntu multiarch layouts, <asm/types.h> lives under
    // /usr/include/<debian-triple>/. On RHEL/Arch/Alpine it's flat at
    // /usr/include/. Probe both and add whichever exists.
    let multiarch_include = debian_multiarch_include(&target_arch);
    let multiarch_exists = multiarch_include
        .as_ref()
        .map(|p| std::path::Path::new(p).exists())
        .unwrap_or(false);

    // List of eBPF programs to compile
    let ebpf_programs = vec!["syscall_tracer.c", "simple_test.c", "offcpu_profiler.c"];

    for program in ebpf_programs {
        let src_path = PathBuf::from(ebpf_src_dir).join(program);
        let obj_name = program.replace(".c", ".o");
        let obj_path = ebpf_out_dir.join(&obj_name);

        println!("cargo:rerun-if-changed={}", src_path.display());

        // Only compile if source file exists
        if !src_path.exists() {
            println!("cargo:warning=eBPF source not found, creating placeholder for {program}");
            create_placeholder_ebpf_program(&src_path);
        }

        // Compile eBPF C program to bytecode
        //
        // -I<vendored>: picks up bpf/bpf_helpers.h and bpf/bpf_tracing.h
        //   from the vendored copy in src/ebpf/include, so libbpf-dev is
        //   not required on the build host.
        // -I/usr/include: picks up linux/bpf.h, linux/ptrace.h, linux/types.h
        //   from linux-libc-dev (part of the standard C dev environment on
        //   every mainstream distro).
        let mut cmd = Command::new("clang");
        cmd.arg("-target")
            .arg("bpf")
            .arg("-O2")
            .arg("-g")
            .arg("-c")
            .arg(&src_path)
            .arg("-o")
            .arg(&obj_path)
            .arg(format!("-I{}", vendored_include.display()))
            .arg("-I/usr/include");
        if multiarch_exists {
            cmd.arg(format!("-I{}", multiarch_include.as_ref().unwrap()));
        }
        cmd.arg(&arch_define)
            .arg("-Wno-unused-value")
            .arg("-Wno-pointer-sign")
            .arg("-Wno-compare-distinct-pointer-types")
            .arg("-Wunused")
            .arg("-Wall")
            .arg("-Werror");
        let compilation = cmd.output();

        match compilation {
            Ok(output) => {
                if !output.status.success() {
                    let stderr = String::from_utf8_lossy(&output.stderr);
                    panic!("Failed to compile {program}: {stderr}");
                }
                println!("cargo:rerun-if-changed={}", obj_path.display());
            }
            Err(e) => {
                panic!("Failed to run clang for {program}: {e}");
            }
        }

        // Tell Rust where to find the compiled object file
        println!(
            "cargo:rustc-env=EBPF_{}_PATH={}",
            obj_name.replace(".o", "").to_uppercase(),
            obj_path.display()
        );
    }
}

/// Create a placeholder eBPF program if it doesn't exist
fn create_placeholder_ebpf_program(path: &PathBuf) {
    let program_name = path.file_stem().unwrap().to_str().unwrap();

    let placeholder_content = match program_name {
        "simple_test" => {
            r#"//! Simple eBPF program for testing tracepoints
//! This is a minimal program that should be easy to load

#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

// Simple array map for testing
struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __type(key, __u32);
    __type(value, __u64);
    __uint(max_entries, 10);
} test_map SEC(".maps");

// Simple tracepoint for openat syscall
SEC("tracepoint/syscalls/sys_enter_openat")
int trace_openat_enter(void *ctx) {
    __u32 key = 0;
    __u64 *value = bpf_map_lookup_elem(&test_map, &key);
    if (value) {
        (*value)++;
    }
    return 0;
}

char LICENSE[] SEC("license") = "GPL";
"#
        }
        "syscall_tracer" => {
            r#"//! Syscall tracing eBPF program
//! This program attaches to syscall tracepoints and counts syscall frequency

#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

// BPF map to store syscall counts per PID
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __type(key, __u32);   // PID
    __type(value, __u64); // syscall count
    __uint(max_entries, 10240);
} syscall_counts SEC(".maps");

// Tracepoint for syscall entry
SEC("tracepoint/syscalls/sys_enter_openat")
int trace_openat_enter(void *ctx) {
    __u32 pid = bpf_get_current_pid_tgid() >> 32;

    // Get current count for this PID
    __u64 *count = bpf_map_lookup_elem(&syscall_counts, &pid);
    if (count) {
        __sync_fetch_and_add(count, 1);
    } else {
        __u64 initial_count = 1;
        bpf_map_update_elem(&syscall_counts, &pid, &initial_count, BPF_ANY);
    }

    return 0;
}

// Additional tracepoints for common syscalls
SEC("tracepoint/syscalls/sys_enter_read")
int trace_read_enter(void *ctx) {
    __u32 pid = bpf_get_current_pid_tgid() >> 32;

    __u64 *count = bpf_map_lookup_elem(&syscall_counts, &pid);
    if (count) {
        __sync_fetch_and_add(count, 1);
    } else {
        __u64 initial_count = 1;
        bpf_map_update_elem(&syscall_counts, &pid, &initial_count, BPF_ANY);
    }

    return 0;
}

SEC("tracepoint/syscalls/sys_enter_write")
int trace_write_enter(void *ctx) {
    __u32 pid = bpf_get_current_pid_tgid() >> 32;

    __u64 *count = bpf_map_lookup_elem(&syscall_counts, &pid);
    if (count) {
        __sync_fetch_and_add(count, 1);
    } else {
        __u64 initial_count = 1;
        bpf_map_update_elem(&syscall_counts, &pid, &initial_count, BPF_ANY);
    }

    return 0;
}

char LICENSE[] SEC("license") = "GPL";
"#
        }
        _ => "// Placeholder eBPF program\n",
    };

    // Create directory if it doesn't exist
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent).unwrap();
    }

    std::fs::write(path, placeholder_content).unwrap();
}
