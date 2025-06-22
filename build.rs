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
        println!("cargo:warning=Building with eBPF support - checking for clang...");

        // Check if clang is available
        if !check_clang_available() {
            panic!(
                "\n\n🚫 ERROR: clang is required to build eBPF programs!\n\n\
                Please install clang:\n\
                - Ubuntu/Debian: sudo apt install clang llvm libbpf-dev\n\
                - CentOS/RHEL: sudo yum install clang llvm-devel libbpf-devel\n\
                - macOS: brew install llvm\n\n\
                Or build without eBPF: cargo build (without --features ebpf)\n"
            );
        }

        println!("cargo:warning=✓ clang found - compiling eBPF programs...");

        // Compile eBPF programs
        compile_ebpf_programs();

        println!("cargo:warning=✓ eBPF programs compiled successfully");
    } else {
        println!("cargo:warning=Building without eBPF support (no --features ebpf)");
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

/// Compile eBPF C programs to bytecode
fn compile_ebpf_programs() {
    let out_dir = env::var("OUT_DIR").unwrap();
    let ebpf_src_dir = "src/ebpf/programs";

    // Create eBPF programs directory in OUT_DIR
    let ebpf_out_dir = PathBuf::from(&out_dir).join("ebpf");
    std::fs::create_dir_all(&ebpf_out_dir).unwrap();

    // List of eBPF programs to compile with clang
    let c_ebpf_programs = vec!["syscall_tracer.c", "offcpu_profiler.c"];

    // Process C-based programs
    for program in c_ebpf_programs {
        let src_path = PathBuf::from(ebpf_src_dir).join(program);
        let obj_name = program.replace(".c", ".o");

        // Create parent directory for output if needed (for subdirectories)
        if let Some(parent) = PathBuf::from(&obj_name).parent() {
            let dir_path = ebpf_out_dir.join(parent);
            std::fs::create_dir_all(&dir_path).unwrap();
        }

        let obj_path = ebpf_out_dir.join(&obj_name);

        println!("cargo:rerun-if-changed={}", src_path.display());

        // Compile eBPF C program to bytecode
        let compilation = Command::new("clang")
            .arg("-target")
            .arg("bpf")
            .arg("-O2")
            .arg("-g")
            .arg("-c")
            .arg(&src_path)
            .arg("-o")
            .arg(&obj_path)
            .arg("-I/usr/include")
            .arg("-I/usr/include/x86_64-linux-gnu")
            .arg("-D__TARGET_ARCH_x86")
            .arg("-Wno-unused-value")
            .arg("-Wno-pointer-sign")
            .arg("-Wno-compare-distinct-pointer-types")
            .arg("-Wunused")
            .arg("-Wall")
            .arg("-Werror")
            .output();

        match compilation {
            Ok(output) => {
                if !output.status.success() {
                    let stderr = String::from_utf8_lossy(&output.stderr);
                    panic!("Failed to compile {program}: {stderr}");
                }
                println!("cargo:warning=✓ Compiled {program} -> {obj_name}");
            }
            Err(e) => {
                panic!("Failed to run clang for {program}: {e}");
            }
        }

        // Tell Rust where to find the compiled object file
        println!(
            "cargo:rustc-env=EBPF_{}_PATH={}",
            obj_name.replace(".o", "").replace("/", "_").to_uppercase(),
            obj_path.display()
        );
    }
}
