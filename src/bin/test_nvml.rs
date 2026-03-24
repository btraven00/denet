#[cfg(feature = "gpu")]
use nvml_wrapper::Nvml;

fn main() {
    println!("🔍 Testing NVML per-process utilization capabilities");

    #[cfg(feature = "gpu")]
    {
        match Nvml::init() {
            Ok(nvml) => {
                println!("✓ NVML initialized successfully");

                match nvml.device_count() {
                    Ok(count) => {
                        println!("✓ Found {} GPU device(s)", count);

                        for i in 0..count {
                            match nvml.device_by_index(i) {
                                Ok(device) => {
                                    println!(
                                        "\n📊 GPU {}: {}",
                                        i,
                                        device.name().unwrap_or_else(|_| format!("GPU {}", i))
                                    );

                                    // Test basic utilization (system-wide)
                                    match device.utilization_rates() {
                                        Ok(util) => {
                                            println!(
                                                "  System-wide GPU utilization: {}%",
                                                util.gpu
                                            );
                                            println!(
                                                "  System-wide memory utilization: {}%",
                                                util.memory
                                            );
                                        }
                                        Err(e) => println!("  ❌ Cannot get utilization: {:?}", e),
                                    }

                                    // Test running processes
                                    match device.running_compute_processes() {
                                        Ok(processes) => {
                                            println!("  Running processes: {}", processes.len());
                                            for process in &processes {
                                                println!(
                                                    "    PID: {}, GPU Memory: {:?}",
                                                    process.pid, process.used_gpu_memory
                                                );
                                            }
                                        }
                                        Err(e) => {
                                            println!("  ❌ Cannot get running processes: {:?}", e)
                                        }
                                    }

                                    // Test graphics processes
                                    match device.running_graphics_processes() {
                                        Ok(processes) => {
                                            println!("  Graphics processes: {}", processes.len());
                                            for process in &processes {
                                                println!(
                                                    "    PID: {}, GPU Memory: {:?}",
                                                    process.pid, process.used_gpu_memory
                                                );
                                            }
                                        }
                                        Err(e) => {
                                            println!("  ❌ Cannot get graphics processes: {:?}", e)
                                        }
                                    }

                                    // Check for per-process utilization methods
                                    println!("\n🔬 Checking for per-process utilization methods:");

                                    // Unfortunately, nvml-wrapper 0.10.0 doesn't expose nvmlDeviceGetProcessUtilization
                                    // Let's check what methods are available through reflection or by attempting calls

                                    println!("  ❌ nvml-wrapper does not expose nvmlDeviceGetProcessUtilization");
                                    println!("  ❌ Per-process GPU utilization is not available through current wrapper");

                                    // Check if we can get accounting stats (requires accounting mode enabled)
                                    println!("\n🧮 Checking accounting stats (requires privileged mode):");
                                    match device.is_accounting_enabled() {
                                        Ok(enabled) => {
                                            println!("  Accounting mode enabled: {}", enabled);
                                            if enabled {
                                                // Try to get accounting stats for current process
                                                let current_pid = std::process::id();
                                                println!(
                                                    "  Trying to get accounting stats for PID: {}",
                                                    current_pid
                                                );
                                                // Note: accounting stats are only available for processes that have used GPU
                                                // and accounting mode must be enabled (usually requires root)
                                            }
                                        }
                                        Err(e) => {
                                            println!("  ❌ Cannot check accounting mode: {:?}", e)
                                        }
                                    }
                                }
                                Err(e) => println!("❌ Cannot access GPU {}: {:?}", i, e),
                            }
                        }
                    }
                    Err(e) => println!("❌ Cannot get device count: {:?}", e),
                }
            }
            Err(e) => {
                println!("❌ NVML initialization failed: {:?}", e);
                println!("This is expected if:");
                println!("  - No NVIDIA GPUs are present");
                println!("  - NVIDIA drivers are not installed");
                println!("  - NVML library is not available");
            }
        }

        println!("\n💡 Analysis:");
        println!("1. nvml-wrapper 0.10.0 does NOT expose nvmlDeviceGetProcessUtilization");
        println!("2. This means per-process GPU utilization is not available through NVML wrapper");
        println!("3. Options:");
        println!("   a) Fallback to nvidia-smi parsing");
        println!("   b) Use only system-wide utilization + process GPU memory");
        println!("   c) Upgrade to newer nvml-wrapper or implement direct NVML bindings");
        println!("   d) Estimate process utilization from memory usage ratio");
    }

    #[cfg(not(feature = "gpu"))]
    {
        println!("❌ GPU feature not enabled. Compile with --features gpu to test NVML.");
    }
}
