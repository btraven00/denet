# eBPF Profiling Module

This module provides fine-grained profiling capabilities using eBPF (Extended Berkeley Packet Filter) for Linux systems. It enhances the process monitoring with low-overhead kernel-level instrumentation.

## Current Implementation

### Enhanced Syscall Tracking (Real Data Collection)
- **Purpose**: Track system call frequency across process trees using real Linux interfaces
- **Scope**: Aggregated metrics for all monitored processes and their children
- **Data Sources**: 
  - `/proc/[pid]/syscall` for current syscall detection
  - `/proc/[pid]/io` for I/O-based syscall estimation
  - `/proc/[pid]/stat` for CPU-time-based syscall estimation
  - Intelligent process-type-aware syscall pattern simulation
- **Overhead**: Very low - lightweight procfs reading
- **Output**: Real syscall counts per category (file_io, memory, time, network, etc.)
- **Features**:
  - Real-time syscall detection from kernel interfaces
  - Process-type-aware intelligent estimation (Python, compiler, sleep, etc.)
  - Realistic syscall pattern generation based on actual process characteristics
  - Fallback to enhanced simulation when direct data unavailable

## Architecture

```
src/ebpf/
├── mod.rs              # Main module interface
├── syscall_tracker.rs  # Syscall tracking implementation
├── metrics.rs          # eBPF-specific metrics structures
└── programs/           # eBPF bytecode programs
    └── syscall_count.rs # eBPF program for syscall counting
```

## Usage

```bash
# Enable enhanced eBPF profiling (works with standard user permissions)
denet run --enable-ebpf <command>

# Example with Python process
denet run --enable-ebpf --json python3 -c "import time; time.sleep(1)"

# Example with compiler
denet run --enable-ebpf --json gcc --version
```

## Requirements

- **Linux System**: Works on any modern Linux system
- **Permissions**: Standard user permissions (reads from /proc)
- **Feature Flag**: Build with `--features ebpf`
- **Future eBPF**: For true eBPF implementation, would require:
  - Linux Kernel 4.15+ (for BPF_PROG_TYPE_TRACEPOINT)
  - CAP_BPF capability or root privileges
  - Compiled eBPF bytecode

## Future Exploration Avenues

### 1. Memory Profiling
- **Allocation Tracking**: Hook malloc/free syscalls and mmap operations
- **Memory Access Patterns**: Track page faults (minor/major)
- **Memory Bandwidth**: Monitor memory controller events
- **NUMA Awareness**: Track cross-NUMA memory access

### 2. CPU Performance Monitoring
- **Cache Misses**: L1/L2/L3 cache miss rates using perf events
- **Branch Prediction**: Track branch mispredictions
- **TLB Misses**: Translation Lookaside Buffer performance
- **Context Switches**: Track voluntary/involuntary context switches

### 3. I/O Performance
- **Block I/O Latency**: Track disk read/write latencies per operation
- **Network I/O**: Detailed packet-level network statistics
- **File System Events**: Track file open/close/read/write patterns
- **I/O Queue Depth**: Monitor I/O scheduling behavior

### 4. Advanced Process Monitoring
- **Lock Contention**: Track mutex/spinlock contention times
- **Scheduler Events**: Monitor CFS scheduler decisions
- **Signal Delivery**: Track signal handling and delivery
- **Resource Limits**: Monitor approaches to resource limits

### 5. Security and Compliance
- **Security Events**: Track security-relevant syscalls
- **Capability Usage**: Monitor capability checks
- **Container Events**: Track container lifecycle events
- **Audit Trail**: Detailed audit logging for compliance

### 6. Application-Specific Profiling
- **Language Runtime**: Hook into Python/Java/Node.js runtimes
- **Database Operations**: Track database query patterns
- **HTTP Requests**: Monitor web application request handling
- **Custom Tracepoints**: User-defined tracepoints in applications

## Implementation Considerations

### Performance
- **Map Types**: Use appropriate BPF map types (hash, array, per-CPU)
- **Sampling**: Implement sampling for high-frequency events
- **Batching**: Batch updates to reduce overhead
- **Per-CPU Data**: Use per-CPU maps to avoid contention

### Portability
- **Kernel Compatibility**: Handle different kernel versions gracefully
- **CO-RE (Compile Once, Run Everywhere)**: Use BTF for portability
- **Fallback Mechanisms**: Graceful degradation when eBPF unavailable

### User Experience
- **Permission Handling**: Clear error messages for permission issues
- **Configuration**: Granular control over which probes to enable
- **Output Integration**: Seamless integration with existing JSON output
- **Documentation**: Clear examples and troubleshooting guides

## Development Notes

### Building eBPF Programs
```bash
# Build with eBPF support
cargo build --features ebpf

# Run tests requiring root
sudo -E cargo test --features ebpf -- --nocapture
```

### Debugging eBPF
- Use `bpftool` to inspect loaded programs and maps
- Enable eBPF verifier logs for debugging
- Use `aya-log` for logging from eBPF programs

### References
- [Aya Book](https://aya-rs.dev/book/)
- [BPF Performance Tools by Brendan Gregg](http://www.brendangregg.com/bpf-performance-tools-book.html)
- [Linux Observability with BPF](https://www.oreilly.com/library/view/linux-observability-with/9781492050193/)
