# CPU Measurement in Denet

## Problem and Solution

### The Problem with sysinfo

The original implementation of denet used the `sysinfo` crate for CPU measurement, which was found to significantly underreport CPU usage:

- For an 8-core CPU burn test, system tools like `psrecord` reported ~800% CPU usage
- denet with sysinfo only reported ~280% maximum CPU usage
- Individual processes showed only 30-50% CPU instead of ~100% when fully utilizing a core

The issue was not with timing or configuration, but rather with how sysinfo fundamentally calculates CPU percentages, which differs from standard tools like `top`, `htop`, and `psutil`.

### The Solution: Direct procfs Reading

To solve this problem, we've implemented a new CPU measurement system that reads directly from the procfs filesystem on Linux. This approach:

1. Matches the calculation method used by standard system tools
2. Provides accurate per-core CPU percentages (0-100% per core)
3. Correctly reports aggregate CPU usage for multi-threaded processes

## Implementation Details

### Architecture

The CPU measurement system consists of:

1. **CpuSampler module**: A standalone component that handles CPU usage calculation
2. **ProcessMonitor integration**: Uses the sampler on Linux, with fallback to sysinfo on other platforms
3. **Cross-platform design**: Structure allows for future implementations on other operating systems

### How It Works

The CPU measurement follows these steps:

1. **First measurement**: Establish a baseline by reading CPU times
2. **Subsequent measurements**: Calculate the delta between readings
3. **Percentage calculation**: `CPU % = (delta_cpu_time / delta_real_time) * 100`

The calculation uses jiffies (clock ticks) from the `/proc/[pid]/stat` file, specifically:
- `utime`: User mode CPU time
- `stime`: System mode CPU time

### Benefits

1. **Accuracy**: Measurements now match what `top` and `htop` report
2. **Efficiency**: No artificial delays between measurements needed
3. **Responsiveness**: Faster sampling without waiting for refresh cycles
4. **Predictability**: Transparent calculation method instead of a black box
5. **Lower overhead**: No need for system-wide CPU refresh operations

## Cross-platform Strategy

While the current implementation is Linux-specific, we have a roadmap for supporting other platforms:

### Linux (Current)
- Uses `procfs` crate to read `/proc/[pid]/stat`
- Gets CPU jiffies and calculates percentage based on time delta
- Matches the calculation method used by tools like `top` and `htop`

### macOS (Planned)
- Will use `host_processor_info()` from libproc
- Will use `proc_pidinfo()` to get `task_info`
- Calculation will be based on CPU ticks delta / time delta
- Will match the calculation method used by Activity Monitor

### Windows (Planned)
- Will use `GetProcessTimes()` for process CPU times
- Will use `GetSystemTimes()` for system-wide times
- Performance Counters API as fallback
- Will match the calculation method used by Task Manager

## Usage

The CPU sampler is used automatically by the ProcessMonitor on Linux systems. No changes to your code are needed to benefit from the improved measurements.

## Testing

The implementation has been verified with several test strategies:

1. **Unit tests**: Test the sampler directly with CPU-intensive processes
2. **Integration tests**: Multi-core stress tests to verify aggregate CPU reporting
3. **Comparison tests**: Scripts to compare measurements with system tools

## Examples

Here's an example of the improved CPU measurement in action:

```rust
// CPU measurement happens automatically when you use ProcessMonitor
let mut monitor = ProcessMonitor::from_pid(pid, interval, max_interval)?;
let metrics = monitor.sample_metrics().unwrap();
println!("CPU Usage: {}%", metrics.cpu_usage);
```

For multi-threaded processes using multiple cores, the reported CPU usage can exceed 100%:

```
CPU Usage: 376.2%  // A process using ~3.8 cores fully
```

## Technical Implementation Notes

### Key Improvements

1. **No artificial delays**: Removed unnecessary sleep operations
2. **Direct source access**: Reading CPU times directly instead of relying on abstractions
3. **Proper time delta calculation**: Ensuring accurate measurement of CPU time changes
4. **Clean stale process tracking**: Automatic cleanup of terminated processes

### Recommendations

- For accurate CPU measurements over time, it's recommended to sample at regular intervals
- First measurement establishes a baseline and returns no CPU usage value
- Process tree measurements automatically track and cleanup child processes