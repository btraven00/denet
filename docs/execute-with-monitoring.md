# Execute with Monitoring

The `execute_with_monitoring` function provides a way to execute commands with zero-miss process monitoring from the very start of execution. This feature uses Unix signals to pause the process during monitor attachment.

## Overview

Traditional process monitoring has a race condition: there's a window between when a process starts and when monitoring begins, during which important early activity can be missed. The `execute_with_monitoring` function solves this by:

1. **Creating the process** with `subprocess.Popen`
2. **Immediately pausing it** with `SIGSTOP` signal
3. **Attaching monitoring** while the process is frozen
4. **Resuming the process** with `SIGCONT` signal
5. **Running monitoring concurrently** with process execution

This ensures that every CPU cycle, memory allocation, and I/O operation is captured from the moment the process begins execution.

## Usage

### Basic Usage

```python
from denet import execute_with_monitoring

# Execute a command with monitoring
exit_code, monitor = execute_with_monitoring(['python', 'my_script.py'])

# Get collected samples
samples = monitor.get_samples()
print(f"Process exited with code {exit_code}")
print(f"Collected {len(samples)} monitoring samples")
```

### Advanced Usage

```python
# Execute with custom monitoring parameters
exit_code, monitor = execute_with_monitoring(
    cmd=['python', 'compute_intensive.py'],
    timeout=300,                    # 5 minute timeout
    base_interval_ms=50,           # Sample every 50ms
    max_interval_ms=500,           # Max interval 500ms
    output_file='monitoring.jsonl', # Save to file
    store_in_memory=True,          # Also keep in memory
    pause_for_attachment=True,     # Use signal-based pausing
    stdout_file='output.log',      # Redirect stdout
    stderr_file='errors.log',      # Redirect stderr
)

# Analyze the results
summary = monitor.get_summary()
print(f"Peak memory usage: {summary['peak_memory_mb']:.1f} MB")
print(f"Average CPU usage: {summary['avg_cpu_percent']:.1f}%")
```

## Parameters

### Required Parameters

- **`cmd`**: Command to execute
  - Type: `Union[str, List[str]]`
  - Example: `['python', 'script.py']` or `"python script.py"`

### Optional Parameters

#### Process Control
- **`timeout`**: Maximum execution time in seconds
  - Type: `Optional[float]`
  - Default: `None` (no timeout)
  - Raises `subprocess.TimeoutExpired` if exceeded

- **`pause_for_attachment`**: Whether to use signal-based pausing
  - Type: `bool`
  - Default: `True`
  - Set to `False` to disable signal pausing (minimal race condition remains)

#### I/O Redirection
- **`stdout_file`**: File path for stdout redirection
  - Type: `Optional[str]`
  - Default: `None` (captured by subprocess)

- **`stderr_file`**: File path for stderr redirection
  - Type: `Optional[str]`
  - Default: `None` (captured by subprocess)

#### Monitoring Configuration
- **`base_interval_ms`**: Starting sampling interval in milliseconds
  - Type: `int`
  - Default: `100`
  - Lower values = higher resolution monitoring

- **`max_interval_ms`**: Maximum sampling interval in milliseconds
  - Type: `int`
  - Default: `1000`
  - Used by adaptive sampling algorithm

- **`since_process_start`**: Whether to measure from process start vs monitor start
  - Type: `bool`
  - Default: `False`

#### Output Options
- **`store_in_memory`**: Whether to keep samples in memory
  - Type: `bool`
  - Default: `True`
  - Disable for very long-running processes to save memory

- **`output_file`**: File path to write samples directly
  - Type: `Optional[str]`
  - Default: `None`
  - Samples written in real-time during execution

- **`output_format`**: Format for file output
  - Type: `str`
  - Default: `"jsonl"`
  - Options: `"jsonl"`, `"json"`, `"csv"`

- **`quiet`**: Whether to suppress output
  - Type: `bool`
  - Default: `False`

## Return Value

Returns a tuple of `(exit_code, monitor)`:

- **`exit_code`**: Process exit code (integer)
- **`monitor`**: ProcessMonitor instance with collected data

## Signal-Based Process Control

### How It Works

The signal-based approach uses standard Unix signals:

1. **SIGSTOP**: Immediately freezes the process (cannot be caught or ignored)
2. **SIGCONT**: Resumes the frozen process
3. **Process Group Isolation**: Uses `start_new_session=True` for clean process management

### Timing Characteristics

Based on performance testing:

- **Process creation**: ~2-3ms
- **Signal pause**: ~0.1ms
- **Monitor attachment**: ~125ms (after optimization)
- **Signal resume**: ~0.1ms
- **Total pause duration**: ~125ms

This pause is negligible for most workloads, especially long-running bioinformatics processes.

### Compatibility

The signal-based approach works well with:
- ✅ **Batch processing tools** (common in bioinformatics)
- ✅ **CPU/memory intensive applications**
- ✅ **Long-running computations**
- ✅ **Scientific computing workflows**

May not be suitable for:
- ❌ **Real-time applications** (brief pause may be problematic)
- ❌ **Processes with custom signal handlers**
- ❌ **Interactive applications** expecting immediate startup

## Examples

### Bioinformatics Workflow

```python
from denet import execute_with_monitoring
import json

# Monitor a sequence alignment
exit_code, monitor = execute_with_monitoring(
    cmd=['blastn', '-query', 'sequences.fasta', '-db', 'nt', '-out', 'results.txt'],
    timeout=3600,  # 1 hour timeout
    base_interval_ms=100,
    output_file='blast_monitoring.jsonl',
    store_in_memory=True
)

if exit_code == 0:
    # Analyze resource usage
    samples = monitor.get_samples()

    # Parse monitoring data
    parsed_samples = []
    for sample in samples:
        if isinstance(sample, str):
            parsed_samples.append(json.loads(sample))

    # Calculate statistics
    cpu_values = [s['cpu_usage'] for s in parsed_samples]
    memory_values = [s['mem_rss_kb'] for s in parsed_samples]

    print(f"BLAST job completed successfully")
    print(f"Peak CPU usage: {max(cpu_values):.1f}%")
    print(f"Peak memory usage: {max(memory_values)/1024:.1f} MB")
    print(f"Average CPU usage: {sum(cpu_values)/len(cpu_values):.1f}%")
else:
    print(f"BLAST job failed with exit code {exit_code}")
```

### Python Script Monitoring

```python
# Monitor a Python data processing script
exit_code, monitor = execute_with_monitoring(
    cmd=['python', 'process_data.py', '--input', 'large_dataset.csv'],
    base_interval_ms=50,  # High resolution monitoring
    pause_for_attachment=True,
    stdout_file='processing.log',
    stderr_file='processing.err'
)

# Generate monitoring report
summary = monitor.get_summary()
print(f"Data processing completed in {summary['elapsed_time']:.1f}s")
print(f"Peak memory: {summary['peak_memory_mb']:.1f} MB")
```

## Error Handling

### Common Exceptions

- **`subprocess.TimeoutExpired`**: Process exceeded timeout
- **`OSError`**: Process creation or signaling failed
- **`RuntimeError`**: Monitor attachment failed
- **`FileNotFoundError`**: Command not found

### Error Handling Example

```python
try:
    exit_code, monitor = execute_with_monitoring(
        cmd=['nonexistent_command'],
        timeout=10
    )
except FileNotFoundError:
    print("Command not found")
except subprocess.TimeoutExpired:
    print("Process timed out")
except RuntimeError as e:
    print(f"Monitoring failed: {e}")
except Exception as e:
    print(f"Unexpected error: {e}")
```

## Performance Considerations

### Memory Usage

For long-running processes, consider:
- Set `store_in_memory=False` to avoid memory accumulation
- Use `output_file` to stream samples to disk
- Increase `base_interval_ms` to reduce sample frequency

### CPU Overhead

Monitoring overhead is minimal:
- ~0.1% CPU overhead for typical sampling intervals
- Scales with sampling frequency
- Negligible impact on most workloads

### Disk I/O

When using `output_file`:
- Samples written in real-time
- Minimal impact on process performance
- JSONL format is efficient for streaming

## Best Practices

### 1. Choose Appropriate Sampling Intervals

```python
# For long-running processes (hours)
base_interval_ms=1000  # Sample every second

# For medium processes (minutes)
base_interval_ms=100   # Sample every 100ms

# For short, intensive processes (seconds)
base_interval_ms=25    # Sample every 25ms
```

### 2. Handle Output Files Properly

```python
import tempfile
import os

# Use temporary files for monitoring data
with tempfile.NamedTemporaryFile(suffix='.jsonl', delete=False) as f:
    monitor_file = f.name

try:
    exit_code, monitor = execute_with_monitoring(
        cmd=['my_command'],
        output_file=monitor_file
    )

    # Process monitoring data
    # ...

finally:
    # Clean up
    if os.path.exists(monitor_file):
        os.unlink(monitor_file)
```

### 3. Validate Process Success

```python
exit_code, monitor = execute_with_monitoring(['my_command'])

if exit_code != 0:
    print(f"Process failed with exit code {exit_code}")
    # Handle failure case
else:
    # Process monitoring data
    samples = monitor.get_samples()
    # ...
```

## Integration with Existing Code

### Replacing subprocess.run()

```python
# Before
import subprocess
result = subprocess.run(['python', 'script.py'], capture_output=True)

# After
from denet import execute_with_monitoring
exit_code, monitor = execute_with_monitoring(['python', 'script.py'])
samples = monitor.get_samples()
```

### Adding to Existing Workflows

```python
def run_analysis_step(command, step_name):
    """Run an analysis step with monitoring"""
    print(f"Starting {step_name}...")

    exit_code, monitor = execute_with_monitoring(
        cmd=command,
        output_file=f"{step_name}_monitoring.jsonl",
        timeout=3600
    )

    if exit_code == 0:
        samples = monitor.get_samples()
        print(f"{step_name} completed successfully ({len(samples)} samples)")
        return True
    else:
        print(f"{step_name} failed with exit code {exit_code}")
        return False

# Use in workflow
success = run_analysis_step(['blast', '-query', 'input.fa'], 'sequence_search')
if success:
    run_analysis_step(['clustal', 'alignment.fa'], 'multiple_alignment')
```

## See Also

- [Data Format Documentation](data-format.md)
