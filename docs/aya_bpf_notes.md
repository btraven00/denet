# Aya BPF API Notes and Solutions

This document captures important information about using the Aya BPF library and solutions to common challenges encountered during development of the stack trace capture functionality.

## API Version Changes

The Aya BPF library has undergone significant API changes between versions. Our project uses Aya v0.13.1, which has some differences from the documentation examples that might be online.

### Type Renaming

- `Bpf` has been renamed to `Ebpf`
- `BpfLoader` has been renamed to `EbpfLoader`

Always use the new names in your code:

```rust
// Old way:
// use aya::{Bpf, BpfLoader};

// New way:
use aya::{Ebpf, EbpfLoader};
```

## Program Loading and Access

### Loading BPF Programs

The simplest way to load a BPF program is using `Ebpf::load()`:

```rust
let bpf = Ebpf::load(BYTECODE).map_err(|e| {
    debug::debug_println(&format!("Failed to load eBPF program: {}", e));
    DenetError::EbpfInitError(format!("Failed to load eBPF program: {}", e))
})?;
```

For more advanced usage with global data settings, use `EbpfLoader`:

```rust
let bpf = EbpfLoader::new()
    .set_global("test_pid", &(std::process::id() as u32), false)
    .load(BYTECODE)?;
```

Note that `set_global` requires three parameters (not two):
1. The global variable name
2. The value to set
3. A boolean flag indicating whether the variable must exist

### Accessing and Casting Programs

To access a program by name and cast it to a specific type:

```rust
// Get program by name
let prog = bpf.program_mut("program_name").ok_or_else(|| {
    DenetError::EbpfInitError("Failed to find program".to_string())
})?;

// Cast to a specific type (using try_as, not as_mut)
let tracepoint = prog.try_as::<TracePoint>().ok_or_else(|| {
    DenetError::EbpfInitError("Failed to cast program".to_string())
})?;
```

Common mistakes:
- Using `as_mut<T>()` instead of `try_as::<T>()`
- Forgetting to load the program before attaching

## Map Operations

### StackTraceMap Operations

The `StackTraceMap` has specific API methods that differ from other map types:

```rust
// Getting a stack trace by ID
let stack_trace = stack_map.get(&stack_id, 0)?;  // The second parameter is flags (usually 0)

// Checking if the stack trace has entries
let frames = stack_trace.frames(); // Returns a slice of u64 addresses
if !frames.is_empty() {
    // Process stack frames
    for (i, &addr) in frames.iter().enumerate().take(5) {
        println!("Frame {}: {:x}", i, addr);
    }
}
```

Key points:
- Use `get(&stack_id, flags)` with two parameters, not `lookup()`
- Access frames using `frames()` method, which returns a slice of addresses
- Stack traces don't have `len()` or `is_empty()` methods directly, but you can use them on the frames slice

### Error Handling for Maps

Map errors are different from standard I/O errors:

```rust
match stack_map.get(&key, 0) {
    Ok(stack) => {
        // Process stack
    }
    Err(e) => {
        // For NotFound errors, this is often expected for unused stack IDs
        if let aya::maps::MapError::NotFound = e {
            // Skip silently
        } else {
            // Log other errors
            debug::debug_println(&format!("Error: {}", e));
        }
    }
}
```

## Common Error Patterns

### Program Attachment

When attaching programs, handle errors correctly:

```rust
match tracepoint.attach("raw_syscalls", "sys_enter") {
    Ok(_) => {
        debug::debug_println("Successfully attached tracepoint");
        Ok(())
    }
    Err(e) => {
        debug::debug_println(&format!("Failed to attach tracepoint: {}", e));
        Err(DenetError::EbpfInitError(format!("Failed to attach: {}", e)))
    }
}
```

### Permission Issues

Common permission-related errors:
- `Operation not permitted` - Missing capabilities or running without sudo
- `Invalid argument` - Missing kernel features or incorrect program type
- `No such file or directory` - Tracepoint doesn't exist

Solutions:
- Ensure the binary has `CAP_BPF` and `CAP_PERFMON` capabilities
- Check kernel settings with `sysctl kernel.unprivileged_bpf_disabled`
- Verify tracepoint paths in tracefs (`/sys/kernel/debug/tracing/events/`)

## Debugging BPF Programs

For debugging BPF programs:

1. Use `bpf_printk()` in your BPF code:
   ```c
   bpf_printk("Debug: stack_id=%d", stack_id);
   ```

2. Read debug output:
   ```bash
   sudo cat /sys/kernel/debug/tracing/trace_pipe
   ```

3. Examine BPF program verification issues:
   ```bash
   sudo bpftool prog tracelog
   ```

## Integration with Rust Error Handling

When integrating with Rust error types, create appropriate conversion methods:

```rust
// Convert from BPF error to your application error
impl From<aya::BpfError> for DenetError {
    fn from(err: aya::BpfError) -> Self {
        DenetError::EbpfInitError(format!("BPF error: {}", err))
    }
}

// Convert from Map error to your application error
impl From<aya::maps::MapError> for DenetError {
    fn from(err: aya::maps::MapError) -> Self {
        DenetError::EbpfInitError(format!("Map error: {}", err))
    }
}
```

By following these patterns, you can navigate the Aya BPF API more effectively and handle common issues appropriately.