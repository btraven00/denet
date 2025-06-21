# Stack Trace Symbolication Implementation Plan

This document outlines the implementation plan for stack trace symbolication in DeNet. Symbolication is the process of converting raw memory addresses in stack traces to human-readable function names, file paths, and line numbers.

## Current Status

DeNet already has a placeholder for stack trace symbolication in the `OffCpuProfiler` class:

```rust
fn get_symbolicated_stack_frames(&self, stack_id: u32, is_user_stack: bool) -> Vec<StackFrame> {
    // Currently returns placeholder frames
}
```

Our goal is to implement actual symbolication functionality to enhance the usefulness of stack traces.

## Symbolication Approach

We'll implement symbolication in a progressive manner, with fallback options when full symbolication isn't possible:

### 1. Full Symbolication (Best Case)

Use a combination of:
- `/proc/{pid}/maps` for memory mapping information
- `/proc/{pid}/exe` and loaded shared libraries for symbol tables
- `addr2line` or a Rust-based symbolication library for source location

### 2. Partial Symbolication (Fallback)

When full source location can't be determined:
- Extract function names from symbols without line information
- Provide module/library information for addresses

### 3. Basic Address Information (Minimal)

When no symbol information is available:
- Show module name and offset if possible
- Format raw addresses in a useful way

## Implementation Steps

### Step 1: Extract Memory Map Information

Create a function to parse `/proc/{pid}/maps`:

```rust
struct MemoryRegion {
    start_addr: u64,
    end_addr: u64,
    permissions: String,
    offset: u64,
    dev: String,
    inode: u64,
    pathname: Option<String>,
}

fn get_memory_maps(pid: u32) -> Result<Vec<MemoryRegion>> {
    // Parse /proc/{pid}/maps and create memory regions
}
```

### Step 2: Find Region for Address

Create a function to find which memory region contains an address:

```rust
fn find_region_for_address(addr: u64, regions: &[MemoryRegion]) -> Option<&MemoryRegion> {
    // Binary search or linear scan to find the region containing the address
}
```

### Step 3: Extract Symbol Information

Implement symbol lookup using one of these approaches:

#### Option A: Use addr2line as External Command

```rust
fn get_symbol_info(addr: u64, binary_path: &str) -> Result<SymbolInfo> {
    // Run addr2line command and parse output
}
```

#### Option B: Use a Rust Symbolication Library

```rust
fn get_symbol_info(addr: u64, binary_path: &str) -> Result<SymbolInfo> {
    // Use a library like addr2line, goblin, or object to extract symbol info
}
```

### Step 4: Cache Results for Performance

Implement caching to avoid repeated lookups:

```rust
struct SymbolCache {
    pid_maps: HashMap<u32, Vec<MemoryRegion>>,
    symbol_cache: HashMap<(String, u64), SymbolInfo>,
}
```

### Step 5: Integrate with OffCpuProfiler

Update the `get_symbolicated_stack_frames` method:

```rust
fn get_symbolicated_stack_frames(&self, stack_id: u32, is_user_stack: bool) -> Vec<StackFrame> {
    // Get raw stack addresses
    // For each address:
    //   1. Find memory region
    //   2. Look up symbol (with caching)
    //   3. Create StackFrame
}
```

## Enhanced StackFrame Structure

Enhance the `StackFrame` struct to include more information:

```rust
pub struct StackFrame {
    pub address: u64,
    pub symbol: Option<String>,
    pub module: Option<String>,
    pub offset: Option<u64>,
    pub source_location: Option<SourceLocation>,
}

pub struct SourceLocation {
    pub file: String,
    pub line: u32,
    pub column: Option<u32>,
}
```

## Error Handling and Fallbacks

Implement a progressive fallback strategy:

1. Try full symbolication with line information
2. If that fails, try to get function name only
3. If that fails, provide module+offset
4. If all else fails, just show the raw address

## Performance Considerations

- Cache memory maps by PID
- Cache symbol lookups by binary path and address
- Use a background thread for symbolication to avoid blocking
- Consider implementing a LRU cache with size limits

## Dependencies

Consider these options for symbolication libraries:

- **addr2line**: Pure Rust library for DWARF debugging info
- **object**: Library to read object file formats
- **goblin**: Library for parsing ELF, Mach-O, PE binaries
- **memmap**: For efficient memory mapping of binary files

## Testing

Create tests with:

1. Known binaries and addresses
2. Edge cases (stripped binaries, non-existent files)
3. Performance tests with large stack traces

## Future Enhancements

- Remote symbolication support
- Symbol server integration
- Support for more binary formats
- JIT and interpreted language support