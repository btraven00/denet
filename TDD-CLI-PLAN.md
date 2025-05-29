# Simple CLI Utility Plan for PMET

## Focus Areas

- Basic command line interface for the process monitoring tool
- Simple, colorful output for metrics in the terminal
- JSON output option for machine processing
- Output redirection to files

## Essential Features

- Process monitoring with basic command line arguments
- Colorful metrics display (CPU, memory, I/O)
- JSON output format option
- File output option
- Configurable sampling interval

## Minimal Dependencies

```toml
[dependencies]
# Command line argument parsing
clap = { version = "4.5", features = ["derive"] }

# Terminal colors for metrics
colored = "2.1"
```

## CLI Usage Examples

```
# Basic monitoring with colored output
pmet run "my_program --with args"

# Output as JSON
pmet run --json "my_program"

# Write output to file
pmet run --out metrics.log "my_program"

# Custom sampling interval (in milliseconds)
pmet run --interval 500 "my_program"

# Combined options
pmet run --json --out metrics.json --interval 1000 "my_program"
```

## Implementation Steps

1. Create a bin entry point at `src/bin/pmet.rs`
2. Set up simple command structure with clap
3. Implement colored output for terminal display
4. Add JSON output option
5. Implement file output option
6. Create basic help information

## Test Cases

- Command line argument parsing
- Metrics formatting for terminal
- JSON output validation
- File writing functionality 

## Definition of Done

- Command-line tool accepts basic arguments
- Colored metrics display in terminal
- JSON output working correctly
- File output working correctly
- README includes usage examples