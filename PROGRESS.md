# PMET Development Progress

## Project Status Overview

PMET is a high-performance process monitoring tool that provides detailed metrics on running processes. This document tracks development progress and plans future work.

## ✅ Completed Items

### Core Infrastructure

- [x] Project structure with Rust core and Python bindings
- [x] Build and install pipeline with maturin
- [x] TDD approach with Rust and Python tests
- [x] Development environment with pixi

### Libraries & Dependencies

- [x] Selected `sysinfo` for process metrics
- [x] Using `serde` + `serde_json` for serialization
- [x] Python bindings with `PyO3` + `maturin`
- [x] Minimal dependencies (no async runtime)

### Core Functionality

- [x] Process launching and monitoring via `std::process::Command`
- [x] Process status checking with `is_running()`
- [x] Monitoring existing processes by PID
- [x] Basic metrics collection:
  - [x] CPU usage
  - [x] Memory usage (RSS)
  - [x] I/O read/write bytes
  - [x] Thread count
  - [x] Process uptime
- [x] Adaptive sampling interval implementation
- [x] JSON serialization of metrics

### Python API

- [x] Python class `PyProcessMonitor` with:
  - [x] Constructor with command and timing parameters
  - [x] Factory method to attach to existing process by PID
  - [x] `run()` method for continuous monitoring
  - [x] `sample_once()` for on-demand metrics
  - [x] `is_running()` for process status
  - [x] `get_pid()` for retrieving process ID

### Testing

- [x] Unit tests for adaptive interval calculation
- [x] Tests for process status tracking
- [x] Basic metrics collection tests
- [x] Python binding tests

## 🚧 Upcoming Development Sessions

### Session 0: Modern CLI Interface

**Goal:** Create a colorful, user-friendly CLI tool for the Rust implementation

- [x] Command-line argument parsing with `clap`
- [x] Colorful terminal output with `colored`
- [x] Human-readable metrics formatting
- [x] Multiple output format options (JSON, simple)
- [x] File output option
- [x] Monitor existing processes by PID
- [x] In-place terminal updates with progress indicators
- [x] Clean shutdown with SIGINT (Ctrl+C) handling
- [x] Duration-limited monitoring for attach command
- [x] Enhanced visual feedback with spinners and elapsed time
- [x] Terminal-aware formatting and display
- [x] Delta I/O accounting (default: shows I/O since monitoring start)
- [x] Optional cumulative I/O accounting with --since-process-start flag
- [x] Separated disk and network I/O metrics
- [x] Linux network I/O monitoring (system-wide approximation)
- [x] Cross-platform network I/O framework (placeholder for other platforms)

**Note**: Current network I/O monitoring shows system-wide network activity, not per-process. This is a known limitation - true per-process network monitoring requires advanced techniques.

### Session 1: Child Process Monitoring

**Goal:** Monitor and collect metrics from child processes

- [x] Child process detection
- [x] Metrics collection from child processes
- [x] Aggregated metrics for process trees
- [x] CLI integration with `--exclude-children` flag
- [x] JSON and human-readable output for process trees
- [x] Comprehensive test coverage for edge cases
- [ ] Python API for child process metrics

### Session 2: Enhanced Metrics Collection

**Goal:** More detailed CPU and memory metrics

- [ ] Per-thread CPU usage
- [ ] Memory breakdown (private/shared)
- [ ] Process command line and name
- [ ] Environment variables
- [ ] Process start time

### Session 3: Metrics History & Analysis

**Goal:** Track metrics over time

- [ ] Time-series storage of metrics
- [ ] Basic statistical analysis (min/max/avg)
- [ ] Historical data access API
- [ ] Metrics sampling rate tracking

### Session 4: Advanced Adaptive Sampling

**Goal:** Smarter sampling based on process activity

- [ ] Activity level detection
- [ ] CPU/memory threshold-based sampling
- [ ] Busyness detection algorithm
- [ ] Process lifecycle phase detection

### Session 5: Configurable Metrics & Output

**Goal:** Customizable metrics collection

- [ ] Configuration for enabling/disabling metrics
- [ ] Filtering and output formatting options
- [ ] Output to file options
- [ ] Multiple output format support

### Session 6: Cross-Platform Enhancements

**Goal:** Better support for Windows and macOS

- [ ] Windows thread counting improvements
- [ ] macOS-specific metrics
- [ ] Platform-specific optimizations
- [ ] Executable path resolution

## 🔮 Future Considerations

- [ ] Event-driven sampling (Linux perf events)
- [ ] Explore eBPF for event-driven sampling (Linux)
- [ ] **eBPF-based per-process network I/O monitoring** (Linux) - would provide accurate per-process network statistics instead of current system-wide approximation
- [ ] Use OpenTelemetry to export distributed metrics
- [ ] Dynamic reconfiguration of sampling based on metrics
- [ ] Prometheus/OpenMetrics exporter
- [ ] Container (Docker, LXC) awareness
- [ ] Per-process network usage metrics via socket tracking (complex alternative to eBPF)
- [ ] GPU utilization metrics
- [ ] Async API option with tokio

## Development Session Template

For each development session, we follow this TDD approach:

1. **Write tests first** that define expected behavior
2. **Implement minimum code** needed to make tests pass
3. **Refactor** the implementation for clarity and efficiency
4. **Integrate** with existing codebase
5. **Update Python bindings** to expose new functionality
6. **Document** the new features and update examples

## Session Status Tracking

| Session | Feature | Status | Date | Notes |
|---------|---------|--------|------|-------|
| - | Initial setup | ✅ Done | - | Project structure and basic functionality |
| 0 | Modern CLI Interface | ✅ Done | 2024-05-29 | CLI with PID tracking, colored output, JSON support, SIGINT handling, enhanced in-place updates, delta I/O accounting, and separated disk/network I/O |
| 1 | Child Process Monitoring | ✅ Done | 2024-12-19 | Recursive child detection, process tree metrics, aggregated data, CLI integration with --exclude-children flag |
| 2 | Enhanced Metrics | 🔄 Next | - | - |
| 3 | Metrics History | 🔄 Planned | - | - |
| 4 | Advanced Sampling | 🔄 Planned | - | - |
| 5 | Configurable Metrics | 🔄 Planned | - | - |
| 6 | Cross-Platform Enhancements | 🔄 Planned | - | - |
