# TODOs for denet

## Code Structure & Technical Debt

- [x] Resolve duplicate ProcessMonitor implementations:
  - We currently have two parallel implementations:
    - Legacy `ProcessMonitor` in the root namespace (used by Python bindings)
    - New `CoreProcessMonitor` (also exposed as `ProcessMonitor` in the `core` module)
  - Decision made: Keep only the `core` implementation with compatibility layer
  - [x] Ensure both disk read and write metrics are accurately tracked in the chosen implementation
  - [x] Add regression tests to verify I/O metrics accuracy
  - [x] Created a compatibility wrapper for the legacy API
  - [x] Fix remaining issues in CPU stress test for child process monitoring
  - [x] Clean up warnings and unused imports in compatibility layer
  - [x] Add deprecation notice to compatibility layer
- [ ] make sure all tests pass (cpu stress test)
- [ ] make sure the python bindings use core::ProcessMonitor
- [ ] make sure python tests pass

## Off-CPU Profiler

- [ ] Add stack trace capture using `bpf_get_stackid` to identify exact code locations
- [ ] Support thread name resolution from `/proc/{pid}/task/{tid}/comm`
- [ ] Add off-CPU state categorization (IO wait, futex, etc.)
- [ ] Implement off-CPU analysis for bottleneck diagnosis
- [ ] Add kernel-space stacks to user-space stacks for better insight
- [ ] Create visualization tools (flamegraphs) for off-CPU time
- [ ] Expose filtering options for minimum/maximum off-CPU time
- [ ] Add syscall-specific off-CPU tracking

## Refactor Existing eBPF Code

- [ ] Move the syscall tracker to use the same Rust-based Aya approach (for some reason all was reverted to use clang, investigate why and if it's possible to revert back to Rust)
- [ ] Create a common eBPF loader infrastructure
- [ ] Add support for profile-guided compilation of eBPF programs
- [ ] Create a unified map structure for aggregation across eBPF programs
- [ ] Implement multi-buffer perf events to reduce overhead

## Platform Support

- [ ] Test and support on different kernel versions
- [ ] Provide fallback mechanisms for older kernels
- [ ] Add BTF (BPF Type Format) support for more efficient programs
- [ ] Test on various Linux distributions

## Documentation

- [ ] Add detailed documentation on eBPF program architecture
- [ ] Document maps and perf buffers used by each program
- [ ] Create examples for different performance bottleneck scenarios
- [ ] Add troubleshooting guide for common eBPF issues

## Per-Process Network Monitoring (eBPF)

Current `net_rx_bytes`/`net_tx_bytes` are read from `/proc/{pid}/net/dev` which
is system-wide, not per-process. eBPF can track per-process network traffic by
correlating socket operations back to a PID.

### Approach

Attach to one of:
- `tracepoint/net/net_dev_xmit` + `tracepoint/skb/skb_copy_datagram_iovec` —
  pure tracepoints, no kprobe stability concerns
- `kprobe:tcp_sendmsg` / `kprobe:tcp_recvmsg` + `kprobe:udp_sendmsg` /
  `kprobe:udp_recvmsg` — more granular, but kprobe names can change across kernels

In the eBPF program: call `bpf_get_current_pid_tgid()` to get the PID, store
cumulative bytes in a `BPF_MAP_TYPE_HASH` keyed by PID, emit deltas to userspace
via perf ring buffer or read the map directly.

TCP and UDP need separate programs; raw sockets are an additional case.

### Effort

Comparable to the syscall tracer. New eBPF C program + Rust integration in
`src/ebpf/`. Replace the `/proc` fallback with eBPF data when available, keep
the fallback for non-eBPF builds.

- [ ] Write `net_monitor.c` eBPF program (TCP + UDP send/recv kprobes or tracepoints)
- [ ] Add `NetMonitor` struct in `src/ebpf/net_monitor.rs` (mirror `SyscallTracker` pattern)
- [ ] Wire into `ProcessMonitor::sample_tree_metrics()` alongside syscall/offcpu
- [ ] Add `net_rx_bytes_ebpf` / `net_tx_bytes_ebpf` fields to metrics (keep procfs fallback)
- [ ] Test on kernel 5.15 and 6.x

## Integration

- [ ] Integrate with process_monitor API for Python access
- [ ] Expose eBPF metrics through a unified interface
- [ ] Add hooks for custom analysis plugins
- [ ] Implement metrics export to visualization tools (Grafana, etc.)
