//! Syscall tracing eBPF program
//! This program attaches to syscall tracepoints and counts syscall frequency.
//!
//! Coverage spans the categories surfaced by `categorize_syscall` in
//! `src/ebpf/metrics.rs`: file_io, memory, process, network, ipc, signal, time.
//! New tracepoints must be mirrored in the `tracepoints` table in
//! `src/ebpf/syscall_tracker.rs`.
//!
//! Note: read/write on a connected socket fd are counted as file_io here.
//! Disambiguating socket vs. file fds is not possible from a syscall
//! tracepoint without an extra fd-type map, so connect/sendmsg/recvmsg are
//! the primary network signal.

#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

// BPF map to store syscall counts per PID
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __type(key, __u32);   // PID
    __type(value, __u64); // syscall count
    __uint(max_entries, 10240);
} syscall_counts SEC(".maps");

// BPF map to store per-syscall counts for each PID
// Key is (pid << 16 | syscall_nr) to fit both in a u32
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __type(key, __u32);   // PID << 16 | syscall_nr
    __type(value, __u32); // count for this syscall
    __uint(max_entries, 65536);
} pid_syscall_map SEC(".maps");

// Helper function to update both syscall maps
static inline void update_syscall_maps(__u32 pid, __u32 syscall_nr) {
    // Update total syscall count for PID
    __u64 *count = bpf_map_lookup_elem(&syscall_counts, &pid);
    if (count) {
        __sync_fetch_and_add(count, 1);
    } else {
        __u64 initial_count = 1;
        bpf_map_update_elem(&syscall_counts, &pid, &initial_count, BPF_ANY);
    }

    // Update per-syscall count for this PID
    __u32 key = (pid << 16) | (syscall_nr & 0xFFFF);
    __u32 *syscall_count = bpf_map_lookup_elem(&pid_syscall_map, &key);
    if (syscall_count) {
        __sync_fetch_and_add(syscall_count, 1);
    } else {
        __u32 initial_count = 1;
        bpf_map_update_elem(&pid_syscall_map, &key, &initial_count, BPF_ANY);
    }
}

// Generate a tracepoint program for a single syscall. The `name` must match
// `/sys/kernel/debug/tracing/events/syscalls/sys_enter_<name>` and the Rust
// attach table in `syscall_tracker.rs`.
#define TRACE_SYSCALL(name, nr)                                                \
    SEC("tracepoint/syscalls/sys_enter_" #name)                                \
    int trace_##name##_enter(void *ctx) {                                      \
        __u32 pid = bpf_get_current_pid_tgid() >> 32;                          \
        update_syscall_maps(pid, (nr));                                        \
        return 0;                                                              \
    }

// file_io
TRACE_SYSCALL(read,    0)
TRACE_SYSCALL(write,   1)
TRACE_SYSCALL(close,   3)
TRACE_SYSCALL(openat,  257)

// memory
TRACE_SYSCALL(mmap,    9)
TRACE_SYSCALL(munmap,  11)
TRACE_SYSCALL(brk,     12)

// process
TRACE_SYSCALL(clone,       56)
TRACE_SYSCALL(fork,        57)
TRACE_SYSCALL(vfork,       58)
TRACE_SYSCALL(execve,      59)
TRACE_SYSCALL(exit,        60)
TRACE_SYSCALL(wait4,       61)
TRACE_SYSCALL(kill,        62)
TRACE_SYSCALL(exit_group, 231)

// network
TRACE_SYSCALL(socket,    41)
TRACE_SYSCALL(connect,   42)
TRACE_SYSCALL(accept,    43)
TRACE_SYSCALL(sendto,    44)
TRACE_SYSCALL(recvfrom,  45)
TRACE_SYSCALL(sendmsg,   46)
TRACE_SYSCALL(recvmsg,   47)
TRACE_SYSCALL(bind,      49)
TRACE_SYSCALL(accept4,  288)

// ipc
TRACE_SYSCALL(futex,    202)
TRACE_SYSCALL(pipe,      22)
TRACE_SYSCALL(pipe2,    293)

// signal
TRACE_SYSCALL(rt_sigaction,   13)
TRACE_SYSCALL(rt_sigprocmask, 14)
TRACE_SYSCALL(tgkill,        234)

// time
TRACE_SYSCALL(nanosleep,        35)
TRACE_SYSCALL(clock_gettime,   228)
TRACE_SYSCALL(clock_nanosleep, 230)

char LICENSE[] SEC("license") = "GPL";
