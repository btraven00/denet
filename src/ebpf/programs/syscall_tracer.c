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
#include "proctree.h"

// Calls made by the monitored tree, indexed by syscall number. Not keyed by
// pid: nothing reports per-process counts, and a per-pid map fills up (and
// then silently drops counts) on a job that starts thousands of processes.
#define MAX_SYSCALL_NR 512
struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __type(key, __u32);
    __type(value, __u64);
    __uint(max_entries, MAX_SYSCALL_NR);
} syscall_counts SEC(".maps");

static __always_inline void count_syscall(__u32 tgid, __u32 syscall_nr) {
    if (!is_tracked(tgid))
        return;
    __u64 *count = bpf_map_lookup_elem(&syscall_counts, &syscall_nr);
    if (count)
        __sync_fetch_and_add(count, 1);
}

// Generate a tracepoint program for a single syscall. The `name` must match
// `/sys/kernel/debug/tracing/events/syscalls/sys_enter_<name>` and the Rust
// attach table in `syscall_tracker.rs`.
#define TRACE_SYSCALL(name, nr)                                                \
    SEC("tracepoint/syscalls/sys_enter_" #name)                                \
    int trace_##name##_enter(void *ctx) {                                      \
        __u32 tgid, tid;                                                       \
        if (current_tgid_pid(&tgid, &tid))                                     \
            count_syscall(tgid, (nr));                                   \
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
