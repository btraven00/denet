//! Off-CPU profiling eBPF program
//!
//! This program attaches to the sched:sched_switch tracepoint to track threads
//! when they are scheduled out (off-CPU) and back in. It measures the time spent
//! off-CPU to help identify bottlenecks related to I/O, locks, and other waits.

#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <linux/ptrace.h>
#include <linux/types.h>
#include "pidns.h"

// Type definitions for convenience
typedef __u32 u32;
typedef __u64 u64;

// Maximum stack depth for stack traces
#define PERF_MAX_STACK_DEPTH 127

// Map to store timestamps when threads go off-CPU (tid → timestamp).
// LRU, like tid_to_tgid below: both see every thread on the host and are
// never cleaned up for exited threads, so a plain hash fills on a busy host
// and then silently drops new threads, i.e. the monitored ones.
struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __type(key, u32);        // tid
    __type(value, u64);      // timestamp (ns) when thread went off-CPU
    __uint(max_entries, 10240);
} thread_last_offcpu SEC(".maps");

// Map to resolve tid → (tgid, tid) as userspace sees them.
//
// The current task in a sched_switch tracepoint is the PREV (outgoing) task,
// so its IDs can only be read then. We record them when a thread goes
// off-CPU and look them up when it comes back on-CPU. Keys are the kernel's
// initial-namespace tids from the tracepoint; values are in denet's PID
// namespace (see pidns.h).
struct task_ids {
    u32 tgid;
    u32 tid;
};

struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __type(key, u32);              // tid (initial namespace)
    __type(value, struct task_ids);
    __uint(max_entries, 10240);
} tid_to_tgid SEC(".maps");

// Event sent to userspace via the perf ring buffer
struct offcpu_event {
    u32 pid;            // Process ID (TGID)
    u32 tid;            // Thread ID
    u32 prev_state;     // Scheduler state when thread went off-CPU
    u64 offcpu_time_ns; // Time spent off-CPU in nanoseconds
    u64 start_time_ns;  // Timestamp when thread went off-CPU
    u64 end_time_ns;    // Timestamp when thread came back on-CPU
    u32 user_stack_id;  // User-space stack trace ID (may be negative on error)
    u32 kernel_stack_id; // Kernel-space stack trace ID
};

struct {
    __uint(type, BPF_MAP_TYPE_PERF_EVENT_ARRAY);
    __uint(key_size, sizeof(u32));
    __uint(value_size, sizeof(u32));
} events SEC(".maps");

// Stack trace maps
struct {
    __uint(type, BPF_MAP_TYPE_STACK_TRACE);
    __uint(key_size, sizeof(u32));
    __uint(value_size, PERF_MAX_STACK_DEPTH * sizeof(u64));
    __uint(max_entries, 1024);
} user_stackmap SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_STACK_TRACE);
    __uint(key_size, sizeof(u32));
    __uint(value_size, PERF_MAX_STACK_DEPTH * sizeof(u64));
    __uint(max_entries, 1024);
} kernel_stackmap SEC(".maps");

// Minimum off-CPU duration to report (1ms)
#define MIN_OFFCPU_TIME_NS 1000000ULL

// sched_switch tracepoint context layout
struct sched_switch_args {
    u64 pad;
    char prev_comm[16];
    int prev_pid;
    int prev_prio;
    long prev_state;
    char next_comm[16];
    int next_pid;
    int next_prio;
};

SEC("tracepoint/sched/sched_switch")
int trace_sched_switch(struct sched_switch_args *ctx) {
    u64 now = bpf_ktime_get_ns();

    // ── Outgoing thread (prev) ────────────────────────────────────────────────
    // bpf_get_current_pid_tgid() is valid here: before the context switch,
    // "current" is still the prev task.
    u32 prev_tid = (u32)ctx->prev_pid;
    struct task_ids prev_ids;

    // Threads outside denet's PID namespace are not recorded, so they never
    // produce an event when they come back on-CPU.
    if (current_tgid_pid(&prev_ids.tgid, &prev_ids.tid)) {
        // Record the IDs so we can reconstruct them when the thread wakes up.
        if (prev_ids.tgid != 0) {
            bpf_map_update_elem(&tid_to_tgid, &prev_tid, &prev_ids, BPF_ANY);
        }
        // Record the timestamp at which this thread leaves the CPU.
        bpf_map_update_elem(&thread_last_offcpu, &prev_tid, &now, BPF_ANY);
    }

    // ── Incoming thread (next) ────────────────────────────────────────────────
    u32 next_tid = (u32)ctx->next_pid;
    u64 *last_ts = bpf_map_lookup_elem(&thread_last_offcpu, &next_tid);
    if (!last_ts) {
        return 0;
    }

    u64 off_cpu_time = now - *last_ts;

    // Remove the entry so we don't double-count.
    bpf_map_delete_elem(&thread_last_offcpu, &next_tid);

    if (off_cpu_time <= MIN_OFFCPU_TIME_NS) {
        return 0;
    }

    // Look up the IDs recorded when this thread last went off-CPU.
    struct task_ids *ids = bpf_map_lookup_elem(&tid_to_tgid, &next_tid);
    // Fall back to using the TID as the PID (correct for single-threaded
    // processes), which is only valid in the initial namespace.
    if (!ids && pidns_ino) {
        return 0;
    }
    u32 event_pid = ids ? ids->tgid : next_tid;
    u32 event_tid = ids ? ids->tid : next_tid;

    u32 user_stack_id = bpf_get_stackid(ctx, &user_stackmap,
                                         BPF_F_USER_STACK | BPF_F_FAST_STACK_CMP);
    u32 kernel_stack_id = bpf_get_stackid(ctx, &kernel_stackmap, BPF_F_FAST_STACK_CMP);

    struct offcpu_event event = {
        .pid             = event_pid,
        .tid             = event_tid,
        .prev_state      = (u32)ctx->prev_state,
        .offcpu_time_ns  = off_cpu_time,
        .start_time_ns   = *last_ts,
        .end_time_ns     = now,
        .user_stack_id   = user_stack_id,
        .kernel_stack_id = kernel_stack_id,
    };

    bpf_perf_event_output(ctx, &events, BPF_F_CURRENT_CPU,
                          &event, sizeof(event));
    return 0;
}

char LICENSE[] SEC("license") = "GPL";
