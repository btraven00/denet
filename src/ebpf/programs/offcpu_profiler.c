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
#include "proctree.h"

// Type definitions for convenience
typedef __u32 u32;
typedef __u64 u64;
typedef __u8 u8;

// Maximum stack depth for stack traces
#define PERF_MAX_STACK_DEPTH 127

// What a monitored thread left the CPU with, keyed by its initial-namespace
// tid (from the tracepoint). Filled when it is switched out, because only
// then is it the current task: its IDs and stacks can't be read when it is
// switched back in, when the current task is the one being switched out.
struct offcpu_start {
    u64 ts;              // when it went off-CPU (ns)
    u32 tgid;            // IDs in denet's PID namespace
    u32 tid;
    u32 prev_state;      // scheduler state it left in (e.g. sleeping)
    u32 user_stack_id;   // stacks it was waiting in; negative on error
    u32 kernel_stack_id;
};

struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __type(key, u32);    // tid (initial namespace)
    __type(value, struct offcpu_start);
    __uint(max_entries, 10240);
} offcpu_start SEC(".maps");

// Event sent to userspace via the perf ring buffer
struct offcpu_event {
    u32 pid;            // Process ID (TGID)
    u32 tid;            // Thread ID
    u32 prev_state;     // Scheduler state when thread went off-CPU
    u32 _pad;           // named, so the initializer zeroes it: kernels
                        // before 6.4 reject uninitialized stack bytes
                        // passed to bpf_perf_event_output
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

// Kernel stacks: 32 frames reach from schedule() to the syscall entry. A
// stack whose hash slot holds a different stack gets -EEXIST (FAST_STACK_CMP),
// so the map is sized well above the stacks a tree uses; 8192 x 256 B = 2 MB.
#define KERNEL_STACK_DEPTH 32
struct {
    __uint(type, BPF_MAP_TYPE_STACK_TRACE);
    __uint(key_size, sizeof(u32));
    __uint(value_size, KERNEL_STACK_DEPTH * sizeof(u64));
    __uint(max_entries, 8192);
} kernel_stackmap SEC(".maps");

// Where a stack goes when its slot in kernel_stackmap is taken. One run
// captures ~50 distinct kernel stacks (every switch-out, not only the reported
// waits), so about 1 boot in 100 put a wait's stack in a used slot and lost
// its name; a stack is now lost only if its slot is taken in both maps.
struct {
    __uint(type, BPF_MAP_TYPE_STACK_TRACE);
    __uint(key_size, sizeof(u32));
    __uint(value_size, KERNEL_STACK_DEPTH * sizeof(u64));
    __uint(max_entries, 8192);
} kernel_stackmap2 SEC(".maps");

// Set in the ids of stacks stored in kernel_stackmap2 (userspace: KSTACK_OVERFLOW)
#define KSTACK_OVERFLOW (1u << 30)
#define EEXIST 17

static __always_inline u32 kernel_stack_id(void *ctx)
{
    long id = bpf_get_stackid(ctx, &kernel_stackmap, BPF_F_FAST_STACK_CMP);
    if (id != -EEXIST)
        return id;
    id = bpf_get_stackid(ctx, &kernel_stackmap2, BPF_F_FAST_STACK_CMP);
    return id < 0 ? id : id | KSTACK_OVERFLOW;
}

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

    // Outgoing thread (prev): "current" is still prev, so its IDs and the
    // stacks it is about to wait in can be read now.
    u32 prev_tid = (u32)ctx->prev_pid;
    struct offcpu_start start = {};
    if (current_tgid_pid(&start.tgid, &start.tid) && start.tgid != 0 &&
        is_tracked(start.tgid)) {
        start.ts = now;
        start.prev_state = (u32)ctx->prev_state;
        start.kernel_stack_id = kernel_stack_id(ctx);
        start.user_stack_id = bpf_get_stackid(ctx, &user_stackmap,
                                              BPF_F_USER_STACK | BPF_F_FAST_STACK_CMP);
        bpf_map_update_elem(&offcpu_start, &prev_tid, &start, BPF_ANY);
    }

    // Incoming thread (next): if it was recorded leaving, report the wait.
    u32 next_tid = (u32)ctx->next_pid;
    struct offcpu_start *s = bpf_map_lookup_elem(&offcpu_start, &next_tid);
    if (!s) {
        return 0;
    }
    struct offcpu_start left = *s;
    bpf_map_delete_elem(&offcpu_start, &next_tid);

    u64 off_cpu_time = now - left.ts;
    if (off_cpu_time <= MIN_OFFCPU_TIME_NS) {
        return 0;
    }

    struct offcpu_event event = {
        .pid             = left.tgid,
        .tid             = left.tid,
        .prev_state      = left.prev_state,
        .offcpu_time_ns  = off_cpu_time,
        .start_time_ns   = left.ts,
        .end_time_ns     = now,
        .user_stack_id   = left.user_stack_id,
        .kernel_stack_id = left.kernel_stack_id,
    };

    bpf_perf_event_output(ctx, &events, BPF_F_CURRENT_CPU,
                          &event, sizeof(event));
    return 0;
}

char LICENSE[] SEC("license") = "GPL";
