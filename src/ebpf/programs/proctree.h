//! Which processes are in the monitored tree, shared by the eBPF programs
//!
//! Userspace seeds pid_filter before attaching and syncs it at every sample,
//! but a sample is up to a second away: a child that does its work and exits
//! in between was never counted. So forks are followed in the kernel, and a
//! child is in the tree from its first instruction.
//!
//! Each program that includes this must also load and attach
//! trace_process_fork and trace_process_exit (sched tracepoints) and set
//! fork_child_pid_off, see `attach_proctree` in src/ebpf/mod.rs.

#pragma once

#include "pidns.h"

// tgid -> monitored flag, in denet's PID namespace (see pidns.h)
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __type(key, __u32);
    __type(value, __u8);
    __uint(max_entries, 4096);
} pid_filter SEC(".maps");

// Children forked by a monitored process, by initial-namespace pid (all the
// fork tracepoint gives), until the child itself first runs a program here
// and joins pid_filter under the pid denet's namespace knows it by.
struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __type(key, __u32);
    __type(value, __u8);
    __uint(max_entries, 4096);
} fork_pending SEC(".maps");

// Whether the current task, with this tgid in denet's namespace, is in the
// monitored tree
static __always_inline int is_tracked(__u32 tgid)
{
    if (bpf_map_lookup_elem(&pid_filter, &tgid))
        return 1;
    __u32 host_tgid = bpf_get_current_pid_tgid() >> 32;
    if (!bpf_map_lookup_elem(&fork_pending, &host_tgid))
        return 0;
    __u8 one = 1;
    bpf_map_update_elem(&pid_filter, &tgid, &one, BPF_ANY);
    bpf_map_delete_elem(&fork_pending, &host_tgid);
    return 1;
}

// Offset of child_pid in the sched_process_fork record. The layout changed
// when the comm fields became __data_loc strings (44 before, 20 after), so
// userspace reads it from the tracepoint's format file and sets it at load.
volatile const __u32 fork_child_pid_off = 44;

// The parent is current. Threads fork too, but share the parent's tgid,
// which is already tracked; their entry here goes when the thread exits.
SEC("tracepoint/sched/sched_process_fork")
int trace_process_fork(void *ctx) {
    __u32 tgid, tid;
    // is_tracked, not the filter alone: a child may fork its own children
    // before anything else has added it
    if (!current_tgid_pid(&tgid, &tid) || !is_tracked(tgid))
        return 0;
    __u32 child = 0;
    if (bpf_probe_read_kernel(&child, sizeof(child), (char *)ctx + fork_child_pid_off))
        return 0;
    __u8 one = 1;
    bpf_map_update_elem(&fork_pending, &child, &one, BPF_ANY);
    return 0;
}

// Forget a task when it exits, so a reused pid is not tracked: a process
// leaves the filter with its main thread, and anything still pending (a
// thread, or a child that never ran a program here) is dropped.
SEC("tracepoint/sched/sched_process_exit")
int trace_process_exit(void *ctx) {
    __u32 host_tid = (__u32)bpf_get_current_pid_tgid();
    bpf_map_delete_elem(&fork_pending, &host_tid);
    __u32 tgid, tid;
    if (current_tgid_pid(&tgid, &tid) && tgid == tid)
        bpf_map_delete_elem(&pid_filter, &tgid);
    return 0;
}
