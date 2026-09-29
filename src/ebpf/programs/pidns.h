//! PID namespace translation shared by the eBPF programs
//!
//! bpf_get_current_pid_tgid() returns IDs from the initial PID namespace. When
//! denet itself runs inside a container, the PIDs it reads from /proc are the
//! container's, so the two never match. Userspace sets these two globals to the
//! device and inode of denet's own PID namespace (/proc/self/ns/pid) before
//! loading; left at zero, the programs use initial-namespace IDs as before.

#pragma once

#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>

volatile const __u64 pidns_dev = 0;
volatile const __u64 pidns_ino = 0;

// TGID and PID of the current task as seen from denet's PID namespace.
// Returns 0 when the task is not visible there (e.g. a host process while
// denet runs in a container), so callers skip it.
static __always_inline int current_tgid_pid(__u32 *tgid, __u32 *pid)
{
    if (!pidns_ino) {
        __u64 v = bpf_get_current_pid_tgid();
        *tgid = v >> 32;
        *pid = (__u32)v;
        return 1;
    }
    // ponytail: needs kernel >= 5.7; with pidns_ino == 0 the verifier prunes
    // this branch, so older kernels keep loading on the host
    struct bpf_pidns_info ns = {};
    if (bpf_get_ns_current_pid_tgid(pidns_dev, pidns_ino, &ns, sizeof(ns)))
        return 0;
    *tgid = ns.tgid;
    *pid = ns.pid;
    return 1;
}
