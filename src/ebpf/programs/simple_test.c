//! Simple eBPF program for testing tracepoints
//! This is a minimal program that should be easy to load

#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

// Simple array map for testing
struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __type(key, __u32);
    __type(value, __u64);
    __uint(max_entries, 10);
} test_map SEC(".maps");

// Simple tracepoint for openat syscall
SEC("tracepoint/syscalls/sys_enter_openat")
int trace_openat_enter(void *ctx) {
    __u32 key = 0;
    __u64 *value = bpf_map_lookup_elem(&test_map, &key);
    if (value) {
        (*value)++;
    }
    return 0;
}

char LICENSE[] SEC("license") = "GPL";