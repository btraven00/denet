//! Syscall tracing eBPF program
//! This program attaches to syscall tracepoints and counts syscall frequency

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

// Tracepoint for openat syscall
SEC("tracepoint/syscalls/sys_enter_openat")
int trace_openat_enter(void *ctx) {
    __u32 pid = bpf_get_current_pid_tgid() >> 32;
    update_syscall_maps(pid, 257); // 257 is openat syscall nr
    return 0;
}

// Tracepoint for read syscall
SEC("tracepoint/syscalls/sys_enter_read")
int trace_read_enter(void *ctx) {
    __u32 pid = bpf_get_current_pid_tgid() >> 32;
    update_syscall_maps(pid, 0); // 0 is read syscall nr
    return 0;
}

// Tracepoint for write syscall
SEC("tracepoint/syscalls/sys_enter_write")
int trace_write_enter(void *ctx) {
    __u32 pid = bpf_get_current_pid_tgid() >> 32;
    update_syscall_maps(pid, 1); // 1 is write syscall nr
    return 0;
}

// Tracepoint for close syscall
SEC("tracepoint/syscalls/sys_enter_close")
int trace_close_enter(void *ctx) {
    __u32 pid = bpf_get_current_pid_tgid() >> 32;
    update_syscall_maps(pid, 3); // 3 is close syscall nr
    return 0;
}

// Tracepoint for mmap syscall
SEC("tracepoint/syscalls/sys_enter_mmap")
int trace_mmap_enter(void *ctx) {
    __u32 pid = bpf_get_current_pid_tgid() >> 32;
    update_syscall_maps(pid, 9); // 9 is mmap syscall nr
    return 0;
}

// Tracepoint for socket syscall
SEC("tracepoint/syscalls/sys_enter_socket")
int trace_socket_enter(void *ctx) {
    __u32 pid = bpf_get_current_pid_tgid() >> 32;
    update_syscall_maps(pid, 41); // 41 is socket syscall nr
    return 0;
}

// Tracepoint for connect syscall
SEC("tracepoint/syscalls/sys_enter_connect")
int trace_connect_enter(void *ctx) {
    __u32 pid = bpf_get_current_pid_tgid() >> 32;
    update_syscall_maps(pid, 42); // 42 is connect syscall nr
    return 0;
}

// Tracepoint for recvfrom syscall
SEC("tracepoint/syscalls/sys_enter_recvfrom")
int trace_recvfrom_enter(void *ctx) {
    __u32 pid = bpf_get_current_pid_tgid() >> 32;
    update_syscall_maps(pid, 45); // 45 is recvfrom syscall nr
    return 0;
}

// Tracepoint for sendto syscall
SEC("tracepoint/syscalls/sys_enter_sendto")
int trace_sendto_enter(void *ctx) {
    __u32 pid = bpf_get_current_pid_tgid() >> 32;
    update_syscall_maps(pid, 44); // 44 is sendto syscall nr
    return 0;
}

char LICENSE[] SEC("license") = "GPL";
