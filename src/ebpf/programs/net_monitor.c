//! Per-process network byte accounting eBPF program
//!
//! Attaches kprobes to the socket-layer send/recv paths so that
//! bpf_get_current_pid_tgid() runs in process context and bytes are
//! attributed to the owning process (net_dev tracepoints fire in softirq
//! context, where the current task is unrelated to RX traffic).
//!
//! Covered: TCP (v4+v6, both share tcp_sendmsg/tcp_recvmsg) and UDP v4.
//! UDP over IPv6 uses udpv6_sendmsg/udpv6_recvmsg and is not counted.
//!
//! TX counts bytes requested at the socket layer (send failures overcount
//! slightly); RX counts bytes actually returned to userspace.

#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <linux/ptrace.h>
#include <linux/types.h>

typedef __u32 u32;
typedef __u64 u64;
typedef __u8 u8;

struct net_bytes_val {
    u64 rx;
    u64 tx;
};

// tgid → monitored flag. Seeded before attach and synced from userspace
// each sample, so only the monitored process tree is accounted.
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __type(key, u32);
    __type(value, u8);
    __uint(max_entries, 1024);
} pid_filter SEC(".maps");

// tgid → cumulative bytes. Bounded by monitored-tree size, not host load.
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __type(key, u32);
    __type(value, struct net_bytes_val);
    __uint(max_entries, 1024);
} net_bytes SEC(".maps");

static __always_inline void add_bytes(u64 rx, u64 tx)
{
    u32 tgid = bpf_get_current_pid_tgid() >> 32;
    if (!bpf_map_lookup_elem(&pid_filter, &tgid))
        return;

    struct net_bytes_val *val = bpf_map_lookup_elem(&net_bytes, &tgid);
    if (val) {
        __sync_fetch_and_add(&val->rx, rx);
        __sync_fetch_and_add(&val->tx, tx);
    } else {
        struct net_bytes_val init = { .rx = rx, .tx = tx };
        bpf_map_update_elem(&net_bytes, &tgid, &init, BPF_ANY);
    }
}

// int tcp_sendmsg(struct sock *sk, struct msghdr *msg, size_t size)
SEC("kprobe/tcp_sendmsg")
int trace_tcp_sendmsg(struct pt_regs *ctx)
{
    add_bytes(0, PT_REGS_PARM3(ctx));
    return 0;
}

// tcp_recvmsg/udp_recvmsg return bytes copied to userspace (or <0 on error).
// Both return int: on x86-64 only the low 32 bits of rax are defined, the
// upper half is garbage — truncate before the sign check or we sum junk.
SEC("kretprobe/tcp_recvmsg")
int trace_tcp_recvmsg_ret(struct pt_regs *ctx)
{
    int ret = (int)PT_REGS_RC(ctx);
    if (ret > 0)
        add_bytes(ret, 0);
    return 0;
}

// int udp_sendmsg(struct sock *sk, struct msghdr *msg, size_t len)
SEC("kprobe/udp_sendmsg")
int trace_udp_sendmsg(struct pt_regs *ctx)
{
    add_bytes(0, PT_REGS_PARM3(ctx));
    return 0;
}

SEC("kretprobe/udp_recvmsg")
int trace_udp_recvmsg_ret(struct pt_regs *ctx)
{
    int ret = (int)PT_REGS_RC(ctx);
    if (ret > 0)
        add_bytes(ret, 0);
    return 0;
}

char LICENSE[] SEC("license") = "GPL";
