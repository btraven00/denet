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

// Type definitions for convenience
typedef __u32 u32;
typedef __u64 u64;

// Maximum stack depth for stack traces
#define PERF_MAX_STACK_DEPTH 127  // Reduced to ensure compatibility

// Map to store timestamps when threads go off-CPU
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __type(key, u32);        // tid (thread id)
    __type(value, u64);      // timestamp when thread went off-CPU
    __uint(max_entries, 10240);
} thread_last_offcpu SEC(".maps");

// Map to store off-CPU statistics per thread
struct offcpu_event {
    u32 pid;            // Process ID
    u32 tid;            // Thread ID
    u32 prev_state;     // Thread state when it went off-CPU
    u64 offcpu_time_ns; // Time spent off-CPU in nanoseconds
    u64 start_time_ns;  // Start timestamp
    u64 end_time_ns;    // End timestamp
    u32 user_stack_id;  // User-space stack trace ID
    u32 kernel_stack_id; // Kernel-space stack trace ID
};

struct {
    __uint(type, BPF_MAP_TYPE_PERF_EVENT_ARRAY);
    __uint(key_size, sizeof(u32));
    __uint(value_size, sizeof(u32));
} events SEC(".maps");

// Stack trace maps for capturing user and kernel stack traces
struct {
    __uint(type, BPF_MAP_TYPE_STACK_TRACE);
    __uint(key_size, sizeof(u32));
    __uint(value_size, PERF_MAX_STACK_DEPTH * sizeof(u64));
    __uint(max_entries, 1024);            // Reduced to ensure compatibility
} user_stackmap SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_STACK_TRACE);
    __uint(key_size, sizeof(u32));
    __uint(value_size, PERF_MAX_STACK_DEPTH * sizeof(u64));
    __uint(max_entries, 1024);            // Reduced to ensure compatibility
} kernel_stackmap SEC(".maps");

// Minimum off-CPU time to track (nanoseconds)
// 1ms = 1,000,000 ns
#define MIN_OFFCPU_TIME_NS 1000000ULL

// sched_switch tracepoint structure
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

// Helper function to get process ID from thread ID
static u32 get_pid_from_tid(u32 tid) {
    // Get the actual process ID (TGID in Linux terminology)
    u64 pid_tgid = bpf_get_current_pid_tgid();
    u32 tgid = pid_tgid >> 32;  // Upper 32 bits contain the TGID (process ID)
    
    // If we can't get the TGID for some reason, fall back to using TID
    if (tgid == 0) {
        return tid;
    }
    
    return tgid;
}

// Trace when a thread is switched out and in
SEC("tracepoint/sched/sched_switch")
int trace_sched_switch(struct sched_switch_args *ctx) {
    // Get current timestamp
    u64 now = bpf_ktime_get_ns();
    
    // Previous thread is going off-CPU
    u32 prev_tid = (u32)ctx->prev_pid;
    // Record timestamp when this thread is scheduled out
    bpf_map_update_elem(&thread_last_offcpu, &prev_tid, &now, BPF_ANY);
    
    // Next thread is coming on-CPU
    u32 next_tid = (u32)ctx->next_pid;
    // Check if next thread has a previous off-CPU timestamp
    u64 *last_ts = bpf_map_lookup_elem(&thread_last_offcpu, &next_tid);
    if (last_ts) {
        // Calculate how long this thread was off-CPU
        u64 off_cpu_time = now - *last_ts;
        
        // Only report if off-CPU time exceeds threshold
        if (off_cpu_time > MIN_OFFCPU_TIME_NS) {
            // Log thread info before attempting stack capture
            bpf_printk("Capturing stacks for TID %d, PID %d\n", next_tid, bpf_get_current_pid_tgid() >> 32);
            
            // Always use FAST_STACK_CMP for better compatibility
            u32 user_stack_id = bpf_get_stackid(ctx, &user_stackmap, BPF_F_USER_STACK | BPF_F_FAST_STACK_CMP);
            
            // Log the result of getting the user stack
            if ((int)user_stack_id < 0) {
                bpf_printk("Failed to get user stack: error %d for TID %d\n", 
                          (int)user_stack_id, next_tid);
            }

            // Capture kernel stack with FAST_STACK_CMP
            u32 kernel_stack_id = bpf_get_stackid(ctx, &kernel_stackmap, BPF_F_FAST_STACK_CMP);

            // Log stack ID errors with more detail
            if ((int)user_stack_id < 0) {
                bpf_printk("Failed to get user stack ID: error %d for TID %d\n", 
                          (int)user_stack_id, next_tid);
                
                // Provide more info about specific error codes
                if ((int)user_stack_id == -14) {
                    bpf_printk("EFAULT: Failed to access user memory during stack walk\n");
                } else if ((int)user_stack_id == -22) {
                    bpf_printk("EINVAL: Invalid argument to bpf_get_stackid\n");
                } else if ((int)user_stack_id == -12) {
                    bpf_printk("ENOMEM: Out of memory in stack map\n");
                }
            } else {
                bpf_printk("Successfully captured user stack ID: %u for TID %d\n", 
                          user_stack_id, next_tid);
            }
            
            if ((int)kernel_stack_id < 0) {
                bpf_printk("Failed to get kernel stack ID: error %d for TID %d\n", 
                          (int)kernel_stack_id, next_tid);
            } else {
                bpf_printk("Successfully captured kernel stack ID: %u for TID %d\n", 
                          kernel_stack_id, next_tid);
            }
            
            // Prepare event for userspace
            // Use the TID as PID for now - this is a common case for single-threaded processes
            u32 event_pid = get_pid_from_tid(next_tid);

            // Process stack IDs with more sophisticated logic
            // We'll pass through negative values (as unsigned) to provide more debugging info
            // This will allow us to see which error codes are most common
            u32 final_user_stack_id;
            u32 final_kernel_stack_id;
            
            // For user stacks, preserve error codes for analysis but don't use a zero value
            // This ensures we get useful debug info in userspace
            if ((int)user_stack_id < 0) {
                // Pass negative values as large u32 for diagnosis
                final_user_stack_id = user_stack_id;
                bpf_printk("Passing error code as stack ID: %u\n", final_user_stack_id);
            } else if (user_stack_id == 0) {
                // A zero stack ID means empty stack - set to special value
                final_user_stack_id = 1; // Use 1 as a marker for empty stack
                bpf_printk("Empty user stack (ID=0), using value 1 instead\n");
            } else {
                final_user_stack_id = user_stack_id;
            }
            
            // For kernel stacks, use similar logic
            if ((int)kernel_stack_id < 0) {
                final_kernel_stack_id = kernel_stack_id;
            } else if (kernel_stack_id == 0) {
                final_kernel_stack_id = 1;
            } else {
                final_kernel_stack_id = kernel_stack_id;
            }

            struct offcpu_event event = {
                .pid = event_pid,
                .tid = next_tid,
                .prev_state = (u32)ctx->prev_state,
                .offcpu_time_ns = off_cpu_time,
                .start_time_ns = *last_ts,
                .end_time_ns = now,
                .user_stack_id = final_user_stack_id,
                .kernel_stack_id = final_kernel_stack_id,
            };
            
            // Send event to userspace
            bpf_perf_event_output(ctx, &events, BPF_F_CURRENT_CPU, 
                                  &event, sizeof(event));
        }
        
        // Remove entry - we'll add it again when thread goes off-CPU
        bpf_map_delete_elem(&thread_last_offcpu, &next_tid);
    }
    
    return 0;
}

char LICENSE[] SEC("license") = "GPL";