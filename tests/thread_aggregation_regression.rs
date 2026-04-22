//! Regression test for thread-as-child double-counting.
//!
//! Bug: sysinfo's `ProcessRefreshKind::everything()` enables `tasks: true`,
//! which causes each kernel thread (TID under `/proc/[tgid]/task/`) to appear
//! as its own entry in `System::processes()`. Those task entries report their
//! parent as the tgid, so `find_children_recursive` treated every thread of
//! the monitored process as a child. The aggregate then added each thread's
//! utime+stime on top of the parent's `/proc/[pid]/stat` (which already
//! includes all threads), producing a massive CPU overestimate for workloads
//! like R with BLAS/OpenMP threads.
//!
//! This test spawns a single process with many OS threads and asserts that
//! neither the child list nor the aggregate inflate.

use denet::ProcessMonitor;
use std::process::{Command, Stdio};
use std::time::Duration;

#[test]
#[cfg(target_os = "linux")]
fn threads_are_not_counted_as_child_processes() {
    // Single Python process that spawns 8 busy-loop OS threads. No
    // subprocess.Popen / multiprocessing — so there are zero real children.
    let script = r#"
import threading, time
stop = time.time() + 8
def spin():
    while time.time() < stop:
        pass
ts = [threading.Thread(target=spin, daemon=True) for _ in range(8)]
for t in ts: t.start()
for t in ts: t.join()
"#;

    let mut child = Command::new("python3")
        .arg("-c")
        .arg(script)
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .expect("failed to spawn python3");

    let pid = child.id() as usize;
    let mut monitor = ProcessMonitor::from_pid(
        pid,
        Duration::from_millis(100),
        Duration::from_millis(500),
    )
    .expect("failed to create ProcessMonitor");

    // Let threads come up.
    std::thread::sleep(Duration::from_millis(1500));

    // Prime the CPU sampler (first call returns None).
    let _ = monitor.sample_tree_metrics();
    std::thread::sleep(Duration::from_millis(500));

    let mut max_children = 0usize;
    let mut max_process_count = 0usize;
    let mut worst_ratio: f32 = 0.0;
    let mut saw_nonzero_parent = false;

    for _ in 0..5 {
        let tree = monitor.sample_tree_metrics();
        let parent = tree.parent.expect("parent metrics should exist");
        let agg = tree.aggregated.expect("aggregated metrics should exist");

        max_children = max_children.max(tree.children.len());
        max_process_count = max_process_count.max(agg.process_count);

        if parent.cpu_usage > 1.0 {
            saw_nonzero_parent = true;
            let ratio = agg.cpu_usage / parent.cpu_usage;
            worst_ratio = worst_ratio.max(ratio);
        }

        println!(
            "parent_cpu={:.1}% agg_cpu={:.1}% children={} process_count={} thread_count={}",
            parent.cpu_usage,
            agg.cpu_usage,
            tree.children.len(),
            agg.process_count,
            agg.thread_count,
        );

        std::thread::sleep(Duration::from_millis(300));
    }

    let _ = child.kill();
    let _ = child.wait();

    assert_eq!(
        max_children, 0,
        "threads of the monitored process must not be reported as children"
    );
    assert_eq!(
        max_process_count, 1,
        "aggregate process_count must stay 1 for a single multi-threaded process"
    );

    // With the bug, aggregate ≈ (1 + num_threads) × parent. Without the bug,
    // aggregate == parent. Allow small slack for sampling jitter across the
    // two /proc reads.
    if saw_nonzero_parent {
        assert!(
            worst_ratio < 1.5,
            "aggregate CPU should not exceed parent CPU (ratio={worst_ratio:.2}); \
             this indicates threads are being double-counted as children",
        );
    }
}
