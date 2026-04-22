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
    let mut monitor =
        ProcessMonitor::from_pid(pid, Duration::from_millis(100), Duration::from_millis(500))
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

/// Mirror of the above: when a process DOES spawn real subprocesses (separate
/// tgids, not threads), they must still be detected and aggregated. Guards
/// against over-correcting the thread fix and accidentally filtering real
/// children.
#[test]
#[cfg(target_os = "linux")]
fn real_subprocesses_are_still_detected() {
    const N_CHILDREN: usize = 3;

    // Parent python spawns N child python processes via subprocess.Popen; each
    // child busy-loops on CPU. Parent itself sleeps (near 0% CPU) so the
    // aggregate comes almost entirely from the children — makes the
    // assertions cleaner.
    let script = format!(
        r#"
import subprocess, sys, time
child_code = "t=__import__('time').time()+8\nwhile __import__('time').time()<t: pass"
kids = [subprocess.Popen([sys.executable, "-c", child_code]) for _ in range({N_CHILDREN})]
time.sleep(7)
for k in kids:
    k.terminate()
    k.wait()
"#
    );

    let mut parent = Command::new("python3")
        .arg("-c")
        .arg(&script)
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .expect("failed to spawn python3 parent");

    let parent_pid = parent.id() as usize;
    let mut monitor = ProcessMonitor::from_pid(
        parent_pid,
        Duration::from_millis(100),
        Duration::from_millis(500),
    )
    .expect("failed to create ProcessMonitor");

    // Let the children come up and start burning CPU.
    std::thread::sleep(Duration::from_millis(2000));

    // Prime the CPU sampler.
    let _ = monitor.sample_tree_metrics();
    std::thread::sleep(Duration::from_millis(500));

    let mut max_children_seen = 0usize;
    let mut max_agg_cpu: f32 = 0.0;
    let mut max_process_count = 0usize;

    for _ in 0..5 {
        let tree = monitor.sample_tree_metrics();
        let agg = tree.aggregated.expect("aggregated metrics should exist");

        max_children_seen = max_children_seen.max(tree.children.len());
        max_process_count = max_process_count.max(agg.process_count);
        max_agg_cpu = max_agg_cpu.max(agg.cpu_usage);

        println!(
            "children={} process_count={} agg_cpu={:.1}% children_pids={:?}",
            tree.children.len(),
            agg.process_count,
            agg.cpu_usage,
            tree.children.iter().map(|c| c.pid).collect::<Vec<_>>(),
        );

        std::thread::sleep(Duration::from_millis(400));
    }

    let _ = parent.kill();
    let _ = parent.wait();

    assert_eq!(
        max_children_seen, N_CHILDREN,
        "parent should have exactly {N_CHILDREN} real subprocesses detected",
    );
    assert_eq!(
        max_process_count,
        N_CHILDREN + 1,
        "aggregate process_count should be parent + {N_CHILDREN} children",
    );
    // Each child busy-loops on one core → ~100% each. Allow generous slack
    // for test jitter and slow CI; assert at least ~1.5 cores of aggregate
    // work, which can only come from real children (parent is ~idle).
    assert!(
        max_agg_cpu > 150.0,
        "aggregate CPU should reflect {N_CHILDREN} busy children (got {max_agg_cpu:.1}%)",
    );
}
