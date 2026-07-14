//! Integration tests for eBPF per-process network byte accounting.
//!
//! Two tiers:
//! - `test_net_monitor_graceful_degradation` always runs (unprivileged OK).
//!   Env hooks let scripts/test_ebpf_caps.sh pin the expected mode:
//!   DENET_EXPECT_EBPF_DENIED=1 asserts degradation actually happened,
//!   DENET_EXPECT_EBPF=1 asserts real eBPF data is flowing.
//! - `*_privileged` tests are #[ignore]d; they need CAP_BPF+CAP_PERFMON or
//!   root. Run via scripts/test_ebpf_caps.sh or:
//!   sudo -E cargo test --features ebpf --test ebpf_net_monitor_tests -- --ignored
#![cfg(all(target_os = "linux", feature = "ebpf"))]

use denet::ebpf::NetMonitor;
use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream, UdpSocket};

fn own_pid() -> u32 {
    std::process::id()
}

/// Privileged tests measure this process's real traffic, so concurrent test
/// bodies would pollute each other's byte counts. Serialize them.
static NET_TEST_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());

fn net_test_guard() -> std::sync::MutexGuard<'static, ()> {
    NET_TEST_LOCK
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner())
}

#[test]
fn test_net_monitor_graceful_degradation() {
    // Constructor is infallible regardless of privilege.
    let mut monitor = NetMonitor::new(vec![own_pid()]).expect("constructor must not fail");
    let metrics = monitor.get_metrics();

    if std::env::var("DENET_EXPECT_EBPF_DENIED").as_deref() == Ok("1") {
        assert!(
            metrics.error.is_some(),
            "expected degradation (no caps), but eBPF attached: {:?}",
            metrics
        );
    }
    if std::env::var("DENET_EXPECT_EBPF").as_deref() == Ok("1") {
        assert!(
            metrics.error.is_none(),
            "expected working eBPF, got error: {:?}",
            metrics.error
        );
    }

    if metrics.error.is_some() {
        // Degraded mode: zeros, and every method is a safe no-op.
        assert_eq!(metrics.rx_bytes, 0);
        assert_eq!(metrics.tx_bytes, 0);
        monitor.update_pids(&[own_pid(), 1]);
        monitor.update_pids(&[own_pid()]);
        let _ = monitor.get_metrics();
    }

    // JSON shape pin: rx/tx always present, error only when set, per_pid
    // omitted while empty (degraded mode never populates it).
    let json = serde_json::to_value(&metrics).unwrap();
    assert!(json.get("rx_bytes").is_some());
    assert!(json.get("tx_bytes").is_some());
    assert_eq!(json.get("error").is_some(), metrics.error.is_some());
    assert_eq!(json.get("per_pid").is_some(), !metrics.per_pid.is_empty());
    assert_eq!(json.get("retired").is_none(), metrics.retired == Default::default());
    if metrics.error.is_some() {
        assert!(metrics.per_pid.is_empty(), "degraded mode leaked per_pid");
    }
}

/// Transfer `total` bytes over localhost TCP within this process, so both
/// endpoints belong to our tgid and rx/tx both see the payload.
fn tcp_localhost_transfer(total: usize) {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = listener.local_addr().unwrap();
    let reader = std::thread::spawn(move || {
        let (mut conn, _) = listener.accept().unwrap();
        let mut buf = [0u8; 64 * 1024];
        let mut seen = 0usize;
        loop {
            match conn.read(&mut buf).unwrap() {
                0 => break,
                n => seen += n,
            }
        }
        seen
    });

    let mut stream = TcpStream::connect(addr).unwrap();
    let chunk = [0xABu8; 64 * 1024];
    let mut sent = 0usize;
    while sent < total {
        let n = chunk.len().min(total - sent);
        stream.write_all(&chunk[..n]).unwrap();
        sent += n;
    }
    drop(stream);
    assert_eq!(reader.join().unwrap(), total);
}

#[test]
#[ignore = "needs CAP_BPF+CAP_PERFMON; run scripts/test_ebpf_caps.sh or sudo -E cargo test -- --ignored"]
fn test_net_monitor_tcp_localhost_privileged() {
    let _guard = net_test_guard();
    const TOTAL: u64 = 5 * 1024 * 1024;
    const SLOP: u64 = 1024 * 1024;

    let monitor = NetMonitor::new(vec![own_pid()]).unwrap();
    let probe = monitor.get_metrics();
    assert!(
        probe.error.is_none(),
        "eBPF attach failed: {:?}",
        probe.error
    );

    tcp_localhost_transfer(TOTAL as usize);

    let m = monitor.get_metrics();
    assert!(
        m.tx_bytes >= TOTAL && m.tx_bytes < TOTAL + SLOP,
        "tx {} outside [{}, {})",
        m.tx_bytes,
        TOTAL,
        TOTAL + SLOP
    );
    assert!(
        m.rx_bytes >= TOTAL && m.rx_bytes < TOTAL + SLOP,
        "rx {} outside [{}, {})",
        m.rx_bytes,
        TOTAL,
        TOTAL + SLOP
    );

    // Per-child breakdown: single-process tree, so our pid is the sole live
    // entry and its bytes equal the aggregate (nothing retired here). This is
    // the same map-iteration path that keys every child tgid separately.
    let own = m.per_pid.get(&own_pid()).expect("own pid missing from per_pid");
    assert_eq!(own.rx_bytes, m.rx_bytes, "per_pid rx != aggregate: {:?}", m);
    assert_eq!(own.tx_bytes, m.tx_bytes, "per_pid tx != aggregate: {:?}", m);
    assert!(
        !m.per_pid.contains_key(&1),
        "unmonitored pid leaked into per_pid: {:?}",
        m
    );

    // Breakdown reconciles exactly: sum(per_pid) + retired == totals.
    let (mut prx, mut ptx) = (m.retired.rx_bytes, m.retired.tx_bytes);
    for b in m.per_pid.values() {
        prx += b.rx_bytes;
        ptx += b.tx_bytes;
    }
    assert_eq!(prx, m.rx_bytes, "per_pid+retired rx != total: {:?}", m);
    assert_eq!(ptx, m.tx_bytes, "per_pid+retired tx != total: {:?}", m);
}

#[test]
#[ignore = "needs CAP_BPF+CAP_PERFMON; run scripts/test_ebpf_caps.sh or sudo -E cargo test -- --ignored"]
fn test_net_monitor_udp_localhost_privileged() {
    let _guard = net_test_guard();
    const DATAGRAMS: usize = 1024;
    const SIZE: usize = 1024;
    const TOTAL: u64 = (DATAGRAMS * SIZE) as u64;
    const SLOP: u64 = 256 * 1024;

    let monitor = NetMonitor::new(vec![own_pid()]).unwrap();
    let probe = monitor.get_metrics();
    assert!(
        probe.error.is_none(),
        "eBPF attach failed: {:?}",
        probe.error
    );

    let rx_sock = UdpSocket::bind("127.0.0.1:0").unwrap();
    let tx_sock = UdpSocket::bind("127.0.0.1:0").unwrap();
    let dst = rx_sock.local_addr().unwrap();
    let payload = [0xCDu8; SIZE];
    let mut buf = [0u8; SIZE];
    for _ in 0..DATAGRAMS {
        tx_sock.send_to(&payload, dst).unwrap();
        // Blocking recv of each datagram: loopback UDP is lossless and
        // ordered, and this keeps the socket buffer from overflowing.
        let (n, _) = rx_sock.recv_from(&mut buf).unwrap();
        assert_eq!(n, SIZE);
    }

    let m = monitor.get_metrics();
    assert!(
        m.tx_bytes >= TOTAL && m.tx_bytes < TOTAL + SLOP,
        "udp tx {} outside [{}, {})",
        m.tx_bytes,
        TOTAL,
        TOTAL + SLOP
    );
    assert!(
        m.rx_bytes >= TOTAL && m.rx_bytes < TOTAL + SLOP,
        "udp rx {} outside [{}, {})",
        m.rx_bytes,
        TOTAL,
        TOTAL + SLOP
    );
}

#[test]
#[ignore = "needs CAP_BPF+CAP_PERFMON; run scripts/test_ebpf_caps.sh or sudo -E cargo test -- --ignored"]
fn test_net_monitor_pid_filter_excludes_others_privileged() {
    let _guard = net_test_guard();
    // Monitor pid 1 (init) — our own traffic must NOT be accounted, proving
    // the filter runs BPF-side rather than in userspace post-filtering.
    let monitor = NetMonitor::new(vec![1]).unwrap();
    let probe = monitor.get_metrics();
    assert!(
        probe.error.is_none(),
        "eBPF attach failed: {:?}",
        probe.error
    );

    tcp_localhost_transfer(1024 * 1024);

    let m = monitor.get_metrics();
    // pid 1 may do minor network I/O of its own (systemd); allow a small
    // budget rather than assert an exact zero.
    assert!(
        m.rx_bytes < 64 * 1024 && m.tx_bytes < 64 * 1024,
        "filter leak: our 1MB transfer showed up under pid 1: {:?}",
        m
    );
}
