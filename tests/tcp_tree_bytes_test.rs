//! Per-tree TCP bytes (sock_diag, no eBPF): a child pair moves a known volume
//! over loopback; the tree's tcp_* fields must report it, and sys_net_* (which
//! skips loopback) must not.

#[test]
#[cfg(target_os = "linux")]
fn tcp_bytes_of_the_tree_match_a_known_transfer() {
    use denet::ProcessMonitor;
    use std::time::Duration;

    const BYTES: usize = 5_000_000;
    let port = std::net::TcpListener::bind("127.0.0.1:0")
        .unwrap()
        .local_addr()
        .unwrap()
        .port();
    // Server and client are separate processes in the tree; each holds its
    // socket open for a second after the transfer so a sample sees the totals.
    let server = format!(
        "import socket,time\n\
         s=socket.socket(); s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)\n\
         s.bind(('127.0.0.1',{port})); s.listen(1); c,_=s.accept(); n=0\n\
         while n<{BYTES}: n+=len(c.recv(65536))\n\
         time.sleep(1)"
    );
    let client = format!(
        "import socket,time\n\
         c=socket.create_connection(('127.0.0.1',{port})); c.sendall(b'x'*{BYTES}); time.sleep(1)"
    );
    let cmd = vec![
        "sh".to_string(),
        "-c".to_string(),
        format!("python3 -c \"{server}\" & sleep 0.3; python3 -c \"{client}\"; wait"),
    ];
    let mut mon = ProcessMonitor::new_with_options(
        cmd,
        Duration::from_millis(100),
        Duration::from_millis(100),
        false,
    )
    .unwrap();
    let mut last = None;
    while mon.is_running() {
        last = Some(mon.sample_tree_metrics().aggregated.unwrap());
        std::thread::sleep(Duration::from_millis(100));
    }
    let agg = last.expect("no samples");
    let (rx, tx) = (agg.tcp_rx_bytes.unwrap(), agg.tcp_tx_bytes.unwrap());
    println!(
        "tcp rx {rx} tx {tx}; sys_net rx {} tx {}",
        agg.sys_net_rx_bytes, agg.sys_net_tx_bytes
    );
    let near = |v: u64| (v as f64 - BYTES as f64).abs() / (BYTES as f64) < 0.02;
    assert!(near(rx), "received {rx}");
    assert!(near(tx), "sent {tx}");
    // Loopback is excluded from sys_net; other host traffic over ~3 s is far
    // below the transfer.
    assert!(agg.sys_net_rx_bytes < BYTES as u64 / 2);
}
