//! Per-process network byte accounting using eBPF kprobes
//!
//! Rust counterpart to `net_monitor.c`: loads the program, seeds the
//! BPF-side PID filter, attaches the TCP/UDP kprobes, and reads cumulative
//! per-tgid byte counts. Unlike the procfs `sys_net_*` path (system-wide),
//! these bytes are attributed to the monitored process tree.
//!
//! Degradation contract: the constructor never fails hard. Load/attach
//! errors (missing capabilities, locked-down kernel) surface as an error
//! string in the returned metrics, and all methods become safe no-ops.

use crate::ebpf::metrics::NetworkMetrics;
use crate::error::{DenetError, Result};
use std::collections::HashSet;

use aya::{maps::HashMap as BpfHashMap, programs::KProbe, Ebpf};

// 8-byte alignment required by the `object` crate's ELF parser (it casts the
// slice directly to FileHeader64). Same pattern as syscall_tracker.rs.
#[repr(align(8))]
struct AlignedBytes<const N: usize>([u8; N]);

static NET_MONITOR_BYTECODE_ALIGNED: AlignedBytes<
    { include_bytes!(concat!(env!("OUT_DIR"), "/ebpf/net_monitor.o")).len() },
> = AlignedBytes(*include_bytes!(concat!(
    env!("OUT_DIR"),
    "/ebpf/net_monitor.o"
)));

const NET_MONITOR_BYTECODE: &[u8] = &NET_MONITOR_BYTECODE_ALIGNED.0;

// Map value layout: [rx_bytes, tx_bytes]. Matches struct net_bytes_val in
// net_monitor.c; a plain array keeps aya's Pod requirement satisfied for free.
type NetBytesMap = BpfHashMap<aya::maps::MapData, u32, [u64; 2]>;
type PidFilterMap = BpfHashMap<aya::maps::MapData, u32, u8>;

/// Per-process network byte monitor (TCP v4/v6 + UDP v4).
pub struct NetMonitor {
    _bpf: Option<Ebpf>,
    net_bytes: Option<NetBytesMap>,
    pid_filter: Option<PidFilterMap>,
    monitored_pids: HashSet<u32>,
    /// Bytes from pids that exited: folded in before their map entries are
    /// deleted, so cumulative totals never regress.
    retired_rx: u64,
    retired_tx: u64,
    init_error: Option<String>,
}

impl std::fmt::Debug for NetMonitor {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("NetMonitor")
            .field("bpf_loaded", &self._bpf.is_some())
            .field("monitored_pids", &self.monitored_pids)
            .field("init_error", &self.init_error)
            .finish()
    }
}

impl NetMonitor {
    /// Create a monitor for the given process tree. Never fails hard: on
    /// load/attach errors the monitor degrades to reporting the error via
    /// metrics.
    pub fn new(pids: Vec<u32>) -> Result<Self> {
        let monitored_pids: HashSet<u32> = pids.into_iter().collect();
        match Self::init_ebpf(&monitored_pids) {
            Ok((bpf, net_bytes, pid_filter)) => {
                log::info!("eBPF net monitor initialized");
                Ok(Self {
                    _bpf: Some(bpf),
                    net_bytes: Some(net_bytes),
                    pid_filter: Some(pid_filter),
                    monitored_pids,
                    retired_rx: 0,
                    retired_tx: 0,
                    init_error: None,
                })
            }
            Err(e) => {
                log::warn!("eBPF net monitor unavailable: {}", e);
                Ok(Self {
                    _bpf: None,
                    net_bytes: None,
                    pid_filter: None,
                    monitored_pids,
                    retired_rx: 0,
                    retired_tx: 0,
                    init_error: Some(e.to_string()),
                })
            }
        }
    }

    fn init_ebpf(pids: &HashSet<u32>) -> Result<(Ebpf, NetBytesMap, PidFilterMap)> {
        let mut bpf = Ebpf::load(NET_MONITOR_BYTECODE).map_err(|e| {
            DenetError::EbpfInitError(format!("failed to load net_monitor bytecode: {}", e))
        })?;

        // Seed the PID filter BEFORE attaching: maps exist after Ebpf::load,
        // so there is no window where probes run against an empty filter and
        // monitored bytes are dropped.
        let mut pid_filter: PidFilterMap = bpf
            .take_map("pid_filter")
            .ok_or_else(|| DenetError::EbpfInitError("pid_filter map not found".to_string()))
            .and_then(|m| {
                BpfHashMap::try_from(m).map_err(|e| {
                    DenetError::EbpfInitError(format!("pid_filter map has unexpected shape: {}", e))
                })
            })?;
        for pid in pids {
            pid_filter.insert(pid, 1, 0).map_err(|e| {
                DenetError::EbpfInitError(format!("failed to seed pid_filter: {}", e))
            })?;
        }

        for (prog_name, fn_name) in [
            ("trace_tcp_sendmsg", "tcp_sendmsg"),
            ("trace_tcp_recvmsg_ret", "tcp_recvmsg"),
            ("trace_udp_sendmsg", "udp_sendmsg"),
            ("trace_udp_recvmsg_ret", "udp_recvmsg"),
        ] {
            let program: &mut KProbe = bpf
                .program_mut(prog_name)
                .ok_or_else(|| {
                    DenetError::EbpfInitError(format!(
                        "program {} not found in bytecode",
                        prog_name
                    ))
                })?
                .try_into()
                .map_err(|e| {
                    DenetError::EbpfInitError(format!("{} is not a kprobe: {}", prog_name, e))
                })?;
            program.load().map_err(|e| {
                DenetError::EbpfInitError(format!("failed to load {}: {}", prog_name, e))
            })?;
            program.attach(fn_name, 0).map_err(|e| {
                DenetError::EbpfInitError(format!(
                    "failed to attach {} to {}: {}",
                    prog_name, fn_name, e
                ))
            })?;
        }

        let net_bytes = bpf
            .take_map("net_bytes")
            .ok_or_else(|| DenetError::EbpfInitError("net_bytes map not found".to_string()))
            .and_then(|m| {
                BpfHashMap::try_from(m).map_err(|e| {
                    DenetError::EbpfInitError(format!("net_bytes map has unexpected shape: {}", e))
                })
            })?;

        Ok((bpf, net_bytes, pid_filter))
    }

    /// Sync the BPF-side PID filter with the current process tree. Bytes of
    /// pids that left the tree are folded into the retired accumulators
    /// before their map entries are removed, keeping totals monotonic.
    /// Safe no-op when degraded.
    pub fn update_pids(&mut self, pids: &[u32]) {
        let (Some(net_bytes), Some(pid_filter)) =
            (self.net_bytes.as_mut(), self.pid_filter.as_mut())
        else {
            return;
        };

        let new: HashSet<u32> = pids.iter().copied().collect();
        for gone in self.monitored_pids.difference(&new) {
            if let Ok([rx, tx]) = net_bytes.get(gone, 0) {
                self.retired_rx += rx;
                self.retired_tx += tx;
            }
            let _ = net_bytes.remove(gone);
            let _ = pid_filter.remove(gone);
        }
        for added in new.difference(&self.monitored_pids) {
            if let Err(e) = pid_filter.insert(added, 1, 0) {
                log::warn!("failed to add pid {} to net filter: {}", added, e);
            }
        }
        self.monitored_pids = new;
    }

    /// Cumulative bytes for the monitored tree since attach, including
    /// already-exited pids. The BPF-side filter guarantees every map entry
    /// belongs to the tree, so the whole map is summed.
    pub fn get_metrics(&self) -> NetworkMetrics {
        let Some(ref map) = self.net_bytes else {
            return NetworkMetrics {
                rx_bytes: 0,
                tx_bytes: 0,
                error: self.init_error.clone(),
            };
        };

        let (mut rx, mut tx) = (self.retired_rx, self.retired_tx);
        for (_tgid, [r, t]) in map.iter().flatten() {
            rx += r;
            tx += t;
        }
        NetworkMetrics {
            rx_bytes: rx,
            tx_bytes: tx,
            error: None,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_net_monitor_creation_is_infallible() {
        // Must construct without error even unprivileged: load/attach failures
        // surface through metrics.error, never a panic or Err.
        let monitor = NetMonitor::new(vec![std::process::id()]).unwrap();
        let metrics = monitor.get_metrics();
        if metrics.error.is_some() {
            assert_eq!(metrics.rx_bytes, 0);
            assert_eq!(metrics.tx_bytes, 0);
        }
    }

    #[test]
    fn test_update_pids_safe_when_degraded() {
        let mut monitor = NetMonitor::new(vec![1]).unwrap();
        // Regardless of privilege, repeated update/get must not panic.
        monitor.update_pids(&[1, 2, 3]);
        monitor.update_pids(&[3]);
        let _ = monitor.get_metrics();
        let _ = monitor.get_metrics();
    }
}
