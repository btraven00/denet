//! Per-process-tree TCP byte counts without eBPF.
//!
//! `/proc/<pid>/net/dev` (the `sys_net_*` fields) counts every interface in the
//! process's network namespace: on a normal host, the whole machine's traffic.
//! TCP keeps per-socket byte counters (`tcp_info.tcpi_bytes_received` /
//! `tcpi_bytes_acked`, Linux >= 4.2) that any user can read for every socket
//! through `NETLINK_SOCK_DIAG`, as `ss -ti` does. We list the socket inodes the
//! tree holds open (`/proc/<pid>/fd`), dump all TCP sockets once per sample and
//! keep the ones that match.
//!
//! `bytes_acked` also counts the SYN and FIN as a byte each, so sent bytes
//! read up to 2 high per connection.
//!
//! Limits: TCP only (UDP and unix sockets keep no byte counters); bytes moved
//! by a socket after its last sample before it closes are lost, as with disk
//! counters at process exit; a tree in another network namespace than denet's
//! reports nothing (`None`), since its sockets are not in our dump.

use std::collections::{HashMap, HashSet};
use std::io;

const SOCK_DIAG_BY_FAMILY: u16 = 20;
const INET_DIAG_INFO: u16 = 2;
/// `struct inet_diag_msg`: idiag_inode is its last field.
const DIAG_MSG_LEN: usize = 72;
const DIAG_MSG_INODE: usize = 68;
/// Offsets in `struct tcp_info` (include/uapi/linux/tcp.h).
const TCPI_BYTES_ACKED: usize = 120;
const TCPI_BYTES_RECEIVED: usize = 128;

/// Socket inodes held open by `pid` (`socket:[N]` fd links).
pub fn socket_inodes(pid: usize, out: &mut HashSet<u64>) {
    let Ok(dir) = std::fs::read_dir(format!("/proc/{pid}/fd")) else {
        return;
    };
    for e in dir.flatten() {
        if let Ok(target) = std::fs::read_link(e.path()) {
            let t = target.to_string_lossy();
            if let Some(n) = t.strip_prefix("socket:[").and_then(|s| s.strip_suffix(']')) {
                if let Ok(ino) = n.parse() {
                    out.insert(ino);
                }
            }
        }
    }
}

/// Parse a `SOCK_DIAG_BY_FAMILY` dump: inode -> (bytes received, bytes acked).
/// Returns `Ok(true)` once the dump's `NLMSG_DONE` is seen.
pub(crate) fn parse_dump(buf: &[u8], out: &mut HashMap<u64, (u64, u64)>) -> io::Result<bool> {
    let u16_at = |b: &[u8], o: usize| u16::from_ne_bytes([b[o], b[o + 1]]);
    let u32_at = |b: &[u8], o: usize| u32::from_ne_bytes(b[o..o + 4].try_into().unwrap());
    let u64_at = |b: &[u8], o: usize| u64::from_ne_bytes(b[o..o + 8].try_into().unwrap());
    let mut off = 0;
    while off + 16 <= buf.len() {
        let len = u32_at(buf, off) as usize;
        let kind = u16_at(buf, off + 4);
        if len < 16 || off + len > buf.len() {
            break;
        }
        match kind as i32 {
            libc::NLMSG_DONE => return Ok(true),
            libc::NLMSG_ERROR => {
                let errno = buf.get(off + 16..off + 20).map(|b| u32_at(b, 0) as i32);
                return Err(io::Error::from_raw_os_error(-errno.unwrap_or(-libc::EIO)));
            }
            _ if kind == SOCK_DIAG_BY_FAMILY && len >= 16 + DIAG_MSG_LEN => {
                let msg = &buf[off + 16..off + len];
                let inode = u32_at(msg, DIAG_MSG_INODE) as u64;
                // rtattrs: u16 len (incl. 4-byte header), u16 type, payload, 4-aligned
                let mut a = DIAG_MSG_LEN;
                while a + 4 <= msg.len() {
                    let alen = u16_at(msg, a) as usize;
                    if alen < 4 || a + alen > msg.len() {
                        break;
                    }
                    if u16_at(msg, a + 2) == INET_DIAG_INFO && alen >= 4 + TCPI_BYTES_RECEIVED + 8 {
                        let info = &msg[a + 4..a + alen];
                        out.insert(
                            inode,
                            (
                                u64_at(info, TCPI_BYTES_RECEIVED),
                                u64_at(info, TCPI_BYTES_ACKED),
                            ),
                        );
                    }
                    a += (alen + 3) & !3;
                }
            }
            _ => {}
        }
        off += (len + 3) & !3;
    }
    Ok(false)
}

/// Dump every TCP socket (IPv4 and IPv6) with its byte counters.
pub fn dump_tcp() -> io::Result<HashMap<u64, (u64, u64)>> {
    let mut out = HashMap::new();
    for family in [libc::AF_INET, libc::AF_INET6] {
        dump_family(family as u8, &mut out)?;
    }
    Ok(out)
}

fn dump_family(family: u8, out: &mut HashMap<u64, (u64, u64)>) -> io::Result<()> {
    // SAFETY: plain socket syscalls on a fd we own and close below.
    let fd = unsafe {
        libc::socket(
            libc::AF_NETLINK,
            libc::SOCK_DGRAM | libc::SOCK_CLOEXEC,
            libc::NETLINK_SOCK_DIAG,
        )
    };
    if fd < 0 {
        return Err(io::Error::last_os_error());
    }
    let res = (|| {
        // nlmsghdr (16) + inet_diag_req_v2 (56): family, protocol, ext, pad,
        // states, then a zeroed inet_diag_sockid.
        let mut req = [0u8; 72];
        req[0..4].copy_from_slice(&72u32.to_ne_bytes());
        req[4..6].copy_from_slice(&SOCK_DIAG_BY_FAMILY.to_ne_bytes());
        let flags = (libc::NLM_F_REQUEST | libc::NLM_F_DUMP) as u16;
        req[6..8].copy_from_slice(&flags.to_ne_bytes());
        req[16] = family;
        req[17] = libc::IPPROTO_TCP as u8;
        req[18] = 1 << (INET_DIAG_INFO - 1);
        req[20..24].copy_from_slice(&u32::MAX.to_ne_bytes()); // all states
                                                              // SAFETY: req outlives the call; kernel address is the zeroed sockaddr_nl.
        let mut addr: libc::sockaddr_nl = unsafe { std::mem::zeroed() };
        addr.nl_family = libc::AF_NETLINK as u16;
        let sent = unsafe {
            libc::sendto(
                fd,
                req.as_ptr().cast(),
                req.len(),
                0,
                (&addr as *const libc::sockaddr_nl).cast(),
                std::mem::size_of::<libc::sockaddr_nl>() as u32,
            )
        };
        if sent < 0 {
            return Err(io::Error::last_os_error());
        }
        let mut buf = vec![0u8; 32 * 1024];
        loop {
            // SAFETY: buf is valid for buf.len() bytes.
            let n = unsafe { libc::recv(fd, buf.as_mut_ptr().cast(), buf.len(), 0) };
            if n < 0 {
                return Err(io::Error::last_os_error());
            }
            if n == 0 || parse_dump(&buf[..n as usize], out)? {
                return Ok(());
            }
        }
    })();
    unsafe { libc::close(fd) };
    res
}

/// Whether `pid` shares denet's network namespace (its sockets are in our dump).
pub fn same_netns(pid: usize) -> bool {
    let ns = |p: &str| std::fs::read_link(format!("/proc/{p}/ns/net")).ok();
    match (ns("self"), ns(&pid.to_string())) {
        (Some(a), Some(b)) => a == b,
        _ => false,
    }
}

/// (received, sent)
type Bytes = (u64, u64);

/// Cumulative TCP bytes of a process tree since monitoring started.
#[derive(Debug, Default)]
pub struct TcpTracker {
    started: bool,
    /// Decided at the first sample: the root may be gone by the last one.
    same_netns: Option<bool>,
    /// inode -> (counters when first seen, last counters seen)
    sockets: HashMap<u64, (Bytes, Bytes)>,
}

impl TcpTracker {
    /// Sample the tree's sockets; `(received, sent)` since the first sample,
    /// or `None` if the tree is not in denet's network namespace or the dump
    /// fails.
    pub fn sample(&mut self, pids: &[usize]) -> Option<(u64, u64)> {
        let root = *pids.first()?;
        if !*self.same_netns.get_or_insert_with(|| same_netns(root)) {
            return None;
        }
        let mut inodes = HashSet::new();
        for &p in pids {
            socket_inodes(p, &mut inodes);
        }
        let all = dump_tcp().ok()?;
        Some(self.update(&inodes, &all))
    }

    pub(crate) fn update(
        &mut self,
        inodes: &HashSet<u64>,
        all: &HashMap<u64, (u64, u64)>,
    ) -> (u64, u64) {
        let first = !self.started;
        self.started = true;
        for ino in inodes {
            if let Some(&cur) = all.get(ino) {
                // Sockets open at the first sample count from then; later ones
                // from zero, as they were opened during the run.
                let base = if first { cur } else { (0, 0) };
                self.sockets.entry(*ino).or_insert((base, cur)).1 = cur;
            }
        }
        // ponytail: closed sockets stay in the map (16 bytes each) so their
        // bytes keep counting; prune if a run ever opens millions of sockets.
        self.sockets.values().fold((0, 0), |(r, s), (b, c)| {
            (r + c.0.saturating_sub(b.0), s + c.1.saturating_sub(b.1))
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// One SOCK_DIAG_BY_FAMILY message carrying a tcp_info attribute, then DONE.
    fn canned(inode: u32, rx: u64, tx: u64) -> Vec<u8> {
        let mut info = vec![0u8; 232];
        info[TCPI_BYTES_ACKED..TCPI_BYTES_ACKED + 8].copy_from_slice(&tx.to_ne_bytes());
        info[TCPI_BYTES_RECEIVED..TCPI_BYTES_RECEIVED + 8].copy_from_slice(&rx.to_ne_bytes());
        let mut msg = vec![0u8; DIAG_MSG_LEN];
        msg[DIAG_MSG_INODE..DIAG_MSG_INODE + 4].copy_from_slice(&inode.to_ne_bytes());
        // an unrelated attribute first (type 1, 5-byte payload, padded)
        msg.extend_from_slice(&9u16.to_ne_bytes());
        msg.extend_from_slice(&1u16.to_ne_bytes());
        msg.extend_from_slice(&[0; 8]);
        msg.extend_from_slice(&((4 + info.len()) as u16).to_ne_bytes());
        msg.extend_from_slice(&INET_DIAG_INFO.to_ne_bytes());
        msg.extend_from_slice(&info);
        let mut buf = Vec::new();
        buf.extend_from_slice(&((16 + msg.len()) as u32).to_ne_bytes());
        buf.extend_from_slice(&SOCK_DIAG_BY_FAMILY.to_ne_bytes());
        buf.extend_from_slice(&[0; 10]);
        buf.extend_from_slice(&msg);
        let mut done = vec![0u8; 20];
        done[0..4].copy_from_slice(&20u32.to_ne_bytes());
        done[4..6].copy_from_slice(&(libc::NLMSG_DONE as u16).to_ne_bytes());
        buf.extend_from_slice(&done);
        buf
    }

    #[test]
    fn parses_tcp_info_bytes_and_stops_at_done() {
        let mut out = HashMap::new();
        assert!(parse_dump(&canned(4242, 5_000_000, 1234), &mut out).unwrap());
        assert_eq!(out.get(&4242), Some(&(5_000_000, 1234)));
    }

    #[test]
    fn netlink_error_is_reported() {
        let mut buf = vec![0u8; 36];
        buf[0..4].copy_from_slice(&36u32.to_ne_bytes());
        buf[4..6].copy_from_slice(&(libc::NLMSG_ERROR as u16).to_ne_bytes());
        buf[16..20].copy_from_slice(&(-libc::EPERM).to_ne_bytes());
        let err = parse_dump(&buf, &mut HashMap::new()).unwrap_err();
        assert_eq!(err.raw_os_error(), Some(libc::EPERM));
    }

    #[test]
    fn tracker_counts_new_sockets_from_zero_and_keeps_closed_ones() {
        let mut t = TcpTracker::default();
        let set = |v: &[u64]| v.iter().copied().collect::<HashSet<_>>();
        // socket 1 already open at the first sample: counts from 100/10
        let mut all = HashMap::from([(1, (100, 10)), (9, (999, 999))]);
        assert_eq!(t.update(&set(&[1]), &all), (0, 0));
        // socket 2 opened during the run: counts from zero; 9 is not ours
        all.insert(1, (150, 30));
        all.insert(2, (40, 4));
        assert_eq!(t.update(&set(&[1, 2]), &all), (90, 24));
        // socket 1 closed: its last-seen bytes still count
        all.remove(&1);
        all.insert(2, (60, 6));
        assert_eq!(t.update(&set(&[2]), &all), (110, 26));
    }

    #[test]
    fn own_loopback_connection_is_counted() {
        use std::io::{Read, Write};
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        let reader = std::thread::spawn(move || {
            let (mut s, _) = listener.accept().unwrap();
            let mut buf = Vec::new();
            s.read_to_end(&mut buf).unwrap();
            buf.len()
        });
        let mut c = std::net::TcpStream::connect(addr).unwrap();
        c.write_all(&vec![7u8; 1 << 20]).unwrap();
        c.flush().unwrap();
        std::thread::sleep(std::time::Duration::from_millis(100));
        let mut inodes = HashSet::new();
        socket_inodes(std::process::id() as usize, &mut inodes);
        let all = dump_tcp().unwrap();
        drop(c);
        assert_eq!(reader.join().unwrap(), 1 << 20);
        let (rx, tx) = inodes
            .iter()
            .filter_map(|i| all.get(i))
            .fold((0, 0), |(r, s), &(a, b)| (r + a, s + b));
        // Both ends live in this process: 1 MiB sent and 1 MiB received;
        // bytes_acked also counts the SYN (and FIN) as one byte each.
        assert_eq!(rx, 1 << 20);
        assert!((1 << 20..=(1 << 20) + 4).contains(&tx), "{tx}");
    }
}
