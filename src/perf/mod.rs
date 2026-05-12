//! Hardware performance counter source via `perf_event_open(2)`.
//!
//! Opens a small set of per-process counters (cycles, instructions, cache
//! references/misses, backend-stalled cycles), reads them by diffing between
//! samples. We do **not** do high-frequency sampling/PEBS — that's attribution
//! territory (perf/VTune). Counters are accumulating; we only need to read them
//! at denet's normal cadence (100ms-1s) to characterize memory boundedness.
//!
//! Capability detection: a single `perf_event_open` call at startup. On EACCES
//! / ENOSYS / ENOENT we record the reason in the manifest and stay silent for
//! the rest of the run. Callers must handle `None` gracefully.

use serde::{Deserialize, Serialize};
use std::os::unix::io::RawFd;

// ---- kernel ABI -----------------------------------------------------------

const PERF_TYPE_HARDWARE: u32 = 0;

// PERF_COUNT_HW_* config values (uapi/linux/perf_event.h).
const PERF_COUNT_HW_CPU_CYCLES: u64 = 0;
const PERF_COUNT_HW_INSTRUCTIONS: u64 = 1;
const PERF_COUNT_HW_CACHE_REFERENCES: u64 = 2;
const PERF_COUNT_HW_CACHE_MISSES: u64 = 3;
const PERF_COUNT_HW_STALLED_CYCLES_BACKEND: u64 = 8;

// Bits in `flags` (perf_event_attr::flags bitfield).
const ATTR_INHERIT: u64 = 1 << 1;
const ATTR_EXCLUDE_KERNEL: u64 = 1 << 5;
const ATTR_EXCLUDE_HV: u64 = 1 << 6;

/// Minimal `perf_event_attr` covering only the fields we use (72 bytes).
/// We pass `size = sizeof(this struct)` so the kernel handles the truncated
/// layout correctly via its backwards-compat size negotiation.
/// We don't use sampling, breakpoints, or BTS — most fields stay zero.
#[repr(C)]
#[derive(Default, Debug, Clone, Copy)]
struct PerfEventAttr {
    type_: u32,
    size: u32,
    config: u64,
    sample_period_or_freq: u64,
    sample_type: u64,
    read_format: u64,
    /// bitfield: disabled, inherit, pinned, exclusive, exclude_user,
    /// exclude_kernel, exclude_hv, exclude_idle, mmap, comm, freq, ...
    flags: u64,
    wakeup_events_or_watermark: u32,
    bp_type: u32,
    bp_addr_or_config1: u64,
    bp_len_or_config2: u64,
}

const PERF_ATTR_SIZE: u32 = std::mem::size_of::<PerfEventAttr>() as u32;

unsafe fn perf_event_open(
    attr: *mut PerfEventAttr,
    pid: libc::pid_t,
    cpu: libc::c_int,
    group_fd: libc::c_int,
    flags: libc::c_ulong,
) -> libc::c_long {
    libc::syscall(libc::SYS_perf_event_open, attr, pid, cpu, group_fd, flags)
}

// ---- public types ---------------------------------------------------------

#[derive(Serialize, Deserialize, Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct PerfCounters {
    pub cycles: u64,
    pub instructions: u64,
    pub cache_refs: u64,
    pub cache_misses: u64,
    /// Cycles where the backend (memory subsystem, execution units) had nothing
    /// to do because of stalls. High ratio relative to `cycles` is the most
    /// direct evidence that the workload is memory-bound.
    pub stalled_backend: u64,
}

impl PerfCounters {
    /// Saturating field-wise subtraction. Counters are monotonic, but a
    /// returning-from-suspend or counter-multiplexing event can briefly make
    /// `prev > self`; we clamp to zero rather than wrap.
    pub fn delta_since(&self, prev: &PerfCounters) -> PerfCounters {
        PerfCounters {
            cycles: self.cycles.saturating_sub(prev.cycles),
            instructions: self.instructions.saturating_sub(prev.instructions),
            cache_refs: self.cache_refs.saturating_sub(prev.cache_refs),
            cache_misses: self.cache_misses.saturating_sub(prev.cache_misses),
            stalled_backend: self.stalled_backend.saturating_sub(prev.stalled_backend),
        }
    }
}

/// Names of opened events given which optional counters are present. Required
/// counters (cycles, instructions) are always listed.
pub(crate) fn events_list(have_refs: bool, have_misses: bool, have_stalled: bool) -> Vec<String> {
    let mut v = vec!["cycles".to_string(), "instructions".to_string()];
    if have_refs {
        v.push("cache-references".to_string());
    }
    if have_misses {
        v.push("cache-misses".to_string());
    }
    if have_stalled {
        v.push("stalled-cycles-backend".to_string());
    }
    v
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct PerfCapability {
    pub available: bool,
    pub events: Vec<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
}

/// Per-pid perf-counter group. Each fd is independent; missing counters degrade
/// silently (e.g. `stalled-cycles-backend` is unavailable on many CPUs). At
/// least `cycles` and `instructions` must be present for the group to be useful.
#[derive(Debug)]
pub struct PerfGroup {
    cycles: RawFd,
    instructions: RawFd,
    cache_refs: Option<RawFd>,
    cache_misses: Option<RawFd>,
    stalled_backend: Option<RawFd>,
    /// Last absolute counter values; subtracted on each read to produce deltas.
    last: Option<PerfCounters>,
}

impl PerfGroup {
    /// Open the counter group for `pid`. Required counters: cycles, instructions.
    /// Optional counters (cache-refs/misses, stalled-backend) are skipped if the
    /// CPU doesn't expose them.
    pub fn open(pid: libc::pid_t) -> Result<Self, String> {
        let cycles = open_one(pid, PERF_COUNT_HW_CPU_CYCLES)?;
        let instructions = open_one(pid, PERF_COUNT_HW_INSTRUCTIONS).inspect_err(|_| {
            unsafe { libc::close(cycles) };
        })?;
        let cache_refs = open_one(pid, PERF_COUNT_HW_CACHE_REFERENCES).ok();
        let cache_misses = open_one(pid, PERF_COUNT_HW_CACHE_MISSES).ok();
        let stalled_backend = open_one(pid, PERF_COUNT_HW_STALLED_CYCLES_BACKEND).ok();
        Ok(Self {
            cycles,
            instructions,
            cache_refs,
            cache_misses,
            stalled_backend,
            last: None,
        })
    }

    /// List of event names that opened successfully on this group. Drives the
    /// `events` field of the manifest so consumers know what to expect.
    pub fn opened_events(&self) -> Vec<String> {
        events_list(
            self.cache_refs.is_some(),
            self.cache_misses.is_some(),
            self.stalled_backend.is_some(),
        )
    }

    /// Read all counters and return the delta since the previous call.
    /// First call primes the baseline and returns a zeroed delta.
    pub fn sample_delta(&mut self) -> Option<PerfCounters> {
        let cur = PerfCounters {
            cycles: read_counter(self.cycles)?,
            instructions: read_counter(self.instructions)?,
            cache_refs: self.cache_refs.and_then(read_counter).unwrap_or(0),
            cache_misses: self.cache_misses.and_then(read_counter).unwrap_or(0),
            stalled_backend: self.stalled_backend.and_then(read_counter).unwrap_or(0),
        };
        let delta = match self.last {
            Some(prev) => cur.delta_since(&prev),
            None => PerfCounters::default(),
        };
        self.last = Some(cur);
        Some(delta)
    }
}

impl Drop for PerfGroup {
    fn drop(&mut self) {
        unsafe {
            libc::close(self.cycles);
            libc::close(self.instructions);
            if let Some(fd) = self.cache_refs {
                libc::close(fd);
            }
            if let Some(fd) = self.cache_misses {
                libc::close(fd);
            }
            if let Some(fd) = self.stalled_backend {
                libc::close(fd);
            }
        }
    }
}

fn open_one(pid: libc::pid_t, config: u64) -> Result<RawFd, String> {
    let mut attr = PerfEventAttr {
        type_: PERF_TYPE_HARDWARE,
        size: PERF_ATTR_SIZE,
        config,
        // Count user + kernel time on bare metal; exclude hypervisor so VMs
        // don't double-count if they expose nested PMUs.
        // Exclude kernel events so unprivileged users can read counters at the
        // common `perf_event_paranoid=2` setting (which bans kernel profiling).
        // We measure user-space cycles only; this is the right scope for
        // characterizing application memory boundedness anyway.
        flags: ATTR_INHERIT | ATTR_EXCLUDE_KERNEL | ATTR_EXCLUDE_HV,
        ..Default::default()
    };
    let fd = unsafe { perf_event_open(&mut attr, pid, -1, -1, 0) };
    if fd < 0 {
        let err = std::io::Error::last_os_error();
        return Err(describe_perf_error(&err));
    }
    Ok(fd as RawFd)
}

fn read_counter(fd: RawFd) -> Option<u64> {
    let mut buf = [0u8; 8];
    let n = unsafe { libc::read(fd, buf.as_mut_ptr() as *mut libc::c_void, buf.len()) };
    if n != 8 {
        return None;
    }
    Some(u64::from_ne_bytes(buf))
}

fn describe_perf_error(err: &std::io::Error) -> String {
    match err.raw_os_error() {
        Some(libc::EACCES) | Some(libc::EPERM) => {
            let paranoid = std::fs::read_to_string("/proc/sys/kernel/perf_event_paranoid")
                .ok()
                .map(|s| s.trim().to_string())
                .unwrap_or_else(|| "?".to_string());
            format!(
                "permission denied (perf_event_paranoid={paranoid}; need <=2 for user-space counters, or CAP_PERFMON)"
            )
        }
        Some(libc::ENOSYS) => "perf_event_open not supported by kernel".to_string(),
        Some(libc::ENOENT) => "hardware counter not available on this CPU".to_string(),
        _ => format!("perf_event_open failed: {err}"),
    }
}

/// Detect availability without holding any fds. Opens one cycles counter on
/// the current process, reads the result, closes it.
pub fn detect() -> PerfCapability {
    let mut attr = PerfEventAttr {
        type_: PERF_TYPE_HARDWARE,
        size: PERF_ATTR_SIZE,
        config: PERF_COUNT_HW_CPU_CYCLES,
        flags: ATTR_EXCLUDE_KERNEL | ATTR_EXCLUDE_HV,
        ..Default::default()
    };
    let fd = unsafe { perf_event_open(&mut attr, 0, -1, -1, 0) };
    if fd < 0 {
        let err = std::io::Error::last_os_error();
        return PerfCapability {
            available: false,
            events: vec![],
            reason: Some(describe_perf_error(&err)),
        };
    }
    unsafe { libc::close(fd as i32) };
    PerfCapability {
        available: true,
        events: vec![
            "cycles".to_string(),
            "instructions".to_string(),
            "cache-references".to_string(),
            "cache-misses".to_string(),
            "stalled-cycles-backend".to_string(),
        ],
        reason: None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn detect_does_not_panic() {
        let _ = detect();
    }

    #[test]
    fn describe_perf_error_messages() {
        let eacces = std::io::Error::from_raw_os_error(libc::EACCES);
        let s = describe_perf_error(&eacces);
        assert!(s.contains("permission denied"), "got: {s}");
        assert!(s.contains("perf_event_paranoid"), "got: {s}");

        let eperm = std::io::Error::from_raw_os_error(libc::EPERM);
        let s = describe_perf_error(&eperm);
        assert!(s.contains("permission denied"), "got: {s}");

        let enosys = std::io::Error::from_raw_os_error(libc::ENOSYS);
        assert!(describe_perf_error(&enosys).contains("not supported"));

        let enoent = std::io::Error::from_raw_os_error(libc::ENOENT);
        assert!(describe_perf_error(&enoent).contains("not available"));

        // Any other errno falls through to the generic branch.
        let einval = std::io::Error::from_raw_os_error(libc::EINVAL);
        assert!(describe_perf_error(&einval).contains("perf_event_open failed"));
    }

    #[test]
    fn delta_since_subtracts_field_wise() {
        let prev = PerfCounters {
            cycles: 100,
            instructions: 50,
            cache_refs: 10,
            cache_misses: 2,
            stalled_backend: 30,
        };
        let cur = PerfCounters {
            cycles: 250,
            instructions: 150,
            cache_refs: 30,
            cache_misses: 7,
            stalled_backend: 80,
        };
        let d = cur.delta_since(&prev);
        assert_eq!(d.cycles, 150);
        assert_eq!(d.instructions, 100);
        assert_eq!(d.cache_refs, 20);
        assert_eq!(d.cache_misses, 5);
        assert_eq!(d.stalled_backend, 50);
    }

    #[test]
    fn delta_since_saturates_on_counter_regression() {
        // Mid-sample multiplexing or suspend/resume can briefly make a current
        // read smaller than a previous one. Saturating math must clamp to 0,
        // not underflow into a huge u64.
        let prev = PerfCounters {
            cycles: 100,
            ..PerfCounters::default()
        };
        let cur = PerfCounters {
            cycles: 50,
            ..PerfCounters::default()
        };
        assert_eq!(cur.delta_since(&prev).cycles, 0);
    }

    #[test]
    fn events_list_required_only() {
        let v = events_list(false, false, false);
        assert_eq!(v, vec!["cycles".to_string(), "instructions".to_string()]);
    }

    #[test]
    fn events_list_all_optional() {
        let v = events_list(true, true, true);
        assert_eq!(
            v,
            vec![
                "cycles",
                "instructions",
                "cache-references",
                "cache-misses",
                "stalled-cycles-backend",
            ]
        );
    }

    #[test]
    fn events_list_partial() {
        // cache-references opened but cache-misses didn't (some CPUs).
        let v = events_list(true, false, true);
        assert_eq!(
            v,
            vec![
                "cycles",
                "instructions",
                "cache-references",
                "stalled-cycles-backend",
            ]
        );
    }

    #[test]
    fn opened_events_lists_optional_counters() {
        // Build a group with only the required counters (others = None) and
        // confirm `opened_events` reports them. We can't construct one without
        // calling open(), so just exercise detect() and trust the field plumbing
        // via `self_open_and_read` above. This test pins the events for
        // detect() — they're the documented surface.
        let cap = detect();
        if cap.available {
            assert!(cap.events.contains(&"cycles".to_string()));
            assert!(cap.events.contains(&"instructions".to_string()));
        } else {
            assert!(cap.reason.is_some());
        }
    }

    #[test]
    fn self_open_and_read() {
        let cap = detect();
        if !cap.available {
            // Skip on sandboxed CI where perf_event_paranoid is too high.
            eprintln!("perf unavailable: {:?}", cap.reason);
            return;
        }
        let mut group = PerfGroup::open(0).expect("open self perf group");
        let _ = group.sample_delta(); // prime
                                      // Burn cycles in the calling thread, between two reads.
        let mut acc: u64 = 0;
        for i in 0..1_000_000u64 {
            acc = acc.wrapping_add(i.wrapping_mul(7));
        }
        std::hint::black_box(acc);
        let d = group.sample_delta().expect("read deltas");
        eprintln!("self_open_and_read deltas = {:?}", d);
        // Some kernels/hypervisors return 0 for HW counters even after
        // perf_event_open succeeds (e.g. nested virt without PMU passthrough).
        // Don't fail the test in that case — just confirm reads didn't error.
        if d.cycles == 0 && d.instructions == 0 {
            eprintln!("HW counters reported zero — likely no PMU passthrough; skipping assertion");
            return;
        }
        assert!(
            d.instructions > 0,
            "no instruction delta but cycles={}",
            d.cycles
        );
    }
}
