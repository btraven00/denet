//! `perf_event_open(2)` syscall plumbing. Isolated here so the pure logic in
//! `super` can be unit-tested independently — this file's body is unreachable
//! in standard CI sandboxes (perf_event_paranoid > 2 / no CAP_PERFMON) and is
//! excluded from coverage in `codecov.yml`. Anything testable without a real
//! kernel cooperation belongs in `super`, not here.

use super::{describe_perf_error, events_list, PerfCapability, PerfCounters};
use std::os::unix::io::RawFd;

const PERF_TYPE_HARDWARE: u32 = 0;

// PERF_COUNT_HW_* config values (uapi/linux/perf_event.h).
const PERF_COUNT_HW_CPU_CYCLES: u64 = 0;
const PERF_COUNT_HW_INSTRUCTIONS: u64 = 1;
const PERF_COUNT_HW_CACHE_REFERENCES: u64 = 2;
const PERF_COUNT_HW_CACHE_MISSES: u64 = 3;
const PERF_COUNT_HW_STALLED_CYCLES_BACKEND: u64 = 8;

const ATTR_INHERIT: u64 = 1 << 1;
const ATTR_EXCLUDE_KERNEL: u64 = 1 << 5;
const ATTR_EXCLUDE_HV: u64 = 1 << 6;

/// Minimal `perf_event_attr` covering only the fields we use (72 bytes).
/// We pass `size = sizeof(this struct)` so the kernel handles the truncated
/// layout correctly via its backwards-compat size negotiation.
#[repr(C)]
#[derive(Default, Debug, Clone, Copy)]
struct PerfEventAttr {
    type_: u32,
    size: u32,
    config: u64,
    sample_period_or_freq: u64,
    sample_type: u64,
    read_format: u64,
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

/// Per-pid perf-counter group. Required counters: cycles, instructions.
/// Optional counters degrade silently when the CPU doesn't expose them.
#[derive(Debug)]
pub struct PerfGroup {
    cycles: RawFd,
    instructions: RawFd,
    cache_refs: Option<RawFd>,
    cache_misses: Option<RawFd>,
    stalled_backend: Option<RawFd>,
    last: Option<PerfCounters>,
}

impl PerfGroup {
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

    pub fn opened_events(&self) -> Vec<String> {
        events_list(
            self.cache_refs.is_some(),
            self.cache_misses.is_some(),
            self.stalled_backend.is_some(),
        )
    }

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
        events: events_list(true, true, true),
        reason: None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn self_open_and_read() {
        let cap = detect();
        if !cap.available {
            eprintln!("perf unavailable: {:?}", cap.reason);
            return;
        }
        let mut group = PerfGroup::open(0).expect("open self perf group");
        let _ = group.sample_delta();
        let mut acc: u64 = 0;
        for i in 0..1_000_000u64 {
            acc = acc.wrapping_add(i.wrapping_mul(7));
        }
        std::hint::black_box(acc);
        let d = group.sample_delta().expect("read deltas");
        // Some kernels/hypervisors return 0 for HW counters even after
        // perf_event_open succeeds (e.g. nested virt without PMU passthrough).
        // Don't fail the test in that case — confirm reads didn't error.
        if d.cycles == 0 && d.instructions == 0 {
            return;
        }
        assert!(
            d.instructions > 0,
            "no instruction delta but cycles={}",
            d.cycles
        );
    }
}
