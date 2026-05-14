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
//!
//! The syscall plumbing lives in `syscall.rs`, which is excluded from coverage
//! because CI sandboxes deny `perf_event_open` and there's no way to drive that
//! path from a unit test. Everything testable without a real kernel
//! cooperation lives here.

use serde::{Deserialize, Serialize};

mod syscall;
pub use syscall::{detect, PerfGroup};

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

pub(crate) fn describe_perf_error(err: &std::io::Error) -> String {
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

#[cfg(test)]
mod tests {
    use super::*;

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
    fn detect_does_not_panic() {
        let _ = detect();
    }
}
