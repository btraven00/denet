//! CPU energy via Intel/AMD RAPL exposed through the powercap sysfs interface.
//!
//! `/sys/class/powercap/intel-rapl:<N>/energy_uj` is a **cumulative** microjoule
//! counter per CPU package (socket). It wraps at `max_energy_range_uj`. We read
//! every top-level package zone, diff against the previous sample (wrap-safe),
//! and sum to get the package energy spent this interval — the *total*.
//!
//! We then attribute a *slice* of that total to the monitored process by its
//! share of machine CPU capacity: `(cpu_usage% / 100) / ncpus`. This is a
//! first-order linear model — it ignores per-core DVFS, uncore/DRAM domains,
//! and that an idle package still burns static power.
//!
//! ponytail: linear cpu-share attribution. Upgrade path if it proves too coarse:
//! weight by per-core `intel-rapl:N:0` (pp0/core) energy, or by cpu-time against
//! `/proc/stat` busy time instead of capacity. Left as a knob, not built yet.
//!
//! Reading `energy_uj` is root-only on most kernels (CVE-2020-8694 mitigation),
//! so absence is the common case and degrades to `None`, never an error.
//!
//! The powercap sysfs plumbing lives in `sysfs.rs`, which is excluded from
//! coverage — CI runners can't read `energy_uj` without root. The pure logic
//! it consumes (`cpu_share`, `counter_delta`) lives here and IS covered.

use serde::{Deserialize, Serialize};

mod sysfs;
pub use sysfs::{detect, RaplSampler};

/// Energy spent during one sample interval, in joules.
#[derive(Serialize, Deserialize, Debug, Clone, Copy, Default, PartialEq)]
pub struct RaplEnergy {
    /// Total package (socket) energy over the interval — all cores, all processes.
    pub package_joules: f64,
    /// Estimated slice attributed to the monitored process (see module docs).
    pub process_joules: f64,
}

/// Capability manifest entry for the JSONL header.
#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct RaplCapability {
    pub available: bool,
    /// Number of package zones being read.
    pub zones: usize,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
}

/// Process share of total machine CPU capacity, clamped to [0, 1].
/// `cpu_usage` is percent where 100 = one full core (may exceed 100).
/// Only used by the Linux-gated sampler; `test` keeps it for cross-platform tests.
#[cfg(any(target_os = "linux", test))]
pub(crate) fn cpu_share(cpu_usage: f32, ncpus: usize) -> f64 {
    if ncpus == 0 {
        return 0.0;
    }
    ((cpu_usage as f64 / 100.0) / ncpus as f64).clamp(0.0, 1.0)
}

/// Wrap-safe delta of a cumulative counter that resets at `max`.
/// Only used by the Linux-gated sampler; `test` keeps it for cross-platform tests.
#[cfg(any(target_os = "linux", test))]
pub(crate) fn counter_delta(prev: u64, cur: u64, max: u64) -> u64 {
    if cur >= prev {
        cur - prev
    } else if max > 0 {
        // Counter wrapped past its range.
        max - prev + cur
    } else {
        0
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn wrap_delta_normal() {
        assert_eq!(counter_delta(100, 300, 1000), 200);
    }

    #[test]
    fn wrap_delta_wraps() {
        // prev near max, cur small → wrapped once.
        assert_eq!(counter_delta(900, 100, 1000), 200);
    }

    #[test]
    fn wrap_delta_no_max_clamps_to_zero() {
        // Decreasing counter with no known range: can't tell, report 0.
        assert_eq!(counter_delta(500, 100, 0), 0);
    }

    #[test]
    fn share_single_core_of_four() {
        // 100% (one full core) on a 4-core box = 1/4 of capacity.
        assert!((cpu_share(100.0, 4) - 0.25).abs() < 1e-9);
    }

    #[test]
    fn share_clamps_and_guards() {
        assert_eq!(cpu_share(100.0, 0), 0.0); // no divide-by-zero
        assert_eq!(cpu_share(1000.0, 4), 1.0); // over-100% multi-thread clamps
        assert_eq!(cpu_share(0.0, 8), 0.0);
    }
}
