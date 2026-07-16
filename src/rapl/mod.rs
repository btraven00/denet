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

use serde::{Deserialize, Serialize};

/// Energy spent during one sample interval, in joules.
#[derive(Serialize, Deserialize, Debug, Clone, Copy, Default, PartialEq)]
pub struct RaplEnergy {
    /// Total package (socket) energy over the interval — all cores, all processes.
    pub package_joules: f64,
    /// Estimated slice attributed to the monitored process (see module docs).
    pub process_joules: f64,
}

/// Process share of total machine CPU capacity, clamped to [0, 1].
/// `cpu_usage` is percent where 100 = one full core (may exceed 100).
fn cpu_share(cpu_usage: f32, ncpus: usize) -> f64 {
    if ncpus == 0 {
        return 0.0;
    }
    ((cpu_usage as f64 / 100.0) / ncpus as f64).clamp(0.0, 1.0)
}

/// Wrap-safe delta of a cumulative counter that resets at `max`.
fn counter_delta(prev: u64, cur: u64, max: u64) -> u64 {
    if cur >= prev {
        cur - prev
    } else if max > 0 {
        // Counter wrapped past its range.
        max - prev + cur
    } else {
        0
    }
}

#[cfg(target_os = "linux")]
const POWERCAP_DIR: &str = "/sys/class/powercap";

#[cfg(target_os = "linux")]
#[derive(Debug)]
struct Zone {
    energy_path: std::path::PathBuf,
    max_uj: u64,
    last_uj: u64,
}

#[cfg(target_os = "linux")]
fn read_uj(path: &std::path::Path) -> Option<u64> {
    std::fs::read_to_string(path).ok()?.trim().parse().ok()
}

/// A package zone is `intel-rapl:<N>` — top level, no second `:` component.
#[cfg(target_os = "linux")]
fn is_package_zone(name: &str) -> bool {
    match name.strip_prefix("intel-rapl:") {
        Some(rest) => !rest.is_empty() && !rest.contains(':'),
        None => false,
    }
}

/// Stateful RAPL reader. Holds the previous counter per package zone.
#[cfg(target_os = "linux")]
#[derive(Debug)]
pub struct RaplSampler {
    zones: Vec<Zone>,
    ncpus: usize,
}

#[cfg(target_os = "linux")]
impl RaplSampler {
    /// Discover readable package zones and take the initial reading. Returns
    /// `None` if the interface is absent or no zone's `energy_uj` is readable
    /// (typically: not root).
    pub fn new() -> Option<Self> {
        let mut zones = Vec::new();
        for entry in std::fs::read_dir(POWERCAP_DIR).ok()?.flatten() {
            let name = entry.file_name();
            let name = name.to_string_lossy();
            if !is_package_zone(&name) {
                continue;
            }
            let dir = entry.path();
            let energy_path = dir.join("energy_uj");
            let Some(last_uj) = read_uj(&energy_path) else {
                continue; // unreadable (permissions) — skip this zone
            };
            let max_uj = read_uj(&dir.join("max_energy_range_uj")).unwrap_or(0);
            zones.push(Zone {
                energy_path,
                max_uj,
                last_uj,
            });
        }
        if zones.is_empty() {
            return None;
        }
        let ncpus = std::thread::available_parallelism()
            .map(|n| n.get())
            .unwrap_or(1);
        Some(Self { zones, ncpus })
    }

    /// Energy since the previous call. First call after `new()` returns a small
    /// nonzero delta (time between construction and first sample).
    pub fn sample_delta(&mut self, cpu_usage: f32) -> Option<RaplEnergy> {
        let mut total_uj: u64 = 0;
        for z in &mut self.zones {
            let cur = read_uj(&z.energy_path)?;
            total_uj += counter_delta(z.last_uj, cur, z.max_uj);
            z.last_uj = cur;
        }
        let package_joules = total_uj as f64 / 1_000_000.0;
        Some(RaplEnergy {
            package_joules,
            process_joules: package_joules * cpu_share(cpu_usage, self.ncpus),
        })
    }
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

#[cfg(target_os = "linux")]
pub fn detect() -> RaplCapability {
    match RaplSampler::new() {
        Some(s) => RaplCapability {
            available: true,
            zones: s.zones.len(),
            reason: None,
        },
        None => RaplCapability {
            available: false,
            zones: 0,
            reason: Some(
                "no readable intel-rapl package zone (interface absent or needs root)".to_string(),
            ),
        },
    }
}

#[cfg(not(target_os = "linux"))]
#[derive(Debug)]
pub struct RaplSampler;

#[cfg(not(target_os = "linux"))]
impl RaplSampler {
    pub fn new() -> Option<Self> {
        None
    }
    pub fn sample_delta(&mut self, _cpu_usage: f32) -> Option<RaplEnergy> {
        None
    }
}

#[cfg(not(target_os = "linux"))]
pub fn detect() -> RaplCapability {
    RaplCapability {
        available: false,
        zones: 0,
        reason: Some("RAPL is Linux-only".to_string()),
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

    #[cfg(target_os = "linux")]
    #[test]
    fn zone_name_matching() {
        assert!(is_package_zone("intel-rapl:0"));
        assert!(is_package_zone("intel-rapl:1"));
        assert!(!is_package_zone("intel-rapl:0:0")); // sub-zone (core/dram)
        assert!(!is_package_zone("intel-rapl-mmio:0")); // mmio mirror
        assert!(!is_package_zone("intel-rapl:")); // malformed
        assert!(!is_package_zone("other"));
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn detect_does_not_panic() {
        // On a box without root/RAPL this is unavailable with a reason.
        let cap = detect();
        if !cap.available {
            assert!(cap.reason.is_some());
        }
    }
}
