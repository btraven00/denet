//! Powercap sysfs plumbing for RAPL. Excluded from coverage (see codecov.yml):
//! reading `energy_uj` needs root, so CI can't exercise these paths. The pure
//! logic these methods call lives in the parent module and is covered there.

#[cfg(target_os = "linux")]
use super::{counter_delta, cpu_share};
use super::{RaplCapability, RaplEnergy};

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

    #[test]
    fn detect_does_not_panic() {
        // On a box without root/RAPL this is unavailable with a reason.
        let cap = detect();
        if !cap.available {
            assert!(cap.reason.is_some());
        }
    }
}
