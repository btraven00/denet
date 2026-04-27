//! Pressure Stall Information (PSI) memory pressure source.
//!
//! Reads `/proc/pressure/memory` (system-wide) and `/proc/<pid>/pressure/memory`
//! (per-process; cgroup v2 + kernel >= 5.2). PSI exposes how much wall-clock time
//! tasks spent waiting on memory — a direct "is the workload memory-pressured?"
//! signal that doesn't need any capability beyond reading the file.
//!
//! File format (two lines):
//! ```text
//! some avg10=0.00 avg60=0.00 avg300=0.00 total=0
//! full avg10=0.00 avg60=0.00 avg300=0.00 total=0
//! ```
//! `some` = at least one task stalled. `full` = every runnable task stalled.

use serde::{Deserialize, Serialize};

const SYSTEM_PSI_PATH: &str = "/proc/pressure/memory";

#[derive(Serialize, Deserialize, Debug, Clone, Copy, Default, PartialEq)]
pub struct PsiMem {
    /// Fraction of the last 10s window in which at least one task stalled on memory.
    pub some_avg10: f32,
    /// Fraction of the last 10s window in which every runnable task was stalled.
    pub full_avg10: f32,
}

#[cfg(target_os = "linux")]
fn parse(content: &str) -> Option<PsiMem> {
    let mut some_avg10 = None;
    let mut full_avg10 = None;
    for line in content.lines() {
        let mut it = line.split_whitespace();
        let kind = it.next()?;
        let target = match kind {
            "some" => &mut some_avg10,
            "full" => &mut full_avg10,
            _ => continue,
        };
        for tok in it {
            if let Some(v) = tok.strip_prefix("avg10=") {
                *target = v.parse::<f32>().ok();
                break;
            }
        }
    }
    Some(PsiMem {
        some_avg10: some_avg10?,
        full_avg10: full_avg10?,
    })
}

#[cfg(target_os = "linux")]
pub fn read_system() -> Option<PsiMem> {
    let content = std::fs::read_to_string(SYSTEM_PSI_PATH).ok()?;
    parse(&content)
}

#[cfg(target_os = "linux")]
pub fn read_process(pid: usize) -> Option<PsiMem> {
    let content = std::fs::read_to_string(format!("/proc/{pid}/pressure/memory")).ok()?;
    parse(&content)
}

#[cfg(not(target_os = "linux"))]
pub fn read_system() -> Option<PsiMem> {
    None
}

#[cfg(not(target_os = "linux"))]
pub fn read_process(_pid: usize) -> Option<PsiMem> {
    None
}

/// Capability detection result for the manifest in the JSONL header.
#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct PsiCapability {
    pub system: bool,
    pub per_process: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
}

pub fn detect(pid: usize) -> PsiCapability {
    #[cfg(target_os = "linux")]
    {
        let system = std::path::Path::new(SYSTEM_PSI_PATH).exists();
        let per_process = std::path::Path::new(&format!("/proc/{pid}/pressure/memory")).exists();
        let reason = if !system {
            Some("kernel does not expose /proc/pressure/memory (PSI disabled?)".to_string())
        } else if !per_process {
            Some("per-process PSI unavailable (kernel < 5.2 or not in cgroup v2)".to_string())
        } else {
            None
        };
        PsiCapability {
            system,
            per_process,
            reason,
        }
    }
    #[cfg(not(target_os = "linux"))]
    {
        let _ = pid;
        PsiCapability {
            system: false,
            per_process: false,
            reason: Some("PSI is Linux-only".to_string()),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_canonical_format() {
        let s = "some avg10=1.23 avg60=4.56 avg300=7.89 total=42\n\
                 full avg10=0.10 avg60=0.20 avg300=0.30 total=7\n";
        #[cfg(target_os = "linux")]
        {
            let p = parse(s).unwrap();
            assert!((p.some_avg10 - 1.23).abs() < 1e-4);
            assert!((p.full_avg10 - 0.10).abs() < 1e-4);
        }
        let _ = s;
    }

    #[test]
    fn rejects_garbage() {
        #[cfg(target_os = "linux")]
        {
            assert!(parse("not a psi file").is_none());
        }
    }
}
