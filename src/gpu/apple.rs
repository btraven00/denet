//! Apple Silicon GPU metrics from the IORegistry (experimental).
//!
//! Every Metal client is an `AGXDeviceUserClient` under the `AGXAccelerator`,
//! with `IOUserClientCreator = "pid N, name"` and
//! `AppUsage = ({API, lastSubmittedTime, accumulatedGPUTime}, ...)`, one entry
//! per command queue, GPU time in nanoseconds. The accelerator's
//! `PerformanceStatistics` holds device-wide `Device Utilization %` and
//! `In use system memory`. All readable without root. See
//! `docs/plans/apple-silicon-gpu.md`.
//!
//! The user clients are not registered, so `IOServiceGetMatchingServices`
//! never finds them: we walk the accelerator's children instead.
//!
//! GPU energy and frequency come from IOReport, a private framework
//! (`libIOReport`), also unprivileged: the `GPU Energy` channel of the
//! `Energy Model` group, and the `GPUPH` residency channel of `GPU Stats` /
//! `GPU Performance States`. Residency is per P-state; `pmgr`'s
//! `voltage-states9` property maps P-state n to a frequency.
//!
//! # Expect this to be brittle
//!
//! None of this is public API. Everything here was verified only on an M1
//! (`AGXAcceleratorG13G_B0`, macOS 26.2): the class names, the property keys
//! (`AppUsage`, `accumulatedGPUTime`, `Device Utilization %`), the IOReport
//! group and channel names and their units, and `voltage-states9` being the
//! GPU's table (its frequency unit is guessed by magnitude). Other chips (M2/M3/M4, Pro/Max/
//! Ultra with several GPU dies) and later macOS releases may rename or drop
//! any of them. Everything degrades to `None` rather than failing, but a
//! renamed key reads as "no data", not as an error. If that starts happening,
//! the likely fix is a small table of overrides per hardware model (keyed by
//! the accelerator class or `model`) mapping to the right names and units,
//! rather than more guessing in the code.

use objc2_core_foundation::{
    CFArray, CFData, CFDictionary, CFMutableDictionary, CFNumber, CFRetained, CFString, CFType,
};
use objc2_io_kit::{
    io_registry_entry_t, kIOMainPortDefault, IOIteratorNext, IOObjectRelease,
    IORegistryEntryCreateCFProperty, IORegistryEntryGetChildIterator, IOServiceGetMatchingService,
    IOServiceMatching, IOServiceNameMatching,
};
use std::collections::HashMap;
use std::ffi::c_void;
use std::ptr::{self, NonNull};

/// One read of the GPU's IORegistry state.
#[derive(Debug, Clone, Default)]
pub(crate) struct Snapshot {
    /// pid -> cumulative GPU time (ns), summed over the pid's clients and queues.
    pub gpu_ns: HashMap<u32, u64>,
    pub device_utilization: Option<u32>,
    pub memory_used: Option<u64>,
    pub name: String,
    /// Since the previous snapshot, from [`IoReportReader`].
    pub report: Reading,
    /// Top of the GPU's P-state table (MHz).
    pub max_freq_mhz: Option<u32>,
}

/// Pid from `IOUserClientCreator`, e.g. `"pid 185, WindowServer"`.
fn parse_creator_pid(s: &str) -> Option<u32> {
    s.strip_prefix("pid ")?
        .split(',')
        .next()?
        .trim()
        .parse()
        .ok()
}

fn prop(entry: io_registry_entry_t, key: &'static str) -> Option<CFRetained<CFType>> {
    unsafe {
        IORegistryEntryCreateCFProperty(entry, Some(&CFString::from_static_str(key)), None, 0)
    }
}

fn as_dict(v: CFRetained<CFType>) -> Option<CFRetained<CFDictionary<CFString, CFType>>> {
    let d = v.downcast::<CFDictionary>().ok()?;
    // SAFETY: IORegistry property dictionaries have string keys and CF values.
    Some(unsafe { CFRetained::cast_unchecked(d) })
}

fn as_array(v: CFRetained<CFType>) -> Option<CFRetained<CFArray<CFType>>> {
    let a = v.downcast::<CFArray>().ok()?;
    // SAFETY: every CFArray element is a CF object.
    Some(unsafe { CFRetained::cast_unchecked(a) })
}

fn int(d: &CFDictionary<CFString, CFType>, key: &'static str) -> Option<i64> {
    d.get(&CFString::from_static_str(key))?
        .downcast::<CFNumber>()
        .ok()?
        .as_i64()
}

/// Read the accelerator and all its Metal clients. `None` if there is no
/// `AGXAccelerator` (not Apple Silicon).
pub(crate) fn snapshot() -> Option<Snapshot> {
    let matching = unsafe { IOServiceMatching(c"AGXAccelerator".as_ptr()) }?;
    let acc = unsafe {
        IOServiceGetMatchingService(
            kIOMainPortDefault,
            Some(CFRetained::<CFDictionary>::from(&matching)),
        )
    };
    if acc == 0 {
        return None;
    }

    let mut snap = Snapshot {
        name: prop(acc, "model")
            .and_then(|v| v.downcast::<CFString>().ok())
            .map(|s| s.to_string())
            .unwrap_or_else(|| "Apple GPU".into()),
        ..Default::default()
    };
    if let Some(stats) = prop(acc, "PerformanceStatistics").and_then(as_dict) {
        snap.device_utilization =
            int(&stats, "Device Utilization %").map(|v| v.clamp(0, 100) as u32);
        snap.memory_used = int(&stats, "In use system memory").map(|v| v.max(0) as u64);
    }

    let mut plane = [0 as std::ffi::c_char; 128];
    for (d, &b) in plane.iter_mut().zip(b"IOService") {
        *d = b as std::ffi::c_char;
    }
    let mut children = 0;
    if unsafe { IORegistryEntryGetChildIterator(acc, &mut plane, &mut children) } == 0 {
        loop {
            let child = IOIteratorNext(children);
            if child == 0 {
                break;
            }
            // Only user clients carry `AppUsage`; other children are skipped.
            let pid = prop(child, "IOUserClientCreator")
                .and_then(|v| v.downcast::<CFString>().ok())
                .and_then(|s| parse_creator_pid(&s.to_string()));
            if let (Some(pid), Some(usage)) = (pid, prop(child, "AppUsage").and_then(as_array)) {
                let ns: i64 = usage
                    .iter()
                    .filter_map(as_dict)
                    .filter_map(|e| int(&e, "accumulatedGPUTime"))
                    .sum();
                *snap.gpu_ns.entry(pid).or_default() += ns.max(0) as u64;
            }
            IOObjectRelease(child);
        }
        IOObjectRelease(children);
    }
    IOObjectRelease(acc);
    Some(snap)
}

#[link(name = "IOReport", kind = "dylib")]
extern "C" {
    fn IOReportCopyChannelsInGroup(
        group: &CFString,
        subgroup: *const CFString,
        a: u64,
        b: u64,
        c: u64,
    ) -> *mut CFDictionary;
    fn IOReportCreateSubscription(
        a: *const c_void,
        channels: &CFMutableDictionary,
        subscribed: *mut *mut CFMutableDictionary,
        d: u64,
        e: *const c_void,
    ) -> *mut CFType;
    fn IOReportCreateSamples(
        subscription: &CFType,
        subscribed: &CFMutableDictionary,
        e: *const c_void,
    ) -> *mut CFDictionary;
    fn IOReportCreateSamplesDelta(
        prev: &CFDictionary,
        cur: &CFDictionary,
        e: *const c_void,
    ) -> *mut CFDictionary;
    fn IOReportMergeChannels(a: &CFDictionary, b: &CFDictionary, nil: *const c_void);
    fn IOReportChannelGetChannelName(channel: &CFDictionary) -> *const CFString;
    fn IOReportStateGetCount(channel: &CFDictionary) -> i32;
    fn IOReportStateGetNameForIndex(channel: &CFDictionary, index: i32) -> *const CFString;
    fn IOReportStateGetResidency(channel: &CFDictionary, index: i32) -> i64;
    fn IOReportChannelGetUnitLabel(channel: &CFDictionary) -> *const CFString;
    fn IOReportSimpleGetIntegerValue(channel: &CFDictionary, index: i32) -> i64;
}

/// Wrap a +1 (Create/Copy rule) CF pointer.
fn owned<T: objc2_core_foundation::Type>(p: *mut T) -> Option<CFRetained<T>> {
    // SAFETY: callers pass only results of IOReport Create/Copy functions.
    NonNull::new(p).map(|p| unsafe { CFRetained::from_raw(p) })
}

/// String from a borrowed (Get rule) `CFStringRef`.
fn borrowed_str(p: *const CFString) -> Option<String> {
    // SAFETY: IOReport Get functions return null or a string owned by the channel.
    unsafe { p.as_ref() }.map(|s| s.to_string())
}

/// GPU P-state frequencies in MHz, indexed by P-state (0 = off), from the
/// `pmgr` node's `voltage-states9`. Empty if the node or property is missing.
fn gpu_pstate_mhz() -> Vec<u32> {
    let Some(matching) = (unsafe { IOServiceNameMatching(c"pmgr".as_ptr()) }) else {
        return Vec::new();
    };
    let pmgr = unsafe {
        IOServiceGetMatchingService(
            kIOMainPortDefault,
            Some(CFRetained::<CFDictionary>::from(&matching)),
        )
    };
    if pmgr == 0 {
        return Vec::new();
    }
    let data = prop(pmgr, "voltage-states9").and_then(|v| v.downcast::<CFData>().ok());
    IOObjectRelease(pmgr);
    data.map(|d| parse_dvfs(&d.to_vec())).unwrap_or_default()
}

/// A DVFS table, (frequency, voltage) little-endian u32 pairs, to MHz.
/// Frequencies are Hz on M1 and reportedly kHz on M4. ponytail: unit chosen by
/// magnitude (GPU clocks are 0.1–3 GHz, so anything over 1e7 is Hz); move to
/// the per-model overrides (see module docs) if a chip breaks this.
fn parse_dvfs(bytes: &[u8]) -> Vec<u32> {
    let hz: Vec<u32> = bytes
        .as_chunks::<8>()
        .0
        .iter()
        .map(|c| u32::from_le_bytes([c[0], c[1], c[2], c[3]]))
        .collect();
    let div = if hz.iter().any(|&f| f > 10_000_000) {
        1_000_000
    } else {
        1_000
    };
    hz.iter().map(|f| f / div).collect()
}

/// Mean frequency over the time the GPU was clocked (`Pn` states), weighted
/// by residency. `None` if it spent the whole interval off.
fn weighted_mhz(states: &[(String, i64)], mhz: &[u32]) -> Option<u32> {
    let (mut num, mut den) = (0.0, 0.0);
    for (name, res) in states {
        let Some(&f) = name
            .strip_prefix('P')
            .and_then(|n| n.parse::<usize>().ok())
            .and_then(|i| mhz.get(i))
        else {
            continue;
        };
        num += *res as f64 * f as f64;
        den += *res as f64;
    }
    (den > 0.0).then(|| (num / den).round() as u32)
}

/// What IOReport saw over one interval.
#[derive(Debug, Clone, Copy, Default)]
pub(crate) struct Reading {
    pub energy_j: Option<f64>,
    pub freq_mhz: Option<u32>,
}

/// IOReport subscription to the GPU's energy and P-state residency.
#[derive(Debug)]
pub(crate) struct IoReportReader {
    subscription: CFRetained<CFType>,
    subscribed: CFRetained<CFMutableDictionary>,
    prev: CFRetained<CFDictionary>,
    /// MHz by P-state; empty means no frequency.
    mhz: Vec<u32>,
}

// SAFETY: only touched through its `GpuMonitor`'s `Mutex`, one thread at a
// time, and CF objects may be used from any thread.
unsafe impl Send for IoReportReader {}

impl IoReportReader {
    /// Subscribe and take the baseline sample. `None` if IOReport refuses.
    pub fn new() -> Option<Self> {
        let group = |g: &'static str, sub: Option<&'static str>| {
            let sub = sub.map(CFString::from_static_str);
            let sub_ptr = sub.as_deref().map_or(ptr::null(), |s| s as *const CFString);
            owned(unsafe {
                IOReportCopyChannelsInGroup(&CFString::from_static_str(g), sub_ptr, 0, 0, 0)
            })
        };
        let channels = group("Energy Model", None)?;
        if let Some(perf) = group("GPU Stats", Some("GPU Performance States")) {
            unsafe { IOReportMergeChannels(&channels, &perf, ptr::null()) };
        }
        let channels = unsafe { CFMutableDictionary::new_copy(None, 0, Some(&channels)) }?;
        let mut subscribed = ptr::null_mut();
        let subscription = owned(unsafe {
            IOReportCreateSubscription(ptr::null(), &channels, &mut subscribed, 0, ptr::null())
        })?;
        let subscribed = owned(subscribed)?;
        let prev =
            owned(unsafe { IOReportCreateSamples(&subscription, &subscribed, ptr::null()) })?;
        Some(Self {
            subscription,
            subscribed,
            prev,
            mhz: gpu_pstate_mhz(),
        })
    }

    pub fn max_mhz(&self) -> Option<u32> {
        self.mhz.iter().copied().max().filter(|&m| m > 0)
    }

    /// GPU energy and mean frequency since the previous call (or since `new`).
    pub fn read(&mut self) -> Reading {
        let mut r = Reading::default();
        let Some(cur) = owned(unsafe {
            IOReportCreateSamples(&self.subscription, &self.subscribed, ptr::null())
        }) else {
            return r;
        };
        let delta = owned(unsafe { IOReportCreateSamplesDelta(&self.prev, &cur, ptr::null()) });
        self.prev = cur;
        // SAFETY: an IOReport sample is a string-keyed CF dictionary.
        let Some(channels) = delta
            .map(|d| unsafe { CFRetained::cast_unchecked::<CFDictionary<CFString, CFType>>(d) })
            .and_then(|d| d.get(&CFString::from_static_str("IOReportChannels")))
            .and_then(as_array)
        else {
            return r;
        };
        for ch in channels.iter() {
            let Ok(ch) = ch.downcast::<CFDictionary>() else {
                continue;
            };
            // Brittle: names and units verified on M1 only (see module docs).
            match borrowed_str(unsafe { IOReportChannelGetChannelName(&ch) }).as_deref() {
                Some("GPU Energy") => {
                    let unit = borrowed_str(unsafe { IOReportChannelGetUnitLabel(&ch) });
                    let scale = match unit.as_deref() {
                        Some("nJ") => 1e-9,
                        Some("uJ") | Some("µJ") => 1e-6,
                        Some("mJ") => 1e-3,
                        _ => continue,
                    };
                    let v = unsafe { IOReportSimpleGetIntegerValue(&ch, 0) };
                    *r.energy_j.get_or_insert(0.0) += v.max(0) as f64 * scale;
                }
                Some("GPUPH") if !self.mhz.is_empty() => {
                    let states: Vec<(String, i64)> = (0..unsafe { IOReportStateGetCount(&ch) })
                        .filter_map(|i| {
                            let name =
                                borrowed_str(unsafe { IOReportStateGetNameForIndex(&ch, i) })?;
                            Some((name, unsafe { IOReportStateGetResidency(&ch, i) }))
                        })
                        .collect();
                    r.freq_mhz = weighted_mhz(&states, &self.mhz);
                }
                _ => {}
            }
        }
        r
    }
}

/// GPU busy % of `pid` between two snapshots `wall_ns` apart. A pid missing
/// from `prev` is new since then and counted from 0. ponytail: a pid whose
/// client closed between snapshots goes backwards and reads 0 for that
/// interval; keep a per-client high-water mark if that ever matters.
pub(crate) fn utilization(prev: &Snapshot, cur: &Snapshot, pid: u32, wall_ns: u64) -> Option<u32> {
    let now = *cur.gpu_ns.get(&pid)?;
    let before = prev.gpu_ns.get(&pid).copied().unwrap_or(0);
    if wall_ns == 0 {
        return None;
    }
    Some(
        (now.saturating_sub(before) as f64 / wall_ns as f64 * 100.0)
            .round()
            .min(100.0) as u32,
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_creator_pid() {
        assert_eq!(parse_creator_pid("pid 185, WindowServer"), Some(185));
        assert_eq!(parse_creator_pid("pid 8059, burn"), Some(8059));
        assert_eq!(parse_creator_pid("WindowServer"), None);
        assert_eq!(parse_creator_pid("pid x, y"), None);
    }

    #[test]
    fn utilization_from_deltas() {
        let snap = |ns: &[(u32, u64)]| Snapshot {
            gpu_ns: ns.iter().copied().collect(),
            ..Default::default()
        };
        let (prev, cur) = (
            snap(&[(1, 1_000), (2, 500)]),
            snap(&[(1, 501_000), (2, 400), (3, 2_000_000)]),
        );
        assert_eq!(utilization(&prev, &cur, 1, 1_000_000), Some(50));
        assert_eq!(utilization(&prev, &cur, 2, 1_000_000), Some(0)); // went backwards
        assert_eq!(utilization(&prev, &cur, 3, 1_000_000), Some(100)); // new pid, clamped
        assert_eq!(utilization(&prev, &cur, 4, 1_000_000), None); // not on the GPU
        assert_eq!(utilization(&prev, &cur, 1, 0), None);
    }

    /// Runs on any Apple Silicon Mac: WindowServer is always a Metal client.
    #[test]
    fn snapshot_reads_the_registry() {
        let Some(s) = snapshot() else { return };
        assert!(s.device_utilization.is_some(), "{s:?}");
        assert!(!s.gpu_ns.is_empty(), "no Metal clients found: {s:?}");
    }

    /// Energy always has a channel; the P-state table must look like GPU clocks.
    #[test]
    fn ioreport_reads_energy_and_pstate_table() {
        if snapshot().is_none() {
            return;
        }
        let mut r = IoReportReader::new().expect("IOReport subscription");
        let max = r.max_mhz().expect("no GPU P-state table");
        assert!((300..4000).contains(&max), "max {max} MHz");
        std::thread::sleep(std::time::Duration::from_millis(200));
        let j = r.read().energy_j.expect("no `GPU Energy` channel");
        assert!((0.0..100.0).contains(&j), "{j} J in 200 ms");
    }

    #[test]
    fn parses_m1_dvfs_table() {
        // `voltage-states9` from an M1 Mac mini (macOS 26.2).
        let hex = "0000000090010000007b9a176a02000000a4781f8d0200000054ea2aaf02000000\
                   1f13370a03000000ea3b436403000080bb2c4ca0030000";
        let hex: String = hex.split_whitespace().collect();
        let bytes: Vec<u8> = (0..hex.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&hex[i..i + 2], 16).unwrap())
            .collect();
        assert_eq!(parse_dvfs(&bytes), [0, 396, 528, 720, 924, 1128, 1278]);
        // The same table in kHz (as on M4) gives the same MHz.
        let khz: Vec<u8> = [0u32, 396_000, 1_278_000]
            .iter()
            .flat_map(|f| [f.to_le_bytes(), [0; 4]].concat())
            .collect();
        assert_eq!(parse_dvfs(&khz), [0, 396, 1278]);
    }

    #[test]
    fn weights_frequency_by_residency() {
        let mhz = [0, 396, 528, 720];
        let st = |v: &[(&str, i64)]| {
            v.iter()
                .map(|&(n, r)| (n.to_string(), r))
                .collect::<Vec<_>>()
        };
        // Idle M1 residency: mostly OFF, some P1 and P3. OFF doesn't count.
        let idle = st(&[
            ("OFF", 23_764_010),
            ("P1", 10_341),
            ("P2", 0),
            ("P3", 543_650),
        ]);
        assert_eq!(weighted_mhz(&idle, &mhz), Some(714));
        assert_eq!(weighted_mhz(&st(&[("P3", 5)]), &mhz), Some(720));
        assert_eq!(weighted_mhz(&st(&[("OFF", 100), ("P1", 0)]), &mhz), None);
        assert_eq!(weighted_mhz(&st(&[("P9", 100)]), &mhz), None); // beyond the table
    }
}
