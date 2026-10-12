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
//! GPU energy comes from IOReport, a private framework (`libIOReport`):
//! the `GPU Energy` channel of the `Energy Model` group, also unprivileged.
//!
//! # Expect this to be brittle
//!
//! None of this is public API. Everything here was verified only on an M1
//! (`AGXAcceleratorG13G_B0`, macOS 26.2): the class names, the property keys
//! (`AppUsage`, `accumulatedGPUTime`, `Device Utilization %`), the IOReport
//! group and channel names, and their units. Other chips (M2/M3/M4, Pro/Max/
//! Ultra with several GPU dies) and later macOS releases may rename or drop
//! any of them. Everything degrades to `None` rather than failing, but a
//! renamed key reads as "no data", not as an error. If that starts happening,
//! the likely fix is a small table of overrides per hardware model (keyed by
//! the accelerator class or `model`) mapping to the right names and units,
//! rather than more guessing in the code.

use objc2_core_foundation::{
    CFArray, CFDictionary, CFMutableDictionary, CFNumber, CFRetained, CFString, CFType,
};
use objc2_io_kit::{
    io_registry_entry_t, kIOMainPortDefault, IOIteratorNext, IOObjectRelease,
    IORegistryEntryCreateCFProperty, IORegistryEntryGetChildIterator, IOServiceGetMatchingService,
    IOServiceMatching,
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
    /// GPU energy (J) since the previous snapshot, set by [`GpuEnergyReader`].
    pub energy_j: Option<f64>,
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
    fn IOReportChannelGetChannelName(channel: &CFDictionary) -> *const CFString;
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

/// IOReport subscription to the GPU's energy counter.
#[derive(Debug)]
pub(crate) struct GpuEnergyReader {
    subscription: CFRetained<CFType>,
    subscribed: CFRetained<CFMutableDictionary>,
    prev: CFRetained<CFDictionary>,
}

// SAFETY: only touched through its `GpuMonitor`'s `Mutex`, one thread at a
// time, and CF objects may be used from any thread.
unsafe impl Send for GpuEnergyReader {}

impl GpuEnergyReader {
    /// Subscribe and take the baseline sample. `None` if IOReport refuses.
    pub fn new() -> Option<Self> {
        let group = CFString::from_static_str("Energy Model");
        let channels = owned(unsafe { IOReportCopyChannelsInGroup(&group, ptr::null(), 0, 0, 0) })?;
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
        })
    }

    /// GPU energy in joules since the previous call (or since `new`).
    pub fn delta_joules(&mut self) -> Option<f64> {
        let cur = owned(unsafe {
            IOReportCreateSamples(&self.subscription, &self.subscribed, ptr::null())
        })?;
        let delta = owned(unsafe { IOReportCreateSamplesDelta(&self.prev, &cur, ptr::null()) })?;
        self.prev = cur;
        // SAFETY: an IOReport sample is a string-keyed CF dictionary.
        let delta: CFRetained<CFDictionary<CFString, CFType>> =
            unsafe { CFRetained::cast_unchecked(delta) };
        let channels = as_array(delta.get(&CFString::from_static_str("IOReportChannels"))?)?;
        let mut joules = None;
        for ch in channels.iter() {
            let Ok(ch) = ch.downcast::<CFDictionary>() else {
                continue;
            };
            // Brittle: channel name and unit verified on M1 only (see module docs).
            if borrowed_str(unsafe { IOReportChannelGetChannelName(&ch) }).as_deref()
                != Some("GPU Energy")
            {
                continue;
            }
            let scale = match borrowed_str(unsafe { IOReportChannelGetUnitLabel(&ch) }).as_deref() {
                Some("nJ") => 1e-9,
                Some("uJ") | Some("µJ") => 1e-6,
                Some("mJ") => 1e-3,
                _ => continue,
            };
            let v = unsafe { IOReportSimpleGetIntegerValue(&ch, 0) };
            *joules.get_or_insert(0.0) += v.max(0) as f64 * scale;
        }
        joules
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

    /// The GPU always draws something, so a second read sees energy.
    #[test]
    fn energy_reader_reads_gpu_energy() {
        if snapshot().is_none() {
            return;
        }
        let mut r = GpuEnergyReader::new().expect("IOReport subscription");
        std::thread::sleep(std::time::Duration::from_millis(200));
        let j = r.delta_joules().expect("no `GPU Energy` channel");
        assert!((0.0..100.0).contains(&j), "{j} J in 200 ms");
    }
}
