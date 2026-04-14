//! Memory map cache for eBPF stack trace symbolication
//!
//! This module provides a cache for storing memory maps of processes
//! that are being monitored. This allows for proper symbolication of
//! stack traces even after a process has exited.

use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use crate::symbolication::{get_memory_maps, MemoryRegion};

/// Cache for process memory maps to support stack trace symbolication
#[derive(Debug, Clone)]
pub struct MemoryMapCache {
    /// Maps process IDs to their memory maps and cache timestamp
    maps: Arc<Mutex<HashMap<u32, (Vec<MemoryRegion>, Instant)>>>,
    /// Maximum age of cached maps before refresh (in seconds)
    max_age: u64,
    /// Debug mode flag
    debug_mode: bool,
}

impl MemoryMapCache {
    /// Create a new memory map cache with default settings
    pub fn new() -> Self {
        Self {
            maps: Arc::new(Mutex::new(HashMap::new())),
            max_age: 30, // Default to 30 seconds max age (reduced for better responsiveness)
            debug_mode: false,
        }
    }

    /// Create a new memory map cache with debug mode enabled
    pub fn with_debug() -> Self {
        let mut cache = Self::new();
        cache.debug_mode = true;
        cache
    }

    /// Set the maximum age for cached memory maps
    pub fn with_max_age(mut self, seconds: u64) -> Self {
        self.max_age = seconds;
        self
    }

    /// Enable or disable debug mode
    pub fn set_debug_mode(&mut self, enable: bool) {
        self.debug_mode = enable;
    }

    /// Get memory maps for a process, either from cache or by reading /proc
    pub fn get_memory_maps(&mut self, pid: u32) -> Vec<MemoryRegion> {
        let should_refresh = {
            let maps = self.maps.lock().unwrap();
            match maps.get(&pid) {
                Some((regions, timestamp)) => {
                    // Check if cache is older than max_age or if regions are empty (retry once)
                    timestamp.elapsed() > Duration::from_secs(self.max_age) || regions.is_empty()
                }
                None => true, // No cache entry, should refresh
            }
        };

        if should_refresh {
            let success = self.refresh_maps_for_pid(pid);

            // If refresh failed and we don't have any previous data, try one more time
            // This helps with processes that might be in a transient state
            if !success {
                if self.debug_mode {
                    crate::ebpf::debug::debug_println(&format!(
                        "Initial refresh failed for PID {}. Retrying after short delay...",
                        pid
                    ));
                }

                // Small delay before retry
                std::thread::sleep(std::time::Duration::from_millis(50));
                self.refresh_maps_for_pid(pid);
            }
        }

        // Return the cached maps (even if refresh failed, we'll get empty vec)
        let maps = self.maps.lock().unwrap();
        match maps.get(&pid) {
            Some((regions, _)) => {
                if self.debug_mode && regions.is_empty() {
                    crate::ebpf::debug::debug_println(&format!(
                        "Warning: Returning empty memory maps for PID {}",
                        pid
                    ));
                }
                regions.clone()
            }
            None => {
                if self.debug_mode {
                    crate::ebpf::debug::debug_println(&format!(
                        "No cached memory maps found for PID {}",
                        pid
                    ));
                }
                Vec::new()
            }
        }
    }

    /// Refresh memory maps for a specific PID
    pub fn refresh_maps_for_pid(&mut self, pid: u32) -> bool {
        let regions = get_memory_maps(pid);
        let success = !regions.is_empty();

        if self.debug_mode {
            if success {
                crate::ebpf::debug::debug_println(&format!(
                    "Cached {} memory regions for PID {}",
                    regions.len(),
                    pid
                ));

                // Print a few example regions for debugging
                if !regions.is_empty() {
                    let exec_regions: Vec<_> = regions
                        .iter()
                        .filter(|r| r.permissions.contains('x'))
                        .take(2)
                        .collect();

                    if !exec_regions.is_empty() {
                        crate::ebpf::debug::debug_println("Sample executable regions:");
                        for (i, region) in exec_regions.iter().enumerate() {
                            crate::ebpf::debug::debug_println(&format!(
                                "  Region {}: 0x{:x}-0x{:x} {} {:?}",
                                i,
                                region.start_addr,
                                region.end_addr,
                                region.permissions,
                                region.pathname
                            ));
                        }
                    }
                }
            } else {
                crate::ebpf::debug::debug_println(&format!(
                    "Failed to cache memory regions for PID {}",
                    pid
                ));

                // Check if the process exists
                let proc_path = format!("/proc/{}/maps", pid);
                match std::fs::metadata(&proc_path) {
                    Ok(_) => {
                        crate::ebpf::debug::debug_println(&format!(
                            "Process {} exists but memory map parsing failed",
                            pid
                        ));

                        // Try a direct file open to get more detailed error
                        match std::fs::File::open(&proc_path) {
                            Ok(_) => {
                                crate::ebpf::debug::debug_println(
                                    "Maps file exists but could not be parsed correctly",
                                );
                            }
                            Err(e) => {
                                crate::ebpf::debug::debug_println(&format!(
                                    "Maps file open error: {}",
                                    e
                                ));
                            }
                        }
                    }
                    Err(_) => {
                        crate::ebpf::debug::debug_println(&format!(
                            "Process {} likely doesn't exist anymore",
                            pid
                        ));
                    }
                }
            }
        }

        // Store maps even if empty (to avoid repeated failed lookups)
        let mut maps = self.maps.lock().unwrap();
        maps.insert(pid, (regions, Instant::now()));

        success
    }

    /// Get a list of all PIDs in the cache
    pub fn cached_pids(&self) -> Vec<u32> {
        let maps = self.maps.lock().unwrap();
        maps.keys().cloned().collect()
    }

    /// Remove a PID from the cache
    pub fn remove_pid(&mut self, pid: u32) -> bool {
        let mut maps = self.maps.lock().unwrap();
        maps.remove(&pid).is_some()
    }

    /// Get cache size (number of PIDs)
    pub fn cache_size(&self) -> usize {
        let maps = self.maps.lock().unwrap();
        maps.len()
    }

    /// Clear all cached maps
    pub fn clear(&mut self) {
        let mut maps = self.maps.lock().unwrap();
        maps.clear();
    }

    /// Print statistics about the cache
    pub fn print_stats(&self) {
        let maps = self.maps.lock().unwrap();
        crate::ebpf::debug::debug_println(&format!(
            "Memory map cache contains {} PIDs",
            maps.len()
        ));

        for (pid, (regions, timestamp)) in maps.iter() {
            let age = timestamp.elapsed().as_secs();
            crate::ebpf::debug::debug_println(&format!(
                "  PID {}: {} regions, cached {} seconds ago",
                pid,
                regions.len(),
                age
            ));
        }
    }
}

impl Default for MemoryMapCache {
    fn default() -> Self {
        Self::new()
    }
}

/// Find a memory region containing a specific address in cached maps
pub fn find_region_for_address_in_cache(
    cache: &mut MemoryMapCache,
    addr: u64,
    pid: u32,
) -> Option<MemoryRegion> {
    let maps = cache.get_memory_maps(pid);

    // Early return if no maps found
    if maps.is_empty() {
        if cache.debug_mode {
            crate::ebpf::debug::debug_println(&format!(
                "No memory maps found for PID {} when searching for address 0x{:x}",
                pid, addr
            ));
        }
        return None;
    }

    // Find the region containing this address
    for region in &maps {
        if addr >= region.start_addr && addr < region.end_addr {
            if cache.debug_mode {
                crate::ebpf::debug::debug_println(&format!(
                    "Found region for address 0x{:x} in PID {}: {:?}",
                    addr, pid, region.pathname
                ));
            }
            return Some(region.clone());
        }
    }

    if cache.debug_mode {
        crate::ebpf::debug::debug_println(&format!(
            "Address 0x{:x} not found in any memory region for PID {}",
            addr, pid
        ));

        // Log address ranges for debugging
        let min_addr = maps.iter().map(|r| r.start_addr).min().unwrap_or(0);
        let max_addr = maps.iter().map(|r| r.end_addr).max().unwrap_or(0);
        crate::ebpf::debug::debug_println(&format!(
            "Available address range: 0x{:x}-0x{:x}",
            min_addr, max_addr
        ));
    }

    None
}

/// Get executable memory regions from the cache for a specific PID
pub fn get_executable_regions(cache: &mut MemoryMapCache, pid: u32) -> Vec<MemoryRegion> {
    cache
        .get_memory_maps(pid)
        .into_iter()
        .filter(|region| region.permissions.contains('x'))
        .collect()
}
