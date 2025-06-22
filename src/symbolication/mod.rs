/// Minimal MVP for memory map parsing and addr2line-based symbolication.
/// This module provides basic functionality to parse `/proc/{pid}/maps`
/// and resolve addresses to symbols using the external `addr2line` tool.
use std::collections::HashMap;
use std::fs::File;
use std::io::{BufRead, BufReader};
use std::process::Command;

#[derive(Debug, Clone)]
pub struct MemoryRegion {
    pub start_addr: u64,
    pub end_addr: u64,
    pub permissions: String,
    pub offset: u64,
    pub dev: String,
    pub inode: u64,
    pub pathname: Option<String>,
}

#[derive(Debug, Clone)]
pub struct SymbolInfo {
    pub function: Option<String>,
    pub file: Option<String>,
    pub line: Option<u32>,
}

/// Parse /proc/{pid}/maps and return a vector of MemoryRegion structs.
/// Returns an empty vector on error.
pub fn get_memory_maps(pid: u32) -> Vec<MemoryRegion> {
    let path = format!("/proc/{pid}/maps");
    let file = match File::open(&path) {
        Ok(f) => f,
        Err(e) => {
            // Log the error to help with debugging
            eprintln!("Failed to open maps file for PID {pid}: {e}");
            return vec![];
        }
    };

    let reader = BufReader::new(file);
    let mut regions = Vec::new();
    let mut skipped_lines = 0;

    for (line_no, line_result) in reader.lines().enumerate() {
        let line = match line_result {
            Ok(l) => l,
            Err(e) => {
                eprintln!("Error reading line {line_no} from maps for PID {pid}: {e}");
                skipped_lines += 1;
                continue;
            }
        };

        // Example line:
        // 00400000-0040b000 r--p 00000000 08:02 131073 /usr/bin/cat
        let parts: Vec<&str> = line.split_whitespace().collect();
        if parts.len() < 5 {
            skipped_lines += 1;
            continue;
        }

        let addrs: Vec<&str> = parts[0].split('-').collect();
        if addrs.len() != 2 {
            skipped_lines += 1;
            continue;
        }

        // Parse address ranges
        let start_addr = match u64::from_str_radix(addrs[0], 16) {
            Ok(addr) => addr,
            Err(_) => {
                skipped_lines += 1;
                continue;
            }
        };

        let end_addr = match u64::from_str_radix(addrs[1], 16) {
            Ok(addr) => addr,
            Err(_) => {
                skipped_lines += 1;
                continue;
            }
        };

        // Parse other fields
        let permissions = parts[1].to_string();

        let offset = match u64::from_str_radix(parts[2], 16) {
            Ok(off) => off,
            Err(_) => {
                skipped_lines += 1;
                continue;
            }
        };

        let dev = parts[3].to_string();

        let inode = match parts[4].parse::<u64>() {
            Ok(i) => i,
            Err(_) => {
                skipped_lines += 1;
                continue;
            }
        };

        // Get pathname if available
        let pathname = if parts.len() >= 6 {
            let path = parts[5..].join(" ");
            // Skip "[vdso]", "[vsyscall]" and other special mappings for symbolication purposes
            if path.starts_with('[') && path.ends_with(']') {
                Some(path)
            }
            // Filter out empty paths or anonymous mappings
            else if path.is_empty() || path == "//anon" {
                None
            } else {
                Some(path)
            }
        } else {
            None
        };

        // Only include regions that are useful for symbolication
        // Either they have a pathname or they're executable (JIT code)
        if pathname.is_some() || permissions.contains('x') {
            regions.push(MemoryRegion {
                start_addr,
                end_addr,
                permissions,
                offset,
                dev,
                inode,
                pathname,
            });
        }
    }

    // Warn if we skipped a significant number of lines
    if skipped_lines > 5 {
        eprintln!("Warning: Skipped {skipped_lines} malformed lines in maps for PID {pid}");
    }

    regions
}

/// Find the memory region containing the given address.
/// Returns the region containing the address, prioritizing executable regions.
pub fn find_region_for_address(addr: u64, regions: &[MemoryRegion]) -> Option<&MemoryRegion> {
    // First look for executable regions that contain this address
    let exec_region = regions
        .iter()
        .find(|r| addr >= r.start_addr && addr < r.end_addr && r.permissions.contains('x'));

    if exec_region.is_some() {
        return exec_region;
    }

    // If no executable region found, try any region with a pathname
    let named_region = regions
        .iter()
        .find(|r| addr >= r.start_addr && addr < r.end_addr && r.pathname.is_some());

    if named_region.is_some() {
        return named_region;
    }

    // Last resort - any region containing the address
    regions
        .iter()
        .find(|r| addr >= r.start_addr && addr < r.end_addr)
}

/// Use addr2line to resolve an address to symbol information.
/// Returns None if resolution fails.
pub fn get_symbol_info_with_addr2line(binary_path: &str, offset: u64) -> Option<SymbolInfo> {
    // Check if binary exists before trying addr2line
    if !std::path::Path::new(binary_path).exists() {
        return None;
    }

    // Format address for addr2line (use hex notation)
    let addr_str = format!("0x{offset:x}");

    // Try with multiple offset calculation methods if needed
    // Sometimes the direct offset works better, sometimes we need additional info
    for attempt in 1..=2 {
        let mut cmd = Command::new("addr2line");
        cmd.arg("-e")
            .arg(binary_path)
            .arg("-f") // print function name
            .arg("-C") // demangle
            .arg(&addr_str);

        // On second attempt, add additional flags for better results
        if attempt == 2 {
            cmd.arg("-a"); // show addresses
        }

        let output = match cmd.output() {
            Ok(out) => out,
            Err(_) => continue, // Try next approach if command fails
        };

        if !output.status.success() {
            continue; // Try next approach if command returns error
        }

        let stdout = String::from_utf8_lossy(&output.stdout);
        let mut lines = stdout.lines();

        // Get function name from first line
        let function = lines
            .next()
            .map(|s| s.trim())
            .filter(|s| !s.contains("??") && !s.is_empty())
            .map(|s| s.to_string());

        // Skip if we couldn't get a function name (try next attempt)
        if function.is_none() && attempt < 2 {
            continue;
        }

        // Get source location from second line
        let location = lines.next().unwrap_or("").trim();

        // Parse location into file and line number
        let (file, line) = if let Some((f, l)) = location.rsplit_once(':') {
            // Skip if file has "??" which indicates failure
            if f.contains("??") && attempt < 2 {
                continue;
            }

            let line_num = l.parse::<u32>().ok();
            (Some(f.to_string()).filter(|s| !s.contains("??")), line_num)
        } else {
            (None, None)
        };

        // Return result if we have at least a function name
        if function.is_some() {
            return Some(SymbolInfo {
                function,
                file,
                line,
            });
        }
    }

    // Try objdump as a fallback for just the function name
    if let Ok(output) = Command::new("objdump").arg("-t").arg(binary_path).output() {
        if output.status.success() {
            let stdout = String::from_utf8_lossy(&output.stdout);

            // Find the closest symbol to our offset
            let mut closest_symbol = None;
            let mut closest_distance = u64::MAX;

            for line in stdout.lines() {
                let parts: Vec<&str> = line.split_whitespace().collect();
                if parts.len() >= 6 {
                    if let Ok(addr) = u64::from_str_radix(parts[0], 16) {
                        if addr <= offset {
                            let distance = offset - addr;
                            if distance < closest_distance {
                                closest_distance = distance;
                                closest_symbol = Some(parts[5].to_string());
                            }
                        }
                    }
                }
            }

            // Only use objdump result if it's reasonably close (within 4KB)
            if closest_distance < 4096 {
                return Some(SymbolInfo {
                    function: closest_symbol,
                    file: None,
                    line: None,
                });
            }
        }
    }

    None
}

/// Minimal cache for memory maps and symbol lookups.
pub struct SymbolicationCache {
    pub pid_maps: HashMap<u32, Vec<MemoryRegion>>,
    pub symbol_cache: HashMap<(String, u64), SymbolInfo>,
    pub last_refresh: HashMap<u32, std::time::Instant>,
    pub max_age_secs: u64,
}

impl Default for SymbolicationCache {
    fn default() -> Self {
        Self::new()
    }
}

impl SymbolicationCache {
    pub fn new() -> Self {
        Self {
            pid_maps: HashMap::new(),
            symbol_cache: HashMap::new(),
            last_refresh: HashMap::new(),
            max_age_secs: 30, // Default refresh interval in seconds
        }
    }

    /// Get memory maps for a PID, refreshing if necessary
    pub fn get_memory_maps_for_pid(&mut self, pid: u32) -> &Vec<MemoryRegion> {
        // Check if we need to refresh the maps
        let should_refresh = match self.last_refresh.get(&pid) {
            Some(instant) => {
                instant.elapsed() > std::time::Duration::from_secs(self.max_age_secs)
                    || self.pid_maps.get(&pid).is_none_or(|maps| maps.is_empty())
            }
            None => true,
        };

        if should_refresh {
            let maps = get_memory_maps(pid);
            self.pid_maps.insert(pid, maps);
            self.last_refresh.insert(pid, std::time::Instant::now());
        }

        self.pid_maps.entry(pid).or_default()
    }

    /// Get symbol info for an address, using the cache when possible
    pub fn get_symbol_info(&mut self, binary_path: &str, offset: u64) -> Option<SymbolInfo> {
        let cache_key = (binary_path.to_string(), offset);

        if let Some(symbol) = self.symbol_cache.get(&cache_key) {
            return Some(symbol.clone());
        }

        // Not in cache, look it up
        if let Some(symbol) = get_symbol_info_with_addr2line(binary_path, offset) {
            self.symbol_cache.insert(cache_key, symbol.clone());
            return Some(symbol);
        }

        None
    }

    /// Clear cache for a specific PID
    pub fn clear_pid(&mut self, pid: u32) {
        self.pid_maps.remove(&pid);
        self.last_refresh.remove(&pid);
    }

    /// Get cache statistics
    pub fn stats(&self) -> (usize, usize, usize) {
        (
            self.pid_maps.len(),
            self.symbol_cache.len(),
            self.last_refresh.len(),
        )
    }
}
