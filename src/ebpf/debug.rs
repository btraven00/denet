//! Debug utilities for eBPF components
//!
//! This module provides debugging facilities for eBPF operations.
//! It controls verbose output based on a global debug flag.

/// Global debug mode flag for eBPF operations
static mut EBPF_DEBUG_MODE: bool = false;

/// Sets the debug mode for eBPF operations
///
/// When enabled, verbose debugging information will be printed to stdout.
///
/// # Safety
///
/// This function uses a static mutable global and is not thread-safe.
/// It should only be called during initialization before any eBPF operations.
#[inline]
pub unsafe fn set_debug_mode(enabled: bool) {
    EBPF_DEBUG_MODE = enabled;
}

/// Gets the current debug mode setting
///
/// # Safety
///
/// This function uses a static mutable global and is not thread-safe.
#[inline]
pub unsafe fn is_debug_mode() -> bool {
    EBPF_DEBUG_MODE
}

/// Prints a debug message if debug mode is enabled
///
/// This function is a no-op if debug mode is disabled.
#[inline]
pub fn debug_println(msg: &str) {
    unsafe {
        if EBPF_DEBUG_MODE {
            println!("DEBUG: {}", msg);
        }
    }
}

/// Prints a formatted debug message if debug mode is enabled
///
/// This macro formats the message like `println!` and is a no-op if debug mode is disabled.
#[macro_export]
macro_rules! ebpf_debug {
    ($($arg:tt)*) => {{
        unsafe {
            if $crate::ebpf::debug::is_debug_mode() {
                println!("DEBUG: {}", format!($($arg)*));
            }
        }
    }};
}
