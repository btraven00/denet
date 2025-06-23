//! Core process monitoring functionality
//!
//! This module contains the main ProcessMonitor implementation and related utilities.

pub mod constants;
pub mod monitoring_utils;
pub mod process_monitor;

// Re-export main types
pub use process_monitor::{ProcessMonitor, ProcessResult};
