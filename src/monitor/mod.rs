//! Process monitoring module
//!
//! This module provides the core process monitoring functionality,
//! split into focused submodules for better organization.

pub mod metrics;
pub mod summary;

// Re-export the main types for convenience
pub use metrics::*;
pub use summary::SummaryGenerator;
