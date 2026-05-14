//! Process monitoring module
//!
//! This module provides the core process monitoring functionality,
//! split into focused submodules for better organization.

pub mod env;
pub mod metrics;
pub mod record;
pub mod summary;

// Re-export the main types for convenience
pub use env::EnvRecord;
pub use metrics::*;
pub use record::{tagged_json, Record};
pub use summary::SummaryGenerator;
