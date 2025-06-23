//! Common duration constants used throughout the denet library
//!
//! This module centralizes timing constants to improve maintainability
//! and ensure consistency across the codebase.

use std::time::Duration;

/// Duration constants for sampling intervals
pub mod sampling {
    use super::Duration;

    /// Fast sampling interval - 50ms
    /// Used for high-frequency monitoring where precision is important
    pub const FAST: Duration = Duration::from_millis(50);

    /// Standard sampling interval - 100ms
    /// Default monitoring interval, good balance of accuracy and performance
    pub const STANDARD: Duration = Duration::from_millis(100);

    /// Slow sampling interval - 200ms
    /// Used for less critical monitoring or to reduce system load
    pub const SLOW: Duration = Duration::from_millis(200);

    /// Very slow sampling interval - 500ms
    /// Used for background monitoring or system startup delays
    pub const VERY_SLOW: Duration = Duration::from_millis(500);

    /// Maximum interval - 1000ms
    /// Default maximum adaptive interval
    pub const MAX_ADAPTIVE: Duration = Duration::from_millis(1000);
}

/// Duration constants for timeouts
pub mod timeouts {
    use super::Duration;

    /// Short timeout - 5 seconds
    /// Used for quick operations that should complete fast
    pub const SHORT: Duration = Duration::from_secs(5);

    /// Medium timeout - 10 seconds
    /// Used for moderate operations like process attachment
    pub const MEDIUM: Duration = Duration::from_secs(10);

    /// Long timeout - 30 seconds
    /// Used for complex operations like comprehensive tests
    pub const LONG: Duration = Duration::from_secs(30);

    /// Test timeout - 30 seconds
    /// Standard timeout for integration tests
    pub const TEST: Duration = Duration::from_secs(30);
}

/// Duration constants for delays and waits
pub mod delays {
    use super::Duration;

    /// Minimal delay - 10ms
    /// Used for brief pauses in tight loops
    pub const MINIMAL: Duration = Duration::from_millis(10);

    /// Short delay - 25ms
    /// Used for quick delays between operations
    pub const SHORT: Duration = Duration::from_millis(25);

    /// Standard delay - 50ms
    /// Used for general purpose delays
    pub const STANDARD: Duration = Duration::from_millis(50);

    /// Startup delay - 500ms
    /// Used to allow processes to initialize before monitoring
    pub const STARTUP: Duration = Duration::from_millis(500);

    /// Final sample delay - 500ms
    /// Used to ensure final metrics are captured after process completion
    pub const FINAL_SAMPLE: Duration = Duration::from_millis(500);

    /// CPU measurement delay - 100ms
    /// Minimum time needed for accurate CPU measurements
    pub const CPU_MEASUREMENT: Duration = Duration::from_millis(100);
}

/// Duration constants for system-specific operations
pub mod system {
    use super::Duration;

    /// Process detection retry delay - 10ms
    /// Used when waiting for processes to appear in system tables
    pub const PROCESS_DETECTION: Duration = Duration::from_millis(10);

    /// System refresh delay - 100ms
    /// Used for system information refresh operations
    pub const SYSTEM_REFRESH: Duration = Duration::from_millis(100);

    /// eBPF initialization timeout - 5 seconds
    /// Maximum time to wait for eBPF programs to load
    pub const EBPF_INIT: Duration = Duration::from_secs(5);
}

/// Default configuration values
pub mod defaults {
    use super::Duration;

    /// Default base monitoring interval
    pub const BASE_INTERVAL: Duration = Duration::from_millis(100);

    /// Default maximum adaptive interval
    pub const MAX_INTERVAL: Duration = Duration::from_millis(1000);

    /// Default test ready timeout
    pub const TEST_READY_TIMEOUT: Duration = Duration::from_secs(5);
}
