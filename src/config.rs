//! Configuration structures for denet monitoring
//!
//! This module provides builder patterns and configuration structs to replace
//! scattered parameters throughout the codebase.

use crate::error::{DenetError, Result};
use std::path::PathBuf;
use std::time::Duration;

/// Output format options for monitoring data
#[derive(Clone, Debug, PartialEq, Default)]
pub enum OutputFormat {
    #[default]
    JsonLines,
    Json,
    Csv,
}

impl std::str::FromStr for OutputFormat {
    type Err = DenetError;

    fn from_str(s: &str) -> Result<Self> {
        match s.to_lowercase().as_str() {
            "json" => Ok(OutputFormat::Json),
            "jsonl" | "jsonlines" => Ok(OutputFormat::JsonLines),
            "csv" => Ok(OutputFormat::Csv),
            _ => Err(DenetError::InvalidConfiguration(format!(
                "Unknown output format: {}",
                s
            ))),
        }
    }
}

impl std::fmt::Display for OutputFormat {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            OutputFormat::Json => write!(f, "json"),
            OutputFormat::JsonLines => write!(f, "jsonl"),
            OutputFormat::Csv => write!(f, "csv"),
        }
    }
}

/// Configuration for process monitoring behavior
#[derive(Clone, Debug)]
pub struct MonitorConfig {
    /// Base sampling interval
    pub base_interval: Duration,
    /// Maximum sampling interval for adaptive sampling
    pub max_interval: Duration,
    /// Whether to show I/O since process start instead of since monitoring start
    pub since_process_start: bool,
    /// Whether to include child processes in monitoring
    pub include_children: bool,
    /// Maximum monitoring duration (None for unlimited)
    pub max_duration: Option<Duration>,
    /// Enable eBPF profiling
    pub enable_ebpf: bool,
}

impl Default for MonitorConfig {
    fn default() -> Self {
        Self {
            base_interval: Duration::from_millis(100),
            max_interval: Duration::from_millis(1000),
            since_process_start: false,
            include_children: true,
            max_duration: None,
            enable_ebpf: false,
        }
    }
}

impl MonitorConfig {
    /// Create a new monitor configuration builder
    pub fn builder() -> MonitorConfigBuilder {
        MonitorConfigBuilder::default()
    }

    /// Validate the configuration
    pub fn validate(&self) -> Result<()> {
        if self.base_interval > self.max_interval {
            return Err(DenetError::InvalidConfiguration(
                "Base interval cannot be greater than max interval".to_string(),
            ));
        }
        if self.base_interval.is_zero() {
            return Err(DenetError::InvalidConfiguration(
                "Base interval cannot be zero".to_string(),
            ));
        }
        Ok(())
    }
}

/// Configuration for output behavior
#[derive(Clone, Debug)]
pub struct OutputConfig {
    /// File to write output to (None for no file output)
    pub output_file: Option<PathBuf>,
    /// Output format
    pub format: OutputFormat,
    /// Whether to store samples in memory
    pub store_in_memory: bool,
    /// Whether to suppress stdout output
    pub quiet: bool,
    /// Whether to update output in place (vs new lines)
    pub update_in_place: bool,
}

impl Default for OutputConfig {
    fn default() -> Self {
        Self {
            output_file: None,
            format: OutputFormat::default(),
            store_in_memory: true,
            quiet: false,
            update_in_place: true,
        }
    }
}

impl OutputConfig {
    /// Create a new output configuration builder
    pub fn builder() -> OutputConfigBuilder {
        OutputConfigBuilder::default()
    }
}

/// Builder for MonitorConfig
#[derive(Default)]
pub struct MonitorConfigBuilder {
    base_interval: Option<Duration>,
    max_interval: Option<Duration>,
    since_process_start: Option<bool>,
    include_children: Option<bool>,
    max_duration: Option<Duration>,
    enable_ebpf: Option<bool>,
}

impl MonitorConfigBuilder {
    pub fn base_interval(mut self, interval: Duration) -> Self {
        self.base_interval = Some(interval);
        self
    }

    pub fn base_interval_ms(mut self, ms: u64) -> Self {
        self.base_interval = Some(Duration::from_millis(ms));
        self
    }

    pub fn max_interval(mut self, interval: Duration) -> Self {
        self.max_interval = Some(interval);
        self
    }

    pub fn max_interval_ms(mut self, ms: u64) -> Self {
        self.max_interval = Some(Duration::from_millis(ms));
        self
    }

    pub fn since_process_start(mut self, since_start: bool) -> Self {
        self.since_process_start = Some(since_start);
        self
    }

    pub fn include_children(mut self, include: bool) -> Self {
        self.include_children = Some(include);
        self
    }

    pub fn max_duration(mut self, duration: Duration) -> Self {
        self.max_duration = Some(duration);
        self
    }

    pub fn max_duration_secs(mut self, secs: u64) -> Self {
        if secs > 0 {
            self.max_duration = Some(Duration::from_secs(secs));
        }
        self
    }
    
    pub fn enable_ebpf(mut self, enable: bool) -> Self {
        self.enable_ebpf = Some(enable);
        self
    }

    pub fn build(self) -> Result<MonitorConfig> {
        let config = MonitorConfig {
            base_interval: self.base_interval.unwrap_or(Duration::from_millis(100)),
            max_interval: self.max_interval.unwrap_or(Duration::from_millis(1000)),
            since_process_start: self.since_process_start.unwrap_or(false),
            include_children: self.include_children.unwrap_or(true),
            max_duration: self.max_duration,
            enable_ebpf: self.enable_ebpf.unwrap_or(false),
        };
        config.validate()?;
        Ok(config)
    }
}

/// Builder for OutputConfig
#[derive(Default)]
pub struct OutputConfigBuilder {
    output_file: Option<PathBuf>,
    format: Option<OutputFormat>,
    store_in_memory: Option<bool>,
    quiet: Option<bool>,
    update_in_place: Option<bool>,
}

impl OutputConfigBuilder {
    pub fn output_file<P: Into<PathBuf>>(mut self, path: P) -> Self {
        self.output_file = Some(path.into());
        self
    }

    pub fn format(mut self, format: OutputFormat) -> Self {
        self.format = Some(format);
        self
    }

    pub fn format_str(mut self, format: &str) -> Result<Self> {
        self.format = Some(format.parse()?);
        Ok(self)
    }

    pub fn store_in_memory(mut self, store: bool) -> Self {
        self.store_in_memory = Some(store);
        self
    }

    pub fn quiet(mut self, quiet: bool) -> Self {
        self.quiet = Some(quiet);
        self
    }

    pub fn update_in_place(mut self, update: bool) -> Self {
        self.update_in_place = Some(update);
        self
    }

    pub fn build(self) -> OutputConfig {
        OutputConfig {
            output_file: self.output_file,
            format: self.format.unwrap_or_default(),
            store_in_memory: self.store_in_memory.unwrap_or(true),
            quiet: self.quiet.unwrap_or(false),
            update_in_place: self.update_in_place.unwrap_or(true),
        }
    }
}

/// Combined configuration for monitoring operations
#[derive(Clone, Debug, Default)]
pub struct DenetConfig {
    pub monitor: MonitorConfig,
    pub output: OutputConfig,
}

impl DenetConfig {
    pub fn builder() -> DenetConfigBuilder {
        DenetConfigBuilder::default()
    }
}

/// Builder for DenetConfig
#[derive(Default)]
pub struct DenetConfigBuilder {
    monitor: Option<MonitorConfig>,
    output: Option<OutputConfig>,
}

impl DenetConfigBuilder {
    pub fn monitor(mut self, config: MonitorConfig) -> Self {
        self.monitor = Some(config);
        self
    }

    pub fn output(mut self, config: OutputConfig) -> Self {
        self.output = Some(config);
        self
    }

    pub fn build(self) -> DenetConfig {
        DenetConfig {
            monitor: self.monitor.unwrap_or_default(),
            output: self.output.unwrap_or_default(),
        }
    }
}
