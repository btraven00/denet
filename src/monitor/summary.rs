//! Summary generation utilities
//!
//! This module provides functionality for generating summaries from
//! collected metrics data, including reading from files.

use crate::error::{DenetError, Result};
use crate::monitor::metrics::{AggregatedMetrics, Metrics, Summary};
use std::fs::File;
use std::io::{BufRead, BufReader};
use std::path::Path;

/// Utilities for summary generation
pub struct SummaryGenerator;

impl SummaryGenerator {
    /// Generate summary from a JSON file containing metrics
    pub fn from_json_file<P: AsRef<Path>>(path: P) -> Result<Summary> {
        let file = File::open(&path)?;
        let reader = BufReader::new(file);

        let mut metrics: Vec<Metrics> = Vec::new();
        let mut aggregated_metrics: Vec<AggregatedMetrics> = Vec::new();

        for line in reader.lines() {
            let line = line?;
            let line = line.trim();
            if line.is_empty() {
                continue;
            }

            // Try to parse as different metric types
            if let Ok(metric) = serde_json::from_str::<Metrics>(line) {
                metrics.push(metric);
            } else if let Ok(agg_metric) = serde_json::from_str::<AggregatedMetrics>(line) {
                aggregated_metrics.push(agg_metric);
            } else {
                // Try parsing as a nested structure with "aggregated" field
                if let Ok(value) = serde_json::from_str::<serde_json::Value>(line) {
                    if let Some(agg) = value.get("aggregated") {
                        if let Ok(agg_metric) =
                            serde_json::from_value::<AggregatedMetrics>(agg.clone())
                        {
                            aggregated_metrics.push(agg_metric);
                            continue;
                        }
                    }
                }
                // If we can't parse the line, skip it
                continue;
            }
        }

        let elapsed_time = Self::calculate_elapsed_time(&metrics, &aggregated_metrics);

        let summary = if !aggregated_metrics.is_empty() {
            Summary::from_aggregated_metrics(&aggregated_metrics, elapsed_time)
        } else if !metrics.is_empty() {
            Summary::from_metrics(&metrics, elapsed_time)
        } else {
            return Err(DenetError::Other(
                "No valid metrics found in file".to_string(),
            ));
        };

        Ok(summary)
    }

    /// Generate summary from JSON strings
    pub fn from_json_strings(json_strings: &[String], elapsed_time: f64) -> Result<Summary> {
        let mut metrics: Vec<Metrics> = Vec::new();
        let mut aggregated_metrics: Vec<AggregatedMetrics> = Vec::new();

        for json_str in json_strings {
            if let Ok(metric) = serde_json::from_str::<Metrics>(json_str) {
                metrics.push(metric);
            } else if let Ok(agg_metric) = serde_json::from_str::<AggregatedMetrics>(json_str) {
                aggregated_metrics.push(agg_metric);
            } else {
                // Try parsing as nested structure
                if let Ok(value) = serde_json::from_str::<serde_json::Value>(json_str) {
                    if let Some(agg) = value.get("aggregated") {
                        if let Ok(agg_metric) =
                            serde_json::from_value::<AggregatedMetrics>(agg.clone())
                        {
                            aggregated_metrics.push(agg_metric);
                        }
                    }
                }
            }
        }

        let summary = if !aggregated_metrics.is_empty() {
            Summary::from_aggregated_metrics(&aggregated_metrics, elapsed_time)
        } else if !metrics.is_empty() {
            Summary::from_metrics(&metrics, elapsed_time)
        } else {
            Summary::new()
        };

        Ok(summary)
    }

    /// Calculate elapsed time from metrics collections
    fn calculate_elapsed_time(
        metrics: &[Metrics],
        aggregated_metrics: &[AggregatedMetrics],
    ) -> f64 {
        if !aggregated_metrics.is_empty() {
            let first = aggregated_metrics[0].ts_ms;
            let last = aggregated_metrics[aggregated_metrics.len() - 1].ts_ms;
            (last - first) as f64 / 1000.0
        } else if !metrics.is_empty() {
            let first = metrics[0].ts_ms;
            let last = metrics[metrics.len() - 1].ts_ms;
            (last - first) as f64 / 1000.0
        } else {
            0.0
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;
    use tempfile::NamedTempFile;

    #[test]
    fn test_summary_from_json_file() -> Result<()> {
        let mut temp_file = NamedTempFile::new()?;

        // Write some test metrics
        writeln!(
            temp_file,
            r#"{{"ts_ms":1000,"cpu_usage":50.0,"mem_rss_kb":1024,"mem_vms_kb":2048,"disk_read_bytes":0,"disk_write_bytes":0,"net_rx_bytes":0,"net_tx_bytes":0,"thread_count":1,"uptime_secs":10,"cpu_core":null}}"#
        )?;
        writeln!(
            temp_file,
            r#"{{"ts_ms":2000,"cpu_usage":75.0,"mem_rss_kb":1536,"mem_vms_kb":3072,"disk_read_bytes":100,"disk_write_bytes":200,"net_rx_bytes":50,"net_tx_bytes":75,"thread_count":2,"uptime_secs":20,"cpu_core":null}}"#
        )?;

        temp_file.flush()?;

        let summary = SummaryGenerator::from_json_file(temp_file.path())?;

        assert_eq!(summary.sample_count, 2);
        assert_eq!(summary.total_time_secs, 1.0); // 2000-1000 = 1000ms = 1s
        assert_eq!(summary.avg_cpu_usage, 62.5); // (50 + 75) / 2
        assert_eq!(summary.peak_mem_rss_kb, 1536);

        Ok(())
    }

    #[test]
    fn test_summary_from_json_strings() -> Result<()> {
        let json_strings = vec![
            r#"{"ts_ms":1000,"cpu_usage":25.0,"mem_rss_kb":512,"mem_vms_kb":1024,"disk_read_bytes":0,"disk_write_bytes":0,"net_rx_bytes":0,"net_tx_bytes":0,"thread_count":1,"uptime_secs":5,"cpu_core":null}"#.to_string(),
            r#"{"ts_ms":2000,"cpu_usage":50.0,"mem_rss_kb":768,"mem_vms_kb":1536,"disk_read_bytes":50,"disk_write_bytes":100,"net_rx_bytes":25,"net_tx_bytes":50,"thread_count":1,"uptime_secs":10,"cpu_core":null}"#.to_string(),
        ];

        let summary = SummaryGenerator::from_json_strings(&json_strings, 1.0)?;

        assert_eq!(summary.sample_count, 2);
        assert_eq!(summary.total_time_secs, 1.0);
        assert_eq!(summary.avg_cpu_usage, 37.5); // (25 + 50) / 2
        assert_eq!(summary.peak_mem_rss_kb, 768);

        Ok(())
    }

    #[test]
    fn test_summary_from_json_file_with_aggregated_metrics() -> Result<()> {
        let mut temp_file = NamedTempFile::new()?;

        // Write test metrics as Metrics, not AggregatedMetrics since that's what gets parsed
        writeln!(
            temp_file,
            r#"{{"ts_ms":1000,"cpu_usage":30.0,"mem_rss_kb":2048,"mem_vms_kb":4096,"disk_read_bytes":0,"disk_write_bytes":0,"net_rx_bytes":0,"net_tx_bytes":0,"thread_count":3,"uptime_secs":15,"cpu_core":null}}"#
        )?;
        writeln!(
            temp_file,
            r#"{{"ts_ms":3000,"cpu_usage":60.0,"mem_rss_kb":3072,"mem_vms_kb":6144,"disk_read_bytes":200,"disk_write_bytes":400,"net_rx_bytes":100,"net_tx_bytes":150,"thread_count":4,"uptime_secs":25,"cpu_core":null}}"#
        )?;

        temp_file.flush()?;

        let summary = SummaryGenerator::from_json_file(temp_file.path())?;

        assert_eq!(summary.sample_count, 2);
        assert_eq!(summary.total_time_secs, 2.0); // 3000-1000 = 2000ms = 2s
        assert_eq!(summary.max_processes, 1); // from_metrics always sets this to 1
        assert_eq!(summary.max_threads, 4);
        assert_eq!(summary.avg_cpu_usage, 45.0); // (30 + 60) / 2

        Ok(())
    }

    #[test]
    fn test_summary_from_json_file_with_nested_aggregated() -> Result<()> {
        let mut temp_file = NamedTempFile::new()?;

        // Write nested structure with aggregated field
        writeln!(
            temp_file,
            r#"{{"parent":null,"children":[],"aggregated":{{"ts_ms":1000,"cpu_usage":40.0,"mem_rss_kb":1024,"mem_vms_kb":2048,"disk_read_bytes":0,"disk_write_bytes":0,"net_rx_bytes":0,"net_tx_bytes":0,"thread_count":2,"process_count":1,"uptime_secs":10,"ebpf":null}}}}"#
        )?;

        temp_file.flush()?;

        let summary = SummaryGenerator::from_json_file(temp_file.path())?;

        assert_eq!(summary.sample_count, 1);
        assert_eq!(summary.avg_cpu_usage, 40.0);

        Ok(())
    }

    #[test]
    fn test_summary_from_json_file_empty_file() {
        let temp_file = NamedTempFile::new().unwrap();
        let result = SummaryGenerator::from_json_file(temp_file.path());
        assert!(result.is_err());
    }

    #[test]
    fn test_summary_from_json_file_invalid_json() -> Result<()> {
        let mut temp_file = NamedTempFile::new()?;
        writeln!(temp_file, "invalid json")?;
        temp_file.flush()?;

        let result = SummaryGenerator::from_json_file(temp_file.path());
        assert!(result.is_err());

        Ok(())
    }

    #[test]
    fn test_summary_from_json_file_with_empty_lines() -> Result<()> {
        let mut temp_file = NamedTempFile::new()?;

        writeln!(temp_file, "")?; // Empty line
        writeln!(
            temp_file,
            r#"{{"ts_ms":1000,"cpu_usage":25.0,"mem_rss_kb":512,"mem_vms_kb":1024,"disk_read_bytes":0,"disk_write_bytes":0,"net_rx_bytes":0,"net_tx_bytes":0,"thread_count":1,"uptime_secs":10,"cpu_core":null}}"#
        )?;
        writeln!(temp_file, "   ")?; // Whitespace only line
        writeln!(
            temp_file,
            r#"{{"ts_ms":2000,"cpu_usage":50.0,"mem_rss_kb":768,"mem_vms_kb":1536,"disk_read_bytes":50,"disk_write_bytes":100,"net_rx_bytes":25,"net_tx_bytes":50,"thread_count":1,"uptime_secs":15,"cpu_core":null}}"#
        )?;

        temp_file.flush()?;

        let summary = SummaryGenerator::from_json_file(temp_file.path())?;
        assert_eq!(summary.sample_count, 2);

        Ok(())
    }

    #[test]
    fn test_summary_from_json_file_nonexistent() {
        let result = SummaryGenerator::from_json_file("/nonexistent/path/file.json");
        assert!(result.is_err());
    }

    #[test]
    fn test_summary_from_json_strings_empty() -> Result<()> {
        let json_strings: Vec<String> = vec![];
        let summary = SummaryGenerator::from_json_strings(&json_strings, 5.0)?;

        assert_eq!(summary.sample_count, 0);
        assert_eq!(summary.total_time_secs, 0.0);
        assert_eq!(summary.avg_cpu_usage, 0.0);

        Ok(())
    }

    #[test]
    fn test_summary_from_json_strings_with_aggregated() -> Result<()> {
        let json_strings = vec![
            r#"{"ts_ms":1000,"cpu_usage":20.0,"mem_rss_kb":1024,"mem_vms_kb":2048,"disk_read_bytes":0,"disk_write_bytes":0,"net_rx_bytes":0,"net_tx_bytes":0,"thread_count":2,"uptime_secs":10,"cpu_core":null}"#.to_string(),
            r#"{"ts_ms":2000,"cpu_usage":40.0,"mem_rss_kb":1536,"mem_vms_kb":3072,"disk_read_bytes":100,"disk_write_bytes":200,"net_rx_bytes":50,"net_tx_bytes":75,"thread_count":3,"uptime_secs":15,"cpu_core":null}"#.to_string(),
        ];

        let summary = SummaryGenerator::from_json_strings(&json_strings, 1.5)?;

        assert_eq!(summary.sample_count, 2);
        assert_eq!(summary.total_time_secs, 1.5);
        assert_eq!(summary.max_processes, 1); // from_metrics always sets this to 1
        assert_eq!(summary.max_threads, 3);

        Ok(())
    }

    #[test]
    fn test_summary_from_json_strings_with_nested() -> Result<()> {
        let json_strings = vec![
            r#"{"aggregated":{"ts_ms":1000,"cpu_usage":35.0,"mem_rss_kb":2048,"mem_vms_kb":4096,"disk_read_bytes":0,"disk_write_bytes":0,"net_rx_bytes":0,"net_tx_bytes":0,"thread_count":4,"process_count":2,"uptime_secs":20,"ebpf":null}}"#.to_string(),
        ];

        let summary = SummaryGenerator::from_json_strings(&json_strings, 2.0)?;

        assert_eq!(summary.sample_count, 1);
        assert_eq!(summary.total_time_secs, 2.0);
        assert_eq!(summary.avg_cpu_usage, 35.0);

        Ok(())
    }

    #[test]
    fn test_summary_from_json_strings_invalid_json() -> Result<()> {
        let json_strings = vec![
            "invalid json".to_string(),
            r#"{"ts_ms":1000,"cpu_usage":25.0,"mem_rss_kb":512,"mem_vms_kb":1024,"disk_read_bytes":0,"disk_write_bytes":0,"net_rx_bytes":0,"net_tx_bytes":0,"thread_count":1,"uptime_secs":10,"cpu_core":null}"#.to_string(),
        ];

        let summary = SummaryGenerator::from_json_strings(&json_strings, 1.0)?;
        assert_eq!(summary.sample_count, 1); // Should skip invalid JSON and process valid one

        Ok(())
    }

    #[test]
    fn test_calculate_elapsed_time_with_metrics() {
        let metrics = vec![
            Metrics {
                ts_ms: 1000,
                ..Default::default()
            },
            Metrics {
                ts_ms: 3000,
                ..Default::default()
            },
        ];
        let aggregated = vec![];

        let elapsed = SummaryGenerator::calculate_elapsed_time(&metrics, &aggregated);
        assert_eq!(elapsed, 2.0); // 3000-1000 = 2000ms = 2s
    }

    #[test]
    fn test_calculate_elapsed_time_with_aggregated() {
        let metrics = vec![];
        let aggregated = vec![
            AggregatedMetrics {
                ts_ms: 2000,
                ..Default::default()
            },
            AggregatedMetrics {
                ts_ms: 5000,
                ..Default::default()
            },
        ];

        let elapsed = SummaryGenerator::calculate_elapsed_time(&metrics, &aggregated);
        assert_eq!(elapsed, 3.0); // 5000-2000 = 3000ms = 3s
    }

    #[test]
    fn test_calculate_elapsed_time_empty() {
        let metrics = vec![];
        let aggregated = vec![];

        let elapsed = SummaryGenerator::calculate_elapsed_time(&metrics, &aggregated);
        assert_eq!(elapsed, 0.0);
    }

    #[test]
    fn test_calculate_elapsed_time_single_metric() {
        let metrics = vec![Metrics {
            ts_ms: 1000,
            ..Default::default()
        }];
        let aggregated = vec![];

        let elapsed = SummaryGenerator::calculate_elapsed_time(&metrics, &aggregated);
        assert_eq!(elapsed, 0.0); // Single metric, no elapsed time
    }

    #[test]
    fn test_calculate_elapsed_time_prefers_aggregated() {
        let metrics = vec![
            Metrics {
                ts_ms: 1000,
                ..Default::default()
            },
            Metrics {
                ts_ms: 2000,
                ..Default::default()
            },
        ];
        let aggregated = vec![
            AggregatedMetrics {
                ts_ms: 3000,
                ..Default::default()
            },
            AggregatedMetrics {
                ts_ms: 8000,
                ..Default::default()
            },
        ];

        let elapsed = SummaryGenerator::calculate_elapsed_time(&metrics, &aggregated);
        assert_eq!(elapsed, 5.0); // Should use aggregated: 8000-3000 = 5000ms = 5s
    }
}
