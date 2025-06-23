//! Python bindings for denet
//!
//! This module contains all PyO3 bindings, separated from the core Rust functionality
//! for better modularity and maintainability.

use crate::config::{OutputConfig, OutputFormat};
use crate::core::process_monitor::ProcessMonitor;
use crate::error::DenetError;
use crate::monitor::{Summary, SummaryGenerator};

use pyo3::prelude::*;
use pyo3::wrap_pyfunction;
use std::time::Duration;

/// Helper function to convert IO errors to Python errors
fn map_io_error(err: std::io::Error) -> pyo3::PyErr {
    pyo3::exceptions::PyRuntimeError::new_err(format!("IO Error: {err}"))
}

/// Python wrapper for ProcessMonitor
#[pyclass(name = "ProcessMonitor")]
struct PyProcessMonitor {
    inner: ProcessMonitor,
    samples: Vec<String>,
    output_config: OutputConfig,
    metadata_written: bool,
}

/// Build OutputConfig with consistent settings
fn build_output_config(
    output_file: Option<String>,
    output_format: &str,
    store_in_memory: bool,
    quiet: bool,
    write_metadata: bool,
) -> PyResult<OutputConfig> {
    let mut builder = OutputConfig::builder()
        .format_str(output_format)?
        .store_in_memory(store_in_memory)
        .quiet(quiet)
        .write_metadata(write_metadata);

    if let Some(path) = output_file {
        builder = builder.output_file(path);
    }

    Ok(builder.build())
}

#[pymethods]
impl PyProcessMonitor {
    #[new]
    #[pyo3(signature = (cmd, base_interval_ms, max_interval_ms, since_process_start=false, output_file=None, output_format="jsonl", store_in_memory=true, quiet=false, include_children=true, write_metadata=false))]
    #[allow(clippy::too_many_arguments)]
    fn new(
        cmd: Vec<String>,
        base_interval_ms: u64,
        max_interval_ms: u64,
        since_process_start: bool,
        output_file: Option<String>,
        output_format: &str,
        store_in_memory: bool,
        quiet: bool,
        include_children: bool,
        write_metadata: bool,
    ) -> PyResult<Self> {
        let output_config = build_output_config(
            output_file,
            output_format,
            store_in_memory,
            quiet,
            write_metadata,
        )?;

        let mut inner = ProcessMonitor::new_with_options(
            cmd,
            Duration::from_millis(base_interval_ms),
            Duration::from_millis(max_interval_ms),
            since_process_start,
        )
        .map_err(map_io_error)?;

        // Enable child process monitoring if requested
        inner.set_include_children(include_children);

        Ok(PyProcessMonitor {
            inner,
            samples: Vec::new(),
            output_config,
            metadata_written: false,
        })
    }

    #[staticmethod]
    #[allow(clippy::too_many_arguments)]
    #[pyo3(signature = (pid, base_interval_ms, max_interval_ms, since_process_start=false, output_file=None, output_format="jsonl", store_in_memory=true, quiet=false, include_children=true, write_metadata=false))]
    fn from_pid(
        pid: usize,
        base_interval_ms: u64,
        max_interval_ms: u64,
        since_process_start: bool,
        output_file: Option<String>,
        output_format: &str,
        store_in_memory: bool,
        quiet: bool,
        include_children: bool,
        write_metadata: Option<bool>,
    ) -> PyResult<Self> {
        let output_config = build_output_config(
            output_file,
            output_format,
            store_in_memory,
            quiet,
            write_metadata.unwrap_or(false),
        )?;
        let mut inner = ProcessMonitor::from_pid_with_options(
            pid,
            Duration::from_millis(base_interval_ms),
            Duration::from_millis(max_interval_ms),
            since_process_start,
        )
        .map_err(map_io_error)?;

        // Enable child process monitoring if requested
        inner.set_include_children(include_children);

        Ok(PyProcessMonitor {
            inner,
            samples: Vec::new(),
            output_config,
            metadata_written: false,
        })
    }

    #[staticmethod]
    #[allow(clippy::too_many_arguments)]
    #[pyo3(signature = (cmd, stdout_file=None, stderr_file=None, timeout=None, base_interval_ms=100, max_interval_ms=1000, store_in_memory=true, output_file=None, output_format="jsonl", since_process_start=false, pause_for_attachment=true, quiet=false, include_children=true))]
    fn execute_with_monitoring(
        py: Python,
        cmd: Vec<String>,
        stdout_file: Option<String>,
        stderr_file: Option<String>,
        timeout: Option<f64>,
        base_interval_ms: u64,
        max_interval_ms: u64,
        store_in_memory: bool,
        output_file: Option<String>,
        output_format: &str,
        since_process_start: bool,
        pause_for_attachment: bool,
        quiet: bool,
        include_children: bool,
    ) -> PyResult<(i32, PyProcessMonitor)> {
        use std::fs::OpenOptions;
        use std::time::Duration;

        // Import Python modules for subprocess and signal handling
        let subprocess = py.import_bound("subprocess")?;
        let os = py.import_bound("os")?;
        let signal = py.import_bound("signal")?;
        let _time = py.import_bound("time")?;

        // Prepare file handles for redirection
        let stdout_arg = if let Some(path) = &stdout_file {
            let file = OpenOptions::new()
                .create(true)
                .write(true)
                .truncate(true)
                .open(path)
                .map_err(map_io_error)?;
            Some(file)
        } else {
            None
        };

        let stderr_arg = if let Some(path) = &stderr_file {
            let file = OpenOptions::new()
                .create(true)
                .write(true)
                .truncate(true)
                .open(path)
                .map_err(map_io_error)?;
            Some(file)
        } else {
            None
        };

        // Create subprocess using Python's subprocess module for better signal control
        let popen_kwargs = pyo3::types::PyDict::new_bound(py);
        popen_kwargs.set_item("start_new_session", true)?;

        if stdout_arg.is_some() {
            popen_kwargs.set_item("stdout", stdout_file.as_ref().unwrap())?;
        }
        if stderr_arg.is_some() {
            popen_kwargs.set_item("stderr", stderr_file.as_ref().unwrap())?;
        }

        let process = subprocess.call_method("Popen", (cmd.clone(),), Some(&popen_kwargs))?;
        let pid: i32 = process.getattr("pid")?.extract()?;

        // Immediately pause the process if requested
        if pause_for_attachment {
            let sigstop = signal.getattr("SIGSTOP")?;
            os.call_method("kill", (pid, sigstop), None)?;
        }

        // Create output configuration
        let output_config = if let Some(path) = output_file {
            OutputConfig::builder()
                .output_file(path)
                .format_str(output_format)?
                .store_in_memory(store_in_memory)
                .quiet(quiet)
                .build()
        } else {
            OutputConfig::builder()
                .format_str(output_format)?
                .store_in_memory(store_in_memory)
                .quiet(quiet)
                .build()
        };

        // Create monitor for the process
        let mut inner = ProcessMonitor::from_pid_with_options(
            pid as usize,
            Duration::from_millis(base_interval_ms),
            Duration::from_millis(max_interval_ms),
            since_process_start,
        )
        .map_err(|e| pyo3::exceptions::PyRuntimeError::new_err(format!("IO Error: {e}")))?;

        // Set include_children flag
        inner.set_include_children(include_children);

        let monitor = PyProcessMonitor {
            inner,
            samples: Vec::new(),
            output_config,
            metadata_written: false,
        };

        // Resume the process if it was paused
        if pause_for_attachment {
            let sigcont = signal.getattr("SIGCONT")?;
            os.call_method("kill", (pid, sigcont), None)?;
        }

        // Wait for process completion with timeout
        let exit_code = if let Some(timeout_secs) = timeout {
            let timeout_dict = pyo3::types::PyDict::new_bound(py);
            timeout_dict.set_item("timeout", timeout_secs)?;

            match process.call_method("wait", (), Some(&timeout_dict)) {
                Ok(code) => code.extract::<i32>()?,
                Err(_e) => {
                    // Handle timeout - kill the process
                    let _ = process.call_method("kill", (), None);
                    return Err(pyo3::exceptions::PyTimeoutError::new_err(format!(
                        "Process timed out after {timeout_secs}s"
                    )));
                }
            }
        } else {
            process.call_method("wait", (), None)?.extract::<i32>()?
        };

        Ok((exit_code, monitor))
    }

    fn run(&mut self) -> PyResult<()> {
        use std::fs::OpenOptions;
        use std::io::Write;
        use std::thread::sleep;

        // Open file if output_file is specified
        let mut file_handle = if let Some(path) = &self.output_config.output_file {
            let file = OpenOptions::new()
                .create(true)
                .write(true)
                .truncate(true)
                .open(path)
                .map_err(map_io_error)?;
            Some(file)
        } else {
            None
        };

        while self.inner.is_running() {
            if let Some(metrics) = self.inner.sample_metrics() {
                let json = serde_json::to_string(&metrics)
                    .map_err(|e| pyo3::exceptions::PyRuntimeError::new_err(e.to_string()))?;

                // Store in memory if enabled
                if self.output_config.store_in_memory {
                    // Convert metrics to JSON string and store
                    if let Ok(json) = serde_json::to_string(&metrics) {
                        self.samples.push(json);
                    }
                }

                // Write to file if output_file is specified
                if let Some(file) = &mut file_handle {
                    match self.output_config.format {
                        OutputFormat::JsonLines => {
                            writeln!(file, "{json}").map_err(map_io_error)?;
                        }
                        _ => {
                            writeln!(file, "{json}").map_err(map_io_error)?;
                        }
                    }
                } else if !self.output_config.quiet {
                    println!("{json}");
                }
            }
            sleep(self.inner.adaptive_interval());
        }
        Ok(())
    }

    fn sample_once(&mut self) -> PyResult<Option<String>> {
        use std::fs::OpenOptions;
        use std::io::Write;

        // First check if the process is running
        if !self.inner.is_running() {
            return Ok(None);
        }

        // Decide which sampling method to use based on include_children setting
        let metrics_json = if self.inner.get_include_children() {
            // Sample the metrics including child processes
            let tree_metrics = self.inner.sample_tree_metrics();
            serde_json::to_string(&tree_metrics)
                .map_err(|e| pyo3::exceptions::PyRuntimeError::new_err(e.to_string()))?
        } else {
            // Sample only the parent process
            match self.inner.sample_metrics() {
                Some(metrics) => serde_json::to_string(&metrics)
                    .map_err(|e| pyo3::exceptions::PyRuntimeError::new_err(e.to_string()))?,
                None => return Ok(None),
            }
        };

        // Store in memory if enabled
        if self.output_config.store_in_memory {
            self.samples.push(metrics_json.clone());
        }

        // Write to file if output_file is specified
        if let Some(path) = &self.output_config.output_file {
            // Write metadata as first line if enabled and not yet written
            if self.output_config.write_metadata && !self.metadata_written {
                if let Some(metadata) = self.inner.get_metadata() {
                    let metadata_json = serde_json::to_string(&metadata)
                        .map_err(|e| pyo3::exceptions::PyRuntimeError::new_err(e.to_string()))?;

                    let mut file = OpenOptions::new()
                        .create(true)
                        .write(true)
                        .truncate(true)
                        .open(path)
                        .map_err(map_io_error)?;

                    writeln!(file, "{metadata_json}").map_err(map_io_error)?;
                    self.metadata_written = true;
                }
            }

            let mut file = OpenOptions::new()
                .create(true)
                .append(true)
                .open(path)
                .map_err(map_io_error)?;

            writeln!(file, "{metrics_json}").map_err(map_io_error)?;
        }

        // Return the metrics JSON
        Ok(Some(metrics_json))
    }

    fn is_running(&mut self) -> PyResult<bool> {
        Ok(self.inner.is_running())
    }

    fn get_pid(&self) -> PyResult<usize> {
        Ok(self.inner.get_pid())
    }

    fn get_metadata(&mut self) -> PyResult<Option<String>> {
        Ok(self
            .inner
            .get_metadata()
            .and_then(|metadata| serde_json::to_string(&metadata).ok()))
    }

    fn get_samples(&self) -> Vec<String> {
        // Samples are already stored as strings, just clone them
        self.samples.clone()
    }

    fn clear_samples(&mut self) {
        self.samples.clear();
    }

    fn save_samples(&self, path: String, format: Option<String>) -> PyResult<()> {
        use std::fs::File;
        use std::io::Write;

        let output_format: OutputFormat = format
            .unwrap_or_else(|| "jsonl".to_string())
            .parse()
            .map_err(|e: DenetError| pyo3::exceptions::PyValueError::new_err(e.to_string()))?;

        let mut file = File::create(&path).map_err(map_io_error)?;

        match output_format {
            OutputFormat::Json => {
                // Create a JSON array from the string samples
                let json_array = format!("[{}]", self.samples.join(","));
                file.write_all(json_array.as_bytes())
                    .map_err(map_io_error)?;
            }
            OutputFormat::Csv => {
                // Write CSV header
                writeln!(file, "ts_ms,cpu_usage,mem_rss_kb,mem_vms_kb,disk_read_bytes,disk_write_bytes,net_rx_bytes,net_tx_bytes,thread_count,uptime_secs")
                    .map_err(map_io_error)?;

                // Write data rows
                for metrics_json in &self.samples {
                    // Parse each JSON string to extract values
                    if let Ok(metrics) = serde_json::from_str::<serde_json::Value>(metrics_json) {
                        // Extract values with fallbacks to 0
                        let ts_ms = metrics.get("ts_ms").and_then(|v| v.as_u64()).unwrap_or(0);
                        let cpu_usage = metrics
                            .get("cpu_usage")
                            .and_then(|v| v.as_f64())
                            .unwrap_or(0.0);
                        let mem_rss_kb = metrics
                            .get("mem_rss_kb")
                            .and_then(|v| v.as_u64())
                            .unwrap_or(0);
                        let mem_vms_kb = metrics
                            .get("mem_vms_kb")
                            .and_then(|v| v.as_u64())
                            .unwrap_or(0);
                        let disk_read_bytes = metrics
                            .get("disk_read_bytes")
                            .and_then(|v| v.as_u64())
                            .unwrap_or(0);
                        let disk_write_bytes = metrics
                            .get("disk_write_bytes")
                            .and_then(|v| v.as_u64())
                            .unwrap_or(0);
                        let net_rx_bytes = metrics
                            .get("net_rx_bytes")
                            .and_then(|v| v.as_u64())
                            .unwrap_or(0);
                        let net_tx_bytes = metrics
                            .get("net_tx_bytes")
                            .and_then(|v| v.as_u64())
                            .unwrap_or(0);
                        let thread_count = metrics
                            .get("thread_count")
                            .and_then(|v| v.as_u64())
                            .unwrap_or(0);
                        let uptime_secs = metrics
                            .get("uptime_secs")
                            .and_then(|v| v.as_u64())
                            .unwrap_or(0);

                        writeln!(
                            file,
                            "{ts_ms},{cpu_usage},{mem_rss_kb},{mem_vms_kb},{disk_read_bytes},{disk_write_bytes},{net_rx_bytes},{net_tx_bytes},{thread_count},{uptime_secs}"
                        )
                        .map_err(map_io_error)?;
                    }
                }
            }
            OutputFormat::JsonLines => {
                // Default to jsonl (one JSON object per line)
                // The samples are already JSON strings, so just write them
                for json in &self.samples {
                    writeln!(file, "{json}").map_err(map_io_error)?;
                }
            }
        }

        Ok(())
    }

    fn get_summary(&mut self) -> PyResult<String> {
        if self.samples.is_empty() {
            return serde_json::to_string(&Summary::new())
                .map_err(|e| pyo3::exceptions::PyRuntimeError::new_err(e.to_string()));
        }

        // Use the specialized function to generate summary from JSON strings
        // This matches what we're doing in the Python Monitor.get_summary() method
        let elapsed = if self.samples.len() > 1 {
            // Parse first and last sample to get timestamps
            let first: serde_json::Value = serde_json::from_str(&self.samples[0])
                .map_err(|e| pyo3::exceptions::PyRuntimeError::new_err(e.to_string()))?;
            let last: serde_json::Value =
                serde_json::from_str(&self.samples[self.samples.len() - 1])
                    .map_err(|e| pyo3::exceptions::PyRuntimeError::new_err(e.to_string()))?;

            let first_ts = first.get("ts_ms").and_then(|v| v.as_u64()).unwrap_or(0);
            let last_ts = last.get("ts_ms").and_then(|v| v.as_u64()).unwrap_or(0);

            (last_ts as f64 - first_ts as f64) / 1000.0
        } else {
            0.0
        };

        // Use the existing function to generate summary from metrics JSON
        let result = generate_summary_from_metrics_json(self.samples.clone(), elapsed)
            .map_err(|e| pyo3::exceptions::PyRuntimeError::new_err(e.to_string()))?;

        Ok(result)
    }
}

#[pyfunction]
fn generate_summary_from_file(path: String) -> PyResult<String> {
    match SummaryGenerator::from_json_file(&path) {
        Ok(summary) => Ok(serde_json::to_string(&summary)
            .map_err(|e| pyo3::exceptions::PyRuntimeError::new_err(e.to_string()))?),
        Err(e) => Err(pyo3::exceptions::PyIOError::new_err(e.to_string())),
    }
}

#[pyfunction]
fn generate_summary_from_metrics_json(
    metrics_json: Vec<String>,
    elapsed_time: f64,
) -> PyResult<String> {
    match SummaryGenerator::from_json_strings(&metrics_json, elapsed_time) {
        Ok(summary) => Ok(serde_json::to_string(&summary)
            .map_err(|e| pyo3::exceptions::PyRuntimeError::new_err(e.to_string()))?),
        Err(e) => Err(pyo3::exceptions::PyRuntimeError::new_err(e.to_string())),
    }
}

/// Register all Python classes and functions with the module
pub fn register_python_module(m: &Bound<'_, PyModule>) -> PyResult<()> {
    m.add_class::<PyProcessMonitor>()?;
    m.add_function(wrap_pyfunction!(generate_summary_from_file, m)?)?;
    m.add_function(wrap_pyfunction!(generate_summary_from_metrics_json, m)?)?;

    // Python profile decorator implementation is now moved to Python layer

    Ok(())
}
