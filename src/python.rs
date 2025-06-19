//! Python bindings for denet
//!
//! This module contains all PyO3 bindings, separated from the core Rust functionality
//! for better modularity and maintainability.

use crate::config::{OutputConfig, OutputFormat};
use crate::error::DenetError;
use crate::monitor::{Metrics, Summary, SummaryGenerator};
use crate::process_monitor::{io_err_to_py_err, ProcessMonitor};

use pyo3::prelude::*;
use pyo3::wrap_pyfunction;
use std::time::Duration;

/// Python wrapper for ProcessMonitor
#[pyclass(name = "ProcessMonitor")]
struct PyProcessMonitor {
    inner: ProcessMonitor,
    samples: Vec<Metrics>,
    output_config: OutputConfig,
}

#[pymethods]
impl PyProcessMonitor {
    #[new]
    #[pyo3(signature = (cmd, base_interval_ms, max_interval_ms, since_process_start=false, output_file=None, output_format="jsonl", store_in_memory=true, quiet=false))]
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
    ) -> PyResult<Self> {
        let output_config = OutputConfig::builder()
            .format_str(output_format)?
            .store_in_memory(store_in_memory)
            .quiet(quiet)
            .build();

        let output_config = if let Some(path) = output_file {
            OutputConfig::builder()
                .output_file(path)
                .format_str(output_format)?
                .store_in_memory(store_in_memory)
                .quiet(quiet)
                .build()
        } else {
            output_config
        };

        let inner = ProcessMonitor::new_with_options(
            cmd,
            Duration::from_millis(base_interval_ms),
            Duration::from_millis(max_interval_ms),
            since_process_start,
        )
        .map_err(io_err_to_py_err)?;

        Ok(PyProcessMonitor {
            inner,
            samples: Vec::new(),
            output_config,
        })
    }

    #[staticmethod]
    #[allow(clippy::too_many_arguments)]
    #[pyo3(signature = (pid, base_interval_ms, max_interval_ms, since_process_start=false, output_file=None, output_format="jsonl", store_in_memory=true, quiet=false))]
    fn from_pid(
        pid: usize,
        base_interval_ms: u64,
        max_interval_ms: u64,
        since_process_start: bool,
        output_file: Option<String>,
        output_format: &str,
        store_in_memory: bool,
        quiet: bool,
    ) -> PyResult<Self> {
        let output_config = OutputConfig::builder()
            .format_str(output_format)?
            .store_in_memory(store_in_memory)
            .quiet(quiet)
            .build();

        let output_config = if let Some(path) = output_file {
            OutputConfig::builder()
                .output_file(path)
                .format_str(output_format)?
                .store_in_memory(store_in_memory)
                .quiet(quiet)
                .build()
        } else {
            output_config
        };

        let inner = ProcessMonitor::from_pid_with_options(
            pid,
            Duration::from_millis(base_interval_ms),
            Duration::from_millis(max_interval_ms),
            since_process_start,
        )
        .map_err(io_err_to_py_err)?;

        Ok(PyProcessMonitor {
            inner,
            samples: Vec::new(),
            output_config,
        })
    }

    #[staticmethod]
    #[allow(clippy::too_many_arguments)]
    #[pyo3(signature = (cmd, stdout_file=None, stderr_file=None, timeout=None, base_interval_ms=100, max_interval_ms=1000, store_in_memory=true, output_file=None, output_format="jsonl", since_process_start=false, pause_for_attachment=true, quiet=false))]
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
                .map_err(io_err_to_py_err)?;
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
                .map_err(io_err_to_py_err)?;
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
        let inner = ProcessMonitor::from_pid_with_options(
            pid as usize,
            Duration::from_millis(base_interval_ms),
            Duration::from_millis(max_interval_ms),
            since_process_start,
        )
        .map_err(io_err_to_py_err)?;

        let monitor = PyProcessMonitor {
            inner,
            samples: Vec::new(),
            output_config,
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
                        "Process timed out after {}s",
                        timeout_secs
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
                .map_err(io_err_to_py_err)?;
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
                    self.samples.push(metrics);
                }

                // Write to file if output_file is specified
                if let Some(file) = &mut file_handle {
                    match self.output_config.format {
                        OutputFormat::JsonLines => {
                            writeln!(file, "{}", json).map_err(io_err_to_py_err)?;
                        }
                        _ => {
                            writeln!(file, "{}", json).map_err(io_err_to_py_err)?;
                        }
                    }
                } else if !self.output_config.quiet {
                    println!("{}", json);
                }
            }
            sleep(self.inner.adaptive_interval());
        }
        Ok(())
    }

    fn sample_once(&mut self) -> PyResult<Option<String>> {
        use std::fs::OpenOptions;
        use std::io::Write;

        let metrics_opt = self.inner.sample_metrics();

        if let Some(metrics) = &metrics_opt {
            // Store in memory if enabled
            if self.output_config.store_in_memory {
                self.samples.push(metrics.clone());
            }

            // Write to file if output_file is specified
            if let Some(path) = &self.output_config.output_file {
                let mut file = OpenOptions::new()
                    .create(true)
                    .append(true)
                    .open(path)
                    .map_err(io_err_to_py_err)?;

                let json = serde_json::to_string(&metrics)
                    .map_err(|e| pyo3::exceptions::PyRuntimeError::new_err(e.to_string()))?;
                writeln!(file, "{}", json).map_err(io_err_to_py_err)?;
            }
        }

        // Return JSON string for backward compatibility
        Ok(metrics_opt.and_then(|metrics| serde_json::to_string(&metrics).ok()))
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
        self.samples
            .iter()
            .filter_map(|m| serde_json::to_string(m).ok())
            .collect()
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

        let mut file = File::create(&path).map_err(io_err_to_py_err)?;

        match output_format {
            OutputFormat::Json => {
                let json_array = serde_json::to_string(&self.samples)
                    .map_err(|e| pyo3::exceptions::PyRuntimeError::new_err(e.to_string()))?;
                file.write_all(json_array.as_bytes())
                    .map_err(io_err_to_py_err)?;
            }
            OutputFormat::Csv => {
                // Write CSV header
                writeln!(file, "ts_ms,cpu_usage,mem_rss_kb,mem_vms_kb,disk_read_bytes,disk_write_bytes,net_rx_bytes,net_tx_bytes,thread_count,uptime_secs")
                    .map_err(io_err_to_py_err)?;

                // Write data rows
                for metrics in &self.samples {
                    writeln!(
                        file,
                        "{},{},{},{},{},{},{},{},{},{}",
                        metrics.ts_ms,
                        metrics.cpu_usage,
                        metrics.mem_rss_kb,
                        metrics.mem_vms_kb,
                        metrics.disk_read_bytes,
                        metrics.disk_write_bytes,
                        metrics.net_rx_bytes,
                        metrics.net_tx_bytes,
                        metrics.thread_count,
                        metrics.uptime_secs
                    )
                    .map_err(io_err_to_py_err)?;
                }
            }
            OutputFormat::JsonLines => {
                // Default to jsonl (one JSON object per line)
                for metrics in &self.samples {
                    let json = serde_json::to_string(&metrics)
                        .map_err(|e| pyo3::exceptions::PyRuntimeError::new_err(e.to_string()))?;
                    writeln!(file, "{}", json).map_err(io_err_to_py_err)?;
                }
            }
        }

        Ok(())
    }

    fn get_summary(&self) -> PyResult<String> {
        if self.samples.is_empty() {
            return serde_json::to_string(&Summary::new())
                .map_err(|e| pyo3::exceptions::PyRuntimeError::new_err(e.to_string()));
        }

        // Calculate elapsed time from first to last sample
        let first = &self.samples[0];
        let last = &self.samples[self.samples.len() - 1];
        let elapsed_time = (last.ts_ms - first.ts_ms) as f64 / 1000.0;

        let summary = Summary::from_metrics(&self.samples, elapsed_time);
        serde_json::to_string(&summary)
            .map_err(|e| pyo3::exceptions::PyRuntimeError::new_err(e.to_string()))
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

// Profile decorator implementation
#[pyfunction]
#[pyo3(signature = (
    func,
    base_interval_ms = 100,
    max_interval_ms = 1000,
    output_file = None,
    output_format = "jsonl",
    store_in_memory = true,
    include_children = true
))]
#[allow(clippy::too_many_arguments)]
fn profile<'a>(
    py: Python<'a>,
    func: &Bound<'a, PyAny>,
    base_interval_ms: u64,
    max_interval_ms: u64,
    output_file: Option<String>,
    output_format: &str,
    store_in_memory: bool,
    include_children: bool,
) -> PyResult<Bound<'a, PyAny>> {
    // Create a decorator that will wrap the function
    use pyo3::types::PyDict;
    let locals = PyDict::new_bound(py);
    locals.set_item("func", func)?;
    locals.set_item("base_interval_ms", base_interval_ms)?;
    locals.set_item("max_interval_ms", max_interval_ms)?;
    locals.set_item("output_file", output_file)?;
    locals.set_item("output_format", output_format)?;
    locals.set_item("store_in_memory", store_in_memory)?;
    locals.set_item("include_children", include_children)?;
    locals.set_item("ProcessMonitor", py.get_type_bound::<PyProcessMonitor>())?;

    // Define a wrapper function
    py.eval_bound(
        include_str!("python/profile_decorator.py"),
        None,
        Some(&locals),
    )
    .map_err(|e| {
        e.print(py);
        pyo3::exceptions::PyRuntimeError::new_err("Failed to create profile decorator")
    })
}

// Context manager implementation
#[pyfunction]
#[pyo3(signature = (
    base_interval_ms = 100,
    max_interval_ms = 1000,
    output_file = None,
    output_format = "jsonl",
    store_in_memory = true
))]
fn monitor<'a>(
    py: Python<'a>,
    base_interval_ms: u64,
    max_interval_ms: u64,
    output_file: Option<String>,
    output_format: &str,
    store_in_memory: bool,
) -> PyResult<Bound<'a, PyAny>> {
    use pyo3::types::PyDict;
    let locals = PyDict::new_bound(py);
    locals.set_item("base_interval_ms", base_interval_ms)?;
    locals.set_item("max_interval_ms", max_interval_ms)?;
    locals.set_item("output_file", output_file)?;
    locals.set_item("output_format", output_format)?;
    locals.set_item("store_in_memory", store_in_memory)?;
    locals.set_item("ProcessMonitor", py.get_type_bound::<PyProcessMonitor>())?;

    py.eval_bound(
        include_str!("python/monitor_context.py"),
        None,
        Some(&locals),
    )
    .map_err(|e| {
        e.print(py);
        pyo3::exceptions::PyRuntimeError::new_err("Failed to create monitor context manager")
    })
}

/// Register all Python classes and functions with the module
pub fn register_python_module(m: &Bound<'_, PyModule>) -> PyResult<()> {
    m.add_class::<PyProcessMonitor>()?;
    m.add_function(wrap_pyfunction!(generate_summary_from_file, m)?)?;
    m.add_function(wrap_pyfunction!(generate_summary_from_metrics_json, m)?)?;
    m.add_function(wrap_pyfunction!(profile, m)?)?;
    m.add_function(wrap_pyfunction!(monitor, m)?)?;
    Ok(())
}
