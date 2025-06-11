// Split into modules to separate PyO3 dependencies from pure Rust code
pub mod process_monitor;

// Re-export the ProcessMonitor and related types for use in tests and binaries
pub use process_monitor::{
    AggregatedMetrics, ChildProcessMetrics, Metrics, ProcessMetadata, ProcessMonitor,
    ProcessTreeMetrics, Summary,
};

// Import what we need for the Python module
#[cfg(feature = "python")]
use pyo3::{prelude::*, wrap_pyfunction};

#[cfg(feature = "python")]
#[pyclass(name = "ProcessMonitor")]
struct PyProcessMonitor {
    inner: process_monitor::ProcessMonitor,
    samples: Vec<process_monitor::Metrics>,
    output_file: Option<String>,
    output_format: String,
    store_in_memory: bool,
}

#[cfg(feature = "python")]
#[pymethods]
impl PyProcessMonitor {
    #[new]
    #[pyo3(signature = (cmd, base_interval_ms, max_interval_ms, since_process_start=false, output_file=None, output_format="jsonl", store_in_memory=true))]
    fn new(
        cmd: Vec<String>,
        base_interval_ms: u64,
        max_interval_ms: u64,
        since_process_start: bool,
        output_file: Option<String>,
        output_format: &str,
        store_in_memory: bool,
    ) -> PyResult<Self> {
        use std::time::Duration;

        let inner = process_monitor::ProcessMonitor::new_with_options(
            cmd,
            Duration::from_millis(base_interval_ms),
            Duration::from_millis(max_interval_ms),
            since_process_start,
        )
        .map_err(process_monitor::io_err_to_py_err)?;

        Ok(PyProcessMonitor { 
            inner,
            samples: Vec::new(),
            output_file,
            output_format: output_format.to_string(),
            store_in_memory,
        })
    }

    #[staticmethod]
    #[pyo3(signature = (pid, base_interval_ms, max_interval_ms, since_process_start=false, output_file=None, output_format="jsonl", store_in_memory=true))]
    fn from_pid(
        pid: usize,
        base_interval_ms: u64,
        max_interval_ms: u64,
        since_process_start: bool,
        output_file: Option<String>,
        output_format: &str,
        store_in_memory: bool,
    ) -> PyResult<Self> {
        use std::time::Duration;

        let inner = process_monitor::ProcessMonitor::from_pid_with_options(
            pid,
            Duration::from_millis(base_interval_ms),
            Duration::from_millis(max_interval_ms),
            since_process_start,
        )
        .map_err(process_monitor::io_err_to_py_err)?;

        Ok(PyProcessMonitor { 
            inner,
            samples: Vec::new(),
            output_file,
            output_format: output_format.to_string(),
            store_in_memory,
        })
    }

    fn run(&mut self) -> PyResult<()> {
        use std::thread::sleep;
        use std::fs::OpenOptions;
        use std::io::Write;

        // Open file if output_file is specified
        let mut file_handle = if let Some(path) = &self.output_file {
            let file = OpenOptions::new()
                .create(true)
                .write(true)
                .truncate(true)
                .open(path)
                .map_err(process_monitor::io_err_to_py_err)?;
            Some(file)
        } else {
            None
        };

        while self.inner.is_running() {
            if let Some(metrics) = self.inner.sample_metrics() {
                let json = serde_json::to_string(&metrics).unwrap();
                
                // Store in memory if enabled
                if self.store_in_memory {
                    self.samples.push(metrics.clone());
                }
                
                // Write to file if output_file is specified
                if let Some(file) = &mut file_handle {
                    // For jsonl format, write one line per sample
                    if self.output_format == "jsonl" {
                        writeln!(file, "{}", json).map_err(process_monitor::io_err_to_py_err)?;
                    } else {
                        // For now, just write jsonl format regardless
                        // TODO: Implement other formats (CSV, etc.)
                        writeln!(file, "{}", json).map_err(process_monitor::io_err_to_py_err)?;
                    }
                } else {
                    // Default behavior: print to stdout
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
        
        // Process metrics if available
        if let Some(metrics) = &metrics_opt {
            // Store in memory if enabled
            if self.store_in_memory {
                self.samples.push(metrics.clone());
            }
            
            // Write to file if output_file is specified
            if let Some(path) = &self.output_file {
                let mut file = OpenOptions::new()
                    .create(true)
                    .append(true)
                    .open(path)
                    .map_err(process_monitor::io_err_to_py_err)?;
                
                let json = serde_json::to_string(&metrics).unwrap_or_default();
                writeln!(file, "{}", json).map_err(process_monitor::io_err_to_py_err)?;
            }
        }
        
        // Return JSON string as before for backward compatibility
        Ok(metrics_opt.map(|metrics| serde_json::to_string(&metrics).unwrap_or_default()))
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
            .map(|metadata| serde_json::to_string(&metadata).unwrap_or_default()))
    }
    
    // New methods for sample management
    
    fn get_samples(&self) -> Vec<String> {
        self.samples
            .iter()
            .map(|m| serde_json::to_string(m).unwrap_or_default())
            .collect()
    }
    
    fn clear_samples(&mut self) -> PyResult<()> {
        self.samples.clear();
        Ok(())
    }
    
    fn save_samples(&self, path: String, format: Option<String>) -> PyResult<()> {
        use std::fs::File;
        use std::io::Write;
        
        let output_format = format.unwrap_or_else(|| "jsonl".to_string());
        let mut file = File::create(&path).map_err(process_monitor::io_err_to_py_err)?;
        
        match output_format.as_str() {
            "json" => {
                // Write as a JSON array
                let json_array = serde_json::to_string(&self.samples).unwrap_or_default();
                file.write_all(json_array.as_bytes())
                    .map_err(process_monitor::io_err_to_py_err)?;
            },
            "csv" => {
                // Write as CSV
                // Header row
                writeln!(file, "ts_ms,cpu_usage,mem_rss_kb,mem_vms_kb,disk_read_bytes,disk_write_bytes,net_rx_bytes,net_tx_bytes,thread_count,uptime_secs")
                    .map_err(process_monitor::io_err_to_py_err)?;
                
                // Data rows
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
                    .map_err(process_monitor::io_err_to_py_err)?;
                }
            },
            _ => {
                // Default to jsonl (one JSON object per line)
                for metrics in &self.samples {
                    let json = serde_json::to_string(&metrics).unwrap_or_default();
                    writeln!(file, "{}", json).map_err(process_monitor::io_err_to_py_err)?;
                }
            }
        }
        
        Ok(())
    }
    
    fn get_summary(&self) -> PyResult<String> {
        if self.samples.is_empty() {
            return Ok(serde_json::to_string(&process_monitor::Summary::new()).unwrap_or_default());
        }
        
        // Calculate elapsed time from first to last sample
        let first = &self.samples[0];
        let last = &self.samples[self.samples.len() - 1];
        let elapsed_time = (last.ts_ms - first.ts_ms) as f64 / 1000.0; // Convert to seconds
        
        let summary = process_monitor::Summary::from_metrics(&self.samples, elapsed_time);
        Ok(serde_json::to_string(&summary).unwrap_or_default())
    }
}

#[cfg(feature = "python")]
#[pyfunction]
fn generate_summary_from_file(path: String) -> PyResult<String> {
    match process_monitor::Summary::from_json_file(&path) {
        Ok(summary) => Ok(serde_json::to_string(&summary).unwrap_or_default()),
        Err(e) => Err(pyo3::exceptions::PyIOError::new_err(format!(
            "Error reading metrics file: {}",
            e
        ))),
    }
}

#[cfg(feature = "python")]
#[pyfunction]
fn generate_summary_from_metrics_json(
    metrics_json: Vec<String>,
    elapsed_time: f64,
) -> PyResult<String> {
    let mut metrics: Vec<Metrics> = Vec::new();
    let mut agg_metrics: Vec<AggregatedMetrics> = Vec::new();

    for json_str in metrics_json {
        // Try parsing as various types of metrics
        if let Ok(m) = serde_json::from_str::<Metrics>(&json_str) {
            metrics.push(m);
        } else if let Ok(am) = serde_json::from_str::<AggregatedMetrics>(&json_str) {
            agg_metrics.push(am);
        } else {
            // Try parsing as tree metrics (with nested structure)
            let json_value: Result<serde_json::Value, _> = serde_json::from_str(&json_str);
            if let Ok(value) = json_value {
                // Check if this is a tree metrics structure with "aggregated" field
                if let Some(agg) = value.get("aggregated") {
                    if let Ok(am) = serde_json::from_value::<AggregatedMetrics>(agg.clone()) {
                        agg_metrics.push(am);
                    }
                }
            }
        }
    }

    let summary = if !agg_metrics.is_empty() {
        process_monitor::Summary::from_aggregated_metrics(&agg_metrics, elapsed_time)
    } else if !metrics.is_empty() {
        process_monitor::Summary::from_metrics(&metrics, elapsed_time)
    } else {
        process_monitor::Summary::new()
    };

    Ok(serde_json::to_string(&summary).unwrap_or_default())
}

#[cfg(feature = "python")]
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
fn profile<'a>(
    py: Python<'a>,
    func: &'a PyAny,
    base_interval_ms: u64,
    max_interval_ms: u64,
    output_file: Option<String>,
    output_format: &str,
    store_in_memory: bool,
    include_children: bool,
) -> PyResult<&'a PyAny> {
    // Create a decorator that will wrap the function
    use pyo3::types::PyDict;
    let locals = PyDict::new(py);
    locals.set_item("func", func)?;
    locals.set_item("base_interval_ms", base_interval_ms)?;
    locals.set_item("max_interval_ms", max_interval_ms)?;
    locals.set_item("output_file", output_file)?;
    locals.set_item("output_format", output_format)?;
    locals.set_item("store_in_memory", store_in_memory)?;
    locals.set_item("include_children", include_children)?;
    locals.set_item("ProcessMonitor", py.get_type::<PyProcessMonitor>())?;

    // Define a wrapper function that will time the original function
    py.eval(
        r#"
def wrapper(*args, **kwargs):
    import os
    import time
    import functools
    
    # Create a unique identifier for this run
    unique_id = f"func_{int(time.time() * 1000)}"
    
    # Create monitoring process with settings
    monitor = ProcessMonitor(
        cmd=["python", "-c", "import time; time.sleep(0.1)"],  # Placeholder
        base_interval_ms=base_interval_ms,
        max_interval_ms=max_interval_ms,
        output_file=output_file,
        output_format=output_format,
        store_in_memory=store_in_memory
    )
    
    # We need to create a monitoring thread since we can't directly monitor
    # the currently running Python process (we'd need to know its PID in advance)
    import threading
    import json
    
    # Flag to control monitoring thread
    monitoring = True
    
    def monitoring_thread():
        try:
            while monitoring:
                # Sample metrics from current process
                if os.name == 'posix':  # Unix-based systems
                    pid = os.getpid()
                    # Create a fresh monitor for each sample to avoid accumulation issues
                    tmp_monitor = ProcessMonitor.from_pid(
                        pid=pid,
                        base_interval_ms=base_interval_ms,
                        max_interval_ms=max_interval_ms,
                        output_file=None,  # We'll handle file output separately
                        store_in_memory=False
                    )
                    metrics_json = tmp_monitor.sample_once()
                    if metrics_json is not None:
                        if monitor.store_in_memory:
                            # Need to parse and manually add to monitor's samples
                            metrics = json.loads(metrics_json)
                            monitor.samples.append(metrics)
                        if output_file:
                            with open(output_file, 'a') as f:
                                f.write(metrics_json + '\n')
                time.sleep(base_interval_ms / 1000.0)  # Convert ms to seconds
        except Exception as e:
            print(f"Monitoring error: {e}")
    
    # Start monitoring in a separate thread
    thread = threading.Thread(target=monitoring_thread)
    thread.daemon = True  # Thread won't block program exit
    thread.start()
    
    start_time = time.time()
    try:
        # Call the original function
        result = func(*args, **kwargs)
        return result, monitor.samples
    finally:
        # Stop monitoring thread
        monitoring = False
        thread.join(timeout=1.0)  # Wait up to 1 second for thread to finish
        
        # If we're not storing in memory but have a file, read it back
        if not store_in_memory and output_file and os.path.exists(output_file):
            with open(output_file, 'r') as f:
                monitor.samples = [json.loads(line) for line in f if line.strip()]
    
    # Return original result and metrics
    return result, monitor.samples

# Return the wrapper function
wrapper = functools.wraps(func)(wrapper)
wrapper
        "#,
        None,
        Some(locals),
    )
    .map_err(|e| {
        e.print(py);
        pyo3::exceptions::PyRuntimeError::new_err("Failed to create decorator")
    })
}

#[cfg(feature = "python")]
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
) -> PyResult<&'a PyAny> {
    use pyo3::types::PyDict;
    let locals = PyDict::new(py);
    locals.set_item("base_interval_ms", base_interval_ms)?;
    locals.set_item("max_interval_ms", max_interval_ms)?;
    locals.set_item("output_file", output_file)?;
    locals.set_item("output_format", output_format)?;
    locals.set_item("store_in_memory", store_in_memory)?;
    locals.set_item("ProcessMonitor", py.get_type::<PyProcessMonitor>())?;

    py.eval(
        r#"
class MonitorContextManager:
    def __init__(self, base_interval_ms, max_interval_ms, output_file, output_format, store_in_memory):
        self.base_interval_ms = base_interval_ms
        self.max_interval_ms = max_interval_ms
        self.output_file = output_file
        self.output_format = output_format
        self.store_in_memory = store_in_memory
        self.monitoring = False
        self.thread = None
        self.samples = []
    
    def __enter__(self):
        import os
        import threading
        import time
        import json
        
        # Start monitoring the current process
        self.pid = os.getpid()
        self.monitoring = True
        
        def monitor_thread():
            try:
                while self.monitoring:
                    # Create a fresh monitor for each sample
                    if os.name == 'posix':  # Unix-based systems
                        tmp_monitor = ProcessMonitor.from_pid(
                            pid=self.pid,
                            base_interval_ms=self.base_interval_ms,
                            max_interval_ms=self.max_interval_ms,
                            output_file=None,
                            store_in_memory=False
                        )
                        metrics_json = tmp_monitor.sample_once()
                        if metrics_json is not None:
                            metrics = json.loads(metrics_json)
                            if self.store_in_memory:
                                self.samples.append(metrics)
                            if self.output_file:
                                with open(self.output_file, 'a') as f:
                                    f.write(metrics_json + '\n')
                    time.sleep(self.base_interval_ms / 1000.0)
            except Exception as e:
                print(f"Monitoring error: {e}")
        
        # Start monitoring in background thread
        self.thread = threading.Thread(target=monitor_thread)
        self.thread.daemon = True
        self.thread.start()
        
        return self
    
    def __exit__(self, exc_type, exc_val, exc_tb):
        # Stop monitoring thread
        self.monitoring = False
        if self.thread:
            self.thread.join(timeout=1.0)
    
    def get_samples(self):
        return self.samples
    
    def get_summary(self):
        if not self.samples:
            return "{}"
        
        import json
        from time import time
        
        # Calculate elapsed time
        if len(self.samples) > 1:
            elapsed = (self.samples[-1]["ts_ms"] - self.samples[0]["ts_ms"]) / 1000.0
        else:
            elapsed = 0.0
        
        # Convert samples to JSON strings
        metrics_json = [json.dumps(sample) for sample in self.samples]
        
        # Use the existing summary generation logic
        from denet import generate_summary_from_metrics_json
        return generate_summary_from_metrics_json(metrics_json, elapsed)
    
    def clear_samples(self):
        self.samples = []
    
    def save_samples(self, path, format=None):
        if not self.samples:
            return
        
        format = format or "jsonl"
        
        import json
        
        with open(path, 'w') as f:
            if format == "json":
                # JSON array format
                json.dump(self.samples, f)
            elif format == "csv":
                # CSV format
                if self.samples:
                    # Write header
                    headers = list(self.samples[0].keys())
                    f.write(','.join(headers) + '\n')
                    
                    # Write data rows
                    for sample in self.samples:
                        row = [str(sample.get(h, '')) for h in headers]
                        f.write(','.join(row) + '\n')
            else:
                # Default to JSONL
                for sample in self.samples:
                    f.write(json.dumps(sample) + '\n')

# Create and return an instance of the context manager
MonitorContextManager(base_interval_ms, max_interval_ms, output_file, output_format, store_in_memory)
        "#,
        None,
        Some(locals),
    )
    .map_err(|e| {
        e.print(py);
        pyo3::exceptions::PyRuntimeError::new_err("Failed to create monitor context manager")
    })
}

#[cfg(feature = "python")]
#[pymodule]
fn _denet(_py: Python, m: &PyModule) -> PyResult<()> {
    m.add_class::<PyProcessMonitor>()?;
    m.add_function(wrap_pyfunction!(generate_summary_from_file, m)?)?;
    m.add_function(wrap_pyfunction!(generate_summary_from_metrics_json, m)?)?;
    m.add_function(wrap_pyfunction!(profile, m)?)?;
    m.add_function(wrap_pyfunction!(monitor, m)?)?;
    Ok(())
}

// Tests moved to process_monitor.rs module

#[cfg(not(feature = "python"))]
pub fn run_monitor(
    cmd: Vec<String>,
    base_interval_ms: u64,
    max_interval_ms: u64,
    since_process_start: bool,
) -> process_monitor::ProcessResult<()> {
    use std::thread::sleep;
    use std::time::Duration;

    let mut monitor = process_monitor::ProcessMonitor::new_with_options(
        cmd,
        Duration::from_millis(base_interval_ms),
        Duration::from_millis(max_interval_ms),
        since_process_start,
    )?;

    while monitor.is_running() {
        if let Some(metrics) = monitor.sample_metrics() {
            let json = serde_json::to_string(&metrics).unwrap();
            println!("{}", json);
        }
        sleep(monitor.adaptive_interval());
    }

    Ok(())
}
