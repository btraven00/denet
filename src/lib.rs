// Split into modules to separate PyO3 dependencies from pure Rust code
pub mod process_monitor;

// Re-export the ProcessMonitor and related types for use in tests and binaries
pub use process_monitor::{ProcessMonitor, Metrics, ProcessMetadata, AggregatedMetrics, ProcessTreeMetrics, ChildProcessMetrics};

// Import what we need for the Python module
#[cfg(feature = "python")]
use pyo3::prelude::*;

#[cfg(feature = "python")]
#[pyclass]
struct PyProcessMonitor {
    inner: ProcessMonitor,
}

#[cfg(feature = "python")]
#[pymethods]
impl PyProcessMonitor {
    #[new]
    #[pyo3(signature = (cmd, base_interval_ms, max_interval_ms, since_process_start=false))]
    fn new(cmd: Vec<String>, base_interval_ms: u64, max_interval_ms: u64, since_process_start: bool) -> PyResult<Self> {
        use std::time::Duration;
        
        let inner = ProcessMonitor::new_with_options(
            cmd,
            Duration::from_millis(base_interval_ms),
            Duration::from_millis(max_interval_ms),
            since_process_start,
        ).map_err(process_monitor::io_err_to_py_err)?;
        
        Ok(PyProcessMonitor { inner })
    }
    
    #[staticmethod]
    #[pyo3(signature = (pid, base_interval_ms, max_interval_ms, since_process_start=false))]
    fn from_pid(pid: usize, base_interval_ms: u64, max_interval_ms: u64, since_process_start: bool) -> PyResult<Self> {
        use std::time::Duration;
        
        let inner = ProcessMonitor::from_pid_with_options(
            pid, 
            Duration::from_millis(base_interval_ms),
            Duration::from_millis(max_interval_ms),
            since_process_start,
        ).map_err(process_monitor::io_err_to_py_err)?;
        
        Ok(PyProcessMonitor { inner })
    }

    fn run(&mut self) -> PyResult<()> {
        use std::thread::sleep;

        while self.inner.is_running() {
            if let Some(metrics) = self.inner.sample_metrics() {
                let json = serde_json::to_string(&metrics).unwrap();
                println!("{}", json);
            }
            sleep(self.inner.adaptive_interval());
        }
        Ok(())
    }
    
    fn sample_once(&mut self) -> PyResult<Option<String>> {
        Ok(self.inner.sample_metrics().map(|metrics| {
            serde_json::to_string(&metrics).unwrap_or_default()
        }))
    }
    
    fn is_running(&mut self) -> PyResult<bool> {
        Ok(self.inner.is_running())
    }
    
    fn get_pid(&self) -> PyResult<usize> {
        Ok(self.inner.get_pid())
    }
    
    fn get_metadata(&mut self) -> PyResult<Option<String>> {
        Ok(self.inner.get_metadata().map(|metadata| {
            serde_json::to_string(&metadata).unwrap_or_default()
        }))
    }
}

#[cfg(feature = "python")]
#[pymodule]
fn pmet(_py: Python, m: &PyModule) -> PyResult<()> {
    m.add_class::<PyProcessMonitor>()?;
    Ok(())
}

// Tests moved to process_monitor.rs module

#[cfg(not(feature = "python"))]
pub fn run_monitor(
    cmd: Vec<String>, 
    base_interval_ms: u64, 
    max_interval_ms: u64,
    since_process_start: bool
) -> process_monitor::ProcessResult<()> {
    use std::time::Duration;
    use std::thread::sleep;
    use process_monitor::ProcessMonitor;
    
    let mut monitor = ProcessMonitor::new_with_options(
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

