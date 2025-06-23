//! Error types for the denet library
//!
//! This module provides comprehensive error handling for all denet operations,
//! including process monitoring, I/O operations, and system interactions.

use std::fmt;

/// Main error type for denet operations
#[derive(Debug)]
pub enum DenetError {
    /// I/O related errors (file operations, network, etc.)
    Io(std::io::Error),
    /// Process not found or inaccessible
    ProcessNotFound(usize),
    /// Process access denied
    ProcessAccessDenied(usize),
    /// System time errors
    SystemTime(std::time::SystemTimeError),
    /// JSON serialization/deserialization errors
    Serialization(serde_json::Error),
    /// Configuration or parameter validation errors
    InvalidConfiguration(String),
    /// Platform-specific operation not supported
    PlatformNotSupported(String),
    /// eBPF initialization or operation errors
    EbpfInitError(String),
    /// eBPF not supported on this platform
    EbpfNotSupported(String),
    /// Generic error with message
    Other(String),
}

impl fmt::Display for DenetError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            DenetError::Io(err) => write!(f, "I/O error: {err}"),
            DenetError::ProcessNotFound(pid) => write!(f, "Process not found: {pid}"),
            DenetError::ProcessAccessDenied(pid) => write!(f, "Access denied for process: {pid}"),
            DenetError::SystemTime(err) => write!(f, "System time error: {err}"),
            DenetError::Serialization(err) => write!(f, "Serialization error: {err}"),
            DenetError::InvalidConfiguration(msg) => write!(f, "Invalid configuration: {msg}"),
            DenetError::PlatformNotSupported(msg) => write!(f, "Platform not supported: {msg}"),
            DenetError::EbpfInitError(msg) => write!(f, "eBPF initialization error: {msg}"),
            DenetError::EbpfNotSupported(msg) => write!(f, "eBPF not supported: {msg}"),
            DenetError::Other(msg) => write!(f, "Error: {msg}"),
        }
    }
}

impl std::error::Error for DenetError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match *self {
            DenetError::Io(ref err) => Some(err),
            DenetError::SystemTime(ref err) => Some(err),
            DenetError::Serialization(ref err) => Some(err),
            _ => None,
        }
    }
}

// Conversions from standard library errors
impl From<std::io::Error> for DenetError {
    fn from(err: std::io::Error) -> Self {
        DenetError::Io(err)
    }
}

impl From<std::time::SystemTimeError> for DenetError {
    fn from(err: std::time::SystemTimeError) -> Self {
        DenetError::SystemTime(err)
    }
}

impl From<serde_json::Error> for DenetError {
    fn from(err: serde_json::Error) -> Self {
        DenetError::Serialization(err)
    }
}

// Additional conversions for compatibility
impl From<DenetError> for std::io::Error {
    fn from(err: DenetError) -> Self {
        match err {
            DenetError::Io(io_err) => io_err,
            _ => std::io::Error::other(err.to_string()),
        }
    }
}

/// Convenience type alias for Results with DenetError
pub type Result<T> = std::result::Result<T, DenetError>;

/// Convert DenetError to PyO3 error for Python bindings
#[cfg(feature = "python")]
impl From<DenetError> for pyo3::PyErr {
    fn from(err: DenetError) -> Self {
        use pyo3::exceptions::*;
        match err {
            DenetError::Io(_) => PyIOError::new_err(err.to_string()),
            DenetError::ProcessNotFound(_) => PyRuntimeError::new_err(err.to_string()),
            DenetError::ProcessAccessDenied(_) => PyPermissionError::new_err(err.to_string()),
            DenetError::InvalidConfiguration(_) => PyValueError::new_err(err.to_string()),
            DenetError::PlatformNotSupported(_) => PyNotImplementedError::new_err(err.to_string()),
            DenetError::EbpfInitError(_) => PyRuntimeError::new_err(err.to_string()),
            DenetError::EbpfNotSupported(_) => PyNotImplementedError::new_err(err.to_string()),
            _ => PyRuntimeError::new_err(err.to_string()),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::error::Error;
    use std::io;

    #[test]
    fn test_denet_error_display() {
        // Test IO error display
        let io_err = io::Error::new(io::ErrorKind::NotFound, "file not found");
        let denet_err = DenetError::Io(io_err);
        assert!(denet_err.to_string().contains("I/O error"));
        assert!(denet_err.to_string().contains("file not found"));

        // Test process not found error
        let pid = 12345;
        let err = DenetError::ProcessNotFound(pid);
        assert_eq!(err.to_string(), format!("Process not found: {}", pid));

        // Test process access denied error
        let err = DenetError::ProcessAccessDenied(pid);
        assert_eq!(
            err.to_string(),
            format!("Access denied for process: {}", pid)
        );

        // Test system time error
        let time_err = std::time::SystemTime::now()
            .duration_since(std::time::SystemTime::now() + std::time::Duration::from_secs(1))
            .unwrap_err();
        let err = DenetError::SystemTime(time_err);
        assert!(err.to_string().contains("System time error"));

        // Test serialization error
        let json_err = serde_json::Error::io(io::Error::new(io::ErrorKind::Other, "JSON error"));
        let err = DenetError::Serialization(json_err);
        assert!(err.to_string().contains("Serialization error"));

        // Test invalid configuration error
        let msg = "Invalid config parameter";
        let err = DenetError::InvalidConfiguration(msg.to_string());
        assert_eq!(err.to_string(), format!("Invalid configuration: {}", msg));

        // Test platform not supported error
        let msg = "Windows feature";
        let err = DenetError::PlatformNotSupported(msg.to_string());
        assert_eq!(err.to_string(), format!("Platform not supported: {}", msg));

        // Test eBPF initialization error
        let msg = "Failed to initialize BPF";
        let err = DenetError::EbpfInitError(msg.to_string());
        assert_eq!(
            err.to_string(),
            format!("eBPF initialization error: {}", msg)
        );

        // Test eBPF not supported error
        let msg = "Kernel too old";
        let err = DenetError::EbpfNotSupported(msg.to_string());
        assert_eq!(err.to_string(), format!("eBPF not supported: {}", msg));

        // Test other error
        let msg = "Generic error";
        let err = DenetError::Other(msg.to_string());
        assert_eq!(err.to_string(), format!("Error: {}", msg));
    }

    #[test]
    fn test_denet_error_source() {
        // Test IO error source
        let io_err = io::Error::new(io::ErrorKind::NotFound, "file not found");
        let denet_err = DenetError::Io(io_err);
        assert!(denet_err.source().is_some());

        // Test system time error source
        let time_err = std::time::SystemTime::now()
            .duration_since(std::time::SystemTime::now() + std::time::Duration::from_secs(1))
            .unwrap_err();
        let denet_err = DenetError::SystemTime(time_err);
        assert!(denet_err.source().is_some());

        // Test serialization error source
        let json_err = serde_json::Error::io(io::Error::new(io::ErrorKind::Other, "JSON error"));
        let denet_err = DenetError::Serialization(json_err);
        assert!(denet_err.source().is_some());

        // Test errors without source
        assert!(DenetError::ProcessNotFound(123).source().is_none());
        assert!(DenetError::ProcessAccessDenied(456).source().is_none());
        assert!(DenetError::InvalidConfiguration("test".to_string())
            .source()
            .is_none());
        assert!(DenetError::PlatformNotSupported("test".to_string())
            .source()
            .is_none());
        assert!(DenetError::EbpfInitError("test".to_string())
            .source()
            .is_none());
        assert!(DenetError::EbpfNotSupported("test".to_string())
            .source()
            .is_none());
        assert!(DenetError::Other("test".to_string()).source().is_none());
    }

    #[test]
    fn test_error_conversions_from_std() {
        // Test From<io::Error>
        let io_err = io::Error::new(io::ErrorKind::NotFound, "file not found");
        let denet_err: DenetError = io_err.into();
        match denet_err {
            DenetError::Io(_) => (),
            _ => panic!("Expected Io error variant"),
        }

        // Test From<SystemTimeError>
        let time_err = std::time::SystemTime::now()
            .duration_since(std::time::SystemTime::now() + std::time::Duration::from_secs(1))
            .unwrap_err();
        let denet_err: DenetError = time_err.into();
        match denet_err {
            DenetError::SystemTime(_) => (),
            _ => panic!("Expected SystemTime error variant"),
        }

        // Test From<serde_json::Error>
        let json_err = serde_json::Error::io(io::Error::new(io::ErrorKind::Other, "JSON error"));
        let denet_err: DenetError = json_err.into();
        match denet_err {
            DenetError::Serialization(_) => (),
            _ => panic!("Expected Serialization error variant"),
        }
    }

    #[test]
    fn test_error_conversion_to_io_error() {
        // Test From<DenetError> for io::Error - IO variant
        let original_io_err = io::Error::new(io::ErrorKind::NotFound, "original io error");
        let denet_err = DenetError::Io(original_io_err);
        let converted_io_err: io::Error = denet_err.into();
        assert!(converted_io_err.to_string().contains("original io error"));

        // Test From<DenetError> for io::Error - non-IO variant
        let original_err = DenetError::ProcessNotFound(123);
        let io_err: io::Error = original_err.into();
        assert!(io_err.to_string().contains("Process not found"));
    }

    #[test]
    fn test_result_type_alias() {
        // Test with success
        let result: Result<i32> = Ok(42);
        assert_eq!(result.unwrap(), 42);

        // Test with error
        let error_result: Result<i32> = Err(DenetError::Other("test error".to_string()));
        assert!(error_result.is_err());
        match error_result {
            Err(DenetError::Other(msg)) => assert_eq!(msg, "test error"),
            _ => panic!("Expected Other error variant"),
        }
    }

    #[test]
    fn test_denet_error_debug() {
        let err = DenetError::ProcessNotFound(123);
        let debug_str = format!("{:?}", err);
        assert!(debug_str.contains("ProcessNotFound"));
        assert!(debug_str.contains("123"));
    }

    #[cfg(feature = "python")]
    #[test]
    fn test_python_error_conversion() {
        use pyo3::exceptions::*;
        use pyo3::Python;

        Python::with_gil(|py| {
            // Test IO error conversion
            let io_err = io::Error::new(io::ErrorKind::NotFound, "file not found");
            let denet_err = DenetError::Io(io_err);
            let py_err: pyo3::PyErr = denet_err.into();
            assert!(py_err.is_instance_of::<PyIOError>(py));

            // Test ProcessNotFound conversion
            let denet_err = DenetError::ProcessNotFound(123);
            let py_err: pyo3::PyErr = denet_err.into();
            assert!(py_err.is_instance_of::<PyRuntimeError>(py));

            // Test ProcessAccessDenied conversion
            let denet_err = DenetError::ProcessAccessDenied(123);
            let py_err: pyo3::PyErr = denet_err.into();
            assert!(py_err.is_instance_of::<PyPermissionError>(py));

            // Test InvalidConfiguration conversion
            let denet_err = DenetError::InvalidConfiguration("test".to_string());
            let py_err: pyo3::PyErr = denet_err.into();
            assert!(py_err.is_instance_of::<PyValueError>(py));

            // Test PlatformNotSupported conversion
            let denet_err = DenetError::PlatformNotSupported("test".to_string());
            let py_err: pyo3::PyErr = denet_err.into();
            assert!(py_err.is_instance_of::<PyNotImplementedError>(py));

            // Test EbpfInitError conversion
            let denet_err = DenetError::EbpfInitError("test".to_string());
            let py_err: pyo3::PyErr = denet_err.into();
            assert!(py_err.is_instance_of::<PyRuntimeError>(py));

            // Test EbpfNotSupported conversion
            let denet_err = DenetError::EbpfNotSupported("test".to_string());
            let py_err: pyo3::PyErr = denet_err.into();
            assert!(py_err.is_instance_of::<PyNotImplementedError>(py));

            // Test Other error conversion (fallback)
            let denet_err = DenetError::Other("test".to_string());
            let py_err: pyo3::PyErr = denet_err.into();
            assert!(py_err.is_instance_of::<PyRuntimeError>(py));

            // Test SystemTime error conversion (fallback)
            let time_err = std::time::SystemTime::now()
                .duration_since(std::time::SystemTime::now() + std::time::Duration::from_secs(1))
                .unwrap_err();
            let denet_err = DenetError::SystemTime(time_err);
            let py_err: pyo3::PyErr = denet_err.into();
            assert!(py_err.is_instance_of::<PyRuntimeError>(py));

            // Test Serialization error conversion (fallback)
            let json_err =
                serde_json::Error::io(io::Error::new(io::ErrorKind::Other, "JSON error"));
            let denet_err = DenetError::Serialization(json_err);
            let py_err: pyo3::PyErr = denet_err.into();
            assert!(py_err.is_instance_of::<PyRuntimeError>(py));
        });
    }
}
