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
    /// Generic error with message
    Other(String),
}

impl fmt::Display for DenetError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            DenetError::Io(err) => write!(f, "I/O error: {}", err),
            DenetError::ProcessNotFound(pid) => write!(f, "Process not found: {}", pid),
            DenetError::ProcessAccessDenied(pid) => write!(f, "Access denied for process: {}", pid),
            DenetError::SystemTime(err) => write!(f, "System time error: {}", err),
            DenetError::Serialization(err) => write!(f, "Serialization error: {}", err),
            DenetError::InvalidConfiguration(msg) => write!(f, "Invalid configuration: {}", msg),
            DenetError::PlatformNotSupported(msg) => write!(f, "Platform not supported: {}", msg),
            DenetError::Other(msg) => write!(f, "Error: {}", msg),
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
            _ => PyRuntimeError::new_err(err.to_string()),
        }
    }
}
