//! Tests for error handling in the denet crate

use denet::error::{DenetError, Result};
use std::error::Error;
use std::io;

#[test]
fn test_error_display() {
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
fn test_error_source() {
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
    assert!(DenetError::InvalidConfiguration("test".to_string())
        .source()
        .is_none());
    assert!(DenetError::Other("test".to_string()).source().is_none());
}

#[test]
fn test_error_conversions() {
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

    // Test From<DenetError> for io::Error
    let original_err = DenetError::ProcessNotFound(123);
    let io_err: io::Error = original_err.into();
    assert!(io_err.to_string().contains("Process not found"));

    let original_io_err = io::Error::new(io::ErrorKind::NotFound, "original io error");
    let denet_err = DenetError::Io(original_io_err);
    let converted_io_err: io::Error = denet_err.into();
    assert!(converted_io_err.to_string().contains("original io error"));
}

#[test]
fn test_result_type() {
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
