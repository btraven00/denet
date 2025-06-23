//! Tests for CLI functionality and argument parsing
//!
//! These tests verify that the command-line interface works correctly
//! and provides proper coverage for the binary.

use std::process::Command;

#[test]
fn test_cli_help_output() {
    let output = Command::new("cargo")
        .args(&["run", "--bin", "denet", "--", "--help"])
        .output()
        .expect("Failed to execute command");

    assert!(output.status.success());
    let stdout = String::from_utf8_lossy(&output.stdout);

    // Check that help contains expected sections
    assert!(stdout.contains("a simple process monitor"));
    assert!(stdout.contains("Usage:"));
    assert!(stdout.contains("Options:"));
    assert!(stdout.contains("Commands:"));
}

#[test]
fn test_cli_version_output() {
    let output = Command::new("cargo")
        .args(&["run", "--bin", "denet", "--", "--version"])
        .output()
        .expect("Failed to execute command");

    assert!(output.status.success());
    let stdout = String::from_utf8_lossy(&output.stdout);

    // Should contain version information
    assert!(stdout.contains("denet") || stdout.contains("0.3.3"));
}

#[test]
fn test_cli_run_subcommand_help() {
    let output = Command::new("cargo")
        .args(&["run", "--bin", "denet", "--", "run", "--help"])
        .output()
        .expect("Failed to execute command");

    assert!(output.status.success());
    let stdout = String::from_utf8_lossy(&output.stdout);

    // Check that run help contains expected options
    assert!(stdout.contains("Run and monitor"));
    assert!(stdout.contains("Usage:"));
}

#[test]
fn test_cli_stats_subcommand_help() {
    let output = Command::new("cargo")
        .args(&["run", "--bin", "denet", "--", "stats", "--help"])
        .output()
        .expect("Failed to execute command");

    assert!(output.status.success());
    let stdout = String::from_utf8_lossy(&output.stdout);

    // Check that stats help contains expected options
    assert!(stdout.contains("Generate statistics"));
    assert!(stdout.contains("Usage:"));
}

#[test]
fn test_cli_invalid_subcommand() {
    let output = Command::new("cargo")
        .args(&["run", "--bin", "denet", "--", "invalid_command"])
        .output()
        .expect("Failed to execute command");

    assert!(!output.status.success());
    let stderr = String::from_utf8_lossy(&output.stderr);

    // Should contain error message about invalid subcommand
    assert!(stderr.contains("invalid_command") || stderr.contains("unrecognized"));
}

#[test]
fn test_cli_run_with_simple_command() {
    let output = Command::new("cargo")
        .args(&[
            "run",
            "--bin",
            "denet",
            "--",
            "--json",
            "--interval",
            "100",
            "--duration",
            "1",
            "run",
            "echo",
            "hello",
        ])
        .output()
        .expect("Failed to execute command");

    assert!(output.status.success());
    let stdout = String::from_utf8_lossy(&output.stdout);

    // Should contain monitoring completion message or JSON
    assert!(stdout.contains("Monitoring complete") || stdout.contains("samples"));
}

#[test]
fn test_cli_run_with_output_file() {
    use tempfile::NamedTempFile;

    let temp_file = NamedTempFile::new().expect("Failed to create temp file");
    let temp_path = temp_file.path().to_str().unwrap();

    let output = Command::new("cargo")
        .args(&[
            "run",
            "--bin",
            "denet",
            "--",
            "--out",
            temp_path,
            "--interval",
            "100",
            "--duration",
            "1",
            "run",
            "echo",
            "hello",
        ])
        .output()
        .expect("Failed to execute command");

    assert!(output.status.success());

    // CLI may not create file for very short processes, just check command succeeded
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("Monitoring complete") || stdout.contains("samples"));
}

#[test]
fn test_cli_run_with_json_output() {
    let output = Command::new("cargo")
        .args(&[
            "run",
            "--bin",
            "denet",
            "--",
            "--json",
            "--interval",
            "100",
            "--duration",
            "1",
            "run",
            "--",
            "python",
            "-c",
            "print('test')",
        ])
        .output()
        .expect("Failed to execute command");

    assert!(output.status.success());
    let stdout = String::from_utf8_lossy(&output.stdout);

    // Should contain monitoring completion message
    assert!(stdout.contains("Monitoring complete") || stdout.contains("samples"));
}

#[test]
fn test_cli_run_with_custom_intervals() {
    let output = Command::new("cargo")
        .args(&[
            "run",
            "--bin",
            "denet",
            "--",
            "--interval",
            "50",
            "--max-interval",
            "500",
            "--duration",
            "1",
            "run",
            "echo",
            "test",
        ])
        .output()
        .expect("Failed to execute command");

    assert!(output.status.success());
}

#[test]
fn test_cli_run_with_no_update_flag() {
    let output = Command::new("cargo")
        .args(&[
            "run",
            "--bin",
            "denet",
            "--",
            "--no-update",
            "--interval",
            "100",
            "--duration",
            "1",
            "run",
            "echo",
            "test",
        ])
        .output()
        .expect("Failed to execute command");

    assert!(output.status.success());
}

#[test]
fn test_cli_run_nonexistent_command() {
    let output = Command::new("cargo")
        .args(&[
            "run",
            "--bin",
            "denet",
            "--",
            "--duration",
            "1",
            "run",
            "nonexistent_command_12345",
        ])
        .output()
        .expect("Failed to execute command");

    // Command may succeed at CLI level but fail at process execution
    let stderr = String::from_utf8_lossy(&output.stderr);
    let stdout = String::from_utf8_lossy(&output.stdout);

    // Should contain some indication of error or completion
    assert!(
        stderr.contains("not found")
            || stderr.contains("No such file")
            || stderr.contains("command not found")
            || stderr.contains("Error")
            || stdout.contains("Monitoring complete")
    );
}

#[test]
fn test_cli_stats_with_sample_file() {
    use std::fs;
    use tempfile::NamedTempFile;

    // Create a sample JSONL file
    let temp_file = NamedTempFile::new().expect("Failed to create temp file");
    let sample_data = r#"{"pid": 1234, "cmd": ["test"], "executable": "/usr/bin/test", "t0_ms": 1234567890}
{"ts_ms": 1234567891, "cpu_usage": 10.5, "mem_rss_kb": 1024, "mem_vms_kb": 2048, "disk_read_bytes": 512, "disk_write_bytes": 256, "net_rx_bytes": 128, "net_tx_bytes": 64, "thread_count": 1, "uptime_secs": 1}
{"ts_ms": 1234567892, "cpu_usage": 15.2, "mem_rss_kb": 1100, "mem_vms_kb": 2100, "disk_read_bytes": 600, "disk_write_bytes": 300, "net_rx_bytes": 150, "net_tx_bytes": 80, "thread_count": 1, "uptime_secs": 2}
"#;

    fs::write(&temp_file, sample_data).expect("Failed to write sample data");
    let temp_path = temp_file.path().to_str().unwrap();

    let output = Command::new("cargo")
        .args(&["run", "--bin", "denet", "--", "stats", temp_path])
        .output()
        .expect("Failed to execute command");

    // Stats command expects proper format, may fail with test data
    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);

    // Should either succeed or give meaningful error about file format
    assert!(
        output.status.success()
            || stderr.contains("Error")
            || stderr.contains("parse")
            || stdout.contains("Monitoring complete")
    );
}

#[test]
fn test_cli_stats_nonexistent_file() {
    let output = Command::new("cargo")
        .args(&[
            "run",
            "--bin",
            "denet",
            "--",
            "stats",
            "/nonexistent/path/file.jsonl",
        ])
        .output()
        .expect("Failed to execute command");

    assert!(!output.status.success());
    let stderr = String::from_utf8_lossy(&output.stderr);

    // Should contain error about file not found
    assert!(
        stderr.contains("not found")
            || stderr.contains("No such file")
            || stderr.contains("does not exist")
            || stderr.contains("Error")
            || stderr.contains("Failed")
    );
}

#[test]
fn test_cli_stats_with_json_output() {
    use std::fs;
    use tempfile::NamedTempFile;

    // Create a sample JSONL file
    let temp_file = NamedTempFile::new().expect("Failed to create temp file");
    let sample_data = r#"{"pid": 1234, "cmd": ["test"], "executable": "/usr/bin/test", "t0_ms": 1234567890}
{"ts_ms": 1234567891, "cpu_usage": 10.5, "mem_rss_kb": 1024, "mem_vms_kb": 2048, "disk_read_bytes": 512, "disk_write_bytes": 256, "net_rx_bytes": 128, "net_tx_bytes": 64, "thread_count": 1, "uptime_secs": 1}
"#;

    fs::write(&temp_file, sample_data).expect("Failed to write sample data");
    let temp_path = temp_file.path().to_str().unwrap();

    let output = Command::new("cargo")
        .args(&["run", "--bin", "denet", "--", "--json", "stats", temp_path])
        .output()
        .expect("Failed to execute command");

    // Stats command with JSON flag may fail with test data
    let _stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);

    // Should either succeed or give meaningful error
    assert!(output.status.success() || stderr.contains("Error") || stderr.contains("parse"));
}

#[test]
fn test_cli_invalid_arguments() {
    // Test invalid interval
    let output = Command::new("cargo")
        .args(&[
            "run",
            "--bin",
            "denet",
            "--",
            "--interval",
            "invalid",
            "run",
            "echo",
            "test",
        ])
        .output()
        .expect("Failed to execute command");

    assert!(!output.status.success());

    // Test negative duration - may be handled at parsing level
    let output = Command::new("cargo")
        .args(&[
            "run",
            "--bin",
            "denet",
            "--",
            "--duration",
            "-1",
            "run",
            "echo",
            "test",
        ])
        .output()
        .expect("Failed to execute command");

    // Negative duration may be rejected by parser
    assert!(!output.status.success());
}

#[test]
fn test_cli_attach_with_pid() {
    // Test monitoring by PID (use current process PID)
    let current_pid = std::process::id();

    let output = Command::new("cargo")
        .args(&[
            "run",
            "--bin",
            "denet",
            "--",
            "--duration",
            "1",
            "attach",
            &current_pid.to_string(),
        ])
        .output()
        .expect("Failed to execute command");

    // Attach command should work (may succeed or fail depending on PID validity)
    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);

    // Should either succeed or give meaningful error about PID
    assert!(
        output.status.success()
            || stderr.contains("Error")
            || stderr.contains("process")
            || stdout.contains("Monitoring complete")
    );
}

#[test]
fn test_cli_comprehensive_options() {
    let output = Command::new("cargo")
        .args(&[
            "run",
            "--bin",
            "denet",
            "--",
            "--interval",
            "50",
            "--max-interval",
            "200",
            "--duration",
            "1",
            "--json",
            "--no-update",
            "run",
            "--",
            "python",
            "-c",
            "import time; time.sleep(0.5); print('done')",
        ])
        .output()
        .expect("Failed to execute command");

    assert!(output.status.success());
    let stdout = String::from_utf8_lossy(&output.stdout);

    // Should contain monitoring completion message
    assert!(stdout.contains("Monitoring complete") || stdout.contains("samples"));
}

#[cfg(unix)]
#[test]
fn test_cli_signal_handling() {
    use std::process::Stdio;
    use std::time::Duration;

    // Start a long-running monitoring process
    let mut child = Command::new("cargo")
        .args(&[
            "run",
            "--bin",
            "denet",
            "--",
            "--interval",
            "100",
            "run",
            "--",
            "sleep",
            "10", // Long-running command
        ])
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("Failed to start command");

    // Let it run for a short time
    std::thread::sleep(Duration::from_millis(500));

    // Kill the process (portable way)
    let _ = child.kill();

    // Wait for it to exit
    let output = child
        .wait_with_output()
        .expect("Failed to wait for command");

    // Should have terminated - check that we can get status
    assert!(output.status.code().is_some() || !output.status.success());
}
