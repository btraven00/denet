# Testing Strategy for `denet`

## Overview

This project follows a Rust-first development approach:
- **Rust unit tests** are the primary way to test core functionality
- **Python tests** are only for testing the Python bindings

## Running Tests with Pixi

The recommended way to run tests is using `pixi`, which manages the development environment for you:

### Rust Tests (Primary)

Run the Rust tests for core functionality:

```bash
pixi run test-rust
```

This is the primary testing approach during development.

### Python Binding Tests (Secondary)

Run the Python binding tests after making changes to the interface:

```bash
pixi run develop  # Build the extension first
pixi run test     # Run Python tests
```

### All Tests

To run both test suites to verify everything works:

```bash
pixi run test-all
```

## Running Tests Manually

If you need to run tests outside of pixi (not recommended):

### Rust Tests

```bash
cargo test --no-default-features
```

### Python Tests

```bash
maturin develop
python -m pytest tests/
```

## Test Structure

### Rust Tests (Primary)

Located in the source code modules as `mod tests` blocks. These tests focus on:

- Core `ProcessMonitor` behavior
- Adaptive interval calculation
- Process launching and monitoring
- System metrics collection
- Error handling and edge cases

These tests should be the main focus of development and are written first.

### Python Tests (Secondary)

Located in the `tests/` directory. These tests focus on:

- Python API validation
- Python-specific error handling
- Testing the binding layer
- Verifying Python interface consistency

## Adding New Tests

### Rust Tests (Primary Approach)

Add new Rust tests to the `tests` module in `src/process_monitor.rs`:

```rust
#[test]
fn test_your_new_functionality() {
    // Your test code here
}
```

Most new features should be tested here first.

### Python Tests (Only for Bindings)

Only add Python tests when testing Python-specific binding functionality:

```python
def test_binding_functionality():
    # Test only the Python binding functionality here
```

## Testing Philosophy

- **Rust-first development**: Core functionality is built and tested in Rust
- **Unit tests** verify that individual components work as expected
- **Avoid binding tests when possible**: Python tests should only test the bindings, not core functionality
- **Minimize test execution time** for faster development cycles
- **Use pixi for environment management** to ensure consistent testing environments
- **Keep CI reliable** by preventing environmental issues from affecting test results