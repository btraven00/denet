# Denet Python Test Suite

This directory contains the refactored Python test suite for denet, designed with modern pytest best practices and focused testing principles.

## Test Structure

### Core Test Modules

- **`test_bindings.py`** - Tests Python-Rust bindings integrity and data flow
- **`test_integration.py`** - End-to-end integration tests for complete workflows  
- **`test_monitor_api.py`** - ProcessMonitor class API functionality tests
- **`test_summary_api.py`** - Summary generation function tests
- **`test_analysis.py`** - Analysis utilities and data processing tests
- **`test_legacy_compatibility.py`** - Backwards compatibility and converted legacy tests

### Support Files

- **`test_helpers.py`** - Focused utility functions for test support
- **`conftest.py`** - Pytest configuration, fixtures, and shared setup

## Design Principles

### ✅ What We Test

1. **Interface Contracts** - API behavior, input/output validation, error handling
2. **Data Integrity** - Correct data flow between Python and Rust layers
3. **Integration Workflows** - Complete end-to-end functionality
4. **Edge Cases** - Boundary conditions, error states, resource constraints
5. **Backwards Compatibility** - Legacy API patterns continue to work

### ❌ What We Don't Test

1. **Implementation Details** - Internal Rust logic (covered by Rust tests)
2. **Algorithm Reimplementation** - Duplicating core functionality in Python
3. **Timing-Dependent Logic** - Flaky tests that depend on precise timing
4. **Platform-Specific Behavior** - Detailed OS-level resource measurement

## Test Categories

### Bindings Tests (`test_bindings.py`)
- ProcessMonitor creation and basic operations
- Data type validation and JSON serialization
- Memory management (store_in_memory functionality)
- Concurrent access safety
- Summary generation function bindings

### Integration Tests (`test_integration.py`)
- `execute_with_monitoring` complete workflows
- File output in different formats
- Error handling scenarios
- Resource-intensive process monitoring
- Multi-format compatibility

### API Tests (`test_monitor_api.py`)
- ProcessMonitor lifecycle (creation, sampling, cleanup)
- File I/O operations (direct output, save_samples)
- Memory management features
- Metadata access methods
- Edge cases and error conditions

### Summary Tests (`test_summary_api.py`)
- Summary generation from metrics JSON
- File-based summary generation
- Tree metrics handling
- Data integrity validation
- Error handling for malformed data

### Analysis Tests (`test_analysis.py`)
- Metrics aggregation functionality
- Peak detection algorithms
- Resource utilization statistics
- Format conversion utilities
- Process tree analysis
- File save/load operations

### Legacy Tests (`test_legacy_compatibility.py`)
- Original unittest-style test patterns converted to pytest
- Backwards compatibility validation
- Legacy API signatures and behaviors

## Running Tests

### Run All Tests
```bash
pixi run pytest tests/python/
```

### Run Specific Test Categories
```bash
# Run only binding tests
pixi run pytest tests/python/test_bindings.py

# Run integration tests
pixi run pytest tests/python/test_integration.py -m integration

# Skip slow tests
pixi run pytest tests/python/ -m "not slow"
```

### Run with Coverage
```bash
pixi run pytest-with-coverage
```

## Test Fixtures and Utilities

### Common Fixtures (from `conftest.py`)
- `denet_module` - Access to the denet module
- `tmp_path` - Temporary directory for test files (pytest built-in)
- `simple_command` - Basic echo command for testing
- `sleep_command(duration)` - Sleep command with configurable duration
- `python_script(script, duration)` - Python script execution helper

### Helper Functions (from `test_helpers.py`)
- `extract_metrics_from_sample(sample)` - Extract metrics from various formats
- `is_valid_metrics_sample(sample)` - Validate metrics sample structure
- `filter_metrics_samples(samples)` - Filter valid metrics from sample list
- `assert_valid_metrics(metrics)` - Assert metrics contain expected fields
- `create_sample_metrics(count)` - Generate test metrics data

## Best Practices

### Writing New Tests

1. **Use pytest style** - No unittest.TestCase, use plain functions and classes
2. **Use tmp_path fixture** - Instead of tempfile for test file creation
3. **Test behavior, not implementation** - Focus on what the API should do
4. **Keep tests isolated** - Each test should be independent
5. **Use descriptive names** - Test names should clearly describe what's being tested
6. **Add proper docstrings** - Explain what each test validates

### Example Test Structure
```python
class TestFeatureName:
    """Test specific feature functionality."""
    
    def test_basic_functionality(self, tmp_path):
        """Test basic feature behavior."""
        # Arrange
        input_data = create_test_data()
        
        # Act
        result = feature_function(input_data)
        
        # Assert
        assert result is not None
        assert_expected_behavior(result)
    
    def test_edge_case(self):
        """Test edge case handling."""
        # Test edge cases, error conditions, etc.
        pass
```

### File Handling Pattern
```python
def test_file_operation(self, tmp_path):
    """Test file operations using tmp_path."""
    # Create test file
    test_file = tmp_path / "test_data.jsonl"
    
    # Write test data
    with open(test_file, 'w') as f:
        f.write('{"test": "data"}\n')
    
    # Test functionality
    result = process_file(str(test_file))
    
    # Verify results
    assert result is not None
    # tmp_path automatically cleaned up by pytest
```

## Migration Notes

### Changes from Previous Test Suite

1. **Removed Files** - Deleted reimplementation tests and overly complex timing tests
2. **Converted unittest to pytest** - All tests now use pytest conventions
3. **Simplified test helpers** - Focused utility functions instead of complex abstractions
4. **Better organization** - Tests grouped by functionality rather than scattered
5. **Improved fixtures** - Proper pytest fixtures instead of manual setup/teardown

### Backwards Compatibility
Legacy API patterns are tested in `test_legacy_compatibility.py` to ensure existing code continues to work.

## Coverage Goals

- **Bindings Coverage** - All Python-Rust interface points
- **API Coverage** - All public methods and functions
- **Error Path Coverage** - Exception handling and edge cases
- **Integration Coverage** - Complete workflows and format compatibility

The test suite prioritizes reliability and maintainability over exhaustive implementation testing, ensuring denet's Python interface works correctly without duplicating the comprehensive Rust test coverage.