"""
Pytest configuration and shared fixtures for denet tests.

This module provides common test configuration and fixtures used across
the denet test suite.
"""

import os
import sys
import pytest

# Add the project root to Python path for tests
project_root = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
if project_root not in sys.path:
    sys.path.insert(0, project_root)

# Verify denet module can be imported
try:
    import denet

    print(f"✓ Using denet module version {getattr(denet, '__version__', 'unknown')}")
except ImportError as e:
    print(f"✗ Failed to import denet: {e}")
    print("Run 'pixi run develop' to build the extension module")
    pytest.exit("denet module not available", returncode=1)


@pytest.fixture(scope="session")
def denet_module():
    """Provide access to the denet module for tests."""
    return denet


@pytest.fixture
def temp_files():
    """Fixture that tracks temporary files for cleanup."""
    temp_files_list = []

    def register_temp_file(path):
        temp_files_list.append(path)
        return path

    yield register_temp_file

    # Cleanup
    for temp_file in temp_files_list:
        try:
            if os.path.exists(temp_file):
                os.unlink(temp_file)
        except OSError:
            pass  # Best effort cleanup


@pytest.fixture
def simple_command():
    """Provide a simple command for testing."""
    return ["echo", "test"]


@pytest.fixture
def sleep_command():
    """Provide a sleep command for testing with specified duration."""

    def _sleep_command(duration=0.1):
        return ["sleep", str(duration)]

    return _sleep_command


@pytest.fixture
def python_script():
    """Provide a Python script command for testing."""

    def _python_script(script_content, duration=0.1):
        return ["python", "-c", f"{script_content}; import time; time.sleep({duration})"]

    return _python_script


def pytest_configure(config):
    """Configure pytest with custom markers and settings."""
    config.addinivalue_line("markers", "slow: marks tests as slow (deselect with '-m \"not slow\"')")
    config.addinivalue_line("markers", "integration: marks tests as integration tests")


def pytest_collection_modifyitems(config, items):
    """Modify test collection to add markers based on test location."""
    for item in items:
        # Mark integration tests
        if "test_integration" in item.nodeid:
            item.add_marker(pytest.mark.integration)

        # Mark potentially slow tests
        if any(keyword in item.nodeid for keyword in ["long_running", "resource_intensive"]):
            item.add_marker(pytest.mark.slow)
