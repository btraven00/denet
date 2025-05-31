import pytest
import os
import sys
from pathlib import Path

# Simple check that the denet module is importable
def pytest_configure(config):
    # Check if the denet module is already importable
    try:
        import denet
    except ImportError:
        print("ERROR: The denet module is not importable.")
        print("Please run 'pixi run develop' before running the tests.")
        print("Or use 'pixi run test-all' to run both Rust and Python tests.")
        sys.exit(1)