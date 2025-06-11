import pytest
import os
import sys
from pathlib import Path

# Simple check that the denet module is importable
def pytest_configure(config):
    # Add the project root to Python path for tests
    project_root = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
    sys.path.insert(0, project_root)
    
    # Check if local modules can be imported (don't exit on failure)
    try:
        import denet
        print("Using installed denet module")
    except ImportError:
        print("NOTE: Using local denet module paths for testing")
        # Allow tests to continue with local imports